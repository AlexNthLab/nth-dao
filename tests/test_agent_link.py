from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from nth_dao.web.agent_link import (
    AgentLinkConflict,
    AgentLinkBusy,
    AgentLinkManager,
    AgentLinkStore,
    AgentLinkStoreFull,
    IdempotencyConflict,
)


def _wait_for(manager, job_id: str, state: str, timeout: float = 5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = manager.get(job_id)
        if job is not None and job.state == state:
            return job
        time.sleep(0.01)
    return None


def test_agent_link_has_ack_processing_and_signed_result_metadata(tmp_path):
    manager = AgentLinkManager(AgentLinkStore(tmp_path))
    try:
        job = manager.submit(
            agent_id="hermes-1",
            agent_did="did:key:z6MkHermes",
            idempotency_key="message-1",
            worker=lambda: {
                "response": "done",
                "receipt_id": "receipt-1",
            },
        )
        assert job.state == "accepted"
        done = _wait_for(manager, job.job_id, "completed")
        assert done is not None
        assert done.response == "done"
        assert done.receipt_id == "receipt-1"
        assert AgentLinkStore(tmp_path).get(job.job_id).state == "completed"
    finally:
        manager.close()


def test_agent_link_serializes_each_agent_but_allows_queueing(tmp_path):
    manager = AgentLinkManager(AgentLinkStore(tmp_path), max_pending_per_agent=2)
    started = threading.Event()
    release = threading.Event()
    order = []

    def first():
        order.append("first")
        started.set()
        release.wait(2.0)
        return {"response": "one"}

    try:
        first_job = manager.submit(
            agent_id="a", agent_did="did:key:z6MkA", worker=first,
        )
        assert started.wait(1.0)
        second_job = manager.submit(
            agent_id="a", agent_did="did:key:z6MkA",
            worker=lambda: (order.append("second") or {"response": "two"}),
        )
        assert manager.get(second_job.job_id).state == "accepted"
        release.set()
        assert _wait_for(
            manager, first_job.job_id, "completed_unverified",
        ) is not None
        assert _wait_for(
            manager, second_job.job_id, "completed_unverified",
        ) is not None
        assert order == ["first", "second"]
    finally:
        release.set()
        manager.close()


def test_agent_link_deferred_start_preserves_status_before_execution(tmp_path):
    manager = AgentLinkManager(AgentLinkStore(tmp_path))
    events = []
    try:
        job = manager.submit(
            agent_id="a",
            agent_did="did:key:z6MkA",
            idempotency_key="ordered",
            request_hash="ordered-hash",
            autostart=False,
            worker=lambda: (events.append("worker") or {"response": "ok"}),
        )
        events.extend(["received", "processing"])
        manager.start(job.agent_did)
        assert _wait_for(manager, job.job_id, "completed_unverified") is not None
        assert events == ["received", "processing", "worker"]
    finally:
        manager.close()


def test_agent_link_idempotency_does_not_execute_twice(tmp_path):
    manager = AgentLinkManager(AgentLinkStore(tmp_path))
    calls = []
    try:
        def worker():
            calls.append(1)
            return {"response": "once"}

        one = manager.submit(
            agent_id="a", agent_did="did:key:z6MkA",
            idempotency_key="same", request_hash="hash-a", worker=worker,
        )
        two = manager.submit(
            agent_id="a", agent_did="did:key:z6MkA",
            idempotency_key="same", request_hash="hash-a", worker=worker,
        )
        assert one.job_id == two.job_id
        assert _wait_for(manager, one.job_id, "completed_unverified") is not None
        assert calls == [1]
        with pytest.raises(IdempotencyConflict):
            manager.submit(
                agent_id="a", agent_did="did:key:z6MkA",
                idempotency_key="same", request_hash="hash-b", worker=worker,
            )
    finally:
        manager.close()


def test_agent_link_state_machine_rejects_backward_transition(tmp_path):
    store = AgentLinkStore(tmp_path)
    job = store.create(
        agent_id="a",
        agent_did="did:key:z6MkA",
        idempotency_key="state-1",
        request_hash="hash-state",
    )
    store.transition(job.job_id, "processing")
    with pytest.raises(ValueError, match="invalid AgentLink transition"):
        store.transition(job.job_id, "accepted")


def test_agent_link_point_read_does_not_take_global_process_lock(
    tmp_path, monkeypatch,
):
    store = AgentLinkStore(tmp_path)
    job = store.create(agent_id="a", agent_did="did:key:z6MkA")

    def forbidden_process_lock():
        raise AssertionError("point reads must not take the global process lock")

    monkeypatch.setattr(store, "_process_lock", forbidden_process_lock)
    assert store.get(job.job_id) == job


def test_agent_link_point_read_observes_another_store_write(tmp_path):
    reader = AgentLinkStore(tmp_path)
    writer = AgentLinkStore(tmp_path)
    job = reader.create(agent_id="a", agent_did="did:key:z6MkA")

    writer.transition(job.job_id, "processing")

    observed = reader.get(job.job_id)
    assert observed is not None
    assert observed.state == "processing"


def test_agent_link_marks_worker_exception_as_failed(tmp_path):
    manager = AgentLinkManager(AgentLinkStore(tmp_path))
    try:
        job = manager.submit(
            agent_id="a", agent_did="did:key:z6MkA",
            worker=lambda: (_ for _ in ()).throw(RuntimeError("provider down")),
        )
        failed = _wait_for(manager, job.job_id, "failed")
        assert failed is not None
        assert "provider down" in failed.error
    finally:
        manager.close()


def test_agent_link_cancelled_queued_job_never_executes(tmp_path):
    manager = AgentLinkManager(AgentLinkStore(tmp_path))
    calls = []
    try:
        job = manager.submit(
            agent_id="a",
            agent_did="did:key:z6MkA",
            autostart=False,
            worker=lambda: (calls.append(1) or {"response": "must-not-run"}),
        )
        cancelled = manager.cancel(job.job_id)
        assert cancelled.state == "cancelled"
        assert cancelled.cancel_requested_at
        assert cancelled.provider_cancel_status == "requested"
        manager.start(job.agent_did)
        time.sleep(0.05)
        assert calls == []
        assert AgentLinkStore(tmp_path).get(job.job_id).state == "cancelled"
    finally:
        manager.close()


def test_agent_link_cancelled_running_job_cannot_publish_late_result(tmp_path):
    manager = AgentLinkManager(AgentLinkStore(tmp_path))
    started = threading.Event()
    release = threading.Event()

    def worker():
        started.set()
        assert release.wait(2.0)
        return {"response": "late result", "receipt_id": "late-receipt"}

    try:
        job = manager.submit(
            agent_id="a", agent_did="did:key:z6MkA", worker=worker,
        )
        assert started.wait(1.0)
        assert manager.cancel(job.job_id).state == "cancelled"
        release.set()
        time.sleep(0.05)
        final = manager.get(job.job_id)
        assert final is not None
        assert final.state == "cancelled"
        assert final.response == ""
        assert final.receipt_id == ""
        assert final.late_result_recorded_at
        assert final.late_result_receipt_id == "late-receipt"
        assert final.late_result_response_sha256
        evidence_path = (
            tmp_path / "agent_links" / "quarantine" / f"{job.job_id}.json"
        )
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        assert evidence["response"] == "late result"
        assert evidence["receipt_id"] == "late-receipt"
        assert evidence["response_sha256"] == final.late_result_response_sha256
        assert manager.cancel(job.job_id).state == "cancelled"
    finally:
        release.set()
        manager.close()


def test_agent_link_quarantines_failure_raised_after_cancellation(tmp_path):
    manager = AgentLinkManager(AgentLinkStore(tmp_path))
    started = threading.Event()
    release = threading.Event()

    def worker():
        started.set()
        assert release.wait(2.0)
        raise RuntimeError("late provider failure")

    try:
        job = manager.submit(
            agent_id="a", agent_did="did:key:z6MkA", worker=worker,
        )
        assert started.wait(1.0)
        manager.cancel(job.job_id)
        release.set()
        deadline = time.monotonic() + 2.0
        final = manager.get(job.job_id)
        while final is not None and not final.late_result_recorded_at:
            assert time.monotonic() < deadline
            time.sleep(0.01)
            final = manager.get(job.job_id)

        assert final is not None
        assert final.state == "cancelled"
        assert final.late_result_error == "provider_error"
        evidence = json.loads(
            (tmp_path / "agent_links" / "quarantine" / f"{job.job_id}.json")
            .read_text(encoding="utf-8")
        )
        assert "late provider failure" in evidence["error"]
    finally:
        release.set()
        manager.close()


def test_agent_link_late_result_hash_covers_full_response_before_truncation(tmp_path):
    store = AgentLinkStore(tmp_path)
    job = store.create(agent_id="a", agent_did="did:key:z6MkA")
    store.transition(job.job_id, "cancelled")
    raw_response = "x" * 100_001

    recorded = store.record_cancelled_late_result(
        job.job_id,
        {"response": raw_response, "receipt_id": "late-large-receipt"},
    )

    evidence = json.loads(
        (tmp_path / "agent_links" / "quarantine" / f"{job.job_id}.json")
        .read_text(encoding="utf-8")
    )
    assert len(evidence["response"].encode("utf-8")) == 100_000
    assert evidence["response_truncated"] is True
    assert recorded.late_result_truncated is True
    assert recorded.late_result_response_sha256 == hashlib.sha256(
        raw_response.encode("utf-8")
    ).hexdigest()


def test_agent_link_loads_legacy_job_without_cancellation_metadata(tmp_path):
    store = AgentLinkStore(tmp_path)
    job = store.create(agent_id="legacy", agent_did="did:key:z6MkLegacy")
    store.transition(job.job_id, "processing")
    store.transition(
        job.job_id,
        "completed",
        response="legacy result",
        receipt_id="legacy-receipt",
    )
    path = tmp_path / "agent_links" / "jobs" / f"{job.job_id}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    for key in tuple(data):
        if key.startswith("provider_cancel_") or key.startswith("late_result_"):
            data.pop(key)
    data.pop("cancel_requested_at", None)
    path.write_text(json.dumps(data), encoding="utf-8")

    loaded = AgentLinkStore(tmp_path).get(job.job_id)

    assert loaded is not None
    assert loaded.state == "completed"
    assert loaded.response == "legacy result"
    assert loaded.provider_cancel_status == ""
    assert loaded.late_result_recorded_at == ""


def test_agent_link_cancel_normalizes_terminal_transition_race(tmp_path, monkeypatch):
    manager = AgentLinkManager(AgentLinkStore(tmp_path))
    job = manager.submit(
        agent_id="a",
        agent_did="did:key:z6MkA",
        autostart=False,
        worker=lambda: {"response": "unused"},
    )
    original_transition = manager.store.transition

    def racing_transition(job_id, state, **fields):
        if state == "cancelled":
            original_transition(job_id, "processing")
            original_transition(
                job_id,
                "completed",
                response="won the race",
                receipt_id="receipt-race",
            )
        return original_transition(job_id, state, **fields)

    monkeypatch.setattr(manager.store, "transition", racing_transition)
    try:
        with pytest.raises(AgentLinkConflict, match="already terminal: completed"):
            manager.cancel(job.job_id)
    finally:
        monkeypatch.setattr(manager.store, "transition", original_transition)
        manager.close()


def test_agent_link_close_preserves_terminal_state_won_by_worker_race(
    tmp_path, monkeypatch,
):
    manager = AgentLinkManager(AgentLinkStore(tmp_path))
    job = manager.submit(
        agent_id="a",
        agent_did="did:key:z6MkA",
        autostart=False,
        worker=lambda: {"response": "unused"},
    )
    original_transition = manager.store.transition
    raced = False

    def racing_transition(job_id, state, **fields):
        nonlocal raced
        if state == "delivery_unknown" and not raced:
            raced = True
            original_transition(job_id, "processing")
            original_transition(
                job_id,
                "completed",
                response="worker completed during shutdown",
                receipt_id="receipt-shutdown-race",
            )
        return original_transition(job_id, state, **fields)

    monkeypatch.setattr(manager.store, "transition", racing_transition)
    manager.close()

    final = manager.get(job.job_id)
    assert final is not None
    assert final.state == "completed"
    assert final.response == "worker completed during shutdown"


def test_agent_link_persists_failure_reason_for_false_worker_result(tmp_path):
    manager = AgentLinkManager(AgentLinkStore(tmp_path))
    try:
        job = manager.submit(
            agent_id="a",
            agent_did="did:key:z6MkA",
            worker=lambda: False,
        )
        failed = _wait_for(manager, job.job_id, "failed")
        assert failed is not None
        assert "without a reason" in failed.error
    finally:
        manager.close()


def test_agent_link_marks_response_without_receipt_unverified(tmp_path):
    manager = AgentLinkManager(AgentLinkStore(tmp_path))
    try:
        job = manager.submit(
            agent_id="a",
            agent_did="did:key:z6MkA",
            worker=lambda: {"response": "text without signed evidence"},
        )
        unverified = _wait_for(manager, job.job_id, "completed_unverified")
        assert unverified is not None
        assert unverified.state == "completed_unverified"
        assert unverified.receipt_id == ""
    finally:
        manager.close()


def test_agent_link_bounds_response_and_persists_truncation_flag(tmp_path):
    oversized = "界" * 40_000
    manager = AgentLinkManager(AgentLinkStore(tmp_path))
    try:
        job = manager.submit(
            agent_id="a",
            agent_did="did:key:z6MkA",
            worker=lambda: {"response": oversized},
        )
        completed = _wait_for(manager, job.job_id, "completed_unverified")
        assert completed is not None
        assert len(completed.response.encode("utf-8")) <= 100_000
        assert completed.response_truncated is True
        persisted = AgentLinkStore(tmp_path).get(job.job_id)
        assert persisted is not None
        assert persisted.response == completed.response
        assert persisted.response_truncated is True
    finally:
        manager.close()


def test_agent_link_close_marks_deferred_jobs_unknown(tmp_path):
    manager = AgentLinkManager(AgentLinkStore(tmp_path))
    job = manager.submit(
        agent_id="a",
        agent_did="did:key:z6MkA",
        idempotency_key="shutdown",
        request_hash="shutdown-hash",
        autostart=False,
        worker=lambda: {"response": "must-not-run"},
    )
    manager.close()
    recovered = AgentLinkStore(tmp_path).get(job.job_id)
    assert recovered is not None
    assert recovered.state == "delivery_unknown"
    assert "shut down" in recovered.error


def test_agent_link_history_has_a_hard_bound(tmp_path):
    manager = AgentLinkManager(AgentLinkStore(tmp_path), max_jobs=1)
    try:
        manager.submit(
            agent_id="a",
            agent_did="did:key:z6MkA",
            idempotency_key="bounded-1",
            request_hash="bounded-hash-1",
            worker=lambda: {"response": "ok"},
        )
        with pytest.raises(AgentLinkStoreFull):
            manager.submit(
                agent_id="a",
                agent_did="did:key:z6MkA",
                idempotency_key="bounded-2",
                request_hash="bounded-hash-2",
                worker=lambda: {"response": "no"},
            )
    finally:
        manager.close()


def test_agent_link_idempotency_is_atomic_across_processes(tmp_path):
    code = (
        "import sys, time; "
        "import nth_dao.web.agent_link as al; "
        "from pathlib import Path; "
        "real = al.atomic_write_json; "
        "al.atomic_write_json = lambda *a, **k: (time.sleep(0.05), real(*a, **k))[1]; "
        "job = al.AgentLinkStore(Path(sys.argv[1])).create("
        "agent_id='a', agent_did='did:key:z', idempotency_key='same', "
        "request_hash='same-hash'); "
        "print(job.job_id, flush=True)"
    )
    env = os.environ.copy()
    root = str(Path(__file__).resolve().parents[1])
    env["PYTHONPATH"] = os.pathsep.join(
        item for item in (root, env.get("PYTHONPATH", "")) if item
    )
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(tmp_path)],
            cwd=root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(6)
    ]
    outputs = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, stderr
        outputs.append(stdout.strip())
    assert len(set(outputs)) == 1


def test_agent_link_rejects_inbox_overflow(tmp_path):
    manager = AgentLinkManager(AgentLinkStore(tmp_path), max_pending_per_agent=1)
    release = threading.Event()
    started = threading.Event()
    try:
        def blocked():
            started.set()
            release.wait(2.0)
            return {"response": "ok"}

        first = manager.submit(
            agent_id="a", agent_did="did:key:z6MkA", worker=blocked,
        )
        assert started.wait(1.0)
        second = manager.submit(
            agent_id="a", agent_did="did:key:z6MkA",
            worker=lambda: {"response": "queued"},
        )
        assert second.state == "accepted"
        with pytest.raises(AgentLinkBusy):
            manager.submit(
                agent_id="a", agent_did="did:key:z6MkA",
                worker=lambda: {"response": "overflow"},
            )
        release.set()
        assert _wait_for(manager, first.job_id, "completed_unverified") is not None
    finally:
        release.set()
        manager.close()


def test_agent_link_marks_restart_outcome_as_unknown(tmp_path):
    first = AgentLinkStore(tmp_path)
    job = first.create(
        agent_id="a",
        agent_did="did:key:z6MkA",
        idempotency_key="restart-1",
        channel_id="general",
        request_message_id="message-1",
    )

    restarted = AgentLinkStore(tmp_path)
    recovered = restarted.get(job.job_id)

    assert recovered is not None
    assert recovered.state == "delivery_unknown"
    assert "outcome is unknown" in recovered.error
    assert recovered.channel_id == "general"
    assert recovered.request_message_id == "message-1"
    assert [item.job_id for item in restarted.all()] == [job.job_id]


def test_agent_link_reconcile_requires_unknown_state_and_persists(tmp_path):
    store = AgentLinkStore(tmp_path)
    job = store.create(
        agent_id="a",
        agent_did="did:key:z6MkA",
        idempotency_key="reconcile-1",
        prompt_sha256="prompt-hash",
    )
    with pytest.raises(ValueError, match="uncertain"):
        store.reconcile_completed(
            job.job_id,
            response="answer",
            receipt_id="receipt-1",
        )

    restarted = AgentLinkStore(tmp_path)
    unknown = restarted.get(job.job_id)
    assert unknown is not None
    assert unknown.state == "delivery_unknown"
    completed = restarted.reconcile_completed(
        job.job_id,
        response="answer",
        receipt_id="receipt-1",
    )
    assert completed.state == "completed"
    assert completed.prompt_sha256 == "prompt-hash"
    assert AgentLinkStore(tmp_path).get(job.job_id).response == "answer"

    with pytest.raises(AgentLinkConflict, match="already completed"):
        restarted.reconcile_completed(
            job.job_id,
            response="different answer",
            receipt_id="receipt-2",
        )
    assert restarted.reconcile_completed(
        job.job_id,
        response="answer",
        receipt_id="receipt-1",
    ).state == "completed"


def test_agent_link_reconcile_rejects_legacy_job_without_prompt_hash(tmp_path):
    store = AgentLinkStore(tmp_path)
    job = store.create(
        agent_id="a",
        agent_did="did:key:z6MkA",
        idempotency_key="legacy",
    )
    restarted = AgentLinkStore(tmp_path)
    assert restarted.get(job.job_id).state == "delivery_unknown"
    # Legacy records cannot be reconciled because they lack the evidence
    # binding required by the recovery protocol.
    with pytest.raises(ValueError, match="no prompt hash"):
        restarted.reconcile_completed(
            job.job_id,
            response="answer",
            receipt_id="receipt-legacy",
        )
