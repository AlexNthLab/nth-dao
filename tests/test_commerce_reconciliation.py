from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from nth_dao.commerce.outbox import (
    OUTBOX_ERROR_DISPATCH_CONTRACT,
    OUTBOX_ERROR_RUNTIME,
    CommerceOutbox,
    sign_envelope,
)
from nth_dao.commerce import CommerceReconciler, ReconcilerConfig
from nth_dao.identity import AgentIdentity
from nth_dao.web import create_app
from fastapi.testclient import TestClient


def _queued(tmp_path, suffix="one"):
    source = AgentIdentity.generate()
    target = AgentIdentity.generate()
    envelope = sign_envelope(
        source,
        target_did=target.as_did(),
        payload={"order": {"id": f"order-{suffix}"}},
        created_at_ms=1_900_000_000_000,
    )
    outbox = CommerceOutbox(tmp_path)
    outbox.enqueue(envelope, target_url="https://seller.example")
    return outbox, envelope


def test_reconciler_persists_backoff_and_resumes_after_restart(tmp_path):
    outbox, envelope = _queued(tmp_path)

    def fail(record, retry_after_ms):
        failed = outbox.record_attempt(
            envelope.message_id,
            error="offline",
            lease_id=record.lease_id,
            retry_after_ms=retry_after_ms,
            now_ms_override=1_900_000_001_000,
        )
        return {"status": failed.status, "error": failed.last_error}

    config = ReconcilerConfig(
        base_backoff_ms=2_000,
        max_backoff_ms=8_000,
        jitter_ratio=0,
    )
    first = CommerceReconciler(outbox, fail, config=config)
    assert first.run_once(now_ms_override=1_900_000_001_000) == {
        "busy": False, "claimed": 1, "acknowledged": 0, "failed": 1,
    }
    assert CommerceReconciler(outbox, fail, config=config).run_once(
        now_ms_override=1_900_000_002_999,
    )["claimed"] == 0

    def acknowledge(record, _retry_after_ms):
        acked = outbox.record_attempt(
            envelope.message_id,
            acknowledged_at_ms=1_900_000_003_000,
            lease_id=record.lease_id,
            now_ms_override=1_900_000_003_000,
        )
        return {"status": acked.status}

    restarted = CommerceReconciler(outbox, acknowledge, config=config)
    result = restarted.run_once(now_ms_override=1_900_000_003_000)
    assert result == {"busy": False, "claimed": 1, "acknowledged": 1, "failed": 0}
    assert outbox.get(envelope.message_id).status == "acknowledged"


def test_reconciler_dispatch_exception_releases_lease_with_backoff(tmp_path):
    outbox, envelope = _queued(tmp_path, "exception")

    def broken(_record, _retry_after_ms):
        raise RuntimeError("adapter crashed")

    reconciler = CommerceReconciler(
        outbox,
        broken,
        config=ReconcilerConfig(base_backoff_ms=4_000, jitter_ratio=0),
    )
    result = reconciler.run_once(now_ms_override=1_900_000_001_000)
    stored = outbox.get(envelope.message_id)
    assert result["failed"] == 1
    assert stored.status == "pending"
    assert stored.next_attempt_at_ms == 1_900_000_005_000
    assert stored.last_error == OUTBOX_ERROR_RUNTIME
    assert reconciler.status()["last_error"] == OUTBOX_ERROR_RUNTIME

    idle = reconciler.run_once(now_ms_override=1_900_000_002_000)
    assert idle["claimed"] == 0
    assert reconciler.status()["last_error"] == OUTBOX_ERROR_RUNTIME


def test_reconciler_exposes_storage_cycle_failure(tmp_path, monkeypatch):
    outbox, _envelope = _queued(tmp_path, "storage-cycle")
    reconciler = CommerceReconciler(outbox, lambda *_args: {})

    def fail_scan(**_kwargs):
        raise OSError("outbox directory unavailable")

    monkeypatch.setattr(outbox, "pending", fail_scan)
    with pytest.raises(OSError, match="directory unavailable"):
        reconciler.run_once(now_ms_override=1_900_000_001_000)
    assert reconciler.status()["last_error"] == OUTBOX_ERROR_RUNTIME


def test_reconciler_finalizes_adapter_that_returns_without_releasing_lease(tmp_path):
    outbox, envelope = _queued(tmp_path, "adapter-contract")
    reconciler = CommerceReconciler(
        outbox,
        lambda _record, _retry_after_ms: {"status": "pending"},
        config=ReconcilerConfig(base_backoff_ms=3_000, jitter_ratio=0),
    )

    result = reconciler.run_once(now_ms_override=1_900_000_001_000)
    stored = outbox.get(envelope.message_id)
    assert result["failed"] == 1
    assert stored.status == "pending"
    assert stored.attempts == 1
    assert stored.next_attempt_at_ms == 1_900_000_004_000
    assert stored.last_error == OUTBOX_ERROR_DISPATCH_CONTRACT


def test_reconciler_uses_durable_ack_when_adapter_raises_after_commit(tmp_path):
    outbox, envelope = _queued(tmp_path, "ack-then-raise")

    def acknowledge_then_raise(record, _retry_after_ms):
        outbox.record_attempt(
            envelope.message_id,
            acknowledged_at_ms=1_900_000_002_000,
            lease_id=record.lease_id,
        )
        raise RuntimeError("response serialization failed after durable ack")

    reconciler = CommerceReconciler(outbox, acknowledge_then_raise)
    result = reconciler.run_once(
        now_ms_override=1_900_000_001_000,
    )
    assert result == {
        "busy": False, "claimed": 1, "acknowledged": 1, "failed": 0,
    }
    assert outbox.get(envelope.message_id).status == "acknowledged"
    status = reconciler.status()
    assert status["last_error"] == ""
    assert status["last_success_at_ms"] == 1_900_000_001_000


def test_retry_jitter_is_stable_bounded_and_message_specific(tmp_path):
    outbox, _envelope = _queued(tmp_path, "jitter")
    reconciler = CommerceReconciler(
        outbox,
        lambda *_args: {},
        config=ReconcilerConfig(
            base_backoff_ms=10_000,
            max_backoff_ms=60_000,
            jitter_ratio=0.2,
        ),
    )
    first_delay = reconciler.retry_delay_ms(0, "message-a")
    second_delay = reconciler.retry_delay_ms(0, "message-b")

    assert 10_000 <= first_delay <= 12_000
    assert first_delay == reconciler.retry_delay_ms(0, "message-a")
    assert second_delay == reconciler.retry_delay_ms(0, "message-b")
    assert first_delay != second_delay
    assert reconciler.retry_delay_ms(20, "message-a") == 60_000


def test_reconciler_archives_old_ack_only_when_retention_is_enabled(tmp_path):
    outbox, envelope = _queued(tmp_path, "retention")
    claimed = outbox.claim(
        envelope.message_id,
        now_ms_override=1_900_000_001_000,
    )
    outbox.record_attempt(
        envelope.message_id,
        acknowledged_at_ms=1_900_000_002_000,
        lease_id=claimed.lease_id,
    )
    now_ms_value = 1_900_000_002_000 + 86_400_000 + 1

    CommerceReconciler(outbox, lambda *_args: {}).run_once(
        now_ms_override=now_ms_value,
    )
    assert outbox.get(envelope.message_id) is not None

    CommerceReconciler(
        outbox,
        lambda *_args: {},
        config=ReconcilerConfig(archive_after_s=86_400),
    ).run_once(now_ms_override=now_ms_value)
    assert outbox.get(envelope.message_id).status == "acknowledged"
    assert not outbox._path(envelope.message_id).exists()
    assert (outbox.archive_root / f"{envelope.message_id[7:]}.json").exists()


def test_two_reconcilers_cannot_dispatch_the_same_lease(tmp_path):
    outbox, envelope = _queued(tmp_path, "concurrent")
    calls = []

    def acknowledge(record, _retry_after_ms):
        calls.append(record.lease_id)
        acked = outbox.record_attempt(
            envelope.message_id,
            acknowledged_at_ms=1_900_000_002_000,
            lease_id=record.lease_id,
        )
        return {"status": acked.status}

    workers = [CommerceReconciler(outbox, acknowledge) for _ in range(2)]
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(
            lambda worker: worker.run_once(now_ms_override=1_900_000_001_000),
            workers,
        ))
    assert sum(result["claimed"] for result in results) == 1
    assert len(calls) == 1
    assert outbox.get(envelope.message_id).status == "acknowledged"


def test_reconciler_does_not_preclaim_later_batch_records(tmp_path):
    outbox, first = _queued(tmp_path, "batch-first")
    _same_root, second = _queued(tmp_path, "batch-second")
    message_ids = {first.message_id, second.message_id}
    observed_other_states = []

    def acknowledge(record, _retry_after_ms):
        current_id = record.envelope["message_id"]
        other_id = (message_ids - {current_id}).pop()
        observed_other_states.append(outbox.get(other_id).status)
        acked = outbox.record_attempt(
            current_id,
            acknowledged_at_ms=1_900_000_002_000,
            lease_id=record.lease_id,
        )
        return {"status": acked.status}

    result = CommerceReconciler(
        outbox,
        acknowledge,
        config=ReconcilerConfig(batch_limit=2),
    ).run_once(now_ms_override=1_900_000_001_000)

    assert result["claimed"] == 2
    assert observed_other_states[0] == "pending"
    assert all(outbox.get(message_id).status == "acknowledged" for message_id in message_ids)


def test_reconciler_scans_pending_records_once_per_cycle(tmp_path, monkeypatch):
    outbox, first = _queued(tmp_path, "single-scan-first")
    _same_root, second = _queued(tmp_path, "single-scan-second")
    real_pending = outbox.pending
    scan_count = 0

    def counted_pending(*, limit):
        nonlocal scan_count
        scan_count += 1
        return real_pending(limit=limit)

    monkeypatch.setattr(outbox, "pending", counted_pending)

    def acknowledge(record, _retry_after_ms):
        stored = outbox.record_attempt(
            record.envelope["message_id"],
            acknowledged_at_ms=1_900_000_002_000,
            lease_id=record.lease_id,
        )
        return {"status": stored.status}

    result = CommerceReconciler(
        outbox,
        acknowledge,
        config=ReconcilerConfig(batch_limit=2),
    ).run_once(now_ms_override=1_900_000_001_000)
    assert result["acknowledged"] == 2
    assert scan_count == 1
    assert outbox.get(first.message_id).status == "acknowledged"
    assert outbox.get(second.message_id).status == "acknowledged"


def test_reconciler_thread_lifecycle_is_idempotent(tmp_path):
    outbox, _envelope = _queued(tmp_path, "lifecycle")

    def fail(record, retry_after_ms):
        stored = outbox.record_attempt(
            record.envelope["message_id"],
            error="offline",
            lease_id=record.lease_id,
            retry_after_ms=retry_after_ms,
        )
        return {"status": stored.status, "error": stored.last_error}

    worker = CommerceReconciler(
        outbox,
        fail,
        config=ReconcilerConfig(poll_interval_s=0.1),
    )
    assert worker.start() is True
    assert worker.start() is False
    assert worker.stop(timeout_s=2.0) is True
    assert worker.stop(timeout_s=2.0) is True
    assert worker.status()["running"] is False


def test_reconciler_worker_log_does_not_expose_exception_details(
    tmp_path,
    monkeypatch,
    caplog,
):
    outbox, _envelope = _queued(tmp_path, "redacted-worker-log")
    reconciler = CommerceReconciler(outbox, lambda *_args: {})
    secret = "provider-token=DO-NOT-LOG"

    def fail_cycle():
        reconciler._stop_event.set()
        raise RuntimeError(secret)

    monkeypatch.setattr(reconciler, "run_once", fail_cycle)
    with caplog.at_level("ERROR"):
        reconciler._run()

    assert "RuntimeError" in caplog.text
    assert secret not in caplog.text
    assert "Traceback" not in caplog.text


def test_web_lifespan_owns_reconciler_and_exposes_status(tmp_path):
    app = create_app(tmp_path, require_console_auth=False)
    worker = app.state.nth.commerce_reconciler
    assert worker.status()["running"] is False

    with TestClient(app) as client:
        response = client.get("/api/v2/commerce/reconciliation")
        assert response.status_code == 200
        assert response.json()["running"] is True
        assert response.json()["pending"] == 0
        assert response.json()["blocked"] == 0
        assert response.json()["pending_truncated"] is False
        assert response.json()["blocked_truncated"] is False

    assert worker.status()["running"] is False


def test_web_reconciler_exposes_configured_orphan_retention(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("NTH_COMMERCE_ORPHAN_AFTER_S", "86400")
    app = create_app(tmp_path, require_console_auth=False)

    response = TestClient(app).get("/api/v2/commerce/reconciliation")

    assert response.status_code == 200
    assert response.json()["config"]["orphan_after_s"] == 86_400


def test_reconciliation_status_marks_capped_counts_as_truncated(tmp_path, monkeypatch):
    app = create_app(tmp_path, require_console_auth=False)
    row = SimpleNamespace(next_attempt_at_ms=0)
    monkeypatch.setattr(
        app.state.nth.commerce_outbox,
        "pending",
        lambda *, limit: [row] * limit,
    )
    monkeypatch.setattr(
        app.state.nth.commerce_outbox,
        "blocked",
        lambda *, limit: [row] * limit,
    )

    response = TestClient(app).get("/api/v2/commerce/reconciliation")
    assert response.status_code == 200
    assert response.json()["pending"] == 1_000
    assert response.json()["blocked"] == 1_000
    assert response.json()["pending_truncated"] is True
    assert response.json()["blocked_truncated"] is True
