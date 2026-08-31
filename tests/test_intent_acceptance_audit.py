"""Explicit, non-authoritative Intent acceptance audit and crash recovery."""

from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
import hashlib
import inspect
import json
import multiprocessing as mp
import os
from pathlib import Path
import sqlite3
import sys
import threading
import traceback

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.plugins.intent_acceptance import IntentAcceptanceRecord, IntentAcceptanceStore, IntentAcceptanceStoreError
from nth_dao.plugins.intent_acceptance_audit import (
    EVENT_INTENT_ACCEPTED, INTENT_ACCEPTANCE_ANCHOR_SCHEMA,
    IntentAcceptanceAuditError, IntentAcceptanceSpineBridge, _anchor_payload,
    validate_intent_acceptance_anchor, verify_intent_acceptance_anchor,
)
from nth_dao.plugins.intent_envelope import IntentAcceptanceContext, sign_intent_envelope
from nth_dao.plugins.schema import validate_schema
from nth_dao.spine import GENESIS_PREV, SignedEventLog, SpineEvent, sign_event
from tools.generate_intent_envelope_vectors import _test_identity


@pytest.fixture
def journal(tmp_path):
    pytest.importorskip("nacl.signing")
    path = Path(__file__).parents[1] / "nth_dao/plugins/vectors/intent-envelope-wire-cases-v1.json"
    cases = json.loads(path.read_text(encoding="utf-8"))["positive_cases"][:2]
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)
    contexts = [IntentAcceptanceContext(**(case["expected"] | {
        "allowed_solver_classes": tuple(case["expected"]["allowed_solver_classes"]),
    })) for case in cases]
    store.accept(cases[0]["envelope"], resolve_context=lambda _: contexts[0])
    audience = _test_identity("intent-envelope-audience-v1")
    return store, cases, contexts, audience


def _signed(payload, audience, **overrides):
    args = dict(seq=0, prev_hash=GENESIS_PREV, event_type=EVENT_INTENT_ACCEPTED,
                payload=payload, identity=audience, ts_ms=1001)
    return sign_event(**(args | overrides))


def test_anchor_is_hash_only_and_does_not_expose_source(journal):
    store, cases, _contexts, audience = journal
    record = store.history()[0]
    payload = _anchor_payload(record)
    validate_schema(INTENT_ACCEPTANCE_ANCHOR_SCHEMA)
    verified = verify_intent_acceptance_anchor(_signed(payload, audience), expected_audience_did=audience.as_did())
    assert verified == payload
    assert verified["observation_digest"] == record.audit_digest
    assert not {"draft_json", "context_json", "nonce", "scope_id", "signer_did"} & set(payload)
    assert cases[0]["envelope"]["draft_json"] not in canonical_json(payload).decode()
    verified["authority"] = "changed"
    assert payload["authority"] == "none"


@pytest.mark.parametrize("updates", [
    {"commit_authority": 0}, {"executable": True}, {"authority": "owner"},
    {"unknown": "ignored?"}, {"format": "unknown"}, {"audience_did": "did:web:example.org"},
    {"accepted_at_ms": True}, {"accepted_at_ms": 2**53},
    {"acceptance_sequence": 0}, {"acceptance_sequence": 2},
    {"envelope_digest": "sha256:" + "F" * 64}, {"context_digest": "sha256:" + "1" * 64},
    {"observation_digest": "sha256:" + "0" * 64}, {"previous_observation_digest": []},
])
def test_malformed_or_elevated_anchor_is_rejected_even_when_signed(journal, updates):
    store, _cases, _contexts, audience = journal
    payload = _anchor_payload(store.history()[0]) | updates
    with pytest.raises(IntentAcceptanceAuditError):
        verify_intent_acceptance_anchor(_signed(payload, audience), expected_audience_did=audience.as_did())


def test_other_signer_tampering_and_wrong_event_type_fail(journal):
    store, _cases, _contexts, audience = journal
    payload = _anchor_payload(store.history()[0])
    stranger = _test_identity("anchor-stranger-v1")
    for event in (
        _signed(payload, stranger), _signed(payload, audience, event_type="trade.accepted"),
        _signed(payload, audience, ts_ms=999),
        replace(_signed(payload, audience), sig="A" * 86),
    ):
        with pytest.raises(IntentAcceptanceAuditError):
            verify_intent_acceptance_anchor(event, expected_audience_did=audience.as_did())
    with pytest.raises(IntentAcceptanceAuditError):
        verify_intent_acceptance_anchor(_signed(payload, audience), expected_audience_did=stranger.as_did())


@pytest.mark.parametrize("changed", ["signer", "type", "time", "sequence"])
def test_anchor_checks_the_same_snapshot_that_is_verified(journal, monkeypatch, changed):
    store, _cases, _contexts, audience = journal
    payload = _anchor_payload(store.history()[0])
    shared = _signed(payload, audience)
    overrides = {
        "signer": {"identity": _test_identity("anchor-stranger-v1")},
        "type": {"event_type": "trade.accepted"},
        "time": {"ts_ms": 999},
        "sequence": {"seq": 2**53},
    }[changed]
    replacement = _signed(payload, audience, **overrides).to_dict()
    ready, changed_event = threading.Event(), threading.Event()
    original = SpineEvent.to_dict

    def capture(event):
        if event is shared:
            ready.set()
            assert changed_event.wait(5)
        return original(event)

    def writer():
        assert ready.wait(5)
        shared.__dict__.update(replacement)
        changed_event.set()

    monkeypatch.setattr(SpineEvent, "to_dict", capture)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(writer)
        try:
            with pytest.raises(IntentAcceptanceAuditError):
                verify_intent_acceptance_anchor(shared, expected_audience_did=audience.as_did())
        finally:
            ready.set()
            future.result(timeout=5)


@pytest.mark.parametrize("change", ["missing", "extra"])
def test_anchor_field_set_is_checked_on_the_captured_payload(journal, change):
    payload = _anchor_payload(journal[0].history()[0])
    ready, changed = threading.Event(), threading.Event()
    code = validate_intent_acceptance_anchor.__code__
    lines, start = inspect.getsourcelines(validate_intent_acceptance_anchor)
    capture_line = start + next(i for i, line in enumerate(lines) if "payload = dict(value)" in line)

    def writer():
        assert ready.wait(5)
        if change == "missing":
            payload.pop("authority")
        else:
            payload["unexpected"] = "field"
        changed.set()

    def schedule(frame, event, arg):
        if frame.f_code is code and event == "line" and frame.f_lineno == capture_line:
            ready.set()
            assert changed.wait(5)
        return schedule

    previous_trace = sys.gettrace()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(writer)
        try:
            sys.settrace(schedule)
            with pytest.raises(IntentAcceptanceAuditError):
                validate_intent_acceptance_anchor(payload)
        finally:
            sys.settrace(previous_trace)
            ready.set()
            future.result(timeout=5)


def test_float_time_is_rejected_before_signing_and_by_payload_validator(journal):
    store, _cases, _contexts, audience = journal
    payload = _anchor_payload(store.history()[0]) | {"accepted_at_ms": 1000.0}
    with pytest.raises(IntentAcceptanceAuditError):
        validate_intent_acceptance_anchor(payload)
    with pytest.raises(ValueError, match="canonical JSON"):
        _signed(payload, audience)


def test_protocol_schema_mutation_does_not_disable_runtime_validation(journal):
    store, _cases, _contexts, _audience = journal
    snapshot = deepcopy(INTENT_ACCEPTANCE_ANCHOR_SCHEMA)
    try:
        INTENT_ACCEPTANCE_ANCHOR_SCHEMA.clear()
        with pytest.raises(IntentAcceptanceAuditError):
            validate_intent_acceptance_anchor(_anchor_payload(store.history()[0]) | {"executable": True})
    finally:
        INTENT_ACCEPTANCE_ANCHOR_SCHEMA.update(snapshot)


def test_zero_acceptance_time_can_be_anchored(journal):
    store, _cases, _contexts, audience = journal
    record = replace(store.history()[0], accepted_at_ms=0)
    record = IntentAcceptanceRecord(**(asdict(record) | {
        "audit_digest": "sha256:" + hashlib.sha256(canonical_json(record.audit)).hexdigest(),
    }))
    payload = _anchor_payload(record)
    assert verify_intent_acceptance_anchor(_signed(payload, audience, ts_ms=1), expected_audience_did=audience.as_did())["accepted_at_ms"] == 0


def _bridge(journal):
    store, _cases, _contexts, audience = journal
    log = SignedEventLog(store.workspace / "audit.spine.jsonl", audience)
    return IntentAcceptanceSpineBridge(store, log, audience_did=audience.as_did())


def test_bridge_restarts_with_expired_envelope_and_no_duplicate(journal):
    store, cases, contexts, audience = journal
    store.accept(cases[1]["envelope"], resolve_context=lambda _: contexts[1])
    bridge = _bridge(journal)
    first = bridge.reconcile(limit=1)
    assert first.next_sequence == 1 and first.has_more and first.anchors[0].created
    second = bridge.reconcile(after_sequence=first.next_sequence, limit=1)
    assert second.next_sequence == 2 and not second.has_more and second.anchors[0].created
    # An expired request is still a recoverable historical observation, not fresh authority.
    expired = IntentAcceptanceStore(store.workspace, clock=lambda: 99999999)
    reopened = _bridge((expired, cases, contexts, audience))
    retry = reopened.reconcile()
    assert len(retry.anchors) == 2 and all(not anchor.created for anchor in retry.anchors)
    assert [a.event_id for a in retry.anchors] == [first.anchors[0].event_id, second.anchors[0].event_id]
    assert len(reopened.spine.verified_snapshot()) == 2
    assert reopened.reconcile(after_sequence=2).anchors == ()


def test_no_implicit_signing_or_acceptance(journal):
    store, _cases, _contexts, _audience = journal
    bridge = _bridge(journal)
    assert bridge.spine.verified_snapshot() == ()
    before = store.verify_history()
    assert bridge.reconcile().anchors[0].created
    assert store.verify_history() == before


@pytest.mark.parametrize("phase", ["before-write", "after-write", "second-record"])
def test_bridge_write_failure_retries_without_losing_or_duplicating(journal, monkeypatch, phase):
    store, cases, contexts, _audience = journal
    store.accept(cases[1]["envelope"], resolve_context=lambda _: contexts[1])
    bridge = _bridge(journal)
    original = bridge.spine._write_record_unlocked
    calls = []

    def failed(record):
        calls.append(record)
        if phase == "after-write":
            original(record)
        if phase != "second-record" or len(calls) == 2:
            raise OSError("PRIVATE-SPINE-DETAIL")
        original(record)

    monkeypatch.setattr(bridge.spine, "_write_record_unlocked", failed)
    with pytest.raises(IntentAcceptanceAuditError) as caught:
        bridge.reconcile()
    assert "PRIVATE-SPINE-DETAIL" not in "".join(traceback.format_exception(caught.value))
    assert store.verify_history()[0] == 2
    monkeypatch.setattr(bridge.spine, "_write_record_unlocked", original)
    recovered = _bridge(journal)
    assert len(recovered.reconcile().anchors) == 2
    assert all(not anchor.created for anchor in recovered.reconcile().anchors)
    assert len(recovered.spine.verified_snapshot()) == 2


def test_bridge_post_commit_readback_failure_is_sanitized_and_retryable(journal, monkeypatch):
    store, cases, contexts, _audience = journal
    store.accept(cases[1]["envelope"], resolve_context=lambda _: contexts[1])
    bridge = _bridge(journal)

    def unavailable(*_args):
        raise PermissionError("PRIVATE-READBACK-DETAIL")

    with monkeypatch.context() as patch:
        patch.setattr(bridge.spine, "_token_after_expected_append", unavailable)
        with pytest.raises(IntentAcceptanceAuditError, match="recover and retry") as caught:
            bridge.reconcile()
    assert "PRIVATE-READBACK-DETAIL" not in "".join(traceback.format_exception(caught.value))
    assert not bridge.spine._pending_path.exists()
    before = tuple(bridge.spine.read_all())
    assert len(before) == 2
    retry = _bridge(journal).reconcile()
    assert [anchor.event_id for anchor in retry.anchors] == [event.event_id for event in before]
    assert all(not anchor.created for anchor in retry.anchors)
    assert len(bridge.spine.verified_snapshot()) == 2


def test_bridge_does_not_hold_acceptance_lock_during_spine_io(journal, monkeypatch):
    store, _cases, _contexts, _audience = journal
    bridge = _bridge(journal)
    original = bridge.spine.append_unique_many

    def checked(*args, **kwargs):
        connection = sqlite3.connect(store.path, timeout=0.01, isolation_level=None)
        try:
            connection.execute("BEGIN EXCLUSIVE")
            connection.commit()
        finally:
            connection.close()
        return original(*args, **kwargs)

    monkeypatch.setattr(bridge.spine, "append_unique_many", checked)
    assert bridge.reconcile().anchors[0].created


def test_audience_mismatch_fails_before_any_append(journal, monkeypatch):
    store, _cases, _contexts, audience = journal
    stranger = _test_identity("anchor-stranger-v1")
    log = SignedEventLog(store.workspace / "other.spine.jsonl", stranger)
    with pytest.raises(IntentAcceptanceAuditError, match="signer"):
        IntentAcceptanceSpineBridge(store, log, audience_did=audience.as_did())
    bridge = IntentAcceptanceSpineBridge(store, log, audience_did=stranger.as_did())
    monkeypatch.setattr(log, "append_unique_many", lambda *_a, **_k: pytest.fail("wrong audience reached append"))
    with pytest.raises(IntentAcceptanceAuditError, match="different"):
        bridge.reconcile()
    assert log.verified_snapshot() == ()


@pytest.mark.parametrize("poison", ["duplicate", "wrong-signer", "conflicting"])
def test_poisoned_existing_anchor_fails_before_appending_other_rows(journal, poison):
    store, cases, contexts, audience = journal
    store.accept(cases[1]["envelope"], resolve_context=lambda _: contexts[1])
    bridge = _bridge(journal)
    payload = _anchor_payload(store.history()[0])
    if poison == "wrong-signer":
        stranger = SignedEventLog(store.workspace / "audit.spine.jsonl", _test_identity("anchor-stranger-v1"))
        stranger.append(EVENT_INTENT_ACCEPTED, payload, ts_ms=1001)
    else:
        bridge.spine.append(EVENT_INTENT_ACCEPTED, payload, ts_ms=1001)
        if poison == "duplicate":
            bridge.spine.append(EVENT_INTENT_ACCEPTED, payload, ts_ms=1002)
        else:
            # Matching envelope digest, with altered bytes, is a semantic conflict.
            payload["executable"] = True
            # Recreate the test log at a separate path; do not edit or delete runtime history.
            log = SignedEventLog(store.workspace / "conflict.spine.jsonl", audience)
            log.append(EVENT_INTENT_ACCEPTED, payload, ts_ms=1001)
            bridge = IntentAcceptanceSpineBridge(store, log, audience_did=audience.as_did())
    before = bridge.spine.verified_snapshot()
    reason = {"duplicate": "duplicate", "wrong-signer": "signer", "conflicting": "authority"}[poison]
    with pytest.raises(IntentAcceptanceAuditError, match=reason):
        bridge.reconcile()
    assert bridge.spine.verified_snapshot() == before


@pytest.mark.parametrize("poison", ["wrong-signer", "early-time", "numeric-coercion"])
def test_concurrent_poison_cannot_write_a_valid_suffix(journal, monkeypatch, poison):
    store, cases, contexts, audience = journal
    store.accept(cases[1]["envelope"], resolve_context=lambda _: contexts[1])
    bridge = _bridge(journal)
    identity = _test_identity("anchor-stranger-v1") if poison == "wrong-signer" else audience
    writer_log = SignedEventLog(store.workspace / "audit.spine.jsonl", identity)
    payload = _anchor_payload(store.history()[0])
    if poison == "numeric-coercion":
        payload["commit_authority"] = 0
    ready, written = threading.Event(), threading.Event()
    original = bridge.spine.append_unique_many

    def append(*args, **kwargs):
        ready.set()
        assert written.wait(5)
        return original(*args, **kwargs)

    def writer():
        assert ready.wait(5)
        writer_log.append(EVENT_INTENT_ACCEPTED, payload, ts_ms=999 if poison == "early-time" else 1001)
        written.set()

    monkeypatch.setattr(bridge.spine, "append_unique_many", append)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(writer)
        try:
            with pytest.raises(IntentAcceptanceAuditError):
                bridge.reconcile()
        finally:
            ready.set()
            future.result(timeout=5)
    assert len(bridge.spine.verified_snapshot()) == 1
    before = bridge.spine.storage_token()
    with pytest.raises(IntentAcceptanceAuditError):
        bridge.reconcile()
    assert bridge.spine.storage_token() == before


def test_corrupt_journal_is_not_signed(journal, monkeypatch):
    store, _cases, _contexts, _audience = journal
    bridge = _bridge(journal)
    connection = sqlite3.connect(store.path)
    try:
        trigger = connection.execute("SELECT sql FROM sqlite_master WHERE name='no_update'").fetchone()[0]
        connection.execute("DROP TRIGGER no_update")
        connection.execute("UPDATE acceptances SET audit_digest=?", ("sha256:" + "0" * 64,))
        connection.execute(trigger)
        connection.commit()
    finally:
        connection.close()
    monkeypatch.setattr(bridge.spine, "append_unique_many", lambda *_a, **_k: pytest.fail("corrupt journal reached append"))
    with pytest.raises(IntentAcceptanceStoreError):
        bridge.reconcile()


@pytest.mark.parametrize("kwargs", [{"limit": True}, {"limit": 101}, {"after_sequence": -1}, {"after_sequence": 1.0}])
def test_bad_pagination_never_reads_or_writes(journal, monkeypatch, kwargs):
    bridge = _bridge(journal)
    monkeypatch.setattr(bridge.store, "history", lambda **_k: pytest.fail("invalid paging reached store"))
    with pytest.raises(ValueError):
        bridge.reconcile(**kwargs)


def test_concurrent_independent_bridges_create_one_anchor(journal):
    bridges = [_bridge(journal), _bridge(journal)]
    barrier = threading.Barrier(2)

    def synchronize(bridge):
        barrier.wait(timeout=10)
        return bridge.reconcile()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(synchronize, bridges))
    assert sum(result.anchors[0].created for result in results) == 1
    assert results[0].anchors[0].event_id == results[1].anchors[0].event_id


def _exit_after_anchor(workspace):
    store = IntentAcceptanceStore(workspace)
    audience = _test_identity("intent-envelope-audience-v1")
    log = SignedEventLog(Path(workspace) / "audit.spine.jsonl", audience)
    bridge = IntentAcceptanceSpineBridge(store, log, audience_did=audience.as_did())
    original = log.append_unique_many

    def committed(*args, **kwargs):
        original(*args, **kwargs)
        os._exit(93)

    log.append_unique_many = committed
    bridge.reconcile()


def test_process_exit_after_append_before_response_is_recoverable(journal):
    store, _cases, _contexts, _audience = journal
    child = mp.get_context("spawn").Process(target=_exit_after_anchor, args=(str(store.workspace),))
    child.start()
    try:
        child.join(20)
        assert child.exitcode == 93
        bridge = _bridge(journal)
        result = bridge.reconcile()
        assert len(result.anchors) == 1 and not result.anchors[0].created
        assert len(bridge.spine.verified_snapshot()) == 1
    finally:
        if child.is_alive():
            child.terminate()
        child.join(5)


def _concurrent_bridge_worker(workspace, start, results):
    assert start.wait(10)
    audience = _test_identity("intent-envelope-audience-v1")
    store = IntentAcceptanceStore(workspace)
    log = SignedEventLog(Path(workspace) / "audit.spine.jsonl", audience)
    bridge = IntentAcceptanceSpineBridge(store, log, audience_did=audience.as_did())
    results.put(bridge.reconcile().anchors[0].created)


def test_separate_processes_anchor_exactly_once(journal):
    store, _cases, _contexts, _audience = journal
    context = mp.get_context("spawn")
    start, results = context.Event(), context.Queue()
    children = [context.Process(target=_concurrent_bridge_worker, args=(str(store.workspace), start, results)) for _ in range(3)]
    try:
        for child in children:
            child.start()
        start.set()
        for child in children:
            child.join(20)
            assert child.exitcode == 0
        assert sum(results.get(timeout=2) for _ in children) == 1
        assert len(_bridge(journal).spine.verified_snapshot()) == 1
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
            if child.pid is not None:
                child.join(5)
        results.close()
        results.join_thread()


def test_reverse_pages_keep_acceptance_and_spine_sequences_distinct(journal):
    store, cases, contexts, _audience = journal
    store.accept(cases[1]["envelope"], resolve_context=lambda _: contexts[1])
    bridge = _bridge(journal)
    later = bridge.reconcile(after_sequence=1).anchors[0]
    earlier = bridge.reconcile(limit=1).anchors[0]
    events = bridge.spine.verified_snapshot()
    assert [event.seq for event in events] == [0, 1]
    assert [event.payload["acceptance_sequence"] for event in events] == [2, 1]
    assert [event.event_id for event in events] == [later.event_id, earlier.event_id]
    assert all(not anchor.created for anchor in bridge.reconcile().anchors)


def test_mixed_audience_page_fails_before_signing_any_record(journal):
    store, cases, contexts, _audience = journal
    stranger = _test_identity("anchor-stranger-v1")
    body = {key: value for key, value in cases[0]["envelope"].items() if key != "signature"}
    body["audience_did"] = stranger.as_did()
    envelope = sign_intent_envelope(body, signer=_test_identity("intent-envelope-signer-v1"))
    store.accept(envelope, resolve_context=lambda _: replace(contexts[0], audience_did=stranger.as_did()))
    bridge = _bridge(journal)
    with pytest.raises(IntentAcceptanceAuditError, match="different acceptance audience"):
        bridge.reconcile()
    assert bridge.spine.verified_snapshot() == ()


def test_empty_journal_emits_no_anchor(tmp_path):
    store = IntentAcceptanceStore(tmp_path)
    audience = _test_identity("intent-envelope-audience-v1")
    bridge = _bridge((store, [], [], audience))
    page = bridge.reconcile()
    assert page.anchors == () and page.next_sequence == 0 and not page.has_more
    assert bridge.spine.verified_snapshot() == ()


def test_anchor_exports_are_host_helpers_not_capabilities():
    import nth_dao.plugins as facade

    assert facade.IntentAcceptanceSpineBridge is IntentAcceptanceSpineBridge
    assert facade.verify_intent_acceptance_anchor is verify_intent_acceptance_anchor
    assert "IntentAcceptanceSpineBridge" in facade.__all__
