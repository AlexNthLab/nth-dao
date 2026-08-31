"""Durability and authorization-boundary tests using disposable workspaces."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
import hashlib
import json
import multiprocessing as mp
import os
from pathlib import Path
import sqlite3
import threading
import time
import tracemalloc
import traceback

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.plugins.intent_acceptance import (
    IntentAcceptanceBusy, IntentAcceptanceCapacity, IntentAcceptanceConflict, IntentAcceptanceHead,
    IntentAcceptanceRecord, IntentAcceptanceStore, IntentAcceptanceStoreError,
)
from nth_dao.plugins.intent_envelope import (
    IntentAcceptanceContext, IntentEnvelopeError, intent_envelope_digest,
    sign_intent_envelope,
)
from nth_dao.plugins.intent_resolver import intent_resolver_request_digest
from tools.generate_intent_envelope_vectors import _test_identity


@pytest.fixture
def accepted():
    pytest.importorskip("nacl.signing")
    case = json.loads((Path(__file__).parents[1] / "nth_dao/plugins/vectors/intent-envelope-wire-cases-v1.json").read_text(encoding="utf-8"))["positive_cases"][0]
    expected = case["expected"] | {"allowed_solver_classes": tuple(case["expected"]["allowed_solver_classes"])}
    return case["envelope"], IntentAcceptanceContext(**expected)


def revision(envelope, expected, *, nonce="1" * 32):
    body = {key: value for key, value in envelope.items() if key != "signature"}
    body.update(revision=envelope["revision"] + 1, previous_digest=intent_envelope_digest(envelope), nonce=nonce)
    signed = sign_intent_envelope(body, signer=_test_identity("intent-envelope-signer-v1"))
    return signed, replace(expected, revision=body["revision"], previous_digest=body["previous_digest"])


def test_accept_restart_retry_and_detached_history(tmp_path, accepted):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)
    heads = []

    def policy(head):
        heads.append(head)
        return expected

    first = store.accept(envelope, resolve_context=policy)
    assert first.created and first.record.sequence == 1
    assert first.record.audit["executable"] is False
    assert heads == [IntentAcceptanceHead(0, "")]
    reopened = IntentAcceptanceStore(tmp_path, clock=lambda: 1001)
    retry = reopened.accept(envelope, resolve_context=policy)
    assert not retry.created and retry.record == first.record
    assert heads[-1] == IntentAcceptanceHead(1, first.record.envelope_digest)
    detached = retry.record.envelope
    detached["scope_id"] = "mutated"
    assert reopened.get(first.record.envelope_digest) == first.record
    assert reopened.verify_history(expected_tail_digest=first.record.audit_digest) == (1, first.record.audit_digest)
    assert len(reopened.history()) == 1


def test_revision_cas_nonce_and_historical_recovery(tmp_path, accepted):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)
    first = store.accept(envelope, resolve_context=lambda _: expected)
    second, second_context = revision(envelope, expected)
    created = store.accept(second, resolve_context=lambda _: second_context)
    assert created.created and created.record.previous_audit_digest == first.record.audit_digest
    fork, fork_context = revision(envelope, expected, nonce="2" * 32)
    with pytest.raises(IntentAcceptanceConflict, match="head"):
        store.accept(fork, resolve_context=lambda _: fork_context)
    replay, replay_context = revision(second, second_context, nonce=envelope["nonce"])
    with pytest.raises(IntentAcceptanceConflict, match="nonce"):
        store.accept(replay, resolve_context=lambda _: replay_context)
    expired = IntentAcceptanceStore(tmp_path, clock=lambda: 61000)
    with pytest.raises(IntentEnvelopeError, match="currently valid"):
        expired.accept(envelope, resolve_context=lambda _: expected)
    assert expired.get(first.record.envelope_digest) == first.record
    assert len(expired.history(after_sequence=1)) == 1


def test_policy_is_rechecked_and_denial_does_not_consume_nonce(tmp_path, accepted):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)
    with pytest.raises(IntentEnvelopeError, match="scope_id"):
        store.accept(envelope, resolve_context=lambda _: replace(expected, scope_id="wrong"))
    assert store.history() == ()
    first = store.accept(envelope, resolve_context=lambda _: expected)

    def revoked(_head):
        raise PermissionError("Host policy revoked")

    with pytest.raises(PermissionError):
        store.accept(envelope, resolve_context=revoked)
    assert store.get(first.record.envelope_digest) == first.record


def test_transaction_failure_rolls_back_artifact_nonce_and_audit(tmp_path, accepted, monkeypatch):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)
    original = store._insert

    def failed(connection, record):
        original(connection, record)
        raise sqlite3.OperationalError("injected commit boundary failure")

    monkeypatch.setattr(store, "_insert", failed)
    with pytest.raises(IntentAcceptanceStoreError):
        store.accept(envelope, resolve_context=lambda _: expected)
    assert store.history() == ()
    monkeypatch.setattr(store, "_insert", original)
    assert store.accept(envelope, resolve_context=lambda _: expected).created


def test_capacity_does_not_block_exact_retry(tmp_path, accepted):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000, max_records=1)
    store.accept(envelope, resolve_context=lambda _: expected)
    assert not store.accept(envelope, resolve_context=lambda _: expected).created
    second, context = revision(envelope, expected)
    with pytest.raises(IntentAcceptanceCapacity):
        store.accept(second, resolve_context=lambda _: context)
    assert len(store.history()) == 1


def test_journal_is_append_only_and_detects_tampering(tmp_path, accepted):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)
    record = store.accept(envelope, resolve_context=lambda _: expected).record
    connection = sqlite3.connect(store.path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM acceptances")
        connection.rollback()
        trigger = connection.execute("SELECT sql FROM sqlite_master WHERE name='no_update'").fetchone()[0]
        connection.execute("DROP TRIGGER no_update")
        connection.execute("UPDATE acceptances SET scope_id='forged'")
        connection.execute(trigger)
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(IntentAcceptanceStoreError, match="integrity"):
        store.get(record.envelope_digest)
    with pytest.raises(IntentAcceptanceStoreError, match="integrity"):
        IntentAcceptanceStore(tmp_path)


def _race_worker(workspace, envelope, expected, start, results):
    assert start.wait(10)
    store = IntentAcceptanceStore(workspace, clock=lambda: 1000)
    try:
        result = store.accept(envelope, resolve_context=lambda _: expected)
        results.put("created" if result.created else "retry")
    except IntentAcceptanceConflict:
        results.put("conflict")


@pytest.mark.parametrize("identical", [True, False])
def test_atomic_first_open_and_accept_across_processes(tmp_path, accepted, identical):
    envelope, expected = accepted
    context = mp.get_context("spawn")
    start, results = context.Event(), context.Queue()
    processes = []
    for n in range(4):
        candidate = envelope
        if not identical:
            body = {k: v for k, v in envelope.items() if k != "signature"}
            body["nonce"] = f"{n:032x}"
            candidate = sign_intent_envelope(body, signer=_test_identity("intent-envelope-signer-v1"))
        processes.append(context.Process(target=_race_worker, args=(tmp_path, candidate, expected, start, results)))
    try:
        for process in processes:
            process.start()
        start.set()
        for process in processes:
            process.join(15)
            assert process.exitcode == 0
        outcomes = [results.get(timeout=2) for _ in processes]
        assert outcomes.count("created") == 1
        assert outcomes.count("retry" if identical else "conflict") == 3
        assert IntentAcceptanceStore(tmp_path).verify_history()[0] == 1
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
            if process.pid is not None:
                process.join(5)
        results.close()
        results.join_thread()


def _crash_worker(workspace, envelope, expected):
    store = IntentAcceptanceStore(workspace, clock=lambda: 1000)
    original = store._insert

    def crash(connection, record):
        original(connection, record)
        os._exit(91)

    store._insert = crash
    store.accept(envelope, resolve_context=lambda _: expected)


def test_process_exit_before_commit_recovers_without_consuming_nonce(tmp_path, accepted):
    envelope, expected = accepted
    process = mp.get_context("spawn").Process(target=_crash_worker, args=(tmp_path, envelope, expected))
    process.start()
    try:
        process.join(15)
        assert process.exitcode == 91
        recovered = IntentAcceptanceStore(tmp_path, clock=lambda: 1001)
        assert recovered.history() == ()
        assert recovered.accept(envelope, resolve_context=lambda _: expected).created
    finally:
        if process.is_alive():
            process.terminate()
        process.join(5)


def test_busy_store_is_distinct_from_invalid_policy(tmp_path, accepted):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, timeout=0.05, clock=lambda: 1000)
    writer = sqlite3.connect(store.path, isolation_level=None)
    try:
        writer.execute("BEGIN IMMEDIATE")
        with pytest.raises(IntentAcceptanceBusy):
            store.accept(envelope, resolve_context=lambda _: expected)
    finally:
        writer.close()
    assert store.accept(envelope, resolve_context=lambda _: expected).created


def test_expiry_after_policy_check_fails_and_caller_mutation_is_isolated(tmp_path, accepted):
    envelope, expected = accepted
    clock = [1000]
    store = IntentAcceptanceStore(tmp_path, clock=lambda: clock[0])

    def slow_policy(_head):
        clock[0] = 61000
        return expected

    with pytest.raises(IntentEnvelopeError):
        store.accept(envelope, resolve_context=slow_policy)
    assert store.history() == ()
    clock[0] = 1000
    original_digest = intent_envelope_digest(envelope)

    def mutating_caller(_head):
        envelope["scope_id"] = "changed-after-snapshot"
        return expected

    accepted = store.accept(envelope, resolve_context=mutating_caller)
    assert accepted.record.envelope_digest == original_digest


def test_retained_audit_tail_detects_truncation(tmp_path, accepted):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)
    store.accept(envelope, resolve_context=lambda _: expected)
    second, context = revision(envelope, expected)
    tail = store.accept(second, resolve_context=lambda _: context).record.audit_digest
    connection = sqlite3.connect(store.path)
    try:
        trigger = connection.execute("SELECT sql FROM sqlite_master WHERE name='no_delete'").fetchone()[0]
        connection.execute("DROP TRIGGER no_delete")
        connection.execute("DELETE FROM acceptances WHERE sequence=2")
        connection.execute(trigger)
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(IntentAcceptanceStoreError, match="retained tail"):
        store.verify_history(expected_tail_digest=tail)


@pytest.mark.parametrize("field", ["envelope_json", "context_json"])
def test_malformed_blob_row_has_a_bounded_storage_error(tmp_path, accepted, field):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)
    store.accept(envelope, resolve_context=lambda _: expected)
    connection = sqlite3.connect(store.path)
    try:
        trigger = connection.execute("SELECT sql FROM sqlite_master WHERE name='no_update'").fetchone()[0]
        connection.execute("DROP TRIGGER no_update")
        connection.execute(f"UPDATE acceptances SET {field}=?", (b"PRIVATE-MARKER",))
        connection.execute(trigger)
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(IntentAcceptanceStoreError, match="integrity"):
        store.history()


def test_unknown_application_id_is_not_overwritten(tmp_path):
    path = tmp_path / ".nth/intent_acceptance_v1/acceptance.sqlite3"
    path.parent.mkdir(parents=True)
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA application_id = 123")
    finally:
        connection.close()
    with pytest.raises(IntentAcceptanceStoreError):
        IntentAcceptanceStore(tmp_path)


@pytest.mark.parametrize("kwargs", [
    {"timeout": True}, {"timeout": 0}, {"timeout": float("nan")}, {"timeout": float("inf")},
    {"max_records": False}, {"max_records": 4097}, {"max_bytes": 0}, {"clock": 1000},
])
def test_invalid_configuration_has_no_storage_side_effects(tmp_path, kwargs):
    with pytest.raises((TypeError, ValueError)):
        IntentAcceptanceStore(tmp_path, **kwargs)
    assert not (tmp_path / ".nth").exists()


@pytest.mark.parametrize("now", [True, -1, 1000.0, "1000", 2**53, 61000])
def test_invalid_clock_never_consumes_nonce(tmp_path, accepted, now):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: now)
    with pytest.raises(IntentEnvelopeError):
        store.accept(envelope, resolve_context=lambda _: expected)
    assert store.history() == ()


@pytest.mark.parametrize("context", [None, True, {}, "trusted"])
def test_policy_must_return_valid_typed_expectations(tmp_path, accepted, context):
    envelope, _ = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)
    with pytest.raises(IntentEnvelopeError):
        store.accept(envelope, resolve_context=lambda _: context)
    assert store.history() == ()


def test_nonce_is_scoped_but_revision_head_is_not_split_by_signer(tmp_path, accepted):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)
    first = store.accept(envelope, resolve_context=lambda _: expected)
    body = {k: v for k, v in envelope.items() if k != "signature"}
    other = _test_identity("intent-acceptance-other-signer")
    body["signer_did"] = other.as_did()
    second_signer = sign_intent_envelope(body, signer=other)
    other_context = replace(expected, signer_did=other.as_did())
    with pytest.raises(IntentAcceptanceConflict, match="head"):
        store.accept(second_signer, resolve_context=lambda _: other_context)
    body.update(revision=2, previous_digest=first.record.envelope_digest)
    next_signed = sign_intent_envelope(body, signer=other)
    next_context = replace(other_context, revision=2, previous_digest=first.record.envelope_digest)
    assert store.accept(next_signed, resolve_context=lambda _: next_context).created
    body.update(scope_id="another-scope", revision=1, previous_digest="")
    other_scope = sign_intent_envelope(body, signer=other)
    other_context = replace(other_context, scope_id="another-scope")
    assert store.accept(other_scope, resolve_context=lambda _: other_context).created
    assert store.verify_history()[0] == 3


def test_byte_capacity_and_clock_rollback_leave_history_unchanged(tmp_path, accepted):
    envelope, expected = accepted
    tiny = IntentAcceptanceStore(tmp_path / "tiny", max_bytes=1, clock=lambda: 1000)
    with pytest.raises(IntentAcceptanceCapacity):
        tiny.accept(envelope, resolve_context=lambda _: expected)
    assert tiny.history() == ()
    store = IntentAcceptanceStore(tmp_path / "clock", clock=lambda: 2000)
    first = store.accept(envelope, resolve_context=lambda _: expected)
    earlier = IntentAcceptanceStore(tmp_path / "clock", clock=lambda: 1000)
    second, context = revision(envelope, expected)
    with pytest.raises(IntentAcceptanceConflict, match="clock"):
        earlier.accept(second, resolve_context=lambda _: context)
    assert earlier.verify_history() == (1, first.record.audit_digest)


@pytest.mark.parametrize("part", [".nth", "acceptance.sqlite3", "acceptance.sqlite3-journal", "acceptance.sqlite3-wal", "acceptance.sqlite3-shm"])
def test_path_and_sidecar_redirections_fail_closed(tmp_path, monkeypatch, part):
    from nth_dao.plugins import intent_acceptance as module

    monkeypatch.setattr(module, "path_is_linklike", lambda path: path.name == part)
    with pytest.raises(IntentAcceptanceStoreError, match="links"):
        IntentAcceptanceStore(tmp_path)
    assert not (tmp_path / ".nth").exists()


def test_invalid_signature_never_reaches_host_policy(tmp_path, accepted):
    envelope, _ = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)

    def forbidden(_head):
        pytest.fail("invalid signature reached Host policy")

    with pytest.raises(IntentEnvelopeError):
        store.accept(envelope | {"signature": "0" * 128}, resolve_context=forbidden)
    assert store.history() == ()


@pytest.mark.parametrize("last_now", [61000, 999, True])
def test_clock_is_rechecked_at_the_insert_boundary(tmp_path, accepted, last_now):
    envelope, expected = accepted
    ticks = iter([1000, last_now])
    store = IntentAcceptanceStore(tmp_path, clock=lambda: next(ticks))
    with pytest.raises((IntentEnvelopeError, IntentAcceptanceConflict)):
        store.accept(envelope, resolve_context=lambda _: expected)
    assert store.history() == ()


def test_facade_exports_store_without_a_provider_capability():
    import nth_dao.plugins as facade

    for symbol in (IntentAcceptanceStore, IntentAcceptanceConflict, IntentAcceptanceRecord):
        assert getattr(facade, symbol.__name__) is symbol
        assert symbol.__name__ in facade.__all__
    assert not hasattr(facade, "INTENT_ACCEPTANCE_CONTRACT")


@pytest.mark.parametrize("statement", [
    "CREATE TRIGGER ignored_insert BEFORE INSERT ON acceptances BEGIN SELECT RAISE(IGNORE); END",
    "ALTER TABLE acceptances RENAME COLUMN nonce TO nonce_old",
    "DROP TRIGGER no_update",
    "CREATE INDEX extra_index ON acceptances(scope_id)",
    "CREATE TABLE extra_state (value TEXT)",
])
@pytest.mark.parametrize("populated", [False, True])
def test_schema_drift_is_rejected_before_policy(tmp_path, accepted, statement, populated):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)
    if populated:
        store.accept(envelope, resolve_context=lambda _: expected)
    connection = sqlite3.connect(store.path)
    try:
        connection.execute(statement)
        connection.commit()
    finally:
        connection.close()

    def forbidden(_head):
        pytest.fail("invalid storage schema reached Host policy")

    with pytest.raises(IntentAcceptanceStoreError, match="schema"):
        store.accept(envelope, resolve_context=forbidden)
    with pytest.raises(IntentAcceptanceStoreError, match="schema"):
        store.history()
    with pytest.raises(IntentAcceptanceStoreError, match="schema"):
        IntentAcceptanceStore(tmp_path)


@pytest.mark.parametrize("mode", ["ignore", "rewrite"])
def test_insert_checks_actual_effect_even_without_schema_guard(tmp_path, accepted, monkeypatch, mode):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)
    connection = sqlite3.connect(store.path)
    try:
        if mode == "ignore":
            connection.execute("CREATE TRIGGER ignore_insert BEFORE INSERT ON acceptances BEGIN SELECT RAISE(IGNORE); END")
        else:
            connection.execute("DROP TRIGGER no_update")
            connection.execute("CREATE TRIGGER rewrite_insert AFTER INSERT ON acceptances BEGIN UPDATE acceptances SET nonce='rewritten' WHERE sequence=NEW.sequence; END")
        connection.commit()
    finally:
        connection.close()
    # Isolate the postcondition guard from the independent schema guard.
    monkeypatch.setattr(store, "_check_schema", lambda _: None)
    with pytest.raises(IntentAcceptanceStoreError, match="insert"):
        store.accept(envelope, resolve_context=lambda _: expected)
    connection = sqlite3.connect(store.path)
    try:
        assert connection.execute("SELECT COUNT(*) FROM acceptances").fetchone()[0] == 0
    finally:
        connection.close()


@pytest.mark.parametrize("operation", ["accept", "get", "history", "verify", "reopen"])
def test_history_verification_holds_no_database_lock(tmp_path, accepted, monkeypatch, operation):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, timeout=0.05, clock=lambda: 1000)
    first = store.accept(envelope, resolve_context=lambda _: expected)
    peer = IntentAcceptanceStore(tmp_path, timeout=0.05, clock=lambda: 1000)
    second, second_context = revision(envelope, expected)
    entered, release = threading.Event(), threading.Event()
    original = IntentAcceptanceStore._verify_rows

    def paused(rows):
        if threading.current_thread().name.startswith("intent-reader") and not entered.is_set():
            entered.set()
            assert release.wait(10)
        return original(rows)

    monkeypatch.setattr(IntentAcceptanceStore, "_verify_rows", staticmethod(paused))

    def read():
        if operation == "accept":
            return store.accept(envelope, resolve_context=lambda _: expected)
        if operation == "get":
            return store.get(first.record.envelope_digest)
        if operation == "history":
            return store.history()
        if operation == "verify":
            return store.verify_history()
        return IntentAcceptanceStore(tmp_path, timeout=0.05)

    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="intent-reader") as pool:
        future = pool.submit(read)
        try:
            assert entered.wait(10)
            assert peer.accept(second, resolve_context=lambda _: second_context).created
        finally:
            release.set()
        outcome = future.result(timeout=10)
    if operation == "accept":
        assert not outcome.created and outcome.record == first.record
    elif operation == "get":
        assert outcome == first.record
    elif operation == "history":
        assert outcome == (first.record,)
    elif operation == "verify":
        assert outcome == (1, first.record.audit_digest)
    assert store.verify_history()[0] == 2


def test_snapshot_compares_all_fields_not_only_tail(tmp_path, accepted, monkeypatch):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)
    store.accept(envelope, resolve_context=lambda _: expected)
    original = store._verify_rows
    changed = False

    def tampered_between_snapshot_and_write(rows):
        nonlocal changed
        records = original(rows)
        if not changed:
            changed = True
            connection = sqlite3.connect(store.path)
            try:
                trigger = connection.execute("SELECT sql FROM sqlite_master WHERE name='no_update'").fetchone()[0]
                connection.execute("DROP TRIGGER no_update")
                connection.execute("UPDATE acceptances SET scope_id='tampered' WHERE sequence=1")
                connection.execute(trigger)
                connection.commit()
            finally:
                connection.close()
        return records

    monkeypatch.setattr(store, "_verify_rows", tampered_between_snapshot_and_write)

    def forbidden(_head):
        pytest.fail("changed history reached Host policy")

    with pytest.raises(IntentAcceptanceStoreError, match="integrity"):
        store.accept(envelope, resolve_context=forbidden)


def test_snapshot_churn_has_a_bounded_retry_budget(tmp_path, accepted, monkeypatch):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)
    peer = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)
    original = store._read_history
    attempts = []

    def competing_writer():
        result = original()
        scope = f"competing-{len(attempts)}"
        body = {k: v for k, v in envelope.items() if k != "signature"}
        body["scope_id"] = scope
        candidate = sign_intent_envelope(body, signer=_test_identity("intent-envelope-signer-v1"))
        context = replace(expected, scope_id=scope)
        attempts.append(peer.accept(candidate, resolve_context=lambda _: context))
        return result

    monkeypatch.setattr(store, "_read_history", competing_writer)
    with pytest.raises(IntentAcceptanceBusy, match="kept changing"):
        store.accept(envelope, resolve_context=lambda _: pytest.fail("stale snapshot reached policy"))
    assert len(attempts) == 4
    assert peer.get(intent_envelope_digest(envelope)) is None


def test_default_capacity_concurrent_retries_do_not_hold_crypto_writer_lock(tmp_path, accepted, capsys):
    from nth_dao.plugins.intent_acceptance import _hash

    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)
    signer = _test_identity("intent-envelope-signer-v1")
    draft = json.loads(envelope["draft_json"])
    draft["source_text"] = "x" * 12000
    request = {key: draft[key] for key in (
        "attachments", "automation_ceiling", "locale", "request_id", "source_kind", "source_text",
    )}
    request["operation"] = "resolve"
    draft["request_digest"] = intent_resolver_request_digest(request)
    encoded = canonical_json(draft)
    body = {key: value for key, value in envelope.items() if key != "signature"}
    body.update(draft_json=encoded.decode(), draft_digest="sha256:" + hashlib.sha256(encoded).hexdigest())
    connection = sqlite3.connect(store.path)
    previous = ""
    try:
        # Build a valid full-sized fixture without quadratic setup verification.
        for n in range(1024):
            body.update(scope_id=f"scope-{n}", nonce=f"{n:032x}")
            signed = sign_intent_envelope(body, signer=signer)
            context = replace(expected, scope_id=body["scope_id"], draft_digest=body["draft_digest"])
            raw_context = asdict(context) | {"allowed_solver_classes": list(context.allowed_solver_classes)}
            record = IntentAcceptanceRecord(
                n + 1, _hash(signed), canonical_json(signed).decode(), canonical_json(raw_context).decode(),
                1000, previous, "",
            )
            record = replace(record, audit_digest=_hash(record.audit))
            store._insert(connection, record)
            previous = record.audit_digest
        connection.commit()
        size = connection.execute("SELECT SUM(LENGTH(CAST(envelope_json AS BLOB))+LENGTH(CAST(context_json AS BLOB))) FROM acceptances").fetchone()[0]
        assert 13 * 1024 * 1024 < size < store.max_bytes
    finally:
        connection.close()

    barrier = threading.Barrier(2)

    def retry():
        barrier.wait(timeout=10)
        started = time.perf_counter()
        result = store.accept(signed, resolve_context=lambda _: context)
        return result, time.perf_counter() - started

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(retry) for _ in range(2)]
        results = [future.result(timeout=120) for future in futures]
    assert all(not result.created and result.record.sequence == 1024 for result, _ in results)
    with capsys.disabled():
        print(f"\nAcceptance capacity benchmark: {size} bytes; concurrent retries {[round(seconds, 3) for _, seconds in results]} seconds")


def test_empty_tail_roundtrips_and_pins_an_empty_journal(tmp_path, accepted):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)
    count, tail = store.verify_history()
    assert count == 0 and tail == ""
    assert IntentAcceptanceStore(tmp_path).verify_history(expected_tail_digest=tail) == (count, tail)
    with pytest.raises(IntentAcceptanceStoreError, match="retained tail"):
        store.verify_history(expected_tail_digest="sha256:" + "1" * 64)
    record = store.accept(envelope, resolve_context=lambda _: expected).record
    with pytest.raises(IntentAcceptanceStoreError, match="retained tail"):
        store.verify_history(expected_tail_digest=tail)
    assert store.verify_history(expected_tail_digest=record.audit_digest) == (1, record.audit_digest)


def test_real_commit_lock_failure_rolls_back_and_retry_succeeds(tmp_path, accepted, monkeypatch):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, timeout=0.05, clock=lambda: 1000)
    inserted = []
    original = store._insert

    def observed_insert(connection, record):
        original(connection, record)
        inserted.append(record.envelope_digest)

    monkeypatch.setattr(store, "_insert", observed_insert)
    reader = sqlite3.connect(store.path, isolation_level=None)
    try:
        assert reader.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        reader.execute("BEGIN")
        reader.execute("SELECT COUNT(*) FROM acceptances").fetchone()
        # The shared reader permits BEGIN IMMEDIATE and INSERT, but blocks COMMIT.
        with pytest.raises(IntentAcceptanceBusy):
            store.accept(envelope, resolve_context=lambda _: expected)
        assert len(inserted) == 1
    finally:
        reader.close()
    recovered = IntentAcceptanceStore(tmp_path, clock=lambda: 1001)
    assert recovered.verify_history() == (0, "")
    assert recovered.get(inserted[0]) is None
    assert recovered.accept(envelope, resolve_context=lambda _: expected).created


def _committed_exit_worker(workspace, envelope, expected):
    store = IntentAcceptanceStore(workspace, clock=lambda: 1000)
    assert store.accept(envelope, resolve_context=lambda _: expected).created
    # Simulate losing the child before it can deliver its successful response.
    os._exit(92)


def test_committed_child_exit_recovers_without_duplicate_acceptance(tmp_path, accepted):
    envelope, expected = accepted
    process = mp.get_context("spawn").Process(target=_committed_exit_worker, args=(tmp_path, envelope, expected))
    process.start()
    try:
        process.join(15)
        assert process.exitcode == 92
        recovered = IntentAcceptanceStore(tmp_path, clock=lambda: 1001)
        record = recovered.get(intent_envelope_digest(envelope))
        assert record is not None and record.sequence == 1
        result = recovered.accept(envelope, resolve_context=lambda _: expected)
        assert not result.created and result.record == record
        assert recovered.verify_history() == (1, record.audit_digest)
    finally:
        if process.is_alive():
            process.terminate()
        process.join(5)


@pytest.mark.parametrize("field,value", [
    ("envelope_digest", "x" * 72),
    ("audience_did", "x" * 129),
    ("scope_id", "x" * 257),
    ("scope_id", "a\x00" + "x" * 256),
    ("scope_id", "\u00e9" * 129),
    ("signer_did", "x" * 129),
    ("nonce", "x" * 33),
    ("previous_audit_digest", "x" * 72),
    ("audit_digest", "x" * 72),
    ("envelope_json", "x" * 262145),
    ("context_json", "x" * 8193),
    ("scope_id", b"invalid-text-type"),
    ("revision", 1.5),
    ("accepted_at_ms", -1),
    ("accepted_at_ms", 2**53),
], ids=[
    "digest", "audience", "scope", "scope-nul", "scope-utf8", "signer", "nonce",
    "previous-audit", "audit", "envelope-json", "context-json", "blob-type",
    "revision-type", "negative-time", "unsafe-time",
])
def test_invalid_fields_rejected_before_full_row_fetch(tmp_path, accepted, monkeypatch, field, value):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)
    store.accept(envelope, resolve_context=lambda _: expected)
    connection = sqlite3.connect(store.path)
    try:
        trigger = connection.execute("SELECT sql FROM sqlite_master WHERE name='no_update'").fetchone()[0]
        connection.execute("DROP TRIGGER no_update")
        connection.execute(f"UPDATE acceptances SET {field}=?", (value,))
        connection.execute(trigger)
        connection.commit()
    finally:
        connection.close()
    statements = []
    original_connect = sqlite3.connect

    def traced_connect(*args, **kwargs):
        connection = original_connect(*args, **kwargs)
        connection.set_trace_callback(statements.append)
        return connection

    monkeypatch.setattr(sqlite3, "connect", traced_connect)
    monkeypatch.setattr(store, "_verify_rows", lambda _: pytest.fail("unbounded or mistyped row reached Python verification"))
    with pytest.raises(IntentAcceptanceStoreError, match="integrity"):
        store.history()
    assert not any(sql.lstrip().startswith("SELECT sequence,") for sql in statements)
    with pytest.raises(IntentAcceptanceStoreError, match="integrity"):
        IntentAcceptanceStore(tmp_path)


def test_oversized_metadata_has_bounded_python_allocation(tmp_path, accepted):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, max_bytes=8192, clock=lambda: 1000)
    store.accept(envelope, resolve_context=lambda _: expected)
    connection = sqlite3.connect(store.path)
    try:
        trigger = connection.execute("SELECT sql FROM sqlite_master WHERE name='no_update'").fetchone()[0]
        connection.execute("DROP TRIGGER no_update")
        connection.execute("UPDATE acceptances SET scope_id=?", ("x" * (8 * 1024 * 1024),))
        connection.execute(trigger)
        connection.commit()
    finally:
        connection.close()
    tracemalloc.start()
    try:
        with pytest.raises(IntentAcceptanceStoreError, match="integrity"):
            store.history()
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 2 * 1024 * 1024


@pytest.mark.parametrize("populated", [False, True])
def test_policy_database_lock_is_not_an_acceptance_journal_lock(tmp_path, accepted, populated):
    import nth_dao.plugins as facade

    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)
    if populated:
        store.accept(envelope, resolve_context=lambda _: expected)
    policy_path = tmp_path / "policy.sqlite3"
    blocker = sqlite3.connect(policy_path, isolation_level=None)
    try:
        blocker.execute("CREATE TABLE policy (allowed INTEGER)")
        blocker.execute("INSERT INTO policy VALUES (1)")
        blocker.execute("BEGIN EXCLUSIVE")

        def read_policy(_head):
            connection = sqlite3.connect(policy_path, timeout=0.01)
            try:
                connection.execute("SELECT allowed FROM policy").fetchone()
            finally:
                connection.close()
            return expected

        with pytest.raises(RuntimeError) as caught:
            store.accept(envelope, resolve_context=read_policy)
        assert type(caught.value).__name__ == "IntentAcceptancePolicyUnavailable"
        assert not isinstance(caught.value, IntentAcceptanceStoreError)
        assert type(caught.value) is facade.IntentAcceptancePolicyUnavailable
        assert "IntentAcceptancePolicyUnavailable" in facade.__all__
    finally:
        blocker.close()
    assert store.verify_history()[0] == int(populated)
    assert store.accept(envelope, resolve_context=lambda _: expected).created is not populated


@pytest.mark.parametrize("error_type", [sqlite3.OperationalError, sqlite3.IntegrityError, sqlite3.DataError])
def test_policy_sqlite_errors_are_sanitized_and_do_not_consume_nonce(tmp_path, accepted, error_type):
    envelope, expected = accepted
    store = IntentAcceptanceStore(tmp_path, clock=lambda: 1000)

    def unavailable(_head):
        raise error_type("PRIVATE-POLICY-DETAIL")

    with pytest.raises(RuntimeError) as caught:
        store.accept(envelope, resolve_context=unavailable)
    assert type(caught.value).__name__ == "IntentAcceptancePolicyUnavailable"
    assert "PRIVATE-POLICY-DETAIL" not in "".join(traceback.format_exception(caught.value))
    assert caught.value.__cause__ is None and caught.value.__suppress_context__
    assert store.history() == ()
    assert store.accept(envelope, resolve_context=lambda _: expected).created
