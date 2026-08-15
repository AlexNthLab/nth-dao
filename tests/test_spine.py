"""Spine chaining, persistence, tamper detection, signature, and projection tests."""
from __future__ import annotations

import json
import multiprocessing
import os
from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.identity import AgentIdentity
import nth_dao.spine.log as spine_log_module
from nth_dao.spine import (
    GENESIS_PREV,
    Projection,
    SignedEventLog,
    SpineAppendOutcomeUnknown,
    replay,
    sign_event,
    verify_event,
)
from nth_dao.spine.log import MAX_SPINE_LINE_BYTES


def _id() -> AgentIdentity:
    return AgentIdentity.generate()


def _rewrite_line(path: Path, idx: int, obj: dict) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[idx] = json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _append_in_process(path: str, index: int, output) -> None:
    try:
        event = SignedEventLog(
            path,
            AgentIdentity.generate(),
            lock_timeout=20,
        ).append("test.concurrent", {"index": index})
        output.put(("ok", event.seq))
    except Exception as exc:
        output.put(("error", type(exc).__name__, str(exc)))


def _append_unique_in_process(path: str, output) -> None:
    try:
        event, created = SignedEventLog(
            path,
            AgentIdentity.generate(),
            lock_timeout=20,
        ).append_unique(
            "trade.execution.recorded",
            {
                "execution_id": "exec-one",
                "receipt_digest": "digest-one",
            },
            unique_payload_fields=("execution_id", "receipt_digest"),
            ts_ms=1,
        )
        output.put(("ok", event.event_id, created))
    except Exception as exc:
        output.put(("error", type(exc).__name__, str(exc)))


def test_append_chains_and_verifies(tmp_path: Path) -> None:
    log = SignedEventLog(tmp_path / "events.jsonl", _id())
    e0 = log.append("market.announce", {"id": "a"})
    e1 = log.append("market.claim", {"id": "a", "by": "x"})
    e2 = log.append("receipt.record", {"rid": "r1"})
    assert [e0.seq, e1.seq, e2.seq] == [0, 1, 2]
    assert e0.prev_hash == GENESIS_PREV
    assert e1.prev_hash == e0.content_hash
    assert e2.prev_hash == e1.content_hash
    ok, why = log.verify_chain()
    assert ok, why


def test_persistence_reloads_head_and_continues(tmp_path: Path) -> None:
    p = tmp_path / "events.jsonl"
    ident = _id()
    log = SignedEventLog(p, ident)
    log.append("t", {"n": 1})
    log.append("t", {"n": 2})
    # A new instance reloads the head and continues the existing chain.
    log2 = SignedEventLog(p, ident)
    assert log2.head_seq == 1
    e = log2.append("t", {"n": 3})
    assert e.seq == 2
    assert e.prev_hash != GENESIS_PREV
    ok, why = log2.verify_chain()
    assert ok, why


def test_spine_constructor_preserves_lock_timeout_diagnosis(
    tmp_path: Path,
    monkeypatch,
) -> None:
    class _BusyLock:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            raise TimeoutError("simulated spine contention")

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(spine_log_module, "InterProcessLock", _BusyLock)
    with pytest.raises(TimeoutError, match="simulated spine contention"):
        SignedEventLog(tmp_path / "events.jsonl", _id())


def test_spine_recovers_exact_signed_partial_append(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "events.jsonl"
    identity = _id()
    log = SignedEventLog(path, identity)
    first = log.append("test.first", {"id": "one"})

    def write_partial_then_fail(record: bytes) -> None:
        with path.open("ab") as stream:
            stream.write(record[: len(record) // 2])
            stream.flush()
            os.fsync(stream.fileno())
        raise OSError("simulated interrupted append")

    monkeypatch.setattr(log, "_write_record_unlocked", write_partial_then_fail)
    with pytest.raises(OSError, match="interrupted append"):
        log.append("test.recovered", {"id": "two"}, ts_ms=2)
    pending_path = path.with_name(path.name + ".append.pending")
    assert pending_path.is_file()

    recovered = SignedEventLog(path, identity)
    events = recovered.verified_snapshot()
    assert [event.type for event in events] == ["test.first", "test.recovered"]
    assert events[0] == first
    assert events[1].prev_hash == first.content_hash
    assert not pending_path.exists()


def test_spine_reconciles_durable_record_without_duplicate_retry(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "events.jsonl"
    log = SignedEventLog(path, _id())
    real_write = log._write_record_unlocked

    def write_then_report_failure(record: bytes) -> None:
        real_write(record)
        raise OSError("simulated fsync outcome ambiguity")

    monkeypatch.setattr(
        log,
        "_write_record_unlocked",
        write_then_report_failure,
    )
    with pytest.raises(SpineAppendOutcomeUnknown) as caught:
        log.append("test.ambiguous", {"id": "one"}, ts_ms=1)
    monkeypatch.setattr(log, "_write_record_unlocked", real_write)

    resolved = log.reconcile_append(caught.value.event_id)

    assert resolved == caught.value.event
    assert log.verified_snapshot() == (resolved,)
    assert log.head_seq == 0


def test_spine_reconciles_durable_intent_without_duplicate_retry(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "events.jsonl"
    log = SignedEventLog(path, _id())
    real_write_intent = log._write_append_intent_unlocked

    def write_intent_then_report_failure(*, base_size: int, line: bytes) -> None:
        real_write_intent(base_size=base_size, line=line)
        raise OSError("simulated directory fsync ambiguity")

    monkeypatch.setattr(
        log,
        "_write_append_intent_unlocked",
        write_intent_then_report_failure,
    )
    with pytest.raises(SpineAppendOutcomeUnknown) as caught:
        log.append("test.ambiguous-intent", {"id": "one"}, ts_ms=1)
    monkeypatch.setattr(
        log,
        "_write_append_intent_unlocked",
        real_write_intent,
    )

    resolved = log.reconcile_append(caught.value.event_id)

    assert resolved == caught.value.event
    assert log.verified_snapshot() == (resolved,)


def test_spine_plain_intent_failure_is_safe_to_retry(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log = SignedEventLog(tmp_path / "events.jsonl", _id())
    real_write_intent = log._write_append_intent_unlocked

    def fail_before_intent(**_kwargs) -> None:
        raise OSError("simulated pre-intent failure")

    monkeypatch.setattr(
        log,
        "_write_append_intent_unlocked",
        fail_before_intent,
    )
    with pytest.raises(OSError, match="pre-intent failure") as caught:
        log.append("test.safe-retry", {"id": "one"}, ts_ms=1)
    assert not isinstance(caught.value, SpineAppendOutcomeUnknown)
    monkeypatch.setattr(
        log,
        "_write_append_intent_unlocked",
        real_write_intent,
    )

    appended = log.append("test.safe-retry", {"id": "one"}, ts_ms=1)

    assert log.verified_snapshot() == (appended,)


def test_append_unique_retry_after_unknown_outcome_is_duplicate_safe(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "events.jsonl"
    log = SignedEventLog(path, _id())
    payload = {"execution_id": "exec-1", "receipt_digest": "digest-1"}
    real_write = log._write_record_unlocked

    def write_partial_then_fail(record: bytes) -> None:
        with path.open("ab") as stream:
            stream.write(record[: len(record) // 2])
            stream.flush()
            os.fsync(stream.fileno())
        raise OSError("simulated interrupted unique append")

    monkeypatch.setattr(log, "_write_record_unlocked", write_partial_then_fail)
    with pytest.raises(SpineAppendOutcomeUnknown):
        log.append_unique(
            "trade.execution.recorded",
            payload,
            unique_payload_fields=("execution_id", "receipt_digest"),
            ts_ms=1,
        )
    monkeypatch.setattr(log, "_write_record_unlocked", real_write)

    recovered, created = log.append_unique(
        "trade.execution.recorded",
        payload,
        unique_payload_fields=("execution_id", "receipt_digest"),
        ts_ms=2,
    )

    assert created is False
    assert recovered.ts_ms == 1
    assert log.verified_snapshot() == (recovered,)


def test_spine_recovery_rejects_tail_not_matching_signed_intent(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "events.jsonl"
    identity = _id()
    log = SignedEventLog(path, identity)
    log.append("test.first", {"id": "one"})

    def write_partial_then_fail(record: bytes) -> None:
        with path.open("ab") as stream:
            stream.write(record[: len(record) // 2])
            stream.flush()
            os.fsync(stream.fileno())
        raise OSError("simulated interrupted append")

    monkeypatch.setattr(log, "_write_record_unlocked", write_partial_then_fail)
    with pytest.raises(OSError):
        log.append("test.must-not-recover", {"id": "two"}, ts_ms=2)
    raw = path.read_bytes()
    path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))

    with pytest.raises(ValueError, match="tail conflicts with signed intent"):
        SignedEventLog(path, identity)
    assert path.with_name(path.name + ".append.pending").exists()


def test_spine_rejects_incomplete_tail_without_signed_intent(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    identity = _id()
    log = SignedEventLog(path, identity)
    log.append("test.first", {"id": "one"})
    with path.open("ab") as stream:
        stream.write(b'{"seq":1')

    with pytest.raises(ValueError, match="incomplete final record"):
        SignedEventLog(path, identity)


def test_spine_recovers_durable_append_after_intent_cleanup_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "events.jsonl"
    identity = _id()
    log = SignedEventLog(path, identity)

    def fail_cleanup() -> None:
        raise OSError("simulated pending cleanup failure")

    monkeypatch.setattr(log, "_clear_append_intent_unlocked", fail_cleanup)
    appended = log.append("test.durable", {"id": "one"}, ts_ms=1)
    pending_path = path.with_name(path.name + ".append.pending")
    assert pending_path.exists()

    recovered = SignedEventLog(path, identity)
    assert recovered.verified_snapshot() == (appended,)
    assert not pending_path.exists()


def test_spine_rejects_pending_event_signed_by_another_identity(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.jsonl"
    owner = _id()
    attacker = _id()
    log = SignedEventLog(path, owner)
    forged = sign_event(
        seq=0,
        prev_hash=GENESIS_PREV,
        event_type="test.forged",
        payload={"id": "forged"},
        identity=attacker,
        ts_ms=1,
    )
    log._write_append_intent_unlocked(
        base_size=0,
        line=log._encode_event(forged),
    )

    with pytest.raises(ValueError, match="unauthorized"):
        SignedEventLog(path, owner)


def test_tamper_payload_breaks_verification(tmp_path: Path) -> None:
    p = tmp_path / "events.jsonl"
    log = SignedEventLog(p, _id())
    log.append("t", {"amount": 5})
    log.append("t", {"amount": 6})
    first = json.loads(p.read_text(encoding="utf-8").splitlines()[0])
    first["payload"]["amount"] = 9999  # Tamper without updating content_hash.
    _rewrite_line(p, 0, first)
    ok, why = SignedEventLog(p, _id()).verify_chain()
    assert not ok
    assert "content_hash mismatch" in why


def test_tamper_prev_hash_breaks_chain(tmp_path: Path) -> None:
    p = tmp_path / "events.jsonl"
    log = SignedEventLog(p, _id())
    log.append("t", {"n": 1})
    log.append("t", {"n": 2})
    second = json.loads(p.read_text(encoding="utf-8").splitlines()[1])
    second["prev_hash"] = "1" * 64  # Break the chain.
    _rewrite_line(p, 1, second)
    ok, why = SignedEventLog(p, _id()).verify_chain()
    assert not ok


def test_append_refuses_structurally_valid_tampered_chain(
    tmp_path: Path,
) -> None:
    p = tmp_path / "events.jsonl"
    log = SignedEventLog(p, _id())
    log.append("test.original", {"amount": 5})
    first = json.loads(p.read_text(encoding="utf-8").splitlines()[0])
    first["payload"]["amount"] = 9999
    _rewrite_line(p, 0, first)

    diagnostic = SignedEventLog(p, _id())
    ok, why = diagnostic.verify_chain()
    assert not ok and "content_hash mismatch" in why
    with pytest.raises(ValueError, match="cannot be appended"):
        diagnostic.append("test.must-not-append", {})
    assert len(p.read_text(encoding="utf-8").splitlines()) == 1


def test_verified_snapshot_never_returns_unverified_events(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.jsonl"
    log = SignedEventLog(path, _id())
    log.append("test.original", {"id": "one"})
    event = json.loads(path.read_text(encoding="utf-8"))
    event["payload"]["id"] = "tampered"
    _rewrite_line(path, 0, event)

    with pytest.raises(ValueError, match="verified snapshot"):
        log.verified_snapshot()


def test_verified_snapshot_with_token_matches_the_verified_bytes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.jsonl"
    log = SignedEventLog(path, _id())
    event = log.append("test.original", {"id": "one"})

    token, events = log.verified_snapshot_with_token()

    assert token == log.storage_token()
    assert events == (event,)


def test_verified_snapshot_rejects_same_size_retimestamped_tamper(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.jsonl"
    log = SignedEventLog(path, _id())
    log.append("test.original", {"id": "one"})
    original_token, _ = log.verified_snapshot_with_token()
    before = path.stat()

    raw = path.read_bytes()
    assert b'"id":"one"' in raw
    path.write_bytes(raw.replace(b'"id":"one"', b'"id":"two"', 1))
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))

    assert path.stat().st_size == before.st_size
    assert log.storage_token() != original_token
    with pytest.raises(ValueError, match="corrupt"):
        log.verified_snapshot_with_token()


def test_verified_snapshot_never_binds_verified_events_to_later_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "events.jsonl"
    log = SignedEventLog(path, _id())
    log.append("test.original", {"id": "one"})
    real_verify = log._verified_events_unlocked

    def verify_then_tamper():
        result = real_verify()
        raw = path.read_bytes()
        path.write_bytes(raw.replace(b'"id":"one"', b'"id":"two"', 1))
        return result

    log._verified_cache_token = None
    monkeypatch.setattr(log, "_verified_events_unlocked", verify_then_tamper)

    with pytest.raises(ValueError, match="corrupt"):
        log.verified_snapshot_with_token()
    assert log._verified_cache_token is None


def test_append_unique_is_idempotent_and_rejects_key_reuse(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.jsonl"
    first_log = SignedEventLog(path, _id())
    payload = {"execution_id": "exec-1", "receipt_digest": "digest-1"}

    first, first_created = first_log.append_unique(
        "trade.execution.recorded",
        payload,
        unique_payload_fields=("execution_id", "receipt_digest"),
        ts_ms=1,
    )
    second, second_created = SignedEventLog(path, _id()).append_unique(
        "trade.execution.recorded",
        payload,
        unique_payload_fields=("execution_id", "receipt_digest"),
        ts_ms=2,
    )

    assert first_created is True
    assert second_created is False
    assert second == first
    with pytest.raises(ValueError, match="conflicting payload"):
        first_log.append_unique(
            "trade.execution.recorded",
            {
                "execution_id": "exec-1",
                "receipt_digest": "digest-2",
            },
            unique_payload_fields=("execution_id", "receipt_digest"),
            ts_ms=3,
        )
    assert len(first_log.verified_snapshot()) == 1


def test_append_unique_many_scans_once_and_prevalidates_conflicts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    log = SignedEventLog(tmp_path / "events.jsonl", _id())
    original = log._verified_events_unlocked
    scans = 0

    def counted_scan():
        nonlocal scans
        scans += 1
        return original()

    monkeypatch.setattr(log, "_verified_events_unlocked", counted_scan)
    payloads = tuple(
        {"execution_id": f"exec-{index}", "receipt_digest": f"digest-{index}"}
        for index in range(3)
    )
    results = log.append_unique_many(
        "trade.execution.recorded",
        payloads,
        unique_payload_fields=("execution_id", "receipt_digest"),
        ts_ms=1,
    )

    assert scans == 1
    assert [created for _event, created in results] == [True, True, True]
    before = log._path.read_bytes()
    with pytest.raises(ValueError, match="conflicting payload"):
        log.append_unique_many(
            "trade.execution.recorded",
            (
                {"execution_id": "exec-4", "receipt_digest": "digest-4"},
                {"execution_id": "exec-0", "receipt_digest": "changed"},
            ),
            unique_payload_fields=("execution_id", "receipt_digest"),
            ts_ms=2,
        )
    assert scans == 1
    assert log._path.read_bytes() == before

    appended = log.append_unique_many(
        "trade.execution.recorded",
        ({"execution_id": "exec-4", "receipt_digest": "digest-4"},),
        unique_payload_fields=("execution_id", "receipt_digest"),
        ts_ms=2,
    )
    assert appended[0][1] is True
    assert scans == 1


def test_verified_indexes_rebuild_after_another_writer_advances_log(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "events.jsonl"
    identity = _id()
    first = SignedEventLog(path, identity)
    first.append_unique(
        "trade.execution.recorded",
        {"execution_id": "exec-1", "receipt_digest": "digest-1"},
        unique_payload_fields=("execution_id", "receipt_digest"),
        ts_ms=1,
    )
    second = SignedEventLog(path, identity)
    second.append_unique(
        "trade.execution.recorded",
        {"execution_id": "exec-2", "receipt_digest": "digest-2"},
        unique_payload_fields=("execution_id", "receipt_digest"),
        ts_ms=2,
    )
    original = first._verified_events_unlocked
    scans = 0

    def counted_scan():
        nonlocal scans
        scans += 1
        return original()

    monkeypatch.setattr(first, "_verified_events_unlocked", counted_scan)
    for _index in range(2):
        event, created = first.append_unique(
            "trade.execution.recorded",
            {"execution_id": "exec-2", "receipt_digest": "digest-2"},
            unique_payload_fields=("execution_id", "receipt_digest"),
            ts_ms=3,
        )
        assert event.seq == 1
        assert created is False
    assert scans == 1


def test_verified_cache_is_bounded_and_reconcile_falls_back(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(spine_log_module, "MAX_SPINE_VERIFIED_CACHE_EVENTS", 1)
    log = SignedEventLog(tmp_path / "events.jsonl", _id())
    first = log.append("test.first", {"id": "one"})
    log.append("test.second", {"id": "two"})

    assert log._verified_cache_token is None
    assert not log._verified_cache_events
    assert not log._verified_cache_by_id
    assert log.reconcile_append(first.event_id) == first
    assert log._verified_cache_token is None


def test_semantic_index_shapes_are_bounded(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(spine_log_module, "MAX_SPINE_SEMANTIC_INDEX_SHAPES", 1)
    log = SignedEventLog(tmp_path / "events.jsonl", _id())
    log.append_unique(
        "test.first",
        {"id": "one"},
        unique_payload_fields=("id",),
    )
    log.append_unique(
        "test.second",
        {"id": "two"},
        unique_payload_fields=("id",),
    )

    assert len(log._semantic_cache) == 1
    assert next(iter(log._semantic_cache))[0] == "test.second"


def test_cross_process_append_serializes_and_reloads_chain(
    tmp_path: Path,
) -> None:
    path = str(tmp_path / "events.jsonl")
    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    processes = [
        context.Process(
            target=_append_in_process,
            args=(path, index, output),
        )
        for index in range(6)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=30)
        assert process.exitcode == 0

    results = [output.get(timeout=5) for _ in processes]
    assert all(result[0] == "ok" for result in results), results
    assert sorted(result[1] for result in results) == list(range(6))
    log = SignedEventLog(path, _id())
    ok, why = log.verify_chain()
    assert ok, why
    assert len(list(log.read_all())) == 6


def test_cross_process_append_unique_writes_one_semantic_event(
    tmp_path: Path,
) -> None:
    path = str(tmp_path / "events.jsonl")
    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    processes = [
        context.Process(
            target=_append_unique_in_process,
            args=(path, output),
        )
        for _ in range(6)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=30)
        assert process.exitcode == 0

    results = [output.get(timeout=5) for _ in processes]
    assert all(result[0] == "ok" for result in results), results
    assert len({result[1] for result in results}) == 1
    assert sum(result[2] for result in results) == 1
    log = SignedEventLog(path, _id())
    assert len(log.verified_snapshot()) == 1


def test_spine_rejects_oversized_line_without_unbounded_read(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.jsonl"
    path.write_bytes(b"{" + b"x" * MAX_SPINE_LINE_BYTES)

    with pytest.raises(ValueError, match="exceeds byte limit"):
        SignedEventLog(path, _id())


def test_corrupt_line_fails_closed_not_crash(tmp_path: Path) -> None:
    # Corrupt rows must return False rather than crash verification.
    # Keep the original handle to simulate silent tampering while it is open.
    p = tmp_path / "events.jsonl"
    log = SignedEventLog(p, _id())
    log.append("t", {"n": 1})
    log.append("t", {"n": 2})
    line0 = p.read_text(encoding="utf-8").splitlines()[0]

    # Invalid JSON returns False without raising.
    p.write_text(line0 + "\n{not json]\n", encoding="utf-8")
    ok, why = log.verify_chain()
    assert not ok and "unparseable" in why

    # Structurally invalid JSON also returns False.
    _rewrite_line(p, 1, {"seq": 1, "prev_hash": "0" * 64, "type": "t",
                         "payload": "notdict", "author_did": "did:key:zX",
                         "ts_ms": 1, "content_hash": "", "sig": ""})
    ok2, _ = log.verify_chain()
    assert not ok2

    # A new writer refuses to open a corrupt log with a clear error.
    with pytest.raises(ValueError, match="corrupt"):
        SignedEventLog(p, _id())


def test_event_authored_by_other_did_verifies(tmp_path: Path) -> None:
    # Verification uses the author's DID, not the local log owner's key.
    author = _id()
    e = sign_event(
        seq=0, prev_hash=GENESIS_PREV, event_type="t",
        payload={"x": 1}, identity=author, ts_ms=1,
    )
    ok, why = verify_event(e)
    assert ok, why
    assert e.author_did == author.as_did()
    # A modified signature fails verification.
    e.sig = e.sig[:-2] + ("aa" if not e.sig.endswith("aa") else "bb")
    ok2, _ = verify_event(e)
    assert not ok2


def test_projection_folds_event_stream(tmp_path: Path) -> None:
    p = tmp_path / "events.jsonl"
    log = SignedEventLog(p, _id())
    log.append("deposit", {"amount": 10})
    log.append("deposit", {"amount": 5})
    log.append("withdraw", {"amount": 3})

    class Balance(Projection):
        def __init__(self) -> None:
            self.total = 0

        def reset(self) -> None:
            self.total = 0

        def apply(self, ev) -> None:
            if ev.type == "deposit":
                self.total += ev.payload["amount"]
            elif ev.type == "withdraw":
                self.total -= ev.payload["amount"]

    ok, why = log.verify_chain()
    assert ok, why
    bal = Balance()
    replay(log.read_all(), bal)
    assert bal.total == 12
