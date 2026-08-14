import hashlib
import json
import multiprocessing
import os
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

import nth_dao.trade_rules as trade_rules_api
from nth_dao.identity import AgentID, AgentIdentity
from nth_dao.spine import SignedEventLog, SpineEvent
from nth_dao.trade_rules.agreement_conformance import VECTORS_PATH
from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.dispute_statement_fetch_journal import (
    TradeDisputeStatementFetchJournal,
    TradeDisputeStatementFetchJournalCapacity,
    TradeDisputeStatementFetchJournalError,
    TradeDisputeStatementFetchReplayConflict,
)
from nth_dao.trade_rules.dispute_statement_fetch_audit import (
    EVENT_TRADE_DISPUTE_STATEMENT_FETCH_SERVED,
    TradeDisputeStatementFetchAuditError,
    trade_dispute_statement_fetch_audit_payload,
    verify_trade_dispute_statement_fetch_audit_event,
)
from nth_dao.trade_rules.dispute_statement_retrieval import (
    TradeDisputeStatementFetchRequest,
    TradeDisputeStatementFetchResponse,
    create_trade_dispute_statement_fetch_request,
)
from nth_dao.trade_rules.dispute_statement_fetch_service import (
    TradeDisputeStatementFetchCoordinator,
    TradeDisputeStatementFetchInProgress,
    TradeDisputeStatementFetchNotFound,
    TradeDisputeStatementFetchRetryLater,
)
from nth_dao.trade_rules.execution_receipt import TradeExecutionReceipt
from nth_dao.trade_rules.receipt_review import TradeReceiptReview
from nth_dao.trade_rules.transport_common import (
    MAX_TRANSPORT_TIMESTAMP_NS,
    datetime_ns,
    timestamp_ns,
)


def _ns(value: str) -> int:
    moment = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )
    delta = moment - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (
        (delta.days * 86_400 + delta.seconds) * 1_000_000_000
        + delta.microseconds * 1_000
    )


def test_trade_transport_timestamp_range_matches_sqlite_integer():
    assert timestamp_ns(
        "2262-04-11T23:47:16.854775807Z",
        label="at",
        error_type=ValueError,
    ) == MAX_TRANSPORT_TIMESTAMP_NS
    with pytest.raises(ValueError, match="signed 64-bit nanosecond range"):
        timestamp_ns(
            "2262-04-11T23:47:16.854775808Z",
            label="at",
            error_type=ValueError,
        )
    with pytest.raises(ValueError, match="signed 64-bit nanosecond range"):
        datetime_ns(
            datetime(9999, 1, 1, tzinfo=timezone.utc),
            error_type=ValueError,
        )


def _artifacts():
    stored = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    order = TradeOrder.from_dict(stored["order"])
    receipt = TradeExecutionReceipt.from_dict(
        stored["execution_receipt"],
        order=order,
    )
    review = TradeReceiptReview.from_dict(
        stored["disputed_receipt_review"],
        receipt=receipt,
        order=order,
    )
    request = TradeDisputeStatementFetchRequest.from_dict(
        stored["trade_dispute_statement_fetch_request"],
        review=review,
        receipt=receipt,
        order=order,
    )
    response = TradeDisputeStatementFetchResponse.from_dict(
        stored["trade_dispute_statement_fetch_response"],
        request=request,
        review=review,
        receipt=receipt,
        order=order,
    )
    return order, receipt, review, request, response


def _identity(label: bytes) -> AgentIdentity:
    signing_module = pytest.importorskip("nacl.signing")
    signing_key = signing_module.SigningKey(
        hashlib.sha256(label).digest()
    )
    verify_key = signing_key.verify_key.encode()
    return AgentIdentity(
        agent_id=AgentID.from_pubkey(verify_key.hex()),
        label="public-conformance-only",
        _signing_key=signing_key.encode(),
        _verify_key=verify_key,
    )


def _taker_identity() -> AgentIdentity:
    return _identity(b"NTH Trade Agreement v1 taker public seed")


def _maker_identity() -> AgentIdentity:
    return _identity(b"NTH Trade Agreement v1 maker public seed")


def _spine(workspace) -> SignedEventLog:
    return SignedEventLog(workspace / "spine" / "events.jsonl", _maker_identity())


_OWNER_TOKEN = "ab" * 32


def _claim(journal, request, *, at: str = "2026-08-01T02:07:02Z") -> str:
    _record, acquired = journal.claim_processing(
        request,
        owner_token=_OWNER_TOKEN,
        at_ns=_ns(at),
        lease_seconds=300,
    )
    assert acquired
    return _OWNER_TOKEN


class _StatementLookup:
    def __init__(self, value, *, delay=0.0):
        self.value = value
        self.delay = delay
        self.calls = 0
        self._lock = threading.Lock()

    def get(self, statement_digest, **_context):
        if self.delay:
            time.sleep(self.delay)
        with self._lock:
            self.calls += 1
        return self.value


def _claim_process(workspace, start_event, result_queue):
    try:
        start_event.wait(20)
        _order, _receipt, _review, request, _response = _artifacts()
        journal = TradeDisputeStatementFetchJournal(Path(workspace))
        owner = hashlib.sha256(str(os.getpid()).encode("ascii")).hexdigest()
        _record, acquired = journal.claim_processing(
            request,
            owner_token=owner,
            at_ns=_ns("2026-08-01T02:07:02Z"),
            lease_seconds=300,
        )
        result_queue.put(("ok", acquired))
    except Exception as exc:
        result_queue.put(("error", type(exc).__name__, str(exc)))


def _alternate_request(order, receipt, review, request, *, nonce="47" * 16):
    document = request.to_dict()
    return create_trade_dispute_statement_fetch_request(
        _taker_identity(),
        review=review,
        receipt=receipt,
        order=order,
        statement_digest=document["statement_digest"],
        responder_did=document["responder_did"],
        created_at="2026-08-01T02:07:00Z",
        not_after="2026-08-01T02:11:00Z",
        nonce=nonce,
        now=datetime.fromisoformat("2026-08-01T02:07:00+00:00"),
    )


def test_fetch_journal_replays_exact_response_across_restart(tmp_path):
    order, receipt, review, request, response = _artifacts()
    journal = TradeDisputeStatementFetchJournal(tmp_path)

    pending, created = journal.reserve(
        request,
        observed_at_ns=_ns("2026-08-01T02:07:01Z"),
    )
    assert created
    assert not pending.completed
    replay, created = journal.reserve(
        request,
        observed_at_ns=_ns("2026-08-01T02:07:02Z"),
    )
    assert not created
    assert replay == pending
    owner_token = _claim(journal, request)

    completed, created = journal.complete(
        request,
        response,
        owner_token=owner_token,
        updated_at_ns=_ns("2026-08-01T02:08:01Z"),
    )
    assert created
    assert completed.completed
    replayed, created = journal.complete(
        request,
        response,
        owner_token=owner_token,
        updated_at_ns=_ns("2026-08-01T02:08:02Z"),
    )
    assert not created
    assert replayed == completed

    restarted = TradeDisputeStatementFetchJournal(tmp_path)
    retained = restarted.get(
        request.to_dict()["requester_did"],
        request.to_dict()["nonce"],
    )
    assert retained == completed
    resolved_request, resolved_response = retained.resolve(
        review=review,
        receipt=receipt,
        order=order,
    )
    assert resolved_request == request
    assert resolved_response == response


def test_fetch_journal_reserve_is_atomic_under_thread_contention(tmp_path):
    _order, _receipt, _review, request, _response = _artifacts()
    journal = TradeDisputeStatementFetchJournal(tmp_path)

    def reserve_once(_index):
        return journal.reserve(
            request,
            observed_at_ns=_ns("2026-08-01T02:07:01Z"),
        )[1]

    with ThreadPoolExecutor(max_workers=8) as executor:
        created = tuple(executor.map(reserve_once, range(16)))
    assert sum(created) == 1


def test_fetch_journal_processing_lease_rejects_late_owner(tmp_path):
    _order, _receipt, _review, request, response = _artifacts()
    journal = TradeDisputeStatementFetchJournal(tmp_path)
    observed = _ns("2026-08-01T02:07:01Z")
    first_owner = "ab" * 32
    second_owner = "cd" * 32
    journal.reserve(request, observed_at_ns=observed)

    first, acquired = journal.claim_processing(
        request,
        owner_token=first_owner,
        at_ns=observed,
        lease_seconds=1,
    )
    assert acquired
    assert first.processing_owner == first_owner
    retained, acquired = journal.claim_processing(
        request,
        owner_token=second_owner,
        at_ns=observed + 500_000_000,
        lease_seconds=1,
    )
    assert not acquired
    assert retained.processing_owner == first_owner
    taken_over, acquired = journal.claim_processing(
        request,
        owner_token=second_owner,
        at_ns=observed + 1_000_000_000,
        lease_seconds=1,
    )
    assert acquired
    assert taken_over.processing_owner == second_owner
    with pytest.raises(
        TradeDisputeStatementFetchReplayConflict,
        match="does not own",
    ):
        journal.complete(
            request,
            response,
            owner_token=first_owner,
            updated_at_ns=observed + 1_000_000_001,
        )
    completed, created = journal.complete(
        request,
        response,
        owner_token=second_owner,
        updated_at_ns=observed + 1_000_000_001,
    )
    assert created
    assert completed.completed


def test_fetch_journal_processing_lease_is_single_owner_across_processes(tmp_path):
    _order, _receipt, _review, request, _response = _artifacts()
    journal = TradeDisputeStatementFetchJournal(tmp_path)
    journal.reserve(
        request,
        observed_at_ns=_ns("2026-08-01T02:07:01Z"),
    )
    context = multiprocessing.get_context("spawn")
    start_event = context.Event()
    result_queue = context.Queue()
    processes = tuple(
        context.Process(
            target=_claim_process,
            args=(str(tmp_path), start_event, result_queue),
        )
        for _index in range(6)
    )
    for process in processes:
        process.start()
    start_event.set()
    results = tuple(result_queue.get(timeout=45) for _process in processes)
    for process in processes:
        process.join(timeout=45)
        assert process.exitcode == 0
    result_queue.close()
    result_queue.join_thread()
    assert all(result[0] == "ok" for result in results), results
    assert sum(bool(result[1]) for result in results) == 1


def test_fetch_journal_limits_pending_records_per_requester(tmp_path):
    order, receipt, review, request, _response = _artifacts()
    journal = TradeDisputeStatementFetchJournal(
        tmp_path,
        max_records=10,
        max_records_per_requester=10,
        max_pending_per_requester=1,
    )
    journal.reserve(request, observed_at_ns=_ns("2026-08-01T02:07:01Z"))
    second = _alternate_request(
        order,
        receipt,
        review,
        request,
        nonce="49" * 16,
    )
    with pytest.raises(
        TradeDisputeStatementFetchJournalCapacity,
        match="max pending fetch records for requester exceeded",
    ):
        journal.reserve(
            second,
            observed_at_ns=_ns("2026-08-01T02:07:02Z"),
        )


def test_fetch_journal_rejects_nonce_rebinding_and_unreserved_completion(tmp_path):
    order, receipt, review, request, response = _artifacts()
    journal = TradeDisputeStatementFetchJournal(tmp_path / "reserved")
    journal.reserve(request, observed_at_ns=_ns("2026-08-01T02:07:01Z"))
    rebound = _alternate_request(order, receipt, review, request)

    with pytest.raises(
        TradeDisputeStatementFetchReplayConflict,
        match="nonce was rebound",
    ):
        journal.reserve(
            rebound,
            observed_at_ns=_ns("2026-08-01T02:07:02Z"),
        )

    empty = TradeDisputeStatementFetchJournal(tmp_path / "unreserved")
    with pytest.raises(
        TradeDisputeStatementFetchReplayConflict,
        match="was not reserved",
    ):
        empty.complete(
            request,
            response,
            owner_token=_OWNER_TOKEN,
            updated_at_ns=_ns("2026-08-01T02:08:01Z"),
        )


def test_fetch_journal_capacity_failure_keeps_pending_record(tmp_path):
    _order, _receipt, _review, request, response = _artifacts()
    maximum = len(request.canonical_bytes) + len(response.canonical_bytes) - 1
    journal = TradeDisputeStatementFetchJournal(tmp_path, max_bytes=maximum)
    journal.reserve(request, observed_at_ns=_ns("2026-08-01T02:07:01Z"))
    owner_token = _claim(journal, request)

    with pytest.raises(
        TradeDisputeStatementFetchJournalCapacity,
        match="max fetch journal bytes exceeded",
    ):
        journal.complete(
            request,
            response,
            owner_token=owner_token,
            updated_at_ns=_ns("2026-08-01T02:08:01Z"),
        )
    retained = journal.get(
        request.to_dict()["requester_did"],
        request.to_dict()["nonce"],
    )
    assert retained is not None
    assert not retained.completed


def test_fetch_journal_record_capacity_is_atomic(tmp_path):
    order, receipt, review, request, _response = _artifacts()
    journal = TradeDisputeStatementFetchJournal(tmp_path, max_records=1)
    journal.reserve(request, observed_at_ns=_ns("2026-08-01T02:07:01Z"))
    second = _alternate_request(
        order,
        receipt,
        review,
        request,
        nonce="48" * 16,
    )

    with pytest.raises(
        TradeDisputeStatementFetchJournalCapacity,
        match="max fetch journal records exceeded",
    ):
        journal.reserve(
            second,
            observed_at_ns=_ns("2026-08-01T02:07:02Z"),
        )
    assert journal.get(
        second.to_dict()["requester_did"],
        second.to_dict()["nonce"],
    ) is None


def test_fetch_journal_purges_only_after_expiry_plus_clock_skew(tmp_path):
    _order, _receipt, _review, request, _response = _artifacts()
    journal = TradeDisputeStatementFetchJournal(tmp_path)
    journal.reserve(request, observed_at_ns=_ns("2026-08-01T02:07:01Z"))

    assert journal.purge_ineligible_replays(
        at_ns=_ns("2026-08-01T02:17:00Z"),
        clock_skew_seconds=300,
    ) == ()
    assert journal.purge_ineligible_replays(
        at_ns=_ns("2026-08-01T02:17:01Z"),
        clock_skew_seconds=300,
    ) == (request.to_dict()["request_id"],)
    assert journal.get(
        request.to_dict()["requester_did"],
        request.to_dict()["nonce"],
    ) is None


def test_fetch_journal_does_not_purge_an_active_processing_lease(tmp_path):
    _order, _receipt, _review, request, _response = _artifacts()
    journal = TradeDisputeStatementFetchJournal(tmp_path)
    observed = _ns("2026-08-01T02:07:01Z")
    journal.reserve(request, observed_at_ns=observed)
    journal.claim_processing(
        request,
        owner_token=_OWNER_TOKEN,
        at_ns=observed,
        lease_seconds=1_000,
    )

    purge_at = _ns("2026-08-01T02:17:01Z")
    assert journal.purge_ineligible_replays(
        at_ns=purge_at,
        clock_skew_seconds=300,
    ) == ()
    assert journal.purge_ineligible_replays(
        at_ns=observed + 1_000_000_000_001,
        clock_skew_seconds=300,
    ) == (request.to_dict()["request_id"],)


def test_fetch_journal_detects_retained_digest_tamper(tmp_path):
    _order, _receipt, _review, request, _response = _artifacts()
    journal = TradeDisputeStatementFetchJournal(tmp_path)
    journal.reserve(request, observed_at_ns=_ns("2026-08-01T02:07:01Z"))
    with sqlite3.connect(journal.path) as connection:
        connection.execute(
            "UPDATE fetch_replay SET request_digest = ?",
            ("sha256:" + ("0" * 64),),
        )

    with pytest.raises(
        TradeDisputeStatementFetchJournalError,
        match="request digest is inconsistent",
    ):
        journal.get(
            request.to_dict()["requester_did"],
            request.to_dict()["nonce"],
        )


def test_fetch_journal_rejects_schema_with_matching_columns_but_no_checks(tmp_path):
    root = tmp_path / "trade"
    root.mkdir()
    path = root / "dispute_statement_fetch_journal_v1.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE fetch_replay (
                requester_did TEXT NOT NULL,
                nonce TEXT NOT NULL,
                request_id TEXT NOT NULL UNIQUE,
                request_digest TEXT NOT NULL,
                request_bytes BLOB NOT NULL,
                response_digest TEXT,
                response_bytes BLOB,
                audit_event_id TEXT,
                processing_owner TEXT,
                lease_until_ns INTEGER,
                next_retry_at_ns INTEGER NOT NULL,
                attempt_count INTEGER NOT NULL,
                observed_at_ns INTEGER NOT NULL,
                updated_at_ns INTEGER NOT NULL,
                not_after_ns INTEGER NOT NULL,
                total_bytes INTEGER NOT NULL,
                PRIMARY KEY (requester_did, nonce)
            ) WITHOUT ROWID;
            PRAGMA user_version = 1;
            """
        )

    with pytest.raises(
        TradeDisputeStatementFetchJournalError,
        match="does not enforce response field pairing",
    ):
        TradeDisputeStatementFetchJournal(tmp_path)


def test_fetch_journal_rejects_linked_trade_directory(tmp_path):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    try:
        (workspace / "trade").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    with pytest.raises(
        TradeDisputeStatementFetchJournalError,
        match="must not contain links",
    ):
        TradeDisputeStatementFetchJournal(workspace)


def test_fetch_journal_is_public_trade_rule_api():
    assert trade_rules_api.TradeDisputeStatementFetchJournal is (
        TradeDisputeStatementFetchJournal
    )
    assert trade_rules_api.TradeDisputeStatementFetchReplayConflict is (
        TradeDisputeStatementFetchReplayConflict
    )
    assert trade_rules_api.TradeDisputeStatementFetchCoordinator is (
        TradeDisputeStatementFetchCoordinator
    )
    assert trade_rules_api.TradeDisputeStatementFetchNotFound is (
        TradeDisputeStatementFetchNotFound
    )
    assert trade_rules_api.TradeDisputeStatementFetchInProgress is (
        TradeDisputeStatementFetchInProgress
    )
    assert trade_rules_api.TradeDisputeStatementFetchRetryLater is (
        TradeDisputeStatementFetchRetryLater
    )
    assert (
        trade_rules_api.EVENT_TRADE_DISPUTE_STATEMENT_FETCH_SERVED
        == EVENT_TRADE_DISPUTE_STATEMENT_FETCH_SERVED
    )
    assert trade_rules_api.TradeDisputeStatementFetchAuditError is (
        TradeDisputeStatementFetchAuditError
    )


def test_fetch_coordinator_matches_public_vector_and_replays_without_lookup(
    tmp_path,
):
    order, receipt, review, request, expected_response = _artifacts()
    lookup = _StatementLookup(expected_response.statement.to_dict())
    journal = TradeDisputeStatementFetchJournal(tmp_path)
    coordinator = TradeDisputeStatementFetchCoordinator(
        journal,
        lookup,
        responder_identity=_maker_identity(),
        spine=_spine(tmp_path),
        package_resolver=None,
    )

    result = coordinator.receive(
        request,
        review=review,
        receipt=receipt,
        order=order,
        at=datetime.fromisoformat("2026-08-01T02:08:00+00:00"),
    )
    assert not result.replayed
    assert result.response == expected_response
    assert result.audit_event_id
    assert lookup.calls == 1

    restarted_spine = _spine(tmp_path)

    def reject_duplicate_append(*_args, **_kwargs):
        raise AssertionError("an audited replay must not append another event")

    restarted_spine.append_unique = reject_duplicate_append
    restarted = TradeDisputeStatementFetchCoordinator(
        TradeDisputeStatementFetchJournal(tmp_path),
        lookup,
        responder_identity=_maker_identity(),
        spine=restarted_spine,
        package_resolver=None,
    )
    replay = restarted.receive(
        request,
        review=review,
        receipt=receipt,
        order=order,
        at=datetime.fromisoformat("2026-08-01T02:09:00+00:00"),
    )
    assert replay.replayed
    assert replay.response == expected_response
    assert replay.audit_event_id == result.audit_event_id
    assert lookup.calls == 1

    def reject_cached_rescan(*_args, **_kwargs):
        raise AssertionError("an unchanged verified Spine must use the audit cache")

    restarted_spine.reconcile_append = reject_cached_rescan
    cached_replay = restarted.receive(
        request,
        review=review,
        receipt=receipt,
        order=order,
        at=datetime.fromisoformat("2026-08-01T02:09:01+00:00"),
    )
    assert cached_replay.replayed
    assert cached_replay.audit_event_id == result.audit_event_id


def test_fetch_coordinator_recovers_response_after_spine_failure(tmp_path):
    order, receipt, review, request, expected_response = _artifacts()
    lookup = _StatementLookup(expected_response.statement.to_dict())
    journal = TradeDisputeStatementFetchJournal(tmp_path)
    spine = _spine(tmp_path)
    append_unique = spine.append_unique
    failures = [1]

    def fail_once(*args, **kwargs):
        if failures[0]:
            failures[0] -= 1
            raise OSError("simulated Spine outage")
        return append_unique(*args, **kwargs)

    spine.append_unique = fail_once
    coordinator = TradeDisputeStatementFetchCoordinator(
        journal,
        lookup,
        responder_identity=_maker_identity(),
        spine=spine,
        package_resolver=None,
    )
    at = datetime.fromisoformat("2026-08-01T02:08:00+00:00")
    with pytest.raises(
        TradeDisputeStatementFetchAuditError,
        match="unable to append",
    ):
        coordinator.receive(
            request,
            review=review,
            receipt=receipt,
            order=order,
            at=at,
        )
    retained = journal.get(
        request.to_dict()["requester_did"],
        request.to_dict()["nonce"],
    )
    assert retained is not None
    assert retained.completed
    assert retained.audit_event_id is None
    assert journal.purge_ineligible_replays(
        at_ns=_ns("2026-08-01T02:17:01Z"),
        clock_skew_seconds=300,
    ) == ()

    recovered = coordinator.receive(
        request,
        review=review,
        receipt=receipt,
        order=order,
        at=datetime.fromisoformat("2026-08-01T02:09:00+00:00"),
    )
    assert recovered.replayed
    assert lookup.calls == 1
    repaired = journal.get(
        request.to_dict()["requester_did"],
        request.to_dict()["nonce"],
    )
    assert repaired is not None
    assert repaired.audit_event_id == recovered.audit_event_id
    events = spine.verified_snapshot()
    assert len(events) == 1
    assert events[0].type == EVENT_TRADE_DISPUTE_STATEMENT_FETCH_SERVED
    ok, reason = verify_trade_dispute_statement_fetch_audit_event(
        events[0],
        request,
        recovered.response,
        review=review,
        receipt=receipt,
        order=order,
    )
    assert ok, reason


def test_fetch_audit_rejects_payload_tamper_and_foreign_signer(tmp_path):
    order, receipt, review, request, expected_response = _artifacts()
    spine = _spine(tmp_path)
    coordinator = TradeDisputeStatementFetchCoordinator(
        TradeDisputeStatementFetchJournal(tmp_path),
        _StatementLookup(expected_response.statement.to_dict()),
        responder_identity=_maker_identity(),
        spine=spine,
        package_resolver=None,
    )
    result = coordinator.receive(
        request,
        review=review,
        receipt=receipt,
        order=order,
        at=datetime.fromisoformat("2026-08-01T02:08:00+00:00"),
    )
    event = spine.verified_snapshot()[0]
    tampered_document = json.loads(json.dumps(event.to_dict()))
    tampered_document["payload"]["status"] = "settled"
    tampered = SpineEvent.from_dict(tampered_document)
    ok, _reason = verify_trade_dispute_statement_fetch_audit_event(
        tampered,
        request,
        result.response,
        review=review,
        receipt=receipt,
        order=order,
    )
    assert not ok

    foreign_spine = SignedEventLog(
        tmp_path / "foreign" / "events.jsonl",
        _taker_identity(),
    )
    foreign_event, _created = foreign_spine.append_unique(
        event.type,
        event.payload,
        unique_payload_fields=("request_digest",),
        ts_ms=event.ts_ms,
    )
    ok, reason = verify_trade_dispute_statement_fetch_audit_event(
        foreign_event,
        request,
        result.response,
        review=review,
        receipt=receipt,
        order=order,
    )
    assert not ok
    assert "unauthorized" in reason


def test_fetch_journal_rejects_valid_audit_event_from_another_spine(tmp_path):
    order, receipt, review, request, response = _artifacts()
    journal = TradeDisputeStatementFetchJournal(tmp_path)
    journal.reserve(
        request,
        observed_at_ns=_ns("2026-08-01T02:07:01Z"),
    )
    owner_token = _claim(journal, request)
    journal.complete(
        request,
        response,
        owner_token=owner_token,
        updated_at_ns=_ns("2026-08-01T02:08:00Z"),
    )
    payload = trade_dispute_statement_fetch_audit_payload(
        request,
        response,
        review=review,
        receipt=receipt,
        order=order,
    )
    other_spine = SignedEventLog(
        tmp_path / "other-spine" / "events.jsonl",
        _maker_identity(),
    )
    event, _created = other_spine.append_unique(
        EVENT_TRADE_DISPUTE_STATEMENT_FETCH_SERVED,
        payload,
        unique_payload_fields=("request_digest",),
        ts_ms=_ns(payload["served_at"]) // 1_000_000,
    )

    with pytest.raises(
        TradeDisputeStatementFetchJournalError,
        match="not persisted in the supplied Spine",
    ):
        journal.mark_audited(
            request,
            response,
            audit_event=event,
            spine=_spine(tmp_path),
            review=review,
            receipt=receipt,
            order=order,
            updated_at_ns=_ns("2026-08-01T02:08:01Z"),
        )
    assert journal.purge_ineligible_replays(
        at_ns=_ns("2026-08-01T02:17:01Z"),
        clock_skew_seconds=300,
    ) == ()


def test_fetch_coordinator_recovers_pending_request_when_statement_appears(tmp_path):
    order, receipt, review, request, expected_response = _artifacts()
    lookup = _StatementLookup(None)
    journal = TradeDisputeStatementFetchJournal(tmp_path)
    processing_now = [_ns("2026-08-01T02:08:00Z")]
    coordinator = TradeDisputeStatementFetchCoordinator(
        journal,
        lookup,
        responder_identity=_maker_identity(),
        spine=_spine(tmp_path),
        package_resolver=None,
        retry_backoff_seconds=0.01,
        processing_clock_ns=lambda: processing_now[0],
    )
    at = datetime.fromisoformat("2026-08-01T02:08:00+00:00")

    with pytest.raises(
        TradeDisputeStatementFetchNotFound,
        match="is not retained",
    ):
        coordinator.receive(
            request,
            review=review,
            receipt=receipt,
            order=order,
            at=at,
        )
    pending = journal.get(
        request.to_dict()["requester_did"],
        request.to_dict()["nonce"],
    )
    assert pending is not None
    assert not pending.completed
    assert lookup.calls == 1

    lookup.value = expected_response.statement.to_dict()
    with pytest.raises(
        TradeDisputeStatementFetchRetryLater,
        match="temporarily rate limited",
    ):
        coordinator.receive(
            request,
            review=review,
            receipt=receipt,
            order=order,
            at=at,
        )
    assert lookup.calls == 1
    processing_now[0] += 11_000_000
    recovered = coordinator.receive(
        request,
        review=review,
        receipt=receipt,
        order=order,
        at=at,
    )
    assert not recovered.replayed
    assert recovered.response == expected_response
    assert lookup.calls == 2


def test_fetch_coordinator_preserves_root_error_when_lease_release_fails(
    tmp_path,
):
    order, receipt, review, request, _expected_response = _artifacts()

    class FailingLookup:
        @staticmethod
        def get(*_args, **_kwargs):
            raise LookupError("primary lookup failure")

    journal = TradeDisputeStatementFetchJournal(tmp_path)

    def fail_release(*_args, **_kwargs):
        raise TradeDisputeStatementFetchReplayConflict(
            "simulated ownership change"
        )

    journal.release_processing = fail_release
    coordinator = TradeDisputeStatementFetchCoordinator(
        journal,
        FailingLookup(),
        responder_identity=_maker_identity(),
        spine=_spine(tmp_path),
        package_resolver=None,
    )
    with pytest.raises(LookupError, match="primary lookup failure"):
        coordinator.receive(
            request,
            review=review,
            receipt=receipt,
            order=order,
            at=datetime.fromisoformat("2026-08-01T02:08:00+00:00"),
        )


def test_fetch_coordinator_converges_concurrent_identical_requests(tmp_path):
    order, receipt, review, request, expected_response = _artifacts()
    lookup = _StatementLookup(expected_response.statement.to_dict(), delay=0.03)
    coordinator = TradeDisputeStatementFetchCoordinator(
        TradeDisputeStatementFetchJournal(tmp_path),
        lookup,
        responder_identity=_maker_identity(),
        spine=_spine(tmp_path),
        package_resolver=None,
    )
    at = datetime.fromisoformat("2026-08-01T02:08:00+00:00")

    def receive_once(_index):
        return coordinator.receive(
            request,
            review=review,
            receipt=receipt,
            order=order,
            at=at,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = tuple(executor.map(receive_once, range(12)))
    assert all(result.response == expected_response for result in results)
    assert sum(not result.replayed for result in results) == 1
    assert lookup.calls == 1


def test_fetch_verification_cache_rejects_changed_input_snapshot(
    tmp_path,
    monkeypatch,
):
    order, receipt, review, request, expected_response = _artifacts()
    coordinator = TradeDisputeStatementFetchCoordinator(
        TradeDisputeStatementFetchJournal(tmp_path),
        _StatementLookup(expected_response.statement.to_dict()),
        responder_identity=_maker_identity(),
        spine=_spine(tmp_path),
        package_resolver=None,
    )
    original = coordinator._verify_inputs_uncached

    def changed_snapshot(*args, **kwargs):
        verified = original(*args, **kwargs)
        return replace(
            verified,
            cache_key=("0" * 64, *verified.cache_key[1:]),
        )

    monkeypatch.setattr(coordinator, "_verify_inputs_uncached", changed_snapshot)
    with pytest.raises(ValueError, match="changed during verification"):
        coordinator.receive(
            request,
            review=review,
            receipt=receipt,
            order=order,
            at=datetime.fromisoformat("2026-08-01T02:08:00+00:00"),
        )
    assert not coordinator._verification_cache


def test_fetch_coordinator_caches_are_bounded(tmp_path):
    order, receipt, review, request, expected_response = _artifacts()
    coordinator = TradeDisputeStatementFetchCoordinator(
        TradeDisputeStatementFetchJournal(tmp_path),
        _StatementLookup(expected_response.statement.to_dict()),
        responder_identity=_maker_identity(),
        spine=_spine(tmp_path),
        package_resolver=None,
        verification_cache_entries=1,
    )
    alternate = _alternate_request(
        order,
        receipt,
        review,
        request,
        nonce="49" * 16,
    )
    at = datetime.fromisoformat("2026-08-01T02:08:00+00:00")

    for candidate in (request, alternate):
        coordinator.receive(
            candidate,
            review=review,
            receipt=receipt,
            order=order,
            at=at,
        )

    assert len(coordinator._verification_cache) == 1
    assert len(coordinator._response_cache) == 1
    assert len(coordinator._audit_cache) == 1


def test_fetch_coordinator_rejects_expired_request_before_reservation(tmp_path):
    order, receipt, review, request, expected_response = _artifacts()
    journal = TradeDisputeStatementFetchJournal(tmp_path)
    coordinator = TradeDisputeStatementFetchCoordinator(
        journal,
        _StatementLookup(expected_response.statement.to_dict()),
        responder_identity=_maker_identity(),
        spine=_spine(tmp_path),
        package_resolver=None,
        clock_skew_seconds=0,
    )

    with pytest.raises(ValueError, match="outside its signed lifetime"):
        coordinator.receive(
            request,
            review=review,
            receipt=receipt,
            order=order,
            at=datetime.fromisoformat("2026-08-01T02:12:01+00:00"),
        )
    assert journal.get(
        request.to_dict()["requester_did"],
        request.to_dict()["nonce"],
    ) is None


def test_fetch_coordinator_caps_policy_and_never_backdates_served_at(tmp_path):
    order, receipt, review, request, expected_response = _artifacts()
    lookup = _StatementLookup(expected_response.statement.to_dict())
    with pytest.raises(ValueError, match="not greater than 86400"):
        TradeDisputeStatementFetchCoordinator(
            TradeDisputeStatementFetchJournal(tmp_path / "invalid"),
            lookup,
            responder_identity=_maker_identity(),
            spine=_spine(tmp_path / "invalid"),
            package_resolver=None,
            max_ttl_seconds=86_401,
        )
    with pytest.raises(ValueError, match="retry_backoff_seconds must be greater"):
        TradeDisputeStatementFetchCoordinator(
            TradeDisputeStatementFetchJournal(tmp_path / "zero-retry"),
            lookup,
            responder_identity=_maker_identity(),
            spine=_spine(tmp_path / "zero-retry"),
            package_resolver=None,
            retry_backoff_seconds=0,
        )

    coordinator = TradeDisputeStatementFetchCoordinator(
        TradeDisputeStatementFetchJournal(tmp_path / "rounding"),
        lookup,
        responder_identity=_maker_identity(),
        spine=_spine(tmp_path / "rounding"),
        package_resolver=None,
        clock_skew_seconds=0,
    )
    observed = datetime.fromisoformat("2026-08-01T02:08:00.000999+00:00")
    result = coordinator.receive(
        request,
        review=review,
        receipt=receipt,
        order=order,
        at=observed,
    )
    served_at = datetime.fromisoformat(
        result.response.to_dict()["served_at"].replace("Z", "+00:00")
    )
    assert served_at == observed
