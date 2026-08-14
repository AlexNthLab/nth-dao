from __future__ import annotations

import copy
import sqlite3

import pytest

import nth_dao.trade_rules as trade_rules_api
from nth_dao.identity import AgentIdentity
from nth_dao.spine import GENESIS_PREV, SignedEventLog, sign_event
from nth_dao.trade_rules.agreement_conformance import generate_vectors
from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.dispute_statement import (
    TradeDisputeStatement,
    TradeDisputeStatementRejected,
)
from nth_dao.trade_rules.dispute_statement_audit import (
    EVENT_TRADE_DISPUTE_STATEMENT_RETAINED,
    TRADE_DISPUTE_STATEMENT_ASSERTION_STATUS,
    TradeDisputeStatementAuditCoordinator,
    TradeDisputeStatementAuditError,
    trade_dispute_statement_audit_payload,
    validate_trade_dispute_statement_audit_binding,
    validate_trade_dispute_statement_audit_event,
    validate_trade_dispute_statement_audit_payload,
)
from nth_dao.trade_rules.dispute_statement_store import (
    TradeDisputeStatementStore,
)
from nth_dao.trade_rules.execution_receipt import TradeExecutionReceipt
from nth_dao.trade_rules.package_store import build_rule_package
from nth_dao.trade_rules.receipt_review import TradeReceiptReview


class _PackageResolver:
    def __init__(self, package):
        self.package = package

    def load(self, digest):
        return self.package if digest == self.package.digest else None


@pytest.fixture(scope="module")
def dispute_artifacts():
    vectors = generate_vectors()
    order = TradeOrder.from_dict(vectors["order"])
    receipt = TradeExecutionReceipt.from_dict(
        vectors["execution_receipt"],
        order=order,
    )
    review = TradeReceiptReview.from_dict(
        vectors["disputed_receipt_review"],
        receipt=receipt,
        order=order,
    )
    package = vectors["rule_package"]
    resolver = _PackageResolver(
        build_rule_package(
            package["manifest"],
            {
                item["digest"]: bytes.fromhex(item["bytes_hex"])
                for item in package["resources"]
            },
        )
    )
    statement = TradeDisputeStatement.from_dict(
        vectors["trade_dispute_statement"],
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )
    return statement, review, receipt, order, resolver


def test_dispute_statement_audit_payload_is_an_exact_claim_binding(
    dispute_artifacts,
):
    statement, review, receipt, order, resolver = dispute_artifacts
    payload = trade_dispute_statement_audit_payload(statement)

    assert payload["assertion_status"] == (TRADE_DISPUTE_STATEMENT_ASSERTION_STATUS)
    assert (
        validate_trade_dispute_statement_audit_binding(
            payload,
            statement=statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
        )
        == payload
    )

    tampered = {**payload, "author_role": "taker"}
    with pytest.raises(
        TradeDisputeStatementAuditError,
        match="does not bind",
    ):
        validate_trade_dispute_statement_audit_binding(
            tampered,
            statement=statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("protocol_version", "2", "version"),
        ("statement_id", "invalid", "statement_id"),
        ("statement_digest", "sha256:BAD", "statement_digest"),
        ("author_did", "did:key:invalid", "author_did"),
        ("author_role", "arbitrator", "author_role"),
        ("statement_type", "verdict", "statement_type"),
        ("created_at", "2026-02-30T00:00:00Z", "created_at"),
        ("assertion_status", "verified-fact", "assertion_status"),
    ],
)
def test_dispute_statement_audit_payload_rejects_invalid_values(
    dispute_artifacts,
    field,
    value,
    message,
):
    statement, _review, _receipt, _order, _resolver = dispute_artifacts
    payload = copy.deepcopy(trade_dispute_statement_audit_payload(statement))
    payload[field] = value

    with pytest.raises(TradeDisputeStatementAuditError, match=message):
        validate_trade_dispute_statement_audit_payload(payload)


def test_dispute_statement_audit_payload_has_a_closed_shape(
    dispute_artifacts,
):
    statement, _review, _receipt, _order, _resolver = dispute_artifacts
    payload = trade_dispute_statement_audit_payload(statement)
    payload["truth"] = True

    with pytest.raises(
        TradeDisputeStatementAuditError,
        match="missing or unknown fields",
    ):
        validate_trade_dispute_statement_audit_payload(payload)


def _coordinator(tmp_path):
    return TradeDisputeStatementAuditCoordinator(
        store=TradeDisputeStatementStore(tmp_path),
        spine=SignedEventLog(
            tmp_path / "spine.jsonl",
            AgentIdentity.generate(label="dispute-auditor"),
        ),
    )


def test_dispute_statement_coordinator_is_durable_and_idempotent(
    tmp_path,
    dispute_artifacts,
):
    statement, review, receipt, order, resolver = dispute_artifacts
    coordinator = _coordinator(tmp_path)
    arguments = {
        "review": review,
        "receipt": receipt,
        "order": order,
        "package_resolver": resolver,
        "observed_at_ms": 1_786_000_000_000,
    }

    first = coordinator.record(statement, **arguments)
    second = coordinator.record(statement, **arguments)

    assert first.store_created is True
    assert first.anchor_created is True
    assert second.store_created is False
    assert second.anchor_created is False
    assert second.event.event_id == first.event.event_id
    assert first.event.type == EVENT_TRADE_DISPUTE_STATEMENT_RETAINED
    assert first.event.payload["assertion_status"] == ("signed-claim-not-adjudicated")
    assert len(coordinator.spine.verified_snapshot()) == 1
    assert (
        validate_trade_dispute_statement_audit_event(
            first.event,
            expected_author_did=coordinator.spine.signer_did,
            statement=statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
        )
        == first.event.payload
    )


def test_dispute_statement_audit_event_rejects_valid_early_signature(
    dispute_artifacts,
):
    statement, review, receipt, order, resolver = dispute_artifacts
    auditor = AgentIdentity.generate(label="early-auditor")
    event = sign_event(
        seq=0,
        prev_hash=GENESIS_PREV,
        event_type=EVENT_TRADE_DISPUTE_STATEMENT_RETAINED,
        payload=trade_dispute_statement_audit_payload(statement),
        identity=auditor,
        ts_ms=1,
    )

    with pytest.raises(
        TradeDisputeStatementAuditError,
        match="observation time is invalid.*too far in the future",
    ):
        validate_trade_dispute_statement_audit_event(
            event,
            expected_author_did=auditor.as_did(),
            statement=statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
            clock_skew_seconds=0,
        )


def test_dispute_statement_audit_event_rejects_unexpected_author(
    dispute_artifacts,
):
    statement, review, receipt, order, resolver = dispute_artifacts
    auditor = AgentIdentity.generate(label="authorized-auditor")
    event = sign_event(
        seq=0,
        prev_hash=GENESIS_PREV,
        event_type=EVENT_TRADE_DISPUTE_STATEMENT_RETAINED,
        payload=trade_dispute_statement_audit_payload(statement),
        identity=AgentIdentity.generate(label="unrelated-auditor"),
        ts_ms=1_786_000_000_000,
    )

    with pytest.raises(
        TradeDisputeStatementAuditError,
        match="author is not authorized",
    ):
        validate_trade_dispute_statement_audit_event(
            event,
            expected_author_did=auditor.as_did(),
            statement=statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
        )


def test_dispute_statement_coordinator_rejects_foreign_existing_anchor(
    tmp_path,
    dispute_artifacts,
):
    statement, review, receipt, order, resolver = dispute_artifacts
    spine_path = tmp_path / "spine.jsonl"
    attacker = SignedEventLog(
        spine_path,
        AgentIdentity.generate(label="foreign-auditor"),
    )
    attacker.append(
        EVENT_TRADE_DISPUTE_STATEMENT_RETAINED,
        trade_dispute_statement_audit_payload(statement),
        ts_ms=1_786_000_000_000,
    )
    receiver_spine = SignedEventLog(
        spine_path,
        AgentIdentity.generate(label="receiver-auditor"),
    )
    coordinator = TradeDisputeStatementAuditCoordinator(
        store=TradeDisputeStatementStore(tmp_path),
        spine=receiver_spine,
    )

    with pytest.raises(
        TradeDisputeStatementAuditError,
        match="signed by an unauthorized DID",
    ):
        coordinator.record(
            statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
            observed_at_ms=1_786_000_000_000,
        )


def test_dispute_statement_coordinator_recovers_after_spine_failure(
    tmp_path,
    dispute_artifacts,
    monkeypatch,
):
    statement, review, receipt, order, resolver = dispute_artifacts
    coordinator = _coordinator(tmp_path)
    digest_value = trade_dispute_statement_audit_payload(statement)["statement_digest"]
    real_append = coordinator.spine.append_unique

    def fail_append(*_args, **_kwargs):
        raise OSError("simulated audit outage")

    monkeypatch.setattr(coordinator.spine, "append_unique", fail_append)
    with pytest.raises(
        TradeDisputeStatementAuditError,
        match="unable to project",
    ):
        coordinator.record(
            statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
            observed_at_ms=1_786_000_000_000,
        )
    assert len(list(coordinator.store.root.glob("*.json"))) == 1
    assert coordinator.spine.verified_snapshot() == ()

    monkeypatch.setattr(coordinator.spine, "append_unique", real_append)
    recovered = coordinator.reconcile_one(
        digest_value,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
        observed_at_ms=1_786_000_001_000,
    )
    assert recovered.store_created is False
    assert recovered.anchor_created is True
    assert len(coordinator.spine.verified_snapshot()) == 1


def test_dispute_statement_coordinator_reconciles_review_page(
    tmp_path,
    dispute_artifacts,
    monkeypatch,
):
    statement, review, receipt, order, resolver = dispute_artifacts
    coordinator = _coordinator(tmp_path)
    real_append = coordinator.spine.append_unique

    monkeypatch.setattr(
        coordinator.spine,
        "append_unique",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")),
    )
    with pytest.raises(TradeDisputeStatementAuditError):
        coordinator.record(
            statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
            observed_at_ms=1_786_000_000_000,
        )
    monkeypatch.setattr(coordinator.spine, "append_unique", real_append)

    recovered = coordinator.reconcile_review(
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
        observed_at_ms=1_786_000_001_000,
    )
    verified = coordinator.reconcile_review(
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
        observed_at_ms=1_786_000_002_000,
    )

    assert recovered.scanned == 1
    assert recovered.anchored == 1
    assert recovered.verified_anchored == 0
    assert recovered.failed == 0
    assert recovered.has_more is False
    assert recovered.next_cursor is None
    assert verified.scanned == 1
    assert verified.anchored == 0
    assert verified.verified_anchored == 1
    assert verified.failed == 0
    assert len(coordinator.spine.verified_snapshot()) == 1


def test_dispute_statement_outbox_recovers_prepare_before_store_failure(
    tmp_path,
    dispute_artifacts,
    monkeypatch,
):
    statement, review, receipt, order, resolver = dispute_artifacts
    coordinator = _coordinator(tmp_path)
    real_put = coordinator.store.put
    monkeypatch.setattr(
        coordinator.store,
        "put",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("injected Store outage after outbox prepare")
        ),
    )

    with pytest.raises(OSError, match="Store outage"):
        coordinator.record(
            statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
            observed_at_ms=1_786_000_000_000,
        )
    pending, has_more = coordinator.audit_outbox.pending()
    assert len(pending) == 1
    assert has_more is False
    assert coordinator.spine.verified_snapshot() == ()
    assert list(coordinator.store.root.glob("*.json")) == []

    monkeypatch.setattr(coordinator.store, "put", real_put)
    restarted = TradeDisputeStatementAuditCoordinator(
        store=coordinator.store,
        spine=coordinator.spine,
    )
    recovered = restarted.reconcile(package_resolver=resolver)

    assert recovered.scanned == 1
    assert recovered.anchored == 1
    assert recovered.failed == 0
    assert restarted.audit_outbox.pending()[0] == ()
    assert len(restarted.spine.verified_snapshot()) == 1


def test_dispute_statement_outbox_tamper_never_anchors(
    tmp_path,
    dispute_artifacts,
    monkeypatch,
):
    statement, review, receipt, order, resolver = dispute_artifacts
    coordinator = _coordinator(tmp_path)
    monkeypatch.setattr(
        coordinator.store,
        "put",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")),
    )
    with pytest.raises(OSError):
        coordinator.record(
            statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
            observed_at_ms=1_786_000_000_000,
        )
    with sqlite3.connect(coordinator.audit_outbox.path) as connection:
        connection.execute(
            "UPDATE pending SET statement_bytes = ?",
            (b'{"tampered":true}',),
        )

    with pytest.raises(
        trade_rules_api.TradeDisputeStatementAuditOutboxError,
        match="byte accounting",
    ):
        coordinator.reconcile(package_resolver=resolver)

    assert coordinator.spine.verified_snapshot() == ()
    with sqlite3.connect(coordinator.audit_outbox.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM pending").fetchone()[0] == 1


def test_dispute_statement_outbox_rejects_unknown_future_schema(tmp_path):
    coordinator = _coordinator(tmp_path)
    with sqlite3.connect(coordinator.audit_outbox.path) as connection:
        connection.execute("PRAGMA user_version = 999")

    with pytest.raises(
        trade_rules_api.TradeDisputeStatementAuditOutboxError,
        match="schema is unsupported",
    ):
        trade_rules_api.TradeDisputeStatementAuditOutbox(tmp_path)


def test_dispute_statement_coordinator_rejects_future_before_any_write(
    tmp_path,
    dispute_artifacts,
):
    statement, review, receipt, order, resolver = dispute_artifacts
    coordinator = _coordinator(tmp_path)

    with pytest.raises(
        TradeDisputeStatementRejected,
        match="too far in the future",
    ):
        coordinator.record(
            statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
            observed_at_ms=1,
            clock_skew_seconds=0,
        )
    assert list(coordinator.store.root.glob("*.json")) == []
    assert coordinator.spine.verified_snapshot() == ()


def test_dispute_statement_coordinator_rejects_conflicting_anchor(
    tmp_path,
    dispute_artifacts,
):
    statement, review, receipt, order, resolver = dispute_artifacts
    coordinator = _coordinator(tmp_path)
    payload = trade_dispute_statement_audit_payload(statement)
    forged = {**payload, "assertion_status": "verified-fact"}
    coordinator.spine.append_unique(
        EVENT_TRADE_DISPUTE_STATEMENT_RETAINED,
        forged,
        unique_payload_fields=("statement_digest",),
        ts_ms=1_786_000_000_000,
    )

    with pytest.raises(
        TradeDisputeStatementAuditError,
        match="conflicting payload",
    ):
        coordinator.record(
            statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
            observed_at_ms=1_786_000_000_001,
        )


def test_dispute_statement_coordinator_rejects_existing_early_anchor(
    tmp_path,
    dispute_artifacts,
):
    statement, review, receipt, order, resolver = dispute_artifacts
    coordinator = _coordinator(tmp_path)
    payload = trade_dispute_statement_audit_payload(statement)
    coordinator.spine.append_unique(
        EVENT_TRADE_DISPUTE_STATEMENT_RETAINED,
        payload,
        unique_payload_fields=("statement_digest",),
        ts_ms=1,
    )

    with pytest.raises(
        TradeDisputeStatementAuditError,
        match="anchor observation time is invalid.*too far in the future",
    ):
        coordinator.record(
            statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
            observed_at_ms=1_786_000_000_001,
            clock_skew_seconds=0,
        )


def test_dispute_statement_audit_is_public_api():
    assert trade_rules_api.TradeDisputeStatementAuditCoordinator is (
        TradeDisputeStatementAuditCoordinator
    )
    assert trade_rules_api.EVENT_TRADE_DISPUTE_STATEMENT_RETAINED == (
        EVENT_TRADE_DISPUTE_STATEMENT_RETAINED
    )
