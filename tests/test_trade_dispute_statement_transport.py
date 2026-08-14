from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
from datetime import datetime, timezone

import pytest

from nth_dao.identity import AgentID, AgentIdentity
from nth_dao.spine import SignedEventLog
from nth_dao.trade_rules.agreement_conformance import (
    DISPUTE_STATEMENT_ACKNOWLEDGEMENT_SCHEMA_PATH,
    DISPUTE_STATEMENT_AUDIT_SCHEMA_PATH,
    DISPUTE_STATEMENT_DELIVERY_SCHEMA_PATH,
    TRADE_DISPUTE_STATEMENT_SCHEMA_PATH,
    generate_vectors,
)
from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.dispute_statement import TradeDisputeStatementRejected
from nth_dao.trade_rules.dispute_statement_transport import (
    DISPUTE_STATEMENT_ACKNOWLEDGEMENT_STATUS,
    DISPUTE_STATEMENT_ACKNOWLEDGEMENT_SIGNING_DOMAIN,
    DISPUTE_STATEMENT_DELIVERY_SIGNING_DOMAIN,
    MAX_DISPUTE_STATEMENT_ACKNOWLEDGEMENT_BYTES,
    TradeDisputeStatementAcknowledgement,
    TradeDisputeStatementAcknowledgementRejected,
    TradeDisputeStatementDelivery,
    TradeDisputeStatementDeliveryRejected,
    create_trade_dispute_statement_acknowledgement,
    create_trade_dispute_statement_delivery,
    trade_dispute_statement_acknowledgement_digest,
    trade_dispute_statement_delivery_digest,
    verify_trade_dispute_statement_acknowledgement,
    verify_trade_dispute_statement_delivery,
)
from nth_dao.trade_rules.signing import (
    encode_ed25519_signature,
    signed_document_input,
    verification_method_for_did,
)
from nth_dao.trade_rules.dispute_statement_audit import (
    TradeDisputeStatementAuditCoordinator,
)
from nth_dao.trade_rules.dispute_statement_dispatch import (
    EVENT_TRADE_DISPUTE_STATEMENT_ACKNOWLEDGED,
    TradeDisputeStatementDispatchCoordinator,
    TradeDisputeStatementDispatchError,
    TradeDisputeStatementDispatchStore,
)
from nth_dao.trade_rules.dispute_statement_intake import (
    DISPUTE_STATEMENT_OBSERVATION_SIGNING_DOMAIN,
    TradeDisputeStatementObservation,
    TradeDisputeStatementObservationRejected,
    TradeDisputeStatementIntakeCoordinator,
    TradeDisputeStatementIntakeJournal,
    TradeDisputeStatementIntakeJournalCapacity,
    TradeDisputeStatementIntakeJournalError,
    create_trade_dispute_statement_observation,
)
from nth_dao.trade_rules.dispute_statement_store import (
    TradeDisputeStatementStore,
)
from nth_dao.trade_rules.execution_receipt import TradeExecutionReceipt
from nth_dao.trade_rules.package_store import build_rule_package
from nth_dao.trade_rules.receipt_review import TradeReceiptReview


def _identity(label: bytes) -> AgentIdentity:
    from nacl.signing import SigningKey

    signing_key = SigningKey(hashlib.sha256(label).digest())
    verify_key = signing_key.verify_key.encode()
    return AgentIdentity(
        agent_id=AgentID.from_pubkey(verify_key.hex()),
        label="public-conformance-only",
        _signing_key=signing_key.encode(),
        _verify_key=verify_key,
    )


class _Resolver:
    def __init__(self, package):
        self.package = package

    def load(self, digest):
        return (
            self.package
            if self.package is not None and digest == self.package.digest
            else None
        )


@pytest.fixture(scope="module")
def transport_artifacts():
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
    resolver = _Resolver(
        build_rule_package(
            package["manifest"],
            {
                item["digest"]: bytes.fromhex(item["bytes_hex"])
                for item in package["resources"]
            },
        )
    )
    maker = _identity(b"NTH Trade Agreement v1 maker public seed")
    taker = _identity(b"NTH Trade Agreement v1 taker public seed")
    return vectors, order, receipt, review, resolver, maker, taker


def _delivery(
    artifacts,
    *,
    nonce="45" * 16,
    created_at="2026-08-01T02:05:00Z",
    not_after="2026-08-01T02:15:00Z",
    now=datetime(2026, 8, 1, 2, 5, tzinfo=timezone.utc),
):
    vectors, order, receipt, review, resolver, maker, _taker = artifacts
    from nth_dao.trade_rules.dispute_statement import TradeDisputeStatement

    statement = TradeDisputeStatement.from_dict(
        vectors["trade_dispute_statement"],
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )
    return create_trade_dispute_statement_delivery(
        maker,
        statement=statement,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
        created_at=created_at,
        not_after=not_after,
        nonce=nonce,
        now=now,
    )


def _observation(artifacts, delivery, digest_value, received_at):
    _vectors, _order, _receipt, _review, _resolver, _maker, taker = artifacts
    return create_trade_dispute_statement_observation(
        taker,
        delivery=delivery,
        delivery_digest=digest_value,
        received_at=received_at,
    )


def test_dispute_statement_delivery_is_destination_bound_and_resolvable(
    transport_artifacts,
):
    _vectors, order, receipt, review, resolver, _maker, taker = transport_artifacts
    delivery = _delivery(transport_artifacts)

    assert verify_trade_dispute_statement_delivery(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
        recipient_did=taker.as_did(),
        at=datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
    ) == (True, "ok")
    assert (
        delivery.statement.resolve(
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=resolver,
        ).canonical_bytes
        == delivery.statement.canonical_bytes
    )
    assert trade_dispute_statement_delivery_digest(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
    ).startswith("sha256:")


def test_dispute_statement_delivery_rejects_retarget_and_expiry(
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, maker, taker = transport_artifacts
    delivery = _delivery(transport_artifacts)
    retargeted = copy.deepcopy(delivery.to_dict())
    retargeted["recipient_did"] = maker.as_did()

    with pytest.raises(
        TradeDisputeStatementDeliveryRejected,
        match="delivery_id does not match",
    ):
        TradeDisputeStatementDelivery.from_dict(
            retargeted,
            review=review,
            receipt=receipt,
            order=order,
        )
    ok, reason = verify_trade_dispute_statement_delivery(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
        recipient_did=taker.as_did(),
        at=datetime(2026, 8, 1, 2, 21, tzinfo=timezone.utc),
        clock_skew_seconds=0,
    )
    assert ok is False
    assert reason == "delivery has expired"


def test_dispute_statement_delivery_stays_unresolved_without_exact_package(
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, _maker, _taker = transport_artifacts
    delivery = _delivery(transport_artifacts)

    with pytest.raises(
        TradeDisputeStatementRejected,
        match="package is unavailable",
    ):
        delivery.statement.resolve(
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=_Resolver(None),
        )


def test_dispute_statement_acknowledgement_binds_retention_not_truth(
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, _maker, taker = transport_artifacts
    delivery = _delivery(transport_artifacts)
    acknowledgement = create_trade_dispute_statement_acknowledgement(
        taker,
        delivery=delivery,
        review=review,
        receipt=receipt,
        order=order,
        received_at="2026-08-01T02:06:00Z",
        audit_event_id="a" * 64,
    )

    assert acknowledgement.to_dict()["status"] == (
        DISPUTE_STATEMENT_ACKNOWLEDGEMENT_STATUS
    )
    assert verify_trade_dispute_statement_acknowledgement(
        acknowledgement,
        delivery=delivery,
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 2, 7, tzinfo=timezone.utc),
    ) == (True, "ok")
    assert trade_dispute_statement_acknowledgement_digest(acknowledgement).startswith(
        "sha256:"
    )


def test_dispute_statement_acknowledgement_rejects_wrong_signer_and_tamper(
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, maker, taker = transport_artifacts
    delivery = _delivery(transport_artifacts)

    with pytest.raises(
        TradeDisputeStatementAcknowledgementRejected,
        match="not delivery recipient",
    ):
        create_trade_dispute_statement_acknowledgement(
            maker,
            delivery=delivery,
            review=review,
            receipt=receipt,
            order=order,
            received_at="2026-08-01T02:06:00Z",
            audit_event_id="a" * 64,
        )
    acknowledgement = create_trade_dispute_statement_acknowledgement(
        taker,
        delivery=delivery,
        review=review,
        receipt=receipt,
        order=order,
        received_at="2026-08-01T02:06:00Z",
        audit_event_id="a" * 64,
    )
    tampered = copy.deepcopy(acknowledgement.to_dict())
    tampered["status"] = "claim-accepted-as-truth"
    with pytest.raises(
        TradeDisputeStatementAcknowledgementRejected,
        match="status is invalid",
    ):
        type(acknowledgement).from_dict(tampered)

    oversized = acknowledgement.to_dict()
    oversized["receiver_did"] = "did:key:z" + (
        "1" * MAX_DISPUTE_STATEMENT_ACKNOWLEDGEMENT_BYTES
    )
    with pytest.raises(
        TradeDisputeStatementAcknowledgementRejected,
        match="acknowledgement exceeds byte limit",
    ):
        TradeDisputeStatementAcknowledgement.from_dict(oversized)


def _intake(
    tmp_path,
    artifacts,
    *,
    resolver=None,
    max_ttl_seconds=600.0,
    clock_skew_seconds=300.0,
):
    _vectors, _order, _receipt, _review, default_resolver, _maker, taker = artifacts
    audit = TradeDisputeStatementAuditCoordinator(
        store=TradeDisputeStatementStore(tmp_path),
        spine=SignedEventLog(
            tmp_path / "spine.jsonl",
            taker,
        ),
    )
    return TradeDisputeStatementIntakeCoordinator(
        audit,
        receiver_identity=taker,
        package_resolver=(default_resolver if resolver is None else resolver),
        max_ttl_seconds=max_ttl_seconds,
        clock_skew_seconds=clock_skew_seconds,
    )


def test_dispute_statement_intake_is_idempotent_and_acknowledged(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, _maker, _taker = transport_artifacts
    intake = _intake(tmp_path, transport_artifacts)
    delivery = _delivery(transport_artifacts)
    arguments = {
        "review": review,
        "receipt": receipt,
        "order": order,
        "at": datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
    }

    first = intake.receive(delivery, **arguments)
    second = intake.receive(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 3, 0, tzinfo=timezone.utc),
    )

    assert first.audit.store_created is True
    assert first.audit.anchor_created is True
    assert second.audit.store_created is False
    assert second.audit.anchor_created is False
    assert second.acknowledgement.canonical_bytes == (
        first.acknowledgement.canonical_bytes
    )
    assert verify_trade_dispute_statement_acknowledgement(
        first.acknowledgement,
        delivery=delivery,
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 2, 7, tzinfo=timezone.utc),
    ) == (True, "ok")


def test_dispute_statement_intake_archive_frees_hot_capacity_and_keeps_replay(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, resolver, _maker, taker = (
        transport_artifacts
    )
    journal = TradeDisputeStatementIntakeJournal(tmp_path, max_records=1)
    audit = TradeDisputeStatementAuditCoordinator(
        store=TradeDisputeStatementStore(tmp_path),
        spine=SignedEventLog(tmp_path / "spine.jsonl", taker),
    )
    intake = TradeDisputeStatementIntakeCoordinator(
        audit,
        receiver_identity=taker,
        package_resolver=resolver,
        journal=journal,
        clock_skew_seconds=0,
    )
    first_delivery = _delivery(transport_artifacts)
    first = intake.receive(
        first_delivery,
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
    )

    assert journal.archive_acknowledged(
        at=datetime(2026, 8, 1, 2, 7, tzinfo=timezone.utc),
        retention_seconds=0,
    ) == (first.delivery_digest,)
    with sqlite3.connect(journal.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM dispute_statement_intake"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM dispute_statement_intake_archive"
        ).fetchone()[0] == 1

    replay = intake.receive(
        first_delivery,
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 3, 0, tzinfo=timezone.utc),
    )
    assert replay.acknowledgement == first.acknowledgement
    assert replay.audit.anchor_created is False

    second_delivery = _delivery(transport_artifacts, nonce="47" * 16)
    second = intake.receive(
        second_delivery,
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
    )
    assert second.delivery_digest != first.delivery_digest
    assert journal.get(second.delivery_digest) is not None


def test_dispute_statement_archive_capacity_preserves_active_record(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, resolver, _maker, taker = (
        transport_artifacts
    )
    journal = TradeDisputeStatementIntakeJournal(
        tmp_path,
        max_archive_records=1,
    )
    audit = TradeDisputeStatementAuditCoordinator(
        store=TradeDisputeStatementStore(tmp_path),
        spine=SignedEventLog(tmp_path / "spine.jsonl", taker),
    )
    intake = TradeDisputeStatementIntakeCoordinator(
        audit,
        receiver_identity=taker,
        package_resolver=resolver,
        journal=journal,
        clock_skew_seconds=0,
    )
    first = intake.receive(
        _delivery(transport_artifacts),
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
    )
    journal.archive_acknowledged(
        at=datetime(2026, 8, 1, 2, 7, tzinfo=timezone.utc)
    )
    second = intake.receive(
        _delivery(transport_artifacts, nonce="47" * 16),
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 2, 8, tzinfo=timezone.utc),
    )

    with pytest.raises(
        TradeDisputeStatementIntakeJournalCapacity,
        match="max_archive_records exceeded",
    ):
        journal.archive_acknowledged(
            at=datetime(2026, 8, 1, 2, 9, tzinfo=timezone.utc)
        )
    with sqlite3.connect(journal.path) as connection:
        active = connection.execute(
            "SELECT delivery_digest FROM dispute_statement_intake"
        ).fetchall()
        archived = connection.execute(
            "SELECT delivery_digest FROM dispute_statement_intake_archive"
        ).fetchall()
    assert active == [(second.delivery_digest,)]
    assert archived == [(first.delivery_digest,)]


def test_dispute_statement_archive_byte_capacity_preserves_active_record(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, resolver, _maker, taker = (
        transport_artifacts
    )
    journal = TradeDisputeStatementIntakeJournal(
        tmp_path,
        max_archive_bytes=1,
    )
    audit = TradeDisputeStatementAuditCoordinator(
        store=TradeDisputeStatementStore(tmp_path),
        spine=SignedEventLog(tmp_path / "spine.jsonl", taker),
    )
    intake = TradeDisputeStatementIntakeCoordinator(
        audit,
        receiver_identity=taker,
        package_resolver=resolver,
        journal=journal,
        clock_skew_seconds=0,
    )
    result = intake.receive(
        _delivery(transport_artifacts),
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
    )

    with pytest.raises(
        TradeDisputeStatementIntakeJournalCapacity,
        match="max_archive_bytes exceeded",
    ):
        journal.archive_acknowledged(
            at=datetime(2026, 8, 1, 2, 7, tzinfo=timezone.utc)
        )
    assert journal.get(result.delivery_digest) is not None
    with sqlite3.connect(journal.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM dispute_statement_intake_archive"
        ).fetchone()[0] == 0


def test_dispute_statement_archive_limit_is_enforced_on_reopen(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, _maker, _taker = (
        transport_artifacts
    )
    intake = _intake(tmp_path, transport_artifacts, clock_skew_seconds=0)
    intake.receive(
        _delivery(transport_artifacts),
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
    )
    intake.journal.archive_acknowledged(
        at=datetime(2026, 8, 1, 2, 7, tzinfo=timezone.utc)
    )

    with pytest.raises(
        TradeDisputeStatementIntakeJournalCapacity,
        match="existing intake archive exceeds max_archive_bytes",
    ):
        TradeDisputeStatementIntakeJournal(tmp_path, max_archive_bytes=1)


def test_dispute_statement_archive_batch_capacity_rolls_back_entire_batch(
    tmp_path,
    transport_artifacts,
    monkeypatch,
):
    _vectors, order, receipt, review, resolver, _maker, taker = (
        transport_artifacts
    )
    journal = TradeDisputeStatementIntakeJournal(
        tmp_path,
        max_archive_records=1,
    )
    audit = TradeDisputeStatementAuditCoordinator(
        store=TradeDisputeStatementStore(tmp_path),
        spine=SignedEventLog(tmp_path / "spine.jsonl", taker),
    )
    intake = TradeDisputeStatementIntakeCoordinator(
        audit,
        receiver_identity=taker,
        package_resolver=resolver,
        journal=journal,
        clock_skew_seconds=0,
    )
    with monkeypatch.context() as patch:
        patch.setattr(journal, "maintain", lambda **_kwargs: None)
        intake.receive(
            _delivery(transport_artifacts),
            review=review,
            receipt=receipt,
            order=order,
            at=datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
        )
        intake.receive(
            _delivery(transport_artifacts, nonce="47" * 16),
            review=review,
            receipt=receipt,
            order=order,
            at=datetime(2026, 8, 1, 2, 7, tzinfo=timezone.utc),
        )

    with pytest.raises(
        TradeDisputeStatementIntakeJournalCapacity,
        match="max_archive_records exceeded",
    ):
        journal.archive_acknowledged(
            at=datetime(2026, 8, 1, 2, 8, tzinfo=timezone.utc),
            limit=2,
        )
    with sqlite3.connect(journal.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM dispute_statement_intake"
        ).fetchone()[0] == 2
        assert connection.execute(
            "SELECT COUNT(*) FROM dispute_statement_intake_archive"
        ).fetchone()[0] == 0


def test_dispute_statement_receive_runs_bounded_maintenance(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, resolver, _maker, taker = (
        transport_artifacts
    )
    journal = TradeDisputeStatementIntakeJournal(tmp_path, max_records=1)
    audit = TradeDisputeStatementAuditCoordinator(
        store=TradeDisputeStatementStore(tmp_path),
        spine=SignedEventLog(tmp_path / "spine.jsonl", taker),
    )
    intake = TradeDisputeStatementIntakeCoordinator(
        audit,
        receiver_identity=taker,
        package_resolver=resolver,
        journal=journal,
        clock_skew_seconds=0,
    )
    first = intake.receive(
        _delivery(transport_artifacts),
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
    )
    second = intake.receive(
        _delivery(transport_artifacts, nonce="47" * 16),
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 2, 7, tzinfo=timezone.utc),
    )

    with sqlite3.connect(journal.path) as connection:
        active = connection.execute(
            "SELECT delivery_digest FROM dispute_statement_intake"
        ).fetchall()
        archived = connection.execute(
            "SELECT delivery_digest FROM dispute_statement_intake_archive"
        ).fetchall()
    assert active == [(second.delivery_digest,)]
    assert archived == [(first.delivery_digest,)]


def test_dispute_statement_invalid_delivery_cannot_trigger_maintenance(
    tmp_path,
    transport_artifacts,
    monkeypatch,
):
    _vectors, order, receipt, review, _resolver, _maker, _taker = (
        transport_artifacts
    )
    intake = _intake(tmp_path, transport_artifacts, clock_skew_seconds=0)

    def unexpected_maintenance(**_kwargs):
        raise AssertionError("unverified Delivery triggered maintenance")

    monkeypatch.setattr(intake.journal, "maintain", unexpected_maintenance)
    with pytest.raises(TradeDisputeStatementDeliveryRejected, match="expired"):
        intake.receive(
            _delivery(transport_artifacts),
            review=review,
            receipt=receipt,
            order=order,
            at=datetime(2026, 8, 1, 2, 16, tzinfo=timezone.utc),
        )


def test_dispute_statement_intake_archive_purges_only_after_safe_horizon(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, _maker, _taker = (
        transport_artifacts
    )
    intake = _intake(tmp_path, transport_artifacts, clock_skew_seconds=0)
    delivery = _delivery(transport_artifacts)
    result = intake.receive(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
    )
    intake.journal.archive_acknowledged(
        at=datetime(2026, 8, 1, 2, 7, tzinfo=timezone.utc),
        retention_seconds=0,
    )

    assert intake.journal.purge_archive(
        at=datetime(2026, 8, 2, 2, 14, tzinfo=timezone.utc)
    ) == ()
    assert intake.journal.purge_archive(
        at=datetime(2026, 8, 2, 2, 16, tzinfo=timezone.utc)
    ) == (result.delivery_digest,)
    assert intake.journal.get(result.delivery_digest) is None
    with pytest.raises(TradeDisputeStatementDeliveryRejected, match="expired"):
        intake.receive(
            delivery,
            review=review,
            receipt=receipt,
            order=order,
            at=datetime(2026, 8, 2, 2, 16, tzinfo=timezone.utc),
        )


def test_dispute_statement_intake_archive_retention_starts_at_archive_time(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, _maker, _taker = (
        transport_artifacts
    )
    intake = _intake(tmp_path, transport_artifacts, clock_skew_seconds=0)
    delivery = _delivery(transport_artifacts)
    result = intake.receive(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
    )
    intake.journal.archive_acknowledged(
        at=datetime(2026, 8, 10, 0, 0, tzinfo=timezone.utc),
        retention_seconds=3_600,
    )

    assert intake.journal.purge_archive(
        at=datetime(2026, 8, 10, 0, 59, 59, tzinfo=timezone.utc)
    ) == ()
    assert intake.journal.purge_archive(
        at=datetime(2026, 8, 10, 1, 0, tzinfo=timezone.utc)
    ) == (result.delivery_digest,)


def test_dispute_statement_intake_rejects_active_archive_duplicate(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, _maker, _taker = (
        transport_artifacts
    )
    intake = _intake(tmp_path, transport_artifacts)
    result = intake.receive(
        _delivery(transport_artifacts),
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
    )
    intake.journal.archive_acknowledged(
        at=datetime(2026, 8, 1, 2, 7, tzinfo=timezone.utc)
    )
    with sqlite3.connect(intake.journal.path) as connection:
        connection.execute(
            "INSERT INTO dispute_statement_intake SELECT "
            "delivery_digest, delivery_bytes, observed_at_ms, received_at, "
            "status, audit_event_id, observation_bytes, acknowledgement_bytes "
            "FROM dispute_statement_intake_archive"
        )

    with pytest.raises(
        TradeDisputeStatementIntakeJournalError,
        match="exists in active and archive",
    ):
        intake.journal.get(result.delivery_digest)


def test_dispute_statement_intake_get_uses_one_snapshot_during_archive(
    tmp_path,
    transport_artifacts,
    monkeypatch,
):
    _vectors, order, receipt, review, _resolver, _maker, _taker = (
        transport_artifacts
    )
    intake = _intake(tmp_path, transport_artifacts)
    result = intake.receive(
        _delivery(transport_artifacts),
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
    )
    other_journal = TradeDisputeStatementIntakeJournal(tmp_path)
    real_connect = intake.journal._connect
    archived = False

    class _ArchiveAfterFetchCursor:
        def __init__(self, cursor):
            self.cursor = cursor

        def __getattr__(self, name):
            return getattr(self.cursor, name)

        def fetchone(self):
            nonlocal archived
            row = self.cursor.fetchone()
            if not archived:
                archived = True
                assert other_journal.archive_acknowledged(
                    at=datetime(2026, 8, 1, 2, 7, tzinfo=timezone.utc)
                ) == (result.delivery_digest,)
            return row

    class _ArchiveDuringReadConnection:
        def __init__(self):
            self.connection = real_connect()

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def execute(self, sql, parameters=()):
            cursor = self.connection.execute(sql, parameters)
            normalized = " ".join(sql.split())
            if normalized == (
                "SELECT * FROM dispute_statement_intake "
                "WHERE delivery_digest = ?"
            ):
                return _ArchiveAfterFetchCursor(cursor)
            return cursor

        def close(self):
            self.connection.close()

    monkeypatch.setattr(intake.journal, "_connect", _ArchiveDuringReadConnection)

    record = intake.journal.get(result.delivery_digest)
    assert record is not None
    assert record.status == "acknowledged"

    archived_record = other_journal.get(result.delivery_digest)
    assert archived_record is not None
    assert archived_record.status == "acknowledged"


def test_dispute_statement_intake_never_archives_unacknowledged_rows(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, _maker, _taker = (
        transport_artifacts
    )
    delivery = _delivery(transport_artifacts)
    digest_value = trade_dispute_statement_delivery_digest(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
    )
    received_at = "2026-08-01T02:06:00Z"
    journal = TradeDisputeStatementIntakeJournal(tmp_path)
    journal.observe(
        digest_value,
        delivery,
        observed_at_ms=1_785_549_960_000,
        received_at=received_at,
        observation=_observation(
            transport_artifacts,
            delivery,
            digest_value,
            received_at,
        ),
    )
    assert journal.archive_acknowledged(
        at=datetime(2026, 8, 2, tzinfo=timezone.utc)
    ) == ()
    journal.mark_anchored(digest_value, audit_event_id="a" * 64)
    assert journal.archive_acknowledged(
        at=datetime(2026, 8, 2, tzinfo=timezone.utc)
    ) == ()


def test_dispute_statement_intake_rejects_wrong_node_and_missing_package(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, resolver, maker, taker = transport_artifacts
    delivery = _delivery(transport_artifacts)
    wrong_audit = TradeDisputeStatementAuditCoordinator(
        store=TradeDisputeStatementStore(tmp_path / "wrong"),
        spine=SignedEventLog(
            tmp_path / "wrong-spine.jsonl",
            maker,
        ),
    )
    wrong = TradeDisputeStatementIntakeCoordinator(
        wrong_audit,
        receiver_identity=maker,
        package_resolver=resolver,
    )
    with pytest.raises(
        TradeDisputeStatementDeliveryRejected,
        match="recipient does not match this node",
    ):
        wrong.receive(
            delivery,
            review=review,
            receipt=receipt,
            order=order,
            at=datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
        )
    assert list(wrong_audit.store.root.glob("*.json")) == []
    assert wrong_audit.spine.verified_snapshot() == ()

    missing = _intake(
        tmp_path / "missing",
        transport_artifacts,
        resolver=_Resolver(None),
    )
    with pytest.raises(
        TradeDisputeStatementRejected,
        match="package is unavailable",
    ):
        missing.receive(
            delivery,
            review=review,
            receipt=receipt,
            order=order,
            at=datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
        )
    assert list(missing.audit_coordinator.store.root.glob("*.json")) == []
    assert missing.audit_coordinator.spine.verified_snapshot() == ()
    observed_record = missing.journal.get(
        trade_dispute_statement_delivery_digest(
            delivery,
            review=review,
            receipt=receipt,
            order=order,
        )
    )
    assert observed_record is not None
    assert observed_record.status == "observed"

    resumed = TradeDisputeStatementIntakeCoordinator(
        missing.audit_coordinator,
        receiver_identity=taker,
        package_resolver=resolver,
        journal=missing.journal,
    )
    recovered = resumed.receive(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 3, 0, tzinfo=timezone.utc),
    )
    assert recovered.audit.store_created is True
    assert recovered.audit.anchor_created is True
    assert resumed.journal.get(recovered.delivery_digest).status == ("acknowledged")


def test_dispute_statement_intake_rejects_spine_signer_mismatch(
    tmp_path,
    transport_artifacts,
):
    _vectors, _order, _receipt, _review, resolver, _maker, taker = (
        transport_artifacts
    )
    audit = TradeDisputeStatementAuditCoordinator(
        store=TradeDisputeStatementStore(tmp_path),
        spine=SignedEventLog(
            tmp_path / "spine.jsonl",
            AgentIdentity.generate(label="unrelated-auditor"),
        ),
    )

    with pytest.raises(
        ValueError,
        match="Spine signer must match dispute intake receiver identity",
    ):
        TradeDisputeStatementIntakeCoordinator(
            audit,
            receiver_identity=taker,
            package_resolver=resolver,
        )


def test_dispute_statement_intake_journal_enforces_typed_digest_and_time(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, _maker, _taker = transport_artifacts
    delivery = _delivery(transport_artifacts)
    digest_value = trade_dispute_statement_delivery_digest(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
    )
    journal = TradeDisputeStatementIntakeJournal(tmp_path)
    received_at = "2026-08-01T02:06:00.000001Z"
    observed_at_ms = 1_785_549_960_001
    observation = _observation(
        transport_artifacts,
        delivery,
        digest_value,
        received_at,
    )

    with pytest.raises(TypeError, match="TradeDisputeStatementDelivery"):
        journal.observe(
            digest_value,
            b"not-a-delivery",
            observed_at_ms=observed_at_ms,
            received_at=received_at,
            observation=observation,
        )
    with pytest.raises(
        TradeDisputeStatementIntakeJournalError,
        match="does not match delivery_bytes",
    ):
        journal.observe(
            "sha256:" + ("0" * 64),
            delivery,
            observed_at_ms=observed_at_ms,
            received_at=received_at,
            observation=observation,
        )
    record, created = journal.observe(
        digest_value,
        delivery,
        observed_at_ms=observed_at_ms,
        received_at=received_at,
        observation=observation,
    )
    assert created is True
    assert record.status == "observed"

    with sqlite3.connect(journal.path) as connection:
        connection.execute(
            "UPDATE dispute_statement_intake SET observed_at_ms = ?",
            (253_402_300_800_000,),
        )
    with pytest.raises(
        TradeDisputeStatementIntakeJournalError,
        match="row is invalid",
    ):
        journal.get(digest_value)


def test_dispute_statement_observation_requires_recipient_signature(
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, _maker, _taker = (
        transport_artifacts
    )
    delivery = _delivery(transport_artifacts)
    digest_value = trade_dispute_statement_delivery_digest(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
    )
    received_at = "2026-08-01T02:06:00Z"
    attacker = _identity(b"forged first-observation attacker")

    with pytest.raises(
        TradeDisputeStatementObservationRejected,
        match="signer is not Delivery recipient",
    ):
        create_trade_dispute_statement_observation(
            attacker,
            delivery=delivery,
            delivery_digest=digest_value,
            received_at=received_at,
        )

    observation = _observation(
        transport_artifacts,
        delivery,
        digest_value,
        received_at,
    )
    forged = observation.to_dict()
    forged["proof"]["proof_value"] = "A" * 86
    forged["proof"]["proof_value"] = encode_ed25519_signature(
        attacker.sign(
            signed_document_input(
                DISPUTE_STATEMENT_OBSERVATION_SIGNING_DOMAIN,
                forged,
            )
        )
    )
    with pytest.raises(
        TradeDisputeStatementObservationRejected,
        match="signature is invalid",
    ):
        TradeDisputeStatementObservation.from_dict(
            forged,
            delivery_digest=digest_value,
            delivery_bytes=delivery.canonical_bytes,
        )


def test_dispute_statement_intake_detects_observation_time_tampering(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, _maker, _taker = (
        transport_artifacts
    )
    delivery = _delivery(transport_artifacts)
    digest_value = trade_dispute_statement_delivery_digest(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
    )
    received_at = "2026-08-01T02:06:00Z"
    journal = TradeDisputeStatementIntakeJournal(tmp_path)
    journal.observe(
        digest_value,
        delivery,
        observed_at_ms=1_785_549_960_000,
        received_at=received_at,
        observation=_observation(
            transport_artifacts,
            delivery,
            digest_value,
            received_at,
        ),
    )
    with sqlite3.connect(journal.path) as connection:
        connection.execute(
            "UPDATE dispute_statement_intake SET "
            "received_at = ?, observed_at_ms = ?",
            ("2026-08-01T02:07:00Z", 1_785_550_020_000),
        )

    with pytest.raises(
        TradeDisputeStatementIntakeJournalError,
        match="Observation time is inconsistent",
    ):
        journal.get(digest_value)


def test_dispute_statement_intake_rejects_noncanonical_observation_storage(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, _maker, _taker = (
        transport_artifacts
    )
    delivery = _delivery(transport_artifacts)
    digest_value = trade_dispute_statement_delivery_digest(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
    )
    received_at = "2026-08-01T02:06:00Z"
    observation = _observation(
        transport_artifacts,
        delivery,
        digest_value,
        received_at,
    )
    journal = TradeDisputeStatementIntakeJournal(tmp_path)
    journal.observe(
        digest_value,
        delivery,
        observed_at_ms=1_785_549_960_000,
        received_at=received_at,
        observation=observation,
    )
    pretty_bytes = json.dumps(
        observation.to_dict(),
        indent=2,
        ensure_ascii=True,
    ).encode("ascii")
    assert pretty_bytes != observation.canonical_bytes
    with sqlite3.connect(journal.path) as connection:
        connection.execute(
            "UPDATE dispute_statement_intake SET observation_bytes = ? "
            "WHERE delivery_digest = ?",
            (pretty_bytes, digest_value),
        )

    with pytest.raises(
        TradeDisputeStatementIntakeJournalError,
        match="Observation is not canonical",
    ):
        journal.get(digest_value)


def test_dispute_statement_intake_migrates_only_empty_unsigned_v1_journal(
    tmp_path,
):
    path = tmp_path / "trade" / "dispute_statement_intake_v1.sqlite3"
    path.parent.mkdir(parents=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE dispute_statement_intake ("
            "delivery_digest TEXT PRIMARY KEY, delivery_bytes BLOB NOT NULL, "
            "observed_at_ms INTEGER NOT NULL, received_at TEXT NOT NULL, "
            "status TEXT NOT NULL, audit_event_id TEXT NOT NULL, "
            "acknowledgement_bytes BLOB) WITHOUT ROWID"
        )
        connection.execute("PRAGMA user_version = 1")

    journal = TradeDisputeStatementIntakeJournal(tmp_path)
    with sqlite3.connect(journal.path) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        columns = {
            row[1]: row[3]
            for row in connection.execute(
                "PRAGMA table_info(dispute_statement_intake)"
            )
        }
    assert version == 3
    assert columns["observation_bytes"] == 1


def test_dispute_statement_intake_rejects_nonempty_unsigned_v1_journal(
    tmp_path,
):
    path = tmp_path / "trade" / "dispute_statement_intake_v1.sqlite3"
    path.parent.mkdir(parents=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE dispute_statement_intake ("
            "delivery_digest TEXT PRIMARY KEY, delivery_bytes BLOB NOT NULL, "
            "observed_at_ms INTEGER NOT NULL, received_at TEXT NOT NULL, "
            "status TEXT NOT NULL, audit_event_id TEXT NOT NULL, "
            "acknowledgement_bytes BLOB) WITHOUT ROWID"
        )
        connection.execute(
            "INSERT INTO dispute_statement_intake VALUES (?, ?, ?, ?, ?, ?, NULL)",
            (
                "sha256:" + ("0" * 64),
                b"{}",
                1,
                "1970-01-01T00:00:00.001Z",
                "observed",
                "",
            ),
        )
        connection.execute("PRAGMA user_version = 1")

    with pytest.raises(
        TradeDisputeStatementIntakeJournalError,
        match="unsigned observations and cannot be trusted",
    ):
        TradeDisputeStatementIntakeJournal(tmp_path)


def test_dispute_statement_intake_migrates_v2_journal_to_archive_schema(
    tmp_path,
):
    path = tmp_path / "trade" / "dispute_statement_intake_v1.sqlite3"
    path.parent.mkdir(parents=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE dispute_statement_intake ("
            "delivery_digest TEXT PRIMARY KEY, delivery_bytes BLOB NOT NULL, "
            "observed_at_ms INTEGER NOT NULL, received_at TEXT NOT NULL, "
            "status TEXT NOT NULL, audit_event_id TEXT NOT NULL, "
            "observation_bytes BLOB NOT NULL, acknowledgement_bytes BLOB) "
            "WITHOUT ROWID"
        )
        connection.execute("PRAGMA user_version = 2")

    journal = TradeDisputeStatementIntakeJournal(tmp_path)
    with sqlite3.connect(journal.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
        archive_columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(dispute_statement_intake_archive)"
            )
        }
    assert "purge_after_ms" in archive_columns


def test_dispute_statement_intake_journal_closes_connections(
    tmp_path,
    monkeypatch,
):
    journal = TradeDisputeStatementIntakeJournal(tmp_path)
    real_connect = journal._connect
    closed: list[bool] = []

    class _TrackedConnection:
        def __init__(self):
            self.connection = real_connect()

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def close(self):
            self.connection.close()
            closed.append(True)

    monkeypatch.setattr(journal, "_connect", _TrackedConnection)
    assert journal.get("sha256:" + ("0" * 64)) is None
    assert closed == [True]


def test_dispute_statement_intake_closes_connection_when_pragma_fails(
    tmp_path,
    monkeypatch,
):
    closed: list[bool] = []

    class _FailingConnection:
        row_factory = None

        def execute(self, _statement):
            raise sqlite3.OperationalError("simulated PRAGMA failure")

        def close(self):
            closed.append(True)

    monkeypatch.setattr(
        sqlite3,
        "connect",
        lambda *_args, **_kwargs: _FailingConnection(),
    )
    with pytest.raises(
        TradeDisputeStatementIntakeJournalError,
        match="unable to initialize.*simulated PRAGMA failure",
    ):
        TradeDisputeStatementIntakeJournal(tmp_path)
    assert closed == [True]


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), -float("inf")])
def test_dispute_statement_intake_rejects_non_finite_sqlite_timeout(
    tmp_path,
    timeout,
):
    with pytest.raises(ValueError, match="finite positive"):
        TradeDisputeStatementIntakeJournal(tmp_path, timeout_seconds=timeout)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_archive_records", 0),
        ("max_archive_records", False),
        ("max_archive_bytes", -1),
        ("max_archive_bytes", True),
    ],
)
def test_dispute_statement_intake_rejects_invalid_archive_capacity(
    tmp_path,
    field,
    value,
):
    with pytest.raises(ValueError, match=f"{field} must be a positive integer"):
        TradeDisputeStatementIntakeJournal(tmp_path, **{field: value})


def test_dispute_statement_intake_reserves_ack_capacity_before_side_effects(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, resolver, _maker, taker = transport_artifacts
    delivery = _delivery(transport_artifacts)
    audit = TradeDisputeStatementAuditCoordinator(
        store=TradeDisputeStatementStore(tmp_path),
        spine=SignedEventLog(tmp_path / "spine.jsonl", taker),
    )
    journal = TradeDisputeStatementIntakeJournal(
        tmp_path,
        max_bytes=(
            len(delivery.canonical_bytes)
            + MAX_DISPUTE_STATEMENT_ACKNOWLEDGEMENT_BYTES
            - 1
        ),
    )
    intake = TradeDisputeStatementIntakeCoordinator(
        audit,
        receiver_identity=taker,
        package_resolver=resolver,
        journal=journal,
    )

    with pytest.raises(
        TradeDisputeStatementIntakeJournalCapacity,
        match="max_bytes exceeded",
    ):
        intake.receive(
            delivery,
            review=review,
            receipt=receipt,
            order=order,
            at=datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
        )
    assert journal.get(
        trade_dispute_statement_delivery_digest(
            delivery,
            review=review,
            receipt=receipt,
            order=order,
        )
    ) is None
    assert list(audit.store.root.glob("*.json")) == []
    assert audit.spine.verified_snapshot() == ()


def test_dispute_statement_journal_rejects_ack_time_before_commit(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, _maker, taker = (
        transport_artifacts
    )
    delivery = _delivery(transport_artifacts)
    digest_value = trade_dispute_statement_delivery_digest(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
    )
    journal = TradeDisputeStatementIntakeJournal(tmp_path)
    received_at = "2026-08-01T02:06:00Z"
    observation = _observation(
        transport_artifacts,
        delivery,
        digest_value,
        received_at,
    )
    journal.observe(
        digest_value,
        delivery,
        observed_at_ms=1_785_549_960_000,
        received_at=received_at,
        observation=observation,
    )
    audit_event_id = "a" * 64
    journal.mark_anchored(digest_value, audit_event_id=audit_event_id)
    wrong_time_ack = create_trade_dispute_statement_acknowledgement(
        taker,
        delivery=delivery,
        review=review,
        receipt=receipt,
        order=order,
        received_at="2026-08-01T02:06:01Z",
        audit_event_id=audit_event_id,
    )

    with pytest.raises(
        TradeDisputeStatementIntakeJournalError,
        match="received_at does not bind journal Delivery",
    ):
        journal.mark_acknowledged(
            digest_value,
            audit_event_id=audit_event_id,
            acknowledgement=wrong_time_ack,
        )
    record = journal.get(digest_value)
    assert record is not None
    assert record.status == "anchored"
    assert record.acknowledgement_bytes is None


def test_dispute_statement_journal_rejects_ack_from_wrong_receiver(
    tmp_path,
    transport_artifacts,
):
    vectors, order, receipt, review, _resolver, _maker, _taker = (
        transport_artifacts
    )
    delivery = _delivery(transport_artifacts)
    digest_value = trade_dispute_statement_delivery_digest(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
    )
    journal = TradeDisputeStatementIntakeJournal(tmp_path)
    received_at = "2026-08-01T02:06:00Z"
    observation = _observation(
        transport_artifacts,
        delivery,
        digest_value,
        received_at,
    )
    journal.observe(
        digest_value,
        delivery,
        observed_at_ms=1_785_549_960_000,
        received_at=received_at,
        observation=observation,
    )
    audit_event_id = "a" * 64
    journal.mark_anchored(digest_value, audit_event_id=audit_event_id)
    attacker = _identity(b"journal ACK binding attacker")
    forged_document = copy.deepcopy(
        vectors["trade_dispute_statement_acknowledgement"]
    )
    forged_document["receiver_did"] = attacker.as_did()
    forged_document["proof"]["verification_method"] = (
        verification_method_for_did(attacker.as_did())
    )
    forged_document["proof"]["proof_value"] = encode_ed25519_signature(
        attacker.sign(
            signed_document_input(
                DISPUTE_STATEMENT_ACKNOWLEDGEMENT_SIGNING_DOMAIN,
                forged_document,
            )
        )
    )
    forged = TradeDisputeStatementAcknowledgement.from_dict(forged_document)

    with pytest.raises(
        TradeDisputeStatementIntakeJournalError,
        match="receiver_did does not bind journal Delivery",
    ):
        journal.mark_acknowledged(
            digest_value,
            audit_event_id=audit_event_id,
            acknowledgement=forged,
        )
    record = journal.get(digest_value)
    assert record is not None
    assert record.status == "anchored"
    assert record.acknowledgement_bytes is None


def test_dispute_statement_intake_journal_detects_artifact_tampering(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, _maker, _taker = transport_artifacts
    delivery = _delivery(transport_artifacts)
    digest_value = trade_dispute_statement_delivery_digest(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
    )
    journal = TradeDisputeStatementIntakeJournal(tmp_path / "delivery")
    received_at = "2026-08-01T02:06:00Z"
    observation = _observation(
        transport_artifacts,
        delivery,
        digest_value,
        received_at,
    )
    journal.observe(
        digest_value,
        delivery,
        observed_at_ms=1_785_549_960_000,
        received_at=received_at,
        observation=observation,
    )
    with sqlite3.connect(journal.path) as connection:
        connection.execute(
            "UPDATE dispute_statement_intake SET delivery_bytes = ?",
            (b"{}",),
        )
    with pytest.raises(
        TradeDisputeStatementIntakeJournalError,
        match="Delivery digest is inconsistent",
    ):
        journal.get(digest_value)

    intake = _intake(tmp_path / "acknowledgement", transport_artifacts)
    result = intake.receive(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
    )
    with sqlite3.connect(intake.journal.path) as connection:
        connection.execute(
            "UPDATE dispute_statement_intake SET acknowledgement_bytes = ?",
            (b"{}",),
        )
    with pytest.raises(
        TradeDisputeStatementIntakeJournalError,
        match="Acknowledgement is invalid",
    ):
        intake.journal.get(result.delivery_digest)


def test_dispute_statement_intake_revalidates_concurrent_first_observation(
    tmp_path,
    transport_artifacts,
    monkeypatch,
):
    _vectors, order, receipt, review, _resolver, _maker, _taker = transport_artifacts
    delivery = _delivery(transport_artifacts)
    intake = _intake(
        tmp_path,
        transport_artifacts,
        clock_skew_seconds=0,
    )
    digest_value = trade_dispute_statement_delivery_digest(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
    )
    received_at = "2026-08-01T02:04:59Z"
    observation = _observation(
        transport_artifacts,
        delivery,
        digest_value,
        received_at,
    )
    intake.journal.observe(
        digest_value,
        delivery,
        observed_at_ms=1_785_549_899_000,
        received_at=received_at,
        observation=observation,
    )
    monkeypatch.setattr(intake.journal, "get", lambda _digest: None)

    with pytest.raises(
        TradeDisputeStatementIntakeJournalError,
        match="persisted delivery observation is invalid",
    ):
        intake.receive(
            delivery,
            review=review,
            receipt=receipt,
            order=order,
            at=datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
        )
    assert list(intake.audit_coordinator.store.root.glob("*.json")) == []
    assert intake.audit_coordinator.spine.verified_snapshot() == ()


def test_dispute_statement_intake_preserves_submillisecond_observation(
    tmp_path,
    transport_artifacts,
):
    vectors, order, receipt, review, resolver, maker, _taker = transport_artifacts
    from nth_dao.trade_rules.dispute_statement import TradeDisputeStatement

    statement = TradeDisputeStatement.from_dict(
        vectors["trade_dispute_statement"],
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
    )
    delivery = create_trade_dispute_statement_delivery(
        maker,
        statement=statement,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=resolver,
        created_at="2026-08-01T02:05:00.000900Z",
        not_after="2026-08-01T02:15:00.000900Z",
        nonce="46" * 16,
        now=datetime(
            2026,
            8,
            1,
            2,
            5,
            0,
            900,
            tzinfo=timezone.utc,
        ),
        clock_skew_seconds=0,
    )
    intake = _intake(
        tmp_path,
        transport_artifacts,
        clock_skew_seconds=0,
    )
    result = intake.receive(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(
            2026,
            8,
            1,
            2,
            5,
            0,
            950,
            tzinfo=timezone.utc,
        ),
    )

    assert result.acknowledgement.to_dict()["received_at"] == (
        "2026-08-01T02:05:00.000950Z"
    )
    assert result.audit.event.ts_ms == 1_785_549_900_001


def test_dispute_statement_transport_public_vectors_verify(
    transport_artifacts,
):
    vectors, order, receipt, review, _resolver, _maker, _taker = transport_artifacts
    delivery = TradeDisputeStatementDelivery.from_dict(
        vectors["trade_dispute_statement_delivery"],
        review=review,
        receipt=receipt,
        order=order,
    )
    assert (
        trade_dispute_statement_delivery_digest(
            delivery,
            review=review,
            receipt=receipt,
            order=order,
        )
        == vectors["trade_dispute_statement_delivery_digest"]
    )
    assert (
        delivery.canonical_bytes.hex()
        == vectors["trade_dispute_statement_delivery_canonical_hex"]
    )
    assert (
        signed_document_input(
            DISPUTE_STATEMENT_DELIVERY_SIGNING_DOMAIN,
            delivery.to_dict(),
        ).hex()
        == vectors["trade_dispute_statement_delivery_signing_input_hex"]
    )
    for case in vectors["trade_dispute_statement_delivery_verification_cases"]:
        ok, _reason = verify_trade_dispute_statement_delivery(
            delivery,
            review=review,
            receipt=receipt,
            order=order,
            recipient_did=case["recipient_did"],
            at=datetime.fromisoformat(case["at"].replace("Z", "+00:00")),
            max_ttl_seconds=case["max_ttl_seconds"],
            clock_skew_seconds=case["clock_skew_seconds"],
        )
        assert ok is case["expected_valid"], case["case"]

    acknowledgement = TradeDisputeStatementAcknowledgement.from_dict(
        vectors["trade_dispute_statement_acknowledgement"]
    )
    assert (
        trade_dispute_statement_acknowledgement_digest(acknowledgement)
        == vectors["trade_dispute_statement_acknowledgement_digest"]
    )
    assert (
        acknowledgement.canonical_bytes.hex()
        == vectors["trade_dispute_statement_acknowledgement_canonical_hex"]
    )
    assert (
        signed_document_input(
            DISPUTE_STATEMENT_ACKNOWLEDGEMENT_SIGNING_DOMAIN,
            acknowledgement.to_dict(),
        ).hex()
        == vectors["trade_dispute_statement_acknowledgement_signing_input_hex"]
    )
    for case in vectors["trade_dispute_statement_acknowledgement_verification_cases"]:
        ok, _reason = verify_trade_dispute_statement_acknowledgement(
            acknowledgement,
            delivery=delivery,
            review=review,
            receipt=receipt,
            order=order,
            at=datetime.fromisoformat(case["at"].replace("Z", "+00:00")),
            clock_skew_seconds=case["clock_skew_seconds"],
        )
        assert ok is case["expected_valid"], case["case"]

    overlong_delivery = TradeDisputeStatementDelivery.from_dict(
        vectors["trade_dispute_statement_overlong_delivery"],
        review=review,
        receipt=receipt,
        order=order,
    )
    overlong_acknowledgement = TradeDisputeStatementAcknowledgement.from_dict(
        vectors["trade_dispute_statement_overlong_acknowledgement"]
    )
    verification_arguments = {
        "delivery": overlong_delivery,
        "review": review,
        "receipt": receipt,
        "order": order,
        "at": datetime(2026, 8, 1, 2, 7, tzinfo=timezone.utc),
        "clock_skew_seconds": 0,
    }
    assert verify_trade_dispute_statement_acknowledgement(
        overlong_acknowledgement,
        **verification_arguments,
    )[0] is False
    assert verify_trade_dispute_statement_acknowledgement(
        overlong_acknowledgement,
        max_ttl_seconds=86_400,
        **verification_arguments,
    ) == (True, "ok")


def test_dispute_statement_intake_propagates_explicit_ttl_policy(
    tmp_path,
    transport_artifacts,
):
    vectors, order, receipt, review, _resolver, _maker, _taker = (
        transport_artifacts
    )
    delivery = TradeDisputeStatementDelivery.from_dict(
        vectors["trade_dispute_statement_overlong_delivery"],
        review=review,
        receipt=receipt,
        order=order,
    )
    intake = _intake(
        tmp_path,
        transport_artifacts,
        max_ttl_seconds=86_400,
        clock_skew_seconds=0,
    )

    result = intake.receive(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
    )
    assert verify_trade_dispute_statement_acknowledgement(
        result.acknowledgement,
        delivery=delivery,
        review=review,
        receipt=receipt,
        order=order,
        at=datetime(2026, 8, 1, 2, 7, tzinfo=timezone.utc),
        max_ttl_seconds=86_400,
        clock_skew_seconds=0,
    ) == (True, "ok")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_ttl_seconds", 86_400.000_001),
        ("max_ttl_seconds", 1e300),
        ("clock_skew_seconds", 86_400.000_001),
        ("clock_skew_seconds", 1e300),
    ],
)
def test_dispute_statement_transport_rejects_unbounded_policy_without_overflow(
    tmp_path,
    transport_artifacts,
    field,
    value,
):
    _vectors, order, receipt, review, resolver, _maker, taker = (
        transport_artifacts
    )
    delivery = _delivery(transport_artifacts)
    arguments = {
        "review": review,
        "receipt": receipt,
        "order": order,
        "recipient_did": taker.as_did(),
        "at": datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
        field: value,
    }
    valid, reason = verify_trade_dispute_statement_delivery(
        delivery,
        **arguments,
    )
    assert valid is False
    assert "not greater than 86400" in reason

    audit = TradeDisputeStatementAuditCoordinator(
        store=TradeDisputeStatementStore(tmp_path),
        spine=SignedEventLog(tmp_path / "spine.jsonl", taker),
    )
    coordinator_arguments = {
        "receiver_identity": taker,
        "package_resolver": resolver,
        field: value,
    }
    with pytest.raises(
        TradeDisputeStatementDeliveryRejected,
        match="not greater than 86400",
    ):
        TradeDisputeStatementIntakeCoordinator(
            audit,
            **coordinator_arguments,
        )


def test_dispute_statement_transport_negative_vectors_fail_closed(
    transport_artifacts,
):
    vectors, order, receipt, review, _resolver, _maker, _taker = transport_artifacts
    cases = {
        case["case"]: case
        for case in vectors["negative_cases"]
        if case["target"].startswith("trade_dispute_statement_")
    }
    for name in (
        "trade-dispute-statement-delivery-retarget",
        "trade-dispute-statement-delivery-signature-tamper",
    ):
        with pytest.raises(TradeDisputeStatementDeliveryRejected):
            TradeDisputeStatementDelivery.from_dict(
                cases[name]["document"],
                review=review,
                receipt=receipt,
                order=order,
            )
    for name in (
        "trade-dispute-statement-ack-status-tamper",
        "trade-dispute-statement-ack-signature-tamper",
    ):
        with pytest.raises(TradeDisputeStatementAcknowledgementRejected):
            TradeDisputeStatementAcknowledgement.from_dict(cases[name]["document"])


def test_dispute_statement_transport_schemas_validate_public_vectors(
    transport_artifacts,
):
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    vectors = transport_artifacts[0]
    statement_schema = json.loads(
        TRADE_DISPUTE_STATEMENT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    delivery_schema = json.loads(
        DISPUTE_STATEMENT_DELIVERY_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    acknowledgement_schema = json.loads(
        DISPUTE_STATEMENT_ACKNOWLEDGEMENT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    audit_schema = json.loads(
        DISPUTE_STATEMENT_AUDIT_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    registry = referencing.Registry().with_resource(
        statement_schema["$id"],
        referencing.Resource.from_contents(statement_schema),
    )
    for schema in (delivery_schema, acknowledgement_schema, audit_schema):
        validator = jsonschema.validators.validator_for(schema)
        validator.check_schema(schema)
    jsonschema.validators.validator_for(delivery_schema)(
        delivery_schema,
        registry=registry,
    ).validate(vectors["trade_dispute_statement_delivery"])
    jsonschema.validators.validator_for(acknowledgement_schema)(
        acknowledgement_schema
    ).validate(vectors["trade_dispute_statement_acknowledgement"])
    jsonschema.validators.validator_for(audit_schema)(audit_schema).validate(
        vectors["trade_dispute_statement_audit"]["payload"]
    )

    unknown = copy.deepcopy(vectors["trade_dispute_statement_delivery"])
    unknown["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validators.validator_for(delivery_schema)(
            delivery_schema,
            registry=registry,
        ).validate(unknown)


def _dispatch_acknowledgement(artifacts, delivery):
    _vectors, order, receipt, review, _resolver, _maker, taker = artifacts
    return create_trade_dispute_statement_acknowledgement(
        taker,
        delivery=delivery,
        review=review,
        receipt=receipt,
        order=order,
        received_at="2026-08-01T02:06:00Z",
        audit_event_id="6" * 64,
    )


def test_dispute_statement_dispatch_persists_and_anchors_acknowledgement(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, maker, _taker = (
        transport_artifacts
    )
    delivery = _delivery(transport_artifacts)
    statement_digest = delivery.to_dict()["statement_digest"]
    store = TradeDisputeStatementDispatchStore(tmp_path)
    moment_ms = int(
        datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc).timestamp() * 1_000
    )

    first = store.prepare(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
        target_url="https://peer.example/nth",
        now_ms=moment_ms,
    )
    retry = store.prepare(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
        target_url="https://peer.example/nth/",
        now_ms=moment_ms + 1,
    )
    coordinator = TradeDisputeStatementDispatchCoordinator(
        store,
        SignedEventLog(tmp_path / "spine.jsonl", maker),
    )
    _leased, lease_token = store.acquire_send_lease(statement_digest)
    retained = coordinator.acknowledge(
        statement_digest,
        _dispatch_acknowledgement(transport_artifacts, delivery),
        remote_event_id="6" * 64,
        lease_token=lease_token,
    )

    assert first.statement_digest == statement_digest
    assert retry.delivery.canonical_bytes == first.delivery.canonical_bytes
    assert retained.acknowledged is True
    assert retained.anchor_event_id
    assert retained.remote_event_id == "6" * 64
    assert retained.attempts == 0
    events = coordinator.spine.verified_snapshot()
    assert len(events) == 1
    assert events[0].type == EVENT_TRADE_DISPUTE_STATEMENT_ACKNOWLEDGED
    assert events[0].payload["statement_digest"] == statement_digest


def test_dispute_statement_dispatch_recovers_ack_after_spine_failure(
    tmp_path,
    transport_artifacts,
    monkeypatch,
):
    _vectors, order, receipt, review, _resolver, maker, _taker = (
        transport_artifacts
    )
    delivery = _delivery(transport_artifacts, nonce="46" * 16)
    statement_digest = delivery.to_dict()["statement_digest"]
    store = TradeDisputeStatementDispatchStore(tmp_path)
    store.prepare(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
        target_url="https://peer.example",
        now_ms=int(
            datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc).timestamp()
            * 1_000
        ),
    )
    spine_path = tmp_path / "spine.jsonl"
    coordinator = TradeDisputeStatementDispatchCoordinator(
        store,
        SignedEventLog(spine_path, maker),
    )
    monkeypatch.setattr(
        coordinator,
        "_anchor",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("injected Spine outage")
        ),
    )
    _leased, lease_token = store.acquire_send_lease(statement_digest)

    with pytest.raises(OSError, match="Spine outage"):
        coordinator.acknowledge(
            statement_digest,
            _dispatch_acknowledgement(transport_artifacts, delivery),
            remote_event_id="6" * 64,
            lease_token=lease_token,
        )
    pending_ack = store.get(statement_digest)
    assert pending_ack is not None
    assert pending_ack.acknowledged is True
    assert pending_ack.anchor_event_id == ""

    restarted = TradeDisputeStatementDispatchCoordinator(
        TradeDisputeStatementDispatchStore(tmp_path),
        SignedEventLog(spine_path, maker),
    )
    recovered = restarted.recover_acknowledgement(statement_digest)

    assert recovered is not None
    assert recovered.anchor_event_id
    assert len(restarted.spine.verified_snapshot()) == 1


def test_dispute_statement_dispatch_rejects_target_rebinding(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, _maker, _taker = (
        transport_artifacts
    )
    delivery = _delivery(transport_artifacts, nonce="47" * 16)
    store = TradeDisputeStatementDispatchStore(tmp_path)
    arguments = {
        "review": review,
        "receipt": receipt,
        "order": order,
        "now_ms": int(
            datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc).timestamp()
            * 1_000
        ),
    }
    store.prepare(
        delivery,
        target_url="https://first.example",
        **arguments,
    )

    with pytest.raises(TradeDisputeStatementDispatchError, match="conflicting"):
        store.prepare(
            delivery,
            target_url="https://second.example",
            **arguments,
        )


def test_dispute_statement_dispatch_renews_only_expired_delivery(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, _maker, _taker = (
        transport_artifacts
    )
    original = _delivery(transport_artifacts, nonce="48" * 16)
    premature_replacement = _delivery(
        transport_artifacts,
        nonce="49" * 16,
        created_at="2026-08-01T02:06:00Z",
        not_after="2026-08-01T02:11:00Z",
        now=datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc),
    )
    replacement = _delivery(
        transport_artifacts,
        nonce="4a" * 16,
        created_at="2026-08-01T02:21:00Z",
        not_after="2026-08-01T02:26:00Z",
        now=datetime(2026, 8, 1, 2, 21, tzinfo=timezone.utc),
    )
    store = TradeDisputeStatementDispatchStore(tmp_path)
    store.prepare(
        original,
        review=review,
        receipt=receipt,
        order=order,
        target_url="https://peer.example",
        now_ms=int(
            datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc).timestamp()
            * 1_000
        ),
    )

    with pytest.raises(
        TradeDisputeStatementDispatchError,
        match="not expired",
    ):
        store.replace_expired(
            premature_replacement,
            review=review,
            receipt=receipt,
            order=order,
            target_url="https://peer.example",
            now_ms=int(
                datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc).timestamp()
                * 1_000
            ),
        )

    renewed = store.replace_expired(
        replacement,
        review=review,
        receipt=receipt,
        order=order,
        target_url="https://peer.example",
        now_ms=int(
            datetime(2026, 8, 1, 2, 21, tzinfo=timezone.utc).timestamp()
            * 1_000
        ),
    )

    assert renewed.generation == 2
    assert renewed.attempts == 0
    assert renewed.superseded_delivery_digests == (
        trade_dispute_statement_delivery_digest(
            original,
            review=review,
            receipt=receipt,
            order=order,
        ),
    )


def test_dispute_statement_dispatch_revalidates_acknowledgement_on_restart(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, _maker, _taker = (
        transport_artifacts
    )
    delivery = _delivery(transport_artifacts, nonce="50" * 16)
    conflicting_delivery = _delivery(transport_artifacts, nonce="51" * 16)
    statement_digest = delivery.to_dict()["statement_digest"]
    store = TradeDisputeStatementDispatchStore(tmp_path)
    store.prepare(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
        target_url="https://peer.example",
        now_ms=int(
            datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc).timestamp()
            * 1_000
        ),
    )
    acknowledgement = _dispatch_acknowledgement(
        transport_artifacts,
        conflicting_delivery,
    )
    path = tmp_path / "trade" / "dispute_dispatch_v1" / "dispatch.sqlite3"
    with sqlite3.connect(path) as connection:
        current = connection.execute(
            "SELECT total_bytes FROM dispatches WHERE statement_digest = ?",
            (statement_digest,),
        ).fetchone()[0]
        connection.execute(
            "UPDATE dispatches SET acknowledgement_bytes = ?, "
            "remote_event_id = ?, observed_at_ms = ?, total_bytes = ? "
            "WHERE statement_digest = ?",
            (
                acknowledgement.canonical_bytes,
                "6" * 64,
                int(
                    datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc).timestamp()
                    * 1_000
                ),
                current + len(acknowledgement.canonical_bytes),
                statement_digest,
            ),
        )

    restarted = TradeDisputeStatementDispatchStore(tmp_path)
    with pytest.raises(
        TradeDisputeStatementDispatchError,
        match="stored acknowledgement is invalid",
    ):
        restarted.get(statement_digest)


def test_dispute_statement_dispatch_rejects_unverified_spine_return(
    tmp_path,
    transport_artifacts,
    monkeypatch,
):
    _vectors, order, receipt, review, _resolver, maker, _taker = (
        transport_artifacts
    )
    delivery = _delivery(transport_artifacts, nonce="52" * 16)
    statement_digest = delivery.to_dict()["statement_digest"]
    store = TradeDisputeStatementDispatchStore(tmp_path)
    store.prepare(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
        target_url="https://peer.example",
        now_ms=int(
            datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc).timestamp()
            * 1_000
        ),
    )
    spine = SignedEventLog(tmp_path / "spine.jsonl", maker)
    coordinator = TradeDisputeStatementDispatchCoordinator(store, spine)
    append_unique = spine.append_unique

    def _tampered_append(*args, **kwargs):
        event, created = append_unique(*args, **kwargs)
        document = event.to_dict()
        document["sig"] = ("A" if document["sig"][0] != "A" else "B") + document[
            "sig"
        ][1:]
        return type(event).from_dict(document), created

    monkeypatch.setattr(spine, "append_unique", _tampered_append)
    _leased, lease_token = store.acquire_send_lease(statement_digest)
    with pytest.raises(
        TradeDisputeStatementDispatchError,
        match="conflicting Statement acknowledgement anchor",
    ):
        coordinator.acknowledge(
            statement_digest,
            _dispatch_acknowledgement(transport_artifacts, delivery),
            remote_event_id="6" * 64,
            lease_token=lease_token,
        )

    retained = store.get(statement_digest)
    assert retained is not None
    assert retained.acknowledged is True
    assert retained.anchor_event_id == ""

    restarted = TradeDisputeStatementDispatchCoordinator(
        TradeDisputeStatementDispatchStore(tmp_path),
        SignedEventLog(tmp_path / "spine.jsonl", maker),
    )
    report = restarted.reconcile()
    recovered = restarted.store.get(statement_digest)
    assert report.scanned == 1
    assert report.anchored == 1
    assert report.failed == 0
    assert recovered is not None and recovered.anchor_event_id


def test_dispute_statement_dispatch_send_lease_is_single_flight_and_recoverable(
    tmp_path,
    transport_artifacts,
):
    _vectors, order, receipt, review, _resolver, _maker, _taker = (
        transport_artifacts
    )
    delivery = _delivery(transport_artifacts, nonce="53" * 16)
    statement_digest = delivery.to_dict()["statement_digest"]
    store = TradeDisputeStatementDispatchStore(tmp_path)
    base_ms = int(
        datetime(2026, 8, 1, 2, 6, tzinfo=timezone.utc).timestamp() * 1_000
    )
    store.prepare(
        delivery,
        review=review,
        receipt=receipt,
        order=order,
        target_url="https://peer.example",
        now_ms=base_ms,
    )
    first_token = "a1" * 16
    second_token = "b2" * 16
    leased, retained_token = store.acquire_send_lease(
        statement_digest,
        lease_token=first_token,
        now_ms=base_ms,
        lease_ms=1_000,
    )

    assert retained_token == first_token
    assert leased.lease_expires_at_ms == base_ms + 1_000
    with pytest.raises(
        TradeDisputeStatementDispatchError,
        match="in progress",
    ):
        store.acquire_send_lease(
            statement_digest,
            lease_token=second_token,
            now_ms=base_ms + 999,
            lease_ms=1_000,
        )

    taken_over, retained_token = store.acquire_send_lease(
        statement_digest,
        lease_token=second_token,
        now_ms=base_ms + 1_000,
        lease_ms=1_000,
    )
    assert retained_token == second_token
    assert taken_over.lease_expires_at_ms == base_ms + 2_000
    with pytest.raises(
        TradeDisputeStatementDispatchError,
        match="does not own the send lease",
    ):
        store.put_acknowledgement(
            statement_digest,
            _dispatch_acknowledgement(transport_artifacts, delivery),
            remote_event_id="6" * 64,
            lease_token=first_token,
        )

    store.note_failure(
        statement_digest,
        error="new owner failed safely",
        lease_token=second_token,
        now_ms=base_ms + 1_001,
    )
    released = store.get(statement_digest)
    assert released is not None
    assert released.attempts == 1
    assert released.lease_expires_at_ms == 0


def test_dispute_statement_dispatch_migrates_v2_send_state_schema(tmp_path):
    path = tmp_path / "trade" / "dispute_dispatch_v1" / "dispatch.sqlite3"
    path.parent.mkdir(parents=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE dispatches (
                statement_digest TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                delivery_bytes BLOB NOT NULL,
                review_bytes BLOB NOT NULL,
                receipt_bytes BLOB NOT NULL,
                order_bytes BLOB NOT NULL,
                attempts INTEGER NOT NULL,
                last_error TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                generation INTEGER NOT NULL,
                acknowledgement_bytes BLOB,
                remote_event_id TEXT NOT NULL,
                observed_at_ms INTEGER NOT NULL,
                anchor_event_id TEXT NOT NULL,
                total_bytes INTEGER NOT NULL,
                superseded_delivery_digests TEXT NOT NULL DEFAULT '[]'
            ) WITHOUT ROWID
            """
        )
        connection.execute("PRAGMA user_version = 2")

    TradeDisputeStatementDispatchStore(tmp_path)
    with sqlite3.connect(path) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(dispatches)"
            ).fetchall()
        }

    assert version == 3
    assert {"lease_token", "lease_expires_at_ms"} <= columns


def test_dispute_statement_federation_is_public_trade_rule_api():
    import nth_dao.trade_rules as trade_rules_api

    assert trade_rules_api.TradeDisputeStatementDelivery is (
        TradeDisputeStatementDelivery
    )
    assert trade_rules_api.TradeDisputeStatementAcknowledgement is (
        TradeDisputeStatementAcknowledgement
    )
    assert trade_rules_api.TradeDisputeStatementIntakeCoordinator is (
        TradeDisputeStatementIntakeCoordinator
    )
    assert trade_rules_api.DISPUTE_STATEMENT_DELIVERY_SIGNING_DOMAIN == (
        DISPUTE_STATEMENT_DELIVERY_SIGNING_DOMAIN
    )
