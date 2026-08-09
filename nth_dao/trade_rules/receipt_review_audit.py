"""Signed Spine projection for persisted Trade Receipt Reviews."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from nth_dao.did_key import is_did_key
from nth_dao.spine import SignedEventLog, SpineEvent
from nth_dao.trade_rules.agreement_order import (
    ORDER_ID_PREFIX,
    TradeOrder,
)
from nth_dao.trade_rules.execution_adapter import TradeExecutionAdapterPolicy
from nth_dao.trade_rules.execution_receipt import (
    EXECUTION_RECEIPT_ID_PREFIX,
    TradeExecutionReceipt,
)
from nth_dao.trade_rules.negotiation import RuleResolutionPolicy
from nth_dao.trade_rules.receipt_review import (
    RECEIPT_REVIEW_DECISIONS,
    RECEIPT_REVIEW_ID_PREFIX,
    TradeReceiptReview,
    receipt_review_digest,
)
from nth_dao.trade_rules.receipt_review_store import (
    TradeReceiptReviewConflict,
    TradeReceiptReviewConflictStatus,
    TradeReceiptReviewStore,
)
from nth_dao.trade_rules.receipt_review_outbox import (
    TradeReceiptReviewOutbox,
)

EVENT_TRADE_RECEIPT_REVIEW_CONFLICTED = "trade.receipt.review.conflicted"
EVENT_TRADE_RECEIPT_REVIEWED = "trade.receipt.reviewed"
RECEIPT_REVIEW_AUDIT_PROTOCOL_VERSION = "1"

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ORDER_ID = re.compile(rf"^{re.escape(ORDER_ID_PREFIX)}[0-9a-f]{{64}}$")
_EXECUTION_ID = re.compile(
    rf"^{re.escape(EXECUTION_RECEIPT_ID_PREFIX)}[0-9a-f]{{64}}$"
)
_REVIEW_ID = re.compile(
    rf"^{re.escape(RECEIPT_REVIEW_ID_PREFIX)}[0-9a-f]{{64}}$"
)
_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{6}))?Z$"
)
_FIELDS = frozenset(
    {
        "protocol_version",
        "review_id",
        "review_digest",
        "order_id",
        "order_digest",
        "execution_id",
        "receipt_digest",
        "reviewer_did",
        "reviewer_role",
        "decision",
        "reviewed_at",
    }
)
_CONFLICT_FIELDS = frozenset(
    {
        "protocol_version",
        "review_id",
        "primary_review_digest",
        "candidate_review_digest",
        "order_id",
        "order_digest",
        "execution_id",
        "receipt_digest",
        "reviewer_did",
        "reviewer_role",
        "candidate_decision",
        "candidate_reviewed_at",
        "retention_complete",
    }
)


class TradeReceiptReviewAuditError(RuntimeError):
    """A Receipt Review audit projection is invalid or unavailable."""


def validate_receipt_review_audit_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise TradeReceiptReviewAuditError(
            "Receipt Review Spine payload has missing or unknown fields"
        )
    if value["protocol_version"] != RECEIPT_REVIEW_AUDIT_PROTOCOL_VERSION:
        raise TradeReceiptReviewAuditError(
            "Receipt Review Spine payload version is unsupported"
        )
    for field, pattern in (
        ("review_id", _REVIEW_ID),
        ("order_id", _ORDER_ID),
        ("execution_id", _EXECUTION_ID),
    ):
        if (
            not isinstance(value[field], str)
            or pattern.fullmatch(value[field]) is None
        ):
            raise TradeReceiptReviewAuditError(
                f"Receipt Review Spine payload {field} is invalid"
            )
    for field in ("review_digest", "order_digest", "receipt_digest"):
        if (
            not isinstance(value[field], str)
            or _DIGEST.fullmatch(value[field]) is None
        ):
            raise TradeReceiptReviewAuditError(
                f"Receipt Review Spine payload {field} is invalid"
            )
    if (
        not isinstance(value["reviewer_did"], str)
        or not is_did_key(value["reviewer_did"])
    ):
        raise TradeReceiptReviewAuditError(
            "Receipt Review Spine payload reviewer_did is invalid"
        )
    if value["reviewer_role"] not in {"maker", "taker"}:
        raise TradeReceiptReviewAuditError(
            "Receipt Review Spine payload reviewer_role is invalid"
        )
    if value["decision"] not in RECEIPT_REVIEW_DECISIONS:
        raise TradeReceiptReviewAuditError(
            "Receipt Review Spine payload decision is invalid"
        )
    reviewed_at = value["reviewed_at"]
    match = (
        _TIMESTAMP.fullmatch(reviewed_at)
        if isinstance(reviewed_at, str)
        else None
    )
    if match is None or match.group(2) == "000000":
        raise TradeReceiptReviewAuditError(
            "Receipt Review Spine payload reviewed_at is invalid"
        )
    try:
        datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TradeReceiptReviewAuditError(
            "Receipt Review Spine payload reviewed_at is invalid"
        ) from exc
    return dict(value)


def validate_receipt_review_conflict_audit_payload(
    value: Any,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _CONFLICT_FIELDS:
        raise TradeReceiptReviewAuditError(
            "Receipt Review conflict payload has missing or unknown fields"
        )
    if value["protocol_version"] != RECEIPT_REVIEW_AUDIT_PROTOCOL_VERSION:
        raise TradeReceiptReviewAuditError(
            "Receipt Review conflict payload version is unsupported"
        )
    for field, pattern in (
        ("review_id", _REVIEW_ID),
        ("order_id", _ORDER_ID),
        ("execution_id", _EXECUTION_ID),
    ):
        if (
            not isinstance(value[field], str)
            or pattern.fullmatch(value[field]) is None
        ):
            raise TradeReceiptReviewAuditError(
                f"Receipt Review conflict payload {field} is invalid"
            )
    for field in (
        "primary_review_digest",
        "candidate_review_digest",
        "order_digest",
        "receipt_digest",
    ):
        if (
            not isinstance(value[field], str)
            or _DIGEST.fullmatch(value[field]) is None
        ):
            raise TradeReceiptReviewAuditError(
                f"Receipt Review conflict payload {field} is invalid"
            )
    if value["primary_review_digest"] == value["candidate_review_digest"]:
        raise TradeReceiptReviewAuditError(
            "Receipt Review conflict digests must differ"
        )
    if (
        not isinstance(value["reviewer_did"], str)
        or not is_did_key(value["reviewer_did"])
    ):
        raise TradeReceiptReviewAuditError(
            "Receipt Review conflict payload reviewer_did is invalid"
        )
    if value["reviewer_role"] not in {"maker", "taker"}:
        raise TradeReceiptReviewAuditError(
            "Receipt Review conflict payload reviewer_role is invalid"
        )
    if value["candidate_decision"] not in RECEIPT_REVIEW_DECISIONS:
        raise TradeReceiptReviewAuditError(
            "Receipt Review conflict payload decision is invalid"
        )
    candidate_reviewed_at = value["candidate_reviewed_at"]
    match = (
        _TIMESTAMP.fullmatch(candidate_reviewed_at)
        if isinstance(candidate_reviewed_at, str)
        else None
    )
    if match is None or match.group(2) == "000000":
        raise TradeReceiptReviewAuditError(
            "Receipt Review conflict payload reviewed_at is invalid"
        )
    try:
        datetime.fromisoformat(candidate_reviewed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TradeReceiptReviewAuditError(
            "Receipt Review conflict payload reviewed_at is invalid"
        ) from exc
    if not isinstance(value["retention_complete"], bool):
        raise TradeReceiptReviewAuditError(
            "Receipt Review conflict retention_complete must be boolean"
        )
    return dict(value)


def receipt_review_conflict_audit_payload(
    review: TradeReceiptReview,
    *,
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    status: TradeReceiptReviewConflictStatus,
) -> dict[str, Any]:
    verified = TradeReceiptReview.from_json(
        review.canonical_bytes,
        receipt=receipt,
        order=order,
    )
    document = verified.to_dict()
    candidate_digest = receipt_review_digest(
        verified,
        receipt=receipt,
        order=order,
    )
    if (
        not status.has_conflict
        or status.review_id != verified.review_id
        or status.primary_review_digest is None
        or status.primary_review_digest == candidate_digest
        or candidate_digest not in status.retained_review_digests
    ):
        raise TradeReceiptReviewAuditError(
            "Receipt Review conflict status does not bind the candidate"
        )
    payload = {
        "protocol_version": RECEIPT_REVIEW_AUDIT_PROTOCOL_VERSION,
        "review_id": document["review_id"],
        "primary_review_digest": status.primary_review_digest,
        "candidate_review_digest": candidate_digest,
        "order_id": document["order_id"],
        "order_digest": document["order_digest"],
        "execution_id": document["execution_id"],
        "receipt_digest": document["receipt_digest"],
        "reviewer_did": document["reviewer_did"],
        "reviewer_role": document["reviewer_role"],
        "candidate_decision": document["decision"],
        "candidate_reviewed_at": document["reviewed_at"],
        "retention_complete": status.retention_complete,
    }
    return validate_receipt_review_conflict_audit_payload(payload)


def receipt_review_audit_payload(
    review: TradeReceiptReview,
    *,
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
) -> dict[str, Any]:
    verified = TradeReceiptReview.from_json(
        review.canonical_bytes,
        receipt=receipt,
        order=order,
    )
    document = verified.to_dict()
    return {
        "protocol_version": RECEIPT_REVIEW_AUDIT_PROTOCOL_VERSION,
        "review_id": document["review_id"],
        "review_digest": receipt_review_digest(
            verified,
            receipt=receipt,
            order=order,
        ),
        "order_id": document["order_id"],
        "order_digest": document["order_digest"],
        "execution_id": document["execution_id"],
        "receipt_digest": document["receipt_digest"],
        "reviewer_did": document["reviewer_did"],
        "reviewer_role": document["reviewer_role"],
        "decision": document["decision"],
        "reviewed_at": document["reviewed_at"],
    }


def validate_receipt_review_audit_binding(
    value: Any,
    *,
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
) -> dict[str, Any]:
    verified_review = (
        TradeReceiptReview.from_json(
            review.canonical_bytes,
            receipt=receipt,
            order=order,
        )
        if isinstance(review, TradeReceiptReview)
        else TradeReceiptReview.from_dict(
            review,
            receipt=receipt,
            order=order,
        )
    )
    expected = receipt_review_audit_payload(
        verified_review,
        receipt=receipt,
        order=order,
    )
    actual = validate_receipt_review_audit_payload(value)
    if actual != expected:
        raise TradeReceiptReviewAuditError(
            "Receipt Review Spine payload does not bind the signed review"
        )
    return actual


@dataclass(frozen=True)
class TradeReceiptReviewAuditResult:
    review: TradeReceiptReview
    event: SpineEvent
    prepared_created: bool
    store_created: bool
    anchor_created: bool
    conflict_detected: bool


@dataclass(frozen=True)
class TradeReceiptReviewAuditReconciliation:
    scanned: int
    anchored: int
    verified_anchored: int
    conflicted: int
    failed: int
    next_cursor: str | None
    has_more: bool


class TradeReceiptReviewCoordinator:
    """Persist a Review CAS before projecting one idempotent Spine event."""

    def __init__(
        self,
        store: TradeReceiptReviewStore,
        spine: SignedEventLog,
        audit_outbox: TradeReceiptReviewOutbox | None = None,
    ) -> None:
        if not isinstance(store, TradeReceiptReviewStore):
            raise TypeError("store must be a TradeReceiptReviewStore")
        if not isinstance(spine, SignedEventLog):
            raise TypeError("spine must be a SignedEventLog")
        if audit_outbox is None:
            audit_outbox = TradeReceiptReviewOutbox(store.workspace_root)
        if not isinstance(audit_outbox, TradeReceiptReviewOutbox):
            raise TypeError(
                "audit_outbox must be a TradeReceiptReviewOutbox"
            )
        self.store = store
        self.spine = spine
        self.audit_outbox = audit_outbox

    @staticmethod
    def _reviewed_at_ms(review: TradeReceiptReview) -> int:
        value = review.to_dict()["reviewed_at"]
        return int(
            datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
            * 1000
        )

    def _find_anchor(
        self,
        *,
        event_type: str,
        payload: dict[str, Any],
        event_id: str = "",
    ) -> SpineEvent | None:
        try:
            events = self.spine.verified_snapshot()
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise TradeReceiptReviewAuditError(
                f"Spine integrity check failed: {exc}"
            ) from exc
        matches = [
            event
            for event in events
            if event.type == event_type
            and event.payload.get("review_id") == payload["review_id"]
            and event.payload.get(
                "review_digest"
                if event_type == EVENT_TRADE_RECEIPT_REVIEWED
                else "candidate_review_digest"
            )
            == (
                payload["review_digest"]
                if event_type == EVENT_TRADE_RECEIPT_REVIEWED
                else payload["candidate_review_digest"]
            )
        ]
        if len(matches) > 1:
            raise TradeReceiptReviewAuditError(
                "Spine contains duplicate Receipt Review anchors"
            )
        event = matches[0] if matches else None
        if event is not None and event.payload != payload:
            raise TradeReceiptReviewAuditError(
                "Spine contains a conflicting Receipt Review anchor"
            )
        if event_id and (event is None or event.event_id != event_id):
            raise TradeReceiptReviewAuditError(
                "outbox event_id does not match Spine"
            )
        return event

    def _process(
        self,
        review_digest: str,
        *,
        prepared_created: bool,
    ) -> TradeReceiptReviewAuditResult:
        try:
            with self.audit_outbox.acquire_reconcile():
                record = self.audit_outbox._get_locked(review_digest)
                if record is None:
                    raise TradeReceiptReviewAuditError(
                        "Receipt Review outbox record disappeared"
                    )
                review, receipt, order = record.artifacts
                moment = max(
                    self._reviewed_at_ms(review),
                    record.updated_at_ms,
                )
                store_created = False
                if record.status == "prepared":
                    try:
                        _stored, store_created = self.store.put_with_status(
                            review,
                            receipt=receipt,
                            order=order,
                        )
                    except TradeReceiptReviewConflict:
                        record = self.audit_outbox._transition_locked(
                            review_digest,
                            expected=frozenset({"prepared"}),
                            status="conflicted",
                            now_ms=moment,
                            event_type=(
                                EVENT_TRADE_RECEIPT_REVIEW_CONFLICTED
                            ),
                        )
                    except (OSError, RuntimeError, TypeError, ValueError):
                        self.audit_outbox._transition_locked(
                            review_digest,
                            expected=frozenset({"prepared"}),
                            status="prepared",
                            now_ms=moment,
                            event_type="",
                            last_error="receipt-review-store-failed",
                            increment_attempts=True,
                        )
                        raise
                    else:
                        record = self.audit_outbox._transition_locked(
                            review_digest,
                            expected=frozenset({"prepared"}),
                            status="reviewed",
                            now_ms=moment,
                            event_type=EVENT_TRADE_RECEIPT_REVIEWED,
                        )
                conflict_detected = record.event_type == (
                    EVENT_TRADE_RECEIPT_REVIEW_CONFLICTED
                )
                if conflict_detected:
                    status = self.store.conflict_status(
                        review.review_id,
                        receipt=receipt,
                        order=order,
                    )
                    payload = receipt_review_conflict_audit_payload(
                        review,
                        receipt=receipt,
                        order=order,
                        status=status,
                    )
                    unique_fields = ("candidate_review_digest",)
                else:
                    payload = receipt_review_audit_payload(
                        review,
                        receipt=receipt,
                        order=order,
                    )
                    unique_fields = ("review_id", "review_digest")
                if record.status == "anchored":
                    event = self._find_anchor(
                        event_type=record.event_type,
                        payload=payload,
                        event_id=record.event_id,
                    )
                    if event is None:
                        raise TradeReceiptReviewAuditError(
                            "anchored outbox record has no Spine event"
                        )
                    return TradeReceiptReviewAuditResult(
                        review=review,
                        event=event,
                        prepared_created=prepared_created,
                        store_created=False,
                        anchor_created=False,
                        conflict_detected=conflict_detected,
                    )
                try:
                    event = self._find_anchor(
                        event_type=record.event_type,
                        payload=payload,
                    )
                    anchor_created = event is None
                    if event is None:
                        event, anchor_created = self.spine.append_unique(
                            record.event_type,
                            payload,
                            unique_payload_fields=unique_fields,
                            ts_ms=moment,
                        )
                except (OSError, RuntimeError, TypeError, ValueError) as exc:
                    self.audit_outbox._transition_locked(
                        review_digest,
                        expected=frozenset({record.status}),
                        status=record.status,
                        now_ms=moment,
                        event_type=record.event_type,
                        last_error="spine-anchor-failed",
                        increment_attempts=True,
                    )
                    raise TradeReceiptReviewAuditError(
                        "unable to project Receipt Review into Spine: "
                        f"{exc}"
                    ) from exc
                record = self.audit_outbox._transition_locked(
                    review_digest,
                    expected=frozenset({record.status}),
                    status="anchored",
                    now_ms=moment,
                    event_type=record.event_type,
                    event_id=event.event_id,
                )
                return TradeReceiptReviewAuditResult(
                    review=review,
                    event=event,
                    prepared_created=prepared_created,
                    store_created=store_created,
                    anchor_created=anchor_created,
                    conflict_detected=conflict_detected,
                )
        except TimeoutError as exc:
            raise TradeReceiptReviewAuditError(
                "Receipt Review reconciliation is busy"
            ) from exc

    def _record(
        self,
        review: TradeReceiptReview | dict[str, Any],
        *,
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        verifier_policy: RuleResolutionPolicy | None = None,
        adapter_policy: TradeExecutionAdapterPolicy | None = None,
        observed_at_ms: int | None = None,
        allow_legacy_without_policy_snapshots: bool = False,
    ) -> TradeReceiptReviewAuditResult:
        if not isinstance(allow_legacy_without_policy_snapshots, bool):
            raise TypeError(
                "allow_legacy_without_policy_snapshots must be boolean"
            )
        if allow_legacy_without_policy_snapshots and (
            verifier_policy is not None or adapter_policy is not None
        ):
            raise TradeReceiptReviewAuditError(
                "legacy Receipt Review records must omit policy snapshots"
            )
        if not allow_legacy_without_policy_snapshots and (
            verifier_policy is None or adapter_policy is None
        ):
            raise TradeReceiptReviewAuditError(
                "Receipt Review policy snapshots are required"
            )
        if not allow_legacy_without_policy_snapshots and observed_at_ms is None:
            raise TradeReceiptReviewAuditError(
                "Receipt Review first observation time is required"
            )
        verified = (
            TradeReceiptReview.from_json(
                review.canonical_bytes,
                receipt=receipt,
                order=order,
            )
            if isinstance(review, TradeReceiptReview)
            else TradeReceiptReview.from_dict(
                review,
                receipt=receipt,
                order=order,
            )
        )
        verified_order = (
            TradeOrder.from_json(order.canonical_bytes)
            if isinstance(order, TradeOrder)
            else TradeOrder.from_dict(order)
        )
        verified_receipt = TradeExecutionReceipt.from_json(
            (
                receipt.canonical_bytes
                if isinstance(receipt, TradeExecutionReceipt)
                else TradeExecutionReceipt.from_dict(
                    receipt,
                    order=verified_order,
                ).canonical_bytes
            ),
            order=verified_order,
        )
        digest = receipt_review_digest(
            verified,
            receipt=verified_receipt,
            order=verified_order,
        )
        observation_ms = (
            self._reviewed_at_ms(verified)
            if allow_legacy_without_policy_snapshots and observed_at_ms is None
            else observed_at_ms
        )
        assert observation_ms is not None
        if allow_legacy_without_policy_snapshots:
            _prepared_record, prepared_created = (
                self.audit_outbox.prepare_legacy(
                    verified,
                    receipt=verified_receipt,
                    order=verified_order,
                    now_ms=observation_ms,
                )
            )
        else:
            assert verifier_policy is not None
            assert adapter_policy is not None
            _prepared_record, prepared_created = self.audit_outbox.prepare(
                verified,
                receipt=verified_receipt,
                order=verified_order,
                now_ms=observation_ms,
                verifier_policy=verifier_policy,
                adapter_policy=adapter_policy,
            )
        result = self._process(
            digest,
            prepared_created=prepared_created,
        )
        if result.conflict_detected:
            raise TradeReceiptReviewConflict(
                "review has contradictory signed candidates"
            )
        return result

    def record(
        self,
        review: TradeReceiptReview | dict[str, Any],
        *,
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        verifier_policy: RuleResolutionPolicy,
        adapter_policy: TradeExecutionAdapterPolicy,
        observed_at_ms: int,
    ) -> TradeReceiptReviewAuditResult:
        """Publish a v2 Review with exact immutable policy snapshots."""

        return self._record(
            review,
            receipt=receipt,
            order=order,
            verifier_policy=verifier_policy,
            adapter_policy=adapter_policy,
            observed_at_ms=observed_at_ms,
        )

    def record_legacy(
        self,
        review: TradeReceiptReview | dict[str, Any],
        *,
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        observed_at_ms: int | None = None,
    ) -> TradeReceiptReviewAuditResult:
        """Record a pre-v2 Review during explicit migration or recovery."""

        return self._record(
            review,
            receipt=receipt,
            order=order,
            observed_at_ms=observed_at_ms,
            allow_legacy_without_policy_snapshots=True,
        )

    def policy_snapshots(
        self,
        review_digest: str,
    ) -> tuple[RuleResolutionPolicy, TradeExecutionAdapterPolicy] | None:
        """Return immutable policy bytes retained with a signed Review."""

        return self.audit_outbox.get_policy_snapshots(review_digest)

    def observed_at_ms(self, review_digest: str) -> int:
        """Return the durable first v2 observation time for one Review."""

        return self.audit_outbox.observed_at_ms(review_digest)

    def reconcile(
        self,
        *,
        limit: int = 100,
        after_digest: str | None = None,
    ) -> TradeReceiptReviewAuditReconciliation:
        records, has_more = self.audit_outbox.pending(
            limit=limit,
            after_digest=after_digest,
        )
        anchored = 0
        verified_anchored = 0
        conflicted = 0
        failed = 0
        for record in records:
            try:
                result = self._process(
                    record.review_digest,
                    prepared_created=False,
                )
            except (
                OSError,
                RuntimeError,
                TypeError,
                ValueError,
            ):
                failed += 1
                continue
            if result.anchor_created:
                anchored += 1
            else:
                verified_anchored += 1
            conflicted += int(result.conflict_detected)
        return TradeReceiptReviewAuditReconciliation(
            scanned=len(records),
            anchored=anchored,
            verified_anchored=verified_anchored,
            conflicted=conflicted,
            failed=failed,
            next_cursor=(
                records[-1].review_digest if records and has_more else None
            ),
            has_more=has_more,
        )


__all__ = [
    "EVENT_TRADE_RECEIPT_REVIEW_CONFLICTED",
    "EVENT_TRADE_RECEIPT_REVIEWED",
    "RECEIPT_REVIEW_AUDIT_PROTOCOL_VERSION",
    "TradeReceiptReviewAuditError",
    "TradeReceiptReviewAuditReconciliation",
    "TradeReceiptReviewAuditResult",
    "TradeReceiptReviewCoordinator",
    "receipt_review_conflict_audit_payload",
    "receipt_review_audit_payload",
    "validate_receipt_review_audit_binding",
    "validate_receipt_review_audit_payload",
    "validate_receipt_review_conflict_audit_payload",
]
