"""Claim-not-fact Spine anchors for retained Trade Dispute Statements."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from nth_dao.did_key import is_did_key
from nth_dao.spine import SignedEventLog, SpineEvent, verify_event
from nth_dao.trade_rules.agreement import DEFAULT_CLOCK_SKEW_SECONDS
from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.dispute_statement import (
    TRADE_DISPUTE_ID_PREFIX,
    TRADE_DISPUTE_STATEMENT_ID_PREFIX,
    TRADE_DISPUTE_STATEMENT_TYPES,
    TradeDisputeStatement,
    TradeDisputeStatementRejected,
)
from nth_dao.trade_rules.canonical import (
    TradeCanonicalJSONError,
    trade_canonical_json,
)
from nth_dao.trade_rules.dispute_statement_store import (
    TradeDisputeStatementStore,
)
from nth_dao.trade_rules.dispute_statement_outbox import (
    TradeDisputeStatementAuditOutbox,
)
from nth_dao.trade_rules.execution_receipt import TradeExecutionReceipt
from nth_dao.trade_rules.execution_receipt import EXECUTION_RECEIPT_ID_PREFIX
from nth_dao.trade_rules.negotiation import RulePackageResolver
from nth_dao.trade_rules.receipt_review import (
    RECEIPT_REVIEW_ID_PREFIX,
    TradeReceiptReview,
)

EVENT_TRADE_DISPUTE_STATEMENT_RETAINED = "trade.dispute.statement.retained"
EVENT_TRADE_DISPUTE_STATEMENT_CREATE_RESERVED = (
    "trade.dispute.statement.create.reserved"
)
EVENT_TRADE_DISPUTE_STATEMENT_CREATE_ATTEMPT_FAILED = (
    "trade.dispute.statement.create.attempt-failed"
)
TRADE_DISPUTE_STATEMENT_AUDIT_PROTOCOL_VERSION = "1"
TRADE_DISPUTE_STATEMENT_ASSERTION_STATUS = "signed-claim-not-adjudicated"
TRADE_DISPUTE_STATEMENT_CREATE_FAILURE_REASONS = frozenset(
    {
        "dependency-unavailable",
        "statement-rejected",
        "parent-chain-unavailable",
        "store-busy",
        "store-capacity",
        "store-integrity-conflict",
        "persistence-incomplete",
    }
)
_CREATE_FAILURE_RETRYABILITY = {
    "dependency-unavailable": True,
    "statement-rejected": False,
    "parent-chain-unavailable": True,
    "store-busy": True,
    "store-capacity": True,
    "store-integrity-conflict": False,
    "persistence-incomplete": True,
}
MAX_TRADE_DISPUTE_AUDIT_OBSERVED_AT_MS = 253_402_300_799_999

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_DISPUTE_ID = re.compile(rf"^{re.escape(TRADE_DISPUTE_ID_PREFIX)}[0-9a-f]{{64}}$")
_STATEMENT_ID = re.compile(
    rf"^{re.escape(TRADE_DISPUTE_STATEMENT_ID_PREFIX)}[0-9a-f]{{64}}$"
)
_REVIEW_ID = re.compile(rf"^{re.escape(RECEIPT_REVIEW_ID_PREFIX)}[0-9a-f]{{64}}$")
_TIMESTAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{6}))?Z$")
_PAYLOAD_FIELDS = frozenset(
    {
        "protocol_version",
        "statement_id",
        "statement_digest",
        "dispute_id",
        "order_digest",
        "receipt_digest",
        "review_digest",
        "review_id",
        "author_did",
        "author_role",
        "statement_type",
        "created_at",
        "assertion_status",
    }
)
_CREATE_FAILURE_PAYLOAD_FIELDS = frozenset(
    {
        "protocol_version",
        "failure_id",
        "operation_id",
        "request_digest",
        "reason_code",
        "retryable",
    }
)
_CREATE_RESERVATION_PAYLOAD_FIELDS = frozenset(
    {
        "protocol_version",
        "operation_id",
        "request_digest",
        "order_digest",
        "execution_id",
        "review_id",
        "author_did",
    }
)
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
_EXECUTION_ID = re.compile(
    rf"^{re.escape(EXECUTION_RECEIPT_ID_PREFIX)}[0-9a-f]{{64}}$"
)


class TradeDisputeStatementAuditError(RuntimeError):
    """A dispute-statement audit projection is invalid or unavailable."""


def trade_dispute_statement_create_reservation_payload(
    *,
    idempotency_key: str,
    body: dict[str, Any],
    order_digest: str,
    execution_id: str,
    review_id: str,
    author_did: str,
) -> dict[str, Any]:
    """Bind one retry key to one exact local Statement creation request."""

    if (
        not isinstance(idempotency_key, str)
        or _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None
    ):
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement idempotency_key is invalid"
        )
    if not isinstance(body, dict):
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement creation body must be an object"
        )
    if not is_did_key(author_did):
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement creation author_did is invalid"
        )
    operation_material = (
        "nth-dao/trade-dispute-statement-create/v1\0"
        + author_did
        + "\0"
        + idempotency_key
    ).encode("ascii", errors="strict")
    request_material = {
        "order_digest": order_digest,
        "execution_id": execution_id,
        "review_id": review_id,
        "author_did": author_did,
        "body": body,
    }
    try:
        canonical_request = trade_canonical_json(request_material)
    except (TradeCanonicalJSONError, TypeError, ValueError, UnicodeError) as exc:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement creation request is not canonicalizable"
        ) from exc
    return validate_trade_dispute_statement_create_reservation_payload(
        {
            "protocol_version": TRADE_DISPUTE_STATEMENT_AUDIT_PROTOCOL_VERSION,
            "operation_id": (
                "sha256:" + hashlib.sha256(operation_material).hexdigest()
            ),
            "request_digest": (
                "sha256:" + hashlib.sha256(canonical_request).hexdigest()
            ),
            "order_digest": order_digest,
            "execution_id": execution_id,
            "review_id": review_id,
            "author_did": author_did,
        }
    )


def validate_trade_dispute_statement_create_reservation_payload(
    value: Any,
) -> dict[str, Any]:
    """Validate the closed wire shape of a creation reservation event."""

    if not isinstance(value, dict) or set(value) != _CREATE_RESERVATION_PAYLOAD_FIELDS:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement creation reservation has missing or unknown fields"
        )
    if value["protocol_version"] != TRADE_DISPUTE_STATEMENT_AUDIT_PROTOCOL_VERSION:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement creation reservation version is unsupported"
        )
    for field in ("operation_id", "request_digest", "order_digest"):
        if not isinstance(value[field], str) or _DIGEST.fullmatch(value[field]) is None:
            raise TradeDisputeStatementAuditError(
                f"Trade Dispute Statement creation reservation {field} is invalid"
            )
    if (
        not isinstance(value["execution_id"], str)
        or _EXECUTION_ID.fullmatch(value["execution_id"]) is None
    ):
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement creation reservation execution_id is invalid"
        )
    if (
        not isinstance(value["review_id"], str)
        or _REVIEW_ID.fullmatch(value["review_id"]) is None
    ):
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement creation reservation review_id is invalid"
        )
    if not is_did_key(value["author_did"]):
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement creation reservation author_did is invalid"
        )
    return dict(value)


def validate_trade_dispute_statement_create_reservation_binding(
    value: Any,
    *,
    idempotency_key: str,
    body: dict[str, Any],
    order_digest: str,
    execution_id: str,
    review_id: str,
    author_did: str,
) -> dict[str, Any]:
    """Require a reservation to bind the exact retry key and request body."""

    payload = validate_trade_dispute_statement_create_reservation_payload(value)
    expected = trade_dispute_statement_create_reservation_payload(
        idempotency_key=idempotency_key,
        body=body,
        order_digest=order_digest,
        execution_id=execution_id,
        review_id=review_id,
        author_did=author_did,
    )
    if payload != expected:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement creation reservation does not bind the request"
        )
    return payload


def trade_dispute_statement_create_failure_payload(
    *,
    operation_id: str,
    request_digest: str,
    reason_code: str,
) -> dict[str, Any]:
    """Build an idempotent signed audit payload for one failed attempt class."""

    if reason_code not in TRADE_DISPUTE_STATEMENT_CREATE_FAILURE_REASONS:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement creation failure reason_code is invalid"
        )
    for field, value in (
        ("operation_id", operation_id),
        ("request_digest", request_digest),
    ):
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            raise TradeDisputeStatementAuditError(
                f"Trade Dispute Statement creation failure payload {field} is invalid"
            )
    failure_material = (
        "nth-dao/trade-dispute-statement-create-failure/v1\0"
        + operation_id
        + "\0"
        + request_digest
        + "\0"
        + reason_code
    ).encode("ascii", errors="strict")
    return validate_trade_dispute_statement_create_failure_payload(
        {
            "protocol_version": TRADE_DISPUTE_STATEMENT_AUDIT_PROTOCOL_VERSION,
            "failure_id": "sha256:" + hashlib.sha256(failure_material).hexdigest(),
            "operation_id": operation_id,
            "request_digest": request_digest,
            "reason_code": reason_code,
            "retryable": _CREATE_FAILURE_RETRYABILITY[reason_code],
        }
    )


def validate_trade_dispute_statement_create_failure_payload(
    value: Any,
) -> dict[str, Any]:
    """Validate the closed wire shape of a creation-attempt failure event."""

    if not isinstance(value, dict) or set(value) != _CREATE_FAILURE_PAYLOAD_FIELDS:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement creation failure payload has missing or unknown fields"
        )
    if value["protocol_version"] != TRADE_DISPUTE_STATEMENT_AUDIT_PROTOCOL_VERSION:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement creation failure payload version is unsupported"
        )
    for field in ("failure_id", "operation_id", "request_digest"):
        if not isinstance(value[field], str) or _DIGEST.fullmatch(value[field]) is None:
            raise TradeDisputeStatementAuditError(
                f"Trade Dispute Statement creation failure payload {field} is invalid"
            )
    if value["reason_code"] not in TRADE_DISPUTE_STATEMENT_CREATE_FAILURE_REASONS:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement creation failure reason_code is invalid"
        )
    if value["retryable"] is not _CREATE_FAILURE_RETRYABILITY[value["reason_code"]]:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement creation failure retryability is invalid"
        )
    failure_material = (
        "nth-dao/trade-dispute-statement-create-failure/v1\0"
        + value["operation_id"]
        + "\0"
        + value["request_digest"]
        + "\0"
        + value["reason_code"]
    ).encode("ascii", errors="strict")
    expected = "sha256:" + hashlib.sha256(failure_material).hexdigest()
    if value["failure_id"] != expected:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement creation failure_id binding is invalid"
        )
    return dict(value)


@dataclass(frozen=True)
class TradeDisputeStatementAuditResult:
    statement: TradeDisputeStatement
    event: SpineEvent
    store_created: bool
    anchor_created: bool


@dataclass(frozen=True)
class TradeDisputeStatementAuditReconciliation:
    """One bounded pass over retained claims for an exact Review."""

    scanned: int
    anchored: int
    verified_anchored: int
    failed: int
    next_cursor: str | None
    has_more: bool


def _canonical_timestamp(value: Any) -> None:
    match = _TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    if match is None or match.group(2) == "000000":
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement Spine payload created_at is invalid"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement Spine payload created_at is invalid"
        ) from exc
    if parsed.tzinfo != timezone.utc:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement Spine payload created_at is invalid"
        )


def _observation(value: Any) -> tuple[int, datetime]:
    if value is None:
        moment = datetime.now(timezone.utc)
        value = int(moment.timestamp() * 1000)
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_TRADE_DISPUTE_AUDIT_OBSERVED_AT_MS
    ):
        raise ValueError("observed_at_ms must be a positive supported UTC millisecond")
    observed = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=value)
    return value, observed


def validate_trade_dispute_statement_audit_payload(
    value: Any,
) -> dict[str, Any]:
    """Validate the closed wire shape of a retained-claim Spine anchor."""

    if not isinstance(value, dict) or set(value) != _PAYLOAD_FIELDS:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement Spine payload has missing or unknown fields"
        )
    if value["protocol_version"] != TRADE_DISPUTE_STATEMENT_AUDIT_PROTOCOL_VERSION:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement Spine payload version is unsupported"
        )
    for field, pattern in (
        ("statement_id", _STATEMENT_ID),
        ("dispute_id", _DISPUTE_ID),
        ("review_id", _REVIEW_ID),
    ):
        if not isinstance(value[field], str) or pattern.fullmatch(value[field]) is None:
            raise TradeDisputeStatementAuditError(
                f"Trade Dispute Statement Spine payload {field} is invalid"
            )
    for field in (
        "statement_digest",
        "order_digest",
        "receipt_digest",
        "review_digest",
    ):
        if not isinstance(value[field], str) or _DIGEST.fullmatch(value[field]) is None:
            raise TradeDisputeStatementAuditError(
                f"Trade Dispute Statement Spine payload {field} is invalid"
            )
    if not isinstance(value["author_did"], str) or not is_did_key(value["author_did"]):
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement Spine payload author_did is invalid"
        )
    if value["author_role"] not in {"maker", "taker"}:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement Spine payload author_role is invalid"
        )
    if value["statement_type"] not in TRADE_DISPUTE_STATEMENT_TYPES:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement Spine payload statement_type is invalid"
        )
    _canonical_timestamp(value["created_at"])
    if value["assertion_status"] != TRADE_DISPUTE_STATEMENT_ASSERTION_STATUS:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement Spine payload assertion_status is invalid"
        )
    return dict(value)


def trade_dispute_statement_audit_payload(
    statement: TradeDisputeStatement,
) -> dict[str, Any]:
    """Build an exact, non-adjudicating audit binding for a verified claim."""

    if not isinstance(statement, TradeDisputeStatement):
        raise TypeError("statement must be a TradeDisputeStatement")
    document = statement.to_dict()
    return validate_trade_dispute_statement_audit_payload(
        {
            "protocol_version": (TRADE_DISPUTE_STATEMENT_AUDIT_PROTOCOL_VERSION),
            "statement_id": document["statement_id"],
            "statement_digest": "sha256:"
            + hashlib.sha256(statement.canonical_bytes).hexdigest(),
            "dispute_id": document["dispute_id"],
            "order_digest": document["order_digest"],
            "receipt_digest": document["receipt_digest"],
            "review_digest": document["review_digest"],
            "review_id": document["review_id"],
            "author_did": document["author_did"],
            "author_role": document["author_role"],
            "statement_type": document["statement_type"],
            "created_at": document["created_at"],
            "assertion_status": (TRADE_DISPUTE_STATEMENT_ASSERTION_STATUS),
        }
    )


def validate_trade_dispute_statement_audit_binding(
    value: Any,
    *,
    statement: TradeDisputeStatement | dict[str, Any],
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    package_resolver: RulePackageResolver | None = None,
) -> dict[str, Any]:
    """Require an anchor to bind the exact fully verified signed claim."""

    verified = _verified_statement(
        statement,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=package_resolver,
    )
    return _assert_payload_binding(value, statement=verified)


def _verified_statement(
    statement: TradeDisputeStatement | dict[str, Any],
    *,
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    package_resolver: RulePackageResolver | None,
) -> TradeDisputeStatement:
    return (
        TradeDisputeStatement.from_json(
            statement.canonical_bytes,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=package_resolver,
        )
        if isinstance(statement, TradeDisputeStatement)
        else TradeDisputeStatement.from_dict(
            statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=package_resolver,
        )
    )


def _verified_context(
    *,
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
) -> tuple[TradeReceiptReview, TradeExecutionReceipt, TradeOrder]:
    verified_order = (
        TradeOrder.from_json(order.canonical_bytes)
        if isinstance(order, TradeOrder)
        else TradeOrder.from_dict(order)
    )
    verified_receipt = (
        TradeExecutionReceipt.from_json(
            receipt.canonical_bytes,
            order=verified_order,
        )
        if isinstance(receipt, TradeExecutionReceipt)
        else TradeExecutionReceipt.from_dict(receipt, order=verified_order)
    )
    verified_review = (
        TradeReceiptReview.from_json(
            review.canonical_bytes,
            receipt=verified_receipt,
            order=verified_order,
        )
        if isinstance(review, TradeReceiptReview)
        else TradeReceiptReview.from_dict(
            review,
            receipt=verified_receipt,
            order=verified_order,
        )
    )
    return verified_review, verified_receipt, verified_order


def _assert_payload_binding(
    value: Any,
    *,
    statement: TradeDisputeStatement,
) -> dict[str, Any]:
    payload = validate_trade_dispute_statement_audit_payload(value)
    expected = trade_dispute_statement_audit_payload(statement)
    if payload != expected:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement Spine payload does not bind the signed claim"
        )
    return payload


def validate_trade_dispute_statement_audit_event(
    event: SpineEvent,
    *,
    expected_author_did: str,
    statement: TradeDisputeStatement | dict[str, Any],
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    package_resolver: RulePackageResolver | None = None,
    clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
) -> dict[str, Any]:
    """Verify one signed Spine event, exact claim binding, and chronology."""

    if not isinstance(event, SpineEvent):
        raise TypeError("event must be a SpineEvent")
    if not isinstance(expected_author_did, str) or not is_did_key(
        expected_author_did
    ):
        raise ValueError("expected_author_did must be an Ed25519 did:key")
    valid, reason = verify_event(event)
    if not valid:
        raise TradeDisputeStatementAuditError(
            f"Trade Dispute Statement Spine event is invalid: {reason}"
        )
    if event.type != EVENT_TRADE_DISPUTE_STATEMENT_RETAINED:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement Spine event type is invalid"
        )
    if event.author_did != expected_author_did:
        raise TradeDisputeStatementAuditError(
            "Trade Dispute Statement Spine event author is not authorized"
        )
    verified = _verified_statement(
        statement,
        review=review,
        receipt=receipt,
        order=order,
        package_resolver=package_resolver,
    )
    payload = _assert_payload_binding(event.payload, statement=verified)
    try:
        _moment, observed = _observation(event.ts_ms)
        verified.assert_observed_at(
            at=observed,
            clock_skew_seconds=clock_skew_seconds,
        )
    except (TradeDisputeStatementRejected, TypeError, ValueError) as exc:
        raise TradeDisputeStatementAuditError(
            f"Trade Dispute Statement Spine event observation time is invalid: {exc}"
        ) from exc
    return payload


class TradeDisputeStatementAuditCoordinator:
    """Persist a verified claim before anchoring its non-adjudicating summary."""

    def __init__(
        self,
        *,
        store: TradeDisputeStatementStore,
        spine: SignedEventLog,
        audit_outbox: TradeDisputeStatementAuditOutbox | None = None,
    ) -> None:
        if not isinstance(store, TradeDisputeStatementStore):
            raise TypeError("store must be a TradeDisputeStatementStore")
        if not isinstance(spine, SignedEventLog):
            raise TypeError("spine must be a SignedEventLog")
        if not is_did_key(spine.signer_did):
            raise ValueError("Spine signer must expose an Ed25519 did:key")
        if audit_outbox is None:
            audit_outbox = TradeDisputeStatementAuditOutbox(
                store.workspace_root
            )
        if not isinstance(audit_outbox, TradeDisputeStatementAuditOutbox):
            raise TypeError(
                "audit_outbox must be a TradeDisputeStatementAuditOutbox"
            )
        if audit_outbox.workspace_root != store.workspace_root:
            raise ValueError("audit outbox and Statement Store must share a workspace")
        self.store = store
        self.spine = spine
        self.audit_outbox = audit_outbox

    def _anchor(
        self,
        statement: TradeDisputeStatement,
        *,
        observed_at_ms: int,
        clock_skew_seconds: float,
    ) -> tuple[SpineEvent, bool]:
        payload = trade_dispute_statement_audit_payload(statement)
        try:
            event, created = self.spine.append_unique(
                EVENT_TRADE_DISPUTE_STATEMENT_RETAINED,
                payload,
                unique_payload_fields=("statement_digest",),
                ts_ms=observed_at_ms,
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise TradeDisputeStatementAuditError(
                f"unable to project Trade Dispute Statement into Spine: {exc}"
            ) from exc
        if (
            event.type != EVENT_TRADE_DISPUTE_STATEMENT_RETAINED
            or event.payload != payload
        ):
            raise TradeDisputeStatementAuditError(
                "Spine returned a conflicting Trade Dispute Statement anchor"
            )
        valid, reason = verify_event(event)
        if not valid:
            raise TradeDisputeStatementAuditError(
                f"Spine returned an invalid Trade Dispute Statement anchor: {reason}"
            )
        if event.author_did != self.spine.signer_did:
            raise TradeDisputeStatementAuditError(
                "Spine returned a Trade Dispute Statement anchor signed by an "
                "unauthorized DID"
            )
        try:
            _moment, event_observed = _observation(event.ts_ms)
            statement.assert_observed_at(
                at=event_observed,
                clock_skew_seconds=clock_skew_seconds,
            )
        except (TradeDisputeStatementRejected, TypeError, ValueError) as exc:
            raise TradeDisputeStatementAuditError(
                "Trade Dispute Statement Spine anchor observation time is invalid: "
                f"{exc}"
            ) from exc
        return event, created

    def record(
        self,
        statement: TradeDisputeStatement | dict[str, Any],
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        package_resolver: RulePackageResolver | None = None,
        observed_at_ms: int | None = None,
        clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
    ) -> TradeDisputeStatementAuditResult:
        """Store and anchor one claim, remaining retryable after Spine failure."""

        moment, observed = _observation(observed_at_ms)
        verified_review, verified_receipt, verified_order = _verified_context(
            review=review,
            receipt=receipt,
            order=order,
        )
        verified = _verified_statement(
            statement,
            review=verified_review,
            receipt=verified_receipt,
            order=verified_order,
            package_resolver=package_resolver,
        )
        verified.assert_observed_at(
            at=observed,
            clock_skew_seconds=clock_skew_seconds,
        )
        pending, _prepared_created = self.audit_outbox.prepare(
            verified,
            review=verified_review,
            receipt=verified_receipt,
            order=verified_order,
            observed_at_ms=moment,
        )
        verified, store_created = self.store.put(
            verified,
            review=verified_review,
            receipt=verified_receipt,
            order=verified_order,
            package_resolver=package_resolver,
            at=observed,
            clock_skew_seconds=clock_skew_seconds,
        )
        event, anchor_created = self._anchor(
            verified,
            observed_at_ms=moment,
            clock_skew_seconds=clock_skew_seconds,
        )
        self.audit_outbox.complete(pending)
        return TradeDisputeStatementAuditResult(
            statement=verified,
            event=event,
            store_created=store_created,
            anchor_created=anchor_created,
        )

    def reconcile(
        self,
        *,
        package_resolver: RulePackageResolver | None = None,
        limit: int = 100,
        after_digest: str | None = None,
        clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
    ) -> TradeDisputeStatementAuditReconciliation:
        """Replay one bounded page of durable prepare-before-publish records."""

        records, has_more = self.audit_outbox.pending(
            limit=limit,
            after_digest=after_digest,
        )
        anchored = 0
        verified_anchored = 0
        failed = 0
        for record in records:
            try:
                statement, review, receipt, order = record.resolve(
                    package_resolver=package_resolver,
                )
                _moment, observed = _observation(record.observed_at_ms)
                self.store.put(
                    statement,
                    review=review,
                    receipt=receipt,
                    order=order,
                    package_resolver=package_resolver,
                    at=observed,
                    clock_skew_seconds=clock_skew_seconds,
                )
                _event, created = self._anchor(
                    statement,
                    observed_at_ms=record.observed_at_ms,
                    clock_skew_seconds=clock_skew_seconds,
                )
                self.audit_outbox.complete(record)
                if created:
                    anchored += 1
                else:
                    verified_anchored += 1
            except (OSError, RuntimeError, TypeError, ValueError):
                failed += 1
        next_cursor = records[-1].statement_digest if has_more and records else None
        return TradeDisputeStatementAuditReconciliation(
            scanned=len(records),
            anchored=anchored,
            verified_anchored=verified_anchored,
            failed=failed,
            next_cursor=next_cursor,
            has_more=has_more,
        )

    def reconcile_one(
        self,
        statement_digest: str,
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        package_resolver: RulePackageResolver | None = None,
        observed_at_ms: int | None = None,
        clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
    ) -> TradeDisputeStatementAuditResult:
        """Recover one retained-but-unanchored claim by exact content digest."""

        moment, observed = _observation(observed_at_ms)
        statement = self.store.get(
            statement_digest,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=package_resolver,
        )
        if statement is None:
            raise TradeDisputeStatementAuditError(
                "retained Trade Dispute Statement is missing"
            )
        statement.assert_observed_at(
            at=observed,
            clock_skew_seconds=clock_skew_seconds,
        )
        event, anchor_created = self._anchor(
            statement,
            observed_at_ms=moment,
            clock_skew_seconds=clock_skew_seconds,
        )
        return TradeDisputeStatementAuditResult(
            statement=statement,
            event=event,
            store_created=False,
            anchor_created=anchor_created,
        )

    def reconcile_review(
        self,
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        package_resolver: RulePackageResolver | None = None,
        limit: int = 100,
        after: str | None = None,
        observed_at_ms: int | None = None,
        clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
    ) -> TradeDisputeStatementAuditReconciliation:
        """Repair missing Spine anchors for one exact signed Review page."""

        page = self.store.list_for_review(
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=package_resolver,
            limit=limit,
            after=after,
        )
        events = self.spine.verified_snapshot()
        anchors: dict[str, list[SpineEvent]] = {}
        for event in events:
            if event.type != EVENT_TRADE_DISPUTE_STATEMENT_RETAINED:
                continue
            payload = validate_trade_dispute_statement_audit_payload(event.payload)
            anchors.setdefault(payload["statement_digest"], []).append(event)

        anchored = 0
        verified_anchored = 0
        failed = 0
        for statement_digest, statement in zip(
            page.statement_digests,
            page.statements,
            strict=True,
        ):
            matching = anchors.get(statement_digest, ())
            try:
                if len(matching) > 1:
                    raise TradeDisputeStatementAuditError(
                        "duplicate Trade Dispute Statement Spine anchors"
                    )
                if matching:
                    validate_trade_dispute_statement_audit_event(
                        matching[0],
                        expected_author_did=self.spine.signer_did,
                        statement=statement,
                        review=review,
                        receipt=receipt,
                        order=order,
                        package_resolver=package_resolver,
                        clock_skew_seconds=clock_skew_seconds,
                    )
                    verified_anchored += 1
                    continue
                _event, created = self._anchor(
                    statement,
                    observed_at_ms=_observation(observed_at_ms)[0],
                    clock_skew_seconds=clock_skew_seconds,
                )
                if created:
                    anchored += 1
                else:
                    verified_anchored += 1
            except (
                OSError,
                RuntimeError,
                TypeError,
                ValueError,
            ):
                failed += 1
        return TradeDisputeStatementAuditReconciliation(
            scanned=len(page.statements),
            anchored=anchored,
            verified_anchored=verified_anchored,
            failed=failed,
            next_cursor=page.next_cursor,
            has_more=page.next_cursor is not None,
        )


__all__ = [
    "EVENT_TRADE_DISPUTE_STATEMENT_CREATE_ATTEMPT_FAILED",
    "EVENT_TRADE_DISPUTE_STATEMENT_RETAINED",
    "EVENT_TRADE_DISPUTE_STATEMENT_CREATE_RESERVED",
    "MAX_TRADE_DISPUTE_AUDIT_OBSERVED_AT_MS",
    "TRADE_DISPUTE_STATEMENT_ASSERTION_STATUS",
    "TRADE_DISPUTE_STATEMENT_AUDIT_PROTOCOL_VERSION",
    "TRADE_DISPUTE_STATEMENT_CREATE_FAILURE_REASONS",
    "TradeDisputeStatementAuditError",
    "TradeDisputeStatementAuditCoordinator",
    "TradeDisputeStatementAuditReconciliation",
    "TradeDisputeStatementAuditResult",
    "trade_dispute_statement_audit_payload",
    "trade_dispute_statement_create_failure_payload",
    "trade_dispute_statement_create_reservation_payload",
    "validate_trade_dispute_statement_audit_binding",
    "validate_trade_dispute_statement_audit_event",
    "validate_trade_dispute_statement_audit_payload",
    "validate_trade_dispute_statement_create_failure_payload",
    "validate_trade_dispute_statement_create_reservation_binding",
    "validate_trade_dispute_statement_create_reservation_payload",
]
