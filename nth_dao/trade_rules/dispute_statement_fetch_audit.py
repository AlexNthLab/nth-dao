"""Signed Spine disclosure audit for Dispute Statement fetch responses."""

from __future__ import annotations

import hashlib
from typing import Any

from nth_dao.spine import SpineEvent, verify_event
from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.dispute_statement_retrieval import (
    DISPUTE_STATEMENT_FETCH_PROTOCOL_VERSION,
    TradeDisputeStatementFetchRequest,
    TradeDisputeStatementFetchResponse,
)
from nth_dao.trade_rules.execution_receipt import TradeExecutionReceipt
from nth_dao.trade_rules.receipt_review import TradeReceiptReview
from nth_dao.trade_rules.transport_common import timestamp_ns

EVENT_TRADE_DISPUTE_STATEMENT_FETCH_SERVED = (
    "trade.dispute.statement.fetch.served"
)
DISPUTE_STATEMENT_FETCH_AUDIT_STATUS = "served"

_PAYLOAD_FIELDS = frozenset(
    {
        "protocol_version",
        "request_id",
        "request_digest",
        "response_id",
        "response_digest",
        "order_digest",
        "receipt_digest",
        "review_digest",
        "statement_digest",
        "requester_did",
        "responder_did",
        "served_at",
        "status",
    }
)


class TradeDisputeStatementFetchAuditError(RuntimeError):
    """A fetch disclosure and its signed Spine anchor disagree."""


def _audit_payload_from_verified(
    request: TradeDisputeStatementFetchRequest,
    response: TradeDisputeStatementFetchResponse,
) -> dict[str, Any]:
    request_document = request.to_dict()
    response_document = response.to_dict()
    return {
        "protocol_version": DISPUTE_STATEMENT_FETCH_PROTOCOL_VERSION,
        "request_id": request_document["request_id"],
        "request_digest": (
            "sha256:" + hashlib.sha256(request.canonical_bytes).hexdigest()
        ),
        "response_id": response_document["response_id"],
        "response_digest": (
            "sha256:" + hashlib.sha256(response.canonical_bytes).hexdigest()
        ),
        "order_digest": response_document["order_digest"],
        "receipt_digest": response_document["receipt_digest"],
        "review_digest": response_document["review_digest"],
        "statement_digest": response_document["statement_digest"],
        "requester_did": response_document["requester_did"],
        "responder_did": response_document["responder_did"],
        "served_at": response_document["served_at"],
        "status": DISPUTE_STATEMENT_FETCH_AUDIT_STATUS,
    }


def trade_dispute_statement_fetch_audit_payload(
    request: TradeDisputeStatementFetchRequest | dict[str, Any],
    response: TradeDisputeStatementFetchResponse | dict[str, Any],
    *,
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
) -> dict[str, Any]:
    """Return the closed payload for one responder-signed disclosure."""

    verified_request = (
        TradeDisputeStatementFetchRequest.from_json(
            request.canonical_bytes,
            review=review,
            receipt=receipt,
            order=order,
        )
        if isinstance(request, TradeDisputeStatementFetchRequest)
        else TradeDisputeStatementFetchRequest.from_dict(
            request,
            review=review,
            receipt=receipt,
            order=order,
        )
    )
    verified_response = (
        TradeDisputeStatementFetchResponse.from_json(
            response.canonical_bytes,
            request=verified_request,
            review=review,
            receipt=receipt,
            order=order,
        )
        if isinstance(response, TradeDisputeStatementFetchResponse)
        else TradeDisputeStatementFetchResponse.from_dict(
            response,
            request=verified_request,
            review=review,
            receipt=receipt,
            order=order,
        )
    )
    return _audit_payload_from_verified(verified_request, verified_response)


def verify_trade_dispute_statement_fetch_audit_event(
    event: SpineEvent,
    request: TradeDisputeStatementFetchRequest | dict[str, Any],
    response: TradeDisputeStatementFetchResponse | dict[str, Any],
    *,
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
) -> tuple[bool, str]:
    """Verify event signature, closed payload, signer, and exact exchange binding."""

    if not isinstance(event, SpineEvent):
        return False, "fetch audit event must be a SpineEvent"
    ok, reason = verify_event(event)
    if not ok:
        return False, f"fetch audit event signature is invalid: {reason}"
    if event.type != EVENT_TRADE_DISPUTE_STATEMENT_FETCH_SERVED:
        return False, "fetch audit event type is invalid"
    try:
        expected = trade_dispute_statement_fetch_audit_payload(
            request,
            response,
            review=review,
            receipt=receipt,
            order=order,
        )
    except (TypeError, ValueError) as exc:
        return False, f"fetch audit exchange is invalid: {exc}"
    if event.author_did != expected["responder_did"]:
        return False, "fetch audit event signer is unauthorized"
    if not isinstance(event.payload, dict) or set(event.payload) != _PAYLOAD_FIELDS:
        return False, "fetch audit payload has missing or unknown fields"
    if event.payload != expected:
        return False, "fetch audit payload does not bind the signed exchange"
    try:
        served_ms = timestamp_ns(
            expected["served_at"],
            label="served_at",
            error_type=ValueError,
        ) // 1_000_000
    except ValueError as exc:
        return False, f"fetch audit served_at is invalid: {exc}"
    if event.ts_ms != served_ms:
        return False, "fetch audit event time does not match served_at"
    return True, "ok"


__all__ = [
    "DISPUTE_STATEMENT_FETCH_AUDIT_STATUS",
    "EVENT_TRADE_DISPUTE_STATEMENT_FETCH_SERVED",
    "TradeDisputeStatementFetchAuditError",
    "trade_dispute_statement_fetch_audit_payload",
    "verify_trade_dispute_statement_fetch_audit_event",
]
