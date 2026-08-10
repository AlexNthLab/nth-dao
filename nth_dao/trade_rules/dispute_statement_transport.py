"""Destination-bound transport for signed Trade Dispute Statements."""

from __future__ import annotations

import copy
import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from nth_dao.did_key import is_did_key
from nth_dao.trade_rules.agreement_order import (
    TradeOrder,
    TradeOrderRejected,
    trade_order_digest,
)
from nth_dao.trade_rules.canonical import (
    TradeCanonicalJSONError,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.dispute_statement import (
    TradeDisputeStatement,
    TradeDisputeStatementRejected,
    UnresolvedTradeDisputeStatement,
    trade_dispute_statement_digest,
)
from nth_dao.trade_rules.execution_receipt import (
    TradeExecutionReceipt,
    TradeExecutionReceiptRejected,
    execution_receipt_digest,
)
from nth_dao.trade_rules.negotiation import RulePackageResolver
from nth_dao.trade_rules.receipt_review import (
    TradeReceiptReview,
    TradeReceiptReviewRejected,
    receipt_review_digest,
)
from nth_dao.trade_rules.signing import (
    TradeProofError,
    encode_ed25519_signature,
    signed_document_input,
    verification_method_for_did,
)
from nth_dao.trade_rules.transport_common import (
    bounded_seconds,
    now_ns,
    opposite_party,
    reject,
    timestamp_ns,
    validate_transport_proof,
    verify_transport_signature,
)

DISPUTE_STATEMENT_DELIVERY_KIND = "nth.dao.trade.dispute-statement-delivery"
DISPUTE_STATEMENT_DELIVERY_PROTOCOL_VERSION = "1"
DISPUTE_STATEMENT_DELIVERY_PROOF_PURPOSE = "tradeDisputeStatementDelivery"
DISPUTE_STATEMENT_ACKNOWLEDGEMENT_KIND = (
    "nth.dao.trade.dispute-statement-acknowledgement"
)
DISPUTE_STATEMENT_ACKNOWLEDGEMENT_PROTOCOL_VERSION = "1"
DISPUTE_STATEMENT_ACKNOWLEDGEMENT_PROOF_PURPOSE = "tradeDisputeStatementAcknowledgement"
DISPUTE_STATEMENT_ACKNOWLEDGEMENT_STATUS = "retained-claim-not-adjudicated"
DISPUTE_STATEMENT_TRANSPORT_PROOF_TYPE = "Ed25519Signature2020"
DISPUTE_STATEMENT_DELIVERY_SIGNING_DOMAIN = (
    b"nth-dao/trade-dispute-statement-delivery/v1"
)
DISPUTE_STATEMENT_ACKNOWLEDGEMENT_SIGNING_DOMAIN = (
    b"nth-dao/trade-dispute-statement-acknowledgement/v1"
)
DEFAULT_MAX_DISPUTE_STATEMENT_DELIVERY_TTL_SECONDS = 600.0
DEFAULT_DISPUTE_STATEMENT_DELIVERY_CLOCK_SKEW_SECONDS = 300.0
MAX_DISPUTE_STATEMENT_TRANSPORT_SECONDS = 86_400.0
MAX_DISPUTE_STATEMENT_ACKNOWLEDGEMENT_BYTES = 4 * 1024

_DELIVERY_ID_PREFIX = "nth:trade:dispute-statement-delivery:sha256:"
_DELIVERY_ID = re.compile(rf"^{re.escape(_DELIVERY_ID_PREFIX)}[0-9a-f]{{64}}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVENT_ID = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^(?:[0-9a-f]{2}){16,64}$")
_DELIVERY_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "delivery_id",
        "nonce",
        "order_digest",
        "receipt_digest",
        "review_digest",
        "statement_digest",
        "sender_did",
        "recipient_did",
        "created_at",
        "not_after",
        "statement",
        "proof",
    }
)
_ACKNOWLEDGEMENT_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "delivery_id",
        "delivery_digest",
        "order_digest",
        "receipt_digest",
        "review_digest",
        "statement_digest",
        "sender_did",
        "receiver_did",
        "received_at",
        "audit_event_id",
        "status",
        "proof",
    }
)


class TradeDisputeStatementDeliveryRejected(ValueError):
    """A Statement delivery is malformed, stale, unsigned, or unbound."""


class TradeDisputeStatementAcknowledgementRejected(ValueError):
    """A Statement acknowledgement is malformed, unsigned, or unbound."""


def _bounded_transport_seconds(
    value: Any,
    *,
    label: str,
    error_type: type[ValueError],
) -> float:
    return bounded_seconds(
        value,
        label=label,
        error_type=error_type,
        maximum=MAX_DISPUTE_STATEMENT_TRANSPORT_SECONDS,
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


def _delivery_binding(document: dict[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(value)
        for key, value in document.items()
        if key not in {"delivery_id", "proof"}
    }


def _expected_delivery_id(document: dict[str, Any]) -> str:
    return (
        _DELIVERY_ID_PREFIX
        + hashlib.sha256(trade_canonical_json(_delivery_binding(document))).hexdigest()
    )


def _validate_delivery_static(
    document: dict[str, Any],
    *,
    review: TradeReceiptReview,
    receipt: TradeExecutionReceipt,
    order: TradeOrder,
) -> UnresolvedTradeDisputeStatement:
    error_type = TradeDisputeStatementDeliveryRejected
    if not isinstance(document, dict) or set(document) != _DELIVERY_FIELDS:
        reject(error_type, "delivery has missing or unknown fields")
    if document["kind"] != DISPUTE_STATEMENT_DELIVERY_KIND:
        reject(error_type, "wrong Trade Dispute Statement delivery kind")
    if document["protocol_version"] != DISPUTE_STATEMENT_DELIVERY_PROTOCOL_VERSION:
        reject(error_type, "unsupported delivery protocol_version")
    if (
        not isinstance(document["delivery_id"], str)
        or _DELIVERY_ID.fullmatch(document["delivery_id"]) is None
        or document["delivery_id"] != _expected_delivery_id(document)
    ):
        reject(error_type, "delivery_id does not match delivery content")
    nonce = document["nonce"]
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        reject(error_type, "nonce must be 16 to 64 bytes of lowercase hex")
    for field in (
        "order_digest",
        "receipt_digest",
        "review_digest",
        "statement_digest",
    ):
        if (
            not isinstance(document[field], str)
            or _DIGEST.fullmatch(document[field]) is None
        ):
            reject(error_type, f"{field} must be a lowercase sha256 digest")
    for field in ("sender_did", "recipient_did"):
        if not isinstance(document[field], str) or not is_did_key(document[field]):
            reject(error_type, f"{field} must be an Ed25519 did:key")
    if document["sender_did"] == document["recipient_did"]:
        reject(error_type, "delivery parties must be different principals")
    if document["order_digest"] != trade_order_digest(order):
        reject(error_type, "order_digest does not match signed Order")
    if document["receipt_digest"] != execution_receipt_digest(
        receipt,
        order=order,
    ):
        reject(error_type, "receipt_digest does not match signed Receipt")
    if document["review_digest"] != receipt_review_digest(
        review,
        receipt=receipt,
        order=order,
    ):
        reject(error_type, "review_digest does not match signed Review")
    try:
        statement = UnresolvedTradeDisputeStatement.from_dict(
            document["statement"],
            review=review,
            receipt=receipt,
            order=order,
        )
    except (TradeDisputeStatementRejected, TypeError, ValueError) as exc:
        raise error_type(f"embedded Trade Dispute Statement is invalid: {exc}") from exc
    if document["statement_digest"] != trade_dispute_statement_digest(
        statement,
        review=review,
        receipt=receipt,
        order=order,
    ):
        reject(error_type, "statement_digest does not match embedded Statement")
    statement_document = statement.to_dict()
    if document["sender_did"] != statement_document["author_did"]:
        reject(error_type, "sender_did does not match Statement author")
    expected_recipient = opposite_party(
        order.to_dict(),
        document["sender_did"],
        error_type=error_type,
    )
    if document["recipient_did"] != expected_recipient:
        reject(error_type, "recipient_did is not the opposing Order party")
    created_ns = timestamp_ns(
        document["created_at"],
        label="created_at",
        error_type=error_type,
    )
    expiry_ns = timestamp_ns(
        document["not_after"],
        label="not_after",
        error_type=error_type,
    )
    statement_ns = timestamp_ns(
        statement_document["created_at"],
        label="statement.created_at",
        error_type=error_type,
    )
    if expiry_ns <= created_ns:
        reject(error_type, "not_after must be later than created_at")
    if created_ns < statement_ns:
        reject(error_type, "delivery cannot predate Statement creation")
    validate_transport_proof(
        document["proof"],
        signer_did=document["sender_did"],
        purpose=DISPUTE_STATEMENT_DELIVERY_PROOF_PURPOSE,
        created_at=document["created_at"],
        proof_type=DISPUTE_STATEMENT_TRANSPORT_PROOF_TYPE,
        error_type=error_type,
    )
    return statement


@dataclass(frozen=True, init=False)
class TradeDisputeStatementDelivery:
    """Canonical destination-bound envelope for one signed claim."""

    _canonical_bytes: bytes
    _statement: UnresolvedTradeDisputeStatement

    @classmethod
    def _create(
        cls,
        canonical: bytes,
        statement: UnresolvedTradeDisputeStatement,
    ) -> "TradeDisputeStatementDelivery":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        object.__setattr__(value, "_statement", statement)
        return value

    @classmethod
    def from_dict(
        cls,
        document: dict[str, Any],
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
    ) -> "TradeDisputeStatementDelivery":
        try:
            verified_review, verified_receipt, verified_order = _verified_context(
                review=review,
                receipt=receipt,
                order=order,
            )
            canonical = trade_canonical_json(copy.deepcopy(document))
            snapshot = parse_trade_json(canonical)
            statement = _validate_delivery_static(
                snapshot,
                review=verified_review,
                receipt=verified_receipt,
                order=verified_order,
            )
            verify_transport_signature(
                snapshot,
                signer_field="sender_did",
                domain=DISPUTE_STATEMENT_DELIVERY_SIGNING_DOMAIN,
                error_type=TradeDisputeStatementDeliveryRejected,
            )
        except (
            TradeCanonicalJSONError,
            TradeDisputeStatementRejected,
            TradeExecutionReceiptRejected,
            TradeOrderRejected,
            TradeProofError,
            TradeReceiptReviewRejected,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            if isinstance(exc, TradeDisputeStatementDeliveryRejected):
                raise
            raise TradeDisputeStatementDeliveryRejected(str(exc)) from exc
        return cls._create(canonical, statement)

    @classmethod
    def from_json(
        cls,
        raw: bytes | str,
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
    ) -> "TradeDisputeStatementDelivery":
        try:
            return cls.from_dict(
                parse_trade_json(raw),
                review=review,
                receipt=receipt,
                order=order,
            )
        except TradeCanonicalJSONError as exc:
            raise TradeDisputeStatementDeliveryRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    @property
    def statement(self) -> UnresolvedTradeDisputeStatement:
        return self._statement

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


def _validate_acknowledgement_static(document: dict[str, Any]) -> None:
    error_type = TradeDisputeStatementAcknowledgementRejected
    if not isinstance(document, dict) or set(document) != (_ACKNOWLEDGEMENT_FIELDS):
        reject(error_type, "acknowledgement has missing or unknown fields")
    if document["kind"] != DISPUTE_STATEMENT_ACKNOWLEDGEMENT_KIND:
        reject(error_type, "wrong Trade Dispute Statement acknowledgement kind")
    if (
        document["protocol_version"]
        != DISPUTE_STATEMENT_ACKNOWLEDGEMENT_PROTOCOL_VERSION
    ):
        reject(error_type, "unsupported acknowledgement protocol_version")
    if (
        not isinstance(document["delivery_id"], str)
        or _DELIVERY_ID.fullmatch(document["delivery_id"]) is None
    ):
        reject(error_type, "acknowledgement delivery_id is invalid")
    for field in (
        "delivery_digest",
        "order_digest",
        "receipt_digest",
        "review_digest",
        "statement_digest",
    ):
        if (
            not isinstance(document[field], str)
            or _DIGEST.fullmatch(document[field]) is None
        ):
            reject(error_type, f"acknowledgement {field} is invalid")
    for field in ("sender_did", "receiver_did"):
        if not isinstance(document[field], str) or not is_did_key(document[field]):
            reject(error_type, f"acknowledgement {field} is invalid")
    if document["sender_did"] == document["receiver_did"]:
        reject(error_type, "acknowledgement parties must be different")
    if (
        not isinstance(document["audit_event_id"], str)
        or _EVENT_ID.fullmatch(document["audit_event_id"]) is None
    ):
        reject(error_type, "acknowledgement audit_event_id is invalid")
    if document["status"] != DISPUTE_STATEMENT_ACKNOWLEDGEMENT_STATUS:
        reject(error_type, "acknowledgement status is invalid")
    timestamp_ns(
        document["received_at"],
        label="received_at",
        error_type=error_type,
    )
    validate_transport_proof(
        document["proof"],
        signer_did=document["receiver_did"],
        purpose=DISPUTE_STATEMENT_ACKNOWLEDGEMENT_PROOF_PURPOSE,
        created_at=document["received_at"],
        proof_type=DISPUTE_STATEMENT_TRANSPORT_PROOF_TYPE,
        error_type=error_type,
    )


@dataclass(frozen=True, init=False)
class TradeDisputeStatementAcknowledgement:
    """Receiver-signed claim of durable Statement retention and anchoring."""

    _canonical_bytes: bytes

    @classmethod
    def _create(
        cls,
        canonical: bytes,
    ) -> "TradeDisputeStatementAcknowledgement":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        return value

    @classmethod
    def from_dict(
        cls,
        document: dict[str, Any],
    ) -> "TradeDisputeStatementAcknowledgement":
        try:
            canonical = trade_canonical_json(copy.deepcopy(document))
            if len(canonical) > MAX_DISPUTE_STATEMENT_ACKNOWLEDGEMENT_BYTES:
                reject(
                    TradeDisputeStatementAcknowledgementRejected,
                    "acknowledgement exceeds byte limit",
                )
            snapshot = parse_trade_json(canonical)
            _validate_acknowledgement_static(snapshot)
            verify_transport_signature(
                snapshot,
                signer_field="receiver_did",
                domain=DISPUTE_STATEMENT_ACKNOWLEDGEMENT_SIGNING_DOMAIN,
                error_type=TradeDisputeStatementAcknowledgementRejected,
            )
        except (
            TradeCanonicalJSONError,
            TradeProofError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            if isinstance(
                exc,
                TradeDisputeStatementAcknowledgementRejected,
            ):
                raise
            raise TradeDisputeStatementAcknowledgementRejected(str(exc)) from exc
        return cls._create(canonical)

    @classmethod
    def from_json(
        cls,
        raw: bytes | str,
    ) -> "TradeDisputeStatementAcknowledgement":
        try:
            return cls.from_dict(parse_trade_json(raw))
        except TradeCanonicalJSONError as exc:
            raise TradeDisputeStatementAcknowledgementRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


def create_trade_dispute_statement_delivery(
    identity: Any,
    *,
    statement: TradeDisputeStatement,
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    package_resolver: RulePackageResolver | None = None,
    created_at: str,
    not_after: str,
    nonce: str | None = None,
    now: datetime | None = None,
    max_ttl_seconds: float = (DEFAULT_MAX_DISPUTE_STATEMENT_DELIVERY_TTL_SECONDS),
    clock_skew_seconds: float = (DEFAULT_DISPUTE_STATEMENT_DELIVERY_CLOCK_SKEW_SECONDS),
) -> TradeDisputeStatementDelivery:
    """Create a short-lived envelope signed by the Statement author."""

    error_type = TradeDisputeStatementDeliveryRejected
    review_value, receipt_value, order_value = _verified_context(
        review=review,
        receipt=receipt,
        order=order,
    )
    verified = TradeDisputeStatement.from_json(
        statement.canonical_bytes,
        review=review_value,
        receipt=receipt_value,
        order=order_value,
        package_resolver=package_resolver,
    )
    sender = identity.as_did()
    if sender != verified.to_dict()["author_did"]:
        reject(error_type, "delivery signer does not match Statement author")
    recipient = opposite_party(
        order_value.to_dict(),
        sender,
        error_type=error_type,
    )
    nonce_value = nonce if nonce is not None else secrets.token_hex(16)
    document = {
        "kind": DISPUTE_STATEMENT_DELIVERY_KIND,
        "protocol_version": DISPUTE_STATEMENT_DELIVERY_PROTOCOL_VERSION,
        "delivery_id": _DELIVERY_ID_PREFIX + ("0" * 64),
        "nonce": nonce_value,
        "order_digest": trade_order_digest(order_value),
        "receipt_digest": execution_receipt_digest(
            receipt_value,
            order=order_value,
        ),
        "review_digest": receipt_review_digest(
            review_value,
            receipt=receipt_value,
            order=order_value,
        ),
        "statement_digest": trade_dispute_statement_digest(
            verified,
            review=review_value,
            receipt=receipt_value,
            order=order_value,
            package_resolver=package_resolver,
        ),
        "sender_did": sender,
        "recipient_did": recipient,
        "created_at": created_at,
        "not_after": not_after,
        "statement": verified.to_dict(),
        "proof": {
            "type": DISPUTE_STATEMENT_TRANSPORT_PROOF_TYPE,
            "created": created_at,
            "verification_method": verification_method_for_did(sender),
            "proof_purpose": DISPUTE_STATEMENT_DELIVERY_PROOF_PURPOSE,
            "proof_value": "A" * 86,
        },
    }
    document["delivery_id"] = _expected_delivery_id(document)
    _validate_delivery_static(
        document,
        review=review_value,
        receipt=receipt_value,
        order=order_value,
    )
    current_ns = now_ns(now, error_type=error_type)
    created_ns = timestamp_ns(
        created_at,
        label="created_at",
        error_type=error_type,
    )
    expiry_ns = timestamp_ns(
        not_after,
        label="not_after",
        error_type=error_type,
    )
    skew = _bounded_transport_seconds(
        clock_skew_seconds,
        label="clock_skew_seconds",
        error_type=error_type,
    )
    ttl = _bounded_transport_seconds(
        max_ttl_seconds,
        label="max_ttl_seconds",
        error_type=error_type,
    )
    if abs(current_ns - created_ns) > int(skew * 1_000_000_000):
        reject(error_type, "created_at exceeds local clock-skew limit")
    if expiry_ns - created_ns > int(ttl * 1_000_000_000):
        reject(error_type, "delivery lifetime exceeds max_ttl_seconds")
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(
            signed_document_input(
                DISPUTE_STATEMENT_DELIVERY_SIGNING_DOMAIN,
                document,
            )
        )
    )
    return TradeDisputeStatementDelivery.from_dict(
        document,
        review=review_value,
        receipt=receipt_value,
        order=order_value,
    )


def verify_trade_dispute_statement_delivery(
    delivery: TradeDisputeStatementDelivery | dict[str, Any],
    *,
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    recipient_did: str,
    at: datetime | None = None,
    max_ttl_seconds: float = (DEFAULT_MAX_DISPUTE_STATEMENT_DELIVERY_TTL_SECONDS),
    clock_skew_seconds: float = (DEFAULT_DISPUTE_STATEMENT_DELIVERY_CLOCK_SKEW_SECONDS),
) -> tuple[bool, str]:
    """Verify signature, destination, artifact bindings, and freshness."""

    error_type = TradeDisputeStatementDeliveryRejected
    try:
        review_value, receipt_value, order_value = _verified_context(
            review=review,
            receipt=receipt,
            order=order,
        )
        verified = (
            TradeDisputeStatementDelivery.from_json(
                delivery.canonical_bytes,
                review=review_value,
                receipt=receipt_value,
                order=order_value,
            )
            if isinstance(delivery, TradeDisputeStatementDelivery)
            else TradeDisputeStatementDelivery.from_dict(
                delivery,
                review=review_value,
                receipt=receipt_value,
                order=order_value,
            )
        )
        if not isinstance(recipient_did, str) or not is_did_key(recipient_did):
            reject(error_type, "expected recipient_did is invalid")
        document = verified.to_dict()
        if document["recipient_did"] != recipient_did:
            reject(error_type, "delivery recipient does not match this node")
        current_ns = now_ns(at, error_type=error_type)
        created_ns = timestamp_ns(
            document["created_at"],
            label="created_at",
            error_type=error_type,
        )
        expiry_ns = timestamp_ns(
            document["not_after"],
            label="not_after",
            error_type=error_type,
        )
        skew_ns = int(
            _bounded_transport_seconds(
                clock_skew_seconds,
                label="clock_skew_seconds",
                error_type=error_type,
            )
            * 1_000_000_000
        )
        ttl_ns = int(
            _bounded_transport_seconds(
                max_ttl_seconds,
                label="max_ttl_seconds",
                error_type=error_type,
            )
            * 1_000_000_000
        )
        if expiry_ns - created_ns > ttl_ns:
            reject(error_type, "delivery lifetime exceeds max_ttl_seconds")
        if current_ns < created_ns - skew_ns:
            reject(error_type, "delivery was created too far in the future")
        if current_ns > expiry_ns + skew_ns:
            reject(error_type, "delivery has expired")
    except (
        TradeCanonicalJSONError,
        TradeDisputeStatementDeliveryRejected,
        TradeDisputeStatementRejected,
        TradeExecutionReceiptRejected,
        TradeOrderRejected,
        TradeProofError,
        TradeReceiptReviewRejected,
        TypeError,
        ValueError,
        UnicodeError,
    ) as exc:
        return False, str(exc)
    return True, "ok"


def trade_dispute_statement_delivery_digest(
    delivery: TradeDisputeStatementDelivery | dict[str, Any],
    *,
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
) -> str:
    verified = (
        TradeDisputeStatementDelivery.from_json(
            delivery.canonical_bytes,
            review=review,
            receipt=receipt,
            order=order,
        )
        if isinstance(delivery, TradeDisputeStatementDelivery)
        else TradeDisputeStatementDelivery.from_dict(
            delivery,
            review=review,
            receipt=receipt,
            order=order,
        )
    )
    return "sha256:" + hashlib.sha256(verified.canonical_bytes).hexdigest()


def create_trade_dispute_statement_acknowledgement(
    identity: Any,
    *,
    delivery: TradeDisputeStatementDelivery,
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    received_at: str,
    audit_event_id: str,
    max_ttl_seconds: float = (DEFAULT_MAX_DISPUTE_STATEMENT_DELIVERY_TTL_SECONDS),
    clock_skew_seconds: float = (DEFAULT_DISPUTE_STATEMENT_DELIVERY_CLOCK_SKEW_SECONDS),
) -> TradeDisputeStatementAcknowledgement:
    """Sign a narrow receipt for retention, not truth or adjudication."""

    error_type = TradeDisputeStatementAcknowledgementRejected
    review_value, receipt_value, order_value = _verified_context(
        review=review,
        receipt=receipt,
        order=order,
    )
    delivery_value = TradeDisputeStatementDelivery.from_json(
        delivery.canonical_bytes,
        review=review_value,
        receipt=receipt_value,
        order=order_value,
    )
    delivery_document = delivery_value.to_dict()
    receiver = identity.as_did()
    if receiver != delivery_document["recipient_did"]:
        reject(error_type, "acknowledgement signer is not delivery recipient")
    received_ns = timestamp_ns(
        received_at,
        label="received_at",
        error_type=error_type,
    )
    created_ns = timestamp_ns(
        delivery_document["created_at"],
        label="delivery.created_at",
        error_type=error_type,
    )
    expiry_ns = timestamp_ns(
        delivery_document["not_after"],
        label="delivery.not_after",
        error_type=error_type,
    )
    skew_ns = int(
        _bounded_transport_seconds(
            clock_skew_seconds,
            label="clock_skew_seconds",
            error_type=error_type,
        )
        * 1_000_000_000
    )
    ttl_ns = int(
        _bounded_transport_seconds(
            max_ttl_seconds,
            label="max_ttl_seconds",
            error_type=error_type,
        )
        * 1_000_000_000
    )
    if expiry_ns - created_ns > ttl_ns:
        reject(error_type, "delivery lifetime exceeds max_ttl_seconds")
    if received_ns < created_ns - skew_ns:
        reject(error_type, "acknowledgement predates delivery creation")
    if received_ns > expiry_ns + skew_ns:
        reject(error_type, "acknowledgement follows delivery expiry")
    document = {
        "kind": DISPUTE_STATEMENT_ACKNOWLEDGEMENT_KIND,
        "protocol_version": (DISPUTE_STATEMENT_ACKNOWLEDGEMENT_PROTOCOL_VERSION),
        "delivery_id": delivery_document["delivery_id"],
        "delivery_digest": trade_dispute_statement_delivery_digest(
            delivery_value,
            review=review_value,
            receipt=receipt_value,
            order=order_value,
        ),
        "order_digest": delivery_document["order_digest"],
        "receipt_digest": delivery_document["receipt_digest"],
        "review_digest": delivery_document["review_digest"],
        "statement_digest": delivery_document["statement_digest"],
        "sender_did": delivery_document["sender_did"],
        "receiver_did": receiver,
        "received_at": received_at,
        "audit_event_id": audit_event_id,
        "status": DISPUTE_STATEMENT_ACKNOWLEDGEMENT_STATUS,
        "proof": {
            "type": DISPUTE_STATEMENT_TRANSPORT_PROOF_TYPE,
            "created": received_at,
            "verification_method": verification_method_for_did(receiver),
            "proof_purpose": (DISPUTE_STATEMENT_ACKNOWLEDGEMENT_PROOF_PURPOSE),
            "proof_value": "A" * 86,
        },
    }
    _validate_acknowledgement_static(document)
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(
            signed_document_input(
                DISPUTE_STATEMENT_ACKNOWLEDGEMENT_SIGNING_DOMAIN,
                document,
            )
        )
    )
    return TradeDisputeStatementAcknowledgement.from_dict(document)


def verify_trade_dispute_statement_acknowledgement(
    acknowledgement: TradeDisputeStatementAcknowledgement | dict[str, Any],
    *,
    delivery: TradeDisputeStatementDelivery | dict[str, Any],
    review: TradeReceiptReview | dict[str, Any],
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    at: datetime | None = None,
    max_ttl_seconds: float = (DEFAULT_MAX_DISPUTE_STATEMENT_DELIVERY_TTL_SECONDS),
    clock_skew_seconds: float = (DEFAULT_DISPUTE_STATEMENT_DELIVERY_CLOCK_SKEW_SECONDS),
) -> tuple[bool, str]:
    """Verify the receiver signature and exact retained-delivery binding."""

    error_type = TradeDisputeStatementAcknowledgementRejected
    try:
        review_value, receipt_value, order_value = _verified_context(
            review=review,
            receipt=receipt,
            order=order,
        )
        delivery_value = (
            TradeDisputeStatementDelivery.from_json(
                delivery.canonical_bytes,
                review=review_value,
                receipt=receipt_value,
                order=order_value,
            )
            if isinstance(delivery, TradeDisputeStatementDelivery)
            else TradeDisputeStatementDelivery.from_dict(
                delivery,
                review=review_value,
                receipt=receipt_value,
                order=order_value,
            )
        )
        verified = (
            TradeDisputeStatementAcknowledgement.from_json(
                acknowledgement.canonical_bytes
            )
            if isinstance(
                acknowledgement,
                TradeDisputeStatementAcknowledgement,
            )
            else TradeDisputeStatementAcknowledgement.from_dict(acknowledgement)
        )
        document = verified.to_dict()
        delivery_document = delivery_value.to_dict()
        expected = {
            "delivery_id": delivery_document["delivery_id"],
            "delivery_digest": trade_dispute_statement_delivery_digest(
                delivery_value,
                review=review_value,
                receipt=receipt_value,
                order=order_value,
            ),
            "order_digest": delivery_document["order_digest"],
            "receipt_digest": delivery_document["receipt_digest"],
            "review_digest": delivery_document["review_digest"],
            "statement_digest": delivery_document["statement_digest"],
            "sender_did": delivery_document["sender_did"],
            "receiver_did": delivery_document["recipient_did"],
        }
        for field, value in expected.items():
            if document[field] != value:
                reject(
                    error_type,
                    f"acknowledgement {field} does not match delivery",
                )
        received_ns = timestamp_ns(
            document["received_at"],
            label="received_at",
            error_type=error_type,
        )
        current_ns = now_ns(at, error_type=error_type)
        created_ns = timestamp_ns(
            delivery_document["created_at"],
            label="delivery.created_at",
            error_type=error_type,
        )
        expiry_ns = timestamp_ns(
            delivery_document["not_after"],
            label="delivery.not_after",
            error_type=error_type,
        )
        skew_ns = int(
            _bounded_transport_seconds(
                clock_skew_seconds,
                label="clock_skew_seconds",
                error_type=error_type,
            )
            * 1_000_000_000
        )
        ttl_ns = int(
            _bounded_transport_seconds(
                max_ttl_seconds,
                label="max_ttl_seconds",
                error_type=error_type,
            )
            * 1_000_000_000
        )
        if expiry_ns - created_ns > ttl_ns:
            reject(error_type, "delivery lifetime exceeds max_ttl_seconds")
        if received_ns < created_ns - skew_ns:
            reject(error_type, "acknowledgement predates delivery creation")
        if received_ns > expiry_ns + skew_ns:
            reject(error_type, "acknowledgement follows delivery expiry")
        if received_ns > current_ns + skew_ns:
            reject(error_type, "acknowledgement was created too far in the future")
    except (
        TradeCanonicalJSONError,
        TradeDisputeStatementAcknowledgementRejected,
        TradeDisputeStatementDeliveryRejected,
        TradeExecutionReceiptRejected,
        TradeOrderRejected,
        TradeProofError,
        TradeReceiptReviewRejected,
        TypeError,
        ValueError,
        UnicodeError,
    ) as exc:
        return False, str(exc)
    return True, "ok"


def trade_dispute_statement_acknowledgement_digest(
    acknowledgement: TradeDisputeStatementAcknowledgement | dict[str, Any],
) -> str:
    verified = (
        TradeDisputeStatementAcknowledgement.from_json(acknowledgement.canonical_bytes)
        if isinstance(
            acknowledgement,
            TradeDisputeStatementAcknowledgement,
        )
        else TradeDisputeStatementAcknowledgement.from_dict(acknowledgement)
    )
    return "sha256:" + hashlib.sha256(verified.canonical_bytes).hexdigest()


__all__ = [
    "DEFAULT_DISPUTE_STATEMENT_DELIVERY_CLOCK_SKEW_SECONDS",
    "DEFAULT_MAX_DISPUTE_STATEMENT_DELIVERY_TTL_SECONDS",
    "MAX_DISPUTE_STATEMENT_ACKNOWLEDGEMENT_BYTES",
    "MAX_DISPUTE_STATEMENT_TRANSPORT_SECONDS",
    "DISPUTE_STATEMENT_ACKNOWLEDGEMENT_KIND",
    "DISPUTE_STATEMENT_ACKNOWLEDGEMENT_PROOF_PURPOSE",
    "DISPUTE_STATEMENT_ACKNOWLEDGEMENT_PROTOCOL_VERSION",
    "DISPUTE_STATEMENT_ACKNOWLEDGEMENT_SIGNING_DOMAIN",
    "DISPUTE_STATEMENT_ACKNOWLEDGEMENT_STATUS",
    "DISPUTE_STATEMENT_DELIVERY_KIND",
    "DISPUTE_STATEMENT_DELIVERY_PROOF_PURPOSE",
    "DISPUTE_STATEMENT_DELIVERY_PROTOCOL_VERSION",
    "DISPUTE_STATEMENT_DELIVERY_SIGNING_DOMAIN",
    "DISPUTE_STATEMENT_TRANSPORT_PROOF_TYPE",
    "TradeDisputeStatementDelivery",
    "TradeDisputeStatementDeliveryRejected",
    "TradeDisputeStatementAcknowledgement",
    "TradeDisputeStatementAcknowledgementRejected",
    "create_trade_dispute_statement_acknowledgement",
    "create_trade_dispute_statement_delivery",
    "trade_dispute_statement_acknowledgement_digest",
    "trade_dispute_statement_delivery_digest",
    "verify_trade_dispute_statement_acknowledgement",
    "verify_trade_dispute_statement_delivery",
]
