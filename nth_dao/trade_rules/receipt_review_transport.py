"""Destination-bound transport for signed Trade Receipt Reviews."""

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
from nth_dao.trade_rules.execution_receipt import (
    TradeExecutionReceipt,
    TradeExecutionReceiptRejected,
    execution_receipt_digest,
)
from nth_dao.trade_rules.execution_adapter import (
    TradeExecutionAdapterPolicy,
    TradeExecutionAdapterRejected,
)
from nth_dao.trade_rules.negotiation import RuleResolutionPolicy
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
    within_clock_skewed_lifetime,
)

RECEIPT_REVIEW_DELIVERY_KIND = "nth.dao.trade.receipt-review-delivery"
RECEIPT_REVIEW_DELIVERY_PROTOCOL_VERSION = "1"
RECEIPT_REVIEW_DELIVERY_PROOF_PURPOSE = "tradeReceiptReviewDelivery"
RECEIPT_REVIEW_ACKNOWLEDGEMENT_KIND = (
    "nth.dao.trade.receipt-review-acknowledgement"
)
RECEIPT_REVIEW_ACKNOWLEDGEMENT_PROTOCOL_VERSION = "1"
RECEIPT_REVIEW_ACKNOWLEDGEMENT_PROOF_PURPOSE = (
    "tradeReceiptReviewAcknowledgement"
)
RECEIPT_REVIEW_TRANSPORT_PROOF_TYPE = "Ed25519Signature2020"
DEFAULT_MAX_RECEIPT_REVIEW_DELIVERY_TTL_SECONDS = 600.0
DEFAULT_RECEIPT_REVIEW_DELIVERY_CLOCK_SKEW_SECONDS = 300.0

_DELIVERY_DOMAIN = b"nth-dao/trade-receipt-review-delivery/v1"
_ACKNOWLEDGEMENT_DOMAIN = (
    b"nth-dao/trade-receipt-review-acknowledgement/v1"
)
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
        "sender_did",
        "recipient_did",
        "created_at",
        "not_after",
        "review",
        "verifier_policy",
        "adapter_policy",
        "proof",
    }
)
_ACKNOWLEDGEMENT_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "order_digest",
        "receipt_digest",
        "review_digest",
        "delivery_digest",
        "sender_did",
        "receiver_did",
        "received_at",
        "audit_event_id",
        "status",
        "proof",
    }
)


class TradeReceiptReviewDeliveryRejected(ValueError):
    """A Review delivery is malformed, stale, unsigned, or unbound."""


class TradeReceiptReviewAcknowledgementRejected(ValueError):
    """A Review acknowledgement is malformed, unsigned, or unbound."""


def _verified_order(order: TradeOrder | dict[str, Any]) -> TradeOrder:
    return (
        TradeOrder.from_json(order.canonical_bytes)
        if isinstance(order, TradeOrder)
        else TradeOrder.from_dict(order)
    )


def _verified_receipt(
    receipt: TradeExecutionReceipt | dict[str, Any],
    *,
    order: TradeOrder,
) -> TradeExecutionReceipt:
    return (
        TradeExecutionReceipt.from_json(receipt.canonical_bytes, order=order)
        if isinstance(receipt, TradeExecutionReceipt)
        else TradeExecutionReceipt.from_dict(receipt, order=order)
    )


def _validate_delivery_static(
    document: dict[str, Any],
    *,
    receipt: TradeExecutionReceipt,
    order: TradeOrder,
) -> tuple[
    TradeReceiptReview,
    RuleResolutionPolicy,
    TradeExecutionAdapterPolicy,
]:
    error_type = TradeReceiptReviewDeliveryRejected
    if not isinstance(document, dict) or set(document) != _DELIVERY_FIELDS:
        reject(error_type, "delivery has missing or unknown fields")
    if document["kind"] != RECEIPT_REVIEW_DELIVERY_KIND:
        reject(error_type, "wrong Receipt Review delivery kind")
    if (
        document["protocol_version"]
        != RECEIPT_REVIEW_DELIVERY_PROTOCOL_VERSION
    ):
        reject(error_type, "unsupported delivery protocol_version")
    nonce = document["nonce"]
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        reject(error_type, "nonce must be 16 to 64 bytes of lowercase hex")
    if document["delivery_id"] != (
        f"nth:trade:receipt-review-delivery:{nonce}"
    ):
        reject(error_type, "delivery_id does not match nonce")
    for field in ("order_digest", "receipt_digest", "review_digest"):
        if (
            not isinstance(document[field], str)
            or _DIGEST.fullmatch(document[field]) is None
        ):
            reject(error_type, f"{field} must be a lowercase sha256 digest")
    for field in ("sender_did", "recipient_did"):
        if (
            not isinstance(document[field], str)
            or not is_did_key(document[field])
        ):
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
    try:
        review = TradeReceiptReview.from_dict(
            document["review"],
            receipt=receipt,
            order=order,
        )
    except (TradeReceiptReviewRejected, TypeError, ValueError) as exc:
        raise error_type(f"embedded Receipt Review is invalid: {exc}") from exc
    review_document = review.to_dict()
    if document["review_digest"] != receipt_review_digest(
        review,
        receipt=receipt,
        order=order,
    ):
        reject(error_type, "review_digest does not match embedded Review")
    if document["sender_did"] != review_document["reviewer_did"]:
        reject(error_type, "sender_did does not match Review signer")
    try:
        verifier_policy = RuleResolutionPolicy.from_dict(
            document["verifier_policy"]
        )
        adapter_policy = TradeExecutionAdapterPolicy.from_dict(
            document["adapter_policy"]
        )
    except (TradeExecutionAdapterRejected, TypeError, ValueError) as exc:
        raise error_type(f"embedded Review policy is invalid: {exc}") from exc
    if review_document["verifier_policy_digest"] != verifier_policy.digest:
        reject(
            error_type,
            "verifier_policy does not match signed Review digest",
        )
    if review_document["adapter_policy_digest"] != adapter_policy.digest:
        reject(
            error_type,
            "adapter_policy does not match signed Review digest",
        )
    order_document = order.to_dict()
    role = review_document["reviewer_role"]
    snapshot = order_document["snapshot"]
    expected_policy = (
        snapshot["proposal"]["taker_policy"]
        if role == "taker"
        else snapshot["acceptance"]["maker_policy"]
    )
    if verifier_policy.canonical_bytes != trade_canonical_json(
        expected_policy
    ):
        reject(
            error_type,
            "verifier_policy does not match the reviewer Order snapshot",
        )
    receipt_document = receipt.to_dict()
    if document["recipient_did"] != receipt_document["executor_did"]:
        reject(error_type, "recipient_did does not match Receipt executor")
    if opposite_party(
        order.to_dict(),
        document["sender_did"],
        error_type=error_type,
    ) != document["recipient_did"]:
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
    reviewed_ns = timestamp_ns(
        review_document["reviewed_at"],
        label="review.reviewed_at",
        error_type=error_type,
    )
    if expiry_ns <= created_ns:
        reject(error_type, "not_after must be later than created_at")
    if created_ns < reviewed_ns:
        reject(error_type, "delivery cannot predate Review creation")
    validate_transport_proof(
        document["proof"],
        signer_did=document["sender_did"],
        purpose=RECEIPT_REVIEW_DELIVERY_PROOF_PURPOSE,
        created_at=document["created_at"],
        proof_type=RECEIPT_REVIEW_TRANSPORT_PROOF_TYPE,
        error_type=error_type,
    )
    return review, verifier_policy, adapter_policy


@dataclass(frozen=True, init=False)
class TradeReceiptReviewDelivery:
    """Canonical destination-bound envelope for one signed Review."""

    _canonical_bytes: bytes
    _review: TradeReceiptReview
    _verifier_policy: RuleResolutionPolicy
    _adapter_policy: TradeExecutionAdapterPolicy

    @classmethod
    def _create(
        cls,
        canonical: bytes,
        review: TradeReceiptReview,
        verifier_policy: RuleResolutionPolicy,
        adapter_policy: TradeExecutionAdapterPolicy,
    ) -> "TradeReceiptReviewDelivery":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        object.__setattr__(value, "_review", review)
        object.__setattr__(value, "_verifier_policy", verifier_policy)
        object.__setattr__(value, "_adapter_policy", adapter_policy)
        return value

    @classmethod
    def from_dict(
        cls,
        document: dict[str, Any],
        *,
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
    ) -> "TradeReceiptReviewDelivery":
        try:
            verified_order = _verified_order(order)
            verified_receipt = _verified_receipt(
                receipt,
                order=verified_order,
            )
            canonical = trade_canonical_json(copy.deepcopy(document))
            snapshot = parse_trade_json(canonical)
            review, verifier_policy, adapter_policy = _validate_delivery_static(
                snapshot,
                receipt=verified_receipt,
                order=verified_order,
            )
            verify_transport_signature(
                snapshot,
                signer_field="sender_did",
                domain=_DELIVERY_DOMAIN,
                error_type=TradeReceiptReviewDeliveryRejected,
            )
        except (
            TradeCanonicalJSONError,
            TradeExecutionReceiptRejected,
            TradeExecutionAdapterRejected,
            TradeOrderRejected,
            TradeProofError,
            TradeReceiptReviewRejected,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            if isinstance(exc, TradeReceiptReviewDeliveryRejected):
                raise
            raise TradeReceiptReviewDeliveryRejected(str(exc)) from exc
        return cls._create(
            canonical,
            review,
            verifier_policy,
            adapter_policy,
        )

    @classmethod
    def from_json(
        cls,
        raw: bytes | str,
        *,
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
    ) -> "TradeReceiptReviewDelivery":
        try:
            return cls.from_dict(
                parse_trade_json(raw),
                receipt=receipt,
                order=order,
            )
        except TradeCanonicalJSONError as exc:
            raise TradeReceiptReviewDeliveryRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    @property
    def review(self) -> TradeReceiptReview:
        return self._review

    @property
    def verifier_policy(self) -> RuleResolutionPolicy:
        return self._verifier_policy

    @property
    def adapter_policy(self) -> TradeExecutionAdapterPolicy:
        return self._adapter_policy

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


def _validate_acknowledgement_static(document: dict[str, Any]) -> None:
    error_type = TradeReceiptReviewAcknowledgementRejected
    if (
        not isinstance(document, dict)
        or set(document) != _ACKNOWLEDGEMENT_FIELDS
    ):
        reject(error_type, "acknowledgement has missing or unknown fields")
    if document["kind"] != RECEIPT_REVIEW_ACKNOWLEDGEMENT_KIND:
        reject(error_type, "wrong Receipt Review acknowledgement kind")
    if (
        document["protocol_version"]
        != RECEIPT_REVIEW_ACKNOWLEDGEMENT_PROTOCOL_VERSION
    ):
        reject(error_type, "unsupported acknowledgement protocol_version")
    for field in (
        "order_digest",
        "receipt_digest",
        "review_digest",
        "delivery_digest",
    ):
        if (
            not isinstance(document[field], str)
            or _DIGEST.fullmatch(document[field]) is None
        ):
            reject(error_type, f"{field} must be a lowercase sha256 digest")
    for field in ("sender_did", "receiver_did"):
        if (
            not isinstance(document[field], str)
            or not is_did_key(document[field])
        ):
            reject(error_type, f"{field} must be an Ed25519 did:key")
    if document["sender_did"] == document["receiver_did"]:
        reject(error_type, "acknowledgement parties must be different principals")
    timestamp_ns(
        document["received_at"],
        label="received_at",
        error_type=error_type,
    )
    if (
        not isinstance(document["audit_event_id"], str)
        or _EVENT_ID.fullmatch(document["audit_event_id"]) is None
    ):
        reject(error_type, "audit_event_id is invalid")
    if document["status"] != "review-retained-verified":
        reject(error_type, "acknowledgement status is invalid")
    validate_transport_proof(
        document["proof"],
        signer_did=document["receiver_did"],
        purpose=RECEIPT_REVIEW_ACKNOWLEDGEMENT_PROOF_PURPOSE,
        created_at=document["received_at"],
        proof_type=RECEIPT_REVIEW_TRANSPORT_PROOF_TYPE,
        error_type=error_type,
    )


@dataclass(frozen=True, init=False)
class TradeReceiptReviewAcknowledgement:
    """Receiver-signed claim that a Review reached CAS and Spine."""

    _canonical_bytes: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "TradeReceiptReviewAcknowledgement":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        return value

    @classmethod
    def from_dict(
        cls,
        document: dict[str, Any],
    ) -> "TradeReceiptReviewAcknowledgement":
        try:
            canonical = trade_canonical_json(copy.deepcopy(document))
            snapshot = parse_trade_json(canonical)
            _validate_acknowledgement_static(snapshot)
            verify_transport_signature(
                snapshot,
                signer_field="receiver_did",
                domain=_ACKNOWLEDGEMENT_DOMAIN,
                error_type=TradeReceiptReviewAcknowledgementRejected,
            )
        except (
            TradeCanonicalJSONError,
            TradeProofError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            if isinstance(exc, TradeReceiptReviewAcknowledgementRejected):
                raise
            raise TradeReceiptReviewAcknowledgementRejected(str(exc)) from exc
        return cls._create(canonical)

    @classmethod
    def from_json(
        cls,
        raw: bytes | str,
    ) -> "TradeReceiptReviewAcknowledgement":
        try:
            return cls.from_dict(parse_trade_json(raw))
        except TradeCanonicalJSONError as exc:
            raise TradeReceiptReviewAcknowledgementRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


def create_trade_receipt_review_delivery(
    identity: Any,
    *,
    review: TradeReceiptReview,
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    verifier_policy: RuleResolutionPolicy,
    adapter_policy: TradeExecutionAdapterPolicy,
    created_at: str,
    not_after: str,
    nonce: str | None = None,
    now: datetime | None = None,
    max_ttl_seconds: float = DEFAULT_MAX_RECEIPT_REVIEW_DELIVERY_TTL_SECONDS,
    clock_skew_seconds: float = (
        DEFAULT_RECEIPT_REVIEW_DELIVERY_CLOCK_SKEW_SECONDS
    ),
) -> TradeReceiptReviewDelivery:
    """Create a short-lived Review envelope signed by its reviewer."""

    error_type = TradeReceiptReviewDeliveryRejected
    verified_order = _verified_order(order)
    verified_receipt = _verified_receipt(receipt, order=verified_order)
    verified_review = TradeReceiptReview.from_json(
        review.canonical_bytes,
        receipt=verified_receipt,
        order=verified_order,
    )
    if not isinstance(verifier_policy, RuleResolutionPolicy):
        raise TypeError("verifier_policy must be a RuleResolutionPolicy")
    if not isinstance(adapter_policy, TradeExecutionAdapterPolicy):
        raise TypeError(
            "adapter_policy must be a TradeExecutionAdapterPolicy"
        )
    review_document = verified_review.to_dict()
    sender = identity.as_did()
    if sender != review_document["reviewer_did"]:
        reject(error_type, "delivery signer does not match Review signer")
    recipient = verified_receipt.to_dict()["executor_did"]
    nonce_value = nonce if nonce is not None else secrets.token_hex(16)
    document = {
        "kind": RECEIPT_REVIEW_DELIVERY_KIND,
        "protocol_version": RECEIPT_REVIEW_DELIVERY_PROTOCOL_VERSION,
        "delivery_id": f"nth:trade:receipt-review-delivery:{nonce_value}",
        "nonce": nonce_value,
        "order_digest": trade_order_digest(verified_order),
        "receipt_digest": execution_receipt_digest(
            verified_receipt,
            order=verified_order,
        ),
        "review_digest": receipt_review_digest(
            verified_review,
            receipt=verified_receipt,
            order=verified_order,
        ),
        "sender_did": sender,
        "recipient_did": recipient,
        "created_at": created_at,
        "not_after": not_after,
        "review": verified_review.to_dict(),
        "verifier_policy": parse_trade_json(
            verifier_policy.canonical_bytes
        ),
        "adapter_policy": adapter_policy.to_dict(),
        "proof": {
            "type": RECEIPT_REVIEW_TRANSPORT_PROOF_TYPE,
            "created": created_at,
            "verification_method": verification_method_for_did(sender),
            "proof_purpose": RECEIPT_REVIEW_DELIVERY_PROOF_PURPOSE,
            "proof_value": "A" * 86,
        },
    }
    _validate_delivery_static(
        document,
        receipt=verified_receipt,
        order=verified_order,
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
    skew = bounded_seconds(
        clock_skew_seconds,
        label="clock_skew_seconds",
        error_type=error_type,
    )
    ttl = bounded_seconds(
        max_ttl_seconds,
        label="max_ttl_seconds",
        error_type=error_type,
    )
    if abs(current_ns - created_ns) > int(skew * 1_000_000_000):
        reject(error_type, "created_at exceeds local clock-skew limit")
    if expiry_ns - created_ns > int(ttl * 1_000_000_000):
        reject(error_type, "delivery lifetime exceeds max_ttl_seconds")
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(signed_document_input(_DELIVERY_DOMAIN, document))
    )
    return TradeReceiptReviewDelivery.from_dict(
        document,
        receipt=verified_receipt,
        order=verified_order,
    )


def verify_trade_receipt_review_delivery(
    delivery: TradeReceiptReviewDelivery | dict[str, Any],
    *,
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    recipient_did: str,
    at: datetime | None = None,
    max_ttl_seconds: float = DEFAULT_MAX_RECEIPT_REVIEW_DELIVERY_TTL_SECONDS,
    clock_skew_seconds: float = (
        DEFAULT_RECEIPT_REVIEW_DELIVERY_CLOCK_SKEW_SECONDS
    ),
) -> tuple[bool, str]:
    """Verify signature, destination, bindings, and freshness."""

    error_type = TradeReceiptReviewDeliveryRejected
    try:
        verified_order = _verified_order(order)
        verified_receipt = _verified_receipt(receipt, order=verified_order)
        verified = (
            TradeReceiptReviewDelivery.from_json(
                delivery.canonical_bytes,
                receipt=verified_receipt,
                order=verified_order,
            )
            if isinstance(delivery, TradeReceiptReviewDelivery)
            else TradeReceiptReviewDelivery.from_dict(
                delivery,
                receipt=verified_receipt,
                order=verified_order,
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
            bounded_seconds(
                clock_skew_seconds,
                label="clock_skew_seconds",
                error_type=error_type,
            )
            * 1_000_000_000
        )
        ttl_ns = int(
            bounded_seconds(
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
        TradeExecutionReceiptRejected,
        TradeOrderRejected,
        TradeProofError,
        TradeReceiptReviewDeliveryRejected,
        TradeReceiptReviewRejected,
        TypeError,
        ValueError,
        UnicodeError,
    ) as exc:
        return False, str(exc)
    return True, "ok"


def trade_receipt_review_delivery_digest(
    delivery: TradeReceiptReviewDelivery | dict[str, Any],
    *,
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
) -> str:
    verified = (
        TradeReceiptReviewDelivery.from_json(
            delivery.canonical_bytes,
            receipt=receipt,
            order=order,
        )
        if isinstance(delivery, TradeReceiptReviewDelivery)
        else TradeReceiptReviewDelivery.from_dict(
            delivery,
            receipt=receipt,
            order=order,
        )
    )
    return "sha256:" + hashlib.sha256(verified.canonical_bytes).hexdigest()


def create_trade_receipt_review_acknowledgement(
    identity: Any,
    *,
    delivery: TradeReceiptReviewDelivery,
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    received_at: str,
    audit_event_id: str,
    clock_skew_seconds: float = (
        DEFAULT_RECEIPT_REVIEW_DELIVERY_CLOCK_SKEW_SECONDS
    ),
) -> TradeReceiptReviewAcknowledgement:
    """Acknowledge that the verified Review reached CAS and Spine."""

    error_type = TradeReceiptReviewAcknowledgementRejected
    verified_order = _verified_order(order)
    verified_receipt = _verified_receipt(receipt, order=verified_order)
    verified_delivery = TradeReceiptReviewDelivery.from_json(
        delivery.canonical_bytes,
        receipt=verified_receipt,
        order=verified_order,
    )
    delivery_document = verified_delivery.to_dict()
    receiver = identity.as_did()
    if delivery_document["recipient_did"] != receiver:
        reject(error_type, "delivery recipient does not match receiver")
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
        bounded_seconds(
            clock_skew_seconds,
            label="clock_skew_seconds",
            error_type=error_type,
        )
        * 1_000_000_000
    )
    if not within_clock_skewed_lifetime(
        received_ns,
        created_ns=created_ns,
        expiry_ns=expiry_ns,
        skew_ns=skew_ns,
    ):
        reject(
            error_type,
            "received_at must be within signed delivery lifetime",
        )
    if (
        not isinstance(audit_event_id, str)
        or _EVENT_ID.fullmatch(audit_event_id) is None
    ):
        reject(error_type, "audit_event_id is invalid")
    document = {
        "kind": RECEIPT_REVIEW_ACKNOWLEDGEMENT_KIND,
        "protocol_version": RECEIPT_REVIEW_ACKNOWLEDGEMENT_PROTOCOL_VERSION,
        "order_digest": delivery_document["order_digest"],
        "receipt_digest": delivery_document["receipt_digest"],
        "review_digest": delivery_document["review_digest"],
        "delivery_digest": trade_receipt_review_delivery_digest(
            verified_delivery,
            receipt=verified_receipt,
            order=verified_order,
        ),
        "sender_did": delivery_document["sender_did"],
        "receiver_did": receiver,
        "received_at": received_at,
        "audit_event_id": audit_event_id,
        "status": "review-retained-verified",
        "proof": {
            "type": RECEIPT_REVIEW_TRANSPORT_PROOF_TYPE,
            "created": received_at,
            "verification_method": verification_method_for_did(receiver),
            "proof_purpose": RECEIPT_REVIEW_ACKNOWLEDGEMENT_PROOF_PURPOSE,
            "proof_value": "A" * 86,
        },
    }
    _validate_acknowledgement_static(document)
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(
            signed_document_input(_ACKNOWLEDGEMENT_DOMAIN, document)
        )
    )
    return TradeReceiptReviewAcknowledgement.from_dict(document)


def verify_trade_receipt_review_acknowledgement(
    acknowledgement: TradeReceiptReviewAcknowledgement | dict[str, Any],
    *,
    delivery: TradeReceiptReviewDelivery,
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
    receiver_did: str,
    audit_event_id: str,
    at: datetime | None = None,
    clock_skew_seconds: float = (
        DEFAULT_RECEIPT_REVIEW_DELIVERY_CLOCK_SKEW_SECONDS
    ),
) -> tuple[bool, str]:
    """Verify ACK signature, delivery bindings, and chronology."""

    error_type = TradeReceiptReviewAcknowledgementRejected
    try:
        verified_order = _verified_order(order)
        verified_receipt = _verified_receipt(receipt, order=verified_order)
        verified_delivery = TradeReceiptReviewDelivery.from_json(
            delivery.canonical_bytes,
            receipt=verified_receipt,
            order=verified_order,
        )
        verified_ack = (
            TradeReceiptReviewAcknowledgement.from_json(
                acknowledgement.canonical_bytes
            )
            if isinstance(
                acknowledgement,
                TradeReceiptReviewAcknowledgement,
            )
            else TradeReceiptReviewAcknowledgement.from_dict(acknowledgement)
        )
        if not isinstance(receiver_did, str) or not is_did_key(receiver_did):
            reject(error_type, "expected receiver_did is invalid")
        if (
            not isinstance(audit_event_id, str)
            or _EVENT_ID.fullmatch(audit_event_id) is None
        ):
            reject(error_type, "expected audit_event_id is invalid")
        delivery_document = verified_delivery.to_dict()
        ack_document = verified_ack.to_dict()
        expected = {
            "order_digest": delivery_document["order_digest"],
            "receipt_digest": delivery_document["receipt_digest"],
            "review_digest": delivery_document["review_digest"],
            "delivery_digest": trade_receipt_review_delivery_digest(
                verified_delivery,
                receipt=verified_receipt,
                order=verified_order,
            ),
            "sender_did": delivery_document["sender_did"],
            "receiver_did": receiver_did,
            "audit_event_id": audit_event_id,
        }
        for field, value in expected.items():
            if ack_document[field] != value:
                reject(
                    error_type,
                    f"acknowledgement {field} does not match delivery",
                )
        if delivery_document["recipient_did"] != receiver_did:
            reject(error_type, "delivery recipient does not match receiver")
        received_ns = timestamp_ns(
            ack_document["received_at"],
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
            bounded_seconds(
                clock_skew_seconds,
                label="clock_skew_seconds",
                error_type=error_type,
            )
            * 1_000_000_000
        )
        if not within_clock_skewed_lifetime(
            received_ns,
            created_ns=created_ns,
            expiry_ns=expiry_ns,
            skew_ns=skew_ns,
        ):
            reject(
                error_type,
                "received_at is outside signed delivery lifetime",
            )
        if at is not None:
            observed_ns = now_ns(at, error_type=error_type)
            if received_ns > observed_ns + skew_ns:
                reject(error_type, "received_at is too far in the future")
    except (
        TradeCanonicalJSONError,
        TradeExecutionReceiptRejected,
        TradeOrderRejected,
        TradeProofError,
        TradeReceiptReviewAcknowledgementRejected,
        TradeReceiptReviewDeliveryRejected,
        TradeReceiptReviewRejected,
        TypeError,
        ValueError,
        UnicodeError,
    ) as exc:
        return False, str(exc)
    return True, "ok"


def trade_receipt_review_acknowledgement_digest(
    acknowledgement: TradeReceiptReviewAcknowledgement | dict[str, Any],
) -> str:
    verified = (
        TradeReceiptReviewAcknowledgement.from_json(
            acknowledgement.canonical_bytes
        )
        if isinstance(acknowledgement, TradeReceiptReviewAcknowledgement)
        else TradeReceiptReviewAcknowledgement.from_dict(acknowledgement)
    )
    return "sha256:" + hashlib.sha256(verified.canonical_bytes).hexdigest()


__all__ = [
    "DEFAULT_MAX_RECEIPT_REVIEW_DELIVERY_TTL_SECONDS",
    "DEFAULT_RECEIPT_REVIEW_DELIVERY_CLOCK_SKEW_SECONDS",
    "RECEIPT_REVIEW_ACKNOWLEDGEMENT_KIND",
    "RECEIPT_REVIEW_ACKNOWLEDGEMENT_PROOF_PURPOSE",
    "RECEIPT_REVIEW_ACKNOWLEDGEMENT_PROTOCOL_VERSION",
    "RECEIPT_REVIEW_DELIVERY_KIND",
    "RECEIPT_REVIEW_DELIVERY_PROOF_PURPOSE",
    "RECEIPT_REVIEW_DELIVERY_PROTOCOL_VERSION",
    "RECEIPT_REVIEW_TRANSPORT_PROOF_TYPE",
    "TradeReceiptReviewAcknowledgement",
    "TradeReceiptReviewAcknowledgementRejected",
    "TradeReceiptReviewDelivery",
    "TradeReceiptReviewDeliveryRejected",
    "create_trade_receipt_review_acknowledgement",
    "create_trade_receipt_review_delivery",
    "trade_receipt_review_acknowledgement_digest",
    "trade_receipt_review_delivery_digest",
    "verify_trade_receipt_review_acknowledgement",
    "verify_trade_receipt_review_delivery",
]
