"""Destination-bound signed transport for accepted Trade Orders."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import math
import re
import secrets
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
from nth_dao.trade_rules.signing import (
    TradeProofError,
    encode_ed25519_signature,
    signed_document_input,
    verification_method_for_did,
    verify_ed25519_did_signature,
)

ORDER_DELIVERY_KIND = "nth.dao.trade.order-delivery"
ORDER_DELIVERY_PROTOCOL_VERSION = "1"
ORDER_DELIVERY_PROOF_PURPOSE = "tradeOrderDelivery"
ORDER_DELIVERY_PROOF_TYPE = "Ed25519Signature2020"
ORDER_INTAKE_RECEIPT_KIND = "nth.dao.trade.order-intake-receipt"
ORDER_INTAKE_RECEIPT_PROTOCOL_VERSION = "1"
ORDER_INTAKE_RECEIPT_PROOF_PURPOSE = "tradeOrderIntakeReceipt"
DEFAULT_MAX_ORDER_DELIVERY_TTL_SECONDS = 600.0
DEFAULT_ORDER_DELIVERY_CLOCK_SKEW_SECONDS = 300.0

_DOMAIN = b"nth-dao/trade-order-delivery/v1"
_INTAKE_RECEIPT_DOMAIN = b"nth-dao/trade-order-intake-receipt/v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVENT_ID = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^(?:[0-9a-f]{2}){16,64}$")
_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(\d{1,9}))?Z$"
)
_PROOF_FIELDS = frozenset(
    {
        "type",
        "created",
        "verification_method",
        "proof_purpose",
        "proof_value",
    }
)
_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "delivery_id",
        "nonce",
        "order_digest",
        "sender_did",
        "recipient_did",
        "created_at",
        "not_after",
        "order",
        "proof",
    }
)
_INTAKE_RECEIPT_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "order_digest",
        "delivery_digest",
        "sender_did",
        "receiver_did",
        "received_at",
        "audit_event_id",
        "status",
        "proof",
    }
)


class TradeOrderDeliveryRejected(ValueError):
    """The Order delivery is malformed, unbound, expired, or unsigned."""


class TradeOrderIntakeReceiptRejected(ValueError):
    """The receiver-signed durable Order receipt is invalid or unbound."""


def _reject(message: str) -> None:
    raise TradeOrderDeliveryRejected(message)


def _timestamp_ns(value: Any, *, label: str) -> int:
    if not isinstance(value, str) or len(value) > 35:
        _reject(f"{label} must be a UTC RFC3339 timestamp")
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        _reject(f"{label} must be a UTC RFC3339 timestamp")
    try:
        base = datetime.strptime(
            match.group(1), "%Y-%m-%dT%H:%M:%S"
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise TradeOrderDeliveryRejected(
            f"{label} is not a real timestamp"
        ) from exc
    nanos = int((match.group(2) or "").ljust(9, "0") or "0")
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = base - epoch
    return (
        (delta.days * 86_400 + delta.seconds) * 1_000_000_000
        + nanos
    )


def _datetime_ns(value: datetime) -> int:
    moment = value.astimezone(timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = moment - epoch
    return (
        (delta.days * 86_400 + delta.seconds) * 1_000_000_000
        + delta.microseconds * 1_000
    )


def _utc_now(value: datetime | None) -> datetime:
    moment = value or datetime.now(timezone.utc)
    if (
        not isinstance(moment, datetime)
        or moment.tzinfo is None
        or moment.utcoffset() is None
    ):
        _reject("now must be timezone-aware")
    return moment.astimezone(timezone.utc)


def _bounded_seconds(value: Any, *, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        _reject(f"{label} must be a finite non-negative number")
    return float(value)


def _validate_static(document: dict[str, Any]) -> TradeOrder:
    if not isinstance(document, dict) or set(document) != _FIELDS:
        _reject("Order delivery has missing or unknown fields")
    if document["kind"] != ORDER_DELIVERY_KIND:
        _reject("wrong Order delivery kind")
    if document["protocol_version"] != ORDER_DELIVERY_PROTOCOL_VERSION:
        _reject("unsupported Order delivery protocol_version")
    nonce = document["nonce"]
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        _reject("nonce must be 16 to 64 bytes of lowercase hex")
    if document["delivery_id"] != f"nth:trade:order-delivery:{nonce}":
        _reject("delivery_id does not match nonce")
    sender = document["sender_did"]
    recipient = document["recipient_did"]
    if not isinstance(sender, str) or not is_did_key(sender):
        _reject("sender_did must be an Ed25519 did:key")
    if not isinstance(recipient, str) or not is_did_key(recipient):
        _reject("recipient_did must be an Ed25519 did:key")
    if sender == recipient:
        _reject("sender and recipient must be different principals")
    claimed_digest = document["order_digest"]
    if (
        not isinstance(claimed_digest, str)
        or _DIGEST.fullmatch(claimed_digest) is None
    ):
        _reject("order_digest must be a lowercase sha256 digest")
    try:
        order = TradeOrder.from_dict(document["order"])
    except (TradeOrderRejected, TypeError, ValueError) as exc:
        raise TradeOrderDeliveryRejected(
            f"embedded Order is invalid: {exc}"
        ) from exc
    order_document = order.to_dict()
    if trade_order_digest(order) != claimed_digest:
        _reject("order_digest does not match embedded Order")
    if order_document["maker_did"] != sender:
        _reject("sender_did does not match Order maker")
    if order_document["taker_did"] != recipient:
        _reject("recipient_did does not match Order taker")
    created = _timestamp_ns(document["created_at"], label="created_at")
    not_after = _timestamp_ns(document["not_after"], label="not_after")
    if not_after <= created:
        _reject("not_after must be later than created_at")
    accepted_at = _timestamp_ns(
        order_document["created_at"], label="order.created_at"
    )
    if created < accepted_at:
        _reject("Order delivery cannot predate the signed Acceptance")
    proof = document["proof"]
    if not isinstance(proof, dict) or set(proof) != _PROOF_FIELDS:
        _reject("proof has missing or unknown fields")
    if proof["type"] != ORDER_DELIVERY_PROOF_TYPE:
        _reject("proof type is invalid")
    if proof["verification_method"] != verification_method_for_did(sender):
        _reject("proof verification_method does not match sender")
    if proof["proof_purpose"] != ORDER_DELIVERY_PROOF_PURPOSE:
        _reject("proof purpose is invalid")
    if not isinstance(proof["proof_value"], str):
        _reject("proof value is invalid")
    if _timestamp_ns(proof["created"], label="proof.created") != created:
        _reject("proof.created must equal delivery created_at")
    return order


def _verify_signature(document: dict[str, Any]) -> None:
    try:
        signing_input = signed_document_input(_DOMAIN, document)
    except TradeProofError as exc:
        raise TradeOrderDeliveryRejected(str(exc)) from exc
    ok, reason = verify_ed25519_did_signature(
        publisher_did=document["sender_did"],
        proof_value=document["proof"]["proof_value"],
        signing_input=signing_input,
    )
    if not ok:
        _reject(reason)


@dataclass(frozen=True, init=False)
class TradeOrderDelivery:
    """Immutable canonical envelope carrying one self-verifying Order."""

    _canonical_bytes: bytes
    _order: TradeOrder

    @classmethod
    def _create(
        cls, canonical: bytes, order: TradeOrder
    ) -> "TradeOrderDelivery":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        object.__setattr__(value, "_order", order)
        return value

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> "TradeOrderDelivery":
        try:
            canonical = trade_canonical_json(copy.deepcopy(document))
            snapshot = parse_trade_json(canonical)
            order = _validate_static(snapshot)
            _verify_signature(snapshot)
        except (
            TradeCanonicalJSONError,
            TradeOrderRejected,
            TradeProofError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            if isinstance(exc, TradeOrderDeliveryRejected):
                raise
            raise TradeOrderDeliveryRejected(str(exc)) from exc
        return cls._create(canonical, order)

    @classmethod
    def from_json(cls, raw: bytes | str) -> "TradeOrderDelivery":
        try:
            return cls.from_dict(parse_trade_json(raw))
        except TradeCanonicalJSONError as exc:
            raise TradeOrderDeliveryRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    @property
    def order(self) -> TradeOrder:
        return self._order

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


def _validate_intake_receipt_static(document: dict[str, Any]) -> None:
    if not isinstance(document, dict) or set(document) != _INTAKE_RECEIPT_FIELDS:
        raise TradeOrderIntakeReceiptRejected(
            "Order intake receipt has missing or unknown fields"
        )
    if document["kind"] != ORDER_INTAKE_RECEIPT_KIND:
        raise TradeOrderIntakeReceiptRejected(
            "wrong Order intake receipt kind"
        )
    if document["protocol_version"] != ORDER_INTAKE_RECEIPT_PROTOCOL_VERSION:
        raise TradeOrderIntakeReceiptRejected(
            "unsupported Order intake receipt protocol_version"
        )
    for field in ("order_digest", "delivery_digest"):
        if (
            not isinstance(document[field], str)
            or _DIGEST.fullmatch(document[field]) is None
        ):
            raise TradeOrderIntakeReceiptRejected(
                f"{field} must be a lowercase sha256 digest"
            )
    for field in ("sender_did", "receiver_did"):
        if not isinstance(document[field], str) or not is_did_key(document[field]):
            raise TradeOrderIntakeReceiptRejected(
                f"{field} must be an Ed25519 did:key"
            )
    if document["sender_did"] == document["receiver_did"]:
        raise TradeOrderIntakeReceiptRejected(
            "Order intake receipt parties must be different principals"
        )
    _timestamp_ns(document["received_at"], label="received_at")
    if (
        not isinstance(document["audit_event_id"], str)
        or _EVENT_ID.fullmatch(document["audit_event_id"]) is None
    ):
        raise TradeOrderIntakeReceiptRejected("audit_event_id is invalid")
    if document["status"] != "retained-accepted":
        raise TradeOrderIntakeReceiptRejected(
            "Order intake receipt status is invalid"
        )
    proof = document["proof"]
    if not isinstance(proof, dict) or set(proof) != _PROOF_FIELDS:
        raise TradeOrderIntakeReceiptRejected(
            "Order intake receipt proof has missing or unknown fields"
        )
    if proof["type"] != ORDER_DELIVERY_PROOF_TYPE:
        raise TradeOrderIntakeReceiptRejected(
            "Order intake receipt proof type is invalid"
        )
    if proof["verification_method"] != verification_method_for_did(
        document["receiver_did"]
    ):
        raise TradeOrderIntakeReceiptRejected(
            "Order intake receipt verification_method does not match receiver"
        )
    if proof["proof_purpose"] != ORDER_INTAKE_RECEIPT_PROOF_PURPOSE:
        raise TradeOrderIntakeReceiptRejected(
            "Order intake receipt proof purpose is invalid"
        )
    if not isinstance(proof["proof_value"], str):
        raise TradeOrderIntakeReceiptRejected(
            "Order intake receipt proof value is invalid"
        )
    if _timestamp_ns(proof["created"], label="proof.created") != _timestamp_ns(
        document["received_at"], label="received_at"
    ):
        raise TradeOrderIntakeReceiptRejected(
            "proof.created must equal receipt received_at"
        )


def _verify_intake_receipt_signature(document: dict[str, Any]) -> None:
    try:
        signing_input = signed_document_input(_INTAKE_RECEIPT_DOMAIN, document)
    except TradeProofError as exc:
        raise TradeOrderIntakeReceiptRejected(str(exc)) from exc
    ok, reason = verify_ed25519_did_signature(
        publisher_did=document["receiver_did"],
        proof_value=document["proof"]["proof_value"],
        signing_input=signing_input,
    )
    if not ok:
        raise TradeOrderIntakeReceiptRejected(reason)


@dataclass(frozen=True, init=False)
class TradeOrderIntakeReceipt:
    """Receiver-signed claim that an accepted Order reached Store and Spine."""

    _canonical_bytes: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "TradeOrderIntakeReceipt":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        return value

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> "TradeOrderIntakeReceipt":
        try:
            canonical = trade_canonical_json(copy.deepcopy(document))
            snapshot = parse_trade_json(canonical)
            _validate_intake_receipt_static(snapshot)
            _verify_intake_receipt_signature(snapshot)
        except (
            TradeCanonicalJSONError,
            TradeProofError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            if isinstance(exc, TradeOrderIntakeReceiptRejected):
                raise
            raise TradeOrderIntakeReceiptRejected(str(exc)) from exc
        return cls._create(canonical)

    @classmethod
    def from_json(cls, raw: bytes | str) -> "TradeOrderIntakeReceipt":
        try:
            return cls.from_dict(parse_trade_json(raw))
        except TradeCanonicalJSONError as exc:
            raise TradeOrderIntakeReceiptRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


def create_trade_order_delivery(
    identity: Any,
    *,
    order: TradeOrder,
    created_at: str,
    not_after: str,
    nonce: str | None = None,
    now: datetime | None = None,
    max_ttl_seconds: float = DEFAULT_MAX_ORDER_DELIVERY_TTL_SECONDS,
    clock_skew_seconds: float = DEFAULT_ORDER_DELIVERY_CLOCK_SKEW_SECONDS,
) -> TradeOrderDelivery:
    """Create one short-lived Order envelope signed by its maker."""

    verified_order = TradeOrder.from_json(order.canonical_bytes)
    order_document = verified_order.to_dict()
    sender = identity.as_did()
    if sender != order_document["maker_did"]:
        _reject("Order delivery signer does not match Order maker")
    nonce_value = nonce if nonce is not None else secrets.token_hex(16)
    document = {
        "kind": ORDER_DELIVERY_KIND,
        "protocol_version": ORDER_DELIVERY_PROTOCOL_VERSION,
        "delivery_id": f"nth:trade:order-delivery:{nonce_value}",
        "nonce": nonce_value,
        "order_digest": trade_order_digest(verified_order),
        "sender_did": sender,
        "recipient_did": order_document["taker_did"],
        "created_at": created_at,
        "not_after": not_after,
        "order": order_document,
        "proof": {
            "type": ORDER_DELIVERY_PROOF_TYPE,
            "created": created_at,
            "verification_method": verification_method_for_did(sender),
            "proof_purpose": ORDER_DELIVERY_PROOF_PURPOSE,
            "proof_value": "A" * 86,
        },
    }
    _validate_static(document)
    current_ns = _datetime_ns(_utc_now(now))
    created_ns = _timestamp_ns(created_at, label="created_at")
    expiry_ns = _timestamp_ns(not_after, label="not_after")
    skew = _bounded_seconds(clock_skew_seconds, label="clock_skew_seconds")
    ttl = _bounded_seconds(max_ttl_seconds, label="max_ttl_seconds")
    if abs(current_ns - created_ns) > int(skew * 1_000_000_000):
        _reject("created_at exceeds the local signing clock-skew limit")
    if expiry_ns - created_ns > int(ttl * 1_000_000_000):
        _reject("Order delivery lifetime exceeds max_ttl_seconds")
    signing_input = signed_document_input(_DOMAIN, document)
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(signing_input)
    )
    return TradeOrderDelivery.from_dict(document)


def verify_trade_order_delivery(
    delivery: TradeOrderDelivery | dict[str, Any],
    *,
    recipient_did: str,
    at: datetime | None = None,
    max_ttl_seconds: float = DEFAULT_MAX_ORDER_DELIVERY_TTL_SECONDS,
    clock_skew_seconds: float = DEFAULT_ORDER_DELIVERY_CLOCK_SKEW_SECONDS,
) -> tuple[bool, str]:
    """Verify signature, destination, freshness, and bounded lifetime."""

    try:
        verified = (
            TradeOrderDelivery.from_json(delivery.canonical_bytes)
            if isinstance(delivery, TradeOrderDelivery)
            else TradeOrderDelivery.from_dict(delivery)
        )
        document = verified.to_dict()
        if document["recipient_did"] != recipient_did:
            _reject("Order delivery recipient does not match this node")
        current_ns = _datetime_ns(_utc_now(at))
        created_ns = _timestamp_ns(document["created_at"], label="created_at")
        expiry_ns = _timestamp_ns(document["not_after"], label="not_after")
        skew = _bounded_seconds(
            clock_skew_seconds, label="clock_skew_seconds"
        )
        ttl = _bounded_seconds(max_ttl_seconds, label="max_ttl_seconds")
        if expiry_ns - created_ns > int(ttl * 1_000_000_000):
            _reject("Order delivery lifetime exceeds max_ttl_seconds")
        if current_ns < created_ns - int(skew * 1_000_000_000):
            _reject("Order delivery was created too far in the future")
        if current_ns > expiry_ns + int(skew * 1_000_000_000):
            _reject("Order delivery has expired")
    except (
        TradeCanonicalJSONError,
        TradeOrderDeliveryRejected,
        TradeOrderRejected,
        TradeProofError,
        TypeError,
        ValueError,
        UnicodeError,
    ) as exc:
        return False, str(exc)
    return True, "ok"


def trade_order_delivery_digest(
    delivery: TradeOrderDelivery | dict[str, Any],
) -> str:
    verified = (
        TradeOrderDelivery.from_json(delivery.canonical_bytes)
        if isinstance(delivery, TradeOrderDelivery)
        else TradeOrderDelivery.from_dict(delivery)
    )
    return "sha256:" + hashlib.sha256(verified.canonical_bytes).hexdigest()


def create_trade_order_intake_receipt(
    identity: Any,
    *,
    delivery: TradeOrderDelivery,
    received_at: str,
    audit_event_id: str,
    clock_skew_seconds: float = DEFAULT_ORDER_DELIVERY_CLOCK_SKEW_SECONDS,
) -> TradeOrderIntakeReceipt:
    """Sign the receiver's durable-retention acknowledgement claim."""

    verified_delivery = TradeOrderDelivery.from_json(delivery.canonical_bytes)
    delivery_document = verified_delivery.to_dict()
    receiver = identity.as_did()
    if delivery_document["recipient_did"] != receiver:
        raise TradeOrderIntakeReceiptRejected(
            "Order Delivery recipient does not match intake receiver"
        )
    received_ns = _timestamp_ns(received_at, label="received_at")
    created_ns = _timestamp_ns(
        delivery_document["created_at"], label="delivery.created_at"
    )
    expiry_ns = _timestamp_ns(
        delivery_document["not_after"], label="delivery.not_after"
    )
    skew_ns = int(
        _bounded_seconds(
            clock_skew_seconds,
            label="clock_skew_seconds",
        )
        * 1_000_000_000
    )
    if received_ns < created_ns or received_ns > expiry_ns + skew_ns:
        raise TradeOrderIntakeReceiptRejected(
            "received_at must be within the signed Delivery lifetime"
        )
    document = {
        "kind": ORDER_INTAKE_RECEIPT_KIND,
        "protocol_version": ORDER_INTAKE_RECEIPT_PROTOCOL_VERSION,
        "order_digest": delivery_document["order_digest"],
        "delivery_digest": trade_order_delivery_digest(verified_delivery),
        "sender_did": delivery_document["sender_did"],
        "receiver_did": receiver,
        "received_at": received_at,
        "audit_event_id": audit_event_id,
        "status": "retained-accepted",
        "proof": {
            "type": ORDER_DELIVERY_PROOF_TYPE,
            "created": received_at,
            "verification_method": verification_method_for_did(receiver),
            "proof_purpose": ORDER_INTAKE_RECEIPT_PROOF_PURPOSE,
            "proof_value": "A" * 86,
        },
    }
    _validate_intake_receipt_static(document)
    signing_input = signed_document_input(_INTAKE_RECEIPT_DOMAIN, document)
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(signing_input)
    )
    return TradeOrderIntakeReceipt.from_dict(document)


def verify_trade_order_intake_receipt(
    receipt: TradeOrderIntakeReceipt | dict[str, Any],
    *,
    delivery: TradeOrderDelivery,
    receiver_did: str,
    audit_event_id: str,
    at: datetime | None = None,
    clock_skew_seconds: float = DEFAULT_ORDER_DELIVERY_CLOCK_SKEW_SECONDS,
) -> tuple[bool, str]:
    """Verify the signed claim, bindings, and plausible chronology."""

    try:
        verified_receipt = (
            TradeOrderIntakeReceipt.from_json(receipt.canonical_bytes)
            if isinstance(receipt, TradeOrderIntakeReceipt)
            else TradeOrderIntakeReceipt.from_dict(receipt)
        )
        verified_delivery = TradeOrderDelivery.from_json(
            delivery.canonical_bytes
        )
        if not isinstance(receiver_did, str) or not is_did_key(receiver_did):
            raise TradeOrderIntakeReceiptRejected(
                "expected receiver_did must be an Ed25519 did:key"
            )
        if (
            not isinstance(audit_event_id, str)
            or _EVENT_ID.fullmatch(audit_event_id) is None
        ):
            raise TradeOrderIntakeReceiptRejected(
                "expected audit_event_id is invalid"
            )
        receipt_document = verified_receipt.to_dict()
        delivery_document = verified_delivery.to_dict()
        expected = {
            "order_digest": delivery_document["order_digest"],
            "delivery_digest": trade_order_delivery_digest(verified_delivery),
            "sender_did": delivery_document["sender_did"],
            "receiver_did": receiver_did,
            "audit_event_id": audit_event_id,
        }
        for field, value in expected.items():
            if receipt_document[field] != value:
                raise TradeOrderIntakeReceiptRejected(
                    f"Order intake receipt {field} does not match Delivery"
                )
        if delivery_document["recipient_did"] != receiver_did:
            raise TradeOrderIntakeReceiptRejected(
                "Order Delivery recipient does not match intake receiver"
            )
        received_ns = _timestamp_ns(
            receipt_document["received_at"], label="received_at"
        )
        created_ns = _timestamp_ns(
            delivery_document["created_at"], label="delivery.created_at"
        )
        expiry_ns = _timestamp_ns(
            delivery_document["not_after"], label="delivery.not_after"
        )
        skew_ns = int(
            _bounded_seconds(
                clock_skew_seconds,
                label="clock_skew_seconds",
            )
            * 1_000_000_000
        )
        if received_ns < created_ns or received_ns > expiry_ns + skew_ns:
            raise TradeOrderIntakeReceiptRejected(
                "received_at is outside the signed Delivery lifetime"
            )
        if at is not None:
            observed_ns = _datetime_ns(_utc_now(at))
            if received_ns > observed_ns + skew_ns:
                raise TradeOrderIntakeReceiptRejected(
                    "received_at is too far in the future"
                )
    except (
        TradeOrderDeliveryRejected,
        TradeOrderIntakeReceiptRejected,
        TradeCanonicalJSONError,
        TradeProofError,
        TypeError,
        ValueError,
        UnicodeError,
    ) as exc:
        return False, str(exc)
    return True, "ok"


def trade_order_intake_receipt_digest(
    receipt: TradeOrderIntakeReceipt | dict[str, Any],
) -> str:
    verified = (
        TradeOrderIntakeReceipt.from_json(receipt.canonical_bytes)
        if isinstance(receipt, TradeOrderIntakeReceipt)
        else TradeOrderIntakeReceipt.from_dict(receipt)
    )
    return "sha256:" + hashlib.sha256(verified.canonical_bytes).hexdigest()


__all__ = [
    "DEFAULT_MAX_ORDER_DELIVERY_TTL_SECONDS",
    "DEFAULT_ORDER_DELIVERY_CLOCK_SKEW_SECONDS",
    "ORDER_DELIVERY_KIND",
    "ORDER_DELIVERY_PROOF_PURPOSE",
    "ORDER_DELIVERY_PROOF_TYPE",
    "ORDER_DELIVERY_PROTOCOL_VERSION",
    "ORDER_INTAKE_RECEIPT_KIND",
    "ORDER_INTAKE_RECEIPT_PROOF_PURPOSE",
    "ORDER_INTAKE_RECEIPT_PROTOCOL_VERSION",
    "TradeOrderDelivery",
    "TradeOrderDeliveryRejected",
    "TradeOrderIntakeReceipt",
    "TradeOrderIntakeReceiptRejected",
    "create_trade_order_delivery",
    "create_trade_order_intake_receipt",
    "trade_order_delivery_digest",
    "trade_order_intake_receipt_digest",
    "verify_trade_order_delivery",
    "verify_trade_order_intake_receipt",
]
