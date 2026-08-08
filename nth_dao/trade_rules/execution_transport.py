"""Destination-bound transport for signed Trade Execution Receipts."""

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
from nth_dao.trade_rules.execution_receipt import (
    TradeExecutionReceipt,
    TradeExecutionReceiptRejected,
    execution_receipt_digest,
)
from nth_dao.trade_rules.signing import (
    TradeProofError,
    encode_ed25519_signature,
    signed_document_input,
    verification_method_for_did,
    verify_ed25519_did_signature,
)

EXECUTION_RECEIPT_DELIVERY_KIND = (
    "nth.dao.trade.execution-receipt-delivery"
)
EXECUTION_RECEIPT_DELIVERY_PROTOCOL_VERSION = "1"
EXECUTION_RECEIPT_DELIVERY_PROOF_PURPOSE = (
    "tradeExecutionReceiptDelivery"
)
EXECUTION_RECEIPT_ACKNOWLEDGEMENT_KIND = (
    "nth.dao.trade.execution-receipt-acknowledgement"
)
EXECUTION_RECEIPT_ACKNOWLEDGEMENT_PROTOCOL_VERSION = "1"
EXECUTION_RECEIPT_ACKNOWLEDGEMENT_PROOF_PURPOSE = (
    "tradeExecutionReceiptAcknowledgement"
)
EXECUTION_RECEIPT_TRANSPORT_PROOF_TYPE = "Ed25519Signature2020"
DEFAULT_MAX_EXECUTION_RECEIPT_DELIVERY_TTL_SECONDS = 600.0
DEFAULT_EXECUTION_RECEIPT_DELIVERY_CLOCK_SKEW_SECONDS = 300.0

_DELIVERY_DOMAIN = b"nth-dao/trade-execution-receipt-delivery/v1"
_ACKNOWLEDGEMENT_DOMAIN = (
    b"nth-dao/trade-execution-receipt-acknowledgement/v1"
)
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
_DELIVERY_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "delivery_id",
        "nonce",
        "order_digest",
        "receipt_digest",
        "sender_did",
        "recipient_did",
        "created_at",
        "not_after",
        "receipt",
        "proof",
    }
)
_ACKNOWLEDGEMENT_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "order_digest",
        "receipt_digest",
        "delivery_digest",
        "sender_did",
        "receiver_did",
        "received_at",
        "audit_event_id",
        "status",
        "proof",
    }
)


class TradeExecutionReceiptDeliveryRejected(ValueError):
    """An execution Receipt delivery is malformed, stale, or unbound."""


class TradeExecutionReceiptAcknowledgementRejected(ValueError):
    """A receiver acknowledgement is malformed, unsigned, or unbound."""


def _raise(error_type: type[ValueError], message: str) -> None:
    raise error_type(message)


def _timestamp_ns(
    value: Any,
    *,
    label: str,
    error_type: type[ValueError],
) -> int:
    if not isinstance(value, str) or len(value) > 35:
        _raise(error_type, f"{label} must be a UTC RFC3339 timestamp")
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        _raise(error_type, f"{label} must be a UTC RFC3339 timestamp")
    try:
        base = datetime.strptime(
            match.group(1), "%Y-%m-%dT%H:%M:%S"
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise error_type(f"{label} is not a real timestamp") from exc
    nanos = int((match.group(2) or "").ljust(9, "0") or "0")
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = base - epoch
    return (
        (delta.days * 86_400 + delta.seconds) * 1_000_000_000
        + nanos
    )


def _datetime_ns(
    value: datetime,
    *,
    error_type: type[ValueError],
) -> int:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        _raise(error_type, "now must be timezone-aware")
    moment = value.astimezone(timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = moment - epoch
    return (
        (delta.days * 86_400 + delta.seconds) * 1_000_000_000
        + delta.microseconds * 1_000
    )


def _now_ns(
    value: datetime | None,
    *,
    error_type: type[ValueError],
) -> int:
    return _datetime_ns(
        value or datetime.now(timezone.utc),
        error_type=error_type,
    )


def _bounded_seconds(
    value: Any,
    *,
    label: str,
    error_type: type[ValueError],
) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        _raise(
            error_type,
            f"{label} must be a finite non-negative number",
        )
    return float(value)


def _verified_order(order: TradeOrder | dict[str, Any]) -> TradeOrder:
    return (
        TradeOrder.from_json(order.canonical_bytes)
        if isinstance(order, TradeOrder)
        else TradeOrder.from_dict(order)
    )


def _opposite_party(
    order_document: dict[str, Any],
    sender_did: str,
    *,
    error_type: type[ValueError],
) -> str:
    if sender_did == order_document["maker_did"]:
        return order_document["taker_did"]
    if sender_did == order_document["taker_did"]:
        return order_document["maker_did"]
    _raise(error_type, "sender_did is not a party to the signed Order")


def _validate_proof(
    proof: Any,
    *,
    signer_did: str,
    purpose: str,
    created_at: str,
    error_type: type[ValueError],
) -> None:
    if not isinstance(proof, dict) or set(proof) != _PROOF_FIELDS:
        _raise(error_type, "proof has missing or unknown fields")
    if proof["type"] != EXECUTION_RECEIPT_TRANSPORT_PROOF_TYPE:
        _raise(error_type, "proof type is invalid")
    if proof["verification_method"] != verification_method_for_did(
        signer_did
    ):
        _raise(
            error_type,
            "proof verification_method does not match signer",
        )
    if proof["proof_purpose"] != purpose:
        _raise(error_type, "proof purpose is invalid")
    if not isinstance(proof["proof_value"], str):
        _raise(error_type, "proof value is invalid")
    proof_ns = _timestamp_ns(
        proof["created"],
        label="proof.created",
        error_type=error_type,
    )
    created_ns = _timestamp_ns(
        created_at,
        label="created_at",
        error_type=error_type,
    )
    if proof_ns != created_ns:
        _raise(error_type, "proof.created must equal created_at")


def _verify_signature(
    document: dict[str, Any],
    *,
    signer_field: str,
    domain: bytes,
    error_type: type[ValueError],
) -> None:
    try:
        signing_input = signed_document_input(domain, document)
    except TradeProofError as exc:
        raise error_type(str(exc)) from exc
    ok, reason = verify_ed25519_did_signature(
        publisher_did=document[signer_field],
        proof_value=document["proof"]["proof_value"],
        signing_input=signing_input,
    )
    if not ok:
        _raise(error_type, reason)


def _validate_delivery_static(
    document: dict[str, Any],
    *,
    order: TradeOrder,
) -> TradeExecutionReceipt:
    error_type = TradeExecutionReceiptDeliveryRejected
    if not isinstance(document, dict) or set(document) != _DELIVERY_FIELDS:
        _raise(error_type, "delivery has missing or unknown fields")
    if document["kind"] != EXECUTION_RECEIPT_DELIVERY_KIND:
        _raise(error_type, "wrong execution Receipt delivery kind")
    if (
        document["protocol_version"]
        != EXECUTION_RECEIPT_DELIVERY_PROTOCOL_VERSION
    ):
        _raise(error_type, "unsupported delivery protocol_version")
    nonce = document["nonce"]
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        _raise(error_type, "nonce must be 16 to 64 bytes of lowercase hex")
    if document["delivery_id"] != (
        f"nth:trade:execution-receipt-delivery:{nonce}"
    ):
        _raise(error_type, "delivery_id does not match nonce")
    for field in ("order_digest", "receipt_digest"):
        if (
            not isinstance(document[field], str)
            or _DIGEST.fullmatch(document[field]) is None
        ):
            _raise(error_type, f"{field} must be a lowercase sha256 digest")
    for field in ("sender_did", "recipient_did"):
        if (
            not isinstance(document[field], str)
            or not is_did_key(document[field])
        ):
            _raise(error_type, f"{field} must be an Ed25519 did:key")
    if document["sender_did"] == document["recipient_did"]:
        _raise(error_type, "delivery parties must be different principals")
    order_document = order.to_dict()
    if document["order_digest"] != trade_order_digest(order):
        _raise(error_type, "order_digest does not match signed Order")
    try:
        receipt = TradeExecutionReceipt.from_dict(
            document["receipt"],
            order=order,
        )
    except (TradeExecutionReceiptRejected, TypeError, ValueError) as exc:
        raise error_type(f"embedded Receipt is invalid: {exc}") from exc
    receipt_document = receipt.to_dict()
    if document["receipt_digest"] != execution_receipt_digest(
        receipt,
        order=order,
    ):
        _raise(error_type, "receipt_digest does not match embedded Receipt")
    if document["sender_did"] != receipt_document["executor_did"]:
        _raise(error_type, "sender_did does not match Receipt executor")
    expected_recipient = _opposite_party(
        order_document,
        document["sender_did"],
        error_type=error_type,
    )
    if document["recipient_did"] != expected_recipient:
        _raise(error_type, "recipient_did is not the opposing Order party")
    created_ns = _timestamp_ns(
        document["created_at"],
        label="created_at",
        error_type=error_type,
    )
    expiry_ns = _timestamp_ns(
        document["not_after"],
        label="not_after",
        error_type=error_type,
    )
    completed_ns = _timestamp_ns(
        receipt_document["completed_at"],
        label="receipt.completed_at",
        error_type=error_type,
    )
    if expiry_ns <= created_ns:
        _raise(error_type, "not_after must be later than created_at")
    if created_ns < completed_ns:
        _raise(error_type, "delivery cannot predate Receipt completion")
    _validate_proof(
        document["proof"],
        signer_did=document["sender_did"],
        purpose=EXECUTION_RECEIPT_DELIVERY_PROOF_PURPOSE,
        created_at=document["created_at"],
        error_type=error_type,
    )
    return receipt


@dataclass(frozen=True, init=False)
class TradeExecutionReceiptDelivery:
    """Canonical destination-bound envelope for one signed Receipt."""

    _canonical_bytes: bytes
    _receipt: TradeExecutionReceipt

    @classmethod
    def _create(
        cls,
        canonical: bytes,
        receipt: TradeExecutionReceipt,
    ) -> "TradeExecutionReceiptDelivery":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        object.__setattr__(value, "_receipt", receipt)
        return value

    @classmethod
    def from_dict(
        cls,
        document: dict[str, Any],
        *,
        order: TradeOrder | dict[str, Any],
    ) -> "TradeExecutionReceiptDelivery":
        try:
            verified_order = _verified_order(order)
            canonical = trade_canonical_json(copy.deepcopy(document))
            snapshot = parse_trade_json(canonical)
            receipt = _validate_delivery_static(
                snapshot,
                order=verified_order,
            )
            _verify_signature(
                snapshot,
                signer_field="sender_did",
                domain=_DELIVERY_DOMAIN,
                error_type=TradeExecutionReceiptDeliveryRejected,
            )
        except (
            TradeCanonicalJSONError,
            TradeExecutionReceiptRejected,
            TradeOrderRejected,
            TradeProofError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            if isinstance(exc, TradeExecutionReceiptDeliveryRejected):
                raise
            raise TradeExecutionReceiptDeliveryRejected(str(exc)) from exc
        return cls._create(canonical, receipt)

    @classmethod
    def from_json(
        cls,
        raw: bytes | str,
        *,
        order: TradeOrder | dict[str, Any],
    ) -> "TradeExecutionReceiptDelivery":
        try:
            return cls.from_dict(parse_trade_json(raw), order=order)
        except TradeCanonicalJSONError as exc:
            raise TradeExecutionReceiptDeliveryRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    @property
    def receipt(self) -> TradeExecutionReceipt:
        return self._receipt

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


def _validate_acknowledgement_static(document: dict[str, Any]) -> None:
    error_type = TradeExecutionReceiptAcknowledgementRejected
    if (
        not isinstance(document, dict)
        or set(document) != _ACKNOWLEDGEMENT_FIELDS
    ):
        _raise(error_type, "acknowledgement has missing or unknown fields")
    if document["kind"] != EXECUTION_RECEIPT_ACKNOWLEDGEMENT_KIND:
        _raise(error_type, "wrong execution Receipt acknowledgement kind")
    if (
        document["protocol_version"]
        != EXECUTION_RECEIPT_ACKNOWLEDGEMENT_PROTOCOL_VERSION
    ):
        _raise(error_type, "unsupported acknowledgement protocol_version")
    for field in ("order_digest", "receipt_digest", "delivery_digest"):
        if (
            not isinstance(document[field], str)
            or _DIGEST.fullmatch(document[field]) is None
        ):
            _raise(error_type, f"{field} must be a lowercase sha256 digest")
    for field in ("sender_did", "receiver_did"):
        if (
            not isinstance(document[field], str)
            or not is_did_key(document[field])
        ):
            _raise(error_type, f"{field} must be an Ed25519 did:key")
    if document["sender_did"] == document["receiver_did"]:
        _raise(
            error_type,
            "acknowledgement parties must be different principals",
        )
    _timestamp_ns(
        document["received_at"],
        label="received_at",
        error_type=error_type,
    )
    if (
        not isinstance(document["audit_event_id"], str)
        or _EVENT_ID.fullmatch(document["audit_event_id"]) is None
    ):
        _raise(error_type, "audit_event_id is invalid")
    if document["status"] != "retained-verified":
        _raise(error_type, "acknowledgement status is invalid")
    _validate_proof(
        document["proof"],
        signer_did=document["receiver_did"],
        purpose=EXECUTION_RECEIPT_ACKNOWLEDGEMENT_PROOF_PURPOSE,
        created_at=document["received_at"],
        error_type=error_type,
    )


@dataclass(frozen=True, init=False)
class TradeExecutionReceiptAcknowledgement:
    """Receiver-signed claim that a Receipt reached CAS and Spine."""

    _canonical_bytes: bytes

    @classmethod
    def _create(
        cls,
        canonical: bytes,
    ) -> "TradeExecutionReceiptAcknowledgement":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        return value

    @classmethod
    def from_dict(
        cls,
        document: dict[str, Any],
    ) -> "TradeExecutionReceiptAcknowledgement":
        try:
            canonical = trade_canonical_json(copy.deepcopy(document))
            snapshot = parse_trade_json(canonical)
            _validate_acknowledgement_static(snapshot)
            _verify_signature(
                snapshot,
                signer_field="receiver_did",
                domain=_ACKNOWLEDGEMENT_DOMAIN,
                error_type=(
                    TradeExecutionReceiptAcknowledgementRejected
                ),
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
                TradeExecutionReceiptAcknowledgementRejected,
            ):
                raise
            raise TradeExecutionReceiptAcknowledgementRejected(
                str(exc)
            ) from exc
        return cls._create(canonical)

    @classmethod
    def from_json(
        cls,
        raw: bytes | str,
    ) -> "TradeExecutionReceiptAcknowledgement":
        try:
            return cls.from_dict(parse_trade_json(raw))
        except TradeCanonicalJSONError as exc:
            raise TradeExecutionReceiptAcknowledgementRejected(
                str(exc)
            ) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


def create_trade_execution_receipt_delivery(
    identity: Any,
    *,
    receipt: TradeExecutionReceipt,
    order: TradeOrder | dict[str, Any],
    created_at: str,
    not_after: str,
    nonce: str | None = None,
    now: datetime | None = None,
    max_ttl_seconds: float = (
        DEFAULT_MAX_EXECUTION_RECEIPT_DELIVERY_TTL_SECONDS
    ),
    clock_skew_seconds: float = (
        DEFAULT_EXECUTION_RECEIPT_DELIVERY_CLOCK_SKEW_SECONDS
    ),
) -> TradeExecutionReceiptDelivery:
    """Create a short-lived envelope signed by the Receipt executor."""

    error_type = TradeExecutionReceiptDeliveryRejected
    verified_order = _verified_order(order)
    verified_receipt = TradeExecutionReceipt.from_json(
        receipt.canonical_bytes,
        order=verified_order,
    )
    receipt_document = verified_receipt.to_dict()
    sender = identity.as_did()
    if sender != receipt_document["executor_did"]:
        _raise(error_type, "delivery signer does not match Receipt executor")
    recipient = _opposite_party(
        verified_order.to_dict(),
        sender,
        error_type=error_type,
    )
    nonce_value = nonce if nonce is not None else secrets.token_hex(16)
    document = {
        "kind": EXECUTION_RECEIPT_DELIVERY_KIND,
        "protocol_version": EXECUTION_RECEIPT_DELIVERY_PROTOCOL_VERSION,
        "delivery_id": (
            f"nth:trade:execution-receipt-delivery:{nonce_value}"
        ),
        "nonce": nonce_value,
        "order_digest": trade_order_digest(verified_order),
        "receipt_digest": execution_receipt_digest(
            verified_receipt,
            order=verified_order,
        ),
        "sender_did": sender,
        "recipient_did": recipient,
        "created_at": created_at,
        "not_after": not_after,
        "receipt": verified_receipt.to_dict(),
        "proof": {
            "type": EXECUTION_RECEIPT_TRANSPORT_PROOF_TYPE,
            "created": created_at,
            "verification_method": verification_method_for_did(sender),
            "proof_purpose": EXECUTION_RECEIPT_DELIVERY_PROOF_PURPOSE,
            "proof_value": "A" * 86,
        },
    }
    _validate_delivery_static(document, order=verified_order)
    current_ns = _now_ns(now, error_type=error_type)
    created_ns = _timestamp_ns(
        created_at,
        label="created_at",
        error_type=error_type,
    )
    expiry_ns = _timestamp_ns(
        not_after,
        label="not_after",
        error_type=error_type,
    )
    skew = _bounded_seconds(
        clock_skew_seconds,
        label="clock_skew_seconds",
        error_type=error_type,
    )
    ttl = _bounded_seconds(
        max_ttl_seconds,
        label="max_ttl_seconds",
        error_type=error_type,
    )
    if abs(current_ns - created_ns) > int(skew * 1_000_000_000):
        _raise(error_type, "created_at exceeds local clock-skew limit")
    if expiry_ns - created_ns > int(ttl * 1_000_000_000):
        _raise(error_type, "delivery lifetime exceeds max_ttl_seconds")
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(signed_document_input(_DELIVERY_DOMAIN, document))
    )
    return TradeExecutionReceiptDelivery.from_dict(
        document,
        order=verified_order,
    )


def verify_trade_execution_receipt_delivery(
    delivery: TradeExecutionReceiptDelivery | dict[str, Any],
    *,
    order: TradeOrder | dict[str, Any],
    recipient_did: str,
    at: datetime | None = None,
    max_ttl_seconds: float = (
        DEFAULT_MAX_EXECUTION_RECEIPT_DELIVERY_TTL_SECONDS
    ),
    clock_skew_seconds: float = (
        DEFAULT_EXECUTION_RECEIPT_DELIVERY_CLOCK_SKEW_SECONDS
    ),
) -> tuple[bool, str]:
    """Verify signature, destination, Order binding, and freshness."""

    error_type = TradeExecutionReceiptDeliveryRejected
    try:
        verified_order = _verified_order(order)
        verified = (
            TradeExecutionReceiptDelivery.from_json(
                delivery.canonical_bytes,
                order=verified_order,
            )
            if isinstance(delivery, TradeExecutionReceiptDelivery)
            else TradeExecutionReceiptDelivery.from_dict(
                delivery,
                order=verified_order,
            )
        )
        if not isinstance(recipient_did, str) or not is_did_key(
            recipient_did
        ):
            _raise(error_type, "expected recipient_did is invalid")
        document = verified.to_dict()
        if document["recipient_did"] != recipient_did:
            _raise(error_type, "delivery recipient does not match this node")
        current_ns = _now_ns(at, error_type=error_type)
        created_ns = _timestamp_ns(
            document["created_at"],
            label="created_at",
            error_type=error_type,
        )
        expiry_ns = _timestamp_ns(
            document["not_after"],
            label="not_after",
            error_type=error_type,
        )
        skew_ns = int(
            _bounded_seconds(
                clock_skew_seconds,
                label="clock_skew_seconds",
                error_type=error_type,
            )
            * 1_000_000_000
        )
        ttl_ns = int(
            _bounded_seconds(
                max_ttl_seconds,
                label="max_ttl_seconds",
                error_type=error_type,
            )
            * 1_000_000_000
        )
        if expiry_ns - created_ns > ttl_ns:
            _raise(error_type, "delivery lifetime exceeds max_ttl_seconds")
        if current_ns < created_ns - skew_ns:
            _raise(error_type, "delivery was created too far in the future")
        if current_ns > expiry_ns + skew_ns:
            _raise(error_type, "delivery has expired")
    except (
        TradeCanonicalJSONError,
        TradeExecutionReceiptDeliveryRejected,
        TradeExecutionReceiptRejected,
        TradeOrderRejected,
        TradeProofError,
        TypeError,
        ValueError,
        UnicodeError,
    ) as exc:
        return False, str(exc)
    return True, "ok"


def trade_execution_receipt_delivery_digest(
    delivery: TradeExecutionReceiptDelivery | dict[str, Any],
    *,
    order: TradeOrder | dict[str, Any],
) -> str:
    verified = (
        TradeExecutionReceiptDelivery.from_json(
            delivery.canonical_bytes,
            order=order,
        )
        if isinstance(delivery, TradeExecutionReceiptDelivery)
        else TradeExecutionReceiptDelivery.from_dict(delivery, order=order)
    )
    return "sha256:" + hashlib.sha256(verified.canonical_bytes).hexdigest()


def create_trade_execution_receipt_acknowledgement(
    identity: Any,
    *,
    delivery: TradeExecutionReceiptDelivery,
    order: TradeOrder | dict[str, Any],
    received_at: str,
    audit_event_id: str,
    clock_skew_seconds: float = (
        DEFAULT_EXECUTION_RECEIPT_DELIVERY_CLOCK_SKEW_SECONDS
    ),
) -> TradeExecutionReceiptAcknowledgement:
    """Acknowledge that the verified Receipt reached CAS and Spine."""

    error_type = TradeExecutionReceiptAcknowledgementRejected
    verified_order = _verified_order(order)
    verified_delivery = TradeExecutionReceiptDelivery.from_json(
        delivery.canonical_bytes,
        order=verified_order,
    )
    delivery_document = verified_delivery.to_dict()
    receiver = identity.as_did()
    if delivery_document["recipient_did"] != receiver:
        _raise(error_type, "delivery recipient does not match receiver")
    received_ns = _timestamp_ns(
        received_at,
        label="received_at",
        error_type=error_type,
    )
    created_ns = _timestamp_ns(
        delivery_document["created_at"],
        label="delivery.created_at",
        error_type=error_type,
    )
    expiry_ns = _timestamp_ns(
        delivery_document["not_after"],
        label="delivery.not_after",
        error_type=error_type,
    )
    skew_ns = int(
        _bounded_seconds(
            clock_skew_seconds,
            label="clock_skew_seconds",
            error_type=error_type,
        )
        * 1_000_000_000
    )
    if received_ns < created_ns or received_ns > expiry_ns + skew_ns:
        _raise(
            error_type,
            "received_at must be within signed delivery lifetime",
        )
    if (
        not isinstance(audit_event_id, str)
        or _EVENT_ID.fullmatch(audit_event_id) is None
    ):
        _raise(error_type, "audit_event_id is invalid")
    document = {
        "kind": EXECUTION_RECEIPT_ACKNOWLEDGEMENT_KIND,
        "protocol_version": (
            EXECUTION_RECEIPT_ACKNOWLEDGEMENT_PROTOCOL_VERSION
        ),
        "order_digest": delivery_document["order_digest"],
        "receipt_digest": delivery_document["receipt_digest"],
        "delivery_digest": trade_execution_receipt_delivery_digest(
            verified_delivery,
            order=verified_order,
        ),
        "sender_did": delivery_document["sender_did"],
        "receiver_did": receiver,
        "received_at": received_at,
        "audit_event_id": audit_event_id,
        "status": "retained-verified",
        "proof": {
            "type": EXECUTION_RECEIPT_TRANSPORT_PROOF_TYPE,
            "created": received_at,
            "verification_method": verification_method_for_did(receiver),
            "proof_purpose": (
                EXECUTION_RECEIPT_ACKNOWLEDGEMENT_PROOF_PURPOSE
            ),
            "proof_value": "A" * 86,
        },
    }
    _validate_acknowledgement_static(document)
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(
            signed_document_input(_ACKNOWLEDGEMENT_DOMAIN, document)
        )
    )
    return TradeExecutionReceiptAcknowledgement.from_dict(document)


def verify_trade_execution_receipt_acknowledgement(
    acknowledgement: (
        TradeExecutionReceiptAcknowledgement | dict[str, Any]
    ),
    *,
    delivery: TradeExecutionReceiptDelivery,
    order: TradeOrder | dict[str, Any],
    receiver_did: str,
    audit_event_id: str,
    at: datetime | None = None,
    clock_skew_seconds: float = (
        DEFAULT_EXECUTION_RECEIPT_DELIVERY_CLOCK_SKEW_SECONDS
    ),
) -> tuple[bool, str]:
    """Verify acknowledgement signature, delivery bindings, and chronology."""

    error_type = TradeExecutionReceiptAcknowledgementRejected
    try:
        verified_order = _verified_order(order)
        verified_delivery = TradeExecutionReceiptDelivery.from_json(
            delivery.canonical_bytes,
            order=verified_order,
        )
        verified_ack = (
            TradeExecutionReceiptAcknowledgement.from_json(
                acknowledgement.canonical_bytes
            )
            if isinstance(
                acknowledgement,
                TradeExecutionReceiptAcknowledgement,
            )
            else TradeExecutionReceiptAcknowledgement.from_dict(
                acknowledgement
            )
        )
        if not isinstance(receiver_did, str) or not is_did_key(
            receiver_did
        ):
            _raise(error_type, "expected receiver_did is invalid")
        if (
            not isinstance(audit_event_id, str)
            or _EVENT_ID.fullmatch(audit_event_id) is None
        ):
            _raise(error_type, "expected audit_event_id is invalid")
        delivery_document = verified_delivery.to_dict()
        ack_document = verified_ack.to_dict()
        expected = {
            "order_digest": delivery_document["order_digest"],
            "receipt_digest": delivery_document["receipt_digest"],
            "delivery_digest": trade_execution_receipt_delivery_digest(
                verified_delivery,
                order=verified_order,
            ),
            "sender_did": delivery_document["sender_did"],
            "receiver_did": receiver_did,
            "audit_event_id": audit_event_id,
        }
        for field, value in expected.items():
            if ack_document[field] != value:
                _raise(
                    error_type,
                    f"acknowledgement {field} does not match delivery",
                )
        if delivery_document["recipient_did"] != receiver_did:
            _raise(error_type, "delivery recipient does not match receiver")
        received_ns = _timestamp_ns(
            ack_document["received_at"],
            label="received_at",
            error_type=error_type,
        )
        created_ns = _timestamp_ns(
            delivery_document["created_at"],
            label="delivery.created_at",
            error_type=error_type,
        )
        expiry_ns = _timestamp_ns(
            delivery_document["not_after"],
            label="delivery.not_after",
            error_type=error_type,
        )
        skew_ns = int(
            _bounded_seconds(
                clock_skew_seconds,
                label="clock_skew_seconds",
                error_type=error_type,
            )
            * 1_000_000_000
        )
        if received_ns < created_ns or received_ns > expiry_ns + skew_ns:
            _raise(
                error_type,
                "received_at is outside signed delivery lifetime",
            )
        if at is not None:
            observed_ns = _now_ns(at, error_type=error_type)
            if received_ns > observed_ns + skew_ns:
                _raise(error_type, "received_at is too far in the future")
    except (
        TradeCanonicalJSONError,
        TradeExecutionReceiptAcknowledgementRejected,
        TradeExecutionReceiptDeliveryRejected,
        TradeExecutionReceiptRejected,
        TradeOrderRejected,
        TradeProofError,
        TypeError,
        ValueError,
        UnicodeError,
    ) as exc:
        return False, str(exc)
    return True, "ok"


def trade_execution_receipt_acknowledgement_digest(
    acknowledgement: (
        TradeExecutionReceiptAcknowledgement | dict[str, Any]
    ),
) -> str:
    verified = (
        TradeExecutionReceiptAcknowledgement.from_json(
            acknowledgement.canonical_bytes
        )
        if isinstance(
            acknowledgement,
            TradeExecutionReceiptAcknowledgement,
        )
        else TradeExecutionReceiptAcknowledgement.from_dict(acknowledgement)
    )
    return "sha256:" + hashlib.sha256(verified.canonical_bytes).hexdigest()


__all__ = [
    "DEFAULT_EXECUTION_RECEIPT_DELIVERY_CLOCK_SKEW_SECONDS",
    "DEFAULT_MAX_EXECUTION_RECEIPT_DELIVERY_TTL_SECONDS",
    "EXECUTION_RECEIPT_ACKNOWLEDGEMENT_KIND",
    "EXECUTION_RECEIPT_ACKNOWLEDGEMENT_PROOF_PURPOSE",
    "EXECUTION_RECEIPT_ACKNOWLEDGEMENT_PROTOCOL_VERSION",
    "EXECUTION_RECEIPT_DELIVERY_KIND",
    "EXECUTION_RECEIPT_DELIVERY_PROOF_PURPOSE",
    "EXECUTION_RECEIPT_DELIVERY_PROTOCOL_VERSION",
    "EXECUTION_RECEIPT_TRANSPORT_PROOF_TYPE",
    "TradeExecutionReceiptAcknowledgement",
    "TradeExecutionReceiptAcknowledgementRejected",
    "TradeExecutionReceiptDelivery",
    "TradeExecutionReceiptDeliveryRejected",
    "create_trade_execution_receipt_acknowledgement",
    "create_trade_execution_receipt_delivery",
    "trade_execution_receipt_acknowledgement_digest",
    "trade_execution_receipt_delivery_digest",
    "verify_trade_execution_receipt_acknowledgement",
    "verify_trade_execution_receipt_delivery",
]
