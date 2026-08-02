"""Signed point-to-point delivery envelope for Trade Proposals."""

from __future__ import annotations

import copy
import hashlib
import math
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from nth_dao.did_key import is_did_key
from nth_dao.trade_rules.agreement import (
    AGREEMENT_PROOF_TYPE,
    TradeAgreementRejected,
    TradeProposal,
    proposal_digest,
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

DELIVERY_KIND = "nth.dao.trade.proposal-delivery"
DELIVERY_PROTOCOL_VERSION = "1"
DELIVERY_PROOF_PURPOSE = "tradeProposalDelivery"
INTAKE_RECEIPT_KIND = "nth.dao.trade.proposal-intake-receipt"
INTAKE_RECEIPT_PROTOCOL_VERSION = "1"
INTAKE_RECEIPT_PROOF_PURPOSE = "tradeProposalIntakeReceipt"
DEFAULT_MAX_DELIVERY_TTL_SECONDS = 10 * 60
DEFAULT_DELIVERY_CLOCK_SKEW_SECONDS = 5 * 60

_DELIVERY_DOMAIN = b"nth-dao/trade-proposal-delivery/v1"
_INTAKE_RECEIPT_DOMAIN = b"nth-dao/trade-proposal-intake-receipt/v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_NONCE = re.compile(r"^[0-9a-f]{32,128}$")
_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(\d{1,9}))?Z$"
)
_DELIVERY_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "delivery_id",
        "nonce",
        "proposal_digest",
        "sender_did",
        "recipient_did",
        "created_at",
        "not_after",
        "proposal",
        "proof",
    }
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
_INTAKE_RECEIPT_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "proposal_digest",
        "delivery_digest",
        "sender_did",
        "receiver_did",
        "received_at",
        "status",
        "proof",
    }
)


class TradeProposalDeliveryRejected(ValueError):
    """The delivery envelope is malformed, unbound, expired, or unsigned."""


class TradeProposalIntakeReceiptRejected(ValueError):
    """The receiver-signed durable intake receipt is invalid or unbound."""


def _reject(message: str) -> None:
    raise TradeProposalDeliveryRejected(message)


def _timestamp(value: Any, *, label: str) -> tuple[datetime, int]:
    if not isinstance(value, str) or len(value) > 35:
        _reject(f"{label} must be a UTC RFC3339 timestamp")
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        _reject(f"{label} must be a UTC RFC3339 timestamp")
    try:
        base = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise TradeProposalDeliveryRejected(
            f"{label} is not a real timestamp"
        ) from exc
    nanos = int((match.group(2) or "").ljust(9, "0") or "0")
    return base, nanos


def _timestamp_ns(value: str, *, label: str) -> int:
    base, nanos = _timestamp(value, label=label)
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


def _validate_static(document: dict[str, Any]) -> TradeProposal:
    if not isinstance(document, dict) or set(document) != _DELIVERY_FIELDS:
        _reject("delivery has missing or unknown fields")
    if document["kind"] != DELIVERY_KIND:
        _reject("wrong delivery kind")
    if document["protocol_version"] != DELIVERY_PROTOCOL_VERSION:
        _reject("unsupported delivery protocol_version")
    nonce = document["nonce"]
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        _reject("nonce must be 16 to 64 bytes of lowercase hex")
    if document["delivery_id"] != f"nth:trade:proposal-delivery:{nonce}":
        _reject("delivery_id does not match nonce")
    sender = document["sender_did"]
    recipient = document["recipient_did"]
    if not isinstance(sender, str) or not is_did_key(sender):
        _reject("sender_did must be an Ed25519 did:key")
    if not isinstance(recipient, str) or not is_did_key(recipient):
        _reject("recipient_did must be an Ed25519 did:key")
    if sender == recipient:
        _reject("sender and recipient must be different principals")
    claimed_digest = document["proposal_digest"]
    if not isinstance(claimed_digest, str) or _DIGEST.fullmatch(claimed_digest) is None:
        _reject("proposal_digest must be a lowercase sha256 digest")
    try:
        proposal = TradeProposal.from_dict(document["proposal"])
    except (TradeAgreementRejected, TypeError, ValueError) as exc:
        raise TradeProposalDeliveryRejected(
            f"embedded proposal is invalid: {exc}"
        ) from exc
    proposal_document = proposal.to_dict()
    if proposal_digest(proposal) != claimed_digest:
        _reject("proposal_digest does not match embedded proposal")
    if proposal_document["taker_did"] != sender:
        _reject("sender_did does not match Proposal taker")
    if proposal_document["maker_did"] != recipient:
        _reject("recipient_did does not match Proposal maker")
    created = _timestamp(document["created_at"], label="created_at")
    not_after = _timestamp(document["not_after"], label="not_after")
    if not_after <= created:
        _reject("not_after must be later than created_at")
    proof = document["proof"]
    if not isinstance(proof, dict) or set(proof) != _PROOF_FIELDS:
        _reject("proof has missing or unknown fields")
    if proof["type"] != AGREEMENT_PROOF_TYPE:
        _reject("proof type is invalid")
    if proof["verification_method"] != verification_method_for_did(sender):
        _reject("proof verification_method does not match sender")
    if proof["proof_purpose"] != DELIVERY_PROOF_PURPOSE:
        _reject("proof purpose is invalid")
    if not isinstance(proof["proof_value"], str):
        _reject("proof value is invalid")
    if _timestamp(proof["created"], label="proof.created") != created:
        _reject("proof.created must equal delivery created_at")
    proposal_created = _timestamp(
        proposal_document["created_at"],
        label="proposal.created_at",
    )
    proposal_not_after = _timestamp(
        proposal_document["not_after"],
        label="proposal.not_after",
    )
    if created < proposal_created:
        _reject("delivery cannot predate the embedded Proposal")
    if not_after > proposal_not_after:
        _reject("delivery cannot outlive the embedded Proposal")
    return proposal


def _verify_signature(document: dict[str, Any]) -> None:
    try:
        signing_input = signed_document_input(_DELIVERY_DOMAIN, document)
    except TradeProofError as exc:
        raise TradeProposalDeliveryRejected(str(exc)) from exc
    ok, reason = verify_ed25519_did_signature(
        publisher_did=document["sender_did"],
        proof_value=document["proof"]["proof_value"],
        signing_input=signing_input,
    )
    if not ok:
        _reject(reason)


@dataclass(frozen=True, init=False)
class TradeProposalDelivery:
    """Immutable canonical delivery whose embedded Proposal remains distinct."""

    _canonical_bytes: bytes
    _proposal: TradeProposal

    @classmethod
    def _create(
        cls,
        canonical: bytes,
        proposal: TradeProposal,
    ) -> "TradeProposalDelivery":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        object.__setattr__(value, "_proposal", proposal)
        return value

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> "TradeProposalDelivery":
        try:
            canonical = trade_canonical_json(copy.deepcopy(document))
            snapshot = parse_trade_json(canonical)
            proposal = _validate_static(snapshot)
            _verify_signature(snapshot)
        except (
            TradeCanonicalJSONError,
            TradeProofError,
            TypeError,
            ValueError,
            UnicodeError,
        ) as exc:
            if isinstance(exc, TradeProposalDeliveryRejected):
                raise
            raise TradeProposalDeliveryRejected(str(exc)) from exc
        return cls._create(canonical, proposal)

    @classmethod
    def from_json(cls, raw: bytes | str) -> "TradeProposalDelivery":
        try:
            return cls.from_dict(parse_trade_json(raw))
        except TradeCanonicalJSONError as exc:
            raise TradeProposalDeliveryRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)

    @property
    def proposal(self) -> TradeProposal:
        return self._proposal


def _validate_intake_receipt_static(document: dict[str, Any]) -> None:
    if not isinstance(document, dict) or set(document) != _INTAKE_RECEIPT_FIELDS:
        raise TradeProposalIntakeReceiptRejected(
            "intake receipt has missing or unknown fields"
        )
    if document["kind"] != INTAKE_RECEIPT_KIND:
        raise TradeProposalIntakeReceiptRejected("wrong intake receipt kind")
    if document["protocol_version"] != INTAKE_RECEIPT_PROTOCOL_VERSION:
        raise TradeProposalIntakeReceiptRejected(
            "unsupported intake receipt protocol_version"
        )
    for field in ("proposal_digest", "delivery_digest"):
        value = document[field]
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            raise TradeProposalIntakeReceiptRejected(
                f"{field} must be a lowercase sha256 digest"
            )
    sender = document["sender_did"]
    receiver = document["receiver_did"]
    if not isinstance(sender, str) or not is_did_key(sender):
        raise TradeProposalIntakeReceiptRejected(
            "sender_did must be an Ed25519 did:key"
        )
    if not isinstance(receiver, str) or not is_did_key(receiver):
        raise TradeProposalIntakeReceiptRejected(
            "receiver_did must be an Ed25519 did:key"
        )
    if sender == receiver:
        raise TradeProposalIntakeReceiptRejected(
            "sender and receiver must be different principals"
        )
    if document["status"] != "retained-unaccepted":
        raise TradeProposalIntakeReceiptRejected(
            "intake receipt status is invalid"
        )
    received_at = _timestamp(document["received_at"], label="received_at")
    proof = document["proof"]
    if not isinstance(proof, dict) or set(proof) != _PROOF_FIELDS:
        raise TradeProposalIntakeReceiptRejected(
            "intake receipt proof has missing or unknown fields"
        )
    if proof["type"] != AGREEMENT_PROOF_TYPE:
        raise TradeProposalIntakeReceiptRejected(
            "intake receipt proof type is invalid"
        )
    if proof["verification_method"] != verification_method_for_did(receiver):
        raise TradeProposalIntakeReceiptRejected(
            "intake receipt verification_method does not match receiver"
        )
    if proof["proof_purpose"] != INTAKE_RECEIPT_PROOF_PURPOSE:
        raise TradeProposalIntakeReceiptRejected(
            "intake receipt proof purpose is invalid"
        )
    if not isinstance(proof["proof_value"], str):
        raise TradeProposalIntakeReceiptRejected(
            "intake receipt proof value is invalid"
        )
    if _timestamp(proof["created"], label="proof.created") != received_at:
        raise TradeProposalIntakeReceiptRejected(
            "proof.created must equal intake receipt received_at"
        )


def _verify_intake_receipt_signature(document: dict[str, Any]) -> None:
    try:
        signing_input = signed_document_input(_INTAKE_RECEIPT_DOMAIN, document)
    except TradeProofError as exc:
        raise TradeProposalIntakeReceiptRejected(str(exc)) from exc
    ok, reason = verify_ed25519_did_signature(
        publisher_did=document["receiver_did"],
        proof_value=document["proof"]["proof_value"],
        signing_input=signing_input,
    )
    if not ok:
        raise TradeProposalIntakeReceiptRejected(reason)


@dataclass(frozen=True, init=False)
class TradeProposalIntakeReceipt:
    """Receiver-signed proof that one verified Delivery reached local CAS."""

    _canonical_bytes: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "TradeProposalIntakeReceipt":
        value = object.__new__(cls)
        object.__setattr__(value, "_canonical_bytes", bytes(canonical))
        return value

    @classmethod
    def from_dict(
        cls, document: dict[str, Any]
    ) -> "TradeProposalIntakeReceipt":
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
            if isinstance(exc, TradeProposalIntakeReceiptRejected):
                raise
            raise TradeProposalIntakeReceiptRejected(str(exc)) from exc
        return cls._create(canonical)

    @classmethod
    def from_json(cls, raw: bytes | str) -> "TradeProposalIntakeReceipt":
        try:
            return cls.from_dict(parse_trade_json(raw))
        except TradeCanonicalJSONError as exc:
            raise TradeProposalIntakeReceiptRejected(str(exc)) from exc

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical_bytes)


def create_trade_proposal_delivery(
    identity: Any,
    *,
    proposal: TradeProposal,
    created_at: str,
    not_after: str,
    nonce: str | None = None,
    now: datetime | None = None,
    max_ttl_seconds: float = DEFAULT_MAX_DELIVERY_TTL_SECONDS,
    clock_skew_seconds: float = DEFAULT_DELIVERY_CLOCK_SKEW_SECONDS,
) -> TradeProposalDelivery:
    """Create a destination-bound short-lived transport envelope."""

    verified_proposal = TradeProposal.from_json(proposal.canonical_bytes)
    proposal_document = verified_proposal.to_dict()
    sender = identity.as_did()
    if sender != proposal_document["taker_did"]:
        _reject("delivery signer does not match Proposal taker")
    nonce_value = nonce if nonce is not None else secrets.token_hex(16)
    body = {
        "kind": DELIVERY_KIND,
        "protocol_version": DELIVERY_PROTOCOL_VERSION,
        "delivery_id": f"nth:trade:proposal-delivery:{nonce_value}",
        "nonce": nonce_value,
        "proposal_digest": proposal_digest(verified_proposal),
        "sender_did": sender,
        "recipient_did": proposal_document["maker_did"],
        "created_at": created_at,
        "not_after": not_after,
        "proposal": proposal_document,
    }
    document = copy.deepcopy(body)
    document["proof"] = {
        "type": AGREEMENT_PROOF_TYPE,
        "created": created_at,
        "verification_method": verification_method_for_did(sender),
        "proof_purpose": DELIVERY_PROOF_PURPOSE,
        "proof_value": "A" * 86,
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
        _reject("delivery lifetime exceeds max_ttl_seconds")
    signing_input = signed_document_input(_DELIVERY_DOMAIN, document)
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(signing_input)
    )
    return TradeProposalDelivery.from_dict(document)


def verify_trade_proposal_delivery(
    delivery: TradeProposalDelivery | dict[str, Any],
    *,
    recipient_did: str,
    at: datetime | None = None,
    max_ttl_seconds: float = DEFAULT_MAX_DELIVERY_TTL_SECONDS,
    clock_skew_seconds: float = DEFAULT_DELIVERY_CLOCK_SKEW_SECONDS,
) -> tuple[bool, str]:
    """Verify static proof, destination, freshness, and hard TTL."""

    try:
        verified = (
            delivery
            if isinstance(delivery, TradeProposalDelivery)
            else TradeProposalDelivery.from_dict(delivery)
        )
        if not isinstance(recipient_did, str) or not is_did_key(recipient_did):
            _reject("expected recipient_did must be an Ed25519 did:key")
        document = verified.to_dict()
        if document["recipient_did"] != recipient_did:
            _reject("delivery is addressed to another recipient")
        current_ns = _datetime_ns(_utc_now(at))
        created_ns = _timestamp_ns(document["created_at"], label="created_at")
        expiry_ns = _timestamp_ns(document["not_after"], label="not_after")
        skew = _bounded_seconds(
            clock_skew_seconds,
            label="clock_skew_seconds",
        )
        ttl = _bounded_seconds(max_ttl_seconds, label="max_ttl_seconds")
        if created_ns - current_ns > int(skew * 1_000_000_000):
            _reject("delivery was created too far in the future")
        if current_ns >= expiry_ns:
            _reject("delivery has expired")
        if expiry_ns - created_ns > int(ttl * 1_000_000_000):
            _reject("delivery lifetime exceeds max_ttl_seconds")
    except (
        TradeAgreementRejected,
        TradeProposalDeliveryRejected,
        TradeCanonicalJSONError,
        TradeProofError,
        TypeError,
        ValueError,
        UnicodeError,
    ) as exc:
        return False, str(exc)
    return True, "ok"


def trade_proposal_delivery_digest(
    delivery: TradeProposalDelivery | dict[str, Any],
) -> str:
    verified = (
        delivery
        if isinstance(delivery, TradeProposalDelivery)
        else TradeProposalDelivery.from_dict(delivery)
    )
    return "sha256:" + hashlib.sha256(verified.canonical_bytes).hexdigest()


def create_trade_proposal_intake_receipt(
    identity: Any,
    *,
    delivery: TradeProposalDelivery,
    received_at: str,
) -> TradeProposalIntakeReceipt:
    """Sign the local commit marker for one already-verified Delivery."""

    verified_delivery = delivery
    delivery_document = verified_delivery.to_dict()
    receiver = identity.as_did()
    if receiver != delivery_document["recipient_did"]:
        raise TradeProposalIntakeReceiptRejected(
            "intake signer does not match Delivery recipient"
        )
    body = {
        "kind": INTAKE_RECEIPT_KIND,
        "protocol_version": INTAKE_RECEIPT_PROTOCOL_VERSION,
        "proposal_digest": delivery_document["proposal_digest"],
        "delivery_digest": trade_proposal_delivery_digest(verified_delivery),
        "sender_did": delivery_document["sender_did"],
        "receiver_did": receiver,
        "received_at": received_at,
        "status": "retained-unaccepted",
    }
    document = copy.deepcopy(body)
    document["proof"] = {
        "type": AGREEMENT_PROOF_TYPE,
        "created": received_at,
        "verification_method": verification_method_for_did(receiver),
        "proof_purpose": INTAKE_RECEIPT_PROOF_PURPOSE,
        "proof_value": "A" * 86,
    }
    _validate_intake_receipt_static(document)
    signing_input = signed_document_input(_INTAKE_RECEIPT_DOMAIN, document)
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(signing_input)
    )
    return TradeProposalIntakeReceipt.from_dict(document)


def verify_trade_proposal_intake_receipt(
    receipt: TradeProposalIntakeReceipt | dict[str, Any],
    *,
    delivery: TradeProposalDelivery,
    receiver_did: str,
) -> tuple[bool, str]:
    """Verify the local commit marker and bind it to the retained Delivery."""

    try:
        verified_receipt = (
            receipt
            if isinstance(receipt, TradeProposalIntakeReceipt)
            else TradeProposalIntakeReceipt.from_dict(receipt)
        )
        verified_delivery = delivery
        if not isinstance(receiver_did, str) or not is_did_key(receiver_did):
            raise TradeProposalIntakeReceiptRejected(
                "expected receiver_did must be an Ed25519 did:key"
            )
        receipt_document = verified_receipt.to_dict()
        delivery_document = verified_delivery.to_dict()
        expected = {
            "proposal_digest": delivery_document["proposal_digest"],
            "delivery_digest": trade_proposal_delivery_digest(
                verified_delivery
            ),
            "sender_did": delivery_document["sender_did"],
            "receiver_did": receiver_did,
        }
        for field, value in expected.items():
            if receipt_document[field] != value:
                raise TradeProposalIntakeReceiptRejected(
                    f"intake receipt {field} does not match Delivery"
                )
        if delivery_document["recipient_did"] != receiver_did:
            raise TradeProposalIntakeReceiptRejected(
                "Delivery recipient does not match intake receiver"
            )
    except (
        TradeProposalDeliveryRejected,
        TradeProposalIntakeReceiptRejected,
        TradeCanonicalJSONError,
        TradeProofError,
        TypeError,
        ValueError,
        UnicodeError,
    ) as exc:
        return False, str(exc)
    return True, "ok"


def trade_proposal_intake_receipt_digest(
    receipt: TradeProposalIntakeReceipt | dict[str, Any],
) -> str:
    verified = (
        receipt
        if isinstance(receipt, TradeProposalIntakeReceipt)
        else TradeProposalIntakeReceipt.from_dict(receipt)
    )
    return "sha256:" + hashlib.sha256(verified.canonical_bytes).hexdigest()


__all__ = [
    "DEFAULT_DELIVERY_CLOCK_SKEW_SECONDS",
    "DEFAULT_MAX_DELIVERY_TTL_SECONDS",
    "DELIVERY_KIND",
    "DELIVERY_PROTOCOL_VERSION",
    "INTAKE_RECEIPT_KIND",
    "INTAKE_RECEIPT_PROTOCOL_VERSION",
    "TradeProposalDelivery",
    "TradeProposalDeliveryRejected",
    "TradeProposalIntakeReceipt",
    "TradeProposalIntakeReceiptRejected",
    "create_trade_proposal_intake_receipt",
    "create_trade_proposal_delivery",
    "trade_proposal_delivery_digest",
    "trade_proposal_intake_receipt_digest",
    "verify_trade_proposal_delivery",
    "verify_trade_proposal_intake_receipt",
]
