"""Shared fail-closed primitives for signed bilateral trade transport."""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any, NoReturn

from nth_dao.trade_rules.signing import (
    TradeProofError,
    signed_document_input,
    verification_method_for_did,
    verify_ed25519_did_signature,
)

TRANSPORT_PROOF_FIELDS = frozenset(
    {
        "type",
        "created",
        "verification_method",
        "proof_purpose",
        "proof_value",
    }
)
_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(\d{1,9}))?Z$"
)


def reject(error_type: type[ValueError], message: str) -> NoReturn:
    raise error_type(message)


def timestamp_ns(
    value: Any,
    *,
    label: str,
    error_type: type[ValueError],
) -> int:
    if not isinstance(value, str) or len(value) > 35:
        reject(error_type, f"{label} must be a UTC RFC3339 timestamp")
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        reject(error_type, f"{label} must be a UTC RFC3339 timestamp")
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


def datetime_ns(
    value: datetime,
    *,
    error_type: type[ValueError],
) -> int:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        reject(error_type, "now must be timezone-aware")
    moment = value.astimezone(timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = moment - epoch
    return (
        (delta.days * 86_400 + delta.seconds) * 1_000_000_000
        + delta.microseconds * 1_000
    )


def now_ns(
    value: datetime | None,
    *,
    error_type: type[ValueError],
) -> int:
    return datetime_ns(
        value or datetime.now(timezone.utc),
        error_type=error_type,
    )


def bounded_seconds(
    value: Any,
    *,
    label: str,
    error_type: type[ValueError],
    maximum: float | None = None,
) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
        or (maximum is not None and value > maximum)
    ):
        maximum_message = (
            f" not greater than {maximum:g}" if maximum is not None else ""
        )
        reject(
            error_type,
            f"{label} must be a finite non-negative number{maximum_message}",
        )
    return float(value)


def within_clock_skewed_lifetime(
    received_ns: int,
    *,
    created_ns: int,
    expiry_ns: int,
    skew_ns: int,
) -> bool:
    """Return whether a receiver timestamp fits a signed lifetime.

    Sender and receiver clocks may differ in either direction, so the same
    bounded skew must be applied to both the creation and expiry edges.
    """

    return (
        received_ns + skew_ns >= created_ns
        and received_ns <= expiry_ns + skew_ns
    )


def opposite_party(
    order_document: dict[str, Any],
    sender_did: str,
    *,
    error_type: type[ValueError],
) -> str:
    if sender_did == order_document["maker_did"]:
        return order_document["taker_did"]
    if sender_did == order_document["taker_did"]:
        return order_document["maker_did"]
    reject(error_type, "sender_did is not a party to the signed Order")


def validate_transport_proof(
    proof: Any,
    *,
    signer_did: str,
    purpose: str,
    created_at: str,
    proof_type: str,
    error_type: type[ValueError],
) -> None:
    if not isinstance(proof, dict) or set(proof) != TRANSPORT_PROOF_FIELDS:
        reject(error_type, "proof has missing or unknown fields")
    if proof["type"] != proof_type:
        reject(error_type, "proof type is invalid")
    if proof["verification_method"] != verification_method_for_did(
        signer_did
    ):
        reject(
            error_type,
            "proof verification_method does not match signer",
        )
    if proof["proof_purpose"] != purpose:
        reject(error_type, "proof purpose is invalid")
    if not isinstance(proof["proof_value"], str):
        reject(error_type, "proof value is invalid")
    proof_ns = timestamp_ns(
        proof["created"],
        label="proof.created",
        error_type=error_type,
    )
    created_ns = timestamp_ns(
        created_at,
        label="created_at",
        error_type=error_type,
    )
    if proof_ns != created_ns:
        reject(error_type, "proof.created must equal created_at")


def verify_transport_signature(
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
        reject(error_type, reason)


__all__ = [
    "TRANSPORT_PROOF_FIELDS",
    "bounded_seconds",
    "datetime_ns",
    "now_ns",
    "opposite_party",
    "reject",
    "timestamp_ns",
    "validate_transport_proof",
    "verify_transport_signature",
    "within_clock_skewed_lifetime",
]
