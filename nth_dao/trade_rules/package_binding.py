"""Signed binding between one immutable Trade Offer and Rule Package."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from nth_dao.identity import AgentIdentity
from nth_dao.trade_rules.canonical import (
    TradeCanonicalJSONError,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.signing import (
    TradeProofError,
    decode_canonical_ed25519_signature,
    encode_ed25519_signature,
    signed_document_input,
    verification_method_for_did,
    verify_ed25519_did_signature,
)

OFFER_PACKAGE_BINDING_KIND = "nth.dao.trade.offer-package-binding"
OFFER_PACKAGE_BINDING_PROTOCOL_VERSION = "1"
OFFER_PACKAGE_BINDING_PROOF_TYPE = "NthEd25519SignatureV1"
OFFER_PACKAGE_BINDING_PROOF_PURPOSE = "assertionMethod"
OFFER_PACKAGE_BINDING_SIGNING_DOMAIN = b"NTH-TRADE-OFFER-PACKAGE-BINDING-V1"

_FIELDS = frozenset({
    "kind",
    "protocol_version",
    "offer_digest",
    "package_digest",
    "publisher_did",
    "proof",
})
_PROOF_FIELDS = frozenset({
    "type",
    "created",
    "verification_method",
    "proof_purpose",
    "proof_value",
})
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_DID = re.compile(r"^did:key:z[1-9A-HJ-NP-Za-km-z]{8,240}$")
_TIMESTAMP = re.compile(
    r"^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.([0-9]{1,9}))?Z$"
)


class OfferPackageBindingRejected(ValueError):
    """A signed Offer-to-Package binding is malformed or unverifiable."""


def _exact_fields(value: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise OfferPackageBindingRejected(f"{label} must be an object")
    if set(value) != expected:
        raise OfferPackageBindingRejected(f"{label} fields are invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise OfferPackageBindingRejected(
            f"{label} must be a lowercase sha256 digest"
        )
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) > 35:
        raise OfferPackageBindingRejected(f"{label} must be a UTC RFC3339 timestamp")
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        raise OfferPackageBindingRejected(f"{label} must be a UTC RFC3339 timestamp")
    try:
        datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise OfferPackageBindingRejected(f"{label} is not a real timestamp") from exc
    return value


def _validate(document: Any) -> dict[str, Any]:
    value = _exact_fields(document, _FIELDS, "Offer Package binding")
    if value["kind"] != OFFER_PACKAGE_BINDING_KIND:
        raise OfferPackageBindingRejected("Offer Package binding kind is invalid")
    if value["protocol_version"] != OFFER_PACKAGE_BINDING_PROTOCOL_VERSION:
        raise OfferPackageBindingRejected("Offer Package binding version is unsupported")
    _digest(value["offer_digest"], "offer_digest")
    _digest(value["package_digest"], "package_digest")
    publisher_did = value["publisher_did"]
    if not isinstance(publisher_did, str) or _DID.fullmatch(publisher_did) is None:
        raise OfferPackageBindingRejected("publisher_did must be a did:key")
    proof = _exact_fields(value["proof"], _PROOF_FIELDS, "proof")
    if proof["type"] != OFFER_PACKAGE_BINDING_PROOF_TYPE:
        raise OfferPackageBindingRejected("Offer Package binding proof type is unsupported")
    if proof["proof_purpose"] != OFFER_PACKAGE_BINDING_PROOF_PURPOSE:
        raise OfferPackageBindingRejected("Offer Package binding proof purpose is unsupported")
    _timestamp(proof["created"], "proof.created")
    if proof["verification_method"] != verification_method_for_did(publisher_did):
        raise OfferPackageBindingRejected(
            "proof.verification_method does not match publisher_did"
        )
    try:
        decode_canonical_ed25519_signature(proof["proof_value"])
        trade_canonical_json(value)
    except (TradeProofError, TradeCanonicalJSONError) as exc:
        raise OfferPackageBindingRejected(str(exc)) from exc
    return value


def _snapshot(document: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    try:
        canonical = trade_canonical_json(document)
        snapshot = parse_trade_json(canonical)
    except TradeCanonicalJSONError as exc:
        raise OfferPackageBindingRejected(str(exc)) from exc
    _validate(snapshot)
    return canonical, snapshot


def _signing_input(snapshot: dict[str, Any]) -> bytes:
    try:
        return signed_document_input(OFFER_PACKAGE_BINDING_SIGNING_DOMAIN, snapshot)
    except TradeProofError as exc:
        raise OfferPackageBindingRejected(str(exc)) from exc


@dataclass(frozen=True, init=False)
class SignedOfferPackageBinding:
    """Immutable publisher assertion over exact Offer and Package digests."""

    _canonical: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "SignedOfferPackageBinding":
        instance = object.__new__(cls)
        object.__setattr__(instance, "_canonical", canonical)
        return instance

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> "SignedOfferPackageBinding":
        canonical, snapshot = _snapshot(document)
        ok, reason = verify_ed25519_did_signature(
            publisher_did=snapshot["publisher_did"],
            proof_value=snapshot["proof"]["proof_value"],
            signing_input=_signing_input(snapshot),
        )
        if not ok:
            raise OfferPackageBindingRejected(
                "crypto unavailable" if reason == "crypto unavailable"
                else "Offer Package binding signature invalid"
            )
        return cls._create(canonical)

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical)

    @property
    def offer_digest(self) -> str:
        return self.to_dict()["offer_digest"]

    @property
    def package_digest(self) -> str:
        return self.to_dict()["package_digest"]

    @property
    def publisher_did(self) -> str:
        return self.to_dict()["publisher_did"]


def sign_offer_package_binding(
    identity: AgentIdentity,
    *,
    offer_digest: str,
    package_digest: str,
    created: str | None = None,
) -> SignedOfferPackageBinding:
    """Sign an immutable Offer-to-Package assertion as the Offer publisher."""

    if not identity.can_sign:
        raise RuntimeError("identity has no signing key")
    document = {
        "kind": OFFER_PACKAGE_BINDING_KIND,
        "protocol_version": OFFER_PACKAGE_BINDING_PROTOCOL_VERSION,
        "offer_digest": _digest(offer_digest, "offer_digest"),
        "package_digest": _digest(package_digest, "package_digest"),
        "publisher_did": identity.as_did(),
        "proof": {
            "type": OFFER_PACKAGE_BINDING_PROOF_TYPE,
            "created": created or datetime.now(timezone.utc).replace(
                microsecond=0
            ).isoformat().replace("+00:00", "Z"),
            "verification_method": verification_method_for_did(identity.as_did()),
            "proof_purpose": OFFER_PACKAGE_BINDING_PROOF_PURPOSE,
            "proof_value": "A" * 86,
        },
    }
    _validate(document)
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(_signing_input(copy.deepcopy(document)))
    )
    return SignedOfferPackageBinding.from_dict(document)


def require_offer_package_binding(
    binding: SignedOfferPackageBinding | dict[str, Any],
    *,
    expected_offer_digest: str | None = None,
    expected_package_digest: str | None = None,
    expected_publisher_did: str | None = None,
) -> SignedOfferPackageBinding:
    """Verify a binding and enforce all caller-known immutable context."""

    verified = (
        binding
        if isinstance(binding, SignedOfferPackageBinding)
        else SignedOfferPackageBinding.from_dict(binding)
    )
    # Re-parse class instances too: callers must not gain trust from type alone.
    verified = SignedOfferPackageBinding.from_dict(verified.to_dict())
    if expected_offer_digest is not None and verified.offer_digest != _digest(
        expected_offer_digest, "expected_offer_digest"
    ):
        raise OfferPackageBindingRejected("binding is for another Offer")
    if expected_package_digest is not None and verified.package_digest != _digest(
        expected_package_digest, "expected_package_digest"
    ):
        raise OfferPackageBindingRejected("binding is for another Rule Package")
    if expected_publisher_did is not None and verified.publisher_did != expected_publisher_did:
        raise OfferPackageBindingRejected("binding signer is not the Offer publisher")
    return verified


__all__ = [
    "OFFER_PACKAGE_BINDING_KIND",
    "OFFER_PACKAGE_BINDING_PROTOCOL_VERSION",
    "OFFER_PACKAGE_BINDING_PROOF_PURPOSE",
    "OFFER_PACKAGE_BINDING_PROOF_TYPE",
    "OFFER_PACKAGE_BINDING_SIGNING_DOMAIN",
    "OfferPackageBindingRejected",
    "SignedOfferPackageBinding",
    "require_offer_package_binding",
    "sign_offer_package_binding",
]
