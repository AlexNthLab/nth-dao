"""Signed, content-addressed Trade Offer v2.

An offer describes what a publisher provides and what it requests. Money is
not privileged: fiat, tokens, products, services, and game assets are all
resource legs. Execution remains outside this module and requires separately
approved Trade Rule adapters.
"""

from __future__ import annotations

import copy
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from nth_dao.did_key import is_did_key
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

OFFER_KIND = "org.nthdao.trade.offer"
OFFER_PROTOCOL_VERSION = "2.0"
OFFER_PROOF_TYPE = "NthEd25519SignatureV1"
OFFER_PROOF_PURPOSE = "assertionMethod"
OFFER_SIGNING_DOMAIN = b"NTH-TRADE-OFFER-V2"

_TOP_LEVEL_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "offer_id",
        "revision",
        "previous_offer_digest",
        "state",
        "publisher_did",
        "title",
        "summary",
        "provides",
        "requests",
        "rule_refs",
        "published_at",
        "not_after",
        "extensions",
        "proof",
    }
)
_BODY_FIELDS = _TOP_LEVEL_FIELDS - {"proof"}
_PROOF_FIELDS = frozenset(
    {
        "type",
        "created",
        "verification_method",
        "proof_purpose",
        "proof_value",
    }
)
_LEG_FIELDS = frozenset(
    {
        "leg_id",
        "resource_type",
        "resource_id",
        "quantity",
        "unit",
        "descriptor_digest",
    }
)
_RULE_REF_FIELDS = frozenset({"rule_id", "digest"})

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_OFFER_ID = re.compile(
    rf"^{_LABEL}(?:\.{_LABEL})+"
    r"(?:/[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?)?$"
)
_RULE_ID = re.compile(
    rf"^{_LABEL}(?:\.{_LABEL})+"
    r"(?:/[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?)?$"
)
_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._:/-]*$")
_RESOURCE_ID = re.compile(
    r"^([a-z][a-z0-9+.-]{0,31}):"
    r"[A-Za-z0-9._~!$&'()*+,;=:@%/?#\[\]-]+$"
)
_UNSAFE_RESOURCE_SCHEMES = frozenset({"data", "file", "javascript", "vbscript"})
_OFFER_STATES = frozenset({"active", "withdrawn"})
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_QUANTITY = re.compile(
    r"^(?:[1-9][0-9]*(?:\.[0-9]*[1-9])?|0\.[0-9]*[1-9])$"
)
_EXTENSION_ID = re.compile(
    rf"^{_LABEL}(?:\.{_LABEL})+"
    r"/[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?$"
)
_TIMESTAMP = re.compile(
    r"^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.([0-9]{1,9}))?Z$"
)


class OfferRejected(ValueError):
    """Raised when a trade offer is malformed, untrusted, or unverifiable."""


def _reject(message: str) -> None:
    raise OfferRejected(message)


def _exact_fields(
    value: Any, expected: frozenset[str], label: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        _reject(f"{label} must be an object")
    if any(not isinstance(key, str) for key in value):
        _reject(f"{label} keys must be strings")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        _reject(f"{label} fields invalid; missing={missing}, unknown={unknown}")
    return value


def _bounded_string(
    value: Any,
    *,
    label: str,
    minimum: int = 1,
    maximum: int,
) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        _reject(f"{label} must be a string of length {minimum}..{maximum}")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise OfferRejected(f"{label} contains invalid Unicode") from exc
    return value


def _token(value: Any, *, label: str, maximum: int = 160) -> str:
    text = _bounded_string(value, label=label, maximum=maximum)
    if not _TOKEN.fullmatch(text):
        _reject(f"{label} is not a valid namespaced token")
    return text


def _digest(value: Any, *, label: str) -> str:
    text = _bounded_string(value, label=label, maximum=71)
    if not _DIGEST.fullmatch(text):
        _reject(f"{label} must be a lowercase sha256 digest")
    return text


def _timestamp_value(value: Any, *, label: str) -> tuple[datetime, int]:
    text = _bounded_string(value, label=label, maximum=35)
    match = _TIMESTAMP.fullmatch(text)
    if not match:
        _reject(f"{label} must be a UTC RFC3339 timestamp")
    try:
        base = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise OfferRejected(f"{label} is not a real timestamp") from exc
    nanos = int((match.group(2) or "").ljust(9, "0") or "0")
    return base, nanos


def _validate_leg(raw: Any, *, label: str) -> tuple[str, str]:
    leg = _exact_fields(raw, _LEG_FIELDS, label)
    leg_id = _token(leg["leg_id"], label=f"{label}.leg_id", maximum=64)
    resource_type = _token(
        leg["resource_type"], label=f"{label}.resource_type", maximum=160
    )
    resource_id = _bounded_string(
        leg["resource_id"], label=f"{label}.resource_id", maximum=512
    )
    resource_match = _RESOURCE_ID.fullmatch(resource_id)
    if resource_match is None:
        _reject(f"{label}.resource_id must be a canonical namespaced identifier")
    if resource_match.group(1) in _UNSAFE_RESOURCE_SCHEMES:
        _reject(f"{label}.resource_id uses a forbidden scheme")
    quantity = _bounded_string(
        leg["quantity"], label=f"{label}.quantity", maximum=80
    )
    if not _QUANTITY.fullmatch(quantity):
        _reject(f"{label}.quantity must be a canonical positive decimal string")
    if len(quantity.replace(".", "")) > 78:
        _reject(f"{label}.quantity exceeds the precision limit")
    if "." in quantity and len(quantity.rsplit(".", 1)[1]) > 30:
        _reject(f"{label}.quantity exceeds the scale limit")
    _token(leg["unit"], label=f"{label}.unit", maximum=80)
    _digest(leg["descriptor_digest"], label=f"{label}.descriptor_digest")
    return leg_id, resource_type


def _validate_legs(
    value: Any, *, label: str, minimum: int
) -> set[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= 32:
        _reject(f"{label} must contain {minimum}..32 entries")
    ids: list[str] = []
    for index, raw in enumerate(value):
        leg_id, _ = _validate_leg(raw, label=f"{label}[{index}]")
        ids.append(leg_id)
    if len(set(ids)) != len(ids):
        _reject(f"{label} contains duplicate leg_id values")
    if ids != sorted(ids):
        _reject(f"{label} must be sorted by leg_id")
    return set(ids)


def _validate_rule_refs(value: Any) -> None:
    if not isinstance(value, list) or len(value) > 32:
        _reject("rule_refs must be a list with at most 32 entries")
    order: list[tuple[str, str]] = []
    for index, raw in enumerate(value):
        item = _exact_fields(raw, _RULE_REF_FIELDS, f"rule_refs[{index}]")
        rule_id = _bounded_string(
            item["rule_id"], label=f"rule_refs[{index}].rule_id", maximum=160
        )
        if not _RULE_ID.fullmatch(rule_id):
            _reject(f"rule_refs[{index}].rule_id is invalid")
        order.append(
            (rule_id, _digest(item["digest"], label=f"rule_refs[{index}].digest"))
        )
    if len(set(order)) != len(order):
        _reject("rule_refs contains duplicate entries")
    if order != sorted(order):
        _reject("rule_refs must be sorted by rule_id and digest")


def _validate_common(document: dict[str, Any]) -> None:
    if document["kind"] != OFFER_KIND:
        _reject("wrong offer kind")
    if document["protocol_version"] != OFFER_PROTOCOL_VERSION:
        _reject("unsupported offer protocol_version")
    offer_id = _bounded_string(
        document["offer_id"], label="offer_id", minimum=3, maximum=256
    )
    if not _OFFER_ID.fullmatch(offer_id):
        _reject("offer_id is invalid")
    revision = document["revision"]
    if (
        isinstance(revision, bool)
        or not isinstance(revision, int)
        or not 1 <= revision <= 2_147_483_647
    ):
        _reject("revision must be an integer in the range 1..2147483647")
    previous_digest = document["previous_offer_digest"]
    if revision == 1:
        if previous_digest is not None:
            _reject("revision 1 must not declare previous_offer_digest")
    else:
        _digest(previous_digest, label="previous_offer_digest")
    if document["state"] not in _OFFER_STATES:
        _reject("state must be active or withdrawn")
    if document["state"] == "withdrawn" and revision == 1:
        _reject("an initial offer cannot be withdrawn")
    publisher_did = _bounded_string(
        document["publisher_did"], label="publisher_did", maximum=256
    )
    if not is_did_key(publisher_did):
        _reject("publisher_did must be an Ed25519 did:key")
    _bounded_string(document["title"], label="title", maximum=160)
    summary = _bounded_string(
        document["summary"], label="summary", minimum=0, maximum=2_000
    )
    if len(summary.encode("utf-8")) > 8_000:
        _reject("summary exceeds UTF-8 byte limit")

    provides_ids = _validate_legs(document["provides"], label="provides", minimum=1)
    requests_ids = _validate_legs(document["requests"], label="requests", minimum=0)
    if provides_ids & requests_ids:
        _reject("leg_id values must be unique across provides and requests")
    _validate_rule_refs(document["rule_refs"])

    published = _timestamp_value(document["published_at"], label="published_at")
    not_after_raw = document["not_after"]
    if not_after_raw is not None:
        not_after = _timestamp_value(not_after_raw, label="not_after")
        if not_after <= published:
            _reject("not_after must be later than published_at")

    extensions = document["extensions"]
    if not isinstance(extensions, dict) or len(extensions) > 32:
        _reject("extensions must be an object with at most 32 entries")
    for extension_id, extension_value in extensions.items():
        if not isinstance(extension_id, str) or not _EXTENSION_ID.fullmatch(
            extension_id
        ):
            _reject(f"invalid extension id: {extension_id!r}")
        if not isinstance(extension_value, dict):
            _reject(f"extension {extension_id!r} must be an object")


def _validate_body(body: Any) -> dict[str, Any]:
    document = _exact_fields(body, _BODY_FIELDS, "offer body")
    _validate_common(document)
    try:
        trade_canonical_json(document)
    except TradeCanonicalJSONError as exc:
        raise OfferRejected(str(exc)) from exc
    return document


def _validate_complete(document: Any) -> dict[str, Any]:
    value = _exact_fields(document, _TOP_LEVEL_FIELDS, "offer")
    _validate_common(value)
    proof = _exact_fields(value["proof"], _PROOF_FIELDS, "proof")
    if proof["type"] != OFFER_PROOF_TYPE:
        _reject("unsupported proof.type")
    if proof["proof_purpose"] != OFFER_PROOF_PURPOSE:
        _reject("unsupported proof.proof_purpose")
    proof_created = _timestamp_value(proof["created"], label="proof.created")
    published = _timestamp_value(value["published_at"], label="published_at")
    if proof_created < published:
        _reject("proof.created must not be before published_at")
    if value["not_after"] is not None:
        not_after = _timestamp_value(value["not_after"], label="not_after")
        if not_after <= proof_created:
            _reject("not_after must be later than proof.created")
    expected_method = verification_method_for_did(value["publisher_did"])
    if proof["verification_method"] != expected_method:
        _reject("proof.verification_method does not match publisher_did")
    proof_value = _bounded_string(
        proof["proof_value"], label="proof.proof_value", minimum=86, maximum=86
    )
    try:
        decode_canonical_ed25519_signature(proof_value)
    except TradeProofError as exc:
        raise OfferRejected(str(exc)) from exc
    try:
        trade_canonical_json(value)
    except TradeCanonicalJSONError as exc:
        raise OfferRejected(str(exc)) from exc
    return value


def _complete_snapshot(document: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    try:
        canonical = trade_canonical_json(document)
    except TradeCanonicalJSONError as exc:
        raise OfferRejected(str(exc)) from exc
    snapshot = parse_trade_json(canonical)
    _validate_complete(snapshot)
    return canonical, snapshot


def _signing_input_from_snapshot(snapshot: dict[str, Any]) -> bytes:
    try:
        return signed_document_input(OFFER_SIGNING_DOMAIN, snapshot)
    except TradeProofError as exc:
        raise OfferRejected(str(exc)) from exc


def offer_signing_input(document: dict[str, Any]) -> bytes:
    """Return the domain-separated bytes covered by an offer signature."""
    _, snapshot = _complete_snapshot(document)
    return _signing_input_from_snapshot(snapshot)


def _verify_snapshot_signature(snapshot: dict[str, Any]) -> tuple[bool, str]:
    try:
        signing_input = _signing_input_from_snapshot(snapshot)
    except (OfferRejected, TradeCanonicalJSONError, TypeError, ValueError):
        return False, "offer signature invalid"
    ok, reason = verify_ed25519_did_signature(
        publisher_did=snapshot["publisher_did"],
        proof_value=snapshot["proof"]["proof_value"],
        signing_input=signing_input,
    )
    return (ok, "ok" if ok else ("crypto unavailable" if reason == "crypto unavailable"
                                 else "offer signature invalid"))


def _verify_signature(document: dict[str, Any]) -> tuple[bool, str]:
    try:
        _, snapshot = _complete_snapshot(document)
    except (
        OfferRejected,
        TradeCanonicalJSONError,
        TypeError,
        ValueError,
        UnicodeError,
    ):
        return False, "offer signature invalid"
    return _verify_snapshot_signature(snapshot)


@dataclass(frozen=True, init=False)
class InspectedTradeOffer:
    """Immutable canonical offer without an implied trust decision."""

    _canonical: bytes

    @classmethod
    def _create(cls, canonical: bytes) -> "InspectedTradeOffer":
        instance = object.__new__(cls)
        object.__setattr__(instance, "_canonical", canonical)
        return instance

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> "InspectedTradeOffer":
        canonical, _ = _complete_snapshot(document)
        return cls._create(canonical)

    @classmethod
    def from_json(cls, raw: bytes | str) -> "InspectedTradeOffer":
        try:
            document = parse_trade_json(raw)
        except TradeCanonicalJSONError as exc:
            raise OfferRejected(str(exc)) from exc
        return cls.from_dict(document)

    def to_dict(self) -> dict[str, Any]:
        return parse_trade_json(self._canonical)

    @property
    def canonical_bytes(self) -> bytes:
        return self._canonical

    @property
    def verified(self) -> bool:
        """Return publisher-signature integrity, not activity or local trust."""
        return _verify_signature(self.to_dict())[0]

    @property
    def offer_id(self) -> str:
        return self.to_dict()["offer_id"]

    @property
    def publisher_did(self) -> str:
        return self.to_dict()["publisher_did"]


@dataclass(frozen=True, init=False)
class TradeOffer(InspectedTradeOffer):
    """Immutable offer verified against its publisher did:key."""

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> "TradeOffer":
        canonical, snapshot = _complete_snapshot(document)
        ok, reason = _verify_snapshot_signature(snapshot)
        if not ok:
            raise OfferRejected(reason)
        return cls._create(canonical)

    @classmethod
    def from_json(cls, raw: bytes | str) -> "TradeOffer":
        try:
            document = parse_trade_json(raw)
        except TradeCanonicalJSONError as exc:
            raise OfferRejected(str(exc)) from exc
        return cls.from_dict(document)


def offer_body(
    *,
    offer_id: str,
    revision: int = 1,
    previous_offer_digest: str | None = None,
    state: str = "active",
    publisher_did: str,
    title: str,
    summary: str,
    provides: Iterable[dict[str, Any]],
    requests: Iterable[dict[str, Any]] = (),
    rule_refs: Iterable[dict[str, Any]] = (),
    published_at: str,
    not_after: str | None = None,
    extensions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build and validate a proof-free offer body."""
    provide_values = [copy.deepcopy(value) for value in provides]
    request_values = [copy.deepcopy(value) for value in requests]
    rule_values = [copy.deepcopy(value) for value in rule_refs]
    for values in (provide_values, request_values):
        if all(isinstance(item, dict) and isinstance(item.get("leg_id"), str)
               for item in values):
            values.sort(key=lambda item: item["leg_id"])
    if all(
        isinstance(item, dict)
        and isinstance(item.get("rule_id"), str)
        and isinstance(item.get("digest"), str)
        for item in rule_values
    ):
        rule_values.sort(key=lambda item: (item["rule_id"], item["digest"]))
    body = {
        "kind": OFFER_KIND,
        "protocol_version": OFFER_PROTOCOL_VERSION,
        "offer_id": offer_id,
        "revision": revision,
        "previous_offer_digest": previous_offer_digest,
        "state": state,
        "publisher_did": publisher_did,
        "title": title,
        "summary": summary,
        "provides": provide_values,
        "requests": request_values,
        "rule_refs": rule_values,
        "published_at": published_at,
        "not_after": not_after,
        "extensions": copy.deepcopy(extensions or {}),
    }
    _validate_body(body)
    return body


def sign_offer(
    identity: AgentIdentity,
    body: dict[str, Any],
    *,
    created: str | None = None,
) -> TradeOffer:
    """Validate and sign one proof-free trade offer."""
    if not identity.can_sign:
        raise RuntimeError("identity has no signing key")
    document = copy.deepcopy(body)
    _validate_body(document)
    if document["publisher_did"] != identity.as_did():
        raise OfferRejected("signer does not match publisher_did")
    proof_created = created or datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
    did = identity.as_did()
    document["proof"] = {
        "type": OFFER_PROOF_TYPE,
        "created": proof_created,
        "verification_method": verification_method_for_did(did),
        "proof_purpose": OFFER_PROOF_PURPOSE,
        "proof_value": "A" * 86,
    }
    _validate_complete(document)
    document["proof"]["proof_value"] = encode_ed25519_signature(
        identity.sign(_signing_input_from_snapshot(document))
    )
    return TradeOffer.from_dict(document)


def verify_offer(
    offer: InspectedTradeOffer | dict[str, Any],
) -> tuple[bool, str]:
    try:
        document = offer.to_dict() if isinstance(offer, InspectedTradeOffer) else offer
        _validate_complete(document)
    except (
        OfferRejected,
        TradeCanonicalJSONError,
        TypeError,
        ValueError,
        UnicodeError,
    ) as exc:
        return False, str(exc)
    return _verify_signature(document)


verify_offer_integrity = verify_offer


def offer_digest(offer: TradeOffer | dict[str, Any]) -> str:
    if isinstance(offer, TradeOffer):
        document = offer.to_dict()
        ok, reason = _verify_signature(document)
        if not ok:
            raise OfferRejected(reason)
        canonical = offer.canonical_bytes
    elif isinstance(offer, InspectedTradeOffer):
        raise OfferRejected("offer_digest requires a cryptographically verified offer")
    else:
        canonical = TradeOffer.from_dict(offer).canonical_bytes
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def offer_inspection_digest(
    offer: InspectedTradeOffer | dict[str, Any],
) -> str:
    """Hash a structurally valid offer without granting publisher trust."""
    if isinstance(offer, InspectedTradeOffer):
        canonical, _ = _complete_snapshot(offer.to_dict())
    else:
        canonical = InspectedTradeOffer.from_dict(offer).canonical_bytes
    return "unverified-sha256:" + hashlib.sha256(canonical).hexdigest()


def _as_verified_document(
    offer: TradeOffer | dict[str, Any],
) -> tuple[dict[str, Any] | None, str]:
    try:
        verified = offer if isinstance(offer, TradeOffer) else TradeOffer.from_dict(offer)
        return verified.to_dict(), "ok"
    except (OfferRejected, TradeCanonicalJSONError, TypeError, ValueError) as exc:
        return None, str(exc)


def evaluate_offer(
    offer: TradeOffer | dict[str, Any],
    *,
    at: datetime | None = None,
) -> tuple[bool, str]:
    """Evaluate cryptographic integrity plus signed lifecycle/time state."""
    document, reason = _as_verified_document(offer)
    if document is None:
        return False, f"invalid: {reason}"
    moment = at or datetime.now(timezone.utc)
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("at must be timezone-aware")
    moment = moment.astimezone(timezone.utc)
    moment_value = (moment.replace(microsecond=0), moment.microsecond * 1_000)
    published = _timestamp_value(document["published_at"], label="published_at")
    if moment_value < published:
        return False, "not_yet_active"
    if document["not_after"] is not None:
        not_after = _timestamp_value(document["not_after"], label="not_after")
        if moment_value >= not_after:
            return False, "expired"
    if document["state"] == "withdrawn":
        return False, "withdrawn"
    return True, "active"


def verify_offer_successor(
    previous: TradeOffer | dict[str, Any],
    successor: TradeOffer | dict[str, Any],
) -> tuple[bool, str]:
    """Verify one append-only revision edge without consulting a registry."""
    previous_document, previous_reason = _as_verified_document(previous)
    if previous_document is None:
        return False, f"previous_invalid: {previous_reason}"
    successor_document, successor_reason = _as_verified_document(successor)
    if successor_document is None:
        return False, f"successor_invalid: {successor_reason}"
    if previous_document["publisher_did"] != successor_document["publisher_did"]:
        return False, "publisher_changed"
    if previous_document["offer_id"] != successor_document["offer_id"]:
        return False, "offer_id_changed"
    if previous_document["state"] == "withdrawn":
        return False, "withdrawal_is_terminal"
    if successor_document["revision"] != previous_document["revision"] + 1:
        return False, "revision_not_sequential"
    if successor_document["previous_offer_digest"] != offer_digest(previous):
        return False, "previous_digest_mismatch"
    previous_published = _timestamp_value(
        previous_document["published_at"], label="previous.published_at"
    )
    successor_published = _timestamp_value(
        successor_document["published_at"], label="successor.published_at"
    )
    if successor_published <= previous_published:
        return False, "published_at_not_increasing"
    return True, "ok"


__all__ = [
    "OFFER_KIND",
    "OFFER_PROOF_PURPOSE",
    "OFFER_PROOF_TYPE",
    "OFFER_PROTOCOL_VERSION",
    "OFFER_SIGNING_DOMAIN",
    "InspectedTradeOffer",
    "OfferRejected",
    "TradeOffer",
    "offer_body",
    "offer_digest",
    "offer_inspection_digest",
    "offer_signing_input",
    "evaluate_offer",
    "sign_offer",
    "verify_offer",
    "verify_offer_integrity",
    "verify_offer_successor",
]
