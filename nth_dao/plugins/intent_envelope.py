"""Host-owned, signed acceptance of a reviewed draft, never execution authority.

This is a protocol primitive, not a provider capability. Signature verification
does not consume a nonce, persist a revision, check delegation, or authorize a
business action. No resolver is given a signing key through this module.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any

from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import (
    DIDKeyError,
    decode_ed25519_did_key,
    encode_ed25519_did_key,
    is_prime_order_ed25519_point,
)
from nth_dao.identity import AgentIdentity, crypto_available

from .intent_resolver import (
    INTENT_RESOLVER_MAX_DRAFT_BYTES,
    INTENT_RESOLVER_MAX_SAFE_INTEGER,
    canonical_intent_draft,
    intent_resolver_request_digest,
)
from .schema import validate_instance


INTENT_ENVELOPE_FORMAT = "org.nth-dao.intent-envelope"
INTENT_ENVELOPE_SIGNING_DOMAIN = b"NTH-DAO:IntentEnvelope:v1\x00"
INTENT_ENVELOPE_MAX_TTL_MS = 86_400_000
INTENT_ENVELOPE_MAX_DOCUMENT_BYTES = 262_144
_ED25519_ORDER = 2**252 + 27742317777372353535851937790883648493
_HASH_RE = re.compile(r"sha256:[0-9a-f]{64}")
_NONCE_RE = re.compile(r"[0-9a-f]{32}")
_SIGNATURE_RE = re.compile(r"[0-9a-f]{128}")
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}")
_LEVELS = ("A0", "A1", "A2", "A3", "A4")
_REQUEST_FIELDS = (
    "attachments", "automation_ceiling", "locale", "request_id",
    "source_kind", "source_text",
)
_INTEGER_SCHEMA = {
    "type": "integer", "minimum": 0,
    "maximum": INTENT_RESOLVER_MAX_SAFE_INTEGER,
}
_BODY_PROPERTIES = {
    "format": {"type": "string", "enum": [INTENT_ENVELOPE_FORMAT]},
    "version": {"type": "string", "enum": ["1"]},
    "purpose": {"type": "string", "enum": ["draft-acceptance"]},
    "authority": {"type": "string", "enum": ["none"]},
    "commit_authority": {"type": "boolean", "enum": [False]},
    "executable": {"type": "boolean", "enum": [False]},
    "draft_json": {"type": "string", "maxLength": INTENT_RESOLVER_MAX_DRAFT_BYTES},
    "draft_digest": {"type": "string", "minLength": 71, "maxLength": 71},
    "signer_did": {"type": "string", "minLength": 1, "maxLength": 128},
    "audience_did": {"type": "string", "minLength": 1, "maxLength": 128},
    "scope_id": {"type": "string", "minLength": 1, "maxLength": 256},
    "solver_classes": {
        "type": "array", "minItems": 1, "maxItems": 16,
        "items": {"type": "string", "minLength": 1, "maxLength": 256},
    },
    "automation_ceiling": {"type": "string", "enum": ["A0", "A1"]},
    "issued_at_ms": deepcopy(_INTEGER_SCHEMA),
    "expires_at_ms": deepcopy(_INTEGER_SCHEMA),
    "nonce": {"type": "string", "minLength": 32, "maxLength": 32},
    "revision": {**_INTEGER_SCHEMA, "minimum": 1},
    "previous_digest": {"type": "string", "maxLength": 71},
}
INTENT_ENVELOPE_BODY_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": deepcopy(_BODY_PROPERTIES), "required": sorted(_BODY_PROPERTIES),
}
INTENT_ENVELOPE_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        **deepcopy(_BODY_PROPERTIES),
        "signature": {"type": "string", "minLength": 128, "maxLength": 128},
    },
    "required": sorted([*_BODY_PROPERTIES, "signature"]),
}


class IntentEnvelopeError(ValueError):
    """An intent acceptance document or its expected context is invalid."""


@dataclass(frozen=True)
class IntentAcceptanceContext:
    """Trusted Host expectations, never populated from the received envelope.

    The Host chooses an authorized direct signer and pins the current revision
    head. Delegation and key rotation must be resolved outside this v1 profile.
    A caller must still atomically consume the nonce and CAS the revision head
    before persisting acceptance or invoking a solver.
    """

    signer_did: str
    audience_did: str
    scope_id: str
    draft_digest: str
    revision: int
    previous_digest: str
    allowed_solver_classes: tuple[str, ...]
    automation_ceiling: str
    authorization_digest: str = ""

    def __post_init__(self) -> None:
        _did(self.signer_did, "expected signer_did")
        _did(self.audience_did, "expected audience_did")
        _identifier(self.scope_id, "expected scope_id")
        if not isinstance(self.draft_digest, str) or _HASH_RE.fullmatch(self.draft_digest) is None:
            raise IntentEnvelopeError("expected draft_digest must be a content hash")
        _lineage(self.revision, self.previous_digest)
        if type(self.allowed_solver_classes) is not tuple:
            raise IntentEnvelopeError("expected solver classes must be an immutable tuple")
        _solver_classes(list(self.allowed_solver_classes))
        if self.automation_ceiling not in ("A0", "A1"):
            raise IntentEnvelopeError("expected automation ceiling must be A0 or A1")
        if self.authorization_digest != "" and (
            not isinstance(self.authorization_digest, str)
            or _HASH_RE.fullmatch(self.authorization_digest) is None
        ):
            raise IntentEnvelopeError(
                "expected authorization_digest must be empty or a content hash"
            )


def _did(value: Any, field: str) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        raise IntentEnvelopeError(f"{field} must be a bounded Ed25519 did:key")
    try:
        if encode_ed25519_did_key(decode_ed25519_did_key(value)) != value:
            raise IntentEnvelopeError(f"{field} is not canonical")
    except DIDKeyError:
        # The decoder's diagnostic may contain the caller's original input.
        raise IntentEnvelopeError(f"{field} must be an Ed25519 did:key") from None


def _identifier(value: Any, field: str) -> None:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise IntentEnvelopeError(f"{field} must be a bounded, exact identifier")


def _integer(value: Any, field: str, minimum: int = 0) -> None:
    if type(value) is not int or not minimum <= value <= INTENT_RESOLVER_MAX_SAFE_INTEGER:
        raise IntentEnvelopeError(f"{field} must be a safe integer >= {minimum}")


def _solver_classes(values: Any) -> None:
    if type(values) is not list or not 1 <= len(values) <= 16:
        raise IntentEnvelopeError("solver_classes must be a list of 1..16 exact classes")
    for value in values:
        _identifier(value, "solver class")
    if values != sorted(set(values)):
        raise IntentEnvelopeError("solver_classes must be sorted and unique")


def _lineage(revision: Any, previous_digest: Any) -> None:
    _integer(revision, "revision", 1)
    if not isinstance(previous_digest, str) or (
        previous_digest != "" if revision == 1
        else _HASH_RE.fullmatch(previous_digest) is None
    ):
        raise IntentEnvelopeError("revision must bind a predecessor except at genesis")


def _check_envelope_shape(value: Any, schema: dict) -> None:
    if type(value) is not dict or len(value) != len(schema["required"]):
        raise IntentEnvelopeError("envelope must contain exactly the required fields")
    if any(type(key) is not str or key not in schema["properties"] for key in value):
        raise IntentEnvelopeError("envelope contains an unknown field")


def _snapshot(value: Any, schema: dict) -> dict:
    # Do not let generic schema diagnostics enumerate or echo attacker-chosen keys.
    _check_envelope_shape(value, schema)
    try:
        validate_instance(value, schema)
        encoded = canonical_json(value)
        if len(encoded) > INTENT_ENVELOPE_MAX_DOCUMENT_BYTES:
            raise IntentEnvelopeError("envelope exceeds the UTF-8 byte limit")
        document = json.loads(encoded)
        # Validate the actual returned snapshot as well as the caller's object.
        _check_envelope_shape(document, schema)
        validate_instance(document, schema)
        return document
    except IntentEnvelopeError:
        raise
    except (TypeError, ValueError, RecursionError):
        raise IntentEnvelopeError("invalid intent envelope structure or JSON encoding") from None


def _draft_snapshot(value: Any) -> tuple[dict, bytes]:
    if type(value) is not str or len(value) > INTENT_RESOLVER_MAX_DRAFT_BYTES:
        raise IntentEnvelopeError("accepted draft must be bounded JSON text")
    try:
        return canonical_intent_draft(value)
    except (TypeError, ValueError, RecursionError):
        # A nested unknown field can also contain sensitive or oversized text.
        # Suppress the cause so traceback logging cannot bypass this boundary.
        raise IntentEnvelopeError("invalid accepted draft JSON, schema or canonical encoding") from None


def _validated_body(value: Any) -> dict:
    body = _snapshot(value, INTENT_ENVELOPE_BODY_SCHEMA)
    _did(body["signer_did"], "signer_did")
    _did(body["audience_did"], "audience_did")
    _identifier(body["scope_id"], "scope_id")
    _solver_classes(body["solver_classes"])
    _lineage(body["revision"], body["previous_digest"])
    if _NONCE_RE.fullmatch(body["nonce"]) is None:
        raise IntentEnvelopeError("nonce must be 16 bytes in lowercase hex")
    ttl = body["expires_at_ms"] - body["issued_at_ms"]
    if not 0 < ttl <= INTENT_ENVELOPE_MAX_TTL_MS:
        raise IntentEnvelopeError("envelope TTL must be positive and at most 24 hours")
    draft, encoded = _draft_snapshot(body["draft_json"])
    request = {field: draft[field] for field in _REQUEST_FIELDS}
    request["operation"] = "resolve"
    if draft["request_digest"] != intent_resolver_request_digest(request):
        raise IntentEnvelopeError("draft does not bind its exact source request")
    if body["draft_digest"] != "sha256:" + hashlib.sha256(encoded).hexdigest():
        raise IntentEnvelopeError("draft_digest does not bind the accepted draft")
    if draft["clarifications"] or not draft["outcomes"]:
        raise IntentEnvelopeError("acceptance requires outcomes and no open clarifications")
    if _LEVELS.index(body["automation_ceiling"]) > _LEVELS.index(draft["automation_ceiling"]):
        raise IntentEnvelopeError("acceptance cannot raise the draft automation ceiling")
    return body


def build_intent_envelope_body(
    *, draft_json: str, signer_did: str, audience_did: str, scope_id: str,
    solver_classes: list[str], automation_ceiling: str, issued_at_ms: int,
    expires_at_ms: int, nonce: str, revision: int = 1, previous_digest: str = "",
) -> dict:
    """Build a detached body for explicit local or client-side signing.

    The caller supplies a fresh random 128-bit nonce and explicit timestamps.
    Constraints/outcomes are bound inside the exact draft, never copied into
    independently editable fields. This does not establish human consent.
    """
    _draft, encoded = _draft_snapshot(draft_json)
    return _validated_body({
        "format": INTENT_ENVELOPE_FORMAT, "version": "1",
        "purpose": "draft-acceptance", "authority": "none",
        "commit_authority": False, "executable": False,
        "draft_json": draft_json,
        "draft_digest": "sha256:" + hashlib.sha256(encoded).hexdigest(),
        "signer_did": signer_did, "audience_did": audience_did,
        "scope_id": scope_id, "solver_classes": solver_classes,
        "automation_ceiling": automation_ceiling,
        "issued_at_ms": issued_at_ms, "expires_at_ms": expires_at_ms,
        "nonce": nonce, "revision": revision, "previous_digest": previous_digest,
    })


def intent_envelope_signing_bytes(body: dict) -> bytes:
    """Return domain-separated bytes; this is not a W3C VC proof suite."""
    return INTENT_ENVELOPE_SIGNING_DOMAIN + canonical_json(_validated_body(body))


def _is_prime_order_point(encoded: bytes) -> bool:
    """Compatibility wrapper around the shared strict DID point validator."""

    return is_prime_order_ed25519_point(encoded)


def _verified_document(envelope: Any) -> dict:
    document = _snapshot(envelope, INTENT_ENVELOPE_SCHEMA)
    signature = document["signature"]
    if _SIGNATURE_RE.fullmatch(signature) is None:
        raise IntentEnvelopeError("signature must be 64 bytes in lowercase hex")
    body = _validated_body({k: v for k, v in document.items() if k != "signature"})
    if not crypto_available():
        raise ImportError("IntentEnvelope verification requires nth-dao[crypto]")
    public_key = decode_ed25519_did_key(body["signer_did"])
    signature_bytes = bytes.fromhex(signature)
    if (
        not _is_prime_order_point(public_key)
        or not _is_prime_order_point(signature_bytes[:32])
        or int.from_bytes(signature_bytes[32:], "little") >= _ED25519_ORDER
    ):
        raise IntentEnvelopeError("intent envelope signature is invalid (strict Ed25519 profile)")
    verifier = AgentIdentity.from_did(body["signer_did"])
    if not verifier.verify(
        INTENT_ENVELOPE_SIGNING_DOMAIN + canonical_json(body), signature_bytes,
    ):
        raise IntentEnvelopeError("intent envelope signature is invalid")
    return document


def sign_intent_envelope(body: dict, *, signer: AgentIdentity) -> dict:
    """Sign explicitly with a caller-held identity; never load a node key."""
    document = _validated_body(body)
    if signer.as_did() != document["signer_did"]:
        raise IntentEnvelopeError("signer does not match the accepting DID")
    if not crypto_available():
        raise ImportError("IntentEnvelope signing requires nth-dao[crypto]")
    document["signature"] = signer.sign(
        INTENT_ENVELOPE_SIGNING_DOMAIN + canonical_json(document),
    ).hex()
    return _verified_document(document)


def intent_envelope_digest(envelope: dict) -> str:
    """Hash the entire signed artifact, after structural/signature checks.

    This also accepts expired historical artifacts. It is not live acceptance,
    replay prevention, a revision-store lookup, or an authorization check.
    """
    return "sha256:" + hashlib.sha256(canonical_json(_verified_document(envelope))).hexdigest()


def verify_intent_envelope(
    envelope: dict, *, expected: IntentAcceptanceContext, now_ms: int,
) -> dict:
    """Return a detached verified snapshot or raise; no persistence or effects.

    ``expected`` and ``now_ms`` must come from trusted local policy/state/clock,
    not wire fields. Verification is repeatable, NOT replay consumption. Signed
    acceptance authenticates who accepted these bytes, not their truth, the
    attachments, human consent, a current delegation, or authority to execute.
    """
    if not isinstance(expected, IntentAcceptanceContext):
        raise IntentEnvelopeError("trusted IntentAcceptanceContext is required")
    _integer(now_ms, "now_ms")
    document = _verified_document(envelope)
    for field in (
        "signer_did", "audience_did", "scope_id", "draft_digest",
        "revision", "previous_digest",
    ):
        if document[field] != getattr(expected, field):
            raise IntentEnvelopeError(f"envelope does not match expected {field}")
    if not document["issued_at_ms"] <= now_ms < document["expires_at_ms"]:
        raise IntentEnvelopeError("envelope is not currently valid")
    if not set(document["solver_classes"]).issubset(expected.allowed_solver_classes):
        raise IntentEnvelopeError("solver classes exceed Host policy")
    if _LEVELS.index(document["automation_ceiling"]) > _LEVELS.index(expected.automation_ceiling):
        raise IntentEnvelopeError("automation ceiling exceeds Host policy")
    return document
