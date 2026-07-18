"""IntentMandate - the AUTHORISATION half of the Mandate triad.

An IntentMandate is the DAO (or human) saying:

    "I authorise agent X to spend up to Y, with counterparties from
     this list, by these settlement methods, until this date."

It's a W3C Verifiable Credential 2.0 (data-model JSON form), signed
with Ed25519Signature2020 over canonical JSON. Shape mirrors AP2's
Intent mandate verbatim so an AP2 facilitator can consume it without
custom code.

Shape::

    {
      "@context": ["https://www.w3.org/ns/credentials/v2",
                   "https://nth-dao.org/credentials/intent-mandate/v1"],
      "type": ["VerifiableCredential", "IntentMandate"],
      "issuer": "did:key:z...",            # the authoriser
      "issuanceDate": "2026-06-...",
      "validFrom":    "2026-06-...",
      "validUntil":   "2026-06-...",
      "credentialSubject": {
        "id":      "did:key:z...",         # the AGENT being authorised
        "intent_id": "...",                # 32-hex uuid; Cart/Payment bind here
        "purpose": "buy code review",
        "constraints": {
          "max_amount": {"value": "100.00", "currency": "USDC"},
          "allowed_counterparties": ["did:key:z...", ...],   # [] = closed
          "allowed_settlement_methods": ["x402:usdc", "ap2:card"]
        }
      },
      "proof": {                            # added by sign_intent_mandate
        "type": "Ed25519Signature2020",
        "created": "2026-06-...",
        "verificationMethod": "did:key:z...#z...",
        "proofPurpose": "capabilityInvocation",
        "proofValue": "<128-hex Ed25519 sig>"
      }
    }

Why proofPurpose="capabilityInvocation"?
    Per VC Data Integrity, capabilityInvocation is the proof purpose
    for delegations/authorisations - exactly what an IntentMandate is.
    AchievementCredential uses assertionMethod because it ASSERTS facts;
    IntentMandate DELEGATES authority. Different semantics, different
    purpose value.

W3C VC Data Integrity 1.0 conformance (T-1.1 / Voss V-1, V-9):
    The signature covers BOTH the document AND the proof options
    (everything in the proof block minus proofValue), per §4.3 of
    the Data Integrity spec. verificationMethod uses the did:key
    multibase fragment, not the raw pubkey hex. This is a BREAKING
    wire change vs the v0.9.x scheme - old signatures will not
    verify under v0.10 code.

Voss-review fixes landed in this revision:
    - constraints fields are now REQUIRED, not optional
    - Decimal rejects NaN/Infinity/scientific/whitespace
    - mandate.issuer == None no longer crashes verify
    - VerifyResult NamedTuple preserves tuple API but bool() returns ok
    - verify raises (not returns False) when crypto libs unavailable
    - intent_expiry_status() distinguishes malformed from expired
    - intent_id keeps full 128 bit UUID
    - context/type constants are Final tuples
    - validUntil > issuanceDate is enforced at build time
    - did:key length is bounded
    - re-signing is rejected
    - verify failures are logged structurally
"""

from __future__ import annotations

import enum
import hashlib
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Final, NamedTuple, Optional, Tuple

from ..identity import AgentIdentity, canonical_json
from ._data_integrity import (
    decode_issuer_pubkey,
    sign_with_data_integrity,
    verification_method,
    verify_with_data_integrity,
)

logger = logging.getLogger("nth_dao.mandate.intent")


# ===== constants (immutable) =====

# Tuples instead of lists so an importer can't mutate them in-place
# and contaminate every future mandate (Voss V-11). At the JSON
# serialisation point we make a fresh `list(...)` from these.
INTENT_CONTEXT: Final[Tuple[str, ...]] = (
    "https://www.w3.org/ns/credentials/v2",
    "https://nth-dao.org/credentials/intent-mandate/v1",
)
INTENT_TYPE: Final[Tuple[str, ...]] = (
    "VerifiableCredential",
    "IntentMandate",
)
PROOF_TYPE: Final[str] = "Ed25519Signature2020"
# Public alias kept for back-compat; the canonical name is
# INTENT_PROOF_PURPOSE so it doesn't collide with the cart/payment
# variants when re-exported from the facade.
INTENT_PROOF_PURPOSE: Final[str] = "capabilityInvocation"
PROOF_PURPOSE: Final[str] = INTENT_PROOF_PURPOSE   # legacy alias

# Ed25519 did:key payload is a 48-character multibase z-string in the
# canonical encoding (multicodec 0xed01 + 32-byte pubkey + base58btc
# overhead). We tolerate a small range so other Ed25519 variants don't
# spuriously fail, but cap absolute length to defeat DoS via 1MB
# strings (Voss V-17). Per did:key spec the realistic ceiling is well
# under 100 chars.
_DID_KEY_BODY_MIN = 43
_DID_KEY_BODY_MAX = 150
_DID_KEY_RE = re.compile(
    r"^did:key:z[1-9A-HJ-NP-Za-km-z]{"
    + str(_DID_KEY_BODY_MIN)
    + ","
    + str(_DID_KEY_BODY_MAX)
    + r"}$"
)

# ISO 4217 currency codes are 3 uppercase letters. We also accept
# longer stablecoin tickers like "USDC". The authoritative whitelist
# lives at the SettlementAdapter layer; here we only enforce shape.
# ISO-like uppercase assets plus namespaced test units such as NTH-TEST.
# The commerce MVP deliberately uses NTH-TEST so no real-money code path is
# required; rejecting that token here made the mandate and money layers
# internally incompatible.
_CURRENCY_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*$")

# Settlement method tokens: `<adapter>:<asset>` with conservative
# character sets so weird whitespace / control chars can't smuggle
# through into the canonical JSON (Voss V-16).
_SETTLEMENT_METHOD_RE = re.compile(
    r"^[a-z][a-z0-9_]{0,15}:[a-z0-9][a-z0-9_]{0,31}$"
)

# Maximum lifetime we are willing to sign. Mandates with longer
# validity must be re-issued; this guards against "issue today, valid
# for 100 years" mistakes that would never be discovered until the
# attacker uses the key (Voss V-12 sanity cap).
_MAX_VALIDITY = timedelta(days=365)

# Known constraint keys; anything else is a typo and must surface
# loudly rather than degrade to permissive (Voss V-15).
_KNOWN_CONSTRAINT_KEYS = frozenset(
    {"max_amount", "allowed_counterparties", "allowed_settlement_methods"}
)

# Ed25519 signature size in raw bytes / hex chars
_ED25519_SIG_HEX_LEN = 128


# ===== one-shot crypto availability probe =====
#
# Done at module load time rather than inside verify() so the hot
# verify path doesn't pay an import lookup per call (Voss V-14).

try:
    from ..did_key import decode_ed25519_did_key as _decode_did_key
    from nacl.signing import VerifyKey as _VerifyKey   # type: ignore[import-not-found]

    _CRYPTO_AVAILABLE = True
    _CRYPTO_IMPORT_ERROR: Optional[str] = None
except ImportError as _exc:    # pragma: no cover - env-dependent
    _decode_did_key = None      # type: ignore[assignment]
    _VerifyKey = None           # type: ignore[assignment]
    _CRYPTO_AVAILABLE = False
    _CRYPTO_IMPORT_ERROR = str(_exc)


# ===== result types =====


class VerifyResult(NamedTuple):
    """Result of verify_intent_mandate.

    Backwards compatible with the previous ``Tuple[bool, str]`` return:
    ``ok, reason = verify_intent_mandate(m)`` still works, and indexing
    by 0/1 still works. The non-back-compat (and deliberate) change is
    ``bool(VerifyResult(False, ...))`` returns False - so the
    classic-but-broken ``if not verify_intent_mandate(...)`` idiom now
    behaves correctly instead of always being False (Voss V-6).
    """

    ok: bool
    reason: str

    def __bool__(self) -> bool:  # type: ignore[override]
        return self.ok


class ExpiryStatus(str, enum.Enum):
    """Distinct expiry states so the UI can render the right badge.

    The previous ``is_intent_expired`` boolean conflated three things:
    valid, expired, and structurally malformed timestamps. A dashboard
    that says "expired" when the mandate is actually corrupt misleads
    the user (Voss V-8). Keep ``is_intent_expired`` as a convenience
    boolean; reach for ``intent_expiry_status`` when you need to
    distinguish the failure modes.
    """

    VALID = "valid"
    EXPIRED = "expired"
    MALFORMED = "malformed"


# ===== build =====


def build_intent_mandate(
    issuer_did: str,
    agent_did: str,
    purpose: str,
    constraints: Dict[str, Any],
    expires_at: str,
    *,
    intent_id: Optional[str] = None,
    issued_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Build an UNSIGNED IntentMandate dict.

    Parameters
    ----------
    issuer_did
        did:key of the authoriser (the DAO or a human user). Must verify
        against the signing identity later in ``sign_intent_mandate``.
    agent_did
        did:key of the agent that's authorised to act under this
        mandate. Becomes ``credentialSubject.id`` per W3C VC convention.
    purpose
        Human-readable phrase describing what the agent may do
        ("buy code review", "pay for compute", "deploy fix").
    constraints
        REQUIRED dict carrying:
          max_amount: {"value": "<finite positive decimal>",
                       "currency": "<3-8 uppercase letters>"}
          allowed_counterparties: list of did:key strings; empty
            list = fail-closed (NO counterparty accepted). Wildcards
            are intentionally unsupported; use explicit DID allow-lists.
          allowed_settlement_methods: list of "<adapter>:<asset>"
            tokens; empty list = fail-closed (NO method allowed).
        All three keys are REQUIRED. Missing them previously produced
        a fail-open authorisation, which Voss flagged as P0 (V-2/V-3).
    expires_at
        ISO-8601 timestamp with timezone marker. Becomes ``validUntil``.
        Must be strictly after the (computed) ``issuanceDate`` and
        within ``_MAX_VALIDITY`` of it.
    intent_id
        Optional 32-hex unique id; auto-generated when omitted. The
        full UUID4 is used (not truncated) to keep 122 bits of entropy
        (Voss V-10).
    issued_at
        Optional issuance time; defaults to ``datetime.now(UTC)``.

    Raises
    ------
    ValueError
        On any structural validation failure - we'd rather fail at
        build time than ship a malformed mandate that a verifier
        rejects later, or worse, ship a fail-open mandate that a
        permissive verifier accepts.
    """
    if not _is_did_key(issuer_did):
        raise ValueError(f"issuer_did must be a did:key, got {issuer_did!r}")
    if not _is_did_key(agent_did):
        raise ValueError(f"agent_did must be a did:key, got {agent_did!r}")
    if not purpose or not isinstance(purpose, str):
        raise ValueError("purpose must be a non-empty string")

    validated_constraints = _validate_constraints(constraints)
    _check_iso_with_tz(expires_at, "expires_at")

    issued_dt = issued_at or datetime.now(timezone.utc)
    if issued_dt.tzinfo is None:
        raise ValueError("issued_at must be timezone-aware")
    deadline = datetime.fromisoformat(expires_at)
    if deadline <= issued_dt:
        raise ValueError(
            f"validUntil {expires_at!r} must be strictly after "
            f"issuanceDate {issued_dt.isoformat()!r}"
        )
    if deadline - issued_dt > _MAX_VALIDITY:
        raise ValueError(
            f"validity window of {deadline - issued_dt} exceeds the "
            f"protocol-level cap of {_MAX_VALIDITY}; re-issue with a "
            "shorter validUntil"
        )

    issued = issued_dt.isoformat()
    # Full UUID4 (32 hex / 122 bits) - the previous [:16] truncation
    # halved the entropy for no real saving (Voss V-10).
    intent_id_value = intent_id or uuid.uuid4().hex

    return {
        "@context": list(INTENT_CONTEXT),
        "type": list(INTENT_TYPE),
        "issuer": issuer_did,
        "issuanceDate": issued,
        "validFrom": issued,
        "validUntil": expires_at,
        "credentialSubject": {
            "id": agent_did,
            "intent_id": intent_id_value,
            "purpose": purpose,
            "constraints": validated_constraints,
        },
    }


# ===== sign =====


def sign_intent_mandate(
    mandate: Dict[str, Any],
    identity: AgentIdentity,
    *,
    created_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Attach Ed25519Signature2020 proof. Returns a NEW dict; input is
    not mutated.

    The identity's DID must match the mandate's issuer - we reject
    cross-issuer signing at build time rather than producing a
    credential no verifier will accept.

    Refuses to sign a mandate that already has a proof block - that
    is almost always a bug (the original signature gets silently
    overwritten); explicit re-signing flows should construct a fresh
    unsigned mandate from the source data (Voss V-18).
    """
    if not identity.can_sign:
        raise RuntimeError("identity has no signing key - cannot sign mandate")

    if "proof" in mandate:
        raise ValueError(
            "mandate already carries a proof block; re-signing would "
            "silently discard the prior signature. Build a fresh unsigned "
            "mandate from the source data instead."
        )

    issuer = mandate.get("issuer") or ""
    if not issuer:
        raise ValueError("mandate has no issuer; cannot sign")

    try:
        expected_did = identity.as_did()
    except Exception as exc:    # noqa: BLE001
        logger.exception("identity DID resolution failed")
        raise RuntimeError(f"identity cannot produce a DID: {exc}") from exc

    if issuer != expected_did:
        raise ValueError(
            f"issuer DID mismatch: mandate.issuer={issuer!r} but "
            f"identity DID is {expected_did!r}"
        )

    # Voss V-1 + V-9: full W3C VC Data Integrity §4 signing. Signature
    # covers BOTH the document AND the proof options (everything in
    # the proof block minus proofValue itself). verificationMethod
    # uses the did:key multibase fragment, not the raw pubkey hex.
    payload = _strip_proof(mandate)
    created = (created_at or datetime.now(timezone.utc)).isoformat()
    proof_options = {
        "type": PROOF_TYPE,
        "created": created,
        "verificationMethod": verification_method(issuer),
        "proofPurpose": INTENT_PROOF_PURPOSE,
    }
    sig_hex = sign_with_data_integrity(
        identity=identity, document=payload, proof_options=proof_options,
    )
    proof = {**proof_options, "proofValue": sig_hex}
    return {**mandate, "proof": proof}


# ===== verify =====


def verify_intent_mandate(mandate: Dict[str, Any]) -> VerifyResult:
    """Verify a signed IntentMandate.

    Returns
    -------
    VerifyResult
        A NamedTuple ``(ok, reason)`` that also evaluates correctly
        under ``bool(...)``. ``ok`` is True iff the credential is
        well-formed AND its Ed25519Signature2020 verifies under the
        issuer's did:key. On failure, ``reason`` names the specific
        check that broke.

    Raises
    ------
    RuntimeError
        If PyNaCl or the did_key decoder is unavailable. We
        DELIBERATELY do NOT return ``(False, ...)`` in that case -
        the difference between "cryptographically invalid" and "we
        can't tell" matters for any authorisation gate, and silently
        downgrading to False is fail-open in the worst direction
        (Voss V-7).
    """
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError(
            f"verification requires PyNaCl and did_key support: "
            f"{_CRYPTO_IMPORT_ERROR}"
        )

    proof = mandate.get("proof")
    if not isinstance(proof, dict):
        return _verify_fail(mandate, "missing proof")
    if proof.get("type") != PROOF_TYPE:
        return _verify_fail(
            mandate, f"unsupported proof type: {proof.get('type')!r}"
        )
    if proof.get("proofPurpose") != INTENT_PROOF_PURPOSE:
        return _verify_fail(
            mandate,
            f"wrong proof purpose: {proof.get('proofPurpose')!r}; "
            f"IntentMandate requires {INTENT_PROOF_PURPOSE!r}",
        )
    sig_hex = proof.get("proofValue", "")
    if not isinstance(sig_hex, str) or not sig_hex:
        return _verify_fail(mandate, "missing proofValue")
    if len(sig_hex) != _ED25519_SIG_HEX_LEN:
        return _verify_fail(
            mandate,
            f"proofValue must be {_ED25519_SIG_HEX_LEN}-hex Ed25519 sig, "
            f"got {len(sig_hex)} chars",
        )

    # `mandate.get("issuer", "")` would return None for an explicit
    # `{"issuer": None}` mandate, and `None.startswith(...)` raises
    # AttributeError - the previous code path would surface that as a
    # vague "signature invalid" message (Voss V-5).
    issuer = mandate.get("issuer") or ""
    if not isinstance(issuer, str) or not issuer.startswith("did:key:"):
        return _verify_fail(mandate, f"unsupported issuer scheme: {issuer!r}")

    # Voss V-9: the verificationMethod must reference the same did:key
    # body as the issuer (multibase fragment). Reject mismatches so
    # an attacker can't redirect a verifier to a different key.
    try:
        expected_vm = verification_method(issuer)
    except ValueError as exc:
        return _verify_fail(mandate, f"issuer is not a valid did:key: {exc}")
    if proof.get("verificationMethod") != expected_vm:
        return _verify_fail(
            mandate,
            f"verificationMethod mismatch: expected {expected_vm!r}, "
            f"got {proof.get('verificationMethod')!r}",
        )

    # Voss V-1: signature is over proof options + document per VC
    # Data Integrity §4.3. The verify helper reconstructs both
    # hashes from the received proof + stripped document.
    payload = _strip_proof(mandate)
    try:
        pubkey_bytes = decode_issuer_pubkey(issuer)
    except ValueError as exc:
        return _verify_fail(mandate, f"issuer decode failed: {exc}")
    except Exception as exc:    # noqa: BLE001
        return _verify_fail(mandate, f"issuer decode failed: {exc}")
    ok, reason = verify_with_data_integrity(
        document=payload, proof=proof, pubkey_bytes=pubkey_bytes,
    )
    if not ok:
        return _verify_fail(mandate, reason)
    return VerifyResult(True, "ok")


# ===== digest =====


def intent_mandate_digest(mandate: Dict[str, Any]) -> str:
    """SHA-256 over canonical JSON minus the proof block.

    Cart and Payment mandates carry this digest in their
    ``intent_mandate_digest`` field so they bind to a specific
    authorisation. Stable across signing - signing only adds a proof
    block, which is excluded from the digest by construction.
    """
    return hashlib.sha256(canonical_json(_strip_proof(mandate))).hexdigest()


# ===== freshness =====


def intent_expiry_status(
    mandate: Dict[str, Any], *, now: Optional[datetime] = None,
) -> ExpiryStatus:
    """Tristate expiry: VALID, EXPIRED, or MALFORMED.

    Prefer this over ``is_intent_expired`` when surfacing to a user;
    a "expired" badge over a corrupt-timestamp mandate is misleading.
    """
    valid_until = mandate.get("validUntil")
    if not isinstance(valid_until, str) or not valid_until:
        return ExpiryStatus.MALFORMED
    try:
        deadline = datetime.fromisoformat(valid_until)
    except (ValueError, TypeError):
        return ExpiryStatus.MALFORMED
    if deadline.tzinfo is None:
        # Naive timestamps are protocol-layer rejected - this can only
        # happen via tampering or a non-conforming issuer.
        return ExpiryStatus.MALFORMED
    current = now or datetime.now(timezone.utc)
    return ExpiryStatus.EXPIRED if current > deadline else ExpiryStatus.VALID


def is_intent_expired(
    mandate: Dict[str, Any], *, now: Optional[datetime] = None,
) -> bool:
    """True iff validUntil has passed and the timestamp is well-formed.

    Convenience wrapper around :func:`intent_expiry_status`. Note the
    semantics CHANGED in this revision: a malformed timestamp now
    returns False here (call ``intent_expiry_status`` to distinguish)
    so that "expired" means strictly "exceeded validUntil". The
    previous behaviour of returning True on malformed mandates
    conflated structural and temporal failure (Voss V-8).
    """
    return intent_expiry_status(mandate, now=now) == ExpiryStatus.EXPIRED


# ===== helpers =====


def _strip_proof(mandate: Dict[str, Any]) -> Dict[str, Any]:
    """Return a shallow copy of ``mandate`` without the proof block.

    Centralised so the sign/verify/digest paths never drift on which
    fields are excluded from the canonical payload (Voss V-13).
    """
    return {k: v for k, v in mandate.items() if k != "proof"}


def _is_did_key(value: Any) -> bool:
    """Cheap shape check with length bound (Voss V-17)."""
    return isinstance(value, str) and _DID_KEY_RE.match(value) is not None


def _verify_fail(mandate: Dict[str, Any], reason: str) -> VerifyResult:
    """Centralised log + return so every verify failure leaves a
    structured trail without leaking the full mandate body."""
    logger.info(
        "intent_mandate verify failed: %s (issuer=%s, intent_id=%s)",
        reason,
        mandate.get("issuer", "?"),
        (mandate.get("credentialSubject") or {}).get("intent_id", "?"),
    )
    return VerifyResult(False, reason)


def _validate_constraints(constraints: Any) -> Dict[str, Any]:
    """Structural validation; returns a CLEAN copy.

    All three known fields (max_amount, allowed_counterparties,
    allowed_settlement_methods) are REQUIRED. Empty lists for the
    two list fields mean "fail-closed" not "any" - the previous
    permissive default was the root of Voss V-2 + V-3. Unknown keys
    are rejected outright to catch typos like ``allowed_counterparty``
    that would silently degrade to fail-open (Voss V-15).
    """
    if not isinstance(constraints, dict):
        raise ValueError("constraints must be a dict")

    unknown = set(constraints) - _KNOWN_CONSTRAINT_KEYS
    if unknown:
        raise ValueError(
            f"unknown constraint keys: {sorted(unknown)}; "
            f"recognised keys are {sorted(_KNOWN_CONSTRAINT_KEYS)}"
        )

    out: Dict[str, Any] = {}

    # max_amount: REQUIRED
    if "max_amount" not in constraints:
        raise ValueError(
            "constraints.max_amount is required (no fail-open default)"
        )
    out["max_amount"] = _validate_max_amount(constraints["max_amount"])

    # allowed_counterparties: REQUIRED, empty list = fail-closed
    if "allowed_counterparties" not in constraints:
        raise ValueError(
            "constraints.allowed_counterparties is required; "
            "use [] for fail-closed or ['<did>', ...] for a whitelist"
        )
    counterparties = constraints["allowed_counterparties"]
    if not isinstance(counterparties, list):
        raise ValueError("allowed_counterparties must be a list")
    # Architect audit M-2 (2026-06-07): the docstring promised wildcard
    # ``["*"]`` semantics in earlier revisions; the current docstring says
    # "wildcards intentionally unsupported". Surface that as an explicit,
    # actionable error message rather than the generic "must be did:key"
    # we'd get by accident from _is_did_key.
    if "*" in counterparties:
        raise ValueError(
            "allowed_counterparties wildcard '*' is not supported; "
            "use explicit did:key allow-list or [] for fail-closed"
        )
    for cp in counterparties:
        if not _is_did_key(cp):
            raise ValueError(
                f"allowed_counterparties entry must be did:key, got {cp!r}"
            )
    out["allowed_counterparties"] = list(counterparties)

    # allowed_settlement_methods: REQUIRED, empty list = fail-closed
    if "allowed_settlement_methods" not in constraints:
        raise ValueError(
            "constraints.allowed_settlement_methods is required; "
            "use [] for fail-closed or ['<adapter>:<asset>', ...]"
        )
    methods = constraints["allowed_settlement_methods"]
    if not isinstance(methods, list):
        raise ValueError("allowed_settlement_methods must be a list")
    # M-2: same explicit-wildcard guard as allowed_counterparties.
    if "*" in methods:
        raise ValueError(
            "allowed_settlement_methods wildcard '*' is not supported; "
            "use explicit '<adapter>:<asset>' allow-list or [] for fail-closed"
        )
    for m in methods:
        if not isinstance(m, str) or not _SETTLEMENT_METHOD_RE.match(m):
            raise ValueError(
                f"allowed_settlement_methods entry must match "
                f"'<adapter>:<asset>' (lowercase, bounded), got {m!r}"
            )
    out["allowed_settlement_methods"] = list(methods)

    return out


def _validate_max_amount(amt: Any) -> Dict[str, str]:
    """Parse and tighten the max_amount sub-object.

    Beyond the previous "is positive Decimal" check, this revision
    rejects (Voss V-4):
      - NaN and Infinity (which compare neither <=0 nor >0, so the
        old ``parsed <= 0`` check let them through)
      - scientific notation (settlement adapters may not handle "1e2"
        identically to "100")
      - surrounding whitespace (Decimal strips it but canonical_json
        keeps the original string in the signed payload)
    """
    if not isinstance(amt, dict):
        raise ValueError("max_amount must be a dict")
    value = amt.get("value")
    currency = amt.get("currency")
    if not isinstance(value, str):
        raise ValueError("max_amount.value must be a decimal string")
    if value != value.strip():
        raise ValueError(
            f"max_amount.value must not have surrounding whitespace, "
            f"got {value!r}"
        )
    if "e" in value.lower():
        raise ValueError(
            f"max_amount.value must be plain decimal (no scientific "
            f"notation), got {value!r}"
        )
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(
            f"max_amount.value is not a valid decimal: {value!r}"
        ) from exc
    if not parsed.is_finite():
        raise ValueError(
            f"max_amount.value must be finite (no NaN/Infinity), got {value!r}"
        )
    if parsed <= 0:
        raise ValueError(f"max_amount.value must be positive, got {value!r}")
    if (
        not isinstance(currency, str)
        or not (3 <= len(currency) <= 16)
        or not _CURRENCY_RE.fullmatch(currency)
    ):
        raise ValueError(
            "max_amount.currency must be an uppercase 3-16 character "
            f"asset code, got {currency!r}"
        )
    return {"value": value, "currency": currency}


def _check_iso_with_tz(value: Any, field_name: str) -> None:
    """Parse value as ISO-8601 with explicit timezone, raise otherwise."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"{field_name} is not valid ISO-8601: {value!r}"
        ) from exc
    if parsed.tzinfo is None:
        raise ValueError(
            f"{field_name} must carry a timezone marker (e.g. '+00:00' "
            f"suffix); naive timestamps are rejected at the protocol layer"
        )
