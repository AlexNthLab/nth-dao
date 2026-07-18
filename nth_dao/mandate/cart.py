"""CartMandate - the OFFER half of the Mandate triad.

After the DAO has signed an IntentMandate (authorising agent X to spend
up to Y for purpose Z), a counterparty (the seller / service provider)
responds with a CartMandate: "here is what I'll do, for this much, on
these settlement rails, and I bind my offer to your specific intent."

The binding is via ``intent_mandate_digest`` (the IntentMandate's
canonical-JSON SHA-256 minus proof). A cart is only actionable if:

  * Its signature verifies under the cart issuer's did:key
  * Its declared digest matches the IntentMandate the DAO actually
    signed (no swap attack)
  * Its total fits inside the IntentMandate's max_amount
  * Its currency matches the IntentMandate's max_amount.currency
  * Its issuer is among the IntentMandate's allowed_counterparties
    (if that list is non-empty - empty means any)
  * At least one of its settlement_methods is among the IntentMandate's
    allowed_settlement_methods (if that list is non-empty)

The match check lives in ``cart_satisfies_intent``. Without it, the
IntentMandate's constraints are theatre - the cart would be free to
ask for ten million USDC and the audit trail would record only that
both sides signed.

Why proofPurpose=assertionMethod (not capabilityInvocation)?
    A CartMandate is the counterparty ASSERTING "I will perform X in
    exchange for Y at price Z". It's a factual claim about what they
    offer, not a delegation of authority. assertionMethod is the right
    VC Data Integrity proof purpose; verify_cart_mandate rejects the
    wrong purpose at the gate.
"""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Final, List, Optional, Tuple

from ..identity import AgentIdentity, canonical_json
from ._data_integrity import (
    decode_issuer_pubkey,
    sign_with_data_integrity,
    verification_method,
    verify_with_data_integrity,
)
from .intent import (
    _DID_KEY_RE,
    _SETTLEMENT_METHOD_RE,
    _check_iso_with_tz,
    ExpiryStatus,
    VerifyResult,
    intent_mandate_digest,
    verify_intent_mandate,
)

logger = logging.getLogger("nth_dao.mandate.cart")


# ===== constants (V-11: immutable) =====
CART_CONTEXT: Final[Tuple[str, ...]] = (
    "https://www.w3.org/ns/credentials/v2",
    "https://nth-dao.org/credentials/cart-mandate/v1",
)
CART_TYPE: Final[Tuple[str, ...]] = (
    "VerifiableCredential",
    "CartMandate",
)
PROOF_TYPE: Final[str] = "Ed25519Signature2020"
# Canonical name (V-19): aliased back to PROOF_PURPOSE for back-compat
# with any caller that imports cart.PROOF_PURPOSE directly.
CART_PROOF_PURPOSE: Final[str] = "assertionMethod"
PROOF_PURPOSE: Final[str] = CART_PROOF_PURPOSE   # legacy alias

# V-12: protocol cap on validity window. Carts past this are almost
# certainly misconfigured offers (an offer "good for 100 years" is a
# bug, not a feature).
_MAX_VALIDITY = timedelta(days=365)


# ===== build =====


def build_cart_mandate(
    issuer_did: str,
    buyer_did: str,
    intent_mandate_digest_hex: str,
    items: List[Dict[str, Any]],
    total: Dict[str, Any],
    settlement_methods: List[str],
    expires_at: str,
    *,
    cart_id: Optional[str] = None,
    issued_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Build an UNSIGNED CartMandate dict.

    Parameters
    ----------
    issuer_did
        did:key of the counterparty (the one making the offer).
    buyer_did
        did:key of the buying agent. Goes in ``credentialSubject.id``
        per W3C VC convention; should equal the agent_did named in
        the IntentMandate.
    intent_mandate_digest_hex
        SHA-256 hex of the IntentMandate this cart binds to. 64 lowercase
        hex characters; ``intent_mandate_digest()`` from .intent
        produces this for you.
    items
        Display-only line items, each a dict with at least a
        ``description``. The CANONICAL value source is ``total`` - items
        are for human audit, not pricing logic.
    total
        ``{"value": "<decimal>", "currency": "<USDC / USD / ...>"}``.
        Positive Decimal; currency uppercase short code.
    settlement_methods
        Non-empty list of ``"<adapter>:<asset>"`` tokens the counterparty
        will accept (``"x402:usdc"``, ``"ap2:card"``, etc.).
    expires_at
        ISO-8601 with timezone marker. Offer freshness window; separate
        from the IntentMandate's validUntil.
    cart_id
        Optional 16-hex unique id; auto-generated when omitted. Payment
        mandates will reference this.
    issued_at
        Optional issuance time; defaults to ``datetime.now(UTC)``.

    Raises
    ------
    ValueError
        On any structural validation failure.
    """
    if not _DID_KEY_RE.match(issuer_did):
        raise ValueError(f"issuer_did must be a did:key, got {issuer_did!r}")
    if not _DID_KEY_RE.match(buyer_did):
        raise ValueError(f"buyer_did must be a did:key, got {buyer_did!r}")
    if not isinstance(intent_mandate_digest_hex, str) or len(intent_mandate_digest_hex) != 64:
        raise ValueError(
            f"intent_mandate_digest must be a 64-hex SHA-256 string, "
            f"got {intent_mandate_digest_hex!r}"
        )
    try:
        bytes.fromhex(intent_mandate_digest_hex)
    except ValueError as exc:
        raise ValueError(
            f"intent_mandate_digest is not valid hex: {intent_mandate_digest_hex!r}"
        ) from exc

    validated_items = _validate_items(items)
    validated_total = _validate_money(total, "total")
    validated_methods = _validate_settlement_methods(settlement_methods)
    _check_iso_with_tz(expires_at, "expires_at")

    # V-12: validUntil must be strictly after issuanceDate and within
    # the protocol cap. Same mirror as intent.py.
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
            f"protocol-level cap of {_MAX_VALIDITY}"
        )

    issued = issued_dt.isoformat()
    # V-10: full UUID4 (32 hex chars / 122 bits) - the previous
    # [:16] truncation halved the entropy.
    cart_id_value = cart_id or uuid.uuid4().hex

    return {
        "@context": list(CART_CONTEXT),
        "type": list(CART_TYPE),
        "issuer": issuer_did,
        "issuanceDate": issued,
        "validFrom": issued,
        "validUntil": expires_at,
        "credentialSubject": {
            "id": buyer_did,
            "cart_id": cart_id_value,
            "intent_mandate_digest": intent_mandate_digest_hex,
            "items": validated_items,
            "total": validated_total,
            "settlement_methods": validated_methods,
        },
    }


# ===== sign =====


def sign_cart_mandate(
    mandate: Dict[str, Any],
    identity: AgentIdentity,
    *,
    created_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Attach Ed25519Signature2020 proof. Returns a NEW dict; input
    is not mutated.

    The signing identity's DID must match ``mandate.issuer`` - we reject
    cross-issuer signing at build time rather than producing a credential
    no verifier will accept.
    """
    if not identity.can_sign:
        raise RuntimeError("identity has no signing key - cannot sign mandate")

    # V-18: refuse to silently overwrite an existing proof. An
    # explicit re-sign flow must build a fresh unsigned mandate from
    # the source data.
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
    except Exception as exc:   # noqa: BLE001
        logger.exception("identity DID resolution failed")
        raise RuntimeError(f"identity cannot produce a DID: {exc}") from exc
    if issuer != expected_did:
        raise ValueError(
            f"issuer DID mismatch: mandate.issuer={issuer!r} but "
            f"identity DID is {expected_did!r}"
        )

    # Voss V-1 + V-9: full W3C VC Data Integrity §4 signing.
    payload = _strip_proof(mandate)
    created = (created_at or datetime.now(timezone.utc)).isoformat()
    proof_options = {
        "type": PROOF_TYPE,
        "created": created,
        "verificationMethod": verification_method(issuer),
        "proofPurpose": PROOF_PURPOSE,
    }
    sig_hex = sign_with_data_integrity(
        identity=identity, document=payload, proof_options=proof_options,
    )
    proof = {**proof_options, "proofValue": sig_hex}
    return {**mandate, "proof": proof}


# ===== verify =====


def verify_cart_mandate(mandate: Dict[str, Any]) -> VerifyResult:
    """Verify a signed CartMandate.

    V-6: returns ``VerifyResult`` (a NamedTuple), so the legacy
    ``ok, reason = verify_cart_mandate(...)`` unpacking still works
    AND ``if not verify_cart_mandate(...)`` now reports the right
    truthiness (the tuple truthy-trap that Voss V-6 documented).

    V-20: every failure path is logged at INFO with the issuer +
    cart_id, so a forensic operator can correlate against the
    EventBus without scraping each call site.
    """
    proof = mandate.get("proof")
    if not isinstance(proof, dict):
        return _verify_fail(mandate, "missing proof")
    if proof.get("type") != PROOF_TYPE:
        return _verify_fail(
            mandate, f"unsupported proof type: {proof.get('type')!r}"
        )
    if proof.get("proofPurpose") != CART_PROOF_PURPOSE:
        return _verify_fail(
            mandate,
            f"wrong proof purpose: {proof.get('proofPurpose')!r}; "
            f"CartMandate requires {CART_PROOF_PURPOSE!r}",
        )

    issuer = mandate.get("issuer") or ""
    if not isinstance(issuer, str) or not issuer.startswith("did:key:"):
        return _verify_fail(mandate, f"unsupported issuer scheme: {issuer!r}")

    # Voss V-9: verificationMethod fragment must reference the same
    # did:key body as the issuer.
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

    payload = _strip_proof(mandate)
    try:
        pubkey_bytes = decode_issuer_pubkey(issuer)
    except Exception as exc:    # noqa: BLE001
        return _verify_fail(mandate, f"issuer decode failed: {exc}")
    ok, reason = verify_with_data_integrity(
        document=payload, proof=proof, pubkey_bytes=pubkey_bytes,
    )
    if not ok:
        return _verify_fail(mandate, reason)
    return VerifyResult(True, "ok")


# ===== intent-cart binding check =====


def cart_satisfies_intent(
    cart: Dict[str, Any],
    intent: Dict[str, Any],
    *,
    require_signed: bool = True,
) -> Tuple[bool, str]:
    """Check that a CartMandate fits inside an IntentMandate's
    constraints.

    Returns ``(ok, reason)``. Without this check the constraints in
    IntentMandate would be theatre: the cart could ask for any total in
    any currency from any counterparty.

    Checks (short-circuit on first failure):

      0. cart and intent BOTH carry a proof block (signed). The previous
         API accepted any dict, which let a buggy caller pass a fabricated
         intent with ``max_amount=10000000`` and the cart would always
         satisfy it (Voss V-21). Set ``require_signed=False`` ONLY for
         tooling that has its own out-of-band verification.
      1. cart.credentialSubject.intent_mandate_digest == digest(intent)
         (swap-attack defence)
      2. cart.total is a positive finite Decimal in a known currency
         (Voss V-23: previously NaN/Infinity silently became "<= any
         max_amount" because NaN comparisons are all False)
      3. cart.total.currency == intent.max_amount.currency
      4. cart.total.value <= intent.max_amount.value (Decimal compare)
      5. cart.issuer in intent.allowed_counterparties. Empty list now
         means FAIL-CLOSED (consistent with intent build-time semantics),
         not "any" - that was the V-22 regression of T-1 V-3.
      6. at least one cart.settlement_methods in
         intent.allowed_settlement_methods. Empty list = fail-closed.

    Authenticity (proof signature itself) is verified by
    ``verify_cart_mandate`` / ``verify_intent_mandate``; pair them with
    this function (or call ``complete_triad_chain``).
    """
    if not isinstance(cart, dict) or not isinstance(intent, dict):
        return False, "cart and intent must be dicts"

    # V-21 (4th-round B-3 fix): the earlier "proof block must exist"
    # check was theatrical - a caller passing
    # ``proof = {"junk": True}`` would have slipped through and then
    # used cart_satisfies_intent as a free constraint oracle against
    # a fabricated intent. The HONEST gate runs the full
    # ``verify_intent_mandate`` / ``verify_cart_mandate`` here.
    #
    # complete_triad_chain already verifies BEFORE calling this; to
    # avoid a redundant Ed25519 verify when called from there, it
    # passes ``require_signed=False``. Standalone callers (the
    # original V-21 attack vector) get strict verification by default.
    if require_signed:
        ok, reason = verify_intent_mandate(intent)
        if not ok:
            return False, f"intent must be signed: {reason}"
        ok, reason = verify_cart_mandate(cart)
        if not ok:
            return False, f"cart must be signed: {reason}"

    cart_subject = cart.get("credentialSubject", {})
    if not isinstance(cart_subject, dict):
        return False, "cart.credentialSubject malformed"

    # 1. binding via digest
    declared_digest = cart_subject.get("intent_mandate_digest", "")
    actual_digest = intent_mandate_digest(intent)
    if declared_digest != actual_digest:
        return False, (
            f"intent digest mismatch: cart binds to "
            f"{declared_digest[:16]}..., intent digest is "
            f"{actual_digest[:16]}..."
        )

    intent_subject = intent.get("credentialSubject", {})
    constraints = intent_subject.get("constraints", {})
    if not isinstance(constraints, dict):
        return False, "intent.credentialSubject.constraints malformed"

    # 2 + 3 + 4. amount / currency
    cart_total = cart_subject.get("total", {})
    if not isinstance(cart_total, dict):
        return False, "cart.total malformed"
    cart_value_str = cart_total.get("value", "")
    cart_currency = cart_total.get("currency", "")
    try:
        cart_value = Decimal(cart_value_str)
    except InvalidOperation:
        return False, f"cart.total.value not a valid decimal: {cart_value_str!r}"
    # V-23: NaN / Infinity bypass.
    #   Decimal("NaN") <= anything is False, so the old `cart_value > max_value`
    #   was False for NaN totals — the cart "satisfied" any budget.
    if not cart_value.is_finite():
        return False, f"cart.total.value must be finite, got {cart_value_str!r}"
    if cart_value <= 0:
        return False, f"cart.total.value must be positive, got {cart_value_str!r}"

    max_amount = constraints.get("max_amount")
    if not isinstance(max_amount, dict) or not max_amount:
        return False, "intent.max_amount missing (malformed intent)"
    max_value_str = max_amount.get("value", "")
    max_currency = max_amount.get("currency", "")
    if cart_currency != max_currency:
        return False, (
            f"currency mismatch: cart {cart_currency!r} != "
            f"intent max_amount {max_currency!r}"
        )
    try:
        max_value = Decimal(max_value_str)
    except InvalidOperation:
        return False, f"intent.max_amount.value not a valid decimal: {max_value_str!r}"
    if not max_value.is_finite():
        return False, f"intent.max_amount.value must be finite, got {max_value_str!r}"
    if cart_value > max_value:
        return False, (
            f"total exceeds budget: cart {cart_value} {cart_currency} > "
            f"intent max {max_value} {max_currency}"
        )

    # 5. counterparty allow-list - V-22: empty list = fail-closed.
    #
    # Prior implementation skipped the check when the list was empty,
    # interpreting `[]` as "any counterparty allowed". That contradicted
    # the build-time semantic established by T-1's V-3 fix (`[]` =
    # explicit fail-closed). Aligned now: missing field is malformed,
    # empty list is fail-closed, populated list is whitelist.
    if "allowed_counterparties" not in constraints:
        return False, "intent.allowed_counterparties missing (malformed intent)"
    allowed_counterparties = constraints["allowed_counterparties"]
    if not isinstance(allowed_counterparties, list):
        return False, "intent.allowed_counterparties must be a list"
    if not allowed_counterparties:
        return False, (
            "intent.allowed_counterparties is empty (fail-closed by "
            "issuer); no counterparty is authorised"
        )
    cart_issuer = cart.get("issuer", "")
    if cart_issuer not in allowed_counterparties:
        return False, (
            f"counterparty {cart_issuer!r} not in intent "
            f"allowed_counterparties list"
        )

    # 6. settlement method allow-list - same V-22 fix.
    if "allowed_settlement_methods" not in constraints:
        return False, "intent.allowed_settlement_methods missing (malformed intent)"
    allowed_methods = constraints["allowed_settlement_methods"]
    if not isinstance(allowed_methods, list):
        return False, "intent.allowed_settlement_methods must be a list"
    if not allowed_methods:
        return False, (
            "intent.allowed_settlement_methods is empty (fail-closed by "
            "issuer); no settlement rail is authorised"
        )
    cart_methods = cart_subject.get("settlement_methods", []) or []
    if not any(m in allowed_methods for m in cart_methods):
        return False, (
            f"no overlap between cart methods {cart_methods} and "
            f"intent allowed_settlement_methods {allowed_methods}"
        )

    return True, "ok"


# ===== digest + freshness =====


def cart_mandate_digest(mandate: Dict[str, Any]) -> str:
    """SHA-256 over canonical JSON minus the proof block.

    PaymentMandate (T-3) will carry this in its ``cart_mandate_digest``
    field so the payment binds to a specific cart. Stable across signing.
    """
    return hashlib.sha256(canonical_json(_strip_proof(mandate))).hexdigest()


def cart_expiry_status(
    mandate: Dict[str, Any], *, now: Optional[datetime] = None,
) -> ExpiryStatus:
    """V-8: tristate expiry - VALID / EXPIRED / MALFORMED.

    UI should prefer this over ``is_cart_expired`` when distinguishing
    "the cart's offer window passed" from "the cart has a corrupt
    timestamp" matters.
    """
    valid_until = mandate.get("validUntil")
    if not isinstance(valid_until, str) or not valid_until:
        return ExpiryStatus.MALFORMED
    try:
        deadline = datetime.fromisoformat(valid_until)
    except (ValueError, TypeError):
        return ExpiryStatus.MALFORMED
    if deadline.tzinfo is None:
        return ExpiryStatus.MALFORMED
    current = now or datetime.now(timezone.utc)
    return ExpiryStatus.EXPIRED if current > deadline else ExpiryStatus.VALID


def is_cart_expired(
    mandate: Dict[str, Any], *, now: Optional[datetime] = None,
) -> bool:
    """True iff validUntil has passed and the timestamp is well-formed.

    V-8 semantic change: a malformed timestamp returns False here
    (call ``cart_expiry_status`` to distinguish). The previous
    behaviour of conflating "expired" with "corrupt" misled UIs.
    """
    return cart_expiry_status(mandate, now=now) == ExpiryStatus.EXPIRED


# ===== helpers =====


def _strip_proof(mandate: Dict[str, Any]) -> Dict[str, Any]:
    """V-13: centralised proof-stripping. Used by sign / verify /
    digest so they can never drift on which fields are excluded
    from the canonical payload."""
    return {k: v for k, v in mandate.items() if k != "proof"}


def _verify_fail(mandate: Dict[str, Any], reason: str) -> VerifyResult:
    """V-20: every verify-failure path is logged with the issuer +
    cart_id so SOC tooling has structured forensic data."""
    logger.info(
        "cart_mandate verify failed: %s (issuer=%s, cart_id=%s)",
        reason,
        mandate.get("issuer", "?"),
        (mandate.get("credentialSubject") or {}).get("cart_id", "?"),
    )
    return VerifyResult(False, reason)


# ===== helpers =====


def _validate_money(amount: Any, field_name: str) -> Dict[str, str]:
    """Strict positive-finite-Decimal + uppercase-currency validation.

    V-4 hardening (mirror of intent's _validate_max_amount):
      - NaN and Infinity rejected (the old ``parsed <= 0`` returned
        False for both, letting them through as "positive")
      - Scientific notation rejected (``"1e2"`` parses as 100 but the
        canonical_json would carry the literal "1e2" into the signed
        payload, diverging from any normaliser)
      - Surrounding whitespace rejected (Decimal trims it but the
        original string survives into the signature)
    """
    if not isinstance(amount, dict):
        raise ValueError(f"{field_name} must be a dict")
    value = amount.get("value", "")
    currency = amount.get("currency", "")
    if not isinstance(value, str):
        raise ValueError(f"{field_name}.value must be a decimal string")
    if value != value.strip():
        raise ValueError(
            f"{field_name}.value must not have surrounding whitespace, "
            f"got {value!r}"
        )
    if "e" in value.lower():
        raise ValueError(
            f"{field_name}.value must be plain decimal (no scientific "
            f"notation), got {value!r}"
        )
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f"{field_name}.value is not a valid decimal: {value!r}") from exc
    if not parsed.is_finite():
        raise ValueError(
            f"{field_name}.value must be finite (no NaN/Infinity), got {value!r}"
        )
    if parsed <= 0:
        raise ValueError(f"{field_name}.value must be positive, got {value!r}")
    if (
        not isinstance(currency, str)
        or not 3 <= len(currency) <= 16
        or re.fullmatch(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*", currency) is None
    ):
        raise ValueError(
            f"{field_name}.currency must be an uppercase 3-16 character "
            f"asset code, got {currency!r}"
        )
    return {"value": value, "currency": currency}


def _validate_items(items: Any) -> List[Dict[str, Any]]:
    """Items are display-only; minimal contract: list of dicts, each
    with at least a non-empty description."""
    if not isinstance(items, list) or not items:
        raise ValueError("items must be a non-empty list")
    out: List[Dict[str, Any]] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"items[{i}] must be a dict")
        description = item.get("description", "")
        if not isinstance(description, str) or not description:
            raise ValueError(f"items[{i}].description must be a non-empty string")
        out.append(dict(item))
    return out


def _validate_settlement_methods(methods: Any) -> List[str]:
    """V-33: tightened to match intent.py's regex.

    Previously this accepted any string containing a colon (`" : "`,
    `"::"`, `"X:Y"` uppercase) while intent.py rejected the same
    inputs. The asymmetry meant a cart built with a sloppy method
    string never matched intent's strict whitelist — fail-closed by
    accident, not by design. Both ends now use the same regex.
    """
    if not isinstance(methods, list) or not methods:
        raise ValueError("settlement_methods must be a non-empty list")
    for m in methods:
        if not isinstance(m, str) or not _SETTLEMENT_METHOD_RE.match(m):
            raise ValueError(
                f"settlement_methods entry must match '<adapter>:<asset>' "
                f"(lowercase, bounded), got {m!r}"
            )
    return list(methods)
