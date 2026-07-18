"""PaymentMandate - the ACCEPTANCE half that closes the Mandate triad.

After:
  1. The DAO signed an IntentMandate authorising agent X to spend Y
  2. The counterparty signed a CartMandate offering goods at price Z
     bound to that intent's digest

...the DAO signs a PaymentMandate accepting the cart and committing to
a specific settlement rail. The triad is now complete:

  IntentMandate  -- authorises  -->  agent
  CartMandate    -- offers      -->  goods at price
  PaymentMandate -- accepts     -->  settles via chosen rail

The PaymentMandate is the signal a SettlementAdapter (x402, AP2 card,
manual, etc.) listens for. Its presence + its three binding checks
(payment->cart->intent) prove every external requirement was met:

  * The DAO authorised this purpose (intent)
  * The counterparty offered these terms (cart)
  * Both sides accept the specific settlement rail (payment)

Why proofPurpose=capabilityInvocation?
    Like IntentMandate, PaymentMandate is a DELEGATION - the DAO
    delegates settlement authority to the named SettlementAdapter for
    this specific cart. capabilityInvocation is the canonical VC Data
    Integrity proof purpose for delegations. CartMandate's
    assertionMethod (an offer being made) is semantically different;
    keeping them distinct prevents callers from confusing an offer
    with an authorisation.

Three-stage check chain (the end-to-end gate):

  1. verify_intent_mandate(intent)
     -> intent is authentic and signed by the DAO

  2. verify_cart_mandate(cart) AND cart_satisfies_intent(cart, intent)
     -> cart is authentic AND fits within the intent's constraints

  3. verify_payment_mandate(payment) AND
     payment_satisfies_cart(payment, cart) AND
     payment.issuer == intent.issuer
     -> payment is authentic AND picks an offered settlement rail
        AND is from the same DAO that issued the intent

complete_triad_chain(intent, cart, payment) does all of this in one
call for callers who don't want to compose manually.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Final, Optional, Tuple

from ..identity import AgentIdentity, canonical_json
from ._data_integrity import (
    decode_issuer_pubkey,
    sign_with_data_integrity,
    verification_method,
    verify_with_data_integrity,
)
from .cart import (
    cart_expiry_status,
    cart_mandate_digest,
    cart_satisfies_intent,
    verify_cart_mandate,
)
from .intent import (
    _DID_KEY_RE,
    _SETTLEMENT_METHOD_RE,
    _check_iso_with_tz,
    ExpiryStatus,
    VerifyResult,
    intent_expiry_status,
    intent_mandate_digest,
    verify_intent_mandate,
)

logger = logging.getLogger("nth_dao.mandate.payment")


# V-11: immutable
PAYMENT_CONTEXT: Final[Tuple[str, ...]] = (
    "https://www.w3.org/ns/credentials/v2",
    "https://nth-dao.org/credentials/payment-mandate/v1",
)
PAYMENT_TYPE: Final[Tuple[str, ...]] = (
    "VerifiableCredential",
    "PaymentMandate",
)
PROOF_TYPE: Final[str] = "Ed25519Signature2020"
# V-19: canonical name with legacy alias.
PAYMENT_PROOF_PURPOSE: Final[str] = "capabilityInvocation"
PROOF_PURPOSE: Final[str] = PAYMENT_PROOF_PURPOSE   # legacy alias

# V-12: protocol cap on validity. Payment authorities longer than
# a year are a configuration smell.
_MAX_VALIDITY = timedelta(days=365)


# ===== build =====


def build_payment_mandate(
    issuer_did: str,
    payee_did: str,
    cart_mandate_digest_hex: str,
    settlement_choice: str,
    expires_at: str,
    *,
    settlement_metadata: Optional[Dict[str, Any]] = None,
    payment_id: Optional[str] = None,
    issued_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Build an UNSIGNED PaymentMandate dict.

    Parameters
    ----------
    issuer_did
        did:key of the DAO accepting the cart. MUST equal the original
        IntentMandate's issuer - same authorising party throughout.
    payee_did
        did:key of the entity receiving payment - normally the
        CartMandate's issuer.
    cart_mandate_digest_hex
        SHA-256 hex of the CartMandate being accepted. ``cart_mandate_digest()``
        from .cart produces this.
    settlement_choice
        ``"<adapter>:<asset>"`` token; MUST be one of the methods the
        cart offered.
    expires_at
        ISO-8601 with timezone marker. How long the settlement adapter
        is authorised to attempt the actual rail transaction.
    settlement_metadata
        Adapter-specific routing info (e.g. ``{"recipient_address":
        "0x..."}`` for x402). Optional; the schema is defined by the
        chosen adapter, not this layer.
    payment_id
        Optional 16-hex unique id; auto-generated when omitted.
    issued_at
        Optional issuance time; defaults to ``datetime.now(UTC)``.
    """
    if not _DID_KEY_RE.match(issuer_did):
        raise ValueError(f"issuer_did must be a did:key, got {issuer_did!r}")
    if not _DID_KEY_RE.match(payee_did):
        raise ValueError(f"payee_did must be a did:key, got {payee_did!r}")
    if not isinstance(cart_mandate_digest_hex, str) or len(cart_mandate_digest_hex) != 64:
        raise ValueError(
            f"cart_mandate_digest must be a 64-hex SHA-256 string, "
            f"got {cart_mandate_digest_hex!r}"
        )
    try:
        bytes.fromhex(cart_mandate_digest_hex)
    except ValueError as exc:
        raise ValueError(
            f"cart_mandate_digest is not valid hex: {cart_mandate_digest_hex!r}"
        ) from exc
    # V-33: same tightening as cart's settlement_methods. Previously
    # `':' not in s` let through " : ", "::", "X:Y", etc.
    if not isinstance(settlement_choice, str) or not _SETTLEMENT_METHOD_RE.match(settlement_choice):
        raise ValueError(
            f"settlement_choice must match '<adapter>:<asset>' "
            f"(lowercase, bounded), got {settlement_choice!r}"
        )
    if settlement_metadata is not None and not isinstance(settlement_metadata, dict):
        raise ValueError("settlement_metadata must be a dict when provided")
    _check_iso_with_tz(expires_at, "expires_at")

    # V-12
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
    # V-10: full UUID4 hex
    payment_id_value = payment_id or uuid.uuid4().hex

    subject: Dict[str, Any] = {
        "id": payee_did,
        "payment_id": payment_id_value,
        "cart_mandate_digest": cart_mandate_digest_hex,
        "settlement_choice": settlement_choice,
    }
    # Only include metadata key when actually present, so the canonical
    # JSON (and therefore the digest) is stable regardless of whether
    # the caller passed an empty dict vs no dict at all.
    if settlement_metadata:
        subject["settlement_metadata"] = dict(settlement_metadata)

    return {
        "@context": list(PAYMENT_CONTEXT),
        "type": list(PAYMENT_TYPE),
        "issuer": issuer_did,
        "issuanceDate": issued,
        "validFrom": issued,
        "validUntil": expires_at,
        "credentialSubject": subject,
    }


# ===== sign =====


def sign_payment_mandate(
    mandate: Dict[str, Any],
    identity: AgentIdentity,
    *,
    created_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Attach Ed25519Signature2020 proof. Returns a NEW dict; input
    is not mutated.

    The signing identity's DID must match ``mandate.issuer``.
    """
    if not identity.can_sign:
        raise RuntimeError("identity has no signing key - cannot sign mandate")

    # V-18: refuse silent re-sign.
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


def verify_payment_mandate(mandate: Dict[str, Any]) -> VerifyResult:
    """Verify a signed PaymentMandate.

    V-6: returns ``VerifyResult`` NamedTuple - back-compat with
    tuple unpacking, but ``bool(...)`` now correctly reflects
    ``ok`` instead of always being truthy.

    Voss V-1 hardening: signature covers proof options + document
    per W3C VC Data Integrity §4.3.
    V-20: failures logged with issuer + payment_id.
    """
    proof = mandate.get("proof")
    if not isinstance(proof, dict):
        return _verify_fail(mandate, "missing proof")
    if proof.get("type") != PROOF_TYPE:
        return _verify_fail(
            mandate, f"unsupported proof type: {proof.get('type')!r}"
        )
    if proof.get("proofPurpose") != PAYMENT_PROOF_PURPOSE:
        return _verify_fail(
            mandate,
            f"wrong proof purpose: {proof.get('proofPurpose')!r}; "
            f"PaymentMandate requires {PAYMENT_PROOF_PURPOSE!r}",
        )

    issuer = mandate.get("issuer") or ""
    if not isinstance(issuer, str) or not issuer.startswith("did:key:"):
        return _verify_fail(mandate, f"unsupported issuer scheme: {issuer!r}")

    # V-9
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


# ===== payment-cart binding check =====


def payment_satisfies_cart(
    payment: Dict[str, Any],
    cart: Dict[str, Any],
    *,
    intent: Optional[Dict[str, Any]] = None,
    require_signed: bool = True,
) -> Tuple[bool, str]:
    """Check that a PaymentMandate accepts a specific cart correctly.

    Returns ``(ok, reason)``. Checks:

      0. payment and cart BOTH signed (Voss V-21). Without this gate
         a fabricated cart could pass the binding check against a
         fabricated payment - the constraint compare would happily
         declare "valid" even though no signature exists. Set
         ``require_signed=False`` only for tooling with out-of-band
         verification.
      1. payment.cart_mandate_digest == digest(cart)
         (swap-attack: payment can't claim acceptance of cart A while
          paired with cart B during settlement)
      2. payment.settlement_choice IS in cart.settlement_methods
         (the DAO can't unilaterally pick a rail the counterparty
          didn't offer)
      3. payment.credentialSubject.id == cart.issuer
         (the payee in the payment must be the same entity that issued
          the cart - prevents redirecting funds to a third party)
      4. (only if ``intent`` is passed) payment.issuer == intent.issuer
         (Voss V-32: issuer continuity. Without this check a hijacker
         DAO can accept someone else's cart and settle under their own
         signature, since none of the prior checks compare the paying
         DAO to the authorising DAO. ``complete_triad_chain`` also
         enforces this, but direct callers of this function used to
         silently skip it.)

    Does NOT verify signatures - pair with verify_payment_mandate +
    verify_cart_mandate, or use complete_triad_chain.
    """
    if not isinstance(payment, dict) or not isinstance(cart, dict):
        return False, "payment and cart must be dicts"

    # V-21 (4th-round B-3 fix): theatrical "proof is a dict" gate
    # replaced by real signature verification. See cart.py for the
    # rationale and complete_triad_chain's require_signed=False
    # pattern to avoid redundant verification on the chain path.
    if require_signed:
        ok, reason = verify_payment_mandate(payment)
        if not ok:
            return False, f"payment must be signed: {reason}"
        ok, reason = verify_cart_mandate(cart)
        if not ok:
            return False, f"cart must be signed: {reason}"

    payment_subject = payment.get("credentialSubject", {})
    if not isinstance(payment_subject, dict):
        return False, "payment.credentialSubject malformed"

    # 1. digest binding
    declared_digest = payment_subject.get("cart_mandate_digest", "")
    actual_digest = cart_mandate_digest(cart)
    if declared_digest != actual_digest:
        return False, (
            f"cart digest mismatch: payment binds to "
            f"{declared_digest[:16]}..., cart digest is "
            f"{actual_digest[:16]}..."
        )

    # 2. settlement choice in cart's offer
    cart_subject = cart.get("credentialSubject", {})
    if not isinstance(cart_subject, dict):
        return False, "cart.credentialSubject malformed"
    chosen = payment_subject.get("settlement_choice", "")
    offered = cart_subject.get("settlement_methods", []) or []
    if chosen not in offered:
        return False, (
            f"settlement_choice {chosen!r} not in cart's offered "
            f"methods {offered}"
        )

    # 3. payee identity matches cart issuer
    payee = payment_subject.get("id", "")
    cart_issuer = cart.get("issuer", "")
    if payee != cart_issuer:
        return False, (
            f"payee mismatch: payment.subject.id={payee!r} but "
            f"cart.issuer={cart_issuer!r} - payment would redirect "
            "funds to a third party"
        )

    # 4. (V-32) issuer continuity if the intent is supplied
    if intent is not None:
        if not isinstance(intent, dict):
            return False, "intent (if provided) must be a dict"
        # B-1 / V-21 (4th-round): real verification, not just a
        # presence check. Fabricated unsigned intent with hijacker's
        # DID in `issuer` would otherwise pass continuity trivially.
        if require_signed:
            ok, reason = verify_intent_mandate(intent)
            if not ok:
                return False, f"intent must be signed: {reason}"
        intent_issuer = intent.get("issuer", "")
        payment_issuer = payment.get("issuer", "")
        if not intent_issuer or intent_issuer != payment_issuer:
            return False, (
                f"issuer continuity broken: intent.issuer={intent_issuer!r} "
                f"!= payment.issuer={payment_issuer!r} (a different DAO "
                "cannot hijack an authorisation)"
            )

    return True, "ok"


# ===== end-to-end triad =====


def complete_triad_chain(
    intent: Dict[str, Any],
    cart: Dict[str, Any],
    payment: Dict[str, Any],
    *,
    now: Optional[datetime] = None,
) -> Tuple[bool, str]:
    """End-to-end gate: verify the entire Intent->Cart->Payment chain.

    Returns ``(ok, reason)``. A SettlementAdapter should call this
    once before initiating any external rail transaction. If it
    returns ok=True, the three mandates are mutually consistent and
    all three signatures are valid.

    Check order (V-31: cheap structural gates first, expensive
    signature verifications last).

    Three Ed25519 verify calls cost about 100us each. The previous
    order ran all three before doing the O(1) issuer-continuity
    string compare - a hijacker DAO using a stolen cart used to burn
    300us of CPU before the cheap final check rejected. Reordered so:

      A. structural: intent.issuer == payment.issuer
         (issuer continuity - rejects hijacker DAO BEFORE crypto)
      B. structural: cart.intent_mandate_digest == digest(intent)
         (rejects swap-attack inputs cheaply)
      C. structural: payment.cart_mandate_digest == digest(cart)
         (rejects swap-attack inputs cheaply)
      D. crypto:     verify_intent_mandate
      E. crypto:     verify_cart_mandate
      F. constraint: cart_satisfies_intent
                     (amount/currency/counterparty/method overlap)
      G. crypto:     verify_payment_mandate
      H. constraint: payment_satisfies_cart with intent= for issuer
                     continuity re-check (Voss V-32 hardening)
    """
    if not isinstance(intent, dict) or not isinstance(cart, dict) or not isinstance(payment, dict):
        return False, "intent, cart, payment must all be dicts"

    # ----- structural cheap gates first -----
    intent_issuer = intent.get("issuer", "")
    payment_issuer = payment.get("issuer", "")
    if not intent_issuer or intent_issuer != payment_issuer:
        return False, (
            f"issuer continuity broken: intent.issuer={intent_issuer!r} != "
            f"payment.issuer={payment_issuer!r} (a different DAO cannot "
            "hijack an authorisation)"
        )

    cart_subject = cart.get("credentialSubject", {})
    if not isinstance(cart_subject, dict):
        return False, "cart vs intent: cart.credentialSubject malformed"
    declared_intent_digest = cart_subject.get("intent_mandate_digest", "")
    actual_intent_digest = intent_mandate_digest(intent)
    if declared_intent_digest != actual_intent_digest:
        return False, (
            f"cart vs intent: digest mismatch "
            f"({declared_intent_digest[:16]}... != "
            f"{actual_intent_digest[:16]}...)"
        )

    payment_subject = payment.get("credentialSubject", {})
    if not isinstance(payment_subject, dict):
        return False, "payment vs cart: payment.credentialSubject malformed"
    declared_cart_digest = payment_subject.get("cart_mandate_digest", "")
    actual_cart_digest = cart_mandate_digest(cart)
    if declared_cart_digest != actual_cart_digest:
        return False, (
            f"payment vs cart: digest mismatch "
            f"({declared_cart_digest[:16]}... != "
            f"{actual_cart_digest[:16]}...)"
        )

    # ----- freshness gates -----
    #
    # This function is the settlement adapter's final authorization
    # gate. A cryptographically valid but expired mandate is not valid
    # authority. Treat malformed timestamps as invalid too: a verifier
    # that cannot establish the validity window must fail closed.
    for label, status in (
        ("intent", intent_expiry_status(intent, now=now)),
        ("cart", cart_expiry_status(cart, now=now)),
        ("payment", payment_expiry_status(payment, now=now)),
    ):
        if status == ExpiryStatus.EXPIRED:
            return False, f"{label}: expired"
        if status == ExpiryStatus.MALFORMED:
            return False, f"{label}: malformed validUntil"

    # ----- expensive crypto verifications -----
    ok, reason = verify_intent_mandate(intent)
    if not ok:
        return False, f"intent: {reason}"
    ok, reason = verify_cart_mandate(cart)
    if not ok:
        return False, f"cart: {reason}"
    # F-2 (4th-round) follow-up: cart_satisfies_intent now does real
    # signature verification when require_signed=True. Since gate D
    # and E above already verified, pass require_signed=False here
    # to avoid 2 redundant Ed25519 verifies. Defense in depth is
    # preserved by the structural gates (A/B/C) which fire first.
    ok, reason = cart_satisfies_intent(cart, intent, require_signed=False)
    if not ok:
        return False, f"cart vs intent: {reason}"
    ok, reason = verify_payment_mandate(payment)
    if not ok:
        return False, f"payment: {reason}"
    # V-32: pass intent= so payment_satisfies_cart re-checks issuer
    # continuity. require_signed=False since chain already verified
    # all three mandates above.
    ok, reason = payment_satisfies_cart(
        payment, cart, intent=intent, require_signed=False,
    )
    if not ok:
        return False, f"payment vs cart: {reason}"

    return True, "ok"


# ===== digest + freshness =====


def payment_mandate_digest(mandate: Dict[str, Any]) -> str:
    """SHA-256 over canonical JSON minus the proof block.

    Stable across signing.
    """
    return hashlib.sha256(canonical_json(_strip_proof(mandate))).hexdigest()


def payment_expiry_status(
    mandate: Dict[str, Any], *, now: Optional[datetime] = None,
) -> ExpiryStatus:
    """V-8: tristate expiry."""
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


def is_payment_expired(
    mandate: Dict[str, Any], *, now: Optional[datetime] = None,
) -> bool:
    """True iff validUntil has passed and the timestamp is well-formed."""
    return payment_expiry_status(mandate, now=now) == ExpiryStatus.EXPIRED


# ===== helpers =====


def _strip_proof(mandate: Dict[str, Any]) -> Dict[str, Any]:
    """V-13: centralised proof-stripping."""
    return {k: v for k, v in mandate.items() if k != "proof"}


def _verify_fail(mandate: Dict[str, Any], reason: str) -> VerifyResult:
    """V-20: structured failure log."""
    logger.info(
        "payment_mandate verify failed: %s (issuer=%s, payment_id=%s)",
        reason,
        mandate.get("issuer", "?"),
        (mandate.get("credentialSubject") or {}).get("payment_id", "?"),
    )
    return VerifyResult(False, reason)
