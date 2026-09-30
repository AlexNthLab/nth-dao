"""Courier envelope — sealed X25519 delivery for store-and-carry transport.

Design doc §9: "Courier 是 transport 的一种，不是新的信任域。Courier 只携带
不透明密文". A sealed courier envelope encrypts the signed delivery envelope
to the recipient's X25519 public key (derived from their Ed25519 identity via
the standard conversion), so a courier — USB carrier, foreign node, untrusted
share — can carry it without being able to read, tamper with, or forge it.

Wire contract (v1):

* ``ciphertext``  — PyNaCl SealedBox (X25519 + XSalsa20-Poly1305) over the
  canonical envelope JSON; anonymous sender (no sender identity in the box,
  by design — the inner envelope carries the author signature).
* ``recipient_did`` — the claimed recipient (plaintext, so any carrier can
  route); receivers must verify it matches their own DID before opening.
* ``courier_id``  — carrier-specific opaque label for tracing.
* ``integrity``   — SHA-256 of the ciphertext so trivial corruption is
  rejected before decryption.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import time
from typing import Any

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.envelope import (
    MAX_ENVELOPE_BYTES,
    TransportEnvelope,
    TransportEnvelopeRejected,
    validate_envelope,
)
from nth_dao.did_key import decode_ed25519_did_key_hex, is_did_key

logger = logging.getLogger("nth_dao.courier")

COURIER_PROTOCOL = "nth-courier-envelope"
COURIER_VERSION = 1
COURIER_FIELDS = (
    "protocol",
    "version",
    "recipient_did",
    "courier_id",
    "ciphertext",
    "integrity",
)
COURIER_ID_MAX = 128
SEALED_BOX_OVERHEAD_BYTES = 48
MAX_COURIER_CIPHERTEXT_BYTES = MAX_ENVELOPE_BYTES + SEALED_BOX_OVERHEAD_BYTES
MAX_COURIER_CIPHERTEXT_CHARS = ((MAX_COURIER_CIPHERTEXT_BYTES + 2) // 3) * 4
_B64U_RE = re.compile(r"\A[A-Za-z0-9_-]+\Z")
_INTEGRITY_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")

try:  # pragma: no cover - exercised via importorskip in tests
    from nacl.public import PrivateKey as _PrivateKey
    from nacl.public import PublicKey as _PublicKey
    from nacl.public import SealedBox as _SealedBox

    _NACL_PUBLIC_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PrivateKey = None  # type: ignore[assignment,misc]
    _PublicKey = None  # type: ignore[assignment,misc]
    _SealedBox = None  # type: ignore[assignment,misc]
    _NACL_PUBLIC_AVAILABLE = False


class CourierEnvelopeRejected(ValueError):
    """Raised when a courier envelope cannot be sealed or opened."""


def _require_crypto() -> None:
    if not _NACL_PUBLIC_AVAILABLE:
        raise CourierEnvelopeRejected(
            "courier encryption requires the optional nth-dao[crypto] dependency"
        )


def _validate_courier_id(courier_id: Any) -> str:
    if not isinstance(courier_id, str):
        raise CourierEnvelopeRejected("courier_id must be a string")
    if len(courier_id) > COURIER_ID_MAX:
        raise CourierEnvelopeRejected("courier_id exceeds 128 chars")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in courier_id):
        raise CourierEnvelopeRejected("courier_id must not contain control characters")
    return courier_id


def validate_courier_wire(
    courier: Any,
    *,
    recipient_did: str | None = None,
) -> bytes:
    """Validate one courier wire object and return decoded ciphertext.

    This is deliberately usable by an untrusted carrier before storage; it
    performs no decryption and exposes no recipient secret.
    """

    if not isinstance(courier, dict) or frozenset(courier) != frozenset(COURIER_FIELDS):
        raise CourierEnvelopeRejected("courier envelope has missing or unknown fields")
    if courier.get("protocol") != COURIER_PROTOCOL:
        raise CourierEnvelopeRejected("wrong courier protocol")
    version = courier.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version != COURIER_VERSION:
        raise CourierEnvelopeRejected("unsupported courier version")
    claimed_recipient = courier.get("recipient_did")
    if not isinstance(claimed_recipient, str) or not is_did_key(claimed_recipient):
        raise CourierEnvelopeRejected("recipient_did must be a did:key")
    if recipient_did is not None and claimed_recipient != recipient_did:
        raise CourierEnvelopeRejected("courier claims a different recipient")
    _validate_courier_id(courier.get("courier_id"))
    encoded_ciphertext = courier.get("ciphertext")
    if not isinstance(encoded_ciphertext, str) or not encoded_ciphertext:
        raise CourierEnvelopeRejected("ciphertext must be non-empty base64url text")
    if len(encoded_ciphertext) > MAX_COURIER_CIPHERTEXT_CHARS:
        raise CourierEnvelopeRejected("ciphertext exceeds the wire limit")
    if _B64U_RE.fullmatch(encoded_ciphertext) is None:
        raise CourierEnvelopeRejected("ciphertext is not canonical base64url")
    integrity = courier.get("integrity")
    if not isinstance(integrity, str) or _INTEGRITY_RE.fullmatch(integrity) is None:
        raise CourierEnvelopeRejected("integrity must be a sha256 digest")
    try:
        ciphertext = b64u_decode(encoded_ciphertext)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CourierEnvelopeRejected("ciphertext is not canonical base64url") from exc
    if len(ciphertext) > MAX_COURIER_CIPHERTEXT_BYTES:
        raise CourierEnvelopeRejected("decoded ciphertext exceeds the wire limit")
    expected_integrity = "sha256:" + hashlib.sha256(ciphertext).hexdigest()
    if not hmac.compare_digest(integrity, expected_integrity):
        raise CourierEnvelopeRejected("ciphertext integrity check failed")
    return ciphertext


def x25519_public_from_did(did: str) -> bytes:
    """Derive the X25519 public key from an Ed25519 did:key using the
    libsodium RFC 7748 conversion (crypto_sign_ed25519_pk_to_curve25519)."""

    _require_crypto()
    if not is_did_key(did):
        raise CourierEnvelopeRejected("recipient DID is not a did:key")
    try:
        ed25519_pub = bytes.fromhex(decode_ed25519_did_key_hex(did))
    except (ValueError, TypeError) as exc:
        raise CourierEnvelopeRejected(f"recipient DID undecodable: {exc}") from exc
    if len(ed25519_pub) != 32:
        raise CourierEnvelopeRejected("recipient pubkey must be 32 bytes")
    from nacl.bindings import crypto_sign_ed25519_pk_to_curve25519

    return crypto_sign_ed25519_pk_to_curve25519(ed25519_pub)


def x25519_private_from_ed25519(ed25519_secret: bytes) -> bytes:
    """Derive the X25519 private key from an Ed25519 secret (libsodium
    crypto_sign_ed25519_sk_to_curve25519 requires the 64-byte form:
    seed || pubkey)."""

    _require_crypto()
    from nacl.bindings import crypto_sign_ed25519_sk_to_curve25519
    from nacl.signing import SigningKey

    if len(ed25519_secret) == 32:
        # seed-only form: libsodium needs seed || pubkey (64 bytes)
        signing = SigningKey(ed25519_secret)
        ed25519_secret = ed25519_secret + bytes(signing.verify_key)
    if len(ed25519_secret) != 64:
        raise CourierEnvelopeRejected("ed25519 secret must be 32 (seed) or 64 bytes")
    return crypto_sign_ed25519_sk_to_curve25519(ed25519_secret)


def seal_courier_envelope(
    envelope: TransportEnvelope,
    *,
    recipient_did: str,
    courier_id: str = "",
) -> dict[str, Any]:
    """Seal one signed envelope for a recipient. Anonymous sender by design."""

    _require_crypto()
    ok, reason = validate_envelope(envelope, require_signature=True)
    if not ok:
        raise TransportEnvelopeRejected(reason)
    if not is_did_key(recipient_did):
        raise CourierEnvelopeRejected("recipient_did must be a did:key")
    _validate_courier_id(courier_id)
    content = canonical_json(envelope.to_dict())
    if len(content) > MAX_ENVELOPE_BYTES:
        raise TransportEnvelopeRejected("envelope exceeds the wire byte limit")
    recipient_x25519 = x25519_public_from_did(recipient_did)
    ciphertext = _SealedBox(_PublicKey(recipient_x25519)).encrypt(content)
    return {
        "protocol": COURIER_PROTOCOL,
        "version": COURIER_VERSION,
        "recipient_did": recipient_did,
        "courier_id": courier_id,
        "ciphertext": b64u_encode(ciphertext),
        "integrity": "sha256:" + hashlib.sha256(ciphertext).hexdigest(),
    }


def open_courier_envelope(
    courier: dict[str, Any],
    *,
    recipient_did: str,
    identity_private: Any,
    now_ms: int | None = None,
) -> TransportEnvelope:
    """Open one courier envelope as the named recipient (fail closed).

    ``identity_private`` is a PyNaCl ``PrivateKey`` (X25519). The claimed
    recipient DID must match, the integrity digest must bind the ciphertext,
    and the decrypted envelope must carry a valid author signature and pass
    all delivery-layer checks before it is returned.
    """

    _require_crypto()
    ciphertext = validate_courier_wire(courier, recipient_did=recipient_did)
    recipient_x25519 = x25519_public_from_did(recipient_did)
    # identity_private: the NTH Ed25519 signing key (nacl.signing.SigningKey
    # or its raw 32-byte seed). The X25519 decryption key is derived via the
    # libsodium RFC 7748 conversion so recipients use ONE key pair.
    try:
        from nacl.signing import SigningKey as _SigningKey

        if isinstance(identity_private, _SigningKey):
            ed_secret = bytes(identity_private)
        elif isinstance(identity_private, bytes) and len(identity_private) in (32, 64):
            ed_secret = identity_private
        else:
            raise CourierEnvelopeRejected(
                "identity_private must be a nacl.signing.SigningKey or a 32/64-byte "
                "Ed25519 seed"
            )
        from nacl.public import PrivateKey as _XPrivateKey

        x25519_secret = x25519_private_from_ed25519(ed_secret)
        x25519_key = _XPrivateKey(x25519_secret)
        if bytes(x25519_key.public_key) != recipient_x25519:
            raise CourierEnvelopeRejected(
                "the provided private key does not match the recipient DID"
            )
    except CourierEnvelopeRejected:
        raise
    except Exception as exc:
        raise CourierEnvelopeRejected(f"key derivation failed: {exc}") from exc
    try:
        content = _SealedBox(x25519_key).decrypt(ciphertext)
    except Exception as exc:
        raise CourierEnvelopeRejected(f"decryption failed: {exc}") from exc
    try:
        import json

        parsed = json.loads(content.decode("utf-8"))
        envelope = TransportEnvelope.from_dict(parsed)
    except (
        ImportError,
        ValueError,
        TypeError,
        UnicodeDecodeError,
        TransportEnvelopeRejected,
    ) as exc:
        raise CourierEnvelopeRejected(f"decrypted content is not an envelope: {exc}") from exc
    validation_time = int(time.time() * 1000) if now_ms is None else now_ms
    ok, reason = validate_envelope(envelope, now_ms=validation_time)
    if not ok:
        raise CourierEnvelopeRejected(f"decrypted envelope invalid: {reason}")
    return envelope


def courier_envelope_digest(courier: dict[str, Any]) -> str:
    """Content digest over the courier envelope's canonical bytes."""

    return "sha256:" + hashlib.sha256(canonical_json(courier)).hexdigest()


__all__ = [
    "COURIER_FIELDS",
    "COURIER_PROTOCOL",
    "COURIER_VERSION",
    "CourierEnvelopeRejected",
    "courier_envelope_digest",
    "open_courier_envelope",
    "seal_courier_envelope",
    "validate_courier_wire",
    "x25519_public_from_did",
]
