"""Shared cryptographic primitives for signed NTH trade documents."""

from __future__ import annotations

import copy
from typing import Any

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.did_key import DIDKeyError, decode_ed25519_did_key
from nth_dao.trade_rules.canonical import TradeCanonicalJSONError, trade_canonical_json

try:
    from nacl.exceptions import BadSignatureError as _BadSignatureError
    from nacl.signing import VerifyKey as _VerifyKey
except ImportError:  # pragma: no cover - depends on optional crypto extra
    _BadSignatureError = ValueError  # type: ignore[assignment,misc]
    _VerifyKey = None  # type: ignore[assignment]


class TradeProofError(ValueError):
    """Raised when shared proof material is malformed."""


def verification_method_for_did(did: str) -> str:
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        raise TradeProofError("publisher DID is not a did:key")
    return f"{did}#{did[len('did:key:'):]}"


def decode_canonical_ed25519_signature(value: Any) -> bytes:
    if not isinstance(value, str) or len(value) != 86:
        raise TradeProofError("proof value is not an Ed25519 signature")
    try:
        signature = b64u_decode(value)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise TradeProofError("proof value is not canonical base64url") from exc
    if len(signature) != 64 or b64u_encode(signature) != value:
        raise TradeProofError("proof value is not a canonical Ed25519 signature")
    return signature


def encode_ed25519_signature(value: bytes) -> str:
    if not isinstance(value, bytes) or len(value) != 64:
        raise TradeProofError("Ed25519 signature must contain 64 bytes")
    return b64u_encode(value)


def signed_document_input(
    domain: bytes,
    document: dict[str, Any],
) -> bytes:
    if not isinstance(domain, bytes) or not domain or b"\x00" in domain:
        raise TradeProofError("signature domain is invalid")
    body = copy.deepcopy(document)
    proof = body.get("proof")
    if not isinstance(proof, dict) or "proof_value" not in proof:
        raise TradeProofError("document proof is incomplete")
    proof = dict(proof)
    proof.pop("proof_value")
    body["proof"] = proof
    try:
        canonical = trade_canonical_json(body)
    except TradeCanonicalJSONError as exc:
        raise TradeProofError(str(exc)) from exc
    return domain + b"\x00" + canonical


def verify_ed25519_did_signature(
    *,
    publisher_did: str,
    proof_value: Any,
    signing_input: bytes,
) -> tuple[bool, str]:
    if _VerifyKey is None:
        return False, "crypto unavailable"
    try:
        signature = decode_canonical_ed25519_signature(proof_value)
        pubkey = decode_ed25519_did_key(publisher_did)
        _VerifyKey(pubkey).verify(signing_input, signature)
    except (
        _BadSignatureError,
        DIDKeyError,
        TradeProofError,
        TypeError,
        ValueError,
        UnicodeError,
    ):
        return False, "signature invalid"
    return True, "ok"


__all__ = [
    "TradeProofError",
    "decode_canonical_ed25519_signature",
    "encode_ed25519_signature",
    "signed_document_input",
    "verification_method_for_did",
    "verify_ed25519_did_signature",
]
