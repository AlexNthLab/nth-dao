"""W3C did:key encoding/decoding for Ed25519 pubkeys.

Spec: https://w3c-ccg.github.io/did-key-spec/

Wire format:

    did:key:z<base58btc(multicodec_prefix || pubkey_bytes)>

Where:
    multicodec_prefix for Ed25519-pub = 0xed 0x01  (varint-encoded 0xed)
    base58btc alphabet                = Bitcoin-style base58
    'z' multibase prefix              = "this is base58btc"

Example for the all-ones-byte test pubkey (32 × 0x01):
    did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSrEEa2NDsR9ZS6sj6kk   (illustrative)

This module provides pure stdlib encode / decode. PyNaCl is NOT required;
the encoding/decoding is just byte juggling.
"""

from __future__ import annotations

import logging
from typing import Optional, Tuple

logger = logging.getLogger("nth_dao.did_key")

# multicodec varint for Ed25519-pub = 0xed = single byte 0xed when expressed
# as a varint (the high bit is 0). Followed by 0x01 (varint version byte
# in the multicodec table). Some implementations write just 0xed 0x01 even
# though strictly the varint encoding of 0xed is 0xed 0x01 (two bytes).
MULTICODEC_ED25519_PUB = b"\xed\x01"

# Base58btc multibase prefix character.
MULTIBASE_BASE58BTC = "z"

DID_KEY_PREFIX = "did:key:"

# Bitcoin base58 alphabet.
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


class DIDKeyError(Exception):
    """Raised on malformed or unsupported did:key strings."""


# ─────────────────── base58btc ───────────────────


def _b58encode(b: bytes) -> str:
    if not b:
        return ""
    # Count leading zeros
    n_zero = 0
    for byte in b:
        if byte == 0:
            n_zero += 1
        else:
            break
    # Convert remaining bytes to int and to base58
    num = int.from_bytes(b, "big")
    out = ""
    while num > 0:
        num, rem = divmod(num, 58)
        out = _B58_ALPHABET[rem] + out
    return "1" * n_zero + out


def _b58decode(s: str) -> bytes:
    if not s:
        return b""
    n_zero = 0
    for ch in s:
        if ch == "1":
            n_zero += 1
        else:
            break
    num = 0
    for ch in s:
        if ch not in _B58_INDEX:
            raise DIDKeyError(f"invalid base58 character {ch!r}")
        num = num * 58 + _B58_INDEX[ch]
    # Number of non-zero bytes
    if num == 0:
        body = b""
    else:
        body = num.to_bytes((num.bit_length() + 7) // 8, "big")
    return b"\x00" * n_zero + body


# ─────────────────── encode / decode did:key ───────────────────


def encode_ed25519_did_key(pubkey_bytes: bytes) -> str:
    """Encode a 32-byte Ed25519 pubkey as a `did:key:z...` string per W3C spec."""
    if len(pubkey_bytes) != 32:
        raise DIDKeyError(
            f"Ed25519 pubkey must be 32 bytes; got {len(pubkey_bytes)}"
        )
    payload = MULTICODEC_ED25519_PUB + pubkey_bytes
    encoded = _b58encode(payload)
    return f"{DID_KEY_PREFIX}{MULTIBASE_BASE58BTC}{encoded}"


def encode_ed25519_did_key_hex(pubkey_hex: str) -> str:
    """Same as `encode_ed25519_did_key` but takes a hex string."""
    try:
        pubkey_bytes = bytes.fromhex(pubkey_hex)
    except ValueError as e:
        raise DIDKeyError(f"pubkey_hex not valid hex: {e}") from e
    return encode_ed25519_did_key(pubkey_bytes)


def decode_ed25519_did_key(did: str) -> bytes:
    """Decode a `did:key:z...` string back to 32-byte Ed25519 pubkey.

    Raises:
        DIDKeyError: malformed prefix, unsupported multibase, wrong multicodec,
                     or pubkey length wrong after decode.
    """
    if not did.startswith(DID_KEY_PREFIX):
        raise DIDKeyError(
            f"did string must start with {DID_KEY_PREFIX!r}; got {did!r}"
        )
    body = did[len(DID_KEY_PREFIX):]
    if not body.startswith(MULTIBASE_BASE58BTC):
        raise DIDKeyError(
            f"only base58btc multibase ('{MULTIBASE_BASE58BTC}') is supported; "
            f"got {body[:1]!r}"
        )
    encoded = body[len(MULTIBASE_BASE58BTC):]
    raw = _b58decode(encoded)
    if not raw.startswith(MULTICODEC_ED25519_PUB):
        raise DIDKeyError(
            f"multicodec prefix must be Ed25519-pub (ed01); "
            f"got {raw[:2].hex()!r}"
        )
    pubkey_bytes = raw[len(MULTICODEC_ED25519_PUB):]
    if len(pubkey_bytes) != 32:
        raise DIDKeyError(
            f"decoded pubkey must be 32 bytes; got {len(pubkey_bytes)}"
        )
    return pubkey_bytes


def decode_ed25519_did_key_hex(did: str) -> str:
    """Decode a did:key into a 64-character hex pubkey string."""
    return decode_ed25519_did_key(did).hex()


def is_did_key(s: str) -> bool:
    """True iff `s` looks like a valid did:key Ed25519 string."""
    if not isinstance(s, str):
        return False
    if not s.startswith(DID_KEY_PREFIX):
        return False
    try:
        decode_ed25519_did_key(s)
        return True
    except DIDKeyError:
        return False


def parse_did(s: str) -> Tuple[str, str]:
    """Split a DID string into (method, method_specific_id).

    For 'did:key:z6Mk...' returns ('key', 'z6Mk...').
    Raises DIDKeyError on malformed input.
    """
    if not isinstance(s, str) or not s.startswith("did:"):
        raise DIDKeyError(f"not a DID string: {s!r}")
    parts = s.split(":", 2)
    if len(parts) != 3:
        raise DIDKeyError(f"DID must have format did:<method>:<id>; got {s!r}")
    _, method, msid = parts
    if not method or not msid:
        raise DIDKeyError(f"DID method or id is empty: {s!r}")
    return method, msid
