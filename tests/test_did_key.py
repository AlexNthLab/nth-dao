"""v0.9.5 — W3C did:key encoding/decoding tests."""

import pytest

from nth_dao.did_key import (
    DIDKeyError,
    decode_ed25519_did_key,
    decode_ed25519_did_key_hex,
    encode_ed25519_did_key,
    encode_ed25519_did_key_hex,
    is_did_key,
    parse_did,
)
from nth_dao.identity import AgentIdentity, crypto_available


# ─────────────────── encode / decode round-trip ───────────────────


def test_encode_returns_did_key_prefix():
    pubkey = b"\x00" * 32
    s = encode_ed25519_did_key(pubkey)
    assert s.startswith("did:key:z")


def test_round_trip_zero_pubkey():
    pubkey = b"\x00" * 32
    s = encode_ed25519_did_key(pubkey)
    decoded = decode_ed25519_did_key(s)
    assert decoded == pubkey


def test_round_trip_random_pubkey():
    pubkey = bytes(range(32))
    s = encode_ed25519_did_key(pubkey)
    decoded = decode_ed25519_did_key(s)
    assert decoded == pubkey


def test_round_trip_hex_form():
    hexkey = "00" * 32
    s = encode_ed25519_did_key_hex(hexkey)
    assert decode_ed25519_did_key_hex(s) == hexkey


def test_encode_rejects_wrong_pubkey_length():
    with pytest.raises(DIDKeyError, match="32 bytes"):
        encode_ed25519_did_key(b"\x00" * 31)
    with pytest.raises(DIDKeyError, match="32 bytes"):
        encode_ed25519_did_key(b"\x00" * 33)


def test_encode_hex_rejects_non_hex():
    with pytest.raises(DIDKeyError):
        encode_ed25519_did_key_hex("not-hex!")


# ─────────────────── decode error paths ───────────────────


def test_decode_rejects_wrong_did_prefix():
    with pytest.raises(DIDKeyError, match="must start with"):
        decode_ed25519_did_key("did:web:example.com")


def test_decode_rejects_unsupported_multibase():
    # 'm' is base64; we only support 'z' base58btc
    with pytest.raises(DIDKeyError, match="base58btc"):
        decode_ed25519_did_key("did:key:mABCDEF")


def test_decode_rejects_wrong_multicodec():
    # Build a did:key with the WRONG multicodec prefix (e.g., secp256k1 0xe7)
    from nth_dao.did_key import _b58encode
    bogus = b"\xe7\x01" + (b"\x00" * 32)
    bad_did = "did:key:z" + _b58encode(bogus)
    with pytest.raises(DIDKeyError, match="multicodec"):
        decode_ed25519_did_key(bad_did)


def test_decode_rejects_short_pubkey():
    from nth_dao.did_key import _b58encode
    # Right multicodec but only 16 bytes of pubkey
    short = b"\xed\x01" + (b"\x00" * 16)
    bad_did = "did:key:z" + _b58encode(short)
    with pytest.raises(DIDKeyError, match="32 bytes"):
        decode_ed25519_did_key(bad_did)


def test_is_did_key_recognizes_valid():
    valid = encode_ed25519_did_key(b"\x00" * 32)
    assert is_did_key(valid)


def test_is_did_key_rejects_invalid():
    assert not is_did_key("did:web:example")
    assert not is_did_key("did:key:m_garbage")
    assert not is_did_key("not a did at all")
    assert not is_did_key(None)
    assert not is_did_key(123)


# ─────────────────── parse_did ───────────────────


def test_parse_did_returns_method_and_id():
    method, msid = parse_did("did:key:z6MkXYZ")
    assert method == "key"
    assert msid == "z6MkXYZ"


def test_parse_did_rejects_non_did():
    with pytest.raises(DIDKeyError):
        parse_did("https://example.com/")
    with pytest.raises(DIDKeyError):
        parse_did("did:key")     # missing msid
    with pytest.raises(DIDKeyError):
        parse_did(":key:abc")    # missing scheme


# ─────────────────── AgentIdentity integration ───────────────────


@pytest.mark.skipif(not crypto_available(), reason="PyNaCl required")
def test_agent_identity_as_did_round_trip():
    ident = AgentIdentity.generate(label="alice")
    did = ident.as_did()
    assert did.startswith("did:key:z")
    # from_did rebuilds a verify-only identity with the same pubkey
    restored = AgentIdentity.from_did(did)
    assert restored.pubkey_hex == ident.pubkey_hex
    assert not restored.can_sign  # verify-only by design
    # And a signature made by the original verifies through the restored
    msg = b"hello"
    sig = ident.sign(msg)
    assert restored.verify(msg, sig)


@pytest.mark.skipif(not crypto_available(), reason="PyNaCl required")
def test_agent_identity_plain_cannot_as_did():
    plain = AgentIdentity.from_string("alice")
    with pytest.raises(ValueError, match="cryptographic"):
        plain.as_did()


@pytest.mark.skipif(not crypto_available(), reason="PyNaCl required")
def test_template_publisher_did_is_real_did_key(tmp_path):
    """v0.9.5 upgrade: publisher_did MUST be a parseable did:key, not a placeholder."""
    from nth_dao.orchestration import MissionStore, mint_template, IOField
    alice = AgentIdentity.generate(label="alice")
    t = mint_template(
        alice, template_id="t", version="1.0.0", name="t",
        inputs={"x": IOField(type="string", required=False, description="x")},
    )
    assert is_did_key(t.publisher_did)
    # Re-decoded pubkey matches what alice's identity holds
    assert decode_ed25519_did_key_hex(t.publisher_did) == alice.pubkey_hex


# ─────────────────── facade ───────────────────


def test_facade_exports_did_key_symbols():
    import nth_dao as nth
    assert nth.encode_ed25519_did_key is encode_ed25519_did_key
    assert nth.decode_ed25519_did_key is decode_ed25519_did_key
    assert nth.is_did_key is is_did_key
    assert nth.DIDKeyError is DIDKeyError
