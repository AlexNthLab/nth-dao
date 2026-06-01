"""v0.9.4 — Key recovery via passphrase-protected kits."""

import json

import pytest

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.key_recovery import (
    KIT_FORMAT_VERSION,
    KeyRecoveryError,
    RecoveryKit,
    export_recovery_kit,
    import_recovery_kit,
)


pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="PyNaCl required for key recovery"
)

# Argon2id at INTERACTIVE difficulty is ~0.5s per try; tests run a handful.
# Override with lower limits to keep CI snappy.
_TEST_OPSLIMIT = 2
_TEST_MEMLIMIT = 8 * 1024 * 1024   # 8 MiB — well below INTERACTIVE default


def _kdf_kwargs():
    return dict(opslimit=_TEST_OPSLIMIT, memlimit=_TEST_MEMLIMIT)


def test_export_round_trip_restores_keypair():
    ident = AgentIdentity.generate(label="alice")
    kit = export_recovery_kit(ident, password="correct horse battery staple",
                              **_kdf_kwargs())
    restored = import_recovery_kit(
        kit, password="correct horse battery staple", **_kdf_kwargs(),
    )
    # Same pubkey + same agent_id derived from it
    assert restored.pubkey_hex == ident.pubkey_hex
    assert str(restored.agent_id) == str(ident.agent_id)
    assert restored.can_sign
    # Round-trip sanity: signature made by restored verifies under original pubkey
    msg = b"test message"
    sig = restored.sign(msg)
    assert ident.verify(msg, sig)


def test_import_uses_kdf_parameters_stored_in_kit():
    ident = AgentIdentity.generate(label="alice")
    kit = export_recovery_kit(
        ident,
        password="correct horse battery staple",
        **_kdf_kwargs(),
    )
    assert kit.opslimit == _TEST_OPSLIMIT
    assert kit.memlimit == _TEST_MEMLIMIT
    restored = import_recovery_kit(kit, password="correct horse battery staple")
    assert restored.pubkey_hex == ident.pubkey_hex


def test_export_returns_kit_with_v1_format_and_metadata():
    ident = AgentIdentity.generate(label="alice's laptop")
    kit = export_recovery_kit(ident, password="x" * 30, **_kdf_kwargs())
    assert kit.version == KIT_FORMAT_VERSION
    assert kit.format == "nth-dao-recovery-v1"
    assert kit.agent_id == str(ident.agent_id)
    assert kit.label == "alice's laptop"
    assert kit.created_at
    # Salt and nonce are random — different kits get different ones
    kit2 = export_recovery_kit(ident, password="x" * 30, **_kdf_kwargs())
    assert kit.salt != kit2.salt
    assert kit.nonce != kit2.nonce


def test_kit_serializes_to_and_from_json():
    ident = AgentIdentity.generate(label="alice")
    kit = export_recovery_kit(ident, password="passphrase", **_kdf_kwargs())
    blob = kit.to_json()
    assert blob.strip().startswith("{")
    reloaded = RecoveryKit.from_json(blob)
    assert reloaded.salt == kit.salt
    assert reloaded.ciphertext == kit.ciphertext


def test_wrong_password_raises_recovery_error():
    ident = AgentIdentity.generate(label="alice")
    kit = export_recovery_kit(ident, password="correct", **_kdf_kwargs())
    with pytest.raises(KeyRecoveryError, match="decryption failed"):
        import_recovery_kit(kit, password="wrong", **_kdf_kwargs())


def test_empty_password_rejected_on_export_and_import():
    ident = AgentIdentity.generate(label="alice")
    with pytest.raises(ValueError, match="empty"):
        export_recovery_kit(ident, password="")
    kit = export_recovery_kit(ident, password="ok", **_kdf_kwargs())
    with pytest.raises(KeyRecoveryError, match="empty"):
        import_recovery_kit(kit, password="", **_kdf_kwargs())


def test_plain_identity_cannot_export():
    """Non-crypto identity has no signing key — nothing to recover."""
    plain = AgentIdentity.from_string("bob")
    with pytest.raises(ValueError, match="signing-capable"):
        export_recovery_kit(plain, password="anything")


def test_import_rejects_unsupported_format():
    bad = {
        "version":  1,
        "format":   "some-other-vendor-v1",  # wrong format
        "salt":     "AAAA",
        "nonce":    "AAAA",
        "ciphertext": "AAAA",
    }
    with pytest.raises(KeyRecoveryError, match="format"):
        import_recovery_kit(bad, password="x")


def test_import_rejects_unsupported_version():
    bad = {
        "version":  99,                  # future version
        "format":   "nth-dao-recovery-v1",
        "salt":     "AAAA",
        "nonce":    "AAAA",
        "ciphertext": "AAAA",
    }
    with pytest.raises(KeyRecoveryError, match="version"):
        import_recovery_kit(bad, password="x")


def test_import_rejects_missing_required_field():
    incomplete = {
        "version": 1,
        "format": "nth-dao-recovery-v1",
        "salt": "AAAA",
        # missing nonce and ciphertext
    }
    with pytest.raises(KeyRecoveryError, match="missing"):
        import_recovery_kit(incomplete, password="x")


def test_import_rejects_malformed_base64():
    bad = {
        "version":  1,
        "format":   "nth-dao-recovery-v1",
        "salt":     "not-base64-!@#$%",
        "nonce":    "AAAA",
        "ciphertext": "AAAA",
    }
    with pytest.raises(KeyRecoveryError):
        import_recovery_kit(bad, password="x")


def test_import_accepts_raw_json_string():
    ident = AgentIdentity.generate(label="alice")
    kit = export_recovery_kit(ident, password="pw", **_kdf_kwargs())
    blob = kit.to_json()
    restored = import_recovery_kit(blob, password="pw", **_kdf_kwargs())
    assert restored.pubkey_hex == ident.pubkey_hex


def test_kit_payload_does_not_leak_private_key_in_plaintext():
    """Outer JSON must not contain the hex private key — only inner ciphertext does."""
    ident = AgentIdentity.generate(label="alice")
    kit = export_recovery_kit(ident, password="pw", **_kdf_kwargs())
    blob = kit.to_json()
    assert ident._signing_key.hex() not in blob


def test_tampered_ciphertext_fails_decryption():
    ident = AgentIdentity.generate(label="alice")
    kit = export_recovery_kit(ident, password="pw", **_kdf_kwargs())
    # Flip a byte in the ciphertext
    import base64
    ct = bytearray(base64.b64decode(kit.ciphertext))
    ct[0] ^= 0x01
    kit.ciphertext = base64.b64encode(bytes(ct)).decode("ascii")
    with pytest.raises(KeyRecoveryError):
        import_recovery_kit(kit, password="pw", **_kdf_kwargs())


def test_facade_exports_key_recovery():
    import nth_dao as nth
    assert nth.export_recovery_kit is export_recovery_kit
    assert nth.import_recovery_kit is import_recovery_kit
    assert nth.RecoveryKit is RecoveryKit
    assert nth.KeyRecoveryError is KeyRecoveryError
