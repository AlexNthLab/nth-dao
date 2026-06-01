"""Key recovery — export and restore Ed25519 identities via passphrase.

Background:
    A NTH DAO agent's authority comes from its Ed25519 private key. If you
    lose the `identity.json` file (disk failure, accidental rm, lost laptop),
    you lose the agent — there is no central authority to reissue it.

What this module provides:
    `export_recovery_kit(identity, password)` — wraps the private key in an
    encrypted blob suitable for offline storage (paper, USB, password
    manager).

    `import_recovery_kit(kit, password)` — restores the AgentIdentity on
    a new machine.

Cryptography:
    - Symmetric encryption: libsodium `crypto_secretbox` (XSalsa20 + Poly1305)
    - Key derivation:        libsodium `pwhash` (Argon2id) with INTERACTIVE
                             parameters (memlimit 64 MiB, opslimit 2).
                             That's ~0.5s per try on a 2024 laptop —
                             tolerable for the legitimate user, expensive
                             for an attacker brute-forcing a stolen kit.
    - Salt:                  16 random bytes per kit (`secrets.token_bytes`).
    - Nonce:                 24 random bytes per kit (`secrets.token_bytes`).

Threat model:
    - Stolen kit + correct password → attacker becomes the agent.
      Mitigation: use a strong passphrase (6 diceware words ≥ 70 bits).
    - Stolen kit + wrong password → bounded by Argon2id cost; brute force
      is ~$1M per million attempts at INTERACTIVE difficulty.
    - Kit + maintainer disappears → kit is portable, anyone with the
      password and a v0.9.4+ runtime can restore.

Future:
    - Guardian-based social recovery (v0.9.5+) — N-of-M peers signing a
      `KeyReplacement` proof, no passphrase required.
    - Hierarchical Deterministic identities (v1.0+) — derive child keys
      from a master seed à la BIP-32.

This module is OPTIONAL: it requires `pip install nth-dao[crypto]`
(PyNaCl). Without PyNaCl, importing the module raises a clear error.
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional, Union

logger = logging.getLogger("nth_dao.key_recovery")

# Version of the kit format; bump if we change wire format.
KIT_FORMAT_VERSION = 1

# Argon2id parameters — INTERACTIVE difficulty. Trade-off:
#   - too low  → recoverable by attacker with a GPU farm
#   - too high → 30-second password prompt for legitimate user
# The defaults below take ~0.5s on a 2024 mid-range laptop.
_OPSLIMIT_INTERACTIVE = 2
_MEMLIMIT_INTERACTIVE = 64 * 1024 * 1024  # 64 MiB


class KeyRecoveryError(Exception):
    """Raised on any recovery-kit format / decryption failure."""


def _require_crypto() -> None:
    try:
        import nacl.secret  # noqa: F401
        import nacl.pwhash  # noqa: F401
    except ImportError as e:
        raise ImportError(
            "key_recovery requires PyNaCl. Install with: "
            "pip install nth-dao[crypto]"
        ) from e


@dataclass
class RecoveryKit:
    """Encrypted bundle that restores an AgentIdentity given a password.

    Wire format (JSON, base64-encoded fields):

        {
            "version":   1,
            "format":    "nth-dao-recovery-v1",
            "salt":      "<base64 16-byte salt>",
            "nonce":     "<base64 24-byte nonce>",
            "ciphertext":"<base64 of crypto_secretbox(plaintext)>",
            "agent_id":  "<plaintext for UX; NOT used for decryption>",
            "label":     "<plaintext for UX>",
            "created_at":"<ISO timestamp>",
            "kdf":       "argon2id",
            "opslimit":  2,
            "memlimit":  67108864
        }

    The plaintext encrypted under `crypto_secretbox` is the JSON of:

        {
            "private_key": "<hex 32 bytes>",
            "pubkey":      "<hex 32 bytes>",
            "label":       "..."
        }

    `agent_id` and `label` outside the ciphertext are convenience metadata
    so a user can identify which kit is which without trying every password.
    They're cryptographically meaningless.
    """

    version: int
    format: str
    salt: str
    nonce: str
    ciphertext: str
    agent_id: str
    label: str
    created_at: str
    kdf: str = "argon2id"
    opslimit: int = _OPSLIMIT_INTERACTIVE
    memlimit: int = _MEMLIMIT_INTERACTIVE

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict) -> "RecoveryKit":
        if not isinstance(data, dict):
            raise KeyRecoveryError("kit must be a JSON object")
        for field_name in ("version", "format", "salt", "nonce", "ciphertext"):
            if field_name not in data:
                raise KeyRecoveryError(
                    f"recovery kit missing required field {field_name!r}"
                )
        if data["format"] != "nth-dao-recovery-v1":
            raise KeyRecoveryError(
                f"unsupported kit format: {data['format']!r}; "
                f"expected 'nth-dao-recovery-v1'"
            )
        if data["version"] != KIT_FORMAT_VERSION:
            raise KeyRecoveryError(
                f"unsupported kit version: {data['version']!r}; "
                f"expected {KIT_FORMAT_VERSION}"
            )
        return cls(
            version=int(data["version"]),
            format=data["format"],
            salt=data["salt"],
            nonce=data["nonce"],
            ciphertext=data["ciphertext"],
            agent_id=data.get("agent_id", ""),
            label=data.get("label", ""),
            created_at=data.get("created_at", ""),
            kdf=data.get("kdf", "argon2id"),
            opslimit=int(data.get("opslimit", _OPSLIMIT_INTERACTIVE)),
            memlimit=int(data.get("memlimit", _MEMLIMIT_INTERACTIVE)),
        )

    @classmethod
    def from_json(cls, blob: str) -> "RecoveryKit":
        try:
            data = json.loads(blob)
        except json.JSONDecodeError as e:
            raise KeyRecoveryError(f"recovery kit is not valid JSON: {e}") from e
        return cls.from_dict(data)


def export_recovery_kit(
    identity,
    password: str,
    *,
    opslimit: int = _OPSLIMIT_INTERACTIVE,
    memlimit: int = _MEMLIMIT_INTERACTIVE,
) -> RecoveryKit:
    """Encrypt an AgentIdentity into a portable recovery kit.

    Args:
        identity: an `AgentIdentity` with a signing key (i.e. `can_sign=True`).
                  Plain (non-crypto) identities have nothing to recover; this
                  raises ValueError.
        password: passphrase. SHOULD be ≥ 6 words of diceware (≈ 70 bits).
                  This is not enforced; we trust the caller.
        opslimit/memlimit: Argon2id parameters. Override only if you know
                  what you're doing — higher values = slower attacks AND
                  slower legitimate restore.

    Returns:
        RecoveryKit — call `.to_json()` for a string you can store.

    Raises:
        ImportError: PyNaCl not installed.
        ValueError:  identity has no signing key; password is empty.
    """
    _require_crypto()
    import nacl.pwhash
    import nacl.secret
    import nacl.utils

    if not getattr(identity, "can_sign", False):
        raise ValueError(
            "export_recovery_kit requires a signing-capable identity"
        )
    if not password:
        raise ValueError("password must not be empty")

    # Plaintext = JSON of the private key + companion metadata
    plaintext = json.dumps({
        "private_key": identity._signing_key.hex(),
        "pubkey":      identity.pubkey_hex,
        "label":       identity.label,
    }, ensure_ascii=False).encode("utf-8")

    salt = secrets.token_bytes(nacl.pwhash.argon2id.SALTBYTES)
    nonce = secrets.token_bytes(nacl.secret.SecretBox.NONCE_SIZE)

    # Derive a 32-byte key from password
    key = nacl.pwhash.argon2id.kdf(
        nacl.secret.SecretBox.KEY_SIZE,
        password.encode("utf-8"),
        salt,
        opslimit=opslimit,
        memlimit=memlimit,
    )
    box = nacl.secret.SecretBox(key)
    ciphertext = box.encrypt(plaintext, nonce).ciphertext

    from datetime import datetime
    return RecoveryKit(
        version=KIT_FORMAT_VERSION,
        format="nth-dao-recovery-v1",
        salt=base64.b64encode(salt).decode("ascii"),
        nonce=base64.b64encode(nonce).decode("ascii"),
        ciphertext=base64.b64encode(ciphertext).decode("ascii"),
        agent_id=str(identity.agent_id),
        label=identity.label,
        created_at=datetime.now().isoformat(),
        kdf="argon2id",
        opslimit=int(opslimit),
        memlimit=int(memlimit),
    )


def import_recovery_kit(
    kit: Union[RecoveryKit, dict, str],
    password: str,
    *,
    opslimit: Optional[int] = None,
    memlimit: Optional[int] = None,
):
    """Decrypt a recovery kit back into a usable AgentIdentity.

    Args:
        kit: a RecoveryKit, its JSON dict form, or a raw JSON string.
        password: the same password used at export time.
        opslimit/memlimit: must match the export-time values. Defaults match
                  `export_recovery_kit` defaults.

    Returns:
        A fresh AgentIdentity with the original private + public keys.

    Raises:
        ImportError:         PyNaCl not installed.
        KeyRecoveryError:    kit format invalid, OR password is wrong.
                             We do NOT distinguish those two failures to
                             avoid leaking which kits exist on a server.
    """
    _require_crypto()
    import nacl.exceptions
    import nacl.pwhash
    import nacl.secret

    if isinstance(kit, dict):
        kit_obj = RecoveryKit.from_dict(kit)
    elif isinstance(kit, str):
        kit_obj = RecoveryKit.from_json(kit)
    elif isinstance(kit, RecoveryKit):
        kit_obj = kit
    else:
        raise TypeError(f"kit must be RecoveryKit, dict, or str; got {type(kit)}")

    if not password:
        raise KeyRecoveryError("password must not be empty")
    if kit_obj.kdf != "argon2id":
        raise KeyRecoveryError(f"unsupported recovery kit kdf: {kit_obj.kdf!r}")
    if opslimit is None:
        opslimit = kit_obj.opslimit
    if memlimit is None:
        memlimit = kit_obj.memlimit

    try:
        salt = base64.b64decode(kit_obj.salt)
        nonce = base64.b64decode(kit_obj.nonce)
        ciphertext = base64.b64decode(kit_obj.ciphertext)
    except (ValueError, TypeError) as e:
        raise KeyRecoveryError(f"kit has malformed base64: {e}") from e

    try:
        key = nacl.pwhash.argon2id.kdf(
            nacl.secret.SecretBox.KEY_SIZE,
            password.encode("utf-8"),
            salt,
            opslimit=opslimit,
            memlimit=memlimit,
        )
    except Exception as e:
        # kdf can fail on extremely large memlimit on tiny VMs
        raise KeyRecoveryError(f"key derivation failed: {e}") from e

    box = nacl.secret.SecretBox(key)
    try:
        plaintext = box.decrypt(ciphertext, nonce)
    except nacl.exceptions.CryptoError as e:
        # Wrong password OR corrupted ciphertext
        raise KeyRecoveryError(
            "recovery kit decryption failed (wrong password, or kit corrupted)"
        ) from e

    try:
        data = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise KeyRecoveryError(f"decrypted plaintext is not valid JSON: {e}") from e

    # Reconstitute an AgentIdentity from the decrypted material
    from .identity import AgentID, AgentIdentity, _SigningKey

    try:
        signing_bytes = bytes.fromhex(data["private_key"])
        verify_bytes = bytes.fromhex(data["pubkey"])
    except (KeyError, ValueError) as e:
        raise KeyRecoveryError(f"decrypted plaintext missing keys: {e}") from e

    # Sanity check the keypair (same check identity.load() does)
    assert _SigningKey is not None
    derived = _SigningKey(signing_bytes).verify_key.encode()
    if derived != verify_bytes:
        raise KeyRecoveryError(
            "decrypted keypair mismatch — kit is tampered or corrupted"
        )

    return AgentIdentity(
        agent_id=AgentID.from_pubkey(data["pubkey"]),
        label=data.get("label", ""),
        metadata={},
        _signing_key=signing_bytes,
        _verify_key=verify_bytes,
    )
