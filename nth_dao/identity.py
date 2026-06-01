"""
Agent identity primitives for NTH DAO.

The identity layer gives an agent a stable local profile and, when PyNaCl is
installed, an Ed25519 keypair for signing future agent-to-agent messages. The
core package keeps PyNaCl optional so the stdlib-only default install continues
to work.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Union

logger = logging.getLogger("nth_dao.identity")


DEFAULT_IDENTITY_DIR = ".nth"
DEFAULT_IDENTITY_FILE = "identity.json"
AGENT_ID_SHORT_LEN = 12

_NACL_AVAILABLE = False
_SigningKey = None
_VerifyKey = None

try:
    from nacl.signing import SigningKey as _NaclSigningKey
    from nacl.signing import VerifyKey as _NaclVerifyKey

    _NACL_AVAILABLE = True
    _SigningKey = _NaclSigningKey
    _VerifyKey = _NaclVerifyKey
except ImportError:
    pass


def crypto_available() -> bool:
    return _NACL_AVAILABLE


def _require_crypto(feature: str) -> None:
    if not _NACL_AVAILABLE:
        raise ImportError(
            f"{feature} requires PyNaCl. Install with "
            "'pip install nth-dao[crypto]' or 'pip install pynacl>=1.5'."
        )


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class AgentID:
    """Stable agent identifier.

    Plain IDs preserve current behavior. Cryptographic IDs are derived from an
    Ed25519 public key fingerprint.
    """

    value: str
    is_cryptographic: bool = False
    pubkey_hex: str = ""

    def __str__(self) -> str:
        return self.value

    @property
    def short(self) -> str:
        return self.value[:8]

    @property
    def is_plain(self) -> bool:
        return not self.is_cryptographic

    @classmethod
    def from_string(cls, agent_id: str) -> "AgentID":
        if not agent_id:
            raise ValueError("agent_id must not be empty")
        return cls(value=agent_id, is_cryptographic=False)

    @classmethod
    def from_pubkey(cls, pubkey_hex: str) -> "AgentID":
        if not pubkey_hex:
            raise ValueError("pubkey_hex must not be empty")
        fingerprint = hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()
        return cls(
            value=fingerprint[:AGENT_ID_SHORT_LEN],
            is_cryptographic=True,
            pubkey_hex=pubkey_hex,
        )


@dataclass
class AgentIdentity:
    """Agent profile plus optional Ed25519 signing material."""

    agent_id: AgentID
    label: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    _signing_key: Optional[bytes] = field(default=None, repr=False)
    _verify_key: Optional[bytes] = field(default=None, repr=False)

    @classmethod
    def from_string(
        cls,
        agent_id: str,
        label: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "AgentIdentity":
        return cls(
            agent_id=AgentID.from_string(agent_id),
            label=label,
            metadata=metadata or {},
        )

    # ─── v0.9.5: W3C did:key standard alignment ───

    def as_did(self) -> str:
        """Return the W3C did:key string for this identity's pubkey.

        Spec: https://w3c-ccg.github.io/did-key-spec/

        For cryptographic identities, this is `did:key:z<base58btc(0xed01 || pubkey)>`.
        For plain identities (no pubkey), raises ValueError — plain agent_ids
        do not have a did:key representation.
        """
        if not self.pubkey_hex:
            raise ValueError(
                "as_did() requires a cryptographic identity; "
                "plain agent_ids have no did:key form"
            )
        from .did_key import encode_ed25519_did_key_hex
        return encode_ed25519_did_key_hex(self.pubkey_hex)

    @classmethod
    def from_did(
        cls,
        did: str,
        label: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "AgentIdentity":
        """Construct a verify-only AgentIdentity from a W3C did:key string.

        The resulting identity has `can_sign=False` — you can verify signatures
        made by this DID but not sign new ones. Use `AgentIdentity.generate()`
        for a signing-capable identity.
        """
        from .did_key import decode_ed25519_did_key
        pubkey_bytes = decode_ed25519_did_key(did)
        return cls(
            agent_id=AgentID.from_pubkey(pubkey_bytes.hex()),
            label=label,
            metadata=metadata or {},
            _signing_key=None,
            _verify_key=pubkey_bytes,
        )

    @classmethod
    def generate(
        cls,
        save_path: Optional[Union[str, Path]] = None,
        label: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "AgentIdentity":
        _require_crypto("AgentIdentity.generate()")
        assert _SigningKey is not None

        signing_key = _SigningKey.generate()
        verify_key = signing_key.verify_key
        verify_bytes = verify_key.encode()
        identity = cls(
            agent_id=AgentID.from_pubkey(verify_bytes.hex()),
            label=label,
            metadata=metadata or {},
            _signing_key=signing_key.encode(),
            _verify_key=verify_bytes,
        )
        if save_path is not None:
            identity.save(save_path)
        return identity

    @classmethod
    def load(cls, path: Union[str, Path]) -> "AgentIdentity":
        identity_path = Path(path)
        data = json.loads(identity_path.read_text(encoding="utf-8"))

        signing_hex = data.get("private_key", "")
        pubkey_hex = data.get("pubkey", "")
        if signing_hex and pubkey_hex:
            _require_crypto("AgentIdentity.load() with a keypair")
            assert _SigningKey is not None

            try:
                signing_bytes = bytes.fromhex(signing_hex)
                verify_bytes = bytes.fromhex(pubkey_hex)
            except ValueError as e:
                raise ValueError(
                    f"identity file {identity_path} has malformed hex keys: {e}"
                ) from e

            # 防 identity 文件被换 pubkey 攻击：
            # 私钥派生出来的真 pubkey 必须等于文件里宣称的 pubkey
            derived_pub = _SigningKey(signing_bytes).verify_key.encode()
            if derived_pub != verify_bytes:
                raise ValueError(
                    f"identity file {identity_path} keypair mismatch: "
                    "private_key does not derive the stored pubkey. "
                    "file may have been tampered with — refuse to load."
                )

            return cls(
                agent_id=AgentID.from_pubkey(pubkey_hex),
                label=data.get("label", ""),
                metadata=data.get("metadata", {}),
                _signing_key=signing_bytes,
                _verify_key=verify_bytes,
            )

        return cls.from_string(
            data.get("agent_id", "anonymous"),
            label=data.get("label", ""),
            metadata=data.get("metadata", {}),
        )

    @property
    def can_sign(self) -> bool:
        return bool(_NACL_AVAILABLE and self._signing_key and self._verify_key)

    @property
    def pubkey_hex(self) -> str:
        return self._verify_key.hex() if self._verify_key else self.agent_id.pubkey_hex

    def public_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": str(self.agent_id),
            "label": self.label,
            "is_cryptographic": self.agent_id.is_cryptographic,
            "pubkey": self.pubkey_hex,
            "fingerprint": self.fingerprint(),
            "metadata": self.metadata,
        }

    def save(self, path: Union[str, Path]) -> None:
        identity_path = Path(path)
        identity_path.parent.mkdir(parents=True, exist_ok=True)

        data = self.public_dict()
        has_private = bool(self._signing_key)
        if has_private:
            data["private_key"] = self._signing_key.hex()

        tmp = identity_path.with_suffix(identity_path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(str(tmp), str(identity_path))

        if has_private:
            _restrict_to_owner(identity_path)

    def sign(self, payload: bytes) -> bytes:
        if not self.can_sign:
            raise RuntimeError(
                f"Agent '{self.agent_id}' has no signing key. "
                "Use AgentIdentity.generate() with PyNaCl installed."
            )
        assert _SigningKey is not None
        assert self._signing_key is not None
        return _SigningKey(self._signing_key).sign(payload).signature

    def sign_json(self, data: Dict[str, Any]) -> str:
        return self.sign(canonical_json(data)).hex()

    def verify(
        self,
        payload: bytes,
        signature: bytes,
        pubkey: Optional[bytes] = None,
    ) -> bool:
        if not _NACL_AVAILABLE:
            return False
        verify_key = pubkey or self._verify_key
        if not verify_key:
            return False
        try:
            assert _VerifyKey is not None
            _VerifyKey(verify_key).verify(payload, signature)
            return True
        except Exception:
            return False

    def verify_json(
        self,
        data: Dict[str, Any],
        signature_hex: str,
        pubkey_hex: Optional[str] = None,
    ) -> bool:
        pubkey = bytes.fromhex(pubkey_hex) if pubkey_hex else None
        return self.verify(canonical_json(data), bytes.fromhex(signature_hex), pubkey)

    def fingerprint(self) -> str:
        payload = self.pubkey_hex or str(self.agent_id)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def default_identity_path(workspace: Union[str, Path]) -> Path:
    return Path(workspace) / DEFAULT_IDENTITY_DIR / DEFAULT_IDENTITY_FILE


def load_or_generate(
    workspace: Union[str, Path],
    label: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> AgentIdentity:
    identity_path = default_identity_path(workspace)
    if identity_path.exists():
        return AgentIdentity.load(identity_path)

    if _NACL_AVAILABLE:
        return AgentIdentity.generate(
            save_path=identity_path,
            label=label,
            metadata=metadata,
        )

    fallback = AgentIdentity.from_string(
        "agent-" + secrets.token_hex(4),
        label=label,
        metadata=metadata,
    )
    fallback.save(identity_path)
    return fallback


# ───────────────────── private-key file permission hardening ─────────────────


def _restrict_to_owner(path: Path) -> None:
    """尽力把文件权限收紧到只有 owner 可读。

    POSIX: chmod 0o600
    Windows: 用 icacls 把 ACL 缩到当前用户；失败必须 warn —— 不能像之前那样
             `except: pass` 把私钥裸奔藏起来。
    """
    if sys.platform == "win32":
        ok = _restrict_windows_acl(path)
        if not ok:
            logger.warning(
                "could not restrict ACL on private key file %s — "
                "file may be readable by other local users. "
                "Inspect permissions with: icacls %s",
                path, path,
            )
        return

    try:
        os.chmod(path, 0o600)
    except OSError as e:
        logger.warning("could not chmod 0600 on %s: %s", path, e)


def _restrict_windows_acl(path: Path) -> bool:
    """Windows: 用 icacls 把私钥 ACL 限制到当前用户。

    正确顺序：
        1) /grant <USER>:(F)     # 先给自己显式 full
        2) /inheritance:r         # 再剥离继承的 ACE
        3) 自检：还能读吗？如果不能 → /inheritance:e 还原（保命）+ 返回 False
    """
    import getpass
    import subprocess

    user = os.environ.get("USERNAME") or getpass.getuser()
    if not user:
        return False
    try:
        # 1) 先 grant 自己
        r1 = subprocess.run(
            ["icacls", str(path), "/grant", f"{user}:(F)"],
            capture_output=True, text=True, timeout=10,
        )
        if r1.returncode != 0:
            return False
        # 2) 再 strip 继承
        r2 = subprocess.run(
            ["icacls", str(path), "/inheritance:r"],
            capture_output=True, text=True, timeout=10,
        )
        if r2.returncode != 0:
            return False
        # 3) 自检读取 —— 若失败立刻还原继承
        try:
            with open(path, "rb") as fh:
                fh.read(1)
        except OSError:
            # 还原 inheritance，至少文件还能用
            subprocess.run(
                ["icacls", str(path), "/inheritance:e"],
                capture_output=True, text=True, timeout=10,
            )
            return False
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False
