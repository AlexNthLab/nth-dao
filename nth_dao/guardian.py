"""Guardian-based social recovery — N-of-M peers can re-bind agent_id → new pubkey.

Problem
-------
A NTH DAO agent's authority comes from its Ed25519 private key. If the key
is lost (disk failure, leaked, etc.), the agent identity is effectively dead.
v0.9.4 introduced passphrase-protected `RecoveryKit` for the local backup
case. This module adds the *social* recovery case: a pre-designated quorum
of guardians collectively signs a `KeyReplacementProof` that re-binds the
agent_id to a fresh pubkey.

Design
------
1. The agent publishes a `GuardianSet` declaring N guardian pubkeys and a
   threshold M (M ≤ N). Each guardian acceptance is a signed statement.

2. To replace a key, the agent (or its surrogate) constructs an
   unsigned `KeyReplacementProof` containing:
        - old_fingerprint  (= sha256(old_pubkey)[:16])
        - new_pubkey       (the replacement)
        - reason
        - effective_at

3. The agent collects M guardian signatures over this proof. Each
   guardian independently verifies the request is legitimate (out of
   band: they should know the human really lost the key, not be
   socially engineered).

4. Anyone presented with the assembled proof + M signatures can verify:
        - All signatures verify under the corresponding guardian pubkeys.
        - Those pubkeys are present in the published `GuardianSet`.
        - The number of distinct valid signatures ≥ `threshold`.

The wire format is intentionally simple and stdlib-friendly so future
adapters (or other languages) can implement the same checks.

Anti-DoS rules
--------------
- A proof referencing a `new_pubkey` that already appears as the replacement
  in an earlier valid proof is rejected (no chained replacements without a
  fresh quorum).
- Old proofs can be invalidated by publishing a `GuardianSet` rotation —
  this is essentially "rotate guardians" and uses the same quorum to sign.

This module deliberately ships only the data structures + verification;
the orchestration ("how do I ask 5 friends to sign on a weekend?") is left
to UX layers per the iron rule (TS for UI, Python for protocol).
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from .identity import AgentIdentity, _NACL_AVAILABLE, _VerifyKey, canonical_json
from .util import InterProcessLock, atomic_write_json, safe_id, safe_load_json

logger = logging.getLogger("nth_dao.guardian")


def _pubkey_fingerprint(pubkey_hex: str) -> str:
    return hashlib.sha256(pubkey_hex.encode("utf-8")).hexdigest()[:16]


def _is_pubkey_hex(value: str) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


# ─────────────────── data types ───────────────────


@dataclass
class GuardianSet:
    """The list of guardians the agent has chosen + the threshold.

    Signed by the agent at the time of publication (the agent's own pubkey
    in `protected_fingerprint`).
    """

    protected_fingerprint: str           # the agent being protected (sha256(pubkey)[:16])
    protected_pubkey: str                # the agent's current pubkey at publication time
    guardian_pubkeys: List[str] = field(default_factory=list)
    threshold: int = 0                   # M of N
    issued_at: str = field(default_factory=lambda: datetime.now().isoformat())
    set_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    sig: str = ""                        # signed by protected_pubkey

    def to_dict(self) -> dict:
        return asdict(self)

    def signable_dict(self) -> dict:
        d = self.to_dict()
        d.pop("sig", None)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "GuardianSet":
        return cls(
            protected_fingerprint=data.get("protected_fingerprint", ""),
            protected_pubkey=data.get("protected_pubkey", ""),
            guardian_pubkeys=list(data.get("guardian_pubkeys", [])),
            threshold=int(data.get("threshold", 0)),
            issued_at=data.get("issued_at", ""),
            set_id=data.get("set_id", ""),
            sig=data.get("sig", ""),
        )

    def verify_signature(self) -> bool:
        if not (_NACL_AVAILABLE and _VerifyKey and self.sig and self.protected_pubkey):
            return False
        try:
            _VerifyKey(bytes.fromhex(self.protected_pubkey)).verify(
                canonical_json(self.signable_dict()),
                bytes.fromhex(self.sig),
            )
            return True
        except Exception:
            return False

    def is_well_formed(self) -> bool:
        if not _is_pubkey_hex(self.protected_pubkey):
            return False
        if self.protected_fingerprint != _pubkey_fingerprint(self.protected_pubkey):
            return False
        if not self.guardian_pubkeys:
            return False
        if self.threshold < 1 or self.threshold > len(self.guardian_pubkeys):
            return False
        if self.protected_pubkey in self.guardian_pubkeys:
            return False
        if any(not _is_pubkey_hex(pk) for pk in self.guardian_pubkeys):
            return False
        # No duplicates
        if len(set(self.guardian_pubkeys)) != len(self.guardian_pubkeys):
            return False
        return True


@dataclass
class GuardianSignature:
    """One guardian's signature over a KeyReplacementProof."""

    guardian_pubkey: str
    sig: str
    signed_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "GuardianSignature":
        return cls(
            guardian_pubkey=data.get("guardian_pubkey", ""),
            sig=data.get("sig", ""),
            signed_at=data.get("signed_at", ""),
        )


@dataclass
class KeyReplacementProof:
    """A signed quorum-based proof that an agent_id is re-bound to a new pubkey.

    `proof_id`, the `signable_dict()` content, and the `signatures` list
    together constitute the verifiable replacement.
    """

    proof_id: str
    old_fingerprint: str
    new_pubkey: str
    set_id: str                           # which GuardianSet authorizes this
    reason: str = ""
    effective_at: str = field(default_factory=lambda: datetime.now().isoformat())
    signatures: List[GuardianSignature] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["signatures"] = [s.to_dict() for s in self.signatures]
        return d

    def signable_dict(self) -> dict:
        """The dict each guardian signs. Excludes the signatures list itself."""
        return {
            "proof_id":        self.proof_id,
            "old_fingerprint": self.old_fingerprint,
            "new_pubkey":      self.new_pubkey,
            "set_id":          self.set_id,
            "reason":          self.reason,
            "effective_at":    self.effective_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "KeyReplacementProof":
        return cls(
            proof_id=data.get("proof_id", ""),
            old_fingerprint=data.get("old_fingerprint", ""),
            new_pubkey=data.get("new_pubkey", ""),
            set_id=data.get("set_id", ""),
            reason=data.get("reason", ""),
            effective_at=data.get("effective_at", ""),
            signatures=[
                GuardianSignature.from_dict(s)
                for s in data.get("signatures", [])
            ],
        )


# ─────────────────── helpers ───────────────────


def publish_guardian_set(
    owner: AgentIdentity,
    guardian_pubkeys: List[str],
    threshold: int,
) -> GuardianSet:
    """Owner signs a fresh GuardianSet.

    Raises:
        ValueError on bad inputs or non-crypto identity.
    """
    if not getattr(owner, "can_sign", False):
        raise ValueError("publish_guardian_set requires a signing-capable identity")
    if not _is_pubkey_hex(owner.pubkey_hex):
        raise ValueError("owner pubkey must be a 32-byte Ed25519 public key")
    if not guardian_pubkeys:
        raise ValueError("at least one guardian pubkey is required")
    if threshold < 1 or threshold > len(guardian_pubkeys):
        raise ValueError(
            f"threshold {threshold} must be in [1, {len(guardian_pubkeys)}]"
        )
    if len(set(guardian_pubkeys)) != len(guardian_pubkeys):
        raise ValueError("guardian_pubkeys must be unique")
    if any(not _is_pubkey_hex(pk) for pk in guardian_pubkeys):
        raise ValueError("guardian_pubkeys must be 32-byte Ed25519 public keys")
    if owner.pubkey_hex in guardian_pubkeys:
        raise ValueError(
            "the protected agent's own pubkey must not appear in the guardian set"
        )

    gs = GuardianSet(
        protected_fingerprint=owner.fingerprint(),
        protected_pubkey=owner.pubkey_hex,
        guardian_pubkeys=list(guardian_pubkeys),
        threshold=int(threshold),
    )
    gs.sig = owner.sign_json(gs.signable_dict())
    return gs


def begin_key_replacement(
    guardian_set: GuardianSet,
    new_pubkey_hex: str,
    reason: str = "",
) -> KeyReplacementProof:
    """Construct an unsigned KeyReplacementProof.

    Pass to each guardian; they call `sign_replacement` to add their signature.
    """
    if not guardian_set.is_well_formed():
        raise ValueError("guardian_set is malformed")
    if not guardian_set.verify_signature():
        raise ValueError("guardian_set signature invalid")
    if not _is_pubkey_hex(new_pubkey_hex):
        raise ValueError("new_pubkey_hex must be a 32-byte Ed25519 public key")
    if new_pubkey_hex == guardian_set.protected_pubkey:
        raise ValueError("new_pubkey_hex must differ from the protected pubkey")
    return KeyReplacementProof(
        proof_id=uuid.uuid4().hex[:12],
        old_fingerprint=guardian_set.protected_fingerprint,
        new_pubkey=new_pubkey_hex,
        set_id=guardian_set.set_id,
        reason=reason,
    )


def sign_replacement(
    guardian: AgentIdentity,
    proof: KeyReplacementProof,
) -> GuardianSignature:
    """A guardian signs the proof.

    Out of band, the guardian SHOULD verify the request is legitimate
    (e.g., voice call with the human owner).

    Returns the GuardianSignature; the caller appends it to `proof.signatures`.
    """
    if not getattr(guardian, "can_sign", False):
        raise ValueError("sign_replacement requires a signing-capable identity")
    sig = guardian.sign_json(proof.signable_dict())
    return GuardianSignature(guardian_pubkey=guardian.pubkey_hex, sig=sig)


def verify_replacement(
    proof: KeyReplacementProof,
    guardian_set: GuardianSet,
) -> Tuple[bool, str]:
    """Validate a fully-assembled replacement proof.

    Returns (valid, reason). `valid=True` only when:
      1. guardian_set itself verifies under protected_pubkey
      2. proof.set_id == guardian_set.set_id
      3. proof.old_fingerprint == guardian_set.protected_fingerprint
      4. ≥ guardian_set.threshold distinct valid signatures from
         guardian pubkeys in guardian_set.guardian_pubkeys
    """
    if not guardian_set.verify_signature():
        return False, "guardian_set signature invalid"
    if not guardian_set.is_well_formed():
        return False, "guardian_set malformed"
    if proof.set_id != guardian_set.set_id:
        return False, "proof refers to a different guardian set"
    if proof.old_fingerprint != guardian_set.protected_fingerprint:
        return False, "proof refers to a different agent"
    if not _is_pubkey_hex(proof.new_pubkey):
        return False, "proof new_pubkey malformed"
    if proof.new_pubkey == guardian_set.protected_pubkey:
        return False, "proof does not replace the protected pubkey"
    if not (_NACL_AVAILABLE and _VerifyKey):
        return False, "crypto unavailable"

    allowed = set(guardian_set.guardian_pubkeys)
    payload = canonical_json(proof.signable_dict())
    valid_signers: set = set()
    for sig_entry in proof.signatures:
        if sig_entry.guardian_pubkey not in allowed:
            continue
        if sig_entry.guardian_pubkey in valid_signers:
            continue
        try:
            _VerifyKey(bytes.fromhex(sig_entry.guardian_pubkey)).verify(
                payload, bytes.fromhex(sig_entry.sig),
            )
            valid_signers.add(sig_entry.guardian_pubkey)
        except Exception:
            continue

    if len(valid_signers) < guardian_set.threshold:
        return False, (
            f"only {len(valid_signers)} valid signatures; "
            f"need {guardian_set.threshold}"
        )
    return True, "ok"


# ─────────────────── persistence ───────────────────


class GuardianStore:
    """File-backed GuardianSet + proof persistence.

    Layout:
        team_recovery/
        ├── guardian_sets/<set_id>.json    # one signed GuardianSet per file
        ├── replacements/<proof_id>.json   # one assembled proof per file
        └── active_replacements.json       # {old_fingerprint: new_pubkey}
                                            # — derived index of verified proofs
    """

    SUBDIR_GS = "guardian_sets"
    SUBDIR_REP = "replacements"
    ACTIVE_NAME = "active_replacements.json"

    def __init__(self, workspace: Union[str, Path], root: str = "team_recovery"):
        self.workspace = Path(workspace)
        self.base = self.workspace / root
        self.base.mkdir(parents=True, exist_ok=True)
        self.gs_dir = self.base / self.SUBDIR_GS
        self.rep_dir = self.base / self.SUBDIR_REP
        self.gs_dir.mkdir(parents=True, exist_ok=True)
        self.rep_dir.mkdir(parents=True, exist_ok=True)
        self.active_path = self.base / self.ACTIVE_NAME

    def save_guardian_set(self, gs: GuardianSet) -> Path:
        if not gs.is_well_formed():
            raise ValueError("refuse to save malformed GuardianSet")
        if not gs.verify_signature():
            raise ValueError("refuse to save GuardianSet with invalid signature")
        path = self.gs_dir / f"{safe_id(gs.set_id)}.json"
        with InterProcessLock(path):
            atomic_write_json(path, gs.to_dict())
        return path

    def load_guardian_set(self, set_id: str) -> Optional[GuardianSet]:
        path = self.gs_dir / f"{safe_id(set_id)}.json"
        data = safe_load_json(path, fallback=None)
        if data is None:
            return None
        try:
            return GuardianSet.from_dict(data)
        except Exception:
            return None

    def save_replacement(self, proof: KeyReplacementProof) -> Path:
        path = self.rep_dir / f"{safe_id(proof.proof_id)}.json"
        with InterProcessLock(path):
            atomic_write_json(path, proof.to_dict())
        return path

    def _iter_replacements(self) -> List[KeyReplacementProof]:
        out: List[KeyReplacementProof] = []
        for path in self.rep_dir.glob("*.json"):
            data = safe_load_json(path, fallback=None)
            if data is None:
                continue
            try:
                out.append(KeyReplacementProof.from_dict(data))
            except Exception:
                continue
        return out

    def load_replacement(self, proof_id: str) -> Optional[KeyReplacementProof]:
        path = self.rep_dir / f"{safe_id(proof_id)}.json"
        data = safe_load_json(path, fallback=None)
        if data is None:
            return None
        try:
            return KeyReplacementProof.from_dict(data)
        except Exception:
            return None

    def commit_replacement(self, proof: KeyReplacementProof) -> bool:
        """Verify the proof and, if valid, persist + update active_replacements.

        Returns True on success. False if verification fails (no state changes).
        """
        with InterProcessLock(self.active_path):
            gs = self.load_guardian_set(proof.set_id)
            if gs is None:
                return False
            valid, reason = verify_replacement(proof, gs)
            if not valid:
                logger.warning("commit_replacement refused: %s", reason)
                return False

            active = safe_load_json(self.active_path, fallback={}) or {}
            if not isinstance(active, dict):
                active = {}
            if proof.old_fingerprint in active:
                logger.warning("commit_replacement refused: old fingerprint already replaced")
                return False
            for entry in active.values():
                if isinstance(entry, dict) and entry.get("new_pubkey") == proof.new_pubkey:
                    logger.warning("commit_replacement refused: new pubkey already active")
                    return False
            for previous in self._iter_replacements():
                if previous.proof_id == proof.proof_id:
                    logger.warning("commit_replacement refused: proof_id replay")
                    return False
                if previous.new_pubkey == proof.new_pubkey:
                    logger.warning("commit_replacement refused: new pubkey already used")
                    return False

            self.save_replacement(proof)
            active[proof.old_fingerprint] = {
                "new_pubkey": proof.new_pubkey,
                "proof_id":   proof.proof_id,
                "effective_at": proof.effective_at,
            }
            atomic_write_json(self.active_path, active)
            return True

    def active_replacements(self) -> Dict[str, Any]:
        return safe_load_json(self.active_path, fallback={}) or {}

    def resolve_current_pubkey(self, old_fingerprint: str) -> Optional[str]:
        """Given an agent's original fingerprint, return the currently-active
        pubkey (the latest replacement target, or None if no replacement).
        """
        active = self.active_replacements()
        entry = active.get(old_fingerprint)
        if entry and isinstance(entry, dict):
            return entry.get("new_pubkey")
        return None
