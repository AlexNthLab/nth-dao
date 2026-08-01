"""Content-addressed durable store for local Recognition policy revisions."""

from __future__ import annotations

import json
import math
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from nth_dao.did_key import is_did_key
from nth_dao.trade_rules.canonical import MAX_TRADE_JSON_BYTES
from nth_dao.trade_rules.recognition_policy import (
    TradeRuleRecognitionPolicy,
    TradeRuleRecognitionPolicyRejected,
    verify_rule_recognition_policy_successor,
)
from nth_dao.util.io import InterProcessLock

RULE_RECOGNITION_POLICY_HEAD_KIND = (
    "nth.dao.trade.rule-recognition-policy-head"
)
RULE_RECOGNITION_POLICY_STORE_VERSION = "1"
GENESIS_POLICY_DIGEST = "sha256:" + ("0" * 64)
DEFAULT_MAX_RULE_RECOGNITION_POLICY_REVISIONS = 4_096
DEFAULT_MAX_RULE_RECOGNITION_POLICY_BYTES = 64 * 1024 * 1024

_HEAD_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "node_did",
        "sequence",
        "policy_digest",
    }
)


class RuleRecognitionPolicyStoreError(RuntimeError):
    """Base error for local Recognition policy persistence."""


class RuleRecognitionPolicyStoreBusy(RuleRecognitionPolicyStoreError):
    """The policy store lock could not be acquired."""


class RuleRecognitionPolicyStoreCapacity(RuleRecognitionPolicyStoreError):
    """A configured policy-store limit would be exceeded."""


class RuleRecognitionPolicyStoreCorruption(RuleRecognitionPolicyStoreError):
    """The policy CAS or durable head is inconsistent."""


@dataclass(frozen=True)
class RuleRecognitionPolicyStoreResult:
    policy: TradeRuleRecognitionPolicy
    created: bool
    checkpoint_advanced: bool


class RuleRecognitionPolicyStore:
    """Single-node signed policy chain with CAS and rollback detection."""

    def __init__(
        self,
        workspace_root: str | Path,
        *,
        node_did: str,
        max_revisions: int = DEFAULT_MAX_RULE_RECOGNITION_POLICY_REVISIONS,
        max_bytes: int = DEFAULT_MAX_RULE_RECOGNITION_POLICY_BYTES,
        lock_timeout: float = 10.0,
    ) -> None:
        if not isinstance(node_did, str) or not is_did_key(node_did):
            raise ValueError("node_did must be an Ed25519 did:key")
        for label, value in (
            ("max_revisions", max_revisions),
            ("max_bytes", max_bytes),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
            ):
                raise ValueError(f"{label} must be a positive integer")
        if (
            isinstance(lock_timeout, bool)
            or not isinstance(lock_timeout, (int, float))
            or not math.isfinite(lock_timeout)
            or lock_timeout <= 0
        ):
            raise ValueError("lock_timeout must be a finite positive number")
        self.workspace_root = Path(workspace_root)
        self.node_did = node_did
        self.root = (
            self.workspace_root / "trade" / "rule_recognition_policy_v1"
        )
        self.statements_root = self.root / "statements"
        self.head_path = self.root / "head.json"
        self.lock_path = self.root / ".locks" / "policy"
        self.max_revisions = max_revisions
        self.max_bytes = max_bytes
        self.lock_timeout = float(lock_timeout)

    @classmethod
    def open_or_create_for_identity(
        cls,
        workspace_root: str | Path,
        *,
        identity_did: str,
        max_revisions: int = DEFAULT_MAX_RULE_RECOGNITION_POLICY_REVISIONS,
        max_bytes: int = DEFAULT_MAX_RULE_RECOGNITION_POLICY_BYTES,
        lock_timeout: float = 10.0,
    ) -> "RuleRecognitionPolicyStore":
        """Open a stable policy namespace across authorized key rotation.

        Before genesis, the namespace is the current identity DID. Once a
        signed policy chain exists, its node DID is permanent: later signing
        identities may advance the chain only through the previous policy's
        controller authorization. The stored DID is accepted only after the
        canonical head and complete signed chain verify under one lock.
        """
        store = cls(
            workspace_root,
            node_did=identity_did,
            max_revisions=max_revisions,
            max_bytes=max_bytes,
            lock_timeout=lock_timeout,
        )
        try:
            with store._acquire():
                head = store._read_head(enforce_node_did=False)
                if head is not None:
                    stored_node_did = head["node_did"]
                    if head["sequence"] == 0:
                        if stored_node_did != identity_did:
                            raise RuleRecognitionPolicyStoreCorruption(
                                "empty Recognition policy namespace does not "
                                "match the current identity"
                            )
                    else:
                        store.node_did = stored_node_did
                store._state_locked()
        except TimeoutError as exc:
            raise RuleRecognitionPolicyStoreBusy(
                "Recognition policy store is busy"
            ) from exc
        except OSError as exc:
            raise RuleRecognitionPolicyStoreError(
                f"Recognition policy store I/O failed: {exc}"
            ) from exc
        return store

    @staticmethod
    def _is_linklike(path: Path) -> bool:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if is_junction and is_junction():
            return True
        if os.name == "nt":
            try:
                metadata = os.lstat(path)
            except FileNotFoundError:
                return False
            return bool(
                getattr(metadata, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            )
        return False

    def _assert_path(self, path: Path) -> None:
        try:
            relative = path.relative_to(self.workspace_root)
        except ValueError as exc:
            raise RuleRecognitionPolicyStoreError(
                "Recognition policy path escapes workspace root"
            ) from exc
        candidates = [self.workspace_root]
        candidates.extend(
            self.workspace_root.joinpath(*relative.parts[:index])
            for index in range(1, len(relative.parts) + 1)
        )
        for candidate in candidates:
            if self._is_linklike(candidate):
                raise RuleRecognitionPolicyStoreError(
                    "Recognition policy store must not contain symlinks "
                    "or junctions"
                )

    def _acquire(self) -> InterProcessLock:
        self._assert_path(self.lock_path.parent)
        try:
            self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise RuleRecognitionPolicyStoreError(
                f"unable to create policy lock directory: {exc}"
            ) from exc
        self._assert_path(self.lock_path.parent)
        return InterProcessLock(
            self.lock_path,
            timeout=self.lock_timeout,
        )

    @staticmethod
    def _digest_filename(digest: str) -> str:
        if (
            not isinstance(digest, str)
            or len(digest) != 71
            or not digest.startswith("sha256:")
            or any(character not in "0123456789abcdef" for character in digest[7:])
        ):
            raise RuleRecognitionPolicyStoreError(
                "Recognition policy digest is invalid"
            )
        return f"{digest[7:]}.json"

    def _statement_path(self, digest: str) -> Path:
        return self.statements_root / self._digest_filename(digest)

    def _atomic_write(self, path: Path, payload: bytes) -> None:
        descriptor: int | None = None
        temporary: str | None = None
        try:
            self._assert_path(path.parent)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._assert_path(path.parent)
            descriptor, temporary = tempfile.mkstemp(
                prefix=path.name + ".",
                suffix=".tmp",
                dir=str(path.parent),
            )
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            temporary = None
        except OSError as exc:
            raise RuleRecognitionPolicyStoreError(
                f"unable to write Recognition policy store: {exc}"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def _head_document(self, *, sequence: int, digest: str) -> dict[str, object]:
        return {
            "kind": RULE_RECOGNITION_POLICY_HEAD_KIND,
            "protocol_version": RULE_RECOGNITION_POLICY_STORE_VERSION,
            "node_did": self.node_did,
            "sequence": sequence,
            "policy_digest": digest,
        }

    def _write_head(self, *, sequence: int, digest: str) -> None:
        payload = (
            json.dumps(
                self._head_document(sequence=sequence, digest=digest),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
        self._atomic_write(self.head_path, payload)

    def _read_head(
        self,
        *,
        enforce_node_did: bool = True,
    ) -> dict[str, object] | None:
        self._assert_path(self.head_path)
        if not self.head_path.exists():
            return None
        try:
            size = self.head_path.stat().st_size
            if size > 4_096:
                raise RuleRecognitionPolicyStoreCorruption(
                    "Recognition policy head exceeds byte limit"
                )
            raw = self.head_path.read_bytes()
            if len(raw) != size:
                raise RuleRecognitionPolicyStoreCorruption(
                    "Recognition policy head changed while being read"
                )
            document = json.loads(raw.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuleRecognitionPolicyStoreCorruption(
                "Recognition policy head is not canonical JSON"
            ) from exc
        except OSError as exc:
            raise RuleRecognitionPolicyStoreError(
                f"unable to read Recognition policy head: {exc}"
            ) from exc
        if not isinstance(document, dict) or set(document) != _HEAD_FIELDS:
            raise RuleRecognitionPolicyStoreCorruption(
                "Recognition policy head has invalid fields"
            )
        canonical = (
            json.dumps(
                document,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
        if raw != canonical:
            raise RuleRecognitionPolicyStoreCorruption(
                "Recognition policy head is not canonical JSON"
            )
        if (
            document["kind"] != RULE_RECOGNITION_POLICY_HEAD_KIND
            or document["protocol_version"]
            != RULE_RECOGNITION_POLICY_STORE_VERSION
            or not isinstance(document["node_did"], str)
            or not is_did_key(document["node_did"])
            or isinstance(document["sequence"], bool)
            or not isinstance(document["sequence"], int)
            or document["sequence"] < 0
            or not isinstance(document["policy_digest"], str)
        ):
            raise RuleRecognitionPolicyStoreCorruption(
                "Recognition policy head metadata is invalid"
            )
        if enforce_node_did and document["node_did"] != self.node_did:
            raise RuleRecognitionPolicyStoreCorruption(
                "Recognition policy head belongs to another node"
            )
        self._digest_filename(document["policy_digest"])
        if (
            document["sequence"] == 0
            and document["policy_digest"] != GENESIS_POLICY_DIGEST
        ):
            raise RuleRecognitionPolicyStoreCorruption(
                "Recognition policy genesis head is invalid"
            )
        if (
            document["sequence"] > 0
            and document["policy_digest"] == GENESIS_POLICY_DIGEST
        ):
            raise RuleRecognitionPolicyStoreCorruption(
                "Recognition policy non-genesis head is invalid"
            )
        return document

    def _statement_files(self) -> list[Path]:
        self._assert_path(self.statements_root)
        if not self.statements_root.exists():
            return []
        try:
            files = sorted(self.statements_root.iterdir())
        except OSError as exc:
            raise RuleRecognitionPolicyStoreError(
                f"unable to list Recognition policies: {exc}"
            ) from exc
        for path in files:
            self._assert_path(path)
            if (
                not path.is_file()
                or path.suffix != ".json"
                or len(path.stem) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in path.stem
                )
            ):
                raise RuleRecognitionPolicyStoreCorruption(
                    "Recognition policy CAS contains an unexpected entry"
                )
        return files

    def _read_policy(self, path: Path) -> TradeRuleRecognitionPolicy:
        try:
            size = path.stat().st_size
            if size > MAX_TRADE_JSON_BYTES:
                raise RuleRecognitionPolicyStoreCorruption(
                    "stored Recognition policy exceeds byte limit"
                )
            raw = path.read_bytes()
        except OSError as exc:
            raise RuleRecognitionPolicyStoreError(
                f"unable to read stored Recognition policy: {exc}"
            ) from exc
        if len(raw) != size:
            raise RuleRecognitionPolicyStoreCorruption(
                "stored Recognition policy changed while being read"
            )
        try:
            policy = TradeRuleRecognitionPolicy.from_json(raw)
        except TradeRuleRecognitionPolicyRejected as exc:
            raise RuleRecognitionPolicyStoreCorruption(
                f"stored Recognition policy is invalid: {exc}"
            ) from exc
        if raw != policy.canonical_bytes:
            raise RuleRecognitionPolicyStoreCorruption(
                "stored Recognition policy is not canonical"
            )
        if path.name != self._digest_filename(policy.digest):
            raise RuleRecognitionPolicyStoreCorruption(
                "stored Recognition policy digest does not match filename"
            )
        if policy.to_dict()["node_did"] != self.node_did:
            raise RuleRecognitionPolicyStoreCorruption(
                "stored Recognition policy belongs to another node"
            )
        return policy

    def _load_chain_locked(self) -> tuple[TradeRuleRecognitionPolicy, ...]:
        files = self._statement_files()
        if len(files) > self.max_revisions:
            raise RuleRecognitionPolicyStoreCapacity(
                "Recognition policy revision limit exceeded"
            )
        total_bytes = sum(path.stat().st_size for path in files)
        if total_bytes > self.max_bytes:
            raise RuleRecognitionPolicyStoreCapacity(
                "Recognition policy byte limit exceeded"
            )
        policies = [self._read_policy(path) for path in files]
        by_sequence: dict[int, list[TradeRuleRecognitionPolicy]] = {}
        for policy in policies:
            sequence = policy.to_dict()["sequence"]
            by_sequence.setdefault(sequence, []).append(policy)
        ordered: list[TradeRuleRecognitionPolicy] = []
        for expected_sequence in range(1, len(policies) + 1):
            candidates = by_sequence.get(expected_sequence, [])
            if len(candidates) != 1:
                reason = "fork" if len(candidates) > 1 else "sequence gap"
                raise RuleRecognitionPolicyStoreCorruption(
                    f"Recognition policy chain contains a {reason}"
                )
            current = candidates[0]
            if ordered:
                try:
                    verify_rule_recognition_policy_successor(
                        ordered[-1],
                        current,
                    )
                except TradeRuleRecognitionPolicyRejected as exc:
                    raise RuleRecognitionPolicyStoreCorruption(
                        f"Recognition policy chain is invalid: {exc}"
                    ) from exc
            elif current.to_dict()["previous_policy_digest"] is not None:
                raise RuleRecognitionPolicyStoreCorruption(
                    "Recognition policy genesis binds a predecessor"
                )
            elif current.to_dict()["signer_did"] != self.node_did:
                raise RuleRecognitionPolicyStoreCorruption(
                    "Recognition policy genesis signer is not node_did"
                )
            ordered.append(current)
        if set(by_sequence) != set(range(1, len(policies) + 1)):
            raise RuleRecognitionPolicyStoreCorruption(
                "Recognition policy chain contains an out-of-range sequence"
            )
        return tuple(ordered)

    def _verify_head_locked(
        self,
        chain: tuple[TradeRuleRecognitionPolicy, ...],
    ) -> bool:
        head = self._read_head()
        if head is None:
            if chain:
                raise RuleRecognitionPolicyStoreCorruption(
                    "Recognition policy head is missing"
                )
            return False
        checkpoint_sequence = head["sequence"]
        if checkpoint_sequence > len(chain):
            raise RuleRecognitionPolicyStoreCorruption(
                "Recognition policy CAS was truncated behind its head"
            )
        if checkpoint_sequence == 0:
            if head["policy_digest"] != GENESIS_POLICY_DIGEST:
                raise RuleRecognitionPolicyStoreCorruption(
                    "Recognition policy genesis head is invalid"
                )
        elif chain[checkpoint_sequence - 1].digest != head["policy_digest"]:
            raise RuleRecognitionPolicyStoreCorruption(
                "Recognition policy head does not match its revision"
            )
        if checkpoint_sequence < len(chain):
            latest = chain[-1]
            self._write_head(
                sequence=latest.to_dict()["sequence"],
                digest=latest.digest,
            )
            return True
        return False

    def _state_locked(
        self,
    ) -> tuple[tuple[TradeRuleRecognitionPolicy, ...], bool]:
        chain = self._load_chain_locked()
        advanced = self._verify_head_locked(chain)
        return chain, advanced

    def append(
        self,
        policy: TradeRuleRecognitionPolicy | dict[str, object],
    ) -> RuleRecognitionPolicyStoreResult:
        verified = (
            TradeRuleRecognitionPolicy.from_json(policy.canonical_bytes)
            if isinstance(policy, TradeRuleRecognitionPolicy)
            else TradeRuleRecognitionPolicy.from_dict(policy)
        )
        if verified.to_dict()["node_did"] != self.node_did:
            raise TradeRuleRecognitionPolicyRejected(
                "Recognition policy belongs to another node"
            )
        try:
            with self._acquire():
                if not self.root.exists():
                    self.root.mkdir(parents=True, exist_ok=True)
                if not self.head_path.exists() and not self._statement_files():
                    self._write_head(
                        sequence=0,
                        digest=GENESIS_POLICY_DIGEST,
                    )
                chain, checkpoint_advanced = self._state_locked()
                existing = next(
                    (item for item in chain if item.digest == verified.digest),
                    None,
                )
                if existing is not None:
                    return RuleRecognitionPolicyStoreResult(
                        policy=existing,
                        created=False,
                        checkpoint_advanced=checkpoint_advanced,
                    )
                if len(chain) >= self.max_revisions:
                    raise RuleRecognitionPolicyStoreCapacity(
                        "Recognition policy revision limit reached"
                    )
                total_bytes = sum(
                    path.stat().st_size for path in self._statement_files()
                )
                if total_bytes + len(verified.canonical_bytes) > self.max_bytes:
                    raise RuleRecognitionPolicyStoreCapacity(
                        "Recognition policy byte limit reached"
                    )
                if chain:
                    verify_rule_recognition_policy_successor(
                        chain[-1],
                        verified,
                    )
                elif verified.to_dict()["sequence"] != 1:
                    raise TradeRuleRecognitionPolicyRejected(
                        "first stored Recognition policy must have sequence 1"
                    )
                elif verified.to_dict()["signer_did"] != self.node_did:
                    raise TradeRuleRecognitionPolicyRejected(
                        "first stored Recognition policy must be signed by node_did"
                    )
                path = self._statement_path(verified.digest)
                self._atomic_write(path, verified.canonical_bytes)
                self._write_head(
                    sequence=verified.to_dict()["sequence"],
                    digest=verified.digest,
                )
                return RuleRecognitionPolicyStoreResult(
                    policy=verified,
                    created=True,
                    checkpoint_advanced=checkpoint_advanced,
                )
        except TimeoutError as exc:
            raise RuleRecognitionPolicyStoreBusy(
                "Recognition policy store is busy"
            ) from exc
        except OSError as exc:
            raise RuleRecognitionPolicyStoreError(
                f"Recognition policy store I/O failed: {exc}"
            ) from exc

    def list_all(self) -> tuple[TradeRuleRecognitionPolicy, ...]:
        try:
            with self._acquire():
                chain, _advanced = self._state_locked()
                return chain
        except TimeoutError as exc:
            raise RuleRecognitionPolicyStoreBusy(
                "Recognition policy store is busy"
            ) from exc
        except OSError as exc:
            raise RuleRecognitionPolicyStoreError(
                f"Recognition policy store I/O failed: {exc}"
            ) from exc

    def head(self) -> TradeRuleRecognitionPolicy | None:
        chain = self.list_all()
        return chain[-1] if chain else None


__all__ = [
    "DEFAULT_MAX_RULE_RECOGNITION_POLICY_BYTES",
    "DEFAULT_MAX_RULE_RECOGNITION_POLICY_REVISIONS",
    "GENESIS_POLICY_DIGEST",
    "RULE_RECOGNITION_POLICY_HEAD_KIND",
    "RULE_RECOGNITION_POLICY_STORE_VERSION",
    "RuleRecognitionPolicyStore",
    "RuleRecognitionPolicyStoreBusy",
    "RuleRecognitionPolicyStoreCapacity",
    "RuleRecognitionPolicyStoreCorruption",
    "RuleRecognitionPolicyStoreError",
    "RuleRecognitionPolicyStoreResult",
]
