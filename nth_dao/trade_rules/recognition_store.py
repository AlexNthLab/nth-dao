"""Durable content-addressed storage for verified Rule Recognition claims."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from nth_dao.trade_rules.canonical import MAX_TRADE_JSON_BYTES
from nth_dao.trade_rules.package_store import (
    RulePackage,
    RulePackageError,
    build_rule_package,
)
from nth_dao.trade_rules.recognition import (
    TradeRuleRecognition,
    TradeRuleRecognitionRejected,
)
from nth_dao.util.io import InterProcessLock

DEFAULT_MAX_RULE_RECOGNITIONS = 10_000
DEFAULT_MAX_RULE_RECOGNITION_STORE_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_RULE_RECOGNITION_QUARANTINE = 2_048
QUARANTINE_KIND = "nth.dao.trade.rule-recognition-quarantine"
QUARANTINE_PROTOCOL_VERSION = "1"


class RuleRecognitionStoreError(RuntimeError):
    """Base error for recognition persistence and verified reads."""


class RuleRecognitionStoreBusy(RuleRecognitionStoreError):
    """The recognition store lock could not be acquired."""


class RuleRecognitionStoreCapacity(RuleRecognitionStoreError):
    """A configured store capacity would be exceeded."""


class RuleRecognitionStoreCorruption(RuleRecognitionStoreError):
    """Stored recognition bytes are malformed, replaced, or misbound."""


@dataclass(frozen=True)
class RuleRecognitionImportResult:
    accepted: bool
    duplicate: bool
    statement: TradeRuleRecognition | None
    input_digest: str
    quarantine_persisted: bool
    rejection_code: str | None


class RuleRecognitionStore:
    """Content-addressed CAS plus bounded metadata-only quarantine.

    Invalid input bytes are never stored. Quarantine records contain only a
    digest, bounded reason code, and observation time, preventing a remote
    sender from turning the store into an arbitrary-content sink.
    """

    def __init__(
        self,
        workspace_root: str | Path,
        *,
        max_statements: int = DEFAULT_MAX_RULE_RECOGNITIONS,
        max_bytes: int = DEFAULT_MAX_RULE_RECOGNITION_STORE_BYTES,
        max_quarantine: int = DEFAULT_MAX_RULE_RECOGNITION_QUARANTINE,
        lock_timeout: float = 10.0,
    ) -> None:
        for label, value in (
            ("max_statements", max_statements),
            ("max_bytes", max_bytes),
            ("max_quarantine", max_quarantine),
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
        self.root = (
            self.workspace_root / "trade" / "rule_recognitions_v1"
        )
        self.statements_root = self.root / "statements"
        self.quarantine_root = self.root / "quarantine"
        self.lock_path = self.root / ".locks" / "recognitions"
        self.max_statements = max_statements
        self.max_bytes = max_bytes
        self.max_quarantine = max_quarantine
        self.lock_timeout = float(lock_timeout)

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
            raise RuleRecognitionStoreError(
                "recognition-store path escapes workspace root"
            ) from exc
        current = self.workspace_root
        for candidate in (self.workspace_root, *(
            self.workspace_root.joinpath(*relative.parts[:index])
            for index in range(1, len(relative.parts) + 1)
        )):
            current = candidate
            if self._is_linklike(current):
                raise RuleRecognitionStoreError(
                    "recognition store must not contain symlinks or junctions"
                )

    def _acquire(self) -> InterProcessLock:
        self._assert_path(self.lock_path.parent)
        try:
            self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise RuleRecognitionStoreError(
                f"unable to create recognition lock directory: {exc}"
            ) from exc
        self._assert_path(self.lock_path.parent)
        return InterProcessLock(
            self.lock_path,
            timeout=self.lock_timeout,
        )

    @staticmethod
    def _verified_package(package: RulePackage) -> RulePackage:
        if not isinstance(package, RulePackage):
            raise TypeError("package must be a RulePackage")
        try:
            verified = build_rule_package(
                package.manifest,
                package.resources,
            )
        except (RulePackageError, TypeError, ValueError) as exc:
            raise RuleRecognitionStoreError(
                f"Rule Package verification failed: {exc}"
            ) from exc
        if verified.digest != package.digest:
            raise RuleRecognitionStoreCorruption(
                "Rule Package digest changed during verification"
            )
        return verified

    @staticmethod
    def _assert_binding(
        statement: TradeRuleRecognition,
        package: RulePackage,
    ) -> None:
        document = statement.to_dict()
        if (
            document["package_digest"] != package.digest
            or document["rule_id"] != package.manifest.rule_id
        ):
            raise TradeRuleRecognitionRejected(
                "recognition does not bind the requested Rule Package"
            )

    @staticmethod
    def _input_bytes(raw: bytes | str) -> bytes:
        if isinstance(raw, bytes):
            return raw
        if isinstance(raw, str):
            try:
                return raw.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise TradeRuleRecognitionRejected(
                    "recognition input contains invalid Unicode"
                ) from exc
        raise TypeError("raw recognition input must be bytes or str")

    @staticmethod
    def _input_digest(payload: bytes) -> str:
        if len(payload) <= MAX_TRADE_JSON_BYTES:
            digest_input = b"full\x00" + payload
        else:
            digest_input = (
                b"oversize\x00"
                + str(len(payload)).encode("ascii")
                + b"\x00"
                + payload[:MAX_TRADE_JSON_BYTES]
            )
        return "sha256:" + hashlib.sha256(digest_input).hexdigest()

    @staticmethod
    def _rejection_code(exc: Exception) -> str:
        message = str(exc)
        if "signature" in message or "proof" in message:
            return "signature-invalid"
        if "exceed" in message or "too large" in message:
            return "size-limit"
        if "bind" in message or "Rule Package" in message:
            return "package-binding"
        return "malformed"

    def _statement_path(self, digest: str) -> Path:
        if (
            not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or len(digest) != 71
            or any(character not in "0123456789abcdef" for character in digest[7:])
        ):
            raise RuleRecognitionStoreError("statement digest is invalid")
        return self.statements_root / f"{digest[7:]}.json"

    def _quarantine_path(self, input_digest: str) -> Path:
        return self.quarantine_root / f"{input_digest[7:]}.json"

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
            raise RuleRecognitionStoreError(
                f"unable to write recognition store: {exc}"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def _statement_files(self) -> list[Path]:
        self._assert_path(self.statements_root)
        if not self.statements_root.exists():
            return []
        files = sorted(self.statements_root.iterdir())
        for path in files:
            self._assert_path(path)
        if any(
            not path.is_file()
            or path.suffix != ".json"
            or len(path.stem) != 64
            or any(
                character not in "0123456789abcdef"
                for character in path.stem
            )
            for path in files
        ):
            raise RuleRecognitionStoreCorruption(
                "recognition store contains an unexpected entry"
            )
        return files

    def _quarantine_count(self) -> int:
        self._assert_path(self.quarantine_root)
        if not self.quarantine_root.exists():
            return 0
        files = sorted(self.quarantine_root.iterdir())
        for path in files:
            self._assert_path(path)
        if any(
            not path.is_file()
            or path.suffix != ".json"
            or len(path.stem) != 64
            or any(
                character not in "0123456789abcdef"
                for character in path.stem
            )
            for path in files
        ):
            raise RuleRecognitionStoreCorruption(
                "recognition quarantine contains an unexpected entry"
            )
        return len(files)

    def _read_bounded(self, path: Path, *, label: str) -> bytes:
        self._assert_path(path)
        try:
            size = path.stat().st_size
            if size > MAX_TRADE_JSON_BYTES:
                raise RuleRecognitionStoreCorruption(
                    f"stored {label} exceeds byte limit"
                )
            payload = path.read_bytes()
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise RuleRecognitionStoreError(
                f"unable to read stored {label}: {exc}"
            ) from exc
        if len(payload) != size:
            raise RuleRecognitionStoreCorruption(
                f"stored {label} changed while being read"
            )
        return payload

    def _persist_verified(
        self,
        statement: TradeRuleRecognition,
    ) -> bool:
        path = self._statement_path(statement.digest)
        self._assert_path(path)
        files = self._statement_files()
        if path.exists():
            existing = self._read_bounded(path, label="recognition")
            if existing != statement.canonical_bytes:
                raise RuleRecognitionStoreCorruption(
                    "content-addressed recognition bytes changed"
                )
            return True
        total_bytes = sum(item.stat().st_size for item in files)
        if len(files) >= self.max_statements:
            raise RuleRecognitionStoreCapacity(
                "recognition statement count limit reached"
            )
        if total_bytes + len(statement.canonical_bytes) > self.max_bytes:
            raise RuleRecognitionStoreCapacity(
                "recognition byte limit reached"
            )
        self._atomic_write(path, statement.canonical_bytes)
        return False

    def _persist_quarantine(
        self,
        *,
        input_digest: str,
        rejection_code: str,
    ) -> bool:
        path = self._quarantine_path(input_digest)
        self._assert_path(path)
        if path.exists():
            return True
        if self._quarantine_count() >= self.max_quarantine:
            return False
        metadata = {
            "kind": QUARANTINE_KIND,
            "protocol_version": QUARANTINE_PROTOCOL_VERSION,
            "input_digest": input_digest,
            "rejection_code": rejection_code,
            "observed_at": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        self._atomic_write(
            path,
            (
                json.dumps(
                    metadata,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("ascii"),
        )
        return True

    def import_json(
        self,
        raw: bytes | str,
        *,
        package: RulePackage,
    ) -> RuleRecognitionImportResult:
        verified_package = self._verified_package(package)
        payload = self._input_bytes(raw)
        input_digest = self._input_digest(payload)
        try:
            if len(payload) > MAX_TRADE_JSON_BYTES:
                raise TradeRuleRecognitionRejected(
                    "recognition input exceeds byte limit"
                )
            statement = TradeRuleRecognition.from_json(payload)
            self._assert_binding(statement, verified_package)
        except TradeRuleRecognitionRejected as exc:
            rejection_code = self._rejection_code(exc)
            try:
                with self._acquire():
                    persisted = self._persist_quarantine(
                        input_digest=input_digest,
                        rejection_code=rejection_code,
                    )
            except TimeoutError as lock_exc:
                raise RuleRecognitionStoreBusy(
                    "recognition store is busy"
                ) from lock_exc
            return RuleRecognitionImportResult(
                accepted=False,
                duplicate=False,
                statement=None,
                input_digest=input_digest,
                quarantine_persisted=persisted,
                rejection_code=rejection_code,
            )
        try:
            with self._acquire():
                duplicate = self._persist_verified(statement)
        except TimeoutError as exc:
            raise RuleRecognitionStoreBusy(
                "recognition store is busy"
            ) from exc
        return RuleRecognitionImportResult(
            accepted=True,
            duplicate=duplicate,
            statement=statement,
            input_digest=input_digest,
            quarantine_persisted=False,
            rejection_code=None,
        )

    def list_for_package(
        self,
        package: RulePackage,
    ) -> tuple[TradeRuleRecognition, ...]:
        verified_package = self._verified_package(package)
        try:
            with self._acquire():
                output: list[TradeRuleRecognition] = []
                for path in self._statement_files():
                    payload = self._read_bounded(
                        path,
                        label="recognition",
                    )
                    try:
                        statement = TradeRuleRecognition.from_json(payload)
                        self._assert_binding(statement, verified_package)
                    except TradeRuleRecognitionRejected as exc:
                        if (
                            "does not bind the requested Rule Package"
                            in str(exc)
                        ):
                            continue
                        raise RuleRecognitionStoreCorruption(
                            f"stored recognition is invalid: {exc}"
                        ) from exc
                    if path != self._statement_path(statement.digest):
                        raise RuleRecognitionStoreCorruption(
                            "stored recognition filename does not match digest"
                        )
                    output.append(statement)
                output.sort(
                    key=lambda statement: (
                        statement.to_dict()["issuer_did"],
                        statement.to_dict()["sequence"],
                        statement.digest,
                    )
                )
                return tuple(output)
        except TimeoutError as exc:
            raise RuleRecognitionStoreBusy(
                "recognition store is busy"
            ) from exc


__all__ = [
    "DEFAULT_MAX_RULE_RECOGNITIONS",
    "DEFAULT_MAX_RULE_RECOGNITION_QUARANTINE",
    "DEFAULT_MAX_RULE_RECOGNITION_STORE_BYTES",
    "QUARANTINE_KIND",
    "QUARANTINE_PROTOCOL_VERSION",
    "RuleRecognitionImportResult",
    "RuleRecognitionStore",
    "RuleRecognitionStoreBusy",
    "RuleRecognitionStoreCapacity",
    "RuleRecognitionStoreCorruption",
    "RuleRecognitionStoreError",
]
