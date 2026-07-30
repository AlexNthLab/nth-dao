"""Conflict-retaining CAS storage for signed Trade Execution Receipts."""

from __future__ import annotations

import math
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.canonical import (
    MAX_TRADE_JSON_BYTES,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.execution_receipt import (
    EXECUTION_RECEIPT_ID_PREFIX,
    TradeExecutionReceipt,
    execution_receipt_digest,
)
from nth_dao.util.io import InterProcessLock

DEFAULT_MAX_EXECUTION_RECEIPTS = 10_000
DEFAULT_MAX_EXECUTION_RECEIPT_STORE_BYTES = 256 * 1024 * 1024

_EXECUTION_ID = re.compile(
    rf"^{re.escape(EXECUTION_RECEIPT_ID_PREFIX)}([0-9a-f]{{64}})$"
)
_PRIMARY_FILE = re.compile(r"^([0-9a-f]{64})\.json$")
_CONFLICT_FILE = re.compile(
    r"^([0-9a-f]{16})\.([0-9a-f]{64})\.conflict\.json$"
)
_CONFLICT_MARKER_FILE = re.compile(r"^([0-9a-f]{64})\.conflicted$")


class TradeExecutionReceiptStoreError(RuntimeError):
    """Base error for receipt persistence."""


class TradeExecutionReceiptConflict(TradeExecutionReceiptStoreError):
    """One execution ID has multiple signed receipt candidates."""


class TradeExecutionReceiptStoreBusy(TradeExecutionReceiptStoreError):
    """The receipt store lock could not be acquired in time."""


class TradeExecutionReceiptStoreCapacity(TradeExecutionReceiptStoreError):
    """A configured receipt-store capacity would be exceeded."""


@dataclass(frozen=True)
class TradeExecutionReceiptConflictStatus:
    """Public conflict state, including incomplete marker-only retention."""

    execution_id: str
    has_conflict: bool
    marker_candidate_digest: str | None
    retained_receipt_digests: tuple[str, ...]
    retention_complete: bool


class TradeExecutionReceiptStore:
    """Persist immutable receipts and retain contradictory signed candidates.

    This store makes receipt publication idempotent. It does not make an
    Adapter's external side effects exactly-once; an Adapter still needs its
    own transactional outbox or equivalent mechanism.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        max_receipts: int = DEFAULT_MAX_EXECUTION_RECEIPTS,
        max_bytes: int = DEFAULT_MAX_EXECUTION_RECEIPT_STORE_BYTES,
        lock_timeout: float = 10.0,
    ) -> None:
        if (
            isinstance(max_receipts, bool)
            or not isinstance(max_receipts, int)
            or max_receipts <= 0
        ):
            raise ValueError("max_receipts must be a positive integer")
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or max_bytes <= 0
        ):
            raise ValueError("max_bytes must be a positive integer")
        if (
            isinstance(lock_timeout, bool)
            or not isinstance(lock_timeout, (int, float))
            or not math.isfinite(lock_timeout)
            or lock_timeout <= 0
        ):
            raise ValueError("lock_timeout must be a finite positive number")
        self.workspace_root = Path(root)
        self.root = (
            self.workspace_root / "trade" / "execution_receipts_v1"
        )
        self.lock_path = self.root / ".locks" / "receipts"
        self.max_receipts = max_receipts
        self.max_bytes = max_bytes
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
            raise TradeExecutionReceiptStoreError(
                "receipt-store path escapes workspace root"
            ) from exc
        candidates = [self.workspace_root]
        current = self.workspace_root
        for part in relative.parts:
            current = current / part
            candidates.append(current)
        for candidate in candidates:
            if self._is_linklike(candidate):
                raise TradeExecutionReceiptStoreError(
                    "receipt store must not contain symlinks or junctions"
                )

    def _path(self, execution_id: str) -> Path:
        match = (
            _EXECUTION_ID.fullmatch(execution_id)
            if isinstance(execution_id, str)
            else None
        )
        if match is None:
            raise TradeExecutionReceiptStoreError(
                "execution_id is invalid"
            )
        return self.root / f"{match.group(1)}.json"

    def _actual_lock_path(self) -> Path:
        return Path(str(self.lock_path) + ".lock")

    def _conflict_marker_path(self, execution_id: str) -> Path:
        return self._path(execution_id).with_suffix(".conflicted")

    def _acquire(self):
        directory = self.lock_path.parent
        self._assert_path(directory)
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise TradeExecutionReceiptStoreError(
                f"unable to create receipt lock directory: {exc}"
            ) from exc
        self._assert_path(directory)
        self._assert_path(self._actual_lock_path())
        return InterProcessLock(self.lock_path, timeout=self.lock_timeout)

    def _read(self, path: Path) -> bytes:
        self._assert_path(path)
        try:
            size = path.stat().st_size
            if size > MAX_TRADE_JSON_BYTES:
                raise TradeExecutionReceiptStoreError(
                    "stored receipt exceeds byte limit"
                )
            payload = path.read_bytes()
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise TradeExecutionReceiptStoreError(
                f"unable to read stored receipt: {exc}"
            ) from exc
        if len(payload) != size:
            raise TradeExecutionReceiptStoreError(
                "stored receipt changed while being read"
            )
        return payload

    def _atomic_write(self, path: Path, payload: bytes) -> None:
        descriptor: int | None = None
        temporary: str | None = None
        try:
            self._assert_path(path.parent)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._assert_path(path.parent)
            self._assert_path(path)
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
            if os.name != "nt":
                directory = os.open(
                    path.parent,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                )
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        except OSError as exc:
            raise TradeExecutionReceiptStoreError(
                f"unable to persist receipt: {exc}"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def _verified(
        self,
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
    ) -> TradeExecutionReceipt:
        return TradeExecutionReceipt.from_json(
            (
                receipt.canonical_bytes
                if isinstance(receipt, TradeExecutionReceipt)
                else TradeExecutionReceipt.from_dict(
                    receipt,
                    order=order,
                ).canonical_bytes
            ),
            order=order,
        )

    def _read_verified(
        self,
        path: Path,
        order: TradeOrder | dict[str, Any],
    ) -> TradeExecutionReceipt:
        return TradeExecutionReceipt.from_json(self._read(path), order=order)

    def _conflict_path(
        self,
        receipt: TradeExecutionReceipt,
        order: TradeOrder | dict[str, Any],
    ) -> Path:
        suffix = receipt.execution_id.removeprefix(
            EXECUTION_RECEIPT_ID_PREFIX
        )
        digest = execution_receipt_digest(receipt, order=order).removeprefix(
            "sha256:"
        )
        return self.root / f"{suffix[:16]}.{digest}.conflict.json"

    def _mark_conflict(
        self,
        receipt: TradeExecutionReceipt,
        order: TradeOrder | dict[str, Any],
    ) -> None:
        path = self._conflict_marker_path(receipt.execution_id)
        candidate_digest = execution_receipt_digest(
            receipt,
            order=order,
        )
        marker = trade_canonical_json({
            "candidate_digest": candidate_digest,
            "execution_id": receipt.execution_id,
        })
        if path.exists():
            if self._conflict_marker_digest(
                receipt.execution_id
            ) is None:
                raise TradeExecutionReceiptStoreError(
                    "conflict marker is corrupt"
                )
            return
        self._atomic_write(path, marker)

    def _conflict_marker_digest(self, execution_id: str) -> str | None:
        path = self._conflict_marker_path(execution_id)
        if not path.exists():
            return None
        marker = parse_trade_json(self._read(path))
        if (
            not isinstance(marker, dict)
            or set(marker) != {"candidate_digest", "execution_id"}
            or marker["execution_id"] != execution_id
            or not isinstance(marker["candidate_digest"], str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", marker["candidate_digest"])
            is None
        ):
            raise TradeExecutionReceiptStoreError(
                "conflict marker is corrupt"
            )
        return marker["candidate_digest"]

    def _conflict_paths(
        self,
        execution_id: str,
        order: TradeOrder | dict[str, Any],
    ) -> tuple[Path, ...]:
        primary = self._path(execution_id)
        output: list[Path] = []
        for path in sorted(
            self.root.glob(f"{primary.stem[:16]}.*.conflict.json")
        ):
            receipt = self._read_verified(path, order)
            if receipt.execution_id == execution_id:
                output.append(path)
        return tuple(output)

    def _usage_locked(self) -> tuple[int, int]:
        if not self.root.exists():
            return 0, 0
        count = 0
        total = 0
        for path in self.root.rglob("*"):
            relative = path.relative_to(self.root)
            if self._is_linklike(path):
                raise TradeExecutionReceiptStoreError(
                    "receipt store must not contain symlinks or junctions"
                )
            if relative.parts and relative.parts[0] == ".locks":
                continue
            if path.is_dir():
                raise TradeExecutionReceiptStoreError(
                    "receipt store contains a directory"
                )
            if (
                _PRIMARY_FILE.fullmatch(path.name) is None
                and _CONFLICT_FILE.fullmatch(path.name) is None
                and _CONFLICT_MARKER_FILE.fullmatch(path.name) is None
            ):
                raise TradeExecutionReceiptStoreError(
                    "receipt store contains an unknown file"
                )
            count += 1
            total += path.stat().st_size
        return count, total

    def put(
        self,
        receipt: TradeExecutionReceipt | dict[str, Any],
        *,
        order: TradeOrder | dict[str, Any],
    ) -> TradeExecutionReceipt:
        verified = self._verified(receipt, order)
        path = self._path(verified.execution_id)
        try:
            with self._acquire():
                count, total = self._usage_locked()
                if path.exists():
                    existing = self._read_verified(path, order)
                    conflicts = self._conflict_paths(
                        verified.execution_id,
                        order,
                    )
                    marker_digest = self._conflict_marker_digest(
                        verified.execution_id
                    )
                    if existing.canonical_bytes == verified.canonical_bytes:
                        if marker_digest is not None or conflicts:
                            raise TradeExecutionReceiptConflict(
                                "execution has contradictory retained receipts"
                            )
                        return existing
                    candidate_digest = execution_receipt_digest(
                        verified,
                        order=order,
                    )
                    if (
                        marker_digest is not None
                        and marker_digest != candidate_digest
                    ):
                        raise TradeExecutionReceiptConflict(
                            "execution has contradictory retained receipts"
                        )
                    self._mark_conflict(verified, order)
                    conflict_path = self._conflict_path(verified, order)
                    if not conflict_path.exists():
                        if count + 1 > self.max_receipts:
                            raise TradeExecutionReceiptStoreCapacity(
                                "max_receipts prevents conflict retention"
                            )
                        if (
                            total + len(verified.canonical_bytes)
                            > self.max_bytes
                        ):
                            raise TradeExecutionReceiptStoreCapacity(
                                "max_bytes prevents conflict retention"
                            )
                        self._atomic_write(
                            conflict_path,
                            verified.canonical_bytes,
                        )
                    else:
                        retained = self._read_verified(conflict_path, order)
                        if retained.canonical_bytes != verified.canonical_bytes:
                            raise TradeExecutionReceiptStoreError(
                                "conflict digest collision or corruption"
                            )
                    raise TradeExecutionReceiptConflict(
                        "execution ID already has different signed bytes; "
                        "all candidates retained"
                    )
                if count + 1 > self.max_receipts:
                    raise TradeExecutionReceiptStoreCapacity(
                        "max_receipts exceeded"
                    )
                if total + len(verified.canonical_bytes) > self.max_bytes:
                    raise TradeExecutionReceiptStoreCapacity(
                        "max_bytes exceeded"
                    )
                self._atomic_write(path, verified.canonical_bytes)
                return verified
        except TimeoutError as exc:
            raise TradeExecutionReceiptStoreBusy(
                "Trade Execution Receipt store is busy"
            ) from exc

    def get(
        self,
        execution_id: str,
        *,
        order: TradeOrder | dict[str, Any],
    ) -> TradeExecutionReceipt | None:
        path = self._path(execution_id)
        if not self.root.exists():
            return None
        try:
            with self._acquire():
                self._usage_locked()
                conflicts = self._conflict_paths(execution_id, order)
                marker_digest = self._conflict_marker_digest(execution_id)
                if (conflicts or marker_digest is not None) and not path.exists():
                    raise TradeExecutionReceiptConflict(
                        "retained receipt candidate has no primary"
                    )
                if conflicts or marker_digest is not None:
                    raise TradeExecutionReceiptConflict(
                        "execution has contradictory retained receipts"
                    )
                if not path.exists():
                    return None
                return self._read_verified(path, order)
        except TimeoutError as exc:
            raise TradeExecutionReceiptStoreBusy(
                "Trade Execution Receipt store is busy"
            ) from exc

    def list_conflicts(
        self,
        execution_id: str,
        *,
        order: TradeOrder | dict[str, Any],
    ) -> tuple[TradeExecutionReceipt, ...]:
        self._path(execution_id)
        if not self.root.exists():
            return ()
        try:
            with self._acquire():
                primary = self._path(execution_id)
                conflicts = tuple(
                    self._read_verified(path, order)
                    for path in self._conflict_paths(execution_id, order)
                )
                marker_digest = self._conflict_marker_digest(execution_id)
                if (
                    conflicts or marker_digest is not None
                ) and not primary.exists():
                    raise TradeExecutionReceiptConflict(
                        "retained receipt candidate has no primary"
                    )
                return conflicts
        except TimeoutError as exc:
            raise TradeExecutionReceiptStoreBusy(
                "Trade Execution Receipt store is busy"
            ) from exc

    def conflict_status(
        self,
        execution_id: str,
        *,
        order: TradeOrder | dict[str, Any],
    ) -> TradeExecutionReceiptConflictStatus:
        """Return observable conflict state without hiding marker-only loss."""

        primary = self._path(execution_id)
        if not self.root.exists():
            return TradeExecutionReceiptConflictStatus(
                execution_id=execution_id,
                has_conflict=False,
                marker_candidate_digest=None,
                retained_receipt_digests=(),
                retention_complete=True,
            )
        try:
            with self._acquire():
                self._usage_locked()
                marker_digest = self._conflict_marker_digest(execution_id)
                conflict_paths = self._conflict_paths(execution_id, order)
                retained: list[str] = []
                if primary.exists():
                    retained.append(
                        execution_receipt_digest(
                            self._read_verified(primary, order),
                            order=order,
                        )
                    )
                retained.extend(
                    execution_receipt_digest(
                        self._read_verified(path, order),
                        order=order,
                    )
                    for path in conflict_paths
                )
                retained_digests = tuple(sorted(set(retained)))
                has_conflict = bool(conflict_paths) or marker_digest is not None
                retention_complete = (
                    not has_conflict
                    or (
                        primary.exists()
                        and marker_digest is not None
                        and marker_digest in retained_digests
                        and len(retained_digests) >= 2
                    )
                )
                return TradeExecutionReceiptConflictStatus(
                    execution_id=execution_id,
                    has_conflict=has_conflict,
                    marker_candidate_digest=marker_digest,
                    retained_receipt_digests=retained_digests,
                    retention_complete=retention_complete,
                )
        except TimeoutError as exc:
            raise TradeExecutionReceiptStoreBusy(
                "Trade Execution Receipt store is busy"
            ) from exc


__all__ = [
    "DEFAULT_MAX_EXECUTION_RECEIPTS",
    "DEFAULT_MAX_EXECUTION_RECEIPT_STORE_BYTES",
    "TradeExecutionReceiptConflict",
    "TradeExecutionReceiptConflictStatus",
    "TradeExecutionReceiptStore",
    "TradeExecutionReceiptStoreBusy",
    "TradeExecutionReceiptStoreCapacity",
    "TradeExecutionReceiptStoreError",
]
