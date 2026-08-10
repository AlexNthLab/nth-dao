"""Bounded content-addressed storage for verified Trade Dispute Statements."""

from __future__ import annotations

import hashlib
import math
import os
import re
import stat
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.canonical import (
    MAX_TRADE_JSON_BYTES,
    parse_trade_json,
    trade_canonical_json,
)
from nth_dao.trade_rules.dispute_statement import (
    TRADE_DISPUTE_ID_PREFIX,
    TRADE_DISPUTE_STATEMENT_ID_PREFIX,
    TRADE_DISPUTE_STATEMENT_KIND,
    TradeDisputeStatement,
)
from nth_dao.trade_rules.agreement import DEFAULT_CLOCK_SKEW_SECONDS
from nth_dao.trade_rules.execution_receipt import TradeExecutionReceipt
from nth_dao.trade_rules.negotiation import RulePackageResolver
from nth_dao.trade_rules.receipt_review import (
    TradeReceiptReview,
    receipt_review_digest,
)
from nth_dao.util.io import InterProcessLock

DEFAULT_MAX_TRADE_DISPUTE_STATEMENTS = 20_000
DEFAULT_MAX_TRADE_DISPUTE_STORE_BYTES = 512 * 1024 * 1024
MAX_TRADE_DISPUTE_PAGE_SIZE = 500

_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
_PAGE_CURSOR = re.compile(r"^v1:([0-9a-f]{64}):([0-9a-f]{64})$")
_STATEMENT_FILE = re.compile(r"^([0-9a-f]{64})\.json$")
_TEMPORARY_FILE = re.compile(r"^[0-9a-f]{64}\.json\.[A-Za-z0-9_-]+\.tmp$")
_STATEMENT_ID = re.compile(
    rf"^{re.escape(TRADE_DISPUTE_STATEMENT_ID_PREFIX)}[0-9a-f]{{64}}$"
)
_DISPUTE_ID = re.compile(rf"^{re.escape(TRADE_DISPUTE_ID_PREFIX)}[0-9a-f]{{64}}$")
_TIMESTAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{6}))?Z$")


class TradeDisputeStatementStoreError(RuntimeError):
    """Base error for dispute-statement persistence."""


class TradeDisputeStatementStoreBusy(TradeDisputeStatementStoreError):
    """The statement-store lock could not be acquired in time."""


class TradeDisputeStatementStoreCapacity(TradeDisputeStatementStoreError):
    """A configured statement-store capacity would be exceeded."""


@dataclass(frozen=True)
class TradeDisputeStatementPage:
    """One deterministic page for a single exact Receipt Review candidate."""

    statements: tuple[TradeDisputeStatement, ...]
    statement_digests: tuple[str, ...]
    next_cursor: str | None


@dataclass(frozen=True)
class TradeDisputeStatementReconciliationReport:
    """Bounded store inspection and explicitly requested temp cleanup."""

    statement_count: int
    total_bytes: int
    temporary_paths: tuple[str, ...]
    corrupt_paths: tuple[str, ...]
    unknown_paths: tuple[str, ...]
    removed_temporary_paths: tuple[str, ...]


@dataclass(frozen=True)
class _StoredRecord:
    path: Path
    payload: bytes
    document: dict[str, Any]
    digest: str
    created_at_micros: int


@dataclass(frozen=True)
class _IndexedRecord:
    path: Path
    digest: str
    review_digest: str
    statement_id: str
    created_at_micros: int


def _canonical_timestamp_micros(value: Any) -> int:
    match = _TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    if match is None or match.group(2) == "000000":
        raise TradeDisputeStatementStoreError(
            "stored dispute statement created_at is invalid"
        )
    fraction = match.group(2)
    try:
        moment = datetime.strptime(
            match.group(1) + (f".{fraction}" if fraction else ""),
            "%Y-%m-%dT%H:%M:%S.%f" if fraction else "%Y-%m-%dT%H:%M:%S",
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise TradeDisputeStatementStoreError(
            "stored dispute statement created_at is invalid"
        ) from exc
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = moment - epoch
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


class TradeDisputeStatementStore:
    """Persist immutable signed statements without asserting claim truth."""

    def __init__(
        self,
        workspace: str | Path,
        *,
        max_statements: int = DEFAULT_MAX_TRADE_DISPUTE_STATEMENTS,
        max_bytes: int = DEFAULT_MAX_TRADE_DISPUTE_STORE_BYTES,
        lock_timeout: float = 10.0,
    ) -> None:
        if (
            isinstance(max_statements, bool)
            or not isinstance(max_statements, int)
            or max_statements <= 0
        ):
            raise ValueError("max_statements must be a positive integer")
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
        self.workspace_root = Path(workspace).resolve()
        self.root = self.workspace_root / "trade" / "dispute_statements_v1"
        self.lock_path = self.root / ".locks" / "statements"
        self.max_statements = max_statements
        self.max_bytes = max_bytes
        self.lock_timeout = float(lock_timeout)
        self._index_cache: dict[str, _IndexedRecord] = {}
        self._index_cache_lock = threading.RLock()

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
            raise TradeDisputeStatementStoreError(
                "dispute-statement store path escapes workspace root"
            ) from exc
        current = self.workspace_root
        candidates = [current]
        for part in relative.parts:
            current = current / part
            candidates.append(current)
        for candidate in candidates:
            if self._is_linklike(candidate):
                raise TradeDisputeStatementStoreError(
                    "dispute-statement store must not contain links"
                )

    @staticmethod
    def _statement_digest(payload: bytes) -> str:
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def _path(self, statement_digest: str) -> Path:
        match = (
            _DIGEST.fullmatch(statement_digest)
            if isinstance(statement_digest, str)
            else None
        )
        if match is None:
            raise TradeDisputeStatementStoreError("statement_digest is invalid")
        return self.root / f"{match.group(1)}.json"

    @staticmethod
    def _snapshot_digest(records: list[_IndexedRecord]) -> str:
        payload = b"\x00".join(record.digest.encode("ascii") for record in records)
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _decode_page_cursor(value: str) -> tuple[str, str]:
        match = _PAGE_CURSOR.fullmatch(value) if isinstance(value, str) else None
        if match is None:
            raise TradeDisputeStatementStoreError("pagination cursor is invalid")
        return match.group(1), "sha256:" + match.group(2)

    @staticmethod
    def _encode_page_cursor(snapshot: str, digest: str) -> str:
        match = _DIGEST.fullmatch(digest)
        if match is None:
            raise TradeDisputeStatementStoreError("statement digest is invalid")
        return f"v1:{snapshot}:{match.group(1)}"

    def _acquire(self) -> InterProcessLock:
        directory = self.lock_path.parent
        self._assert_path(directory)
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise TradeDisputeStatementStoreError(
                f"unable to create statement-store lock directory: {exc}"
            ) from exc
        self._assert_path(directory)
        self._assert_path(Path(str(self.lock_path) + ".lock"))
        return InterProcessLock(self.lock_path, timeout=self.lock_timeout)

    def _read(self, path: Path) -> bytes:
        self._assert_path(path)
        try:
            with path.open("rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise TradeDisputeStatementStoreError(
                        "stored dispute statement is not a regular file"
                    )
                if before.st_size > MAX_TRADE_JSON_BYTES:
                    raise TradeDisputeStatementStoreError(
                        "stored dispute statement exceeds byte limit"
                    )
                payload = stream.read(MAX_TRADE_JSON_BYTES + 1)
                after = os.fstat(stream.fileno())
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise TradeDisputeStatementStoreError(
                f"unable to read stored dispute statement: {exc}"
            ) from exc
        if len(payload) > MAX_TRADE_JSON_BYTES:
            raise TradeDisputeStatementStoreError(
                "stored dispute statement exceeds byte limit"
            )
        if before.st_size != after.st_size or len(payload) != after.st_size:
            raise TradeDisputeStatementStoreError(
                "stored dispute statement changed while being read"
            )
        return payload

    def _atomic_write(self, path: Path, payload: bytes) -> None:
        descriptor: int | None = None
        temporary: str | None = None
        try:
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
            raise TradeDisputeStatementStoreError(
                f"unable to persist dispute statement: {exc}"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def _record_from_payload(self, path: Path, payload: bytes) -> _StoredRecord:
        match = _STATEMENT_FILE.fullmatch(path.name)
        if match is None:
            raise TradeDisputeStatementStoreError(
                "dispute-statement store contains an unknown file"
            )
        try:
            document = parse_trade_json(payload)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise TradeDisputeStatementStoreError(
                "stored dispute statement is not canonical"
            ) from exc
        if trade_canonical_json(document) != payload:
            raise TradeDisputeStatementStoreError(
                "stored dispute statement is not canonical"
            )
        digest_value = self._statement_digest(payload)
        if digest_value.removeprefix("sha256:") != match.group(1):
            raise TradeDisputeStatementStoreError(
                "stored dispute statement content digest mismatch"
            )
        if (
            document.get("kind") != TRADE_DISPUTE_STATEMENT_KIND
            or not isinstance(document.get("statement_id"), str)
            or _STATEMENT_ID.fullmatch(document["statement_id"]) is None
            or not isinstance(document.get("dispute_id"), str)
            or _DISPUTE_ID.fullmatch(document["dispute_id"]) is None
            or not isinstance(document.get("review_digest"), str)
            or _DIGEST.fullmatch(document["review_digest"]) is None
        ):
            raise TradeDisputeStatementStoreError(
                "stored dispute statement header is invalid"
            )
        created_at_micros = _canonical_timestamp_micros(document.get("created_at"))
        return _StoredRecord(
            path,
            payload,
            document,
            digest_value,
            created_at_micros,
        )

    def _read_record(self, path: Path) -> _StoredRecord:
        return self._record_from_payload(path, self._read(path))

    def _scan_inventory_locked(self) -> tuple[int, int]:
        if not self.root.exists():
            return 0, 0
        count = 0
        total = 0
        try:
            entries = sorted(self.root.iterdir())
        except OSError as exc:
            raise TradeDisputeStatementStoreError(
                f"unable to inspect dispute-statement store: {exc}"
            ) from exc
        for path in entries:
            if path.name == ".locks":
                if self._is_linklike(path) or not path.is_dir():
                    raise TradeDisputeStatementStoreError(
                        "dispute-statement lock path is invalid"
                    )
                continue
            if self._is_linklike(path):
                raise TradeDisputeStatementStoreError(
                    "dispute-statement store must not contain links"
                )
            if path.is_dir():
                raise TradeDisputeStatementStoreError(
                    "dispute-statement store contains an unknown directory"
                )
            if _TEMPORARY_FILE.fullmatch(path.name) is not None:
                continue
            if _STATEMENT_FILE.fullmatch(path.name) is None:
                raise TradeDisputeStatementStoreError(
                    "dispute-statement store contains an unknown file"
                )
            try:
                metadata = path.stat()
            except OSError as exc:
                raise TradeDisputeStatementStoreError(
                    f"unable to inspect stored dispute statement: {exc}"
                ) from exc
            if not stat.S_ISREG(metadata.st_mode):
                raise TradeDisputeStatementStoreError(
                    "stored dispute statement is not a regular file"
                )
            if metadata.st_size > MAX_TRADE_JSON_BYTES:
                raise TradeDisputeStatementStoreError(
                    "stored dispute statement exceeds byte limit"
                )
            count += 1
            total += int(metadata.st_size)
        return count, total

    def _records_locked(self) -> tuple[_IndexedRecord, ...]:
        if not self.root.exists():
            return ()
        with self._index_cache_lock:
            records: list[_IndexedRecord] = []
            next_cache: dict[str, _IndexedRecord] = {}
            for path in sorted(self.root.rglob("*")):
                relative = path.relative_to(self.root)
                if relative.parts and relative.parts[0] == ".locks":
                    continue
                if (
                    len(relative.parts) == 1
                    and _TEMPORARY_FILE.fullmatch(path.name) is not None
                ):
                    continue
                if self._is_linklike(path):
                    raise TradeDisputeStatementStoreError(
                        "dispute-statement store must not contain links"
                    )
                if path.is_dir():
                    raise TradeDisputeStatementStoreError(
                        "dispute-statement store contains an unknown directory"
                    )
                match = _STATEMENT_FILE.fullmatch(path.name)
                if match is None:
                    raise TradeDisputeStatementStoreError(
                        "dispute-statement store contains an unknown file"
                    )
                payload = self._read(path)
                digest_value = self._statement_digest(payload)
                if digest_value.removeprefix("sha256:") != match.group(1):
                    raise TradeDisputeStatementStoreError(
                        "stored dispute statement content digest mismatch"
                    )
                indexed = self._index_cache.get(path.name)
                if indexed is None or indexed.digest != digest_value:
                    stored = self._record_from_payload(path, payload)
                    indexed = _IndexedRecord(
                        path=path,
                        digest=stored.digest,
                        review_digest=stored.document["review_digest"],
                        statement_id=stored.document["statement_id"],
                        created_at_micros=stored.created_at_micros,
                    )
                next_cache[path.name] = indexed
                records.append(indexed)
            self._index_cache = next_cache
            return tuple(records)

    @staticmethod
    def _verified_context(
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
    ) -> tuple[TradeReceiptReview, TradeExecutionReceipt, TradeOrder]:
        verified_order = (
            TradeOrder.from_json(order.canonical_bytes)
            if isinstance(order, TradeOrder)
            else TradeOrder.from_dict(order)
        )
        verified_receipt = (
            TradeExecutionReceipt.from_json(
                receipt.canonical_bytes,
                order=verified_order,
            )
            if isinstance(receipt, TradeExecutionReceipt)
            else TradeExecutionReceipt.from_dict(
                receipt,
                order=verified_order,
            )
        )
        verified_review = (
            TradeReceiptReview.from_json(
                review.canonical_bytes,
                receipt=verified_receipt,
                order=verified_order,
            )
            if isinstance(review, TradeReceiptReview)
            else TradeReceiptReview.from_dict(
                review,
                receipt=verified_receipt,
                order=verified_order,
            )
        )
        return verified_review, verified_receipt, verified_order

    @classmethod
    def _verified_statement(
        cls,
        statement: TradeDisputeStatement | dict[str, Any],
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        package_resolver: RulePackageResolver | None,
    ) -> TradeDisputeStatement:
        verified_review, verified_receipt, verified_order = cls._verified_context(
            review=review,
            receipt=receipt,
            order=order,
        )
        raw = (
            statement.canonical_bytes
            if isinstance(statement, TradeDisputeStatement)
            else trade_canonical_json(statement)
        )
        return TradeDisputeStatement.from_json(
            raw,
            review=verified_review,
            receipt=verified_receipt,
            order=verified_order,
            package_resolver=package_resolver,
        )

    def put(
        self,
        statement: TradeDisputeStatement | dict[str, Any],
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        package_resolver: RulePackageResolver | None = None,
        at: datetime | None = None,
        clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
    ) -> tuple[TradeDisputeStatement, bool]:
        """Retain one verified statement; return ``(statement, created)``."""

        verified = self._verified_statement(
            statement,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=package_resolver,
        )
        verified.assert_observed_at(
            at=at,
            clock_skew_seconds=clock_skew_seconds,
        )
        digest_value = self._statement_digest(verified.canonical_bytes)
        path = self._path(digest_value)
        try:
            with self._acquire():
                if path.exists():
                    existing = self._read_record(path)
                    if existing.payload != verified.canonical_bytes:
                        raise TradeDisputeStatementStoreError(
                            "statement digest collision or store corruption"
                    )
                    return verified, False
                count, total = self._scan_inventory_locked()
                if count + 1 > self.max_statements:
                    raise TradeDisputeStatementStoreCapacity("max_statements exceeded")
                if total + len(verified.canonical_bytes) > self.max_bytes:
                    raise TradeDisputeStatementStoreCapacity("max_bytes exceeded")
                self._atomic_write(path, verified.canonical_bytes)
                return verified, True
        except TimeoutError as exc:
            raise TradeDisputeStatementStoreBusy(
                "Trade Dispute Statement store is busy"
            ) from exc

    def get(
        self,
        statement_digest: str,
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        package_resolver: RulePackageResolver | None = None,
    ) -> TradeDisputeStatement | None:
        path = self._path(statement_digest)
        if not self.root.exists():
            return None
        try:
            with self._acquire():
                try:
                    record = self._read_record(path)
                except FileNotFoundError:
                    record = None
        except TimeoutError as exc:
            raise TradeDisputeStatementStoreBusy(
                "Trade Dispute Statement store is busy"
            ) from exc
        if record is None:
            return None
        return self._verified_statement(
            record.document,
            review=review,
            receipt=receipt,
            order=order,
            package_resolver=package_resolver,
        )

    def list_for_review(
        self,
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        package_resolver: RulePackageResolver | None = None,
        limit: int = 100,
        after: str | None = None,
    ) -> TradeDisputeStatementPage:
        """List statements bound to one exact signed Review candidate."""

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or limit < 1
            or limit > MAX_TRADE_DISPUTE_PAGE_SIZE
        ):
            raise ValueError(
                f"limit must be between 1 and {MAX_TRADE_DISPUTE_PAGE_SIZE}"
            )
        cursor_snapshot: str | None = None
        cursor_digest: str | None = None
        if after is not None:
            cursor_snapshot, cursor_digest = self._decode_page_cursor(after)
        verified_review, verified_receipt, verified_order = self._verified_context(
            review=review,
            receipt=receipt,
            order=order,
        )
        review_digest_value = receipt_review_digest(
            verified_review,
            receipt=verified_receipt,
            order=verified_order,
        )
        if not self.root.exists():
            if cursor_snapshot is not None:
                raise TradeDisputeStatementStoreError(
                    "pagination snapshot changed; restart listing"
                )
            return TradeDisputeStatementPage((), (), None)
        try:
            with self._acquire():
                matching = [
                    record
                    for record in self._records_locked()
                    if record.review_digest == review_digest_value
                ]
                matching.sort(
                    key=lambda record: (
                        record.created_at_micros,
                        record.statement_id,
                        record.digest,
                    )
                )
                snapshot = self._snapshot_digest(matching)
                if cursor_snapshot is not None and cursor_snapshot != snapshot:
                    raise TradeDisputeStatementStoreError(
                        "pagination snapshot changed; restart listing"
                    )
                start = 0
                if cursor_digest is not None:
                    positions = [
                        index
                        for index, record in enumerate(matching)
                        if record.digest == cursor_digest
                    ]
                    if not positions:
                        raise TradeDisputeStatementStoreError(
                            "pagination cursor is not in this Review"
                        )
                    start = positions[0] + 1
                selected_index = matching[start : start + limit]
                try:
                    selected = [
                        self._read_record(record.path) for record in selected_index
                    ]
                except FileNotFoundError as exc:
                    raise TradeDisputeStatementStoreError(
                        "dispute-statement store changed during listing"
                    ) from exc
                has_more = start + len(selected_index) < len(matching)
        except TimeoutError as exc:
            raise TradeDisputeStatementStoreBusy(
                "Trade Dispute Statement store is busy"
            ) from exc
        statements = tuple(
            TradeDisputeStatement.from_json(
                record.payload,
                review=verified_review,
                receipt=verified_receipt,
                order=verified_order,
                package_resolver=package_resolver,
            )
            for record in selected
        )
        return TradeDisputeStatementPage(
            statements=statements,
            statement_digests=tuple(record.digest for record in selected),
            next_cursor=(
                self._encode_page_cursor(snapshot, selected[-1].digest)
                if has_more and selected
                else None
            ),
        )

    def reconcile(
        self,
        *,
        cleanup_temporary: bool = False,
    ) -> TradeDisputeStatementReconciliationReport:
        """Inspect all files and optionally remove only atomic-write residue."""

        if not isinstance(cleanup_temporary, bool):
            raise TypeError("cleanup_temporary must be a boolean")
        if not self.root.exists():
            return TradeDisputeStatementReconciliationReport(0, 0, (), (), (), ())
        try:
            with self._acquire():
                temporary: list[str] = []
                corrupt: list[str] = []
                unknown: list[str] = []
                removed: list[str] = []
                statement_count = 0
                total_bytes = 0
                for path in sorted(self.root.rglob("*")):
                    relative = path.relative_to(self.root)
                    if relative.parts and relative.parts[0] == ".locks":
                        continue
                    name = relative.as_posix()
                    if self._is_linklike(path) or path.is_dir():
                        unknown.append(name)
                        continue
                    if (
                        len(relative.parts) == 1
                        and _TEMPORARY_FILE.fullmatch(path.name) is not None
                    ):
                        temporary.append(name)
                        if cleanup_temporary:
                            try:
                                path.unlink()
                            except OSError as exc:
                                raise TradeDisputeStatementStoreError(
                                    f"unable to remove temporary file: {exc}"
                                ) from exc
                            removed.append(name)
                        continue
                    if _STATEMENT_FILE.fullmatch(path.name) is None:
                        unknown.append(name)
                        continue
                    try:
                        record = self._read_record(path)
                    except (TradeDisputeStatementStoreError, ValueError):
                        corrupt.append(name)
                        continue
                    statement_count += 1
                    total_bytes += len(record.payload)
                return TradeDisputeStatementReconciliationReport(
                    statement_count=statement_count,
                    total_bytes=total_bytes,
                    temporary_paths=tuple(temporary),
                    corrupt_paths=tuple(corrupt),
                    unknown_paths=tuple(unknown),
                    removed_temporary_paths=tuple(removed),
                )
        except TimeoutError as exc:
            raise TradeDisputeStatementStoreBusy(
                "Trade Dispute Statement store is busy"
            ) from exc


__all__ = [
    "DEFAULT_MAX_TRADE_DISPUTE_STATEMENTS",
    "DEFAULT_MAX_TRADE_DISPUTE_STORE_BYTES",
    "MAX_TRADE_DISPUTE_PAGE_SIZE",
    "TradeDisputeStatementPage",
    "TradeDisputeStatementReconciliationReport",
    "TradeDisputeStatementStore",
    "TradeDisputeStatementStoreBusy",
    "TradeDisputeStatementStoreCapacity",
    "TradeDisputeStatementStoreError",
]
