"""Durable prepare-before-publish records for Dispute Statement audit."""

from __future__ import annotations

import hashlib
import math
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.dispute_statement import TradeDisputeStatement
from nth_dao.trade_rules.execution_receipt import TradeExecutionReceipt
from nth_dao.trade_rules.negotiation import RulePackageResolver
from nth_dao.trade_rules.receipt_review import TradeReceiptReview

DEFAULT_MAX_DISPUTE_AUDIT_PENDING_RECORDS = 20_000
DEFAULT_MAX_DISPUTE_AUDIT_PENDING_BYTES = 512 * 1024 * 1024
MAX_DISPUTE_AUDIT_PENDING_RECORD_BYTES = 2 * 1024 * 1024

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SCHEMA_VERSION = 1
_MAX_OBSERVED_AT_MS = 253_402_300_799_999


class TradeDisputeStatementAuditOutboxError(RuntimeError):
    """The durable audit outbox is unavailable or internally inconsistent."""


class TradeDisputeStatementAuditOutboxBusy(
    TradeDisputeStatementAuditOutboxError
):
    """Another process holds the SQLite writer lock."""


class TradeDisputeStatementAuditOutboxCapacity(
    TradeDisputeStatementAuditOutboxError
):
    """A configured record or byte limit would be exceeded."""


@dataclass(frozen=True)
class TradeDisputeStatementAuditPendingRecord:
    statement_digest: str
    statement_bytes: bytes
    review_bytes: bytes
    receipt_bytes: bytes
    order_bytes: bytes
    observed_at_ms: int

    @property
    def total_bytes(self) -> int:
        return sum(
            len(value)
            for value in (
                self.statement_bytes,
                self.review_bytes,
                self.receipt_bytes,
                self.order_bytes,
            )
        )

    def resolve(
        self,
        *,
        package_resolver: RulePackageResolver | None,
    ) -> tuple[
        TradeDisputeStatement,
        TradeReceiptReview,
        TradeExecutionReceipt,
        TradeOrder,
    ]:
        """Re-verify every signed artifact retained for restart recovery."""

        try:
            order = TradeOrder.from_json(self.order_bytes)
            receipt = TradeExecutionReceipt.from_json(
                self.receipt_bytes,
                order=order,
            )
            review = TradeReceiptReview.from_json(
                self.review_bytes,
                receipt=receipt,
                order=order,
            )
            statement = TradeDisputeStatement.from_json(
                self.statement_bytes,
                review=review,
                receipt=receipt,
                order=order,
                package_resolver=package_resolver,
            )
        except (TypeError, ValueError) as exc:
            raise TradeDisputeStatementAuditOutboxError(
                "pending Dispute Statement audit context is invalid"
            ) from exc
        actual = "sha256:" + hashlib.sha256(statement.canonical_bytes).hexdigest()
        if actual != self.statement_digest:
            raise TradeDisputeStatementAuditOutboxError(
                "pending Dispute Statement digest binding is invalid"
            )
        return statement, review, receipt, order


class TradeDisputeStatementAuditOutbox:
    """Bounded SQLite outbox committed before Statement Store publication."""

    def __init__(
        self,
        workspace: str | Path,
        *,
        max_records: int = DEFAULT_MAX_DISPUTE_AUDIT_PENDING_RECORDS,
        max_bytes: int = DEFAULT_MAX_DISPUTE_AUDIT_PENDING_BYTES,
        timeout_seconds: float = 30.0,
    ) -> None:
        if (
            isinstance(max_records, bool)
            or not isinstance(max_records, int)
            or max_records <= 0
        ):
            raise ValueError("max_records must be a positive integer")
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or max_bytes <= 0
        ):
            raise ValueError("max_bytes must be a positive integer")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a finite positive number")
        self.workspace_root = Path(workspace).resolve()
        self.root = self.workspace_root / "trade"
        self.path = self.root / "dispute_statement_audit_outbox_v1.sqlite3"
        self.max_records = max_records
        self.max_bytes = max_bytes
        self.timeout_seconds = float(timeout_seconds)
        self._initialize()

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
            raise TradeDisputeStatementAuditOutboxError(
                "Dispute Statement audit outbox path escapes workspace"
            ) from exc
        current = self.workspace_root
        for part in ("", *relative.parts):
            current = current if not part else current / part
            if self._is_linklike(current):
                raise TradeDisputeStatementAuditOutboxError(
                    "Dispute Statement audit outbox must not contain links"
                )

    def _connect(self) -> sqlite3.Connection:
        self._assert_path(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._assert_path(self.root)
        self._assert_path(self.path)
        self._assert_path(Path(str(self.path) + "-wal"))
        self._assert_path(Path(str(self.path) + "-shm"))
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=self.timeout_seconds,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except sqlite3.Error as exc:
            raise TradeDisputeStatementAuditOutboxError(
                "unable to open Dispute Statement audit outbox"
            ) from exc

    @staticmethod
    def _raise_database_error(exc: sqlite3.Error) -> None:
        if isinstance(exc, sqlite3.OperationalError) and (
            "locked" in str(exc).lower() or "busy" in str(exc).lower()
        ):
            raise TradeDisputeStatementAuditOutboxBusy(
                "Dispute Statement audit outbox is busy"
            ) from exc
        raise TradeDisputeStatementAuditOutboxError(
            "Dispute Statement audit outbox operation failed"
        ) from exc

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in {0, _SCHEMA_VERSION}:
                raise TradeDisputeStatementAuditOutboxError(
                    "Dispute Statement audit outbox schema is unsupported"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS pending (
                    statement_digest TEXT PRIMARY KEY,
                    statement_bytes BLOB NOT NULL,
                    review_bytes BLOB NOT NULL,
                    receipt_bytes BLOB NOT NULL,
                    order_bytes BLOB NOT NULL,
                    observed_at_ms INTEGER NOT NULL,
                    total_bytes INTEGER NOT NULL
                ) WITHOUT ROWID
                """
            )
            if version == 0:
                connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        except TradeDisputeStatementAuditOutboxError:
            raise
        except sqlite3.Error as exc:
            self._raise_database_error(exc)
        finally:
            connection.close()

    @staticmethod
    def _digest(value: Any) -> str:
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            raise TradeDisputeStatementAuditOutboxError(
                "statement_digest is invalid"
            )
        return value

    @staticmethod
    def _observed_at_ms(value: Any) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= _MAX_OBSERVED_AT_MS
        ):
            raise TradeDisputeStatementAuditOutboxError(
                "observed_at_ms is invalid"
            )
        return value

    @classmethod
    def _record(cls, row: sqlite3.Row) -> TradeDisputeStatementAuditPendingRecord:
        blob_fields = (
            "statement_bytes",
            "review_bytes",
            "receipt_bytes",
            "order_bytes",
        )
        if any(
            not isinstance(row[field], (bytes, bytearray, memoryview))
            for field in blob_fields
        ):
            raise TradeDisputeStatementAuditOutboxError(
                "pending Dispute Statement audit blobs are invalid"
            )
        total_bytes = row["total_bytes"]
        if isinstance(total_bytes, bool) or not isinstance(total_bytes, int):
            raise TradeDisputeStatementAuditOutboxError(
                "pending Dispute Statement byte accounting is invalid"
            )
        record = TradeDisputeStatementAuditPendingRecord(
            statement_digest=cls._digest(row["statement_digest"]),
            statement_bytes=bytes(row["statement_bytes"]),
            review_bytes=bytes(row["review_bytes"]),
            receipt_bytes=bytes(row["receipt_bytes"]),
            order_bytes=bytes(row["order_bytes"]),
            observed_at_ms=cls._observed_at_ms(row["observed_at_ms"]),
        )
        if record.total_bytes != total_bytes:
            raise TradeDisputeStatementAuditOutboxError(
                "pending Dispute Statement byte accounting is invalid"
            )
        if record.total_bytes > MAX_DISPUTE_AUDIT_PENDING_RECORD_BYTES:
            raise TradeDisputeStatementAuditOutboxError(
                "pending Dispute Statement audit record exceeds byte limit"
            )
        return record

    def prepare(
        self,
        statement: TradeDisputeStatement,
        *,
        review: TradeReceiptReview,
        receipt: TradeExecutionReceipt,
        order: TradeOrder,
        observed_at_ms: int,
    ) -> tuple[TradeDisputeStatementAuditPendingRecord, bool]:
        if not isinstance(statement, TradeDisputeStatement):
            raise TypeError("statement must be a TradeDisputeStatement")
        if not isinstance(review, TradeReceiptReview):
            raise TypeError("review must be a TradeReceiptReview")
        if not isinstance(receipt, TradeExecutionReceipt):
            raise TypeError("receipt must be a TradeExecutionReceipt")
        if not isinstance(order, TradeOrder):
            raise TypeError("order must be a TradeOrder")
        digest = "sha256:" + hashlib.sha256(statement.canonical_bytes).hexdigest()
        record = TradeDisputeStatementAuditPendingRecord(
            statement_digest=digest,
            statement_bytes=statement.canonical_bytes,
            review_bytes=review.canonical_bytes,
            receipt_bytes=receipt.canonical_bytes,
            order_bytes=order.canonical_bytes,
            observed_at_ms=self._observed_at_ms(observed_at_ms),
        )
        if record.total_bytes > MAX_DISPUTE_AUDIT_PENDING_RECORD_BYTES:
            raise TradeDisputeStatementAuditOutboxCapacity(
                "pending Dispute Statement audit record exceeds byte limit"
            )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing_row = connection.execute(
                "SELECT * FROM pending WHERE statement_digest = ?",
                (digest,),
            ).fetchone()
            if existing_row is not None:
                existing = self._record(existing_row)
                if existing != record:
                    raise TradeDisputeStatementAuditOutboxError(
                        "pending Dispute Statement digest has conflicting context"
                    )
                connection.execute("COMMIT")
                return existing, False
            usage = connection.execute(
                "SELECT COUNT(*) AS records, "
                "COALESCE(SUM(total_bytes), 0) AS bytes FROM pending"
            ).fetchone()
            if usage["records"] + 1 > self.max_records:
                raise TradeDisputeStatementAuditOutboxCapacity(
                    "max pending Dispute Statement audit records exceeded"
                )
            if usage["bytes"] + record.total_bytes > self.max_bytes:
                raise TradeDisputeStatementAuditOutboxCapacity(
                    "max pending Dispute Statement audit bytes exceeded"
                )
            connection.execute(
                "INSERT INTO pending VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    record.statement_digest,
                    record.statement_bytes,
                    record.review_bytes,
                    record.receipt_bytes,
                    record.order_bytes,
                    record.observed_at_ms,
                    record.total_bytes,
                ),
            )
            connection.execute("COMMIT")
            return record, True
        except TradeDisputeStatementAuditOutboxError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            self._raise_database_error(exc)
        finally:
            connection.close()

    def pending(
        self,
        *,
        limit: int = 100,
        after_digest: str | None = None,
    ) -> tuple[tuple[TradeDisputeStatementAuditPendingRecord, ...], bool]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        after = self._digest(after_digest) if after_digest is not None else ""
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM pending WHERE statement_digest > ? "
                "ORDER BY statement_digest LIMIT ?",
                (after, limit + 1),
            ).fetchall()
        except sqlite3.Error as exc:
            self._raise_database_error(exc)
        finally:
            connection.close()
        return tuple(self._record(row) for row in rows[:limit]), len(rows) > limit

    def complete(self, record: TradeDisputeStatementAuditPendingRecord) -> bool:
        digest = self._digest(record.statement_digest)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM pending WHERE statement_digest = ?",
                (digest,),
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return False
            if self._record(row) != record:
                raise TradeDisputeStatementAuditOutboxError(
                    "pending Dispute Statement changed before completion"
                )
            connection.execute(
                "DELETE FROM pending WHERE statement_digest = ?",
                (digest,),
            )
            connection.execute("COMMIT")
            return True
        except TradeDisputeStatementAuditOutboxError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            self._raise_database_error(exc)
        finally:
            connection.close()


__all__ = [
    "DEFAULT_MAX_DISPUTE_AUDIT_PENDING_BYTES",
    "DEFAULT_MAX_DISPUTE_AUDIT_PENDING_RECORDS",
    "MAX_DISPUTE_AUDIT_PENDING_RECORD_BYTES",
    "TradeDisputeStatementAuditOutbox",
    "TradeDisputeStatementAuditOutboxBusy",
    "TradeDisputeStatementAuditOutboxCapacity",
    "TradeDisputeStatementAuditOutboxError",
    "TradeDisputeStatementAuditPendingRecord",
]
