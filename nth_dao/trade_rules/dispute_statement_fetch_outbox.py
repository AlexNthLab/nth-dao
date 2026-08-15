"""Durable requester-side state for signed Dispute Statement fetches."""

from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nth_dao.canonical_json import canonical_json
from nth_dao.spine import SpineEvent
from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.canonical import parse_trade_json, trade_canonical_json
from nth_dao.trade_rules.dispute_statement_retrieval import (
    TradeDisputeStatementFetchRequest,
    TradeDisputeStatementFetchResponse,
)
from nth_dao.trade_rules.execution_receipt import TradeExecutionReceipt
from nth_dao.trade_rules.receipt_review import TradeReceiptReview
from nth_dao.trade_rules.transport_common import (
    MAX_TRANSPORT_TIMESTAMP_NS,
    timestamp_ns,
)

DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_OUTBOX_RECORDS = 10_000
DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_OUTBOX_BYTES = 512 * 1024 * 1024
MAX_DISPUTE_STATEMENT_FETCH_OUTBOX_RECORD_BYTES = 1024 * 1024
DEFAULT_DISPUTE_STATEMENT_FETCH_OUTBOX_RETENTION_SECONDS = 24 * 60 * 60
DEFAULT_DISPUTE_STATEMENT_FETCH_OUTBOX_CLEANUP_LIMIT = 1_000
MAX_DISPUTE_STATEMENT_FETCH_OUTBOX_CLEANUP_LIMIT = 10_000
MAX_DISPUTE_STATEMENT_FETCH_OUTBOX_RETENTION_SECONDS = 365 * 24 * 60 * 60

_SCHEMA_VERSION = 1


class TradeDisputeStatementFetchOutboxError(RuntimeError):
    """Requester fetch state is unavailable or inconsistent."""


class TradeDisputeStatementFetchOutboxBusy(TradeDisputeStatementFetchOutboxError):
    """Another process currently owns the outbox writer lock."""


class TradeDisputeStatementFetchOutboxCapacity(TradeDisputeStatementFetchOutboxError):
    """A configured requester outbox bound would be exceeded."""


class TradeDisputeStatementFetchOutboxConflict(TradeDisputeStatementFetchOutboxError):
    """Retained requester material conflicts with a retry."""


@dataclass(frozen=True)
class TradeDisputeStatementFetchOutboxRecord:
    operation_id: str
    generation: int
    target_url: str
    request_digest: str
    request_bytes: bytes
    response_digest: str | None
    response_bytes: bytes | None
    audit_event_id: str | None
    audit_event_bytes: bytes | None
    not_after_ns: int
    created_at_ns: int
    updated_at_ns: int
    attempts: int
    last_error: str

    @property
    def completed(self) -> bool:
        return self.response_bytes is not None

    @property
    def total_bytes(self) -> int:
        return (
            len(self.target_url.encode("utf-8"))
            + len(self.request_bytes)
            + len(self.response_bytes or b"")
            + len(self.audit_event_bytes or b"")
        )

    def resolve(
        self,
        *,
        review: TradeReceiptReview | dict[str, Any],
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
    ) -> tuple[
        TradeDisputeStatementFetchRequest,
        TradeDisputeStatementFetchResponse | None,
        SpineEvent | None,
    ]:
        """Reparse every retained signed object against current local context."""

        try:
            request = TradeDisputeStatementFetchRequest.from_json(
                self.request_bytes,
                review=review,
                receipt=receipt,
                order=order,
            )
            response = (
                TradeDisputeStatementFetchResponse.from_json(
                    self.response_bytes,
                    request=request,
                    review=review,
                    receipt=receipt,
                    order=order,
                )
                if self.response_bytes is not None
                else None
            )
            event = (
                SpineEvent.from_dict(json.loads(self.audit_event_bytes.decode("utf-8")))
                if self.audit_event_bytes is not None
                else None
            )
        except (KeyError, TypeError, UnicodeDecodeError, ValueError) as exc:
            raise TradeDisputeStatementFetchOutboxError(
                "retained requester fetch material failed verification"
            ) from exc
        return request, response, event


def _trade_dispute_statement_fetch_operation_id_from_document(
    target_url: str,
    document: dict[str, Any],
) -> str:
    if not isinstance(target_url, str) or not 1 <= len(target_url) <= 2_048:
        raise TradeDisputeStatementFetchOutboxError("target_url is invalid")
    try:
        identity = {
            "target_url": target_url,
            "order_digest": document["order_digest"],
            "execution_id": document["execution_id"],
            "review_id": document["review_id"],
            "statement_digest": document["statement_digest"],
            "requester_did": document["requester_did"],
            "responder_did": document["responder_did"],
        }
    except KeyError as exc:
        raise TradeDisputeStatementFetchOutboxError(
            "fetch request identity is incomplete"
        ) from exc
    if any(not isinstance(value, str) or not value for value in identity.values()):
        raise TradeDisputeStatementFetchOutboxError(
            "fetch request identity is invalid"
        )
    return hashlib.sha256(canonical_json(identity)).hexdigest()


def trade_dispute_statement_fetch_operation_id(
    target_url: str,
    request: TradeDisputeStatementFetchRequest,
) -> str:
    """Return the stable business key used across request generations."""

    if not isinstance(request, TradeDisputeStatementFetchRequest):
        raise TypeError("request must be a TradeDisputeStatementFetchRequest")
    return _trade_dispute_statement_fetch_operation_id_from_document(
        target_url,
        request.to_dict(),
    )


class TradeDisputeStatementFetchOutbox:
    """Bounded SQLite outbox that preserves exact signed retry material."""

    def __init__(
        self,
        workspace: str | Path,
        *,
        max_records: int = DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_OUTBOX_RECORDS,
        max_bytes: int = DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_OUTBOX_BYTES,
        timeout_seconds: float = 30.0,
        retention_seconds: float = (
            DEFAULT_DISPUTE_STATEMENT_FETCH_OUTBOX_RETENTION_SECONDS
        ),
        cleanup_limit: int = DEFAULT_DISPUTE_STATEMENT_FETCH_OUTBOX_CLEANUP_LIMIT,
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
        if (
            isinstance(retention_seconds, bool)
            or not isinstance(retention_seconds, (int, float))
            or not math.isfinite(retention_seconds)
            or not 0
            <= retention_seconds
            <= MAX_DISPUTE_STATEMENT_FETCH_OUTBOX_RETENTION_SECONDS
        ):
            raise ValueError("retention_seconds is invalid")
        if (
            isinstance(cleanup_limit, bool)
            or not isinstance(cleanup_limit, int)
            or not 1
            <= cleanup_limit
            <= MAX_DISPUTE_STATEMENT_FETCH_OUTBOX_CLEANUP_LIMIT
        ):
            raise ValueError("cleanup_limit is invalid")
        self.workspace_root = Path(workspace).resolve()
        self.root = self.workspace_root / "trade"
        self.path = self.root / "dispute_statement_fetch_outbox_v1.sqlite3"
        self.max_records = max_records
        self.max_bytes = max_bytes
        self.timeout_seconds = float(timeout_seconds)
        self.retention_ns = int(float(retention_seconds) * 1_000_000_000)
        self.cleanup_limit = cleanup_limit
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
            raise TradeDisputeStatementFetchOutboxError(
                "fetch outbox path escapes workspace"
            ) from exc
        current = self.workspace_root
        for part in ("", *relative.parts):
            current = current if not part else current / part
            if self._is_linklike(current):
                raise TradeDisputeStatementFetchOutboxError(
                    "fetch outbox path must not contain links"
                )

    def _connect(self) -> sqlite3.Connection:
        self._assert_path(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._assert_path(self.root)
        for path in (
            self.path,
            Path(str(self.path) + "-wal"),
            Path(str(self.path) + "-shm"),
            Path(str(self.path) + "-journal"),
        ):
            self._assert_path(path)
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=self.timeout_seconds,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except sqlite3.Error as exc:
            self._raise_database_error(exc)

    @staticmethod
    def _raise_database_error(exc: sqlite3.Error) -> None:
        if isinstance(exc, sqlite3.OperationalError) and any(
            marker in str(exc).lower() for marker in ("locked", "busy")
        ):
            raise TradeDisputeStatementFetchOutboxBusy("fetch outbox is busy") from exc
        raise TradeDisputeStatementFetchOutboxError(
            "fetch outbox operation failed"
        ) from exc

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in {0, _SCHEMA_VERSION}:
                raise TradeDisputeStatementFetchOutboxError(
                    "fetch outbox schema is unsupported"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS fetch_outbox (
                    operation_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    target_url TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    request_bytes BLOB NOT NULL,
                    response_digest TEXT,
                    response_bytes BLOB,
                    audit_event_id TEXT,
                    audit_event_bytes BLOB,
                    not_after_ns INTEGER NOT NULL,
                    created_at_ns INTEGER NOT NULL,
                    updated_at_ns INTEGER NOT NULL,
                    attempts INTEGER NOT NULL,
                    last_error TEXT NOT NULL,
                    total_bytes INTEGER NOT NULL,
                    PRIMARY KEY (operation_id, generation),
                    CHECK (generation >= 1),
                    CHECK (attempts >= 0),
                    CHECK (
                        (response_bytes IS NULL AND response_digest IS NULL
                         AND audit_event_id IS NULL AND audit_event_bytes IS NULL)
                        OR
                        (response_bytes IS NOT NULL AND response_digest IS NOT NULL
                         AND audit_event_id IS NOT NULL AND audit_event_bytes IS NOT NULL)
                    )
                ) WITHOUT ROWID
                """
            )
            if version == 0:
                connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise TradeDisputeStatementFetchOutboxError(
                    "fetch outbox integrity check failed"
                )
        except TradeDisputeStatementFetchOutboxError:
            raise
        except sqlite3.Error as exc:
            self._raise_database_error(exc)
        finally:
            connection.close()

    @staticmethod
    def _record(row: sqlite3.Row) -> TradeDisputeStatementFetchOutboxRecord:
        try:
            record = TradeDisputeStatementFetchOutboxRecord(
                operation_id=str(row["operation_id"]),
                generation=int(row["generation"]),
                target_url=str(row["target_url"]),
                request_digest=str(row["request_digest"]),
                request_bytes=bytes(row["request_bytes"]),
                response_digest=(
                    str(row["response_digest"])
                    if row["response_digest"] is not None
                    else None
                ),
                response_bytes=(
                    bytes(row["response_bytes"])
                    if row["response_bytes"] is not None
                    else None
                ),
                audit_event_id=(
                    str(row["audit_event_id"])
                    if row["audit_event_id"] is not None
                    else None
                ),
                audit_event_bytes=(
                    bytes(row["audit_event_bytes"])
                    if row["audit_event_bytes"] is not None
                    else None
                ),
                not_after_ns=int(row["not_after_ns"]),
                created_at_ns=int(row["created_at_ns"]),
                updated_at_ns=int(row["updated_at_ns"]),
                attempts=int(row["attempts"]),
                last_error=str(row["last_error"]),
            )
        except (IndexError, OverflowError, TypeError, ValueError) as exc:
            raise TradeDisputeStatementFetchOutboxError(
                "retained fetch outbox record is invalid"
            ) from exc
        try:
            request_document = parse_trade_json(record.request_bytes)
            if trade_canonical_json(request_document) != record.request_bytes:
                raise ValueError("request is not canonical")
            if (
                _trade_dispute_statement_fetch_operation_id_from_document(
                    record.target_url,
                    request_document,
                )
                != record.operation_id
            ):
                raise ValueError("request identity changed")
            if (
                timestamp_ns(
                    request_document["not_after"],
                    label="request not_after",
                    error_type=ValueError,
                )
                != record.not_after_ns
            ):
                raise ValueError("request expiry changed")
            if record.response_bytes is not None:
                response_document = parse_trade_json(record.response_bytes)
                if trade_canonical_json(response_document) != record.response_bytes:
                    raise ValueError("response is not canonical")
            if record.audit_event_bytes is not None:
                audit_document = json.loads(record.audit_event_bytes.decode("utf-8"))
                if canonical_json(audit_document) != record.audit_event_bytes:
                    raise ValueError("audit event is not canonical")
                if (
                    SpineEvent.from_dict(audit_document).event_id
                    != record.audit_event_id
                ):
                    raise ValueError("audit event ID changed")
        except (
            KeyError,
            TradeDisputeStatementFetchOutboxError,
            TypeError,
            UnicodeDecodeError,
            ValueError,
        ) as exc:
            raise TradeDisputeStatementFetchOutboxError(
                "retained fetch outbox bytes are invalid"
            ) from exc
        if (
            len(record.operation_id) != 64
            or any(char not in "0123456789abcdef" for char in record.operation_id)
            or record.generation < 1
            or not 1 <= record.not_after_ns <= MAX_TRANSPORT_TIMESTAMP_NS
            or not 1 <= record.created_at_ns <= MAX_TRANSPORT_TIMESTAMP_NS
            or not record.created_at_ns
            <= record.updated_at_ns
            <= MAX_TRANSPORT_TIMESTAMP_NS
            or record.attempts < 0
            or record.total_bytes != int(row["total_bytes"])
            or record.total_bytes > MAX_DISPUTE_STATEMENT_FETCH_OUTBOX_RECORD_BYTES
            or record.request_digest
            != "sha256:" + hashlib.sha256(record.request_bytes).hexdigest()
            or (
                record.response_bytes is not None
                and record.response_digest
                != "sha256:" + hashlib.sha256(record.response_bytes).hexdigest()
            )
        ):
            raise TradeDisputeStatementFetchOutboxError(
                "retained fetch outbox record is invalid"
            )
        return record

    @staticmethod
    def _latest(
        connection: sqlite3.Connection,
        operation_id: str,
    ) -> TradeDisputeStatementFetchOutboxRecord | None:
        row = connection.execute(
            "SELECT * FROM fetch_outbox WHERE operation_id = ? "
            "ORDER BY generation DESC LIMIT 1",
            (operation_id,),
        ).fetchone()
        return TradeDisputeStatementFetchOutbox._record(row) if row else None

    @staticmethod
    def _timestamp(value: int, *, label: str) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= MAX_TRANSPORT_TIMESTAMP_NS
        ):
            raise ValueError(f"{label} is invalid")
        return value

    @staticmethod
    def _purge_expired_pending_unlocked(
        connection: sqlite3.Connection,
        *,
        cutoff_ns: int,
        limit: int,
    ) -> tuple[tuple[str, int], ...]:
        if cutoff_ns <= 0:
            return ()
        rows = connection.execute(
            "SELECT * FROM fetch_outbox WHERE response_bytes IS NULL "
            "AND not_after_ns < ? ORDER BY not_after_ns, operation_id, generation "
            "LIMIT ?",
            (cutoff_ns, limit),
        ).fetchall()
        records = tuple(TradeDisputeStatementFetchOutbox._record(row) for row in rows)
        for record in records:
            deleted = connection.execute(
                "DELETE FROM fetch_outbox WHERE operation_id = ? AND generation = ? "
                "AND response_bytes IS NULL AND not_after_ns < ?",
                (record.operation_id, record.generation, cutoff_ns),
            )
            if deleted.rowcount != 1:
                raise TradeDisputeStatementFetchOutboxConflict(
                    "expired fetch outbox record changed during cleanup"
                )
        return tuple((record.operation_id, record.generation) for record in records)

    def purge_expired_pending(
        self,
        *,
        at_ns: int,
        retention_seconds: float | None = None,
        limit: int | None = None,
    ) -> tuple[tuple[str, int], ...]:
        """Remove bounded, expired, incomplete requests after a retention window."""

        observed = self._timestamp(at_ns, label="at_ns")
        retention_ns = self.retention_ns
        if retention_seconds is not None:
            if (
                isinstance(retention_seconds, bool)
                or not isinstance(retention_seconds, (int, float))
                or not math.isfinite(retention_seconds)
                or not 0
                <= retention_seconds
                <= MAX_DISPUTE_STATEMENT_FETCH_OUTBOX_RETENTION_SECONDS
            ):
                raise ValueError("retention_seconds is invalid")
            retention_ns = int(float(retention_seconds) * 1_000_000_000)
        cleanup_limit = self.cleanup_limit if limit is None else limit
        if (
            isinstance(cleanup_limit, bool)
            or not isinstance(cleanup_limit, int)
            or not 1
            <= cleanup_limit
            <= MAX_DISPUTE_STATEMENT_FETCH_OUTBOX_CLEANUP_LIMIT
        ):
            raise ValueError("limit is invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            removed = self._purge_expired_pending_unlocked(
                connection,
                cutoff_ns=observed - retention_ns,
                limit=cleanup_limit,
            )
            connection.execute("COMMIT")
            return removed
        except TradeDisputeStatementFetchOutboxError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            self._raise_database_error(exc)
        finally:
            connection.close()

    @staticmethod
    def _monotonic_updated_at(
        record: TradeDisputeStatementFetchOutboxRecord,
        updated_at_ns: int,
    ) -> int:
        if (
            isinstance(updated_at_ns, bool)
            or not isinstance(updated_at_ns, int)
            or not 1 <= updated_at_ns <= MAX_TRANSPORT_TIMESTAMP_NS
        ):
            raise ValueError("updated_at_ns is invalid")
        return max(record.created_at_ns, record.updated_at_ns, updated_at_ns)

    def reserve(
        self,
        target_url: str,
        request: TradeDisputeStatementFetchRequest,
        *,
        observed_at_ns: int,
    ) -> tuple[TradeDisputeStatementFetchOutboxRecord, bool]:
        """Atomically retain or reuse the active signed request generation."""

        if not isinstance(request, TradeDisputeStatementFetchRequest):
            raise TypeError("request must be a TradeDisputeStatementFetchRequest")
        observed_at_ns = self._timestamp(observed_at_ns, label="observed_at_ns")
        request_bytes = request.canonical_bytes
        request_digest = "sha256:" + hashlib.sha256(request_bytes).hexdigest()
        not_after_ns = timestamp_ns(
            request.to_dict()["not_after"],
            label="request not_after",
            error_type=TradeDisputeStatementFetchOutboxError,
        )
        operation_id = trade_dispute_statement_fetch_operation_id(
            target_url,
            request,
        )
        projected_bytes = len(target_url.encode("utf-8")) + len(request_bytes)
        if projected_bytes > MAX_DISPUTE_STATEMENT_FETCH_OUTBOX_RECORD_BYTES:
            raise TradeDisputeStatementFetchOutboxCapacity(
                "fetch outbox record exceeds byte limit"
            )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            retained = self._latest(connection, operation_id)
            if retained is not None and retained.target_url != target_url:
                raise TradeDisputeStatementFetchOutboxConflict(
                    "fetch outbox target changed for the same operation"
                )
            if retained is not None and (
                retained.completed or retained.not_after_ns >= observed_at_ns
            ):
                connection.execute("COMMIT")
                return retained, False
            if not_after_ns < observed_at_ns:
                raise TradeDisputeStatementFetchOutboxConflict(
                    "replacement fetch request is already expired"
                )
            self._purge_expired_pending_unlocked(
                connection,
                cutoff_ns=observed_at_ns - self.retention_ns,
                limit=self.cleanup_limit,
            )
            usage = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(total_bytes), 0) FROM fetch_outbox"
            ).fetchone()
            if int(usage[0]) >= self.max_records:
                raise TradeDisputeStatementFetchOutboxCapacity(
                    "fetch outbox record limit exceeded"
                )
            if int(usage[1]) + projected_bytes > self.max_bytes:
                raise TradeDisputeStatementFetchOutboxCapacity(
                    "fetch outbox byte limit exceeded"
                )
            generation = retained.generation + 1 if retained is not None else 1
            connection.execute(
                "INSERT INTO fetch_outbox VALUES (?, ?, ?, ?, ?, NULL, NULL, "
                "NULL, NULL, ?, ?, ?, 0, '', ?)",
                (
                    operation_id,
                    generation,
                    target_url,
                    request_digest,
                    request_bytes,
                    not_after_ns,
                    observed_at_ns,
                    observed_at_ns,
                    projected_bytes,
                ),
            )
            connection.execute("COMMIT")
            created = self._latest(connection, operation_id)
            if created is None:
                raise TradeDisputeStatementFetchOutboxError(
                    "fetch outbox insert was not retained"
                )
            return created, True
        except TradeDisputeStatementFetchOutboxError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            self._raise_database_error(exc)
        finally:
            connection.close()

    def mark_attempt(
        self,
        record: TradeDisputeStatementFetchOutboxRecord,
        *,
        updated_at_ns: int,
        error: str = "",
    ) -> TradeDisputeStatementFetchOutboxRecord:
        if not isinstance(record, TradeDisputeStatementFetchOutboxRecord):
            raise TypeError("record must be a fetch outbox record")
        if not isinstance(error, str):
            raise TypeError("error must be a string")
        self._monotonic_updated_at(record, updated_at_ns)
        if len(error) > 512:
            error = error[:512]
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = self._latest(connection, record.operation_id)
            if current is None or current.generation != record.generation:
                raise TradeDisputeStatementFetchOutboxConflict(
                    "fetch outbox generation disappeared"
                )
            if current.request_bytes != record.request_bytes:
                raise TradeDisputeStatementFetchOutboxConflict(
                    "fetch outbox request changed before attempt"
                )
            effective_updated_at_ns = self._monotonic_updated_at(
                current,
                updated_at_ns,
            )
            connection.execute(
                "UPDATE fetch_outbox SET attempts = attempts + 1, updated_at_ns = ?, "
                "last_error = ? WHERE operation_id = ? AND generation = ?",
                (
                    effective_updated_at_ns,
                    error,
                    record.operation_id,
                    record.generation,
                ),
            )
            if connection.total_changes != 1:
                raise TradeDisputeStatementFetchOutboxConflict(
                    "fetch outbox generation disappeared"
                )
            connection.execute("COMMIT")
            updated = self._latest(connection, record.operation_id)
            if updated is None or updated.generation != record.generation:
                raise TradeDisputeStatementFetchOutboxConflict(
                    "fetch outbox generation changed"
                )
            return updated
        except TradeDisputeStatementFetchOutboxError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            self._raise_database_error(exc)
        finally:
            connection.close()

    def note_failure(
        self,
        record: TradeDisputeStatementFetchOutboxRecord,
        *,
        updated_at_ns: int,
        error: str,
    ) -> None:
        """Persist a bounded diagnostic without counting a second attempt."""

        if not isinstance(record, TradeDisputeStatementFetchOutboxRecord):
            raise TypeError("record must be a fetch outbox record")
        self._monotonic_updated_at(record, updated_at_ns)
        bounded_error = str(error)[:512]
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = self._latest(connection, record.operation_id)
            if current is None or current.generation != record.generation:
                raise TradeDisputeStatementFetchOutboxConflict(
                    "fetch outbox generation disappeared"
                )
            if current.request_bytes != record.request_bytes:
                raise TradeDisputeStatementFetchOutboxConflict(
                    "fetch outbox request changed before failure note"
                )
            if current.completed:
                connection.execute("COMMIT")
                return
            effective_updated_at_ns = self._monotonic_updated_at(
                current,
                updated_at_ns,
            )
            connection.execute(
                "UPDATE fetch_outbox SET updated_at_ns = ?, last_error = ? "
                "WHERE operation_id = ? AND generation = ?",
                (
                    effective_updated_at_ns,
                    bounded_error,
                    record.operation_id,
                    record.generation,
                ),
            )
            if connection.total_changes != 1:
                raise TradeDisputeStatementFetchOutboxConflict(
                    "fetch outbox generation disappeared"
                )
            connection.execute("COMMIT")
        except TradeDisputeStatementFetchOutboxError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            self._raise_database_error(exc)
        finally:
            connection.close()

    def complete(
        self,
        record: TradeDisputeStatementFetchOutboxRecord,
        response: TradeDisputeStatementFetchResponse,
        audit_event: SpineEvent,
        *,
        updated_at_ns: int,
    ) -> tuple[TradeDisputeStatementFetchOutboxRecord, bool]:
        if not isinstance(record, TradeDisputeStatementFetchOutboxRecord):
            raise TypeError("record must be a fetch outbox record")
        if not isinstance(response, TradeDisputeStatementFetchResponse):
            raise TypeError("response must be a TradeDisputeStatementFetchResponse")
        if not isinstance(audit_event, SpineEvent):
            raise TypeError("audit_event must be a SpineEvent")
        self._monotonic_updated_at(record, updated_at_ns)
        response_bytes = response.canonical_bytes
        response_digest = "sha256:" + hashlib.sha256(response_bytes).hexdigest()
        audit_bytes = canonical_json(audit_event.to_dict())
        projected_bytes = (
            len(record.target_url.encode("utf-8"))
            + len(record.request_bytes)
            + len(response_bytes)
            + len(audit_bytes)
        )
        if projected_bytes > MAX_DISPUTE_STATEMENT_FETCH_OUTBOX_RECORD_BYTES:
            raise TradeDisputeStatementFetchOutboxCapacity(
                "completed fetch outbox record exceeds byte limit"
            )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = self._latest(connection, record.operation_id)
            if current is None or current.generation != record.generation:
                raise TradeDisputeStatementFetchOutboxConflict(
                    "fetch outbox generation changed before completion"
                )
            if current.request_bytes != record.request_bytes:
                raise TradeDisputeStatementFetchOutboxConflict(
                    "fetch outbox request changed before completion"
                )
            effective_updated_at_ns = self._monotonic_updated_at(
                current,
                updated_at_ns,
            )
            if current.completed:
                if (
                    current.response_bytes != response_bytes
                    or current.audit_event_bytes != audit_bytes
                    or current.audit_event_id != audit_event.event_id
                ):
                    raise TradeDisputeStatementFetchOutboxConflict(
                        "fetch outbox completion conflicts with retained response"
                    )
                connection.execute("COMMIT")
                return current, False
            usage = connection.execute(
                "SELECT COALESCE(SUM(total_bytes), 0) FROM fetch_outbox"
            ).fetchone()
            if int(usage[0]) - current.total_bytes + projected_bytes > self.max_bytes:
                raise TradeDisputeStatementFetchOutboxCapacity(
                    "fetch outbox byte limit exceeded"
                )
            connection.execute(
                "UPDATE fetch_outbox SET response_digest = ?, response_bytes = ?, "
                "audit_event_id = ?, audit_event_bytes = ?, updated_at_ns = ?, "
                "last_error = '', total_bytes = ? WHERE operation_id = ? "
                "AND generation = ?",
                (
                    response_digest,
                    response_bytes,
                    audit_event.event_id,
                    audit_bytes,
                    effective_updated_at_ns,
                    projected_bytes,
                    record.operation_id,
                    record.generation,
                ),
            )
            connection.execute("COMMIT")
            completed = self._latest(connection, record.operation_id)
            if completed is None:
                raise TradeDisputeStatementFetchOutboxError(
                    "fetch outbox completion was not retained"
                )
            return completed, True
        except TradeDisputeStatementFetchOutboxError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            self._raise_database_error(exc)
        finally:
            connection.close()


__all__ = [
    "DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_OUTBOX_BYTES",
    "DEFAULT_MAX_DISPUTE_STATEMENT_FETCH_OUTBOX_RECORDS",
    "DEFAULT_DISPUTE_STATEMENT_FETCH_OUTBOX_CLEANUP_LIMIT",
    "DEFAULT_DISPUTE_STATEMENT_FETCH_OUTBOX_RETENTION_SECONDS",
    "MAX_DISPUTE_STATEMENT_FETCH_OUTBOX_RECORD_BYTES",
    "MAX_DISPUTE_STATEMENT_FETCH_OUTBOX_CLEANUP_LIMIT",
    "MAX_DISPUTE_STATEMENT_FETCH_OUTBOX_RETENTION_SECONDS",
    "TradeDisputeStatementFetchOutbox",
    "TradeDisputeStatementFetchOutboxBusy",
    "TradeDisputeStatementFetchOutboxCapacity",
    "TradeDisputeStatementFetchOutboxConflict",
    "TradeDisputeStatementFetchOutboxError",
    "TradeDisputeStatementFetchOutboxRecord",
    "trade_dispute_statement_fetch_operation_id",
]
