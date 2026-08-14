"""Durable sender state for federated Trade Dispute Statements."""

from __future__ import annotations

import json
import math
import os
import re
import secrets
import sqlite3
import stat
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from nth_dao.spine import SignedEventLog, SpineEvent, verify_event
from nth_dao.trade_rules.agreement_order import TradeOrder
from nth_dao.trade_rules.canonical import MAX_SAFE_INTEGER
from nth_dao.trade_rules.dispute_statement_transport import (
    TradeDisputeStatementAcknowledgement,
    TradeDisputeStatementDelivery,
    trade_dispute_statement_acknowledgement_digest,
    trade_dispute_statement_delivery_digest,
    verify_trade_dispute_statement_acknowledgement,
    verify_trade_dispute_statement_delivery,
)
from nth_dao.trade_rules.execution_receipt import TradeExecutionReceipt
from nth_dao.trade_rules.receipt_review import TradeReceiptReview

EVENT_TRADE_DISPUTE_STATEMENT_ACKNOWLEDGED = (
    "trade.dispute.statement-acknowledged"
)
DISPUTE_STATEMENT_DISPATCH_PROTOCOL_VERSION = "1"
DEFAULT_MAX_PENDING_DISPUTE_STATEMENTS = 4_096
DEFAULT_MAX_DISPUTE_STATEMENT_ACKNOWLEDGEMENTS = 65_536
DEFAULT_MAX_DISPUTE_STATEMENT_DISPATCH_BYTES = 2 * 1024 * 1024 * 1024
MAX_DISPUTE_STATEMENT_DISPATCH_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_SUPERSEDED_DISPUTE_STATEMENT_DELIVERIES = 128
DEFAULT_DISPUTE_STATEMENT_SEND_LEASE_MS = 30_000

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVENT_ID = re.compile(r"^[0-9a-f]{64}$")
_LEASE_TOKEN = re.compile(r"^[0-9a-f]{32,128}$")
_MAX_ERROR_LENGTH = 512
_SCHEMA_VERSION = 3


class TradeDisputeStatementDispatchError(RuntimeError):
    """Dispute Statement dispatch state is invalid or unavailable."""


class TradeDisputeStatementDispatchBusy(TradeDisputeStatementDispatchError):
    """Another process currently owns the dispatch transaction."""


class TradeDisputeStatementDispatchCapacity(TradeDisputeStatementDispatchError):
    """The bounded dispatch store is full."""


def _now_ms(value: int | None = None) -> int:
    result = time.time_ns() // 1_000_000 if value is None else value
    if (
        isinstance(result, bool)
        or not isinstance(result, int)
        or not 0 < result <= MAX_SAFE_INTEGER
    ):
        raise ValueError("now_ms must be a safe positive integer")
    return result


def _digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise TradeDisputeStatementDispatchError(f"{label} is invalid")
    return value


def _event_id(value: Any) -> str:
    if not isinstance(value, str) or _EVENT_ID.fullmatch(value) is None:
        raise TradeDisputeStatementDispatchError("remote_event_id is invalid")
    return value


def _lease_token(value: Any) -> str:
    if not isinstance(value, str) or _LEASE_TOKEN.fullmatch(value) is None:
        raise TradeDisputeStatementDispatchError("lease_token is invalid")
    return value


def _target_url(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 2_048:
        raise TradeDisputeStatementDispatchError("target_url is invalid")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise TradeDisputeStatementDispatchError(
            "target_url contains control characters"
        )
    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError as exc:
        raise TradeDisputeStatementDispatchError("target_url is invalid") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TradeDisputeStatementDispatchError(
            "target_url must be an HTTP(S) URL"
        )
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise TradeDisputeStatementDispatchError(
            "target_url must not include credentials, query, or fragment"
        )
    host = parsed.hostname.lower().rstrip(".")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host + (f":{port}" if port is not None else "")
    return urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path.rstrip("/"), "", "")
    ).rstrip("/")


@dataclass(frozen=True)
class TradeDisputeStatementDispatchRecord:
    statement_digest: str
    target_url: str
    delivery: TradeDisputeStatementDelivery
    review: TradeReceiptReview
    receipt: TradeExecutionReceipt
    order: TradeOrder
    attempts: int
    last_error: str
    created_at_ms: int
    updated_at_ms: int
    generation: int
    superseded_delivery_digests: tuple[str, ...] = ()
    acknowledgement: TradeDisputeStatementAcknowledgement | None = None
    remote_event_id: str = ""
    observed_at_ms: int = 0
    anchor_event_id: str = ""
    lease_expires_at_ms: int = 0

    @property
    def acknowledged(self) -> bool:
        return self.acknowledgement is not None

    @property
    def delivery_digest(self) -> str:
        return trade_dispute_statement_delivery_digest(
            self.delivery,
            review=self.review,
            receipt=self.receipt,
            order=self.order,
        )

    @property
    def acknowledgement_digest(self) -> str:
        if self.acknowledgement is None:
            return ""
        return trade_dispute_statement_acknowledgement_digest(
            self.acknowledgement
        )


@dataclass(frozen=True)
class TradeDisputeStatementDispatchReconciliation:
    scanned: int
    anchored: int
    failed: int
    next_cursor: str
    has_more: bool


class TradeDisputeStatementDispatchStore:
    """SQLite-backed process-safe delivery and acknowledgement retention."""

    def __init__(
        self,
        workspace: str | Path,
        *,
        max_pending: int = DEFAULT_MAX_PENDING_DISPUTE_STATEMENTS,
        max_acknowledgements: int = DEFAULT_MAX_DISPUTE_STATEMENT_ACKNOWLEDGEMENTS,
        max_bytes: int = DEFAULT_MAX_DISPUTE_STATEMENT_DISPATCH_BYTES,
        timeout: float = 30.0,
    ) -> None:
        for label, value in (
            ("max_pending", max_pending),
            ("max_acknowledgements", max_acknowledgements),
            ("max_bytes", max_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{label} must be a positive integer")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("timeout must be finite and positive")
        self.workspace_root = Path(workspace).resolve()
        self.root = self.workspace_root / "trade" / "dispute_dispatch_v1"
        self.path = self.root / "dispatch.sqlite3"
        self.max_pending = max_pending
        self.max_acknowledgements = max_acknowledgements
        self.max_bytes = max_bytes
        self.timeout = float(timeout)
        self._initialize()

    @staticmethod
    def _is_linklike(path: Path) -> bool:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if is_junction and is_junction():
            return True
        if os.name == "nt" and path.exists():
            metadata = os.lstat(path)
            return bool(
                getattr(metadata, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            )
        return False

    def _assert_storage_path(self) -> None:
        try:
            relative = self.path.relative_to(self.workspace_root)
        except ValueError as exc:
            raise TradeDisputeStatementDispatchError(
                "dispatch store escapes workspace"
            ) from exc
        current = self.workspace_root
        for part in ("", *relative.parts):
            current = current if not part else current / part
            if self._is_linklike(current):
                raise TradeDisputeStatementDispatchError(
                    "dispatch store must not contain links"
                )
        for suffix in ("-wal", "-shm"):
            if self._is_linklike(Path(str(self.path) + suffix)):
                raise TradeDisputeStatementDispatchError(
                    "dispatch store must not contain links"
                )

    def _connect(self) -> sqlite3.Connection:
        self._assert_storage_path()
        self.root.mkdir(parents=True, exist_ok=True)
        self._assert_storage_path()
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=self.timeout,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise TradeDisputeStatementDispatchBusy(
                    "Dispute Statement dispatch store is busy"
                ) from exc
            raise TradeDisputeStatementDispatchError(
                "unable to open Dispute Statement dispatch store"
            ) from exc
        except sqlite3.Error as exc:
            raise TradeDisputeStatementDispatchError(
                "unable to open Dispute Statement dispatch store"
            ) from exc

    @staticmethod
    def _database_error(exc: sqlite3.Error) -> None:
        if isinstance(exc, sqlite3.OperationalError) and (
            "locked" in str(exc).lower() or "busy" in str(exc).lower()
        ):
            raise TradeDisputeStatementDispatchBusy(
                "Dispute Statement dispatch store is busy"
            ) from exc
        raise TradeDisputeStatementDispatchError(
            "Dispute Statement dispatch store operation failed"
        ) from exc

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in {0, 1, 2, _SCHEMA_VERSION}:
                raise TradeDisputeStatementDispatchError(
                    "Dispute Statement dispatch schema is unsupported"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS dispatches (
                    statement_digest TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    delivery_bytes BLOB NOT NULL,
                    review_bytes BLOB NOT NULL,
                    receipt_bytes BLOB NOT NULL,
                    order_bytes BLOB NOT NULL,
                    attempts INTEGER NOT NULL,
                    last_error TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL,
                    generation INTEGER NOT NULL,
                    acknowledgement_bytes BLOB,
                    remote_event_id TEXT NOT NULL,
                    observed_at_ms INTEGER NOT NULL,
                    anchor_event_id TEXT NOT NULL,
                    total_bytes INTEGER NOT NULL,
                    superseded_delivery_digests TEXT NOT NULL DEFAULT '[]',
                    lease_token TEXT NOT NULL DEFAULT '',
                    lease_expires_at_ms INTEGER NOT NULL DEFAULT 0
                ) WITHOUT ROWID
                """
            )
            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(dispatches)"
                ).fetchall()
            }
            if "superseded_delivery_digests" not in columns:
                connection.execute(
                    "ALTER TABLE dispatches ADD COLUMN "
                    "superseded_delivery_digests TEXT NOT NULL DEFAULT '[]'"
                )
            if "lease_token" not in columns:
                connection.execute(
                    "ALTER TABLE dispatches ADD COLUMN "
                    "lease_token TEXT NOT NULL DEFAULT ''"
                )
            if "lease_expires_at_ms" not in columns:
                connection.execute(
                    "ALTER TABLE dispatches ADD COLUMN "
                    "lease_expires_at_ms INTEGER NOT NULL DEFAULT 0"
                )
            if version < _SCHEMA_VERSION:
                connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        except TradeDisputeStatementDispatchError:
            raise
        except sqlite3.Error as exc:
            self._database_error(exc)
        finally:
            connection.close()

    @staticmethod
    def _context(
        review_bytes: bytes,
        receipt_bytes: bytes,
        order_bytes: bytes,
    ) -> tuple[TradeReceiptReview, TradeExecutionReceipt, TradeOrder]:
        try:
            order = TradeOrder.from_json(order_bytes)
            receipt = TradeExecutionReceipt.from_json(receipt_bytes, order=order)
            review = TradeReceiptReview.from_json(
                review_bytes,
                receipt=receipt,
                order=order,
            )
        except (TypeError, ValueError) as exc:
            raise TradeDisputeStatementDispatchError(
                "dispatch signed context is invalid"
            ) from exc
        return review, receipt, order

    @classmethod
    def _record(cls, row: sqlite3.Row) -> TradeDisputeStatementDispatchRecord:
        try:
            delivery_bytes = bytes(row["delivery_bytes"])
            review_bytes = bytes(row["review_bytes"])
            receipt_bytes = bytes(row["receipt_bytes"])
            order_bytes = bytes(row["order_bytes"])
            acknowledgement_raw = row["acknowledgement_bytes"]
            acknowledgement_bytes = (
                bytes(acknowledgement_raw)
                if acknowledgement_raw is not None
                else None
            )
        except (TypeError, ValueError) as exc:
            raise TradeDisputeStatementDispatchError(
                "dispatch artifact bytes are invalid"
            ) from exc
        total = sum(
            len(value)
            for value in (delivery_bytes, review_bytes, receipt_bytes, order_bytes)
        ) + (len(acknowledgement_bytes) if acknowledgement_bytes else 0)
        stored_total = row["total_bytes"]
        if (
            isinstance(stored_total, bool)
            or not isinstance(stored_total, int)
            or total != stored_total
            or total > (
            MAX_DISPUTE_STATEMENT_DISPATCH_DOCUMENT_BYTES
            )
        ):
            raise TradeDisputeStatementDispatchError(
                "dispatch byte accounting is invalid"
            )
        review, receipt, order = cls._context(
            review_bytes,
            receipt_bytes,
            order_bytes,
        )
        try:
            delivery = TradeDisputeStatementDelivery.from_json(
                delivery_bytes,
                review=review,
                receipt=receipt,
                order=order,
            )
            acknowledgement = (
                TradeDisputeStatementAcknowledgement.from_json(
                    acknowledgement_bytes
                )
                if acknowledgement_bytes is not None
                else None
            )
        except (TypeError, ValueError) as exc:
            raise TradeDisputeStatementDispatchError(
                "dispatch signed artifact is invalid"
            ) from exc
        statement_digest = _digest(
            row["statement_digest"],
            label="statement_digest",
        )
        if delivery.to_dict()["statement_digest"] != statement_digest:
            raise TradeDisputeStatementDispatchError(
                "dispatch Statement binding is invalid"
            )
        attempts = row["attempts"]
        created_at_ms = row["created_at_ms"]
        updated_at_ms = row["updated_at_ms"]
        last_error = row["last_error"]
        try:
            history = json.loads(row["superseded_delivery_digests"])
        except (json.JSONDecodeError, TypeError) as exc:
            raise TradeDisputeStatementDispatchError(
                "dispatch generation history is invalid"
            ) from exc
        generation = row["generation"]
        current_delivery_digest = trade_dispute_statement_delivery_digest(
            delivery,
            review=review,
            receipt=receipt,
            order=order,
        )
        if (
            isinstance(attempts, bool)
            or not isinstance(attempts, int)
            or not 0 <= attempts <= MAX_SAFE_INTEGER
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 < value <= MAX_SAFE_INTEGER
                for value in (created_at_ms, updated_at_ms)
            )
            or updated_at_ms < created_at_ms
            or not isinstance(last_error, str)
            or len(last_error) > _MAX_ERROR_LENGTH
            or isinstance(generation, bool)
            or not isinstance(generation, int)
            or not 1 <= generation <= MAX_SAFE_INTEGER
            or not isinstance(history, list)
            or len(history) > MAX_SUPERSEDED_DISPUTE_STATEMENT_DELIVERIES
            or any(
                not isinstance(item, str) or _DIGEST.fullmatch(item) is None
                for item in history
            )
            or len(set(history)) != len(history)
            or generation != len(history) + 1
            or current_delivery_digest in history
        ):
            raise TradeDisputeStatementDispatchError(
                "dispatch counters, timestamps, or generation history are invalid"
            )
        remote_event_id = row["remote_event_id"]
        observed_at_ms = row["observed_at_ms"]
        anchor_event_id = row["anchor_event_id"]
        lease_token = row["lease_token"]
        lease_expires_at_ms = row["lease_expires_at_ms"]
        if not isinstance(lease_token, str) or (
            lease_token and _LEASE_TOKEN.fullmatch(lease_token) is None
        ):
            raise TradeDisputeStatementDispatchError(
                "dispatch send lease is invalid"
            )
        if lease_token:
            lease_expires_at_ms = _now_ms(lease_expires_at_ms)
        elif lease_expires_at_ms != 0:
            raise TradeDisputeStatementDispatchError(
                "dispatch send lease is invalid"
            )
        if acknowledgement is None:
            if remote_event_id != "" or observed_at_ms != 0 or anchor_event_id != "":
                raise TradeDisputeStatementDispatchError(
                    "pending dispatch contains acknowledgement state"
                )
        else:
            if lease_token or lease_expires_at_ms:
                raise TradeDisputeStatementDispatchError(
                    "acknowledged dispatch retains a send lease"
                )
            remote_event_id = _event_id(remote_event_id)
            observed_at_ms = _now_ms(observed_at_ms)
            if anchor_event_id:
                anchor_event_id = _event_id(anchor_event_id)
            if acknowledgement.to_dict()["audit_event_id"] != remote_event_id:
                raise TradeDisputeStatementDispatchError(
                    "stored acknowledgement audit event binding is invalid"
                )
            valid, reason = verify_trade_dispute_statement_acknowledgement(
                acknowledgement,
                delivery=delivery,
                review=review,
                receipt=receipt,
                order=order,
                at=datetime.fromtimestamp(
                    observed_at_ms / 1_000,
                    tz=timezone.utc,
                ),
            )
            if not valid:
                raise TradeDisputeStatementDispatchError(
                    f"stored acknowledgement is invalid: {reason}"
                )
        return TradeDisputeStatementDispatchRecord(
            statement_digest=statement_digest,
            target_url=_target_url(row["target_url"]),
            delivery=delivery,
            review=review,
            receipt=receipt,
            order=order,
            attempts=attempts,
            last_error=last_error,
            created_at_ms=created_at_ms,
            updated_at_ms=updated_at_ms,
            generation=generation,
            superseded_delivery_digests=tuple(history),
            acknowledgement=acknowledgement,
            remote_event_id=remote_event_id,
            observed_at_ms=observed_at_ms,
            anchor_event_id=anchor_event_id,
            lease_expires_at_ms=lease_expires_at_ms,
        )

    @staticmethod
    def _total_bytes(
        delivery: TradeDisputeStatementDelivery,
        review: TradeReceiptReview,
        receipt: TradeExecutionReceipt,
        order: TradeOrder,
        acknowledgement: TradeDisputeStatementAcknowledgement | None = None,
    ) -> int:
        return sum(
            len(value)
            for value in (
                delivery.canonical_bytes,
                review.canonical_bytes,
                receipt.canonical_bytes,
                order.canonical_bytes,
                acknowledgement.canonical_bytes if acknowledgement else b"",
            )
        )

    @staticmethod
    def _usage(connection: sqlite3.Connection) -> tuple[int, int, int]:
        row = connection.execute(
            "SELECT "
            "SUM(CASE WHEN acknowledgement_bytes IS NULL THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN acknowledgement_bytes IS NOT NULL THEN 1 ELSE 0 END), "
            "COALESCE(SUM(total_bytes), 0) FROM dispatches"
        ).fetchone()
        return int(row[0] or 0), int(row[1] or 0), int(row[2] or 0)

    def prepare(
        self,
        delivery: TradeDisputeStatementDelivery,
        *,
        review: TradeReceiptReview,
        receipt: TradeExecutionReceipt,
        order: TradeOrder,
        target_url: str,
        now_ms: int | None = None,
    ) -> TradeDisputeStatementDispatchRecord:
        moment = _now_ms(now_ms)
        normalized_target = _target_url(target_url)
        verified = TradeDisputeStatementDelivery.from_json(
            delivery.canonical_bytes,
            review=review,
            receipt=receipt,
            order=order,
        )
        document = verified.to_dict()
        ok, reason = verify_trade_dispute_statement_delivery(
            verified,
            review=review,
            receipt=receipt,
            order=order,
            recipient_did=document["recipient_did"],
            at=datetime.fromtimestamp(moment / 1_000, tz=timezone.utc),
        )
        if not ok:
            raise TradeDisputeStatementDispatchError(
                f"delivery is not usable: {reason}"
            )
        statement_digest = _digest(
            document["statement_digest"],
            label="statement_digest",
        )
        total = self._total_bytes(verified, review, receipt, order)
        if total > MAX_DISPUTE_STATEMENT_DISPATCH_DOCUMENT_BYTES:
            raise TradeDisputeStatementDispatchCapacity(
                "dispatch record exceeds byte limit"
            )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM dispatches WHERE statement_digest = ?",
                (statement_digest,),
            ).fetchone()
            if row is not None:
                existing = self._record(row)
                if (
                    existing.target_url != normalized_target
                    or existing.delivery.canonical_bytes != verified.canonical_bytes
                ):
                    raise TradeDisputeStatementDispatchError(
                        "Statement dispatch already has conflicting delivery state"
                    )
                connection.execute("COMMIT")
                return existing
            pending, acknowledged, used = self._usage(connection)
            if pending + 1 > self.max_pending:
                raise TradeDisputeStatementDispatchCapacity(
                    "max pending Statement dispatches exceeded"
                )
            if acknowledged > self.max_acknowledgements or used + total > self.max_bytes:
                raise TradeDisputeStatementDispatchCapacity(
                    "Statement dispatch store capacity exceeded"
                )
            connection.execute(
                "INSERT INTO dispatches (statement_digest, target_url, "
                "delivery_bytes, review_bytes, receipt_bytes, order_bytes, "
                "attempts, last_error, created_at_ms, updated_at_ms, "
                "generation, acknowledgement_bytes, remote_event_id, "
                "observed_at_ms, anchor_event_id, total_bytes, "
                "superseded_delivery_digests, lease_token, "
                "lease_expires_at_ms) VALUES "
                "(?, ?, ?, ?, ?, ?, 0, '', ?, ?, 1, NULL, '', 0, '', ?, "
                "'[]', '', 0)",
                (
                    statement_digest,
                    normalized_target,
                    verified.canonical_bytes,
                    review.canonical_bytes,
                    receipt.canonical_bytes,
                    order.canonical_bytes,
                    moment,
                    moment,
                    total,
                ),
            )
            connection.execute("COMMIT")
        except TradeDisputeStatementDispatchError:
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
            self._database_error(exc)
        finally:
            connection.close()
        state = self.get(statement_digest)
        if state is None:
            raise TradeDisputeStatementDispatchError(
                "prepared dispatch state disappeared"
            )
        return state

    def replace_expired(
        self,
        delivery: TradeDisputeStatementDelivery,
        *,
        review: TradeReceiptReview,
        receipt: TradeExecutionReceipt,
        order: TradeOrder,
        target_url: str,
        now_ms: int | None = None,
    ) -> TradeDisputeStatementDispatchRecord:
        moment = _now_ms(now_ms)
        verified = TradeDisputeStatementDelivery.from_json(
            delivery.canonical_bytes,
            review=review,
            receipt=receipt,
            order=order,
        )
        statement_digest = _digest(
            verified.to_dict()["statement_digest"],
            label="statement_digest",
        )
        normalized_target = _target_url(target_url)
        total = self._total_bytes(verified, review, receipt, order)
        if total > MAX_DISPUTE_STATEMENT_DISPATCH_DOCUMENT_BYTES:
            raise TradeDisputeStatementDispatchCapacity(
                "dispatch record exceeds byte limit"
            )
        replacement_document = verified.to_dict()
        replacement_ok, replacement_reason = verify_trade_dispute_statement_delivery(
            verified,
            review=review,
            receipt=receipt,
            order=order,
            recipient_did=replacement_document["recipient_did"],
            at=datetime.fromtimestamp(moment / 1_000, tz=timezone.utc),
        )
        if not replacement_ok:
            raise TradeDisputeStatementDispatchError(
                f"replacement delivery is not usable: {replacement_reason}"
            )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM dispatches WHERE statement_digest = ?",
                (statement_digest,),
            ).fetchone()
            if row is None:
                raise TradeDisputeStatementDispatchError(
                    "pending Statement dispatch does not exist"
                )
            existing = self._record(row)
            if existing.acknowledged:
                connection.execute("COMMIT")
                return existing
            if existing.target_url != normalized_target:
                raise TradeDisputeStatementDispatchError(
                    "pending dispatch targets a different peer"
                )
            if (
                row["lease_token"]
                and row["lease_expires_at_ms"] > moment
            ):
                raise TradeDisputeStatementDispatchBusy(
                    "pending Statement delivery is in progress"
                )
            if (
                existing.review.canonical_bytes != review.canonical_bytes
                or existing.receipt.canonical_bytes != receipt.canonical_bytes
                or existing.order.canonical_bytes != order.canonical_bytes
            ):
                raise TradeDisputeStatementDispatchError(
                    "replacement does not match pending signed context"
                )
            existing_document = existing.delivery.to_dict()
            for field in (
                "kind",
                "protocol_version",
                "order_digest",
                "receipt_digest",
                "review_digest",
                "statement_digest",
                "sender_did",
                "recipient_did",
                "statement",
            ):
                if existing_document[field] != replacement_document[field]:
                    raise TradeDisputeStatementDispatchError(
                        "replacement does not match pending Statement scope"
                    )
            at = datetime.fromtimestamp(moment / 1_000, tz=timezone.utc)
            old_ok, old_reason = verify_trade_dispute_statement_delivery(
                existing.delivery,
                review=existing.review,
                receipt=existing.receipt,
                order=existing.order,
                recipient_did=existing_document["recipient_did"],
                at=at,
            )
            if old_ok or "expired" not in old_reason:
                raise TradeDisputeStatementDispatchError(
                    "pending delivery is not expired"
                )
            old_digest = existing.delivery_digest
            new_digest = trade_dispute_statement_delivery_digest(
                verified,
                review=review,
                receipt=receipt,
                order=order,
            )
            if old_digest == new_digest:
                raise TradeDisputeStatementDispatchError(
                    "replacement delivery must use fresh signed bytes"
                )
            history = (*existing.superseded_delivery_digests, old_digest)
            if len(history) > MAX_SUPERSEDED_DISPUTE_STATEMENT_DELIVERIES:
                raise TradeDisputeStatementDispatchCapacity(
                    "delivery generation history is full"
                )
            _pending, _acknowledged, used = self._usage(connection)
            if used - row["total_bytes"] + total > self.max_bytes:
                raise TradeDisputeStatementDispatchCapacity(
                    "Statement dispatch store capacity exceeded"
                )
            connection.execute(
                "UPDATE dispatches SET delivery_bytes = ?, review_bytes = ?, "
                "receipt_bytes = ?, order_bytes = ?, updated_at_ms = ?, "
                "generation = ?, attempts = 0, last_error = '', total_bytes = ?, "
                "superseded_delivery_digests = ? "
                "WHERE statement_digest = ?",
                (
                    verified.canonical_bytes,
                    review.canonical_bytes,
                    receipt.canonical_bytes,
                    order.canonical_bytes,
                    max(moment, existing.updated_at_ms),
                    existing.generation + 1,
                    total,
                    json.dumps(list(history), separators=(",", ":")),
                    statement_digest,
                ),
            )
            connection.execute("COMMIT")
        except TradeDisputeStatementDispatchError:
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
            self._database_error(exc)
        finally:
            connection.close()
        state = self.get(statement_digest)
        if state is None:
            raise TradeDisputeStatementDispatchError(
                "renewed dispatch state disappeared"
            )
        return state

    def acquire_send_lease(
        self,
        statement_digest: str,
        *,
        lease_token: str | None = None,
        now_ms: int | None = None,
        lease_ms: int = DEFAULT_DISPUTE_STATEMENT_SEND_LEASE_MS,
    ) -> tuple[TradeDisputeStatementDispatchRecord, str]:
        """Claim one crash-recoverable single-flight network send lease."""

        digest = _digest(statement_digest, label="statement_digest")
        token = _lease_token(lease_token or secrets.token_hex(16))
        moment = _now_ms(now_ms)
        if (
            isinstance(lease_ms, bool)
            or not isinstance(lease_ms, int)
            or not 1_000 <= lease_ms <= 600_000
            or moment + lease_ms > MAX_SAFE_INTEGER
        ):
            raise ValueError("lease_ms must be between 1000 and 600000")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM dispatches WHERE statement_digest = ?",
                (digest,),
            ).fetchone()
            if row is None:
                raise TradeDisputeStatementDispatchError(
                    "pending Statement dispatch does not exist"
                )
            record = self._record(row)
            if record.acknowledged:
                raise TradeDisputeStatementDispatchError(
                    "Statement dispatch is already acknowledged"
                )
            retained_token = row["lease_token"]
            retained_expiry = row["lease_expires_at_ms"]
            if retained_token and retained_expiry > moment:
                if retained_token != token:
                    raise TradeDisputeStatementDispatchBusy(
                        "pending Statement delivery is in progress"
                    )
                connection.execute("COMMIT")
                return record, token
            connection.execute(
                "UPDATE dispatches SET lease_token = ?, lease_expires_at_ms = ? "
                "WHERE statement_digest = ?",
                (token, moment + lease_ms, digest),
            )
            connection.execute("COMMIT")
        except TradeDisputeStatementDispatchError:
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
            self._database_error(exc)
        finally:
            connection.close()
        leased = self.get(digest)
        if leased is None:
            raise TradeDisputeStatementDispatchError(
                "leased dispatch state disappeared"
            )
        return leased, token

    def release_send_lease(
        self,
        statement_digest: str,
        *,
        lease_token: str,
    ) -> None:
        digest = _digest(statement_digest, label="statement_digest")
        token = _lease_token(lease_token)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT acknowledgement_bytes, lease_token FROM dispatches "
                "WHERE statement_digest = ?",
                (digest,),
            ).fetchone()
            if row is None:
                raise TradeDisputeStatementDispatchError(
                    "Statement dispatch does not exist"
                )
            if row["acknowledgement_bytes"] is None:
                if row["lease_token"] != token:
                    raise TradeDisputeStatementDispatchError(
                        "Statement dispatch send lease is not owned by caller"
                    )
                connection.execute(
                    "UPDATE dispatches SET lease_token = '', "
                    "lease_expires_at_ms = 0 WHERE statement_digest = ?",
                    (digest,),
                )
            connection.execute("COMMIT")
        except TradeDisputeStatementDispatchError:
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
            self._database_error(exc)
        finally:
            connection.close()

    def note_failure(
        self,
        statement_digest: str,
        *,
        error: str,
        lease_token: str,
        now_ms: int | None = None,
    ) -> None:
        digest = _digest(statement_digest, label="statement_digest")
        if not isinstance(error, str):
            raise TypeError("error must be a string")
        safe_error = error.replace("\r", " ").replace("\n", " ")[:_MAX_ERROR_LENGTH]
        token = _lease_token(lease_token)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                "UPDATE dispatches SET attempts = attempts + 1, "
                "last_error = ?, updated_at_ms = ?, lease_token = '', "
                "lease_expires_at_ms = 0 WHERE statement_digest = ? "
                "AND acknowledgement_bytes IS NULL AND lease_token = ?",
                (safe_error, _now_ms(now_ms), digest, token),
            ).rowcount
            if changed != 1:
                raise TradeDisputeStatementDispatchError(
                    "pending Statement dispatch does not exist"
                )
            connection.execute("COMMIT")
        except TradeDisputeStatementDispatchError:
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
            self._database_error(exc)
        finally:
            connection.close()

    def put_acknowledgement(
        self,
        statement_digest: str,
        acknowledgement: TradeDisputeStatementAcknowledgement,
        *,
        remote_event_id: str,
        lease_token: str,
    ) -> TradeDisputeStatementDispatchRecord:
        digest = _digest(statement_digest, label="statement_digest")
        event_id = _event_id(remote_event_id)
        token = _lease_token(lease_token)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM dispatches WHERE statement_digest = ?",
                (digest,),
            ).fetchone()
            if row is None:
                raise TradeDisputeStatementDispatchError(
                    "pending Statement dispatch does not exist"
                )
            existing = self._record(row)
            if existing.acknowledged:
                if (
                    existing.acknowledgement.canonical_bytes
                    != acknowledgement.canonical_bytes
                    or existing.remote_event_id != event_id
                ):
                    raise TradeDisputeStatementDispatchError(
                        "Statement acknowledgement conflicts with retained bytes"
                    )
                connection.execute("COMMIT")
                return existing
            if row["lease_token"] != token:
                raise TradeDisputeStatementDispatchError(
                    "Statement acknowledgement does not own the send lease"
                )
            valid, reason = verify_trade_dispute_statement_acknowledgement(
                acknowledgement,
                delivery=existing.delivery,
                review=existing.review,
                receipt=existing.receipt,
                order=existing.order,
                at=datetime.now(timezone.utc),
            )
            if not valid:
                raise TradeDisputeStatementDispatchError(
                    f"Statement acknowledgement is invalid: {reason}"
                )
            document = acknowledgement.to_dict()
            if document["audit_event_id"] != event_id:
                raise TradeDisputeStatementDispatchError(
                    "remote_event_id does not match signed acknowledgement"
                )
            observed = _now_ms()
            total = self._total_bytes(
                existing.delivery,
                existing.review,
                existing.receipt,
                existing.order,
                acknowledgement,
            )
            if total > MAX_DISPUTE_STATEMENT_DISPATCH_DOCUMENT_BYTES:
                raise TradeDisputeStatementDispatchCapacity(
                    "acknowledged dispatch record exceeds byte limit"
                )
            _pending, acknowledged, used = self._usage(connection)
            if acknowledged + 1 > self.max_acknowledgements:
                raise TradeDisputeStatementDispatchCapacity(
                    "max acknowledged Statement dispatches exceeded"
                )
            if used - row["total_bytes"] + total > self.max_bytes:
                raise TradeDisputeStatementDispatchCapacity(
                    "Statement dispatch store capacity exceeded"
                )
            connection.execute(
                "UPDATE dispatches SET acknowledgement_bytes = ?, "
                "remote_event_id = ?, observed_at_ms = ?, updated_at_ms = ?, "
                "last_error = '', total_bytes = ?, lease_token = '', "
                "lease_expires_at_ms = 0 WHERE statement_digest = ?",
                (
                    acknowledgement.canonical_bytes,
                    event_id,
                    observed,
                    max(observed, existing.updated_at_ms),
                    total,
                    digest,
                ),
            )
            connection.execute("COMMIT")
        except TradeDisputeStatementDispatchError:
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
            self._database_error(exc)
        finally:
            connection.close()
        state = self.get(digest)
        if state is None:
            raise TradeDisputeStatementDispatchError(
                "acknowledged dispatch state disappeared"
            )
        return state

    def mark_anchored(
        self,
        statement_digest: str,
        *,
        anchor_event_id: str,
    ) -> TradeDisputeStatementDispatchRecord:
        digest = _digest(statement_digest, label="statement_digest")
        event_id = _event_id(anchor_event_id)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM dispatches WHERE statement_digest = ?",
                (digest,),
            ).fetchone()
            if row is None:
                raise TradeDisputeStatementDispatchError(
                    "acknowledged Statement dispatch does not exist"
                )
            existing = self._record(row)
            if not existing.acknowledged:
                raise TradeDisputeStatementDispatchError(
                    "Statement dispatch is not acknowledged"
                )
            if existing.anchor_event_id and existing.anchor_event_id != event_id:
                raise TradeDisputeStatementDispatchError(
                    "Statement dispatch has conflicting anchor event"
                )
            connection.execute(
                "UPDATE dispatches SET anchor_event_id = ? "
                "WHERE statement_digest = ?",
                (event_id, digest),
            )
            connection.execute("COMMIT")
        except TradeDisputeStatementDispatchError:
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
            self._database_error(exc)
        finally:
            connection.close()
        state = self.get(digest)
        if state is None:
            raise TradeDisputeStatementDispatchError(
                "anchored dispatch state disappeared"
            )
        return state

    def get(self, statement_digest: str) -> TradeDisputeStatementDispatchRecord | None:
        digest = _digest(statement_digest, label="statement_digest")
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM dispatches WHERE statement_digest = ?",
                (digest,),
            ).fetchone()
        except sqlite3.Error as exc:
            self._database_error(exc)
        finally:
            connection.close()
        return self._record(row) if row is not None else None

    def recoverable(
        self,
        *,
        limit: int = 100,
        after_digest: str | None = None,
    ) -> tuple[tuple[TradeDisputeStatementDispatchRecord, ...], bool]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        after = _digest(after_digest, label="after_digest") if after_digest else ""
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM dispatches WHERE statement_digest > ? "
                "AND acknowledgement_bytes IS NOT NULL AND anchor_event_id = '' "
                "ORDER BY statement_digest LIMIT ?",
                (after, limit + 1),
            ).fetchall()
        except sqlite3.Error as exc:
            self._database_error(exc)
        finally:
            connection.close()
        return tuple(self._record(row) for row in rows[:limit]), len(rows) > limit


def dispute_statement_acknowledgement_audit_payload(
    record: TradeDisputeStatementDispatchRecord,
) -> dict[str, Any]:
    if not record.acknowledged:
        raise TradeDisputeStatementDispatchError(
            "dispatch has no acknowledgement"
        )
    document = record.acknowledgement.to_dict()
    return {
        "protocol_version": DISPUTE_STATEMENT_DISPATCH_PROTOCOL_VERSION,
        "statement_digest": record.statement_digest,
        "delivery_digest": record.delivery_digest,
        "acknowledgement_digest": record.acknowledgement_digest,
        "receiver_did": document["receiver_did"],
        "remote_event_id": record.remote_event_id,
        "received_at": document["received_at"],
        "status": document["status"],
        "generation": record.generation,
        "superseded_delivery_digests": list(
            record.superseded_delivery_digests
        ),
    }


class TradeDisputeStatementDispatchCoordinator:
    """Persist network state before anchoring a verified remote ACK."""

    def __init__(
        self,
        store: TradeDisputeStatementDispatchStore,
        spine: SignedEventLog,
    ) -> None:
        if not isinstance(store, TradeDisputeStatementDispatchStore):
            raise TypeError("store must be a TradeDisputeStatementDispatchStore")
        if not isinstance(spine, SignedEventLog):
            raise TypeError("spine must be a SignedEventLog")
        self.store = store
        self.spine = spine

    def _anchor(
        self,
        record: TradeDisputeStatementDispatchRecord,
    ) -> tuple[SpineEvent, bool]:
        payload = dispute_statement_acknowledgement_audit_payload(record)
        event, created = self.spine.append_unique(
            EVENT_TRADE_DISPUTE_STATEMENT_ACKNOWLEDGED,
            payload,
            unique_payload_fields=("statement_digest",),
            ts_ms=record.observed_at_ms,
        )
        event_ok, _event_reason = verify_event(event)
        if (
            not event_ok
            or event.type != EVENT_TRADE_DISPUTE_STATEMENT_ACKNOWLEDGED
            or event.payload != payload
            or event.author_did != self.spine.signer_did
            or event.ts_ms != record.observed_at_ms
        ):
            raise TradeDisputeStatementDispatchError(
                "Spine returned conflicting Statement acknowledgement anchor"
            )
        return event, created

    def acknowledge(
        self,
        statement_digest: str,
        acknowledgement: TradeDisputeStatementAcknowledgement,
        *,
        remote_event_id: str,
        lease_token: str,
    ) -> TradeDisputeStatementDispatchRecord:
        record = self.store.put_acknowledgement(
            statement_digest,
            acknowledgement,
            remote_event_id=remote_event_id,
            lease_token=lease_token,
        )
        event, _created = self._anchor(record)
        return self.store.mark_anchored(
            statement_digest,
            anchor_event_id=event.event_id,
        )

    def recover_acknowledgement(
        self,
        statement_digest: str,
    ) -> TradeDisputeStatementDispatchRecord | None:
        record = self.store.get(statement_digest)
        if record is None or not record.acknowledged:
            return None
        if record.anchor_event_id:
            return record
        event, _created = self._anchor(record)
        return self.store.mark_anchored(
            statement_digest,
            anchor_event_id=event.event_id,
        )

    def reconcile(
        self,
        *,
        limit: int = 100,
        after_digest: str | None = None,
    ) -> TradeDisputeStatementDispatchReconciliation:
        records, has_more = self.store.recoverable(
            limit=limit,
            after_digest=after_digest,
        )
        anchored = 0
        failed = 0
        for record in records:
            try:
                event, _created = self._anchor(record)
                self.store.mark_anchored(
                    record.statement_digest,
                    anchor_event_id=event.event_id,
                )
                anchored += 1
            except (OSError, RuntimeError, TypeError, ValueError):
                failed += 1
        return TradeDisputeStatementDispatchReconciliation(
            scanned=len(records),
            anchored=anchored,
            failed=failed,
            next_cursor=(records[-1].statement_digest if has_more and records else ""),
            has_more=has_more,
        )


__all__ = [
    "DEFAULT_MAX_DISPUTE_STATEMENT_ACKNOWLEDGEMENTS",
    "DEFAULT_MAX_DISPUTE_STATEMENT_DISPATCH_BYTES",
    "DEFAULT_MAX_PENDING_DISPUTE_STATEMENTS",
    "DEFAULT_DISPUTE_STATEMENT_SEND_LEASE_MS",
    "DISPUTE_STATEMENT_DISPATCH_PROTOCOL_VERSION",
    "EVENT_TRADE_DISPUTE_STATEMENT_ACKNOWLEDGED",
    "MAX_DISPUTE_STATEMENT_DISPATCH_DOCUMENT_BYTES",
    "MAX_SUPERSEDED_DISPUTE_STATEMENT_DELIVERIES",
    "TradeDisputeStatementDispatchBusy",
    "TradeDisputeStatementDispatchCapacity",
    "TradeDisputeStatementDispatchCoordinator",
    "TradeDisputeStatementDispatchError",
    "TradeDisputeStatementDispatchRecord",
    "TradeDisputeStatementDispatchReconciliation",
    "TradeDisputeStatementDispatchStore",
    "dispute_statement_acknowledgement_audit_payload",
]
