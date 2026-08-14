"""Durable sender outbox for federated Trade Execution Receipts."""

from __future__ import annotations

import json
import math
import re
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from nth_dao.spine import SignedEventLog, SpineEvent
from nth_dao.trade_rules.agreement_order import TradeOrder, trade_order_digest
from nth_dao.trade_rules.canonical import MAX_SAFE_INTEGER
from nth_dao.trade_rules.execution_transport import (
    DEFAULT_EXECUTION_RECEIPT_DELIVERY_CLOCK_SKEW_SECONDS,
    TradeExecutionReceiptAcknowledgement,
    TradeExecutionReceiptDelivery,
    trade_execution_receipt_acknowledgement_digest,
    trade_execution_receipt_delivery_digest,
    verify_trade_execution_receipt_acknowledgement,
    verify_trade_execution_receipt_delivery,
)
from nth_dao.util.io import InterProcessLock
from nth_dao.util.jsonl_safe import LOCK_TIMEOUT_PATIENT
from nth_dao.util.path_security import path_is_linklike

EVENT_TRADE_EXECUTION_RECEIPT_ACKNOWLEDGED = (
    "trade.execution.receipt-acknowledged"
)
EXECUTION_RECEIPT_DISPATCH_PROTOCOL_VERSION = "1"
DEFAULT_MAX_PENDING_EXECUTION_RECEIPTS = 4_096
DEFAULT_MAX_EXECUTION_RECEIPT_ACKNOWLEDGEMENTS = 65_536
DEFAULT_MAX_EXECUTION_DISPATCH_BYTES = 2 * 1024 * 1024 * 1024
MAX_EXECUTION_DISPATCH_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_SUPERSEDED_EXECUTION_RECEIPT_DELIVERIES = 256
MAX_EXECUTION_DISPATCH_STATE_BATCH = 500

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVENT_ID = re.compile(r"^[0-9a-f]{64}$")
_OBSERVATION_CLOCK_SKEW_MS = int(
    DEFAULT_EXECUTION_RECEIPT_DELIVERY_CLOCK_SKEW_SECONDS * 1_000
)


class TradeExecutionReceiptDispatchError(RuntimeError):
    """Execution Receipt dispatch state is invalid or unavailable."""


class TradeExecutionReceiptDispatchBusy(TradeExecutionReceiptDispatchError):
    """Another process currently owns the durable dispatch transaction."""


class TradeExecutionReceiptDispatchCapacity(
    TradeExecutionReceiptDispatchError
):
    """The bounded execution Receipt dispatch store is full."""


def _raise_sqlite_operational(
    exc: sqlite3.OperationalError,
    *,
    action: str,
) -> None:
    """Distinguish transient lock contention from durable store failure."""

    code = getattr(exc, "sqlite_errorcode", None)
    if code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
        raise TradeExecutionReceiptDispatchBusy(
            "dispatch store is busy"
        ) from exc
    raise TradeExecutionReceiptDispatchError(
        f"unable to {action}"
    ) from exc


def _now_ms(value: int | None = None) -> int:
    result = time.time_ns() // 1_000_000 if value is None else value
    if (
        isinstance(result, bool)
        or not isinstance(result, int)
        or not 0 < result <= MAX_SAFE_INTEGER
    ):
        raise ValueError("now_ms must be a safe positive integer")
    return result


def _normalize_target_url(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 2_048:
        raise TradeExecutionReceiptDispatchError("target_url is invalid")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise TradeExecutionReceiptDispatchError(
            "target_url contains control characters"
        )
    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError as exc:
        raise TradeExecutionReceiptDispatchError(
            "target_url is invalid"
        ) from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TradeExecutionReceiptDispatchError(
            "target_url must be an HTTP(S) URL"
        )
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise TradeExecutionReceiptDispatchError(
            "target_url must not include credentials, query, or fragment"
        )
    host = parsed.hostname.lower().rstrip(".")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host + (f":{port}" if port is not None else "")
    return urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path.rstrip("/"), "", "")
    ).rstrip("/")


def _digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise TradeExecutionReceiptDispatchError(f"{label} is invalid")
    return value


def _event_id(value: Any) -> str:
    if not isinstance(value, str) or _EVENT_ID.fullmatch(value) is None:
        raise TradeExecutionReceiptDispatchError("remote_event_id is invalid")
    return value


def _signed_timestamp_ms(value: Any) -> int:
    from datetime import datetime

    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise TradeExecutionReceiptDispatchError(
            "signed acknowledgement timestamp is invalid"
        ) from exc
    return int(moment.timestamp() * 1_000)


def _bounded_document(raw: bytes, *, label: str) -> bytes:
    if not isinstance(raw, bytes) or not raw:
        raise TradeExecutionReceiptDispatchError(f"{label} is empty")
    if len(raw) > MAX_EXECUTION_DISPATCH_DOCUMENT_BYTES:
        raise TradeExecutionReceiptDispatchCapacity(f"{label} is too large")
    return raw


def _is_linklike(path: Path) -> bool:
    return path_is_linklike(path)


@dataclass(frozen=True)
class TradeExecutionReceiptDispatchRecord:
    receipt_digest: str
    order_digest: str
    target_url: str
    delivery: TradeExecutionReceiptDelivery
    order: TradeOrder
    attempts: int
    last_error: str
    created_at_ms: int
    updated_at_ms: int
    acknowledged: bool = False
    generation: int = 1
    superseded_delivery_digests: tuple[str, ...] = ()


@dataclass(frozen=True)
class TradeExecutionReceiptAcknowledgedDispatch:
    receipt_digest: str
    order_digest: str
    target_url: str
    delivery: TradeExecutionReceiptDelivery
    order: TradeOrder
    acknowledgement: TradeExecutionReceiptAcknowledgement
    remote_event_id: str
    observed_at_ms: int
    generation: int = 1
    superseded_delivery_digests: tuple[str, ...] = ()

    @property
    def delivery_digest(self) -> str:
        return trade_execution_receipt_delivery_digest(
            self.delivery,
            order=self.order,
        )

    @property
    def acknowledgement_digest(self) -> str:
        return trade_execution_receipt_acknowledgement_digest(
            self.acknowledgement
        )


@dataclass(frozen=True)
class TradeExecutionReceiptDispatchReconciliation:
    scanned: int
    anchored: int
    completed: int
    failed: int
    next_cursor: str
    has_more: bool


class TradeExecutionReceiptDispatchStore:
    """SQLite-backed process-safe pending and acknowledgement retention."""

    def __init__(
        self,
        root: str | Path,
        *,
        max_pending: int = DEFAULT_MAX_PENDING_EXECUTION_RECEIPTS,
        max_acknowledgements: int = (
            DEFAULT_MAX_EXECUTION_RECEIPT_ACKNOWLEDGEMENTS
        ),
        max_bytes: int = DEFAULT_MAX_EXECUTION_DISPATCH_BYTES,
        timeout: float = LOCK_TIMEOUT_PATIENT,
    ) -> None:
        for label, value in (
            ("max_pending", max_pending),
            ("max_acknowledgements", max_acknowledgements),
            ("max_bytes", max_bytes),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 1
            ):
                raise ValueError(f"{label} must be a positive integer")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("timeout must be finite and positive")
        self.workspace_root = Path(root)
        self.root = self.workspace_root / "trade" / "execution_dispatch_v1"
        self.path = self.root / "dispatch.sqlite3"
        self.max_pending = max_pending
        self.max_acknowledgements = max_acknowledgements
        self.max_bytes = max_bytes
        self.timeout = float(timeout)
        self._assert_storage_path()
        self.root.mkdir(parents=True, exist_ok=True)
        self._assert_storage_path()
        try:
            with InterProcessLock(
                self.root / ".initialize",
                timeout=self.timeout,
            ):
                self._initialize()
        except TimeoutError as exc:
            raise TradeExecutionReceiptDispatchBusy(
                "dispatch initialization is busy"
            ) from exc

    def _assert_storage_path(self) -> None:
        current = self.workspace_root
        for part in ("trade", "execution_dispatch_v1"):
            if _is_linklike(current):
                raise TradeExecutionReceiptDispatchError(
                    "dispatch store must not contain links or junctions"
                )
            current = current / part
        if _is_linklike(current) or _is_linklike(self.path):
            raise TradeExecutionReceiptDispatchError(
                "dispatch store must not contain links or junctions"
            )

    def _connect(self) -> sqlite3.Connection:
        self._assert_storage_path()
        connection = sqlite3.connect(
            str(self.path),
            timeout=self.timeout,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute(
            f"PRAGMA busy_timeout = {max(1, int(self.timeout * 1_000))}"
        )
        return connection

    def _initialize(self) -> None:
        try:
            with self._connect() as connection:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("PRAGMA synchronous = FULL")
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS pending (
                        receipt_digest TEXT PRIMARY KEY,
                        order_digest TEXT NOT NULL,
                        target_url TEXT NOT NULL,
                        delivery_bytes BLOB NOT NULL,
                        order_bytes BLOB NOT NULL,
                        attempts INTEGER NOT NULL,
                        last_error TEXT NOT NULL,
                        created_at_ms INTEGER NOT NULL,
                        updated_at_ms INTEGER NOT NULL
                        , generation INTEGER NOT NULL DEFAULT 1
                        , superseded_delivery_digests TEXT NOT NULL DEFAULT '[]'
                    );
                    CREATE TABLE IF NOT EXISTS acknowledgements (
                        receipt_digest TEXT PRIMARY KEY,
                        order_digest TEXT NOT NULL,
                        target_url TEXT NOT NULL,
                        delivery_bytes BLOB NOT NULL,
                        order_bytes BLOB NOT NULL,
                        acknowledgement_bytes BLOB NOT NULL,
                        remote_event_id TEXT NOT NULL,
                        observed_at_ms INTEGER NOT NULL,
                        generation INTEGER NOT NULL DEFAULT 1,
                        superseded_delivery_digests TEXT NOT NULL DEFAULT '[]'
                    );
                    """
                )
                columns = {
                    row["name"]
                    for row in connection.execute(
                        "PRAGMA table_info(pending)"
                    ).fetchall()
                }
                if "generation" not in columns:
                    connection.execute(
                        "ALTER TABLE pending ADD COLUMN generation "
                        "INTEGER NOT NULL DEFAULT 1"
                    )
                if "superseded_delivery_digests" not in columns:
                    connection.execute(
                        "ALTER TABLE pending ADD COLUMN "
                        "superseded_delivery_digests TEXT NOT NULL "
                        "DEFAULT '[]'"
                    )
                acknowledgement_columns = {
                    row["name"]
                    for row in connection.execute(
                        "PRAGMA table_info(acknowledgements)"
                    ).fetchall()
                }
                if "generation" not in acknowledgement_columns:
                    connection.execute(
                        "ALTER TABLE acknowledgements ADD COLUMN generation "
                        "INTEGER NOT NULL DEFAULT 1"
                    )
                if (
                    "superseded_delivery_digests"
                    not in acknowledgement_columns
                ):
                    connection.execute(
                        "ALTER TABLE acknowledgements ADD COLUMN "
                        "superseded_delivery_digests TEXT NOT NULL "
                        "DEFAULT '[]'"
                    )
        except sqlite3.Error as exc:
            raise TradeExecutionReceiptDispatchError(
                "unable to initialize dispatch store"
            ) from exc

    @staticmethod
    def _decode_generation_history(
        row: sqlite3.Row,
        delivery: TradeExecutionReceiptDelivery,
        order: TradeOrder,
        *,
        label: str,
    ) -> tuple[int, tuple[str, ...]]:
        generation = row["generation"]
        try:
            superseded_raw = json.loads(row["superseded_delivery_digests"])
        except (json.JSONDecodeError, TypeError) as exc:
            raise TradeExecutionReceiptDispatchError(
                f"{label} generation history is invalid"
            ) from exc
        current_delivery_digest = trade_execution_receipt_delivery_digest(
            delivery,
            order=order,
        )
        if (
            isinstance(generation, bool)
            or not isinstance(generation, int)
            or not 1 <= generation <= MAX_SAFE_INTEGER
            or not isinstance(superseded_raw, list)
            or len(superseded_raw)
            > MAX_SUPERSEDED_EXECUTION_RECEIPT_DELIVERIES
            or any(
                not isinstance(item, str) or _DIGEST.fullmatch(item) is None
                for item in superseded_raw
            )
            or len(set(superseded_raw)) != len(superseded_raw)
            or generation != len(superseded_raw) + 1
            or current_delivery_digest in superseded_raw
        ):
            raise TradeExecutionReceiptDispatchError(
                f"{label} generation history is invalid"
            )
        return generation, tuple(superseded_raw)

    @staticmethod
    def _decode_pending(row: sqlite3.Row) -> TradeExecutionReceiptDispatchRecord:
        try:
            order = TradeOrder.from_json(
                _bounded_document(row["order_bytes"], label="stored Order")
            )
            delivery = TradeExecutionReceiptDelivery.from_json(
                _bounded_document(
                    row["delivery_bytes"],
                    label="stored delivery",
                ),
                order=order,
            )
        except (TypeError, ValueError) as exc:
            raise TradeExecutionReceiptDispatchError(
                "pending signed bytes are invalid"
            ) from exc
        receipt_digest = _digest(
            row["receipt_digest"],
            label="receipt_digest",
        )
        document = delivery.to_dict()
        if (
            document["receipt_digest"] != receipt_digest
            or trade_order_digest(order) != row["order_digest"]
            or document["order_digest"] != row["order_digest"]
        ):
            raise TradeExecutionReceiptDispatchError(
                "pending digest binding is invalid"
            )
        attempts = row["attempts"]
        created = row["created_at_ms"]
        updated = row["updated_at_ms"]
        if (
            isinstance(attempts, bool)
            or not isinstance(attempts, int)
            or not 0 <= attempts <= MAX_SAFE_INTEGER
            or any(
                isinstance(item, bool)
                or not isinstance(item, int)
                or not 0 < item <= MAX_SAFE_INTEGER
                for item in (created, updated)
            )
            or updated < created
        ):
            raise TradeExecutionReceiptDispatchError(
                "pending counters or timestamps are invalid"
            )
        last_error = row["last_error"]
        if not isinstance(last_error, str) or len(last_error) > 500:
            raise TradeExecutionReceiptDispatchError(
                "pending last_error is invalid"
            )
        generation, superseded = (
            TradeExecutionReceiptDispatchStore._decode_generation_history(
                row,
                delivery,
                order,
                label="pending",
            )
        )
        return TradeExecutionReceiptDispatchRecord(
            receipt_digest=receipt_digest,
            order_digest=_digest(row["order_digest"], label="order_digest"),
            target_url=_normalize_target_url(row["target_url"]),
            delivery=delivery,
            order=order,
            attempts=attempts,
            last_error=last_error,
            created_at_ms=created,
            updated_at_ms=updated,
            acknowledged=False,
            generation=generation,
            superseded_delivery_digests=superseded,
        )

    @staticmethod
    def _decode_acknowledgement(
        row: sqlite3.Row,
    ) -> TradeExecutionReceiptAcknowledgedDispatch:
        try:
            order = TradeOrder.from_json(
                _bounded_document(row["order_bytes"], label="stored Order")
            )
            delivery = TradeExecutionReceiptDelivery.from_json(
                _bounded_document(
                    row["delivery_bytes"],
                    label="stored delivery",
                ),
                order=order,
            )
            acknowledgement = TradeExecutionReceiptAcknowledgement.from_json(
                _bounded_document(
                    row["acknowledgement_bytes"],
                    label="stored acknowledgement",
                )
            )
        except (TypeError, ValueError) as exc:
            raise TradeExecutionReceiptDispatchError(
                "acknowledgement signed bytes are invalid"
            ) from exc
        receipt_digest = _digest(
            row["receipt_digest"],
            label="receipt_digest",
        )
        order_digest = _digest(row["order_digest"], label="order_digest")
        remote_event_id = _event_id(row["remote_event_id"])
        ok, reason = verify_trade_execution_receipt_acknowledgement(
            acknowledgement,
            delivery=delivery,
            order=order,
            receiver_did=delivery.to_dict()["recipient_did"],
            audit_event_id=remote_event_id,
        )
        if not ok:
            raise TradeExecutionReceiptDispatchError(reason)
        if (
            delivery.to_dict()["receipt_digest"] != receipt_digest
            or trade_order_digest(order) != order_digest
            or delivery.to_dict()["order_digest"] != order_digest
        ):
            raise TradeExecutionReceiptDispatchError(
                "acknowledgement digest binding is invalid"
            )
        observed = row["observed_at_ms"]
        if (
            isinstance(observed, bool)
            or not isinstance(observed, int)
            or not 0 < observed <= MAX_SAFE_INTEGER
        ):
            raise TradeExecutionReceiptDispatchError(
                "observed_at_ms is invalid"
            )
        if observed + _OBSERVATION_CLOCK_SKEW_MS < _signed_timestamp_ms(
            acknowledgement.to_dict()["received_at"]
        ):
            raise TradeExecutionReceiptDispatchError(
                "acknowledgement observation predates signed receipt"
            )
        generation, superseded = (
            TradeExecutionReceiptDispatchStore._decode_generation_history(
                row,
                delivery,
                order,
                label="acknowledgement",
            )
        )
        return TradeExecutionReceiptAcknowledgedDispatch(
            receipt_digest=receipt_digest,
            order_digest=order_digest,
            target_url=_normalize_target_url(row["target_url"]),
            delivery=delivery,
            order=order,
            acknowledgement=acknowledgement,
            remote_event_id=remote_event_id,
            observed_at_ms=observed,
            generation=generation,
            superseded_delivery_digests=superseded,
        )

    def _usage(self, connection: sqlite3.Connection) -> tuple[int, int, int]:
        pending = connection.execute(
            "SELECT COUNT(*) AS count FROM pending"
        ).fetchone()["count"]
        acknowledgements = connection.execute(
            "SELECT COUNT(*) AS count FROM acknowledgements"
        ).fetchone()["count"]
        total = connection.execute(
            """
            SELECT COALESCE(SUM(size), 0) AS total FROM (
                SELECT length(delivery_bytes) + length(order_bytes)
                     + length(superseded_delivery_digests) AS size
                FROM pending
                UNION ALL
                SELECT length(delivery_bytes) + length(order_bytes)
                     + length(acknowledgement_bytes)
                     + length(superseded_delivery_digests) AS size
                FROM acknowledgements
            )
            """
        ).fetchone()["total"]
        return int(pending), int(acknowledgements), int(total)

    def prepare(
        self,
        delivery: TradeExecutionReceiptDelivery,
        *,
        order: TradeOrder | dict[str, Any],
        target_url: str,
        now_ms: int | None = None,
    ) -> TradeExecutionReceiptDispatchRecord:
        verified_order = (
            TradeOrder.from_json(order.canonical_bytes)
            if isinstance(order, TradeOrder)
            else TradeOrder.from_dict(order)
        )
        verified_delivery = TradeExecutionReceiptDelivery.from_json(
            delivery.canonical_bytes,
            order=verified_order,
        )
        document = verified_delivery.to_dict()
        receipt_digest = document["receipt_digest"]
        order_digest = document["order_digest"]
        target = _normalize_target_url(target_url)
        moment = _now_ms(now_ms)
        delivery_bytes = _bounded_document(
            verified_delivery.canonical_bytes,
            label="delivery",
        )
        order_bytes = _bounded_document(
            verified_order.canonical_bytes,
            label="Order",
        )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                ack = connection.execute(
                    "SELECT * FROM acknowledgements WHERE receipt_digest = ?",
                    (receipt_digest,),
                ).fetchone()
                if ack is not None:
                    retained = self._decode_acknowledgement(ack)
                    retained_document = retained.delivery.to_dict()
                    if (
                        retained.target_url != target
                        or retained.order.canonical_bytes != order_bytes
                        or retained.delivery.receipt.canonical_bytes
                        != verified_delivery.receipt.canonical_bytes
                        or retained_document["sender_did"]
                        != document["sender_did"]
                        or retained_document["recipient_did"]
                        != document["recipient_did"]
                    ):
                        raise TradeExecutionReceiptDispatchError(
                            "dispatch conflicts with acknowledged Receipt scope"
                        )
                    connection.commit()
                    return TradeExecutionReceiptDispatchRecord(
                        receipt_digest=receipt_digest,
                        order_digest=order_digest,
                        target_url=target,
                        delivery=retained.delivery,
                        order=retained.order,
                        attempts=0,
                        last_error="",
                        created_at_ms=retained.observed_at_ms,
                        updated_at_ms=retained.observed_at_ms,
                        acknowledged=True,
                        generation=retained.generation,
                        superseded_delivery_digests=(
                            retained.superseded_delivery_digests
                        ),
                    )
                existing = connection.execute(
                    "SELECT * FROM pending WHERE receipt_digest = ?",
                    (receipt_digest,),
                ).fetchone()
                if existing is not None:
                    retained = self._decode_pending(existing)
                    retained_document = retained.delivery.to_dict()
                    if (
                        retained.target_url != target
                        or retained.order.canonical_bytes != order_bytes
                        or retained.delivery.receipt.canonical_bytes
                        != verified_delivery.receipt.canonical_bytes
                        or retained_document["sender_did"]
                        != document["sender_did"]
                        or retained_document["recipient_did"]
                        != document["recipient_did"]
                    ):
                        raise TradeExecutionReceiptDispatchError(
                            "pending dispatch conflicts with Receipt scope"
                        )
                    connection.commit()
                    return retained
                pending_count, _ack_count, total = self._usage(connection)
                if pending_count + 1 > self.max_pending:
                    raise TradeExecutionReceiptDispatchCapacity(
                        "max_pending exceeded"
                    )
                empty_history = "[]"
                if (
                    total
                    + len(delivery_bytes)
                    + len(order_bytes)
                    + len(empty_history)
                    > self.max_bytes
                ):
                    raise TradeExecutionReceiptDispatchCapacity(
                        "max_bytes exceeded"
                    )
                connection.execute(
                    """
                    INSERT INTO pending (
                        receipt_digest, order_digest, target_url,
                        delivery_bytes, order_bytes, attempts, last_error,
                        created_at_ms, updated_at_ms, generation,
                        superseded_delivery_digests
                    ) VALUES (?, ?, ?, ?, ?, 0, '', ?, ?, 1, ?)
                    """,
                    (
                        receipt_digest,
                        order_digest,
                        target,
                        delivery_bytes,
                        order_bytes,
                        moment,
                        moment,
                        empty_history,
                    ),
                )
                retained = TradeExecutionReceiptDispatchRecord(
                    receipt_digest=receipt_digest,
                    order_digest=order_digest,
                    target_url=target,
                    delivery=verified_delivery,
                    order=verified_order,
                    attempts=0,
                    last_error="",
                    created_at_ms=moment,
                    updated_at_ms=moment,
                    acknowledged=False,
                    generation=1,
                    superseded_delivery_digests=(),
                )
                connection.commit()
                return retained
        except sqlite3.OperationalError as exc:
            _raise_sqlite_operational(exc, action="prepare dispatch")
        except sqlite3.Error as exc:
            raise TradeExecutionReceiptDispatchError(
                "unable to prepare dispatch"
            ) from exc

    def renew_expired(
        self,
        delivery: TradeExecutionReceiptDelivery,
        *,
        order: TradeOrder | dict[str, Any],
        target_url: str,
        now_ms: int | None = None,
    ) -> TradeExecutionReceiptDispatchRecord:
        """Replace only an expired pending envelope for the same Receipt."""

        verified_order = (
            TradeOrder.from_json(order.canonical_bytes)
            if isinstance(order, TradeOrder)
            else TradeOrder.from_dict(order)
        )
        replacement = TradeExecutionReceiptDelivery.from_json(
            delivery.canonical_bytes,
            order=verified_order,
        )
        document = replacement.to_dict()
        receipt_digest = document["receipt_digest"]
        target = _normalize_target_url(target_url)
        moment = _now_ms(now_ms)
        at = datetime.fromtimestamp(moment / 1_000, tz=timezone.utc)
        ok, reason = verify_trade_execution_receipt_delivery(
            replacement,
            order=verified_order,
            recipient_did=document["recipient_did"],
            at=at,
        )
        if not ok:
            raise TradeExecutionReceiptDispatchError(
                f"replacement delivery is not current: {reason}"
            )
        replacement_bytes = _bounded_document(
            replacement.canonical_bytes,
            label="replacement delivery",
        )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute(
                    "SELECT 1 FROM acknowledgements WHERE receipt_digest = ?",
                    (receipt_digest,),
                ).fetchone() is not None:
                    raise TradeExecutionReceiptDispatchError(
                        "acknowledged dispatch cannot be renewed"
                    )
                row = connection.execute(
                    "SELECT * FROM pending WHERE receipt_digest = ?",
                    (receipt_digest,),
                ).fetchone()
                if row is None:
                    raise TradeExecutionReceiptDispatchError(
                        "pending dispatch is missing"
                    )
                current = self._decode_pending(row)
                if (
                    current.target_url != target
                    or current.order.canonical_bytes
                    != verified_order.canonical_bytes
                    or current.delivery.receipt.canonical_bytes
                    != replacement.receipt.canonical_bytes
                    or current.delivery.to_dict()["sender_did"]
                    != document["sender_did"]
                    or current.delivery.to_dict()["recipient_did"]
                    != document["recipient_did"]
                ):
                    raise TradeExecutionReceiptDispatchError(
                        "replacement does not match pending dispatch scope"
                    )
                old_ok, old_reason = verify_trade_execution_receipt_delivery(
                    current.delivery,
                    order=current.order,
                    recipient_did=current.delivery.to_dict()["recipient_did"],
                    at=at,
                )
                if old_ok or "expired" not in old_reason:
                    raise TradeExecutionReceiptDispatchError(
                        "pending delivery is not expired"
                    )
                old_digest = trade_execution_receipt_delivery_digest(
                    current.delivery,
                    order=current.order,
                )
                new_digest = trade_execution_receipt_delivery_digest(
                    replacement,
                    order=verified_order,
                )
                if old_digest == new_digest:
                    raise TradeExecutionReceiptDispatchError(
                        "replacement delivery must use fresh signed bytes"
                    )
                history = (*current.superseded_delivery_digests, old_digest)
                if (
                    len(history)
                    > MAX_SUPERSEDED_EXECUTION_RECEIPT_DELIVERIES
                ):
                    raise TradeExecutionReceiptDispatchCapacity(
                        "delivery generation history is full"
                    )
                history_json = json.dumps(
                    list(history),
                    separators=(",", ":"),
                )
                _pending_count, _ack_count, total = self._usage(connection)
                previous_history = row["superseded_delivery_digests"]
                projected_total = (
                    total
                    - len(row["delivery_bytes"])
                    - len(previous_history.encode("utf-8"))
                    + len(replacement_bytes)
                    + len(history_json.encode("ascii"))
                )
                if projected_total > self.max_bytes:
                    raise TradeExecutionReceiptDispatchCapacity(
                        "max_bytes exceeded"
                    )
                connection.execute(
                    """
                    UPDATE pending
                    SET delivery_bytes = ?, attempts = 0, last_error = '',
                        updated_at_ms = ?, generation = ?,
                        superseded_delivery_digests = ?
                    WHERE receipt_digest = ?
                    """,
                    (
                        replacement_bytes,
                        max(moment, current.updated_at_ms),
                        current.generation + 1,
                        history_json,
                        receipt_digest,
                    ),
                )
                retained = TradeExecutionReceiptDispatchRecord(
                    receipt_digest=receipt_digest,
                    order_digest=document["order_digest"],
                    target_url=target,
                    delivery=replacement,
                    order=verified_order,
                    attempts=0,
                    last_error="",
                    created_at_ms=current.created_at_ms,
                    updated_at_ms=max(moment, current.updated_at_ms),
                    acknowledged=False,
                    generation=current.generation + 1,
                    superseded_delivery_digests=history,
                )
                connection.commit()
            return retained
        except sqlite3.OperationalError as exc:
            _raise_sqlite_operational(exc, action="renew dispatch")
        except sqlite3.Error as exc:
            raise TradeExecutionReceiptDispatchError(
                "unable to renew dispatch"
            ) from exc

    def note_failure(
        self,
        receipt_digest: str,
        *,
        error: str,
        now_ms: int | None = None,
    ) -> TradeExecutionReceiptDispatchRecord:
        digest = _digest(receipt_digest, label="receipt_digest")
        moment = _now_ms(now_ms)
        message = str(error).replace("\r", " ").replace("\n", " ")[:500]
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM pending WHERE receipt_digest = ?",
                    (digest,),
                ).fetchone()
                if row is None:
                    raise TradeExecutionReceiptDispatchError(
                        "pending dispatch is missing"
                    )
                record = self._decode_pending(row)
                if record.attempts >= MAX_SAFE_INTEGER:
                    raise TradeExecutionReceiptDispatchCapacity(
                        "pending attempt counter is exhausted"
                    )
                connection.execute(
                    """
                    UPDATE pending
                    SET attempts = ?, last_error = ?, updated_at_ms = ?
                    WHERE receipt_digest = ?
                    """,
                    (
                        record.attempts + 1,
                        message,
                        max(moment, record.updated_at_ms),
                        digest,
                    ),
                )
                retained = TradeExecutionReceiptDispatchRecord(
                    receipt_digest=record.receipt_digest,
                    order_digest=record.order_digest,
                    target_url=record.target_url,
                    delivery=record.delivery,
                    order=record.order,
                    attempts=record.attempts + 1,
                    last_error=message,
                    created_at_ms=record.created_at_ms,
                    updated_at_ms=max(moment, record.updated_at_ms),
                    acknowledged=False,
                    generation=record.generation,
                    superseded_delivery_digests=(
                        record.superseded_delivery_digests
                    ),
                )
                connection.commit()
                return retained
        except sqlite3.OperationalError as exc:
            _raise_sqlite_operational(exc, action="record dispatch failure")
        except sqlite3.Error as exc:
            raise TradeExecutionReceiptDispatchError(
                "unable to record dispatch failure"
            ) from exc

    def put_acknowledgement(
        self,
        delivery: TradeExecutionReceiptDelivery,
        acknowledgement: TradeExecutionReceiptAcknowledgement,
        *,
        order: TradeOrder | dict[str, Any],
        target_url: str,
        remote_event_id: str,
        observed_at_ms: int | None = None,
    ) -> TradeExecutionReceiptAcknowledgedDispatch:
        verified_order = (
            TradeOrder.from_json(order.canonical_bytes)
            if isinstance(order, TradeOrder)
            else TradeOrder.from_dict(order)
        )
        verified_delivery = TradeExecutionReceiptDelivery.from_json(
            delivery.canonical_bytes,
            order=verified_order,
        )
        verified_ack = TradeExecutionReceiptAcknowledgement.from_json(
            acknowledgement.canonical_bytes
        )
        receipt_digest = verified_delivery.to_dict()["receipt_digest"]
        order_digest = verified_delivery.to_dict()["order_digest"]
        target = _normalize_target_url(target_url)
        event_id = _event_id(remote_event_id)
        observed = _now_ms(observed_at_ms)
        ok, reason = verify_trade_execution_receipt_acknowledgement(
            verified_ack,
            delivery=verified_delivery,
            order=verified_order,
            receiver_did=verified_delivery.to_dict()["recipient_did"],
            audit_event_id=event_id,
        )
        if not ok:
            raise TradeExecutionReceiptDispatchError(reason)
        if observed + _OBSERVATION_CLOCK_SKEW_MS < _signed_timestamp_ms(
            verified_ack.to_dict()["received_at"]
        ):
            raise TradeExecutionReceiptDispatchError(
                "acknowledgement observation predates signed receipt"
            )
        delivery_bytes = _bounded_document(
            verified_delivery.canonical_bytes,
            label="delivery",
        )
        order_bytes = _bounded_document(
            verified_order.canonical_bytes,
            label="Order",
        )
        ack_bytes = _bounded_document(
            verified_ack.canonical_bytes,
            label="acknowledgement",
        )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT * FROM acknowledgements WHERE receipt_digest = ?",
                    (receipt_digest,),
                ).fetchone()
                if existing is not None:
                    retained = self._decode_acknowledgement(existing)
                    if (
                        retained.target_url != target
                        or retained.delivery.canonical_bytes != delivery_bytes
                        or retained.order.canonical_bytes != order_bytes
                        or retained.acknowledgement.canonical_bytes != ack_bytes
                        or retained.remote_event_id != event_id
                    ):
                        raise TradeExecutionReceiptDispatchError(
                            "acknowledgement conflicts with retained bytes"
                        )
                    connection.commit()
                    return retained
                pending = connection.execute(
                    "SELECT * FROM pending WHERE receipt_digest = ?",
                    (receipt_digest,),
                ).fetchone()
                if pending is None:
                    raise TradeExecutionReceiptDispatchError(
                        "acknowledgement has no pending dispatch"
                    )
                pending_record = self._decode_pending(pending)
                if (
                    pending_record.target_url != target
                    or pending_record.delivery.canonical_bytes != delivery_bytes
                    or pending_record.order.canonical_bytes != order_bytes
                ):
                    raise TradeExecutionReceiptDispatchError(
                        "acknowledgement does not match pending dispatch"
                    )
                history_json = json.dumps(
                    list(pending_record.superseded_delivery_digests),
                    separators=(",", ":"),
                )
                _pending_count, ack_count, total = self._usage(connection)
                if ack_count + 1 > self.max_acknowledgements:
                    raise TradeExecutionReceiptDispatchCapacity(
                        "max_acknowledgements exceeded"
                    )
                if (
                    total
                    + len(delivery_bytes)
                    + len(order_bytes)
                    + len(ack_bytes)
                    + len(history_json.encode("ascii"))
                    > self.max_bytes
                ):
                    raise TradeExecutionReceiptDispatchCapacity(
                        "max_bytes exceeded"
                    )
                connection.execute(
                    """
                    INSERT INTO acknowledgements (
                        receipt_digest, order_digest, target_url,
                        delivery_bytes, order_bytes, acknowledgement_bytes,
                        remote_event_id, observed_at_ms, generation,
                        superseded_delivery_digests
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        receipt_digest,
                        order_digest,
                        target,
                        delivery_bytes,
                        order_bytes,
                        ack_bytes,
                        event_id,
                        observed,
                        pending_record.generation,
                        history_json,
                    ),
                )
                retained = TradeExecutionReceiptAcknowledgedDispatch(
                    receipt_digest=receipt_digest,
                    order_digest=order_digest,
                    target_url=target,
                    delivery=verified_delivery,
                    order=verified_order,
                    acknowledgement=verified_ack,
                    remote_event_id=event_id,
                    observed_at_ms=observed,
                    generation=pending_record.generation,
                    superseded_delivery_digests=(
                        pending_record.superseded_delivery_digests
                    ),
                )
                connection.commit()
                return retained
        except sqlite3.OperationalError as exc:
            _raise_sqlite_operational(exc, action="retain acknowledgement")
        except sqlite3.Error as exc:
            raise TradeExecutionReceiptDispatchError(
                "unable to retain acknowledgement"
            ) from exc

    def get_pending(
        self,
        receipt_digest: str,
    ) -> TradeExecutionReceiptDispatchRecord | None:
        digest = _digest(receipt_digest, label="receipt_digest")
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM pending WHERE receipt_digest = ?",
                    (digest,),
                ).fetchone()
            return None if row is None else self._decode_pending(row)
        except sqlite3.OperationalError as exc:
            _raise_sqlite_operational(exc, action="read pending dispatch")
        except sqlite3.Error as exc:
            raise TradeExecutionReceiptDispatchError(
                "unable to read pending dispatch"
            ) from exc

    def get_acknowledgement(
        self,
        receipt_digest: str,
    ) -> TradeExecutionReceiptAcknowledgedDispatch | None:
        digest = _digest(receipt_digest, label="receipt_digest")
        try:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT * FROM acknowledgements WHERE receipt_digest = ?
                    """,
                    (digest,),
                ).fetchone()
            return None if row is None else self._decode_acknowledgement(row)
        except sqlite3.OperationalError as exc:
            _raise_sqlite_operational(exc, action="read acknowledgement")
        except sqlite3.Error as exc:
            raise TradeExecutionReceiptDispatchError(
                "unable to read acknowledgement"
            ) from exc

    def get_states(
        self,
        receipt_digests: tuple[str, ...],
    ) -> dict[
        str,
        tuple[
            TradeExecutionReceiptDispatchRecord | None,
            TradeExecutionReceiptAcknowledgedDispatch | None,
        ],
    ]:
        """Read bounded pending/ACK state in one consistent transaction."""

        if not isinstance(receipt_digests, tuple):
            raise TypeError("receipt_digests must be a tuple")
        if len(receipt_digests) > MAX_EXECUTION_DISPATCH_STATE_BATCH:
            raise ValueError(
                "receipt_digests exceeds the bounded batch size"
            )
        digests = tuple(
            dict.fromkeys(
                _digest(value, label="receipt_digest")
                for value in receipt_digests
            )
        )
        if not digests:
            return {}
        placeholders = ",".join("?" for _value in digests)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN")
                pending_rows = connection.execute(
                    f"SELECT * FROM pending WHERE receipt_digest IN "
                    f"({placeholders})",  # noqa: S608 - placeholders only
                    digests,
                ).fetchall()
                acknowledgement_rows = connection.execute(
                    f"SELECT * FROM acknowledgements WHERE receipt_digest IN "
                    f"({placeholders})",  # noqa: S608 - placeholders only
                    digests,
                ).fetchall()
                connection.commit()
            pending = {
                row["receipt_digest"]: self._decode_pending(row)
                for row in pending_rows
            }
            acknowledgements = {
                row["receipt_digest"]: self._decode_acknowledgement(row)
                for row in acknowledgement_rows
            }
            return {
                digest: (pending.get(digest), acknowledgements.get(digest))
                for digest in digests
            }
        except sqlite3.OperationalError as exc:
            _raise_sqlite_operational(exc, action="read dispatch states")
        except sqlite3.Error as exc:
            raise TradeExecutionReceiptDispatchError(
                "unable to read dispatch states"
            ) from exc

    def list_acknowledgements(
        self,
        *,
        limit: int = 1_000,
        after: str | None = None,
    ) -> tuple[tuple[TradeExecutionReceiptAcknowledgedDispatch, ...], str]:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 1_000
        ):
            raise ValueError("limit must be in 1..1000")
        cursor = _digest(after, label="after") if after is not None else ""
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    """
                    SELECT * FROM acknowledgements
                    WHERE receipt_digest > ?
                    ORDER BY receipt_digest ASC
                    LIMIT ?
                    """,
                    (cursor, limit + 1),
                ).fetchall()
            page = rows[:limit]
            next_cursor = (
                page[-1]["receipt_digest"]
                if len(rows) > limit and page
                else ""
            )
            return (
                tuple(self._decode_acknowledgement(row) for row in page),
                next_cursor,
            )
        except sqlite3.OperationalError as exc:
            _raise_sqlite_operational(exc, action="list acknowledgements")
        except sqlite3.Error as exc:
            raise TradeExecutionReceiptDispatchError(
                "unable to list acknowledgements"
            ) from exc

    def list_recoverable_acknowledgements(
        self,
        *,
        limit: int = 1_000,
        after: str | None = None,
    ) -> tuple[tuple[TradeExecutionReceiptAcknowledgedDispatch, ...], str]:
        """List only ACKs whose pending marker still needs retiring."""

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 1_000
        ):
            raise ValueError("limit must be in 1..1000")
        cursor = _digest(after, label="after") if after is not None else ""
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    """
                    SELECT acknowledgements.*
                    FROM acknowledgements
                    INNER JOIN pending USING (receipt_digest)
                    WHERE acknowledgements.receipt_digest > ?
                    ORDER BY acknowledgements.receipt_digest ASC
                    LIMIT ?
                    """,
                    (cursor, limit + 1),
                ).fetchall()
            page = rows[:limit]
            next_cursor = (
                page[-1]["receipt_digest"]
                if len(rows) > limit and page
                else ""
            )
            return (
                tuple(self._decode_acknowledgement(row) for row in page),
                next_cursor,
            )
        except sqlite3.OperationalError as exc:
            _raise_sqlite_operational(
                exc,
                action="list recoverable acknowledgements",
            )
        except sqlite3.Error as exc:
            raise TradeExecutionReceiptDispatchError(
                "unable to list recoverable acknowledgements"
            ) from exc

    def complete_pending(self, receipt_digest: str) -> bool:
        digest = _digest(receipt_digest, label="receipt_digest")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                pending = connection.execute(
                    "SELECT * FROM pending WHERE receipt_digest = ?",
                    (digest,),
                ).fetchone()
                ack = connection.execute(
                    "SELECT * FROM acknowledgements WHERE receipt_digest = ?",
                    (digest,),
                ).fetchone()
                if ack is None:
                    raise TradeExecutionReceiptDispatchError(
                        "dispatch cannot complete without an acknowledgement"
                    )
                if pending is None:
                    connection.commit()
                    return False
                pending_record = self._decode_pending(pending)
                acknowledgement = self._decode_acknowledgement(ack)
                if (
                    pending_record.target_url != acknowledgement.target_url
                    or pending_record.delivery.canonical_bytes
                    != acknowledgement.delivery.canonical_bytes
                    or pending_record.order.canonical_bytes
                    != acknowledgement.order.canonical_bytes
                ):
                    raise TradeExecutionReceiptDispatchError(
                        "pending dispatch conflicts with acknowledgement"
                    )
                connection.execute(
                    "DELETE FROM pending WHERE receipt_digest = ?",
                    (digest,),
                )
                connection.commit()
                return True
        except sqlite3.OperationalError as exc:
            _raise_sqlite_operational(exc, action="complete pending dispatch")
        except sqlite3.Error as exc:
            raise TradeExecutionReceiptDispatchError(
                "unable to complete pending dispatch"
            ) from exc


def execution_receipt_acknowledgement_audit_payload(
    acknowledgement: TradeExecutionReceiptAcknowledgedDispatch,
) -> dict[str, Any]:
    document = acknowledgement.acknowledgement.to_dict()
    return {
        "protocol_version": EXECUTION_RECEIPT_DISPATCH_PROTOCOL_VERSION,
        "order_digest": acknowledgement.order_digest,
        "receipt_digest": acknowledgement.receipt_digest,
        "delivery_digest": acknowledgement.delivery_digest,
        "acknowledgement_digest": acknowledgement.acknowledgement_digest,
        "receiver_did": document["receiver_did"],
        "remote_event_id": acknowledgement.remote_event_id,
        "received_at": document["received_at"],
        "generation": acknowledgement.generation,
        "superseded_delivery_digests": list(
            acknowledgement.superseded_delivery_digests
        ),
    }


class TradeExecutionReceiptDispatchCoordinator:
    """Retain ACK, anchor it locally, then retire durable pending work."""

    def __init__(
        self,
        store: TradeExecutionReceiptDispatchStore,
        spine: SignedEventLog,
    ) -> None:
        if not isinstance(store, TradeExecutionReceiptDispatchStore):
            raise TypeError(
                "store must be a TradeExecutionReceiptDispatchStore"
            )
        if not isinstance(spine, SignedEventLog):
            raise TypeError("spine must be a SignedEventLog")
        self.store = store
        self.spine = spine

    def prepare(
        self,
        delivery: TradeExecutionReceiptDelivery,
        *,
        order: TradeOrder | dict[str, Any],
        target_url: str,
        now_ms: int | None = None,
    ) -> TradeExecutionReceiptDispatchRecord:
        return self.store.prepare(
            delivery,
            order=order,
            target_url=target_url,
            now_ms=now_ms,
        )

    def failed(
        self,
        receipt_digest: str,
        *,
        error: str,
        now_ms: int | None = None,
    ) -> TradeExecutionReceiptDispatchRecord:
        return self.store.note_failure(
            receipt_digest,
            error=error,
            now_ms=now_ms,
        )

    def renew_expired(
        self,
        delivery: TradeExecutionReceiptDelivery,
        *,
        order: TradeOrder | dict[str, Any],
        target_url: str,
        now_ms: int | None = None,
    ) -> TradeExecutionReceiptDispatchRecord:
        return self.store.renew_expired(
            delivery,
            order=order,
            target_url=target_url,
            now_ms=now_ms,
        )

    def _anchor(
        self,
        acknowledgement: TradeExecutionReceiptAcknowledgedDispatch,
    ) -> tuple[SpineEvent, bool]:
        return self.spine.append_unique(
            EVENT_TRADE_EXECUTION_RECEIPT_ACKNOWLEDGED,
            execution_receipt_acknowledgement_audit_payload(
                acknowledgement
            ),
            unique_payload_fields=("receipt_digest", "delivery_digest"),
            ts_ms=acknowledgement.observed_at_ms,
        )

    def acknowledge(
        self,
        delivery: TradeExecutionReceiptDelivery,
        acknowledgement: TradeExecutionReceiptAcknowledgement,
        *,
        order: TradeOrder | dict[str, Any],
        target_url: str,
        remote_event_id: str,
        observed_at_ms: int | None = None,
    ) -> TradeExecutionReceiptAcknowledgedDispatch:
        retained = self.store.put_acknowledgement(
            delivery,
            acknowledgement,
            order=order,
            target_url=target_url,
            remote_event_id=remote_event_id,
            observed_at_ms=observed_at_ms,
        )
        self._anchor(retained)
        self.store.complete_pending(retained.receipt_digest)
        return retained

    def recover_acknowledgement(
        self,
        receipt_digest: str,
    ) -> TradeExecutionReceiptAcknowledgedDispatch | None:
        acknowledgement = self.store.get_acknowledgement(receipt_digest)
        if acknowledgement is None:
            return None
        self._anchor(acknowledgement)
        self.store.complete_pending(receipt_digest)
        return acknowledgement

    def reconcile(
        self,
        *,
        limit: int = 1_000,
        after: str | None = None,
    ) -> TradeExecutionReceiptDispatchReconciliation:
        acknowledgements, next_cursor = (
            self.store.list_recoverable_acknowledgements(
                limit=limit,
                after=after,
            )
        )
        anchored = 0
        completed = 0
        failed = 0
        for acknowledgement in acknowledgements:
            try:
                _event, created = self._anchor(acknowledgement)
                anchored += int(created)
                completed += int(
                    self.store.complete_pending(
                        acknowledgement.receipt_digest
                    )
                )
            except (OSError, RuntimeError, TypeError, ValueError):
                failed += 1
        return TradeExecutionReceiptDispatchReconciliation(
            scanned=len(acknowledgements),
            anchored=anchored,
            completed=completed,
            failed=failed,
            next_cursor=next_cursor,
            has_more=bool(next_cursor),
        )


__all__ = [
    "DEFAULT_MAX_EXECUTION_DISPATCH_BYTES",
    "DEFAULT_MAX_EXECUTION_RECEIPT_ACKNOWLEDGEMENTS",
    "DEFAULT_MAX_PENDING_EXECUTION_RECEIPTS",
    "EVENT_TRADE_EXECUTION_RECEIPT_ACKNOWLEDGED",
    "EXECUTION_RECEIPT_DISPATCH_PROTOCOL_VERSION",
    "MAX_EXECUTION_DISPATCH_DOCUMENT_BYTES",
    "MAX_EXECUTION_DISPATCH_STATE_BATCH",
    "MAX_SUPERSEDED_EXECUTION_RECEIPT_DELIVERIES",
    "TradeExecutionReceiptAcknowledgedDispatch",
    "TradeExecutionReceiptDispatchBusy",
    "TradeExecutionReceiptDispatchCapacity",
    "TradeExecutionReceiptDispatchCoordinator",
    "TradeExecutionReceiptDispatchError",
    "TradeExecutionReceiptDispatchReconciliation",
    "TradeExecutionReceiptDispatchRecord",
    "TradeExecutionReceiptDispatchStore",
    "execution_receipt_acknowledgement_audit_payload",
]
