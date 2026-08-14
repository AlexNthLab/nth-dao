"""Durable sender outbox for federated Trade Receipt Reviews."""

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
from nth_dao.trade_rules.execution_receipt import (
    TradeExecutionReceipt,
    execution_receipt_digest,
)
from nth_dao.trade_rules.receipt_review_transport import (
    DEFAULT_RECEIPT_REVIEW_DELIVERY_CLOCK_SKEW_SECONDS,
    TradeReceiptReviewAcknowledgement,
    TradeReceiptReviewDelivery,
    trade_receipt_review_acknowledgement_digest,
    trade_receipt_review_delivery_digest,
    verify_trade_receipt_review_acknowledgement,
    verify_trade_receipt_review_delivery,
)
from nth_dao.util.io import InterProcessLock
from nth_dao.util.jsonl_safe import LOCK_TIMEOUT_PATIENT
from nth_dao.util.path_security import path_is_linklike

EVENT_TRADE_RECEIPT_REVIEW_ACKNOWLEDGED = (
    "trade.receipt.review-acknowledged"
)
RECEIPT_REVIEW_DISPATCH_PROTOCOL_VERSION = "1"
DEFAULT_MAX_PENDING_RECEIPT_REVIEWS = 4_096
DEFAULT_MAX_RECEIPT_REVIEW_ACKNOWLEDGEMENTS = 65_536
DEFAULT_MAX_RECEIPT_REVIEW_DISPATCH_BYTES = 2 * 1024 * 1024 * 1024
MAX_RECEIPT_REVIEW_DISPATCH_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_SUPERSEDED_RECEIPT_REVIEW_DELIVERIES = 256

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVENT_ID = re.compile(r"^[0-9a-f]{64}$")
_OBSERVATION_CLOCK_SKEW_MS = int(
    DEFAULT_RECEIPT_REVIEW_DELIVERY_CLOCK_SKEW_SECONDS * 1_000
)


class TradeReceiptReviewDispatchError(RuntimeError):
    """Receipt Review dispatch state is invalid or unavailable."""


class TradeReceiptReviewDispatchBusy(TradeReceiptReviewDispatchError):
    """Another process currently owns the dispatch transaction."""


class TradeReceiptReviewDispatchCapacity(TradeReceiptReviewDispatchError):
    """The bounded Receipt Review dispatch store is full."""


def _raise_sqlite_operational(
    exc: sqlite3.OperationalError,
    *,
    action: str,
) -> None:
    code = getattr(exc, "sqlite_errorcode", None)
    if code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
        raise TradeReceiptReviewDispatchBusy(
            "Receipt Review dispatch store is busy"
        ) from exc
    raise TradeReceiptReviewDispatchError(f"unable to {action}") from exc


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
        raise TradeReceiptReviewDispatchError("target_url is invalid")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise TradeReceiptReviewDispatchError(
            "target_url contains control characters"
        )
    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError as exc:
        raise TradeReceiptReviewDispatchError(
            "target_url is invalid"
        ) from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TradeReceiptReviewDispatchError(
            "target_url must be an HTTP(S) URL"
        )
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise TradeReceiptReviewDispatchError(
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
        raise TradeReceiptReviewDispatchError(f"{label} is invalid")
    return value


def _event_id(value: Any) -> str:
    if not isinstance(value, str) or _EVENT_ID.fullmatch(value) is None:
        raise TradeReceiptReviewDispatchError("remote_event_id is invalid")
    return value


def _signed_timestamp_ms(value: Any) -> int:
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise TradeReceiptReviewDispatchError(
            "signed acknowledgement timestamp is invalid"
        ) from exc
    return int(moment.timestamp() * 1_000)


def _bounded_document(raw: bytes, *, label: str) -> bytes:
    if not isinstance(raw, bytes) or not raw:
        raise TradeReceiptReviewDispatchError(f"{label} is empty")
    if len(raw) > MAX_RECEIPT_REVIEW_DISPATCH_DOCUMENT_BYTES:
        raise TradeReceiptReviewDispatchCapacity(f"{label} is too large")
    return raw


def _is_linklike(path: Path) -> bool:
    return path_is_linklike(path)


@dataclass(frozen=True)
class TradeReceiptReviewDispatchRecord:
    review_digest: str
    receipt_digest: str
    order_digest: str
    target_url: str
    delivery: TradeReceiptReviewDelivery
    receipt: TradeExecutionReceipt
    order: TradeOrder
    attempts: int
    last_error: str
    created_at_ms: int
    updated_at_ms: int
    acknowledged: bool = False
    generation: int = 1
    superseded_delivery_digests: tuple[str, ...] = ()


@dataclass(frozen=True)
class TradeReceiptReviewAcknowledgedDispatch:
    review_digest: str
    receipt_digest: str
    order_digest: str
    target_url: str
    delivery: TradeReceiptReviewDelivery
    receipt: TradeExecutionReceipt
    order: TradeOrder
    acknowledgement: TradeReceiptReviewAcknowledgement
    remote_event_id: str
    observed_at_ms: int
    generation: int = 1
    superseded_delivery_digests: tuple[str, ...] = ()

    @property
    def delivery_digest(self) -> str:
        return trade_receipt_review_delivery_digest(
            self.delivery,
            receipt=self.receipt,
            order=self.order,
        )

    @property
    def acknowledgement_digest(self) -> str:
        return trade_receipt_review_acknowledgement_digest(
            self.acknowledgement
        )


@dataclass(frozen=True)
class TradeReceiptReviewDispatchReconciliation:
    scanned: int
    anchored: int
    completed: int
    failed: int
    next_cursor: str
    has_more: bool


class TradeReceiptReviewDispatchStore:
    """SQLite-backed process-safe pending and ACK retention."""

    def __init__(
        self,
        root: str | Path,
        *,
        max_pending: int = DEFAULT_MAX_PENDING_RECEIPT_REVIEWS,
        max_acknowledgements: int = (
            DEFAULT_MAX_RECEIPT_REVIEW_ACKNOWLEDGEMENTS
        ),
        max_bytes: int = DEFAULT_MAX_RECEIPT_REVIEW_DISPATCH_BYTES,
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
        self.root = self.workspace_root / "trade" / "review_dispatch_v1"
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
            raise TradeReceiptReviewDispatchBusy(
                "Receipt Review dispatch initialization is busy"
            ) from exc

    def _assert_storage_path(self) -> None:
        current = self.workspace_root
        for part in ("trade", "review_dispatch_v1"):
            if _is_linklike(current):
                raise TradeReceiptReviewDispatchError(
                    "dispatch store must not contain links or junctions"
                )
            current = current / part
        if _is_linklike(current) or _is_linklike(self.path):
            raise TradeReceiptReviewDispatchError(
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
                        review_digest TEXT PRIMARY KEY,
                        receipt_digest TEXT NOT NULL,
                        order_digest TEXT NOT NULL,
                        target_url TEXT NOT NULL,
                        delivery_bytes BLOB NOT NULL,
                        receipt_bytes BLOB NOT NULL,
                        order_bytes BLOB NOT NULL,
                        attempts INTEGER NOT NULL,
                        last_error TEXT NOT NULL,
                        created_at_ms INTEGER NOT NULL,
                        updated_at_ms INTEGER NOT NULL,
                        generation INTEGER NOT NULL,
                        superseded_delivery_digests TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS acknowledgements (
                        review_digest TEXT PRIMARY KEY,
                        receipt_digest TEXT NOT NULL,
                        order_digest TEXT NOT NULL,
                        target_url TEXT NOT NULL,
                        delivery_bytes BLOB NOT NULL,
                        receipt_bytes BLOB NOT NULL,
                        order_bytes BLOB NOT NULL,
                        acknowledgement_bytes BLOB NOT NULL,
                        remote_event_id TEXT NOT NULL,
                        observed_at_ms INTEGER NOT NULL,
                        generation INTEGER NOT NULL,
                        superseded_delivery_digests TEXT NOT NULL
                    );
                    """
                )
        except sqlite3.Error as exc:
            raise TradeReceiptReviewDispatchError(
                "unable to initialize Receipt Review dispatch store"
            ) from exc

    @staticmethod
    def _decode_artifacts(
        row: sqlite3.Row,
    ) -> tuple[TradeOrder, TradeExecutionReceipt, TradeReceiptReviewDelivery]:
        try:
            order = TradeOrder.from_json(
                _bounded_document(row["order_bytes"], label="stored Order")
            )
            receipt = TradeExecutionReceipt.from_json(
                _bounded_document(
                    row["receipt_bytes"],
                    label="stored Receipt",
                ),
                order=order,
            )
            delivery = TradeReceiptReviewDelivery.from_json(
                _bounded_document(
                    row["delivery_bytes"],
                    label="stored delivery",
                ),
                receipt=receipt,
                order=order,
            )
        except (TypeError, ValueError) as exc:
            raise TradeReceiptReviewDispatchError(
                "stored signed dispatch artifacts are invalid"
            ) from exc
        return order, receipt, delivery

    @staticmethod
    def _decode_history(
        row: sqlite3.Row,
        delivery: TradeReceiptReviewDelivery,
        receipt: TradeExecutionReceipt,
        order: TradeOrder,
    ) -> tuple[int, tuple[str, ...]]:
        try:
            history = json.loads(row["superseded_delivery_digests"])
        except (json.JSONDecodeError, TypeError) as exc:
            raise TradeReceiptReviewDispatchError(
                "dispatch generation history is invalid"
            ) from exc
        generation = row["generation"]
        current = trade_receipt_review_delivery_digest(
            delivery,
            receipt=receipt,
            order=order,
        )
        if (
            isinstance(generation, bool)
            or not isinstance(generation, int)
            or not 1 <= generation <= MAX_SAFE_INTEGER
            or not isinstance(history, list)
            or len(history) > MAX_SUPERSEDED_RECEIPT_REVIEW_DELIVERIES
            or any(
                not isinstance(item, str) or _DIGEST.fullmatch(item) is None
                for item in history
            )
            or len(set(history)) != len(history)
            or generation != len(history) + 1
            or current in history
        ):
            raise TradeReceiptReviewDispatchError(
                "dispatch generation history is invalid"
            )
        return generation, tuple(history)

    @classmethod
    def _decode_pending(
        cls,
        row: sqlite3.Row,
    ) -> TradeReceiptReviewDispatchRecord:
        order, receipt, delivery = cls._decode_artifacts(row)
        document = delivery.to_dict()
        review_digest = _digest(row["review_digest"], label="review_digest")
        receipt_digest = _digest(
            row["receipt_digest"],
            label="receipt_digest",
        )
        order_digest = _digest(row["order_digest"], label="order_digest")
        if (
            document["review_digest"] != review_digest
            or document["receipt_digest"] != receipt_digest
            or document["order_digest"] != order_digest
            or execution_receipt_digest(receipt, order=order)
            != receipt_digest
            or trade_order_digest(order) != order_digest
        ):
            raise TradeReceiptReviewDispatchError(
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
            raise TradeReceiptReviewDispatchError(
                "pending counters or timestamps are invalid"
            )
        last_error = row["last_error"]
        if not isinstance(last_error, str) or len(last_error) > 500:
            raise TradeReceiptReviewDispatchError(
                "pending last_error is invalid"
            )
        generation, history = cls._decode_history(
            row,
            delivery,
            receipt,
            order,
        )
        return TradeReceiptReviewDispatchRecord(
            review_digest=review_digest,
            receipt_digest=receipt_digest,
            order_digest=order_digest,
            target_url=_normalize_target_url(row["target_url"]),
            delivery=delivery,
            receipt=receipt,
            order=order,
            attempts=attempts,
            last_error=last_error,
            created_at_ms=created,
            updated_at_ms=updated,
            generation=generation,
            superseded_delivery_digests=history,
        )

    @classmethod
    def _decode_acknowledgement(
        cls,
        row: sqlite3.Row,
    ) -> TradeReceiptReviewAcknowledgedDispatch:
        order, receipt, delivery = cls._decode_artifacts(row)
        try:
            acknowledgement = TradeReceiptReviewAcknowledgement.from_json(
                _bounded_document(
                    row["acknowledgement_bytes"],
                    label="stored acknowledgement",
                )
            )
        except (TypeError, ValueError) as exc:
            raise TradeReceiptReviewDispatchError(
                "stored acknowledgement is invalid"
            ) from exc
        review_digest = _digest(row["review_digest"], label="review_digest")
        receipt_digest = _digest(
            row["receipt_digest"],
            label="receipt_digest",
        )
        order_digest = _digest(row["order_digest"], label="order_digest")
        event_id = _event_id(row["remote_event_id"])
        observed = row["observed_at_ms"]
        if (
            delivery.to_dict()["review_digest"] != review_digest
            or delivery.to_dict()["receipt_digest"] != receipt_digest
            or delivery.to_dict()["order_digest"] != order_digest
            or isinstance(observed, bool)
            or not isinstance(observed, int)
            or not 0 < observed <= MAX_SAFE_INTEGER
        ):
            raise TradeReceiptReviewDispatchError(
                "acknowledgement binding or observation is invalid"
            )
        ok, reason = verify_trade_receipt_review_acknowledgement(
            acknowledgement,
            delivery=delivery,
            receipt=receipt,
            order=order,
            receiver_did=delivery.to_dict()["recipient_did"],
            audit_event_id=event_id,
        )
        if not ok:
            raise TradeReceiptReviewDispatchError(reason)
        if observed + _OBSERVATION_CLOCK_SKEW_MS < _signed_timestamp_ms(
            acknowledgement.to_dict()["received_at"]
        ):
            raise TradeReceiptReviewDispatchError(
                "acknowledgement observation predates signed receipt"
            )
        generation, history = cls._decode_history(
            row,
            delivery,
            receipt,
            order,
        )
        return TradeReceiptReviewAcknowledgedDispatch(
            review_digest=review_digest,
            receipt_digest=receipt_digest,
            order_digest=order_digest,
            target_url=_normalize_target_url(row["target_url"]),
            delivery=delivery,
            receipt=receipt,
            order=order,
            acknowledgement=acknowledgement,
            remote_event_id=event_id,
            observed_at_ms=observed,
            generation=generation,
            superseded_delivery_digests=history,
        )

    @staticmethod
    def _same_scope(
        record: TradeReceiptReviewDispatchRecord,
        *,
        delivery: TradeReceiptReviewDelivery,
        receipt: TradeExecutionReceipt,
        order: TradeOrder,
        target_url: str,
    ) -> bool:
        current = record.delivery.to_dict()
        candidate = delivery.to_dict()
        return (
            record.target_url == target_url
            and record.order.canonical_bytes == order.canonical_bytes
            and record.receipt.canonical_bytes == receipt.canonical_bytes
            and record.delivery.review.canonical_bytes
            == delivery.review.canonical_bytes
            and current["sender_did"] == candidate["sender_did"]
            and current["recipient_did"] == candidate["recipient_did"]
        )

    @staticmethod
    def _usage(connection: sqlite3.Connection) -> tuple[int, int, int]:
        pending = connection.execute(
            "SELECT COUNT(*) AS count FROM pending"
        ).fetchone()["count"]
        acknowledgements = connection.execute(
            "SELECT COUNT(*) AS count FROM acknowledgements"
        ).fetchone()["count"]
        total = connection.execute(
            """
            SELECT COALESCE(SUM(size), 0) AS total FROM (
                SELECT length(delivery_bytes) + length(receipt_bytes)
                     + length(order_bytes)
                     + length(superseded_delivery_digests) AS size
                FROM pending
                UNION ALL
                SELECT length(delivery_bytes) + length(receipt_bytes)
                     + length(order_bytes) + length(acknowledgement_bytes)
                     + length(superseded_delivery_digests) AS size
                FROM acknowledgements
            )
            """
        ).fetchone()["total"]
        return int(pending), int(acknowledgements), int(total)

    def prepare(
        self,
        delivery: TradeReceiptReviewDelivery,
        *,
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        target_url: str,
        now_ms: int | None = None,
    ) -> TradeReceiptReviewDispatchRecord:
        order_value = (
            TradeOrder.from_json(order.canonical_bytes)
            if isinstance(order, TradeOrder)
            else TradeOrder.from_dict(order)
        )
        receipt_value = (
            TradeExecutionReceipt.from_json(
                receipt.canonical_bytes,
                order=order_value,
            )
            if isinstance(receipt, TradeExecutionReceipt)
            else TradeExecutionReceipt.from_dict(receipt, order=order_value)
        )
        delivery_value = TradeReceiptReviewDelivery.from_json(
            delivery.canonical_bytes,
            receipt=receipt_value,
            order=order_value,
        )
        document = delivery_value.to_dict()
        review_digest = document["review_digest"]
        target = _normalize_target_url(target_url)
        moment = _now_ms(now_ms)
        payloads = (
            _bounded_document(delivery_value.canonical_bytes, label="delivery"),
            _bounded_document(receipt_value.canonical_bytes, label="Receipt"),
            _bounded_document(order_value.canonical_bytes, label="Order"),
        )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                ack = connection.execute(
                    "SELECT * FROM acknowledgements WHERE review_digest = ?",
                    (review_digest,),
                ).fetchone()
                if ack is not None:
                    retained_ack = self._decode_acknowledgement(ack)
                    if (
                        retained_ack.target_url != target
                        or retained_ack.delivery.review.canonical_bytes
                        != delivery_value.review.canonical_bytes
                        or retained_ack.receipt.canonical_bytes
                        != receipt_value.canonical_bytes
                        or retained_ack.order.canonical_bytes
                        != order_value.canonical_bytes
                    ):
                        raise TradeReceiptReviewDispatchError(
                            "dispatch conflicts with acknowledged Review scope"
                        )
                    connection.commit()
                    return TradeReceiptReviewDispatchRecord(
                        review_digest=review_digest,
                        receipt_digest=document["receipt_digest"],
                        order_digest=document["order_digest"],
                        target_url=target,
                        delivery=retained_ack.delivery,
                        receipt=retained_ack.receipt,
                        order=retained_ack.order,
                        attempts=0,
                        last_error="",
                        created_at_ms=retained_ack.observed_at_ms,
                        updated_at_ms=retained_ack.observed_at_ms,
                        acknowledged=True,
                        generation=retained_ack.generation,
                        superseded_delivery_digests=(
                            retained_ack.superseded_delivery_digests
                        ),
                    )
                row = connection.execute(
                    "SELECT * FROM pending WHERE review_digest = ?",
                    (review_digest,),
                ).fetchone()
                if row is not None:
                    retained = self._decode_pending(row)
                    if not self._same_scope(
                        retained,
                        delivery=delivery_value,
                        receipt=receipt_value,
                        order=order_value,
                        target_url=target,
                    ):
                        raise TradeReceiptReviewDispatchError(
                            "pending dispatch conflicts with Review scope"
                        )
                    connection.commit()
                    return retained
                pending_count, _ack_count, total = self._usage(connection)
                if pending_count + 1 > self.max_pending:
                    raise TradeReceiptReviewDispatchCapacity(
                        "max_pending exceeded"
                    )
                history = "[]"
                if total + sum(map(len, payloads)) + len(history) > self.max_bytes:
                    raise TradeReceiptReviewDispatchCapacity(
                        "max_bytes exceeded"
                    )
                connection.execute(
                    """
                    INSERT INTO pending (
                        review_digest, receipt_digest, order_digest,
                        target_url, delivery_bytes, receipt_bytes,
                        order_bytes, attempts, last_error, created_at_ms,
                        updated_at_ms, generation,
                        superseded_delivery_digests
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, '', ?, ?, 1, ?)
                    """,
                    (
                        review_digest,
                        document["receipt_digest"],
                        document["order_digest"],
                        target,
                        *payloads,
                        moment,
                        moment,
                        history,
                    ),
                )
                connection.commit()
                return TradeReceiptReviewDispatchRecord(
                    review_digest=review_digest,
                    receipt_digest=document["receipt_digest"],
                    order_digest=document["order_digest"],
                    target_url=target,
                    delivery=delivery_value,
                    receipt=receipt_value,
                    order=order_value,
                    attempts=0,
                    last_error="",
                    created_at_ms=moment,
                    updated_at_ms=moment,
                )
        except sqlite3.OperationalError as exc:
            _raise_sqlite_operational(exc, action="prepare dispatch")
        except sqlite3.Error as exc:
            raise TradeReceiptReviewDispatchError(
                "unable to prepare Receipt Review dispatch"
            ) from exc

    def renew_expired(
        self,
        delivery: TradeReceiptReviewDelivery,
        *,
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        target_url: str,
        now_ms: int | None = None,
    ) -> TradeReceiptReviewDispatchRecord:
        order_value = (
            TradeOrder.from_json(order.canonical_bytes)
            if isinstance(order, TradeOrder)
            else TradeOrder.from_dict(order)
        )
        receipt_value = (
            TradeExecutionReceipt.from_json(
                receipt.canonical_bytes,
                order=order_value,
            )
            if isinstance(receipt, TradeExecutionReceipt)
            else TradeExecutionReceipt.from_dict(receipt, order=order_value)
        )
        replacement = TradeReceiptReviewDelivery.from_json(
            delivery.canonical_bytes,
            receipt=receipt_value,
            order=order_value,
        )
        document = replacement.to_dict()
        target = _normalize_target_url(target_url)
        moment = _now_ms(now_ms)
        at = datetime.fromtimestamp(moment / 1_000, tz=timezone.utc)
        ok, reason = verify_trade_receipt_review_delivery(
            replacement,
            receipt=receipt_value,
            order=order_value,
            recipient_did=document["recipient_did"],
            at=at,
        )
        if not ok:
            raise TradeReceiptReviewDispatchError(
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
                    "SELECT 1 FROM acknowledgements WHERE review_digest = ?",
                    (document["review_digest"],),
                ).fetchone() is not None:
                    raise TradeReceiptReviewDispatchError(
                        "acknowledged dispatch cannot be renewed"
                    )
                row = connection.execute(
                    "SELECT * FROM pending WHERE review_digest = ?",
                    (document["review_digest"],),
                ).fetchone()
                if row is None:
                    raise TradeReceiptReviewDispatchError(
                        "pending dispatch is missing"
                    )
                current = self._decode_pending(row)
                if not self._same_scope(
                    current,
                    delivery=replacement,
                    receipt=receipt_value,
                    order=order_value,
                    target_url=target,
                ):
                    raise TradeReceiptReviewDispatchError(
                        "replacement does not match pending Review scope"
                    )
                old_ok, old_reason = verify_trade_receipt_review_delivery(
                    current.delivery,
                    receipt=current.receipt,
                    order=current.order,
                    recipient_did=(
                        current.delivery.to_dict()["recipient_did"]
                    ),
                    at=at,
                )
                if old_ok or "expired" not in old_reason:
                    raise TradeReceiptReviewDispatchError(
                        "pending delivery is not expired"
                    )
                old_digest = trade_receipt_review_delivery_digest(
                    current.delivery,
                    receipt=current.receipt,
                    order=current.order,
                )
                new_digest = trade_receipt_review_delivery_digest(
                    replacement,
                    receipt=receipt_value,
                    order=order_value,
                )
                if old_digest == new_digest:
                    raise TradeReceiptReviewDispatchError(
                        "replacement delivery must use fresh signed bytes"
                    )
                history = (*current.superseded_delivery_digests, old_digest)
                if len(history) > MAX_SUPERSEDED_RECEIPT_REVIEW_DELIVERIES:
                    raise TradeReceiptReviewDispatchCapacity(
                        "delivery generation history is full"
                    )
                history_json = json.dumps(list(history), separators=(",", ":"))
                _pending_count, _ack_count, total = self._usage(connection)
                projected = (
                    total
                    - len(row["delivery_bytes"])
                    - len(row["superseded_delivery_digests"].encode("utf-8"))
                    + len(replacement_bytes)
                    + len(history_json.encode("ascii"))
                )
                if projected > self.max_bytes:
                    raise TradeReceiptReviewDispatchCapacity(
                        "max_bytes exceeded"
                    )
                updated = max(moment, current.updated_at_ms)
                connection.execute(
                    """
                    UPDATE pending
                    SET delivery_bytes = ?, attempts = 0, last_error = '',
                        updated_at_ms = ?, generation = ?,
                        superseded_delivery_digests = ?
                    WHERE review_digest = ?
                    """,
                    (
                        replacement_bytes,
                        updated,
                        current.generation + 1,
                        history_json,
                        current.review_digest,
                    ),
                )
                connection.commit()
                return TradeReceiptReviewDispatchRecord(
                    review_digest=current.review_digest,
                    receipt_digest=current.receipt_digest,
                    order_digest=current.order_digest,
                    target_url=target,
                    delivery=replacement,
                    receipt=receipt_value,
                    order=order_value,
                    attempts=0,
                    last_error="",
                    created_at_ms=current.created_at_ms,
                    updated_at_ms=updated,
                    generation=current.generation + 1,
                    superseded_delivery_digests=history,
                )
        except sqlite3.OperationalError as exc:
            _raise_sqlite_operational(exc, action="renew dispatch")
        except sqlite3.Error as exc:
            raise TradeReceiptReviewDispatchError(
                "unable to renew Receipt Review dispatch"
            ) from exc

    def note_failure(
        self,
        review_digest: str,
        *,
        error: str,
        now_ms: int | None = None,
    ) -> TradeReceiptReviewDispatchRecord:
        digest = _digest(review_digest, label="review_digest")
        moment = _now_ms(now_ms)
        message = str(error).replace("\r", " ").replace("\n", " ")[:500]
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM pending WHERE review_digest = ?",
                    (digest,),
                ).fetchone()
                if row is None:
                    raise TradeReceiptReviewDispatchError(
                        "pending dispatch is missing"
                    )
                record = self._decode_pending(row)
                if record.attempts >= MAX_SAFE_INTEGER:
                    raise TradeReceiptReviewDispatchCapacity(
                        "pending attempt counter is exhausted"
                    )
                updated = max(moment, record.updated_at_ms)
                connection.execute(
                    """
                    UPDATE pending
                    SET attempts = ?, last_error = ?, updated_at_ms = ?
                    WHERE review_digest = ?
                    """,
                    (record.attempts + 1, message, updated, digest),
                )
                connection.commit()
                return TradeReceiptReviewDispatchRecord(
                    **{
                        **record.__dict__,
                        "attempts": record.attempts + 1,
                        "last_error": message,
                        "updated_at_ms": updated,
                    }
                )
        except sqlite3.OperationalError as exc:
            _raise_sqlite_operational(exc, action="record dispatch failure")
        except sqlite3.Error as exc:
            raise TradeReceiptReviewDispatchError(
                "unable to record dispatch failure"
            ) from exc

    def put_acknowledgement(
        self,
        delivery: TradeReceiptReviewDelivery,
        acknowledgement: TradeReceiptReviewAcknowledgement,
        *,
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        target_url: str,
        remote_event_id: str,
        observed_at_ms: int | None = None,
    ) -> TradeReceiptReviewAcknowledgedDispatch:
        order_value = (
            TradeOrder.from_json(order.canonical_bytes)
            if isinstance(order, TradeOrder)
            else TradeOrder.from_dict(order)
        )
        receipt_value = (
            TradeExecutionReceipt.from_json(
                receipt.canonical_bytes,
                order=order_value,
            )
            if isinstance(receipt, TradeExecutionReceipt)
            else TradeExecutionReceipt.from_dict(receipt, order=order_value)
        )
        delivery_value = TradeReceiptReviewDelivery.from_json(
            delivery.canonical_bytes,
            receipt=receipt_value,
            order=order_value,
        )
        ack_value = TradeReceiptReviewAcknowledgement.from_json(
            acknowledgement.canonical_bytes
        )
        document = delivery_value.to_dict()
        target = _normalize_target_url(target_url)
        event_id = _event_id(remote_event_id)
        observed = _now_ms(observed_at_ms)
        ok, reason = verify_trade_receipt_review_acknowledgement(
            ack_value,
            delivery=delivery_value,
            receipt=receipt_value,
            order=order_value,
            receiver_did=document["recipient_did"],
            audit_event_id=event_id,
        )
        if not ok:
            raise TradeReceiptReviewDispatchError(reason)
        if observed + _OBSERVATION_CLOCK_SKEW_MS < _signed_timestamp_ms(
            ack_value.to_dict()["received_at"]
        ):
            raise TradeReceiptReviewDispatchError(
                "acknowledgement observation predates signed receipt"
            )
        payloads = (
            _bounded_document(delivery_value.canonical_bytes, label="delivery"),
            _bounded_document(receipt_value.canonical_bytes, label="Receipt"),
            _bounded_document(order_value.canonical_bytes, label="Order"),
            _bounded_document(
                ack_value.canonical_bytes,
                label="acknowledgement",
            ),
        )
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT * FROM acknowledgements WHERE review_digest = ?",
                    (document["review_digest"],),
                ).fetchone()
                if existing is not None:
                    retained = self._decode_acknowledgement(existing)
                    if (
                        retained.target_url != target
                        or retained.delivery.canonical_bytes != payloads[0]
                        or retained.receipt.canonical_bytes != payloads[1]
                        or retained.order.canonical_bytes != payloads[2]
                        or retained.acknowledgement.canonical_bytes != payloads[3]
                        or retained.remote_event_id != event_id
                    ):
                        raise TradeReceiptReviewDispatchError(
                            "acknowledgement conflicts with retained state"
                        )
                    connection.commit()
                    return retained
                pending = connection.execute(
                    "SELECT * FROM pending WHERE review_digest = ?",
                    (document["review_digest"],),
                ).fetchone()
                if pending is None:
                    raise TradeReceiptReviewDispatchError(
                        "acknowledgement has no pending dispatch"
                    )
                pending_record = self._decode_pending(pending)
                if (
                    pending_record.target_url != target
                    or pending_record.delivery.canonical_bytes != payloads[0]
                    or pending_record.receipt.canonical_bytes != payloads[1]
                    or pending_record.order.canonical_bytes != payloads[2]
                ):
                    raise TradeReceiptReviewDispatchError(
                        "acknowledgement does not match current pending delivery"
                    )
                _pending_count, ack_count, total = self._usage(connection)
                if ack_count + 1 > self.max_acknowledgements:
                    raise TradeReceiptReviewDispatchCapacity(
                        "max_acknowledgements exceeded"
                    )
                history_json = json.dumps(
                    list(pending_record.superseded_delivery_digests),
                    separators=(",", ":"),
                )
                if (
                    total
                    + sum(map(len, payloads))
                    + len(history_json.encode("ascii"))
                    > self.max_bytes
                ):
                    raise TradeReceiptReviewDispatchCapacity(
                        "max_bytes exceeded"
                    )
                connection.execute(
                    """
                    INSERT INTO acknowledgements (
                        review_digest, receipt_digest, order_digest,
                        target_url, delivery_bytes, receipt_bytes,
                        order_bytes, acknowledgement_bytes,
                        remote_event_id, observed_at_ms, generation,
                        superseded_delivery_digests
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        document["review_digest"],
                        document["receipt_digest"],
                        document["order_digest"],
                        target,
                        *payloads,
                        event_id,
                        observed,
                        pending_record.generation,
                        history_json,
                    ),
                )
                connection.commit()
                return TradeReceiptReviewAcknowledgedDispatch(
                    review_digest=document["review_digest"],
                    receipt_digest=document["receipt_digest"],
                    order_digest=document["order_digest"],
                    target_url=target,
                    delivery=delivery_value,
                    receipt=receipt_value,
                    order=order_value,
                    acknowledgement=ack_value,
                    remote_event_id=event_id,
                    observed_at_ms=observed,
                    generation=pending_record.generation,
                    superseded_delivery_digests=(
                        pending_record.superseded_delivery_digests
                    ),
                )
        except sqlite3.OperationalError as exc:
            _raise_sqlite_operational(exc, action="retain acknowledgement")
        except sqlite3.Error as exc:
            raise TradeReceiptReviewDispatchError(
                "unable to retain acknowledgement"
            ) from exc

    def get_pending(
        self,
        review_digest: str,
    ) -> TradeReceiptReviewDispatchRecord | None:
        digest = _digest(review_digest, label="review_digest")
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM pending WHERE review_digest = ?",
                    (digest,),
                ).fetchone()
            return None if row is None else self._decode_pending(row)
        except sqlite3.OperationalError as exc:
            _raise_sqlite_operational(exc, action="read pending dispatch")
        except sqlite3.Error as exc:
            raise TradeReceiptReviewDispatchError(
                "unable to read pending dispatch"
            ) from exc

    def get_acknowledgement(
        self,
        review_digest: str,
    ) -> TradeReceiptReviewAcknowledgedDispatch | None:
        digest = _digest(review_digest, label="review_digest")
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM acknowledgements WHERE review_digest = ?",
                    (digest,),
                ).fetchone()
            return None if row is None else self._decode_acknowledgement(row)
        except sqlite3.OperationalError as exc:
            _raise_sqlite_operational(exc, action="read acknowledgement")
        except sqlite3.Error as exc:
            raise TradeReceiptReviewDispatchError(
                "unable to read acknowledgement"
            ) from exc

    def get_state(
        self,
        review_digest: str,
    ) -> tuple[
        TradeReceiptReviewDispatchRecord | None,
        TradeReceiptReviewAcknowledgedDispatch | None,
    ]:
        """Read pending and ACK state from one consistent transaction."""

        digest = _digest(review_digest, label="review_digest")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN")
                pending = connection.execute(
                    "SELECT * FROM pending WHERE review_digest = ?",
                    (digest,),
                ).fetchone()
                acknowledgement = connection.execute(
                    "SELECT * FROM acknowledgements WHERE review_digest = ?",
                    (digest,),
                ).fetchone()
                connection.commit()
            return (
                None if pending is None else self._decode_pending(pending),
                (
                    None
                    if acknowledgement is None
                    else self._decode_acknowledgement(acknowledgement)
                ),
            )
        except sqlite3.OperationalError as exc:
            _raise_sqlite_operational(exc, action="read dispatch state")
        except sqlite3.Error as exc:
            raise TradeReceiptReviewDispatchError(
                "unable to read dispatch state"
            ) from exc

    def list_recoverable_acknowledgements(
        self,
        *,
        limit: int = 1_000,
        after: str | None = None,
    ) -> tuple[tuple[TradeReceiptReviewAcknowledgedDispatch, ...], str]:
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
                    INNER JOIN pending USING (review_digest)
                    WHERE acknowledgements.review_digest > ?
                    ORDER BY acknowledgements.review_digest ASC
                    LIMIT ?
                    """,
                    (cursor, limit + 1),
                ).fetchall()
            page = rows[:limit]
            next_cursor = (
                page[-1]["review_digest"]
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
            raise TradeReceiptReviewDispatchError(
                "unable to list recoverable acknowledgements"
            ) from exc

    def complete_pending(self, review_digest: str) -> bool:
        digest = _digest(review_digest, label="review_digest")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                pending = connection.execute(
                    "SELECT * FROM pending WHERE review_digest = ?",
                    (digest,),
                ).fetchone()
                ack = connection.execute(
                    "SELECT * FROM acknowledgements WHERE review_digest = ?",
                    (digest,),
                ).fetchone()
                if ack is None:
                    raise TradeReceiptReviewDispatchError(
                        "dispatch cannot complete without an acknowledgement"
                    )
                if pending is None:
                    connection.commit()
                    return False
                pending_record = self._decode_pending(pending)
                retained = self._decode_acknowledgement(ack)
                if (
                    pending_record.target_url != retained.target_url
                    or pending_record.delivery.canonical_bytes
                    != retained.delivery.canonical_bytes
                    or pending_record.receipt.canonical_bytes
                    != retained.receipt.canonical_bytes
                    or pending_record.order.canonical_bytes
                    != retained.order.canonical_bytes
                ):
                    raise TradeReceiptReviewDispatchError(
                        "pending dispatch conflicts with acknowledgement"
                    )
                connection.execute(
                    "DELETE FROM pending WHERE review_digest = ?",
                    (digest,),
                )
                connection.commit()
                return True
        except sqlite3.OperationalError as exc:
            _raise_sqlite_operational(exc, action="complete pending dispatch")
        except sqlite3.Error as exc:
            raise TradeReceiptReviewDispatchError(
                "unable to complete pending dispatch"
            ) from exc


def receipt_review_acknowledgement_audit_payload(
    acknowledgement: TradeReceiptReviewAcknowledgedDispatch,
) -> dict[str, Any]:
    document = acknowledgement.acknowledgement.to_dict()
    return {
        "protocol_version": RECEIPT_REVIEW_DISPATCH_PROTOCOL_VERSION,
        "order_digest": acknowledgement.order_digest,
        "receipt_digest": acknowledgement.receipt_digest,
        "review_digest": acknowledgement.review_digest,
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


class TradeReceiptReviewDispatchCoordinator:
    """Retain ACK, anchor it locally, then retire durable pending work."""

    def __init__(
        self,
        store: TradeReceiptReviewDispatchStore,
        spine: SignedEventLog,
    ) -> None:
        if not isinstance(store, TradeReceiptReviewDispatchStore):
            raise TypeError(
                "store must be a TradeReceiptReviewDispatchStore"
            )
        if not isinstance(spine, SignedEventLog):
            raise TypeError("spine must be a SignedEventLog")
        self.store = store
        self.spine = spine

    def prepare(
        self,
        delivery: TradeReceiptReviewDelivery,
        *,
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        target_url: str,
        now_ms: int | None = None,
    ) -> TradeReceiptReviewDispatchRecord:
        return self.store.prepare(
            delivery,
            receipt=receipt,
            order=order,
            target_url=target_url,
            now_ms=now_ms,
        )

    def failed(
        self,
        review_digest: str,
        *,
        error: str,
        now_ms: int | None = None,
    ) -> TradeReceiptReviewDispatchRecord:
        return self.store.note_failure(
            review_digest,
            error=error,
            now_ms=now_ms,
        )

    def renew_expired(
        self,
        delivery: TradeReceiptReviewDelivery,
        *,
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        target_url: str,
        now_ms: int | None = None,
    ) -> TradeReceiptReviewDispatchRecord:
        return self.store.renew_expired(
            delivery,
            receipt=receipt,
            order=order,
            target_url=target_url,
            now_ms=now_ms,
        )

    def _anchor(
        self,
        acknowledgement: TradeReceiptReviewAcknowledgedDispatch,
    ) -> tuple[SpineEvent, bool]:
        return self.spine.append_unique(
            EVENT_TRADE_RECEIPT_REVIEW_ACKNOWLEDGED,
            receipt_review_acknowledgement_audit_payload(acknowledgement),
            unique_payload_fields=("review_digest", "delivery_digest"),
            ts_ms=acknowledgement.observed_at_ms,
        )

    def acknowledge(
        self,
        delivery: TradeReceiptReviewDelivery,
        acknowledgement: TradeReceiptReviewAcknowledgement,
        *,
        receipt: TradeExecutionReceipt | dict[str, Any],
        order: TradeOrder | dict[str, Any],
        target_url: str,
        remote_event_id: str,
        observed_at_ms: int | None = None,
    ) -> TradeReceiptReviewAcknowledgedDispatch:
        retained = self.store.put_acknowledgement(
            delivery,
            acknowledgement,
            receipt=receipt,
            order=order,
            target_url=target_url,
            remote_event_id=remote_event_id,
            observed_at_ms=observed_at_ms,
        )
        self._anchor(retained)
        self.store.complete_pending(retained.review_digest)
        return retained

    def recover_acknowledgement(
        self,
        review_digest: str,
    ) -> TradeReceiptReviewAcknowledgedDispatch | None:
        acknowledgement = self.store.get_acknowledgement(review_digest)
        if acknowledgement is None:
            return None
        self._anchor(acknowledgement)
        self.store.complete_pending(review_digest)
        return acknowledgement

    def reconcile(
        self,
        *,
        limit: int = 1_000,
        after: str | None = None,
    ) -> TradeReceiptReviewDispatchReconciliation:
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
                        acknowledgement.review_digest
                    )
                )
            except (OSError, RuntimeError, TypeError, ValueError):
                failed += 1
        return TradeReceiptReviewDispatchReconciliation(
            scanned=len(acknowledgements),
            anchored=anchored,
            completed=completed,
            failed=failed,
            next_cursor=next_cursor,
            has_more=bool(next_cursor),
        )


__all__ = [
    "DEFAULT_MAX_PENDING_RECEIPT_REVIEWS",
    "DEFAULT_MAX_RECEIPT_REVIEW_ACKNOWLEDGEMENTS",
    "DEFAULT_MAX_RECEIPT_REVIEW_DISPATCH_BYTES",
    "EVENT_TRADE_RECEIPT_REVIEW_ACKNOWLEDGED",
    "MAX_RECEIPT_REVIEW_DISPATCH_DOCUMENT_BYTES",
    "MAX_SUPERSEDED_RECEIPT_REVIEW_DELIVERIES",
    "RECEIPT_REVIEW_DISPATCH_PROTOCOL_VERSION",
    "TradeReceiptReviewAcknowledgedDispatch",
    "TradeReceiptReviewDispatchBusy",
    "TradeReceiptReviewDispatchCapacity",
    "TradeReceiptReviewDispatchCoordinator",
    "TradeReceiptReviewDispatchError",
    "TradeReceiptReviewDispatchReconciliation",
    "TradeReceiptReviewDispatchRecord",
    "TradeReceiptReviewDispatchStore",
    "receipt_review_acknowledgement_audit_payload",
]
