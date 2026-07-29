"""Recoverable write-ahead audit anchoring for accepted Trade Orders."""

from __future__ import annotations

import json
import math
import os
import re
import stat
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import is_did_key
from nth_dao.spine import SignedEventLog, SpineEvent
from nth_dao.trade_rules.canonical import MAX_SAFE_INTEGER
from nth_dao.trade_rules.agreement_order import (
    MAX_TRADE_JSON_BYTES,
    TradeOrder,
    TradeOrderConflict,
    TradeOrderStore,
    trade_order_digest,
)
from nth_dao.util.io import InterProcessLock
from nth_dao.util.jsonl_safe import LOCK_TIMEOUT_PATIENT

ORDER_AUDIT_KIND = "nth.dao.trade.order-audit-work"
ORDER_AUDIT_PROTOCOL_VERSION = "1"
EVENT_TRADE_ORDER_ACCEPTED = "trade.order.accepted"
DEFAULT_MAX_ORDER_AUDIT_RECORDS = 4_096
DEFAULT_MAX_ORDER_AUDIT_BYTES = 2 * 1024 * 1024 * 1024
MAX_ORDER_AUDIT_RECORD_BYTES = 384 * 1024

ORDER_AUDIT_ERROR_ORDER_CONFLICT = "order-conflict"
ORDER_AUDIT_ERROR_ORDER_STORE = "order-store-failed"
ORDER_AUDIT_ERROR_SPINE = "spine-anchor-failed"
_ERROR_CODES = frozenset(
    {
        "",
        ORDER_AUDIT_ERROR_ORDER_CONFLICT,
        ORDER_AUDIT_ERROR_ORDER_STORE,
        ORDER_AUDIT_ERROR_SPINE,
    }
)
_STATUSES = frozenset({"prepared", "cached", "anchored", "blocked"})
_TRANSITIONS = {
    "prepared": frozenset({"prepared", "cached", "blocked"}),
    "cached": frozenset({"cached", "anchored", "blocked"}),
    "anchored": frozenset({"anchored"}),
    "blocked": frozenset({"blocked"}),
}
_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
_EVENT_ID = re.compile(r"^[0-9a-f]{64}$")
_ORDER_ID = re.compile(r"^nth-trade-order-sha256:([0-9a-f]{64})$")
_RECORD_FILE = re.compile(r"^([0-9a-f]{64})\.json$")
_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(\d{1,9}))?Z$"
)
_RECORD_FIELDS = frozenset(
    {
        "kind",
        "protocol_version",
        "order_digest",
        "order_b64u",
        "status",
        "event_id",
        "created_at_ms",
        "updated_at_ms",
        "attempts",
        "last_error",
    }
)
_ANCHOR_FIELDS = frozenset(
    {
        "protocol_version",
        "order_id",
        "order_digest",
        "proposal_digest",
        "acceptance_digest",
        "offer_digest",
        "maker_did",
        "taker_did",
        "created_at",
    }
)


class TradeOrderAuditError(RuntimeError):
    """The Order audit outbox or its cross-log binding is invalid."""


class TradeOrderAuditCapacity(TradeOrderAuditError):
    """The bounded Order audit outbox has reached its configured capacity."""


class TradeOrderAuditBusy(TradeOrderAuditError):
    """Another process owns the Order audit reconciliation lock."""


@dataclass(frozen=True)
class TradeOrderAuditRecord:
    kind: str
    protocol_version: str
    order_digest: str
    order_b64u: str
    status: str
    event_id: str
    created_at_ms: int
    updated_at_ms: int
    attempts: int
    last_error: str

    @property
    def order(self) -> TradeOrder:
        try:
            raw = b64u_decode(self.order_b64u)
        except (TypeError, ValueError) as exc:
            raise TradeOrderAuditError(
                "audit record contains invalid Order encoding"
            ) from exc
        if b64u_encode(raw) != self.order_b64u:
            raise TradeOrderAuditError(
                "audit record Order encoding is not canonical"
            )
        if len(raw) > MAX_TRADE_JSON_BYTES:
            raise TradeOrderAuditError(
                "audit record Order exceeds protocol byte limit"
            )
        try:
            order = TradeOrder.from_json(raw)
        except (TypeError, ValueError) as exc:
            raise TradeOrderAuditError(
                "audit record contains an invalid Trade Order"
            ) from exc
        if trade_order_digest(order) != self.order_digest:
            raise TradeOrderAuditError(
                "audit record Order digest binding mismatch"
            )
        return order

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "protocol_version": self.protocol_version,
            "order_digest": self.order_digest,
            "order_b64u": self.order_b64u,
            "status": self.status,
            "event_id": self.event_id,
            "created_at_ms": self.created_at_ms,
            "updated_at_ms": self.updated_at_ms,
            "attempts": self.attempts,
            "last_error": self.last_error,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "TradeOrderAuditRecord":
        if not isinstance(value, dict) or set(value) != _RECORD_FIELDS:
            raise TradeOrderAuditError(
                "audit record has missing or unknown fields"
            )
        if value["kind"] != ORDER_AUDIT_KIND:
            raise TradeOrderAuditError("audit record has the wrong kind")
        if value["protocol_version"] != ORDER_AUDIT_PROTOCOL_VERSION:
            raise TradeOrderAuditError(
                "audit record has an unsupported protocol version"
            )
        if (
            not isinstance(value["order_digest"], str)
            or _DIGEST.fullmatch(value["order_digest"]) is None
        ):
            raise TradeOrderAuditError("audit record order_digest is invalid")
        if not isinstance(value["order_b64u"], str) or not value["order_b64u"]:
            raise TradeOrderAuditError("audit record order_b64u is invalid")
        if value["status"] not in _STATUSES:
            raise TradeOrderAuditError("audit record status is invalid")
        if not isinstance(value["event_id"], str):
            raise TradeOrderAuditError("audit record event_id is invalid")
        if value["status"] == "anchored":
            if _EVENT_ID.fullmatch(value["event_id"]) is None:
                raise TradeOrderAuditError(
                    "anchored audit record has no valid event_id"
                )
        elif value["event_id"]:
            raise TradeOrderAuditError(
                "unanchored audit record must not have an event_id"
            )
        for field in ("created_at_ms", "updated_at_ms"):
            item = value[field]
            if (
                isinstance(item, bool)
                or not isinstance(item, int)
                or not 0 < item <= MAX_SAFE_INTEGER
            ):
                raise TradeOrderAuditError(
                    f"audit record {field} must be a safe positive integer"
                )
        if value["updated_at_ms"] < value["created_at_ms"]:
            raise TradeOrderAuditError(
                "audit record updated_at_ms precedes created_at_ms"
            )
        attempts = value["attempts"]
        if (
            isinstance(attempts, bool)
            or not isinstance(attempts, int)
            or not 0 <= attempts <= MAX_SAFE_INTEGER
        ):
            raise TradeOrderAuditError("audit record attempts is invalid")
        if value["last_error"] not in _ERROR_CODES:
            raise TradeOrderAuditError("audit record last_error is invalid")
        if value["status"] == "blocked":
            if value["last_error"] != ORDER_AUDIT_ERROR_ORDER_CONFLICT:
                raise TradeOrderAuditError(
                    "blocked audit record has the wrong error code"
                )
        elif value["last_error"] == ORDER_AUDIT_ERROR_ORDER_CONFLICT:
            raise TradeOrderAuditError(
                "order conflict error requires blocked status"
            )
        record = cls(**value)
        record.order
        return record


@dataclass(frozen=True)
class TradeOrderAuditResult:
    record: TradeOrderAuditRecord
    created: bool
    cache_created: bool
    anchor_created: bool


@dataclass(frozen=True)
class TradeOrderAuditReconciliation:
    scanned: int
    anchored: int
    verified_anchored: int
    blocked: int
    failed: int


def _now_ms(value: int | None = None) -> int:
    result = int(time.time() * 1000) if value is None else value
    if (
        isinstance(result, bool)
        or not isinstance(result, int)
        or not 0 < result <= MAX_SAFE_INTEGER
    ):
        raise ValueError("now_ms must be a safe positive integer")
    return result


def _reject_float(value: str) -> None:
    raise TradeOrderAuditError(f"float is forbidden: {value}")


def _reject_constant(value: str) -> None:
    raise TradeOrderAuditError(f"non-finite number is forbidden: {value}")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise TradeOrderAuditError(
                f"audit record contains duplicate key {key!r}"
            )
        output[key] = value
    return output


def _timestamp_ms(value: Any, *, label: str) -> int:
    match = _TIMESTAMP.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise TradeOrderAuditError(f"{label} is not a UTC RFC3339 timestamp")
    try:
        base = datetime.strptime(
            match.group(1),
            "%Y-%m-%dT%H:%M:%S",
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise TradeOrderAuditError(f"{label} is not a real timestamp") from exc
    nanos = int((match.group(2) or "").ljust(9, "0") or "0")
    return int(base.timestamp()) * 1000 + nanos // 1_000_000


class TradeOrderAuditOutbox:
    """Bounded durable write-ahead work records for Order audit anchoring."""

    def __init__(
        self,
        root: str | Path,
        *,
        max_records: int = DEFAULT_MAX_ORDER_AUDIT_RECORDS,
        max_bytes: int = DEFAULT_MAX_ORDER_AUDIT_BYTES,
        lock_timeout: float = LOCK_TIMEOUT_PATIENT,
    ) -> None:
        if (
            isinstance(max_records, bool)
            or not isinstance(max_records, int)
            or max_records < 1
        ):
            raise ValueError("max_records must be a positive integer")
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or max_bytes < MAX_ORDER_AUDIT_RECORD_BYTES
        ):
            raise ValueError(
                f"max_bytes must be at least {MAX_ORDER_AUDIT_RECORD_BYTES}"
            )
        if (
            isinstance(lock_timeout, bool)
            or not isinstance(lock_timeout, (int, float))
            or not math.isfinite(lock_timeout)
            or lock_timeout <= 0
        ):
            raise ValueError("lock_timeout must be a finite positive number")
        self.workspace_root = Path(root)
        self.root = self.workspace_root / "trade" / "order_audit_outbox"
        self.lock_path = self.root / ".locks" / "records"
        self.reconcile_lock_path = self.root / ".locks" / "reconcile"
        self.max_records = max_records
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
            raise TradeOrderAuditError(
                "audit outbox path escapes workspace root"
            ) from exc
        current = self.workspace_root
        candidates = [current]
        for part in relative.parts:
            current = current / part
            candidates.append(current)
        for candidate in candidates:
            if self._is_linklike(candidate):
                raise TradeOrderAuditError(
                    "audit outbox must not contain symlinks or junctions"
                )

    def _path(self, digest: str) -> Path:
        match = _DIGEST.fullmatch(digest) if isinstance(digest, str) else None
        if match is None:
            raise TradeOrderAuditError("Order audit digest is invalid")
        return self.root / f"{match.group(1)}.json"

    def _acquire(self):
        self._assert_path(self.lock_path.parent)
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._assert_path(self.lock_path.parent)
        return InterProcessLock(self.lock_path, timeout=self.lock_timeout)

    def acquire_reconcile(self):
        self._assert_path(self.reconcile_lock_path.parent)
        self.reconcile_lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._assert_path(self.reconcile_lock_path.parent)
        return InterProcessLock(
            self.reconcile_lock_path,
            timeout=self.lock_timeout,
        )

    def _read(self, path: Path) -> TradeOrderAuditRecord:
        self._assert_path(path)
        try:
            with path.open("rb") as stream:
                raw = stream.read(MAX_ORDER_AUDIT_RECORD_BYTES + 1)
        except OSError as exc:
            raise TradeOrderAuditError(
                "unable to read Order audit record"
            ) from exc
        if len(raw) > MAX_ORDER_AUDIT_RECORD_BYTES:
            raise TradeOrderAuditError("Order audit record exceeds byte limit")
        try:
            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_pairs,
                parse_float=_reject_float,
                parse_constant=_reject_constant,
            )
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise TradeOrderAuditError("Order audit record is invalid JSON") from exc
        if not isinstance(value, dict) or raw != canonical_json(value):
            raise TradeOrderAuditError(
                "Order audit record is not canonical JSON"
            )
        record = TradeOrderAuditRecord.from_dict(value)
        if path != self._path(record.order_digest):
            raise TradeOrderAuditError(
                "Order audit filename does not match its digest"
            )
        return record

    def _write(self, path: Path, record: TradeOrderAuditRecord) -> None:
        payload = canonical_json(record.to_dict())
        if len(payload) > MAX_ORDER_AUDIT_RECORD_BYTES:
            raise TradeOrderAuditCapacity(
                "Order audit record exceeds byte limit"
            )
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
            raise TradeOrderAuditError(
                "unable to persist Order audit record"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def _usage_locked(self) -> tuple[int, int]:
        if not self.root.exists():
            return 0, 0
        count = 0
        total = 0
        for path in self.root.rglob("*"):
            relative = path.relative_to(self.root)
            if self._is_linklike(path):
                raise TradeOrderAuditError(
                    "audit outbox must not contain symlinks or junctions"
                )
            if relative.parts and relative.parts[0] == ".locks":
                continue
            if path.is_dir():
                raise TradeOrderAuditError(
                    "audit outbox contains an unexpected directory"
                )
            if path.name.endswith(".tmp"):
                raise TradeOrderAuditError(
                    "audit outbox contains temporary crash residue"
                )
            if _RECORD_FILE.fullmatch(path.name) is None:
                raise TradeOrderAuditError(
                    "audit outbox contains an unknown file"
                )
            count += 1
            total += path.stat().st_size
            if count > self.max_records:
                raise TradeOrderAuditCapacity(
                    "existing audit outbox exceeds max_records"
                )
            if total > self.max_bytes:
                raise TradeOrderAuditCapacity(
                    "existing audit outbox exceeds max_bytes"
                )
        return count, total

    def prepare(
        self,
        order: TradeOrder | dict[str, Any],
        *,
        now_ms: int | None = None,
    ) -> tuple[TradeOrderAuditRecord, bool]:
        verified = (
            TradeOrder.from_json(order.canonical_bytes)
            if isinstance(order, TradeOrder)
            else TradeOrder.from_dict(order)
        )
        digest = trade_order_digest(verified)
        path = self._path(digest)
        moment = _now_ms(now_ms)
        accepted_at_ms = _timestamp_ms(
            verified.to_dict()["created_at"],
            label="Order created_at",
        )
        if moment < accepted_at_ms:
            raise TradeOrderAuditError(
                "Order audit time precedes the signed Acceptance"
            )
        try:
            with self._acquire():
                count, total = self._usage_locked()
                if path.exists():
                    return self._read(path), False
                record = TradeOrderAuditRecord.from_dict(
                    {
                        "kind": ORDER_AUDIT_KIND,
                        "protocol_version": ORDER_AUDIT_PROTOCOL_VERSION,
                        "order_digest": digest,
                        "order_b64u": b64u_encode(verified.canonical_bytes),
                        "status": "prepared",
                        "event_id": "",
                        "created_at_ms": moment,
                        "updated_at_ms": moment,
                        "attempts": 0,
                        "last_error": "",
                    }
                )
                encoded_size = len(canonical_json(record.to_dict()))
                if count + 1 > self.max_records:
                    raise TradeOrderAuditCapacity("max_records exceeded")
                if total + encoded_size > self.max_bytes:
                    raise TradeOrderAuditCapacity("max_bytes exceeded")
                self._write(path, record)
                return record, True
        except TimeoutError as exc:
            raise TradeOrderAuditBusy("Order audit outbox is busy") from exc

    def get(self, digest: str) -> TradeOrderAuditRecord | None:
        path = self._path(digest)
        try:
            with self._acquire():
                if not path.exists():
                    return None
                self._usage_locked()
                return self._read(path)
        except TimeoutError as exc:
            raise TradeOrderAuditBusy("Order audit outbox is busy") from exc

    def records(
        self,
        *,
        statuses: frozenset[str],
        limit: int,
    ) -> tuple[TradeOrderAuditRecord, ...]:
        if (
            not isinstance(statuses, frozenset)
            or not statuses
            or not statuses.issubset(_STATUSES)
        ):
            raise ValueError("statuses must be a non-empty status frozenset")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        if not self.root.exists():
            return ()
        try:
            with self._acquire():
                self._usage_locked()
                output: list[TradeOrderAuditRecord] = []
                for path in sorted(self.root.glob("*.json")):
                    record = self._read(path)
                    if record.status in statuses:
                        output.append(record)
                    if len(output) >= limit:
                        break
                return tuple(output)
        except TimeoutError as exc:
            raise TradeOrderAuditBusy("Order audit outbox is busy") from exc

    def pending(self, *, limit: int = 100) -> tuple[TradeOrderAuditRecord, ...]:
        return self.records(
            statuses=frozenset({"prepared", "cached"}),
            limit=limit,
        )

    def transition(
        self,
        digest: str,
        *,
        expected: frozenset[str],
        status: str,
        event_id: str = "",
        last_error: str = "",
        now_ms: int | None = None,
        increment_attempts: bool = False,
    ) -> TradeOrderAuditRecord:
        if status not in _STATUSES:
            raise ValueError("invalid Order audit status")
        if (
            not isinstance(expected, frozenset)
            or not expected
            or not expected.issubset(_STATUSES)
        ):
            raise ValueError("expected must be a non-empty status frozenset")
        path = self._path(digest)
        moment = _now_ms(now_ms)
        try:
            with self._acquire():
                record = self._read(path)
                if record.status not in expected:
                    raise TradeOrderAuditError(
                        f"unexpected audit state {record.status!r}"
                    )
                if status not in _TRANSITIONS[record.status]:
                    raise TradeOrderAuditError(
                        f"invalid audit transition {record.status!r} "
                        f"to {status!r}"
                    )
                updated = TradeOrderAuditRecord.from_dict(
                    {
                        **record.to_dict(),
                        "status": status,
                        "event_id": event_id,
                        "updated_at_ms": max(moment, record.updated_at_ms),
                        "attempts": (
                            record.attempts + 1
                            if increment_attempts
                            else record.attempts
                        ),
                        "last_error": last_error,
                    }
                )
                self._write(path, updated)
                return updated
        except FileNotFoundError as exc:
            raise TradeOrderAuditError("Order audit record is missing") from exc
        except TimeoutError as exc:
            raise TradeOrderAuditBusy("Order audit outbox is busy") from exc


def order_audit_payload(order: TradeOrder) -> dict[str, Any]:
    verified = TradeOrder.from_json(order.canonical_bytes)
    document = verified.to_dict()
    return {
        "protocol_version": ORDER_AUDIT_PROTOCOL_VERSION,
        "order_id": verified.order_id,
        "order_digest": trade_order_digest(verified),
        "proposal_digest": document["proposal_digest"],
        "acceptance_digest": document["acceptance_digest"],
        "offer_digest": document["offer_digest"],
        "maker_did": document["maker_did"],
        "taker_did": document["taker_did"],
        "created_at": document["created_at"],
    }


def validate_order_audit_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _ANCHOR_FIELDS:
        raise TradeOrderAuditError(
            "Order Spine anchor has missing or unknown fields"
        )
    if value["protocol_version"] != ORDER_AUDIT_PROTOCOL_VERSION:
        raise TradeOrderAuditError(
            "Order Spine anchor has an unsupported protocol version"
        )
    order_match = (
        _ORDER_ID.fullmatch(value["order_id"])
        if isinstance(value["order_id"], str)
        else None
    )
    if order_match is None:
        raise TradeOrderAuditError("Order Spine anchor order_id is invalid")
    for field in (
        "order_digest",
        "proposal_digest",
        "acceptance_digest",
        "offer_digest",
    ):
        if (
            not isinstance(value[field], str)
            or _DIGEST.fullmatch(value[field]) is None
        ):
            raise TradeOrderAuditError(
                f"Order Spine anchor {field} is invalid"
            )
    if order_match.group(1) != value["proposal_digest"].removeprefix("sha256:"):
        raise TradeOrderAuditError(
            "Order Spine anchor order_id/proposal_digest binding mismatch"
        )
    for field in ("maker_did", "taker_did"):
        if not is_did_key(value[field]):
            raise TradeOrderAuditError(
                f"Order Spine anchor {field} is invalid"
            )
    _timestamp_ms(
        value["created_at"],
        label="Order Spine anchor created_at",
    )
    return dict(value)


class TradeOrderAuditCoordinator:
    """Recover cache persistence and exact Spine anchoring after crashes."""

    def __init__(
        self,
        outbox: TradeOrderAuditOutbox,
        order_store: TradeOrderStore,
        spine: SignedEventLog,
    ) -> None:
        self.outbox = outbox
        self.order_store = order_store
        self.spine = spine

    def _anchor_index(
        self,
    ) -> tuple[dict[str, SpineEvent], dict[str, SpineEvent]]:
        ok, reason = self.spine.verify_chain()
        if not ok:
            raise TradeOrderAuditError(
                f"Spine integrity check failed: {reason}"
            )
        by_order_id: dict[str, SpineEvent] = {}
        by_digest: dict[str, SpineEvent] = {}
        for event in self.spine.read_all():
            if event.type != EVENT_TRADE_ORDER_ACCEPTED:
                continue
            payload = validate_order_audit_payload(event.payload)
            order_id = payload["order_id"]
            digest = payload["order_digest"]
            if order_id in by_order_id or digest in by_digest:
                raise TradeOrderAuditError(
                    "Order Spine contains duplicate or conflicting anchors"
                )
            by_order_id[order_id] = event
            by_digest[digest] = event
        return by_order_id, by_digest

    @staticmethod
    def _find_anchor(
        order: TradeOrder,
        anchor_index: tuple[dict[str, SpineEvent], dict[str, SpineEvent]],
    ) -> SpineEvent | None:
        expected = order_audit_payload(order)
        by_order_id, by_digest = anchor_index
        by_id = by_order_id.get(order.order_id)
        by_hash = by_digest.get(expected["order_digest"])
        if by_id is not None and by_hash is not None and by_id != by_hash:
            raise TradeOrderAuditError(
                "Order Spine contains a conflicting anchor index"
            )
        event = by_id or by_hash
        if event is not None and event.payload != expected:
            raise TradeOrderAuditError(
                "Order Spine contains a conflicting anchor"
            )
        return event

    def _reconcile_locked(
        self,
        digest: str,
        *,
        now_ms: int,
        prepared_created: bool,
        anchor_index: tuple[dict[str, SpineEvent], dict[str, SpineEvent]],
    ) -> TradeOrderAuditResult:
        record = self.outbox.get(digest)
        if record is None:
            raise TradeOrderAuditError("Order audit record disappeared")
        order = record.order
        accepted_at_ms = _timestamp_ms(
            order.to_dict()["created_at"],
            label="Order created_at",
        )
        if now_ms < accepted_at_ms:
            raise TradeOrderAuditError(
                "Order audit time precedes the signed Acceptance"
            )
        cache_created = False
        anchor_created = False
        if record.status == "blocked":
            raise TradeOrderConflict(
                "Order audit is blocked by an equivocation conflict"
            )
        if record.status in {"prepared", "cached", "anchored"}:
            try:
                cache_created = self.order_store.get(order.order_id) is None
                stored = self.order_store.put(order)
                if stored.canonical_bytes != order.canonical_bytes:
                    raise TradeOrderConflict(
                        "Order cache returned different accepted bytes"
                    )
            except TradeOrderConflict:
                if record.status != "anchored":
                    self.outbox.transition(
                        digest,
                        expected=frozenset({record.status}),
                        status="blocked",
                        last_error=ORDER_AUDIT_ERROR_ORDER_CONFLICT,
                        now_ms=now_ms,
                        increment_attempts=True,
                    )
                raise
            except (OSError, RuntimeError, TypeError, ValueError):
                if record.status != "anchored":
                    self.outbox.transition(
                        digest,
                        expected=frozenset({record.status}),
                        status=record.status,
                        last_error=ORDER_AUDIT_ERROR_ORDER_STORE,
                        now_ms=now_ms,
                        increment_attempts=True,
                    )
                raise
        if record.status == "anchored":
            event = self._find_anchor(order, anchor_index)
            if event is None or event.event_id != record.event_id:
                raise TradeOrderAuditError(
                    "anchored audit record does not match the Spine event"
                )
            return TradeOrderAuditResult(
                record=record,
                created=prepared_created,
                cache_created=cache_created,
                anchor_created=False,
            )
        if record.status == "prepared":
            record = self.outbox.transition(
                digest,
                expected=frozenset({"prepared"}),
                status="cached",
                now_ms=now_ms,
                last_error="",
            )
        if record.status == "cached":
            try:
                event = self._find_anchor(order, anchor_index)
                if event is None:
                    event = self.spine.append(
                        EVENT_TRADE_ORDER_ACCEPTED,
                        order_audit_payload(order),
                        ts_ms=now_ms,
                    )
                    anchor_created = True
                    anchor_index[0][order.order_id] = event
                    anchor_index[1][digest] = event
            except (OSError, RuntimeError, TypeError, ValueError):
                self.outbox.transition(
                    digest,
                    expected=frozenset({"cached"}),
                    status="cached",
                    last_error=ORDER_AUDIT_ERROR_SPINE,
                    now_ms=now_ms,
                    increment_attempts=True,
                )
                raise
            record = self.outbox.transition(
                digest,
                expected=frozenset({"cached"}),
                status="anchored",
                event_id=event.event_id,
                now_ms=now_ms,
                last_error="",
            )
        if record.status != "anchored":
            raise TradeOrderAuditError(
                f"Order audit stopped in unexpected state {record.status!r}"
            )
        return TradeOrderAuditResult(
            record=record,
            created=prepared_created,
            cache_created=cache_created,
            anchor_created=anchor_created,
        )

    def accept(
        self,
        order: TradeOrder | dict[str, Any],
        *,
        now_ms: int | None = None,
    ) -> TradeOrderAuditResult:
        moment = _now_ms(now_ms)
        prepared, created = self.outbox.prepare(order, now_ms=moment)
        try:
            with self.outbox.acquire_reconcile():
                anchor_index = self._anchor_index()
                return self._reconcile_locked(
                    prepared.order_digest,
                    now_ms=moment,
                    prepared_created=created,
                    anchor_index=anchor_index,
                )
        except TimeoutError as exc:
            raise TradeOrderAuditBusy(
                "Order audit reconciliation is busy"
            ) from exc

    def reconcile(
        self,
        *,
        limit: int = 100,
        now_ms: int | None = None,
    ) -> TradeOrderAuditReconciliation:
        moment = _now_ms(now_ms)
        anchored = 0
        verified_anchored = 0
        blocked = 0
        failed = 0
        scanned = 0
        try:
            with self.outbox.acquire_reconcile():
                anchor_index = self._anchor_index()
                records = self.outbox.pending(limit=limit)
                anchored_records = self.outbox.records(
                    statuses=frozenset({"anchored"}),
                    limit=self.outbox.max_records,
                )
                for record in records:
                    scanned += 1
                    try:
                        self._reconcile_locked(
                            record.order_digest,
                            now_ms=moment,
                            prepared_created=False,
                            anchor_index=anchor_index,
                        )
                        anchored += 1
                    except TradeOrderConflict:
                        blocked += 1
                    except (OSError, RuntimeError, TypeError, ValueError):
                        failed += 1
                for record in anchored_records:
                    scanned += 1
                    try:
                        self._reconcile_locked(
                            record.order_digest,
                            now_ms=moment,
                            prepared_created=False,
                            anchor_index=anchor_index,
                        )
                        verified_anchored += 1
                    except (OSError, RuntimeError, TypeError, ValueError):
                        failed += 1
        except TimeoutError as exc:
            raise TradeOrderAuditBusy(
                "Order audit reconciliation is busy"
            ) from exc
        return TradeOrderAuditReconciliation(
            scanned=scanned,
            anchored=anchored,
            verified_anchored=verified_anchored,
            blocked=blocked,
            failed=failed,
        )


__all__ = [
    "DEFAULT_MAX_ORDER_AUDIT_BYTES",
    "DEFAULT_MAX_ORDER_AUDIT_RECORDS",
    "EVENT_TRADE_ORDER_ACCEPTED",
    "MAX_ORDER_AUDIT_RECORD_BYTES",
    "ORDER_AUDIT_ERROR_ORDER_CONFLICT",
    "ORDER_AUDIT_ERROR_ORDER_STORE",
    "ORDER_AUDIT_ERROR_SPINE",
    "ORDER_AUDIT_KIND",
    "ORDER_AUDIT_PROTOCOL_VERSION",
    "TradeOrderAuditBusy",
    "TradeOrderAuditCapacity",
    "TradeOrderAuditCoordinator",
    "TradeOrderAuditError",
    "TradeOrderAuditOutbox",
    "TradeOrderAuditReconciliation",
    "TradeOrderAuditRecord",
    "TradeOrderAuditResult",
    "order_audit_payload",
    "validate_order_audit_payload",
]
