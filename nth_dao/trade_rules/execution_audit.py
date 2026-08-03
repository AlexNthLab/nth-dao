"""Recoverable write-ahead audit records for Trade Execution Receipts."""

from __future__ import annotations

import json
import math
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import is_did_key
from nth_dao.trade_rules.agreement_order import ORDER_ID_PREFIX, TradeOrder
from nth_dao.trade_rules.execution_receipt import (
    EXECUTION_RECEIPT_ID_PREFIX,
    EXECUTION_OUTCOMES,
    TradeExecutionReceipt,
    execution_receipt_digest,
)
from nth_dao.trade_rules.execution_receipt_store import (
    TradeExecutionReceiptConflict,
)
from nth_dao.util.io import InterProcessLock

EXECUTION_AUDIT_KIND = "nth.dao.trade.execution-audit-work"
EXECUTION_AUDIT_PROTOCOL_VERSION = "1"
EVENT_TRADE_EXECUTION_RECORDED = "trade.execution.recorded"
DEFAULT_MAX_EXECUTION_AUDIT_RECORDS = 10_000
DEFAULT_MAX_EXECUTION_AUDIT_BYTES = 2 * 1024 * 1024 * 1024
MAX_EXECUTION_AUDIT_RECORD_BYTES = 1024 * 1024

EXECUTION_AUDIT_ERROR_RECEIPT_CONFLICT = "receipt-conflict"
EXECUTION_AUDIT_ERROR_RECEIPT_STORE = "receipt-store-failed"
EXECUTION_AUDIT_ERROR_SPINE = "spine-anchor-failed"

_STATUSES = frozenset({"prepared", "stored", "anchored", "blocked"})
_ERROR_CODES = frozenset({
    "",
    EXECUTION_AUDIT_ERROR_RECEIPT_CONFLICT,
    EXECUTION_AUDIT_ERROR_RECEIPT_STORE,
    EXECUTION_AUDIT_ERROR_SPINE,
})
_TRANSITIONS = {
    "prepared": frozenset({"prepared", "stored", "blocked"}),
    "stored": frozenset({"stored", "anchored", "blocked"}),
    "anchored": frozenset({"anchored", "blocked"}),
    "blocked": frozenset({"blocked"}),
}
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXECUTION_ID = re.compile(
    rf"^{re.escape(EXECUTION_RECEIPT_ID_PREFIX)}([0-9a-f]{{64}})$"
)
_EVENT_ID = re.compile(r"^[0-9a-f]{64}$")
_ORDER_ID = re.compile(
    rf"^{re.escape(ORDER_ID_PREFIX)}[0-9a-f]{{64}}$"
)
_OPERATION_ID = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
_TIMESTAMP = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(\d{6}))?Z$"
)
_RECORD_FILE = re.compile(r"^[0-9a-f]{64}\.json$")
_TEMPORARY_FILE = re.compile(
    r"^[0-9a-f]{64}\.json\.[A-Za-z0-9_-]{1,64}\.tmp$"
)
_RECORD_FIELDS = frozenset({
    "kind",
    "protocol_version",
    "execution_id",
    "receipt_digest",
    "receipt_b64u",
    "order_b64u",
    "status",
    "event_id",
    "created_at_ms",
    "updated_at_ms",
    "attempts",
    "last_error",
})
_ANCHOR_FIELDS = frozenset({
    "protocol_version",
    "execution_id",
    "receipt_digest",
    "order_id",
    "order_digest",
    "executor_did",
    "operation_id",
    "outcome",
    "completed_at",
})


class TradeExecutionAuditError(RuntimeError):
    """Execution audit state or its cross-log binding is invalid."""


class TradeExecutionAuditCapacity(TradeExecutionAuditError):
    """The bounded execution audit outbox has reached capacity."""


class TradeExecutionAuditBusy(TradeExecutionAuditError):
    """Another process owns execution audit reconciliation."""


def _safe_int(value: Any, *, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 9_007_199_254_740_991
    ):
        raise TradeExecutionAuditError(f"{label} is invalid")
    return value


def _strict_json(raw: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in items:
            if key in output:
                raise TradeExecutionAuditError(
                    f"duplicate execution audit field {key!r}"
                )
            output[key] = value
        return output

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except TradeExecutionAuditError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TradeExecutionAuditError(
            "execution audit record is not valid UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        raise TradeExecutionAuditError(
            "execution audit record must be an object"
        )
    return value


@dataclass(frozen=True)
class TradeExecutionAuditRecord:
    kind: str
    protocol_version: str
    execution_id: str
    receipt_digest: str
    receipt_b64u: str
    order_b64u: str
    status: str
    event_id: str
    created_at_ms: int
    updated_at_ms: int
    attempts: int
    last_error: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "TradeExecutionAuditRecord":
        if not isinstance(value, dict) or set(value) != _RECORD_FIELDS:
            raise TradeExecutionAuditError(
                "execution audit record has missing or unknown fields"
            )
        for field in (
            "kind",
            "protocol_version",
            "execution_id",
            "receipt_digest",
            "receipt_b64u",
            "order_b64u",
            "status",
            "event_id",
            "last_error",
        ):
            if not isinstance(value[field], str):
                raise TradeExecutionAuditError(
                    f"execution audit record {field} is invalid"
                )
        record = cls(**value)
        if record.kind != EXECUTION_AUDIT_KIND:
            raise TradeExecutionAuditError(
                "execution audit record has the wrong kind"
            )
        if record.protocol_version != EXECUTION_AUDIT_PROTOCOL_VERSION:
            raise TradeExecutionAuditError(
                "execution audit record has an unsupported version"
            )
        if _EXECUTION_ID.fullmatch(record.execution_id) is None:
            raise TradeExecutionAuditError(
                "execution audit record execution_id is invalid"
            )
        if _DIGEST.fullmatch(record.receipt_digest) is None:
            raise TradeExecutionAuditError(
                "execution audit record receipt_digest is invalid"
            )
        if not record.receipt_b64u or not record.order_b64u:
            raise TradeExecutionAuditError(
                "execution audit record artifact encoding is missing"
            )
        if record.status not in _STATUSES:
            raise TradeExecutionAuditError(
                "execution audit record status is invalid"
            )
        if record.event_id and _EVENT_ID.fullmatch(record.event_id) is None:
            raise TradeExecutionAuditError(
                "execution audit record event_id is invalid"
            )
        for field in ("created_at_ms", "updated_at_ms", "attempts"):
            _safe_int(getattr(record, field), label=f"record.{field}")
        if record.updated_at_ms < record.created_at_ms:
            raise TradeExecutionAuditError(
                "execution audit record time moved backwards"
            )
        if record.last_error not in _ERROR_CODES:
            raise TradeExecutionAuditError(
                "execution audit record last_error is invalid"
            )
        if record.status == "anchored" and not record.event_id:
            raise TradeExecutionAuditError(
                "anchored execution audit record has no event_id"
            )
        if record.status in {"prepared", "stored"} and record.event_id:
            raise TradeExecutionAuditError(
                "unanchored execution audit record has an event_id"
            )
        if record.status == "blocked":
            if record.last_error != EXECUTION_AUDIT_ERROR_RECEIPT_CONFLICT:
                raise TradeExecutionAuditError(
                    "blocked execution audit record has the wrong error"
                )
        elif record.status == "anchored" and record.last_error:
            raise TradeExecutionAuditError(
                "anchored execution audit record must clear last_error"
            )
        elif record.last_error == EXECUTION_AUDIT_ERROR_RECEIPT_CONFLICT:
            raise TradeExecutionAuditError(
                "unblocked execution audit record claims a conflict"
            )
        elif (
            record.status == "prepared"
            and record.last_error == EXECUTION_AUDIT_ERROR_SPINE
        ):
            raise TradeExecutionAuditError(
                "prepared execution audit record has a Spine error"
            )
        return record

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "protocol_version": self.protocol_version,
            "execution_id": self.execution_id,
            "receipt_digest": self.receipt_digest,
            "receipt_b64u": self.receipt_b64u,
            "order_b64u": self.order_b64u,
            "status": self.status,
            "event_id": self.event_id,
            "created_at_ms": self.created_at_ms,
            "updated_at_ms": self.updated_at_ms,
            "attempts": self.attempts,
            "last_error": self.last_error,
        }

    @property
    def order(self) -> TradeOrder:
        try:
            raw = b64u_decode(self.order_b64u)
        except (TypeError, ValueError) as exc:
            raise TradeExecutionAuditError(
                "execution audit Order encoding is invalid"
            ) from exc
        if b64u_encode(raw) != self.order_b64u:
            raise TradeExecutionAuditError(
                "execution audit Order encoding is not canonical"
            )
        try:
            return TradeOrder.from_json(raw)
        except (TypeError, ValueError) as exc:
            raise TradeExecutionAuditError(
                "execution audit contains an invalid Order"
            ) from exc

    @property
    def receipt(self) -> TradeExecutionReceipt:
        order = self.order
        try:
            raw = b64u_decode(self.receipt_b64u)
        except (TypeError, ValueError) as exc:
            raise TradeExecutionAuditError(
                "execution audit Receipt encoding is invalid"
            ) from exc
        if b64u_encode(raw) != self.receipt_b64u:
            raise TradeExecutionAuditError(
                "execution audit Receipt encoding is not canonical"
            )
        try:
            receipt = TradeExecutionReceipt.from_json(raw, order=order)
        except (TypeError, ValueError) as exc:
            raise TradeExecutionAuditError(
                "execution audit contains an invalid Receipt"
            ) from exc
        if receipt.execution_id != self.execution_id:
            raise TradeExecutionAuditError(
                "execution audit execution_id binding mismatch"
            )
        if execution_receipt_digest(receipt, order=order) != self.receipt_digest:
            raise TradeExecutionAuditError(
                "execution audit Receipt digest binding mismatch"
            )
        return receipt


@dataclass(frozen=True)
class _TradeExecutionAuditSnapshot:
    records: tuple[TradeExecutionAuditRecord, ...]
    file_count: int
    total_bytes: int


class TradeExecutionAuditOutbox:
    """Bounded durable records prepared before Receipt CAS publication."""

    def __init__(
        self,
        root: str | Path,
        *,
        max_records: int = DEFAULT_MAX_EXECUTION_AUDIT_RECORDS,
        max_bytes: int = DEFAULT_MAX_EXECUTION_AUDIT_BYTES,
        lock_timeout: float = 30.0,
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
            isinstance(lock_timeout, bool)
            or not isinstance(lock_timeout, (int, float))
            or not math.isfinite(lock_timeout)
            or lock_timeout <= 0
        ):
            raise ValueError("lock_timeout must be a finite positive number")
        self.workspace_root = Path(root)
        self.root = self.workspace_root / "trade" / "execution_audit_outbox_v1"
        self.lock_path = self.root / ".locks" / "reconcile"
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
            raise TradeExecutionAuditError(
                "execution audit path escapes workspace root"
            ) from exc
        current = self.workspace_root
        for part in ("", *relative.parts):
            current = current if not part else current / part
            if self._is_linklike(current):
                raise TradeExecutionAuditError(
                    "execution audit outbox must not contain links"
                )

    def _path(self, execution_id: str) -> Path:
        match = (
            _EXECUTION_ID.fullmatch(execution_id)
            if isinstance(execution_id, str)
            else None
        )
        if match is None:
            raise TradeExecutionAuditError("execution_id is invalid")
        return self.root / f"{match.group(1)}.json"

    def acquire_reconcile(self) -> InterProcessLock:
        self._assert_path(self.lock_path.parent)
        try:
            self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise TradeExecutionAuditError(
                f"unable to create execution audit lock directory: {exc}"
            ) from exc
        self._assert_path(self.lock_path.parent)
        self._assert_path(Path(f"{self.lock_path}.lock"))
        return InterProcessLock(self.lock_path, timeout=self.lock_timeout)

    def _read(self, path: Path) -> TradeExecutionAuditRecord:
        self._assert_path(path)
        try:
            size = path.stat().st_size
            if size > MAX_EXECUTION_AUDIT_RECORD_BYTES:
                raise TradeExecutionAuditError(
                    "execution audit record exceeds byte limit"
                )
            raw = path.read_bytes()
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise TradeExecutionAuditError(
                f"unable to read execution audit record: {exc}"
            ) from exc
        if len(raw) != size:
            raise TradeExecutionAuditError(
                "execution audit record changed while being read"
            )
        record = TradeExecutionAuditRecord.from_dict(_strict_json(raw))
        _ = record.receipt
        if raw != canonical_json(record.to_dict()):
            raise TradeExecutionAuditError(
                "execution audit record is not canonical JSON"
            )
        return record

    def _write(self, path: Path, record: TradeExecutionAuditRecord) -> None:
        payload = canonical_json(record.to_dict())
        if len(payload) > MAX_EXECUTION_AUDIT_RECORD_BYTES:
            raise TradeExecutionAuditCapacity(
                "execution audit record exceeds byte limit"
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
                directory = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        except OSError as exc:
            raise TradeExecutionAuditError(
                f"unable to persist execution audit record: {exc}"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def _snapshot_locked(self) -> _TradeExecutionAuditSnapshot:
        if not self.root.exists():
            return _TradeExecutionAuditSnapshot((), 0, 0)
        output: list[TradeExecutionAuditRecord] = []
        temporary_count = 0
        temporary_bytes = 0
        for path in sorted(self.root.rglob("*")):
            relative = path.relative_to(self.root)
            if self._is_linklike(path):
                raise TradeExecutionAuditError(
                    "execution audit outbox must not contain links"
                )
            if relative.parts and relative.parts[0] == ".locks":
                continue
            if path.is_dir():
                raise TradeExecutionAuditError(
                    "execution audit outbox contains an unexpected directory"
                )
            if _TEMPORARY_FILE.fullmatch(path.name) is not None:
                try:
                    size = path.stat().st_size
                except OSError as exc:
                    raise TradeExecutionAuditError(
                        "unable to inspect execution audit temporary file"
                    ) from exc
                if size > MAX_EXECUTION_AUDIT_RECORD_BYTES:
                    raise TradeExecutionAuditCapacity(
                        "execution audit temporary file exceeds byte limit"
                    )
                temporary_count += 1
                temporary_bytes += size
                continue
            if _RECORD_FILE.fullmatch(path.name) is None:
                raise TradeExecutionAuditError(
                    "execution audit outbox contains an unknown file"
                )
            output.append(self._read(path))
        if len(output) + temporary_count > self.max_records:
            raise TradeExecutionAuditCapacity(
                "execution audit files exceed max_records"
            )
        total = sum(
            len(canonical_json(record.to_dict())) for record in output
        ) + temporary_bytes
        if total > self.max_bytes:
            raise TradeExecutionAuditCapacity(
                "existing execution audit records exceed max_bytes"
            )
        return _TradeExecutionAuditSnapshot(
            records=tuple(output),
            file_count=len(output) + temporary_count,
            total_bytes=total,
        )

    def _records_locked(self) -> tuple[TradeExecutionAuditRecord, ...]:
        return self._snapshot_locked().records

    def _get_locked(
        self,
        execution_id: str,
    ) -> TradeExecutionAuditRecord | None:
        path = self._path(execution_id)
        if not path.exists():
            return None
        return self._read(path)

    def prepare(
        self,
        receipt: TradeExecutionReceipt | dict[str, Any],
        *,
        order: TradeOrder | dict[str, Any],
        now_ms: int,
    ) -> tuple[TradeExecutionAuditRecord, bool]:
        moment = _safe_int(now_ms, label="now_ms")
        verified_order = (
            TradeOrder.from_json(order.canonical_bytes)
            if isinstance(order, TradeOrder)
            else TradeOrder.from_dict(order)
        )
        verified_receipt = TradeExecutionReceipt.from_json(
            (
                receipt.canonical_bytes
                if isinstance(receipt, TradeExecutionReceipt)
                else TradeExecutionReceipt.from_dict(
                    receipt,
                    order=verified_order,
                ).canonical_bytes
            ),
            order=verified_order,
        )
        digest = execution_receipt_digest(
            verified_receipt,
            order=verified_order,
        )
        wanted = TradeExecutionAuditRecord(
            kind=EXECUTION_AUDIT_KIND,
            protocol_version=EXECUTION_AUDIT_PROTOCOL_VERSION,
            execution_id=verified_receipt.execution_id,
            receipt_digest=digest,
            receipt_b64u=b64u_encode(verified_receipt.canonical_bytes),
            order_b64u=b64u_encode(verified_order.canonical_bytes),
            status="prepared",
            event_id="",
            created_at_ms=moment,
            updated_at_ms=moment,
            attempts=0,
            last_error="",
        )
        try:
            with self.acquire_reconcile():
                snapshot = self._snapshot_locked()
                existing = next(
                    (
                        record
                        for record in snapshot.records
                        if record.execution_id == wanted.execution_id
                    ),
                    None,
                )
                if existing is not None:
                    _ = existing.receipt
                    if (
                        existing.receipt_digest != wanted.receipt_digest
                        or existing.receipt_b64u != wanted.receipt_b64u
                        or existing.order_b64u != wanted.order_b64u
                    ):
                        raise TradeExecutionReceiptConflict(
                            "execution audit ID has different signed bytes"
                        )
                    return existing, False
                payload_size = len(canonical_json(wanted.to_dict()))
                if snapshot.file_count + 1 > self.max_records:
                    raise TradeExecutionAuditCapacity(
                        "max_records exceeded"
                    )
                if snapshot.total_bytes + payload_size > self.max_bytes:
                    raise TradeExecutionAuditCapacity("max_bytes exceeded")
                self._write(self._path(wanted.execution_id), wanted)
                return wanted, True
        except TimeoutError as exc:
            raise TradeExecutionAuditBusy(
                "execution audit reconciliation is busy"
            ) from exc

    def get(self, execution_id: str) -> TradeExecutionAuditRecord | None:
        try:
            with self.acquire_reconcile():
                self._path(execution_id)
                records = self._snapshot_locked().records
                return next(
                    (
                        record
                        for record in records
                        if record.execution_id == execution_id
                    ),
                    None,
                )
        except TimeoutError as exc:
            raise TradeExecutionAuditBusy(
                "execution audit reconciliation is busy"
            ) from exc

    def _transition_locked(
        self,
        execution_id: str,
        *,
        expected: frozenset[str],
        status: str,
        now_ms: int,
        event_id: str | None = None,
        last_error: str = "",
        increment_attempts: bool = False,
    ) -> TradeExecutionAuditRecord:
        if status not in _STATUSES or last_error not in _ERROR_CODES:
            raise TradeExecutionAuditError(
                "execution audit transition is invalid"
            )
        moment = _safe_int(now_ms, label="now_ms")
        current = self._get_locked(execution_id)
        if current is None:
            raise TradeExecutionAuditError(
                "execution audit record is missing"
            )
        if current.status not in expected:
            raise TradeExecutionAuditError(
                "execution audit compare-and-set status mismatch"
            )
        moment = max(moment, current.updated_at_ms)
        if status not in _TRANSITIONS[current.status]:
            raise TradeExecutionAuditError(
                "execution audit state transition is forbidden"
            )
        updated = TradeExecutionAuditRecord.from_dict({
            **current.to_dict(),
            "status": status,
            "event_id": (
                current.event_id if event_id is None else event_id
            ),
            "updated_at_ms": moment,
            "attempts": (
                current.attempts + 1
                if increment_attempts
                else current.attempts
            ),
            "last_error": last_error,
        })
        self._write(self._path(execution_id), updated)
        return updated

    def _reconcile_batch_locked(
        self,
        *,
        limit: int,
        after_execution_id: str | None,
        pending_only: bool = False,
    ) -> tuple[tuple[TradeExecutionAuditRecord, ...], bool]:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError("limit must be a positive integer")
        if after_execution_id is not None:
            self._path(after_execution_id)
        ordered = sorted(
            self._snapshot_locked().records,
            key=lambda record: record.execution_id,
        )
        eligible = [
            record
            for record in ordered
            if (
                (
                    after_execution_id is None
                    or record.execution_id > after_execution_id
                )
                and (
                    not pending_only
                    or record.status in {"prepared", "stored"}
                )
            )
        ]
        return tuple(eligible[:limit]), len(eligible) > limit


def execution_audit_payload(
    receipt: TradeExecutionReceipt,
    *,
    order: TradeOrder,
) -> dict[str, Any]:
    verified_order = TradeOrder.from_json(order.canonical_bytes)
    verified_receipt = TradeExecutionReceipt.from_json(
        receipt.canonical_bytes,
        order=verified_order,
    )
    document = verified_receipt.to_dict()
    return {
        "protocol_version": EXECUTION_AUDIT_PROTOCOL_VERSION,
        "execution_id": verified_receipt.execution_id,
        "receipt_digest": execution_receipt_digest(
            verified_receipt,
            order=verified_order,
        ),
        "order_id": document["order_id"],
        "order_digest": document["order_digest"],
        "executor_did": document["executor_did"],
        "operation_id": document["operation"]["operation_id"],
        "outcome": document["outcome"],
        "completed_at": document["completed_at"],
    }


def validate_execution_audit_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _ANCHOR_FIELDS:
        raise TradeExecutionAuditError(
            "execution Spine anchor has missing or unknown fields"
        )
    if value["protocol_version"] != EXECUTION_AUDIT_PROTOCOL_VERSION:
        raise TradeExecutionAuditError(
            "execution Spine anchor has an unsupported version"
        )
    if (
        not isinstance(value["execution_id"], str)
        or _EXECUTION_ID.fullmatch(value["execution_id"]) is None
    ):
        raise TradeExecutionAuditError(
            "execution Spine anchor execution_id is invalid"
        )
    for field in ("receipt_digest", "order_digest"):
        if (
            not isinstance(value[field], str)
            or _DIGEST.fullmatch(value[field]) is None
        ):
            raise TradeExecutionAuditError(
                f"execution Spine anchor {field} is invalid"
            )
    if (
        not isinstance(value["order_id"], str)
        or _ORDER_ID.fullmatch(value["order_id"]) is None
    ):
        raise TradeExecutionAuditError(
            "execution Spine anchor order_id is invalid"
        )
    if (
        not isinstance(value["executor_did"], str)
        or not is_did_key(value["executor_did"])
    ):
        raise TradeExecutionAuditError(
            "execution Spine anchor executor_did is invalid"
        )
    if (
        not isinstance(value["operation_id"], str)
        or _OPERATION_ID.fullmatch(value["operation_id"]) is None
    ):
        raise TradeExecutionAuditError(
            "execution Spine anchor operation_id is invalid"
        )
    if (
        not isinstance(value["outcome"], str)
        or value["outcome"] not in EXECUTION_OUTCOMES
    ):
        raise TradeExecutionAuditError(
            "execution Spine anchor outcome is invalid"
        )
    completed_at = value["completed_at"]
    match = (
        _TIMESTAMP.fullmatch(completed_at)
        if isinstance(completed_at, str)
        else None
    )
    if match is None or match.group(2) == "000000":
        raise TradeExecutionAuditError(
            "execution Spine anchor completed_at is invalid"
        )
    try:
        datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TradeExecutionAuditError(
            "execution Spine anchor completed_at is invalid"
        ) from exc
    return dict(value)


def validate_execution_audit_binding(
    value: Any,
    *,
    receipt: TradeExecutionReceipt | dict[str, Any],
    order: TradeOrder | dict[str, Any],
) -> dict[str, Any]:
    payload = validate_execution_audit_payload(value)
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
    expected = execution_audit_payload(
        verified_receipt,
        order=verified_order,
    )
    if payload != expected:
        raise TradeExecutionAuditError(
            "execution Spine anchor does not match its Receipt and Order"
        )
    return payload


__all__ = [
    "DEFAULT_MAX_EXECUTION_AUDIT_BYTES",
    "DEFAULT_MAX_EXECUTION_AUDIT_RECORDS",
    "EVENT_TRADE_EXECUTION_RECORDED",
    "EXECUTION_AUDIT_ERROR_RECEIPT_CONFLICT",
    "EXECUTION_AUDIT_ERROR_RECEIPT_STORE",
    "EXECUTION_AUDIT_ERROR_SPINE",
    "EXECUTION_AUDIT_KIND",
    "EXECUTION_AUDIT_PROTOCOL_VERSION",
    "MAX_EXECUTION_AUDIT_RECORD_BYTES",
    "TradeExecutionAuditBusy",
    "TradeExecutionAuditCapacity",
    "TradeExecutionAuditError",
    "TradeExecutionAuditOutbox",
    "TradeExecutionAuditRecord",
    "execution_audit_payload",
    "validate_execution_audit_binding",
    "validate_execution_audit_payload",
]
