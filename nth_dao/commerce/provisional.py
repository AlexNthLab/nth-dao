"""Durable journal for crash-safe federated commerce imports."""

from __future__ import annotations

import hashlib
import os
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List

from nth_dao.canonical_json import canonical_json
from nth_dao.commerce.outbox import trade_chain_head
from nth_dao.commerce.trade import TradeConflict, TradeRejected
from nth_dao.did_key import is_did_key
from nth_dao.util import safe_append_jsonl
from nth_dao.util.io import InterProcessLock, atomic_write_json, safe_load_json


class ProvisionalImportRejected(RuntimeError):
    """Raised when a provisional import record is invalid or conflicts."""


@dataclass(frozen=True)
class ProvisionalImport:
    order_id: str
    message_id: str
    source_did: str
    chain_head: str
    created_at_ms: int
    kind: str = "nth-commerce-provisional-import-v1"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "ProvisionalImport":
        if not isinstance(value, dict) or set(value) != set(cls.__dataclass_fields__):
            raise ProvisionalImportRejected(
                "provisional import has missing or unknown fields"
            )
        record = cls(**value)
        if record.kind != "nth-commerce-provisional-import-v1":
            raise ProvisionalImportRejected("invalid provisional import kind")
        if (
            not isinstance(record.order_id, str)
            or not record.order_id.startswith("nth-order-sha256:")
            or len(record.order_id) != 81
        ):
            raise ProvisionalImportRejected("invalid provisional order_id")
        if (
            not isinstance(record.message_id, str)
            or not record.message_id.startswith("sha256:")
            or len(record.message_id) != 71
        ):
            raise ProvisionalImportRejected("invalid provisional message_id")
        if (
            not isinstance(record.chain_head, str)
            or not record.chain_head.startswith("sha256:")
            or len(record.chain_head) != 71
        ):
            raise ProvisionalImportRejected("invalid provisional chain_head")
        try:
            bytes.fromhex(record.order_id.removeprefix("nth-order-sha256:"))
            bytes.fromhex(record.message_id.removeprefix("sha256:"))
            bytes.fromhex(record.chain_head.removeprefix("sha256:"))
        except ValueError as exc:
            raise ProvisionalImportRejected(
                "provisional import contains a non-hex digest"
            ) from exc
        if not isinstance(record.source_did, str) or not is_did_key(record.source_did):
            raise ProvisionalImportRejected("invalid provisional source_did")
        if (
            isinstance(record.created_at_ms, bool)
            or not isinstance(record.created_at_ms, int)
            or record.created_at_ms <= 0
        ):
            raise ProvisionalImportRejected("invalid provisional created_at_ms")
        return record


_LOCKS: Dict[str, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()


def _thread_lock(path: Path) -> threading.RLock:
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(str(path), threading.RLock())


class ProvisionalImportStore:
    """Track imports that have a Trade chain but no visible Order yet."""

    def __init__(self, root: str | Path) -> None:
        commerce_root = Path(root) / "commerce"
        self.root = commerce_root / "provisional_imports"
        self.quarantine_root = commerce_root / "quarantine"
        self.audit_path = commerce_root / "import_reconciliation.jsonl"
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _storage_key(order_id: str) -> str:
        return hashlib.sha256(order_id.encode("utf-8")).hexdigest()

    def _path(self, order_id: str) -> Path:
        return self.root / f"{self._storage_key(order_id)}.json"

    def _load_path(self, path: Path) -> ProvisionalImport | None:
        value = safe_load_json(path, fallback=None)
        if value is None:
            return None
        return ProvisionalImport.from_dict(value)

    def _write_locked(self, path: Path, record: ProvisionalImport) -> None:
        existing = self._load_path(path)
        if path.exists() and existing is None:
            raise ProvisionalImportRejected(
                "stored provisional import is unreadable"
            )
        if existing is not None:
            if existing != record:
                raise ProvisionalImportRejected(
                    "provisional import binding conflict"
                )
            return
        atomic_write_json(path, record.to_dict())

    def import_bundle(
        self,
        *,
        order: Any,
        trade_events: List[Dict[str, Any]],
        message_id: str,
        source_did: str,
        orders: Any,
        trades: Any,
        created_at_ms: int = 0,
    ) -> None:
        """Persist a hidden Trade then its Order under one journal lock."""
        record = ProvisionalImport.from_dict({
            "order_id": order.order_id,
            "message_id": message_id,
            "source_did": source_did,
            "chain_head": trade_chain_head(trade_events),
            "created_at_ms": created_at_ms or time.time_ns() // 1_000_000,
            "kind": "nth-commerce-provisional-import-v1",
        })
        path = self._path(record.order_id)
        with _thread_lock(path), InterProcessLock(path):
            self._write_locked(path, record)
            trades.import_verified_events(record.order_id, trade_events)
            orders.import_verified(order)
            path.unlink(missing_ok=True)

    def _audit(self, event_type: str, record: ProvisionalImport, now_ms: int) -> None:
        body = {
            "type": event_type,
            "order_id": record.order_id,
            "message_id": record.message_id,
            "source_did": record.source_did,
            "chain_head": record.chain_head,
            "recorded_at_ms": now_ms,
        }
        body["event_id"] = "sha256:" + hashlib.sha256(
            canonical_json(body)
        ).hexdigest()
        safe_append_jsonl(self.audit_path, body)

    def _quarantine_marker(self, path: Path, record: ProvisionalImport) -> None:
        destination = (
            self.quarantine_root
            / "provisional_imports"
            / f"{self._storage_key(record.order_id)}.json"
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise ProvisionalImportRejected(
                "provisional quarantine destination already exists"
            )
        os.replace(path, destination)

    def _quarantine_invalid_marker(self, path: Path, now_ms: int) -> None:
        destination = (
            self.quarantine_root
            / "invalid_provisional_imports"
            / f"{path.stem}-{now_ms}.json"
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise ProvisionalImportRejected(
                "invalid marker quarantine destination already exists"
            )
        raw = path.read_bytes()
        safe_append_jsonl(self.audit_path, {
            "type": "commerce.provisional.invalid_quarantined",
            "marker_sha256": hashlib.sha256(raw).hexdigest(),
            "recorded_at_ms": now_ms,
        })
        os.replace(path, destination)

    def reconcile(
        self,
        *,
        orders: Any,
        trades: Any,
        orphan_after_s: int,
        limit: int,
        now_ms_override: int = 0,
    ) -> Dict[str, int]:
        """Quarantine old, verified journaled Trades that still lack an Order."""
        if (
            isinstance(orphan_after_s, bool)
            or not isinstance(orphan_after_s, int)
            or orphan_after_s < 86_400
        ):
            raise ValueError("orphan_after_s must be at least 86400")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        now_ms = now_ms_override or time.time_ns() // 1_000_000
        cutoff_ms = now_ms - orphan_after_s * 1_000
        result = {
            "scanned": 0,
            "completed": 0,
            "quarantined": 0,
            "retained": 0,
            "invalid": 0,
        }
        def modified(path: Path) -> int:
            try:
                return path.stat().st_mtime_ns
            except OSError:
                return 0

        for path in sorted(self.root.glob("*.json"), key=modified)[:limit]:
            result["scanned"] += 1
            with _thread_lock(path), InterProcessLock(path):
                try:
                    record = self._load_path(path)
                except OSError:
                    result["invalid"] += 1
                    continue
                except (ProvisionalImportRejected, TypeError, ValueError):
                    self._quarantine_invalid_marker(path, now_ms)
                    result["invalid"] += 1
                    result["quarantined"] += 1
                    continue
                if record is None:
                    if not path.exists():
                        continue
                    self._quarantine_invalid_marker(path, now_ms)
                    result["invalid"] += 1
                    result["quarantined"] += 1
                    continue
                if orders.get(record.order_id) is not None:
                    self._audit("commerce.provisional.completed", record, now_ms)
                    path.unlink(missing_ok=True)
                    result["completed"] += 1
                    continue
                if record.created_at_ms > cutoff_ms:
                    result["retained"] += 1
                    continue
                events = trades.get_events(record.order_id)
                if not events:
                    self._audit("commerce.provisional.expired_empty", record, now_ms)
                    self._quarantine_marker(path, record)
                    result["quarantined"] += 1
                    continue
                try:
                    valid = trades.validate_verified_orphan(
                        record.order_id,
                        expected_chain_head=record.chain_head,
                    )
                    if not valid:
                        result["invalid"] += 1
                        continue
                except OSError:
                    result["invalid"] += 1
                    continue
                except (
                    ProvisionalImportRejected,
                    TradeConflict,
                    TradeRejected,
                    TypeError,
                    ValueError,
                ):
                    self._audit(
                        "commerce.provisional.validation_failed",
                        record,
                        now_ms,
                    )
                    self._quarantine_invalid_marker(path, now_ms)
                    result["invalid"] += 1
                    result["quarantined"] += 1
                    continue
                self._audit(
                    "commerce.provisional.orphan_quarantine_requested",
                    record,
                    now_ms,
                )
                try:
                    moved = trades.quarantine_verified_orphan(
                        record.order_id,
                        expected_chain_head=record.chain_head,
                        destination=(
                            self.quarantine_root
                            / "trades"
                            / f"{self._storage_key(record.order_id)}.json"
                        ),
                    )
                except (
                    OSError,
                    ProvisionalImportRejected,
                    TradeConflict,
                    TradeRejected,
                    TypeError,
                    ValueError,
                ):
                    result["invalid"] += 1
                    continue
                if not moved:
                    result["invalid"] += 1
                    continue
                self._quarantine_marker(path, record)
                self._audit(
                    "commerce.provisional.orphan_quarantined",
                    record,
                    now_ms,
                )
                result["quarantined"] += 1
        return result
