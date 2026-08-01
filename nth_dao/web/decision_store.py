"""Durable, process-safe queue for operator decisions."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from nth_dao.util.io import InterProcessLock


class DecisionNotFound(KeyError):
    """The requested decision is not pending."""


class DecisionConflict(RuntimeError):
    """A different pending decision already owns the same identifier."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _encode(decision: Dict[str, Any]) -> str:
    return json.dumps(
        decision,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


@dataclass
class DecisionResolution:
    decision: Dict[str, Any]
    action: str = ""
    receipt_id: str = ""

    def complete(self, action: str, *, receipt_id: str = "") -> None:
        if action not in {"approved", "rejected", "deferred"}:
            raise ValueError(f"unsupported decision action: {action}")
        self.action = action
        self.receipt_id = str(receipt_id or "")


class DecisionStore:
    """SQLite-backed pending queue with an append-only event projection."""

    def __init__(self, workspace: Path, *, timeout: float = 10.0) -> None:
        root = Path(workspace) / "decisions"
        root.mkdir(parents=True, exist_ok=True)
        self.path = root / "decisions.sqlite3"
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise TypeError("timeout must be a positive number")
        self.timeout = float(timeout)
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        # SQLite serializes data transactions, but concurrent first-open DDL
        # and journal-mode negotiation can still fail immediately on Windows.
        # One durable lock covers initialization across threads and processes.
        with InterProcessLock(root / ".initialize", timeout=self.timeout):
            self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.path),
            timeout=self.timeout,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            f"PRAGMA busy_timeout = {max(1, int(self.timeout * 1_000))}"
        )
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS decisions (
                    decision_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    raised_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS decision_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_kind TEXT NOT NULL,
                    decision_id TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    receipt_id TEXT NOT NULL DEFAULT ''
                )
                """
            )

    @staticmethod
    def _decode(payload_json: str) -> Dict[str, Any]:
        payload = json.loads(payload_json)
        if not isinstance(payload, dict):
            raise ValueError("stored decision payload is not an object")
        return payload

    def put(self, decision: Dict[str, Any]) -> None:
        decision_id = str(decision.get("id") or "").strip()
        if not decision_id:
            raise ValueError("decision id is required")
        if len(decision_id) > 200:
            raise ValueError("decision id exceeds 200 characters")
        normalized = dict(decision)
        normalized["id"] = decision_id
        payload_json = _encode(normalized)
        if len(payload_json.encode("utf-8")) > 256 * 1024:
            raise ValueError("decision payload exceeds 256 KiB")
        payload_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        raised_at = str(normalized.get("raised_at") or _now())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT payload_hash FROM decisions WHERE decision_id = ?",
                (decision_id,),
            ).fetchone()
            if existing is not None:
                if existing["payload_hash"] != payload_hash:
                    connection.rollback()
                    raise DecisionConflict(
                        f"decision id {decision_id!r} already exists"
                    )
                connection.commit()
                return
            connection.execute(
                """
                INSERT INTO decisions (
                    decision_id, payload_json, payload_hash, raised_at
                ) VALUES (?, ?, ?, ?)
                """,
                (decision_id, payload_json, payload_hash, raised_at),
            )
            connection.execute(
                """
                INSERT INTO decision_events (
                    event_kind, decision_id, occurred_at, payload_hash
                ) VALUES ('decision.raised', ?, ?, ?)
                """,
                (decision_id, _now(), payload_hash),
            )
            connection.commit()

    def get(
        self, decision_id: str, default: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM decisions WHERE decision_id = ?",
                (decision_id,),
            ).fetchone()
        return default if row is None else self._decode(row["payload_json"])

    def values(self) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload_json FROM decisions
                ORDER BY raised_at ASC, decision_id ASC
                """
            ).fetchall()
        return [self._decode(row["payload_json"]) for row in rows]

    def complete(
        self,
        decision_id: str,
        action: str,
        *,
        receipt_id: str = "",
    ) -> Dict[str, Any]:
        """Atomically remove one pending item and append its outcome event."""

        if action not in {"approved", "rejected", "deferred"}:
            raise ValueError(f"unsupported decision action: {action}")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT payload_json, payload_hash
                FROM decisions WHERE decision_id = ?
                """,
                (decision_id,),
            ).fetchone()
            if row is None:
                raise DecisionNotFound(decision_id)
            connection.execute(
                "DELETE FROM decisions WHERE decision_id = ?",
                (decision_id,),
            )
            connection.execute(
                """
                INSERT INTO decision_events (
                    event_kind, decision_id, occurred_at, payload_hash,
                    receipt_id
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    f"decision.{action}",
                    decision_id,
                    _now(),
                    row["payload_hash"],
                    str(receipt_id or ""),
                ),
            )
            connection.commit()
        return self._decode(row["payload_json"])

    @contextmanager
    def resolution(self, decision_id: str) -> Iterator[DecisionResolution]:
        """Lock, resolve, and remove one decision in a single transaction."""

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT payload_json, payload_hash
                FROM decisions WHERE decision_id = ?
                """,
                (decision_id,),
            ).fetchone()
            if row is None:
                raise DecisionNotFound(decision_id)
            resolution = DecisionResolution(self._decode(row["payload_json"]))
            yield resolution
            if not resolution.action:
                connection.rollback()
                return
            deleted = connection.execute(
                "DELETE FROM decisions WHERE decision_id = ?",
                (decision_id,),
            ).rowcount
            if deleted != 1:
                raise DecisionNotFound(decision_id)
            connection.execute(
                """
                INSERT INTO decision_events (
                    event_kind, decision_id, occurred_at, payload_hash,
                    receipt_id
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    f"decision.{resolution.action}",
                    decision_id,
                    _now(),
                    row["payload_hash"],
                    resolution.receipt_id,
                ),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def events(self) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT sequence, event_kind, decision_id, occurred_at,
                       payload_hash, receipt_id
                FROM decision_events ORDER BY sequence ASC
                """
            ).fetchall()
        return [dict(row) for row in rows]


__all__ = [
    "DecisionConflict",
    "DecisionNotFound",
    "DecisionResolution",
    "DecisionStore",
]
