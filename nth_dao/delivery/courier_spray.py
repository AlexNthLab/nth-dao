"""Courier spray — replicate one sealed message across budgeted carriers.

Design doc §四 / §九: spray-and-wait. A sender may replicate one logical
message to at most ``copy_budget`` distinct carriers; when the recipient
acknowledges through ANY carrier, the remaining copies are cancelled
(outbox-level "收到任一有效 ACK 后取消其余副本").

This module provides the spray bookkeeping that survives restarts:

* :class:`CourierSpray` — registers a logical spray (message digest, the
  carrier stores it was sealed into), persisted as a JSONL journal;
* :meth:`cancel_siblings` — given one delivering carrier's ACK, cancels
  every other carrier's copy (via each store's hand_over) and marks the
  spray complete;
* :meth:`pending_sprays` — lists incomplete sprays whose envelopes may
  still be carried (hosts use this to re-spray or give up after TTL).

The spray never re-signs or re-seals: it coordinates already-sealed
envelopes produced by ``seal_courier_envelope``. Each carrier receives
its own ciphertext (per-seal ephemeral X25519 means carriers cannot even
compare notes that two copies are the same message).
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from nth_dao.canonical_json import canonical_json

logger = logging.getLogger("nth_dao.courier")

DEFAULT_MAX_SPRAYS = 1024
DEFAULT_MAX_CARRIERS_PER_SPRAY = 8
_JOURNAL = "spray.journal.jsonl"
_SPRAY_EVENTS = ("registered", "cancelled", "completed")


class CourierSprayError(RuntimeError):
    """Raised for spray bookkeeping failures."""


class CourierSpray:
    """Restart-surviving bookkeeping for spray-and-wait replication."""

    def __init__(
        self,
        directory: Union[str, Path],
        *,
        max_carriers: int = DEFAULT_MAX_CARRIERS_PER_SPRAY,
        clock: Optional[Callable[[], int]] = None,
    ) -> None:
        if isinstance(max_carriers, bool) or not isinstance(max_carriers, int) or max_carriers < 1:
            raise ValueError("max_carriers must be a positive integer")
        self._dir = Path(directory)
        self._journal_path = self._dir / _JOURNAL
        self._lock_path = self._dir / "spray.lock"
        self._max_carriers = max_carriers
        self._clock = clock or (lambda: int(time.time() * 1000))
        self._lock = threading.RLock()
        # spray_id -> {"carriers": {carrier_name: courier_dict}, "status": str}
        self._sprays: Dict[str, Dict[str, Any]] = {}
        self._dir.mkdir(parents=True, exist_ok=True)
        self._load()

    # ─────────────────────── persistence ───────────────────────

    def _load(self) -> None:
        if not self._journal_path.exists():
            return
        raw = self._journal_path.read_bytes()
        torn = bool(raw) and not raw.endswith(b"\n")
        lines = raw.split(b"\n")
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            if index == len(lines) - 1 and torn:
                logger.warning("spray journal has a torn final line; ignoring it")
                break
            try:
                event = json.loads(line.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise CourierSprayError(
                    f"corrupt spray journal line {index + 1}: {exc}"
                ) from exc
            kind = event.get("event")
            if kind not in _SPRAY_EVENTS:
                raise CourierSprayError(f"unknown spray journal event: {kind!r}")
            spray_id = event.get("spray_id", "")
            if kind == "registered":
                # journals hold digests, not ciphertexts: after a restart the
                # in-memory carriers are empty and cancel_siblings records
                # cancellations without store operations (the stores already
                # dropped or will drop via their own TTL)
                self._sprays[spray_id] = {
                    "carriers": {},
                    "journal_carriers": set(event.get("carrier_digests", {})),
                    "message_id": event.get("message_id", ""),
                    "status": "pending",
                    "created_at_ms": event.get("created_at_ms", 0),
                }
            elif kind == "cancelled":
                spray = self._sprays.get(spray_id)
                if spray is not None:
                    spray["carriers"].pop(event.get("carrier", ""), None)
            elif kind == "completed":
                spray = self._sprays.get(spray_id)
                if spray is not None:
                    spray["status"] = "completed"

    def _append(self, event: Dict[str, Any]) -> None:
        with _file_lock(self._lock_path):
            with open(self._journal_path, "ab") as handle:
                handle.write(canonical_json(event) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())

    # ─────────────────────── spray operations ───────────────────────

    def register(
        self,
        *,
        message_id: str,
        carrier_copies: Dict[str, Dict[str, Any]],
    ) -> str:
        """Register one spray: message_id → {carrier_name: courier envelope}.

        The caller seals one fresh envelope per carrier (distinct
        ciphertexts) and hands the mapping here. At most ``max_carriers``
        carriers per spray.
        """

        if not isinstance(message_id, str) or not message_id:
            raise CourierSprayError("message_id is required")
        if not isinstance(carrier_copies, dict) or not carrier_copies:
            raise CourierSprayError("carrier_copies must be a non-empty mapping")
        if len(carrier_copies) > self._max_carriers:
            raise CourierSprayError(
                f"at most {self._max_carriers} carriers per spray, got {len(carrier_copies)}"
            )
        with self._lock:
            spray_id = "spray-" + secrets.token_hex(8)
            while spray_id in self._sprays:
                spray_id = "spray-" + secrets.token_hex(8)
            # journal records DIGESTS only (round-22 bug JJ-1: the full
            # courier ciphertexts in a local journal multiplied the
            # sensitive-material copies for no operational need)
            event = {
                "event": "registered",
                "spray_id": spray_id,
                "message_id": message_id,
                "carrier_digests": {
                    name: "sha256:" + __import__("hashlib").sha256(
                        canonical_json(courier)
                    ).hexdigest()
                    for name, courier in carrier_copies.items()
                },
                "created_at_ms": self._clock(),
            }
            self._append(event)
            self._sprays[spray_id] = {
                "carriers": dict(carrier_copies),  # memory only
                "journal_carriers": set(carrier_copies),
                "message_id": message_id,
                "status": "pending",
                "created_at_ms": event["created_at_ms"],
            }
            return spray_id

    def cancel_siblings(
        self,
        spray_id: str,
        *,
        delivering_carrier: str,
        carrier_stores: Dict[str, Any],
    ) -> int:
        """Cancel every sibling copy after one carrier delivered.

        ``carrier_stores`` maps carrier_name → CourierStore. Every carrier
        other than ``delivering_carrier`` that still holds the sprayed
        envelope gets it handed over (removed). Returns the number of
        cancelled copies. Marks the spray completed.
        """

        with self._lock:
            spray = self._sprays.get(spray_id)
            if spray is None:
                raise CourierSprayError(f"unknown spray: {spray_id}")
            if spray["status"] == "completed":
                return 0
            cancelled = 0
            sprayed_names = set(spray["carriers"]) | set(
                spray.get("journal_carriers", set())
            )
            for carrier_name in sorted(sprayed_names):
                if carrier_name == delivering_carrier:
                    continue
                courier = spray["carriers"].get(carrier_name)
                store = carrier_stores.get(carrier_name)
                if courier is None or store is None:
                    # unknown store: still record the cancellation so the
                    # spray bookkeeping reflects the intent
                    self._append({
                        "event": "cancelled",
                        "spray_id": spray_id,
                        "carrier": carrier_name,
                    })
                    spray["carriers"].pop(carrier_name, None)
                    cancelled += 1
                    continue
                try:
                    store.hand_over(courier)
                except Exception:  # noqa: BLE001 - already delivered/absent
                    pass
                self._append({
                    "event": "cancelled",
                    "spray_id": spray_id,
                    "carrier": carrier_name,
                })
                spray["carriers"].pop(carrier_name, None)
                cancelled += 1
            self._append({"event": "completed", "spray_id": spray_id})
            spray["status"] = "completed"
            return cancelled

    def pending_sprays(self) -> List[Dict[str, Any]]:
        """List incomplete sprays (hosts re-spray or give up after TTL)."""

        with self._lock:
            return [
                {
                    "spray_id": spray_id,
                    "message_id": spray["message_id"],
                    "carriers": list(spray["carriers"]),
                    "created_at_ms": spray["created_at_ms"],
                }
                for spray_id, spray in self._sprays.items()
                if spray["status"] == "pending"
            ]

    def stats(self) -> Dict[str, int]:
        with self._lock:
            pending = sum(1 for s in self._sprays.values() if s["status"] == "pending")
            return {"sprays": len(self._sprays), "pending": pending}


class _FileLock:
    def __init__(self, path: Path) -> None:
        import fcntl

        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(path, "a+")
        fcntl.flock(self._fh, fcntl.LOCK_EX)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        import fcntl

        fcntl.flock(self._fh, fcntl.LOCK_UN)
        self._fh.close()


def _file_lock(path: Path) -> "_FileLock":
    return _FileLock(path)


__all__ = [
    "DEFAULT_MAX_CARRIERS_PER_SPRAY",
    "CourierSpray",
    "CourierSprayError",
]
