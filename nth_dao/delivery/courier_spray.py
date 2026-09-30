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

import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from nth_dao.canonical_json import canonical_json
from nth_dao.util.io import InterProcessLock, atomic_write_bytes

logger = logging.getLogger("nth_dao.courier")

DEFAULT_MAX_SPRAYS = 1024
DEFAULT_MAX_CARRIERS_PER_SPRAY = 8
MAX_MESSAGE_ID_BYTES = 256
MAX_CARRIER_NAME_BYTES = 128
_JOURNAL = "spray.journal.jsonl"
_JOURNAL_MAX_BYTES = 8 * 1024 * 1024
_JOURNAL_RECOVERY_SLACK_BYTES = 64 * 1024
_SPRAY_EVENTS = ("registered", "delivered", "cancelled", "completed")
_SPRAY_ID_RE = re.compile(r"\Aspray-[0-9a-f]{16}\Z")
_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")


class CourierSprayError(RuntimeError):
    """Raised for spray bookkeeping failures."""


class CourierSpray:
    """Restart-surviving bookkeeping for spray-and-wait replication."""

    def __init__(
        self,
        directory: str | Path,
        *,
        max_carriers: int = DEFAULT_MAX_CARRIERS_PER_SPRAY,
        max_sprays: int = DEFAULT_MAX_SPRAYS,
        max_history: int = DEFAULT_MAX_SPRAYS,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if isinstance(max_carriers, bool) or not isinstance(max_carriers, int) or max_carriers < 1:
            raise ValueError("max_carriers must be a positive integer")
        if isinstance(max_sprays, bool) or not isinstance(max_sprays, int) or max_sprays < 1:
            raise ValueError("max_sprays must be a positive integer")
        if isinstance(max_history, bool) or not isinstance(max_history, int) or max_history < 1:
            raise ValueError("max_history must be a positive integer")
        self._dir = Path(directory)
        self._journal_path = self._dir / _JOURNAL
        self._lock_target = self._dir / "spray"
        self._max_carriers = max_carriers
        self._max_sprays = max_sprays
        self._max_history = max_history
        self._clock = clock or (lambda: int(time.time() * 1000))
        self._lock = threading.RLock()
        # spray_id -> {"carriers": {carrier_name: courier_dict}, "status": str}
        self._sprays: dict[str, dict[str, Any]] = {}
        self._dir.mkdir(parents=True, exist_ok=True)
        with self._lock, InterProcessLock(
            self._lock_target, timeout=10.0, poll=0.01
        ):
            self._refresh_from_disk_locked()

    # ─────────────────────── persistence ───────────────────────

    def _load(self) -> None:
        if not self._journal_path.exists():
            return
        raw = self._read_journal_bounded()
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
            if not isinstance(event, dict):
                raise CourierSprayError(
                    f"spray journal line {index + 1} is not an object"
                )
            kind = event.get("event")
            if kind not in _SPRAY_EVENTS:
                raise CourierSprayError(f"unknown spray journal event: {kind!r}")
            spray_id = event.get("spray_id")
            if not isinstance(spray_id, str) or _SPRAY_ID_RE.fullmatch(spray_id) is None:
                raise CourierSprayError(
                    f"invalid {kind} event spray_id on line {index + 1}"
                )
            if kind == "registered":
                if set(event) != {
                    "event",
                    "spray_id",
                    "message_id",
                    "carrier_digests",
                    "created_at_ms",
                }:
                    raise CourierSprayError(
                        f"invalid registered event fields on line {index + 1}"
                    )
                if spray_id in self._sprays:
                    raise CourierSprayError(
                        f"duplicate registered event on line {index + 1}"
                    )
                message_id = event.get("message_id")
                if not isinstance(message_id, str):
                    raise CourierSprayError(
                        f"invalid registered event message_id on line {index + 1}"
                    )
                self._validate_text(
                    message_id,
                    field="registered event message_id",
                    max_bytes=MAX_MESSAGE_ID_BYTES,
                )
                carrier_digests = event.get("carrier_digests")
                if (
                    not isinstance(carrier_digests, dict)
                    or not carrier_digests
                    or len(carrier_digests) > self._max_carriers
                ):
                    raise CourierSprayError(
                        f"invalid registered event carrier_digests on line {index + 1}"
                    )
                validated_digests: dict[str, str] = {}
                for carrier, digest in carrier_digests.items():
                    if not isinstance(carrier, str) or not isinstance(digest, str):
                        raise CourierSprayError(
                            f"invalid registered event digest on line {index + 1}"
                        )
                    self._validate_text(
                        carrier,
                        field="registered event carrier name",
                        max_bytes=MAX_CARRIER_NAME_BYTES,
                    )
                    if _DIGEST_RE.fullmatch(digest) is None:
                        raise CourierSprayError(
                            f"invalid registered event digest on line {index + 1}"
                        )
                    validated_digests[carrier] = digest
                created_at_ms = event.get("created_at_ms")
                if (
                    isinstance(created_at_ms, bool)
                    or not isinstance(created_at_ms, int)
                    or created_at_ms < 1
                ):
                    raise CourierSprayError(
                        f"invalid registered event created_at_ms on line {index + 1}"
                    )
                self._sprays[spray_id] = {
                    "carriers": {},
                    "carrier_digests": dict(validated_digests),
                    "all_carrier_digests": dict(validated_digests),
                    "message_id": message_id,
                    "status": "pending",
                    "created_at_ms": created_at_ms,
                }
            elif kind in {"delivered", "cancelled"}:
                if set(event) != {"event", "spray_id", "carrier"}:
                    raise CourierSprayError(
                        f"invalid {kind} event fields on line {index + 1}"
                    )
                spray = self._sprays.get(spray_id)
                if spray is None:
                    raise CourierSprayError(
                        f"{kind} event references unknown spray on line {index + 1}"
                    )
                carrier = event.get("carrier")
                if not isinstance(carrier, str):
                    raise CourierSprayError(
                        f"invalid {kind} event carrier name on line {index + 1}"
                    )
                self._validate_text(
                    carrier,
                    field=f"{kind} event carrier name",
                    max_bytes=MAX_CARRIER_NAME_BYTES,
                )
                spray["carriers"].pop(carrier, None)
                spray["carrier_digests"].pop(carrier, None)
            elif kind == "completed":
                if set(event) != {"event", "spray_id"}:
                    raise CourierSprayError(
                        f"invalid completed event fields on line {index + 1}"
                    )
                spray = self._sprays.get(spray_id)
                if spray is None:
                    raise CourierSprayError(
                        f"completed event references unknown spray on line {index + 1}"
                    )
                spray["status"] = "completed"

    def _read_journal_bounded(self) -> bytes:
        limit = _JOURNAL_MAX_BYTES + _JOURNAL_RECOVERY_SLACK_BYTES
        with open(self._journal_path, "rb") as handle:
            raw = handle.read(limit + 1)
        if len(raw) > limit:
            raise CourierSprayError(
                "spray journal exceeds the bounded crash-recovery limit"
            )
        return raw

    def _refresh_from_disk_locked(self) -> None:
        self._sprays = {}
        self._load()
        pruned = self._prune_completed_locked()
        oversized = (
            self._journal_path.exists()
            and self._journal_path.stat().st_size > _JOURNAL_MAX_BYTES
        )
        if pruned or oversized:
            self._compact_locked()

    def _prune_completed_locked(self) -> bool:
        completed = [
            spray_id
            for spray_id, spray in self._sprays.items()
            if spray["status"] == "completed"
        ]
        excess = len(completed) - self._max_history
        for spray_id in completed[:max(0, excess)]:
            self._sprays.pop(spray_id, None)
        return excess > 0

    def _snapshot_bytes(self) -> bytes:
        snapshot = bytearray()
        for spray_id, spray in self._sprays.items():
            all_digests = dict(spray["all_carrier_digests"])
            events = [{
                "event": "registered",
                "spray_id": spray_id,
                "message_id": spray["message_id"],
                "carrier_digests": all_digests,
                "created_at_ms": spray["created_at_ms"],
            }]
            unresolved = set(spray["carrier_digests"])
            events.extend(
                {
                    "event": "cancelled",
                    "spray_id": spray_id,
                    "carrier": carrier,
                }
                for carrier in sorted(set(all_digests) - unresolved)
            )
            if spray["status"] == "completed":
                events.append({"event": "completed", "spray_id": spray_id})
            for event in events:
                snapshot.extend(canonical_json(event))
                snapshot.extend(b"\n")
                if len(snapshot) > _JOURNAL_MAX_BYTES:
                    raise CourierSprayError(
                        "live spray state exceeds the journal size limit"
                    )
        return bytes(snapshot)

    def _compact_locked(self) -> None:
        atomic_write_bytes(self._journal_path, self._snapshot_bytes())

    def compact(self) -> None:
        """Atomically compact the journal while preserving live state."""

        with self._lock, InterProcessLock(
            self._lock_target, timeout=10.0, poll=0.01
        ):
            self._sprays = {}
            self._load()
            self._prune_completed_locked()
            self._compact_locked()

    def _append(self, event: dict[str, Any]) -> None:
        with InterProcessLock(self._lock_target, timeout=10.0, poll=0.01):
            self._append_record_locked(event)

    def _append_record_locked(self, event: dict[str, Any]) -> None:
        with open(self._journal_path, "ab") as handle:
            handle.write(canonical_json(event) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())

    @staticmethod
    def _validate_text(value: str, *, field: str, max_bytes: int) -> None:
        if not isinstance(value, str) or not value:
            raise CourierSprayError(f"{field} is required")
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise CourierSprayError(f"{field} is not valid UTF-8 text") from exc
        if len(encoded) > max_bytes:
            raise CourierSprayError(f"{field} exceeds {max_bytes} UTF-8 bytes")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
            raise CourierSprayError(f"{field} must not contain control characters")

    # ─────────────────────── spray operations ───────────────────────

    def register(
        self,
        *,
        message_id: str,
        carrier_copies: dict[str, dict[str, Any]],
    ) -> str:
        """Register one spray: message_id → {carrier_name: courier envelope}.

        The caller seals one fresh envelope per carrier (distinct
        ciphertexts) and hands the mapping here. At most ``max_carriers``
        carriers per spray.
        """

        self._validate_text(
            message_id,
            field="message_id",
            max_bytes=MAX_MESSAGE_ID_BYTES,
        )
        if not isinstance(carrier_copies, dict) or not carrier_copies:
            raise CourierSprayError("carrier_copies must be a non-empty mapping")
        if len(carrier_copies) > self._max_carriers:
            raise CourierSprayError(
                f"at most {self._max_carriers} carriers per spray, got {len(carrier_copies)}"
            )
        for carrier_name in carrier_copies:
            self._validate_text(
                carrier_name,
                field="carrier name",
                max_bytes=MAX_CARRIER_NAME_BYTES,
            )
        from nth_dao.delivery.courier import (
            CourierEnvelopeRejected,
            validate_courier_wire,
        )

        for carrier_name, courier in carrier_copies.items():
            try:
                validate_courier_wire(courier)
            except CourierEnvelopeRejected as exc:
                raise CourierSprayError(
                    f"invalid carrier copy for {carrier_name}: {exc}"
                ) from exc
        with self._lock, InterProcessLock(
            self._lock_target, timeout=10.0, poll=0.01
        ):
            # Refresh while holding the same inter-process lock used for the
            # append. Otherwise two stale instances can both pass the cap.
            self._refresh_from_disk_locked()
            pending = sum(
                1 for spray in self._sprays.values() if spray["status"] == "pending"
            )
            if pending >= self._max_sprays:
                raise CourierSprayError("pending-spray quota exhausted")
            spray_id = "spray-" + secrets.token_hex(8)
            while spray_id in self._sprays:
                spray_id = "spray-" + secrets.token_hex(8)
            # journal records DIGESTS only (round-22 bug JJ-1: the full
            # courier ciphertexts in a local journal multiplied the
            # sensitive-material copies for no operational need)
            carrier_digests = {
                name: "sha256:"
                + hashlib.sha256(canonical_json(courier)).hexdigest()
                for name, courier in carrier_copies.items()
            }
            created_at_ms = self._clock()
            if (
                isinstance(created_at_ms, bool)
                or not isinstance(created_at_ms, int)
                or created_at_ms < 1
            ):
                raise CourierSprayError("clock must return a positive integer")
            event: dict[str, Any] = {
                "event": "registered",
                "spray_id": spray_id,
                "message_id": message_id,
                "carrier_digests": carrier_digests,
                "created_at_ms": created_at_ms,
            }
            self._append_record_locked(event)
            self._sprays[spray_id] = {
                "carriers": dict(carrier_copies),  # memory only
                "carrier_digests": dict(carrier_digests),
                "all_carrier_digests": dict(carrier_digests),
                "message_id": message_id,
                "status": "pending",
                "created_at_ms": created_at_ms,
            }
            return spray_id

    def cancel_siblings(
        self,
        spray_id: str,
        *,
        delivering_carrier: str,
        carrier_stores: dict[str, Any],
    ) -> int:
        """Cancel every sibling copy after one carrier delivered.

        ``carrier_stores`` maps carrier_name → CourierStore. Every carrier
        other than ``delivering_carrier`` that still holds the sprayed
        envelope gets it handed over (removed). Returns the number of
        cancelled copies. Marks the spray completed.
        """

        with self._lock:
            with InterProcessLock(
                self._lock_target, timeout=10.0, poll=0.01
            ):
                self._refresh_from_disk_locked()
            spray = self._sprays.get(spray_id)
            if spray is None:
                raise CourierSprayError(f"unknown spray: {spray_id}")
            if spray["status"] == "completed":
                return 0
            if (
                delivering_carrier in spray["carriers"]
                or delivering_carrier in spray["carrier_digests"]
            ):
                self._append({
                    "event": "delivered",
                    "spray_id": spray_id,
                    "carrier": delivering_carrier,
                })
                spray["carriers"].pop(delivering_carrier, None)
                spray["carrier_digests"].pop(delivering_carrier, None)
            cancelled = 0
            sprayed_names = set(spray["carriers"]) | set(spray["carrier_digests"])
            for carrier_name in sorted(sprayed_names):
                courier = spray["carriers"].get(carrier_name)
                store = carrier_stores.get(carrier_name)
                if store is None:
                    # An uncontacted carrier remains pending. Recording an
                    # imaginary cancellation would make live copies orphaned.
                    continue
                try:
                    digest = spray["carrier_digests"].get(carrier_name, "")
                    if hasattr(store, "discard_digest") and digest:
                        store.discard_digest(digest)
                    elif courier is not None:
                        store.hand_over(courier)
                    else:
                        continue
                except (OSError, RuntimeError) as exc:
                    logger.warning(
                        "could not cancel spray %s on carrier %s: %s",
                        spray_id,
                        carrier_name,
                        exc,
                    )
                    continue
                self._append({
                    "event": "cancelled",
                    "spray_id": spray_id,
                    "carrier": carrier_name,
                })
                spray["carriers"].pop(carrier_name, None)
                spray["carrier_digests"].pop(carrier_name, None)
                cancelled += 1
            if not spray["carriers"] and not spray["carrier_digests"]:
                self._append({"event": "completed", "spray_id": spray_id})
                spray["status"] = "completed"
            return cancelled

    def pending_sprays(self) -> list[dict[str, Any]]:
        """List incomplete sprays (hosts re-spray or give up after TTL)."""

        with self._lock, InterProcessLock(
            self._lock_target, timeout=10.0, poll=0.01
        ):
            self._refresh_from_disk_locked()
            return [
                {
                    "spray_id": spray_id,
                    "message_id": spray["message_id"],
                    "carriers": sorted(
                        set(spray["carriers"]) | set(spray["carrier_digests"])
                    ),
                    "created_at_ms": spray["created_at_ms"],
                }
                for spray_id, spray in self._sprays.items()
                if spray["status"] == "pending"
            ]

    def stats(self) -> dict[str, int]:
        with self._lock, InterProcessLock(
            self._lock_target, timeout=10.0, poll=0.01
        ):
            self._refresh_from_disk_locked()
            pending = sum(1 for s in self._sprays.values() if s["status"] == "pending")
            return {"sprays": len(self._sprays), "pending": pending}


__all__ = [
    "DEFAULT_MAX_CARRIERS_PER_SPRAY",
    "DEFAULT_MAX_SPRAYS",
    "CourierSpray",
    "CourierSprayError",
]
