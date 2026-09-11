"""Courier store — quota-bounded pool of sealed envelopes for a carrier.

Design doc §9: a courier carries sealed envelopes under hard limits so a
hostile or careless carrier cannot exhaust its storage, and so recipients
get predictable handover behavior:

* **Quota** — total ciphertext bytes and per-source-envelopes are capped
  (fail closed on overflow; the SENDER is told the carrier is full).
* **Spray-and-wait** — a sender may replicate one logical message to
  ``copy_budget`` distinct carriers; delivery to the recipient cancels the
  other copies (outbox-level, per the design doc "收到任一有效 ACK 后取消
  其余副本").
* **TTL** — envelopes expire; expired entries are dropped at sweep time.
* **Handover** — a receiving node drains every envelope addressed to it,
  acknowledging each (removing it from the pool) only after the envelope
  has been successfully opened and validated.
* **Persistence** — the pool is a JSONL journal (same crash-safety pattern
  as the outbox: fsync per event, torn-tail tolerated, atomic rotation).
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
from nth_dao.did_key import is_did_key

logger = logging.getLogger("nth_dao.courier")

DEFAULT_MAX_TOTAL_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_PER_RECIPIENT = 64
DEFAULT_MAX_ENVELOPES = 512
_JOURNAL = "courier.journal.jsonl"
_JOURNAL_MAX_BYTES = 32 * 1024 * 1024


class CourierStoreError(RuntimeError):
    """Raised for courier store operational failures."""


class CourierStoreFull(CourierStoreError):
    """Raised when the carrier's quota is exhausted (fail closed)."""


class CourierStore:
    """Quota-bounded pool of sealed courier envelopes on one carrier."""

    def __init__(
        self,
        directory: Union[str, Path],
        *,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
        max_per_recipient: int = DEFAULT_MAX_PER_RECIPIENT,
        max_envelopes: int = DEFAULT_MAX_ENVELOPES,
        clock: Optional[Callable[[], int]] = None,
    ) -> None:
        for name, value in (
            ("max_total_bytes", max_total_bytes),
            ("max_per_recipient", max_per_recipient),
            ("max_envelopes", max_envelopes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        self._dir = Path(directory)
        self._journal_path = self._dir / _JOURNAL
        self._lock_path = self._dir / "courier.lock"
        self._max_total_bytes = max_total_bytes
        self._max_per_recipient = max_per_recipient
        self._max_envelopes = max_envelopes
        self._clock = clock or (lambda: int(time.time() * 1000))
        self._lock = threading.RLock()
        # digest → (envelope dict, sealed_at_ms)
        self._pool: Dict[str, Dict[str, Any]] = {}
        self._pool_order: List[str] = []
        self._dir.mkdir(parents=True, exist_ok=True)
        self._load()

    # ─────────────────────── persistence ───────────────────────

    def _load(self) -> None:
        """Constructor-time load (rotation allowed — no lock held)."""

        if not self._journal_path.exists():
            return
        if self._journal_path.stat().st_size > _JOURNAL_MAX_BYTES:
            self._rotate_from_memory()
            return
        pool, order = self._parse_journal(self._journal_path.read_bytes())
        self._pool = pool
        self._pool_order = order

    @staticmethod
    def _parse_journal(raw: bytes) -> "tuple[Dict[str, Dict[str, Any]], List[str]]":
        """Parse journal bytes into (pool, order); no side effects, no locks
        (usable under the file lock without deadlocking)."""

        pool: Dict[str, Dict[str, Any]] = {}
        order: List[str] = []
        torn = bool(raw) and not raw.endswith(b"\n")
        lines = raw.split(b"\n")
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            if index == len(lines) - 1 and torn:
                logger.warning("courier journal has a torn final line; ignoring it")
                break
            try:
                event = json.loads(line.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise CourierStoreError(
                    f"corrupt courier journal line {index + 1}: {exc}"
                ) from exc
            kind = event.get("event")
            if kind == "sealed":
                digest = event.get("digest", "")
                pool[digest] = event.get("envelope", {})
                order.append(digest)
            elif kind == "handed_over":
                digest = event.get("digest", "")
                pool.pop(digest, None)
                if digest in order:
                    order.remove(digest)
            else:
                raise CourierStoreError(f"unknown courier journal event: {kind!r}")
        return pool, order

    def _append(self, event: Dict[str, Any]) -> None:
        with self._acquire_file_lock():
            with open(self._journal_path, "ab") as handle:
                handle.write(canonical_json(event) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        if (
            self._journal_path.exists()
            and self._journal_path.stat().st_size > _JOURNAL_MAX_BYTES
        ):
            self._rotate_from_memory()

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

    def _acquire_file_lock(self):
        return self._FileLock(self._lock_path)

    def _rotate_from_memory(self) -> None:
        """Rewrite the journal holding only live entries (lossless)."""

        tmp = self._journal_path.with_suffix(f".jsonl.{secrets.token_hex(4)}.tmp")
        with self._acquire_file_lock():
            with open(tmp, "wb") as handle:
                for digest in self._pool_order:
                    if digest in self._pool:
                        handle.write(canonical_json({
                            "event": "sealed",
                            "digest": digest,
                            "envelope": self._pool[digest],
                        }) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._journal_path)
        logger.warning("courier journal rotated; %d live entries", len(self._pool_order))

    # ─────────────────────── pool operations ───────────────────────

    def seal_into(
        self,
        courier: Dict[str, Any],
        *,
        now_ms: Optional[int] = None,
    ) -> str:
        """Admit one sealed envelope into the pool; return its digest.

        Fails closed with :class:`CourierStoreFull` when any quota is hit.
        """

        from nth_dao.delivery.courier import COURIER_FIELDS

        if not isinstance(courier, dict) or frozenset(courier) != frozenset(COURIER_FIELDS):
            raise CourierStoreError("courier envelope has missing or unknown fields")
        now = self._clock() if now_ms is None else now_ms
        digest = "sha256:" + __import__("hashlib").sha256(
            canonical_json(courier)
        ).hexdigest()
        ciphertext = courier.get("ciphertext", "")
        envelope_bytes = (len(ciphertext) * 3) // 4  # b64url expansion
        with self._lock, self._acquire_file_lock():
            # cross-process quota enforcement (round-23 bug KK-9): re-parse
            # the journal under the file lock (pure parse — no rotation, so
            # no second-lock deadlock) so the check sees every process's
            # envelopes
            if self._journal_path.exists():
                disk_pool, disk_order = self._parse_journal(
                    self._journal_path.read_bytes()
                )
                self._pool = disk_pool
                self._pool_order = disk_order
            if digest in self._pool:
                return digest  # idempotent re-offer
            current_bytes = sum(
                (len(e.get("ciphertext", "")) * 3) // 4 for e in self._pool.values()
            )
            if current_bytes + envelope_bytes > self._max_total_bytes:
                raise CourierStoreFull("carrier total-bytes quota exhausted")
            if len(self._pool) >= self._max_envelopes:
                raise CourierStoreFull("carrier envelope-count quota exhausted")
            recipient = courier.get("recipient_did", "")
            per_recipient = sum(
                1
                for e in self._pool.values()
                if e.get("recipient_did") == recipient
            )
            if per_recipient >= self._max_per_recipient:
                raise CourierStoreFull(
                    f"per-recipient quota exhausted for {recipient[:24]}..."
                )
            event = {
                "event": "sealed",
                "digest": digest,
                "envelope": courier,
                "sealed_at_ms": now,
            }
            # write INLINE under the already-held file lock — calling
            # _append() here would re-acquire the same flock on a new fd
            # and deadlock (round-23 review)
            with open(self._journal_path, "ab") as handle:
                handle.write(canonical_json(event) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._pool[digest] = courier
            self._pool_order.append(digest)
            journal_bytes = (
                self._journal_path.stat().st_size
                if self._journal_path.exists()
                else 0
            )
        # rotation (which takes the file lock fresh) runs OUTSIDE the held
        # lock so it can never self-deadlock
        if journal_bytes > _JOURNAL_MAX_BYTES:
            self._rotate_from_memory()
        return digest

    def drain_for(
        self,
        recipient_did: str,
        *,
        max_items: int = 64,
    ) -> List[Dict[str, Any]]:
        """List envelopes addressed to one recipient.

        TTL is NOT filtered here: expiration is the opening side's decision
        (the courier may not know the true wall clock), enforced by
        ``open_courier_envelope``'s now_ms check."""

        if not is_did_key(recipient_did):
            raise CourierStoreError("recipient_did must be a did:key")
        with self._lock:
            out: List[Dict[str, Any]] = []
            for digest in list(self._pool_order):
                envelope = self._pool.get(digest)
                if envelope is None:
                    continue
                if envelope.get("recipient_did") != recipient_did:
                    continue
                out.append(envelope)
                if len(out) >= max_items:
                    break
            return out

    def hand_over(self, courier: Dict[str, Any]) -> None:
        """Remove one envelope after successful handover (open + validate)."""

        digest = "sha256:" + __import__("hashlib").sha256(
            canonical_json(courier)
        ).hexdigest()
        with self._lock:
            if digest not in self._pool:
                raise CourierStoreError("hand_over: envelope not in pool")
            self._append({"event": "handed_over", "digest": digest})
            self._pool.pop(digest, None)
            if digest in self._pool_order:
                self._pool_order.remove(digest)

    def stats(self) -> Dict[str, int]:
        with self._lock:
            total_bytes = sum(
                (len(e.get("ciphertext", "")) * 3) // 4 for e in self._pool.values()
            )
            return {
                "envelopes": len(self._pool),
                "total_bytes": total_bytes,
            }


__all__ = [
    "DEFAULT_MAX_ENVELOPES",
    "DEFAULT_MAX_PER_RECIPIENT",
    "DEFAULT_MAX_TOTAL_BYTES",
    "CourierStore",
    "CourierStoreError",
    "CourierStoreFull",
]
