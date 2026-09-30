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
import re
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.envelope import MAX_ENVELOPE_BYTES
from nth_dao.did_key import is_did_key
from nth_dao.util.io import InterProcessLock, atomic_write_bytes

logger = logging.getLogger("nth_dao.courier")

DEFAULT_MAX_TOTAL_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_PER_RECIPIENT = 64
DEFAULT_MAX_ENVELOPES = 512
_JOURNAL = "courier.journal.jsonl"
_JOURNAL_MAX_BYTES = 32 * 1024 * 1024
_JOURNAL_RECOVERY_SLACK_BYTES = (2 * MAX_ENVELOPE_BYTES) + 4096
_SHA256_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")


class CourierStoreError(RuntimeError):
    """Raised for courier store operational failures."""


class CourierStoreFull(CourierStoreError):
    """Raised when the carrier's quota is exhausted (fail closed)."""


class CourierStore:
    """Quota-bounded pool of sealed courier envelopes on one carrier."""

    def __init__(
        self,
        directory: str | Path,
        *,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
        max_per_recipient: int = DEFAULT_MAX_PER_RECIPIENT,
        max_envelopes: int = DEFAULT_MAX_ENVELOPES,
        clock: Callable[[], int] | None = None,
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
        self._lock_target = self._dir / "courier"
        self._max_total_bytes = max_total_bytes
        self._max_per_recipient = max_per_recipient
        self._max_envelopes = max_envelopes
        self._clock = clock or (lambda: int(time.time() * 1000))
        self._lock = threading.RLock()
        # digest → (envelope dict, sealed_at_ms)
        self._pool: dict[str, dict[str, Any]] = {}
        self._pool_order: list[str] = []
        self._dir.mkdir(parents=True, exist_ok=True)
        self._load()

    # ─────────────────────── persistence ───────────────────────

    def _load(self) -> None:
        """Load and, when needed, compact one bounded journal snapshot."""

        with self._lock, self._acquire_file_lock():
            self._refresh_from_disk_locked()

    @staticmethod
    def _parse_journal(raw: bytes) -> tuple[dict[str, dict[str, Any]], list[str]]:
        """Parse journal bytes into (pool, order); no side effects, no locks
        (usable under the file lock without deadlocking)."""

        from nth_dao.delivery.courier import (
            CourierEnvelopeRejected,
            validate_courier_wire,
        )

        pool: dict[str, dict[str, Any]] = {}
        order: list[str] = []
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
            if not isinstance(event, dict):
                raise CourierStoreError(
                    f"courier journal line {index + 1} is not an object"
                )
            kind = event.get("event")
            if kind == "sealed":
                allowed = {"event", "digest", "envelope", "sealed_at_ms"}
                if set(event) not in (
                    {"event", "digest", "envelope"},
                    allowed,
                ):
                    raise CourierStoreError(
                        f"invalid sealed event fields on line {index + 1}"
                    )
                digest = event.get("digest")
                envelope = event.get("envelope")
                if (
                    not isinstance(digest, str)
                    or _SHA256_DIGEST_RE.fullmatch(digest) is None
                ):
                    raise CourierStoreError(
                        f"invalid courier digest on line {index + 1}"
                    )
                if not isinstance(envelope, dict):
                    raise CourierStoreError(
                        f"sealed envelope on line {index + 1} is not an object"
                    )
                try:
                    validate_courier_wire(envelope)
                except CourierEnvelopeRejected as exc:
                    raise CourierStoreError(
                        f"invalid courier envelope on line {index + 1}: {exc}"
                    ) from exc
                actual = "sha256:" + __import__("hashlib").sha256(
                    canonical_json(envelope)
                ).hexdigest()
                if digest != actual:
                    raise CourierStoreError(
                        f"courier digest mismatch on line {index + 1}"
                    )
                sealed_at_ms = event.get("sealed_at_ms")
                if sealed_at_ms is not None and (
                    isinstance(sealed_at_ms, bool)
                    or not isinstance(sealed_at_ms, int)
                    or sealed_at_ms < 1
                ):
                    raise CourierStoreError(
                        f"invalid sealed_at_ms on line {index + 1}"
                    )
                if digest in pool:
                    raise CourierStoreError(
                        f"duplicate sealed digest on line {index + 1}"
                    )
                pool[digest] = envelope
                order.append(digest)
            elif kind in {"handed_over", "discarded"}:
                if set(event) != {"event", "digest"}:
                    raise CourierStoreError(
                        f"invalid {kind} event fields on line {index + 1}"
                    )
                digest = event.get("digest")
                if (
                    not isinstance(digest, str)
                    or _SHA256_DIGEST_RE.fullmatch(digest) is None
                ):
                    raise CourierStoreError(
                        f"invalid courier digest on line {index + 1}"
                    )
                pool.pop(digest, None)
                if digest in order:
                    order.remove(digest)
            else:
                raise CourierStoreError(f"unknown courier journal event: {kind!r}")
        return pool, order

    def _acquire_file_lock(self) -> InterProcessLock:
        return InterProcessLock(self._lock_target, timeout=10.0, poll=0.01)

    def _read_journal_bounded(self) -> bytes:
        limit = _JOURNAL_MAX_BYTES + _JOURNAL_RECOVERY_SLACK_BYTES
        with open(self._journal_path, "rb") as handle:
            raw = handle.read(limit + 1)
        if len(raw) > limit:
            raise CourierStoreError(
                "courier journal exceeds the bounded crash-recovery limit"
            )
        return raw

    def _refresh_from_disk_locked(self) -> None:
        if not self._journal_path.exists():
            self._pool = {}
            self._pool_order = []
            return
        raw = self._read_journal_bounded()
        pool, order = self._parse_journal(raw)
        if len(raw) > _JOURNAL_MAX_BYTES:
            atomic_write_bytes(
                self._journal_path,
                self._snapshot_bytes(pool, order),
            )
        self._pool = pool
        self._pool_order = order

    def _append_record_locked(self, event: dict[str, Any]) -> None:
        with open(self._journal_path, "ab") as handle:
            handle.write(canonical_json(event) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())

    @staticmethod
    def _snapshot_bytes(
        pool: dict[str, dict[str, Any]], order: list[str]
    ) -> bytes:
        snapshot = bytearray()
        for digest in order:
            if digest not in pool:
                continue
            snapshot.extend(canonical_json({
                "event": "sealed",
                "digest": digest,
                "envelope": pool[digest],
            }))
            snapshot.extend(b"\n")
            if len(snapshot) > _JOURNAL_MAX_BYTES:
                raise CourierStoreError(
                    "live courier state exceeds the journal size limit"
                )
        return bytes(snapshot)

    def _rotate_from_memory(self) -> None:
        """Compact from the current disk state, never a stale memory view."""

        with self._lock, self._acquire_file_lock():
            if not self._journal_path.exists():
                return
            pool, order = self._parse_journal(self._read_journal_bounded())
            atomic_write_bytes(
                self._journal_path,
                self._snapshot_bytes(pool, order),
            )
            self._pool = pool
            self._pool_order = order
        logger.warning("courier journal rotated; %d live entries", len(order))

    # ─────────────────────── pool operations ───────────────────────

    def seal_into(
        self,
        courier: dict[str, Any],
        *,
        now_ms: int | None = None,
    ) -> str:
        """Admit one sealed envelope into the pool; return its digest.

        Fails closed with :class:`CourierStoreFull` when any quota is hit.
        """

        from nth_dao.delivery.courier import (
            CourierEnvelopeRejected,
            validate_courier_wire,
        )

        try:
            ciphertext_bytes = validate_courier_wire(courier)
        except CourierEnvelopeRejected as exc:
            raise CourierStoreError(str(exc)) from exc
        now = self._clock() if now_ms is None else now_ms
        if isinstance(now, bool) or not isinstance(now, int) or now < 1:
            raise CourierStoreError("now_ms must be a positive integer")
        digest = "sha256:" + __import__("hashlib").sha256(
            canonical_json(courier)
        ).hexdigest()
        envelope_bytes = len(ciphertext_bytes)
        with self._lock, self._acquire_file_lock():
            # cross-process quota enforcement (round-23 bug KK-9): re-parse
            # the journal under the file lock (pure parse — no rotation, so
            # no second-lock deadlock) so the check sees every process's
            # envelopes
            self._refresh_from_disk_locked()
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
            self._append_record_locked(event)
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
    ) -> list[dict[str, Any]]:
        """List envelopes addressed to one recipient.

        TTL is NOT filtered here: expiration is the opening side's decision
        (the courier may not know the true wall clock), enforced by
        ``open_courier_envelope``'s now_ms check."""

        if not is_did_key(recipient_did):
            raise CourierStoreError("recipient_did must be a did:key")
        if isinstance(max_items, bool) or not isinstance(max_items, int) or max_items < 1:
            raise CourierStoreError("max_items must be a positive integer")
        with self._lock, self._acquire_file_lock():
            self._refresh_from_disk_locked()
            out: list[dict[str, Any]] = []
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

    def hand_over(self, courier: dict[str, Any]) -> None:
        """Remove one envelope after successful handover (open + validate)."""

        digest = "sha256:" + __import__("hashlib").sha256(
            canonical_json(courier)
        ).hexdigest()
        with self._lock, self._acquire_file_lock():
            self._refresh_from_disk_locked()
            if digest not in self._pool:
                raise CourierStoreError("hand_over: envelope not in pool")
            self._append_record_locked({"event": "handed_over", "digest": digest})
            self._pool.pop(digest, None)
            if digest in self._pool_order:
                self._pool_order.remove(digest)

    def discard_digest(self, digest: str) -> bool:
        """Idempotently discard one exact sealed envelope by content digest.

        Spray state persists envelope digests rather than ciphertext. This
        method lets a restarted coordinator cancel the precise copy without
        duplicating sensitive envelope material in its own journal. ``False``
        means the copy was already absent, which is also a resolved state.
        """

        if not isinstance(digest, str) or _SHA256_DIGEST_RE.fullmatch(digest) is None:
            raise CourierStoreError("digest must be sha256:<64 lowercase hex chars>")
        with self._lock, self._acquire_file_lock():
            self._refresh_from_disk_locked()
            if digest not in self._pool:
                return False
            self._append_record_locked({"event": "discarded", "digest": digest})
            self._pool.pop(digest, None)
            if digest in self._pool_order:
                self._pool_order.remove(digest)
            return True

    def stats(self) -> dict[str, int]:
        with self._lock, self._acquire_file_lock():
            self._refresh_from_disk_locked()
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
