"""Fail-closed delivery inbox with a persistent replay cache.

The inbox is the ONLY door from transports into business logic. Before any
envelope reaches the domain layer it passes the ordered pipeline required by
the integration design doc §5.1 / §10:

1. structure  — exact field set, canonical JSON, bounded size and depth;
2. signature  — sender's Ed25519 did:key verifies the author-signed body;
3. freshness  — expiry in the past, or creation beyond clock skew, rejects;
4. replay     — (sender_did, nonce) pairs already seen are rejected; the
   cache persists across process restarts (journal-backed);
5. dedup      — a ``message_id`` that was already accepted is an idempotent
   drop, not an error: receivers act once per content address;
6. authority  — the host-provided ``authorize`` callback decides membership
   and business permission. The inbox itself grants nothing.

Every rejection is recorded with an explicit reason. The replay cache is
bounded: when the entry cap is reached, the oldest entry is evicted and the
eviction is journaled, so a reload folds to the identical state.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple, Union

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.envelope import (
    TransportEnvelope,
    TransportEnvelopeRejected,
    envelope_digest,
    validate_envelope,
)
from nth_dao.util.io import InterProcessLock

logger = logging.getLogger("nth_dao.delivery")

PathLike = Union[str, Path]

DEFAULT_MAX_REPLAY_ENTRIES = 65_536
DEFAULT_MAX_REJECTION_LOG = 8_192
REJECTION_LOG_MAX_BYTES = 4 * 1024 * 1024
MAX_CACHE_JOURNAL_BYTES = 16 * 1024 * 1024
_MESSAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CACHE_EVENTS = ("accepted", "evicted")

AuthorizeCallable = Callable[[TransportEnvelope], Tuple[bool, str]]


@dataclass
class InboxDecision:
    """Outcome of one inbox pipeline run. Never raises for bad input."""

    accepted: bool
    reason: str
    message_id: str = ""
    envelope_sha256: str = ""
    envelope: Optional[TransportEnvelope] = None
    duplicate: bool = False
    replayed: bool = False

    def __post_init__(self) -> None:
        if self.envelope is not None and not self.accepted:
            raise ValueError("a rejected decision cannot carry an envelope")


class DeliveryInbox:
    """One receiver's fail-closed inbox over a delivery directory."""

    def __init__(
        self,
        directory: PathLike,
        *,
        authorize: Optional[AuthorizeCallable] = None,
        clock: Optional[Callable[[], int]] = None,
        max_replay_entries: int = DEFAULT_MAX_REPLAY_ENTRIES,
    ) -> None:
        if max_replay_entries < 1:
            raise ValueError("max_replay_entries must be a positive integer")
        self._dir = Path(directory)
        self._cache_path = self._dir / "inbox.cache.jsonl"
        self._rejection_path = self._dir / "inbox.rejections.jsonl"
        self._lock_path = self._dir / "inbox.lock"
        self._authorize = authorize
        self._clock = clock or (lambda: int(time.time() * 1000))
        self._max_entries = max_replay_entries
        self._thread_lock = threading.RLock()
        self._dir.mkdir(parents=True, exist_ok=True)
        # message_id -> (sender_did, nonce); insertion order = eviction order
        self._by_message_id: "OrderedDict[str, Tuple[str, str]]" = OrderedDict()
        self._nonces: Dict[Tuple[str, str], str] = {}
        self._cache_stat: Optional[Tuple[int, int]] = None
        self._load_cache()

    # ─────────────────────── the pipeline ───────────────────────

    def accept(
        self,
        source: Union[str, TransportEnvelope, Dict[str, Any]],
        *,
        now_ms: Optional[int] = None,
    ) -> InboxDecision:
        """Run the full pipeline. Returns a decision; never raises for
        malformed input — everything is an explicit rejection reason."""

        now = self._clock() if now_ms is None else now_ms
        if isinstance(source, str):
            envelope, decision = self._parse(source)
        elif isinstance(source, TransportEnvelope):
            envelope, decision = source, None
        elif isinstance(source, dict):
            envelope, decision = self._parse_dict(source)
        else:
            return self._reject("", "", "unsupported input type")
        if decision is not None:
            return decision

        assert envelope is not None
        ok, reason = validate_envelope(envelope, now_ms=now, require_signature=False)
        if not ok:
            return self._reject(envelope.message_id, envelope.sender_did, reason)
        ok, reason = validate_envelope(envelope, now_ms=now, require_signature=True)
        if not ok:
            return self._reject(envelope.message_id, envelope.sender_did, reason)

        digest = envelope_digest(envelope)
        with self._thread_lock:
            self._refold_if_changed()
            if envelope.message_id in self._by_message_id:
                return InboxDecision(
                    accepted=False,
                    reason="duplicate",
                    message_id=envelope.message_id,
                    envelope_sha256=digest,
                    duplicate=True,
                )
            nonce_key = (envelope.sender_did, envelope.nonce)
            if nonce_key in self._nonces:
                return self._reject(
                    envelope.message_id, envelope.sender_did, "replayed nonce",
                    replayed=True,
                )
            if self._authorize is not None:
                try:
                    allowed, authorize_reason = self._authorize(envelope)
                except Exception as exc:
                    allowed, authorize_reason = False, f"authorize error: {exc}"
                if not allowed:
                    return self._reject(
                        envelope.message_id,
                        envelope.sender_did,
                        authorize_reason or "unauthorized",
                    )
            self._remember(envelope, now)
        return InboxDecision(
            accepted=True,
            reason="ok",
            message_id=envelope.message_id,
            envelope_sha256=digest,
            envelope=envelope,
        )

    # ─────────────────────── cache management ───────────────────────

    def seen(self, message_id: str) -> bool:
        with self._thread_lock:
            self._refold_if_changed()
            return message_id in self._by_message_id

    def entry_count(self) -> int:
        with self._thread_lock:
            self._refold_if_changed()
            return len(self._by_message_id)

    def compact_rejections(self, max_keep: int = DEFAULT_MAX_REJECTION_LOG) -> int:
        """Trim the rejection log to the most recent ``max_keep`` lines."""

        import os
        import secrets

        if max_keep < 1:
            raise ValueError("max_keep must be a positive integer")
        with InterProcessLock(self._lock_path):
            if not self._rejection_path.exists():
                return 0
            lines = self._rejection_path.read_bytes().splitlines()
            kept = lines[-max_keep:]
            tmp = self._rejection_path.with_suffix(
                f".jsonl.{secrets.token_hex(4)}.tmp"
            )
            try:
                with open(tmp, "wb") as handle:
                    handle.writelines(line + b"\n" for line in kept)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, self._rejection_path)
            except OSError:
                tmp.unlink(missing_ok=True)
                raise
            return len(kept)

    # ─────────────────────── internals ───────────────────────

    def _parse(self, envelope_json: str) -> Tuple[Optional[TransportEnvelope], Optional[InboxDecision]]:
        if len(envelope_json.encode("utf-8")) > 2_097_152:
            return None, self._reject("", "", "envelope exceeds the absolute size limit")
        try:
            parsed = json.loads(envelope_json)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            return None, self._reject("", "", "envelope is not valid JSON")
        return self._parse_dict(parsed, override_json=envelope_json)

    def _parse_dict(
        self, value: Any, *, override_json: Optional[str] = None
    ) -> Tuple[Optional[TransportEnvelope], Optional[InboxDecision]]:
        try:
            envelope = TransportEnvelope.from_dict(value)
        except TransportEnvelopeRejected as exc:
            return None, self._reject("", "", f"structure: {exc}")
        except TypeError:
            return None, self._reject("", "", "structure: envelope is not an object")
        if override_json is not None:
            # canonical-bytes discipline: the wire digest must be computed
            # from the exact bytes received
            try:
                encoded = canonical_json(envelope.to_dict())
            except (TypeError, ValueError, RecursionError):
                return None, self._reject("", "", "structure: envelope is not canonical JSON")
            if encoded.decode("utf-8") != override_json:
                return None, self._reject(
                    getattr(envelope, "message_id", ""),
                    getattr(envelope, "sender_did", ""),
                    "envelope_json is not the canonical encoding",
                )
        return envelope, None

    def _reject(
        self,
        message_id: str,
        sender_did: str,
        reason: str,
        *,
        replayed: bool = False,
    ) -> InboxDecision:
        decision = InboxDecision(
            accepted=False,
            reason=reason,
            message_id=message_id,
            replayed=replayed,
        )
        self._journal_rejection(message_id, sender_did, reason)
        return decision

    def _journal_rejection(self, message_id: str, sender_did: str, reason: str) -> None:
        import os

        event = {
            "at_ms": self._clock(),
            "message_id": message_id,
            "sender_did": sender_did,
            "reason": reason[:512],
        }
        try:
            with (
                InterProcessLock(self._lock_path),
                open(self._rejection_path, "ab") as handle,
            ):
                handle.write(canonical_json(event) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._trim_rejections_if_large()
        except OSError as exc:  # pragma: no cover - logging must never crash intake
            logger.warning("could not journal inbox rejection: %s", exc)

    def _trim_rejections_if_large(self) -> None:
        """Bound the rejection journal (flood-hostile): once it exceeds the
        byte cap, keep only the newest entries that fit in 75% of the cap.

        Runs under the cross-process lock with a unique tmp name — without
        the lock, a trim racing another process's append (or its own
        compact) could silently drop lines or corrupt the temp file
        (round-4 bug R).
        """

        import os
        import secrets

        try:
            if self._rejection_path.stat().st_size <= REJECTION_LOG_MAX_BYTES:
                return
            with InterProcessLock(self._lock_path):
                # re-stat under the lock: another process may have trimmed
                if self._rejection_path.stat().st_size <= REJECTION_LOG_MAX_BYTES:
                    return
                lines = self._rejection_path.read_bytes().splitlines()
                budget = int(REJECTION_LOG_MAX_BYTES * 0.75)
                kept: list = []
                total = 0
                for line in reversed(lines):
                    candidate = total + len(line) + 1
                    if candidate > budget or len(kept) >= DEFAULT_MAX_REJECTION_LOG:
                        break
                    kept.append(line)
                    total = candidate
                kept.reverse()
                tmp = self._rejection_path.with_suffix(
                    f".jsonl.{secrets.token_hex(4)}.tmp"
                )
                try:
                    with open(tmp, "wb") as handle:
                        for line in kept:
                            handle.write(line + b"\n")
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(tmp, self._rejection_path)
                except OSError:
                    tmp.unlink(missing_ok=True)
                    raise
                logger.warning(
                    "inbox rejection journal exceeded %d bytes; trimmed to the "
                    "newest %d entries", REJECTION_LOG_MAX_BYTES, len(kept),
                )
        except OSError as exc:  # pragma: no cover - trim is best-effort
            logger.warning("could not trim inbox rejection journal: %s", exc)

    def _remember(self, envelope: TransportEnvelope, now_ms: int) -> None:
        """Journal-first acceptance with bounded eviction.

        The journal line (accepted + optional evicted) is fsynced BEFORE the
        in-memory state moves, so a crash or full disk can never leave memory
        ahead of the durable replay cache. The eviction victim is only
        *peeked* before the write and removed from memory after it — a failed
        write must not mutate memory at all.
        """

        import os

        message_id = envelope.message_id
        nonce_key = (envelope.sender_did, envelope.nonce)
        evicted_id: Optional[str] = None
        evicted_key: Optional[Tuple[str, str]] = None
        if len(self._by_message_id) >= self._max_entries:
            # peek the oldest entry; no mutation until the write succeeded
            evicted_id, evicted_key = next(iter(self._by_message_id.items()))
        event = {
            "event": "accepted",
            "message_id": message_id,
            "sender_did": envelope.sender_did,
            "nonce": envelope.nonce,
            "at_ms": now_ms,
        }
        with (
            InterProcessLock(self._lock_path),
            open(self._cache_path, "ab") as handle,
        ):
            handle.write(canonical_json(event) + b"\n")
            if evicted_id is not None:
                handle.write(
                    canonical_json({"event": "evicted", "message_id": evicted_id}) + b"\n"
                )
            handle.flush()
            os.fsync(handle.fileno())
            # fingerprint captured while STILL holding the lock: one taken
            # after release could absorb another process's append and hide
            # it from the re-fold check forever (round-4 bug Q)
            try:
                stat = os.fstat(handle.fileno())
                self._journal_stat = (stat.st_mtime_ns, stat.st_size)
            except OSError:  # pragma: no cover - fstat on our own fd
                pass
        # durable now — apply to memory
        self._by_message_id[message_id] = nonce_key
        self._nonces[nonce_key] = message_id
        if evicted_key is not None and evicted_id is not None:
            self._by_message_id.pop(evicted_id, None)
            self._nonces.pop(evicted_key, None)
        # bound the journal on the append path too: crossing the cap folds
        # and rewrites losslessly instead of growing forever (round-11 BB-p)
        try:
            if self._cache_path.stat().st_size > MAX_CACHE_JOURNAL_BYTES:
                self._compact_cache_journal()
        except OSError:  # pragma: no cover - stat raced an external replace
            pass

    def _compact_cache_journal(self) -> None:
        """Losslessly rewrite an oversized cache journal to its live entries.

        The oversized journal is folded into memory first (torn tail
        tolerated, corruption still fails closed), then the journal is
        rewritten holding only the live entries. The rewritten journal folds
        to the identical in-memory state, so dedup semantics are unchanged
        and the inbox recovers instead of bricking (round-11 bug BB-p). The
        caller must hold ``self._thread_lock``.
        """

        import os
        import secrets

        self._by_message_id.clear()
        self._nonces.clear()
        raw = self._cache_path.read_bytes()
        self._fold_cache_lines(raw)
        tmp = self._cache_path.with_suffix(f".jsonl.{secrets.token_hex(4)}.tmp")
        try:
            with (
                InterProcessLock(self._lock_path),
                open(tmp, "wb") as handle,
            ):
                for message_id, (sender_did, nonce) in self._by_message_id.items():
                    handle.write(canonical_json({
                        "event": "accepted",
                        "message_id": message_id,
                        "sender_did": sender_did,
                        "nonce": nonce,
                    }) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._cache_path)
        except OSError:
            tmp.unlink(missing_ok=True)
            raise
        try:
            stat = self._cache_path.stat()
            self._cache_stat = (stat.st_mtime_ns, stat.st_size)
        except OSError:  # pragma: no cover - stat after our own replace
            self._cache_stat = None
        logger.warning(
            "inbox cache journal exceeded %d bytes; compacted to %d live "
            "entries", MAX_CACHE_JOURNAL_BYTES, len(self._by_message_id),
        )

    def _refold_if_changed(self) -> None:
        """Re-fold the cache journal when another process appended to it.

        Every mutation is journaled before it is applied in memory, so a
        re-fold is always safe and makes cross-process dedup live instead of
        restart-only.
        """

        try:
            stat = self._cache_path.stat()
        except OSError:
            return
        current = (stat.st_mtime_ns, stat.st_size)
        if current != self._cache_stat:
            logger.debug("delivery inbox cache changed on disk; re-folding")
            self._by_message_id.clear()
            self._nonces.clear()
            self._load_cache()

    def _load_cache(self) -> None:
        if not self._cache_path.exists():
            self._cache_stat = None
            return
        if self._cache_path.stat().st_size > MAX_CACHE_JOURNAL_BYTES:
            # round-11 bug BB-p: the journal grows monotonically (accepted +
            # evicted pairs), so at the cap the inbox used to brick itself
            # forever. Compaction IS the recovery: fold, rewrite losslessly,
            # and continue with a live state (no operator intervention).
            self._compact_cache_journal()
            return
        try:
            stat = self._cache_path.stat()
            self._cache_stat = (stat.st_mtime_ns, stat.st_size)
        except OSError:  # pragma: no cover - raced an external replace
            self._cache_stat = None
        self._fold_cache_lines(self._cache_path.read_bytes())

    def _fold_cache_lines(self, raw: bytes) -> None:
        """Fold cache journal bytes into the in-memory state (fail closed)."""

        torn_tail = bool(raw) and not raw.endswith(b"\n")
        lines = raw.split(b"\n")
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            if index == len(lines) - 1 and torn_tail:
                logger.warning("inbox cache has a torn final line; ignoring it")
                break
            try:
                event = json.loads(line.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise DeliveryInboxCacheCorrupt(
                    f"corrupt inbox cache line {index + 1}: {exc}"
                ) from exc
            kind = event.get("event")
            if kind not in _CACHE_EVENTS:
                raise DeliveryInboxCacheCorrupt(f"unknown cache event: {kind!r}")
            message_id = event.get("message_id")
            if not isinstance(message_id, str) or _MESSAGE_ID_RE.fullmatch(message_id) is None:
                raise DeliveryInboxCacheCorrupt("cache event message_id is invalid")
            if kind == "evicted":
                existing = self._by_message_id.pop(message_id, None)
                if existing is not None:
                    self._nonces.pop(existing, None)
                continue
            sender_did = event.get("sender_did")
            nonce = event.get("nonce")
            if not isinstance(sender_did, str) or not isinstance(nonce, str):
                raise DeliveryInboxCacheCorrupt("accepted event missing sender or nonce")
            self._by_message_id[message_id] = (sender_did, nonce)
            self._nonces[(sender_did, nonce)] = message_id


class DeliveryInboxCacheCorrupt(RuntimeError):
    """Raised when the persisted replay cache is damaged (fail closed)."""


__all__ = [
    "DEFAULT_MAX_REJECTION_LOG",
    "DEFAULT_MAX_REPLAY_ENTRIES",
    "REJECTION_LOG_MAX_BYTES",
    "DeliveryInbox",
    "DeliveryInboxCacheCorrupt",
    "InboxDecision",
]
