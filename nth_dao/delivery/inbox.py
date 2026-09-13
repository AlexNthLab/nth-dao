"""Fail-closed delivery inbox with a persistent replay cache.

The inbox is the ONLY door from transports into business logic. Before any
envelope reaches the domain layer it passes the ordered pipeline required by
the integration design doc §5.1 / §10:

1. structure  — exact field set, canonical JSON, bounded size and depth;
2. signature  — sender's Ed25519 did:key verifies the author-signed body;
3. freshness  — expiry in the past, or creation beyond clock skew, rejects;
4. authority  — the host-provided ``authorize`` callback decides membership
   and business permission. The inbox itself grants nothing;
5. replay     — (sender_did, nonce) pairs already seen are rejected; the
   cache persists across process restarts (journal-backed);
6. dedup      — a ``message_id`` that was already accepted is an idempotent
   drop, not an error: receivers act once per content address;
7. durability — the full canonical envelope remains pending until the domain
   layer explicitly calls ``mark_processed``.

Every rejection is recorded with an explicit reason. The replay cache is
bounded. Only processed replay entries may be evicted; an inbox full of
unprocessed envelopes rejects new intake instead of silently losing work.
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
from nth_dao.delivery.authorization import (
    AuthorizationDecision,
    AuthorizationResult,
    coerce_authorization_decision,
)
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
MAX_CACHE_LIVE_BYTES = 16 * 1024 * 1024
MAX_CACHE_JOURNAL_READ_BYTES = 64 * 1024 * 1024
_MESSAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CACHE_EVENTS = ("accepted", "processed", "evicted")
_ACCEPTED_REQUIRED_FIELDS = frozenset(
    {"event", "message_id", "sender_did", "nonce"}
)
_ACCEPTED_OPTIONAL_FIELDS = frozenset(
    {"at_ms", "envelope_json", "evicted_message_id", "evicted_message_ids"}
)

AuthorizeCallable = Callable[[TransportEnvelope], AuthorizationResult]


@dataclass
class InboxDecision:
    """Outcome of one inbox pipeline run. Never raises for bad input."""

    accepted: bool
    reason: str
    code: str = ""
    retryable: bool = False
    message_id: str = ""
    envelope_sha256: str = ""
    envelope: Optional[TransportEnvelope] = None
    duplicate: bool = False
    replayed: bool = False

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            raise TypeError("accepted must be a bool")
        if type(self.retryable) is not bool:
            raise TypeError("retryable must be a bool")
        if self.accepted and self.retryable:
            raise ValueError("an accepted inbox decision cannot be retryable")
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
        if (
            isinstance(max_replay_entries, bool)
            or not isinstance(max_replay_entries, int)
            or max_replay_entries < 1
        ):
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
        self._pending_json: "OrderedDict[str, str]" = OrderedDict()
        self._cache_snapshot_sizes: Dict[str, int] = {}
        self._cache_snapshot_bytes = 0
        self._cache_stat: Optional[Tuple[int, int]] = None
        with InterProcessLock(self._lock_path):
            self._load_cache_locked()

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
        try:
            envelope = TransportEnvelope.from_dict(envelope.to_dict())
        except (TransportEnvelopeRejected, TypeError, ValueError, RecursionError):
            return self._reject("", "", "structure: envelope snapshot failed")
        ok, reason = validate_envelope(envelope, now_ms=now, require_signature=False)
        if not ok:
            return self._reject(envelope.message_id, envelope.sender_did, reason)
        ok, reason = validate_envelope(envelope, now_ms=now, require_signature=True)
        if not ok:
            return self._reject(envelope.message_id, envelope.sender_did, reason)

        digest = envelope_digest(envelope)
        if self._authorize is not None:
            callback_envelope = TransportEnvelope.from_dict(envelope.to_dict())
            try:
                raw_authorization = self._authorize(callback_envelope)
            except Exception as exc:
                logger.warning(
                    "delivery inbox authorization callback failed (%s)",
                    type(exc).__name__,
                )
                authorization = AuthorizationDecision.deny(
                    code="authorization-callback-failed",
                    reason="authorization callback failed",
                    retryable=True,
                )
            else:
                try:
                    authorization = coerce_authorization_decision(
                        raw_authorization,
                        deny_code="unauthorized",
                    )
                except (TypeError, ValueError):
                    logger.warning(
                        "delivery inbox authorization callback returned an invalid decision"
                    )
                    authorization = AuthorizationDecision.deny(
                        code="authorization-decision-invalid",
                        reason="authorization callback returned an invalid decision",
                    )
            if not authorization.allowed:
                return self._reject(
                    envelope.message_id,
                    envelope.sender_did,
                    authorization.reason,
                    code=authorization.code,
                    retryable=authorization.retryable,
                )

        replayed = False
        full_reason = ""
        with self._thread_lock:
            with InterProcessLock(self._lock_path):
                self._refold_if_changed_locked()
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
                    replayed = True
                else:
                    try:
                        self._remember_locked(envelope, now)
                    except DeliveryInboxFull as exc:
                        full_reason = str(exc)
        if replayed:
            return self._reject(
                envelope.message_id,
                envelope.sender_did,
                "replayed nonce",
                replayed=True,
            )
        if full_reason:
            return self._reject(
                envelope.message_id,
                envelope.sender_did,
                full_reason,
                code="inbox-capacity-exhausted",
                retryable=True,
            )
        return InboxDecision(
            accepted=True,
            reason="ok",
            code="accepted",
            message_id=envelope.message_id,
            envelope_sha256=digest,
            envelope=envelope,
        )

    # ─────────────────────── cache management ───────────────────────

    def seen(self, message_id: str) -> bool:
        with self._thread_lock:
            with InterProcessLock(self._lock_path):
                self._refold_if_changed_locked()
                return message_id in self._by_message_id

    def entry_count(self) -> int:
        with self._thread_lock:
            with InterProcessLock(self._lock_path):
                self._refold_if_changed_locked()
                return len(self._by_message_id)

    def pending(self, *, max_items: int = 64) -> list[TransportEnvelope]:
        """Return durably accepted envelopes awaiting business processing."""

        if isinstance(max_items, bool) or not isinstance(max_items, int) or max_items < 1:
            raise ValueError("max_items must be a positive integer")
        with self._thread_lock:
            with InterProcessLock(self._lock_path):
                self._refold_if_changed_locked()
                pending_json = list(self._pending_json.values())[:max_items]
        envelopes: list[TransportEnvelope] = []
        for encoded in pending_json:
            try:
                envelopes.append(TransportEnvelope.from_dict(json.loads(encoded)))
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise DeliveryInboxCacheCorrupt(
                    f"persisted pending envelope is invalid: {exc}"
                ) from exc
        return envelopes

    def mark_processed(self, message_id: str) -> bool:
        """Durably mark one accepted envelope as handled by the domain layer."""

        if not isinstance(message_id, str) or _MESSAGE_ID_RE.fullmatch(message_id) is None:
            raise ValueError("message_id is not a content address")
        with self._thread_lock:
            with InterProcessLock(self._lock_path):
                self._refold_if_changed_locked()
                if message_id not in self._by_message_id:
                    raise KeyError(message_id)
                if message_id not in self._pending_json:
                    return False
                sender_did, nonce = self._by_message_id[message_id]
                processed_size = self._cache_snapshot_line_size(
                    message_id=message_id,
                    sender_did=sender_did,
                    nonce=nonce,
                )
                previous_size = self._cache_snapshot_sizes[message_id]
                self._append_cache_locked(
                    {"event": "processed", "message_id": message_id}
                )
                self._pending_json.pop(message_id, None)
                self._cache_snapshot_sizes[message_id] = processed_size
                self._cache_snapshot_bytes += processed_size - previous_size
                self._compact_if_oversized_locked()
                return True

    def compact_rejections(self, max_keep: int = DEFAULT_MAX_REJECTION_LOG) -> int:
        """Trim the rejection log to the most recent ``max_keep`` lines."""

        if isinstance(max_keep, bool) or not isinstance(max_keep, int) or max_keep < 1:
            raise ValueError("max_keep must be a positive integer")
        with InterProcessLock(self._lock_path):
            if not self._rejection_path.exists():
                return 0
            kept = self._read_rejection_tail_locked(
                max_keep=max_keep,
                byte_budget=REJECTION_LOG_MAX_BYTES,
            )
            self._write_rejections_locked(kept)
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
        code: str = "rejected",
        retryable: bool = False,
        replayed: bool = False,
    ) -> InboxDecision:
        decision = InboxDecision(
            accepted=False,
            reason=reason,
            code=code,
            retryable=retryable,
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

        try:
            if self._rejection_path.stat().st_size <= REJECTION_LOG_MAX_BYTES:
                return
            with InterProcessLock(self._lock_path):
                # re-stat under the lock: another process may have trimmed
                if self._rejection_path.stat().st_size <= REJECTION_LOG_MAX_BYTES:
                    return
                budget = int(REJECTION_LOG_MAX_BYTES * 0.75)
                kept = self._read_rejection_tail_locked(
                    max_keep=DEFAULT_MAX_REJECTION_LOG,
                    byte_budget=budget,
                )
                self._write_rejections_locked(kept)
                logger.warning(
                    "inbox rejection journal exceeded %d bytes; trimmed to the "
                    "newest %d entries", REJECTION_LOG_MAX_BYTES, len(kept),
                )
        except OSError as exc:  # pragma: no cover - trim is best-effort
            logger.warning("could not trim inbox rejection journal: %s", exc)

    def _read_rejection_tail_locked(
        self, *, max_keep: int, byte_budget: int
    ) -> list[bytes]:
        """Read only the newest complete JSONL records within a hard budget."""

        import os

        with open(self._rejection_path, "rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            window = min(size, byte_budget)
            start = size - window
            handle.seek(start)
            raw = handle.read(window)

        if start:
            # The window usually starts inside an older record. Never retain
            # that fragment as if it were a complete rejection event.
            separator = raw.find(b"\n")
            if separator < 0:
                return []
            raw = raw[separator + 1 :]
        if raw and not raw.endswith(b"\n"):
            raw = raw.rsplit(b"\n", 1)[0]

        kept: list[bytes] = []
        total = 0
        for line in reversed(raw.splitlines()):
            candidate = total + len(line) + 1
            if candidate > byte_budget or len(kept) >= max_keep:
                break
            kept.append(line)
            total = candidate
        kept.reverse()
        return kept

    def _write_rejections_locked(self, lines: list[bytes]) -> None:
        """Atomically replace the rejection journal while its lock is held."""

        import os
        import secrets

        tmp = self._rejection_path.with_suffix(f".jsonl.{secrets.token_hex(4)}.tmp")
        try:
            with open(tmp, "wb") as handle:
                handle.writelines(line + b"\n" for line in lines)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._rejection_path)
        except OSError:
            tmp.unlink(missing_ok=True)
            raise

    def _remember_locked(self, envelope: TransportEnvelope, now_ms: int) -> None:
        """Persist an accepted envelope while holding the process lock."""

        message_id = envelope.message_id
        nonce_key = (envelope.sender_did, envelope.nonce)
        envelope_json = canonical_json(envelope.to_dict()).decode("utf-8")
        snapshot_size = self._cache_snapshot_line_size(
            message_id=message_id,
            sender_did=envelope.sender_did,
            nonce=envelope.nonce,
            envelope_json=envelope_json,
        )
        evicted: list[tuple[str, Tuple[str, str], int]] = []
        evicted_bytes = 0
        for candidate_id, candidate_key in self._by_message_id.items():
            count_full = len(self._by_message_id) - len(evicted) >= self._max_entries
            bytes_full = (
                self._cache_snapshot_bytes - evicted_bytes + snapshot_size
                > MAX_CACHE_LIVE_BYTES
            )
            if not count_full and not bytes_full:
                break
            if candidate_id in self._pending_json:
                continue
            candidate_size = self._cache_snapshot_sizes[candidate_id]
            evicted.append((candidate_id, candidate_key, candidate_size))
            evicted_bytes += candidate_size
        if (
            len(self._by_message_id) - len(evicted) >= self._max_entries
            or self._cache_snapshot_bytes - evicted_bytes + snapshot_size
            > MAX_CACHE_LIVE_BYTES
        ):
            raise DeliveryInboxFull(
                "inbox replay cache capacity is occupied by unprocessed envelopes"
            )

        event: Dict[str, Any] = {
            "event": "accepted",
            "message_id": message_id,
            "sender_did": envelope.sender_did,
            "nonce": envelope.nonce,
            "at_ms": now_ms,
            "envelope_json": envelope_json,
        }
        if evicted:
            # The replacement is one journal record. A torn append is ignored
            # on reload; a complete append applies every eviction together.
            event["evicted_message_ids"] = [item[0] for item in evicted]
        self._append_cache_locked(event)

        self._by_message_id[message_id] = nonce_key
        self._nonces[nonce_key] = message_id
        self._pending_json[message_id] = envelope_json
        self._cache_snapshot_sizes[message_id] = snapshot_size
        self._cache_snapshot_bytes += snapshot_size
        for evicted_id, evicted_key, evicted_size in evicted:
            self._by_message_id.pop(evicted_id, None)
            self._nonces.pop(evicted_key, None)
            self._pending_json.pop(evicted_id, None)
            self._cache_snapshot_sizes.pop(evicted_id, None)
            self._cache_snapshot_bytes -= evicted_size
        self._compact_if_oversized_locked()

    def _compact_if_oversized_locked(self) -> None:
        try:
            if self._cache_path.stat().st_size > MAX_CACHE_JOURNAL_BYTES:
                self._compact_cache_journal_locked()
        except OSError:  # pragma: no cover - stat after our own append
            pass

    def _append_cache_locked(self, event: Dict[str, Any]) -> None:
        self._append_cache_events_locked([event])

    def _append_cache_events_locked(self, events: list[Dict[str, Any]]) -> None:
        import os

        lines = [canonical_json(event) + b"\n" for event in events]
        append_bytes = sum(len(line) for line in lines)
        with open(self._cache_path, "ab") as handle:
            handle.seek(0, os.SEEK_END)
            current_size = handle.tell()
        if current_size + append_bytes > MAX_CACHE_JOURNAL_READ_BYTES:
            self._compact_cache_journal_locked()
        with open(self._cache_path, "ab") as handle:
            handle.seek(0, os.SEEK_END)
            if handle.tell() + append_bytes > MAX_CACHE_JOURNAL_READ_BYTES:
                raise DeliveryInboxFull(
                    "inbox cache has insufficient space for the next durable event"
                )
            for line in lines:
                handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
            stat = os.fstat(handle.fileno())
            self._cache_stat = (stat.st_mtime_ns, stat.st_size)

    def _compact_cache_journal_locked(self) -> None:
        """Rewrite the current cache state while holding the process lock."""

        import os
        import secrets

        tmp = self._cache_path.with_suffix(f".jsonl.{secrets.token_hex(4)}.tmp")
        try:
            with open(tmp, "wb") as handle:
                for message_id, (sender_did, nonce) in self._by_message_id.items():
                    event = self._cache_snapshot_event(
                        message_id=message_id,
                        sender_did=sender_did,
                        nonce=nonce,
                        envelope_json=self._pending_json.get(message_id),
                    )
                    handle.write(canonical_json(event) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._cache_path)
        except OSError:
            tmp.unlink(missing_ok=True)
            raise
        stat = self._cache_path.stat()
        self._cache_stat = (stat.st_mtime_ns, stat.st_size)
        logger.warning(
            "inbox cache journal exceeded %d bytes; compacted to %d live entries",
            MAX_CACHE_JOURNAL_BYTES,
            len(self._by_message_id),
        )

    def _refold_if_changed_locked(self) -> None:
        """Re-fold when another process changed the cache journal."""

        try:
            stat = self._cache_path.stat()
        except OSError:
            return
        current = (stat.st_mtime_ns, stat.st_size)
        if current != self._cache_stat:
            logger.debug("delivery inbox cache changed on disk; re-folding")
            self._by_message_id.clear()
            self._nonces.clear()
            self._pending_json.clear()
            self._cache_snapshot_sizes.clear()
            self._cache_snapshot_bytes = 0
            self._load_cache_locked()

    def _load_cache_locked(self) -> None:
        if not self._cache_path.exists():
            self._cache_stat = None
            return
        size = self._cache_path.stat().st_size
        if size > MAX_CACHE_JOURNAL_READ_BYTES:
            raise DeliveryInboxCacheCorrupt(
                "inbox cache journal exceeds the hard read limit of "
                f"{MAX_CACHE_JOURNAL_READ_BYTES} bytes"
            )
        with open(self._cache_path, "rb") as handle:
            raw = handle.read(MAX_CACHE_JOURNAL_READ_BYTES + 1)
        if len(raw) > MAX_CACHE_JOURNAL_READ_BYTES:
            raise DeliveryInboxCacheCorrupt(
                "inbox cache journal grew beyond the hard read limit while loading"
            )
        self._fold_cache_lines(raw)
        self._recompute_cache_snapshot_budget()
        if len(raw) > MAX_CACHE_JOURNAL_BYTES:
            self._compact_cache_journal_locked()
            return
        stat = self._cache_path.stat()
        self._cache_stat = (stat.st_mtime_ns, stat.st_size)

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
            if not isinstance(event, dict):
                raise DeliveryInboxCacheCorrupt("cache event must be an object")
            kind = event.get("event")
            if kind not in _CACHE_EVENTS:
                raise DeliveryInboxCacheCorrupt(f"unknown cache event: {kind!r}")
            fields = frozenset(event)
            if kind == "accepted":
                if not _ACCEPTED_REQUIRED_FIELDS <= fields or not fields <= (
                    _ACCEPTED_REQUIRED_FIELDS | _ACCEPTED_OPTIONAL_FIELDS
                ):
                    raise DeliveryInboxCacheCorrupt(
                        "accepted cache event has missing or unknown fields"
                    )
            elif fields != frozenset({"event", "message_id"}):
                raise DeliveryInboxCacheCorrupt(
                    f"{kind} cache event has missing or unknown fields"
                )
            message_id = event.get("message_id")
            if not isinstance(message_id, str) or _MESSAGE_ID_RE.fullmatch(message_id) is None:
                raise DeliveryInboxCacheCorrupt("cache event message_id is invalid")
            if kind == "evicted":
                existing = self._by_message_id.pop(message_id, None)
                if existing is None:
                    raise DeliveryInboxCacheCorrupt(
                        "evicted cache event references an unknown message"
                    )
                self._nonces.pop(existing, None)
                self._pending_json.pop(message_id, None)
                continue
            if kind == "processed":
                if message_id not in self._by_message_id:
                    raise DeliveryInboxCacheCorrupt(
                        "processed cache event references an unknown message"
                    )
                if self._pending_json.pop(message_id, None) is None:
                    raise DeliveryInboxCacheCorrupt(
                        "processed cache event repeats an existing transition"
                    )
                continue
            sender_did = event.get("sender_did")
            nonce = event.get("nonce")
            if not isinstance(sender_did, str) or not isinstance(nonce, str):
                raise DeliveryInboxCacheCorrupt("accepted event missing sender or nonce")
            nonce_key = (sender_did, nonce)
            existing = self._by_message_id.get(message_id)
            if existing is not None:
                raise DeliveryInboxCacheCorrupt(
                    "accepted cache event repeats a message_id"
                )
            existing_nonce_message = self._nonces.get(nonce_key)
            if existing_nonce_message is not None:
                raise DeliveryInboxCacheCorrupt(
                    "accepted cache event reuses a sender nonce"
                )
            at_ms = event.get("at_ms")
            if at_ms is not None and (
                isinstance(at_ms, bool) or not isinstance(at_ms, int) or at_ms < 1
            ):
                raise DeliveryInboxCacheCorrupt("accepted event at_ms is invalid")
            evicted_message_id = event.get("evicted_message_id")
            evicted_message_ids = event.get("evicted_message_ids")
            if evicted_message_id is not None and evicted_message_ids is not None:
                raise DeliveryInboxCacheCorrupt(
                    "accepted event has conflicting eviction references"
                )
            if evicted_message_ids is not None:
                if (
                    not isinstance(evicted_message_ids, list)
                    or not evicted_message_ids
                    or len(evicted_message_ids) > self._max_entries
                    or any(not isinstance(item, str) for item in evicted_message_ids)
                    or len(set(evicted_message_ids)) != len(evicted_message_ids)
                ):
                    raise DeliveryInboxCacheCorrupt(
                        "accepted event eviction references are invalid"
                    )
                evicted_ids = evicted_message_ids
            elif evicted_message_id is not None:
                evicted_ids = [evicted_message_id]
            else:
                evicted_ids = []
            for evicted_id in evicted_ids:
                if (
                    not isinstance(evicted_id, str)
                    or _MESSAGE_ID_RE.fullmatch(evicted_id) is None
                    or evicted_id == message_id
                ):
                    raise DeliveryInboxCacheCorrupt(
                        "accepted event eviction reference is invalid"
                    )
                evicted_nonce = self._by_message_id.get(evicted_id)
                if evicted_nonce is None:
                    raise DeliveryInboxCacheCorrupt(
                        "accepted event evicts an unknown message"
                    )
                if evicted_id in self._pending_json:
                    raise DeliveryInboxCacheCorrupt(
                        "accepted event attempts to evict pending work"
                    )
            envelope_json = event.get("envelope_json")
            if envelope_json is not None:
                if not isinstance(envelope_json, str):
                    raise DeliveryInboxCacheCorrupt(
                        "accepted event envelope_json must be text"
                    )
                try:
                    envelope = TransportEnvelope.from_dict(json.loads(envelope_json))
                except (json.JSONDecodeError, TypeError, ValueError) as exc:
                    raise DeliveryInboxCacheCorrupt(
                        f"accepted event envelope_json is invalid: {exc}"
                    ) from exc
                if canonical_json(envelope.to_dict()).decode("utf-8") != envelope_json:
                    raise DeliveryInboxCacheCorrupt(
                        "accepted event envelope_json is not canonical"
                    )
                ok, reason = validate_envelope(envelope, require_signature=True)
                if not ok or envelope.message_id != message_id:
                    raise DeliveryInboxCacheCorrupt(
                        f"accepted event envelope is invalid: {reason}"
                    )
                if envelope.sender_did != sender_did or envelope.nonce != nonce:
                    raise DeliveryInboxCacheCorrupt(
                        "accepted event envelope binding mismatch"
                    )
                self._pending_json[message_id] = envelope_json
            for evicted_id in evicted_ids:
                evicted_nonce = self._by_message_id.pop(evicted_id)
                self._nonces.pop(evicted_nonce, None)
                self._pending_json.pop(evicted_id, None)
            self._by_message_id[message_id] = nonce_key
            self._nonces[nonce_key] = message_id

    @staticmethod
    def _cache_snapshot_event(
        *,
        message_id: str,
        sender_did: str,
        nonce: str,
        envelope_json: Optional[str] = None,
    ) -> Dict[str, Any]:
        event: Dict[str, Any] = {
            "event": "accepted",
            "message_id": message_id,
            "sender_did": sender_did,
            "nonce": nonce,
        }
        if envelope_json is not None:
            event["envelope_json"] = envelope_json
        return event

    def _cache_snapshot_line_size(
        self,
        *,
        message_id: str,
        sender_did: str,
        nonce: str,
        envelope_json: Optional[str] = None,
    ) -> int:
        event = self._cache_snapshot_event(
            message_id=message_id,
            sender_did=sender_did,
            nonce=nonce,
            envelope_json=envelope_json,
        )
        return len(canonical_json(event)) + 1

    def _recompute_cache_snapshot_budget(self) -> None:
        sizes: Dict[str, int] = {}
        for message_id, (sender_did, nonce) in self._by_message_id.items():
            sizes[message_id] = self._cache_snapshot_line_size(
                message_id=message_id,
                sender_did=sender_did,
                nonce=nonce,
                envelope_json=self._pending_json.get(message_id),
            )
        self._cache_snapshot_sizes = sizes
        self._cache_snapshot_bytes = sum(sizes.values())


class DeliveryInboxCacheCorrupt(RuntimeError):
    """Raised when the persisted replay cache is damaged (fail closed)."""


class DeliveryInboxFull(RuntimeError):
    """Raised when no processed replay entry can be evicted safely."""


__all__ = [
    "DEFAULT_MAX_REJECTION_LOG",
    "DEFAULT_MAX_REPLAY_ENTRIES",
    "REJECTION_LOG_MAX_BYTES",
    "DeliveryInbox",
    "DeliveryInboxCacheCorrupt",
    "DeliveryInboxFull",
    "InboxDecision",
]
