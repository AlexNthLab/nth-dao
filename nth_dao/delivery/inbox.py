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
import os
import re
import stat
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Tuple, Union

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery._journal import journal_fingerprint, recover_torn_tail
from nth_dao.delivery.envelope import (
    TransportEnvelope,
    TransportEnvelopeRejected,
    envelope_digest,
    validate_envelope,
)
from nth_dao.util.io import InterProcessLock, atomic_write_bytes, open_independent_file
from nth_dao.util.path_security import check_independent_file, path_is_linklike

logger = logging.getLogger("nth_dao.delivery")

PathLike = Union[str, Path]

DEFAULT_MAX_REPLAY_ENTRIES = 65_536
DEFAULT_MAX_REJECTION_LOG = 8_192
REJECTION_LOG_MAX_BYTES = 4 * 1024 * 1024
MAX_CACHE_JOURNAL_BYTES = 16 * 1024 * 1024
MAX_TRANSPORT_QUARANTINE_ENTRIES = 256
MAX_TRANSPORT_QUARANTINE_BYTES = 16 * 1024 * 1024
MAX_TRANSPORT_QUARANTINE_RECORD_BYTES = 2 * 1024 * 1024
_MESSAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CACHE_EVENTS = ("accepted", "processed", "evicted")
_ACCEPTED_REQUIRED_FIELDS = frozenset(
    {"event", "message_id", "sender_did", "nonce"}
)
_ACCEPTED_OPTIONAL_FIELDS = frozenset(
    {"at_ms", "envelope_json", "envelope_sha256", "evicted_message_id"}
)

AuthorizeCallable = Callable[[TransportEnvelope], Tuple[bool, str]]


@dataclass(frozen=True)
class RetainedInboxEntry:
    """A detached envelope and its durable, original intake timestamp."""

    envelope: TransportEnvelope
    accepted_at_ms: int


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
    retryable: bool = False

    def __post_init__(self) -> None:
        if self.envelope is not None and not self.accepted:
            raise ValueError("a rejected decision cannot carry an envelope")
        if type(self.retryable) is not bool or (self.retryable and (self.accepted or self.duplicate)):
            raise ValueError("only a rejected decision can be retryable")


class DeliveryInbox:
    """One receiver's fail-closed inbox over a delivery directory."""

    def __init__(
        self,
        directory: PathLike,
        *,
        authorize: Optional[AuthorizeCallable] = None,
        clock: Optional[Callable[[], int]] = None,
        max_replay_entries: int = DEFAULT_MAX_REPLAY_ENTRIES,
        reject_links: bool = False,
        evict_processed: bool = True,
        max_pending_bytes: int | None = None,
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
        if type(reject_links) is not bool:
            raise ValueError("reject_links must be a boolean")
        self._reject_links = reject_links
        if type(evict_processed) is not bool:
            raise ValueError("evict_processed must be a boolean")
        self._evict_processed = evict_processed
        if max_pending_bytes is not None and (
            isinstance(max_pending_bytes, bool) or not isinstance(max_pending_bytes, int) or max_pending_bytes < 1
        ):
            raise ValueError("max_pending_bytes must be a positive integer")
        self._max_pending_bytes = max_pending_bytes
        self._thread_lock = threading.RLock()
        if self._reject_links:
            for path in (self._cache_path, self._rejection_path):
                check_independent_file(path, missing_ok=True)
        self._dir.mkdir(parents=True, exist_ok=True)
        # message_id -> (sender_did, nonce); insertion order = eviction order
        self._by_message_id: "OrderedDict[str, Tuple[str, str]]" = OrderedDict()
        self._accepted_at_ms: Dict[str, int] = {}
        self._envelope_digests: dict[str, str] = {}
        self._nonces: Dict[Tuple[str, str], str] = {}
        self._pending_json: "OrderedDict[str, str]" = OrderedDict()
        self._cache_stat: Optional[Tuple[int, ...]] = None
        self._cache_seen = False
        with self._process_lock():
            self._load_cache_locked()

    def _process_lock(self) -> InterProcessLock:
        if self._reject_links:
            return InterProcessLock(self._lock_path, reject_links=True)
        return InterProcessLock(self._lock_path)

    def _open_storage(self, path: Path, mode: str):
        if self._reject_links:
            return open_independent_file(path, mode)
        return open(path, mode)

    def _storage_metadata(self, path: Path):
        if self._reject_links:
            return check_independent_file(path)
        return path.stat()

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
        if self._authorize is not None:
            retryable = False
            try:
                allowed, authorize_reason = self._authorize(envelope)
            except Exception:
                logger.exception("delivery inbox authorization callback failed")
                allowed, authorize_reason = False, "authorization callback failed"
                retryable = True
            if not allowed:
                return self._reject(
                    envelope.message_id,
                    envelope.sender_did,
                    authorize_reason or "unauthorized",
                    retryable=retryable,
                )

        replayed = False
        full = False
        with self._thread_lock:
            with self._process_lock():
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
                    except DeliveryInboxFull:
                        full = True
        if replayed:
            return self._reject(
                envelope.message_id,
                envelope.sender_did,
                "replayed nonce",
                replayed=True,
            )
        if full:
            return self._reject(
                envelope.message_id,
                envelope.sender_did,
                ("inbox replay cache is full of unprocessed envelopes" if self._evict_processed
                 else "inbox replay cache retains all envelopes at capacity"),
                retryable=True,
            )
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
            with self._process_lock():
                self._refold_if_changed_locked()
                return message_id in self._by_message_id

    def accepted_at(self, message_id: str) -> Optional[int]:
        """Return the durable first-acceptance time for one message.

        Legacy compacted records may not contain ``at_ms`` and return
        ``None``. Callers must use a deterministic fallback in that case.
        """

        if (
            not isinstance(message_id, str)
            or _MESSAGE_ID_RE.fullmatch(message_id) is None
        ):
            raise ValueError("message_id is not a content address")
        with self._thread_lock:
            with self._process_lock():
                self._refold_if_changed_locked()
                accepted_at_ms = self._accepted_at_ms.get(message_id, 0)
                return accepted_at_ms or None

    def entry_count(self) -> int:
        with self._thread_lock:
            with self._process_lock():
                self._refold_if_changed_locked()
                return len(self._by_message_id)

    def processed_message_ids(self, *, max_items: int = 64) -> tuple[str, ...]:
        """Enumerate durable handled identities, independently of a new lease."""
        if isinstance(max_items, bool) or not isinstance(max_items, int) or max_items < 1:
            raise ValueError("max_items must be a positive integer")
        with self._thread_lock, self._process_lock():
            self._refold_if_changed_locked()
            return tuple(message_id for message_id in self._by_message_id
                         if message_id not in self._pending_json)[:max_items]

    def pending(self, *, max_items: int = 64) -> list[TransportEnvelope]:
        """Return durably accepted envelopes awaiting business processing."""

        if isinstance(max_items, bool) or not isinstance(max_items, int) or max_items < 1:
            raise ValueError("max_items must be a positive integer")
        with self._thread_lock:
            with self._process_lock():
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

    def retained_pending(self, message_id: str) -> RetainedInboxEntry | None:
        """Read payload and first-intake time together, never a supplied timestamp."""
        if not isinstance(message_id, str) or _MESSAGE_ID_RE.fullmatch(message_id) is None:
            raise ValueError("message_id is not a content address")
        with self._thread_lock, self._process_lock():
            self._refold_if_changed_locked()
            encoded = self._pending_json.get(message_id)
            if encoded is None:
                return None
            accepted_at = self._accepted_at_ms.get(message_id)
            if not accepted_at:
                raise DeliveryInboxCacheCorrupt("pending intake lacks its original timestamp")
            envelope = TransportEnvelope.from_dict(json.loads(encoded))
            valid, reason = validate_envelope(envelope, now_ms=accepted_at, require_signature=True)
            if not valid or envelope.message_id != message_id:
                raise DeliveryInboxCacheCorrupt(f"invalid retained intake: {reason}")
            return RetainedInboxEntry(envelope=envelope, accepted_at_ms=accepted_at)

    def quarantine_transport_item(
        self, item: Mapping[str, Any], *, transport: str, reason: str, at_ms: int,
    ) -> None:
        """Durably isolate rejected wire bytes before releasing a provider lease.

        This bounded local evidence store grants no business or replay authority.
        Exact descriptors are idempotent; capacity failure never evicts evidence.
        """
        if not isinstance(transport, str) or not transport or len(transport) > 256:
            raise ValueError("quarantine transport must be bounded text")
        if not isinstance(reason, str) or not reason or len(reason) > 512:
            raise ValueError("quarantine reason must be bounded text")
        if isinstance(at_ms, bool) or not isinstance(at_ms, int) or at_ms < 1:
            raise ValueError("quarantine time must be positive integer ms")
        descriptor = json.loads(canonical_json({"transport": transport, "item": dict(item)}))
        digest = sha256(canonical_json(descriptor)).hexdigest()
        raw = canonical_json({"version": 1, **descriptor, "reason": reason, "at_ms": at_ms})
        if len(raw) > MAX_TRANSPORT_QUARANTINE_RECORD_BYTES:
            raise DeliveryInboxFull("transport quarantine record exceeds the byte limit")
        directory = self._dir / "transport_quarantine"
        path = directory / f"{digest}.json"
        with self._thread_lock, self._process_lock():
            if self._reject_links and any(path_is_linklike(p) for p in (directory, *directory.parents)):
                raise ValueError("transport quarantine path traverses a link")
            directory.mkdir(parents=True, exist_ok=True)
            try:
                metadata = self._storage_metadata(path)
            except FileNotFoundError:
                metadata = None
            if metadata is not None:
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_TRANSPORT_QUARANTINE_RECORD_BYTES:
                    raise DeliveryInboxCacheCorrupt("retained transport quarantine file is unsafe")
                with self._open_storage(path, "rb") as handle:
                    retained_raw = handle.read(MAX_TRANSPORT_QUARANTINE_RECORD_BYTES + 1)
                try:
                    retained = json.loads(retained_raw)
                    valid = (
                        canonical_json(retained) == retained_raw
                        and set(retained) == {"version", "transport", "item", "reason", "at_ms"}
                        and type(retained["version"]) is int and retained["version"] == 1
                        and type(retained["at_ms"]) is int and retained["at_ms"] > 0
                        and isinstance(retained["reason"], str) and 0 < len(retained["reason"]) <= 512
                        and canonical_json({"transport": retained["transport"], "item": retained["item"]})
                        == canonical_json(descriptor)
                    )
                except (TypeError, ValueError, KeyError, RecursionError) as exc:
                    raise DeliveryInboxCacheCorrupt("retained transport quarantine is invalid") from exc
                if not valid:
                    raise DeliveryInboxCacheCorrupt("retained transport quarantine binding differs")
                return
            files = list(directory.iterdir())
            total = 0
            for entry in files:
                entry_metadata = self._storage_metadata(entry)
                if not stat.S_ISREG(entry_metadata.st_mode):
                    raise DeliveryInboxCacheCorrupt("transport quarantine contains an unsafe entry")
                total += entry_metadata.st_size
            if len(files) >= MAX_TRANSPORT_QUARANTINE_ENTRIES or total + len(raw) > MAX_TRANSPORT_QUARANTINE_BYTES:
                raise DeliveryInboxFull("transport quarantine is at capacity")
            atomic_write_bytes(path, raw, reject_links=self._reject_links)
            if os.name != "nt":
                fd = os.open(self._dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)

    def retained_duplicate(self, encoded: str) -> InboxDecision | None:
        """Recognize exact prior wire bytes, not a fresh intake after expiry.

        Old journals without a retained digest fail closed and cannot use this
        recovery path. Domain processing still rechecks its own authorization.
        """
        envelope, rejected = self._parse(encoded)
        if rejected is not None:
            return rejected
        assert envelope is not None
        valid, _reason = validate_envelope(envelope, require_signature=True)
        if not valid:
            return None
        digest = envelope_digest(envelope)
        with self._thread_lock, self._process_lock():
            self._refold_if_changed_locked()
            accepted_at = self._accepted_at_ms.get(envelope.message_id)
            if not accepted_at or self._envelope_digests.get(envelope.message_id) != digest:
                return None
            valid, _reason = validate_envelope(envelope, now_ms=accepted_at, require_signature=True)
            if not valid:
                return None
        if self._authorize is not None:
            try:
                allowed, reason = self._authorize(envelope)
            except Exception:
                logger.exception("delivery inbox authorization callback failed")
                return self._reject(envelope.message_id, envelope.sender_did,
                                    "authorization callback failed", retryable=True)
            if not allowed:
                return self._reject(envelope.message_id, envelope.sender_did, reason or "unauthorized")
        return InboxDecision(accepted=False, reason="duplicate", message_id=envelope.message_id,
                             envelope_sha256=digest, duplicate=True)

    def mark_processed(self, message_id: str) -> bool:
        """Durably mark one accepted envelope as handled by the domain layer."""

        if not isinstance(message_id, str) or _MESSAGE_ID_RE.fullmatch(message_id) is None:
            raise ValueError("message_id is not a content address")
        with self._thread_lock:
            with self._process_lock():
                self._refold_if_changed_locked()
                if message_id not in self._by_message_id:
                    raise KeyError(message_id)
                if message_id not in self._pending_json:
                    return False
                self._append_cache_locked(
                    {"event": "processed", "message_id": message_id}
                )
                self._pending_json.pop(message_id, None)
                self._compact_if_oversized_locked()
                return True

    def compact_rejections(self, max_keep: int = DEFAULT_MAX_REJECTION_LOG) -> int:
        """Trim the rejection log to the most recent ``max_keep`` lines."""

        if max_keep < 1:
            raise ValueError("max_keep must be a positive integer")
        with self._process_lock():
            if not self._rejection_path.exists():
                return 0
            with self._open_storage(self._rejection_path, "rb") as handle:
                lines = handle.read().splitlines()
            kept = lines[-max_keep:]
            atomic_write_bytes(self._rejection_path, b"".join(line + b"\n" for line in kept),
                               reject_links=self._reject_links)
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
        retryable: bool = False,
    ) -> InboxDecision:
        decision = InboxDecision(
            accepted=False,
            reason=reason,
            message_id=message_id,
            replayed=replayed,
            retryable=retryable,
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
                self._process_lock(),
                self._open_storage(self._rejection_path, "ab") as handle,
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
            if self._storage_metadata(self._rejection_path).st_size <= REJECTION_LOG_MAX_BYTES:
                return
            with self._process_lock():
                # re-stat under the lock: another process may have trimmed
                if self._storage_metadata(self._rejection_path).st_size <= REJECTION_LOG_MAX_BYTES:
                    return
                with self._open_storage(self._rejection_path, "rb") as handle:
                    lines = handle.read().splitlines()
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
                atomic_write_bytes(self._rejection_path, b"".join(line + b"\n" for line in kept),
                                   reject_links=self._reject_links)
                logger.warning(
                    "inbox rejection journal exceeded %d bytes; trimmed to the "
                    "newest %d entries", REJECTION_LOG_MAX_BYTES, len(kept),
                )
        except OSError as exc:  # pragma: no cover - trim is best-effort
            logger.warning("could not trim inbox rejection journal: %s", exc)

    def _remember_locked(self, envelope: TransportEnvelope, now_ms: int) -> None:
        """Persist an accepted envelope while holding the process lock."""

        message_id = envelope.message_id
        nonce_key = (envelope.sender_did, envelope.nonce)
        evicted_id: Optional[str] = None
        evicted_key: Optional[Tuple[str, str]] = None
        if len(self._by_message_id) >= self._max_entries:
            if not self._evict_processed:
                raise DeliveryInboxFull("replay cache retains all envelopes at capacity")
            for candidate_id, candidate_key in self._by_message_id.items():
                if candidate_id not in self._pending_json:
                    evicted_id, evicted_key = candidate_id, candidate_key
                    break
            if evicted_id is None:
                raise DeliveryInboxFull(
                    "replay cache capacity is occupied by unprocessed envelopes"
                )

        envelope_json = canonical_json(envelope.to_dict()).decode("utf-8")
        if self._max_pending_bytes is not None and (
            sum(len(raw.encode("utf-8")) for raw in self._pending_json.values())
            + len(envelope_json.encode("utf-8")) > self._max_pending_bytes
        ):
            raise DeliveryInboxFull("pending envelope bytes exceed the intake budget")
        event: Dict[str, Any] = {
            "event": "accepted",
            "message_id": message_id,
            "sender_did": envelope.sender_did,
            "nonce": envelope.nonce,
            "at_ms": now_ms,
            "envelope_json": envelope_json,
            "envelope_sha256": envelope_digest(envelope),
        }
        if evicted_id is not None:
            # The replacement is one journal record. A torn append is ignored
            # on reload; a complete append applies both changes together.
            event["evicted_message_id"] = evicted_id
        self._append_cache_locked(event)

        self._by_message_id[message_id] = nonce_key
        self._accepted_at_ms[message_id] = now_ms
        self._envelope_digests[message_id] = event["envelope_sha256"]
        self._nonces[nonce_key] = message_id
        self._pending_json[message_id] = envelope_json
        if evicted_key is not None and evicted_id is not None:
            self._by_message_id.pop(evicted_id, None)
            self._accepted_at_ms.pop(evicted_id, None)
            self._envelope_digests.pop(evicted_id, None)
            self._nonces.pop(evicted_key, None)
            self._pending_json.pop(evicted_id, None)
        self._compact_if_oversized_locked()

    def _compact_if_oversized_locked(self) -> None:
        try:
            if self._storage_metadata(self._cache_path).st_size > MAX_CACHE_JOURNAL_BYTES:
                self._compact_cache_journal_locked()
        except OSError:  # pragma: no cover - stat after our own append
            pass

    def _append_cache_locked(self, event: Dict[str, Any]) -> None:
        self._append_cache_events_locked([event])

    def _append_cache_events_locked(self, events: list[Dict[str, Any]]) -> None:
        import os

        with self._open_storage(self._cache_path, "ab") as handle:
            for event in events:
                handle.write(canonical_json(event) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
            self._cache_seen = True
        # Windows fstat/stat disagree about ctime; sample the closed pathname
        # while the caller still owns the process lock.
        stat = self._storage_metadata(self._cache_path)
        self._cache_stat = journal_fingerprint(stat)

    def _compact_cache_journal_locked(self) -> None:
        """Rewrite the current cache state while holding the process lock."""

        lines = []
        for message_id, (sender_did, nonce) in self._by_message_id.items():
            event: Dict[str, Any] = {
                "event": "accepted", "message_id": message_id,
                "sender_did": sender_did, "nonce": nonce,
            }
            accepted_at_ms = self._accepted_at_ms.get(message_id, 0)
            if accepted_at_ms:
                event["at_ms"] = accepted_at_ms
            if message_id in self._envelope_digests:
                event["envelope_sha256"] = self._envelope_digests[message_id]
            envelope_json = self._pending_json.get(message_id)
            if envelope_json is not None:
                event["envelope_json"] = envelope_json
            lines.append(canonical_json(event) + b"\n")
        atomic_write_bytes(self._cache_path, b"".join(lines), reject_links=self._reject_links)
        stat = self._storage_metadata(self._cache_path)
        self._cache_stat = journal_fingerprint(stat)
        logger.warning(
            "inbox cache journal exceeded %d bytes; compacted to %d live entries",
            MAX_CACHE_JOURNAL_BYTES,
            len(self._by_message_id),
        )

    def _refold_if_changed_locked(self) -> None:
        """Re-fold when another process changed the cache journal."""

        try:
            stat = self._storage_metadata(self._cache_path)
        except FileNotFoundError as exc:
            if self._cache_seen:
                raise DeliveryInboxCacheCorrupt("previously retained inbox journal is missing") from exc
            return
        current = journal_fingerprint(stat)
        if current != self._cache_stat:
            logger.debug("delivery inbox cache changed on disk; re-folding")
            self._by_message_id.clear()
            self._accepted_at_ms.clear()
            self._envelope_digests.clear()
            self._nonces.clear()
            self._pending_json.clear()
            self._load_cache_locked()

    def _load_cache_locked(self) -> None:
        try:
            self._storage_metadata(self._cache_path)
        except FileNotFoundError as exc:
            if self._cache_seen:
                raise DeliveryInboxCacheCorrupt("previously retained inbox journal is missing") from exc
            self._cache_stat = None
            return
        self._cache_seen = True
        with self._open_storage(self._cache_path, "rb") as handle:
            raw = handle.read()
        self._fold_cache_lines(raw)
        recover_torn_tail(self._cache_path, raw)
        if len(raw) > MAX_CACHE_JOURNAL_BYTES:
            self._compact_cache_journal_locked()
            return
        stat = self._storage_metadata(self._cache_path)
        self._cache_stat = journal_fingerprint(stat)

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
                self._accepted_at_ms.pop(message_id, None)
                self._envelope_digests.pop(message_id, None)
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
            if evicted_message_id is not None:
                if (
                    not isinstance(evicted_message_id, str)
                    or _MESSAGE_ID_RE.fullmatch(evicted_message_id) is None
                    or evicted_message_id == message_id
                ):
                    raise DeliveryInboxCacheCorrupt(
                        "accepted event eviction reference is invalid"
                    )
                evicted_nonce = self._by_message_id.get(evicted_message_id)
                if evicted_nonce is None:
                    raise DeliveryInboxCacheCorrupt(
                        "accepted event evicts an unknown message"
                    )
                if evicted_message_id in self._pending_json:
                    raise DeliveryInboxCacheCorrupt(
                        "accepted event attempts to evict pending work"
                    )
            envelope_json = event.get("envelope_json")
            digest = event.get("envelope_sha256")
            if digest is not None and (not isinstance(digest, str) or _MESSAGE_ID_RE.fullmatch(digest) is None):
                raise DeliveryInboxCacheCorrupt("accepted envelope digest is invalid")
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
                actual_digest = envelope_digest(envelope)
                if digest is not None and digest != actual_digest:
                    raise DeliveryInboxCacheCorrupt("accepted envelope digest differs from its bytes")
                digest = actual_digest
                self._pending_json[message_id] = envelope_json
            if evicted_message_id is not None:
                evicted_nonce = self._by_message_id.pop(evicted_message_id)
                self._accepted_at_ms.pop(evicted_message_id, None)
                self._envelope_digests.pop(evicted_message_id, None)
                self._nonces.pop(evicted_nonce, None)
                self._pending_json.pop(evicted_message_id, None)
            self._by_message_id[message_id] = nonce_key
            self._accepted_at_ms[message_id] = at_ms or 0
            if digest is not None:
                self._envelope_digests[message_id] = digest
            self._nonces[nonce_key] = message_id


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
    "RetainedInboxEntry",
]
