"""Signed append-only hash-chain log for one DAO node.

Each event is signed by the local identity and linked to the previous event.
The JSONL log has one canonical event per line. Full verification checks
sequence continuity, previous hashes, and every author signature.

One node process owns a log as its writer. Federation merges independent
logs; it does not make multiple processes write the same file concurrently.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import Iterator, Optional, Tuple, Union

from nth_dao.execution_receipt import now_ms
from nth_dao.identity import AgentIdentity
from nth_dao.spine.event import GENESIS_PREV, SpineEvent, sign_event, verify_event
from nth_dao.util.io import InterProcessLock, atomic_write_bytes

MAX_SPINE_LINE_BYTES = 2 * 1024 * 1024
MAX_SPINE_APPEND_BATCH = 1_000
MAX_SPINE_VERIFIED_CACHE_BYTES = 16 * 1024 * 1024
MAX_SPINE_VERIFIED_CACHE_EVENTS = 10_000
MAX_SPINE_SEMANTIC_INDEX_SHAPES = 64
DEFAULT_SPINE_LOCK_TIMEOUT_SECONDS = 30.0
SPINE_APPEND_INTENT_VERSION = 1
MAX_SPINE_APPEND_INTENT_BYTES = MAX_SPINE_LINE_BYTES + 1_024

StorageToken = tuple[int, int, int, int, int, str]

logger = logging.getLogger(__name__)


class SpineAppendOutcomeUnknown(OSError):
    """An append may be durable and must be reconciled before retrying."""

    def __init__(self, event: SpineEvent, cause: OSError) -> None:
        self.event = event
        self.event_id = event.event_id
        super().__init__(
            "spine append outcome is unknown for event "
            f"{self.event_id}; call reconcile_append(event_id) before retrying: "
            f"{cause}"
        )


class SignedEventLog:
    """Append-only signed JSONL hash chain with an in-memory head."""

    def __init__(
        self,
        path: Union[str, Path],
        identity: AgentIdentity,
        *,
        lock_timeout: float = DEFAULT_SPINE_LOCK_TIMEOUT_SECONDS,
    ) -> None:
        self._path = Path(path)
        self._pending_path = self._path.with_name(
            self._path.name + ".append.pending"
        )
        self._identity = identity
        self._lock = threading.Lock()
        if (
            isinstance(lock_timeout, bool)
            or not isinstance(lock_timeout, (int, float))
            or lock_timeout <= 0
        ):
            raise ValueError("lock_timeout must be a positive number")
        self._lock_timeout = float(lock_timeout)
        self._head_hash = GENESIS_PREV
        self._head_seq = -1
        self._verified_cache_token: StorageToken | None = None
        self._verified_cache_events: tuple[SpineEvent, ...] = ()
        self._verified_cache_by_id: dict[str, SpineEvent] = {}
        self._semantic_cache: dict[
            tuple[str, tuple[str, ...]],
            dict[tuple[str, str], set[tuple[str, int]]],
        ] = {}
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._load_head()

    def _load_head(self) -> None:
        try:
            with InterProcessLock(
                self._path,
                timeout=self._lock_timeout,
            ):
                self._recover_pending_append_unlocked()
                events: list[SpineEvent] = []
                if self._path.exists():
                    for line_number, raw in self._raw_lines():
                        if not raw.endswith(b"\n"):
                            raise ValueError(
                                f"line {line_number}: incomplete final record"
                            )
                        if raw.strip():
                            events.append(self._decode_line(raw, line_number))
        except TimeoutError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError(
                f"spine log at {self._path} is corrupt and cannot be opened "
                f"for diagnosis or appending: {exc}"
            ) from exc
        last = events[-1] if events else None
        self._head_hash = last.content_hash if last is not None else GENESIS_PREV
        self._head_seq = last.seq if last is not None else -1

    @staticmethod
    def _encode_event(event: SpineEvent) -> bytes:
        return json.dumps(
            event.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")

    def _write_append_intent_unlocked(
        self,
        *,
        base_size: int,
        line: bytes,
    ) -> None:
        document = {
            "version": SPINE_APPEND_INTENT_VERSION,
            "base_size": base_size,
            "line": line.decode("ascii"),
            "line_sha256": hashlib.sha256(line).hexdigest(),
        }
        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        if len(encoded) > MAX_SPINE_APPEND_INTENT_BYTES:
            raise ValueError("spine append intent exceeds byte limit")
        atomic_write_bytes(self._pending_path, encoded)

    def _read_append_intent_unlocked(self) -> tuple[int, bytes] | None:
        try:
            raw = self._pending_path.read_bytes()
        except FileNotFoundError:
            return None
        if not 1 <= len(raw) <= MAX_SPINE_APPEND_INTENT_BYTES:
            raise ValueError("spine append intent exceeds byte limit")
        try:
            document = json.loads(raw.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("spine append intent is unparseable") from exc
        if not isinstance(document, dict) or set(document) != {
            "version",
            "base_size",
            "line",
            "line_sha256",
        }:
            raise ValueError("spine append intent structure is invalid")
        base_size = document["base_size"]
        line_text = document["line"]
        line_digest = document["line_sha256"]
        if (
            document["version"] != SPINE_APPEND_INTENT_VERSION
            or isinstance(base_size, bool)
            or not isinstance(base_size, int)
            or base_size < 0
            or not isinstance(line_text, str)
            or not isinstance(line_digest, str)
        ):
            raise ValueError("spine append intent fields are invalid")
        try:
            line = line_text.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("spine append intent line is not ASCII") from exc
        if (
            not 1 <= len(line) <= MAX_SPINE_LINE_BYTES
            or "\n" in line_text
            or "\r" in line_text
            or hashlib.sha256(line).hexdigest() != line_digest
        ):
            raise ValueError("spine append intent line is invalid")
        return base_size, line

    def _clear_append_intent_unlocked(self) -> None:
        self._pending_path.unlink(missing_ok=True)
        if os.name != "nt":
            parent_fd = os.open(self._pending_path.parent, os.O_RDONLY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)

    def _write_record_unlocked(self, record: bytes) -> None:
        with self._path.open("ab") as stream:
            stream.write(record)
            stream.flush()
            os.fsync(stream.fileno())

    def _recover_pending_append_unlocked(self) -> None:
        intent = self._read_append_intent_unlocked()
        if intent is None:
            return
        base_size, line = intent
        current_size = self._path.stat().st_size if self._path.exists() else 0
        if current_size < base_size:
            raise ValueError("spine append intent base exceeds log size")
        if base_size:
            with self._path.open("rb") as stream:
                stream.seek(base_size - 1)
                if stream.read(1) != b"\n":
                    raise ValueError("spine append intent base is not line-aligned")
        ok, reason, prefix_events = self._verified_events_unlocked(
            stop_offset=base_size
        )
        if not ok:
            raise ValueError(f"spine append intent prefix is corrupt: {reason}")
        event = self._decode_line(line, len(prefix_events) + 1)
        if self._encode_event(event) != line:
            raise ValueError("spine append intent event is not canonical")
        expected_prev = (
            prefix_events[-1].content_hash if prefix_events else GENESIS_PREV
        )
        expected_seq = prefix_events[-1].seq + 1 if prefix_events else 0
        valid, verify_reason = verify_event(event)
        if (
            event.seq != expected_seq
            or event.prev_hash != expected_prev
            or event.author_did != self._identity.as_did()
            or not valid
        ):
            raise ValueError(
                "spine append intent event is unauthorized or does not extend "
                f"the verified prefix: {verify_reason}"
            )

        record = line + b"\n"
        available = current_size - base_size
        existing_suffix = b""
        if available:
            with self._path.open("rb") as stream:
                stream.seek(base_size)
                existing_suffix = stream.read(min(available, len(record)))
        if existing_suffix != record[: len(existing_suffix)]:
            raise ValueError("spine append tail conflicts with signed intent")
        if available < len(record):
            if current_size:
                with self._path.open("r+b") as stream:
                    stream.truncate(base_size)
                    stream.flush()
                    os.fsync(stream.fileno())
            self._write_record_unlocked(record)

        self._verified_cache_token = None
        ok, reason, events, _token = self._verified_events_cached_unlocked()
        if not ok:
            raise ValueError(f"recovered spine append is corrupt: {reason}")
        if event.seq >= len(events) or events[event.seq] != event:
            raise ValueError("recovered spine append does not match signed intent")
        self._clear_append_intent_unlocked()

    def _decode_line(self, raw: bytes, line_number: int) -> SpineEvent:
        if len(raw) > MAX_SPINE_LINE_BYTES:
            raise ValueError(f"line {line_number}: event exceeds byte limit")
        try:
            document = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"line {line_number}: unparseable ({exc})") from exc
        try:
            return SpineEvent.from_dict(document)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"line {line_number}: invalid event structure ({exc})"
            ) from exc

    def _raw_lines(
        self,
        *,
        stop_offset: int | None = None,
    ) -> Iterator[tuple[int, bytes]]:
        with self._path.open("rb") as stream:
            if stop_offset == 0:
                return
            line_number = 0
            consumed = 0
            while True:
                raw = stream.readline(MAX_SPINE_LINE_BYTES + 1)
                if not raw:
                    if stop_offset is not None and consumed != stop_offset:
                        raise ValueError("spine append intent base exceeds log size")
                    return
                line_number += 1
                if len(raw) > MAX_SPINE_LINE_BYTES:
                    raise ValueError(
                        f"line {line_number}: event exceeds byte limit"
                    )
                consumed += len(raw)
                if stop_offset is not None and consumed > stop_offset:
                    raise ValueError(
                        "spine append intent base is not line-aligned"
                    )
                yield line_number, raw
                if stop_offset is not None and consumed == stop_offset:
                    return

    def _verified_events_unlocked(
        self,
        *,
        stop_offset: int | None = None,
    ) -> tuple[bool, str, tuple[SpineEvent, ...]]:
        if not self._path.exists():
            if stop_offset not in {None, 0}:
                return False, "spine append intent base exceeds log size", ()
            return True, "ok", ()
        expected_prev = GENESIS_PREV
        expected_seq = 0
        events: list[SpineEvent] = []
        try:
            for line_number, raw in self._raw_lines(stop_offset=stop_offset):
                if not raw.endswith(b"\n"):
                    return (
                        False,
                        f"line {line_number}: incomplete final record",
                        tuple(events),
                    )
                if not raw.strip():
                    continue
                event = self._decode_line(raw, line_number)
                if event.seq != expected_seq:
                    return (
                        False,
                        f"seq gap at {event.seq} (expected {expected_seq})",
                        tuple(events),
                    )
                if event.prev_hash != expected_prev:
                    return (
                        False,
                        f"chain break at seq {event.seq}",
                        tuple(events),
                    )
                ok, reason = verify_event(event)
                if not ok:
                    return (
                        False,
                        f"event {event.seq}: {reason}",
                        tuple(events),
                    )
                expected_prev = event.content_hash
                expected_seq += 1
                events.append(event)
        except (OSError, TypeError, ValueError) as exc:
            return False, str(exc), tuple(events)
        return True, "ok", tuple(events)

    def _remember_verified_unlocked(
        self,
        events: tuple[SpineEvent, ...],
        token: StorageToken,
    ) -> None:
        if (
            len(events) > MAX_SPINE_VERIFIED_CACHE_EVENTS
            or token[2] > MAX_SPINE_VERIFIED_CACHE_BYTES
        ):
            self._verified_cache_events = ()
            self._verified_cache_by_id = {}
            self._semantic_cache.clear()
            self._verified_cache_token = None
            return
        previous = self._verified_cache_events
        if len(events) >= len(previous) and events[: len(previous)] == previous:
            appended = events[len(previous) :]
            for event in appended:
                self._verified_cache_by_id[event.event_id] = event
            for (event_type, fields), owners in self._semantic_cache.items():
                for event in appended:
                    if event.type != event_type:
                        continue
                    for field in fields:
                        value = event.payload.get(field)
                        if isinstance(value, str) and value:
                            owners.setdefault((field, value), set()).add(
                                ("existing", event.seq)
                            )
        else:
            self._verified_cache_by_id = {
                event.event_id: event for event in events
            }
            self._semantic_cache.clear()
        self._verified_cache_events = events
        self._verified_cache_token = token

    def _semantic_owners_unlocked(
        self,
        event_type: str,
        fields: tuple[str, ...],
        events: tuple[SpineEvent, ...],
    ) -> dict[tuple[str, str], set[tuple[str, int]]]:
        cache_key = (event_type, fields)
        retained = self._semantic_cache.get(cache_key)
        if retained is None:
            retained = {}
            for event in events:
                if event.type != event_type:
                    continue
                for field in fields:
                    value = event.payload.get(field)
                    if isinstance(value, str) and value:
                        retained.setdefault((field, value), set()).add(
                            ("existing", event.seq)
                        )
            if self._verified_cache_token is not None:
                if len(self._semantic_cache) >= MAX_SPINE_SEMANTIC_INDEX_SHAPES:
                    self._semantic_cache.pop(next(iter(self._semantic_cache)))
                self._semantic_cache[cache_key] = retained
        return {key: set(owners) for key, owners in retained.items()}

    def _verified_events_cached_unlocked(
        self,
    ) -> tuple[bool, str, tuple[SpineEvent, ...], StorageToken | None]:
        events: tuple[SpineEvent, ...] = ()
        for _attempt in range(3):
            token_before = self.storage_token()
            if self._verified_cache_token == token_before:
                return True, "ok", self._verified_cache_events, token_before
            ok, reason, events = self._verified_events_unlocked()
            if not ok:
                self._verified_cache_events = ()
                self._verified_cache_by_id = {}
                self._semantic_cache.clear()
                self._verified_cache_token = None
                return False, reason, events, None
            token_after = self.storage_token()
            if token_before != token_after:
                continue
            self._remember_verified_unlocked(events, token_after)
            return True, "ok", events, token_after
        self._verified_cache_events = ()
        self._verified_cache_by_id = {}
        self._semantic_cache.clear()
        self._verified_cache_token = None
        return (
            False,
            "spine changed repeatedly during verification",
            events,
            None,
        )

    def _scan_verified(
        self,
    ) -> tuple[bool, str, Optional[SpineEvent]]:
        ok, reason, events, _token = self._verified_events_cached_unlocked()
        return ok, reason, events[-1] if events else None

    def read_all(self) -> Iterator[SpineEvent]:
        """Yield stored events in order without verifying the full chain."""
        if not self._path.exists():
            return
        for line_number, raw in self._raw_lines():
            if raw.strip():
                yield self._decode_line(raw, line_number)

    @property
    def head_hash(self) -> str:
        return self._head_hash

    @property
    def head_seq(self) -> int:
        return self._head_seq

    @property
    def signer_did(self) -> str:
        """Return the DID authorized to append through this log instance."""

        return self._identity.as_did()

    def storage_token(self) -> StorageToken:
        """Return a content-bound invalidation token for the on-disk log."""

        try:
            digest = hashlib.sha256()
            with self._path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
                metadata = os.fstat(stream.fileno())
        except FileNotFoundError:
            return (0, 0, 0, 0, 0, "")
        return (
            int(getattr(metadata, "st_dev", 0)),
            int(getattr(metadata, "st_ino", 0)),
            int(metadata.st_size),
            int(metadata.st_mtime_ns),
            int(metadata.st_ctime_ns),
            digest.hexdigest(),
        )

    def _token_after_expected_append(
        self,
        prefix_token: StorageToken,
        suffix: bytes,
    ) -> StorageToken:
        """Bind a verified prefix to exact newly appended bytes without rescanning events."""

        prefix_size = prefix_token[2]
        expected_size = prefix_size + len(suffix)
        digest = hashlib.sha256()
        try:
            with self._path.open("rb") as stream:
                remaining = prefix_size
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("spine verified prefix was truncated")
                    digest.update(chunk)
                    remaining -= len(chunk)
                expected_prefix_digest = prefix_token[5] or hashlib.sha256(
                    b""
                ).hexdigest()
                if digest.hexdigest() != expected_prefix_digest:
                    raise ValueError("spine verified prefix changed before append")
                retained_suffix = stream.read(len(suffix))
                if retained_suffix != suffix or stream.read(1):
                    raise ValueError("spine appended bytes do not match signed events")
                digest.update(retained_suffix)
                metadata = os.fstat(stream.fileno())
        except FileNotFoundError as exc:
            raise ValueError("spine disappeared after append") from exc
        if metadata.st_size != expected_size:
            raise ValueError("spine size changed after append")
        return (
            int(getattr(metadata, "st_dev", 0)),
            int(getattr(metadata, "st_ino", 0)),
            int(metadata.st_size),
            int(metadata.st_mtime_ns),
            int(metadata.st_ctime_ns),
            digest.hexdigest(),
        )

    def verified_snapshot_with_token(
        self,
    ) -> tuple[StorageToken, tuple[SpineEvent, ...]]:
        """Return a storage token and events from one verified lock snapshot."""

        with self._lock:
            with InterProcessLock(
                self._path,
                timeout=self._lock_timeout,
            ):
                self._recover_pending_append_unlocked()
                ok, reason, events, token = self._verified_events_cached_unlocked()
                if not ok:
                    raise ValueError(
                        f"spine log at {self._path} is corrupt: {reason}"
                    )
                if token is None:
                    raise RuntimeError("verified spine snapshot has no storage token")
                return token, events

    def append(
        self, event_type: str, payload: dict, *, ts_ms: Optional[int] = None,
    ) -> SpineEvent:
        """Sign and append one non-idempotent event.

        If this raises :class:`SpineAppendOutcomeUnknown`, callers must invoke
        :meth:`reconcile_append` with the exception's ``event_id`` before they
        consider issuing a new append. Business writes with semantic keys
        should use :meth:`append_unique` instead.
        """
        with self._lock:
            with InterProcessLock(
                self._path,
                timeout=self._lock_timeout,
            ):
                self._recover_pending_append_unlocked()
                # A second process may have advanced the chain since this
                # instance was constructed.
                ok, reason, events, token = self._verified_events_cached_unlocked()
                if not ok:
                    raise ValueError(
                        f"spine log at {self._path} is corrupt and cannot be "
                        f"appended: {reason}"
                    )
                if token is None:
                    raise RuntimeError("verified spine prefix has no storage token")
                event = self._append_after_verified(
                    event_type,
                    payload,
                    ts_ms=ts_ms,
                    last=events[-1] if events else None,
                )
                appended_events = events + (event,)
                appended_token = self._token_after_expected_append(
                    token,
                    self._encode_event(event) + b"\n",
                )
                self._remember_verified_unlocked(appended_events, appended_token)
                return event

    def _append_after_verified(
        self,
        event_type: str,
        payload: dict,
        *,
        ts_ms: Optional[int],
        last: Optional[SpineEvent],
    ) -> SpineEvent:
        self._verified_cache_token = None
        self._head_hash = (
            last.content_hash if last is not None else GENESIS_PREV
        )
        self._head_seq = last.seq if last is not None else -1
        event = sign_event(
            seq=self._head_seq + 1,
            prev_hash=self._head_hash,
            event_type=event_type,
            payload=payload,
            identity=self._identity,
            ts_ms=ts_ms if ts_ms is not None else now_ms(),
        )
        line = self._encode_event(event)
        if len(line) > MAX_SPINE_LINE_BYTES:
            raise ValueError("spine event exceeds line byte limit")
        base_size = self._path.stat().st_size if self._path.exists() else 0
        try:
            self._write_append_intent_unlocked(base_size=base_size, line=line)
        except OSError as exc:
            try:
                persisted_intent = self._read_append_intent_unlocked()
            except (OSError, ValueError):
                raise SpineAppendOutcomeUnknown(event, exc) from exc
            if persisted_intent is not None:
                raise SpineAppendOutcomeUnknown(event, exc) from exc
            raise
        try:
            self._write_record_unlocked(line + b"\n")
        except OSError as exc:
            raise SpineAppendOutcomeUnknown(event, exc) from exc
        try:
            self._clear_append_intent_unlocked()
        except OSError as exc:
            logger.warning(
                "spine event %s is durable but append intent cleanup failed: %s",
                event.event_id,
                exc,
            )
        self._head_hash = event.content_hash
        self._head_seq = event.seq
        return event

    def reconcile_append(self, event_id: str) -> Optional[SpineEvent]:
        """Recover pending I/O and return the exact committed event, if any.

        ``None`` means recovery completed and that event ID is absent, so the
        caller may safely decide whether to issue a new append.
        """

        if (
            not isinstance(event_id, str)
            or len(event_id) != 64
            or any(character not in "0123456789abcdef" for character in event_id)
        ):
            raise ValueError("event_id must be 64 lowercase hexadecimal characters")
        with self._lock:
            with InterProcessLock(
                self._path,
                timeout=self._lock_timeout,
            ):
                self._recover_pending_append_unlocked()
                ok, reason, events, _token = self._verified_events_cached_unlocked()
                if not ok:
                    raise ValueError(
                        f"spine log at {self._path} is corrupt and cannot "
                        f"reconcile an append: {reason}"
                    )
                last = events[-1] if events else None
                self._head_hash = (
                    last.content_hash if last is not None else GENESIS_PREV
                )
                self._head_seq = last.seq if last is not None else -1
                cached = self._verified_cache_by_id.get(event_id)
                if cached is not None:
                    return cached
                return next(
                    (event for event in events if event.event_id == event_id),
                    None,
                )

    def verified_snapshot(self) -> tuple[SpineEvent, ...]:
        """Return one lock-consistent, signature-verified event snapshot."""

        with self._lock:
            with InterProcessLock(
                self._path,
                timeout=self._lock_timeout,
            ):
                self._recover_pending_append_unlocked()
                ok, reason, events, _token = self._verified_events_cached_unlocked()
                if not ok:
                    raise ValueError(
                        f"spine log at {self._path} is corrupt and cannot be "
                        f"read as a verified snapshot: {reason}"
                    )
                return events

    def append_unique(
        self,
        event_type: str,
        payload: dict,
        *,
        unique_payload_fields: tuple[str, ...],
        ts_ms: Optional[int] = None,
    ) -> tuple[SpineEvent, bool]:
        """Append once, rejecting any event that reuses a semantic key."""

        return self.append_unique_many(
            event_type,
            (payload,),
            unique_payload_fields=unique_payload_fields,
            ts_ms=ts_ms,
        )[0]

    def append_unique_many(
        self,
        event_type: str,
        payloads: tuple[dict, ...],
        *,
        unique_payload_fields: tuple[str, ...],
        ts_ms: Optional[int] = None,
    ) -> tuple[tuple[SpineEvent, bool], ...]:
        """Append one idempotent batch after a single verified scan.

        All semantic conflicts are checked before the first write. An I/O
        failure may still leave a valid prefix, which remains retryable by the
        same semantic keys.
        """

        if (
            not isinstance(unique_payload_fields, tuple)
            or not unique_payload_fields
            or any(
                not isinstance(field, str) or not field
                for field in unique_payload_fields
            )
            or len(set(unique_payload_fields)) != len(unique_payload_fields)
        ):
            raise ValueError(
                "unique_payload_fields must be unique non-empty strings"
            )
        if not isinstance(payloads, tuple):
            raise ValueError("payloads must be a tuple")
        if not payloads:
            return ()
        if len(payloads) > MAX_SPINE_APPEND_BATCH:
            raise ValueError(
                f"payload batch exceeds {MAX_SPINE_APPEND_BATCH} events"
            )
        for payload in payloads:
            if not isinstance(payload, dict):
                raise ValueError("payload must be an object")
            for field in unique_payload_fields:
                if (
                    field not in payload
                    or not isinstance(payload[field], str)
                    or not payload[field]
                ):
                    raise ValueError(
                        f"unique payload field {field!r} must be a non-empty string"
                    )
        with self._lock:
            with InterProcessLock(
                self._path,
                timeout=self._lock_timeout,
            ):
                self._recover_pending_append_unlocked()
                ok, reason, events, token = self._verified_events_cached_unlocked()
                if not ok:
                    raise ValueError(
                        f"spine log at {self._path} is corrupt and cannot be "
                        f"appended: {reason}"
                    )
                if token is None:
                    raise RuntimeError("verified spine prefix has no storage token")
                owners = self._semantic_owners_unlocked(
                    event_type,
                    unique_payload_fields,
                    events,
                )
                planned: list[dict] = []
                resolutions: list[tuple[tuple[str, int], bool]] = []
                for payload in payloads:
                    matched: set[tuple[str, int]] = set()
                    for field in unique_payload_fields:
                        matched.update(
                            owners.get((field, payload[field]), set())
                        )
                    if len(matched) > 1:
                        raise ValueError(
                            "spine contains duplicate semantic event keys"
                        )
                    if matched:
                        owner = next(iter(matched))
                        owner_payload = (
                            events[owner[1]].payload
                            if owner[0] == "existing"
                            else planned[owner[1]]
                        )
                        if owner_payload != payload:
                            raise ValueError(
                                "spine semantic event key has conflicting payload"
                            )
                        resolutions.append((owner, False))
                        continue
                    owner = ("planned", len(planned))
                    planned.append(payload)
                    resolutions.append((owner, True))
                    for field in unique_payload_fields:
                        owners.setdefault((field, payload[field]), set()).add(
                            owner
                        )

                appended: list[SpineEvent] = []
                last = events[-1] if events else None
                for payload in planned:
                    event = self._append_after_verified(
                        event_type,
                        payload,
                        ts_ms=ts_ms,
                        last=last,
                    )
                    appended.append(event)
                    last = event
                appended_events = events + tuple(appended)
                appended_token = self._token_after_expected_append(
                    token,
                    b"".join(self._encode_event(event) + b"\n" for event in appended),
                )
                self._remember_verified_unlocked(appended_events, appended_token)
                return tuple(
                    (
                        events[owner[1]]
                        if owner[0] == "existing"
                        else appended[owner[1]],
                        created,
                    )
                    for owner, created in resolutions
                )

    def verify_chain(self) -> Tuple[bool, str]:
        """Verify sequence, links, structure, and signatures fail-closed.

        Corrupt JSON or malformed event rows return ``(False, reason)``.
        Integrity verification must not crash and accidentally hide tampering.
        """
        with self._lock:
            with InterProcessLock(
                self._path,
                timeout=self._lock_timeout,
            ):
                try:
                    self._recover_pending_append_unlocked()
                except (OSError, TypeError, ValueError) as exc:
                    return False, str(exc)
                ok, reason, _events = self._verified_events_unlocked()
                return ok, reason
