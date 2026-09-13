"""Durable outbox for signed transport envelopes (delivery layer v1).

Extracted as the generic delivery core from the patterns proven by
``nth_dao.commerce.outbox`` and ``nth_dao.trade_rules.execution_dispatch``,
per the integration design doc §9: commerce replication becomes one USER of
this core instead of every subsystem carrying its own outbox copy.

Guarantees:

* **Crash-safe** — every state change is one appended JSONL line, flushed
  and fsynced before the call returns. A process crash between "write" and
  "acknowledge" replays from the journal on the next load. A torn final
  line (crash mid-append) is ignored on recovery; corruption anywhere else
  fails closed.
* **Idempotent** — enqueueing the same ``message_id`` twice never creates a
  second record.
* **ACK-terminal** — one authorized signed ACK for the exact queued envelope
  marks it delivered and cancels every other in-flight copy.
* **Cross-process safe** — journal mutation happens under an
  ``InterProcessLock`` on the journal file.
* **Bounded** — non-terminal record count is capped; enqueue fails closed
  with :class:`DeliveryOutboxFull` instead of silently growing.

The outbox never interprets payloads. It stores canonical envelope bytes
and moves records between states; business semantics stay in the domain
layer exactly as the design doc §5.1 requires.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Union

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.acknowledgement import (
    DeliveryAck,
    validate_ack,
)
from nth_dao.delivery.authorization import (
    AuthorizationDecision,
    AuthorizationResult,
    coerce_authorization_decision,
)
from nth_dao.delivery.envelope import (
    MAX_CLOCK_SKEW_MS,
    MAX_ENVELOPE_BYTES,
    MAX_SAFE_INTEGER,
    TransportEnvelope,
    TransportEnvelopeRejected,
    envelope_digest,
    validate_envelope,
)
from nth_dao.did_key import DIDKeyError, decode_ed25519_did_key
from nth_dao.util.io import InterProcessLock

logger = logging.getLogger("nth_dao.delivery")

PathLike = Union[str, Path]
AckAuthorizer = Callable[[DeliveryAck, TransportEnvelope], AuthorizationResult]

OUTBOX_STATE_QUEUED = "queued"
OUTBOX_STATE_DELIVERED = "delivered"
OUTBOX_STATE_REJECTED = "rejected"
OUTBOX_STATE_EXPIRED = "expired"
OUTBOX_TERMINAL_STATES = (OUTBOX_STATE_DELIVERED, OUTBOX_STATE_REJECTED, OUTBOX_STATE_EXPIRED)

OUTBOX_ATTEMPT_SENT = "sent"
OUTBOX_ATTEMPT_ERROR = "error"
OUTBOX_ATTEMPT_REJECTED = "rejected"
OUTBOX_ATTEMPT_OUTCOMES = (OUTBOX_ATTEMPT_SENT, OUTBOX_ATTEMPT_ERROR, OUTBOX_ATTEMPT_REJECTED)

DEFAULT_MAX_PENDING_RECORDS = 4_096
DEFAULT_MAX_TERMINAL_TOMBSTONES = 65_536
MAX_ATTEMPTS_PER_RECORD = 256
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
MAX_TOMBSTONE_FILE_BYTES = 32 * 1024 * 1024
_JOURNAL_EVENTS = ("enqueued", "attempt", "delivered", "rejected", "expired")
_MESSAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TRANSPORT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_EVENT_FIELDS = {
    "enqueued": frozenset(
        {
            "event",
            "message_id",
            "envelope_json",
            "envelope_sha256",
            "created_at_ms",
            "expires_at_ms",
            "at_ms",
        }
    ),
    "attempt": frozenset({"event", "message_id", "transport", "at_ms", "outcome"}),
    "delivered": frozenset({"event", "message_id", "at_ms", "ack_json"}),
    "rejected": frozenset(
        {"event", "message_id", "transport", "at_ms", "error_code"}
    ),
    "expired": frozenset({"event", "message_id", "at_ms"}),
}
_TOMBSTONE_FIELDS = frozenset(
    {
        "message_id",
        "envelope_sha256",
        "state",
        "compacted_at_ms",
        "delivered_by",
        "delivered_at_ms",
        "last_error_code",
    }
)
MAX_ERROR_CODE_LENGTH = 256


class DeliveryOutboxError(RuntimeError):
    """Base error for outbox operation failures."""


class DeliveryAckAuthorizationError(DeliveryOutboxError):
    """Structured, fail-closed rejection at the shared-recipient ACK boundary."""

    def __init__(self, decision: AuthorizationDecision) -> None:
        normalized = coerce_authorization_decision(decision)
        if normalized.allowed:
            raise ValueError("ACK authorization errors require a denied decision")
        self.decision = normalized
        self.code = normalized.code
        self.retryable = normalized.retryable
        super().__init__(normalized.reason)


class DeliveryOutboxFull(DeliveryOutboxError):
    """Raised when the pending-record cap is reached (fail closed)."""


class DeliveryOutboxCorrupt(DeliveryOutboxError):
    """Raised when the journal is damaged beyond a torn final line."""


@dataclass
class OutboxAttempt:
    transport: str
    at_ms: int
    outcome: str
    error_code: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "transport": self.transport,
            "at_ms": self.at_ms,
            "outcome": self.outcome,
        }
        if self.error_code:
            data["error_code"] = self.error_code
        return data


@dataclass
class OutboxRecord:
    message_id: str
    envelope_json: str
    envelope_sha256: str
    created_at_ms: int
    expires_at_ms: int
    state: str = OUTBOX_STATE_QUEUED
    attempts: List[OutboxAttempt] = field(default_factory=list)
    delivered_by: str = ""
    delivered_at_ms: int = 0
    last_error_code: str = ""

    @property
    def is_terminal(self) -> bool:
        return self.state in OUTBOX_TERMINAL_STATES


@dataclass(frozen=True)
class _OutboxTombstone:
    message_id: str
    envelope_sha256: str
    state: str
    compacted_at_ms: int
    delivered_by: str = ""
    delivered_at_ms: int = 0
    last_error_code: str = ""


def _validate_transport_name(value: Any) -> str:
    if not isinstance(value, str) or _TRANSPORT_NAME_RE.fullmatch(value) is None:
        raise DeliveryOutboxError("transport name must be a bounded identifier")
    return value


def _validate_error_code(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > MAX_ERROR_CODE_LENGTH
        or (bool(value) and not value.isprintable())
    ):
        raise DeliveryOutboxError(
            "error_code must be printable text no longer than "
            f"{MAX_ERROR_CODE_LENGTH} UTF-8 bytes"
        )
    return value


def _validate_operation_time(value: Any, name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 < value <= MAX_SAFE_INTEGER
    ):
        raise DeliveryOutboxError(f"{name} must be a positive safe integer")
    return value


class DurableOutbox:
    """Append-only journal backed outbox for one workspace delivery dir."""

    def __init__(
        self,
        directory: PathLike,
        *,
        max_pending_records: int = DEFAULT_MAX_PENDING_RECORDS,
        max_terminal_tombstones: int = DEFAULT_MAX_TERMINAL_TOMBSTONES,
        clock: Optional[Callable[[], int]] = None,
        authorize_ack: Optional[AckAuthorizer] = None,
    ) -> None:
        self._dir = Path(directory)
        self._journal_path = self._dir / "outbox.journal.jsonl"
        self._tombstone_path = self._dir / "outbox.tombstones.jsonl"
        self._lock_path = self._dir / "outbox.lock"
        self._max_pending = max_pending_records
        if (
            isinstance(max_pending_records, bool)
            or not isinstance(max_pending_records, int)
            or max_pending_records < 1
        ):
            raise ValueError("max_pending_records must be a positive integer")
        if (
            isinstance(max_terminal_tombstones, bool)
            or not isinstance(max_terminal_tombstones, int)
            or max_terminal_tombstones < 1
        ):
            raise ValueError("max_terminal_tombstones must be a positive integer")
        self._max_tombstones = max_terminal_tombstones
        self._clock = clock or (lambda: int(time.time() * 1000))
        self._authorize_ack = authorize_ack
        self._records: Dict[str, OutboxRecord] = {}
        self._tombstones: "OrderedDict[str, _OutboxTombstone]" = OrderedDict()
        self._thread_lock = threading.RLock()
        self._journal_stat: Optional[tuple] = None
        self._tombstone_stat: Optional[tuple] = None
        self._dir.mkdir(parents=True, exist_ok=True)
        with InterProcessLock(self._lock_path):
            self._load()

    # ─────────────────────── persistence ───────────────────────

    def _load(self) -> None:
        """Fold the journal. Tolerates a torn final line; corrupts loudly."""

        records: Dict[str, OutboxRecord] = {}
        self._load_tombstones()
        if not self._journal_path.exists():
            self._records = records
            self._journal_stat = None
            return
        with open(self._journal_path, "rb") as handle:
            stat = os.fstat(handle.fileno())
            if stat.st_size > MAX_JOURNAL_BYTES:
                raise DeliveryOutboxCorrupt(
                    f"outbox journal exceeds {MAX_JOURNAL_BYTES} bytes; run compact() "
                    "before loading (fail closed against disk-exhaustion floods)"
                )
            raw = handle.read(MAX_JOURNAL_BYTES + 1)
        if len(raw) > MAX_JOURNAL_BYTES:
            raise DeliveryOutboxCorrupt(
                "outbox journal grew beyond its hard read limit while loading"
            )
        self._journal_stat = (stat.st_mtime_ns, stat.st_size)
        lines = raw.split(b"\n")
        torn_tail = bool(raw) and not raw.endswith(b"\n")
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            is_last = index == len(lines) - 1
            if is_last and torn_tail:
                logger.warning(
                    "delivery outbox journal has a torn final line; ignoring it "
                    "(crash during append) — %s", self._journal_path,
                )
                break
            try:
                event = json.loads(line.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise DeliveryOutboxCorrupt(
                    f"corrupt journal line {index + 1} in {self._journal_path}: {exc}"
                ) from exc
            if not isinstance(event, dict):
                raise DeliveryOutboxCorrupt(f"journal line {index + 1} is not an object")
            _fold_event(records, event)
        self._records = records

    def _refold_if_changed(self) -> None:
        """Re-fold the journal when another process mutated it on disk.

        Every mutation is journaled before it is applied in memory, so a
        re-fold is always safe and keeps enqueue idempotency, expiry, and
        compaction correct across processes.
        """

        journal_stat = _file_stat(self._journal_path)
        tombstone_stat = _file_stat(self._tombstone_path)
        if (
            journal_stat != self._journal_stat
            or tombstone_stat != self._tombstone_stat
        ):
            logger.debug("delivery outbox journal changed on disk; re-folding")
            self._records = {}
            self._tombstones = OrderedDict()
            self._load()

    def _append_locked(self, event: Dict[str, Any]) -> None:
        """Append while the caller holds ``self._lock_path``.

        State-changing operations deliberately hold one process lock across
        refold, validation, append, and the in-memory update. Locking only
        this write would leave a check-then-append race between processes.
        """

        line = canonical_json(event) + b"\n"
        with open(self._journal_path, "ab") as handle:
            handle.seek(0, os.SEEK_END)
            current_size = handle.tell()
            if current_size + len(line) > MAX_JOURNAL_BYTES:
                raise DeliveryOutboxFull(
                    "outbox journal has insufficient space for the next event; "
                    "run compact() and retry"
                )
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
            # capture our fingerprint while STILL holding the lock: a stat
            # taken after release could absorb another process's append and
            # permanently hide it from the re-fold check (round-4 bug Q)
            try:
                stat = os.fstat(handle.fileno())
                self._journal_stat = (stat.st_mtime_ns, stat.st_size)
            except OSError:  # pragma: no cover - fstat on our own fd
                pass

    def _load_tombstones(self) -> None:
        self._tombstones = OrderedDict()
        if not self._tombstone_path.exists():
            self._tombstone_stat = None
            return
        with open(self._tombstone_path, "rb") as handle:
            stat = os.fstat(handle.fileno())
            if stat.st_size > MAX_TOMBSTONE_FILE_BYTES:
                raise DeliveryOutboxCorrupt(
                    "outbox tombstone file exceeds its hard size limit"
                )
            raw = handle.read(MAX_TOMBSTONE_FILE_BYTES + 1)
        if len(raw) > MAX_TOMBSTONE_FILE_BYTES:
            raise DeliveryOutboxCorrupt(
                "outbox tombstone file grew beyond its hard read limit while loading"
            )
        if not raw.endswith(b"\n") and raw:
            raise DeliveryOutboxCorrupt("outbox tombstone file has a torn tail")
        for index, line in enumerate(raw.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line.decode("utf-8"))
                tombstone = _parse_tombstone(event)
            except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError) as exc:
                raise DeliveryOutboxCorrupt(
                    f"invalid outbox tombstone line {index}: {exc}"
                ) from exc
            if tombstone.message_id in self._tombstones:
                raise DeliveryOutboxCorrupt("duplicate outbox tombstone message_id")
            self._tombstones[tombstone.message_id] = tombstone
        if len(self._tombstones) > self._max_tombstones:
            raise DeliveryOutboxCorrupt("outbox tombstone count exceeds configured limit")
        self._tombstone_stat = (stat.st_mtime_ns, stat.st_size)

    def _write_tombstones_locked(
        self, tombstones: "OrderedDict[str, _OutboxTombstone]"
    ) -> "OrderedDict[str, _OutboxTombstone]":
        # Keep a contiguous newest-first retention window. Count alone is not
        # sufficient because UTF-8 metadata sizes vary; writing a file larger
        # than our own read ceiling would make the next process fail to start.
        selected_newest: list[tuple[str, _OutboxTombstone, bytes]] = []
        selected_bytes = 0
        for message_id, tombstone in reversed(tombstones.items()):
            try:
                validated = _parse_tombstone(_tombstone_dict(tombstone))
                line = canonical_json(_tombstone_dict(validated)) + b"\n"
            except (TypeError, ValueError) as exc:
                raise DeliveryOutboxCorrupt(
                    f"cannot persist invalid outbox tombstone: {exc}"
                ) from exc
            if len(line) > MAX_TOMBSTONE_FILE_BYTES:
                raise DeliveryOutboxCorrupt(
                    "one outbox tombstone exceeds the hard file size limit"
                )
            if len(selected_newest) >= self._max_tombstones:
                break
            if selected_bytes + len(line) > MAX_TOMBSTONE_FILE_BYTES:
                break
            selected_newest.append((message_id, validated, line))
            selected_bytes += len(line)

        selected = OrderedDict(
            (message_id, tombstone)
            for message_id, tombstone, _line in reversed(selected_newest)
        )
        tmp_path = self._tombstone_path.with_suffix(".jsonl.tmp")
        try:
            with open(tmp_path, "wb") as handle:
                for _message_id, _tombstone, line in reversed(selected_newest):
                    handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, self._tombstone_path)
        except OSError:
            tmp_path.unlink(missing_ok=True)
            raise
        stat = self._tombstone_path.stat()
        self._tombstone_stat = (stat.st_mtime_ns, stat.st_size)
        return selected

    # ─────────────────────── queries ───────────────────────

    def get(self, message_id: str) -> Optional[OutboxRecord]:
        with self._thread_lock:
            with InterProcessLock(self._lock_path):
                self._refold_if_changed()
                record = self._records.get(message_id)
                return _copy_record(record) if record else None

    def pending(self, now_ms: Optional[int] = None) -> List[OutboxRecord]:
        """Non-terminal records; expired ones are folded to expired first."""

        now = _validate_operation_time(
            self._clock() if now_ms is None else now_ms, "now_ms"
        )
        with self._thread_lock:
            with InterProcessLock(self._lock_path):
                self._refold_if_changed()
                expired = [
                    record
                    for record in self._records.values()
                    if record.state == OUTBOX_STATE_QUEUED
                    and record.expires_at_ms <= now
                ]
                for record in expired:
                    self._transition_expired(record, now)
                return [
                    _copy_record(record)
                    for record in self._records.values()
                    if record.state == OUTBOX_STATE_QUEUED
                ]

    def stats(self) -> Dict[str, int]:
        with self._thread_lock:
            with InterProcessLock(self._lock_path):
                self._refold_if_changed()
                counts: Dict[str, int] = {}
                for record in self._records.values():
                    counts[record.state] = counts.get(record.state, 0) + 1
                counts["total"] = len(self._records)
                counts["compacted_terminal"] = len(self._tombstones)
                return counts

    # ─────────────────────── mutations ───────────────────────

    def enqueue(
        self, envelope: TransportEnvelope, *, now_ms: Optional[int] = None
    ) -> OutboxRecord:
        """Register one signed envelope. Idempotent by message_id.

        Already-expired envelopes are rejected (fail closed) instead of
        being parked as dead records.
        """

        if not isinstance(envelope, TransportEnvelope):
            raise TransportEnvelopeRejected("envelope must be a TransportEnvelope")
        # Freeze caller-owned mutable payload/routing data before validation so
        # the bytes validated below are exactly the bytes persisted.
        stable_envelope = TransportEnvelope.from_dict(
            TransportEnvelope.to_dict(envelope)
        )
        clock_now = _validate_operation_time(self._clock(), "now_ms")
        requested_now = (
            clock_now
            if now_ms is None
            else _validate_operation_time(now_ms, "now_ms")
        )
        now = max(clock_now, requested_now)
        ok, reason = validate_envelope(
            stable_envelope,
            now_ms=now,
            require_signature=True,
        )
        if not ok:
            raise TransportEnvelopeRejected(reason)
        envelope_json = canonical_json(stable_envelope.to_dict()).decode("utf-8")
        if len(envelope_json.encode("utf-8")) > MAX_ENVELOPE_BYTES:
            raise TransportEnvelopeRejected("envelope exceeds the wire byte limit")
        with self._thread_lock:
            with InterProcessLock(self._lock_path):
                self._refold_if_changed()
                existing = self._records.get(stable_envelope.message_id)
                if existing is not None:
                    if existing.envelope_sha256 != envelope_digest(stable_envelope):
                        raise DeliveryOutboxError(
                            "message_id already bound to different envelope bytes"
                        )
                    return _copy_record(existing)
                tombstone = self._tombstones.get(stable_envelope.message_id)
                if tombstone is not None:
                    if tombstone.envelope_sha256 != envelope_digest(stable_envelope):
                        raise DeliveryOutboxError(
                            "message_id tombstone is bound to different envelope bytes"
                        )
                    return OutboxRecord(
                        message_id=stable_envelope.message_id,
                        envelope_json=envelope_json,
                        envelope_sha256=tombstone.envelope_sha256,
                        created_at_ms=stable_envelope.created_at_ms,
                        expires_at_ms=stable_envelope.expires_at_ms,
                        state=tombstone.state,
                        delivered_by=tombstone.delivered_by,
                        delivered_at_ms=tombstone.delivered_at_ms,
                        last_error_code=tombstone.last_error_code,
                    )
                pending_count = sum(
                    1 for record in self._records.values() if not record.is_terminal
                )
                if pending_count >= self._max_pending:
                    raise DeliveryOutboxFull(
                        f"outbox holds {pending_count} pending records; cap is "
                        f"{self._max_pending}"
                    )
                record = OutboxRecord(
                    message_id=stable_envelope.message_id,
                    envelope_json=envelope_json,
                    envelope_sha256=envelope_digest(stable_envelope),
                    created_at_ms=stable_envelope.created_at_ms,
                    expires_at_ms=stable_envelope.expires_at_ms,
                )
                self._append_locked(
                    {
                        "event": "enqueued",
                        "message_id": record.message_id,
                        "envelope_json": envelope_json,
                        "envelope_sha256": record.envelope_sha256,
                        "created_at_ms": record.created_at_ms,
                        "expires_at_ms": record.expires_at_ms,
                        "at_ms": now,
                    }
                )
                self._records[record.message_id] = record
                return _copy_record(record)

    def record_attempt(
        self,
        message_id: str,
        *,
        transport: str,
        outcome: str,
        at_ms: Optional[int] = None,
        error_code: str = "",
    ) -> OutboxRecord:
        """Append one delivery attempt outcome for a queued record."""

        _validate_transport_name(transport)
        if outcome not in OUTBOX_ATTEMPT_OUTCOMES:
            raise DeliveryOutboxError(f"unsupported attempt outcome: {outcome}")
        _validate_error_code(error_code)
        now = _validate_operation_time(
            self._clock() if at_ms is None else at_ms, "at_ms"
        )
        with self._thread_lock:
            with InterProcessLock(self._lock_path):
                self._refold_if_changed()
                record = self._require_live(message_id)
                if len(record.attempts) >= MAX_ATTEMPTS_PER_RECORD:
                    raise DeliveryOutboxError("attempt history exceeds the cap")
                event: Dict[str, Any] = {
                    "event": "attempt",
                    "message_id": message_id,
                    "transport": transport,
                    "at_ms": now,
                    "outcome": outcome,
                }
                if error_code:
                    event["error_code"] = error_code
                self._append_locked(event)
                record.attempts.append(
                    OutboxAttempt(
                        transport=transport,
                        at_ms=now,
                        outcome=outcome,
                        error_code=error_code,
                    )
                )
                if outcome == OUTBOX_ATTEMPT_REJECTED:
                    record.state = OUTBOX_STATE_REJECTED
                    record.last_error_code = error_code
                else:
                    record.last_error_code = error_code
                return _copy_record(record)

    def handle_ack(self, ack: DeliveryAck, *, now_ms: Optional[int] = None) -> OutboxRecord:
        """Apply one verified ACK: mark delivered, cancel other copies.

        The ACK must carry a valid receiver signature. Matching is by
        ``message_id`` (content address) — a forwarded copy with a different
        hop count legitimately ACKs the same message identity.
        """

        clock_now = _validate_operation_time(self._clock(), "now_ms")
        requested_now = (
            clock_now
            if now_ms is None
            else _validate_operation_time(now_ms, "now_ms")
        )
        now = max(clock_now, requested_now)
        if not isinstance(ack, DeliveryAck):
            raise TransportEnvelopeRejected(
                "invalid delivery ack: ack must be a DeliveryAck"
            )
        try:
            stable_ack = DeliveryAck.from_dict(ack.to_dict())
        except (AttributeError, TypeError, ValueError):
            raise TransportEnvelopeRejected(
                "invalid delivery ack: ACK snapshot could not be created"
            ) from None
        ok, reason = validate_ack(stable_ack, now_ms=now)
        if not ok:
            raise TransportEnvelopeRejected(f"invalid delivery ack: {reason}")

        authorizer: Optional[AckAuthorizer] = None
        authorized_envelope_sha256 = ""
        authorized_recipient = ""
        callback_envelope: Optional[TransportEnvelope] = None
        with self._thread_lock:
            with InterProcessLock(self._lock_path):
                record, envelope, already_delivered = self._validated_ack_target_locked(
                    stable_ack, now
                )
                if already_delivered:
                    return _copy_record(record)
                if envelope.recipient.startswith("did:key:"):
                    if stable_ack.receiver_did != envelope.recipient:
                        raise DeliveryOutboxError(
                            "ack receiver is not the envelope recipient"
                        )
                    return self._commit_ack_locked(record, stable_ack, now)
                authorizer = self._authorize_ack
                if authorizer is None:
                    raise DeliveryAckAuthorizationError(
                        AuthorizationDecision.deny(
                            code="ack-authorization-required",
                            reason="ack authorization is required for shared recipients",
                        )
                    )
                authorized_envelope_sha256 = record.envelope_sha256
                authorized_recipient = envelope.recipient
                callback_envelope = TransportEnvelope.from_dict(envelope.to_dict())

        assert authorizer is not None
        assert callback_envelope is not None
        callback_ack = DeliveryAck.from_dict(stable_ack.to_dict())
        try:
            raw_authorization = authorizer(callback_ack, callback_envelope)
        except Exception as exc:
            logger.warning(
                "delivery outbox ACK authorization callback failed (%s)",
                type(exc).__name__,
            )
            raise DeliveryAckAuthorizationError(
                AuthorizationDecision.deny(
                    code="authorization-callback-failed",
                    reason="ack authorization callback failed",
                    retryable=True,
                )
            ) from None
        try:
            authorization = coerce_authorization_decision(
                raw_authorization,
                deny_code="ack-receiver-unauthorized",
            )
        except (TypeError, ValueError) as exc:
            logger.warning(
                "delivery outbox ACK authorization callback returned an invalid "
                "decision (%s)",
                type(exc).__name__,
            )
            raise DeliveryAckAuthorizationError(
                AuthorizationDecision.deny(
                    code="authorization-decision-invalid",
                    reason="ack authorization callback returned an invalid decision",
                )
            ) from None
        if not authorization.allowed:
            raise DeliveryAckAuthorizationError(authorization)

        commit_now = max(
            now,
            _validate_operation_time(self._clock(), "now_ms"),
        )
        ok, reason = validate_ack(stable_ack, now_ms=commit_now)
        if not ok:
            raise TransportEnvelopeRejected(f"invalid delivery ack: {reason}")

        with self._thread_lock:
            with InterProcessLock(self._lock_path):
                record, envelope, already_delivered = self._validated_ack_target_locked(
                    stable_ack, commit_now
                )
                if already_delivered:
                    return _copy_record(record)
                if (
                    record.envelope_sha256 != authorized_envelope_sha256
                    or envelope.recipient != authorized_recipient
                ):
                    raise DeliveryOutboxCorrupt(
                        "ACK authorization target changed before commit"
                    )
                return self._commit_ack_locked(record, stable_ack, commit_now)

    def _validated_ack_target_locked(
        self,
        ack: DeliveryAck,
        now: int,
    ) -> tuple[OutboxRecord, TransportEnvelope, bool]:
        """Return the current ACK target while the caller owns both locks."""

        self._refold_if_changed()
        record = self._records.get(ack.message_id)
        if record is None:
            raise DeliveryOutboxError("ack for unknown message_id")
        if record.state == OUTBOX_STATE_QUEUED and record.expires_at_ms <= now:
            self._transition_expired(record, now)
            raise DeliveryOutboxError("cannot acknowledge expired record")
        envelope = _record_envelope(record)
        if ack.received_at_ms > envelope.expires_at_ms:
            raise DeliveryOutboxError("ack received_at_ms is after envelope expiry")
        if ack.received_at_ms + MAX_CLOCK_SKEW_MS < envelope.created_at_ms:
            raise DeliveryOutboxError(
                "ack received_at_ms predates envelope creation beyond clock skew"
            )
        if not _ack_digest_matches_envelope(ack.envelope_sha256, envelope):
            raise DeliveryOutboxError(
                "ack envelope_sha256 does not match a valid forwarded envelope"
            )
        if record.state == OUTBOX_STATE_DELIVERED:
            if ack.receiver_did != record.delivered_by:
                raise DeliveryOutboxError(
                    "ack receiver does not match the recorded delivery"
                )
            return record, envelope, True
        if record.state != OUTBOX_STATE_QUEUED:
            raise DeliveryOutboxError(
                f"cannot acknowledge record in state {record.state}"
            )
        return record, envelope, False

    def _commit_ack_locked(
        self,
        record: OutboxRecord,
        ack: DeliveryAck,
        now: int,
    ) -> OutboxRecord:
        """Persist an already-validated ACK while the caller owns both locks."""

        self._append_locked(
            {
                "event": "delivered",
                "message_id": record.message_id,
                "at_ms": now,
                "ack_json": canonical_json(ack.to_dict()).decode("utf-8"),
            }
        )
        record.state = OUTBOX_STATE_DELIVERED
        record.delivered_by = ack.receiver_did
        record.delivered_at_ms = ack.received_at_ms
        return _copy_record(record)

    def compact(self) -> int:
        """Rewrite live records and retain bounded terminal tombstones.

        Tombstones preserve enqueue idempotency for the most recent
        ``max_terminal_tombstones`` compacted terminal records. Older entries
        deliberately age out, so delivery remains bounded at-least-once rather
        than claiming infinite-history exactly-once semantics.
        """

        now = _validate_operation_time(self._clock(), "now_ms")
        with self._thread_lock:
            # refold must happen INSIDE the cross-process lock: refolding
            # before acquiring it leaves a window where another process
            # appends a record and our os.replace below silently drops it
            # (round-3 review bug I)
            with InterProcessLock(self._lock_path):
                self._refold_if_changed()
                keep = [
                    record
                    for record in self._records.values()
                    if not record.is_terminal
                ]
                tombstones = OrderedDict(self._tombstones)
                for record in self._records.values():
                    if not record.is_terminal:
                        continue
                    tombstones.pop(record.message_id, None)
                    tombstones[record.message_id] = _OutboxTombstone(
                        message_id=record.message_id,
                        envelope_sha256=record.envelope_sha256,
                        state=record.state,
                        compacted_at_ms=now,
                        delivered_by=record.delivered_by,
                        delivered_at_ms=record.delivered_at_ms,
                        last_error_code=record.last_error_code,
                    )
                # Write tombstones first. A crash before the live-journal
                # replace leaves duplicate terminal evidence, never amnesia.
                tombstones = self._write_tombstones_locked(tombstones)
                tmp_path = self._journal_path.with_suffix(".jsonl.tmp")
                try:
                    with open(tmp_path, "wb") as handle:
                        for record in keep:
                            handle.write(canonical_json(
                                {
                                    "event": "enqueued",
                                    "message_id": record.message_id,
                                    "envelope_json": record.envelope_json,
                                    "envelope_sha256": record.envelope_sha256,
                                    "created_at_ms": record.created_at_ms,
                                    "expires_at_ms": record.expires_at_ms,
                                    "at_ms": record.created_at_ms,
                                }
                            ) + b"\n")
                            for attempt in record.attempts:
                                event: Dict[str, Any] = {
                                    "event": "attempt",
                                    "message_id": record.message_id,
                                    "transport": attempt.transport,
                                    "at_ms": attempt.at_ms,
                                    "outcome": attempt.outcome,
                                }
                                if attempt.error_code:
                                    event["error_code"] = attempt.error_code
                                handle.write(canonical_json(event) + b"\n")
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(tmp_path, self._journal_path)
                except OSError:
                    tmp_path.unlink(missing_ok=True)
                    raise
                # fingerprint captured INSIDE the lock (round-4 bug Q)
                try:
                    stat = os.stat(self._journal_path)
                    self._journal_stat = (stat.st_mtime_ns, stat.st_size)
                except OSError:  # pragma: no cover - stat after our own replace
                    pass
            self._records = {record.message_id: record for record in keep}
            self._tombstones = tombstones
            return len(keep)

    # ─────────────────────── internals ───────────────────────

    def _require_live(self, message_id: str) -> OutboxRecord:
        record = self._records.get(message_id)
        if record is None:
            raise DeliveryOutboxError("outbox record missing")
        if record.state == OUTBOX_STATE_DELIVERED:
            raise DeliveryOutboxError("record is already delivered")
        if record.state == OUTBOX_STATE_REJECTED:
            raise DeliveryOutboxError("record is terminally rejected")
        if record.state == OUTBOX_STATE_EXPIRED:
            raise DeliveryOutboxError("record is expired")
        return record

    def _transition_expired(self, record: OutboxRecord, now_ms: int) -> None:
        self._append_locked(
            {
                "event": "expired",
                "message_id": record.message_id,
                "at_ms": now_ms,
            }
        )
        record.state = OUTBOX_STATE_EXPIRED


def _fold_event(records: Dict[str, OutboxRecord], event: Dict[str, Any]) -> None:
    """Apply one journal event to the fold. Unknown shapes fail closed."""

    kind = event.get("event")
    if kind not in _JOURNAL_EVENTS:
        raise DeliveryOutboxCorrupt(f"unknown journal event: {kind!r}")
    allowed_fields = _EVENT_FIELDS[kind]
    fields = frozenset(event)
    if kind == "attempt":
        if not allowed_fields <= fields or not fields <= allowed_fields | {"error_code"}:
            raise DeliveryOutboxCorrupt("attempt event has missing or unknown fields")
    elif fields != allowed_fields:
        raise DeliveryOutboxCorrupt(
            f"{kind} event has missing or unknown fields"
        )
    message_id = event.get("message_id")
    if not isinstance(message_id, str) or _MESSAGE_ID_RE.fullmatch(message_id) is None:
        raise DeliveryOutboxCorrupt("journal event message_id is not a content address")

    if kind == "enqueued":
        if message_id in records:
            raise DeliveryOutboxCorrupt("duplicate enqueued event for message_id")
        envelope_json = event.get("envelope_json")
        envelope_sha256 = event.get("envelope_sha256")
        created_at_ms = event.get("created_at_ms")
        expires_at_ms = event.get("expires_at_ms")
        if not isinstance(envelope_json, str) or not envelope_json:
            raise DeliveryOutboxCorrupt("enqueued event missing envelope_json")
        if not isinstance(envelope_sha256, str) or _MESSAGE_ID_RE.fullmatch(envelope_sha256) is None:
            raise DeliveryOutboxCorrupt("enqueued event missing envelope_sha256")
        for value in (created_at_ms, expires_at_ms):
            if isinstance(value, bool) or not isinstance(value, int):
                raise DeliveryOutboxCorrupt("enqueued event timestamps must be integers")
        _fold_at_ms(event)
        assert isinstance(created_at_ms, int)
        assert isinstance(expires_at_ms, int)
        enqueued_record = OutboxRecord(
            message_id=message_id,
            envelope_json=envelope_json,
            envelope_sha256=envelope_sha256,
            created_at_ms=created_at_ms,
            expires_at_ms=expires_at_ms,
        )
        _record_envelope(enqueued_record)
        records[message_id] = enqueued_record
        return

    record = records.get(message_id)
    if record is None:
        raise DeliveryOutboxCorrupt(f"journal event for unknown message_id: {kind}")

    if kind == "attempt":
        if record.state != OUTBOX_STATE_QUEUED:
            raise DeliveryOutboxCorrupt("attempt event follows a terminal state")
        if len(record.attempts) >= MAX_ATTEMPTS_PER_RECORD:
            raise DeliveryOutboxCorrupt("attempt history exceeds the cap")
        transport = _fold_transport(event)
        outcome = event.get("outcome")
        if outcome not in OUTBOX_ATTEMPT_OUTCOMES:
            raise DeliveryOutboxCorrupt(f"unsupported attempt outcome: {outcome!r}")
        at_ms = _fold_at_ms(event)
        error_code = event.get("error_code", "")
        try:
            validated_error_code = _validate_error_code(error_code)
        except DeliveryOutboxError as exc:
            raise DeliveryOutboxCorrupt(str(exc)) from exc
        record.attempts.append(
            OutboxAttempt(
                transport=transport,
                at_ms=at_ms,
                outcome=outcome,
                error_code=validated_error_code,
            )
        )
        if outcome == OUTBOX_ATTEMPT_REJECTED and record.state == OUTBOX_STATE_QUEUED:
            record.state = OUTBOX_STATE_REJECTED
        if validated_error_code:
            record.last_error_code = validated_error_code
        return

    if record.state in OUTBOX_TERMINAL_STATES:
        raise DeliveryOutboxCorrupt(f"{kind} event follows a terminal state")

    at_ms = _fold_at_ms(event)
    if kind == "delivered":
        ack_json = event.get("ack_json")
        if not isinstance(ack_json, str):
            raise DeliveryOutboxCorrupt("delivered event ack_json must be text")
        try:
            ack = DeliveryAck.from_dict(json.loads(ack_json))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise DeliveryOutboxCorrupt(f"delivered event ACK is invalid: {exc}") from exc
        if canonical_json(ack.to_dict()).decode("utf-8") != ack_json:
            raise DeliveryOutboxCorrupt("delivered event ACK is not canonical JSON")
        ok, reason = validate_ack(ack, now_ms=at_ms)
        if not ok:
            raise DeliveryOutboxCorrupt(f"delivered event ACK is invalid: {reason}")
        envelope = _record_envelope(record)
        if ack.message_id != message_id or not _ack_digest_matches_envelope(
            ack.envelope_sha256, envelope
        ):
            raise DeliveryOutboxCorrupt("delivered event ACK binding mismatch")
        if (
            envelope.recipient.startswith("did:key:")
            and ack.receiver_did != envelope.recipient
        ):
            raise DeliveryOutboxCorrupt("delivered event ACK receiver mismatch")
        record.state = OUTBOX_STATE_DELIVERED
        record.delivered_by = ack.receiver_did
        record.delivered_at_ms = ack.received_at_ms
        return
    if kind == "rejected":
        transport = _fold_transport(event)
        error_code = event.get("error_code")
        try:
            validated_error_code = _validate_error_code(error_code)
        except DeliveryOutboxError as exc:
            raise DeliveryOutboxCorrupt(str(exc)) from exc
        record.state = OUTBOX_STATE_REJECTED
        record.last_error_code = validated_error_code
        return
    if kind == "expired":
        record.state = OUTBOX_STATE_EXPIRED
        return
    raise DeliveryOutboxCorrupt(f"unhandled journal event: {kind}")  # pragma: no cover


def _tombstone_dict(tombstone: _OutboxTombstone) -> Dict[str, Any]:
    return {
        "message_id": tombstone.message_id,
        "envelope_sha256": tombstone.envelope_sha256,
        "state": tombstone.state,
        "compacted_at_ms": tombstone.compacted_at_ms,
        "delivered_by": tombstone.delivered_by,
        "delivered_at_ms": tombstone.delivered_at_ms,
        "last_error_code": tombstone.last_error_code,
    }


def _parse_tombstone(value: Any) -> _OutboxTombstone:
    if not isinstance(value, dict) or frozenset(value) != _TOMBSTONE_FIELDS:
        raise ValueError("tombstone has missing or unknown fields")
    for field_name in ("message_id", "envelope_sha256"):
        if (
            not isinstance(value[field_name], str)
            or _MESSAGE_ID_RE.fullmatch(value[field_name]) is None
        ):
            raise ValueError(f"tombstone {field_name} is invalid")
    state = value["state"]
    if state not in OUTBOX_TERMINAL_STATES:
        raise ValueError("tombstone state is not terminal")
    for field_name in ("compacted_at_ms", "delivered_at_ms"):
        field_value = value[field_name]
        if (
            isinstance(field_value, bool)
            or not isinstance(field_value, int)
            or field_value < 0
            or field_value > MAX_SAFE_INTEGER
        ):
            raise ValueError(f"tombstone {field_name} is invalid")
    if value["compacted_at_ms"] < 1:
        raise ValueError("tombstone compacted_at_ms is invalid")
    delivered_by = value["delivered_by"]
    if (
        not isinstance(delivered_by, str)
        or len(delivered_by.encode("utf-8")) > 512
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in delivered_by)
    ):
        raise ValueError("tombstone delivered_by is invalid")
    last_error_code = value["last_error_code"]
    try:
        _validate_error_code(last_error_code)
    except DeliveryOutboxError as exc:
        raise ValueError("tombstone last_error_code is invalid") from exc
    if state == OUTBOX_STATE_DELIVERED:
        if not delivered_by or value["delivered_at_ms"] < 1:
            raise ValueError("delivered tombstone is missing receiver evidence")
        try:
            decode_ed25519_did_key(delivered_by)
        except (DIDKeyError, TypeError, ValueError) as exc:
            raise ValueError("delivered tombstone receiver DID is invalid") from exc
    elif delivered_by or value["delivered_at_ms"] != 0:
        raise ValueError("non-delivered tombstone carries receiver evidence")
    return _OutboxTombstone(
        message_id=value["message_id"],
        envelope_sha256=value["envelope_sha256"],
        state=state,
        compacted_at_ms=value["compacted_at_ms"],
        delivered_by=delivered_by,
        delivered_at_ms=value["delivered_at_ms"],
        last_error_code=last_error_code,
    )


def _file_stat(path: Path) -> Optional[tuple[int, int]]:
    try:
        stat = path.stat()
    except OSError:
        return None
    return stat.st_mtime_ns, stat.st_size


def _fold_transport(event: Mapping[str, Any]) -> str:
    transport = event.get("transport")
    if not isinstance(transport, str) or _TRANSPORT_NAME_RE.fullmatch(transport) is None:
        raise DeliveryOutboxCorrupt("journal event transport name is invalid")
    return transport


def _fold_at_ms(event: Mapping[str, Any]) -> int:
    at_ms = event.get("at_ms")
    if isinstance(at_ms, bool) or not isinstance(at_ms, int) or at_ms < 0:
        raise DeliveryOutboxCorrupt("journal event at_ms must be a non-negative integer")
    return at_ms


def _copy_record(record: OutboxRecord) -> OutboxRecord:
    return OutboxRecord(
        message_id=record.message_id,
        envelope_json=record.envelope_json,
        envelope_sha256=record.envelope_sha256,
        created_at_ms=record.created_at_ms,
        expires_at_ms=record.expires_at_ms,
        state=record.state,
        attempts=list(record.attempts),
        delivered_by=record.delivered_by,
        delivered_at_ms=record.delivered_at_ms,
        last_error_code=record.last_error_code,
    )


def _ack_digest_matches_envelope(
    acknowledged_digest: str,
    envelope: TransportEnvelope,
) -> bool:
    """Accept only origin bytes or a valid hop-count-only forwarded copy."""

    start_hop = envelope.routing["hop_count"]
    hop_limit = envelope.routing["hop_limit"]
    for hop_count in range(start_hop, hop_limit + 1):
        candidate = envelope.to_dict()
        candidate["routing"]["hop_count"] = hop_count
        if envelope_digest(candidate) == acknowledged_digest:
            return True
    return False


def _record_envelope(record: OutboxRecord) -> TransportEnvelope:
    """Reconstruct and verify the envelope bound into an outbox record."""

    try:
        parsed = json.loads(record.envelope_json)
        envelope = TransportEnvelope.from_dict(parsed)
        if canonical_json(envelope.to_dict()).decode("utf-8") != record.envelope_json:
            raise DeliveryOutboxCorrupt("enqueued envelope_json is not canonical")
        ok, reason = validate_envelope(envelope, require_signature=True)
        if not ok:
            raise DeliveryOutboxCorrupt(f"enqueued envelope is invalid: {reason}")
        if envelope.message_id != record.message_id:
            raise DeliveryOutboxCorrupt("enqueued message_id does not match envelope")
        if envelope_digest(envelope) != record.envelope_sha256:
            raise DeliveryOutboxCorrupt("enqueued envelope_sha256 does not match envelope")
        if (
            envelope.created_at_ms != record.created_at_ms
            or envelope.expires_at_ms != record.expires_at_ms
        ):
            raise DeliveryOutboxCorrupt("enqueued timestamps do not match envelope")
        return envelope
    except DeliveryOutboxCorrupt:
        raise
    except (json.JSONDecodeError, TypeError, ValueError, UnicodeError) as exc:
        raise DeliveryOutboxCorrupt(f"enqueued envelope_json is invalid: {exc}") from exc
