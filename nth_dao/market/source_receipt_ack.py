"""Source-side durable intake of recipient-signed source receipt ACKs.

The return envelope uses the existing delivery.ack wire format. It closes only
the original source receipt outbox record and repairs its audit on exact retry.
No acknowledgement-of-acknowledgement, work acceptance, or settlement follows.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from nth_dao.delivery.acknowledgement import (
    DeliveryAck,
    DeliveryAckRejected,
    ack_from_envelope,
)
from nth_dao.delivery.envelope import MAX_CLOCK_SKEW_MS, TransportEnvelope
from nth_dao.delivery.inbox import DeliveryInbox
from nth_dao.delivery.outbox import OUTBOX_STATE_REJECTED, OutboxRecord
from nth_dao.identity import AgentIdentity
from nth_dao.market.source_receipt_delivery import (
    SourceReceiptDeliveryDeferred,
    SourceReceiptDeliveryFailure,
    SourceReceiptDeliveryRejected,
    _acknowledge_source_receipt_delivery,
    _checked_path,
    _snapshot,
    open_source_receipt_delivery_outbox,
    require_prepared_source_receipt_delivery,
    source_receipt_delivery_failure,
)
from nth_dao.spine.log import SignedEventLog

MAX_SOURCE_RECEIPT_ACK_ENTRIES = 256
MAX_SOURCE_RECEIPT_ACK_PENDING_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class SourceReceiptAckResult:
    """Return-envelope identity and the original, audited outbox transition."""

    message_id: str
    delivery: OutboxRecord


@dataclass(frozen=True)
class SourceReceiptAckResumeResult:
    results: tuple[SourceReceiptAckResult, ...]
    failures: tuple[SourceReceiptDeliveryFailure, ...]


class SourceReceiptAckReceiver:
    """Local source principal; every received ACK rechecks prepared evidence."""

    def __init__(
        self, workspace: Path, *, identity: AgentIdentity, spine: SignedEventLog,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if not isinstance(identity, AgentIdentity) or not identity.can_sign:
            raise TypeError("source identity must be a signing AgentIdentity")
        if not isinstance(spine, SignedEventLog) or spine.signer_did != identity.as_did():
            raise SourceReceiptDeliveryRejected("source ACK Spine signer differs from the selected identity")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        self.workspace = Path(workspace)
        self.identity = identity
        self.spine = spine
        self._clock = clock or (lambda: int(time.time() * 1000))
        spine.require_independent_storage()
        self._source_outbox = open_source_receipt_delivery_outbox(self.workspace, clock=self.current_time_ms)
        self._directory = Path(".nth/source_receipt_ack_inbox") / sha256(identity.as_did().encode()).hexdigest()
        self._check_storage_paths()
        self.inbox = DeliveryInbox(
            _checked_path(self.workspace, self._directory), authorize=self._authorize,
            clock=self.current_time_ms, max_replay_entries=MAX_SOURCE_RECEIPT_ACK_ENTRIES,
            reject_links=True, archive_processed=True, max_pending_bytes=MAX_SOURCE_RECEIPT_ACK_PENDING_BYTES,
        )

    def current_time_ms(self) -> int:
        now = self._clock()
        if isinstance(now, bool) or not isinstance(now, int) or now < 1:
            raise SourceReceiptDeliveryRejected("source ACK clock must return positive integer ms")
        return now

    def _check_storage_paths(self) -> None:
        for name in ("inbox.cache.jsonl", "inbox.rejections.jsonl", "inbox.lock"):
            _checked_path(self.workspace, self._directory / name)

    def _verify_local(self, envelope: TransportEnvelope, *, accepted_at_ms: int | None) -> DeliveryAck:
        try:
            ack = ack_from_envelope(envelope, now_ms=accepted_at_ms)
        except DeliveryAckRejected as exc:
            raise SourceReceiptDeliveryRejected(str(exc)) from exc
        if (
            envelope.recipient != self.identity.as_did() or envelope.dao_id is not None
            or envelope.routing != {"hop_limit": 0, "hop_count": 0}
        ):
            raise SourceReceiptDeliveryRejected("source receipt ACK requires direct source DID routing")
        queued = self._source_outbox.get(ack.message_id)
        if queued is None:
            raise SourceReceiptDeliveryRejected("ACK does not identify a retained source receipt delivery")
        original = require_prepared_source_receipt_delivery(
            TransportEnvelope.from_dict(json.loads(queued.envelope_json)),
            workspace=self.workspace, identity=self.identity, spine=self.spine,
        )
        if (
            ack.receiver_did != original.recipient or ack.envelope_sha256 != queued.envelope_sha256
            or not original.created_at_ms - MAX_CLOCK_SKEW_MS <= ack.received_at_ms < original.expires_at_ms
            or queued.state == OUTBOX_STATE_REJECTED
        ):
            raise SourceReceiptDeliveryRejected("ACK differs from the original recipient, digest or lifetime")
        return ack

    def owns_ack(self, envelope: TransportEnvelope) -> bool:
        """Route only verified ACKs whose original delivery belongs here.

        This is ownership selection, not authorization; receive still checks
        source evidence, exact recipient, digest, lifetime and signed audit.
        """
        self._check_storage_paths()
        try:
            ack = ack_from_envelope(_snapshot(envelope))
        except DeliveryAckRejected as exc:
            raise SourceReceiptDeliveryRejected(str(exc)) from exc
        return self._source_outbox.get(ack.message_id) is not None

    def _authorize(self, envelope: TransportEnvelope) -> tuple[bool, str]:
        try:
            # Inbox enforces freshness at the explicit first-intake time.
            # Authorization must not redate durable intake using a new clock.
            self._verify_local(envelope, accepted_at_ms=None)
        except (TypeError, ValueError, RecursionError) as exc:
            return False, str(exc)
        return True, "ok"

    def _process(self, envelope: TransportEnvelope) -> SourceReceiptAckResult:
        self._check_storage_paths()
        accepted_at = self.inbox.accepted_at(envelope.message_id)
        if accepted_at is None:
            raise SourceReceiptDeliveryRejected("returned ACK lacks durable first-intake time")
        ack = self._verify_local(envelope, accepted_at_ms=accepted_at)
        delivery = _acknowledge_source_receipt_delivery(
            ack, workspace=self.workspace, identity=self.identity, spine=self.spine, clock=self._clock,
            outbox=self._source_outbox,
        )
        self.inbox.mark_processed(envelope.message_id)
        return SourceReceiptAckResult(message_id=envelope.message_id, delivery=delivery)

    def _receive_snapshot(self, envelope: TransportEnvelope, *, accepted_at_ms: int) -> SourceReceiptAckResult:
        self._check_storage_paths()
        self._verify_local(envelope, accepted_at_ms=accepted_at_ms)
        decision = self.inbox.accept(envelope, now_ms=accepted_at_ms)
        if not decision.accepted and not decision.duplicate:
            error = SourceReceiptDeliveryDeferred if decision.retryable else SourceReceiptDeliveryRejected
            raise error(decision.reason)
        return self._process(envelope)

    def receive(self, envelope: TransportEnvelope) -> SourceReceiptAckResult:
        return self._receive_snapshot(_snapshot(envelope), accepted_at_ms=self.current_time_ms())

    def receive_retained(self, ingress: DeliveryInbox, message_id: str) -> SourceReceiptAckResult:
        """Recover local staging; never accept a remote backdating parameter."""
        if not isinstance(ingress, DeliveryInbox):
            raise TypeError("ACK ingress must be a DeliveryInbox")
        retained = ingress.retained_entry(message_id)
        if retained is None:
            # Legacy compacted staging can lack bytes. Only independently
            # retained source intake may recover it, never a remote backdate.
            retained = self.inbox.retained_entry(message_id)
            if retained is None:
                raise SourceReceiptDeliveryDeferred("retained ACK ingress is unavailable")
            return self._process(_snapshot(retained.envelope))
        return self._receive_snapshot(_snapshot(retained.envelope), accepted_at_ms=retained.accepted_at_ms)

    def resume_pending(self) -> SourceReceiptAckResumeResult:
        try:
            self._check_storage_paths()
            pending = self.inbox.pending(max_items=MAX_SOURCE_RECEIPT_ACK_ENTRIES)
        except (OSError, TypeError, ValueError, RuntimeError, RecursionError) as exc:
            return SourceReceiptAckResumeResult(results=(), failures=(source_receipt_delivery_failure("", exc),))
        results = []
        failures = []
        for envelope in pending:
            try:
                results.append(self._process(_snapshot(envelope)))
            except (OSError, TypeError, ValueError, RuntimeError, RecursionError) as exc:
                failures.append(source_receipt_delivery_failure(envelope.message_id, exc))
        return SourceReceiptAckResumeResult(results=tuple(results), failures=tuple(failures))


__all__ = [
    "MAX_SOURCE_RECEIPT_ACK_ENTRIES",
    "MAX_SOURCE_RECEIPT_ACK_PENDING_BYTES",
    "SourceReceiptAckReceiver",
    "SourceReceiptAckResult",
    "SourceReceiptAckResumeResult",
]
