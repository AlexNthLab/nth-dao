"""Durable claimant preparation of one exact, explicitly routed ACK return.

No ACK-of-ACK, implicit renewal, network admission or business acceptance is
created here. The original locally verified receipt determines the recipient.
"""

from __future__ import annotations

import json
from pathlib import Path

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.acknowledgement import (
    ack_digest,
    ack_from_envelope,
    sign_ack_envelope,
)
from nth_dao.delivery.envelope import (
    MAX_ENVELOPE_BYTES,
    MAX_TTL_MS,
    TransportEnvelope,
    envelope_digest,
    validate_envelope,
)
from nth_dao.delivery.outbox import DeliveryOutboxCorrupt, DurableOutbox
from nth_dao.market.source_receipt_delivery import (
    SourceReceiptDeliveryDeferred,
    SourceReceiptDeliveryReceiver,
    SourceReceiptDeliveryRejected,
    SourceReceiptDeliveryResult,
    _checked_path,
    _snapshot,
    _write_delivery_bytes,
)
from nth_dao.spine.event import SpineEvent
from nth_dao.util.io import InterProcessLock, open_independent_file

SOURCE_RECEIPT_ACK_RETURN_PREPARED_EVENT = "market.claim.completion.source_receipt.ack_return.prepared"
SOURCE_RECEIPT_ACK_RETURN_COMMITTED_EVENT = "market.claim.completion.source_receipt.ack_return.committed"


class SourceReceiptAckReturnStore:
    """One immutable return per original delivery, audited before disclosure.

    File -> signed v2 preparation -> outbox -> signed commit precedes export.
    Interrupted preparation reuses exact bytes. A committed record must never
    be recreated from a missing journal. Expiry never produces a fresh nonce.
    """

    def __init__(self, receiver: SourceReceiptDeliveryReceiver) -> None:
        if not isinstance(receiver, SourceReceiptDeliveryReceiver):
            raise TypeError("receiver must be a SourceReceiptDeliveryReceiver")
        self.receiver = receiver
        self._relative = Path(".nth/source_receipt_ack_return_outbox") / receiver.source_claim_id
        self._check()
        self.outbox = DurableOutbox(
            self._path(Path(".")), clock=receiver.current_time_ms,
            retain_terminal_records=True, reject_links=True,
        )

    def _path(self, relative: Path) -> Path:
        return _checked_path(self.receiver.workspace, self._relative / relative)

    def _check(self) -> None:
        receiver = self.receiver
        if not receiver.identity.can_sign or receiver.spine.signer_did != receiver.identity.as_did():
            raise SourceReceiptDeliveryRejected("claimant Spine signer differs from the selected identity")
        receiver.spine.require_independent_storage()
        for name in ("outbox.journal.jsonl", "outbox.lock", "preparation.lock"):
            self._path(Path(name))

    def _prepared_path(self, original: TransportEnvelope) -> Path:
        return self._path(Path("prepared") / (original.message_id[7:] + ".json"))

    def _read(self, original: TransportEnvelope) -> TransportEnvelope:
        with open_independent_file(self._prepared_path(original), "rb") as stream:
            raw = stream.read(MAX_ENVELOPE_BYTES + 1)
        if len(raw) > MAX_ENVELOPE_BYTES:
            raise SourceReceiptDeliveryRejected("ACK return exceeds the wire byte limit")
        value = json.loads(raw)
        if canonical_json(value) != raw:
            raise SourceReceiptDeliveryRejected("retained ACK return is not canonical JSON")
        return _snapshot(TransportEnvelope.from_dict(value))

    def _payload(
        self, envelope: TransportEnvelope, original: TransportEnvelope, result: SourceReceiptDeliveryResult,
    ) -> dict:
        ack = ack_from_envelope(envelope)
        if (
            envelope.recipient != original.sender_did or envelope.dao_id is not None
            or envelope.routing != {"hop_limit": 0, "hop_count": 0}
            or canonical_json(ack.to_dict()) != canonical_json(result.ack.to_dict())
        ):
            raise SourceReceiptDeliveryRejected("ACK return differs from verified local delivery evidence")
        return {
            "original_message_id": original.message_id,
            "message_id": envelope.message_id, "envelope_sha256": envelope_digest(envelope),
            "ack_digest": ack_digest(ack), "source_claim_id": self.receiver.source_claim_id,
            "observation_event_id": result.observation["local_observation_event_id"],
            "sender_did": envelope.sender_did, "recipient_did": envelope.recipient,
            "verification_scope": "transport_receipt_only", "accepted": False, "settled": False,
        }

    def _audit(
        self, message_id: str, *, event_type: str = SOURCE_RECEIPT_ACK_RETURN_PREPARED_EVENT,
    ) -> SpineEvent | None:
        return self.receiver.spine.find_unique_event(
            event_type,
            payload_field="original_message_id", payload_value=message_id,
        )

    def _require_audit(
        self, payload: dict, *, event_type: str = SOURCE_RECEIPT_ACK_RETURN_PREPARED_EVENT,
    ) -> SpineEvent:
        event = self._audit(payload["original_message_id"], event_type=event_type)
        expected = payload
        if (event is not None and event_type == SOURCE_RECEIPT_ACK_RETURN_PREPARED_EVENT
                and "preparation_version" in event.payload):
            if type(event.payload["preparation_version"]) is not int or event.payload["preparation_version"] != 2:
                raise SourceReceiptDeliveryRejected("ACK return preparation version is unsupported")
            expected = {**payload, "preparation_version": 2}
        if (
            event is None or event.author_did != self.receiver.identity.as_did()
            or canonical_json(event.payload) != canonical_json(expected)
        ):
            raise SourceReceiptDeliveryRejected("ACK return lacks matching claimant preparation or commit audit")
        return event

    @staticmethod
    def _commit_payload(payload: dict, preparation: SpineEvent) -> dict:
        return {**payload, "preparation_event_id": preparation.event_id}

    def _require_outbox(self, envelope: TransportEnvelope, *, committed: bool = False) -> None:
        self.outbox.require_retained_independent_storage(self._path(Path(".")))
        record = self.outbox.get(envelope.message_id)
        if record is None and committed:
            raise DeliveryOutboxCorrupt("committed ACK return outbox record is missing; automatic recreation is forbidden")
        if record is None or record.envelope_json.encode("utf-8") != canonical_json(envelope.to_dict()):
            raise SourceReceiptDeliveryRejected("ACK return lacks matching retained outbox bytes")

    def prepare(self, original_message_id: str, *, ttl_ms: int = 600_000) -> TransportEnvelope:
        """Persist once or repair an interrupted preparation; never implicitly renew.

        A completed, expired preparation is returned unchanged for inspection.
        An expired partial preparation cannot be freshly queued. An already
        queued v2 preparation may finish its commit without changing bytes.
        Legacy preparation can be adopted only with its retained queue record.
        """
        if type(ttl_ms) is not int or not 1 <= ttl_ms <= MAX_TTL_MS:
            raise ValueError("ACK return TTL must be a positive integer within the wire limit")
        self._check()
        with InterProcessLock(self._path(Path("preparation.lock")), reject_links=True):
            self._check()
            self.outbox.require_retained_independent_storage(self._path(Path(".")))
            original, result = self.receiver.get_retained_delivery(original_message_id)
            committed = self._audit(original.message_id, event_type=SOURCE_RECEIPT_ACK_RETURN_COMMITTED_EVENT)
            path = self._prepared_path(original)
            if path.exists():
                envelope = self._read(original)
            else:
                if self._audit(original.message_id) is not None or committed is not None:
                    raise SourceReceiptDeliveryRejected("audited ACK return bytes are missing")
                now = self.receiver.current_time_ms()
                envelope = sign_ack_envelope(
                    self.receiver.identity, result.ack, recipient=original.sender_did,
                    created_at_ms=now, expires_at_ms=now + ttl_ms,
                )
                _write_delivery_bytes(self.receiver.workspace, path, canonical_json(envelope.to_dict()))
            payload = self._payload(envelope, original, result)
            event = self._audit(original.message_id)
            record = self.outbox.get(envelope.message_id)
            if event is not None:
                event = self._require_audit(payload)
            if committed is not None:
                if event is None:
                    raise SourceReceiptDeliveryRejected("committed ACK return preparation audit is missing")
                self._require_audit(self._commit_payload(payload, event), event_type=SOURCE_RECEIPT_ACK_RETURN_COMMITTED_EVENT)
                self._require_outbox(envelope, committed=True)
                return envelope
            if record is not None:
                self._require_outbox(envelope)
                if event is None:
                    raise DeliveryOutboxCorrupt("ACK return queue record lacks its preparation audit")
            elif event is not None and "preparation_version" not in event.payload:
                raise DeliveryOutboxCorrupt("legacy ACK return queue history is missing; explicit recovery is required")
            if record is None:
                if envelope.expires_at_ms <= self.receiver.current_time_ms():
                    raise SourceReceiptDeliveryDeferred("partial ACK return expired; no implicit renewal")
                valid, reason = validate_envelope(
                    envelope, now_ms=self.receiver.current_time_ms(), require_signature=True,
                )
                if not valid:
                    raise SourceReceiptDeliveryRejected(reason)
                self.receiver.spine.append_unique(
                    SOURCE_RECEIPT_ACK_RETURN_PREPARED_EVENT, {**payload, "preparation_version": 2},
                    unique_payload_fields=("original_message_id",),
                )
                event = self._require_audit(payload)
                self.outbox.enqueue(envelope, now_ms=self.receiver.current_time_ms())
            if event is None:
                raise SourceReceiptDeliveryRejected("ACK return preparation was not persisted")
            self._require_outbox(envelope)
            commit_payload = self._commit_payload(payload, event)
            self.receiver.spine.append_unique(
                SOURCE_RECEIPT_ACK_RETURN_COMMITTED_EVENT, commit_payload,
                unique_payload_fields=("original_message_id",),
            )
            self._require_audit(commit_payload, event_type=SOURCE_RECEIPT_ACK_RETURN_COMMITTED_EVENT)
            self._require_outbox(envelope, committed=True)
            return envelope

    def get(self, original_message_id: str) -> TransportEnvelope:
        """Reverify exact prepared bytes, local proof, audit and outbox before export."""
        self._check()
        with InterProcessLock(self._path(Path("preparation.lock")), reject_links=True):
            self._check()
            self.outbox.require_retained_independent_storage(self._path(Path(".")))
            original, result = self.receiver.get_retained_delivery(original_message_id)
            envelope = self._read(original)
            payload = self._payload(envelope, original, result)
            event = self._require_audit(payload)
            self._require_audit(self._commit_payload(payload, event), event_type=SOURCE_RECEIPT_ACK_RETURN_COMMITTED_EVENT)
            self._require_outbox(envelope, committed=True)
            return envelope


__all__ = [
    "SOURCE_RECEIPT_ACK_RETURN_COMMITTED_EVENT",
    "SOURCE_RECEIPT_ACK_RETURN_PREPARED_EVENT",
    "SourceReceiptAckReturnStore",
]
