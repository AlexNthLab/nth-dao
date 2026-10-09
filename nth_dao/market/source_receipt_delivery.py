"""Directed source receipt delivery, independent of any network provider.

The outer envelope authorizes delivery, not business acceptance. Its embedded
JSON is canonical text so transports never round large signed integers.
"""

from __future__ import annotations

import json
import os
import re
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.acknowledgement import (
    MAX_ACK_BYTES,
    DeliveryAck,
    sign_ack,
    validate_ack,
)
from nth_dao.delivery.envelope import (
    MAX_ENVELOPE_BYTES,
    TransportEnvelope,
    envelope_digest,
    sign_envelope,
    validate_envelope,
)
from nth_dao.delivery.inbox import DeliveryInbox, DeliveryInboxCacheCorrupt
from nth_dao.delivery.outbox import DeliveryOutboxCorrupt, DurableOutbox, OutboxRecord
from nth_dao.identity import AgentIdentity
from nth_dao.market.claim_evidence import resolve_confirmed_claim_evidence
from nth_dao.market.claimant_receipt_store import ClaimantSourceReceiptStore
from nth_dao.market.completion_flow import build_portable_completion_proof_with_pins
from nth_dao.market.source_completion_inbox import SourceCompletionInbox, _io_path
from nth_dao.market.source_completion_receipt import (
    MAX_SOURCE_RECEIPT_RESPONSE_BYTES,
    extract_source_completion_receipt,
    verify_source_completion_receipt,
)
from nth_dao.spine.log import SignedEventLog
from nth_dao.util.io import InterProcessLock, atomic_write_bytes
from nth_dao.util.path_security import path_is_linklike

SOURCE_RECEIPT_DELIVERY_KIND = "market.claim.completion.source-receipt"
SOURCE_RECEIPT_DELIVERY_PREPARED_EVENT = "market.claim.completion.source_receipt.delivery.prepared"
SOURCE_RECEIPT_DELIVERY_ACKNOWLEDGED_EVENT = "market.claim.completion.source_receipt.delivery.acknowledged"
_PAYLOAD_FIELDS = frozenset({
    "source_claim_id", "completion_head_digest", "proof_digest", "source_receipt_json",
})
_MAX_DELIVERIES_PER_CLAIM = 32
_MESSAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_RESULT_BYTES = MAX_ENVELOPE_BYTES + MAX_ACK_BYTES + 1_024


class SourceReceiptDeliveryRejected(ValueError):
    """A delivery is unauthenticated, unbound, stale, or not intended for this node."""


class SourceReceiptDeliveryDeferred(SourceReceiptDeliveryRejected):
    """Valid intake must wait for local evidence or explicit storage maintenance."""


@dataclass(frozen=True)
class SourceReceiptDeliveryResult:
    """A signed transport ACK and a separately audited local observation."""

    observation: dict[str, Any]
    ack: DeliveryAck


@dataclass(frozen=True)
class SourceReceiptDeliveryFailure:
    message_id: str
    error_code: str
    reason: str
    retryable: bool = True


def source_receipt_delivery_failure(message_id: str, exc: Exception) -> SourceReceiptDeliveryFailure:
    return SourceReceiptDeliveryFailure(
        message_id=message_id, error_code=type(exc).__name__, reason=str(exc)[:512],
        retryable=(
            isinstance(exc, (OSError, RuntimeError, SourceReceiptDeliveryDeferred))
            and not isinstance(exc, (DeliveryInboxCacheCorrupt, DeliveryOutboxCorrupt))
        ),
    )


@dataclass(frozen=True)
class SourceReceiptResumeResult:
    """Independent outcomes; a failed item remains pending for an exact retry."""

    results: tuple[SourceReceiptDeliveryResult, ...]
    failures: tuple[SourceReceiptDeliveryFailure, ...]


def _canonical_snapshot(value: Any) -> Any:
    try:
        return json.loads(canonical_json(value))
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise SourceReceiptDeliveryRejected("delivery is not canonical JSON") from exc


def _checked_path(workspace: Path, relative: Path) -> Path:
    if relative.anchor or ".." in relative.parts or any(":" in part for part in relative.parts):
        raise SourceReceiptDeliveryRejected("delivery path must stay inside its workspace")
    path = _io_path(workspace.absolute() / relative)
    if any(path_is_linklike(parent) for parent in (path, *path.parents)):
        raise SourceReceiptDeliveryRejected("delivery path traverses a link")
    try:
        metadata = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return path
    if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
        raise SourceReceiptDeliveryRejected("delivery file is not an independent regular file")
    return path


def _write_delivery_bytes(workspace: Path, path: Path, raw: bytes) -> None:
    root = _checked_path(workspace, Path("."))
    if root not in path.parents:
        raise SourceReceiptDeliveryRejected("delivery storage must stay inside its workspace")
    atomic_write_bytes(path, raw, reject_links=True)
    if os.name != "nt":
        # A freshly created result/generation directory must itself survive
        # restart, not just the bytes inside it.
        for directory in path.parents:
            fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            if directory == root:
                break


def _receipt(envelope: TransportEnvelope) -> tuple[dict, dict, list]:
    if envelope.kind != SOURCE_RECEIPT_DELIVERY_KIND:
        raise SourceReceiptDeliveryRejected("wrong source receipt delivery kind")
    if envelope.dao_id is not None or envelope.routing != {"hop_limit": 0, "hop_count": 0}:
        raise SourceReceiptDeliveryRejected("source receipt delivery requires direct DID routing")
    payload = envelope.payload
    if set(payload) != _PAYLOAD_FIELDS:
        raise SourceReceiptDeliveryRejected("delivery payload has missing or unknown fields")
    text = payload["source_receipt_json"]
    try:
        if not isinstance(text, str) or len(text) > MAX_SOURCE_RECEIPT_RESPONSE_BYTES:
            raise ValueError("source receipt text exceeds size limit")
        raw = text.encode("utf-8")
        if len(raw) > MAX_SOURCE_RECEIPT_RESPONSE_BYTES:
            raise ValueError("source receipt text exceeds size limit")
        response = json.loads(raw)
        if canonical_json(response) != raw:
            raise ValueError("source receipt text must be canonical JSON")
        event, chain = extract_source_completion_receipt(response)
        signed = event["payload"]
        if not isinstance(signed, dict):
            raise TypeError("source receipt payload is invalid")
        if envelope.sender_did != event["author_did"]:
            raise ValueError("delivery signer differs from the receipt signer")
        if envelope.recipient != signed["claimant_did"]:
            raise ValueError("delivery recipient differs from the signed claimant")
        for field in _PAYLOAD_FIELDS - {"source_receipt_json"}:
            if not isinstance(payload[field], str) or payload[field] != signed[field]:
                raise ValueError(f"delivery {field} differs from the signed receipt")
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise SourceReceiptDeliveryRejected(str(exc)) from exc
    return response, event, chain


def _snapshot(envelope: TransportEnvelope) -> TransportEnvelope:
    if not isinstance(envelope, TransportEnvelope):
        raise SourceReceiptDeliveryRejected("delivery must be a TransportEnvelope")
    try:
        raw = canonical_json(envelope.to_dict())
        if len(raw) > MAX_ENVELOPE_BYTES:
            raise ValueError("delivery exceeds envelope size limit")
        snapshot = TransportEnvelope.from_dict(json.loads(raw))
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise SourceReceiptDeliveryRejected(str(exc)) from exc
    valid, reason = validate_envelope(snapshot, require_signature=True)
    if not valid:
        raise SourceReceiptDeliveryRejected(reason)
    return snapshot


def create_source_receipt_delivery(
    source: AgentIdentity,
    proof: dict,
    response: dict,
    *,
    expected_source_did: str,
    expected_federation_key: str,
    created_at_ms: int,
    expires_at_ms: int,
    nonce: str | None = None,
) -> TransportEnvelope:
    """Verify externally pinned proof/receipt before signing a directed envelope.

    This pure signing helper performs no disclosure audit or transport effects.
    A historic receipt signed by a retired key uses the offline import path;
    this version does not delegate delivery authority to a different key.
    """
    proof = _canonical_snapshot(proof)
    response = _canonical_snapshot(response)
    try:
        event, chain = extract_source_completion_receipt(response)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise SourceReceiptDeliveryRejected(str(exc)) from exc
    valid, reason = verify_source_completion_receipt(
        proof, event, expected_source_did=expected_source_did,
        expected_federation_key=expected_federation_key, rotation_chain=chain,
    )
    if not valid:
        raise SourceReceiptDeliveryRejected(reason)
    if source.as_did() != event["author_did"]:
        raise SourceReceiptDeliveryRejected("delivery signer differs from the receipt signer")
    signed = event["payload"]
    try:
        envelope = sign_envelope(
            source, kind=SOURCE_RECEIPT_DELIVERY_KIND, recipient=signed["claimant_did"],
            payload={
                **{field: signed[field] for field in _PAYLOAD_FIELDS - {"source_receipt_json"}},
                "source_receipt_json": canonical_json(response).decode("utf-8"),
            },
            created_at_ms=created_at_ms, expires_at_ms=expires_at_ms, nonce=nonce,
        )
    except ValueError as exc:
        raise SourceReceiptDeliveryRejected(str(exc)) from exc
    _receipt(envelope)
    return envelope


def source_receipt_preparation_payload(envelope: TransportEnvelope) -> dict:
    snapshot = _snapshot(envelope)
    _receipt(snapshot)
    return {
        "message_id": snapshot.message_id, "envelope_sha256": envelope_digest(snapshot),
        **{field: snapshot.payload[field] for field in (
            "source_claim_id", "completion_head_digest", "proof_digest",
        )},
        "sender_did": snapshot.sender_did, "recipient_did": snapshot.recipient,
        "accepted": False, "settled": False,
    }


def require_prepared_source_receipt_delivery(
    envelope: TransportEnvelope, *, workspace: Path, identity: AgentIdentity,
    spine: SignedEventLog,
) -> TransportEnvelope:
    """Bind ACK mutation or export to audited local source evidence."""
    snapshot = _snapshot(envelope)
    _, selected, _ = _receipt(snapshot)
    if snapshot.sender_did != identity.as_did() or spine.signer_did != identity.as_did():
        raise SourceReceiptDeliveryRejected("delivery signer differs from the selected identity")
    spine.require_independent_storage()
    retained = SourceCompletionInbox(
        workspace, source_did=identity.as_did(), spine=spine,
    ).get(snapshot.payload["source_claim_id"], snapshot.payload["completion_head_digest"][7:])
    if retained is None or canonical_json(retained["source_receipt_event"]) != canonical_json(selected):
        raise SourceReceiptDeliveryRejected("delivery differs from the source's retained receipt")
    prepared = spine.find_unique_event(
        SOURCE_RECEIPT_DELIVERY_PREPARED_EVENT,
        payload_field="message_id", payload_value=snapshot.message_id,
    )
    if (
        prepared is None or prepared.author_did != identity.as_did()
        or canonical_json(prepared.payload) != canonical_json(source_receipt_preparation_payload(snapshot))
    ):
        raise SourceReceiptDeliveryRejected("delivery lacks matching audited preparation")
    return snapshot


def open_source_receipt_delivery_outbox(
    workspace: Path, *, clock: Callable[[], int] | None = None,
) -> DurableOutbox:
    """Use the same secure, evidence-retaining outbox for every entry point."""
    relative = Path(".nth/source_receipt_delivery_outbox")
    for name in ("outbox.journal.jsonl", "outbox.lock"):
        _checked_path(workspace, relative / name)
    return DurableOutbox(
        _checked_path(workspace, relative), clock=clock,
        retain_terminal_records=True, reject_links=True,
    )


def acknowledge_source_receipt_delivery(
    ack: DeliveryAck, *, workspace: Path, identity: AgentIdentity,
    spine: SignedEventLog, clock: Callable[[], int] | None = None,
) -> OutboxRecord:
    """Verify local source evidence before ACK mutation, then sign its audit.

    If audit fails after delivery persistence, raise and allow the same ACK
    to repair the audit. Neither success nor a transport ACK accepts work.
    """
    return _acknowledge_source_receipt_delivery(
        ack, workspace=workspace, identity=identity, spine=spine, clock=clock,
    )


def _acknowledge_source_receipt_delivery(
    ack: DeliveryAck, *, workspace: Path, identity: AgentIdentity,
    spine: SignedEventLog, clock: Callable[[], int] | None = None,
    outbox: DurableOutbox | None = None,
) -> OutboxRecord:
    """Shared gate; reuse storage only after exact scope/policy validation."""
    if not isinstance(ack, DeliveryAck):
        raise SourceReceiptDeliveryRejected("ack must be a DeliveryAck")
    raw = canonical_json(ack.to_dict())
    if len(raw) > MAX_ACK_BYTES:
        raise SourceReceiptDeliveryRejected("ack exceeds the wire byte limit")
    snapshot = DeliveryAck.from_dict(json.loads(raw))
    now = clock() if clock is not None else int(time.time() * 1000)
    valid, reason = validate_ack(snapshot, now_ms=now)
    if not valid:
        raise SourceReceiptDeliveryRejected(reason)
    if outbox is None:
        outbox = open_source_receipt_delivery_outbox(workspace, clock=clock)
    if not isinstance(outbox, DurableOutbox):
        raise TypeError("source receipt outbox must be a DurableOutbox")
    outbox.require_retained_independent_storage(
        _checked_path(workspace, Path(".nth/source_receipt_delivery_outbox")),
    )
    queued = outbox.get(snapshot.message_id)
    if queued is None:
        raise SourceReceiptDeliveryRejected("ack for unknown source receipt delivery")
    require_prepared_source_receipt_delivery(
        TransportEnvelope.from_dict(json.loads(queued.envelope_json)),
        workspace=workspace, identity=identity, spine=spine,
    )
    delivered = outbox.handle_ack(snapshot, now_ms=now, allow_expired=True)
    spine.append_unique(
        SOURCE_RECEIPT_DELIVERY_ACKNOWLEDGED_EVENT,
        {
            "message_id": delivered.message_id,
            "envelope_sha256": delivered.envelope_sha256,
            "receiver_did": delivered.delivered_by,
            "verification_scope": "transport_receipt_only",
            "accepted": False, "settled": False,
        },
        unique_payload_fields=("message_id",),
    )
    return delivered


class SourceReceiptDeliveryReceiver:
    """One confirmed local claim's durable, fail-closed receipt delivery inbox.

    Pass the claimant's signing identity, not a different operator's identity.
    ``receive`` checks freshness for new intake; ``resume_pending`` only retries
    previously durable intake and rechecks the full local proof and pins.
    """

    def __init__(
        self, workspace: Path, *, nonce: str, identity: AgentIdentity,
        spine: SignedEventLog, clock: Callable[[], int] | None = None,
    ) -> None:
        self.workspace = Path(workspace)
        self.nonce = nonce
        self.identity = identity
        self.spine = spine
        spine.require_independent_storage()
        self._clock = clock or (lambda: int(time.time() * 1000))
        claim = resolve_confirmed_claim_evidence(self.workspace, nonce)
        if claim["intent"]["claimant_did"] != identity.as_did() or not identity.can_sign:
            raise SourceReceiptDeliveryRejected("receiver identity differs from the confirmed claimant")
        self.store = ClaimantSourceReceiptStore(
            self.workspace, observer_did=identity.as_did(), spine=spine,
        )
        self._source_claim_id = claim["authority_ack"]["ack_id"]
        self._directory = Path(".nth") / "source_receipt_deliveries" / self._source_claim_id
        self._check_storage_paths()
        directory = _checked_path(self.workspace, self._directory)
        self._intake_lock = _checked_path(self.workspace, self._directory / "intake.lock")
        self.inbox = DeliveryInbox(
            directory, authorize=self._authorize, clock=self._clock,
            max_replay_entries=_MAX_DELIVERIES_PER_CLAIM,
            reject_links=True,
            evict_processed=False,
        )

    @property
    def source_claim_id(self) -> str:
        return self._source_claim_id

    def current_time_ms(self) -> int:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise SourceReceiptDeliveryRejected("delivery clock must return positive integer ms")
        return value

    def _check_storage_paths(self) -> None:
        for name in ("inbox.cache.jsonl", "inbox.rejections.jsonl", "inbox.lock", "intake.lock"):
            _checked_path(self.workspace, self._directory / name)
        for name in ("inbox.lock", "intake.lock"):
            InterProcessLock(
                _checked_path(self.workspace, self._directory / name), reject_links=True,
            ).check_path()

    def _verify_local(self, envelope: TransportEnvelope) -> dict:
        response, event, chain = _receipt(envelope)
        if envelope.recipient != self.identity.as_did():
            raise SourceReceiptDeliveryRejected("delivery is intended for another recipient")
        if envelope.payload["source_claim_id"] != self._source_claim_id:
            raise SourceReceiptDeliveryRejected("delivery differs from the selected local claim")
        built = build_portable_completion_proof_with_pins(
            self.workspace, self.nonce,
            head_digest=envelope.payload["completion_head_digest"],
        )
        if built is None:
            raise SourceReceiptDeliveryDeferred("matching local completion head is unavailable")
        proof, source_did, federation_key = built
        if proof["intent"]["claimant_did"] != self.identity.as_did():
            raise SourceReceiptDeliveryRejected("local claimant identity changed")
        valid, reason = verify_source_completion_receipt(
            proof, event, expected_source_did=source_did,
            expected_federation_key=federation_key, rotation_chain=chain,
        )
        if not valid:
            raise SourceReceiptDeliveryRejected(reason)
        return response

    def _authorize(self, envelope: TransportEnvelope) -> tuple[bool, str]:
        try:
            self._verify_local(envelope)
        except (TypeError, ValueError, RecursionError) as exc:
            return False, str(exc)
        return True, "ok"

    def _result_path(self, message_id: str) -> Path:
        if not isinstance(message_id, str) or _MESSAGE_ID_RE.fullmatch(message_id) is None:
            raise SourceReceiptDeliveryRejected("delivery message ID is invalid")
        return _checked_path(self.workspace, self._directory / "results" / (message_id[7:] + ".json"))

    def _read_result(self, path: Path) -> dict:
        before = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > _MAX_RESULT_BYTES:
            raise SourceReceiptDeliveryRejected("retained delivery result is unsafe")
        flags = (
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            after = path.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(after.st_mode)
                or opened.st_nlink != 1 or after.st_nlink != 1
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                or opened.st_size > _MAX_RESULT_BYTES
            ):
                raise SourceReceiptDeliveryRejected("retained delivery result changed during read")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(_MAX_RESULT_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > _MAX_RESULT_BYTES:
            raise SourceReceiptDeliveryRejected("retained delivery result exceeds size limit")
        value = json.loads(raw)
        if (
            canonical_json(value) != raw
            or set(value) != {"version", "envelope", "ack", "observation_event_id"}
            or type(value["version"]) is not int or value["version"] != 1
        ):
            raise SourceReceiptDeliveryRejected("retained delivery result is not canonical v1")
        return value

    def _retained_result(self, envelope: TransportEnvelope) -> SourceReceiptDeliveryResult | None:
        path = self._result_path(envelope.message_id)
        if not path.exists():
            return None
        value = self._read_result(path)
        retained = _snapshot(TransportEnvelope.from_dict(value["envelope"]))
        if canonical_json(retained.to_dict()) != canonical_json(envelope.to_dict()):
            raise SourceReceiptDeliveryRejected("retained delivery envelope differs")
        self._verify_local(retained)
        ack = DeliveryAck.from_dict(value["ack"])
        valid, reason = validate_ack(ack, now_ms=self._clock())
        if not valid:
            raise SourceReceiptDeliveryRejected(reason)
        if (
            ack.message_id != envelope.message_id
            or ack.envelope_sha256 != envelope_digest(envelope)
            or ack.receiver_did != self.identity.as_did()
            or ack.received_at_ms != self.inbox.accepted_at(envelope.message_id)
        ):
            raise SourceReceiptDeliveryRejected("retained delivery ACK binding differs")
        valid, reason = validate_envelope(envelope, now_ms=ack.received_at_ms, require_signature=True)
        if not valid:
            raise SourceReceiptDeliveryRejected(reason)
        observation = self.store.get(self.nonce, envelope.payload["completion_head_digest"])
        if observation is None or observation["local_observation_event_id"] != value["observation_event_id"]:
            raise SourceReceiptDeliveryRejected("retained delivery observation is unavailable or differs")
        return SourceReceiptDeliveryResult(observation=observation, ack=ack)

    def get_ack(self, message_id: str) -> SourceReceiptDeliveryResult:
        """Reverify and export a durable result without accepting a new envelope."""
        self._check_storage_paths()
        with InterProcessLock(self._intake_lock, reject_links=True):
            self._check_storage_paths()
            value = self._read_result(self._result_path(message_id))
            envelope = _snapshot(TransportEnvelope.from_dict(value["envelope"]))
            if envelope.message_id != message_id:
                raise SourceReceiptDeliveryRejected("retained delivery result belongs to another message")
            return self._process(envelope)

    def export_retained_acks(self) -> SourceReceiptResumeResult:
        """Reverify a bounded ACK worklist from the durable handled index.

        Returned ACKs are export candidates, not evidence of their return to
        the source. Repeated exports are exact and cause no new business work.
        An empty failure message_id denotes worklist enumeration failure.
        """
        try:
            self._check_storage_paths()
            message_ids = self.inbox.processed_message_ids(max_items=_MAX_DELIVERIES_PER_CLAIM)
        except (OSError, DeliveryInboxCacheCorrupt, SourceReceiptDeliveryRejected) as exc:
            return SourceReceiptResumeResult(results=(), failures=(source_receipt_delivery_failure("", exc),))
        results = []
        failures = []
        for message_id in message_ids:
            try:
                results.append(self.get_ack(message_id))
            except (OSError, TypeError, ValueError, RuntimeError, RecursionError) as exc:
                failures.append(source_receipt_delivery_failure(message_id, exc))
        return SourceReceiptResumeResult(results=tuple(results), failures=tuple(failures))

    def _process(self, envelope: TransportEnvelope) -> SourceReceiptDeliveryResult:
        accepted_at = self.inbox.accepted_at(envelope.message_id)
        if accepted_at is None:
            raise SourceReceiptDeliveryRejected("delivery lacks durable first-acceptance time")
        valid, reason = validate_envelope(envelope, now_ms=accepted_at, require_signature=True)
        if not valid:
            raise SourceReceiptDeliveryRejected(reason)
        retained = self._retained_result(envelope)
        if retained is not None:
            self.inbox.mark_processed(envelope.message_id)
            return retained
        response = self._verify_local(envelope)
        observation = self.store.record(self.nonce, response)
        ack = sign_ack(
            self.identity, message_id=envelope.message_id,
            envelope_sha256=envelope_digest(envelope), received_at_ms=accepted_at,
        )
        _write_delivery_bytes(self.workspace, self._result_path(envelope.message_id), canonical_json({
            "version": 1, "envelope": envelope.to_dict(), "ack": ack.to_dict(),
            "observation_event_id": observation["local_observation_event_id"],
        }))
        self.inbox.mark_processed(envelope.message_id)
        return SourceReceiptDeliveryResult(observation=observation, ack=ack)

    def receive(self, envelope: TransportEnvelope) -> SourceReceiptDeliveryResult:
        snapshot = _snapshot(envelope)
        return self._receive_snapshot(snapshot, accepted_at_ms=self.current_time_ms())

    def receive_retained(
        self, ingress: DeliveryInbox, message_id: str,
    ) -> SourceReceiptDeliveryResult:
        """Resume trusted local intake; never backdate using a caller's timestamp.

        The ingress grants no domain authority. Full proof and independently
        pinned source identity are reverified before observation or signing.
        """
        if not isinstance(ingress, DeliveryInbox):
            raise TypeError("ingress must be a DeliveryInbox")
        retained = ingress.retained_pending(message_id)
        if retained is None:
            if self.inbox.seen(message_id) and self._result_path(message_id).exists():
                return self.get_ack(message_id)
            raise SourceReceiptDeliveryDeferred("retained ingress item is unavailable")
        return self._receive_snapshot(
            _snapshot(retained.envelope), accepted_at_ms=retained.accepted_at_ms,
        )

    def _receive_snapshot(
        self, snapshot: TransportEnvelope, *, accepted_at_ms: int,
    ) -> SourceReceiptDeliveryResult:
        self._check_storage_paths()
        with InterProcessLock(self._intake_lock, reject_links=True):
            self._check_storage_paths()
            if self._result_path(snapshot.message_id).exists():
                return self._process(snapshot)
            valid, reason = validate_envelope(snapshot, now_ms=accepted_at_ms, require_signature=True)
            if not valid:
                raise SourceReceiptDeliveryRejected(reason)
            self._verify_local(snapshot)
            # Do not inherit the general Inbox's processed-entry eviction.
            # A completed claim has a bounded number of receipt deliveries;
            # preserving every nonce is safer than making old replays fresh.
            if (
                not self.inbox.seen(snapshot.message_id)
                and self.inbox.entry_count() >= _MAX_DELIVERIES_PER_CLAIM
            ):
                raise SourceReceiptDeliveryDeferred("source receipt delivery inbox is at capacity")
            decision = self.inbox.accept(snapshot, now_ms=accepted_at_ms)
            if not decision.accepted and not decision.duplicate:
                raise SourceReceiptDeliveryRejected(decision.reason)
            return self._process(snapshot)

    def resume_pending(self) -> SourceReceiptResumeResult:
        """Resume already durable work, including after its intake TTL expired."""
        self._check_storage_paths()
        with InterProcessLock(self._intake_lock, reject_links=True):
            self._check_storage_paths()
            results = []
            failures = []
            for envelope in self.inbox.pending(max_items=_MAX_DELIVERIES_PER_CLAIM):
                try:
                    results.append(self._process(_snapshot(envelope)))
                except (OSError, TypeError, ValueError, RuntimeError, RecursionError) as exc:
                    failures.append(source_receipt_delivery_failure(envelope.message_id, exc))
            return SourceReceiptResumeResult(results=tuple(results), failures=tuple(failures))


__all__ = [
    "SOURCE_RECEIPT_DELIVERY_ACKNOWLEDGED_EVENT",
    "SOURCE_RECEIPT_DELIVERY_KIND",
    "SOURCE_RECEIPT_DELIVERY_PREPARED_EVENT",
    "SourceReceiptDeliveryDeferred",
    "SourceReceiptDeliveryFailure",
    "SourceReceiptDeliveryReceiver",
    "SourceReceiptDeliveryRejected",
    "SourceReceiptDeliveryResult",
    "SourceReceiptResumeResult",
    "acknowledge_source_receipt_delivery",
    "create_source_receipt_delivery",
    "open_source_receipt_delivery_outbox",
    "require_prepared_source_receipt_delivery",
    "source_receipt_delivery_failure",
    "source_receipt_preparation_payload",
]
