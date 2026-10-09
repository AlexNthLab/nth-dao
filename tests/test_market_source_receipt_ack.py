"""Source ACK intake binds a durable return envelope to prepared local evidence."""

from __future__ import annotations

import multiprocessing
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

import pytest

pytest.importorskip("nacl")

from test_market_source_receipt_delivery import _delivery, _prepare_source

from nth_dao.delivery.acknowledgement import DeliveryAck, sign_ack, sign_ack_envelope
from nth_dao.delivery.envelope import envelope_digest, sign_envelope
from nth_dao.delivery.inbox import DeliveryInbox, DeliveryInboxCacheCorrupt
from nth_dao.delivery.outbox import OUTBOX_STATE_DELIVERED, OUTBOX_STATE_QUEUED
from nth_dao.identity import AgentIdentity
from nth_dao.market.source_receipt_ack import SourceReceiptAckReceiver
from nth_dao.market.source_receipt_delivery import (
    SOURCE_RECEIPT_DELIVERY_ACKNOWLEDGED_EVENT,
    SourceReceiptDeliveryRejected,
    open_source_receipt_delivery_outbox,
)
from nth_dao.spine.log import SignedEventLog


def _setup_return(tmp_path):
    source, claimant, _, _, original, claimant_receiver, now = _delivery(tmp_path)
    _prepare_source(tmp_path, source, original)
    outbox = open_source_receipt_delivery_outbox(tmp_path / "source", clock=lambda: now)
    outbox.enqueue(original)
    result = claimant_receiver.receive(original)
    returned = sign_ack_envelope(claimant, result.ack, recipient=source.as_did(),
                                 created_at_ms=now, expires_at_ms=now + 60_000)
    source_receiver = SourceReceiptAckReceiver(
        tmp_path / "source", identity=source,
        spine=SignedEventLog(tmp_path / "source/spine.jsonl", source), clock=lambda: now,
    )
    return source, claimant, original, returned, source_receiver, outbox, now


def _receive_ack_in_process(args):
    workspace, identity, returned, now = args
    receiver = SourceReceiptAckReceiver(workspace, identity=identity,
                                        spine=SignedEventLog(workspace / "spine.jsonl", identity),
                                        clock=lambda: now)
    return receiver.receive(returned).delivery.message_id


def test_source_ack_intake_closes_only_original_receipt_and_signs_audit(tmp_path):
    source, _, original, returned, receiver, outbox, _ = _setup_return(tmp_path)
    result = receiver.receive(returned)
    assert result.message_id == returned.message_id
    assert result.delivery.message_id == original.message_id and result.delivery.state == OUTBOX_STATE_DELIVERED
    assert outbox.get(original.message_id).state == OUTBOX_STATE_DELIVERED
    assert receiver.inbox.pending() == [] and receiver.resume_pending().results == ()
    event = receiver.spine.find_unique_event(SOURCE_RECEIPT_DELIVERY_ACKNOWLEDGED_EVENT,
                                            payload_field="message_id", payload_value=original.message_id)
    assert event.author_did == source.as_did()
    assert not event.payload["accepted"] and not event.payload["settled"]
    assert receiver.spine.verify_chain()[0]


@pytest.mark.parametrize("mismatch", ["receiver", "digest", "time", "unknown", "route", "unsigned"])
def test_valid_outer_signature_cannot_authorize_unbound_inner_ack(tmp_path, mismatch):
    source, claimant, original, returned, receiver, outbox, now = _setup_return(tmp_path)
    signer = AgentIdentity.generate() if mismatch == "receiver" else claimant
    ack = sign_ack(
        signer, message_id="sha256:" + "0" * 64 if mismatch == "unknown" else original.message_id,
        envelope_sha256="sha256:" + "0" * 64 if mismatch == "digest" else envelope_digest(original),
        received_at_ms=original.expires_at_ms if mismatch == "time" else now,
    )
    returned = sign_envelope(
        signer, kind="delivery.ack", recipient=claimant.as_did() if mismatch == "route" else source.as_did(),
        payload={"ack": ack.to_dict()}, created_at_ms=now, expires_at_ms=now + 120_000,
    )
    if mismatch == "unsigned":
        returned.signature = ""
    with pytest.raises(ValueError):
        receiver.receive(returned)
    assert receiver.inbox.entry_count() == 0
    assert outbox.get(original.message_id).state == OUTBOX_STATE_QUEUED


def test_audit_failure_leaves_ack_pending_and_repairs_after_expiry_and_restart(tmp_path, monkeypatch):
    source, _, original, returned, receiver, outbox, now = _setup_return(tmp_path)

    def fail(*args, **kwargs):
        raise OSError("injected source ACK audit failure")

    with monkeypatch.context() as patch:
        patch.setattr(receiver.spine, "append_unique", fail)
        with pytest.raises(OSError, match="audit failure"):
            receiver.receive(returned)
    assert outbox.get(original.message_id).state == OUTBOX_STATE_DELIVERED
    assert receiver.inbox.pending()[0].message_id == returned.message_id
    restarted = SourceReceiptAckReceiver(receiver.workspace, identity=source,
                                         spine=SignedEventLog(receiver.workspace / "spine.jsonl", source),
                                         clock=lambda: now + 120_000)
    with pytest.raises(SourceReceiptDeliveryRejected, match="expired"):
        restarted.receive(returned)
    resumed = restarted.resume_pending()
    assert resumed.failures == () and resumed.results[0].delivery.state == OUTBOX_STATE_DELIVERED
    assert restarted.inbox.pending() == [] and restarted.spine.verify_chain()[0]


def test_parallel_source_ack_retries_have_one_delivery_audit(tmp_path):
    _, _, original, returned, receiver, outbox, _ = _setup_return(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: receiver.receive(returned), range(6)))
    assert all(item.delivery.state == OUTBOX_STATE_DELIVERED for item in results)
    assert receiver.inbox.entry_count() == 1 and receiver.inbox.pending() == []
    assert outbox.get(original.message_id).state == OUTBOX_STATE_DELIVERED
    assert receiver.spine.find_unique_event(SOURCE_RECEIPT_DELIVERY_ACKNOWLEDGED_EVENT,
                                           payload_field="message_id", payload_value=original.message_id) is not None


def test_source_ack_cannot_bypass_changed_preparation_evidence(tmp_path, monkeypatch):
    _, _, original, returned, receiver, outbox, _ = _setup_return(tmp_path)
    assert receiver.inbox.accept(returned).accepted
    monkeypatch.setattr(receiver.spine, "find_unique_event", lambda *a, **k: None)
    failed = receiver.resume_pending()
    assert failed.results == () and not failed.failures[0].retryable
    assert receiver.inbox.pending()[0].message_id == returned.message_id
    assert outbox.get(original.message_id).state == OUTBOX_STATE_QUEUED


def test_retained_ack_staging_uses_local_first_intake_not_current_expired_time(tmp_path, monkeypatch):
    _, _, original, returned, receiver, outbox, now = _setup_return(tmp_path)
    ingress = DeliveryInbox(tmp_path / "trusted-stage", clock=lambda: now)
    assert ingress.accept(returned).accepted
    monkeypatch.setattr(receiver, "_clock", lambda: now + 120_000)
    result = receiver.receive_retained(ingress, returned.message_id)
    assert result.delivery.state == OUTBOX_STATE_DELIVERED
    assert outbox.get(original.message_id).state == OUTBOX_STATE_DELIVERED


@pytest.mark.parametrize("error,retryable", [(OSError, True), (DeliveryInboxCacheCorrupt, False)])
def test_pending_worklist_failure_is_visible_without_fabricating_delivery(tmp_path, monkeypatch, error, retryable):
    _, _, original, _, receiver, outbox, _ = _setup_return(tmp_path)

    def unavailable(*args, **kwargs):
        raise error("injected ACK worklist failure")

    monkeypatch.setattr(receiver.inbox, "pending", unavailable)
    batch = receiver.resume_pending()
    assert batch.results == () and len(batch.failures) == 1
    assert batch.failures[0].message_id == "" and batch.failures[0].retryable is retryable
    assert outbox.get(original.message_id).state == OUTBOX_STATE_QUEUED


def test_source_ack_concurrent_processes_reuse_one_intake_and_audit(tmp_path):
    source, _, original, returned, receiver, outbox, now = _setup_return(tmp_path)
    args = (receiver.workspace, source, returned, now)
    with ProcessPoolExecutor(max_workers=3, mp_context=multiprocessing.get_context("spawn")) as pool:
        result = list(pool.map(_receive_ack_in_process, [args] * 6))
    assert result == [original.message_id] * 6
    assert outbox.get(original.message_id).state == OUTBOX_STATE_DELIVERED
    assert receiver.inbox.entry_count() == 1 and receiver.inbox.pending() == []
    assert receiver.spine.verify_chain()[0]


def test_fresh_return_may_confirm_a_previously_expired_original(tmp_path):
    source, claimant, original, returned, receiver, outbox, now = _setup_return(tmp_path)
    ack = returned.payload["ack"]
    late = now + 120_000
    returned = sign_ack_envelope(claimant, DeliveryAck.from_dict(ack), recipient=source.as_did(),
                                 created_at_ms=late, expires_at_ms=late + 60_000)
    receiver = SourceReceiptAckReceiver(receiver.workspace, identity=source,
                                        spine=SignedEventLog(receiver.workspace / "spine.jsonl", source),
                                        clock=lambda: late)
    assert receiver.receive(returned).delivery.state == OUTBOX_STATE_DELIVERED
    assert outbox.get(original.message_id).state == OUTBOX_STATE_DELIVERED


def test_changed_return_bytes_cannot_reuse_a_retained_nonce(tmp_path):
    source, claimant, original, returned, receiver, outbox, now = _setup_return(tmp_path)
    receiver.receive(returned)
    changed = sign_ack_envelope(claimant, DeliveryAck.from_dict(returned.payload["ack"]),
                                recipient=source.as_did(), nonce=returned.nonce,
                                created_at_ms=now, expires_at_ms=now + 90_000)
    with pytest.raises(SourceReceiptDeliveryRejected, match="replayed nonce"):
        receiver.receive(changed)
    assert receiver.inbox.entry_count() == 1
    assert outbox.get(original.message_id).state == OUTBOX_STATE_DELIVERED
    assert receiver.spine.verify_chain()[0]


def test_corrupt_source_outbox_is_non_retryable_and_does_not_discard_pending_ack(tmp_path):
    _, _, original, returned, receiver, _, _ = _setup_return(tmp_path)
    assert receiver.inbox.accept(returned).accepted
    journal = receiver.workspace / ".nth/source_receipt_delivery_outbox/outbox.journal.jsonl"
    corrupted = journal.read_bytes() + b'{"event":"unknown"}\n'
    journal.write_bytes(corrupted)
    batch = receiver.resume_pending()
    assert batch.results == () and len(batch.failures) == 1 and not batch.failures[0].retryable
    assert batch.failures[0].error_code == "DeliveryOutboxCorrupt"
    assert receiver.inbox.pending()[0].message_id == returned.message_id
    assert journal.read_bytes() == corrupted
    assert receiver.spine.find_unique_event(SOURCE_RECEIPT_DELIVERY_ACKNOWLEDGED_EVENT,
                                           payload_field="message_id", payload_value=original.message_id) is None


def test_completed_ack_capacity_reuses_slots_without_removing_replay_history(tmp_path, monkeypatch):
    monkeypatch.setattr("nth_dao.market.source_receipt_ack.MAX_SOURCE_RECEIPT_ACK_ENTRIES", 1)
    source, claimant, original, returned, receiver, outbox, now = _setup_return(tmp_path)
    receiver.receive(returned)
    changed = sign_ack_envelope(claimant, DeliveryAck.from_dict(returned.payload["ack"]),
                                recipient=source.as_did(), created_at_ms=now, expires_at_ms=now + 90_000)
    assert receiver.receive(changed).delivery.state == OUTBOX_STATE_DELIVERED
    assert receiver.inbox.entry_count() == 1 and receiver.inbox.pending() == []
    assert receiver.receive(returned).delivery.state == OUTBOX_STATE_DELIVERED
    assert outbox.get(original.message_id).state == OUTBOX_STATE_DELIVERED


def test_ack_processing_does_not_reopen_and_refold_source_outbox_per_verification(tmp_path, monkeypatch):
    _, _, _, returned, receiver, _, _ = _setup_return(tmp_path)
    from nth_dao.delivery.outbox import DurableOutbox
    load = DurableOutbox._load
    reloads = []
    def counted(self):
        if self._dir.name == "source_receipt_delivery_outbox":
            reloads.append(self._dir)
        return load(self)
    monkeypatch.setattr(DurableOutbox, "_load", counted)
    assert receiver.receive(returned).delivery.state == OUTBOX_STATE_DELIVERED
    assert len(reloads) <= 1, "each ACK reopened the full source journal for every authorization check"
