"""Governed bidirectional receipt flow; ACK return never accepts work or funds."""

from __future__ import annotations

import json
import os

import pytest

pytest.importorskip("nacl")

from test_market_source_receipt_plugin import _authority, _setup

from nth_dao.delivery.acknowledgement import DeliveryAck, sign_ack, sign_ack_envelope
from nth_dao.delivery.envelope import TransportEnvelope, envelope_digest, sign_envelope
from nth_dao.delivery.inbox import DeliveryInbox, DeliveryInboxCacheCorrupt
from nth_dao.delivery.outbox import (
    OUTBOX_STATE_DELIVERED,
    OUTBOX_STATE_QUEUED,
    DurableOutbox,
)
from nth_dao.delivery.plugin_runtime import (
    PluginDeliveryRuntime,
    PluginDeliveryRuntimeError,
)
from nth_dao.market.source_receipt_ack import SourceReceiptAckReceiver
from nth_dao.market.source_receipt_delivery import (
    SOURCE_RECEIPT_DELIVERY_ACKNOWLEDGED_EVENT,
    SourceReceiptDeliveryRejected,
)
from nth_dao.market.source_receipt_plugin import (
    open_source_receipt_plugin_inbox,
    receive_source_receipt_acks,
    receive_source_receipt_deliveries,
)
from nth_dao.plugins.builtin.loopback_transport import loopback_route_id
from nth_dao.plugins.host import PluginInvocationError
from nth_dao.spine.log import SignedEventLog


def _setup_pipeline(tmp_path):
    source, claimant, original, claimant_receiver, now, host, binding, sender, runtime = _setup(tmp_path)
    assert sender.submit(original).accepted
    batch = receive_source_receipt_deliveries(runtime=runtime, receiver=claimant_receiver, receive_id="forward")
    ack = batch.domain.results[0].ack
    returned = sign_ack_envelope(claimant, ack, recipient=source.as_did(),
                                 created_at_ms=now, expires_at_ms=now + 60_000)
    returner = PluginDeliveryRuntime(
        binding=binding, authority=_authority(claimant, source.as_did()), route_resolver=loopback_route_id,
        outbox=DurableOutbox(tmp_path / "claimant/ack-return-outbox", clock=lambda: now,
                             retain_terminal_records=True, reject_links=True), clock=lambda: now,
    )
    source_receiver = SourceReceiptAckReceiver(
        tmp_path / "source", identity=source,
        spine=SignedEventLog(tmp_path / "source/spine.jsonl", source), clock=lambda: now,
    )
    source_runtime = PluginDeliveryRuntime(
        binding=binding, authority=_authority(source), route_resolver=loopback_route_id,
        outbox=sender.outbox, inbox=source_receiver.inbox, clock=lambda: now,
    )
    return source, claimant, original, returned, source_receiver, source_runtime, returner, sender, host, binding, now


def test_bidirectional_plugin_flow_applies_signed_ack_without_manual_sender_call(tmp_path):
    source, _, original, returned, receiver, runtime, returner, sender, _host, _, _ = _setup_pipeline(tmp_path)
    assert returner.submit(returned).accepted
    assert sender.outbox.get(original.message_id).state == OUTBOX_STATE_QUEUED
    batch = receive_source_receipt_acks(runtime=runtime, receiver=receiver, receive_id="ack-return")
    assert batch.transport.transport_acknowledged and batch.transport_error is None
    assert batch.domain.failures == () and len(batch.domain.results) == 1
    assert batch.domain.results[0].delivery.message_id == original.message_id
    assert sender.outbox.get(original.message_id).state == OUTBOX_STATE_DELIVERED
    # Sending a terminal ACK is not proof that the source applied it. No ACK
    # of ACK is minted to manufacture a delivered state for the return outbox.
    assert returner.outbox.get(returned.message_id).state == OUTBOX_STATE_QUEUED
    assert receiver.inbox.pending() == [] and open_source_receipt_plugin_inbox(receiver).pending() == []
    event = receiver.spine.find_unique_event(SOURCE_RECEIPT_DELIVERY_ACKNOWLEDGED_EVENT,
                                            payload_field="message_id", payload_value=original.message_id)
    assert event.author_did == source.as_did() and not event.payload["accepted"] and not event.payload["settled"]
    assert receiver.spine.verify_chain()[0]
    assert returner.submit(returned).accepted
    duplicate = receive_source_receipt_acks(runtime=runtime, receiver=receiver, receive_id="duplicate")
    assert not duplicate.transport.found and duplicate.domain.failures == ()
    assert receiver.inbox.entry_count() == 1


def test_return_outbox_exact_bytes_survive_runtime_restart(tmp_path):
    _, claimant, original, returned, receiver, runtime, returner, sender, _host, binding, now = _setup_pipeline(tmp_path)
    returner.outbox.enqueue(returned)
    restarted = PluginDeliveryRuntime(
        binding=binding, authority=_authority(claimant, receiver.identity.as_did()), route_resolver=loopback_route_id,
        outbox=DurableOutbox(tmp_path / "claimant/ack-return-outbox", clock=lambda: now,
                             retain_terminal_records=True, reject_links=True), clock=lambda: now,
    )
    retained = TransportEnvelope.from_dict(json.loads(restarted.outbox.get(returned.message_id).envelope_json))
    assert retained.to_dict() == returned.to_dict() and restarted.submit(retained).accepted
    result = receive_source_receipt_acks(runtime=runtime, receiver=receiver, receive_id="restarted-return")
    assert result.domain.results[0].delivery.message_id == original.message_id
    assert sender.outbox.get(original.message_id).state == OUTBOX_STATE_DELIVERED


@pytest.mark.parametrize("mismatch", ["principal", "inbox"])
def test_source_runtime_substitution_is_rejected_before_provider_call(tmp_path, monkeypatch, mismatch):
    _, claimant, _, _, receiver, runtime, _, _, host, binding, now = _setup_pipeline(tmp_path)
    bad = PluginDeliveryRuntime(
        binding=binding, authority=_authority(claimant if mismatch == "principal" else receiver.identity),
        route_resolver=loopback_route_id, outbox=runtime.outbox,
        inbox=DeliveryInbox(tmp_path / "unrelated-inbox") if mismatch == "inbox" else receiver.inbox,
        clock=lambda: now,
    )
    monkeypatch.setattr(host, "invoke", lambda *a, **k: pytest.fail("mismatched runtime invoked provider"))
    with pytest.raises(SourceReceiptDeliveryRejected, match="differs"):
        receive_source_receipt_acks(runtime=bad, receiver=receiver, receive_id="wrong-source")


def test_return_sender_obeys_explicit_route_grants(tmp_path):
    _, claimant, original, returned, receiver, _, returner, sender, _host, binding, now = _setup_pipeline(tmp_path)
    unscoped = PluginDeliveryRuntime(
        binding=binding, authority=_authority(claimant), route_resolver=loopback_route_id,
        outbox=returner.outbox, clock=lambda: now,
    )
    with pytest.raises(PluginDeliveryRuntimeError):
        unscoped.submit(returned)
    assert sender.outbox.get(original.message_id).state == OUTBOX_STATE_QUEUED
    assert open_source_receipt_plugin_inbox(receiver).entry_count() == 0


def test_source_audit_failure_recovers_from_empty_provider_after_return_expiry(tmp_path, monkeypatch):
    source, _, original, returned, receiver, runtime, returner, sender, _host, binding, now = _setup_pipeline(tmp_path)
    assert returner.submit(returned).accepted

    def unavailable(*args, **kwargs):
        raise OSError("injected source audit storage failure")

    with monkeypatch.context() as patch:
        patch.setattr(receiver.spine, "append_unique", unavailable)
        first = receive_source_receipt_acks(runtime=runtime, receiver=receiver, receive_id="source-audit-fail")
    assert first.transport.transport_acknowledged and first.domain.results == ()
    assert first.domain.failures[0].retryable and receiver.inbox.pending()
    assert sender.outbox.get(original.message_id).state == OUTBOX_STATE_DELIVERED
    restarted = SourceReceiptAckReceiver(receiver.workspace, identity=source,
                                         spine=SignedEventLog(receiver.workspace / "spine.jsonl", source),
                                         clock=lambda: now + 120_000)
    restarted_runtime = PluginDeliveryRuntime(
        binding=binding, authority=_authority(source), route_resolver=loopback_route_id,
        outbox=sender.outbox, inbox=restarted.inbox, clock=lambda: now + 120_000,
    )
    recovered = receive_source_receipt_acks(runtime=restarted_runtime, receiver=restarted, receive_id="audit-repaired")
    assert not recovered.transport.found and recovered.domain.failures == ()
    assert recovered.domain.results[0].delivery.message_id == original.message_id
    assert restarted.inbox.pending() == [] and open_source_receipt_plugin_inbox(restarted).pending() == []


def test_provider_revocation_cannot_block_authorized_source_ack_recovery(tmp_path):
    _, _, original, returned, receiver, runtime, _, sender, host, binding, _ = _setup_pipeline(tmp_path)
    assert open_source_receipt_plugin_inbox(receiver).accept(returned).accepted
    assert host.disable(binding.plugin_id)
    recovered = receive_source_receipt_acks(runtime=runtime, receiver=receiver, receive_id="disabled-provider")
    assert recovered.transport_error is not None and not recovered.transport.transport_acknowledged
    assert recovered.domain.failures == () and recovered.domain.results[0].delivery.message_id == original.message_id
    assert sender.outbox.get(original.message_id).state == OUTBOX_STATE_DELIVERED


def test_lost_provider_lease_ack_keeps_valid_source_transition_visible(tmp_path, monkeypatch):
    _, _, original, returned, receiver, runtime, returner, sender, host, _, _ = _setup_pipeline(tmp_path)
    assert returner.submit(returned).accepted
    invoke = host.invoke

    def lose_ack(binding, request, *, authority):
        if request["operation"] == "ack":
            raise PluginInvocationError("lost return lease ACK")
        return invoke(binding, request, authority=authority)

    with monkeypatch.context() as patch:
        patch.setattr(host, "invoke", lose_ack)
        batch = receive_source_receipt_acks(runtime=runtime, receiver=receiver, receive_id="lost-lease-ack")
    assert batch.transport_error is not None and not batch.transport.transport_acknowledged
    assert batch.domain.results[0].delivery.message_id == original.message_id
    assert sender.outbox.get(original.message_id).state == OUTBOX_STATE_DELIVERED
    retry = receive_source_receipt_acks(runtime=runtime, receiver=receiver, receive_id="lost-lease-ack")
    assert retry.transport.transport_acknowledged and retry.transport.decisions[0].duplicate


def test_other_domain_messages_remain_staged_and_do_not_close_source_delivery(tmp_path):
    _, claimant, original, _, receiver, runtime, returner, sender, _host, _, now = _setup_pipeline(tmp_path)
    unrelated = sign_envelope(claimant, kind="chat.message", recipient=receiver.identity.as_did(),
                              payload={"text": "not an ACK"}, created_at_ms=now, expires_at_ms=now + 60_000)
    assert returner.submit(unrelated).accepted
    batch = receive_source_receipt_acks(runtime=runtime, receiver=receiver, receive_id="other-kind")
    assert batch.transport.transport_acknowledged and batch.domain.results == () and batch.domain.failures == ()
    assert open_source_receipt_plugin_inbox(receiver).pending()[0].message_id == unrelated.message_id
    assert sender.outbox.get(original.message_id).state == OUTBOX_STATE_QUEUED


def test_completed_return_history_does_not_saturate_staging_or_business_inbox(tmp_path, monkeypatch):
    monkeypatch.setattr("nth_dao.market.source_receipt_plugin.MAX_PLUGIN_INGRESS_ENTRIES", 2)
    monkeypatch.setattr("nth_dao.market.source_receipt_ack.MAX_SOURCE_RECEIPT_ACK_ENTRIES", 2)
    source, claimant, original, returned, receiver, runtime, returner, sender, _host, _binding, now = _setup_pipeline(tmp_path)
    ack = DeliveryAck.from_dict(returned.payload["ack"])
    packets = [sign_ack_envelope(claimant, ack, recipient=source.as_did(), nonce=f"{index:032x}",
                                 created_at_ms=now, expires_at_ms=now + 60_000) for index in range(5)]
    for index, packet in enumerate(packets):
        assert returner.submit(packet).accepted
        batch = receive_source_receipt_acks(runtime=runtime, receiver=receiver, receive_id=f"history-{index}")
        assert batch.transport.transport_acknowledged and batch.domain.failures == ()
        assert batch.domain.results[0].delivery.message_id == original.message_id
    staging = open_source_receipt_plugin_inbox(receiver)
    assert staging.entry_count() == receiver.inbox.entry_count() == 2
    assert staging.pending() == receiver.inbox.pending() == []
    replay = sign_ack_envelope(claimant, ack, recipient=source.as_did(), nonce=packets[0].nonce,
                               created_at_ms=now, expires_at_ms=now + 90_000)
    assert staging.accept(replay).replayed and receiver.inbox.accept(replay).replayed
    assert sender.outbox.get(original.message_id).state == OUTBOX_STATE_DELIVERED


def test_valid_foreign_domain_ack_is_left_for_its_handler_without_repeated_failures(tmp_path):
    source, claimant, original, _, receiver, runtime, returner, sender, _host, _, now = _setup_pipeline(tmp_path)
    chat = sign_envelope(source, kind="chat.message", recipient=claimant.as_did(), payload={"text": "hello"},
                         created_at_ms=now, expires_at_ms=now + 60_000)
    DurableOutbox(tmp_path / "source/chat-outbox", clock=lambda: now).enqueue(chat)
    ack = sign_ack(claimant, message_id=chat.message_id, envelope_sha256=envelope_digest(chat), received_at_ms=now)
    foreign = sign_ack_envelope(claimant, ack, recipient=source.as_did(),
                               created_at_ms=now, expires_at_ms=now + 60_000)
    assert returner.submit(foreign).accepted
    for index in range(2):
        batch = receive_source_receipt_acks(runtime=runtime, receiver=receiver, receive_id=f"foreign-{index}")
        assert batch.domain.results == batch.domain.failures == ()
    assert open_source_receipt_plugin_inbox(receiver).pending()[0].message_id == foreign.message_id
    assert receiver.inbox.pending() == []
    assert sender.outbox.get(original.message_id).state == OUTBOX_STATE_QUEUED


def test_invalid_inner_signature_is_not_hidden_as_a_foreign_ack(tmp_path):
    source, claimant, _, returned, receiver, runtime, returner, _, _host, _, now = _setup_pipeline(tmp_path)
    payload = json.loads(json.dumps(returned.payload))
    payload["ack"]["signature"] = ""
    hostile = sign_envelope(claimant, kind="delivery.ack", recipient=source.as_did(), payload=payload,
                            created_at_ms=now, expires_at_ms=now + 60_000)
    assert returner.submit(hostile).accepted
    batch = receive_source_receipt_acks(runtime=runtime, receiver=receiver, receive_id="bad-inner")
    assert batch.domain.results == () and len(batch.domain.failures) == 1
    assert not batch.domain.failures[0].retryable


def test_concurrent_completed_staging_is_reverified_not_reported_as_missing(tmp_path, monkeypatch):
    _, _, original, returned, receiver, runtime, _, sender, _host, _, _ = _setup_pipeline(tmp_path)
    ingress = open_source_receipt_plugin_inbox(receiver)
    assert ingress.accept(returned).accepted
    def interleave(method):
        def read(self, message_id):
            if self._dir == ingress._dir:
                receiver.receive(returned)
                ingress.mark_processed(message_id)
            return method(self, message_id)
        return read
    monkeypatch.setattr(DeliveryInbox, "retained_pending", interleave(DeliveryInbox.retained_pending))
    monkeypatch.setattr(DeliveryInbox, "retained_entry", interleave(DeliveryInbox.retained_entry))
    batch = receive_source_receipt_acks(runtime=runtime, receiver=receiver, receive_id="concurrent-completed")
    assert batch.domain.failures == () and len(batch.domain.results) == 1
    assert batch.domain.results[0].delivery.message_id == original.message_id
    assert sender.outbox.get(original.message_id).state == OUTBOX_STATE_DELIVERED


def test_completed_staging_recovery_rechecks_source_authority(tmp_path, monkeypatch):
    _, _, _, returned, receiver, _, _, _, _host, _, _ = _setup_pipeline(tmp_path)
    ingress = open_source_receipt_plugin_inbox(receiver)
    assert ingress.accept(returned).accepted
    receiver.receive_retained(ingress, returned.message_id)
    ingress.mark_processed(returned.message_id)
    monkeypatch.setattr(receiver.spine, "find_unique_event", lambda *a, **k: None)
    with pytest.raises(SourceReceiptDeliveryRejected):
        receiver.receive_retained(ingress, returned.message_id)


@pytest.mark.parametrize("error,retryable", [(OSError, True), (DeliveryInboxCacheCorrupt, False)])
def test_completed_domain_result_is_separate_from_staging_marker_failure(tmp_path, monkeypatch, error, retryable):
    _, _, original, returned, receiver, runtime, _, sender, _host, _, _ = _setup_pipeline(tmp_path)
    ingress = open_source_receipt_plugin_inbox(receiver)
    assert ingress.accept(returned).accepted and receiver.inbox.accept(returned).accepted
    processed = DeliveryInbox.mark_processed
    def fail_marker(self, message_id):
        if self._dir == ingress._dir:
            raise error("injected staging marker failure")
        return processed(self, message_id)
    with monkeypatch.context() as patch:
        patch.setattr(DeliveryInbox, "mark_processed", fail_marker)
        batch = receive_source_receipt_acks(runtime=runtime, receiver=receiver, receive_id="marker-failed")
    assert len(batch.domain.results) == 1 and batch.domain.failures == ()
    assert batch.domain.results[0].message_id == returned.message_id
    assert len(batch.staging_failures) == 1 and batch.staging_failures[0].message_id == returned.message_id
    assert batch.staging_failures[0].retryable is retryable
    assert ingress.pending() and sender.outbox.get(original.message_id).state == OUTBOX_STATE_DELIVERED
    retry = receive_source_receipt_acks(runtime=runtime, receiver=receiver, receive_id="marker-repaired")
    assert retry.staging_failures == retry.domain.failures == ()
    assert retry.domain.results[0].message_id == returned.message_id and ingress.pending() == []


def test_linked_staging_archive_does_not_block_independent_source_recovery(tmp_path, monkeypatch):
    monkeypatch.setattr("nth_dao.market.source_receipt_plugin.MAX_PLUGIN_INGRESS_ENTRIES", 1)
    source, claimant, original, returned, receiver, runtime, returner, sender, _host, _, now = _setup_pipeline(tmp_path)
    ingress = open_source_receipt_plugin_inbox(receiver)
    assert ingress.accept(returned).accepted and receiver.inbox.accept(returned).accepted
    ingress.mark_processed(returned.message_id)
    extra = sign_envelope(claimant, kind="chat.message", recipient=source.as_did(), payload={"test": "eviction"},
                          created_at_ms=now, expires_at_ms=now + 60_000)
    assert ingress.accept(extra).accepted
    ingress.mark_processed(extra.message_id)
    try:
        os.link(ingress._archive._message_path(returned.message_id), tmp_path / "archive-alias.json")
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {type(exc).__name__}")
    assert returner.submit(returned).accepted
    batch = receive_source_receipt_acks(runtime=runtime, receiver=receiver, receive_id="linked-archive")
    assert not batch.transport.transport_acknowledged
    assert batch.transport_error.error_code == "intake-integrity-failed" and not batch.transport_error.retryable
    assert batch.domain.failures == () and batch.domain.results[0].delivery.message_id == original.message_id
    assert sender.outbox.get(original.message_id).state == OUTBOX_STATE_DELIVERED
