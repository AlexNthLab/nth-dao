"""Host authorization and durable domain boundaries for receipt transport."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest

pytest.importorskip("nacl")

from test_market_source_receipt_delivery import _delivery, _prepare_source, _resign

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.acknowledgement import sign_ack
from nth_dao.delivery.envelope import envelope_digest
from nth_dao.delivery.inbox import DeliveryInbox
from nth_dao.delivery.outbox import OUTBOX_STATE_DELIVERED, DurableOutbox
from nth_dao.delivery.plugin_runtime import (
    PluginDeliveryRuntime,
    PluginDeliveryRuntimeError,
)
from nth_dao.identity import AgentIdentity
from nth_dao.market.source_receipt_delivery import (
    SOURCE_RECEIPT_DELIVERY_ACKNOWLEDGED_EVENT,
    SOURCE_RECEIPT_DELIVERY_PREPARED_EVENT,
    SourceReceiptDeliveryDeferred,
    SourceReceiptDeliveryReceiver,
    SourceReceiptDeliveryRejected,
    source_receipt_preparation_payload,
)
from nth_dao.market.source_receipt_plugin import (
    SourceReceiptPluginSender,
    open_source_receipt_plugin_inbox,
    receive_source_receipt_deliveries,
)
from nth_dao.plugins.builtin.loopback_transport import (
    loopback_route_id,
    register_loopback_transport,
)
from nth_dao.plugins.host import (
    InvocationAuthority,
    PluginHost,
    PluginHostPolicy,
    PluginInvocationError,
)
from nth_dao.plugins.transport import TRANSPORT_CAPABILITY_ID
from nth_dao.spine.log import SignedEventLog


def _authority(identity, *recipients):
    return InvocationAuthority(
        principal=identity.as_did(), capability_ids=frozenset({TRANSPORT_CAPABILITY_ID}),
        resource_ids=frozenset(loopback_route_id(item) for item in recipients),
    )


def _setup(tmp_path, *, prepared=True, source_routes=True):
    source, claimant, _proof, _response, envelope, receiver, now = _delivery(tmp_path)
    if prepared:
        _prepare_source(tmp_path, source, envelope)
    host = PluginHost(policy=PluginHostPolicy(), workspace_root=tmp_path / "host")
    manifest = register_loopback_transport(host)
    host.authorize(manifest.plugin_id, set())
    binding = host.enable(manifest.plugin_id)[0]
    sender = SourceReceiptPluginSender(
        workspace=tmp_path / "source", identity=source,
        spine=SignedEventLog(tmp_path / "source/spine.jsonl", source),
        binding=binding,
        authority=_authority(source, claimant.as_did()) if source_routes else _authority(source),
        route_resolver=loopback_route_id, clock=lambda: now,
    )
    runtime = PluginDeliveryRuntime(
        binding=binding, authority=_authority(claimant, source.as_did()),
        route_resolver=loopback_route_id,
        outbox=DurableOutbox(tmp_path / "claimant/return-outbox", clock=lambda: now),
        inbox=receiver.inbox, clock=lambda: now,
    )
    return source, claimant, envelope, receiver, now, host, binding, sender, runtime


def test_two_workspace_governed_receipt_delivery_and_signed_ack(tmp_path: Path) -> None:
    source, claimant, envelope, receiver, _now, _host, _binding, sender, runtime = _setup(tmp_path)
    assert sender.submit(envelope).accepted
    batch = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="receipt-1")
    assert batch.transport.transport_acknowledged
    assert batch.domain.failures == ()
    result = batch.domain.results[0]
    assert result.observation["receipt_verified"] is True
    assert result.observation["accepted"] is False
    assert result.observation["settled"] is False
    assert sender.outbox.get(envelope.message_id).state != OUTBOX_STATE_DELIVERED
    delivered = sender.acknowledge(result.ack)
    assert delivered.state == OUTBOX_STATE_DELIVERED
    assert delivered.delivered_by == claimant.as_did()
    assert receiver.inbox.pending() == []
    assert sender.outbox.compact() == 1
    source_spine = SignedEventLog(tmp_path / "source/spine.jsonl", source)
    audit = source_spine.find_unique_event(SOURCE_RECEIPT_DELIVERY_ACKNOWLEDGED_EVENT,
                                         payload_field="message_id", payload_value=envelope.message_id)
    assert audit.payload["verification_scope"] == "transport_receipt_only"
    assert not audit.payload["accepted"] and not audit.payload["settled"]
    assert source_spine.verify_chain()[0]
    assert receiver.spine.verify_chain()[0]


@pytest.mark.parametrize("prepared,wrong_kind", [(False, False), (True, True)])
def test_sender_requires_prepared_receipt_before_provider_disclosure(
    tmp_path: Path, monkeypatch, prepared, wrong_kind,
) -> None:
    source, _, envelope, _, _, host, _, sender, _ = _setup(tmp_path, prepared=prepared)
    if wrong_kind:
        envelope = _resign(source, envelope, kind="chat.message")

    def unexpected(*args, **kwargs):
        pytest.fail("unprepared or wrong-domain receipt reached provider")

    monkeypatch.setattr(host, "invoke", unexpected)
    with pytest.raises(SourceReceiptDeliveryRejected):
        sender.submit(envelope)
    assert sender.outbox.stats()["total"] == 0


@pytest.mark.parametrize("reason", ["scope", "disabled"])
def test_sender_obeys_host_route_scope_and_binding_revocation(tmp_path: Path, reason) -> None:
    _, _, envelope, _, _, host, binding, sender, _ = _setup(tmp_path, source_routes=reason != "scope")
    if reason == "disabled":
        assert host.disable(binding.plugin_id)
    with pytest.raises(PluginDeliveryRuntimeError):
        sender.submit(envelope)
    record = sender.outbox.get(envelope.message_id)
    assert record.state != OUTBOX_STATE_DELIVERED
    assert record.attempts[-1].error_code == "plugin-invocation-failed"


def test_source_principal_mismatch_is_rejected_before_storage_creation(tmp_path: Path) -> None:
    source, claimant, _envelope, _receiver, now, _host, binding, _sender, _runtime = _setup(tmp_path)
    workspace = tmp_path / "unrelated"
    with pytest.raises(SourceReceiptDeliveryRejected, match="principal"):
        SourceReceiptPluginSender(
            workspace=workspace, identity=source,
            spine=SignedEventLog(tmp_path / "source/spine.jsonl", source),
            binding=binding, authority=_authority(claimant), route_resolver=loopback_route_id,
            clock=lambda: now,
        )
    assert not workspace.exists()


@pytest.mark.parametrize("mismatch", ["principal", "inbox"])
def test_receive_cannot_substitute_principal_or_durable_inbox(tmp_path: Path, monkeypatch, mismatch) -> None:
    source, claimant, _, receiver, now, host, binding, _, _ = _setup(tmp_path)
    runtime = PluginDeliveryRuntime(
        binding=binding, authority=_authority(source if mismatch == "principal" else claimant),
        route_resolver=loopback_route_id, outbox=DurableOutbox(tmp_path / "bad-outbox"),
        inbox=receiver.inbox if mismatch == "principal" else DeliveryInbox(tmp_path / "bad-inbox"),
        clock=lambda: now,
    )

    def unexpected(*args, **kwargs):
        pytest.fail("mismatched receiver reached provider")

    monkeypatch.setattr(host, "invoke", unexpected)
    with pytest.raises(SourceReceiptDeliveryRejected):
        receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="bad-receiver")


def test_provider_ack_failure_retains_intake_for_retry(tmp_path: Path, monkeypatch) -> None:
    _, _, envelope, receiver, _, host, _, sender, runtime = _setup(tmp_path)
    assert sender.submit(envelope).accepted
    invoke = host.invoke

    def fail_ack(binding_arg, payload, *, authority):
        if payload.get("operation") == "ack":
            raise PluginInvocationError("injected provider ACK failure")
        return invoke(binding_arg, payload, authority=authority)

    with monkeypatch.context() as patch:
        patch.setattr(host, "invoke", fail_ack)
        partial = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="provider-retry")
    assert partial.transport_error is not None
    assert partial.transport.found and not partial.transport.transport_acknowledged
    assert partial.transport.decisions[0].accepted
    assert len(partial.domain.results) == 1
    assert receiver.inbox.pending() == []
    retried = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="provider-retry")
    assert retried.transport.replayed
    assert retried.transport.decisions[0].duplicate
    assert len(retried.domain.results) == 1
    assert sender.acknowledge(retried.domain.results[0].ack).state == OUTBOX_STATE_DELIVERED
    assert retried.domain.results[0].ack.to_dict() == partial.domain.results[0].ack.to_dict()


def test_duplicate_provider_batch_recovers_exact_preexisting_ack(tmp_path: Path) -> None:
    _source, _claimant, envelope, receiver, _now, _host, _binding, sender, runtime = _setup(tmp_path)
    assert sender.submit(envelope).accepted
    first = receiver.receive(envelope)
    batch = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="preexisting-ack")
    assert batch.transport.decisions[0].accepted
    assert batch.domain.results[0].ack.to_dict() == first.ack.to_dict()
    assert batch.domain.results[0].observation["local_observation_event_id"] == first.observation["local_observation_event_id"]


def test_domain_audit_failure_is_not_reported_as_signed_ack(tmp_path: Path, monkeypatch) -> None:
    _source, _claimant, envelope, receiver, _now, _host, _binding, sender, runtime = _setup(tmp_path)
    assert sender.submit(envelope).accepted
    append = SignedEventLog.append_unique

    def fail(*args, **kwargs):
        raise OSError("injected domain audit failure")

    with monkeypatch.context() as patch:
        patch.setattr(SignedEventLog, "append_unique", fail)
        failed = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="domain-failure")
    assert failed.transport.transport_acknowledged
    assert failed.domain.results == ()
    assert failed.domain.failures[0].message_id == envelope.message_id
    assert receiver.inbox.pending()[0].message_id == envelope.message_id
    assert sender.outbox.get(envelope.message_id).state != OUTBOX_STATE_DELIVERED
    assert SignedEventLog.append_unique is append
    recovered = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="empty-recovery")
    assert not recovered.transport.found
    assert len(recovered.domain.results) == 1
    assert sender.acknowledge(recovered.domain.results[0].ack).state == OUTBOX_STATE_DELIVERED


def test_plugin_intake_cannot_evict_processed_receipt_nonce_history(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("nth_dao.market.source_receipt_delivery._MAX_DELIVERIES_PER_CLAIM", 2)
    source, _claimant, original, receiver, _now, _host, _binding, sender, runtime = _setup(tmp_path)
    for index in range(2):
        envelope = _resign(source, original, nonce=f"retainednonce{index:04d}")
        _prepare_source(tmp_path, source, envelope)
        assert sender.submit(envelope).accepted
        result = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver,
                                                 receive_id=f"retained-{index}")
        assert len(result.domain.results) == 1
    third = _resign(source, original, nonce="newdeliverynonce0003")
    _prepare_source(tmp_path, source, third)
    assert sender.submit(third).accepted
    rejected = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="capacity")
    assert rejected.transport.decisions[0].accepted
    assert rejected.domain.failures[0].reason == "source receipt delivery inbox is at capacity"
    assert rejected.domain.results == ()
    assert receiver.inbox.entry_count() == 2
    assert not receiver.inbox.seen(third.message_id)
    assert open_source_receipt_plugin_inbox(receiver).pending()[0].message_id == third.message_id
    assert rejected.domain.failures[0].retryable


def test_two_claims_for_same_did_are_retained_and_dispatched_separately(tmp_path, monkeypatch):
    source, claimant, first, receiver, _now, _host, binding, sender, runtime = _setup(tmp_path)
    generate = AgentIdentity.generate

    def same_identity(**kwargs):
        if kwargs.get("label") == "claimant":
            return claimant
        if kwargs.get("label") == "source":
            return source
        return generate(**kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(AgentIdentity, "generate", same_identity)
        _, _, _, _, second, second_receiver, now2 = _delivery(tmp_path)
    _prepare_source(tmp_path, source, second)
    assert sender.submit(first).accepted
    assert sender.submit(second).accepted
    batch = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="claim-a")
    assert batch.transport.transport_acknowledged
    assert len(batch.domain.results) == 1 and batch.domain.failures == ()
    assert second_receiver.inbox.entry_count() == 0
    assert [item.message_id for item in open_source_receipt_plugin_inbox(receiver).pending()] == [second.message_id]
    second_runtime = PluginDeliveryRuntime(
        binding=binding, authority=_authority(claimant), route_resolver=loopback_route_id,
        outbox=DurableOutbox(tmp_path / "return2"), inbox=second_receiver.inbox, clock=lambda: now2,
    )
    recovered = receive_source_receipt_deliveries(
        runtime=second_runtime, receiver=second_receiver, receive_id="claim-b",
    )
    assert not recovered.transport.found
    assert [item.ack.message_id for item in recovered.domain.results] == [second.message_id]
    assert sender.acknowledge(recovered.domain.results[0].ack).state == OUTBOX_STATE_DELIVERED
    assert open_source_receipt_plugin_inbox(second_receiver).pending() == []


@pytest.mark.parametrize("dao_id,hop_limit", [(None, 0), ("group-a", 2)])
def test_unhandled_kind_is_retained_without_business_ack(tmp_path, dao_id, hop_limit):
    source, claimant, _, receiver, now, _host, binding, _, runtime = _setup(tmp_path)
    from nth_dao.delivery.envelope import sign_envelope
    from nth_dao.plugins.transport import transport_envelope_digest

    envelope = sign_envelope(
        source, kind="chat.message", recipient=claimant.as_did(), payload={"body": "retained"},
        created_at_ms=now, expires_at_ms=now + 60_000,
        dao_id=dao_id, hop_limit=hop_limit,
    )
    raw = canonical_json(envelope.to_dict()).decode("utf-8")
    binding.invoke({
        "operation": "send", "delivery_id": envelope.message_id,
        "destination_route_id": loopback_route_id(claimant.as_did()),
        "envelope_json": raw, "envelope_sha256": transport_envelope_digest(raw),
        "expires_at_ms": envelope.expires_at_ms,
    }, authority=_authority(source, claimant.as_did()))
    batch = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="other-kind")
    assert batch.transport.transport_acknowledged
    assert batch.domain.results == () and batch.domain.failures == ()
    assert receiver.inbox.entry_count() == 0
    assert open_source_receipt_plugin_inbox(receiver).pending()[0].message_id == envelope.message_id


def test_shared_ingress_full_is_retryable_not_provider_acknowledged(tmp_path, monkeypatch):
    monkeypatch.setattr("nth_dao.market.source_receipt_plugin.MAX_PLUGIN_INGRESS_ENTRIES", 1)
    source, _, first, receiver, _, _host, _, sender, runtime = _setup(tmp_path)
    assert sender.submit(first).accepted
    receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="fill-ingress")
    second = _resign(source, first, nonce="secondaftercapacity0001")
    _prepare_source(tmp_path, source, second)
    assert sender.submit(second).accepted
    full = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="full-ingress")
    assert full.transport.decisions[0].retryable
    assert not full.transport.transport_acknowledged
    monkeypatch.setattr("nth_dao.market.source_receipt_plugin.MAX_PLUGIN_INGRESS_ENTRIES", 2)
    retry = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="full-ingress")
    assert retry.transport.replayed and retry.transport.transport_acknowledged
    assert retry.domain.results[0].ack.message_id == second.message_id


def test_missing_local_head_remains_durable_and_resumes_after_expiry(tmp_path, monkeypatch):
    _source, claimant, envelope, receiver, now, _host, binding, sender, runtime = _setup(tmp_path)
    assert sender.submit(envelope).accepted
    with monkeypatch.context() as patch:
        patch.setattr("nth_dao.market.source_receipt_delivery.build_portable_completion_proof_with_pins",
                      lambda *args, **kwargs: None)
        failed = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="no-head")
    assert failed.transport.transport_acknowledged
    assert failed.domain.results == ()
    assert failed.domain.failures[0].error_code == SourceReceiptDeliveryDeferred.__name__
    assert failed.domain.failures[0].retryable
    assert receiver.inbox.entry_count() == 0
    assert len(open_source_receipt_plugin_inbox(receiver).pending()) == 1
    restarted = SourceReceiptDeliveryReceiver(
        receiver.workspace, nonce=receiver.nonce, identity=claimant,
        spine=SignedEventLog(receiver.workspace / "spine.jsonl", claimant), clock=lambda: now + 120_000,
    )
    restarted_runtime = PluginDeliveryRuntime(
        binding=binding, authority=_authority(claimant), route_resolver=loopback_route_id,
        outbox=DurableOutbox(tmp_path / "return-outbox"), inbox=restarted.inbox, clock=lambda: now + 120_000,
    )
    recovered = receive_source_receipt_deliveries(runtime=restarted_runtime, receiver=restarted, receive_id="head-ready")
    assert len(recovered.domain.results) == 1 and recovered.domain.failures == ()
    assert recovered.domain.results[0].ack.received_at_ms == now
    assert sender.acknowledge(recovered.domain.results[0].ack).state == OUTBOX_STATE_DELIVERED
    assert open_source_receipt_plugin_inbox(restarted).pending() == []


@pytest.mark.parametrize("mutation", ["proof", "sender", "recipient", "unsigned", "expired"])
def test_ingress_does_not_turn_staging_into_business_authority(tmp_path, mutation):
    source, _claimant, envelope, receiver, now, _host, _binding, sender, _runtime = _setup(tmp_path)
    stranger = AgentIdentity.generate(label="stranger")
    if mutation == "proof":
        payload = dict(envelope.payload, proof_digest="sha256:" + "0" * 64)
        forged = _resign(source, envelope, payload=payload)
    elif mutation == "sender":
        forged = _resign(stranger, envelope)
    elif mutation == "recipient":
        forged = _resign(source, envelope, recipient=stranger.as_did())
    elif mutation == "expired":
        forged = _resign(source, envelope, created_at_ms=now - 60_001, expires_at_ms=now - 1)
    else:
        forged = _resign(source, envelope)
        forged.signature = ""
    ingress = open_source_receipt_plugin_inbox(receiver)
    decision = ingress.accept(forged)
    if mutation in ("proof", "sender"):
        assert decision.accepted
        with pytest.raises(SourceReceiptDeliveryRejected):
            receiver.receive_retained(ingress, forged.message_id)
    else:
        assert not decision.accepted
    assert receiver.inbox.entry_count() == 0
    assert sender.outbox.stats()["total"] == 0


@pytest.mark.parametrize("provider_fails", [False, True])
def test_signed_ack_wins_two_thread_send_completion_race(tmp_path, monkeypatch, provider_fails):
    _, _, envelope, receiver, _, host, _, sender, _ = _setup(tmp_path)
    invoke = host.invoke
    send_queued, ack_committed = Event(), Event()

    def delay_send(binding, payload, *, authority):
        response = invoke(binding, payload, authority=authority)
        if payload.get("operation") == "send":
            send_queued.set()
            assert ack_committed.wait(10)
            if provider_fails:
                raise PluginInvocationError("late provider failure after delivery")
        return response

    def receive_and_ack():
        assert send_queued.wait(10)
        result = receiver.receive(envelope)
        delivered = sender.acknowledge(result.ack)
        ack_committed.set()
        return delivered

    monkeypatch.setattr(host, "invoke", delay_send)
    with ThreadPoolExecutor(max_workers=2) as pool:
        send = pool.submit(sender.submit, envelope)
        ack = pool.submit(receive_and_ack)
        assert ack.result(timeout=15).state == OUTBOX_STATE_DELIVERED
        assert send.result(timeout=15).accepted
    record = sender.outbox.get(envelope.message_id)
    assert record.state == OUTBOX_STATE_DELIVERED
    assert len(record.attempts) == 1
    assert record.attempts[0].outcome == ("error" if provider_fails else "sent")
    assert record.attempts[0].attempt_id
    assert sender.outbox.compact() == 1
    assert sender.outbox.get(envelope.message_id).state == OUTBOX_STATE_DELIVERED


@pytest.mark.parametrize("limit", ["attempts", "journal"])
def test_capacity_exhaustion_blocks_provider_before_side_effect(tmp_path, monkeypatch, limit):
    from nth_dao.delivery import outbox as outbox_module

    _, _, envelope, _, now, host, binding, sender, _ = _setup(tmp_path)
    sender.outbox.enqueue(envelope, now_ms=now)
    if limit == "attempts":
        for _ in range(outbox_module.MAX_ATTEMPTS_PER_RECORD):
            sender.outbox.record_attempt(
                envelope.message_id, transport=binding.plugin_id, outcome="error", at_ms=now,
            )
        expected_attempts = 256
    else:
        journal = tmp_path / "source/.nth/source_receipt_delivery_outbox/outbox.journal.jsonl"
        monkeypatch.setattr(outbox_module, "MAX_JOURNAL_BYTES", journal.stat().st_size + 500)
        expected_attempts = 0

    def forbidden(*args, **kwargs):
        pytest.fail("capacity exhaustion must prevent external provider invocation")

    monkeypatch.setattr(host, "invoke", forbidden)
    result = sender.submit(envelope)
    assert not result.accepted and result.error_code == "outbox-attempt-capacity"
    assert len(sender.outbox.get(envelope.message_id).attempts) == expected_attempts


def test_crashed_send_start_is_visible_and_retry_preserves_message_id(tmp_path, monkeypatch):
    from nth_dao.delivery.outbox import OUTBOX_ATTEMPT_STARTED

    source, claimant, envelope, _receiver, now, host, binding, sender, _runtime = _setup(tmp_path)
    invoke = host.invoke

    def crash(*args, **kwargs):
        raise KeyboardInterrupt("simulated process interruption before provider send")

    with monkeypatch.context() as patch:
        patch.setattr(host, "invoke", crash)
        with pytest.raises(KeyboardInterrupt):
            sender.submit(envelope)
    restarted = SourceReceiptPluginSender(
        workspace=tmp_path / "source", identity=source,
        spine=SignedEventLog(tmp_path / "source/spine.jsonl", source), binding=binding,
        authority=_authority(source, claimant.as_did()), route_resolver=loopback_route_id, clock=lambda: now,
    )
    first = restarted.outbox.get(envelope.message_id).attempts[0]
    assert first.outcome == OUTBOX_ATTEMPT_STARTED
    assert restarted.submit(envelope).accepted
    record = restarted.outbox.get(envelope.message_id)
    assert [item.outcome for item in record.attempts] == ["started", "sent"]
    assert len({item.attempt_id for item in record.attempts}) == 2
    assert record.message_id == envelope.message_id
    assert host.invoke == invoke


@pytest.mark.parametrize("pending_location", ["domain", "ingress"])
def test_provider_revocation_does_not_block_verified_local_recovery(tmp_path, pending_location):
    _, _, envelope, receiver, _, host, binding, sender, runtime = _setup(tmp_path)
    inbox = receiver.inbox if pending_location == "domain" else open_source_receipt_plugin_inbox(receiver)
    assert inbox.accept(envelope).accepted
    assert host.disable(binding.plugin_id)
    recovered = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="offline-resume")
    assert recovered.transport_error is not None
    assert "not active" in recovered.transport_error.reason or "disabled" in recovered.transport_error.reason
    assert not recovered.transport.transport_acknowledged
    assert len(recovered.domain.results) == 1 and recovered.domain.failures == ()
    assert receiver.inbox.pending() == []
    assert open_source_receipt_plugin_inbox(receiver).pending() == []
    assert sender.outbox.stats()["total"] == 0


def test_provider_failure_and_domain_failure_are_both_visible(tmp_path, monkeypatch):
    _, _, envelope, receiver, _, host, binding, _, runtime = _setup(tmp_path)
    assert open_source_receipt_plugin_inbox(receiver).accept(envelope).accepted
    assert host.disable(binding.plugin_id)

    def storage_failure(*args, **kwargs):
        raise OSError("injected local audit failure")

    monkeypatch.setattr(SignedEventLog, "append_unique", storage_failure)
    failed = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="both-fail")
    assert failed.transport_error is not None
    assert failed.domain.results == ()
    assert failed.domain.failures[0].retryable
    assert len(open_source_receipt_plugin_inbox(receiver).pending()) == 1


@pytest.mark.parametrize("failure", ["open", "write", "read"])
def test_ingress_io_failure_does_not_block_independent_domain_recovery(tmp_path, monkeypatch, failure):
    source, _, first, receiver, _, host, _, sender, runtime = _setup(tmp_path)
    assert receiver.inbox.accept(first).accepted
    second = _resign(source, first, nonce="independentstoragefailure0002")
    _prepare_source(tmp_path, source, second)
    assert sender.submit(second).accepted
    append, pending = DeliveryInbox._append_cache_locked, DeliveryInbox.pending

    def unavailable(*args, **kwargs):
        raise OSError("injected ingress storage unavailable")

    def write(self, event):
        if "plugin_delivery_ingress" in self._dir.parts:
            unavailable()
        return append(self, event)

    def read(self, **kwargs):
        if "plugin_delivery_ingress" in self._dir.parts:
            unavailable()
        return pending(self, **kwargs)

    with monkeypatch.context() as patch:
        if failure == "open":
            patch.setattr("nth_dao.market.source_receipt_plugin.open_source_receipt_plugin_inbox", unavailable)
        elif failure == "write":
            patch.setattr(DeliveryInbox, "_append_cache_locked", write)
        else:
            patch.setattr(DeliveryInbox, "pending", read)
        batch = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="io-recovery")
    assert batch.transport_error is not None and batch.transport_error.retryable
    assert [result.ack.message_id for result in batch.domain.results] == [first.message_id]
    assert receiver.inbox.pending() == []
    if failure == "write":
        assert not batch.transport.transport_acknowledged
        assert batch.transport.decisions[0].retryable
    retry = receive_source_receipt_deliveries(
        runtime=runtime, receiver=receiver, receive_id="io-recovery" if failure == "write" else "io-recovered",
    )
    assert second.message_id in {result.ack.message_id for result in retry.domain.results}
    host.disable(runtime._binding.plugin_id)


def test_transport_closed_claim_error_preserves_stable_code_and_retryability(tmp_path):
    _, _, envelope, receiver, _, _host, _, sender, runtime = _setup(tmp_path)
    assert sender.submit(envelope).accepted
    receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="closed")
    repeated = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="closed")
    assert repeated.transport_error.error_code == "claim-closed"
    assert repeated.transport_error.retryable is False


@pytest.mark.parametrize("failure", ["open", "read"])
def test_ingress_integrity_failure_does_not_block_independent_domain_recovery(tmp_path, monkeypatch, failure):
    from nth_dao.delivery.inbox import DeliveryInboxCacheCorrupt

    _, _, envelope, receiver, _, _host, _, _, runtime = _setup(tmp_path)
    assert receiver.inbox.accept(envelope).accepted
    pending = DeliveryInbox.pending

    def corrupt(*args, **kwargs):
        raise DeliveryInboxCacheCorrupt("injected ingress corruption")

    def read(self, **kwargs):
        if "plugin_delivery_ingress" in self._dir.parts:
            corrupt()
        return pending(self, **kwargs)

    with monkeypatch.context() as patch:
        if failure == "open":
            patch.setattr("nth_dao.market.source_receipt_plugin.open_source_receipt_plugin_inbox", corrupt)
        else:
            patch.setattr(DeliveryInbox, "pending", read)
        batch = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="corrupt-ingress")
    assert batch.transport_error.error_code == "ingress-integrity-failed"
    assert batch.transport_error.retryable is False
    assert [result.ack.message_id for result in batch.domain.results] == [envelope.message_id]
    assert batch.domain.failures == () and receiver.inbox.pending() == []


def test_lost_provider_ack_reexports_exact_signed_ack_after_intake_expiry(tmp_path, monkeypatch):
    _source, _claimant, envelope, receiver, now, host, _, sender, runtime = _setup(tmp_path)
    assert sender.submit(envelope).accepted
    invoke = host.invoke

    def fail_ack(binding, payload, *, authority):
        if payload.get("operation") == "ack":
            raise PluginInvocationError("lost transport ACK")
        return invoke(binding, payload, authority=authority)

    with monkeypatch.context() as patch:
        patch.setattr(host, "invoke", fail_ack)
        first = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="lost-ack")
    assert first.transport_error is not None
    ack = first.domain.results[0].ack
    monkeypatch.setattr(runtime, "_clock", lambda: now + 120_000)
    monkeypatch.setattr(receiver, "_clock", lambda: now + 120_000)
    recovered = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="lost-ack")
    assert recovered.transport.decisions[0].duplicate
    assert recovered.domain.results[0].ack.to_dict() == ack.to_dict()
    assert sender.acknowledge(ack).state == OUTBOX_STATE_DELIVERED


@pytest.mark.parametrize("marker", ["source_receipt_deliveries", "plugin_delivery_ingress"])
def test_crash_before_ack_return_recovers_from_durable_export_worklist(tmp_path, monkeypatch, marker):
    _, claimant, envelope, receiver, now, _host, binding, sender, runtime = _setup(tmp_path)
    assert sender.submit(envelope).accepted
    processed = DeliveryInbox.mark_processed

    def crash_after_durable_marker(self, message_id):
        result = processed(self, message_id)
        if marker in self._dir.parts:
            raise KeyboardInterrupt("crash after durable marker before returning ACK")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(DeliveryInbox, "mark_processed", crash_after_durable_marker)
        with pytest.raises(KeyboardInterrupt):
            receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="before-return")
    original = receiver.get_ack(envelope.message_id)
    restarted = SourceReceiptDeliveryReceiver(
        receiver.workspace, nonce=receiver.nonce, identity=claimant,
        spine=SignedEventLog(receiver.workspace / "spine.jsonl", claimant), clock=lambda: now,
    )
    restarted_runtime = PluginDeliveryRuntime(
        binding=binding, authority=_authority(claimant), route_resolver=loopback_route_id,
        outbox=DurableOutbox(tmp_path / "restarted-return-outbox"), inbox=restarted.inbox, clock=lambda: now,
    )
    recovered = receive_source_receipt_deliveries(
        runtime=restarted_runtime, receiver=restarted, receive_id="recover-export",
    )
    assert not recovered.transport.found
    assert len(recovered.ack_exports.results) == 1 and recovered.ack_exports.failures == ()
    exported = recovered.ack_exports.results[0]
    assert exported.ack.to_dict() == original.ack.to_dict()
    assert exported.observation["local_observation_event_id"] == original.observation["local_observation_event_id"]
    assert sender.acknowledge(exported.ack).state == OUTBOX_STATE_DELIVERED
    assert len(restarted.export_retained_acks().results) == 1


def test_ack_export_survives_provider_and_all_node_clocks_expiring(tmp_path, monkeypatch):
    from nth_dao.plugins.builtin.loopback_transport import LoopbackTransportProvider

    _, _, envelope, receiver, now, host, _, sender, runtime = _setup(tmp_path)
    assert sender.submit(envelope).accepted
    invoke = host.invoke

    def lose_provider_ack(binding, payload, *, authority):
        if payload["operation"] == "ack":
            raise PluginInvocationError("lost provider ACK")
        return invoke(binding, payload, authority=authority)

    with monkeypatch.context() as patch:
        patch.setattr(host, "invoke", lose_provider_ack)
        first = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="first-export")
    original = first.domain.results[0].ack
    future = now + 120_000
    monkeypatch.setattr(runtime, "_clock", lambda: future)
    monkeypatch.setattr(receiver, "_clock", lambda: future)
    monkeypatch.setattr(sender, "_clock", lambda: future)
    monkeypatch.setattr(LoopbackTransportProvider, "_now_ms", lambda self: future)
    recovered = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="expired-provider")
    assert not recovered.transport.found and recovered.domain.results == ()
    assert recovered.ack_exports.results[0].ack.to_dict() == original.to_dict()
    assert sender.acknowledge(recovered.ack_exports.results[0].ack).state == OUTBOX_STATE_DELIVERED


def test_ack_export_index_io_failure_does_not_hide_new_domain_result(tmp_path, monkeypatch):
    _, _, envelope, receiver, _, _host, _, sender, runtime = _setup(tmp_path)
    assert sender.submit(envelope).accepted

    def unavailable(*args, **kwargs):
        raise OSError("injected ACK export index failure")

    with monkeypatch.context() as patch:
        patch.setattr(DeliveryInbox, "processed_message_ids", unavailable)
        batch = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="export-index-io")
    assert batch.transport.transport_acknowledged and batch.transport_error is None
    assert [result.ack.message_id for result in batch.domain.results] == [envelope.message_id]
    assert batch.ack_exports.results == ()
    assert batch.ack_exports.failures[0].message_id == "" and batch.ack_exports.failures[0].retryable
    assert receiver.export_retained_acks().results[0].ack.to_dict() == batch.domain.results[0].ack.to_dict()


def test_sender_rejects_wrong_receiver_ack_and_retries_source_audit(tmp_path: Path, monkeypatch) -> None:
    _source, _claimant, envelope, receiver, now, _host, _binding, sender, runtime = _setup(tmp_path)
    assert sender.submit(envelope).accepted
    batch = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="signed-ack")
    ack = batch.domain.results[0].ack
    stranger = AgentIdentity.generate(label="stranger")
    wrong = sign_ack(stranger, message_id=envelope.message_id,
                     envelope_sha256=envelope_digest(envelope), received_at_ms=now)
    with pytest.raises(RuntimeError, match="receiver"):
        sender.acknowledge(wrong)
    assert sender.outbox.get(envelope.message_id).state != OUTBOX_STATE_DELIVERED

    def fail(*args, **kwargs):
        raise OSError("injected source ACK audit failure")

    with monkeypatch.context() as patch:
        patch.setattr(SignedEventLog, "append_unique", fail)
        with pytest.raises(OSError, match="source ACK audit"):
            sender.acknowledge(ack)
    assert sender.outbox.get(envelope.message_id).state == OUTBOX_STATE_DELIVERED
    assert sender.acknowledge(ack).state == OUTBOX_STATE_DELIVERED
    assert canonical_json(receiver.get_ack(envelope.message_id).ack.to_dict()) == canonical_json(ack.to_dict())


def test_validly_signed_preparation_by_another_author_is_not_authority(tmp_path: Path, monkeypatch) -> None:
    _source, _claimant, envelope, _receiver, _now, host, _binding, sender, _runtime = _setup(
        tmp_path, prepared=False,
    )
    stranger = AgentIdentity.generate(label="stranger")
    SignedEventLog(tmp_path / "source/spine.jsonl", stranger).append_unique(
        SOURCE_RECEIPT_DELIVERY_PREPARED_EVENT,
        source_receipt_preparation_payload(envelope), unique_payload_fields=("message_id",),
    )

    def unexpected(*args, **kwargs):
        pytest.fail("another author's preparation authorized disclosure")

    monkeypatch.setattr(host, "invoke", unexpected)
    with pytest.raises(SourceReceiptDeliveryRejected, match="audited preparation"):
        sender.submit(envelope)
    assert sender.outbox.stats()["total"] == 0


def test_sender_and_receiver_restart_share_the_same_durable_evidence(tmp_path: Path) -> None:
    source, claimant, envelope, receiver, now, _host, binding, sender, _runtime = _setup(tmp_path)
    assert sender.submit(envelope).accepted
    restarted_sender = SourceReceiptPluginSender(
        workspace=tmp_path / "source", identity=source,
        spine=SignedEventLog(tmp_path / "source/spine.jsonl", source), binding=binding,
        authority=_authority(source, claimant.as_did()), route_resolver=loopback_route_id,
        clock=lambda: now,
    )
    assert restarted_sender.submit(envelope).accepted
    restarted_receiver = SourceReceiptDeliveryReceiver(
        receiver.workspace, nonce=receiver.nonce, identity=claimant,
        spine=SignedEventLog(receiver.workspace / "spine.jsonl", claimant), clock=lambda: now,
    )
    restarted_runtime = PluginDeliveryRuntime(
        binding=binding, authority=_authority(claimant), route_resolver=loopback_route_id,
        outbox=DurableOutbox(tmp_path / "claimant/return-outbox"),
        inbox=restarted_receiver.inbox, clock=lambda: now,
    )
    batch = receive_source_receipt_deliveries(runtime=restarted_runtime, receiver=restarted_receiver,
                                            receive_id="after-restart")
    assert len(batch.domain.results) == 1
    ack = batch.domain.results[0].ack
    assert restarted_sender.acknowledge(ack).state == OUTBOX_STATE_DELIVERED
    assert sender.outbox.get(envelope.message_id).state == OUTBOX_STATE_DELIVERED
    assert receiver.get_ack(envelope.message_id).ack.to_dict() == ack.to_dict()
    assert sender.outbox.stats()["total"] == 1


def test_partial_domain_failure_does_not_hide_successful_ack(tmp_path: Path, monkeypatch) -> None:
    source, _claimant, first, receiver, _now, _host, _binding, sender, runtime = _setup(tmp_path)
    second = _resign(source, first, nonce="independentreceipt0002")
    _prepare_source(tmp_path, source, second)
    assert sender.submit(first).accepted
    assert sender.submit(second).accepted
    process = receiver._process

    def fail_first(envelope):
        if envelope.message_id == first.message_id:
            raise OSError("injected first-item failure")
        return process(envelope)

    with monkeypatch.context() as patch:
        patch.setattr(receiver, "_process", fail_first)
        batch = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="partial")
    assert batch.transport.transport_acknowledged
    assert [item.message_id for item in batch.domain.failures] == [first.message_id]
    assert [item.ack.message_id for item in batch.domain.results] == [second.message_id]
    assert sender.acknowledge(batch.domain.results[0].ack).state == OUTBOX_STATE_DELIVERED
    recovered = receive_source_receipt_deliveries(runtime=runtime, receiver=receiver, receive_id="partial-recovery")
    assert not recovered.transport.found
    assert [item.ack.message_id for item in recovered.domain.results] == [first.message_id]
    assert sender.acknowledge(recovered.domain.results[0].ack).state == OUTBOX_STATE_DELIVERED
