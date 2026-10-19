"""Durable return preparation is evidence-bound, exact and explicitly governed."""

from __future__ import annotations

import json
import multiprocessing
import os
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path

import pytest

pytest.importorskip("nacl")

from test_market_source_receipt_delivery import _delivery, _resign
from test_market_source_receipt_plugin import _authority, _setup

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.acknowledgement import ack_from_envelope
from nth_dao.delivery.outbox import (
    OUTBOX_ATTEMPT_REJECTED,
    OUTBOX_STATE_QUEUED,
    DeliveryOutboxCorrupt,
    DurableOutbox,
)
from nth_dao.delivery.plugin_runtime import (
    PluginDeliveryRuntime,
    PluginDeliveryRuntimeError,
)
from nth_dao.identity import AgentIdentity
from nth_dao.market.source_receipt_ack import SourceReceiptAckReceiver
from nth_dao.market.source_receipt_ack_return import (
    SOURCE_RECEIPT_ACK_RETURN_COMMITTED_EVENT,
    SOURCE_RECEIPT_ACK_RETURN_PREPARED_EVENT,
    SourceReceiptAckReturnStore,
)
from nth_dao.market.source_receipt_delivery import (
    SOURCE_RECEIPT_DELIVERY_ACKNOWLEDGED_EVENT,
    SourceReceiptDeliveryDeferred,
    SourceReceiptDeliveryReceiver,
    SourceReceiptDeliveryRejected,
    source_receipt_delivery_failure,
)
from nth_dao.market.source_receipt_plugin import (
    SourceReceiptAckPluginSender,
    receive_source_receipt_acks,
    receive_source_receipt_deliveries,
)
from nth_dao.plugins.builtin.loopback_transport import loopback_route_id
from nth_dao.spine.log import SignedEventLog


def _retained(tmp_path):
    source, claimant, proof, _, original, receiver, now = _delivery(tmp_path)
    result = receiver.receive(original)
    return source, claimant, proof, original, receiver, result, now


def _prepare_in_process(args):
    workspace, claimant, nonce, message_id, now = args
    receiver = SourceReceiptDeliveryReceiver(
        workspace, nonce=nonce, identity=claimant,
        spine=SignedEventLog(workspace / "spine.jsonl", claimant), clock=lambda: now,
    )
    return canonical_json(SourceReceiptAckReturnStore(receiver).prepare(message_id).to_dict())


def test_prepare_reuses_exact_bytes_after_receiver_restart(tmp_path):
    source, claimant, proof, original, receiver, result, now = _retained(tmp_path)
    store = SourceReceiptAckReturnStore(receiver)
    returned = store.prepare(original.message_id, ttl_ms=60_000)
    assert returned.recipient == source.as_did()
    assert ack_from_envelope(returned).to_dict() == result.ack.to_dict()
    assert store.outbox.get(returned.message_id).state == OUTBOX_STATE_QUEUED
    restarted = SourceReceiptDeliveryReceiver(
        receiver.workspace, nonce=proof["nonce"], identity=claimant,
        spine=SignedEventLog(receiver.workspace / "spine.jsonl", claimant), clock=lambda: now + 1_000,
    )
    other = SourceReceiptAckReturnStore(restarted)
    assert other.prepare(original.message_id, ttl_ms=500).to_dict() == returned.to_dict()
    assert other.get(original.message_id).to_dict() == returned.to_dict()
    audit = restarted.spine.find_unique_event(
        SOURCE_RECEIPT_ACK_RETURN_PREPARED_EVENT,
        payload_field="original_message_id", payload_value=original.message_id,
    )
    assert audit.author_did == claimant.as_did()
    assert audit.payload["verification_scope"] == "transport_receipt_only"
    assert not audit.payload["accepted"] and not audit.payload["settled"]


@pytest.mark.parametrize("concurrency", ["threads", "processes"])
def test_concurrent_preparation_is_one_exact_operation(tmp_path, concurrency):
    _, claimant, proof, original, receiver, _, now = _retained(tmp_path)
    args = (receiver.workspace, claimant, proof["nonce"], original.message_id, now)
    pool = (
        ThreadPoolExecutor(max_workers=4) if concurrency == "threads"
        else ProcessPoolExecutor(max_workers=4, mp_context=multiprocessing.get_context("spawn"))
    )
    with pool:
        values = list(pool.map(_prepare_in_process, [args] * 4))
    assert len(set(values)) == 1
    assert SourceReceiptAckReturnStore(receiver).outbox.stats()["total"] == 1
    assert receiver.spine.verify_chain()[0]


@pytest.mark.parametrize("failure_stage", ["audit", "enqueue"])
def test_interrupted_preparation_repairs_the_same_envelope(tmp_path, monkeypatch, failure_stage):
    _, _, _, original, receiver, _, _ = _retained(tmp_path)
    store = SourceReceiptAckReturnStore(receiver)

    def unavailable(*args, **kwargs):
        raise OSError("injected persistence failure")

    with monkeypatch.context() as patch:
        target = receiver.spine if failure_stage == "audit" else store.outbox
        patch.setattr(target, "append_unique" if failure_stage == "audit" else "enqueue", unavailable)
        with pytest.raises(OSError):
            store.prepare(original.message_id)
    persisted = store._prepared_path(original).read_bytes()
    with pytest.raises(SourceReceiptDeliveryRejected):
        store.get(original.message_id)
    restarted = SourceReceiptAckReturnStore(receiver)
    recovered = restarted.prepare(original.message_id)
    assert canonical_json(recovered.to_dict()) == persisted
    assert restarted.get(original.message_id).to_dict() == recovered.to_dict()


def test_expiry_never_renews_or_changes_original_return(tmp_path):
    _, _, _, original, receiver, _, now = _retained(tmp_path)
    store = SourceReceiptAckReturnStore(receiver)
    returned = store.prepare(original.message_id, ttl_ms=1000)
    receiver._clock = lambda: now + 2000
    assert store.prepare(original.message_id).to_dict() == returned.to_dict()
    assert store.get(original.message_id).to_dict() == returned.to_dict()
    assert store.outbox.stats()["total"] == 1


def test_expired_partial_preparation_cannot_be_backdated_into_outbox(tmp_path, monkeypatch):
    _, _, _, original, receiver, _, now = _retained(tmp_path)
    store = SourceReceiptAckReturnStore(receiver)
    with monkeypatch.context() as patch:
        patch.setattr(receiver.spine, "append_unique", lambda *a, **k: (_ for _ in ()).throw(OSError("crash")))
        with pytest.raises(OSError):
            store.prepare(original.message_id, ttl_ms=1000)
    retained = store._prepared_path(original).read_bytes()
    receiver._clock = lambda: now + 2000
    with pytest.raises(SourceReceiptDeliveryDeferred, match="expired"):
        store.prepare(original.message_id)
    assert store._prepared_path(original).read_bytes() == retained
    assert store.outbox.stats()["total"] == 0


@pytest.mark.parametrize("ttl", [True, 0, -1, 604_800_001, 0.5])
def test_invalid_ttl_has_no_preparation_side_effect(tmp_path, ttl):
    _, _, _, original, receiver, _, _ = _retained(tmp_path)
    store = SourceReceiptAckReturnStore(receiver)
    with pytest.raises(ValueError, match="TTL"):
        store.prepare(original.message_id, ttl_ms=ttl)
    assert not store._prepared_path(original).exists()
    assert store.outbox.stats()["total"] == 0


def test_unreceived_delivery_cannot_generate_a_return(tmp_path):
    _, _, _, _, original, receiver, _ = _delivery(tmp_path)
    store = SourceReceiptAckReturnStore(receiver)
    with pytest.raises(OSError):
        store.prepare(original.message_id)
    assert store.outbox.stats()["total"] == 0


def test_wrong_spine_signer_is_rejected(tmp_path):
    _, _, _, _, receiver, _, _ = _retained(tmp_path)
    receiver.spine = SignedEventLog(receiver.workspace / "other.jsonl", AgentIdentity.generate(label="other"))
    with pytest.raises(SourceReceiptDeliveryRejected, match="Spine signer"):
        SourceReceiptAckReturnStore(receiver)


@pytest.mark.parametrize("mode", ["signature", "wrong-recipient", "hardlink", "missing", "audit-conflict"])
def test_corrupted_preparation_cannot_be_exported_or_repaired_as_fresh(tmp_path, mode):
    _, claimant, _, original, receiver, _, _ = _retained(tmp_path)
    store = SourceReceiptAckReturnStore(receiver)
    returned = store.prepare(original.message_id)
    path = store._prepared_path(original)
    if mode == "signature":
        value = returned.to_dict()
        value["signature"] = "00" * 64
        path.write_bytes(canonical_json(value))
    elif mode == "wrong-recipient":
        path.write_bytes(canonical_json(_resign(claimant, returned, recipient=claimant.as_did()).to_dict()))
    elif mode == "hardlink":
        os.link(path, tmp_path / "linked-return.json")
    elif mode == "missing":
        path.rename(tmp_path / "moved-return.json")
    else:
        path.write_bytes(canonical_json(_resign(claimant, returned, nonce="a" * 32).to_dict()))
    with pytest.raises((OSError, ValueError)):
        store.get(original.message_id)
    with pytest.raises((OSError, ValueError)):
        store.prepare(original.message_id)
    assert store.outbox.stats()["total"] == 1


def test_export_and_retry_reverify_local_proof(tmp_path, monkeypatch):
    _, _, _, original, receiver, _, _ = _retained(tmp_path)
    store = SourceReceiptAckReturnStore(receiver)
    store.prepare(original.message_id)
    monkeypatch.setattr("nth_dao.market.source_receipt_delivery.build_portable_completion_proof_with_pins",
                        lambda *a, **k: None)
    for action in (store.get, store.prepare):
        with pytest.raises(SourceReceiptDeliveryDeferred):
            action(original.message_id)
    assert store.outbox.stats()["total"] == 1


@pytest.mark.parametrize("reason", ["directory", "retention", "links"])
def test_outbox_substitution_fails_before_preparation_side_effects(tmp_path, reason):
    _, _, _, original, receiver, _, _ = _retained(tmp_path)
    store = SourceReceiptAckReturnStore(receiver)
    directory = tmp_path / "wrong-outbox" if reason == "directory" else store._path(Path("."))
    store.outbox = DurableOutbox(
        directory, retain_terminal_records=reason != "retention", reject_links=reason != "links",
    )
    with pytest.raises(ValueError, match="exact selected directory"):
        store.prepare(original.message_id)
    assert not store._prepared_path(original).exists()
    assert store._audit(original.message_id) is None


def test_future_partial_return_is_not_audited_or_queued(tmp_path):
    _, claimant, _, original, receiver, result, now = _retained(tmp_path)
    from nth_dao.delivery.acknowledgement import sign_ack_envelope

    store = SourceReceiptAckReturnStore(receiver)
    future = sign_ack_envelope(claimant, result.ack, recipient=original.sender_did,
                               created_at_ms=now + 600_000, expires_at_ms=now + 700_000)
    path = store._prepared_path(original)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(future.to_dict()))
    with pytest.raises(SourceReceiptDeliveryRejected, match="future"):
        store.prepare(original.message_id)
    assert store._audit(original.message_id) is None and store.outbox.stats()["total"] == 0


def test_exposed_snapshots_cannot_mutate_retained_return_evidence(tmp_path):
    _, _, _, original, receiver, _, _ = _retained(tmp_path)
    store = SourceReceiptAckReturnStore(receiver)
    prepared = store.prepare(original.message_id)
    pristine = canonical_json(prepared.to_dict())
    prepared.payload["ack"]["signature"] = "00" * 64
    exposed, result = receiver.get_retained_delivery(original.message_id)
    exposed.payload["source_receipt_json"] = "{}"
    result.observation["local_observation_event_id"] = "0" * 64
    assert canonical_json(store.get(original.message_id).to_dict()) == pristine


def _governed(tmp_path):
    source, claimant, original, receiver, now, host, binding, sender, runtime = _setup(tmp_path)
    assert sender.submit(original).accepted
    assert receive_source_receipt_deliveries(
        runtime=runtime, receiver=receiver, receive_id="forward",
    ).domain.failures == ()
    returner = SourceReceiptAckPluginSender(
        receiver=receiver, binding=binding, authority=_authority(claimant, source.as_did()),
        route_resolver=loopback_route_id,
    )
    return source, claimant, original, receiver, now, host, binding, sender, returner


def test_governed_return_prepared_on_claimant_closes_only_source_delivery(tmp_path):
    source, _, original, receiver, now, _host, binding, sender, returner = _governed(tmp_path)
    returned = returner.store.prepare(original.message_id)
    assert returner.submit(original.message_id).accepted
    source_receiver = SourceReceiptAckReceiver(
        tmp_path / "source", identity=source,
        spine=SignedEventLog(tmp_path / "source/spine.jsonl", source), clock=lambda: now,
    )
    runtime = PluginDeliveryRuntime(
        binding=binding, authority=_authority(source), route_resolver=loopback_route_id,
        outbox=sender.outbox, inbox=source_receiver.inbox, clock=lambda: now,
    )
    batch = receive_source_receipt_acks(runtime=runtime, receiver=source_receiver, receive_id="return")
    assert batch.domain.failures == ()
    assert batch.domain.results[0].delivery.message_id == original.message_id
    assert sender.outbox.get(original.message_id).state == "delivered"
    assert returner.store.outbox.get(returned.message_id).state == OUTBOX_STATE_QUEUED
    assert receiver.spine.verify_chain()[0] and source_receiver.spine.verify_chain()[0]


@pytest.mark.parametrize("reason", ["scope", "disabled", "wrong-principal", "proof", "unprepared"])
def test_return_sender_never_bypasses_domain_or_host_gates(tmp_path, monkeypatch, reason):
    source, claimant, original, receiver, _, host, binding, _, returner = _governed(tmp_path)
    if reason != "unprepared":
        returner.store.prepare(original.message_id)
    if reason == "scope":
        returner = SourceReceiptAckPluginSender(
            receiver=receiver, binding=binding, authority=_authority(claimant), route_resolver=loopback_route_id,
        )
    elif reason == "disabled":
        host.disable(binding.plugin_id)
    elif reason == "wrong-principal":
        with pytest.raises(SourceReceiptDeliveryRejected):
            SourceReceiptAckPluginSender(
                receiver=receiver, binding=binding, authority=_authority(source), route_resolver=loopback_route_id,
            )
        return
    else:
        monkeypatch.setattr(host, "invoke", lambda *a, **k: pytest.fail("unverified ACK disclosed"))
        if reason == "proof":
            monkeypatch.setattr("nth_dao.market.source_receipt_delivery.build_portable_completion_proof_with_pins",
                                lambda *a, **k: None)
    with pytest.raises((OSError, SourceReceiptDeliveryRejected, PluginDeliveryRuntimeError)):
        returner.submit(original.message_id)


def test_expired_return_submission_fails_without_provider_io(tmp_path, monkeypatch):
    _, _, original, receiver, now, host, _, _, returner = _governed(tmp_path)
    returned = returner.store.prepare(original.message_id, ttl_ms=1000)
    receiver._clock = lambda: now + 2000
    monkeypatch.setattr(host, "invoke", lambda *a, **k: pytest.fail("expired return disclosed"))
    outcome = returner.submit(original.message_id)
    assert not outcome.accepted and "expired" in outcome.error_code
    assert returner.store.get(original.message_id).message_id == returned.message_id
    assert returner.store.outbox.stats()["total"] == 1


def _cli_args(command, receiver, key, *extra):
    return [command, "--workspace", str(receiver.workspace), "--identity-file", str(key),
            "--spine-file", "spine.jsonl", *extra]


def test_cli_explicit_offline_return_roundtrip_and_exact_repack(tmp_path, capsys):
    from nth_dao.cli.source_receipt_delivery import main

    source, claimant, _, original, receiver, _, now = _retained(tmp_path)
    # Retain the source's original audited outgoing receipt, independently of
    # the claimant's prepared return.
    from test_market_source_receipt_delivery import _prepare_source

    from nth_dao.market.source_receipt_delivery import (
        open_source_receipt_delivery_outbox,
    )

    _prepare_source(tmp_path, source, original)
    source_outbox = open_source_receipt_delivery_outbox(tmp_path / "source", clock=lambda: now)
    source_outbox.enqueue(original)
    key = tmp_path / "claimant-key.json"
    claimant.save(key)
    args = _cli_args("pack-ack-return", receiver, key, "--nonce", receiver.nonce,
                     "--message-id", original.message_id)
    assert main(args) == 0
    packed = json.loads(capsys.readouterr().out)
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out) == packed
    assert main(_cli_args("export-ack-return", receiver, key, "--nonce", receiver.nonce,
                          "--message-id", original.message_id)) == 0
    assert json.loads(capsys.readouterr().out) == packed
    packet = tmp_path / "return.json"
    packet.write_bytes(canonical_json(packed))
    source_key = tmp_path / "source-key.json"
    source.save(source_key)
    source_receiver = SourceReceiptAckReceiver(
        tmp_path / "source", identity=source,
        spine=SignedEventLog(tmp_path / "source/spine.jsonl", source), clock=lambda: now,
    )
    intake = _cli_args("receive-ack-return", source_receiver, source_key, "--envelope-file", str(packet))
    assert main(intake) == 0
    outcome = json.loads(capsys.readouterr().out)
    assert outcome["state"] == "delivered" and outcome["original_message_id"] == original.message_id
    assert outcome["message_id"] == packed["message_id"]
    assert not outcome["accepted"] and not outcome["settled"]
    assert source_outbox.get(original.message_id).state == "delivered"
    assert main(intake) == 0
    assert json.loads(capsys.readouterr().out) == outcome
    assert main(_cli_args("resume-ack-returns", source_receiver, source_key)) == 0
    assert json.loads(capsys.readouterr().out) == {"resumed": [], "failed": []}


def test_cli_repairs_durable_source_audit_failure_after_return_expiry(tmp_path, capsys, monkeypatch):
    from nth_dao.cli.source_receipt_delivery import main

    source, _, original, _, now, _host, _, _, returner = _governed(tmp_path)
    returned = returner.store.prepare(original.message_id, ttl_ms=1000)
    packet = tmp_path / "return.json"
    packet.write_bytes(canonical_json(returned.to_dict()))
    key = tmp_path / "source-key.json"
    source.save(key)
    receiver = SourceReceiptAckReceiver(
        tmp_path / "source", identity=source,
        spine=SignedEventLog(tmp_path / "source/spine.jsonl", source), clock=lambda: now,
    )
    append = SignedEventLog.append_unique

    def fail_audit(self, event_type, *args, **kwargs):
        if event_type == SOURCE_RECEIPT_DELIVERY_ACKNOWLEDGED_EVENT:
            raise OSError("injected source audit failure")
        return append(self, event_type, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr("nth_dao.market.source_receipt_ack.time.time", lambda: now / 1000)
        patch.setattr(SignedEventLog, "append_unique", fail_audit)
        assert main(_cli_args("receive-ack-return", receiver, key, "--envelope-file", str(packet))) == 1
    assert "injected source audit failure" in capsys.readouterr().err
    monkeypatch.setattr("nth_dao.market.source_receipt_ack.time.time", lambda: (now + 2000) / 1000)
    assert main(_cli_args("resume-ack-returns", receiver, key)) == 0
    resumed = json.loads(capsys.readouterr().out)
    assert resumed["failed"] == [] and resumed["resumed"][0]["original_message_id"] == original.message_id


@pytest.mark.parametrize("terminal", [False, True])
@pytest.mark.parametrize("loss", ["missing", "empty"])
def test_committed_queue_history_loss_cannot_resurrect_return(tmp_path, terminal, loss):
    _, _, _, original, receiver, _, now = _retained(tmp_path)
    store = SourceReceiptAckReturnStore(receiver)
    returned = store.prepare(original.message_id)
    if terminal:
        store.outbox.record_attempt(returned.message_id, transport="test-provider", at_ms=now,
                                    outcome=OUTBOX_ATTEMPT_REJECTED, error_code="permanent-policy-rejection")
    before = store.outbox.get(returned.message_id)
    assert before.state == ("rejected" if terminal else "queued")
    journal = store._path(Path("outbox.journal.jsonl"))
    journal.rename(journal.with_name("preserved-history.jsonl"))
    if loss == "empty":
        journal.write_bytes(b"")
    restarted = SourceReceiptAckReturnStore(receiver)
    for action in (restarted.get, restarted.prepare):
        with pytest.raises(DeliveryOutboxCorrupt, match="committed.*missing") as caught:
            action(original.message_id)
        assert not source_receipt_delivery_failure(returned.message_id, caught.value).retryable
    if loss == "missing":
        assert not journal.exists()
    else:
        assert journal.read_bytes() == b""
    assert restarted.outbox.stats()["total"] == 0
    if loss == "empty":
        journal.rename(journal.with_name("preserved-empty.jsonl"))
    journal.with_name("preserved-history.jsonl").rename(journal)
    restored = SourceReceiptAckReturnStore(receiver)
    assert restored.prepare(original.message_id).to_dict() == returned.to_dict()
    assert restored.outbox.get(returned.message_id) == before


@pytest.mark.parametrize("write_then_fail", [False, True])
def test_commit_write_failure_never_exposes_an_uncommitted_packet(tmp_path, monkeypatch, write_then_fail):
    _, _, _, original, receiver, _, now = _retained(tmp_path)
    store = SourceReceiptAckReturnStore(receiver)
    append = receiver.spine.append_unique

    def fail_commit(event_type, *args, **kwargs):
        if event_type == SOURCE_RECEIPT_ACK_RETURN_COMMITTED_EVENT:
            if write_then_fail:
                append(event_type, *args, **kwargs)
            raise OSError("injected commit write failure")
        return append(event_type, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(receiver.spine, "append_unique", fail_commit)
        with pytest.raises(OSError, match="commit write"):
            store.prepare(original.message_id, ttl_ms=1000)
    prepared = store._prepared_path(original).read_bytes()
    if write_then_fail:
        assert canonical_json(store.get(original.message_id).to_dict()) == prepared
    else:
        with pytest.raises(SourceReceiptDeliveryRejected, match="commit audit"):
            store.get(original.message_id)
    receiver._clock = lambda: now + 2000
    restarted = SourceReceiptAckReturnStore(receiver)
    monkeypatch.setattr(restarted.outbox, "enqueue", lambda *a, **k: pytest.fail("durable entry was re-enqueued"))
    assert canonical_json(restarted.prepare(original.message_id).to_dict()) == prepared
    assert canonical_json(restarted.get(original.message_id).to_dict()) == prepared
    assert restarted.outbox.stats()["total"] == 1


def test_enqueue_unknown_outcome_repairs_commit_after_expiry_without_requeue(tmp_path, monkeypatch):
    _, _, _, original, receiver, _, now = _retained(tmp_path)
    store = SourceReceiptAckReturnStore(receiver)
    enqueue = store.outbox.enqueue

    def unknown(*args, **kwargs):
        enqueue(*args, **kwargs)
        raise OSError("injected unknown enqueue outcome")

    with monkeypatch.context() as patch:
        patch.setattr(store.outbox, "enqueue", unknown)
        with pytest.raises(OSError):
            store.prepare(original.message_id, ttl_ms=1000)
    raw = store._prepared_path(original).read_bytes()
    receiver._clock = lambda: now + 2000
    restarted = SourceReceiptAckReturnStore(receiver)
    monkeypatch.setattr(restarted.outbox, "enqueue", lambda *a, **k: pytest.fail("re-enqueue after expiry"))
    assert canonical_json(restarted.prepare(original.message_id).to_dict()) == raw


def _legacy_preparation(tmp_path, *, queued, rejected=False):
    from nth_dao.delivery.acknowledgement import sign_ack_envelope

    _, _, _, original, receiver, result, now = _retained(tmp_path)
    store = SourceReceiptAckReturnStore(receiver)
    envelope = sign_ack_envelope(receiver.identity, result.ack, recipient=original.sender_did,
                                 created_at_ms=now, expires_at_ms=now + 60_000)
    path = store._prepared_path(original)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(envelope.to_dict()))
    receiver.spine.append_unique(SOURCE_RECEIPT_ACK_RETURN_PREPARED_EVENT,
                                 store._payload(envelope, original, result),
                                 unique_payload_fields=("original_message_id",))
    if queued:
        store.outbox.enqueue(envelope)
        if rejected:
            store.outbox.record_attempt(envelope.message_id, transport="test-provider", at_ms=now,
                                        outcome=OUTBOX_ATTEMPT_REJECTED, error_code="legacy-rejection")
    return original, receiver, envelope


@pytest.mark.parametrize("rejected", [False, True])
def test_legacy_adoption_requires_and_preserves_existing_queue_history(tmp_path, rejected):
    original, receiver, envelope = _legacy_preparation(tmp_path, queued=True, rejected=rejected)
    store = SourceReceiptAckReturnStore(receiver)
    before = store.outbox.get(envelope.message_id)
    with pytest.raises(SourceReceiptDeliveryRejected, match="commit audit"):
        store.get(original.message_id)
    assert store.prepare(original.message_id).to_dict() == envelope.to_dict()
    assert store.get(original.message_id).to_dict() == envelope.to_dict()
    after = store.outbox.get(envelope.message_id)
    assert after == before
    assert store._audit(original.message_id).payload.get("preparation_version") is None


def test_legacy_without_queue_evidence_cannot_be_assumed_interrupted_preparation(tmp_path):
    original, receiver, _ = _legacy_preparation(tmp_path, queued=False)
    store = SourceReceiptAckReturnStore(receiver)
    with pytest.raises(DeliveryOutboxCorrupt, match="legacy.*missing"):
        store.prepare(original.message_id)
    assert store.outbox.stats()["total"] == 0
    assert store._audit(original.message_id, event_type=SOURCE_RECEIPT_ACK_RETURN_COMMITTED_EVENT) is None


@pytest.mark.parametrize("corrupt", ["author", "preparation_id"])
def test_invalid_signed_commit_cannot_authorize_export_or_recovery(tmp_path, monkeypatch, corrupt):
    _, _, _, original, receiver, result, _ = _retained(tmp_path)
    store = SourceReceiptAckReturnStore(receiver)
    append = receiver.spine.append_unique

    def stop_commit(event_type, *args, **kwargs):
        if event_type == SOURCE_RECEIPT_ACK_RETURN_COMMITTED_EVENT:
            raise OSError("stop before commit")
        return append(event_type, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(receiver.spine, "append_unique", stop_commit)
        with pytest.raises(OSError):
            store.prepare(original.message_id)
    envelope = store._read(original)
    payload = store._commit_payload(store._payload(envelope, original, result), store._audit(original.message_id))
    if corrupt == "preparation_id":
        payload["preparation_event_id"] = "0" * 64
        writer = receiver.spine
    else:
        writer = SignedEventLog(receiver.workspace / "spine.jsonl", AgentIdentity.generate(label="foreign"))
    writer.append_unique(SOURCE_RECEIPT_ACK_RETURN_COMMITTED_EVENT, payload,
                         unique_payload_fields=("original_message_id",))
    for action in (store.get, store.prepare):
        with pytest.raises(SourceReceiptDeliveryRejected, match="commit audit"):
            action(original.message_id)


def test_restarted_sender_cannot_invoke_provider_after_committed_journal_loss(tmp_path, monkeypatch):
    source, claimant, original, receiver, _, host, binding, _, returner = _governed(tmp_path)
    returner.store.prepare(original.message_id)
    journal = returner.store._path(Path("outbox.journal.jsonl"))
    journal.rename(journal.with_name("preserved-journal.jsonl"))
    restarted = SourceReceiptAckPluginSender(
        receiver=receiver, binding=binding, authority=_authority(claimant, source.as_did()),
        route_resolver=loopback_route_id,
    )
    monkeypatch.setattr(host, "invoke", lambda *a, **k: pytest.fail("incomplete queue was disclosed"))
    with pytest.raises(DeliveryOutboxCorrupt, match="committed.*missing"):
        restarted.submit(original.message_id)


@pytest.mark.parametrize("command", ["pack-ack-return", "export-ack-return"])
def test_cli_does_not_print_or_recreate_committed_return_with_missing_queue(tmp_path, capsys, command):
    from nth_dao.cli.source_receipt_delivery import main

    _, claimant, _, original, receiver, _, _ = _retained(tmp_path)
    store = SourceReceiptAckReturnStore(receiver)
    store.prepare(original.message_id)
    journal = store._path(Path("outbox.journal.jsonl"))
    journal.rename(journal.with_name("preserved-journal.jsonl"))
    key = tmp_path / "claimant-key.json"
    claimant.save(key)
    assert main(_cli_args(command, receiver, key, "--nonce", receiver.nonce,
                          "--message-id", original.message_id)) == 1
    output = capsys.readouterr()
    assert output.out == "" and "committed ACK return outbox record is missing" in output.err
    assert not journal.exists()


def test_ack_sender_never_reenqueues_if_journal_is_lost_after_domain_verification(tmp_path, monkeypatch):
    _, _, original, _, _, host, _, _, returner = _governed(tmp_path)
    returner.store.prepare(original.message_id)
    get = returner.store.get

    def lose_after_check(message_id):
        envelope = get(message_id)
        journal = returner.store._path(Path("outbox.journal.jsonl"))
        journal.rename(journal.with_name("preserved-journal.jsonl"))
        journal.write_bytes(b"")
        return envelope

    monkeypatch.setattr(returner.store, "get", lose_after_check)
    monkeypatch.setattr(returner.store.outbox, "enqueue", lambda *a, **k: pytest.fail("committed return was re-enqueued"))
    monkeypatch.setattr(host, "invoke", lambda *a, **k: pytest.fail("lost queue was disclosed"))
    with pytest.raises(DeliveryOutboxCorrupt):
        returner.submit(original.message_id)


_COMMIT_VECTORS = json.loads((Path(__file__).resolve().parents[1] / "nth_dao/market/vectors/ack-return-commit-policy-v1.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("vector", _COMMIT_VECTORS["cases"], ids=lambda item: item["name"])
def test_local_commit_policy_vectors(tmp_path, vector):
    from nth_dao.delivery.acknowledgement import sign_ack_envelope

    assert SOURCE_RECEIPT_ACK_RETURN_PREPARED_EVENT == _COMMIT_VECTORS["preparation_event_type"]
    assert SOURCE_RECEIPT_ACK_RETURN_COMMITTED_EVENT == _COMMIT_VECTORS["commit_event_type"]
    _, _, _, original, receiver, result, now = _retained(tmp_path)
    store = SourceReceiptAckReturnStore(receiver)
    returned = None
    if vector["preparation_version"] is not None:
        returned = sign_ack_envelope(receiver.identity, result.ack, recipient=original.sender_did,
                                     created_at_ms=now, expires_at_ms=now + 1000)
        path = store._prepared_path(original)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical_json(returned.to_dict()))
        payload = store._payload(returned, original, result)
        preparation_payload = (
            {**payload, "preparation_version": 2} if vector["preparation_version"] == 2 else payload
        )
        preparation, _ = receiver.spine.append_unique(
            SOURCE_RECEIPT_ACK_RETURN_PREPARED_EVENT, preparation_payload,
            unique_payload_fields=("original_message_id",),
        )
        if vector["queued"]:
            store.outbox.enqueue(returned)
            if vector["rejected"]:
                store.outbox.record_attempt(returned.message_id, transport="test-provider", at_ms=now,
                                            outcome=OUTBOX_ATTEMPT_REJECTED, error_code="vector-rejection")
        if vector["committed"]:
            receiver.spine.append_unique(
                SOURCE_RECEIPT_ACK_RETURN_COMMITTED_EVENT,
                {**payload, _COMMIT_VECTORS["commit_binding_field"]: preparation.event_id},
                unique_payload_fields=("original_message_id",),
            )
    if vector["expired"]:
        receiver._clock = lambda: now + 2000
    if vector["expected"] != "ready":
        error = DeliveryOutboxCorrupt if vector["expected"] == "integrity-error" else SourceReceiptDeliveryDeferred
        with pytest.raises(error):
            store.prepare(original.message_id)
        assert store.outbox.stats()["total"] == 0
        return
    actual = store.prepare(original.message_id)
    if returned is not None:
        assert actual.to_dict() == returned.to_dict()
    assert store.get(original.message_id).to_dict() == actual.to_dict()
    record = store.outbox.get(actual.message_id)
    assert record.state == ("rejected" if vector["rejected"] else "queued")
    assert len(record.attempts) == int(vector["rejected"])
