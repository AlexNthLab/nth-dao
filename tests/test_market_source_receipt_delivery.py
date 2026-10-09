"""Recipient-bound completion receipt delivery over the existing delivery layer."""

from __future__ import annotations

import copy
import json
import multiprocessing
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path

import pytest

pytest.importorskip("nacl")

from test_market_source_completion import _source_and_proof

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.acknowledgement import validate_ack
from nth_dao.delivery.envelope import sign_envelope
from nth_dao.delivery.outbox import OUTBOX_STATE_DELIVERED, DurableOutbox
from nth_dao.delivery.transports.file_bundle import FileBundleTransport
from nth_dao.identity import AgentIdentity
from nth_dao.market.claimant_receipt_store import OBSERVED_EVENT
from nth_dao.market.source_completion_inbox import SourceCompletionInbox
from nth_dao.market.source_receipt_delivery import (
    SOURCE_RECEIPT_DELIVERY_PREPARED_EVENT,
    SourceReceiptDeliveryReceiver,
    SourceReceiptDeliveryRejected,
    create_source_receipt_delivery,
    source_receipt_preparation_payload,
)
from nth_dao.spine.log import SignedEventLog


def _delivery(tmp_path: Path):
    source, authority, claimant, announcement, proof = _source_and_proof(tmp_path)
    source_spine = SignedEventLog(source / "spine.jsonl", authority)
    response = SourceCompletionInbox(
        source, source_did=authority.as_did(), spine=source_spine,
    ).record(proof)
    from nth_dao.market.announcement import announcement_federation_key

    now = int(time.time() * 1000)
    envelope = create_source_receipt_delivery(
        authority, proof, response,
        expected_source_did=authority.as_did(),
        expected_federation_key=announcement_federation_key(announcement),
        created_at_ms=now, expires_at_ms=now + 60_000,
    )
    workspace = tmp_path / "claimant"
    spine = SignedEventLog(workspace / "spine.jsonl", claimant)
    receiver = SourceReceiptDeliveryReceiver(
        workspace, nonce=proof["nonce"], identity=claimant,
        spine=spine, clock=lambda: now,
    )
    return authority, claimant, proof, response, envelope, receiver, now


def _resign(identity, envelope, **changes):
    fields = {
        "kind": envelope.kind, "recipient": envelope.recipient,
        "payload": copy.deepcopy(envelope.payload),
        "created_at_ms": envelope.created_at_ms,
        "expires_at_ms": envelope.expires_at_ms, "nonce": envelope.nonce,
    }
    fields.update(changes)
    return sign_envelope(identity, **fields)


def _prepare_source(tmp_path, identity, envelope):
    SignedEventLog(tmp_path / "source" / "spine.jsonl", identity).append_unique(
        SOURCE_RECEIPT_DELIVERY_PREPARED_EVENT, source_receipt_preparation_payload(envelope),
        unique_payload_fields=("message_id",),
    )


def _pack_args(tmp_path, authority, proof, response):
    from nth_dao.market.announcement import (
        TaskAnnouncement,
        announcement_federation_key,
    )

    key, proof_file, receipt_file = tmp_path / "source-key.json", tmp_path / "proof.json", tmp_path / "receipt.json"
    authority.save(key)
    proof_file.write_bytes(canonical_json(proof))
    receipt_file.write_bytes(canonical_json(response))
    return [
        "pack", "--workspace", str(tmp_path / "source"), "--identity-file", str(key),
        "--spine-file", "spine.jsonl", "--proof-file", str(proof_file),
        "--receipt-file", str(receipt_file), "--source-did", authority.as_did(),
        "--federation-key", announcement_federation_key(TaskAnnouncement.from_dict(proof["announcement"])),
    ]


def _receive_in_process(args):
    workspace, claimant, nonce, envelope, now = args
    receiver = SourceReceiptDeliveryReceiver(
        workspace, nonce=nonce, identity=claimant,
        spine=SignedEventLog(workspace / "spine.jsonl", claimant), clock=lambda: now,
    )
    result = receiver.receive(envelope)
    return result.observation["local_observation_event_id"], canonical_json(result.ack.to_dict())


def _pack_in_process(args):
    from nth_dao.cli.source_receipt_delivery import _pack, _spine

    namespace, authority, proof, response = args
    spine = _spine(namespace.workspace, Path("spine.jsonl"), authority)
    return canonical_json(_pack(namespace, authority, proof, response, spine).to_dict())


def test_two_workspaces_use_existing_bundle_and_signed_ack(tmp_path: Path) -> None:
    authority, claimant, proof, _, envelope, receiver, now = _delivery(tmp_path)
    exchange = tmp_path / "exchange"
    sender = FileBundleTransport(exchange, authority, state_dir=tmp_path / "sender")
    transport = FileBundleTransport(exchange, claimant, state_dir=tmp_path / "receiver")
    outbox = DurableOutbox(tmp_path / "outbox", clock=lambda: now)
    outbox.enqueue(envelope)
    assert sender.send(envelope).accepted
    wire = transport.poll()[0]
    result = receiver.receive(wire)
    assert result.observation["source_claim_id"] == proof["source_claim_id"]
    assert result.observation["receipt_verified"] is True
    assert result.observation["accepted"] is False
    assert result.observation["settled"] is False
    assert validate_ack(result.ack, now_ms=now) == (True, "ok")
    assert outbox.handle_ack(result.ack).state == OUTBOX_STATE_DELIVERED
    assert receiver.inbox.pending() == []
    assert receiver.spine.verify_chain()[0]


def test_restart_and_retry_are_idempotent(tmp_path: Path) -> None:
    _, claimant, proof, _, envelope, receiver, now = _delivery(tmp_path)
    first = receiver.receive(envelope)
    restarted = SourceReceiptDeliveryReceiver(
        tmp_path / "claimant", nonce=proof["nonce"], identity=claimant,
        spine=SignedEventLog(tmp_path / "claimant" / "spine.jsonl", claimant),
        clock=lambda: now,
    )
    second = restarted.receive(envelope)
    assert second.observation["already_observed"] is True
    assert second.observation["local_observation_event_id"] == first.observation["local_observation_event_id"]
    assert second.ack.to_dict() == first.ack.to_dict()


@pytest.mark.parametrize("mutation", ["recipient", "sender", "head", "proof", "kind", "unsigned", "expired"])
def test_invalid_delivery_is_not_retained_or_acknowledged(tmp_path: Path, mutation: str) -> None:
    authority, claimant, _, _, envelope, receiver, now = _delivery(tmp_path)
    stranger = AgentIdentity.generate(label="stranger")
    if mutation == "recipient":
        envelope = _resign(authority, envelope, recipient=stranger.as_did())
    elif mutation == "sender":
        envelope = _resign(stranger, envelope)
    elif mutation in ("head", "proof"):
        payload = dict(envelope.payload)
        payload["completion_head_digest" if mutation == "head" else "proof_digest"] = "sha256:" + "0" * 64
        envelope = _resign(authority, envelope, payload=payload)
    elif mutation == "kind":
        envelope = _resign(authority, envelope, kind="chat.message")
    elif mutation == "unsigned":
        envelope.signature = ""
    else:
        envelope = _resign(authority, envelope, created_at_ms=now - 60_001, expires_at_ms=now - 1)
    with pytest.raises(SourceReceiptDeliveryRejected):
        receiver.receive(envelope)
    assert receiver.inbox.entry_count() == 0
    assert not receiver.spine.find_unique_event(OBSERVED_EVENT, payload_field="claimant_did", payload_value=claimant.as_did())


def test_nonce_reuse_for_another_envelope_is_rejected(tmp_path: Path) -> None:
    authority, _, _, _, envelope, receiver, now = _delivery(tmp_path)
    receiver.receive(envelope)
    replay = _resign(authority, envelope, expires_at_ms=now + 59_000)
    with pytest.raises(SourceReceiptDeliveryRejected, match="replayed nonce"):
        receiver.receive(replay)


def test_lost_success_ack_is_exportable_after_restart_and_expiry(tmp_path: Path) -> None:
    _, claimant, proof, _, envelope, receiver, now = _delivery(tmp_path)
    first = receiver.receive(envelope)
    restarted = SourceReceiptDeliveryReceiver(
        receiver.workspace, nonce=proof["nonce"], identity=claimant,
        spine=SignedEventLog(receiver.workspace / "spine.jsonl", claimant),
        clock=lambda: now + 120_000,
    )
    exported = restarted.get_ack(envelope.message_id)
    assert exported.ack.to_dict() == first.ack.to_dict()
    assert exported.observation["already_observed"] is True
    assert restarted.receive(envelope).ack.to_dict() == first.ack.to_dict()
    assert restarted.inbox.pending() == []


def test_result_write_failure_keeps_pending_until_retry(tmp_path: Path, monkeypatch) -> None:
    _, _, _, _, envelope, receiver, _ = _delivery(tmp_path)

    def fail(*_args, **_kwargs):
        raise OSError("injected result persistence failure")

    with monkeypatch.context() as patch:
        patch.setattr("nth_dao.market.source_receipt_delivery.atomic_write_bytes", fail)
        with pytest.raises(OSError, match="result persistence"):
            receiver.receive(envelope)
    assert len(receiver.inbox.pending()) == 1
    result = receiver.resume_pending().results[0]
    assert result.observation["already_observed"] is True
    assert receiver.get_ack(envelope.message_id).ack.to_dict() == result.ack.to_dict()


def test_retained_result_tampering_is_not_silently_repaired(tmp_path: Path) -> None:
    _, _, _, _, envelope, receiver, _ = _delivery(tmp_path)
    receiver.receive(envelope)
    path = receiver._result_path(envelope.message_id)
    value = json.loads(path.read_bytes())
    value["ack"]["envelope_sha256"] = "sha256:" + "0" * 64
    path.write_bytes(canonical_json(value))
    with pytest.raises(SourceReceiptDeliveryRejected):
        receiver.get_ack(envelope.message_id)


def test_ack_export_requires_a_known_durable_message(tmp_path: Path) -> None:
    *_, receiver, _ = _delivery(tmp_path)
    with pytest.raises(FileNotFoundError):
        receiver.get_ack("sha256:" + "0" * 64)
    assert receiver.inbox.entry_count() == 0


def test_ack_export_rejects_missing_intake_journal_even_with_cached_result(tmp_path: Path) -> None:
    from nth_dao.delivery.inbox import DeliveryInboxCacheCorrupt

    _, claimant, proof, _, envelope, receiver, now = _delivery(tmp_path)
    first = receiver.receive(envelope)
    journal = receiver.inbox._cache_path
    saved = journal.with_suffix(".test-saved")
    journal.rename(saved)
    with pytest.raises(DeliveryInboxCacheCorrupt, match="journal is missing"):
        receiver.get_ack(envelope.message_id)
    with pytest.raises(DeliveryInboxCacheCorrupt, match="journal is missing"):
        receiver.receive(envelope)
    restarted = SourceReceiptDeliveryReceiver(
        receiver.workspace, nonce=proof["nonce"], identity=claimant,
        spine=SignedEventLog(receiver.workspace / "spine.jsonl", claimant), clock=lambda: now,
    )
    with pytest.raises(SourceReceiptDeliveryRejected, match="durable first-acceptance"):
        restarted.get_ack(envelope.message_id)
    assert not journal.exists()
    saved.rename(journal)
    assert receiver.get_ack(envelope.message_id).ack.to_dict() == first.ack.to_dict()


def test_pending_resume_ack_closes_expired_source_delivery(tmp_path: Path) -> None:
    _, _, _, _, envelope, receiver, now = _delivery(tmp_path)
    outbox = DurableOutbox(tmp_path / "outbox", clock=lambda: now + 120_000, retain_terminal_records=True)
    outbox.enqueue(envelope, now_ms=now)
    assert receiver.inbox.accept(envelope).accepted
    outbox.pending()
    result = receiver.resume_pending().results[0]
    assert outbox.handle_ack(result.ack, allow_expired=True).state == OUTBOX_STATE_DELIVERED


@pytest.mark.parametrize("source_offset", [-300_000, -60_000, 0, 60_000, 300_000])
def test_two_node_clock_skew_ack_survives_expiry_and_restart(tmp_path: Path, source_offset: int) -> None:
    authority, _, _, _, envelope, receiver, now = _delivery(tmp_path)
    shifted = _resign(authority, envelope, created_at_ms=now + source_offset,
                      expires_at_ms=now + source_offset + 600_000)
    result = receiver.receive(shifted)
    directory = tmp_path / "outbox"
    outbox = DurableOutbox(directory, clock=lambda: shifted.created_at_ms, retain_terminal_records=True)
    outbox.enqueue(shifted)
    expired_at = shifted.expires_at_ms + 1
    outbox.pending(now_ms=expired_at)
    assert outbox.handle_ack(result.ack, now_ms=expired_at, allow_expired=True).state == OUTBOX_STATE_DELIVERED
    assert DurableOutbox(directory).get(shifted.message_id).delivered_at_ms == now


def test_audit_failure_keeps_delivery_pending_for_restart_after_expiry(tmp_path: Path, monkeypatch) -> None:
    _, claimant, proof, _, envelope, receiver, now = _delivery(tmp_path)

    def fail(*_args, **_kwargs):
        raise OSError("injected audit failure")

    monkeypatch.setattr(receiver.spine, "append_unique", fail)
    with pytest.raises(OSError, match="injected audit"):
        receiver.receive(envelope)
    assert len(receiver.inbox.pending()) == 1
    restarted = SourceReceiptDeliveryReceiver(
        tmp_path / "claimant", nonce=proof["nonce"], identity=claimant,
        spine=SignedEventLog(tmp_path / "claimant" / "spine.jsonl", claimant),
        clock=lambda: now + 120_000,
    )
    with pytest.raises(SourceReceiptDeliveryRejected, match="expired"):
        restarted.receive(envelope)
    batch = restarted.resume_pending()
    assert batch.failures == ()
    results = batch.results
    assert len(results) == 1
    assert results[0].ack.received_at_ms == now
    assert results[0].observation["observed_locally"] is True
    assert restarted.inbox.pending() == []


def test_concurrent_retries_have_one_observation_and_identical_ack(tmp_path: Path) -> None:
    _, _, _, _, envelope, receiver, _ = _delivery(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: receiver.receive(envelope), range(8)))
    assert len({value.observation["local_observation_event_id"] for value in results}) == 1
    assert len({canonical_json(value.ack.to_dict()) for value in results}) == 1


def test_strict_embedded_json_cannot_hide_duplicate_fields(tmp_path: Path) -> None:
    authority, _, _, _, envelope, receiver, _ = _delivery(tmp_path)
    payload = dict(envelope.payload)
    raw = payload["source_receipt_json"]
    response = json.loads(raw)
    payload["source_receipt_json"] = raw[:-1] + ',"audit_event_id":' + json.dumps(response["audit_event_id"]) + "}"
    envelope = _resign(authority, envelope, payload=payload)
    with pytest.raises(SourceReceiptDeliveryRejected, match="canonical"):
        receiver.receive(envelope)
    assert receiver.inbox.entry_count() == 0


def test_receiver_supports_paths_without_python312_junction_api(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delattr(Path, "is_junction", raising=False)
    *_, envelope, receiver, _ = _delivery(tmp_path)
    assert receiver.receive(envelope).observation["receipt_verified"] is True


def test_receiver_rejects_linklike_storage_before_inbox_creation(tmp_path: Path, monkeypatch) -> None:
    _, claimant, proof, _, _, _, now = _delivery(tmp_path)
    monkeypatch.setattr(
        "nth_dao.market.source_receipt_delivery.path_is_linklike",
        lambda path: path.name == "source_receipt_deliveries",
    )
    with pytest.raises(SourceReceiptDeliveryRejected, match="traverses a link"):
        SourceReceiptDeliveryReceiver(
            tmp_path / "claimant", nonce=proof["nonce"], identity=claimant,
            spine=SignedEventLog(tmp_path / "claimant" / "spine.jsonl", claimant),
            clock=lambda: now,
        )


def test_receiver_requires_claimant_not_unrelated_operator(tmp_path: Path) -> None:
    _, _, proof, _, _, _, now = _delivery(tmp_path)
    operator = AgentIdentity.generate(label="operator")
    with pytest.raises(SourceReceiptDeliveryRejected, match="confirmed claimant"):
        SourceReceiptDeliveryReceiver(
            tmp_path / "claimant", nonce=proof["nonce"], identity=operator,
            spine=SignedEventLog(tmp_path / "claimant" / "spine.jsonl", operator),
            clock=lambda: now,
        )


def test_mutation_after_snapshot_does_not_change_retained_receipt(tmp_path: Path, monkeypatch) -> None:
    _, _, _, _, envelope, receiver, _ = _delivery(tmp_path)
    accept = receiver.inbox.accept

    def mutate_original(snapshot):
        envelope.payload["source_receipt_json"] = "{}"
        return accept(snapshot)

    monkeypatch.setattr(receiver.inbox, "accept", mutate_original)
    assert receiver.receive(envelope).observation["receipt_verified"] is True


def test_mark_processed_failure_never_returns_ack_and_can_resume(tmp_path: Path, monkeypatch) -> None:
    _, _, _, _, envelope, receiver, _ = _delivery(tmp_path)
    mark = receiver.inbox.mark_processed

    def fail(_message_id):
        raise OSError("injected processed journal failure")

    monkeypatch.setattr(receiver.inbox, "mark_processed", fail)
    with pytest.raises(OSError, match="processed journal failure"):
        receiver.receive(envelope)
    assert len(receiver.inbox.pending()) == 1
    monkeypatch.setattr(receiver.inbox, "mark_processed", mark)
    assert receiver.resume_pending().results[0].observation["already_observed"] is True


@pytest.mark.parametrize("failed_index", [0, 1])
def test_batch_failure_preserves_and_exports_other_results(tmp_path: Path, monkeypatch, failed_index: int) -> None:
    authority, _, _, _, envelope, receiver, now = _delivery(tmp_path)
    envelopes = [envelope, _resign(authority, envelope, nonce="b" * 32)]
    for value in envelopes:
        assert receiver.inbox.accept(value).accepted
    failed = envelopes[failed_index]
    successful = envelopes[1 - failed_index]
    process = receiver._process

    def fail_one(value):
        if value.message_id == failed.message_id:
            raise OSError("injected one-item failure")
        return process(value)

    monkeypatch.setattr(receiver, "_process", fail_one)
    monkeypatch.setattr(receiver, "_clock", lambda: now + 120_000)
    batch = receiver.resume_pending()
    assert [item.ack.message_id for item in batch.results] == [successful.message_id]
    assert [item.message_id for item in batch.failures] == [failed.message_id]
    assert batch.failures[0].error_code == "OSError"
    assert receiver.get_ack(successful.message_id).ack.to_dict() == batch.results[0].ack.to_dict()
    assert [item.message_id for item in receiver.inbox.pending()] == [failed.message_id]
    monkeypatch.setattr(receiver, "_process", process)
    retried = receiver.resume_pending()
    assert retried.failures == ()
    assert [item.ack.message_id for item in retried.results] == [failed.message_id]


def test_cli_partial_resume_outputs_successes_and_returns_failure(tmp_path: Path, monkeypatch, capsys) -> None:
    from nth_dao.cli.source_receipt_delivery import main

    authority, claimant, proof, _, envelope, receiver, _ = _delivery(tmp_path)
    second = _resign(authority, envelope, nonce="b" * 32)
    assert receiver.inbox.accept(envelope).accepted
    assert receiver.inbox.accept(second).accepted
    key = tmp_path / "claimant-key.json"
    claimant.save(key)
    process = SourceReceiptDeliveryReceiver._process

    def fail_one(self, value):
        if value.message_id == second.message_id:
            raise OSError("injected one-item failure")
        return process(self, value)

    monkeypatch.setattr(SourceReceiptDeliveryReceiver, "_process", fail_one)
    assert main([
        "resume", "--workspace", str(receiver.workspace), "--identity-file", str(key),
        "--spine-file", "spine.jsonl", "--nonce", proof["nonce"],
    ]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["resumed"][0]["ack"]["message_id"] == envelope.message_id
    assert output["failed"][0]["message_id"] == second.message_id


def test_corrupt_local_receipt_is_not_silently_repaired_on_duplicate(tmp_path: Path) -> None:
    _, _, proof, _, envelope, receiver, _ = _delivery(tmp_path)
    receiver.receive(envelope)
    retained = next((receiver.store.root / proof["source_claim_id"]).glob("*.json"))
    # Mechanical corruption of test-owned evidence, not user/runtime files.
    retained.write_bytes(b"{}")
    with pytest.raises(ValueError, match="content hash"):
        receiver.receive(envelope)


@pytest.mark.parametrize("receipt_form", ["response", "event"])
def test_cli_pack_receive_and_ack_roundtrip(tmp_path: Path, capsys, receipt_form: str) -> None:
    from nth_dao.cli.source_receipt_delivery import main
    from nth_dao.market.announcement import (
        TaskAnnouncement,
        announcement_federation_key,
    )

    authority, claimant, proof, response, _, receiver, _ = _delivery(tmp_path)
    source_key = tmp_path / "source-key.json"
    claimant_key = tmp_path / "claimant-key.json"
    authority.save(source_key)
    claimant.save(claimant_key)
    proof_file = tmp_path / "proof.json"
    receipt_file = tmp_path / "receipt.json"
    proof_file.write_bytes(canonical_json(proof))
    receipt_file.write_bytes(canonical_json(
        response if receipt_form == "response" else response["source_receipt_event"],
    ))
    assert main([
        "pack", "--workspace", str(tmp_path / "source"),
        "--spine-file", "spine.jsonl", "--identity-file", str(source_key),
        "--proof-file", str(proof_file), "--receipt-file", str(receipt_file),
        "--source-did", authority.as_did(), "--federation-key",
        announcement_federation_key(TaskAnnouncement.from_dict(proof["announcement"])),
    ]) == 0
    envelope_json = capsys.readouterr().out.strip()
    envelope_file = tmp_path / "envelope.json"
    envelope_file.write_text(envelope_json, encoding="utf-8")
    assert main([
        "receive", "--workspace", str(tmp_path / "claimant"),
        "--spine-file", "spine.jsonl", "--identity-file", str(claimant_key),
        "--nonce", proof["nonce"], "--envelope-file", str(envelope_file),
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["observation"]["receipt_verified"] is True
    assert result["ack"]["message_id"] == json.loads(envelope_json)["message_id"]
    assert receiver.store.get(proof["nonce"], response["completion_head_digest"])["observed_locally"] is True
    ack_file = tmp_path / "ack.json"
    ack_file.write_bytes(canonical_json(result["ack"]))
    assert main([
        "acknowledge", "--workspace", str(tmp_path / "source"),
        "--spine-file", "spine.jsonl", "--identity-file", str(source_key),
        "--ack-file", str(ack_file),
    ]) == 0
    acknowledged = json.loads(capsys.readouterr().out)
    assert acknowledged["state"] == OUTBOX_STATE_DELIVERED
    assert acknowledged["accepted"] is False
    assert acknowledged["settled"] is False


def test_pack_retries_and_export_reuse_one_retained_envelope(tmp_path: Path, capsys) -> None:
    from nth_dao.cli.source_receipt_delivery import _outbox, main

    authority, _, proof, response, _, _, _ = _delivery(tmp_path)
    args = _pack_args(tmp_path, authority, proof, response)
    outputs = []
    for _ in range(3):
        assert main(args) == 0
        outputs.append(json.loads(capsys.readouterr().out))
    assert outputs[0] == outputs[1] == outputs[2]
    assert _outbox(tmp_path / "source").stats()["total"] == 1
    assert main([
        "export-envelope", "--workspace", str(tmp_path / "source"),
        "--identity-file", str(tmp_path / "source-key.json"), "--spine-file", "spine.jsonl",
        "--message-id", outputs[0]["message_id"],
    ]) == 0
    assert json.loads(capsys.readouterr().out) == outputs[0]


def test_pack_renewal_is_explicit_and_only_after_expiry(tmp_path: Path, monkeypatch, capsys) -> None:
    from nth_dao.cli.source_receipt_delivery import _outbox, main

    authority, _, proof, response, _, _, now = _delivery(tmp_path)
    args = _pack_args(tmp_path, authority, proof, response) + ["--ttl-seconds", "1"]
    monkeypatch.setattr("nth_dao.cli.source_receipt_delivery.time.time", lambda: now / 1000)
    assert main(args) == 0
    first = json.loads(capsys.readouterr().out)
    renewal = args + ["--renew", "--renew-from", first["message_id"]]
    assert main(renewal) == 1
    assert capsys.readouterr().out == ""
    monkeypatch.setattr("nth_dao.cli.source_receipt_delivery.time.time", lambda: (now + 2_000) / 1000)
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out) == first
    assert main(renewal) == 0
    renewed = json.loads(capsys.readouterr().out)
    assert renewed["message_id"] != first["message_id"]
    assert renewed["created_at_ms"] == now + 2_000
    assert _outbox(tmp_path / "source").stats()["total"] == 2
    assert len(list((tmp_path / "source/.nth/source_receipt_delivery_outbox/prepared").glob("*/*.json"))) == 2
    assert main(renewal) == 0
    assert json.loads(capsys.readouterr().out) == renewed
    assert _outbox(tmp_path / "source").stats()["total"] == 2


@pytest.mark.parametrize("failure", ["audit", "enqueue"])
def test_renewal_failure_retries_exact_operation_after_restart(
    tmp_path: Path, monkeypatch, capsys, failure: str,
) -> None:
    from nth_dao.cli.source_receipt_delivery import _outbox, main

    authority, _, proof, response, _, _, now = _delivery(tmp_path)
    args = _pack_args(tmp_path, authority, proof, response) + ["--ttl-seconds", "60"]
    monkeypatch.setattr("nth_dao.cli.source_receipt_delivery.time.time", lambda: now / 1000)
    assert main(args) == 0
    first = json.loads(capsys.readouterr().out)
    renewal = args + ["--renew", "--renew-from", first["message_id"]]
    monkeypatch.setattr("nth_dao.cli.source_receipt_delivery.time.time", lambda: (now + 61_000) / 1000)

    def fail(*_args, **_kwargs):
        raise OSError("injected renewed preparation failure")

    with monkeypatch.context() as patch:
        patch.setattr(SignedEventLog if failure == "audit" else DurableOutbox,
                      "append_unique" if failure == "audit" else "enqueue", fail)
        assert main(renewal) == 1
    assert capsys.readouterr().out == ""
    files = sorted((tmp_path / "source/.nth/source_receipt_delivery_outbox/prepared").glob("*/*.json"))
    assert len(files) == 2
    expected = json.loads(files[1].read_bytes())
    assert main(renewal) == 0
    assert json.loads(capsys.readouterr().out) == expected
    assert main(renewal) == 0
    assert json.loads(capsys.readouterr().out) == expected
    assert _outbox(tmp_path / "source").stats()["total"] == 2


@pytest.mark.parametrize("renewal_args", [
    ["--renew"], ["--renew", "--renew-from", "invalid"],
    ["--renew", "--renew-from", "sha256:" + "a" * 64],
    ["--renew-from", "sha256:" + "a" * 64],
])
def test_renewal_requires_exact_retained_predecessor(tmp_path: Path, capsys, renewal_args) -> None:
    from nth_dao.cli.source_receipt_delivery import main

    authority, _, proof, response, _, _, _ = _delivery(tmp_path)
    args = _pack_args(tmp_path, authority, proof, response)
    assert main(args) == 0
    capsys.readouterr()
    assert main(args + renewal_args) == 1
    assert capsys.readouterr().out == ""
    assert len(list((tmp_path / "source/.nth/source_receipt_delivery_outbox/prepared").glob("*/*.json"))) == 1


def test_failed_pack_audit_retries_same_prepared_bytes(tmp_path: Path, monkeypatch, capsys) -> None:
    from nth_dao.cli.source_receipt_delivery import main

    authority, _, proof, response, _, _, _ = _delivery(tmp_path)
    args = _pack_args(tmp_path, authority, proof, response)

    def fail(*_args, **_kwargs):
        raise OSError("injected preparation audit failure")

    with monkeypatch.context() as patch:
        patch.setattr(SignedEventLog, "append_unique", fail)
        assert main(args) == 1
    assert capsys.readouterr().out == ""
    files = list((tmp_path / "source/.nth/source_receipt_delivery_outbox/prepared").glob("*/*.json"))
    assert len(files) == 1
    retained = json.loads(files[0].read_bytes())
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out) == retained


def test_pack_cross_process_retries_share_one_generation(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from nth_dao.cli.source_receipt_delivery import _outbox
    from nth_dao.market.announcement import (
        TaskAnnouncement,
        announcement_federation_key,
    )

    authority, _, proof, response, _, _, _ = _delivery(tmp_path)
    namespace = SimpleNamespace(
        workspace=tmp_path / "source", source_did=authority.as_did(),
        federation_key=announcement_federation_key(TaskAnnouncement.from_dict(proof["announcement"])),
        ttl_seconds=600, renew=False,
    )
    args = (namespace, authority, proof, response)
    with ProcessPoolExecutor(max_workers=3, mp_context=multiprocessing.get_context("spawn")) as pool:
        results = list(pool.map(_pack_in_process, [args] * 6))
    assert len(set(results)) == 1
    assert _outbox(tmp_path / "source").stats()["total"] == 1


def test_expired_packet_is_rejected_before_proof_reconstruction(tmp_path: Path, monkeypatch) -> None:
    authority, _, _, _, envelope, receiver, now = _delivery(tmp_path)
    expired = _resign(authority, envelope, created_at_ms=now - 60_001, expires_at_ms=now - 1)

    def unexpected(*_args, **_kwargs):
        pytest.fail("expired new intake must not reconstruct its proof")

    monkeypatch.setattr("nth_dao.market.source_receipt_delivery.build_portable_completion_proof_with_pins", unexpected)
    with pytest.raises(SourceReceiptDeliveryRejected, match="expired"):
        receiver.receive(expired)


def test_cli_can_export_an_expired_success_ack(tmp_path: Path, monkeypatch, capsys) -> None:
    from nth_dao.cli.source_receipt_delivery import main

    _, claimant, proof, _, envelope, receiver, now = _delivery(tmp_path)
    first = receiver.receive(envelope)
    key = tmp_path / "claimant-key.json"
    claimant.save(key)
    monkeypatch.setattr("nth_dao.cli.source_receipt_delivery.time.time", lambda: (now + 120_000) / 1000)
    assert main([
        "export-ack", "--workspace", str(receiver.workspace), "--identity-file", str(key),
        "--spine-file", "spine.jsonl", "--nonce", proof["nonce"],
        "--message-id", envelope.message_id,
    ]) == 0
    assert json.loads(capsys.readouterr().out)["ack"] == first.ack.to_dict()


def test_cli_does_not_generate_missing_keys_or_accept_duplicate_json(tmp_path: Path, capsys) -> None:
    from nth_dao.cli.source_receipt_delivery import main

    _, claimant, proof, _, _, _, _ = _delivery(tmp_path)
    key = tmp_path / "key.json"
    claimant.save(key)
    missing = tmp_path / "missing-key.json"
    envelope_file = tmp_path / "duplicate.json"
    envelope_file.write_text('{"version":1,"version":1}', encoding="utf-8")
    args = [
        "receive", "--workspace", str(tmp_path / "claimant"),
        "--spine-file", "spine.jsonl", "--identity-file", str(missing),
        "--nonce", proof["nonce"], "--envelope-file", str(envelope_file),
    ]
    assert main(args) == 1
    assert not missing.exists()
    assert capsys.readouterr().out == ""
    args[args.index(str(missing))] = str(key)
    assert main(args) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert "repeats a field" in output.err


def test_cli_rejects_non_regular_and_oversized_inputs(tmp_path: Path) -> None:
    from nth_dao.cli.source_receipt_delivery import _read

    with pytest.raises(ValueError, match="regular file"):
        _read(tmp_path, 100)
    path = tmp_path / "oversized.json"
    path.write_bytes(b" " * 101)
    with pytest.raises(ValueError, match="bounded"):
        _read(path, 100)


def test_delivery_preserves_large_signed_integer_as_text(tmp_path: Path) -> None:
    from nth_dao.market.announcement import (
        TaskAnnouncement,
        announcement_federation_key,
    )
    from nth_dao.spine.event import sign_event

    authority, _, proof, response, envelope, receiver, now = _delivery(tmp_path)
    signed = response["source_receipt_event"]
    event = sign_event(
        seq=2**53 + 1, prev_hash=signed["prev_hash"], event_type=signed["type"],
        payload=signed["payload"], identity=authority, ts_ms=signed["ts_ms"],
    )
    response = {**response, "source_receipt_event": event.to_dict(), "audit_event_id": event.event_id}
    envelope = create_source_receipt_delivery(
        authority, proof, response, expected_source_did=authority.as_did(),
        expected_federation_key=announcement_federation_key(TaskAnnouncement.from_dict(proof["announcement"])),
        created_at_ms=now, expires_at_ms=now + 60_000,
    )
    assert '"seq":9007199254740993' in envelope.payload["source_receipt_json"]
    result = receiver.receive(envelope)
    assert result.observation["receipt_verified"] is True
    assert result.observation["audit_inclusion_verified"] is False


def test_public_wire_vector_has_real_signatures_and_complete_proof() -> None:
    from nth_dao.delivery.acknowledgement import DeliveryAck
    from nth_dao.delivery.envelope import (
        TransportEnvelope,
        envelope_digest,
        validate_envelope,
    )
    from nth_dao.market.source_completion_receipt import (
        verify_source_completion_receipt,
    )
    from nth_dao.market.source_receipt_delivery import _receipt

    vector = json.loads((
        Path(__file__).parents[1] / "nth_dao/market/vectors/source-receipt-delivery-v1.json"
    ).read_text(encoding="utf-8"))
    assert vector["format"] == "nth-market-source-receipt-delivery-v1"
    envelope = TransportEnvelope.from_dict(vector["envelope"])
    assert validate_envelope(envelope, now_ms=vector["now_ms"]) == (True, "ok")
    assert envelope_digest(envelope) == vector["envelope_sha256"]
    assert envelope.recipient == vector["expected_recipient_did"]
    _, event, chain = _receipt(envelope)
    assert event["seq"] == 2**53 + 1
    assert verify_source_completion_receipt(
        vector["proof"], event, expected_source_did=vector["expected_source_did"],
        expected_federation_key=vector["expected_federation_key"], rotation_chain=chain,
    ) == (True, "ok")
    ack = DeliveryAck.from_dict(vector["ack"])
    assert validate_ack(ack, now_ms=vector["now_ms"]) == (True, "ok")
    assert ack.message_id == envelope.message_id
    assert ack.envelope_sha256 == vector["envelope_sha256"]
    assert ack.receiver_did == envelope.recipient
    from dataclasses import replace

    from nth_dao.delivery.envelope import MAX_CLOCK_SKEW_MS
    from nth_dao.delivery.outbox import _ack_within_lifetime

    assert vector["clock_skew_ms"] == MAX_CLOCK_SKEW_MS
    for item in vector["ack_time_cases"]:
        boundary = envelope.created_at_ms if item["boundary"] == "created" else envelope.expires_at_ms
        receipt_time = boundary + item["offset_ms"]
        assert validate_envelope(envelope, now_ms=receipt_time)[0] is item["accepted"]
        assert _ack_within_lifetime(replace(ack, received_at_ms=receipt_time), envelope) is item["accepted"]


def test_capacity_does_not_evict_fresh_replay_history(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("nth_dao.market.source_receipt_delivery._MAX_DELIVERIES_PER_CLAIM", 2)
    authority, _, _, _, envelope, receiver, _ = _delivery(tmp_path)
    receiver.receive(envelope)
    second = _resign(authority, envelope, nonce="B" * 32)
    receiver.receive(second)
    with pytest.raises(SourceReceiptDeliveryRejected, match="capacity"):
        receiver.receive(_resign(authority, envelope, nonce="C" * 32))
    assert receiver.inbox.seen(envelope.message_id)
    assert receiver.receive(envelope).observation["already_observed"] is True


def test_linklike_inbox_journal_is_checked_again_at_intake(tmp_path: Path, monkeypatch) -> None:
    _, _, _, _, envelope, receiver, _ = _delivery(tmp_path)
    monkeypatch.setattr(
        "nth_dao.market.source_receipt_delivery.path_is_linklike",
        lambda path: path.name == "inbox.cache.jsonl",
    )
    with pytest.raises(SourceReceiptDeliveryRejected, match="traverses a link"):
        receiver.receive(envelope)
    assert receiver.inbox.entry_count() == 0


def test_cross_process_delivery_has_one_observation_and_identical_ack(tmp_path: Path) -> None:
    _, claimant, proof, _, envelope, _, now = _delivery(tmp_path)
    args = (tmp_path / "claimant", claimant, proof["nonce"], envelope, now)
    with ProcessPoolExecutor(max_workers=2, mp_context=multiprocessing.get_context("spawn")) as pool:
        results = list(pool.map(_receive_in_process, [args] * 4))
    assert len(set(results)) == 1


def test_directed_delivery_accepts_only_authenticated_source_rotation(tmp_path: Path) -> None:
    from nth_dao.market.announcement import announcement_federation_key
    from nth_dao.market.source_identity import record_source_identity_rotation

    source, old, claimant, announcement, proof = _source_and_proof(tmp_path)
    successor = AgentIdentity.generate(label="successor")
    record_source_identity_rotation(source, old, successor)
    response = SourceCompletionInbox(
        source, source_did=successor.as_did(), spine=SignedEventLog(source / "spine.jsonl", successor),
    ).record(proof)
    now = int(time.time() * 1000)
    envelope = create_source_receipt_delivery(
        successor, proof, response, expected_source_did=old.as_did(),
        expected_federation_key=announcement_federation_key(announcement),
        created_at_ms=now, expires_at_ms=now + 60_000,
    )
    receiver = SourceReceiptDeliveryReceiver(
        tmp_path / "claimant", nonce=proof["nonce"], identity=claimant,
        spine=SignedEventLog(tmp_path / "claimant" / "spine.jsonl", claimant), clock=lambda: now,
    )
    assert receiver.receive(envelope).observation["receipt_verified"] is True
    with pytest.raises(SourceReceiptDeliveryRejected, match="pinned source"):
        create_source_receipt_delivery(
            successor, proof, {**response, "source_rotation_chain": []},
            expected_source_did=old.as_did(),
            expected_federation_key=announcement_federation_key(announcement),
            created_at_ms=now, expires_at_ms=now + 60_000,
        )


def test_cli_rejects_validly_signed_ack_from_wrong_recipient(tmp_path: Path, capsys) -> None:
    from nth_dao.cli.source_receipt_delivery import main
    from nth_dao.delivery.acknowledgement import sign_ack
    from nth_dao.delivery.envelope import envelope_digest

    authority, _, _, _, envelope, _, now = _delivery(tmp_path)
    _prepare_source(tmp_path, authority, envelope)
    source = tmp_path / "source"
    outbox = DurableOutbox(source / ".nth/source_receipt_delivery_outbox", clock=lambda: now)
    outbox.enqueue(envelope)
    key = tmp_path / "key.json"
    authority.save(key)
    stranger = AgentIdentity.generate(label="stranger")
    ack = sign_ack(
        stranger, message_id=envelope.message_id,
        envelope_sha256=envelope_digest(envelope), received_at_ms=now,
    )
    ack_file = tmp_path / "ack.json"
    ack_file.write_bytes(canonical_json(ack.to_dict()))
    assert main([
        "acknowledge", "--workspace", str(source), "--identity-file", str(key),
        "--spine-file", "spine.jsonl", "--ack-file", str(ack_file),
    ]) == 1
    assert capsys.readouterr().out == ""
    assert outbox.get(envelope.message_id).state != OUTBOX_STATE_DELIVERED


def test_cli_ack_audit_failure_is_explicit_and_retryable(tmp_path: Path, capsys, monkeypatch) -> None:
    from nth_dao.cli.source_receipt_delivery import main
    from nth_dao.delivery.acknowledgement import sign_ack
    from nth_dao.delivery.envelope import envelope_digest

    authority, claimant, _, _, envelope, _, now = _delivery(tmp_path)
    _prepare_source(tmp_path, authority, envelope)
    source = tmp_path / "source"
    outbox = DurableOutbox(source / ".nth/source_receipt_delivery_outbox", clock=lambda: now)
    outbox.enqueue(envelope)
    key = tmp_path / "key.json"
    authority.save(key)
    ack = sign_ack(
        claimant, message_id=envelope.message_id,
        envelope_sha256=envelope_digest(envelope), received_at_ms=now,
    )
    ack_file = tmp_path / "ack.json"
    ack_file.write_bytes(canonical_json(ack.to_dict()))
    args = [
        "acknowledge", "--workspace", str(source), "--identity-file", str(key),
        "--spine-file", "spine.jsonl", "--ack-file", str(ack_file),
    ]

    def fail(*_args, **_kwargs):
        raise OSError("injected source ACK audit failure")

    append = SignedEventLog.append_unique
    monkeypatch.setattr(SignedEventLog, "append_unique", fail)
    assert main(args) == 1
    assert capsys.readouterr().out == ""
    assert outbox.get(envelope.message_id).state == OUTBOX_STATE_DELIVERED
    monkeypatch.setattr(SignedEventLog, "append_unique", append)
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["state"] == OUTBOX_STATE_DELIVERED


@pytest.mark.parametrize("mutation", ["kind", "unprepared", "preparation"])
def test_cli_ack_requires_receipt_domain_and_matching_preparation(tmp_path: Path, capsys, mutation: str) -> None:
    from nth_dao.cli.source_receipt_delivery import main
    from nth_dao.delivery.acknowledgement import sign_ack
    from nth_dao.delivery.envelope import envelope_digest

    authority, claimant, _, _, envelope, _, now = _delivery(tmp_path)
    if mutation == "kind":
        envelope = _resign(authority, envelope, kind="chat.message")
    elif mutation == "preparation":
        payload = source_receipt_preparation_payload(envelope)
        payload["envelope_sha256"] = "sha256:" + "0" * 64
        SignedEventLog(tmp_path / "source" / "spine.jsonl", authority).append_unique(
            SOURCE_RECEIPT_DELIVERY_PREPARED_EVENT, payload, unique_payload_fields=("message_id",),
        )
    outbox = DurableOutbox(tmp_path / "source/.nth/source_receipt_delivery_outbox", clock=lambda: now)
    outbox.enqueue(envelope)
    key = tmp_path / "key.json"
    authority.save(key)
    ack = sign_ack(claimant, message_id=envelope.message_id,
                   envelope_sha256=envelope_digest(envelope), received_at_ms=now)
    ack_file = tmp_path / "ack.json"
    ack_file.write_bytes(canonical_json(ack.to_dict()))
    assert main([
        "acknowledge", "--workspace", str(tmp_path / "source"), "--identity-file", str(key),
        "--spine-file", "spine.jsonl", "--ack-file", str(ack_file),
    ]) == 1
    assert capsys.readouterr().out == ""
    assert outbox.get(envelope.message_id).state != OUTBOX_STATE_DELIVERED
    assert SignedEventLog(tmp_path / "source/spine.jsonl", authority).find_unique_event(
        "market.claim.completion.source_receipt.delivery.acknowledged",
        payload_field="message_id", payload_value=envelope.message_id,
    ) is None


@pytest.mark.parametrize("relative", ["../outside", "C:outside", "D:outside", "events.jsonl:stream"])
def test_workspace_path_guard_rejects_drive_relative_and_stream_paths(tmp_path: Path, relative: str) -> None:
    from nth_dao.market.source_receipt_delivery import _checked_path

    with pytest.raises(SourceReceiptDeliveryRejected, match="inside its workspace"):
        _checked_path(tmp_path, Path(relative))


def test_pack_does_not_write_through_a_hardlinked_journal(tmp_path: Path, capsys) -> None:
    import os

    from nth_dao.cli.source_receipt_delivery import main

    authority, _, proof, response, _, _, _ = _delivery(tmp_path)
    args = _pack_args(tmp_path, authority, proof, response)
    directory = tmp_path / "source/.nth/source_receipt_delivery_outbox"
    directory.mkdir(parents=True)
    target = tmp_path / "test-owned-unrelated.bin"
    target.write_bytes(b"")
    os.link(target, directory / "outbox.journal.jsonl")
    assert main(args) == 1
    assert capsys.readouterr().out == ""
    assert target.read_bytes() == b""


@pytest.mark.parametrize("component", ["claimant-lock", "spine-lock", "spine-journal", "spine-pending"])
def test_receiver_rechecks_nested_storage_links_at_operation_time(tmp_path: Path, component: str) -> None:
    import os

    from nth_dao.util.io import InterProcessLock

    _, _, proof, _, envelope, receiver, _ = _delivery(tmp_path)
    if component == "claimant-lock":
        path = InterProcessLock(receiver.store._lock_target(proof["source_claim_id"])).lock_path
    elif component == "spine-lock":
        path = InterProcessLock(receiver.spine._path).lock_path
    elif component == "spine-journal":
        path = receiver.spine._path
    else:
        path = receiver.spine._pending_path
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.rename(path.with_suffix(path.suffix + ".test-saved"))
    target = tmp_path / "test-owned-unrelated.bin"
    original = b"test-owned bytes"
    target.write_bytes(original)
    os.link(target, path)
    with pytest.raises(ValueError, match="independent regular"):
        receiver.receive(envelope)
    assert target.read_bytes() == original
    assert not receiver._result_path(envelope.message_id).exists()
