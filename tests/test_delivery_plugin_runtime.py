"""Governed PluginHost bridge tests for the durable delivery runtime."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.delivery.acknowledgement import sign_ack
from nth_dao.delivery.envelope import sign_envelope
from nth_dao.delivery.inbox import DeliveryInbox, DeliveryInboxCacheCorrupt
from nth_dao.delivery.outbox import OUTBOX_STATE_DELIVERED, DurableOutbox
from nth_dao.delivery.plugin_runtime import (
    PluginDeliveryRuntime,
    PluginDeliveryRuntimeError,
)
from nth_dao.identity import AgentIdentity
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
from nth_dao.plugins.transport import (
    TRANSPORT_CAPABILITY_ID,
    transport_envelope_digest,
)

pytest.importorskip("nacl")


def _authority(principal: str, *routes: str) -> InvocationAuthority:
    return InvocationAuthority(
        principal=principal,
        capability_ids=frozenset({TRANSPORT_CAPABILITY_ID}),
        resource_ids=frozenset(routes),
    )


def _enabled_binding(tmp_path: Path):
    host = PluginHost(policy=PluginHostPolicy(), workspace_root=tmp_path)
    manifest = register_loopback_transport(host)
    host.authorize(manifest.plugin_id, set())
    return host, host.enable(manifest.plugin_id)[0]


def _runtime(
    tmp_path: Path,
    *,
    name: str,
    identity: AgentIdentity,
    binding,
    routes: tuple[str, ...] = (),
    authorize=None,
) -> PluginDeliveryRuntime:
    now_ms = int(time.time() * 1_000)
    return PluginDeliveryRuntime(
        binding=binding,
        authority=_authority(identity.as_did(), *routes),
        route_resolver=loopback_route_id,
        outbox=DurableOutbox(tmp_path / name / "outbox", clock=lambda: now_ms),
        inbox=DeliveryInbox(
            tmp_path / name / "inbox",
            authorize=authorize,
            clock=lambda: now_ms,
        ),
        clock=lambda: now_ms,
    )


def _envelope(sender: AgentIdentity, recipient: str):
    now_ms = int(time.time() * 1_000)
    return sign_envelope(
        sender,
        kind="chat.message",
        recipient=recipient,
        payload={"body": "hello"},
        created_at_ms=now_ms,
        expires_at_ms=now_ms + 60_000,
    )


def test_plugin_runtime_persists_before_transport_ack_and_applies_signed_ack(
    tmp_path: Path,
) -> None:
    _, binding = _enabled_binding(tmp_path)
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    bob_route = loopback_route_id(bob.as_did())
    alice_runtime = _runtime(
        tmp_path,
        name="alice",
        identity=alice,
        binding=binding,
        routes=(bob_route,),
    )
    bob_runtime = _runtime(
        tmp_path,
        name="bob",
        identity=bob,
        binding=binding,
        authorize=lambda item: (item.recipient == bob.as_did(), "wrong recipient"),
    )
    envelope = _envelope(alice, bob.as_did())

    assert alice_runtime.submit(envelope).accepted is True
    received = bob_runtime.receive(receive_id="receive-1")

    assert received.found is True
    assert received.transport_acknowledged is True
    assert received.decisions[0].accepted is True
    assert bob_runtime.inbox.pending()[0].message_id == envelope.message_id

    ack = sign_ack(
        bob,
        message_id=envelope.message_id,
        envelope_sha256=received.decisions[0].envelope_sha256,
        received_at_ms=int(time.time() * 1_000),
    )
    delivered = alice_runtime.apply_ack(ack)
    assert delivered.state == OUTBOX_STATE_DELIVERED
    assert delivered.delivered_by == bob.as_did()

    empty = bob_runtime.receive(receive_id="receive-2")
    assert empty.found is False
    assert empty.transport_acknowledged is False
    assert empty.decisions == ()


def test_send_only_runtime_has_no_receive_side_effects(tmp_path: Path, monkeypatch) -> None:
    host, binding = _enabled_binding(tmp_path)
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    runtime = PluginDeliveryRuntime(
        binding=binding, authority=_authority(alice.as_did(), loopback_route_id(bob.as_did())),
        route_resolver=loopback_route_id, outbox=DurableOutbox(tmp_path / "outbox"),
    )
    assert runtime.principal == alice.as_did()
    assert runtime.submit(_envelope(alice, bob.as_did())).accepted

    def unexpected(*args, **kwargs):
        pytest.fail("receive without an inbox must not invoke the provider")

    monkeypatch.setattr(host, "invoke", unexpected)
    with pytest.raises(PluginDeliveryRuntimeError, match="not configured"):
        runtime.receive(receive_id="unconfigured")


def test_submit_uses_only_the_durably_queued_snapshot(tmp_path: Path, monkeypatch) -> None:
    host, binding = _enabled_binding(tmp_path)
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    envelope = _envelope(alice, bob.as_did())
    expected = canonical_json(envelope.to_dict()).decode("utf-8")
    runtime = _runtime(tmp_path, name="alice", identity=alice, binding=binding,
                       routes=(loopback_route_id(bob.as_did()),))
    original_enqueue = runtime.outbox.enqueue
    original_invoke = host.invoke
    submitted = []

    def enqueue_and_mutate(candidate, **kwargs):
        record = original_enqueue(candidate, **kwargs)
        candidate.recipient = alice.as_did()
        candidate.payload.clear()
        envelope.signature = "mutated"
        return record

    def capture(binding_arg, payload, *, authority):
        if payload.get("operation") == "send":
            submitted.append(dict(payload))
        return original_invoke(binding_arg, payload, authority=authority)

    monkeypatch.setattr(runtime.outbox, "enqueue", enqueue_and_mutate)
    monkeypatch.setattr(host, "invoke", capture)
    assert runtime.submit(envelope).accepted
    assert submitted[0]["envelope_json"] == expected
    assert submitted[0]["destination_route_id"] == loopback_route_id(bob.as_did())


def test_submit_rejects_malformed_input_without_queueing(tmp_path: Path) -> None:
    _, binding = _enabled_binding(tmp_path)
    alice = AgentIdentity.generate(label="alice")
    runtime = _runtime(tmp_path, name="alice", identity=alice, binding=binding)
    assert not runtime.submit({"not": "an envelope"}).accepted
    assert runtime.outbox.stats()["total"] == 0


def test_plugin_runtime_recovers_after_crash_window_before_transport_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, binding = _enabled_binding(tmp_path)
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    bob_route = loopback_route_id(bob.as_did())
    alice_runtime = _runtime(
        tmp_path,
        name="alice",
        identity=alice,
        binding=binding,
        routes=(bob_route,),
    )
    bob_runtime = _runtime(
        tmp_path,
        name="bob",
        identity=bob,
        binding=binding,
        authorize=lambda item: (True, "ok"),
    )
    envelope = _envelope(alice, bob.as_did())
    assert alice_runtime.submit(envelope).accepted is True

    original_invoke = host.invoke

    def fail_ack_once(binding_arg, payload, *, authority):
        if payload.get("operation") == "ack":
            raise PluginInvocationError("simulated crash before provider ack")
        return original_invoke(binding_arg, payload, authority=authority)

    monkeypatch.setattr(host, "invoke", fail_ack_once)
    with pytest.raises(PluginDeliveryRuntimeError, match="receive failed"):
        bob_runtime.receive(receive_id="receive-crash")
    assert bob_runtime.inbox.seen(envelope.message_id) is True

    monkeypatch.setattr(host, "invoke", original_invoke)
    replay = bob_runtime.receive(receive_id="receive-crash")
    assert replay.replayed is True
    assert replay.transport_acknowledged is True
    assert replay.decisions[0].duplicate is True


def test_plugin_runtime_keeps_lease_for_transient_inbox_failure(
    tmp_path: Path,
) -> None:
    _, binding = _enabled_binding(tmp_path)
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    bob_route = loopback_route_id(bob.as_did())
    alice_runtime = _runtime(
        tmp_path,
        name="alice",
        identity=alice,
        binding=binding,
        routes=(bob_route,),
    )
    allow = False

    def authorize(_):
        if not allow:
            raise RuntimeError("authorization database unavailable")
        return True, "ok"

    bob_runtime = _runtime(
        tmp_path,
        name="bob",
        identity=bob,
        binding=binding,
        authorize=authorize,
    )
    envelope = _envelope(alice, bob.as_did())
    assert alice_runtime.submit(envelope).accepted is True

    first = bob_runtime.receive(receive_id="receive-transient")
    assert first.transport_acknowledged is False
    assert first.decisions[0].reason == "authorization callback failed"

    allow = True
    second = bob_runtime.receive(receive_id="receive-transient")
    assert second.replayed is True
    assert second.transport_acknowledged is True
    assert second.decisions[0].accepted is True


def test_plugin_runtime_rejects_routes_outside_host_authority(tmp_path: Path) -> None:
    _, binding = _enabled_binding(tmp_path)
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    runtime = _runtime(
        tmp_path,
        name="alice",
        identity=alice,
        binding=binding,
    )
    envelope = _envelope(alice, bob.as_did())

    with pytest.raises(PluginDeliveryRuntimeError, match="invocation failed"):
        runtime.submit(envelope)

    record = runtime.outbox.get(envelope.message_id)
    assert record is not None
    assert record.attempts[-1].error_code == "plugin-invocation-failed"


def test_plugin_runtime_observes_host_binding_revocation(tmp_path: Path) -> None:
    host, binding = _enabled_binding(tmp_path)
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    bob_route = loopback_route_id(bob.as_did())
    runtime = _runtime(
        tmp_path,
        name="alice",
        identity=alice,
        binding=binding,
        routes=(bob_route,),
    )
    assert host.disable(binding.plugin_id) is True

    with pytest.raises(PluginDeliveryRuntimeError, match="invocation failed"):
        runtime.submit(_envelope(alice, bob.as_did()))


def test_plugin_runtime_quarantines_provider_id_substitution_before_lease_ack(tmp_path: Path) -> None:
    _, binding = _enabled_binding(tmp_path)
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    bob_route = loopback_route_id(bob.as_did())
    envelope = _envelope(alice, bob.as_did())
    encoded = canonical_json(envelope.to_dict()).decode("utf-8")
    binding.invoke(
        {
            "operation": "send",
            "delivery_id": "substituted-delivery-id",
            "destination_route_id": bob_route,
            "envelope_json": encoded,
            "envelope_sha256": transport_envelope_digest(encoded),
            "expires_at_ms": envelope.expires_at_ms,
        },
        authority=_authority(alice.as_did(), bob_route),
    )
    bob_runtime = _runtime(
        tmp_path,
        name="bob",
        identity=bob,
        binding=binding,
        authorize=lambda item: (True, "ok"),
    )

    result = bob_runtime.receive(receive_id="receive-substitution")
    assert result.transport_acknowledged
    assert not result.decisions[0].accepted and not result.decisions[0].duplicate
    assert "delivery_id" in result.decisions[0].reason
    retained = list((tmp_path / "bob/inbox/transport_quarantine").glob("*.json"))
    assert len(retained) == 1
    assert json.loads(retained[0].read_bytes())["item"]["envelope_json"] == encoded
    assert bob_runtime.inbox.seen(envelope.message_id) is False


def test_plugin_runtime_quarantines_provider_expiry_substitution_before_lease_ack(
    tmp_path: Path,
) -> None:
    _, binding = _enabled_binding(tmp_path)
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    bob_route = loopback_route_id(bob.as_did())
    envelope = _envelope(alice, bob.as_did())
    encoded = canonical_json(envelope.to_dict()).decode("utf-8")
    binding.invoke(
        {
            "operation": "send",
            "delivery_id": envelope.message_id,
            "destination_route_id": bob_route,
            "envelope_json": encoded,
            "envelope_sha256": transport_envelope_digest(encoded),
            "expires_at_ms": envelope.expires_at_ms + 1_000,
        },
        authority=_authority(alice.as_did(), bob_route),
    )
    bob_runtime = _runtime(
        tmp_path,
        name="bob",
        identity=bob,
        binding=binding,
        authorize=lambda item: (True, "ok"),
    )

    result = bob_runtime.receive(receive_id="receive-expiry-substitution")
    assert result.transport_acknowledged
    assert not result.decisions[0].accepted and "expiry" in result.decisions[0].reason
    assert len(list((tmp_path / "bob/inbox/transport_quarantine").glob("*.json"))) == 1
    assert bob_runtime.inbox.seen(envelope.message_id) is False


@pytest.mark.parametrize("field", ["delivery_id", "expires_at_ms"])
def test_poisoned_first_item_does_not_block_valid_sibling(tmp_path, field):
    host, binding = _enabled_binding(tmp_path)
    alice, bob = AgentIdentity.generate(label="alice"), AgentIdentity.generate(label="bob")
    envelope = _envelope(alice, bob.as_did())
    raw = canonical_json(envelope.to_dict()).decode("utf-8")
    payload = {
        "operation": "send", "delivery_id": "poison-first",
        "destination_route_id": loopback_route_id(bob.as_did()),
        "envelope_json": raw, "envelope_sha256": transport_envelope_digest(raw),
        "expires_at_ms": envelope.expires_at_ms,
    }
    if field == "expires_at_ms":
        payload["delivery_id"] = envelope.message_id
        payload["expires_at_ms"] += 1000
    binding.invoke(payload, authority=_authority(alice.as_did(), loopback_route_id(bob.as_did())))
    valid = _envelope(alice, bob.as_did())
    sender = _runtime(tmp_path, name="alice", identity=alice, binding=binding,
                      routes=(loopback_route_id(bob.as_did()),))
    assert sender.submit(valid).accepted
    receiver = _runtime(tmp_path, name="bob", identity=bob, binding=binding,
                        authorize=lambda item: (item.recipient == bob.as_did(), "wrong recipient"))
    original = host.invoke

    def require_durable_quarantine(binding_arg, request, *, authority):
        if request["operation"] == "ack":
            assert len(list((tmp_path / "bob/inbox/transport_quarantine").glob("*.json"))) == 1
            assert receiver.inbox.seen(valid.message_id)
        return original(binding_arg, request, authority=authority)

    from unittest.mock import patch

    with patch.object(host, "invoke", require_durable_quarantine):
        received = receiver.receive(receive_id="poison-and-valid")
    assert received.transport_acknowledged
    assert len(received.decisions) == 2
    assert not received.decisions[0].accepted and received.decisions[1].accepted
    assert [item.message_id for item in receiver.inbox.pending()] == [valid.message_id]
    assert not receiver.inbox.seen(envelope.message_id)
    assert not receiver.receive(receive_id="after-quarantine").found


@pytest.mark.parametrize("quota", ["entries", "bytes"])
def test_quarantine_capacity_keeps_lease_but_retains_valid_sibling(tmp_path, monkeypatch, quota):
    from nth_dao.delivery import inbox as inbox_module

    _, binding = _enabled_binding(tmp_path)
    alice, bob = AgentIdentity.generate(label="alice"), AgentIdentity.generate(label="bob")
    if quota == "entries":
        monkeypatch.setattr(inbox_module, "MAX_TRANSPORT_QUARANTINE_ENTRIES", 0)
    else:
        monkeypatch.setattr(inbox_module, "MAX_TRANSPORT_QUARANTINE_BYTES", 1)
    receiver = _runtime(tmp_path, name="bob", identity=bob, binding=binding)
    invalid = _envelope(alice, bob.as_did())
    raw = canonical_json(invalid.to_dict()).decode("utf-8")
    binding.invoke({
        "operation": "send", "delivery_id": "mismatched",
        "destination_route_id": loopback_route_id(bob.as_did()), "envelope_json": raw,
        "envelope_sha256": transport_envelope_digest(raw), "expires_at_ms": invalid.expires_at_ms,
    }, authority=_authority(alice.as_did(), loopback_route_id(bob.as_did())))
    sender = _runtime(tmp_path, name="alice", identity=alice, binding=binding,
                      routes=(loopback_route_id(bob.as_did()),))
    valid = _envelope(alice, bob.as_did())
    assert sender.submit(valid).accepted
    result = receiver.receive(receive_id="quarantine-full")
    assert not result.transport_acknowledged and result.decisions[0].retryable
    assert result.decisions[1].accepted and receiver.inbox.seen(valid.message_id)
    assert not receiver.inbox.seen(invalid.message_id)


def test_intake_io_error_retains_partial_progress_and_does_not_ack_batch(tmp_path, monkeypatch):
    _host, binding = _enabled_binding(tmp_path)
    alice, bob = AgentIdentity.generate(label="alice"), AgentIdentity.generate(label="bob")
    sender = _runtime(tmp_path, name="alice", identity=alice, binding=binding,
                      routes=(loopback_route_id(bob.as_did()),))
    first, second = _envelope(alice, bob.as_did()), _envelope(alice, bob.as_did())
    assert sender.submit(first).accepted and sender.submit(second).accepted
    receiver = _runtime(tmp_path, name="bob", identity=bob, binding=binding)
    accept = receiver.inbox.accept

    def fail_first(encoded, **kwargs):
        if json.loads(encoded)["message_id"] == first.message_id:
            raise OSError("first intake file temporarily unavailable")
        return accept(encoded, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(receiver.inbox, "accept", fail_first)
        with pytest.raises(PluginDeliveryRuntimeError) as caught:
            receiver.receive(receive_id="partial-io")
    partial = caught.value.partial_result
    assert caught.value.error_code == "intake-storage-unavailable"
    assert not partial.transport_acknowledged
    assert partial.decisions[0].retryable and partial.decisions[1].accepted
    assert receiver.inbox.seen(second.message_id) and not receiver.inbox.seen(first.message_id)
    recovered = receiver.receive(receive_id="partial-io")
    assert recovered.transport_acknowledged
    assert recovered.decisions[0].accepted and recovered.decisions[1].duplicate


@pytest.mark.parametrize("failure", [OSError, KeyError, ValueError])
def test_failed_local_route_resolution_creates_no_provider_attempt(tmp_path, monkeypatch, failure):
    host, binding = _enabled_binding(tmp_path)
    alice, bob = AgentIdentity.generate(label="alice"), AgentIdentity.generate(label="bob")
    sender = _runtime(tmp_path, name="alice", identity=alice, binding=binding,
                      routes=(loopback_route_id(bob.as_did()),))
    envelope = _envelope(alice, bob.as_did())

    def unavailable(_did):
        raise failure("local route unavailable")

    def forbidden(*args, **kwargs):
        pytest.fail("route failure must not invoke the transport provider")

    with monkeypatch.context() as patch:
        patch.setattr(sender, "_route_resolver", unavailable)
        patch.setattr(host, "invoke", forbidden)
        with pytest.raises(PluginDeliveryRuntimeError) as caught:
            sender.submit(envelope)
    assert caught.value.error_code == "route-resolution-failed"
    assert caught.value.retryable is (failure is not ValueError)
    assert sender.outbox.get(envelope.message_id).attempts == []
    assert sender.submit(envelope).accepted
    attempt = sender.outbox.get(envelope.message_id).attempts[0]
    assert attempt.outcome == "sent"
    from nth_dao.delivery.envelope import envelope_digest

    sender.apply_ack(sign_ack(bob, message_id=envelope.message_id,
                              envelope_sha256=envelope_digest(envelope), received_at_ms=attempt.at_ms))
    assert sender.outbox.compact() == 0


@pytest.mark.parametrize("integrity_failure", ["inbox", "transport"])
def test_receive_integrity_failure_preserves_earlier_durable_decisions(tmp_path, monkeypatch, integrity_failure):
    _host, binding = _enabled_binding(tmp_path)
    alice, bob = AgentIdentity.generate(label="alice"), AgentIdentity.generate(label="bob")
    sender = _runtime(tmp_path, name="alice", identity=alice, binding=binding,
                      routes=(loopback_route_id(bob.as_did()),))
    first, second = _envelope(alice, bob.as_did()), _envelope(alice, bob.as_did())
    assert sender.submit(first).accepted and sender.submit(second).accepted
    receiver = _runtime(tmp_path, name="bob", identity=bob, binding=binding)
    persist = receiver._persist_transport_item

    def corrupt_second(item):
        if item["delivery_id"] == second.message_id:
            if integrity_failure == "inbox":
                raise DeliveryInboxCacheCorrupt("injected intake corruption")
            raise PluginDeliveryRuntimeError(
                "injected post-validation digest change", error_code="transport-integrity-failed", retryable=False,
            )
        return persist(item)

    with monkeypatch.context() as patch:
        patch.setattr(receiver, "_persist_transport_item", corrupt_second)
        with pytest.raises(PluginDeliveryRuntimeError) as caught:
            receiver.receive(receive_id="partial-integrity")
    assert caught.value.retryable is False
    assert caught.value.error_code == (
        "intake-integrity-failed" if integrity_failure == "inbox" else "transport-integrity-failed"
    )
    partial = caught.value.partial_result
    assert len(partial.decisions) == 1 and partial.decisions[0].message_id == first.message_id
    assert partial.decisions[0].accepted and not partial.transport_acknowledged
    assert receiver.inbox.seen(first.message_id) and not receiver.inbox.seen(second.message_id)
    recovered = receiver.receive(receive_id="partial-integrity")
    assert recovered.transport_acknowledged
    assert recovered.decisions[0].duplicate and recovered.decisions[1].accepted


def test_expiry_during_route_resolution_prevents_provider_call(tmp_path, monkeypatch):
    host, binding = _enabled_binding(tmp_path)
    alice, bob = AgentIdentity.generate(label="alice"), AgentIdentity.generate(label="bob")
    envelope = _envelope(alice, bob.as_did())
    now = [envelope.created_at_ms]
    sender = _runtime(tmp_path, name="alice", identity=alice, binding=binding,
                      routes=(loopback_route_id(bob.as_did()),))
    monkeypatch.setattr(sender, "_clock", lambda: now[0])

    def delayed(did):
        now[0] = envelope.expires_at_ms
        return loopback_route_id(did)

    monkeypatch.setattr(sender, "_route_resolver", delayed)
    monkeypatch.setattr(host, "invoke", lambda *a, **kw: pytest.fail("expired route must not be sent"))
    result = sender.submit(envelope)
    assert not result.accepted and result.error_code == "outbox-terminal"
    record = sender.outbox.get(envelope.message_id)
    assert record.state == "expired" and record.attempts == []


def test_provider_io_failure_finishes_attempt_without_claiming_delivery(tmp_path, monkeypatch):
    host, binding = _enabled_binding(tmp_path)
    alice, bob = AgentIdentity.generate(label="alice"), AgentIdentity.generate(label="bob")
    sender = _runtime(tmp_path, name="alice", identity=alice, binding=binding,
                      routes=(loopback_route_id(bob.as_did()),))
    envelope = _envelope(alice, bob.as_did())
    invoke = host.invoke

    def ambiguous_send(*args, **kwargs):
        invoke(*args, **kwargs)
        raise OSError("provider response was lost after enqueue")

    with monkeypatch.context() as patch:
        patch.setattr(host, "invoke", ambiguous_send)
        with pytest.raises(PluginDeliveryRuntimeError) as caught:
            sender.submit(envelope)
    assert caught.value.error_code == "provider-io-failed"
    record = sender.outbox.get(envelope.message_id)
    assert record.state == "queued" and record.attempts[0].outcome == "error"
    assert sender.submit(envelope).accepted
    assert [item.outcome for item in sender.outbox.get(envelope.message_id).attempts] == ["error", "sent"]


def test_plugin_runtime_acks_permanently_invalid_transport_items(
    tmp_path: Path,
) -> None:
    _, binding = _enabled_binding(tmp_path)
    alice = AgentIdentity.generate(label="alice")
    bob = AgentIdentity.generate(label="bob")
    bob_route = loopback_route_id(bob.as_did())
    encoded = canonical_json({"not": "a delivery envelope"}).decode("utf-8")
    binding.invoke(
        {
            "operation": "send",
            "delivery_id": "invalid-envelope-1",
            "destination_route_id": bob_route,
            "envelope_json": encoded,
            "envelope_sha256": transport_envelope_digest(encoded),
            "expires_at_ms": int(time.time() * 1_000) + 60_000,
        },
        authority=_authority(alice.as_did(), bob_route),
    )
    bob_runtime = _runtime(
        tmp_path,
        name="bob",
        identity=bob,
        binding=binding,
        authorize=lambda item: (True, "ok"),
    )

    result = bob_runtime.receive(receive_id="receive-invalid")
    assert result.transport_acknowledged is True
    assert result.decisions[0].accepted is False
    assert result.decisions[0].reason.startswith("structure:")
    assert bob_runtime.receive(receive_id="receive-after-invalid").found is False
