"""Lifecycle, isolation, lease, and concurrency tests for loopback transport."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import threading
import time

import pytest

from nth_dao.canonical_json import canonical_json
from nth_dao.plugins.builtin.loopback_transport import (
    LOOPBACK_TRANSPORT_PLUGIN_ID,
    LoopbackTransportProvider,
    loopback_route_id,
    loopback_transport_manifest,
    register_loopback_transport,
)
from nth_dao.plugins.host import (
    InvocationAuthority,
    PluginAuthorizationError,
    PluginHost,
    PluginHostPolicy,
    PluginInvocationContext,
    PluginInvocationError,
)
from nth_dao.plugins.transport import (
    TRANSPORT_CAPABILITY_ID,
    TransportOperationError,
    transport_envelope_digest,
)
from nth_dao.web import create_app


class _Clock:
    def __init__(self, value: float = 1_750_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def _authority(principal: str) -> InvocationAuthority:
    return InvocationAuthority(
        principal=principal,
        capability_ids=frozenset({TRANSPORT_CAPABILITY_ID}),
        resource_ids=frozenset({loopback_route_id("did:key:zBob")}),
    )


def _context(principal: str) -> PluginInvocationContext:
    return PluginInvocationContext(
        plugin_id=LOOPBACK_TRANSPORT_PLUGIN_ID,
        capability_id=TRANSPORT_CAPABILITY_ID,
        invocation_id="test-invocation",
        authority=_authority(principal),
        granted_permissions=frozenset(),
        workspace_root=None,
    )


def _send(
    recipient: str,
    *,
    delivery_id: str = "delivery-1",
    body: str = "hello",
    expires_at_ms: int | None = None,
) -> dict:
    if expires_at_ms is None:
        expires_at_ms = int(time.time() * 1_000) + 60_000
    envelope_json = canonical_json(
        {"id": delivery_id, "payload": {"body": body}, "type": "chat.message"}
    ).decode("utf-8")
    return {
        "operation": "send",
        "delivery_id": delivery_id,
        "destination_route_id": loopback_route_id(recipient),
        "envelope_json": envelope_json,
        "envelope_sha256": transport_envelope_digest(envelope_json),
        "expires_at_ms": expires_at_ms,
    }


def _receive(receive_id: str = "receive-1", *, limit: int = 10, lease_ms: int = 30_000):
    return {
        "operation": "receive",
        "receive_id": receive_id,
        "limit": limit,
        "lease_ms": lease_ms,
    }


def _ack(receive: dict) -> dict:
    return {
        "operation": "ack",
        "receive_id": receive["receive_id"],
        "lease_id": receive["lease_id"],
        "batch_sha256": receive["batch_sha256"],
    }


def _enabled_binding(tmp_path: Path):
    host = PluginHost(policy=PluginHostPolicy(), workspace_root=tmp_path)
    item = register_loopback_transport(host)
    host.authorize(item.plugin_id, set())
    binding = host.enable(item.plugin_id)[0]
    return host, item, binding


def test_loopback_transport_is_installed_but_disabled_by_default(tmp_path: Path) -> None:
    host = PluginHost(policy=PluginHostPolicy(), workspace_root=tmp_path)
    item = register_loopback_transport(host)
    status = host.status(item.plugin_id)
    assert status.state == "installed"
    assert status.risk_tier == 0
    assert status.declared_permissions == ()
    assert host.resolve(TRANSPORT_CAPABILITY_ID) == ()


def test_web_registers_loopback_transport_without_enabling_it(tmp_path: Path) -> None:
    app = create_app(tmp_path)
    status = app.state.nth.plugin_host.status(LOOPBACK_TRANSPORT_PLUGIN_ID)
    assert status.state == "installed"
    assert status.desired_enabled is False
    assert app.state.nth.plugin_host.resolve(TRANSPORT_CAPABILITY_ID) == ()


def test_loopback_manifest_and_route_are_bounded_and_non_authoritative() -> None:
    item = loopback_transport_manifest()
    assert item.plugin_id == LOOPBACK_TRANSPORT_PLUGIN_ID
    assert item.kind == "transport.provider"
    assert item.permissions == ()
    assert item.provides[0].capability_id == TRANSPORT_CAPABILITY_ID
    route = loopback_route_id("did:key:zAlice")
    assert route == loopback_route_id("did:key:zAlice")
    assert route != loopback_route_id("did:key:zBob")
    assert "Alice" not in route


def test_loopback_send_receive_ack_round_trip_and_replays(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    payload = _send("did:key:zBob")
    sent = binding.invoke(payload, authority=_authority("did:key:zAlice"))
    assert sent["accepted"] is True
    assert sent["state"] == "queued"
    assert sent["replayed"] is False

    send_replay = binding.invoke(
        payload, authority=_authority("did:key:zAlice")
    )
    assert send_replay["replayed"] is True
    assert send_replay["state"] == "queued"

    received = binding.invoke(_receive(), authority=_authority("did:key:zBob"))
    assert received["found"] is True
    assert [item["delivery_id"] for item in received["items"]] == ["delivery-1"]
    receive_replay = binding.invoke(
        _receive(), authority=_authority("did:key:zBob")
    )
    assert receive_replay == {**received, "replayed": True}

    acknowledged = binding.invoke(_ack(received), authority=_authority("did:key:zBob"))
    assert acknowledged["acknowledged"] is True
    assert acknowledged["acknowledged_count"] == 1
    ack_replay = binding.invoke(_ack(received), authority=_authority("did:key:zBob"))
    assert ack_replay == {**acknowledged, "replayed": True}

    empty = binding.invoke(
        _receive("receive-2"), authority=_authority("did:key:zBob")
    )
    assert empty["found"] is False
    terminal_send = binding.invoke(
        payload, authority=_authority("did:key:zAlice")
    )
    assert terminal_send["replayed"] is True
    assert terminal_send["state"] == "acknowledged"
    assert host.status(LOOPBACK_TRANSPORT_PLUGIN_ID).state == "enabled"


def test_loopback_principal_isolation_prevents_cross_inbox_reads(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    binding.invoke(_send("did:key:zBob"), authority=_authority("did:key:zAlice"))
    wrong = binding.invoke(_receive(), authority=_authority("did:key:zMallory"))
    assert wrong["found"] is False
    right = binding.invoke(_receive(), authority=_authority("did:key:zBob"))
    assert right["found"] is True


def test_loopback_send_requires_explicit_destination_scope(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    authority = InvocationAuthority(
        principal="did:key:zAlice",
        capability_ids=frozenset({TRANSPORT_CAPABILITY_ID}),
        resource_ids=frozenset({loopback_route_id("did:key:zCarol")}),
    )
    with pytest.raises(PluginAuthorizationError, match="resource scope"):
        binding.invoke(_send("did:key:zBob"), authority=authority)
    assert host.status(LOOPBACK_TRANSPORT_PLUGIN_ID).state == "enabled"
    assert host.status(LOOPBACK_TRANSPORT_PLUGIN_ID).state == "enabled"


def test_loopback_delivery_id_and_receive_id_bind_immutable_input(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    binding.invoke(_send("did:key:zBob"), authority=_authority("did:key:zAlice"))
    with pytest.raises(TransportOperationError) as send_error:
        binding.invoke(
            _send("did:key:zBob", body="substituted"),
            authority=_authority("did:key:zAlice"),
        )
    assert send_error.value.code == "conflict"

    binding.invoke(_receive(), authority=_authority("did:key:zBob"))
    with pytest.raises(TransportOperationError) as receive_error:
        binding.invoke(
            _receive(limit=1), authority=_authority("did:key:zBob")
        )
    assert receive_error.value.code == "conflict"
    assert host.status(LOOPBACK_TRANSPORT_PLUGIN_ID).state == "enabled"


def test_loopback_ack_rejects_wrong_principal_lease_and_batch(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    binding.invoke(_send("did:key:zBob"), authority=_authority("did:key:zAlice"))
    received = binding.invoke(_receive(), authority=_authority("did:key:zBob"))
    with pytest.raises(TransportOperationError) as wrong_principal:
        binding.invoke(_ack(received), authority=_authority("did:key:zMallory"))
    assert wrong_principal.value.code == "delivery-not-found"

    wrong_lease = _ack(received)
    wrong_lease["lease_id"] = "lease:wrong"
    with pytest.raises(TransportOperationError) as lease_error:
        binding.invoke(wrong_lease, authority=_authority("did:key:zBob"))
    assert lease_error.value.code == "lease-conflict"

    wrong_batch = _ack(received)
    wrong_batch["batch_sha256"] = "0" * 64
    with pytest.raises(TransportOperationError) as batch_error:
        binding.invoke(wrong_batch, authority=_authority("did:key:zBob"))
    assert batch_error.value.code == "lease-conflict"
    assert host.status(LOOPBACK_TRANSPORT_PLUGIN_ID).state == "enabled"


def test_loopback_expired_lease_redelivers_under_new_receive_id() -> None:
    clock = _Clock()
    provider = LoopbackTransportProvider(clock=clock)
    provider.invoke(
        _send("did:key:zBob", expires_at_ms=1_750_000_060_000),
        _context("did:key:zAlice"),
    )
    first = provider.invoke(
        _receive("receive-1", lease_ms=1_000), _context("did:key:zBob")
    )
    clock.value += 2
    with pytest.raises(TransportOperationError) as old_ack:
        provider.invoke(_ack(first), _context("did:key:zBob"))
    assert old_ack.value.code == "lease-expired"
    second = provider.invoke(_receive("receive-2"), _context("did:key:zBob"))
    assert second["found"] is True
    assert second["items"] == first["items"]
    assert second["lease_id"] != first["lease_id"]


def test_loopback_expired_delivery_retry_fails_without_recreation() -> None:
    clock = _Clock()
    provider = LoopbackTransportProvider(clock=clock)
    payload = _send("did:key:zBob", expires_at_ms=1_750_000_001_000)
    provider.invoke(payload, _context("did:key:zAlice"))
    clock.value += 2
    empty = provider.invoke(_receive(), _context("did:key:zBob"))
    assert empty["found"] is False
    with pytest.raises(TransportOperationError) as retry:
        provider.invoke(payload, _context("did:key:zAlice"))
    assert retry.value.code == "expired"


def test_loopback_empty_receive_id_binds_input_for_its_lease() -> None:
    clock = _Clock()
    provider = LoopbackTransportProvider(clock=clock)
    request = _receive("empty-1", limit=3, lease_ms=1_000)
    first = provider.invoke(request, _context("did:key:zBob"))
    assert first["found"] is False
    assert first["replayed"] is False
    replay = provider.invoke(request, _context("did:key:zBob"))
    assert replay == {**first, "replayed": True}
    with pytest.raises(TransportOperationError) as conflict:
        provider.invoke(
            _receive("empty-1", limit=2, lease_ms=1_000),
            _context("did:key:zBob"),
        )
    assert conflict.value.code == "conflict"
    clock.value += 2
    reused = provider.invoke(request, _context("did:key:zBob"))
    assert reused["found"] is False
    assert reused["replayed"] is False


def test_loopback_empty_claim_quota_isolated_per_principal(monkeypatch) -> None:
    import nth_dao.plugins.builtin.loopback_transport as transport_module

    monkeypatch.setattr(
        transport_module, "LOOPBACK_TRANSPORT_MAX_CLAIMS_PER_PRINCIPAL", 2
    )
    provider = LoopbackTransportProvider(clock=_Clock())
    provider.invoke(_receive("bob-1"), _context("did:key:zBob"))
    provider.invoke(_receive("bob-2"), _context("did:key:zBob"))
    with pytest.raises(TransportOperationError) as full:
        provider.invoke(_receive("bob-3"), _context("did:key:zBob"))
    assert full.value.code == "quota-exceeded"
    assert provider.invoke(
        _receive("carol-1"), _context("did:key:zCarol")
    )["found"] is False


def test_loopback_terminal_claim_quota_releases_after_retry_window(monkeypatch) -> None:
    import nth_dao.plugins.builtin.loopback_transport as transport_module

    monkeypatch.setattr(
        transport_module, "LOOPBACK_TRANSPORT_MAX_CLAIMS_PER_PRINCIPAL", 1
    )
    monkeypatch.setattr(
        transport_module, "LOOPBACK_TRANSPORT_CLAIM_REPLAY_RETENTION_SECONDS", 1
    )
    clock = _Clock()
    provider = LoopbackTransportProvider(clock=clock)
    provider.invoke(
        _send(
            "did:key:zBob",
            delivery_id="delivery-claim-retention",
            expires_at_ms=1_750_000_060_000,
        ),
        _context("did:key:zAlice"),
    )
    received = provider.invoke(_receive("claim-1"), _context("did:key:zBob"))
    provider.invoke(_ack(received), _context("did:key:zBob"))
    with pytest.raises(TransportOperationError) as retained:
        provider.invoke(_receive("claim-2"), _context("did:key:zBob"))
    assert retained.value.code == "quota-exceeded"

    clock.value += 2
    fresh = provider.invoke(_receive("claim-2"), _context("did:key:zBob"))
    assert fresh["found"] is False


def test_loopback_sender_byte_quota_isolated_per_principal(monkeypatch) -> None:
    import nth_dao.plugins.builtin.loopback_transport as transport_module

    first = _send("did:key:zBob", delivery_id="alice-1", body="x" * 64)
    byte_length = len(first["envelope_json"].encode("utf-8"))
    monkeypatch.setattr(
        transport_module, "LOOPBACK_TRANSPORT_MAX_BYTES_PER_PRINCIPAL", byte_length
    )
    provider = LoopbackTransportProvider()
    provider.invoke(first, _context("did:key:zAlice"))
    with pytest.raises(TransportOperationError) as full:
        provider.invoke(
            _send("did:key:zBob", delivery_id="alice-2", body="x"),
            _context("did:key:zAlice"),
        )
    assert full.value.code == "quota-exceeded"
    provider.invoke(
        _send("did:key:zBob", delivery_id="carol-1", body="x"),
        _context("did:key:zCarol"),
    )


def test_loopback_assigns_unique_transport_ids_across_senders() -> None:
    clock = _Clock()
    provider = LoopbackTransportProvider(clock=clock)
    expires_at_ms = 1_750_000_060_000
    provider.invoke(
        _send("did:key:zBob", expires_at_ms=expires_at_ms),
        _context("did:key:zAlice"),
    )
    provider.invoke(
        _send("did:key:zBob", expires_at_ms=expires_at_ms),
        _context("did:key:zCarol"),
    )
    received = provider.invoke(
        _receive(limit=2),
        _context("did:key:zBob"),
    )
    assert [item["delivery_id"] for item in received["items"]] == [
        "delivery-1",
        "delivery-1",
    ]
    assert len(
        {item["transport_delivery_id"] for item in received["items"]}
    ) == 2


def test_loopback_never_evicts_unexpired_idempotency_evidence(monkeypatch) -> None:
    import nth_dao.plugins.builtin.loopback_transport as transport_module

    monkeypatch.setattr(transport_module, "LOOPBACK_TRANSPORT_MAX_TOMBSTONES", 2)
    clock = _Clock()
    provider = LoopbackTransportProvider(clock=clock)
    expires_at_ms = 1_750_000_060_000
    for index in range(2):
        payload = _send(
            "did:key:zBob",
            delivery_id=f"delivery-{index}",
            expires_at_ms=expires_at_ms,
        )
        provider.invoke(payload, _context("did:key:zAlice"))
        received = provider.invoke(
            _receive(f"receive-{index}"), _context("did:key:zBob")
        )
        provider.invoke(_ack(received), _context("did:key:zBob"))
    replay = provider.invoke(
        _send(
            "did:key:zBob",
            delivery_id="delivery-0",
            expires_at_ms=expires_at_ms,
        ),
        _context("did:key:zAlice"),
    )
    assert replay["state"] == "acknowledged"
    with pytest.raises(TransportOperationError) as full:
        provider.invoke(
            _send(
                "did:key:zBob",
                delivery_id="delivery-2",
                expires_at_ms=expires_at_ms,
            ),
            _context("did:key:zAlice"),
        )
    assert full.value.code == "quota-exceeded"


def test_loopback_idempotency_quota_isolated_per_sender(monkeypatch) -> None:
    import nth_dao.plugins.builtin.loopback_transport as transport_module

    monkeypatch.setattr(
        transport_module,
        "LOOPBACK_TRANSPORT_MAX_IDEMPOTENCY_KEYS_PER_PRINCIPAL",
        1,
    )
    provider = LoopbackTransportProvider()
    provider.invoke(
        _send("did:key:zBob", delivery_id="alice-1"),
        _context("did:key:zAlice"),
    )
    received = provider.invoke(_receive("bob-1"), _context("did:key:zBob"))
    provider.invoke(_ack(received), _context("did:key:zBob"))

    with pytest.raises(TransportOperationError) as alice_full:
        provider.invoke(
            _send("did:key:zBob", delivery_id="alice-2"),
            _context("did:key:zAlice"),
        )
    assert alice_full.value.code == "quota-exceeded"
    assert provider.invoke(
        _send("did:key:zBob", delivery_id="carol-1"),
        _context("did:key:zCarol"),
    )["accepted"] is True


def test_loopback_concurrent_receive_claims_exactly_one_batch(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    binding.invoke(_send("did:key:zBob"), authority=_authority("did:key:zAlice"))
    gate = threading.Barrier(8)

    def receive(index: int) -> dict:
        gate.wait()
        return binding.invoke(
            _receive(f"receive-{index}"), authority=_authority("did:key:zBob")
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(receive, range(8)))
    assert sum(result["found"] for result in results) == 1
    assert host.status(LOOPBACK_TRANSPORT_PLUGIN_ID).state == "enabled"


def test_loopback_batch_ack_is_atomic_for_multiple_deliveries(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    for index in range(3):
        binding.invoke(
            _send("did:key:zBob", delivery_id=f"delivery-{index}"),
            authority=_authority("did:key:zAlice"),
        )
    received = binding.invoke(
        _receive(limit=3), authority=_authority("did:key:zBob")
    )
    assert len(received["items"]) == 3
    acknowledged = binding.invoke(_ack(received), authority=_authority("did:key:zBob"))
    assert acknowledged["acknowledged_count"] == 3
    assert not binding.invoke(
        _receive("receive-after"), authority=_authority("did:key:zBob")
    )["found"]
    assert host.status(LOOPBACK_TRANSPORT_PLUGIN_ID).state == "enabled"


def test_loopback_deactivation_fails_closed() -> None:
    provider = LoopbackTransportProvider()
    provider.deactivate()
    with pytest.raises(TransportOperationError) as error:
        provider.invoke({"operation": "probe"}, _context("did:key:zAlice"))
    assert error.value.code == "inactive"


def test_loopback_rejects_wrong_plugin_context() -> None:
    provider = LoopbackTransportProvider()
    context = _context("did:key:zAlice")
    wrong = PluginInvocationContext(
        plugin_id="org.nth-dao.transport.other",
        capability_id=context.capability_id,
        invocation_id=context.invocation_id,
        authority=context.authority,
        granted_permissions=context.granted_permissions,
        workspace_root=context.workspace_root,
    )
    with pytest.raises(PluginInvocationError, match="context id mismatch"):
        provider.invoke({"operation": "probe"}, wrong)
