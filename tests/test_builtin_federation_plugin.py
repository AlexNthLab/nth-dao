"""The reference plugin wraps, rather than forks, federation discovery."""

from __future__ import annotations

import hashlib
from pathlib import Path
import threading
import time

import pytest
from fastapi.testclient import TestClient

from nth_dao.canonical_json import canonical_json
from nth_dao.plugins import (
    InvocationAuthority,
    PluginHost,
    PluginHostPolicy,
    PluginInvocationError,
)
from nth_dao.plugins.network import VerifiedPeerEndpoint
from nth_dao.web import create_app
from nth_dao.plugins.builtin import (
    FEDERATION_DISCOVERY_CAPABILITY_ID,
    FEDERATION_DISCOVERY_CONTRACT,
    federation_discovery_manifest,
    register_federation_discovery,
)


GRANTS = frozenset(
    {
        "filesystem.read.workspace",
        "filesystem.write.workspace",
        "network.client",
    }
)
AUTHORITY = InvocationAuthority(
    principal="test-suite",
    capability_ids=frozenset({FEDERATION_DISCOVERY_CAPABILITY_ID}),
)


def host(workspace: Path) -> PluginHost:
    return PluginHost(
        policy=PluginHostPolicy(
            allowed_permissions=GRANTS,
            max_risk_tier=3,
        ),
        workspace_root=workspace,
    )


def endpoint(url: str, did: str, *, resolved_ip: str = "93.184.216.34"):
    now = int(time.time() * 1000)
    return VerifiedPeerEndpoint(
        url=url,
        did=did,
        resolved_ip=resolved_ip,
        verified_at_ms=now - 1_000,
        expires_at_ms=now + 60_000,
    )


def test_manifest_binds_direct_execution_closure_and_existing_wire_contract() -> None:
    item = federation_discovery_manifest()
    root = Path(__file__).parents[1]
    relative_paths = (
        "nth_dao/discovery/federation_registry.py",
        "nth_dao/plugins/builtin/federation_discovery.py",
        "nth_dao/plugins/network.py",
        "nth_dao/web/market_federation_poll.py",
    )
    files = [
        {
            "path": relative,
            "sha256": hashlib.sha256((root / relative).read_bytes()).hexdigest(),
        }
        for relative in relative_paths
    ]
    expected = f"sha256:{hashlib.sha256(canonical_json({'files': files})).hexdigest()}"
    assert item.artifact_digest == expected
    assert item.provides == (FEDERATION_DISCOVERY_CONTRACT,)
    assert item.permissions == tuple(sorted(GRANTS))
    assert item.risk_tier == 3


def test_register_does_not_authorize_enable_or_touch_network(tmp_path: Path) -> None:
    calls = []
    plugin_host = host(tmp_path)
    item = register_federation_discovery(
        plugin_host,
        tmp_path,
        get_seed_peers=lambda: calls.append("seeds") or [],
        verify_seed_peer=lambda _url: None,
        verify_gossip_peer=lambda _url, _ip: None,
        http_get=lambda url, ip: calls.append((url, ip)),
    )
    assert plugin_host.status(item.plugin_id).state == "installed"
    assert plugin_host.resolve(FEDERATION_DISCOVERY_CAPABILITY_ID) == ()
    assert calls == []


def test_web_runtime_registers_plugin_but_does_not_auto_authorize_or_enable(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    status = app.state.nth.plugin_host.status(
        federation_discovery_manifest().plugin_id
    )
    assert status.state == "installed"
    assert status.desired_enabled is False
    assert app.state.nth.plugin_host.resolve(FEDERATION_DISCOVERY_CAPABILITY_ID) == ()
    with TestClient(app) as client:
        response = client.get("/api/plugins", params={"actor_id": "admin"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["audit"] == {"ok": True, "reason": "ok"}
    assert body["plugins"][0]["plugin_id"] == status.plugin_id


def test_enable_exposes_revocable_binding_but_discovery_remains_on_demand(
    tmp_path: Path,
) -> None:
    calls = []
    plugin_host = host(tmp_path)
    item = register_federation_discovery(
        plugin_host,
        tmp_path,
        get_seed_peers=lambda: calls.append("seeds") or [],
        verify_seed_peer=lambda _url: None,
        verify_gossip_peer=lambda _url, _ip: None,
        http_get=lambda url, ip: calls.append((url, ip)),
    )
    plugin_host.authorize(item.plugin_id, GRANTS)
    binding = plugin_host.enable(item.plugin_id)[0]
    assert calls == []

    cycle = binding.invoke({}, authority=AUTHORITY)
    assert cycle["known_peers"] == 0
    assert cycle["cached_announcements"] == 0
    assert calls == ["seeds"]

    plugin_host.disable(item.plugin_id)
    with pytest.raises(PluginInvocationError, match="disabled or stale"):
        binding.invoke({}, authority=AUTHORITY)


def test_configured_seed_is_rejected_without_verified_identity(tmp_path: Path) -> None:
    peer = "https://peer.example"
    http_calls = []
    verify_calls = []
    plugin_host = host(tmp_path)
    item = register_federation_discovery(
        plugin_host,
        tmp_path,
        get_seed_peers=lambda: [peer],
        verify_seed_peer=lambda url: verify_calls.append(url) or None,
        verify_gossip_peer=lambda _url, _ip: None,
        http_get=lambda url, ip: http_calls.append((url, ip)) or {},
        max_duration_s=1.0,
    )
    plugin_host.authorize(item.plugin_id, GRANTS)
    binding = plugin_host.enable(item.plugin_id)[0]
    cycle = binding.invoke({}, authority=AUTHORITY)
    assert cycle["attempted_sources"] == 1
    assert cycle["completed_sources"] == 0
    assert cycle["cached_announcements"] == 0
    assert verify_calls == [peer]
    assert http_calls == []


def test_provider_records_bounded_failure_without_forging_success(tmp_path: Path) -> None:
    # A syntactically valid did:key is enough to reach the injected transport;
    # the transport then fails before any announcement can be cached.
    from nth_dao.identity import AgentIdentity

    identity = AgentIdentity.generate(label="peer")
    peer = "https://peer.example"
    plugin_host = host(tmp_path)
    item = register_federation_discovery(
        plugin_host,
        tmp_path,
        get_seed_peers=lambda: [peer],
        verify_seed_peer=lambda url: endpoint(url, identity.as_did()),
        verify_gossip_peer=lambda _url, _ip: None,
        http_get=lambda _url, _ip: (_ for _ in ()).throw(OSError("network down")),
        max_duration_s=1.0,
    )
    plugin_host.authorize(item.plugin_id, GRANTS)
    binding = plugin_host.enable(item.plugin_id)[0]
    cycle = binding.invoke({}, authority=AUTHORITY)
    assert cycle["attempted_sources"] == 1
    assert cycle["completed_sources"] == 0
    assert cycle["cached_announcements"] == 0


def test_verified_seed_pins_transport_to_trust_kernel_ip(tmp_path: Path) -> None:
    from nth_dao.identity import AgentIdentity

    identity = AgentIdentity.generate(label="peer")
    calls = []
    peer = "https://peer.example"
    plugin_host = host(tmp_path)
    item = register_federation_discovery(
        plugin_host,
        tmp_path,
        get_seed_peers=lambda: [peer],
        verify_seed_peer=lambda url: endpoint(
            url,
            identity.as_did(),
            resolved_ip="1.1.1.1",
        ),
        verify_gossip_peer=lambda _url, _ip: None,
        http_get=lambda url, ip: calls.append((url, ip))
        or (_ for _ in ()).throw(OSError("stop after pin assertion")),
        max_duration_s=1.0,
    )
    plugin_host.authorize(item.plugin_id, GRANTS)
    cycle = plugin_host.enable(item.plugin_id)[0].invoke({}, authority=AUTHORITY)
    assert cycle["attempted_sources"] == 1
    assert calls
    assert {ip for _url, ip in calls} == {"1.1.1.1"}


def test_verified_seed_rejects_private_expired_or_retargeted_binding(
    tmp_path: Path,
) -> None:
    from nth_dao.identity import AgentIdentity

    identity = AgentIdentity.generate(label="peer")
    with pytest.raises(ValueError, match="globally routable"):
        endpoint(
            "https://peer.example",
            identity.as_did(),
            resolved_ip="127.0.0.1",
        )

    now = int(time.time() * 1000)
    expired = VerifiedPeerEndpoint(
        url="https://peer.example",
        did=identity.as_did(),
        resolved_ip="1.1.1.1",
        verified_at_ms=now - 20_000,
        expires_at_ms=now - 10_000,
    )
    calls = []
    plugin_host = host(tmp_path / "expired")
    item = register_federation_discovery(
        plugin_host,
        tmp_path / "expired",
        get_seed_peers=lambda: ["https://peer.example"],
        verify_seed_peer=lambda _url: expired,
        verify_gossip_peer=lambda _url, _ip: None,
        http_get=lambda url, ip: calls.append((url, ip)),
    )
    plugin_host.authorize(item.plugin_id, GRANTS)
    cycle = plugin_host.enable(item.plugin_id)[0].invoke({}, authority=AUTHORITY)
    assert cycle["attempted_sources"] == 1
    assert cycle["completed_sources"] == 0
    assert calls == []

    retargeted_host = host(tmp_path / "retargeted")
    retargeted_item = register_federation_discovery(
        retargeted_host,
        tmp_path / "retargeted",
        get_seed_peers=lambda: ["https://peer.example"],
        verify_seed_peer=lambda _url: endpoint(
            "https://other.example",
            identity.as_did(),
        ),
        verify_gossip_peer=lambda _url, _ip: None,
        http_get=lambda url, ip: calls.append((url, ip)),
    )
    retargeted_host.authorize(retargeted_item.plugin_id, GRANTS)
    retargeted = retargeted_host.enable(retargeted_item.plugin_id)[0].invoke(
        {},
        authority=AUTHORITY,
    )
    assert retargeted["completed_sources"] == 0
    assert calls == []


def test_seed_source_failure_is_persisted_and_raised(tmp_path: Path) -> None:
    plugin_host = host(tmp_path)
    item = register_federation_discovery(
        plugin_host,
        tmp_path,
        get_seed_peers=lambda: (_ for _ in ()).throw(OSError("seed store down")),
        verify_seed_peer=lambda _url: None,
        verify_gossip_peer=lambda _url, _ip: None,
    )
    plugin_host.authorize(item.plugin_id, GRANTS)
    binding = plugin_host.enable(item.plugin_id)[0]
    with pytest.raises(OSError, match="seed store down"):
        binding.invoke({}, authority=AUTHORITY)


def test_seed_list_is_bounded_before_network_use(tmp_path: Path) -> None:
    plugin_host = host(tmp_path)
    item = register_federation_discovery(
        plugin_host,
        tmp_path,
        get_seed_peers=lambda: (f"https://peer-{idx}.example" for idx in range(65)),
        verify_seed_peer=lambda _url: None,
        verify_gossip_peer=lambda _url, _ip: None,
    )
    plugin_host.authorize(item.plugin_id, GRANTS)
    binding = plugin_host.enable(item.plugin_id)[0]
    with pytest.raises(ValueError, match="exceed 64"):
        binding.invoke({}, authority=AUTHORITY)


def test_disable_cancels_inflight_cycle_without_waiting_for_cycle_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from nth_dao.identity import AgentIdentity
    from nth_dao.web import market_federation_poll

    identity = AgentIdentity.generate(label="peer")
    entered = threading.Event()

    def cancellable_federate(_peers, _http_get, **kwargs):
        entered.set()
        deadline = time.monotonic() + 2.0
        while not kwargs["cancelled"]() and time.monotonic() < deadline:
            time.sleep(0.01)
        kwargs["cycle_report"].cancelled = kwargs["cancelled"]()
        return {}

    monkeypatch.setattr(market_federation_poll, "federate_once", cancellable_federate)
    plugin_host = host(tmp_path)
    item = register_federation_discovery(
        plugin_host,
        tmp_path,
        get_seed_peers=lambda: ["https://peer.example"],
        verify_seed_peer=lambda url: endpoint(url, identity.as_did()),
        verify_gossip_peer=lambda _url, _ip: None,
    )
    plugin_host.authorize(item.plugin_id, GRANTS)
    binding = plugin_host.enable(item.plugin_id)[0]
    worker = threading.Thread(
        target=lambda: binding.invoke({}, authority=AUTHORITY),
    )
    worker.start()
    assert entered.wait(1.0)
    started = time.monotonic()
    assert plugin_host.disable(item.plugin_id) is True
    assert time.monotonic() - started < 0.5
    worker.join(timeout=1.0)
    assert not worker.is_alive()
