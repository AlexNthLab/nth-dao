"""The reference plugin wraps, rather than forks, federation discovery."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import threading
import time

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from nth_dao.canonical_json import canonical_json
from nth_dao.plugins import (
    CapabilitySchemas,
    InvocationAuthority,
    PluginAuditError,
    PluginHost,
    PluginHostPolicy,
    PluginInvocationError,
    PluginLifecycleError,
)
from nth_dao.plugins.network import VerifiedPeerEndpoint
from nth_dao.web import create_app
from nth_dao.plugins.builtin import (
    FEDERATION_DISCOVERY_CAPABILITY_ID,
    FEDERATION_DISCOVERY_CONTRACT,
    FEDERATION_DISCOVERY_INPUT_SCHEMA,
    FEDERATION_DISCOVERY_OUTPUT_SCHEMA,
    FEDERATION_DISCOVERY_PLUGIN_ID,
    FederationDiscoveryPlugin,
    federation_discovery_manifest,
    register_federation_discovery as register_reviewed_federation_discovery,
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


def register_federation_discovery(
    plugin_host: PluginHost,
    workspace: Path,
    **arguments,
):
    """Test-only constructor for injecting deterministic trust/transport fakes."""

    item = federation_discovery_manifest()
    plugin_host.register_builtin(
        item,
        lambda: FederationDiscoveryPlugin(workspace, **arguments),
        allow_manifest_upgrade=True,
        schemas={
            FEDERATION_DISCOVERY_CAPABILITY_ID: CapabilitySchemas(
                FEDERATION_DISCOVERY_INPUT_SCHEMA,
                FEDERATION_DISCOVERY_OUTPUT_SCHEMA,
            )
        },
    )
    return item


def test_manifest_binds_direct_execution_closure_and_existing_wire_contract() -> None:
    item = federation_discovery_manifest()
    root = Path(__file__).parents[1]
    relative_paths = (
        "nth_dao/discovery/federation_registry.py",
        "nth_dao/plugins/builtin/federation_discovery.py",
        "nth_dao/plugins/federation_trust.py",
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
    assert all("v2_api.py" not in item for item in relative_paths)
    assert all("web/__init__.py" not in item for item in relative_paths)


def test_reviewed_registration_does_not_accept_replacement_trust_callbacks(
    tmp_path: Path,
) -> None:
    plugin_host = host(tmp_path)
    with pytest.raises(TypeError, match="unexpected keyword"):
        register_reviewed_federation_discovery(
            plugin_host,
            tmp_path,
            get_seed_peers=lambda: [],
            verify_seed_peer=lambda _url: None,
        )

    item = register_reviewed_federation_discovery(
        plugin_host,
        tmp_path,
        get_seed_peers=lambda: [],
    )
    assert plugin_host.status(item.plugin_id).state == "installed"


def test_federation_capability_matches_checked_in_v2_vector() -> None:
    vector_path = (
        Path(__file__).parents[1]
        / "nth_dao"
        / "plugins"
        / "vectors"
        / "federation-discovery-capability-v2.json"
    )
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    assert vector["format"] == "nth-dao-plugin-capability-conformance-v1"
    assert vector["schema_version"] == 1
    assert vector["capability"] == FEDERATION_DISCOVERY_CONTRACT.to_dict()
    assert vector["expected_digest"] == FEDERATION_DISCOVERY_CONTRACT.digest
    assert "network-write" in vector["capability"]["effects"]


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
    assert app.state.market_fed_cache is app.state.nth.market_fed_cache
    with TestClient(app) as client:
        response = client.get("/api/plugins", params={"actor_id": "admin"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["audit"] == {"ok": True, "reason": "ok"}
    plugin_rows = {
        item["plugin_id"]: item
        for item in body["plugins"]
    }
    assert plugin_rows[status.plugin_id]["state"] == "installed"
    assert plugin_rows[status.plugin_id]["desired_enabled"] is False
    assert "last_error" not in plugin_rows[status.plugin_id]


def test_web_plugin_invocation_updates_the_market_visible_cache(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    plugin_host = app.state.nth.plugin_host
    item = federation_discovery_manifest()
    plugin_host.authorize(item.plugin_id, set(item.permissions))
    binding = plugin_host.enable(item.plugin_id)[0]

    result = binding.invoke(
        {},
        authority=InvocationAuthority(
            principal="nth-dao:test-suite",
            capability_ids=frozenset({FEDERATION_DISCOVERY_CAPABILITY_ID}),
        ),
    )

    assert result["known_peers"] == 0
    assert app.state.market_fed_cache.status()["cached_announcements"] == 0
    assert app.state.market_fed_cache is app.state.nth.market_fed_cache


def test_admin_plugin_api_enables_refreshes_and_revokes_binding(tmp_path: Path) -> None:
    app = create_app(
        tmp_path,
        require_console_auth=False,
        allow_unauthenticated_plugin_admin=True,
    )
    app.state.nth.membership.ensure_member("member")

    with TestClient(app) as client:
        forbidden = client.post(
            f"/api/plugins/{FEDERATION_DISCOVERY_PLUGIN_ID}/enable",
            json={"actor_id": "member"},
        )
        assert forbidden.status_code == 403

        enabled = client.post(
            f"/api/plugins/{FEDERATION_DISCOVERY_PLUGIN_ID}/enable",
            json={"actor_id": "admin"},
        )
        assert enabled.status_code == 200, enabled.text
        assert enabled.json()["changed"] is True
        assert enabled.json()["plugin"]["state"] == "enabled"
        assert set(enabled.json()["plugin"]["authorized_permissions"]) == GRANTS

        repeated = client.post(
            f"/api/plugins/{FEDERATION_DISCOVERY_PLUGIN_ID}/enable",
            json={"actor_id": "admin"},
        )
        assert repeated.status_code == 200
        assert repeated.json()["changed"] is False

        refreshed = client.post(
            "/api/plugins/federation/refresh",
            json={"actor_id": "admin"},
        )
        assert refreshed.status_code == 200, refreshed.text
        assert refreshed.json()["result"]["known_peers"] == 0

        binding = app.state.nth.plugin_host.resolve_one(
            FEDERATION_DISCOVERY_CAPABILITY_ID
        )
        disabled = client.post(
            f"/api/plugins/{FEDERATION_DISCOVERY_PLUGIN_ID}/disable",
            json={"actor_id": "admin"},
        )
        assert disabled.status_code == 200, disabled.text
        assert disabled.json()["plugin"]["state"] == "authorized"
        with pytest.raises(PluginInvocationError, match="disabled or stale"):
            binding.invoke({}, authority=AUTHORITY)

        unavailable = client.post(
            "/api/plugins/federation/refresh",
            json={"actor_id": "admin"},
        )
        assert unavailable.status_code == 409
        missing = client.post(
            "/api/plugins/org.nth-dao.missing/enable",
            json={"actor_id": "admin"},
        )
        assert missing.status_code == 404

    records = app.state.nth.plugin_host._audit_log.read_verified()
    expected_operator_events = {
        "plugin.authorized",
        "plugin.enable.succeeded",
        "plugin.refresh.succeeded",
        "plugin.disable.succeeded",
    }
    attributed = {
        item["event_type"]: item["details"]["operator"]
        for item in records
        if item["event_type"] in expected_operator_events
    }
    assert set(attributed) == expected_operator_events
    assert all(
        operator
        == {"actor_id": "admin", "principal_type": "anonymous-local"}
        for operator in attributed.values()
    )


def test_cap_token_cannot_administer_plugins_by_spoofing_admin_actor(
    tmp_path: Path,
) -> None:
    from nth_dao.identity import AgentIdentity

    app = create_app(tmp_path, require_console_auth=True)
    with TestClient(app) as client:
        helper = AgentIdentity.generate(label="delegated-helper")
        issued = client.post(
            "/api/cap_tokens/issue",
            json={
                "subject_did": helper.as_did(),
                "capabilities": ["example:read"],
            },
            headers={
                "Authorization": f"Bearer {app.state.nth_console_token}",
            },
        )
        assert issued.status_code == 200, issued.text
        delegated_headers = {
            "Authorization": issued.json()["authorization_header_value"],
        }

        for path in (
            f"/api/plugins/{FEDERATION_DISCOVERY_PLUGIN_ID}/enable",
            f"/api/plugins/{FEDERATION_DISCOVERY_PLUGIN_ID}/disable",
            "/api/plugins/federation/refresh",
        ):
            response = client.post(
                path,
                json={"actor_id": "admin"},
                headers=delegated_headers,
            )
            assert response.status_code == 403, response.text

        assert app.state.nth.plugin_host.status(
            FEDERATION_DISCOVERY_PLUGIN_ID
        ).state == "installed"

        console_headers = {
            "Authorization": f"Bearer {app.state.nth_console_token}",
        }
        enabled = client.post(
            f"/api/plugins/{FEDERATION_DISCOVERY_PLUGIN_ID}/enable",
            json={"actor_id": "admin"},
            headers=console_headers,
        )
        assert enabled.status_code == 200, enabled.text
        records = app.state.nth.plugin_host._audit_log.read_verified()
        lifecycle = [
            item
            for item in records
            if item["event_type"] == "plugin.enable.succeeded"
        ]
        assert lifecycle[-1]["details"]["operator"] == {
            "actor_id": "admin",
            "principal_type": "console",
        }
        disabled = client.post(
            f"/api/plugins/{FEDERATION_DISCOVERY_PLUGIN_ID}/disable",
            json={"actor_id": "admin"},
            headers=console_headers,
        )
        assert disabled.status_code == 200, disabled.text


def test_unauthenticated_plugin_admin_requires_explicit_loopback_mode(
    tmp_path: Path,
) -> None:
    from fastapi import HTTPException
    from nth_dao.web import PluginActionPayload

    default_app = create_app(tmp_path / "default", require_console_auth=False)
    with TestClient(default_app) as client:
        denied = client.post(
            f"/api/plugins/{FEDERATION_DISCOVERY_PLUGIN_ID}/enable",
            json={"actor_id": "admin"},
        )
    assert denied.status_code == 403

    loopback_only_app = create_app(
        tmp_path / "loopback-only",
        require_console_auth=False,
        allow_unauthenticated_plugin_admin=True,
    )
    enable_endpoint = next(
        route.endpoint
        for route in loopback_only_app.routes
        if getattr(route, "path", "") == "/api/plugins/{plugin_id}/enable"
    )
    remote_request = Request(
        {
            "type": "http",
            "app": loopback_only_app,
            "headers": [],
            "client": ("203.0.113.10", 4321),
        }
    )
    with pytest.raises(HTTPException) as caught:
        enable_endpoint(
            remote_request,
            FEDERATION_DISCOVERY_PLUGIN_ID,
            PluginActionPayload(actor_id="admin"),
        )
    assert caught.value.status_code == 403
    assert caught.value.detail == "plugin administration requires a loopback client"


def test_web_plugin_switches_legacy_poller_and_disable_blocks_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.web.v2_api as v2_api

    pollers = []

    class ControlledThread:
        def __init__(self, stop_event: threading.Event, mode: str) -> None:
            self.stop_event = stop_event
            self.mode = mode
            self.alive = True

        def join(self, timeout: float) -> None:
            assert timeout == 10.0
            if self.stop_event.is_set():
                self.alive = False

        def is_alive(self) -> bool:
            return self.alive

    def start_legacy(_get_peers, _cache, **kwargs):
        thread = ControlledThread(kwargs["stop_event"], "legacy")
        pollers.append(thread)
        return thread

    def start_plugin(binding, _cache, **kwargs):
        assert binding.plugin_id == FEDERATION_DISCOVERY_PLUGIN_ID
        assert kwargs["principal"] == "local-system:federation-poller"
        thread = ControlledThread(kwargs["stop_event"], "plugin")
        pollers.append(thread)
        return thread

    monkeypatch.setenv("NTH_FED_PEERS", "https://seed.example")
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.start_poller",
        start_legacy,
    )
    monkeypatch.setattr(v2_api, "_start_plugin_market_fed_poller", start_plugin)
    app = create_app(
        tmp_path,
        require_console_auth=False,
        allow_unauthenticated_plugin_admin=True,
    )

    with TestClient(app) as client:
        assert app.state.market_fed_poller_mode == "legacy"
        assert len(pollers) == 1

        enabled = client.post(
            f"/api/plugins/{FEDERATION_DISCOVERY_PLUGIN_ID}/enable",
            json={"actor_id": "admin"},
        )
        assert enabled.status_code == 200, enabled.text
        assert pollers[0].stop_event.is_set()
        assert app.state.market_fed_poller_mode == "plugin"
        assert len(pollers) == 2

        repeated = client.post(
            f"/api/plugins/{FEDERATION_DISCOVERY_PLUGIN_ID}/enable",
            json={"actor_id": "admin"},
        )
        assert repeated.status_code == 200, repeated.text
        assert repeated.json()["changed"] is False
        assert len(pollers) == 2

        competing_app = create_app(
            tmp_path,
            require_console_auth=False,
            allow_unauthenticated_plugin_admin=True,
        )
        with TestClient(competing_app) as competing_client:
            competing = competing_client.post(
                f"/api/plugins/{FEDERATION_DISCOVERY_PLUGIN_ID}/enable",
                json={"actor_id": "admin"},
            )
            assert competing.status_code == 503, competing.text
            assert getattr(
                competing_app.state,
                "market_fed_poller_started",
                False,
            ) is False
            assert app.state.market_fed_poller_mode == "plugin"
            assert len(pollers) == 2

        disabled = client.post(
            f"/api/plugins/{FEDERATION_DISCOVERY_PLUGIN_ID}/disable",
            json={"actor_id": "admin"},
        )
        assert disabled.status_code == 200, disabled.text
        assert pollers[1].stop_event.is_set()
        assert app.state.market_fed_plugin_suspended is True
        assert app.state.market_fed_poller_started is False
        assert app.state.market_fed_poller_mode == ""

        status = client.get("/api/v2/market/federation/status").json()
        assert status["plugin_suspended"] is True
        assert status["poller_started"] is False
        assert len(pollers) == 2

    restarted = create_app(tmp_path, require_console_auth=False)
    with TestClient(restarted) as client:
        restarted_status = client.get(
            "/api/v2/market/federation/status",
        ).json()
        assert restarted_status["runtime_preference"] == "suspended"
        assert restarted_status["plugin_suspended"] is True
        assert restarted_status["poller_started"] is False
        assert len(pollers) == 2


def test_web_plugin_activation_failure_rolls_back_enabled_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.web.v2_api as v2_api

    monkeypatch.setattr(
        v2_api,
        "activate_market_federation_plugin",
        lambda _app: (_ for _ in ()).throw(RuntimeError("poller conflict")),
    )
    app = create_app(
        tmp_path,
        require_console_auth=False,
        allow_unauthenticated_plugin_admin=True,
    )

    with TestClient(app) as client:
        response = client.post(
            f"/api/plugins/{FEDERATION_DISCOVERY_PLUGIN_ID}/enable",
            json={"actor_id": "admin"},
        )

    assert response.status_code == 503
    status = app.state.nth.plugin_host.status(FEDERATION_DISCOVERY_PLUGIN_ID)
    assert status.state == "authorized"
    assert status.desired_enabled is False
    assert app.state.nth.plugin_host.resolve(FEDERATION_DISCOVERY_CAPABILITY_ID) == ()
    assert app.state.market_fed_plugin_suspended is True


def test_concurrent_enable_disable_is_serialized_to_disabled_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.web.v2_api as v2_api
    from nth_dao.web import PluginActionPayload

    app = create_app(
        tmp_path,
        require_console_auth=False,
        allow_unauthenticated_plugin_admin=True,
    )
    original_activate = v2_api.activate_market_federation_plugin
    activate_entered = threading.Event()
    allow_activate = threading.Event()
    disable_done = threading.Event()
    results = {}
    errors = []

    def blocking_activate(target_app):
        activate_entered.set()
        assert allow_activate.wait(timeout=2.0)
        return original_activate(target_app)

    monkeypatch.setattr(
        v2_api,
        "activate_market_federation_plugin",
        blocking_activate,
    )
    enable_endpoint = next(
        route.endpoint
        for route in app.routes
        if getattr(route, "path", "") == "/api/plugins/{plugin_id}/enable"
    )
    disable_endpoint = next(
        route.endpoint
        for route in app.routes
        if getattr(route, "path", "") == "/api/plugins/{plugin_id}/disable"
    )
    payload = PluginActionPayload(actor_id="admin")

    def run_enable() -> None:
        try:
            results["enable"] = enable_endpoint(
                Request(
                    {
                        "type": "http",
                        "app": app,
                        "headers": [],
                        "client": ("127.0.0.1", 4321),
                    }
                ),
                FEDERATION_DISCOVERY_PLUGIN_ID,
                payload,
            )
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    def run_disable() -> None:
        try:
            results["disable"] = disable_endpoint(
                Request(
                    {
                        "type": "http",
                        "app": app,
                        "headers": [],
                        "client": ("127.0.0.1", 4322),
                    }
                ),
                FEDERATION_DISCOVERY_PLUGIN_ID,
                payload,
            )
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)
        finally:
            disable_done.set()

    enable_worker = threading.Thread(target=run_enable)
    disable_worker = threading.Thread(target=run_disable)
    enable_worker.start()
    assert activate_entered.wait(timeout=2.0)
    disable_worker.start()
    assert not disable_done.wait(timeout=0.1)
    allow_activate.set()
    enable_worker.join(timeout=2.0)
    disable_worker.join(timeout=2.0)

    assert not enable_worker.is_alive()
    assert not disable_worker.is_alive()
    assert errors == []
    assert results["enable"]["changed"] is True
    assert results["disable"]["changed"] is True
    status = app.state.nth.plugin_host.status(FEDERATION_DISCOVERY_PLUGIN_ID)
    assert status.state == "authorized"
    assert status.desired_enabled is False
    assert app.state.market_fed_runtime_preference == "suspended"
    assert getattr(app.state, "market_fed_poller_started", False) is False


@pytest.mark.parametrize(
    "body",
    [
        "{broken",
        '{"version":true,"mode":"legacy"}',
        '{"version":1,"mode":[]}',
        " " * 4097,
    ],
)
def test_corrupt_runtime_preference_fails_closed_across_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    body: str,
) -> None:
    started = []
    preference = tmp_path / ".nth" / "plugin-host" / "federation-runtime.json"
    preference.parent.mkdir(parents=True)
    preference.write_text(body, encoding="utf-8")
    monkeypatch.setenv("NTH_FED_PEERS", "https://seed.example")
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.start_poller",
        lambda *args, **kwargs: started.append(True),
    )

    app = create_app(
        tmp_path,
        require_console_auth=False,
        allow_unauthenticated_plugin_admin=True,
    )
    with TestClient(app) as client:
        status = client.get("/api/v2/market/federation/status").json()

    assert started == []
    assert status["runtime_preference"] == "suspended"
    assert status["plugin_suspended"] is True


def test_external_suspension_invalidates_cached_legacy_preference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.web.v2_api as v2_api

    app = create_app(tmp_path, require_console_auth=False)
    state = app.state
    assert v2_api._initialize_fed_runtime_preference(state, tmp_path) == "legacy"
    assert state.market_fed_plugin_suspended is False

    v2_api._write_fed_runtime_preference(tmp_path, "suspended")
    monkeypatch.setenv("NTH_FED_PEERS", "https://seed.example")
    monkeypatch.setattr(
        v2_api,
        "_start_legacy_market_fed_poller",
        lambda *_args, **_kwargs: pytest.fail(
            "stale legacy preference restarted federation after suspension"
        ),
    )

    cache = v2_api._state_market_fed_cache(
        Request({"type": "http", "app": app}),
    )

    assert cache is state.market_fed_cache
    assert state.market_fed_runtime_preference == "suspended"
    assert state.market_fed_plugin_suspended is True
    assert getattr(state, "market_fed_poller_started", False) is False


def test_plugin_poller_stops_on_revoked_binding_without_leaking_error(
    tmp_path: Path,
) -> None:
    import nth_dao.web.v2_api as v2_api
    from nth_dao.web.market_federation_poll import FederationCache

    class RevokedBinding:
        def __init__(self) -> None:
            self.calls = []

        def invoke(self, payload, *, authority):
            self.calls.append((payload, authority))
            raise PluginInvocationError("private path must not escape")

    binding = RevokedBinding()
    cache = FederationCache()
    stop_event = threading.Event()
    thread = v2_api._start_plugin_market_fed_poller(
        binding,
        cache,
        stop_event=stop_event,
        interval_s=1.0,
        principal="test-poller",
    )
    thread.join(timeout=2.0)

    assert not thread.is_alive()
    assert stop_event.is_set()
    assert len(binding.calls) == 1
    assert binding.calls[0][0] == {}
    assert binding.calls[0][1].principal == "test-poller"
    assert cache.status()["last_error"] == "PluginInvocationError"


def test_cache_and_lifecycle_api_never_expose_raw_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.web.market_federation_poll import FederationCache

    private_identity = "C:" + r"\Users\private\identity.json?token=secret"
    private_audit = "C:" + r"\Users\private\audit.jsonl?token=secret"
    cache = FederationCache()
    cache.mark_error(
        f"OSError: {private_identity}",
        peer_count=1,
    )
    assert cache.status()["last_error"] == "federation-cycle-failed"

    app = create_app(
        tmp_path,
        require_console_auth=False,
        allow_unauthenticated_plugin_admin=True,
    )
    monkeypatch.setattr(
        app.state.nth.plugin_host,
        "enable",
        lambda _plugin_id, **_kwargs: (_ for _ in ()).throw(
            PluginLifecycleError(f"failed at {private_identity}")
        ),
    )
    with TestClient(app) as client:
        response = client.post(
            f"/api/plugins/{FEDERATION_DISCOVERY_PLUGIN_ID}/enable",
            json={"actor_id": "admin"},
        )

    assert response.status_code == 409
    assert response.json()["detail"] == "plugin lifecycle transition rejected"
    assert "private" not in response.text

    audit_app = create_app(
        tmp_path / "audit-failure",
        require_console_auth=False,
        allow_unauthenticated_plugin_admin=True,
    )
    with TestClient(audit_app) as client:
        enabled = client.post(
            f"/api/plugins/{FEDERATION_DISCOVERY_PLUGIN_ID}/enable",
            json={"actor_id": "admin"},
        )
        assert enabled.status_code == 200, enabled.text
        assert audit_app.state.nth.plugin_host._audit_log is not None
        monkeypatch.setattr(
            audit_app.state.nth.plugin_host._audit_log,
            "append",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                PluginAuditError(private_audit)
            ),
        )
        refresh = client.post(
            "/api/plugins/federation/refresh",
            json={"actor_id": "admin"},
        )
    assert refresh.status_code == 503
    assert refresh.json()["detail"] == "plugin audit commit failed"
    assert "private" not in refresh.text


def test_reverse_hello_is_bounded_and_failure_is_soft(tmp_path: Path) -> None:
    peer = "https://seed.example"
    hello_calls = []
    plugin_host = host(tmp_path)
    item = register_federation_discovery(
        plugin_host,
        tmp_path,
        get_seed_peers=lambda: [peer],
        verify_seed_peer=lambda _url: None,
        verify_gossip_peer=lambda _url, _ip: None,
        announce_self=lambda peers: hello_calls.append(tuple(peers))
        or (_ for _ in ()).throw(OSError("hello unavailable")),
        hello_interval_s=60.0,
    )
    plugin_host.authorize(item.plugin_id, GRANTS)
    binding = plugin_host.enable(item.plugin_id)[0]

    first = binding.invoke({}, authority=AUTHORITY)
    second = binding.invoke({}, authority=AUTHORITY)

    assert first["known_peers"] == 1
    assert second["known_peers"] == 1
    assert hello_calls == [(peer,)]


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
    from nth_dao.web.market_federation_poll import FederationCache

    cache = FederationCache()
    plugin_host = host(tmp_path)
    item = register_federation_discovery(
        plugin_host,
        tmp_path,
        cache=cache,
        get_seed_peers=lambda: (_ for _ in ()).throw(OSError("seed store down")),
        verify_seed_peer=lambda _url: None,
        verify_gossip_peer=lambda _url, _ip: None,
    )
    plugin_host.authorize(item.plugin_id, GRANTS)
    binding = plugin_host.enable(item.plugin_id)[0]
    with pytest.raises(OSError, match="seed store down"):
        binding.invoke({}, authority=AUTHORITY)
    assert cache.status()["last_error"] == "OSError"


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
