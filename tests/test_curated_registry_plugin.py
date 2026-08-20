"""Security and persistence tests for curated registry discovery."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nth_dao.canonical_json import canonical_json
from nth_dao.discovery.federation_registry import LearnedPeerStore
from nth_dao.identity import AgentIdentity
from nth_dao.plugins.builtin.curated_registry_discovery import (
    CURATED_REGISTRY_CAPABILITY_ID,
    CURATED_REGISTRY_CONTRACT,
    CURATED_REGISTRY_FORMAT,
    CuratedRegistryDiscoveryProvider,
    _fetch_registry_document,
    _parse_registry_hints,
    curated_registry_manifest,
    register_curated_registry_discovery,
)
from nth_dao.plugins import (
    InvocationAuthority,
    PluginAuditError,
    PluginAuditLog,
    PluginAuthorizationError,
    PluginHost,
    PluginHostPolicy,
)
from nth_dao.plugins.discovery_admission import FederationPeerAdmission
from nth_dao.plugins.federation_trust import VerifiedFederationIdentity
from nth_dao.plugins.network import VerifiedPeerEndpoint
from nth_dao.plugins.registry_trust import CuratedRegistryTrust


_REGISTRY_PUBLISHER = AgentIdentity.generate(label="registry-publisher")


def _registry_document(peers, *, version: int = 1) -> dict:
    now = datetime.now(timezone.utc)
    document = {
        "format": CURATED_REGISTRY_FORMAT,
        "publisher_did": _REGISTRY_PUBLISHER.as_did(),
        "version": version,
        "issued_at": (now - timedelta(seconds=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "peers": peers,
    }
    document["sig"] = _REGISTRY_PUBLISHER.sign_json(document)
    return document


def _registry_security(workspace: Path) -> dict:
    return {
        "get_registry_publisher_did": _REGISTRY_PUBLISHER.as_did,
        "registry_trust": CuratedRegistryTrust(workspace),
    }


def _configure_registry_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "NTH_CURATED_REGISTRY_URL",
        "https://registry.example/v1/peers.json",
    )
    monkeypatch.setenv(
        "NTH_CURATED_REGISTRY_PUBLISHER_DID",
        _REGISTRY_PUBLISHER.as_did(),
    )


def _verified(identity: AgentIdentity, peer_url: str) -> VerifiedFederationIdentity:
    now = int(time.time() * 1000)
    endpoint = VerifiedPeerEndpoint(
        url=peer_url,
        did=identity.as_did(),
        resolved_ip="93.184.216.34",
        verified_at_ms=now,
        expires_at_ms=now + 300_000,
    )
    return VerifiedFederationIdentity(
        endpoint=endpoint,
        pubkey_hex=identity.pubkey_hex,
        identity_url=f"{peer_url}/.well-known/nth-dao/identity.json",
        card_kind="nth-dao-identity-card-v1",
        federation_protocol="nth-dao-federation-v1",
    )


class _Trust:
    def __init__(self, values):
        self.values = values
        self.calls = []

    def verify_public_hint_identity(self, peer_url, *, timeout_seconds=5.0):
        self.calls.append((peer_url, timeout_seconds))
        return self.values.get(peer_url)


def _admission(workspace: Path, trust) -> FederationPeerAdmission:
    return FederationPeerAdmission(workspace, trust_kernel=trust)


def test_manifest_binds_registry_and_trust_execution_closure() -> None:
    item = curated_registry_manifest()
    root = Path(__file__).parents[1]
    relative_paths = (
        "nth_dao/canonical_json.py",
        "nth_dao/did_key.py",
        "nth_dao/discovery/federation_registry.py",
        "nth_dao/federation_transport.py",
        "nth_dao/plugins/audit.py",
        "nth_dao/plugins/builtin/curated_registry_discovery.py",
        "nth_dao/plugins/contracts.py",
        "nth_dao/plugins/discovery_admission.py",
        "nth_dao/plugins/federation_trust.py",
        "nth_dao/plugins/host.py",
        "nth_dao/plugins/network.py",
        "nth_dao/plugins/registry_trust.py",
        "nth_dao/plugins/schema.py",
        "nth_dao/util/io.py",
        "requirements/crypto.lock.txt",
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
    assert item.provides == (CURATED_REGISTRY_CONTRACT,)
    assert item.risk_tier == 3
    assert "PyNaCl==1.5.0" in (
        root / "requirements" / "crypto.lock.txt"
    ).read_text(encoding="utf-8")


def test_curated_registry_capability_matches_checked_in_vector() -> None:
    vector_path = (
        Path(__file__).parents[1]
        / "nth_dao"
        / "plugins"
        / "vectors"
        / "curated-registry-capability-v1.json"
    )
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    assert vector["format"] == "nth-dao-plugin-capability-conformance-v1"
    assert vector["schema_version"] == 1
    assert vector["capability"] == CURATED_REGISTRY_CONTRACT.to_dict()
    assert vector["expected_digest"] == CURATED_REGISTRY_CONTRACT.digest


def test_hint_parser_is_bounded_strict_and_https_only() -> None:
    identity = AgentIdentity.generate(label="peer")
    document = {
        "format": CURATED_REGISTRY_FORMAT,
        "peers": [
            {"peer_url": "https://one.example", "did": identity.as_did()},
            {"peer_url": "http://private.example"},
            {"peer_url": "https://one.example"},
            {"peer_url": "https://two.example", "extra": True},
            {"peer_url": "https://three.example"},
        ],
    }

    hints, attempted, rejected, truncated = _parse_registry_hints(
        document,
        limit=2,
    )

    assert hints == [
        ("https://one.example", identity.as_did()),
        ("https://three.example", ""),
    ]
    assert attempted == 5
    assert rejected == 3
    assert truncated is False

    with pytest.raises(ValueError, match="fields"):
        _parse_registry_hints(
            {"format": CURATED_REGISTRY_FORMAT, "peers": [], "proof": {}},
            limit=2,
        )
    with pytest.raises(ValueError, match="hint limit"):
        _parse_registry_hints(
            {"format": CURATED_REGISTRY_FORMAT, "peers": [{}] * 257},
            limit=2,
        )


def test_provider_reverifies_did_and_persists_only_admitted_peers(
    tmp_path: Path,
) -> None:
    accepted_identity = AgentIdentity.generate(label="accepted")
    mismatched_identity = AgentIdentity.generate(label="mismatch")
    claimed_identity = AgentIdentity.generate(label="claim")
    accepted_url = "https://accepted.example"
    mismatched_url = "https://mismatch.example"
    unavailable_url = "https://unavailable.example"
    trust = _Trust(
        {
            accepted_url: _verified(accepted_identity, accepted_url),
            mismatched_url: _verified(mismatched_identity, mismatched_url),
            unavailable_url: None,
        }
    )
    provider = CuratedRegistryDiscoveryProvider(
        tmp_path,
        get_registry_url=lambda: "https://registry.example/v1/peers.json",
        admission=_admission(tmp_path, trust),
        **_registry_security(tmp_path),
        fetch_document=lambda _url: _registry_document(
            [
                {"peer_url": accepted_url, "did": accepted_identity.as_did()},
                {"peer_url": mismatched_url, "did": claimed_identity.as_did()},
                {"peer_url": unavailable_url},
            ]
        ),
    )

    result = provider.discover(limit=3)

    assert result["attempted_hints"] == 3
    assert result["rejected_hints"] == 2
    assert result["truncated"] is False
    assert [item["peer_url"] for item in result["verified_peers"]] == [accepted_url]
    assert trust.calls == [
        (accepted_url, 2.0),
        (mismatched_url, 2.0),
        (unavailable_url, 2.0),
    ]
    active = LearnedPeerStore(tmp_path).active()
    assert [(item.peer_url, item.did) for item in active] == [
        (accepted_url, accepted_identity.as_did())
    ]


def test_provider_disable_revokes_future_discovery(tmp_path: Path) -> None:
    provider = CuratedRegistryDiscoveryProvider(
        tmp_path,
        get_registry_url=lambda: "https://registry.example/v1/peers.json",
        admission=_admission(tmp_path, _Trust({})),
        **_registry_security(tmp_path),
        fetch_document=lambda _url: _registry_document([]),
    )
    provider.deactivate()
    with pytest.raises(RuntimeError, match="disabled"):
        provider.discover()


def test_missing_publisher_pin_fails_before_registry_network_access(
    tmp_path: Path,
) -> None:
    calls = []
    provider = CuratedRegistryDiscoveryProvider(
        tmp_path,
        get_registry_url=lambda: "https://registry.example/v1/peers.json",
        get_registry_publisher_did=lambda: "",
        admission=_admission(tmp_path, _Trust({})),
        registry_trust=CuratedRegistryTrust(tmp_path),
        fetch_document=lambda url: calls.append(url),
    )

    with pytest.raises(ValueError, match="publisher DID is not configured"):
        provider.discover()

    assert calls == []


def test_admission_rejects_nonpublic_and_expired_bindings(tmp_path: Path) -> None:
    identity = AgentIdentity.generate(label="remote")
    now = int(time.time() * 1000)
    admission = _admission(tmp_path, _Trust({}))
    configured = VerifiedFederationIdentity(
        endpoint=VerifiedPeerEndpoint(
            url="http://127.0.0.1:8080",
            did=identity.as_did(),
            resolved_ip="127.0.0.1",
            verified_at_ms=now - 1_000,
            expires_at_ms=now + 1_000,
            network_scope="configured",
        ),
        pubkey_hex=identity.pubkey_hex,
        identity_url="http://127.0.0.1:8080/.well-known/nth-dao/identity.json",
        card_kind="nth-dao-identity-card-v1",
        federation_protocol="nth-dao-federation-v1",
    )
    expired = VerifiedFederationIdentity(
        endpoint=VerifiedPeerEndpoint(
            url="https://remote.example",
            did=identity.as_did(),
            resolved_ip="93.184.216.34",
            verified_at_ms=now - 2_000,
            expires_at_ms=now - 1_000,
        ),
        pubkey_hex=identity.pubkey_hex,
        identity_url="https://remote.example/.well-known/nth-dao/identity.json",
        card_kind="nth-dao-identity-card-v1",
        federation_protocol="nth-dao-federation-v1",
    )

    with pytest.raises(ValueError, match="public peer binding"):
        admission.persist_verified(configured)
    with pytest.raises(ValueError, match="expired"):
        admission.persist_verified(expired)
    assert LearnedPeerStore(tmp_path).active() == []


def test_duplicate_verified_did_is_not_amplified_across_registry_urls(
    tmp_path: Path,
) -> None:
    identity = AgentIdentity.generate(label="same-agent")
    first = "https://first.example"
    second = "https://second.example"
    provider = CuratedRegistryDiscoveryProvider(
        tmp_path,
        get_registry_url=lambda: "https://registry.example/v1/peers.json",
        admission=_admission(
            tmp_path,
            _Trust(
                {
                    first: _verified(identity, first),
                    second: _verified(identity, second),
                }
            ),
        ),
        **_registry_security(tmp_path),
        fetch_document=lambda _url: _registry_document(
            [{"peer_url": first}, {"peer_url": second}]
        ),
    )

    result = provider.discover(limit=8)

    assert len(result["verified_peers"]) == 1
    assert result["rejected_hints"] == 1
    assert len(LearnedPeerStore(tmp_path).active()) == 1


def test_limited_refresh_commits_signed_version_against_replay(
    tmp_path: Path,
) -> None:
    first_identity = AgentIdentity.generate(label="first")
    second_identity = AgentIdentity.generate(label="second")
    first = "https://first.example"
    second = "https://second.example"
    trust = _Trust(
        {
            first: _verified(first_identity, first),
            second: _verified(second_identity, second),
        }
    )
    document = _registry_document(
        [{"peer_url": first}, {"peer_url": second}]
    )
    provider = CuratedRegistryDiscoveryProvider(
        tmp_path,
        get_registry_url=lambda: "https://registry.example/v1/peers.json",
        admission=_admission(tmp_path, trust),
        **_registry_security(tmp_path),
        fetch_document=lambda _url: document,
    )

    result = provider.discover(limit=1)

    assert result["truncated"] is True
    assert result["version_committed"] is True
    assert len(result["verified_peers"]) == 1
    retry = provider.discover(limit=1)
    assert retry["registry_version"] == result["registry_version"]
    assert retry["verified_peers"] == result["verified_peers"]


def test_persistence_failure_aborts_without_forging_verified_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = AgentIdentity.generate(label="remote")
    peer_url = "https://remote.example"
    admission = _admission(
        tmp_path,
        _Trust({peer_url: _verified(identity, peer_url)}),
    )
    document = _registry_document([{"peer_url": peer_url}])
    provider = CuratedRegistryDiscoveryProvider(
        tmp_path,
        get_registry_url=lambda: "https://registry.example/v1/peers.json",
        admission=admission,
        **_registry_security(tmp_path),
        fetch_document=lambda _url: document,
    )
    persist = admission.persist_verified
    monkeypatch.setattr(
        admission,
        "persist_verified",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk unavailable")),
    )

    with pytest.raises(OSError, match="disk unavailable"):
        provider.discover()

    monkeypatch.setattr(admission, "persist_verified", persist)
    retry = provider.discover()
    assert [item["peer_url"] for item in retry["verified_peers"]] == [peer_url]


def test_trust_kernel_programming_error_is_not_hidden_as_peer_rejection(
    tmp_path: Path,
) -> None:
    class BrokenTrust:
        def verify_public_hint_identity(self, _url, **_kwargs):
            raise TypeError("broken trust adapter")

    provider = CuratedRegistryDiscoveryProvider(
        tmp_path,
        get_registry_url=lambda: "https://registry.example/v1/peers.json",
        admission=_admission(tmp_path, BrokenTrust()),
        **_registry_security(tmp_path),
        fetch_document=lambda _url: _registry_document(
            [{"peer_url": "https://remote.example"}]
        ),
    )

    with pytest.raises(TypeError, match="broken trust adapter"):
        provider.discover()


def test_disable_during_verification_prevents_post_disable_persistence(
    tmp_path: Path,
) -> None:
    identity = AgentIdentity.generate(label="remote")
    peer_url = "https://remote.example"
    entered = threading.Event()
    release = threading.Event()

    class BlockingTrust:
        def verify_public_hint_identity(self, url, **_kwargs):
            entered.set()
            assert release.wait(5.0)
            return _verified(identity, url)

    provider = CuratedRegistryDiscoveryProvider(
        tmp_path,
        get_registry_url=lambda: "https://registry.example/v1/peers.json",
        admission=_admission(tmp_path, BlockingTrust()),
        **_registry_security(tmp_path),
        fetch_document=lambda _url: _registry_document(
            [{"peer_url": peer_url}]
        ),
    )
    errors = []
    worker = threading.Thread(
        target=lambda: _capture_error(provider.discover, errors)
    )
    worker.start()
    assert entered.wait(2.0)
    with pytest.raises(RuntimeError, match="already running"):
        provider.discover()
    provider.deactivate()
    release.set()
    worker.join(timeout=5.0)

    assert not worker.is_alive()
    assert len(errors) == 1
    assert isinstance(errors[0], RuntimeError)
    assert LearnedPeerStore(tmp_path).active() == []


def test_workspace_lease_covers_version_acceptance_and_peer_persistence(
    tmp_path: Path,
) -> None:
    old_identity = AgentIdentity.generate(label="old-peer")
    new_identity = AgentIdentity.generate(label="new-peer")
    old_url = "https://old.example"
    new_url = "https://new.example"
    entered = threading.Event()
    release = threading.Event()

    class BlockingTrust:
        def verify_public_hint_identity(self, url, **_kwargs):
            entered.set()
            assert release.wait(5.0)
            return _verified(old_identity, url)

    old_provider = CuratedRegistryDiscoveryProvider(
        tmp_path,
        get_registry_url=lambda: "https://registry.example/v1/peers.json",
        admission=_admission(tmp_path, BlockingTrust()),
        **_registry_security(tmp_path),
        fetch_document=lambda _url: _registry_document(
            [{"peer_url": old_url}], version=10,
        ),
    )
    new_trust = _Trust({new_url: _verified(new_identity, new_url)})
    new_provider = CuratedRegistryDiscoveryProvider(
        tmp_path,
        get_registry_url=lambda: "https://registry.example/v1/peers.json",
        admission=_admission(tmp_path, new_trust),
        **_registry_security(tmp_path),
        fetch_document=lambda _url: _registry_document(
            [{"peer_url": new_url}], version=11,
        ),
    )
    errors = []
    worker = threading.Thread(
        target=lambda: _capture_error(old_provider.discover, errors),
    )
    worker.start()
    assert entered.wait(2.0)

    with pytest.raises(RuntimeError, match="already running"):
        new_provider.discover()
    assert new_trust.calls == []
    assert LearnedPeerStore(tmp_path).active() == []

    release.set()
    worker.join(timeout=5.0)
    assert not worker.is_alive()
    assert errors == []

    result = new_provider.discover()
    assert result["registry_version"] == 11
    assert {item.peer_url for item in LearnedPeerStore(tmp_path).active()} == {
        old_url,
        new_url,
    }


def _capture_error(call, errors) -> None:
    try:
        call()
    except Exception as exc:  # noqa: BLE001 - asserted by the parent test
        errors.append(exc)


def test_discovery_deadline_stops_new_peer_verification(
    tmp_path: Path,
) -> None:
    trust = _Trust({})
    ticks = iter((0.0, 31.0))
    provider = CuratedRegistryDiscoveryProvider(
        tmp_path,
        get_registry_url=lambda: "https://registry.example/v1/peers.json",
        admission=_admission(tmp_path, trust),
        clock=lambda: next(ticks),
        **_registry_security(tmp_path),
        fetch_document=lambda _url: _registry_document(
            [{"peer_url": "https://remote.example"}]
        ),
    )

    result = provider.discover()

    assert result["truncated"] is True
    assert result["version_committed"] is True
    assert result["verified_peers"] == []
    assert trust.calls == []


def test_registry_fetch_rejects_private_or_non_https_before_network() -> None:
    with pytest.raises(ValueError, match="credential-free HTTPS"):
        _fetch_registry_document("http://registry.example/v1/peers.json")
    with pytest.raises(ValueError, match="public HTTPS"):
        _fetch_registry_document("https://127.0.0.1/v1/peers.json")


def test_registry_fetch_rejects_duplicate_signed_envelope_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.plugins.builtin.curated_registry_discovery as registry

    monkeypatch.setattr(
        registry,
        "resolve_safe_public_https_ip",
        lambda *_args, **_kwargs: "93.184.216.34",
    )
    monkeypatch.setattr(
        registry,
        "get_https_bytes_pinned",
        lambda *_args, **_kwargs: b'{"format":"first","format":"second"}',
    )

    with pytest.raises(ValueError, match="invalid JSON"):
        _fetch_registry_document("https://registry.example/v1/peers.json")


def test_reviewed_registration_does_not_accept_trust_or_transport_overrides(
    tmp_path: Path,
) -> None:
    host = PluginHost(
        policy=PluginHostPolicy(
            allowed_permissions=frozenset(
                {
                    "filesystem.read.workspace",
                    "filesystem.write.workspace",
                    "network.client",
                }
            ),
            max_risk_tier=3,
        ),
        workspace_root=tmp_path,
    )
    with pytest.raises(TypeError, match="unexpected keyword"):
        register_curated_registry_discovery(
            host,
            tmp_path,
            get_registry_url=lambda: "https://registry.example/v1/peers.json",
            get_registry_publisher_did=_REGISTRY_PUBLISHER.as_did,
            trust_kernel=_Trust({}),
        )


def test_web_plugin_refresh_reverifies_and_imports_registry_hint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.plugins.builtin.curated_registry_discovery as registry_plugin
    from nth_dao.plugins.federation_trust import FederationTrustKernel
    from nth_dao.web import create_app

    identity = AgentIdentity.generate(label="remote")
    peer_url = "https://remote.example"
    _configure_registry_env(monkeypatch)
    monkeypatch.setattr(
        registry_plugin,
        "_fetch_registry_document",
        lambda _url: _registry_document(
            [{"peer_url": peer_url, "did": identity.as_did()}]
        ),
    )
    monkeypatch.setattr(
        FederationTrustKernel,
        "verify_public_hint_identity",
        lambda _self, url, **_kwargs: _verified(identity, url),
    )
    app = create_app(
        tmp_path,
        require_console_auth=False,
        allow_unauthenticated_plugin_admin=True,
    )

    with TestClient(app) as client:
        listed = client.get("/api/plugins", params={"actor_id": "admin"})
        assert listed.status_code == 200
        registry = next(
            item
            for item in listed.json()["plugins"]
            if item["plugin_id"] == curated_registry_manifest().plugin_id
        )
        assert registry["state"] == "installed"

        disabled_refresh = client.post(
            "/api/plugins/registry/refresh",
            json={"actor_id": "admin", "limit": 8},
        )
        assert disabled_refresh.status_code == 409

        enabled = client.post(
            f"/api/plugins/{curated_registry_manifest().plugin_id}/enable",
            json={"actor_id": "admin"},
        )
        assert enabled.status_code == 200, enabled.text
        assert enabled.json()["plugin"]["provided_capabilities"] == [
            CURATED_REGISTRY_CAPABILITY_ID
        ]

        refreshed = client.post(
            "/api/plugins/registry/refresh",
            json={"actor_id": "admin", "limit": 8},
        )
        assert refreshed.status_code == 200, refreshed.text
        refresh_result = refreshed.json()["result"]
        assert refresh_result["verified_peers"][0]["did"] == (
            identity.as_did()
        )
        assert refresh_result["publisher_did"] == _REGISTRY_PUBLISHER.as_did()
        assert refresh_result["registry_version"] == 1
        assert refresh_result["version_committed"] is True
        assert app.state.nth.plugin_host.incomplete_refreshes() == ()

    active = LearnedPeerStore(tmp_path).active()
    assert [(item.peer_url, item.did) for item in active] == [
        (peer_url, identity.as_did())
    ]


def test_curated_registry_binding_rejects_unaudited_direct_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.web import create_app

    _configure_registry_env(monkeypatch)
    app = create_app(
        tmp_path,
        require_console_auth=False,
        allow_unauthenticated_plugin_admin=True,
    )
    plugin_id = curated_registry_manifest().plugin_id
    with TestClient(app) as client:
        assert client.post(
            f"/api/plugins/{plugin_id}/enable",
            json={"actor_id": "admin"},
        ).status_code == 200
        binding = app.state.nth.plugin_host.resolve_one(
            CURATED_REGISTRY_CAPABILITY_ID,
        )
        with pytest.raises(PluginAuthorizationError, match="audited refresh"):
            binding.invoke(
                {"limit": 1},
                authority=InvocationAuthority(
                    principal="local-test",
                    capability_ids=frozenset(
                        {CURATED_REGISTRY_CAPABILITY_ID}
                    ),
                ),
            )


def test_web_disable_revokes_an_inflight_registry_refresh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.plugins.builtin.curated_registry_discovery as registry_plugin
    from nth_dao.plugins.federation_trust import FederationTrustKernel
    from nth_dao.web import create_app

    identity = AgentIdentity.generate(label="remote")
    peer_url = "https://remote.example"
    entered = threading.Event()
    release = threading.Event()
    deactivated = threading.Event()
    _configure_registry_env(monkeypatch)
    monkeypatch.setattr(
        registry_plugin,
        "_fetch_registry_document",
        lambda _url: _registry_document([{"peer_url": peer_url}]),
    )

    def blocking_verify(_self, url, **_kwargs):
        entered.set()
        assert release.wait(5.0)
        return _verified(identity, url)

    monkeypatch.setattr(
        FederationTrustKernel,
        "verify_public_hint_identity",
        blocking_verify,
    )
    app = create_app(
        tmp_path,
        require_console_auth=False,
        allow_unauthenticated_plugin_admin=True,
    )
    plugin_id = curated_registry_manifest().plugin_id
    refresh_responses = []
    disable_responses = []
    with TestClient(app) as client:
        assert client.post(
            f"/api/plugins/{plugin_id}/enable",
            json={"actor_id": "admin"},
        ).status_code == 200
        runtime = app.state.nth.plugin_host._records[plugin_id].runtime
        provider = runtime._provider
        original_deactivate = provider.deactivate

        def observed_deactivate() -> None:
            original_deactivate()
            deactivated.set()

        monkeypatch.setattr(provider, "deactivate", observed_deactivate)
        refresh_thread = threading.Thread(
            target=lambda: refresh_responses.append(
                client.post(
                    "/api/plugins/registry/refresh",
                    json={"actor_id": "admin"},
                )
            )
        )
        refresh_thread.start()
        assert entered.wait(2.0)
        busy = client.post(
            "/api/plugins/registry/refresh",
            json={"actor_id": "admin"},
        )
        assert busy.status_code == 409
        assert busy.json()["detail"] == (
            "curated registry refresh is already running"
        )
        disable_thread = threading.Thread(
            target=lambda: disable_responses.append(
                client.post(
                    f"/api/plugins/{plugin_id}/disable",
                    json={"actor_id": "admin"},
                )
            )
        )
        disable_thread.start()
        assert deactivated.wait(2.0)
        release.set()
        refresh_thread.join(timeout=5.0)
        disable_thread.join(timeout=5.0)

    assert not refresh_thread.is_alive()
    assert not disable_thread.is_alive()
    assert refresh_responses[0].status_code == 503
    assert disable_responses[0].status_code == 200
    assert LearnedPeerStore(tmp_path).active() == []


def test_web_registry_refresh_rate_limit_is_bounded_per_operator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.plugins.builtin.curated_registry_discovery as registry_plugin
    from nth_dao.web import create_app

    _configure_registry_env(monkeypatch)
    versions = iter(range(1, 8))
    monkeypatch.setattr(
        registry_plugin,
        "_fetch_registry_document",
        lambda _url: _registry_document([], version=next(versions)),
    )
    app = create_app(
        tmp_path,
        require_console_auth=False,
        allow_unauthenticated_plugin_admin=True,
    )
    plugin_id = curated_registry_manifest().plugin_id
    with TestClient(app) as client:
        assert client.post(
            f"/api/plugins/{plugin_id}/enable",
            json={"actor_id": "admin"},
        ).status_code == 200
        allowed = [
            client.post(
                "/api/plugins/registry/refresh",
                json={"actor_id": "admin"},
            )
            for _ in range(6)
        ]
        denied = client.post(
            "/api/plugins/registry/refresh",
            json={"actor_id": "admin"},
        )

    assert all(response.status_code == 200 for response in allowed)
    assert denied.status_code == 429
    assert int(denied.headers["retry-after"]) >= 1


def test_web_refresh_fails_closed_when_registry_is_unconfigured_or_audit_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.web import create_app

    monkeypatch.delenv("NTH_CURATED_REGISTRY_URL", raising=False)
    monkeypatch.delenv("NTH_CURATED_REGISTRY_PUBLISHER_DID", raising=False)
    app = create_app(
        tmp_path,
        require_console_auth=False,
        allow_unauthenticated_plugin_admin=True,
    )
    plugin_id = curated_registry_manifest().plugin_id
    with TestClient(app) as client:
        enabled = client.post(
            f"/api/plugins/{plugin_id}/enable",
            json={"actor_id": "admin"},
        )
        assert enabled.status_code == 200
        failed = client.post(
            "/api/plugins/registry/refresh",
            json={"actor_id": "admin"},
        )
        assert failed.status_code == 503
        assert failed.json()["detail"] == "curated registry refresh failed"

        monkeypatch.setattr(
            app.state.nth.plugin_host,
            "record_refresh",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                PluginAuditError("audit unavailable")
            ),
        )
        audit_failed = client.post(
            "/api/plugins/registry/refresh",
            json={"actor_id": "admin"},
        )
        assert audit_failed.status_code == 503
        assert audit_failed.json()["detail"] == "plugin audit commit failed"


def test_web_refresh_commits_audit_intent_before_peer_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.plugins.builtin.curated_registry_discovery as registry_plugin
    from nth_dao.plugins.federation_trust import FederationTrustKernel
    from nth_dao.web import create_app

    identity = AgentIdentity.generate(label="remote")
    peer_url = "https://remote.example"
    _configure_registry_env(monkeypatch)
    monkeypatch.setattr(
        registry_plugin,
        "_fetch_registry_document",
        lambda _url: _registry_document([{"peer_url": peer_url}]),
    )
    monkeypatch.setattr(
        FederationTrustKernel,
        "verify_public_hint_identity",
        lambda _self, url, **_kwargs: _verified(identity, url),
    )
    app = create_app(
        tmp_path,
        require_console_auth=False,
        allow_unauthenticated_plugin_admin=True,
    )
    plugin_id = curated_registry_manifest().plugin_id
    with TestClient(app) as client:
        assert client.post(
            f"/api/plugins/{plugin_id}/enable",
            json={"actor_id": "admin"},
        ).status_code == 200
        monkeypatch.setattr(
            app.state.nth.plugin_host,
            "begin_refresh",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                PluginAuditError("audit unavailable")
            ),
        )
        response = client.post(
            "/api/plugins/registry/refresh",
            json={"actor_id": "admin"},
        )

    assert response.status_code == 503
    assert response.json()["detail"] == "plugin audit commit failed"
    assert LearnedPeerStore(tmp_path).active() == []


def test_web_completion_audit_failure_leaves_recoverable_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.plugins.builtin.curated_registry_discovery as registry_plugin
    from nth_dao.plugins.federation_trust import FederationTrustKernel
    from nth_dao.web import create_app

    identity = AgentIdentity.generate(label="remote")
    peer_url = "https://remote.example"
    _configure_registry_env(monkeypatch)
    monkeypatch.setattr(
        registry_plugin,
        "_fetch_registry_document",
        lambda _url: _registry_document([{"peer_url": peer_url}]),
    )
    monkeypatch.setattr(
        FederationTrustKernel,
        "verify_public_hint_identity",
        lambda _self, url, **_kwargs: _verified(identity, url),
    )
    app = create_app(
        tmp_path,
        require_console_auth=False,
        allow_unauthenticated_plugin_admin=True,
    )
    plugin_id = curated_registry_manifest().plugin_id
    with TestClient(app) as client:
        assert client.post(
            f"/api/plugins/{plugin_id}/enable",
            json={"actor_id": "admin"},
        ).status_code == 200
        original_record = app.state.nth.plugin_host.record_refresh

        def fail_completion(*args, **kwargs):
            if kwargs.get("invocation_id"):
                raise PluginAuditError("completion unavailable")
            return original_record(*args, **kwargs)

        monkeypatch.setattr(
            app.state.nth.plugin_host,
            "record_refresh",
            fail_completion,
        )
        response = client.post(
            "/api/plugins/registry/refresh",
            json={"actor_id": "admin"},
        )
        listed = client.get("/api/plugins", params={"actor_id": "admin"})

    assert response.status_code == 503
    assert response.json()["detail"] == "plugin audit commit failed"
    assert len(LearnedPeerStore(tmp_path).active()) == 1
    pending = app.state.nth.plugin_host.incomplete_refreshes(plugin_id)
    assert len(pending) == 1
    assert listed.status_code == 200
    assert listed.json()["incomplete_refreshes"] == list(pending)


def test_refresh_audit_rejects_terminal_event_without_matching_intent(
    tmp_path: Path,
) -> None:
    log = PluginAuditLog(tmp_path / "audit.jsonl")
    plugin_id = curated_registry_manifest().plugin_id
    log.append(
        "plugin.registered",
        plugin_id,
        {"manifest_digest": curated_registry_manifest().digest},
    )

    with pytest.raises(PluginAuditError, match="no matching intent"):
        log.append(
            "plugin.refresh.completed",
            plugin_id,
            {
                "invocation_id": "a" * 32,
                "result_digest": "sha256:" + "b" * 64,
                "result_count": 0,
                "operator": {
                    "actor_id": "admin",
                    "principal_type": "console",
                },
            },
        )
    assert [item["event_type"] for item in log.read_verified()] == [
        "plugin.registered"
    ]


def test_pending_refresh_can_be_aborted_after_host_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.web import create_app

    _configure_registry_env(monkeypatch)
    plugin_id = curated_registry_manifest().plugin_id
    first = create_app(
        tmp_path,
        require_console_auth=False,
        allow_unauthenticated_plugin_admin=True,
    )
    with TestClient(first) as client:
        assert client.post(
            f"/api/plugins/{plugin_id}/enable",
            json={"actor_id": "admin"},
        ).status_code == 200
        invocation_id = first.state.nth.plugin_host.begin_refresh(
            plugin_id,
            operator={
                "principal_type": "anonymous-local",
                "actor_id": "admin",
            },
        )
        assert len(first.state.nth.plugin_host.incomplete_refreshes(plugin_id)) == 1

    restarted = create_app(
        tmp_path,
        require_console_auth=False,
        allow_unauthenticated_plugin_admin=True,
    )
    with TestClient(restarted) as client:
        response = client.post(
            f"/api/plugins/{plugin_id}/refreshes/{invocation_id}/abort",
            json={"actor_id": "admin"},
        )

    assert response.status_code == 200, response.text
    assert response.json()["aborted"] is True
    assert restarted.state.nth.plugin_host.incomplete_refreshes(plugin_id) == ()
    terminal = restarted.state.nth.plugin_host._audit_log.read_verified()[-1]
    assert terminal["event_type"] == "plugin.refresh.aborted"
    assert terminal["details"]["error_type"] == (
        "OperatorReconciledOutcomeUnknown"
    )
