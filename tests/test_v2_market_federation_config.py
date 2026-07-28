from __future__ import annotations

import json
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.did_key import encode_ed25519_did_key
from nth_dao.web import create_app
from nth_dao.web.market_federation_poll import FederationCache


NEW_NODE_DID = encode_ed25519_did_key(bytes.fromhex("34" * 32))


def _verified_metadata(peer_url: str, label: str) -> dict:
    pubkey = hashlib.sha256(label.encode("utf-8")).digest()
    return {
        "peer_url": peer_url,
        "identity_url": f"{peer_url}/.well-known/nth-dao/identity.json",
        "did": encode_ed25519_did_key(pubkey),
        "pubkey_hex": pubkey.hex(),
    }


def _signed_identity_card(identity, peer_url: str) -> dict:
    card = {
        "kind": "nth-dao-identity-card-v1",
        "agent_id": "admin",
        "did": identity.as_did(),
        "pubkey_hex": identity.pubkey_hex,
        "capabilities": ["nth-dao-federation"],
        "issued_at": "2026-07-10T00:00:00+00:00",
        "base_url": peer_url,
        "federation": {
            "protocol": "nth-dao-federation-v1",
            "enabled": True,
            "peer_url": peer_url,
        },
    }
    card["sig"] = identity.sign_json(card)
    return card


def test_federation_status_empty_without_runtime_side_effects(tmp_path: Path) -> None:
    c = TestClient(create_app(tmp_path, require_console_auth=False))

    r = c.get("/api/v2/market/federation/status")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["peers"] == []
    assert body["file_peers"] == []
    assert body["env_peers"] == []
    assert body["cached_announcements"] == 0
    assert body["last_error"] == ""
    assert not (tmp_path / "federation" / "peers.json").exists()


def test_federation_status_requires_bearer_when_console_auth_is_enabled(
    tmp_path: Path,
) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=True))

    assert client.get("/api/v2/market/federation/status").status_code == 401
    response = client.get(
        "/api/v2/market/federation/status",
        headers={
            "Authorization": f"Bearer {client.app.state.nth_console_token}",
        },
    )

    assert response.status_code == 200, response.text


def test_public_peer_directory_does_not_expose_private_operator_seed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.start_poller",
        lambda *args, **kwargs: None,
    )
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    seed = "http://127.0.0.1:8081"

    added = client.post(
        "/api/v2/market/federation/peers",
        json={"peer_url": seed, "action": "add"},
    )

    assert added.status_code == 200, added.text
    assert client.get("/api/v2/market/federation/peers").json() == {"peers": []}
    assert client.get("/api/v2/market/federation/status").json()["peers"] == [seed]


def test_public_peer_directory_ignores_malformed_seed_metadata(
    tmp_path: Path,
) -> None:
    seed = "https://public.example"
    federation = tmp_path / "federation"
    federation.mkdir(parents=True)
    (federation / "peers.json").write_text(
        json.dumps([seed]), encoding="utf-8",
    )
    (federation / "peers_meta.json").write_text(
        json.dumps({
            seed: {
                "peer_url": seed,
                "identity_url": f"{seed}/.well-known/nth-dao/identity.json",
                "did": NEW_NODE_DID,
                "pubkey_hex": "\N{SNOWMAN}",
                "verified_at": "2026-07-15T00:00:00+00:00",
                "card_kind": "nth-dao-identity-card-v1",
                "federation_protocol": "nth-dao-federation-v1",
            },
        }),
        encoding="utf-8",
    )
    client = TestClient(create_app(tmp_path, require_console_auth=False))

    response = client.get("/api/v2/market/federation/peers")

    assert response.status_code == 200, response.text
    assert response.json() == {"peers": []}


def test_federation_peer_add_remove_persists_normalized_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    started: list[tuple[list[str], float]] = []

    def fake_start_poller(
        get_peers,
        cache: FederationCache,
        *,
        get_untrusted_peers=None,
        announce_self=None,
        hello_interval_s=300.0,
        stop_event=None,
        interval_s,
        http_get=None,
        verify_gossip_peer=None,
        verify_seed_peer=None,
        max_duration_s=30.0,
    ):
        started.append((get_peers(), interval_s))
        return None

    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.start_poller",
        fake_start_poller,
    )
    c = TestClient(create_app(tmp_path, require_console_auth=False))

    r = c.post(
        "/api/v2/market/federation/peers",
        json={"peer_url": "http://127.0.0.1:8081/", "action": "add"},
    )

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["updated"] is True
    assert body["peers"] == ["http://127.0.0.1:8081"]
    assert body["file_peers"] == ["http://127.0.0.1:8081"]
    assert body["poller_started"] is True
    assert started == [(["http://127.0.0.1:8081"], 20.0)]
    assert json.loads((tmp_path / "federation" / "peers.json").read_text()) == [
        "http://127.0.0.1:8081"
    ]

    r = c.post(
        "/api/v2/market/federation/peers",
        json={"peer_url": "http://127.0.0.1:8081", "action": "remove"},
    )

    assert r.status_code == 200, r.text
    assert r.json()["file_peers"] == []
    assert r.json()["poller_started"] is False
    assert json.loads((tmp_path / "federation" / "peers.json").read_text()) == []
    assert len(started) == 1


def test_app_lifespan_starts_and_stops_configured_federation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    started: list[dict] = []
    joined: list[float] = []

    class FakeThread:
        def join(self, timeout: float) -> None:
            joined.append(timeout)

    def fake_start_poller(get_peers, cache, **kwargs):
        started.append({
            "peers": get_peers(),
            "stop_event": kwargs["stop_event"],
            "interval_s": kwargs["interval_s"],
        })
        return FakeThread()

    monkeypatch.setenv("NTH_FED_PEERS", "https://seed.example")
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.start_poller",
        fake_start_poller,
    )
    app = create_app(tmp_path, require_console_auth=False)

    with TestClient(app):
        assert app.state.market_fed_poller_started is True
        assert started[0]["peers"] == ["https://seed.example"]
        assert started[0]["stop_event"].is_set() is False

    assert started[0]["stop_event"].is_set() is True
    assert joined == [10.0]
    assert app.state.market_fed_poller_started is False

    with TestClient(app):
        assert len(started) == 2
        assert started[1]["stop_event"].is_set() is False

    assert started[1]["stop_event"].is_set() is True
    assert joined == [10.0, 10.0]


def test_app_lifespan_clamps_negative_federation_interval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    intervals: list[float] = []

    monkeypatch.setenv("NTH_FED_PEERS", "https://seed.example")
    monkeypatch.setenv("NTH_FED_POLL_INTERVAL_S", "-5")
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.start_poller",
        lambda *args, **kwargs: intervals.append(kwargs["interval_s"]),
    )
    app = create_app(tmp_path, require_console_auth=False)

    with TestClient(app):
        assert intervals == [1.0]


def test_app_lifespan_discovers_federation_without_browser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading

    import nth_dao.web.v2_api as v2_api

    called = threading.Event()
    calls: list[dict] = []

    def fake_discover(request, **kwargs):
        calls.append(dict(kwargs))
        called.set()
        return {"discovered": True}

    monkeypatch.setenv("NTH_LAN_DISCOVERY", "1")
    monkeypatch.setenv("NTH_FED_DISCOVERY_INTERVAL_S", "3600")
    monkeypatch.setattr(
        v2_api, "_discover_and_import_market_federation", fake_discover,
    )
    app = create_app(tmp_path, require_console_auth=False)

    with TestClient(app):
        assert called.wait(timeout=2.0)
        assert calls == [{
            "actor_id": "admin",
            "timeout_seconds": 1.25,
            "add": True,
            "refresh": False,
        }]
        assert app.state.market_fed_discovery_thread.is_alive()

    assert app.state.market_fed_discovery_thread is None
    assert app.state.market_fed_discovery_stop_event is None


def test_stuck_poller_is_not_duplicated_and_restarts_after_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading
    import nth_dao.web.v2_api as v2_api

    class ControlledThread:
        def __init__(self, *, alive: bool) -> None:
            self.alive = alive

        def join(self, timeout: float) -> None:
            assert timeout == 10.0

        def is_alive(self) -> bool:
            return self.alive

    monkeypatch.setenv("NTH_FED_PEERS", "https://seed.example")
    app = create_app(tmp_path, require_console_auth=False)
    old_stop = threading.Event()
    old_thread = ControlledThread(alive=True)
    app.state.market_fed_cache = FederationCache()
    app.state.market_fed_poller_started = True
    app.state.market_fed_poller_stop_event = old_stop
    app.state.market_fed_poller_thread = old_thread

    v2_api.stop_market_federation_runtime(app)

    assert old_stop.is_set() is True
    assert app.state.market_fed_poller_started is True
    assert app.state.market_fed_poller_thread is old_thread

    started: list[bool] = []
    new_thread = ControlledThread(alive=True)
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.start_poller",
        lambda *args, **kwargs: started.append(True) or new_thread,
    )
    old_thread.alive = False

    v2_api.start_market_federation_runtime(app)

    assert started == [True]
    assert app.state.market_fed_poller_thread is new_thread
    assert app.state.market_fed_poller_started is True


@pytest.mark.parametrize(
    "peer_url",
    [
        "",
        "ftp://example.test",
        "https://user:pass@example.test",
        "https://example.test/path?token=secret",
        "https://example.test/path#frag",
    ],
)
def test_federation_peer_rejects_unsafe_operator_urls(
    tmp_path: Path, peer_url: str,
) -> None:
    c = TestClient(create_app(tmp_path, require_console_auth=False))

    r = c.post(
        "/api/v2/market/federation/peers",
        json={"peer_url": peer_url, "action": "add"},
    )

    assert r.status_code == 400


def test_federation_refresh_with_no_peers_is_safe_noop(tmp_path: Path) -> None:
    c = TestClient(create_app(tmp_path, require_console_auth=False))

    r = c.post("/api/v2/market/federation/refresh")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["refreshed"] is True
    assert body["cached_announcements"] == 0
    assert body["last_peer_count"] == 0


def test_federation_refresh_updates_market_open_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity, crypto_available
    from nth_dao.market.announcement import sign_announcement

    if not crypto_available():
        pytest.skip("PyNaCl needed for signed market announcements")

    publisher = AgentIdentity.generate(label="peer")
    ann = sign_announcement(
        publisher=publisher,
        title="peer product",
        context="tools",
        reward_minor=42,
        input_schema={"__nth_listing_type": "product"},
    )

    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.start_poller",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.federate_once",
        lambda peers, **kwargs: {
            ann.announcement_id: {"ann": ann, "source": peers[0]},
        },
    )
    c = TestClient(create_app(tmp_path, require_console_auth=False))
    assert c.post(
        "/api/v2/market/federation/peers",
        json={"peer_url": "http://127.0.0.1:8089", "action": "add"},
    ).status_code == 200

    r = c.post("/api/v2/market/federation/refresh")

    assert r.status_code == 200, r.text
    assert r.json()["cached_announcements"] == 1
    rows = c.get("/api/v2/market/open", params={"listing_type": "product"}).json()
    assert len(rows) == 1
    assert rows[0]["title"] == "peer product"
    assert rows[0]["federated"] is True
    assert rows[0]["listing_type"] == "product"
    assert rows[0]["source_peer"] == "http://127.0.0.1:8089"


def test_federation_peer_remove_clears_cached_remote_announcements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity, crypto_available
    from nth_dao.market.announcement import sign_announcement

    if not crypto_available():
        pytest.skip("PyNaCl needed for signed market announcements")

    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.start_poller",
        lambda *args, **kwargs: None,
    )
    c = TestClient(create_app(tmp_path, require_console_auth=False))
    assert c.post(
        "/api/v2/market/federation/peers",
        json={"peer_url": "http://127.0.0.1:8089", "action": "add"},
    ).status_code == 200

    publisher = AgentIdentity.generate(label="peer")
    ann = sign_announcement(
        publisher=publisher,
        title="stale remote product",
        context="tools",
        reward_minor=42,
        input_schema={"__nth_listing_type": "product"},
    )
    c.app.state.market_fed_cache.replace_all(
        {ann.announcement_id: {"ann": ann, "source": "http://127.0.0.1:8089"}},
        peer_count=1,
    )
    assert len(c.get(
        "/api/v2/market/open", params={"listing_type": "product"},
    ).json()) == 1

    r = c.post(
        "/api/v2/market/federation/peers",
        json={"peer_url": "http://127.0.0.1:8089", "action": "remove"},
    )

    assert r.status_code == 200, r.text
    assert r.json()["cached_announcements"] == 0
    assert c.get(
        "/api/v2/market/open", params={"listing_type": "product"},
    ).json() == []


def test_federation_status_skips_invalid_env_peer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "NTH_FED_PEERS",
        "ftp://bad,http://127.0.0.1:8082,https://example.test/path?x=1",
    )
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.start_poller",
        lambda *args, **kwargs: None,
    )
    c = TestClient(create_app(tmp_path, require_console_auth=False))

    r = c.get("/api/v2/market/federation/status")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["peers"] == ["http://127.0.0.1:8082"]
    assert body["env_peers"] == ["http://127.0.0.1:8082"]


def test_federation_discover_imports_only_http_reachable_peers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LAN identity discovery is not enough; only explicit HTTP URLs are seeds."""
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.start_poller",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.federate_once",
        lambda peers: {},
    )
    import nth_dao.web.v2_api as v2_api

    monkeypatch.setattr(
        v2_api,
        "_discover_market_federation_peers",
        lambda *args, **kwargs: ([
            {
                "agent_id": "reachable",
                "label": "Reachable DAO",
                "did": "did:key:zReachable",
                "capabilities": ["nth-dao-federation"],
                "groups": ["home"],
                "ws_url": "http://192.168.1.20:8080",
                "source_addr": "192.168.1.20:8080",
                "federation_peer_url": "http://192.168.1.20:8080",
                "metadata": {},
            },
            {
                "agent_id": "did-only",
                "label": "DID only",
                "did": "did:key:zDidOnly",
                "capabilities": [],
                "groups": [],
                "ws_url": "",
                "source_addr": "192.168.1.21:9877",
                "federation_peer_url": "",
                "metadata": {},
            },
        ], []),
    )
    monkeypatch.setattr(
        v2_api,
        "_fetch_and_verify_federation_identity",
        lambda peer_url, *, timeout_seconds, expected_did="", resolved_ip="": (
            {
                "peer_url": peer_url,
                "identity_url": f"{peer_url}/.well-known/nth-dao/identity.json",
                "did": "did:key:zReachable",
                "pubkey_hex": "ab" * 32,
                "verified_at": "2026-07-10T00:00:00+00:00",
                "card_kind": "nth-dao-identity-card-v1",
                "federation_protocol": "nth-dao-federation-v1",
            },
            "",
        ),
    )
    c = TestClient(create_app(tmp_path, require_console_auth=False))

    r = c.post(
        "/api/v2/market/federation/discover",
        json={"actor_id": "admin", "timeout_seconds": 0.5},
    )

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["discovered"] is True
    assert body["imported_peers"] == ["http://192.168.1.20:8080"]
    assert body["peers"] == ["http://192.168.1.20:8080"]
    assert len(body["discovered_peers"]) == 2
    assert body["skipped_peers"][0]["agent_id"] == "did-only"
    assert json.loads((tmp_path / "federation" / "peers.json").read_text()) == [
        "http://192.168.1.20:8080"
    ]
    metadata = json.loads(
        (tmp_path / "federation" / "peers_meta.json").read_text()
    )
    assert metadata["http://192.168.1.20:8080"]["did"] == "did:key:zReachable"
    assert body["identity_verified_peers"] == ["http://192.168.1.20:8080"]


def test_federation_discover_rejects_private_target_not_matching_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.start_poller",
        lambda *args, **kwargs: None,
    )
    import nth_dao.web.v2_api as v2_api

    monkeypatch.setattr(
        v2_api,
        "_discover_market_federation_peers",
        lambda *args, **kwargs: ([{
            "agent_id": "malicious",
            "did": "did:key:zMalicious",
            "source_addr": "192.168.1.20:8080",
            "federation_peer_url": "http://192.168.1.1:80",
        }], []),
    )

    def unexpected_fetch(*args, **kwargs):
        raise AssertionError("mismatched private target must not be fetched")

    monkeypatch.setattr(
        v2_api, "_fetch_and_verify_federation_identity", unexpected_fetch,
    )
    client = TestClient(create_app(tmp_path, require_console_auth=False))

    response = client.post(
        "/api/v2/market/federation/discover",
        json={"actor_id": "admin", "timeout_seconds": 0.5},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["imported_peers"] == []
    assert body["skipped_peers"][0]["identity_error"] == (
        "private federation URL does not match discovery source"
    )


def test_federation_url_from_discovered_peer_prefers_metadata() -> None:
    import nth_dao.web.v2_api as v2_api

    peer = SimpleNamespace(
        ws_url="http://wrong.example:8080",
        metadata={"federation_url": "https://dao.example/base/"},
    )

    assert (
        v2_api._federation_url_from_discovered_peer(peer)
        == "https://dao.example/base"
    )


def test_federation_discover_rejects_non_member_actor(tmp_path: Path) -> None:
    c = TestClient(create_app(tmp_path, require_console_auth=False))

    r = c.post(
        "/api/v2/market/federation/discover",
        json={"actor_id": "stranger", "timeout_seconds": 0.5},
    )

    assert r.status_code == 403


def test_identity_card_verification_binds_did_key_and_peer_url() -> None:
    from nth_dao.identity import AgentIdentity, crypto_available

    if not crypto_available():
        pytest.skip("PyNaCl needed for identity card verification")
    import nth_dao.web.v2_api as v2_api

    identity = AgentIdentity.generate(label="peer")
    peer_url = "http://192.168.1.20:8080"
    metadata, error = v2_api._verify_federation_identity_card(
        peer_url, _signed_identity_card(identity, peer_url),
    )

    assert error == ""
    assert metadata is not None
    assert metadata["peer_url"] == peer_url
    assert metadata["did"] == identity.as_did()
    assert metadata["pubkey_hex"] == identity.pubkey_hex


def test_identity_card_verification_rejects_url_mismatch() -> None:
    from nth_dao.identity import AgentIdentity, crypto_available

    if not crypto_available():
        pytest.skip("PyNaCl needed for identity card verification")
    import nth_dao.web.v2_api as v2_api

    identity = AgentIdentity.generate(label="peer")
    card = _signed_identity_card(identity, "http://192.168.1.21:8080")
    metadata, error = v2_api._verify_federation_identity_card(
        "http://192.168.1.20:8080", card,
    )

    assert metadata is None
    assert "does not match discovery" in error


def test_identity_card_verification_rejects_base_url_mismatch() -> None:
    from nth_dao.identity import AgentIdentity, crypto_available

    if not crypto_available():
        pytest.skip("PyNaCl needed for identity card verification")
    import nth_dao.web.v2_api as v2_api

    identity = AgentIdentity.generate(label="peer")
    peer_url = "http://192.168.1.20:8080"
    card = _signed_identity_card(identity, peer_url)
    card["base_url"] = "http://192.168.1.21:8080"
    card["sig"] = identity.sign_json({k: v for k, v in card.items() if k != "sig"})

    metadata, error = v2_api._verify_federation_identity_card(peer_url, card)

    assert metadata is None
    assert "base_url does not match discovery" in error


def test_identity_card_fetch_rejects_discovery_did_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity, crypto_available

    if not crypto_available():
        pytest.skip("PyNaCl needed for identity card verification")
    import nth_dao.web.v2_api as v2_api

    identity = AgentIdentity.generate(label="peer")
    peer_url = "http://192.168.1.20:8080"
    card = _signed_identity_card(identity, peer_url)
    monkeypatch.setattr(
        v2_api,
        "_open_federation_identity_card",
        lambda url, timeout_seconds: json.dumps(card).encode("utf-8"),
    )

    metadata, error = v2_api._fetch_and_verify_federation_identity(
        peer_url,
        timeout_seconds=0.5,
        expected_did="did:key:zDifferentDiscoveryRecord",
    )

    assert metadata is None
    assert "does not match discovery record" in error


def test_discovered_federation_url_rejects_loopback_but_allows_lan() -> None:
    import nth_dao.web.v2_api as v2_api

    assert not v2_api._is_safe_discovered_federation_url(
        "http://127.0.0.1:8080"
    )
    assert not v2_api._is_safe_discovered_federation_url(
        "http://localhost:8080"
    )
    assert v2_api._is_safe_discovered_federation_url(
        "http://192.168.1.20:8080"
    )


def test_discovered_federation_dns_rejects_loopback_and_metadata_aliases() -> None:
    import nth_dao.web.v2_api as v2_api

    def resolve_loopback(*_args):
        return [(2, 1, 6, "", ("127.0.0.1", 0))]

    def resolve_metadata(*_args):
        return [(2, 1, 6, "", ("169.254.169.254", 0))]

    assert v2_api._resolve_safe_discovered_federation_ip(
        "http://alias.example:8080", resolve=resolve_loopback,
    ) is None
    assert v2_api._resolve_safe_discovered_federation_ip(
        "http://metadata.example", resolve=resolve_metadata,
    ) is None


def test_discovered_federation_dns_returns_pinned_lan_ip() -> None:
    import nth_dao.web.v2_api as v2_api

    def resolve_lan(*_args):
        return [(2, 1, 6, "", ("192.168.1.20", 0))]

    assert v2_api._resolve_safe_discovered_federation_ip(
        "http://dao.lan.example:8080", resolve=resolve_lan,
    ) == "192.168.1.20"


def test_gossip_identity_verifier_uses_bounded_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.web.v2_api as v2_api

    c = TestClient(create_app(tmp_path, require_console_auth=False))
    calls: list[str] = []

    def fake_fetch(
        peer_url: str,
        *,
        timeout_seconds: float,
        expected_did: str = "",
        resolved_ip: str = "",
    ):
        calls.append(peer_url)
        return ({"did": "did:key:zPeer"}, "")

    monkeypatch.setattr(v2_api, "_fetch_and_verify_federation_identity", fake_fetch)
    verifier = v2_api._market_fed_gossip_identity_verifier(
        SimpleNamespace(app=c.app),
    )

    assert verifier("https://peer.example/", "93.184.216.34") == "did:key:zPeer"
    assert verifier("https://peer.example", "93.184.216.34") == "did:key:zPeer"
    assert calls == ["https://peer.example"]


def test_gossip_identity_verifier_forwards_resolved_ip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.web.v2_api as v2_api

    c = TestClient(create_app(tmp_path, require_console_auth=False))
    resolved: list[str] = []

    def fake_fetch(
        peer_url: str,
        *,
        timeout_seconds: float,
        expected_did: str = "",
        resolved_ip: str = "",
    ):
        resolved.append(resolved_ip)
        return ({"did": "did:key:zPeer"}, "")

    monkeypatch.setattr(v2_api, "_fetch_and_verify_federation_identity", fake_fetch)
    verifier = v2_api._market_fed_gossip_identity_verifier(
        SimpleNamespace(app=c.app),
    )

    assert verifier("https://peer.example", "93.184.216.34") == "did:key:zPeer"
    assert resolved == ["93.184.216.34"]


def test_gossip_identity_verifier_single_flights_concurrent_fetches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    import nth_dao.web.v2_api as v2_api

    c = TestClient(create_app(tmp_path, require_console_auth=False))
    calls = 0
    calls_lock = threading.Lock()

    def fake_fetch(
        peer_url: str,
        *,
        timeout_seconds: float,
        expected_did: str = "",
        resolved_ip: str = "",
    ):
        nonlocal calls
        with calls_lock:
            calls += 1
        time.sleep(0.05)
        return ({"did": "did:key:zPeer"}, "")

    monkeypatch.setattr(v2_api, "_fetch_and_verify_federation_identity", fake_fetch)
    verifier = v2_api._market_fed_gossip_identity_verifier(
        SimpleNamespace(app=c.app),
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(
            lambda _idx: verifier("https://peer.example", "93.184.216.34"),
            range(2),
        ))

    assert results == ["did:key:zPeer", "did:key:zPeer"]
    assert calls == 1


def test_identity_card_fetch_rejects_tampered_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity, crypto_available

    if not crypto_available():
        pytest.skip("PyNaCl needed for identity card verification")
    import nth_dao.web.v2_api as v2_api

    identity = AgentIdentity.generate(label="peer")
    peer_url = "http://192.168.1.20:8080"
    card = _signed_identity_card(identity, peer_url)
    card["capabilities"] = ["malicious-rewrite"]
    monkeypatch.setattr(
        v2_api,
        "_open_federation_identity_card",
        lambda url, timeout_seconds: json.dumps(card).encode("utf-8"),
    )

    metadata, error = v2_api._fetch_and_verify_federation_identity(
        peer_url, timeout_seconds=0.5,
    )

    assert metadata is None
    assert "signature verification failed" in error


def test_gossip_identity_verifier_persists_verified_learned_peer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.web.v2_api as v2_api
    from nth_dao.discovery.federation_registry import LearnedPeerStore

    peer_url = "https://learned.example"
    metadata = _verified_metadata(peer_url, "learned")
    monkeypatch.setattr(
        v2_api,
        "_fetch_and_verify_federation_identity",
        lambda *args, **kwargs: (metadata, ""),
    )
    client = TestClient(create_app(tmp_path, require_console_auth=False))

    verifier = v2_api._market_fed_gossip_identity_verifier(
        SimpleNamespace(app=client.app), persist_learned=True,
    )

    assert verifier(peer_url, "93.184.216.34") == metadata["did"]
    records = LearnedPeerStore(tmp_path).active()
    assert len(records) == 1
    assert records[0].peer_url == peer_url
    assert records[0].did == metadata["did"]


def test_gossip_identity_cache_is_bound_to_resolved_ip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.web.v2_api as v2_api

    peer_url = "https://moving.example"
    calls: list[str] = []

    def fake_fetch(*args, **kwargs):
        calls.append(str(kwargs.get("resolved_ip") or ""))
        return (_verified_metadata(peer_url, "moving"), "")

    monkeypatch.setattr(v2_api, "_fetch_and_verify_federation_identity", fake_fetch)
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    verifier = v2_api._market_fed_gossip_identity_verifier(
        SimpleNamespace(app=client.app), persist_learned=True,
    )

    expected_did = _verified_metadata(peer_url, "moving")["did"]
    assert verifier(peer_url, "93.184.216.34") == expected_did
    assert verifier(peer_url, "93.184.216.35") == expected_did
    assert calls == ["93.184.216.34", "93.184.216.35"]


def test_cached_seed_identity_can_be_durably_learned_without_refetch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.web.v2_api as v2_api
    from nth_dao.discovery.federation_registry import LearnedPeerStore

    peer_url = "https://cached.example"
    metadata = _verified_metadata(peer_url, "cached")
    calls = 0

    def fake_fetch(*args, **kwargs):
        nonlocal calls
        calls += 1
        return metadata, ""

    monkeypatch.setattr(v2_api, "_fetch_and_verify_federation_identity", fake_fetch)
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    request = SimpleNamespace(app=client.app)
    seed_verifier = v2_api._market_fed_gossip_identity_verifier(request)
    learned_verifier = v2_api._market_fed_gossip_identity_verifier(
        request, persist_learned=True,
    )

    assert seed_verifier(peer_url, "93.184.216.34") == metadata["did"]
    assert learned_verifier(peer_url, "93.184.216.34") == metadata["did"]
    assert calls == 1
    assert LearnedPeerStore(tmp_path).active()[0].peer_url == peer_url


def test_cached_seed_identity_does_not_rewrite_unchanged_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.web.v2_api as v2_api

    peer_url = "https://stable-seed.example"
    metadata = _verified_metadata(peer_url, "stable-seed")
    monkeypatch.setenv("NTH_FED_PEERS", peer_url)
    monkeypatch.setattr(
        v2_api,
        "_fetch_and_verify_federation_identity",
        lambda *args, **kwargs: (metadata, ""),
    )
    writes = 0
    original_write = v2_api._write_fed_peer_metadata

    def counted_write(*args, **kwargs):
        nonlocal writes
        writes += 1
        return original_write(*args, **kwargs)

    monkeypatch.setattr(v2_api, "_write_fed_peer_metadata", counted_write)
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    verifier = v2_api._market_fed_gossip_identity_verifier(
        SimpleNamespace(app=client.app),
    )

    assert verifier(peer_url, "93.184.216.34") == metadata["did"]
    assert verifier(peer_url, "93.184.216.34") == metadata["did"]
    assert writes == 1


def test_gossip_identity_verifier_rejects_learning_self(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.web.v2_api as v2_api
    from nth_dao.discovery.federation_registry import LearnedPeerStore

    client = TestClient(create_app(tmp_path, require_console_auth=False))
    local_identity = client.app.state.nth.node_identity
    peer_url = "https://self.example"
    monkeypatch.setattr(
        v2_api,
        "_fetch_and_verify_federation_identity",
        lambda *args, **kwargs: ({
            "peer_url": peer_url,
            "identity_url": f"{peer_url}/.well-known/nth-dao/identity.json",
            "did": local_identity.as_did(),
            "pubkey_hex": local_identity.pubkey_hex,
        }, ""),
    )
    verifier = v2_api._market_fed_gossip_identity_verifier(
        SimpleNamespace(app=client.app), persist_learned=True,
    )

    assert verifier(peer_url, "93.184.216.34") is None
    assert LearnedPeerStore(tmp_path).active() == []


def test_status_and_peer_gossip_include_active_learned_peers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.discovery.federation_registry import LearnedPeerStore

    peer_url = "https://durable.example"
    LearnedPeerStore(tmp_path).upsert_verified(
        peer_url,
        _verified_metadata(peer_url, "durable"),
    )
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.start_poller",
        lambda *args, **kwargs: None,
    )
    client = TestClient(create_app(tmp_path, require_console_auth=False))

    status = client.get("/api/v2/market/federation/status").json()
    directory = client.get("/api/v2/market/federation/peers").json()

    assert status["seed_peers"] == []
    assert status["peers"] == [peer_url]
    assert status["learned_peers"][peer_url]["did"] == _verified_metadata(
        peer_url, "durable",
    )["did"]
    assert directory["peers"] == [peer_url]


def test_refresh_passes_learned_peers_through_untrusted_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.discovery.federation_registry import LearnedPeerStore

    peer_url = "https://restart.example"
    LearnedPeerStore(tmp_path).upsert_verified(
        peer_url,
        _verified_metadata(peer_url, "restart"),
    )
    captured: dict = {}

    def fake_federate(peers, **kwargs):
        captured["seeds"] = peers
        captured["learned"] = kwargs.get("untrusted_peers")
        return {}

    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.start_poller",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.federate_once",
        fake_federate,
    )
    client = TestClient(create_app(tmp_path, require_console_auth=False))

    response = client.post("/api/v2/market/federation/refresh")

    assert response.status_code == 200, response.text
    assert captured == {"seeds": [], "learned": [peer_url]}


def test_public_peer_hello_fetches_verifies_and_persists_without_console_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.web.v2_api as v2_api

    peer_url = "https://new-node.example"
    metadata = {
        "peer_url": peer_url,
        "identity_url": f"{peer_url}/.well-known/nth-dao/identity.json",
        "did": NEW_NODE_DID,
        "pubkey_hex": "34" * 32,
    }
    observed: list[tuple[str, str, str]] = []
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll._resolve_safe_gossip_ip",
        lambda url: "93.184.216.34",
    )

    def fake_fetch(peer_url, *, timeout_seconds, expected_did="", resolved_ip=""):
        observed.append((peer_url, expected_did, resolved_ip))
        return metadata, ""

    monkeypatch.setattr(v2_api, "_fetch_and_verify_federation_identity", fake_fetch)
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.start_poller",
        lambda *args, **kwargs: None,
    )
    client = TestClient(create_app(tmp_path, require_console_auth=True))

    response = client.post(
        "/api/v2/market/federation/hello",
        json={"peer_url": peer_url, "did": NEW_NODE_DID},
    )

    assert response.status_code == 200, response.text
    assert response.json()["learned"] is True
    assert observed == [(peer_url, NEW_NODE_DID, "93.184.216.34")]
    assert client.get("/api/v2/market/federation/peers").json()["peers"] == [
        peer_url
    ]


def test_peer_hello_rejects_non_public_target_before_identity_fetch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.web.v2_api as v2_api

    fetched: list[str] = []
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll._resolve_safe_gossip_ip",
        lambda url: None,
    )
    monkeypatch.setattr(
        v2_api,
        "_fetch_and_verify_federation_identity",
        lambda peer_url, **kwargs: fetched.append(peer_url) or (None, "bad"),
    )
    client = TestClient(create_app(tmp_path, require_console_auth=False))

    response = client.post(
        "/api/v2/market/federation/hello",
        json={"peer_url": "https://private.example", "did": "did:key:zPrivate"},
    )

    assert response.status_code == 400
    assert fetched == []


def test_peer_hello_rejects_malformed_did_before_identity_fetch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.web.v2_api as v2_api

    fetched: list[str] = []
    monkeypatch.setattr(
        v2_api,
        "_fetch_and_verify_federation_identity",
        lambda peer_url, **kwargs: fetched.append(peer_url) or (None, "bad"),
    )
    client = TestClient(create_app(tmp_path, require_console_auth=False))

    response = client.post(
        "/api/v2/market/federation/hello",
        json={
            "peer_url": "https://public.example",
            "did": "did:key:z\N{SNOWMAN}",
        },
    )

    assert response.status_code == 400
    assert "valid Ed25519 did:key" in response.text
    assert fetched == []


def test_peer_hello_rate_limits_invalid_did_attempts(
    tmp_path: Path,
) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    payload = {
        "peer_url": "https://public.example",
        "did": "did:key:z-not-valid",
    }

    responses = [
        client.post("/api/v2/market/federation/hello", json=payload)
        for _ in range(6)
    ]
    # Simulate another web worker: no shared in-memory limiter instance, same
    # workspace-backed budget.
    delattr(client.app.state, "market_fed_hello_limiter")
    responses.extend(
        client.post("/api/v2/market/federation/hello", json=payload)
        for _ in range(7)
    )

    assert all(response.status_code == 400 for response in responses[:12])
    assert responses[12].status_code == 429
    assert "Retry-After" in responses[12].headers


def test_peer_hello_has_cross_client_global_budget(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    client.app.state.market_fed_hello_limiter = SimpleNamespace(
        check=lambda _key: SimpleNamespace(
            allowed=True, retry_after_seconds=0.0,
        )
    )
    payload = {
        "peer_url": "https://public.example",
        "did": "did:key:z-not-valid",
    }

    responses = [
        client.post("/api/v2/market/federation/hello", json=payload)
        for _ in range(121)
    ]

    assert all(response.status_code == 400 for response in responses[:120])
    assert responses[120].status_code == 429
    assert "Retry-After" in responses[120].headers


def test_federation_hello_proxy_header_requires_explicit_trust(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.web.v2_api as v2_api

    request = SimpleNamespace(
        client=SimpleNamespace(host="10.0.0.10"),
        headers={"x-forwarded-for": "203.0.113.8, 10.0.0.10"},
    )
    monkeypatch.delenv("NTH_TRUSTED_PROXY_IPS", raising=False)
    assert v2_api._federation_hello_client_key(request) == "10.0.0.10"

    monkeypatch.setenv("NTH_TRUSTED_PROXY_IPS", "10.0.0.10")
    assert v2_api._federation_hello_client_key(request) == "203.0.113.8"


def test_peer_hello_limiter_failure_is_fail_closed_without_path_leak(
    tmp_path: Path,
) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    client.app.state.market_fed_hello_limiter = SimpleNamespace(
        check=lambda _key: (_ for _ in ()).throw(
            OSError("C:" + "\\Users\\PrivateOperator\\limit.json")
        )
    )

    response = client.post(
        "/api/v2/market/federation/hello",
        json={"peer_url": "https://public.example", "did": NEW_NODE_DID},
    )

    assert response.status_code == 503
    assert "temporarily unavailable" in response.text
    assert "PrivateOperator" not in response.text


def test_peer_hello_does_not_expose_identity_fetch_details(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.web.v2_api as v2_api

    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll._resolve_safe_gossip_ip",
        lambda url: "93.184.216.34",
    )
    monkeypatch.setattr(
        v2_api,
        "_fetch_and_verify_federation_identity",
        lambda *args, **kwargs: (
            None,
            "identity card fetch failed at "
            + "C:"
            + "\\Users\\PrivateOperator\\identity.json",
        ),
    )
    client = TestClient(create_app(tmp_path, require_console_auth=False))

    response = client.post(
        "/api/v2/market/federation/hello",
        json={"peer_url": "https://broken.example", "did": NEW_NODE_DID},
    )

    assert response.status_code == 400
    assert "could not be verified" in response.text
    assert "PrivateOperator" not in response.text
    assert "identity.json" not in response.text


def test_peer_hello_does_not_expose_local_path_on_persistence_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.web.v2_api as v2_api

    peer_url = "https://write-fail.example"
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll._resolve_safe_gossip_ip",
        lambda url: "93.184.216.34",
    )
    monkeypatch.setattr(
        v2_api,
        "_fetch_and_verify_federation_identity",
        lambda *args, **kwargs: ({
            "peer_url": peer_url,
            "identity_url": f"{peer_url}/.well-known/nth-dao/identity.json",
            "did": NEW_NODE_DID,
            "pubkey_hex": "34" * 32,
        }, ""),
    )
    monkeypatch.setattr(
        v2_api,
        "_learned_fed_peer_store",
        lambda ws: SimpleNamespace(
            upsert_verified=lambda *args, **kwargs: (_ for _ in ()).throw(
                OSError("C:" + "\\Users\\PrivateOperator\\identity.json")
            )
        ),
    )
    client = TestClient(create_app(tmp_path, require_console_auth=False))

    response = client.post(
        "/api/v2/market/federation/hello",
        json={"peer_url": peer_url, "did": NEW_NODE_DID},
    )

    assert response.status_code == 503
    assert "PrivateOperator" not in response.text
    assert "temporarily unavailable" in response.text


def test_reverse_hello_callback_requires_explicit_public_https_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nth_dao.web.v2_api as v2_api

    monkeypatch.setenv("NTH_PUBLIC_BASE_URL", "https://self.example")
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    callback = v2_api._market_fed_announce_self(SimpleNamespace(app=client.app))
    called: list[tuple[list[str], str, str]] = []
    monkeypatch.setattr(
        "nth_dao.web.market_federation_poll.announce_peer_hello",
        lambda peers, *, peer_url, did: called.append((peers, peer_url, did)) or {},
    )

    assert callback is not None
    callback(["https://seed.example"])
    assert called[0][0] == ["https://seed.example"]
    assert called[0][1] == "https://self.example"
    assert called[0][2].startswith("did:key:")
