from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.web import create_app
from nth_dao.web.market_federation_poll import FederationCache


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


def test_federation_peer_add_remove_persists_normalized_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    started: list[tuple[list[str], float]] = []

    def fake_start_poller(
        get_peers,
        cache: FederationCache,
        *,
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
    assert json.loads((tmp_path / "federation" / "peers.json").read_text()) == []
    assert len(started) == 1


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
        lambda peer_url, *, timeout_seconds, expected_did="": (
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

    assert verifier("https://peer.example/", "93.184.216.34") is True
    assert verifier("https://peer.example", "93.184.216.34") is True
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

    assert verifier("https://peer.example", "93.184.216.34") is True
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

    assert results == [True, True]
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
