from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.web import create_app
from nth_dao.web.market_federation_poll import FederationCache


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

    def fake_start_poller(get_peers, cache: FederationCache, *, interval_s, http_get=None):
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
        lambda peers: {ann.announcement_id: {"ann": ann, "source": peers[0]}},
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
