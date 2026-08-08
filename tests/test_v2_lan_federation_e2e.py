"""Two-node LAN federation acceptance tests.

The UDP query is aimed at loopback because broadcast is not reliable in CI.
The query/hello transport, signed identity card, peer persistence, HTTP feed,
and Task verification are otherwise real.
"""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("nacl")
uvicorn = pytest.importorskip("uvicorn")

from fastapi.testclient import TestClient  # noqa: E402

from nth_dao.identity import crypto_available  # noqa: E402
from nth_dao.web import create_app  # noqa: E402

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="PyNaCl is required for signed federation",
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _BackgroundServer:
    def __init__(self, app, port: int) -> None:
        self._server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=port,
                log_level="error",
            )
        )
        self._thread = threading.Thread(
            target=self._server.run,
            name=f"nth-test-node-{port}",
            daemon=True,
        )

    def __enter__(self):
        self._thread.start()
        for _ in range(200):
            if self._server.started:
                return self
            time.sleep(0.025)
        raise RuntimeError("test federation node did not start")

    def __exit__(self, *_exc) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=5)


def test_discovered_node_is_verified_and_its_task_is_pulled_over_http(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A task published on node B becomes visible on node A after discovery."""
    import nth_dao.web.market_federation_poll as poll
    import nth_dao.web.v2_api as v2_api
    import nth_dao.discovery as discovery
    from nth_dao.discovery.lan import LANDiscovery

    source_port = _free_port()
    discovery_port = _free_port()
    source_url = f"http://127.0.0.1:{source_port}"
    monkeypatch.setenv("NTH_PUBLIC_BASE_URL", source_url)
    monkeypatch.setenv("NTH_LAN_PUBLISH", "1")
    monkeypatch.setenv("NTH_LAN_DISCOVERY", "1")
    monkeypatch.setenv("NTH_LAN_DISCOVERY_PORT", str(discovery_port))
    source_app = create_app(
        tmp_path / "source",
        require_console_auth=False,
    )
    source_did = source_app.state.nth.node_identity.as_did()

    with _BackgroundServer(source_app, source_port):
        published = TestClient(source_app).post(
            "/api/v2/market/announce",
            json={
                "title": "LAN federation acceptance task",
                "capability_set": ["code_review"],
                "reward_minor": 7,
            },
        )
        assert published.status_code == 200, published.text
        announcement_id = published.json()["announcement_id"]

        target_app = create_app(
            tmp_path / "target",
            require_console_auth=False,
        )
        target = TestClient(target_app)
        class _LoopbackQuerier(LANDiscovery):
            def discover(self, timeout=3.0, wanted_capabilities=None, target_addrs=None):
                return super().discover(
                    timeout=timeout,
                    wanted_capabilities=wanted_capabilities,
                    target_addrs=["127.0.0.1"],
                )

        monkeypatch.setattr(discovery, "LANDiscovery", _LoopbackQuerier)
        monkeypatch.setattr(discovery, "mdns_available", lambda: False)
        # Loopback stands in for two private LAN addresses in CI. Keep the
        # source-IP binding check unchanged; only public-IP rejection is
        # replaced because loopback is deliberately forbidden in production.
        monkeypatch.setattr(
            v2_api,
            "_resolve_safe_discovered_federation_ip",
            lambda _url: "127.0.0.1",
        )
        monkeypatch.setattr(
            poll,
            "_resolve_safe_gossip_ip",
            lambda _url, **_kwargs: "127.0.0.1",
        )

        discovered = target.post(
            "/api/v2/market/federation/discover",
            json={
                "actor_id": "admin",
                "timeout_seconds": 1.0,
                "add": True,
                "refresh": True,
            },
        )
        assert discovered.status_code == 200, discovered.text
        body = discovered.json()
        assert body["identity_verified_peers"] == [source_url]
        assert body["imported_peers"] == [source_url]
        assert body["skipped_peers"] == []
        assert body["discovered_peers"][0]["peer_did"] == source_did

        visible = target.get("/api/v2/market/open")
        assert visible.status_code == 200, visible.text
        rows = visible.json()
        remote = next(
            row for row in rows
            if row["announcement_id"] == announcement_id
        )
        assert remote["federated"] is True
        assert remote["source_peer"] == source_url
