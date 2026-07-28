"""Two-node LAN federation acceptance tests.

The discovery transport is injected because multicast is not reliable in CI.
Everything after discovery is real: a signed identity card is fetched over a
socket, the peer is persisted, and its signed task feed is pulled over HTTP.
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

    source_app = create_app(
        tmp_path / "source",
        require_console_auth=False,
    )
    source_port = _free_port()
    source_url = f"http://127.0.0.1:{source_port}"
    source_app.state.nth_public_base_url = source_url
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
        monkeypatch.setattr(
            v2_api,
            "_discover_market_federation_peers",
            lambda *_args, **_kwargs: ([
                {
                    "agent_id": "source-node",
                    "label": "Source DAO",
                    "did": source_did,
                    "capabilities": ["nth-dao-federation"],
                    "groups": ["home"],
                    "ws_url": source_url,
                    "source_addr": f"127.0.0.1:{source_port}",
                    "federation_peer_url": source_url,
                    "metadata": {"federation_url": source_url},
                }
            ], []),
        )
        # Loopback stands in for two private LAN addresses in CI. Keep the
        # production resolver and source-IP checks unchanged.
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

        visible = target.get("/api/v2/market/open")
        assert visible.status_code == 200, visible.text
        rows = visible.json()
        remote = next(
            row for row in rows
            if row["announcement_id"] == announcement_id
        )
        assert remote["federated"] is True
        assert remote["source_peer"] == source_url
