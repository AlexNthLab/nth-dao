from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import nth_dao.web as web_mod
from nth_dao.web import create_app


def _client(tmp_path: Path) -> TestClient:
    web_mod._lan_discover_limiter.reset()
    return TestClient(create_app(tmp_path))


def test_v2_lan_discover_alias_uses_same_member_gate(tmp_path: Path) -> None:
    client = _client(tmp_path)

    class _NoOpLAN:
        def __init__(self, *_, **__):
            pass

        def discover(self, *_, **__):
            return []

    with patch.object(web_mod, "LANDiscovery", _NoOpLAN):
        missing = client.post("/api/v2/agents/lan_discover", json={})
        stranger = client.post(
            "/api/v2/agents/lan_discover",
            json={"actor_id": "stranger"},
        )
        ok = client.post(
            "/api/v2/agents/lan_discover",
            json={"actor_id": "admin", "timeout_seconds": 0.5},
        )

    assert missing.status_code == 400
    assert stranger.status_code == 403
    assert ok.status_code == 200
    assert ok.json() == {"peers": []}


def test_v2_add_agent_alias_persists_contact_like_legacy_path(
    tmp_path: Path,
) -> None:
    client = _client(tmp_path)
    resp = client.post(
        "/api/v2/agents/add",
        json={
            "actor_id": "admin",
            "target_agent_id": "alice-agent",
            "label": "Alice",
        },
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["agent_id"] == "alice-agent"
    assert body["label"] == "Alice"

    search = client.get(
        "/api/agents/search",
        params={"q": "alice-agent", "actor_id": "admin"},
    )
    assert search.status_code == 200
    assert any(r["agent_id"] == "alice-agent" for r in search.json()["results"])
