"""Local backend readiness endpoint for the v2 startup guide."""
from __future__ import annotations

from fastapi.testclient import TestClient

from nth_dao.web import create_app


def test_backend_status_endpoint_lists_supported_kinds_without_paths(tmp_path):
    app = create_app(workspace=tmp_path, require_console_auth=False)
    client = TestClient(app)

    resp = client.get("/api/v2/agents/backends/status")
    assert resp.status_code == 200
    body = resp.json()
    backends = body["backends"]
    assert set(backends) == {"mock", "claude-code", "codex", "hermes"}
    assert backends["mock"]["ready"] is True

    rendered = repr(body)
    assert "TonyWU" not in rendered
    assert "Users\\" not in rendered
    assert "ANTHROPIC_API_KEY" not in rendered
    assert "auth.json" not in rendered


def test_backend_status_route_is_not_swallowed_by_did_route(tmp_path):
    app = create_app(workspace=tmp_path, require_console_auth=False)
    client = TestClient(app)

    resp = client.get("/api/v2/agents/backends/status")
    assert resp.status_code == 200
    assert "backends" in resp.json()
