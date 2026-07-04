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


def test_backend_status_reports_codex_runtime_without_paths(tmp_path, monkeypatch):
    import nth_dao.web.dummy_agent as dummy_agent

    (tmp_path / ".codex").mkdir()
    monkeypatch.setattr(dummy_agent.Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(
        dummy_agent._CodexCliAskBackend,
        "_resolve_binary",
        lambda self: r"C:\Example\npm\codex.cmd",
    )
    monkeypatch.setattr(
        dummy_agent._CodexCliAskBackend,
        "_looks_like_node_shim",
        staticmethod(lambda _path: True),
    )

    status = dummy_agent.backend_runtime_status()["codex"]

    assert status["ready"] is True
    assert status["runtime"] == "node-shim"
    assert "npm shim" in status["detail"]
    rendered = repr(status)
    assert "Users" not in rendered
    assert "AppData" not in rendered
    assert "codex.cmd" not in rendered
