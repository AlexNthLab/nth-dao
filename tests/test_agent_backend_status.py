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


def test_backend_status_gates_windows_claude_cli_without_conpty(
    tmp_path, monkeypatch,
):
    import importlib.util
    import shutil
    import nth_dao.web.dummy_agent as dummy_agent

    monkeypatch.setattr(dummy_agent.Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(dummy_agent.sys, "platform", "win32")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    original_find_spec = importlib.util.find_spec

    def fake_find_spec(name: str):
        if name in {"anthropic", "winpty", "pywinpty", "run_agent"}:
            return None
        return original_find_spec(name)

    def fake_which(name: str):
        if name == "claude":
            return r"C:\Example\bin\claude.exe"
        return None

    monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)
    monkeypatch.setattr(shutil, "which", fake_which)

    status = dummy_agent.backend_runtime_status()["claude-code"]

    assert status["available"] is True
    assert status["ready"] is False
    assert status["runtime"] == "cli-needs-conpty"
    assert "ConPTY" in status["detail"]
    rendered = repr(status)
    assert "C:\\Example" not in rendered
    assert "claude.exe" not in rendered


def test_backend_status_keeps_windows_claude_cli_disabled_with_pywinpty(
    tmp_path, monkeypatch,
):
    import importlib.util
    import shutil
    import nth_dao.web.dummy_agent as dummy_agent

    monkeypatch.setattr(dummy_agent.Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(dummy_agent.sys, "platform", "win32")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    original_find_spec = importlib.util.find_spec

    class _Spec:
        pass

    def fake_find_spec(name: str):
        if name == "winpty":
            return _Spec()
        if name in {"anthropic", "run_agent"}:
            return None
        return original_find_spec(name)

    def fake_which(name: str):
        if name == "claude":
            return r"C:\Example\bin\claude.CMD"
        return None

    monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)
    monkeypatch.setattr(shutil, "which", fake_which)

    status = dummy_agent.backend_runtime_status()["claude-code"]

    assert status["available"] is True
    assert status["ready"] is False
    assert status["runtime"] == "cli-conpty-disabled"
    assert "disabled by default" in status["detail"]
    rendered = repr(status)
    assert "C:\\Example" not in rendered
    assert "claude.CMD" not in rendered


def test_backend_status_rejects_windows_claude_cli_when_health_fails(
    tmp_path, monkeypatch,
):
    import importlib.util
    import shutil
    import nth_dao.web.dummy_agent as dummy_agent

    monkeypatch.setattr(dummy_agent.Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(dummy_agent.sys, "platform", "win32")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("NTH_ENABLE_WINDOWS_CLAUDE_CLI", "1")
    original_find_spec = importlib.util.find_spec

    class _Spec:
        pass

    def fake_find_spec(name: str):
        if name == "winpty":
            return _Spec()
        if name in {"anthropic", "run_agent"}:
            return None
        return original_find_spec(name)

    def fake_which(name: str):
        if name == "claude":
            return r"C:\Example\bin\claude.CMD"
        return None

    monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)
    monkeypatch.setattr(shutil, "which", fake_which)
    monkeypatch.setattr(
        dummy_agent._ClaudeCliAskBackend,
        "_windows_cli_health",
        classmethod(lambda cls: (False, "health-access-violation")),
    )

    status = dummy_agent.backend_runtime_status()["claude-code"]

    assert status["available"] is True
    assert status["ready"] is False
    assert status["runtime"] == "cli-conpty-unhealthy"
    assert "health-access-violation" in status["detail"]
    rendered = repr(status)
    assert "C:\\Example" not in rendered
    assert "claude.CMD" not in rendered


def test_backend_status_allows_windows_claude_cli_with_explicit_opt_in(
    tmp_path, monkeypatch,
):
    import importlib.util
    import shutil
    import nth_dao.web.dummy_agent as dummy_agent

    monkeypatch.setattr(dummy_agent.Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(dummy_agent.sys, "platform", "win32")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("NTH_ENABLE_WINDOWS_CLAUDE_CLI", "1")
    original_find_spec = importlib.util.find_spec

    class _Spec:
        pass

    def fake_find_spec(name: str):
        if name == "winpty":
            return _Spec()
        if name in {"anthropic", "run_agent"}:
            return None
        return original_find_spec(name)

    def fake_which(name: str):
        if name == "claude":
            return r"C:\Example\bin\claude.CMD"
        return None

    monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)
    monkeypatch.setattr(shutil, "which", fake_which)
    monkeypatch.setattr(
        dummy_agent._ClaudeCliAskBackend,
        "_windows_cli_health",
        classmethod(lambda cls: (True, "ok")),
    )

    status = dummy_agent.backend_runtime_status()["claude-code"]

    assert status["available"] is True
    assert status["ready"] is True
    assert status["runtime"] == "cli-conpty"
    assert "pywinpty" in status["detail"]
    rendered = repr(status)
    assert "C:\\Example" not in rendered
    assert "claude.CMD" not in rendered
