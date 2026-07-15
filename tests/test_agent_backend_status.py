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
    assert backends["mock"]["transport_ready"] is True
    assert backends["mock"]["provider_verified"] is True
    assert backends["hermes"]["provider_verified"] is False
    assert backends["codex"]["ask_timeout_s"] > 90
    assert backends["hermes"]["ask_timeout_s"] >= 170

    rendered = repr(body)
    assert str(tmp_path) not in rendered
    assert "ANTHROPIC_API_KEY" not in rendered
    assert "auth.json" not in rendered


def test_backend_status_route_is_not_swallowed_by_did_route(tmp_path):
    app = create_app(workspace=tmp_path, require_console_auth=False)
    client = TestClient(app)

    resp = client.get("/api/v2/agents/backends/status")
    assert resp.status_code == 200
    assert "backends" in resp.json()


def test_backend_status_projects_live_hermes_provider_state(tmp_path):
    from nth_dao.web.agent_supervisor import (
        AgentRecord, AgentSupervisor, InMemoryRunner,
    )

    app = create_app(workspace=tmp_path, require_console_auth=False)
    supervisor = AgentSupervisor(InMemoryRunner())
    record = AgentRecord(
        agent_id="live-hermes",
        kind="hermes",
        label="Live Hermes",
        did="did:key:z6MkLiveHermes",
        capabilities=[],
        started_at="now",
        last_seen="now",
        alive=True,
        provider_state="ready",
        provider_checked_at="2026-07-15T01:02:03+00:00",
    )
    supervisor._agents[record.agent_id] = record  # type: ignore[attr-defined]
    supervisor._runner._alive[record.agent_id] = True  # type: ignore[attr-defined]
    app.state.v2_supervisor = supervisor

    status = TestClient(app).get("/api/v2/agents/backends/status")

    assert status.status_code == 200
    hermes = status.json()["backends"]["hermes"]
    assert hermes["runtime"] == "provider-verified"
    assert hermes["provider_state"] == "ready"
    assert hermes["provider_verified"] is True
    assert hermes["last_provider_check_at"] == "2026-07-15T01:02:03+00:00"
    assert "live supervised Hermes" in hermes["detail"]


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
    monkeypatch.setattr(
        dummy_agent._CodexCliAskBackend,
        "_cli_contract_preflight",
        classmethod(lambda _cls, _path: (True, "", "codex-cli 1.2.3")),
    )

    status = dummy_agent.backend_runtime_status()["codex"]

    assert status["ready"] is True
    assert status["runtime"] == "node-shim"
    assert status["transport_ready"] is True
    assert status["provider_verified"] is False
    assert status["version"] == "codex-cli 1.2.3"
    assert "npm shim" in status["detail"]
    assert "approval" not in status["warning"].lower()
    rendered = repr(status)
    assert "Users" not in rendered
    assert "AppData" not in rendered
    assert "codex.cmd" not in rendered

    monkeypatch.setattr(
        dummy_agent._CodexCliAskBackend,
        "_looks_like_node_shim",
        staticmethod(lambda _path: False),
    )
    native = dummy_agent.backend_runtime_status()["codex"]
    assert native["runtime"] == "native"
    assert "approval" not in native["warning"].lower()


def test_codex_contract_preflight_rejects_cli_missing_required_flags(
    monkeypatch,
):
    import subprocess
    import nth_dao.web.dummy_agent as dummy_agent

    class _Result:
        returncode = 0
        stderr = ""

        def __init__(self, stdout: str):
            self.stdout = stdout

    def fake_run(argv, **_kwargs):
        if "--version" in argv:
            return _Result("codex-cli 0.1")
        return _Result("--sandbox --skip-git-repo-check")

    monkeypatch.setattr(subprocess, "run", fake_run)
    backend = dummy_agent._CodexCliAskBackend
    backend._clear_preflight_cache()

    ok, reason, version = backend._cli_contract_preflight("codex-old")

    assert ok is False
    assert "required supervised exec flags" in reason
    assert version == "codex-cli 0.1"


def test_backend_status_reports_hermes_model_without_secret_paths(
    tmp_path, monkeypatch,
):
    import importlib.util
    import nth_dao.web.dummy_agent as dummy_agent

    (tmp_path / ".hermes").mkdir()
    monkeypatch.setattr(dummy_agent.Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setenv("NTH_HERMES_MODEL", "fast-local")
    original_find_spec = importlib.util.find_spec

    class _Spec:
        pass

    def fake_find_spec(name: str):
        if name == "run_agent":
            return _Spec()
        return original_find_spec(name)

    monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)

    status = dummy_agent.backend_runtime_status()["hermes"]

    assert status["ready"] is True
    assert status["runtime"] == "provider-unverified"
    assert status["model"] == "fast-local"
    assert status["tool_policy"] == "safe-verified-on-start"
    assert status["unsafe_tools_enabled"] is False
    assert "provider responsiveness is not verified" in status["detail"]
    rendered = repr(status)
    assert "auth.json" not in rendered
    assert "Users" not in rendered
    assert str(tmp_path) not in rendered


def test_backend_status_discloses_unsafe_hermes_tool_opt_in(monkeypatch):
    import nth_dao.web.dummy_agent as dummy_agent

    monkeypatch.setenv("NTH_HERMES_TOOLSETS", "safe,terminal")
    monkeypatch.setenv("NTH_ALLOW_UNSAFE_HERMES_TOOLS", "1")

    status = dummy_agent.backend_runtime_status()["hermes"]

    assert status["tool_policy"] == "operator-unsafe"
    assert status["unsafe_tools_enabled"] is True
    assert "not an OS sandbox" in status["warning"]


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
