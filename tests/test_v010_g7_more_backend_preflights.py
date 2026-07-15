"""G-7 (Voss audit): hermes / openhands / openclaw get real preflight.

The original PR-1 only overrode preflight_check on ClaudeCode and
Codex. The other 3 backends inherited the default which just calls
is_available() - the audit doc itself flagged is_available as too
weak (binary existence only, no liveness probe).

Hermes is the NTH DAO main backend so it MUST have real preflight.
OpenHands and OpenClaw are HTTP-based - a stale URL pointing at a
dead server would pass is_available (URL is set) and only fail at
first send_turn().
"""

from __future__ import annotations

import subprocess
from unittest import mock

import pytest


# =====================================================================
# Hermes: real `hermes --version` round-trip
# =====================================================================


def test_G7_hermes_preflight_passes_on_successful_version(monkeypatch):
    from team_layer.backends.hermes import HermesBackend
    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/hermes")
    fake = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="hermes 0.5.1", stderr="",
    )
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: fake)

    result = HermesBackend().preflight_check()
    assert result.ok is True
    assert result.backend_id == "hermes"


def test_G7_hermes_preflight_reports_nonzero_returncode_as_failure(monkeypatch):
    from team_layer.backends.hermes import HermesBackend
    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/hermes")
    fake = subprocess.CompletedProcess(
        args=[], returncode=1, stdout="", stderr="hermes: not configured",
    )
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: fake)

    result = HermesBackend().preflight_check()
    assert result.ok is False
    assert "not configured" in result.detail


def test_G7_hermes_preflight_decodes_binary_windows_output(monkeypatch):
    from team_layer.backends.hermes import HermesBackend

    monkeypatch.setattr("shutil.which", lambda name: "C:/fake/hermes.exe")
    fake = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout="正常输出".encode("gbk"),
        stderr="失败原因".encode("gbk"),
    )
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: fake)

    result = HermesBackend().preflight_check()
    assert result.ok is False
    assert isinstance(result.detail, str)
    assert result.structured["returncode"] == 1


def test_G7_hermes_preflight_handles_timeout(monkeypatch):
    from team_layer.backends.hermes import HermesBackend
    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/hermes")

    def _raise(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="hermes", timeout=5)
    monkeypatch.setattr(subprocess, "run", _raise)

    result = HermesBackend().preflight_check(timeout=0.5)
    assert result.ok is False
    assert "TimeoutExpired" in result.detail


def test_G7_hermes_preflight_falls_back_to_module_probe_when_cli_missing(
    monkeypatch,
):
    """When hermes CLI isn't on PATH the preflight tries the
    is_available() module-import probe instead of immediately failing."""
    from team_layer.backends.hermes import HermesBackend
    monkeypatch.setattr("shutil.which", lambda name: None)
    monkeypatch.setattr(
        HermesBackend, "is_available", classmethod(lambda cls, **kw: True),
    )
    result = HermesBackend().preflight_check()
    assert result.ok is True


# =====================================================================
# OpenHands: HTTP /api/health
# =====================================================================


class _FakeResponse:
    def __init__(self, status: int):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_G7_openhands_preflight_passes_on_http_200(monkeypatch):
    from team_layer.backends.openhands import OpenHandsBackend
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *a, **kw: _FakeResponse(200),
    )
    result = OpenHandsBackend().preflight_check()
    assert result.ok is True
    assert result.structured.get("http_status") == 200


def test_G7_openhands_preflight_fails_on_http_500(monkeypatch):
    from team_layer.backends.openhands import OpenHandsBackend
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *a, **kw: _FakeResponse(500),
    )
    result = OpenHandsBackend().preflight_check()
    assert result.ok is False
    assert "500" in result.detail


def test_G7_openhands_preflight_handles_unreachable_server(monkeypatch):
    from team_layer.backends.openhands import OpenHandsBackend

    def _raise(*a, **kw):
        raise ConnectionRefusedError("connection refused")
    monkeypatch.setattr("urllib.request.urlopen", _raise)

    result = OpenHandsBackend().preflight_check(timeout=0.5)
    assert result.ok is False
    assert "ConnectionRefusedError" in result.detail


# =====================================================================
# OpenClaw: HTTP /health + URL configured check
# =====================================================================


def test_G7_openclaw_preflight_fails_when_url_not_set(monkeypatch):
    """Pre-fix: is_available() returned False (URL unset) but
    preflight inherited the default that only chained is_available.
    Now openclaw has its own explicit message about the env var."""
    from team_layer.backends.openclaw import OpenClawBackend
    monkeypatch.delenv("OPENCLAW_API_URL", raising=False)
    result = OpenClawBackend().preflight_check()
    assert result.ok is False
    assert "OPENCLAW_API_URL" in result.detail


def test_G7_openclaw_preflight_passes_on_http_200(monkeypatch):
    from team_layer.backends.openclaw import OpenClawBackend
    monkeypatch.setenv("OPENCLAW_API_URL", "https://openclaw.example.com")
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *a, **kw: _FakeResponse(200),
    )
    result = OpenClawBackend().preflight_check()
    assert result.ok is True


def test_G7_openclaw_preflight_fails_on_unreachable_server(monkeypatch):
    from team_layer.backends.openclaw import OpenClawBackend
    monkeypatch.setenv("OPENCLAW_API_URL", "https://openclaw.example.com")

    def _raise(*a, **kw):
        raise TimeoutError("network timeout")
    monkeypatch.setattr("urllib.request.urlopen", _raise)

    result = OpenClawBackend().preflight_check(timeout=0.5)
    assert result.ok is False
    assert "TimeoutError" in result.detail
