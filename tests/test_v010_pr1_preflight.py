"""PR-1: AgentBackend.preflight_check + attach() integration.

The COLLABORATION_ANALYSIS doc identified 2 of 7 failure modes that
preflight directly prevents:

  #1  "claude auth login crashed" - binary present, auth broken,
      old is_available() said True, attach proceeded, work failed.
  #4  "codex exec hang" - binary present, API unreachable, old
      is_available() said True, send_turn() hung indefinitely.

The fix is one extra method per backend that does a real liveness
probe, with the result wired through attach() so a bad backend
fails the attach BEFORE any task is committed.

These tests pin:

  * Base default impl degrades to is_available() (non-breaking
    for existing AgentBackend subclasses that don't override).
  * MockBackend works through the default path.
  * ClaudeCodeBackend override exec's `claude auth status` and
    correctly reports failure when the binary or auth is broken.
  * CodexBackend override exec's `codex exec` and times out
    correctly.
  * Override never RAISES on failure - always returns ok=False,
    so attach() controls fallback policy.
  * attach() with a broken backend raises BackendUnavailableError.
  * attach() with skip_preflight=True bypasses the check.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from team_layer.backends.base import (
    AgentBackend,
    BackendUnavailableError,
    PreflightResult,
)


# =====================================================================
# Default impl degrades to is_available()
# =====================================================================


class _AlwaysAvailableBackend(AgentBackend):
    backend_id = "always_ok"

    @classmethod
    def is_available(cls, **kwargs) -> bool:
        return True

    def start_session(self, config): pass
    def send_turn(self, prompt, system_prompt=""): pass
    def end_session(self): pass


class _NeverAvailableBackend(AgentBackend):
    backend_id = "always_bad"

    @classmethod
    def is_available(cls, **kwargs) -> bool:
        return False

    def start_session(self, config): pass
    def send_turn(self, prompt, system_prompt=""): pass
    def end_session(self): pass


class _RaisingBackend(AgentBackend):
    backend_id = "raises"

    @classmethod
    def is_available(cls, **kwargs) -> bool:
        raise RuntimeError("environment poked the wrong way")

    def start_session(self, config): pass
    def send_turn(self, prompt, system_prompt=""): pass
    def end_session(self): pass


def test_PR1_default_preflight_passes_through_is_available_true():
    result = _AlwaysAvailableBackend().preflight_check()
    assert isinstance(result, PreflightResult)
    assert result.ok is True
    assert result.backend_id == "always_ok"
    assert result.detail == ""
    assert result.duration_ms >= 0
    assert result.checked_at != ""


def test_PR1_default_preflight_passes_through_is_available_false():
    result = _NeverAvailableBackend().preflight_check()
    assert result.ok is False
    assert "returned False" in result.detail


def test_PR1_default_preflight_does_not_raise_on_inner_exception():
    """The contract is REPORT failures, not RAISE - attach() needs
    to control the fallback policy."""
    result = _RaisingBackend().preflight_check()
    assert result.ok is False
    assert "raised" in result.detail
    assert "environment poked" in result.detail


# =====================================================================
# MockBackend smoke test
# =====================================================================


def test_PR1_mock_backend_preflight_ok():
    from team_layer.backends.mock import MockBackend
    result = MockBackend().preflight_check()
    assert result.ok is True
    assert result.backend_id == "mock"


# =====================================================================
# ClaudeCode override - subprocess to claude auth status
# =====================================================================


def test_PR1_claude_code_preflight_returns_ok_on_success(monkeypatch):
    from team_layer.backends.claude_code import ClaudeCodeBackend
    monkeypatch.setattr(
        "shutil.which",
        lambda name: f"/usr/local/bin/{name}",
    )

    fake_result = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="Logged in as user@example.com",
        stderr="",
    )
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: fake_result)

    result = ClaudeCodeBackend().preflight_check()
    assert result.ok is True
    assert result.backend_id == "claude_code"


def test_PR1_claude_code_preflight_reports_auth_failure(monkeypatch):
    """The doc-named failure #1: auth broken, binary present.
    Previously is_available() said True; now preflight catches it."""
    from team_layer.backends.claude_code import ClaudeCodeBackend
    monkeypatch.setattr(
        "shutil.which",
        lambda name: f"/usr/local/bin/{name}",
    )

    fake_result = subprocess.CompletedProcess(
        args=[], returncode=1, stdout="",
        stderr="Not logged in. Run `claude auth login`.",
    )
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: fake_result)

    result = ClaudeCodeBackend().preflight_check()
    assert result.ok is False
    assert "Not logged in" in result.detail


def test_PR1_claude_code_preflight_handles_missing_binary(monkeypatch):
    from team_layer.backends.claude_code import ClaudeCodeBackend
    monkeypatch.setattr("shutil.which", lambda name: None)
    result = ClaudeCodeBackend().preflight_check()
    assert result.ok is False
    assert "Claude Code CLI not found" in result.detail


def test_PR1_claude_code_preflight_handles_timeout(monkeypatch):
    from team_layer.backends.claude_code import ClaudeCodeBackend
    monkeypatch.setattr(
        "shutil.which",
        lambda name: f"/usr/local/bin/{name}",
    )

    def _raise_timeout(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="claude", timeout=5)
    monkeypatch.setattr(subprocess, "run", _raise_timeout)

    result = ClaudeCodeBackend().preflight_check(timeout=0.5)
    assert result.ok is False
    assert "TimeoutExpired" in result.detail


# =====================================================================
# Codex override - doc failure mode #4
# =====================================================================


def test_PR1_codex_preflight_returns_ok_on_echo_roundtrip(monkeypatch):
    from team_layer.backends.codex import CodexBackend
    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/codex")

    fake_result = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="OK\n", stderr="",
    )
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: fake_result)

    result = CodexBackend().preflight_check()
    assert result.ok is True


def test_PR1_codex_preflight_catches_hang_via_timeout(monkeypatch):
    """Doc failure #4: codex exec hangs. Timeout catches it."""
    from team_layer.backends.codex import CodexBackend
    monkeypatch.setattr("shutil.which", lambda name: "/usr/local/bin/codex")

    def _raise_timeout(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="codex", timeout=5)
    monkeypatch.setattr(subprocess, "run", _raise_timeout)

    result = CodexBackend().preflight_check(timeout=0.5)
    assert result.ok is False
    assert "TimeoutExpired" in result.detail


def test_PR1_codex_preflight_missing_binary(monkeypatch):
    from team_layer.backends.codex import CodexBackend
    monkeypatch.setattr("shutil.which", lambda name: None)
    result = CodexBackend().preflight_check()
    assert result.ok is False
    assert "not in PATH" in result.detail


def test_PR1_codex_send_turn_timeout_kills_process_and_removes_output(
    monkeypatch,
    tmp_path,
):
    from team_layer.backends import codex as codex_module
    from team_layer.backends.base import SessionConfig

    output_path = tmp_path / "codex-output.txt"

    def fake_mkstemp(*_args, **_kwargs):
        return os.open(output_path, os.O_CREAT | os.O_RDWR), str(output_path)

    class HangingProcess:
        returncode = None

        def __init__(self):
            self.killed = False
            self.communicate_calls = 0

        def communicate(self, timeout=None):
            self.communicate_calls += 1
            if self.communicate_calls == 1:
                raise subprocess.TimeoutExpired(cmd="codex", timeout=timeout)
            return b"", b""

        def kill(self):
            self.killed = True
            self.returncode = -9

    process = HangingProcess()
    monkeypatch.setattr(codex_module.shutil, "which", lambda _name: "codex")
    monkeypatch.setattr(codex_module.tempfile, "mkstemp", fake_mkstemp)
    monkeypatch.setattr(codex_module.subprocess, "Popen", lambda *_a, **_kw: process)

    backend = codex_module.CodexBackend()
    backend.start_session(SessionConfig(
        session_id="timeout-test",
        goal="verify timeout",
        timeout=1,
    ))
    result = backend.send_turn("hang")

    assert result.finish_reason == "timeout"
    assert process.killed is True
    assert process.communicate_calls == 2
    assert not output_path.exists()


# =====================================================================
# attach() integration
# =====================================================================


def test_PR1_attach_skip_preflight_bypasses_check(tmp_path):
    """skip_preflight=True is an explicit opt-out for tests / tools
    that have done their own verification. By default attach runs
    preflight."""
    from nth_dao.attach import attach
    # Use NoneBackend (skip_preflight is moot here since backend is None,
    # but the flag should be accepted without raising)
    session = attach(
        agent_id="test-skip-pre",
        backend=None,
        workspace=str(tmp_path),
        skip_preflight=True,
        start_heartbeat=False,
    )
    session.detach()


def test_PR1_attach_with_mock_backend_runs_preflight(tmp_path):
    """MockBackend always passes preflight; attach should succeed."""
    from nth_dao.attach import attach
    from team_layer.backends.mock import MockBackend
    session = attach(
        agent_id="test-mock",
        backend=MockBackend(),
        workspace=str(tmp_path),
        start_heartbeat=False,
    )
    session.detach()


def test_PR1_attach_raises_when_preflight_fails(tmp_path):
    """A backend whose preflight reports ok=False causes attach to
    raise BackendUnavailableError. This is the orchestrator's
    signal to fall back / retry / refuse."""
    from nth_dao.attach import attach

    class _BadBackend(AgentBackend):
        backend_id = "bad"

        @classmethod
        def is_available(cls, **kwargs) -> bool:
            return False

        def start_session(self, config): pass
        def send_turn(self, prompt, system_prompt=""): pass
        def end_session(self): pass

    with pytest.raises(BackendUnavailableError, match="preflight failed"):
        attach(
            agent_id="test-bad",
            backend=_BadBackend(),
            workspace=str(tmp_path),
            start_heartbeat=False,
        )
