"""
ClaudeCodeBackend   Anthropic Claude Code CLI


-  `claude -p "<prompt>" --output-format stream-json`
-  stream-json NDJSON JSON
-  token


-  npm  @anthropic-ai/claude-code
-  cli.js NTH Agent Pro  ClaudeCodeBridge


-  NTH Agent Pro: src/nth_agent_pro/claude_code_bridge.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List, Optional

from .base import (
    AgentBackend,
    BackendCapabilities,
    BackendUnavailableError,
    PreflightResult,
    SessionConfig,
    SessionSummary,
    TokenUsage,
    TurnResponse,
)


def _decode_process_output(value: object) -> str:
    """Decode CLI output without inheriting the Windows console codec."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    return str(value or "")


class ClaudeCodeBackend(AgentBackend):
    """Claude Code CLI """

    backend_id = "claude_code"

    # CLI
    CLI_NAMES = ["claude", "claude-code"]

    def __init__(
        self,
        cli_path: Optional[str] = None,
        model: Optional[str] = None,
        allowed_tools: Optional[List[str]] = None,
        **kwargs,
    ):
        """
        Args:
            cli_path:  CLI None
            model:  "claude-sonnet-4-6"
            allowed_tools:
        """
        super().__init__(cli_path=cli_path, model=model, **kwargs)
        self._cli_path = cli_path
        self.model = model
        self.allowed_tools = allowed_tools

    @classmethod
    def is_available(cls, cli_path: Optional[str] = None, **kwargs) -> bool:
        """ claude CLI """
        if cli_path:
            return Path(cli_path).exists()
        for name in cls.CLI_NAMES:
            if shutil.which(name):
                return True
        return False

    def preflight_check(self, *, timeout: float = 5.0):
        """PR-1: real Claude auth check, not just binary presence.

        Doc-level failure mode #1: claude auth login crashed but the
        binary existed, so the previous ``is_available()`` returned
        True and the attach proceeded. ``claude auth status`` is the
        one-shot CLI call that surfaces the broken auth state.
        """
        # G-9 (Voss audit): imports promoted to module scope.
        t0 = time.monotonic()
        try:
            cli = self._resolve_cli()
        except BackendUnavailableError as exc:
            return PreflightResult(
                ok=False, backend_id=self.backend_id,
                checked_at=datetime.now(timezone.utc).isoformat(),
                duration_ms=int((time.monotonic() - t0) * 1000),
                detail=str(exc),
            )
        try:
            result = subprocess.run(
                [cli, "auth", "status"],
                stdin=subprocess.DEVNULL,
                capture_output=True, timeout=timeout,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            return PreflightResult(
                ok=False, backend_id=self.backend_id,
                checked_at=datetime.now(timezone.utc).isoformat(),
                duration_ms=int((time.monotonic() - t0) * 1000),
                detail=f"claude auth status {type(exc).__name__}: {exc}",
            )
        stdout = _decode_process_output(result.stdout)
        stderr = _decode_process_output(result.stderr)
        ok = result.returncode == 0
        detail = "" if ok else (stderr or stdout).strip()[:200]
        return PreflightResult(
            ok=ok, backend_id=self.backend_id,
            checked_at=datetime.now(timezone.utc).isoformat(),
            duration_ms=int((time.monotonic() - t0) * 1000),
            detail=detail,
            structured={
                "returncode": result.returncode,
                "stdout_head": stdout[:500],
            },
        )

    def _resolve_cli(self) -> str:
        """ CLI """
        if self._cli_path:
            return self._cli_path
        for name in self.CLI_NAMES:
            found = shutil.which(name)
            if found:
                return found
        raise BackendUnavailableError(
            "Claude Code CLI not found. Install with: "
            "npm install -g @anthropic-ai/claude-code"
        )

    def start_session(self, config: SessionConfig) -> None:
        if not self.is_available(cli_path=self._cli_path):
            raise BackendUnavailableError("claude CLI not available")
        self._session_config = config
        self._session_started_at = time.time()
        self._turn_count = 0
        self._cumulative_usage = TokenUsage()

    def send_turn(
        self,
        prompt: str,
        system_prompt: str = "",
    ) -> TurnResponse:
        if not self._session_config:
            raise RuntimeError("call start_session() first")

        start = self._track_turn_start()
        cli = self._resolve_cli()

        #  ClaudeCodeBridge
        args = [cli, "-p", "--output-format", "stream-json", "--verbose"]
        if self.model:
            args += ["--model", self.model]
        if self.allowed_tools:
            args += ["--allowedTools", ",".join(self.allowed_tools)]
        if system_prompt:
            args += ["--append-system-prompt", system_prompt]

        # workdir
        cwd = str(self._session_config.workdir) if self._session_config.workdir else None
        env = {**os.environ, **self._session_config.env}
        env.setdefault("PYTHONIOENCODING", "utf-8")

        try:
            #  Popen + binary read hermes.py  Python 3.14 Windows
            #  UTF-8 locale  subprocess.run reader thread  UnicodeDecodeError
            popen = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=env,
            )
            try:
                stdout_bytes, stderr_bytes = popen.communicate(
                    input=prompt.encode("utf-8"),
                    timeout=self._session_config.timeout,
                )
            finally:
                # communicate  PIPE defensive
                pass
            returncode = popen.returncode
            stdout = (stdout_bytes or b"").decode("utf-8", errors="replace")
            stderr = (stderr_bytes or b"").decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            latency = self._track_turn_end(start, TokenUsage())
            return TurnResponse(
                content="",
                finish_reason="timeout",
                latency_seconds=latency,
                error=f"claude CLI timed out after {self._session_config.timeout}s",
            )
        except Exception as e:
            latency = self._track_turn_end(start, TokenUsage())
            return TurnResponse(
                content="",
                finish_reason="error",
                latency_seconds=latency,
                error=f"subprocess failed: {type(e).__name__}: {e}",
            )

        #  stream-json (NDJSON)
        content, usage, finish_reason, error = self._parse_stream_json(
            stdout, stderr, returncode
        )
        latency = self._track_turn_end(start, usage)

        return TurnResponse(
            content=content,
            finish_reason=finish_reason,
            usage=usage,
            latency_seconds=latency,
            error=error,
            metadata={"backend": self.backend_id, "cli": cli},
        )

    def end_session(self) -> SessionSummary:
        return self._build_summary()

    def capabilities(self) -> BackendCapabilities:
        return BackendCapabilities(
            supports_streaming=True,
            supports_tools=True,
            supports_system_prompt=True,
            supports_multi_turn=False,  #
            max_context_tokens=200_000,
            cost_per_1k_input=3.0,    # Sonnet pricing ~ $3/M
            cost_per_1k_output=15.0,
            notes=(
                "Anthropic Claude Code CLI. "
                "Install: npm install -g @anthropic-ai/claude-code. "
                "Requires ANTHROPIC_API_KEY or claude login."
            ),
        )

    #

    def _parse_stream_json(
        self,
        stdout: str,
        stderr: str,
        returncode: int,
    ) -> tuple:
        """
         Claude Code  stream-json NDJSON

        (content, usage, finish_reason, error)
        """
        if returncode != 0:
            error = (stderr or "")[:500] or f"exit {returncode}"
            return "", TokenUsage(), "error", error

        content_parts = []
        usage = TokenUsage()
        finish_reason = "stop"

        for line in (stdout or "").split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            event_type = event.get("type", "")

            #
            if event_type == "assistant":
                msg = event.get("message", {})
                for block in msg.get("content", []):
                    if isinstance(block, dict) and block.get("type") == "text":
                        content_parts.append(block.get("text", ""))

            #  usage
            elif event_type == "result":
                if event.get("subtype") == "success":
                    finish_reason = "stop"
                else:
                    finish_reason = event.get("subtype", "error")
                result_usage = event.get("usage", {})
                usage.input_tokens = result_usage.get("input_tokens", 0)
                usage.output_tokens = result_usage.get("output_tokens", 0)

        return "\n".join(content_parts).strip(), usage, finish_reason, None
