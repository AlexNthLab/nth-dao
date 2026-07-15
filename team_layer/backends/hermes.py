"""
HermesBackend   hermes-agent CLI


1.  hermes python -c "import hermes")
2.  subprocess  `python -m hermes.cli` `hermes`
3.  batch_runner  prompt  response


-  `pip install -e .`  Hermes
-  Hermes  tool/skill  NTH DAO runtime

 Hermes is_available()  False backend
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from typing import Optional

from datetime import datetime, timezone

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


class HermesBackend(AgentBackend):
    """Hermes Agent subprocess """

    backend_id = "hermes"

    #  Hermes
    HERMES_ENTRYPOINTS = [
        ["hermes"],                                    #  PATH
        [sys.executable, "-m", "hermes_cli.main"],     # python -m hermes_cli.main (Windows compat)
        [sys.executable, "-m", "hermes"],              # python -m hermes
    ]

    def __init__(
        self,
        model: Optional[str] = None,
        hermes_args: Optional[list] = None,
        **kwargs,
    ):
        """
        Args:
            model:  "anthropic/claude-sonnet-4-6"
            hermes_args:  hermes CLI
        """
        super().__init__(model=model, **kwargs)
        self.model = model
        self.hermes_args = hermes_args or []
        self._cmd: Optional[list] = None  #

    @classmethod
    def is_available(cls, **kwargs) -> bool:
        """ hermes CLI """
        # 1.  PATH  hermes
        if shutil.which("hermes"):
            return True
        # 2.  python -m hermes
        try:
            # Use binary mode to avoid Windows UTF-8/GBK decode errors
            result = subprocess.run(
                [sys.executable, "-c", "import hermes; print('ok')"],
                capture_output=True,
                timeout=5,
            )
            stdout = _decode_process_output(result.stdout)
            return result.returncode == 0 and "ok" in stdout
        except Exception:
            return False

    def preflight_check(self, *, timeout: float = 5.0):
        """G-7 (Voss audit): real `hermes --version` round-trip.

        The COLLABORATION_ANALYSIS doc named Hermes as the NTH DAO
        main backend - it MUST not fall back to the weak default
        ``is_available()`` (which only checks ``shutil.which``).
        Running ``hermes --version`` confirms the CLI not only exists
        on PATH but actually executes successfully.
        """
        # G-9 (Voss audit): imports promoted to module scope.
        t0 = time.monotonic()
        if not shutil.which("hermes"):
            # Fall back to module import probe per is_available()
            available = self.is_available()
            return PreflightResult(
                ok=available, backend_id=self.backend_id,
                checked_at=datetime.now(timezone.utc).isoformat(),
                duration_ms=int((time.monotonic() - t0) * 1000),
                detail="" if available else (
                    "hermes CLI not in PATH and `import hermes` failed"
                ),
            )
        # Resolve .CMD shim on Windows (shutil.which returns the full path)
        cli = shutil.which("hermes")
        try:
            result = subprocess.run(
                [cli, "--version"],
                stdin=subprocess.DEVNULL,
                capture_output=True, timeout=timeout,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            return PreflightResult(
                ok=False, backend_id=self.backend_id,
                checked_at=datetime.now(timezone.utc).isoformat(),
                duration_ms=int((time.monotonic() - t0) * 1000),
                detail=f"hermes --version {type(exc).__name__}: {exc}",
            )
        ok = result.returncode == 0
        stdout = _decode_process_output(result.stdout)
        stderr = _decode_process_output(result.stderr)
        return PreflightResult(
            ok=ok, backend_id=self.backend_id,
            checked_at=datetime.now(timezone.utc).isoformat(),
            duration_ms=int((time.monotonic() - t0) * 1000),
            detail="" if ok else (stderr or stdout).strip()[:200],
            structured={
                "returncode": result.returncode,
                "stdout_head": stdout[:500],
            },
        )

    def _resolve_cmd(self) -> list:
        """ hermes """
        if self._cmd is not None:
            return self._cmd
        for cmd in self.HERMES_ENTRYPOINTS:
            try:
                result = subprocess.run(
                    cmd + ["--help"],
                    capture_output=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    self._cmd = cmd
                    return cmd
            except Exception:
                continue
        raise BackendUnavailableError("no working hermes entrypoint found")

    def start_session(self, config: SessionConfig) -> None:
        if not self.is_available():
            raise BackendUnavailableError(
                "HermesBackend requires `pip install -e .` (Hermes is in this repo)"
            )
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
        cmd = self._resolve_cmd()

        # Hermes CLI: `hermes chat -q QUERY -Q -m MODEL`
        # - chat  single-query non-interactive
        # - -q / --query
        # - -Q / --quiet      banner/spinner
        # - -m / --model
        # Hermes  --system system_prompt  query
        #  ** --ignore-user-config hermes  ~/.hermes/config.yaml + .env
        #        .env  API key  CI
        #        hermes_args=["--ignore-user-config"]
        full_prompt = self._compose_prompt(system_prompt, prompt)

        full_args = list(cmd) + ["chat", "-q", full_prompt, "-Q"]
        if self.model:
            full_args += ["-m", self.model]
        #  args --provider / --skills / --max-turns / --ignore-user-config
        full_args += self.hermes_args

        cwd = str(self._session_config.workdir) if self._session_config.workdir else None
        env = {**os.environ, **self._session_config.env}
        env.setdefault("PYTHONIOENCODING", "utf-8")

        try:
            #  Popen +  read  subprocess.run
            # Python 3.14  Windows  UTF-8 locale ( CP936/GBK)
            # subprocess.run/communicate  _readerthread  binary
            #  unhandled UnicodeDecodeError  stderr
            # Popen + read()
            popen = subprocess.Popen(
                full_args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=cwd,
            )
            try:
                stdout_bytes = popen.stdout.read()
                stderr_bytes = popen.stderr.read()
                popen.wait(timeout=self._session_config.timeout)
            finally:
                try:
                    popen.stdout.close()
                    popen.stderr.close()
                except Exception:
                    pass

            returncode = popen.returncode
            proc_stdout = (stdout_bytes or b"").decode("utf-8", errors="replace")
            proc_stderr = (stderr_bytes or b"").decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            latency = self._track_turn_end(start, TokenUsage())
            return TurnResponse(
                content="",
                finish_reason="timeout",
                latency_seconds=latency,
                error=f"hermes timed out after {self._session_config.timeout}s",
            )
        except Exception as e:
            latency = self._track_turn_end(start, TokenUsage())
            return TurnResponse(
                content="",
                finish_reason="error",
                latency_seconds=latency,
                error=f"subprocess failed: {type(e).__name__}: {e}",
            )

        stdout = proc_stdout
        stderr = proc_stderr

        #  Hermes exit 0  setup
        if self._looks_unconfigured(stdout, stderr):
            latency = self._track_turn_end(start, TokenUsage())
            return TurnResponse(
                content=stdout.strip(),
                finish_reason="error",
                latency_seconds=latency,
                error=(
                    "Hermes is not configured. Run: hermes setup "
                    "(or `hermes login` for OAuth providers, "
                    "or set provider API keys via `hermes secrets`)"
                ),
            )

        usage = self._extract_usage(stdout, stderr)
        latency = self._track_turn_end(start, usage)

        if returncode != 0:
            return TurnResponse(
                content=stdout.strip(),
                finish_reason="error",
                usage=usage,
                latency_seconds=latency,
                error=f"hermes exit {returncode}: {stderr[:300] or stdout[:300]}",
            )

        # Quiet  stdout  session info
        content = self._extract_final_response(stdout)

        return TurnResponse(
            content=content,
            finish_reason="stop",
            usage=usage,
            latency_seconds=latency,
            metadata={"backend": self.backend_id, "cmd": cmd},
        )

    #  prompt

    @staticmethod
    def _compose_prompt(system_prompt: str, user_prompt: str) -> str:
        """Hermes  --system system  user """
        if not system_prompt:
            return user_prompt
        return (
            "<system-context>\n"
            f"{system_prompt}\n"
            "</system-context>\n\n"
            f"{user_prompt}"
        )

    #

    @staticmethod
    def _looks_unconfigured(stdout: str, stderr: str) -> bool:
        """ Hermes """
        markers = [
            "isn't configured yet",
            "no API keys or providers found",
            "Run:  hermes setup",
            "Run: hermes setup",
        ]
        combined = (stdout or "") + "\n" + (stderr or "")
        return any(m in combined for m in markers)

    @staticmethod
    def _extract_final_response(stdout: str) -> str:
        """
        Quiet  stdout  final response session info
         'Session ID:' / 'Session:'
        """
        if not stdout:
            return ""
        lines = stdout.rstrip().split("\n")
        #  session
        while lines and (
            lines[-1].strip().startswith(("Session ID:", "Session:", "Tokens used:", "Cost:"))
            or not lines[-1].strip()
        ):
            lines.pop()
        return "\n".join(lines).strip()

    def end_session(self) -> SessionSummary:
        return self._build_summary()

    def capabilities(self) -> BackendCapabilities:
        return BackendCapabilities(
            supports_streaming=False,  # subprocess
            supports_tools=True,        # Hermes  tool/skill
            supports_system_prompt=True,
            supports_multi_turn=False,  #  batch one-shot
            max_context_tokens=200_000,
            notes="Hermes via subprocess. Install with: pip install -e . (current repo)",
        )

    #

    @staticmethod
    def _extract_usage(stdout: str, stderr: str) -> TokenUsage:
        """ Hermes  token best-effort"""
        usage = TokenUsage()
        # Hermes  statusline  token  "[12345 tokens]"
        combined = (stdout or "") + "\n" + (stderr or "")
        import re
        m = re.search(r"input[:\s]+(\d+)\s*tokens?", combined, re.I)
        if m:
            usage.input_tokens = int(m.group(1))
        m = re.search(r"output[:\s]+(\d+)\s*tokens?", combined, re.I)
        if m:
            usage.output_tokens = int(m.group(1))
        return usage
