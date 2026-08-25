"""
OpenClawBackend  OpenClaw stub

OpenClaw  Claude Code  Runtime +  24/7
ACP (Agent Conversation Protocol)  HTTP/JSON.

 stub
- is_available()  False OPENCLAW_API_URL
- send_turn()  HTTP POST  ACP endpoint
-  OPENCLAW_API_URL + OPENCLAW_TOKEN


1.  OpenClaw  ACP listener
2.  envOPENCLAW_API_URL=http://localhost:8080
3.  token  envOPENCLAW_TOKEN=xxx
4. webhook / SSE
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Optional

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


class OpenClawBackend(AgentBackend):
    """OpenClaw ACP HTTP """

    backend_id = "openclaw"

    DEFAULT_TIMEOUT = 60

    def __init__(
        self,
        api_url: Optional[str] = None,
        token: Optional[str] = None,
        model: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(api_url=api_url, token=token, model=model, **kwargs)
        self.api_url = api_url or os.environ.get("OPENCLAW_API_URL")
        self.token = token or os.environ.get("OPENCLAW_TOKEN", "")
        self.model = model

    @classmethod
    def is_available(cls, api_url: Optional[str] = None, **kwargs) -> bool:
        """env  API URL"""
        url = api_url or os.environ.get("OPENCLAW_API_URL")
        return bool(url)

    def preflight_check(self, *, timeout: float = 5.0):
        """G-7 (Voss audit): real HTTP /health probe against the
        configured OPENCLAW_API_URL.

        is_available() only checked that the env var was SET, not
        that the endpoint actually answered. A stale URL pointing at
        a dead server would have passed the old check and broken at
        first send_turn().
        """
        # G-9 (Voss audit): imports promoted to module scope.
        t0 = time.monotonic()
        url = self.api_url or os.environ.get("OPENCLAW_API_URL")
        if not url:
            return PreflightResult(
                ok=False, backend_id=self.backend_id,
                checked_at=datetime.now(timezone.utc).isoformat(),
                duration_ms=int((time.monotonic() - t0) * 1000),
                detail="OPENCLAW_API_URL not configured",
            )
        try:
            req = urllib.request.Request(
                f"{url.rstrip('/')}/health", method="GET",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
        except Exception as exc:    # noqa: BLE001
            return PreflightResult(
                ok=False, backend_id=self.backend_id,
                checked_at=datetime.now(timezone.utc).isoformat(),
                duration_ms=int((time.monotonic() - t0) * 1000),
                detail=f"GET {url}/health: {type(exc).__name__}: {exc}",
            )
        ok = status == 200
        return PreflightResult(
            ok=ok, backend_id=self.backend_id,
            checked_at=datetime.now(timezone.utc).isoformat(),
            duration_ms=int((time.monotonic() - t0) * 1000),
            detail="" if ok else f"unexpected HTTP {status}",
            structured={"url": url, "http_status": status},
        )

    def start_session(self, config: SessionConfig) -> None:
        if not self.api_url:
            raise BackendUnavailableError(
                "OpenClawBackend requires OPENCLAW_API_URL env var "
                "(or api_url kwarg). See team_layer/backends/openclaw.py for setup."
            )
        self._session_config = config
        self._session_started_at = time.time()
        self._turn_count = 0
        self._cumulative_usage = TokenUsage()

    def send_turn(self, prompt: str, system_prompt: str = "") -> TurnResponse:
        if not self._session_config:
            raise RuntimeError("call start_session() first")

        start = self._track_turn_start()

        payload = {
            "session_id": self._session_config.session_id,
            "prompt": prompt,
            "system_prompt": system_prompt,
            "model": self.model,
            "max_tokens": self._session_config.max_tokens,
            "temperature": (
                0.7
                if self._session_config.temperature is None
                else self._session_config.temperature
            ),
            "metadata": {"backend": self.backend_id},
        }

        try:
            req = urllib.request.Request(
                f"{self.api_url.rstrip('/')}/acp/turn",
                data=json.dumps(payload).encode("utf-8"),
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.token}" if self.token else "",
                    "User-Agent": "nth-dao-agent/1.0",
                },
            )
            with urllib.request.urlopen(req, timeout=self._session_config.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            latency = self._track_turn_end(start, TokenUsage())
            return TurnResponse(
                content="",
                finish_reason="error",
                latency_seconds=latency,
                error=f"HTTP {e.code}: {e.reason}",
            )
        except (urllib.error.URLError, json.JSONDecodeError) as e:
            latency = self._track_turn_end(start, TokenUsage())
            return TurnResponse(
                content="",
                finish_reason="error",
                latency_seconds=latency,
                error=f"{type(e).__name__}: {e}",
            )
        except Exception as e:
            latency = self._track_turn_end(start, TokenUsage())
            return TurnResponse(
                content="",
                finish_reason="error",
                latency_seconds=latency,
                error=f"unexpected: {type(e).__name__}: {e}",
            )

        usage = TokenUsage(
            input_tokens=body.get("usage", {}).get("input_tokens", 0),
            output_tokens=body.get("usage", {}).get("output_tokens", 0),
        )
        latency = self._track_turn_end(start, usage)

        return TurnResponse(
            content=body.get("content", ""),
            finish_reason=body.get("finish_reason", "stop"),
            usage=usage,
            latency_seconds=latency,
            metadata={"backend": self.backend_id, **body.get("metadata", {})},
        )

    def end_session(self) -> SessionSummary:
        return self._build_summary()

    def capabilities(self) -> BackendCapabilities:
        return BackendCapabilities(
            supports_streaming=False,
            supports_tools=True,
            supports_system_prompt=True,
            supports_multi_turn=True,  # ACP
            supports_temperature=True,
            max_context_tokens=200_000,
            notes=(
                "OpenClaw via ACP HTTP. "
                "Set OPENCLAW_API_URL env var to enable. "
                "Persistent runtime, 24/7 autonomous mode."
            ),
        )
