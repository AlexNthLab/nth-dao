"""
AgentBackend ABC +

 backend
    is_available()         backend
    start_session()
    send_turn()
    end_session()


    stream_turn()          send_turn  chunk
    capabilities()
"""

from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


#
# Exceptions
#

class BackendUnavailableError(RuntimeError):
    """backend API key """


#
#
#

@dataclass
class TokenUsage:
    """ /  token """
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens

    def __add__(self, other: "TokenUsage") -> "TokenUsage":
        return TokenUsage(
            self.input_tokens + other.input_tokens,
            self.output_tokens + other.output_tokens,
        )


@dataclass
class ToolCall:
    """backend  turn """
    name: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    id: str = ""


@dataclass
class SessionConfig:
    """ backend """
    session_id: str
    goal: str
    model: Optional[str] = None
    # None means the caller did not request a temperature override. Backends
    # may then choose their own default; an explicit 0.7 remains explicit.
    temperature: Optional[float] = None
    max_tokens: int = 4096
    timeout: int = 120
    workdir: Optional[Path] = None
    env: Dict[str, str] = field(default_factory=dict)
    #
    allowed_tools: Optional[List[str]] = None  # None = backend
    #  backend
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TurnResponse:
    """"""
    content: str
    finish_reason: str = "stop"   # stop / length / tool_call / error / timeout
    usage: TokenUsage = field(default_factory=TokenUsage)
    tool_calls: List[ToolCall] = field(default_factory=list)
    latency_seconds: float = 0.0
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_error(self) -> bool:
        return self.finish_reason == "error" or self.error is not None


@dataclass
class SessionSummary:
    """"""
    session_id: str
    backend_id: str
    total_turns: int
    total_usage: TokenUsage
    duration_seconds: float
    final_status: str = "completed"  # completed / interrupted / error / timeout
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BackendCapabilities:
    """backend  NTH DAO runtime """
    supports_streaming: bool = False
    supports_tools: bool = False
    supports_system_prompt: bool = True
    supports_multi_turn: bool = True
    # A false value means SessionConfig.temperature is not an execution
    # control for this backend. Adapters must reject every explicit override.
    supports_temperature: bool = False
    max_context_tokens: int = 8192
    # USD / 1k tokens 0
    cost_per_1k_input: float = 0.0
    cost_per_1k_output: float = 0.0
    notes: str = ""


@dataclass
class PreflightResult:
    """PR-1: outcome of AgentBackend.preflight_check().

    Returned by the pre-attach feasibility check so the orchestrator
    can decide between (a) proceeding, (b) falling back to another
    backend, and (c) refusing the attach with an audit-trail entry.

    Fields
    ------
    ok
        True iff the backend is usable RIGHT NOW (auth valid, binary
        responsive within timeout, network reachable as applicable).
    backend_id
        Mirrors ``AgentBackend.backend_id`` so the caller can
        correlate against the registry without re-introspecting.
    checked_at
        ISO-8601 UTC. Together with ``duration_ms`` lets ops graph
        preflight health over time.
    duration_ms
        Wall-clock cost. Useful when investigating slow attaches.
    detail
        Human-readable failure cause when ok=False. Empty on success.
    structured
        Machine-readable details (stdout, stderr, returncode etc.)
        for backends that exec a subprocess. Free-form; the audit
        chain just stores it verbatim.
    """

    ok: bool
    backend_id: str
    checked_at: str = ""
    duration_ms: int = 0
    detail: str = ""
    structured: Dict[str, Any] = field(default_factory=dict)


#
# AgentBackend ABC
#

class AgentBackend(abc.ABC):
    """ Agent """

    #: "hermes" / "claude_code" / ...
    backend_id: str = "abstract"

    def __init__(self, **kwargs):
        """ backend """
        self.config = kwargs
        self._session_config: Optional[SessionConfig] = None
        self._session_started_at: float = 0.0
        self._turn_count: int = 0
        self._cumulative_usage: TokenUsage = TokenUsage()

    #

    @classmethod
    @abc.abstractmethod
    def is_available(cls, **kwargs) -> bool:
        """ backend """

    @abc.abstractmethod
    def start_session(self, config: SessionConfig) -> None:
        """"""

    @abc.abstractmethod
    def send_turn(
        self,
        prompt: str,
        system_prompt: str = "",
    ) -> TurnResponse:
        """"""

    @abc.abstractmethod
    def end_session(self) -> SessionSummary:
        """"""

    # PR-1: pre-attach feasibility check.
    #
    # Concrete method with a default impl - subclasses SHOULD override
    # to perform a real liveness check (claude auth status, codex
    # exec, hermes --version, etc.), but ABC users that don't will
    # automatically get the is_available() fallback so the trait
    # extension is non-breaking. Adding @abstractmethod here would
    # have broken every existing AgentBackend subclass.

    def preflight_check(self, *, timeout: float = 5.0) -> PreflightResult:
        """Verify this backend is usable RIGHT NOW.

        Default implementation degrades to ``is_available()``: if the
        binary or library is present we treat the backend as ok.
        Subclasses with real auth / network / process dependencies
        should override and exec a minimal real action:

            * ClaudeCodeBackend: ``claude auth status``
            * CodexBackend: ``codex exec "echo OK"`` with timeout
            * HermesBackend: ``hermes --version``

        Failures must be REPORTED via ``ok=False`` and ``detail``,
        NOT raised - the caller (attach.py) decides whether to fall
        back, retry, or refuse the attach. Raising would bypass the
        fallback path and force a hard failure.
        """
        t0 = time.monotonic()
        try:
            available = self.is_available()
            detail = "" if available else "is_available() returned False"
            ok = bool(available)
        except Exception as exc:    # noqa: BLE001
            available = False
            ok = False
            detail = f"is_available() raised: {exc!s}"
        return PreflightResult(
            ok=ok,
            backend_id=self.backend_id,
            checked_at=datetime.now(timezone.utc).isoformat(),
            duration_ms=int((time.monotonic() - t0) * 1000),
            detail=detail,
        )

    #

    def stream_turn(
        self,
        prompt: str,
        system_prompt: str = "",
    ) -> Iterator[str]:
        """
         send_turn  chunk


        """
        response = self.send_turn(prompt, system_prompt)
        yield response.content

    def capabilities(self) -> BackendCapabilities:
        """ backend """
        return BackendCapabilities()

    def cancel(self) -> None:
        """ turn backend """
        pass

    #

    def _track_turn_start(self) -> float:
        """ send_turn """
        self._turn_count += 1
        return time.time()

    def _track_turn_end(self, start_at: float, usage: TokenUsage) -> float:
        """ send_turn """
        self._cumulative_usage = self._cumulative_usage + usage
        return time.time() - start_at

    def _build_summary(
        self,
        final_status: str = "completed",
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SessionSummary:
        """ SessionSummary end_session """
        duration = time.time() - self._session_started_at if self._session_started_at else 0.0
        session_id = self._session_config.session_id if self._session_config else "unknown"
        return SessionSummary(
            session_id=session_id,
            backend_id=self.backend_id,
            total_turns=self._turn_count,
            total_usage=self._cumulative_usage,
            duration_seconds=duration,
            final_status=final_status,
            error=error,
            metadata=metadata or {},
        )

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} backend_id={self.backend_id!r}>"
