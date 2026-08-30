"""Reviewed, self-contained reference provider for agent sessions.

The provider is intentionally a small deterministic engine rather than a
wrapper around ``team_layer.backends``. This keeps the T0 reference plugin
free from legacy-backend import side effects. Its unsigned artifact digest is
a local change detector for an explicit reviewed source set, not publisher
attestation or a complete Python import-graph proof. Real model providers must
use the supervised subprocess boundary described by the plugin architecture.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
import threading
import time
from typing import Any, Dict, Optional

from nth_dao.canonical_json import canonical_json
from nth_dao.plugins.agent_provider import (
    AGENT_SESSION_CAPABILITY_ID,
    AGENT_SESSION_CONTRACT,
    AGENT_SESSION_INPUT_SCHEMA,
    AGENT_SESSION_OUTPUT_SCHEMA,
    agent_session_operation_rule,
    capability_document,
    validate_agent_session_input,
    validate_agent_session_identifier,
    validate_agent_session_output,
)
from nth_dao.plugins.contracts import PLUGIN_BASE_HOST_API_VERSION, PluginManifest
from nth_dao.plugins.host import (
    CapabilitySchemas,
    PluginContext,
    PluginHost,
    PluginInvocationContext,
    PluginInvocationError,
)


MOCK_AGENT_PROVIDER_PLUGIN_ID = "org.nth-dao.agent.mock"
_MAX_ACTIVE_SESSIONS = 32
_MAX_SESSIONS_PER_PRINCIPAL = 8
_MAX_TURNS_PER_SESSION = 4_096
_SESSION_IDLE_TTL_SECONDS = 900.0
_REVIEWED_ARTIFACT_PATHS = (
    "nth_dao/canonical_json.py",
    "nth_dao/plugins/agent_provider.py",
    "nth_dao/plugins/builtin/mock_agent_provider.py",
    "nth_dao/plugins/contracts.py",
    "nth_dao/plugins/host.py",
    "nth_dao/plugins/schema.py",
)


def _reviewed_artifact_digest() -> str:
    root = Path(__file__).parents[3]
    files = [
        {
            "path": relative,
            "sha256": hashlib.sha256((root / relative).read_bytes()).hexdigest(),
        }
        for relative in _REVIEWED_ARTIFACT_PATHS
    ]
    document = {"format": "nth-dao-reviewed-source-set-v1", "files": files}
    return f"sha256:{hashlib.sha256(canonical_json(document)).hexdigest()}"


def mock_agent_provider_manifest() -> PluginManifest:
    return PluginManifest(
        manifest_version=1,
        plugin_id=MOCK_AGENT_PROVIDER_PLUGIN_ID,
        version="1.0.0",
        host_api=PLUGIN_BASE_HOST_API_VERSION,
        kind="agent.provider",
        runtime="builtin",
        provides=(AGENT_SESSION_CONTRACT,),
        requires=(),
        permissions=(),
        artifact_digest=_reviewed_artifact_digest(),
    )


@dataclass(frozen=True)
class _Capabilities:
    supports_streaming: bool = False
    supports_tools: bool = True
    supports_system_prompt: bool = True
    supports_multi_turn: bool = True
    supports_temperature: bool = False
    max_context_tokens: int = 100_000
    notes: str = "Deterministic offline reference provider."


_CAPABILITIES = _Capabilities()


@dataclass
class _Usage:
    input_tokens: int = 0
    output_tokens: int = 0

    def __add__(self, other: "_Usage") -> "_Usage":
        return _Usage(
            self.input_tokens + other.input_tokens,
            self.output_tokens + other.output_tokens,
        )


@dataclass(frozen=True)
class _TurnResult:
    content: str
    finish_reason: str
    usage: _Usage
    tool_calls: tuple[Dict[str, str], ...] = ()
    error: str = ""


@dataclass(frozen=True)
class _CompletedTurn:
    request_digest: str
    response: Dict[str, Any]


@dataclass
class _OwnedSession:
    principal: str
    session_id: str
    started_at: float
    last_activity: float
    max_output_tokens: int
    turn_lock: threading.Lock = field(default_factory=threading.Lock)
    cancelled: threading.Event = field(default_factory=threading.Event)
    turns: int = 0
    usage: _Usage = field(default_factory=_Usage)
    completed_turns: dict[str, _CompletedTurn] = field(default_factory=dict)


def _dispatch_mock_turn(prompt: str, system_prompt: str) -> _TurnResult:
    """Return a bounded deterministic response without I/O or blocking."""

    input_tokens = (len(prompt) + len(system_prompt)) // 4
    lower = prompt.lower()
    if "fail" in lower or "raise error" in lower:
        content = "[mock error: prompt contained 'fail']"
        return _TurnResult(
            content=content,
            finish_reason="error",
            usage=_Usage(input_tokens, len(content) // 4),
            error="intentional failure (keyword 'fail' in prompt)",
        )
    if "timeout" in lower:
        content = "[mock timeout: simulated]"
        return _TurnResult(
            content=content,
            finish_reason="timeout",
            usage=_Usage(input_tokens, len(content) // 4),
            error="intentional timeout",
        )
    if "tool" in lower or "use_tool" in lower:
        match = re.search(r"tool[:\s]+(\w+)", lower)
        tool_name = match.group(1) if match else "search_web"
        content = f"Calling tool: {tool_name}"
        arguments_json = canonical_json({"query": prompt[:50]}).decode("utf-8")
        return _TurnResult(
            content=content,
            finish_reason="tool_call",
            usage=_Usage(input_tokens, len(content) // 4),
            tool_calls=(
                {"arguments_json": arguments_json, "id": "mock-1", "name": tool_name},
            ),
        )
    summary = prompt[:60].replace("\n", " ")
    suffix = "..." if len(prompt) > 60 else ""
    content = f"Mock response to: '{summary}{suffix}'"
    return _TurnResult(
        content=content,
        finish_reason="stop",
        usage=_Usage(input_tokens, len(content) // 4),
    )


def _apply_output_limit(result: _TurnResult, max_output_tokens: int) -> _TurnResult:
    """Apply the accepted per-turn output budget to the reference response."""

    if result.usage.output_tokens <= max_output_tokens:
        return result
    content = result.content[: max_output_tokens * 4]
    finish_reason = "length" if result.finish_reason == "stop" else result.finish_reason
    return _TurnResult(
        content=content,
        finish_reason=finish_reason,
        usage=_Usage(result.usage.input_tokens, max_output_tokens),
        tool_calls=result.tool_calls,
        error=result.error,
    )


class MockAgentSessionProvider:
    """Principal-scoped, bounded session manager for the offline reference."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[tuple[str, str], _OwnedSession] = {}
        self._active = True

    def deactivate(self) -> None:
        with self._lock:
            self._active = False
            sessions = tuple(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            session.cancelled.set()

    def _require_active(self) -> None:
        if not self._active:
            raise PluginInvocationError("mock agent provider is disabled")

    @staticmethod
    def _require_fields(
        payload: Mapping[str, Any],
        *,
        allowed: frozenset[str],
        required: frozenset[str] = frozenset(),
    ) -> None:
        unexpected = set(payload) - allowed
        missing = required - set(payload)
        if unexpected:
            raise PluginInvocationError(
                f"operation does not accept fields: {sorted(unexpected)}"
            )
        if missing:
            raise PluginInvocationError(
                f"operation requires fields: {sorted(missing)}"
            )

    @staticmethod
    def _session_id(payload: Mapping[str, Any]) -> str:
        try:
            return validate_agent_session_identifier(
                payload.get("session_id"), field="session_id"
            )
        except ValueError as exc:
            raise PluginInvocationError("session_id is required") from exc

    @staticmethod
    def _turn_id(payload: Mapping[str, Any]) -> str:
        try:
            return validate_agent_session_identifier(
                payload.get("turn_id"), field="turn_id"
            )
        except ValueError as exc:
            raise PluginInvocationError("turn_id is required") from exc

    @staticmethod
    def _base_response(
        *,
        operation: str,
        session_id: str,
        state: str,
        ready: bool = True,
        detail: str = "",
        duration_ms: int = 0,
        total_turns: int = 0,
        total_usage: Optional[_Usage] = None,
        lease_remaining_ms: int = 0,
    ) -> Dict[str, Any]:
        usage = total_usage or _Usage()
        return {
            "backend_id": "mock",
            "capabilities": capability_document(_CAPABILITIES),
            "content": "",
            "detail": detail[:4_096],
            "duration_ms": max(0, int(duration_ms)),
            "error": "",
            "finish_reason": "",
            "final_status": "",
            "input_tokens": 0,
            "latency_ms": 0,
            "lease_remaining_ms": max(0, int(lease_remaining_ms)),
            "operation": operation,
            "output_tokens": 0,
            "ready": bool(ready),
            "receipt_content_hash": "",
            "receipt_id": "",
            "replayed": False,
            "session_id": session_id,
            "state": state,
            "tool_calls": [],
            "total_input_tokens": max(0, int(usage.input_tokens)),
            "total_output_tokens": max(0, int(usage.output_tokens)),
            "total_turns": max(0, int(total_turns)),
            "turn_id": "",
        }

    def _probe(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        started = time.monotonic()
        return self._base_response(
            operation="probe",
            session_id="",
            state="ready",
            duration_ms=int((time.monotonic() - started) * 1_000),
        )

    def _open(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> Dict[str, Any]:
        session_id = self._session_id(payload)
        if "temperature_milli" in payload:
            raise PluginInvocationError(
                "mock agent provider does not support temperature control"
            )
        key = (context.authority.principal, session_id)
        with self._lock:
            self._require_active()
            now = time.monotonic()
            self._reap_expired_locked(now)
            if key in self._sessions:
                raise PluginInvocationError("session is already active")
            if len(self._sessions) >= _MAX_ACTIVE_SESSIONS:
                raise PluginInvocationError("mock agent provider session limit reached")
            principal_sessions = sum(
                item.principal == context.authority.principal
                for item in self._sessions.values()
            )
            if principal_sessions >= _MAX_SESSIONS_PER_PRINCIPAL:
                raise PluginInvocationError(
                    "mock agent provider principal session limit reached"
                )
            session = _OwnedSession(
                principal=context.authority.principal,
                session_id=session_id,
                started_at=now,
                last_activity=now,
                max_output_tokens=int(payload.get("max_tokens", 4_096)),
            )
            self._sessions[key] = session
        return self._base_response(
            operation="open",
            session_id=session_id,
            state="active",
            lease_remaining_ms=int(_SESSION_IDLE_TTL_SECONDS * 1_000),
        )

    def _reap_expired_locked(self, now: float) -> frozenset[tuple[str, str]]:
        expired = frozenset(
            key
            for key, session in self._sessions.items()
            if (
                not session.turn_lock.locked()
                and now - session.last_activity >= _SESSION_IDLE_TTL_SECONDS
            )
        )
        for key in expired:
            session = self._sessions.pop(key)
            session.cancelled.set()
        return expired

    def _owned_session(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> tuple[tuple[str, str], _OwnedSession]:
        session_id = self._session_id(payload)
        key = (context.authority.principal, session_id)
        with self._lock:
            self._require_active()
            expired = self._reap_expired_locked(time.monotonic())
            if key in expired:
                raise PluginInvocationError("session lease expired")
            session = self._sessions.get(key)
            if session is None:
                raise PluginInvocationError("session is not active for this principal")
            return key, session

    def _turn(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> Dict[str, Any]:
        key, session = self._owned_session(payload, context)
        turn_id = self._turn_id(payload)
        request_digest = f"sha256:{hashlib.sha256(canonical_json(dict(payload))).hexdigest()}"
        timeout_ms = int(payload.get("timeout_ms", 120_000))
        if not session.turn_lock.acquire(blocking=False):
            raise PluginInvocationError("session is busy with another turn")
        try:
            started = time.monotonic()
            with self._lock:
                self._require_active()
                if self._sessions.get(key) is not session or session.cancelled.is_set():
                    raise PluginInvocationError("session is no longer active")
                session.last_activity = started
                completed = session.completed_turns.get(turn_id)
                if completed is not None:
                    if completed.request_digest != request_digest:
                        raise PluginInvocationError(
                            "turn_id was already used for different input"
                        )
                    replay = dict(completed.response)
                    replay["replayed"] = True
                    return replay
                if session.turns >= _MAX_TURNS_PER_SESSION:
                    raise PluginInvocationError("mock agent session turn limit reached")
            result = _dispatch_mock_turn(
                str(payload["prompt"]),
                str(payload.get("system_prompt", "")),
            )
            result = _apply_output_limit(result, session.max_output_tokens)
            elapsed_ms = int((time.monotonic() - started) * 1_000)
            with self._lock:
                if self._sessions.get(key) is not session or session.cancelled.is_set():
                    raise PluginInvocationError("session was cancelled during turn")
                if elapsed_ms >= timeout_ms:
                    result = _TurnResult(
                        content="",
                        finish_reason="timeout",
                        usage=result.usage,
                        error="mock turn exceeded timeout_ms",
                    )
                session.turns += 1
                session.usage = session.usage + result.usage
                session.last_activity = time.monotonic()
                response = self._base_response(
                    operation="turn",
                    session_id=session.session_id,
                    state="active",
                    duration_ms=int((time.monotonic() - session.started_at) * 1_000),
                    total_turns=session.turns,
                    total_usage=session.usage,
                    lease_remaining_ms=int(_SESSION_IDLE_TTL_SECONDS * 1_000),
                )
                response.update(
                    {
                        "content": result.content,
                        "error": result.error,
                        "finish_reason": result.finish_reason,
                        "input_tokens": result.usage.input_tokens,
                        "latency_ms": max(0, elapsed_ms),
                        "output_tokens": result.usage.output_tokens,
                        "tool_calls": list(result.tool_calls),
                        "turn_id": turn_id,
                    }
                )
                session.completed_turns[turn_id] = _CompletedTurn(
                    request_digest=request_digest,
                    response=dict(response),
                )
                return response
        finally:
            session.turn_lock.release()

    def _status(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> Dict[str, Any]:
        key, session = self._owned_session(payload, context)
        with self._lock:
            if self._sessions.get(key) is not session or session.cancelled.is_set():
                raise PluginInvocationError("session is no longer active")
            now = time.monotonic()
            session.last_activity = now
            return self._base_response(
                operation="status",
                session_id=session.session_id,
                state="active",
                duration_ms=int((time.monotonic() - session.started_at) * 1_000),
                total_turns=session.turns,
                total_usage=session.usage,
                lease_remaining_ms=int(_SESSION_IDLE_TTL_SECONDS * 1_000),
            )

    def _close_or_cancel(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
        *,
        cancel: bool,
    ) -> Dict[str, Any]:
        operation = "cancel" if cancel else "close"
        if cancel:
            session_id = self._session_id(payload)
            key = (context.authority.principal, session_id)
            with self._lock:
                self._require_active()
                self._reap_expired_locked(time.monotonic())
                session = self._sessions.pop(key, None)
                if session is not None:
                    session.cancelled.set()
            state = "cancelled"
            final_status = "interrupted"
            duration_ms = (
                int((time.monotonic() - session.started_at) * 1_000)
                if session is not None
                else 0
            )
            turns = session.turns if session is not None else 0
            usage = session.usage if session is not None else _Usage()
        else:
            key, session = self._owned_session(payload, context)
            if not session.turn_lock.acquire(blocking=False):
                raise PluginInvocationError(
                    "session is busy; cancel it or retry close after the turn"
                )
            try:
                with self._lock:
                    self._require_active()
                    if self._sessions.pop(key, None) is not session:
                        raise PluginInvocationError("session is no longer active")
            finally:
                session.turn_lock.release()
            state = "closed"
            final_status = "completed"
            session_id = session.session_id
            duration_ms = int((time.monotonic() - session.started_at) * 1_000)
            turns = session.turns
            usage = session.usage
        response = self._base_response(
            operation=operation,
            session_id=session_id,
            state=state,
            duration_ms=duration_ms,
            total_turns=turns,
            total_usage=usage,
        )
        response["final_status"] = final_status
        return response

    def invoke(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> Mapping[str, Any]:
        if context.capability_id != AGENT_SESSION_CAPABILITY_ID:
            raise PluginInvocationError("agent session capability context mismatch")
        operation = payload.get("operation")
        if not isinstance(operation, str):
            raise PluginInvocationError("agent session operation is required")
        try:
            allowed, required = agent_session_operation_rule(operation)
        except ValueError as exc:
            raise PluginInvocationError("unsupported agent session operation") from exc
        self._require_fields(payload, allowed=allowed, required=required)
        if operation == "probe":
            with self._lock:
                self._require_active()
            return self._probe(payload)
        if operation == "open":
            return self._open(payload, context)
        if operation == "turn":
            return self._turn(payload, context)
        if operation == "status":
            return self._status(payload, context)
        if operation == "close":
            return self._close_or_cancel(payload, context, cancel=False)
        if operation == "cancel":
            return self._close_or_cancel(payload, context, cancel=True)
        raise PluginInvocationError("unsupported agent session operation")


class MockAgentProviderPlugin:
    def __init__(self) -> None:
        self._provider: Optional[MockAgentSessionProvider] = None

    def start(self, context: PluginContext) -> Mapping[str, object]:
        if context.plugin_id != MOCK_AGENT_PROVIDER_PLUGIN_ID:
            raise RuntimeError("mock agent plugin context id mismatch")
        if context.granted_permissions:
            raise PermissionError("mock agent plugin accepts no host permissions")
        self._provider = MockAgentSessionProvider()
        return {AGENT_SESSION_CAPABILITY_ID: self._provider}

    def stop(self) -> None:
        provider = self._provider
        self._provider = None
        if provider is not None:
            provider.deactivate()


def register_mock_agent_provider(host: PluginHost) -> PluginManifest:
    """Install the reviewed offline provider without authorizing or enabling it."""

    if not isinstance(host, PluginHost):
        raise TypeError("host must be a PluginHost")
    item = mock_agent_provider_manifest()
    host.register_builtin(
        item,
        MockAgentProviderPlugin,
        allow_manifest_upgrade=True,
        schemas={
            AGENT_SESSION_CAPABILITY_ID: CapabilitySchemas(
                AGENT_SESSION_INPUT_SCHEMA,
                AGENT_SESSION_OUTPUT_SCHEMA,
                input_validator=validate_agent_session_input,
                output_validator=validate_agent_session_output,
            )
        },
    )
    return item


__all__ = [
    "MOCK_AGENT_PROVIDER_PLUGIN_ID",
    "MockAgentProviderPlugin",
    "MockAgentSessionProvider",
    "mock_agent_provider_manifest",
    "register_mock_agent_provider",
]
