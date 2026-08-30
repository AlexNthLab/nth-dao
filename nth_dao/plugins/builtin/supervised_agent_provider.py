"""Strict Agent Provider bridge for one Host-supervised Agent.

The plugin is fixed to one target DID at registration time. Invocation payloads
cannot choose a process, endpoint, credential, working directory, or command.
Those values remain behind the Host-owned ``SupervisedAgentInvoker`` boundary.

The unsigned artifact digest is a local reviewed-source change detector. It is
not publisher attestation and does not prove the complete Python import graph.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import threading
import time
from typing import Any, Dict, Optional, Protocol

from nth_dao.canonical_json import canonical_json
from nth_dao.did_key import is_did_key
from nth_dao.plugins.agent_provider import (
    AGENT_SESSION_CAPABILITY_ID,
    AGENT_SESSION_INPUT_SCHEMA,
    AGENT_SESSION_OUTPUT_SCHEMA,
    AGENT_SESSION_SUPERVISED_CONTRACT,
    agent_session_operation_rule,
    capability_document,
    validate_agent_session_identifier,
    validate_agent_session_input,
    validate_agent_session_output,
)
from nth_dao.plugins.contracts import (
    PLUGIN_BASE_HOST_API_VERSION,
    PluginManifest,
)
from nth_dao.plugins.host import (
    CapabilitySchemas,
    PluginContext,
    PluginHost,
    PluginInvocationContext,
    PluginInvocationError,
)


_PLUGIN_ID_PREFIX = "org.nth-dao.agent.s"
_MAX_ACTIVE_SESSIONS = 16
_MAX_SESSIONS_PER_PRINCIPAL = 4
_MAX_TURNS_PER_SESSION = 64
_MIN_OUTPUT_TOKENS = 16
_MAX_OUTPUT_TOKENS = 8_192
_MAX_TIMEOUT_MS = 300_000
_SESSION_IDLE_TTL_SECONDS = 900.0
_MAX_DETAIL_CHARS = 4_096
_MAX_CONTENT_CHARS = 524_288
_MAX_ACCOUNTED_TOKENS = 1_000_000_000
_MAX_TOOL_CALLS = 64
_REVIEWED_ARTIFACT_PATHS = (
    "nth_dao/canonical_json.py",
    "nth_dao/did_key.py",
    "nth_dao/plugins/agent_provider.py",
    "nth_dao/plugins/builtin/supervised_agent_provider.py",
    "nth_dao/plugins/contracts.py",
    "nth_dao/plugins/host.py",
    "nth_dao/plugins/schema.py",
)


class SupervisedAgentOutcomeUnknown(RuntimeError):
    """The dispatch boundary was crossed but no terminal result is trusted."""


SUPERVISED_AGENT_SESSION_CONTRACT = AGENT_SESSION_SUPERVISED_CONTRACT


def _bounded_text(value: Any, *, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    ):
        raise ValueError(f"{label} must be trimmed bounded text")
    return value


@dataclass(frozen=True)
class SupervisedAgentTarget:
    """Immutable routing identity selected by the Host, never the caller."""

    agent_id: str
    agent_did: str
    backend_id: str
    execution_target_revision: str

    def __post_init__(self) -> None:
        _bounded_text(self.agent_id, label="agent_id", maximum=128)
        _bounded_text(self.backend_id, label="backend_id", maximum=128)
        if len(self.agent_did) > 512 or not is_did_key(self.agent_did):
            raise ValueError("agent_did must be an Ed25519 did:key")
        if (
            len(self.execution_target_revision) != 64
            or any(
                char not in "0123456789abcdef"
                for char in self.execution_target_revision
            )
        ):
            raise ValueError("execution_target_revision must be a SHA-256 hex digest")


@dataclass(frozen=True)
class SupervisedAgentCapabilities:
    supports_streaming: bool = False
    supports_tools: bool = False
    supports_system_prompt: bool = True
    supports_multi_turn: bool = False
    supports_temperature: bool = False
    max_context_tokens: int = 0
    notes: str = "Host-supervised local A2A Agent."


@dataclass(frozen=True)
class SupervisedAgentProbe:
    ready: bool
    capabilities: SupervisedAgentCapabilities
    detail: str = ""


@dataclass(frozen=True)
class SupervisedAgentTurnRequest:
    principal: str
    session_id: str
    turn_id: str
    goal: str
    prompt: str
    system_prompt: str
    model: str
    max_output_tokens: int
    temperature_milli: int | None
    timeout_ms: int


@dataclass(frozen=True)
class SupervisedAgentTurnResult:
    content: str
    finish_reason: str
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    error: str = ""
    tool_calls: tuple[Dict[str, str], ...] = ()
    receipt_id: str = ""
    receipt_content_hash: str = ""


class SupervisedAgentInvoker(Protocol):
    """Host-owned execution boundary.

    Implementations must inject authorization out of band and must verify and
    durably persist the target's signed Receipt before ``turn`` returns.
    ``cancel`` returns true only after the target execution boundary confirms
    that the named in-flight turn is no longer running.
    """

    def probe(
        self,
        target: SupervisedAgentTarget,
        *,
        timeout_ms: int,
    ) -> SupervisedAgentProbe: ...

    def turn(
        self,
        target: SupervisedAgentTarget,
        request: SupervisedAgentTurnRequest,
    ) -> SupervisedAgentTurnResult: ...

    def cancel(
        self,
        target: SupervisedAgentTarget,
        *,
        session_id: str,
        turn_id: str,
    ) -> bool: ...


@dataclass
class _Usage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass(frozen=True)
class _CompletedTurn:
    request_digest: str
    response: Dict[str, Any]


@dataclass
class _OwnedSession:
    principal: str
    session_id: str
    goal: str
    model: str
    max_output_tokens: int
    temperature_milli: int | None
    timeout_ms: int
    capabilities: SupervisedAgentCapabilities
    started_at: float
    last_activity: float
    turn_lock: threading.Lock = field(default_factory=threading.Lock)
    cancelled: threading.Event = field(default_factory=threading.Event)
    cancelling: bool = False
    active_turn_id: str = ""
    turns: int = 0
    usage: _Usage = field(default_factory=_Usage)
    completed_turns: dict[str, _CompletedTurn] = field(default_factory=dict)


def supervised_agent_plugin_id(agent_did: str) -> str:
    """Return the stable plugin identity bound to one target DID."""

    if len(agent_did) > 512 or not is_did_key(agent_did):
        raise ValueError("agent_did must be an Ed25519 did:key")
    suffix = hashlib.sha256(agent_did.encode("utf-8")).hexdigest()[:24]
    return f"{_PLUGIN_ID_PREFIX}{suffix}"


def _reviewed_artifact_digest(
    additional_paths: tuple[str, ...] = (),
) -> str:
    root = Path(__file__).parents[3]
    if (
        not isinstance(additional_paths, tuple)
        or any(
            not isinstance(relative, str)
            or not relative
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
            for relative in additional_paths
        )
    ):
        raise ValueError("reviewed artifact paths must be safe relative paths")
    relative_paths = tuple(sorted(set(_REVIEWED_ARTIFACT_PATHS + additional_paths)))
    files = [
        {
            "path": relative,
            "sha256": hashlib.sha256((root / relative).read_bytes()).hexdigest(),
        }
        for relative in relative_paths
    ]
    document = {"format": "nth-dao-reviewed-source-set-v1", "files": files}
    return f"sha256:{hashlib.sha256(canonical_json(document)).hexdigest()}"


def supervised_agent_manifest(
    target: SupervisedAgentTarget,
    *,
    reviewed_artifact_paths: tuple[str, ...] = (),
) -> PluginManifest:
    if not isinstance(target, SupervisedAgentTarget):
        raise TypeError("target must be a SupervisedAgentTarget")
    return PluginManifest(
        manifest_version=1,
        plugin_id=supervised_agent_plugin_id(target.agent_did),
        version="1.0.0",
        host_api=PLUGIN_BASE_HOST_API_VERSION,
        kind="agent.provider",
        runtime="builtin",
        provides=(SUPERVISED_AGENT_SESSION_CONTRACT,),
        requires=(),
        permissions=("network.client",),
        artifact_digest=_reviewed_artifact_digest(reviewed_artifact_paths),
    )


class SupervisedAgentSessionProvider:
    """Bounded, principal-scoped session facade over one supervised target."""

    def __init__(
        self,
        target: SupervisedAgentTarget,
        invoker: SupervisedAgentInvoker,
    ) -> None:
        if not isinstance(target, SupervisedAgentTarget):
            raise TypeError("target must be a SupervisedAgentTarget")
        for method in ("probe", "turn", "cancel"):
            if not callable(getattr(invoker, method, None)):
                raise TypeError(f"invoker must provide {method}()")
        self._target = target
        self._invoker = invoker
        self._lock = threading.RLock()
        self._sessions: dict[tuple[str, str], _OwnedSession] = {}
        self._active = True

    @staticmethod
    def _base_response(
        *,
        target: SupervisedAgentTarget,
        capabilities: SupervisedAgentCapabilities,
        operation: str,
        session_id: str,
        state: str,
        ready: bool = True,
        detail: str = "",
        duration_ms: int = 0,
        total_turns: int = 0,
        usage: Optional[_Usage] = None,
        lease_remaining_ms: int = 0,
    ) -> Dict[str, Any]:
        totals = usage or _Usage()
        return {
            "backend_id": target.backend_id,
            "capabilities": capability_document(capabilities),
            "content": "",
            "detail": detail[:_MAX_DETAIL_CHARS],
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
            "total_input_tokens": max(0, int(totals.input_tokens)),
            "total_output_tokens": max(0, int(totals.output_tokens)),
            "total_turns": max(0, int(total_turns)),
            "turn_id": "",
        }

    def _require_active(self) -> None:
        if not self._active:
            raise PluginInvocationError("supervised agent provider is disabled")

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
            self._sessions.pop(key).cancelled.set()
        return expired

    def _owned_session(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> tuple[tuple[str, str], _OwnedSession]:
        try:
            session_id = validate_agent_session_identifier(
                payload.get("session_id"), field="session_id"
            )
        except ValueError as exc:
            raise PluginInvocationError("session_id is required") from exc
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

    def _probe_result(self, timeout_ms: int) -> SupervisedAgentProbe:
        try:
            result = self._invoker.probe(self._target, timeout_ms=timeout_ms)
        except Exception as exc:  # noqa: BLE001 - provider boundary is untrusted
            return SupervisedAgentProbe(
                ready=False,
                capabilities=SupervisedAgentCapabilities(),
                detail=f"invoker probe failed ({type(exc).__name__})",
            )
        if not isinstance(result, SupervisedAgentProbe):
            return SupervisedAgentProbe(
                ready=False,
                capabilities=SupervisedAgentCapabilities(),
                detail="invoker returned an invalid probe result",
            )
        try:
            capability_document(result.capabilities)
        except (TypeError, ValueError):
            return SupervisedAgentProbe(
                ready=False,
                capabilities=SupervisedAgentCapabilities(),
                detail="invoker returned invalid capability metadata",
            )
        if not isinstance(result.ready, bool) or not isinstance(result.detail, str):
            return SupervisedAgentProbe(
                ready=False,
                capabilities=SupervisedAgentCapabilities(),
                detail="invoker returned malformed readiness metadata",
            )
        return SupervisedAgentProbe(
            ready=result.ready,
            capabilities=result.capabilities,
            # Invoker detail is untrusted free text and may contain local
            # paths, command lines, credentials, or provider responses.
            detail=(
                "supervised target reported ready"
                if result.ready
                else "supervised target reported unavailable"
            ),
        )

    def _probe(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        timeout_ms = min(int(payload.get("timeout_ms", 5_000)), _MAX_TIMEOUT_MS)
        started = time.monotonic()
        probe = self._probe_result(timeout_ms)
        return self._base_response(
            target=self._target,
            capabilities=probe.capabilities,
            operation="probe",
            session_id="",
            state="ready" if probe.ready else "unavailable",
            ready=probe.ready,
            detail=probe.detail,
            duration_ms=int((time.monotonic() - started) * 1_000),
        )

    def _open(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> Dict[str, Any]:
        session_id = validate_agent_session_identifier(
            payload.get("session_id"), field="session_id"
        )
        max_tokens = int(payload.get("max_tokens", 4_096))
        timeout_ms = int(payload.get("timeout_ms", 120_000))
        if not _MIN_OUTPUT_TOKENS <= max_tokens <= _MAX_OUTPUT_TOKENS:
            raise PluginInvocationError(
                "supervised session max_tokens must be between "
                f"{_MIN_OUTPUT_TOKENS} and {_MAX_OUTPUT_TOKENS}"
            )
        if timeout_ms > _MAX_TIMEOUT_MS:
            raise PluginInvocationError(
                f"supervised session timeout_ms exceeds {_MAX_TIMEOUT_MS}"
            )
        probe = self._probe_result(min(timeout_ms, 5_000))
        if not probe.ready:
            detail = probe.detail or "target is unavailable"
            raise PluginInvocationError(f"supervised agent is not ready: {detail}")
        if (
            "temperature_milli" in payload
            and not probe.capabilities.supports_temperature
        ):
            raise PluginInvocationError(
                "supervised target does not support temperature control"
            )
        key = (context.authority.principal, session_id)
        with self._lock:
            self._require_active()
            now = time.monotonic()
            self._reap_expired_locked(now)
            if key in self._sessions:
                raise PluginInvocationError("session is already active")
            if len(self._sessions) >= _MAX_ACTIVE_SESSIONS:
                raise PluginInvocationError("supervised agent session limit reached")
            owned = sum(
                item.principal == context.authority.principal
                for item in self._sessions.values()
            )
            if owned >= _MAX_SESSIONS_PER_PRINCIPAL:
                raise PluginInvocationError(
                    "supervised agent principal session limit reached"
                )
            self._sessions[key] = _OwnedSession(
                principal=context.authority.principal,
                session_id=session_id,
                goal=str(payload.get("goal", "")),
                model=str(payload.get("model", "")),
                max_output_tokens=max_tokens,
                temperature_milli=(
                    int(payload["temperature_milli"])
                    if "temperature_milli" in payload
                    else None
                ),
                timeout_ms=timeout_ms,
                capabilities=probe.capabilities,
                started_at=now,
                last_activity=now,
            )
        return self._base_response(
            target=self._target,
            capabilities=probe.capabilities,
            operation="open",
            session_id=session_id,
            state="active",
            lease_remaining_ms=int(_SESSION_IDLE_TTL_SECONDS * 1_000),
        )

    @staticmethod
    def _safe_failed_turn(error: str, latency_ms: int) -> SupervisedAgentTurnResult:
        detail = str(error or "supervised agent execution failed")[:_MAX_DETAIL_CHARS]
        return SupervisedAgentTurnResult(
            content="",
            finish_reason="error",
            latency_ms=max(0, int(latency_ms)),
            error=detail,
        )

    def _normalized_turn_result(
        self,
        result: Any,
        *,
        session: _OwnedSession,
        elapsed_ms: int,
        trusted_failure_detail: bool = False,
    ) -> SupervisedAgentTurnResult:
        if not isinstance(result, SupervisedAgentTurnResult):
            return self._safe_failed_turn(
                "invoker returned an invalid turn result", elapsed_ms
            )
        content_limit = min(
            _MAX_CONTENT_CHARS,
            max(1, session.max_output_tokens),
        )
        content_bytes = (
            len(result.content.encode("utf-8"))
            if isinstance(result.content, str)
            else _MAX_CONTENT_CHARS + 1
        )
        if (
            not isinstance(result.content, str)
            or content_bytes > content_limit
            or result.finish_reason
            not in {"error", "length", "stop", "timeout", "tool_call"}
            or type(result.input_tokens) is not int
            or not 0 <= result.input_tokens <= _MAX_ACCOUNTED_TOKENS
            or type(result.output_tokens) is not int
            or not 0 <= result.output_tokens <= _MAX_ACCOUNTED_TOKENS
            or result.output_tokens > session.max_output_tokens
            or type(result.latency_ms) is not int
            or result.latency_ms < 0
            or not isinstance(result.error, str)
            or len(result.error) > _MAX_DETAIL_CHARS
            or not isinstance(result.tool_calls, tuple)
            or len(result.tool_calls) > _MAX_TOOL_CALLS
        ):
            return self._safe_failed_turn(
                "invoker returned a malformed or over-budget turn result",
                elapsed_ms,
            )
        receipt_id = result.receipt_id
        receipt_hash = result.receipt_content_hash
        if (
            not isinstance(receipt_id, str)
            or not isinstance(receipt_hash, str)
            or bool(receipt_id) != bool(receipt_hash)
            or (
                receipt_id
                and (
                    receipt_id != receipt_id.strip()
                    or len(receipt_id) > 256
                    or any(
                        ord(char) < 0x20 or ord(char) == 0x7F
                        for char in receipt_id
                    )
                )
            )
            or (
                receipt_hash
                and (
                    len(receipt_hash) != 64
                    or any(
                        char not in "0123456789abcdef" for char in receipt_hash
                    )
                )
            )
        ):
            return self._safe_failed_turn(
                "invoker returned malformed Receipt references",
                elapsed_ms,
            )
        if result.content and result.output_tokens == 0:
            # A child that cannot report tokenizer-specific usage is charged a
            # conservative UTF-8 byte upper bound. Every emitted text token
            # contains at least one byte, so this never understates usage.
            result = SupervisedAgentTurnResult(
                content=result.content,
                finish_reason=result.finish_reason,
                input_tokens=result.input_tokens,
                output_tokens=content_bytes,
                latency_ms=result.latency_ms,
                error=result.error,
                tool_calls=result.tool_calls,
                receipt_id=result.receipt_id,
                receipt_content_hash=result.receipt_content_hash,
            )
        tool_ids = []
        for item in result.tool_calls:
            if (
                not isinstance(item, Mapping)
                or set(item) != {"arguments_json", "id", "name"}
                or not isinstance(item["arguments_json"], str)
                or len(item["arguments_json"]) > 65_536
                or not isinstance(item["id"], str)
                or not 1 <= len(item["id"]) <= 256
                or not isinstance(item["name"], str)
                or not 1 <= len(item["name"]) <= 256
            ):
                return self._safe_failed_turn(
                    "invoker returned malformed tool-call metadata",
                    elapsed_ms,
                )
            tool_ids.append(item["id"])
        if len(tool_ids) != len(set(tool_ids)):
            return self._safe_failed_turn(
                "invoker returned duplicate tool-call ids",
                elapsed_ms,
            )
        if (result.finish_reason == "tool_call") != bool(result.tool_calls):
            return self._safe_failed_turn(
                "invoker tool calls do not match finish_reason",
                elapsed_ms,
            )
        if result.finish_reason in {"error", "timeout"}:
            if not result.error:
                return self._safe_failed_turn(
                    "invoker returned a failed turn without error detail",
                    elapsed_ms,
                )
            if not trusted_failure_detail:
                result = SupervisedAgentTurnResult(
                    content="",
                    finish_reason=result.finish_reason,
                    input_tokens=result.input_tokens,
                    output_tokens=0,
                    latency_ms=result.latency_ms,
                    error=(
                        "supervised agent execution timed out"
                        if result.finish_reason == "timeout"
                        else "supervised agent execution failed"
                    ),
                    receipt_id=result.receipt_id,
                    receipt_content_hash=result.receipt_content_hash,
                )
        elif result.error:
            return self._safe_failed_turn(
                "invoker returned error detail for a successful turn",
                elapsed_ms,
            )
        elif not receipt_id:
            return self._safe_failed_turn(
                "invoker returned a successful turn without a verified Receipt",
                elapsed_ms,
            )
        return result

    def _turn(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> Dict[str, Any]:
        key, session = self._owned_session(payload, context)
        turn_id = validate_agent_session_identifier(
            payload.get("turn_id"), field="turn_id"
        )
        request_digest = (
            "sha256:" + hashlib.sha256(canonical_json(dict(payload))).hexdigest()
        )
        if not session.turn_lock.acquire(blocking=False):
            raise PluginInvocationError("session is busy with another turn")
        try:
            started = time.monotonic()
            with self._lock:
                self._require_active()
                if (
                    self._sessions.get(key) is not session
                    or session.cancelled.is_set()
                    or session.cancelling
                ):
                    raise PluginInvocationError("session is no longer active")
                completed = session.completed_turns.get(turn_id)
                if completed is not None:
                    if completed.request_digest != request_digest:
                        raise PluginInvocationError(
                            "turn_id was already used for different input"
                        )
                    replay = dict(completed.response)
                    replay["replayed"] = True
                    return replay
                if session.turns and not session.capabilities.supports_multi_turn:
                    raise PluginInvocationError(
                        "supervised target does not support multiple turns"
                    )
                if session.turns >= _MAX_TURNS_PER_SESSION:
                    raise PluginInvocationError(
                        "supervised agent session turn limit reached"
                    )
                session.active_turn_id = turn_id
                session.last_activity = started
            request = SupervisedAgentTurnRequest(
                principal=session.principal,
                session_id=session.session_id,
                turn_id=turn_id,
                goal=session.goal,
                prompt=str(payload["prompt"]),
                system_prompt=str(payload.get("system_prompt", "")),
                model=session.model,
                max_output_tokens=session.max_output_tokens,
                temperature_milli=session.temperature_milli,
                timeout_ms=min(
                    int(payload.get("timeout_ms", session.timeout_ms)),
                    session.timeout_ms,
                ),
            )
            if request.system_prompt and not session.capabilities.supports_system_prompt:
                trusted_failure_detail = True
                raw_result = self._safe_failed_turn(
                    "supervised target does not support a separate system prompt",
                    int((time.monotonic() - started) * 1_000),
                )
            else:
                trusted_failure_detail = False
                try:
                    raw_result = self._invoker.turn(self._target, request)
                except SupervisedAgentOutcomeUnknown as exc:
                    raise PluginInvocationError(
                        "supervised Agent turn outcome is unknown; retry the same turn"
                    ) from exc
                except Exception as exc:  # noqa: BLE001 - outcome is uncertain
                    trusted_failure_detail = True
                    raw_result = self._safe_failed_turn(
                        f"supervised agent execution failed ({type(exc).__name__})",
                        int((time.monotonic() - started) * 1_000),
                    )
            elapsed_ms = int((time.monotonic() - started) * 1_000)
            result = self._normalized_turn_result(
                raw_result,
                session=session,
                elapsed_ms=elapsed_ms,
                trusted_failure_detail=trusted_failure_detail,
            )
            if elapsed_ms >= request.timeout_ms and result.finish_reason not in {
                "error",
                "timeout",
            }:
                result = SupervisedAgentTurnResult(
                    content="",
                    finish_reason="timeout",
                    input_tokens=result.input_tokens,
                    output_tokens=0,
                    latency_ms=elapsed_ms,
                    error="supervised agent turn exceeded timeout_ms",
                    receipt_id=result.receipt_id,
                    receipt_content_hash=result.receipt_content_hash,
                )
            with self._lock:
                if self._sessions.get(key) is not session or session.cancelled.is_set():
                    raise PluginInvocationError(
                        "supervised agent session was cancelled during turn"
                    )
                session.active_turn_id = ""
                session.turns += 1
                session.usage.input_tokens += result.input_tokens
                session.usage.output_tokens += result.output_tokens
                session.last_activity = time.monotonic()
                response = self._base_response(
                    target=self._target,
                    capabilities=session.capabilities,
                    operation="turn",
                    session_id=session.session_id,
                    state="active",
                    duration_ms=int((time.monotonic() - session.started_at) * 1_000),
                    total_turns=session.turns,
                    usage=session.usage,
                    lease_remaining_ms=int(_SESSION_IDLE_TTL_SECONDS * 1_000),
                )
                response.update(
                    {
                        "content": result.content,
                        "error": result.error,
                        "finish_reason": result.finish_reason,
                        "input_tokens": result.input_tokens,
                        "latency_ms": max(result.latency_ms, elapsed_ms),
                        "output_tokens": result.output_tokens,
                        "receipt_content_hash": result.receipt_content_hash,
                        "receipt_id": result.receipt_id,
                        "tool_calls": [dict(item) for item in result.tool_calls],
                        "turn_id": turn_id,
                    }
                )
                try:
                    validate_agent_session_output(response)
                except Exception:  # noqa: BLE001 - reject untrusted result
                    failed = self._safe_failed_turn(
                        "invoker result failed output validation", elapsed_ms
                    )
                    response.update(
                        {
                            "content": "",
                            "error": failed.error,
                            "finish_reason": "error",
                            "input_tokens": 0,
                            "output_tokens": 0,
                            "receipt_content_hash": "",
                            "receipt_id": "",
                            "tool_calls": [],
                        }
                    )
                session.completed_turns[turn_id] = _CompletedTurn(
                    request_digest=request_digest,
                    response=dict(response),
                )
                return response
        finally:
            with self._lock:
                if session.active_turn_id == turn_id:
                    session.active_turn_id = ""
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
                target=self._target,
                capabilities=session.capabilities,
                operation="status",
                session_id=session.session_id,
                state="active",
                duration_ms=int((now - session.started_at) * 1_000),
                total_turns=session.turns,
                usage=session.usage,
                lease_remaining_ms=int(_SESSION_IDLE_TTL_SECONDS * 1_000),
            )

    def _close(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> Dict[str, Any]:
        key, session = self._owned_session(payload, context)
        if not session.turn_lock.acquire(blocking=False):
            raise PluginInvocationError(
                "session is busy; cancel it or retry close after the turn"
            )
        try:
            with self._lock:
                self._require_active()
                if session.cancelling:
                    raise PluginInvocationError("session cancellation is in progress")
                if self._sessions.pop(key, None) is not session:
                    raise PluginInvocationError("session is no longer active")
        finally:
            session.turn_lock.release()
        response = self._base_response(
            target=self._target,
            capabilities=session.capabilities,
            operation="close",
            session_id=session.session_id,
            state="closed",
            duration_ms=int((time.monotonic() - session.started_at) * 1_000),
            total_turns=session.turns,
            usage=session.usage,
        )
        response["final_status"] = "completed"
        return response

    def _cancel(
        self,
        payload: Mapping[str, Any],
        context: PluginInvocationContext,
    ) -> Dict[str, Any]:
        session_id = validate_agent_session_identifier(
            payload.get("session_id"), field="session_id"
        )
        key = (context.authority.principal, session_id)
        with self._lock:
            self._require_active()
            self._reap_expired_locked(time.monotonic())
            session = self._sessions.get(key)
            if session is not None and session.cancelling:
                raise PluginInvocationError("session cancellation is already in progress")
            if session is not None:
                # This state transition and _turn's dispatch transition share
                # the same lock. Once set, no new turn may cross the invoker
                # boundary while cancellation decides whether remote work is
                # active and confirmably stoppable.
                session.cancelling = True
            active_turn_id = session.active_turn_id if session is not None else ""
        if session is not None and active_turn_id:
            try:
                confirmed = self._invoker.cancel(
                    self._target,
                    session_id=session.session_id,
                    turn_id=active_turn_id,
                )
            except Exception as exc:  # noqa: BLE001 - cancellation must fail closed
                with self._lock:
                    if self._sessions.get(key) is session:
                        session.cancelling = False
                raise PluginInvocationError(
                    f"supervised agent cancellation failed ({type(exc).__name__})"
                ) from exc
            if confirmed is not True:
                with self._lock:
                    if self._sessions.get(key) is session:
                        session.cancelling = False
                raise PluginInvocationError(
                    "supervised agent did not confirm cancellation"
                )
        with self._lock:
            current = self._sessions.pop(key, None)
            if current is not None:
                current.cancelled.set()
        ended = current or session
        capabilities = (
            ended.capabilities if ended is not None else SupervisedAgentCapabilities()
        )
        response = self._base_response(
            target=self._target,
            capabilities=capabilities,
            operation="cancel",
            session_id=session_id,
            state="cancelled",
            duration_ms=(
                int((time.monotonic() - ended.started_at) * 1_000)
                if ended is not None
                else 0
            ),
            total_turns=ended.turns if ended is not None else 0,
            usage=ended.usage if ended is not None else None,
        )
        response["final_status"] = "interrupted"
        return response

    def deactivate(self) -> None:
        """Disable locally, failing cleanup if an in-flight turn is unconfirmed."""

        with self._lock:
            self._active = False
            sessions = tuple(self._sessions.values())
        failures = []
        for session in sessions:
            turn_id = session.active_turn_id
            if turn_id:
                try:
                    confirmed = self._invoker.cancel(
                        self._target,
                        session_id=session.session_id,
                        turn_id=turn_id,
                    )
                except Exception as exc:  # noqa: BLE001
                    failures.append(type(exc).__name__)
                    continue
                if confirmed is not True:
                    failures.append(f"{session.session_id}: cancellation unconfirmed")
                    continue
            session.cancelled.set()
            with self._lock:
                self._sessions.pop((session.principal, session.session_id), None)
        if failures:
            raise RuntimeError(
                "supervised agent cleanup failed for "
                f"{len(failures)} session(s)"
            )

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
            return self._close(payload, context)
        if operation == "cancel":
            return self._cancel(payload, context)
        raise PluginInvocationError("unsupported agent session operation")


class SupervisedAgentProviderPlugin:
    def __init__(
        self,
        target: SupervisedAgentTarget,
        invoker: SupervisedAgentInvoker,
    ) -> None:
        self._target = target
        self._invoker = invoker
        self._provider: Optional[SupervisedAgentSessionProvider] = None

    def start(self, context: PluginContext) -> Mapping[str, object]:
        expected_id = supervised_agent_plugin_id(self._target.agent_did)
        if context.plugin_id != expected_id:
            raise RuntimeError("supervised agent plugin target binding mismatch")
        if context.granted_permissions != frozenset({"network.client"}):
            raise PermissionError(
                "supervised agent plugin requires only network.client"
            )
        self._provider = SupervisedAgentSessionProvider(
            self._target,
            self._invoker,
        )
        return {AGENT_SESSION_CAPABILITY_ID: self._provider}

    def stop(self) -> None:
        provider = self._provider
        if provider is not None:
            provider.deactivate()
            # Keep the provider reachable when deactivate() fails. PluginHost
            # records cleanup-failed and may retry stop after an in-flight
            # execution ends or remote cancellation becomes confirmable.
            self._provider = None


def register_supervised_agent_provider(
    host: PluginHost,
    target: SupervisedAgentTarget,
    invoker: SupervisedAgentInvoker,
    *,
    reviewed_artifact_paths: tuple[str, ...] = (),
) -> PluginManifest:
    """Install one fixed-target provider without authorizing or enabling it."""

    if not isinstance(host, PluginHost):
        raise TypeError("host must be a PluginHost")
    if not isinstance(target, SupervisedAgentTarget):
        raise TypeError("target must be a SupervisedAgentTarget")
    item = supervised_agent_manifest(
        target,
        reviewed_artifact_paths=reviewed_artifact_paths,
    )

    def factory() -> SupervisedAgentProviderPlugin:
        return SupervisedAgentProviderPlugin(target, invoker)

    host.register_builtin(
        item,
        factory,
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
    "SUPERVISED_AGENT_SESSION_CONTRACT",
    "SupervisedAgentOutcomeUnknown",
    "SupervisedAgentCapabilities",
    "SupervisedAgentInvoker",
    "SupervisedAgentProbe",
    "SupervisedAgentProviderPlugin",
    "SupervisedAgentSessionProvider",
    "SupervisedAgentTarget",
    "SupervisedAgentTurnRequest",
    "SupervisedAgentTurnResult",
    "register_supervised_agent_provider",
    "supervised_agent_manifest",
    "supervised_agent_plugin_id",
]
