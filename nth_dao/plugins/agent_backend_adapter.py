"""Explicit bridge from an agent-session plugin binding to AgentBackend.

Importing the plugin contract or host must not import the legacy ``team_layer``
package. Applications that need the Python facade opt into this adapter
module; wire-only and subprocess consumers remain independent of it.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import math
import secrets
import threading
import time
from typing import Any, Dict, Mapping

from team_layer.backends import (
    AgentBackend,
    BackendCapabilities,
    SessionConfig,
    SessionSummary,
    TokenUsage,
    ToolCall,
    TurnResponse,
)
from team_layer.backends.base import PreflightResult

from nth_dao.canonical_json import canonical_json

from .agent_provider import (
    AGENT_SESSION_CAPABILITY_ID,
    AGENT_SESSION_CONTRACT,
    AGENT_SESSION_LEGACY_CAPABILITY_VERSION,
    AGENT_SESSION_SUPERVISED_CONTRACT,
    AGENT_SESSION_V1_CONTRACT,
    validate_agent_session_input,
    validate_agent_session_output,
)
from .host import InvocationAuthority, PluginInvocationError, ProviderBinding


_MAX_ERROR_CHARS = 4_096
class PluginAgentBackend(AgentBackend):
    """Adapt one enabled agent-session capability to ``AgentBackend``.

    A proxy is bound to one provider binding and one local authority. It
    cannot switch providers or principals after construction.
    """

    backend_id = "plugin-agent"

    def __init__(
        self,
        binding: ProviderBinding,
        *,
        authority: InvocationAuthority,
        backend_id: str,
        allowed_models: frozenset[str] | set[str] = frozenset(),
        allowed_tools: frozenset[str] | set[str] = frozenset(),
        max_session_tokens: int = 65_536,
        max_timeout_s: float = 300.0,
    ) -> None:
        if not isinstance(binding, ProviderBinding):
            raise TypeError("binding must be a ProviderBinding")
        if binding.contract.capability_id != AGENT_SESSION_CAPABILITY_ID:
            raise ValueError("binding does not provide the agent session capability")
        approved_contracts = (
            AGENT_SESSION_V1_CONTRACT,
            AGENT_SESSION_CONTRACT,
            AGENT_SESSION_SUPERVISED_CONTRACT,
        )
        if binding.contract not in approved_contracts:
            raise ValueError("binding has an incompatible agent session contract")
        if not isinstance(authority, InvocationAuthority):
            raise TypeError("authority must be an InvocationAuthority")
        if AGENT_SESSION_CAPABILITY_ID not in authority.capability_ids:
            raise ValueError("authority does not grant the agent session capability")
        if not isinstance(backend_id, str) or not backend_id.strip():
            raise ValueError("backend_id must be non-empty text")
        if len(backend_id.encode("utf-8")) > 128:
            raise ValueError("backend_id is too long")
        super().__init__()
        self.backend_id = backend_id.strip()
        self._allowed_models = _bounded_policy_values(
            allowed_models,
            label="allowed_models",
        )
        self._allowed_tools = _bounded_policy_values(
            allowed_tools,
            label="allowed_tools",
        )
        if (
            type(max_session_tokens) is not int
            or not 1 <= max_session_tokens <= 1_000_000
        ):
            raise ValueError("max_session_tokens must be an integer from 1 to 1000000")
        if (
            isinstance(max_timeout_s, bool)
            or not isinstance(max_timeout_s, (int, float))
            or not math.isfinite(max_timeout_s)
            or not 0.1 <= float(max_timeout_s) <= 3_600.0
        ):
            raise ValueError("max_timeout_s must be finite and between 0.1 and 3600")
        self._max_session_tokens = max_session_tokens
        self._max_timeout_ms = int(float(max_timeout_s) * 1_000)
        self._binding = binding
        self._protocol_version = binding.contract.version
        self._authority = authority
        self._active = False
        self._capabilities = BackendCapabilities()
        self._call_lock = threading.RLock()
        self._state_lock = threading.RLock()
        self._pending_turn: tuple[str, str, str] | None = None
        self._cleanup_session_id: str | None = None
        self._session_allowed_tools: frozenset[str] = frozenset()

    @classmethod
    def is_available(cls, **kwargs: Any) -> bool:
        return isinstance(kwargs.get("binding"), ProviderBinding)

    def _invoke(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        result = self._binding.invoke(payload, authority=self._authority)
        validate_agent_session_output(result, version=self._protocol_version)
        normalized = dict(result)
        if self._protocol_version == AGENT_SESSION_LEGACY_CAPABILITY_VERSION:
            capabilities = dict(result["capabilities"])
            capabilities["supports_temperature"] = False
            normalized["capabilities"] = capabilities
        return normalized

    def _invoke_expected(
        self,
        payload: Mapping[str, Any],
        *,
        state: str,
    ) -> Dict[str, Any]:
        operation = str(payload["operation"])
        session_id = str(payload.get("session_id", ""))
        turn_id = str(payload.get("turn_id", ""))
        result = self._invoke(payload)
        if (
            result["operation"] != operation
            or result["session_id"] != session_id
            or result["backend_id"] != self.backend_id
            or result["state"] != state
            or not result["ready"]
            or result["turn_id"] != turn_id
            or (operation != "turn" and result["replayed"])
        ):
            raise PluginInvocationError("agent provider response binding mismatch")
        final_status = str(result["final_status"])
        if operation == "close":
            if final_status not in {"completed", "error", "interrupted", "timeout"}:
                raise PluginInvocationError("agent provider close status is invalid")
        elif operation == "cancel":
            if final_status != "interrupted":
                raise PluginInvocationError("agent provider cancel status is invalid")
        elif final_status:
            raise PluginInvocationError("active agent operation returned a final status")
        return result

    def _cancel_session_best_effort(self, session_id: str) -> bool:
        try:
            self._invoke_expected(
                {"operation": "cancel", "session_id": session_id},
                state="cancelled",
            )
        except Exception:  # The original boundary failure remains authoritative.
            return False
        self._cleanup_session_id = None
        return True

    def preflight_check(self, *, timeout: float = 5.0) -> PreflightResult:
        started = time.monotonic()
        try:
            with self._call_lock, self._state_lock:
                timeout_ms = max(100, min(3_600_000, int(float(timeout) * 1_000)))
                result = self._invoke({"operation": "probe", "timeout_ms": timeout_ms})
                expected_state = "ready" if result["ready"] else "unavailable"
                if (
                    result["operation"] != "probe"
                    or result["session_id"] != ""
                    or result["backend_id"] != self.backend_id
                    or result["state"] != expected_state
                    or result["final_status"] != ""
                ):
                    raise PluginInvocationError("agent provider probe binding mismatch")
                ok = bool(result["ready"])
                detail = str(result["detail"])
                self._capabilities = self._effective_capabilities(
                    result["capabilities"]
                )
        except Exception as exc:  # Plugin boundary reports failure; preflight never raises.
            ok = False
            detail = f"{type(exc).__name__}: {exc}"
        return PreflightResult(
            ok=ok,
            backend_id=self.backend_id,
            checked_at=datetime.now(timezone.utc).isoformat(),
            duration_ms=int((time.monotonic() - started) * 1_000),
            detail=detail[:_MAX_ERROR_CHARS],
        )

    def start_session(self, config: SessionConfig) -> None:
        with self._call_lock, self._state_lock:
            if not isinstance(config, SessionConfig):
                raise TypeError("config must be a SessionConfig")
            if self._active:
                raise RuntimeError("plugin agent session is already active")
            if self._cleanup_session_id is not None:
                raise RuntimeError(
                    "previous plugin session cleanup is unresolved; cancel it before opening"
                )
            if config.env or config.extra:
                raise ValueError(
                    "plugin agent sessions do not accept caller-controlled env or extra"
                )
            if config.workdir is not None:
                raise ValueError("plugin agent session workdir is host-controlled")
            requested_tools = _bounded_policy_values(
                config.allowed_tools or (),
                label="session allowed_tools",
            )
            if not requested_tools <= self._allowed_tools:
                raise ValueError("session requested tools outside the host allowlist")
            if config.model is not None and config.model not in self._allowed_models:
                raise ValueError("session model is outside the host allowlist")
            if type(config.max_tokens) is not int or not (
                1 <= config.max_tokens <= self._max_session_tokens
            ):
                raise ValueError("session max_tokens exceeds the host policy")
            if (
                isinstance(config.timeout, bool)
                or not isinstance(config.timeout, (int, float))
                or not math.isfinite(config.timeout)
            ):
                raise ValueError("session timeout must be finite")
            timeout_ms = int(float(config.timeout) * 1_000)
            if not 100 <= timeout_ms <= self._max_timeout_ms:
                raise ValueError("session timeout exceeds the host policy")
            if config.temperature is not None and (
                isinstance(config.temperature, bool)
                or not isinstance(config.temperature, (int, float))
                or not math.isfinite(config.temperature)
                or not 0 <= float(config.temperature) <= 2
            ):
                raise ValueError(
                    "session temperature must be None or a number between 0 and 2"
                )
            temperature_milli: int | None = None
            if config.temperature is not None:
                scaled_temperature = float(config.temperature) * 1_000.0
                rounded_temperature = round(scaled_temperature)
                if not math.isclose(
                    scaled_temperature,
                    float(rounded_temperature),
                    rel_tol=0.0,
                    abs_tol=1e-9,
                ):
                    raise ValueError(
                        "session temperature supports at most three decimal places"
                    )
                temperature_milli = int(rounded_temperature)
            payload: Dict[str, Any] = {
                "goal": config.goal,
                "max_tokens": config.max_tokens,
                "operation": "open",
                "session_id": config.session_id,
                "timeout_ms": timeout_ms,
            }
            if config.temperature is not None:
                probe = self._invoke(
                    {"operation": "probe", "timeout_ms": timeout_ms}
                )
                if (
                    probe["operation"] != "probe"
                    or probe["backend_id"] != self.backend_id
                    or not probe["ready"]
                    or probe["state"] != "ready"
                ):
                    raise PluginInvocationError(
                        "agent provider is not ready for session creation"
                    )
                probed_capabilities = self._effective_capabilities(
                    probe["capabilities"]
                )
                if not probed_capabilities.supports_temperature:
                    raise ValueError(
                        "agent provider does not support temperature overrides"
                    )
                payload["temperature_milli"] = temperature_milli
            if config.model is not None:
                payload["model"] = config.model
            validate_agent_session_input(payload)
            self._cleanup_session_id = config.session_id
            try:
                result = self._invoke_expected(payload, state="active")
            except Exception:
                self._cancel_session_best_effort(config.session_id)
                raise
            self._session_config = config
            self._session_started_at = time.time()
            self._turn_count = 0
            self._cumulative_usage = TokenUsage()
            self._capabilities = self._effective_capabilities(result["capabilities"])
            self._pending_turn = None
            self._cleanup_session_id = None
            self._session_allowed_tools = requested_tools
            self._active = True

    def send_turn(self, prompt: str, system_prompt: str = "") -> TurnResponse:
        with self._call_lock:
            with self._state_lock:
                if not self._active or self._session_config is None:
                    raise RuntimeError("plugin agent session is not active")
                if self._pending_turn is None:
                    if self._turn_count and not self._capabilities.supports_multi_turn:
                        raise RuntimeError(
                            "agent provider does not support multiple turns"
                        )
                    pending = (secrets.token_hex(16), prompt, system_prompt)
                else:
                    pending = self._pending_turn
                turn_id, pending_prompt, pending_system_prompt = pending
                if (pending_prompt, pending_system_prompt) != (prompt, system_prompt):
                    raise RuntimeError(
                        "previous agent turn outcome is unknown; retry the same turn or cancel"
                    )
                session_id = self._session_config.session_id
                max_output_tokens = self._session_config.max_tokens
                timeout_ms = int(self._session_config.timeout * 1_000)
                payload = {
                    "operation": "turn",
                    "prompt": prompt,
                    "session_id": session_id,
                    "system_prompt": system_prompt,
                    "timeout_ms": timeout_ms,
                    "turn_id": turn_id,
                }
                validate_agent_session_input(payload)
                if self._pending_turn is None:
                    self._pending_turn = pending
            result = self._invoke_expected(payload, state="active")
            usage = TokenUsage(
                input_tokens=int(result["input_tokens"]),
                output_tokens=int(result["output_tokens"]),
            )
            if usage.output_tokens > max_output_tokens:
                raise PluginInvocationError(
                    "agent provider exceeded the session output-token limit"
                )
            total_turns = int(result["total_turns"])
            cumulative_usage = TokenUsage(
                input_tokens=int(result["total_input_tokens"]),
                output_tokens=int(result["total_output_tokens"]),
            )
            tool_calls = []
            for item in result["tool_calls"]:
                if item["name"] not in self._session_allowed_tools:
                    raise PluginInvocationError(
                        f"agent provider requested unauthorized tool {item['name']!r}"
                    )
                arguments = _decode_tool_arguments(item["arguments_json"])
                tool_calls.append(
                    ToolCall(
                        id=str(item["id"]),
                        name=str(item["name"]),
                        arguments=arguments,
                    )
                )
            metadata = {
                "provider_plugin_id": self._binding.plugin_id,
                "replayed": bool(result["replayed"]),
                "turn_id": turn_id,
            }
            receipt_id = str(result.get("receipt_id", ""))
            receipt_hash = str(result.get("receipt_content_hash", ""))
            if receipt_id and receipt_hash:
                metadata.update(
                    {
                        "receipt_content_hash": receipt_hash,
                        "receipt_id": receipt_id,
                    }
                )
            response = TurnResponse(
                content=str(result["content"]),
                finish_reason=str(result["finish_reason"]),
                usage=usage,
                tool_calls=tool_calls,
                latency_seconds=int(result["latency_ms"]) / 1_000.0,
                error=str(result["error"]) or None,
                metadata=metadata,
            )
            with self._state_lock:
                if (
                    not self._active
                    or self._session_config is None
                    or self._session_config.session_id != session_id
                ):
                    raise PluginInvocationError("agent session was cancelled during turn")
                expected_usage = self._cumulative_usage + usage
                if (
                    total_turns != self._turn_count + 1
                    or cumulative_usage != expected_usage
                ):
                    raise PluginInvocationError(
                        "agent provider cumulative turn accounting mismatch"
                    )
                self._turn_count = total_turns
                self._cumulative_usage = cumulative_usage
                self._pending_turn = None
            return response

    def end_session(self) -> SessionSummary:
        with self._call_lock, self._state_lock:
            if not self._active or self._session_config is None:
                raise RuntimeError("plugin agent session is not active")
            if self._pending_turn is not None:
                raise RuntimeError(
                    "agent turn outcome is unknown; retry the same turn or cancel"
                )
            session_id = self._session_config.session_id
            self._cleanup_session_id = session_id
            try:
                result = self._invoke_expected(
                    {"operation": "close", "session_id": session_id},
                    state="closed",
                )
                total_usage = TokenUsage(
                    input_tokens=int(result["total_input_tokens"]),
                    output_tokens=int(result["total_output_tokens"]),
                )
                if (
                    int(result["total_turns"]) != self._turn_count
                    or total_usage != self._cumulative_usage
                ):
                    raise PluginInvocationError(
                        "agent provider final session accounting mismatch"
                    )
                summary = SessionSummary(
                    session_id=session_id,
                    backend_id=self.backend_id,
                    total_turns=int(result["total_turns"]),
                    total_usage=total_usage,
                    duration_seconds=int(result["duration_ms"]) / 1_000.0,
                    final_status=str(result["final_status"]),
                    error=str(result["error"]) or None,
                    metadata={"provider_plugin_id": self._binding.plugin_id},
                )
            except Exception:
                self._cancel_session_best_effort(session_id)
                self._active = False
                self._pending_turn = None
                self._session_config = None
                self._session_allowed_tools = frozenset()
                raise
            self._active = False
            self._pending_turn = None
            self._cleanup_session_id = None
            self._session_config = None
            self._session_allowed_tools = frozenset()
            return summary

    def cancel(self) -> None:
        with self._state_lock:
            session_id = (
                self._session_config.session_id
                if self._active and self._session_config is not None
                else self._cleanup_session_id
            )
            if session_id is None:
                return
            self._cleanup_session_id = session_id
            self._active = False
            self._pending_turn = None
            self._session_config = None
            self._session_allowed_tools = frozenset()
        self._invoke_expected(
            {"operation": "cancel", "session_id": session_id},
            state="cancelled",
        )
        with self._state_lock:
            if self._cleanup_session_id == session_id:
                self._cleanup_session_id = None

    def close(self) -> None:
        """Release an active provider session during ``TeamSession.detach``."""

        self.cancel()

    def capabilities(self) -> BackendCapabilities:
        with self._state_lock:
            return self._capabilities

    def _effective_capabilities(
        self,
        value: Mapping[str, Any],
    ) -> BackendCapabilities:
        capabilities = _capabilities_from_document(value)
        capabilities.supports_tools = bool(
            capabilities.supports_tools and self._allowed_tools
        )
        return capabilities


def _capabilities_from_document(value: Mapping[str, Any]) -> BackendCapabilities:
    return BackendCapabilities(
        supports_streaming=bool(value["supports_streaming"]),
        supports_tools=bool(value["supports_tools"]),
        supports_system_prompt=bool(value["supports_system_prompt"]),
        supports_multi_turn=bool(value["supports_multi_turn"]),
        supports_temperature=bool(value["supports_temperature"]),
        max_context_tokens=int(value["max_context_tokens"]),
        notes=str(value["notes"]),
    )


def _decode_tool_arguments(value: str) -> Dict[str, Any]:
    if not isinstance(value, str):
        raise PluginInvocationError("tool arguments must be canonical JSON text")

    def reject_duplicates(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate tool argument field {key!r}")
            result[key] = item
        return result

    try:
        decoded = json.loads(value, object_pairs_hook=reject_duplicates)
        if not isinstance(decoded, dict):
            raise ValueError("tool arguments root is not an object")
        if canonical_json(decoded).decode("utf-8") != value:
            raise ValueError("tool arguments are not canonical JSON")
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError) as exc:
        raise PluginInvocationError(
            "tool arguments are not canonical JSON object text"
        ) from exc
    return decoded


def _bounded_policy_values(value: Any, *, label: str) -> frozenset[str]:
    if not isinstance(value, (set, frozenset, list, tuple)):
        raise TypeError(f"{label} must be a finite collection of strings")
    items = tuple(value)
    if len(items) > 256:
        raise ValueError(f"{label} exceeds 256 entries")
    if any(
        not isinstance(item, str)
        or not item
        or item != item.strip()
        or len(item.encode("utf-8")) > 256
        for item in items
    ):
        raise ValueError(f"{label} contains an invalid value")
    if len(items) != len(set(items)):
        raise ValueError(f"{label} must not contain duplicates")
    return frozenset(items)


__all__ = ["PluginAgentBackend"]
