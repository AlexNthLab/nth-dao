"""Lifecycle, isolation, and facade tests for the reference agent provider."""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import threading
import time

import pytest

import nth_dao as nth
import nth_dao.plugins.builtin.mock_agent_provider as mock_provider_module
from nth_dao.plugins import (
    AGENT_SESSION_CAPABILITY_ID,
    AGENT_SESSION_INPUT_SCHEMA,
    AGENT_SESSION_OUTPUT_SCHEMA,
    CapabilitySchemas,
    InvocationAuthority,
    PluginAuthorizationError,
    PluginHost,
    PluginHostPolicy,
    PluginInvocationError,
    PluginSchemaError,
    validate_agent_session_input,
    validate_agent_session_output,
)
from nth_dao.plugins.agent_backend_adapter import PluginAgentBackend
from nth_dao.plugins.agent_provider import capability_document
from nth_dao.plugins.builtin import (
    MockAgentProviderPlugin,
    mock_agent_provider_manifest,
    register_mock_agent_provider,
)
from nth_dao.web import create_app
from team_layer.backends import BackendCapabilities, SessionConfig


def _authority(principal: str = "test-operator") -> InvocationAuthority:
    return InvocationAuthority(
        principal=principal,
        capability_ids=frozenset({AGENT_SESSION_CAPABILITY_ID}),
    )


def _host(tmp_path: Path) -> PluginHost:
    return PluginHost(policy=PluginHostPolicy(), workspace_root=tmp_path)


def _enabled_binding(tmp_path: Path):
    host = _host(tmp_path)
    item = register_mock_agent_provider(host)
    host.authorize(item.plugin_id, set())
    binding = host.enable(item.plugin_id)[0]
    return host, item, binding


def _wire_response(*, operation: str, session_id: str, state: str) -> dict:
    return {
        "backend_id": "mock",
        "capabilities": capability_document(BackendCapabilities()),
        "content": "",
        "detail": "",
        "duration_ms": 0,
        "error": "",
        "final_status": "",
        "finish_reason": "",
        "input_tokens": 0,
        "latency_ms": 0,
        "lease_remaining_ms": 900_000 if state == "active" else 0,
        "operation": operation,
        "output_tokens": 0,
        "ready": True,
        "replayed": False,
        "session_id": session_id,
        "state": state,
        "tool_calls": [],
        "total_input_tokens": 0,
        "total_output_tokens": 0,
        "total_turns": 0,
        "turn_id": "",
    }


def test_mock_agent_provider_is_installed_but_disabled_by_default(tmp_path: Path) -> None:
    host = _host(tmp_path)
    item = register_mock_agent_provider(host)
    status = host.status(item.plugin_id)
    assert status.state == "installed"
    assert status.risk_tier == 0
    assert status.declared_permissions == ()
    assert host.resolve(AGENT_SESSION_CAPABILITY_ID) == ()


def test_web_registers_mock_agent_provider_without_enabling_it(tmp_path: Path) -> None:
    app = create_app(tmp_path)
    status = app.state.nth.plugin_host.status(mock_agent_provider_manifest().plugin_id)
    assert status.state == "installed"
    assert status.desired_enabled is False
    assert app.state.nth.plugin_host.resolve(AGENT_SESSION_CAPABILITY_ID) == ()


def test_host_enforces_agent_session_semantic_validators(tmp_path: Path) -> None:
    class ContradictoryProvider:
        def invoke(self, payload, context):
            del payload, context
            response = _wire_response(operation="probe", session_id="", state="ready")
            response["ready"] = False
            return response

    class Runtime:
        def start(self, context):
            del context
            return {AGENT_SESSION_CAPABILITY_ID: ContradictoryProvider()}

        def stop(self):
            return None

    host = _host(tmp_path)
    item = replace(
        mock_agent_provider_manifest(),
        plugin_id="org.nth-dao.agent.semantic-rejection",
        artifact_digest="sha256:" + "7" * 64,
    )
    host.register_builtin(
        item,
        Runtime,
        schemas={
            AGENT_SESSION_CAPABILITY_ID: CapabilitySchemas(
                AGENT_SESSION_INPUT_SCHEMA,
                AGENT_SESSION_OUTPUT_SCHEMA,
                input_validator=validate_agent_session_input,
                output_validator=validate_agent_session_output,
            )
        },
    )
    host.authorize(item.plugin_id, set())
    binding = host.enable(item.plugin_id)[0]
    with pytest.raises(PluginSchemaError, match="ready/state mismatch"):
        binding.invoke({"operation": "probe"}, authority=_authority())


def test_plugin_agent_backend_round_trip(tmp_path: Path) -> None:
    host, item, binding = _enabled_binding(tmp_path)
    backend = PluginAgentBackend(
        binding,
        authority=_authority(),
        backend_id="mock",
    )
    assert backend.preflight_check().ok is True
    backend.start_session(SessionConfig(session_id="round-trip", goal="test"))
    response = backend.send_turn("hello")
    assert response.content == "Mock response to: 'hello'"
    assert response.finish_reason == "stop"
    assert response.metadata["provider_plugin_id"] == item.plugin_id
    assert response.metadata["replayed"] is False
    assert len(response.metadata["turn_id"]) == 32
    summary = backend.end_session()
    assert summary.total_turns == 1
    assert summary.backend_id == "mock"
    assert summary.final_status == "completed"
    assert host.disable(item.plugin_id) is True


def test_plugin_agent_backend_preserves_canonical_tool_arguments(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    backend = PluginAgentBackend(
        binding,
        authority=_authority(),
        backend_id="mock",
        allowed_tools={"search"},
    )
    backend.start_session(
        SessionConfig(
            session_id="tools",
            goal="test",
            allowed_tools=["search"],
        )
    )
    assert backend.capabilities().supports_streaming is False
    response = backend.send_turn("tool: search")
    assert response.finish_reason == "tool_call"
    assert response.tool_calls[0].name == "search"
    assert response.tool_calls[0].arguments == {"query": "tool: search"}
    backend.end_session()
    host.disable(binding.plugin_id)


def test_plugin_agent_backend_rejects_valid_shape_with_wrong_response_binding(
    tmp_path: Path,
) -> None:
    cancelled = []

    class WrongSessionProvider:
        def invoke(self, payload, context):
            del context
            if payload["operation"] == "cancel":
                cancelled.append(payload["session_id"])
                response = _wire_response(
                    operation="cancel",
                    session_id=payload["session_id"],
                    state="cancelled",
                )
                response["final_status"] = "interrupted"
                return response
            return _wire_response(
                operation=payload["operation"],
                session_id="retargeted",
                state="active",
            )

    class Runtime:
        def start(self, context):
            del context
            return {AGENT_SESSION_CAPABILITY_ID: WrongSessionProvider()}

        def stop(self):
            return None

    host = _host(tmp_path)
    item = replace(
        mock_agent_provider_manifest(),
        plugin_id="org.nth-dao.agent.wrong-response",
        artifact_digest="sha256:" + "1" * 64,
    )
    host.register_builtin(
        item,
        Runtime,
        schemas={
            AGENT_SESSION_CAPABILITY_ID: CapabilitySchemas(
                AGENT_SESSION_INPUT_SCHEMA,
                AGENT_SESSION_OUTPUT_SCHEMA,
            )
        },
    )
    host.authorize(item.plugin_id, set())
    binding = host.enable(item.plugin_id)[0]
    backend = PluginAgentBackend(
        binding,
        authority=_authority(),
        backend_id="mock",
    )
    with pytest.raises(PluginInvocationError, match="binding mismatch"):
        backend.start_session(SessionConfig(session_id="expected", goal="test"))
    assert cancelled == ["expected"]
    with pytest.raises(RuntimeError, match="not active"):
        backend.send_turn("no hidden session")


def test_plugin_backend_reuses_pending_turn_id_after_unknown_outcome(
    tmp_path: Path,
) -> None:
    seen_turn_ids = []

    class OutcomeUnknownProvider:
        def invoke(self, payload, context):
            del context
            operation = payload["operation"]
            state = {"open": "active", "turn": "active", "cancel": "cancelled"}[
                operation
            ]
            response = _wire_response(
                operation=operation,
                session_id=payload["session_id"],
                state=state,
            )
            if operation == "turn":
                seen_turn_ids.append(payload["turn_id"])
                response["turn_id"] = payload["turn_id"]
                response["finish_reason"] = "stop"
                response["content"] = "completed once"
                response["total_turns"] = 1
                if len(seen_turn_ids) == 1:
                    response["session_id"] = "malformed-after-execution"
                else:
                    response["replayed"] = True
            elif operation == "cancel":
                response["final_status"] = "interrupted"
            return response

    class Runtime:
        def start(self, context):
            del context
            return {AGENT_SESSION_CAPABILITY_ID: OutcomeUnknownProvider()}

        def stop(self):
            return None

    host = _host(tmp_path)
    item = replace(
        mock_agent_provider_manifest(),
        plugin_id="org.nth-dao.agent.outcome-unknown",
        artifact_digest="sha256:" + "3" * 64,
    )
    host.register_builtin(
        item,
        Runtime,
        schemas={
            AGENT_SESSION_CAPABILITY_ID: CapabilitySchemas(
                AGENT_SESSION_INPUT_SCHEMA,
                AGENT_SESSION_OUTPUT_SCHEMA,
            )
        },
    )
    host.authorize(item.plugin_id, set())
    backend = PluginAgentBackend(
        host.enable(item.plugin_id)[0],
        authority=_authority(),
        backend_id="mock",
    )
    backend.start_session(SessionConfig(session_id="pending", goal="test"))
    with pytest.raises(PluginInvocationError, match="binding mismatch"):
        backend.send_turn("execute once")
    with pytest.raises(RuntimeError, match="retry the same turn"):
        backend.send_turn("different input")
    replay = backend.send_turn("execute once")
    assert replay.content == "completed once"
    assert replay.metadata["replayed"] is True
    assert len(seen_turn_ids) == 2
    assert seen_turn_ids[0] == seen_turn_ids[1]
    backend.cancel()


def test_plugin_backend_cleans_up_after_invalid_close_response(tmp_path: Path) -> None:
    events = []

    class InvalidCloseProvider:
        def invoke(self, payload, context):
            del context
            operation = payload["operation"]
            if operation == "open":
                return _wire_response(
                    operation="open",
                    session_id=payload["session_id"],
                    state="active",
                )
            if operation == "close":
                events.append("closed")
                response = _wire_response(
                    operation="close",
                    session_id=payload["session_id"],
                    state="active",
                )
                response["final_status"] = "completed"
                return response
            events.append("cancelled")
            response = _wire_response(
                operation="cancel",
                session_id=payload["session_id"],
                state="cancelled",
            )
            response["final_status"] = "interrupted"
            return response

    class Runtime:
        def start(self, context):
            del context
            return {AGENT_SESSION_CAPABILITY_ID: InvalidCloseProvider()}

        def stop(self):
            return None

    host = _host(tmp_path)
    item = replace(
        mock_agent_provider_manifest(),
        plugin_id="org.nth-dao.agent.invalid-close",
        artifact_digest="sha256:" + "4" * 64,
    )
    host.register_builtin(
        item,
        Runtime,
        schemas={
            AGENT_SESSION_CAPABILITY_ID: CapabilitySchemas(
                AGENT_SESSION_INPUT_SCHEMA,
                AGENT_SESSION_OUTPUT_SCHEMA,
            )
        },
    )
    host.authorize(item.plugin_id, set())
    backend = PluginAgentBackend(
        host.enable(item.plugin_id)[0],
        authority=_authority(),
        backend_id="mock",
    )
    backend.start_session(SessionConfig(session_id="close-cleanup", goal="test"))
    with pytest.raises(PluginSchemaError, match="terminal state"):
        backend.end_session()
    assert events == ["closed", "cancelled"]
    with pytest.raises(RuntimeError, match="not active"):
        backend.send_turn("after failed close")


def test_plugin_backend_rejects_inconsistent_cumulative_accounting(
    tmp_path: Path,
) -> None:
    class BadAccountingProvider:
        def invoke(self, payload, context):
            del context
            operation = payload["operation"]
            state = {"open": "active", "turn": "active", "cancel": "cancelled"}[
                operation
            ]
            response = _wire_response(
                operation=operation,
                session_id=payload["session_id"],
                state=state,
            )
            if operation == "turn":
                response["turn_id"] = payload["turn_id"]
                response["finish_reason"] = "stop"
                response["total_turns"] = 9
            elif operation == "cancel":
                response["final_status"] = "interrupted"
            return response

    class Runtime:
        def start(self, context):
            del context
            return {AGENT_SESSION_CAPABILITY_ID: BadAccountingProvider()}

        def stop(self):
            return None

    host = _host(tmp_path)
    item = replace(
        mock_agent_provider_manifest(),
        plugin_id="org.nth-dao.agent.bad-accounting",
        artifact_digest="sha256:" + "5" * 64,
    )
    host.register_builtin(
        item,
        Runtime,
        schemas={
            AGENT_SESSION_CAPABILITY_ID: CapabilitySchemas(
                AGENT_SESSION_INPUT_SCHEMA,
                AGENT_SESSION_OUTPUT_SCHEMA,
            )
        },
    )
    host.authorize(item.plugin_id, set())
    backend = PluginAgentBackend(
        host.enable(item.plugin_id)[0],
        authority=_authority(),
        backend_id="mock",
    )
    backend.start_session(SessionConfig(session_id="accounting", goal="test"))
    with pytest.raises(PluginInvocationError, match="accounting mismatch"):
        backend.send_turn("bad totals")
    with pytest.raises(RuntimeError, match="retry the same turn"):
        backend.send_turn("different turn")
    backend.cancel()


def test_plugin_backend_cancel_interrupts_an_inflight_turn(tmp_path: Path) -> None:
    entered = threading.Event()
    cancelled = threading.Event()

    class CancellableProvider:
        def invoke(self, payload, context):
            del context
            operation = payload["operation"]
            if operation == "open":
                return _wire_response(
                    operation="open",
                    session_id=payload["session_id"],
                    state="active",
                )
            if operation == "cancel":
                cancelled.set()
                response = _wire_response(
                    operation="cancel",
                    session_id=payload["session_id"],
                    state="cancelled",
                )
                response["final_status"] = "interrupted"
                return response
            entered.set()
            assert cancelled.wait(1.0)
            response = _wire_response(
                operation="turn",
                session_id=payload["session_id"],
                state="active",
            )
            response["turn_id"] = payload["turn_id"]
            response["finish_reason"] = "stop"
            response["total_turns"] = 1
            return response

    class Runtime:
        def start(self, context):
            del context
            return {AGENT_SESSION_CAPABILITY_ID: CancellableProvider()}

        def stop(self):
            return None

    host = _host(tmp_path)
    item = replace(
        mock_agent_provider_manifest(),
        plugin_id="org.nth-dao.agent.cancellable",
        artifact_digest="sha256:" + "6" * 64,
    )
    host.register_builtin(
        item,
        Runtime,
        schemas={
            AGENT_SESSION_CAPABILITY_ID: CapabilitySchemas(
                AGENT_SESSION_INPUT_SCHEMA,
                AGENT_SESSION_OUTPUT_SCHEMA,
            )
        },
    )
    host.authorize(item.plugin_id, set())
    backend = PluginAgentBackend(
        host.enable(item.plugin_id)[0],
        authority=_authority(),
        backend_id="mock",
    )
    backend.start_session(SessionConfig(session_id="interrupt", goal="test"))
    errors = []

    def run_turn() -> None:
        try:
            backend.send_turn("block")
        except PluginInvocationError as exc:
            errors.append(str(exc))

    thread = threading.Thread(target=run_turn)
    thread.start()
    assert entered.wait(1.0)
    started = time.monotonic()
    backend.cancel()
    assert time.monotonic() - started < 0.1
    thread.join(1.0)
    assert errors == ["agent session was cancelled during turn"]


def test_plugin_agent_backend_rejects_noncanonical_tool_argument_json(
    tmp_path: Path,
) -> None:
    class DuplicateArgumentProvider:
        def invoke(self, payload, context):
            del context
            operation = payload["operation"]
            state = {
                "open": "active",
                "turn": "active",
                "close": "closed",
            }[operation]
            response = _wire_response(
                operation=operation,
                session_id=payload["session_id"],
                state=state,
            )
            if operation == "turn":
                response["turn_id"] = payload["turn_id"]
                response["finish_reason"] = "tool_call"
                response["tool_calls"] = [
                    {
                        "arguments_json": '{"query":"one","query":"two"}',
                        "id": "call-1",
                        "name": "search",
                    }
                ]
                response["total_turns"] = 1
            elif operation == "close":
                response["final_status"] = "completed"
            return response

    class Runtime:
        def start(self, context):
            del context
            return {AGENT_SESSION_CAPABILITY_ID: DuplicateArgumentProvider()}

        def stop(self):
            return None

    host = _host(tmp_path)
    item = replace(
        mock_agent_provider_manifest(),
        plugin_id="org.nth-dao.agent.bad-tool-json",
        artifact_digest="sha256:" + "2" * 64,
    )
    host.register_builtin(
        item,
        Runtime,
        schemas={
            AGENT_SESSION_CAPABILITY_ID: CapabilitySchemas(
                AGENT_SESSION_INPUT_SCHEMA,
                AGENT_SESSION_OUTPUT_SCHEMA,
            )
        },
    )
    host.authorize(item.plugin_id, set())
    binding = host.enable(item.plugin_id)[0]
    backend = PluginAgentBackend(
        binding,
        authority=_authority(),
        backend_id="mock",
        allowed_tools={"search"},
    )
    backend.start_session(
        SessionConfig(
            session_id="tool-json",
            goal="test",
            allowed_tools=["search"],
        )
    )
    with pytest.raises(PluginInvocationError, match="canonical JSON"):
        backend.send_turn("use a tool")


def test_plugin_agent_backend_rejects_same_id_with_incompatible_contract(
    tmp_path: Path,
) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    incompatible = replace(
        binding,
        contract=replace(binding.contract, privacy="public"),
    )
    with pytest.raises(ValueError, match="incompatible"):
        PluginAgentBackend(
            incompatible,
            authority=_authority(),
            backend_id="mock",
        )
    assert host.status(binding.plugin_id).state == "enabled"


def test_agent_provider_session_is_scoped_to_principal(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    owner = _authority("owner")
    stranger = _authority("stranger")
    binding.invoke(
        {"operation": "open", "session_id": "same", "goal": "owner"},
        authority=owner,
    )
    with pytest.raises(PluginInvocationError, match="not active for this principal"):
        binding.invoke(
            {
                "operation": "turn",
                "session_id": "same",
                "prompt": "steal",
                "turn_id": "stranger-turn",
            },
            authority=stranger,
        )
    second = binding.invoke(
        {"operation": "open", "session_id": "same", "goal": "stranger"},
        authority=stranger,
    )
    assert second["state"] == "active"
    assert host.status(binding.plugin_id).state == "enabled"


def test_agent_provider_requires_capability_authority(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    wrong = InvocationAuthority(
        principal="wrong-scope",
        capability_ids=frozenset({"org.nth-dao.other.capability"}),
    )
    with pytest.raises(PluginAuthorizationError, match="not authorized"):
        binding.invoke({"operation": "probe"}, authority=wrong)
    with pytest.raises(ValueError, match="does not grant"):
        PluginAgentBackend(binding, authority=wrong, backend_id="mock")
    assert host.status(binding.plugin_id).state == "enabled"


def test_agent_provider_enforces_global_session_capacity(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    for index in range(32):
        binding.invoke(
            {
                "operation": "open",
                "session_id": f"session-{index}",
                "goal": "capacity",
            },
            authority=_authority(f"principal-{index}"),
        )
    with pytest.raises(PluginInvocationError, match="session limit"):
        binding.invoke(
            {"operation": "open", "session_id": "overflow", "goal": "capacity"},
            authority=_authority("overflow-principal"),
        )
    host.disable(binding.plugin_id)


def test_agent_provider_enforces_per_principal_session_capacity(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    authority = _authority("capacity-owner")
    for index in range(8):
        binding.invoke(
            {
                "operation": "open",
                "session_id": f"owned-{index}",
                "goal": "capacity",
            },
            authority=authority,
        )
    with pytest.raises(PluginInvocationError, match="principal session limit"):
        binding.invoke(
            {"operation": "open", "session_id": "owned-overflow", "goal": "capacity"},
            authority=authority,
        )
    other = binding.invoke(
        {"operation": "open", "session_id": "other", "goal": "capacity"},
        authority=_authority("other-principal"),
    )
    assert other["state"] == "active"
    host.disable(binding.plugin_id)


def test_expired_session_is_reaped_and_identifier_can_be_reused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": 100.0}

    class FakeTime:
        @staticmethod
        def monotonic() -> float:
            return clock["now"]

    monkeypatch.setattr(mock_provider_module, "time", FakeTime)
    host, _, binding = _enabled_binding(tmp_path)
    authority = _authority("lease-owner")
    opened = binding.invoke(
        {"operation": "open", "session_id": "leased", "goal": "test"},
        authority=authority,
    )
    assert opened["lease_remaining_ms"] == 900_000
    clock["now"] += 901.0
    with pytest.raises(PluginInvocationError, match="lease expired"):
        binding.invoke(
            {"operation": "status", "session_id": "leased"},
            authority=authority,
        )
    reopened = binding.invoke(
        {"operation": "open", "session_id": "leased", "goal": "again"},
        authority=authority,
    )
    assert reopened["state"] == "active"
    assert host.status(binding.plugin_id).state == "enabled"


def test_agent_provider_rejects_operation_field_smuggling(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    with pytest.raises(PluginSchemaError, match="does not accept fields"):
        binding.invoke(
            {"operation": "probe", "session_id": "smuggled"},
            authority=_authority(),
        )
    with pytest.raises(PluginSchemaError, match="unknown fields"):
        binding.invoke(
            {"operation": "probe", "command": "whoami"},
            authority=_authority(),
        )
    assert host.status(binding.plugin_id).state == "enabled"


def test_agent_provider_rejects_ambiguous_session_identifier(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    with pytest.raises(PluginSchemaError, match="session_id"):
        binding.invoke(
            {"operation": "open", "session_id": " padded ", "goal": "test"},
            authority=_authority(),
        )
    with pytest.raises(PluginSchemaError, match="session_id"):
        binding.invoke(
            {"operation": "open", "session_id": "control\u0000", "goal": "test"},
            authority=_authority(),
        )
    assert host.status(binding.plugin_id).state == "enabled"


def test_plugin_backend_rejects_host_owned_session_configuration(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    backend = PluginAgentBackend(
        binding,
        authority=_authority(),
        backend_id="mock",
    )
    with pytest.raises(ValueError, match="host-controlled"):
        backend.start_session(
            SessionConfig(session_id="bad-workdir", goal="test", workdir=tmp_path)
        )
    with pytest.raises(ValueError, match="caller-controlled"):
        backend.start_session(
            SessionConfig(session_id="bad-env", goal="test", env={"TOKEN": "secret"})
        )
    assert host.status(binding.plugin_id).state == "enabled"


def test_plugin_backend_enforces_host_model_and_resource_policy(
    tmp_path: Path,
) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    backend = PluginAgentBackend(
        binding,
        authority=_authority(),
        backend_id="mock",
        allowed_models={"reviewed-model"},
        max_session_tokens=8_192,
        max_timeout_s=30,
    )
    with pytest.raises(ValueError, match="model.*allowlist"):
        backend.start_session(
            SessionConfig(session_id="bad-model", goal="test", model="other")
        )
    with pytest.raises(ValueError, match="max_tokens"):
        backend.start_session(
            SessionConfig(session_id="too-many-tokens", goal="test", max_tokens=8_193)
        )
    with pytest.raises(ValueError, match="timeout"):
        backend.start_session(
            SessionConfig(session_id="too-long", goal="test", timeout=31)
        )
    backend.start_session(
        SessionConfig(
            session_id="policy-approved",
            goal="test",
            model="reviewed-model",
            max_tokens=8_192,
            timeout=30,
        )
    )
    backend.cancel()
    host.disable(binding.plugin_id)


def test_mock_provider_enforces_per_turn_output_token_limit(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    authority = _authority()
    binding.invoke(
        {
            "goal": "test",
            "max_tokens": 1,
            "operation": "open",
            "session_id": "small-output-budget",
        },
        authority=authority,
    )
    result = binding.invoke(
        {
            "operation": "turn",
            "prompt": "a response that is longer than four characters",
            "session_id": "small-output-budget",
            "turn_id": "limited-turn",
        },
        authority=authority,
    )
    assert result["finish_reason"] == "length"
    assert result["output_tokens"] == 1
    assert len(result["content"]) <= 4


def test_plugin_backend_rejects_provider_output_over_session_limit(
    tmp_path: Path,
) -> None:
    class OverBudgetProvider:
        def invoke(self, payload, context):
            del context
            operation = payload["operation"]
            state = {"open": "active", "turn": "active", "cancel": "cancelled"}[
                operation
            ]
            response = _wire_response(
                operation=operation,
                session_id=payload["session_id"],
                state=state,
            )
            if operation == "turn":
                response.update(
                    {
                        "content": "too many tokens",
                        "finish_reason": "stop",
                        "input_tokens": 1,
                        "output_tokens": 2,
                        "total_input_tokens": 1,
                        "total_output_tokens": 2,
                        "total_turns": 1,
                        "turn_id": payload["turn_id"],
                    }
                )
            elif operation == "cancel":
                response["final_status"] = "interrupted"
            return response

    class Runtime:
        def start(self, context):
            del context
            return {AGENT_SESSION_CAPABILITY_ID: OverBudgetProvider()}

        def stop(self):
            return None

    host = _host(tmp_path)
    item = replace(
        mock_agent_provider_manifest(),
        plugin_id="org.nth-dao.agent.over-budget",
        artifact_digest="sha256:" + "8" * 64,
    )
    host.register_builtin(
        item,
        Runtime,
        schemas={
            AGENT_SESSION_CAPABILITY_ID: CapabilitySchemas(
                AGENT_SESSION_INPUT_SCHEMA,
                AGENT_SESSION_OUTPUT_SCHEMA,
                input_validator=validate_agent_session_input,
                output_validator=validate_agent_session_output,
            )
        },
    )
    host.authorize(item.plugin_id, set())
    binding = host.enable(item.plugin_id)[0]
    backend = PluginAgentBackend(
        binding,
        authority=_authority(),
        backend_id="mock",
        max_session_tokens=1,
    )
    backend.start_session(
        SessionConfig(session_id="reject-over-budget", goal="test", max_tokens=1)
    )
    with pytest.raises(PluginInvocationError, match="output-token limit"):
        backend.send_turn("hello")
    backend.cancel()


def test_plugin_backend_requires_host_and_session_tool_grants(
    tmp_path: Path,
) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    backend = PluginAgentBackend(
        binding,
        authority=_authority(),
        backend_id="mock",
        allowed_tools={"search"},
    )
    with pytest.raises(ValueError, match="outside the host allowlist"):
        backend.start_session(
            SessionConfig(
                session_id="unapproved-tool",
                goal="test",
                allowed_tools=["shell"],
            )
        )
    backend.start_session(
        SessionConfig(session_id="no-session-tool-grant", goal="test")
    )
    with pytest.raises(PluginInvocationError, match="unauthorized tool"):
        backend.send_turn("tool: search")
    backend.cancel()
    host.disable(binding.plugin_id)


def test_local_open_validation_failure_does_not_poison_adapter(
    tmp_path: Path,
) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    backend = PluginAgentBackend(
        binding,
        authority=_authority(),
        backend_id="mock",
    )
    with pytest.raises(ValueError, match="timeout"):
        backend.start_session(
            SessionConfig(session_id="invalid-timeout", goal="test", timeout=0)
        )
    backend.start_session(SessionConfig(session_id="valid-after-rejection", goal="test"))
    backend.cancel()
    host.disable(binding.plugin_id)


def test_local_turn_validation_failure_does_not_create_pending_turn(
    tmp_path: Path,
) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    backend = PluginAgentBackend(
        binding,
        authority=_authority(),
        backend_id="mock",
    )
    backend.start_session(SessionConfig(session_id="turn-validation", goal="test"))
    with pytest.raises(PluginSchemaError, match="prompt"):
        backend.send_turn("x" * 262_145)
    response = backend.send_turn("valid after rejection")
    assert response.finish_reason == "stop"
    backend.cancel()
    host.disable(binding.plugin_id)


def test_mock_provider_has_no_runtime_loader_or_legacy_backend_import() -> None:
    source = Path(mock_provider_module.__file__).read_text(encoding="utf-8")
    assert "backend_factory" not in source
    imported = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    assert all(not name.startswith("team_layer") for name in imported)
    with pytest.raises(TypeError, match="unexpected keyword"):
        MockAgentProviderPlugin(backend_factory=lambda: object())  # type: ignore[call-arg]


def test_registration_upgrades_changed_reviewed_artifact_digest(tmp_path: Path) -> None:
    old_host = _host(tmp_path)
    old_item = replace(
        mock_agent_provider_manifest(),
        artifact_digest="sha256:" + "0" * 64,
    )
    old_host.register_builtin(
        old_item,
        MockAgentProviderPlugin,
        schemas={
            AGENT_SESSION_CAPABILITY_ID: CapabilitySchemas(
                AGENT_SESSION_INPUT_SCHEMA,
                AGENT_SESSION_OUTPUT_SCHEMA,
            )
        },
    )

    upgraded_host = _host(tmp_path)
    upgraded = register_mock_agent_provider(upgraded_host)
    assert upgraded.artifact_digest != old_item.artifact_digest
    assert upgraded_host.status(upgraded.plugin_id).state == "installed"


def test_concurrent_turn_queue_is_bounded_by_fail_fast_busy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = threading.Event()
    release = threading.Event()
    original = mock_provider_module._dispatch_mock_turn

    def blocked_dispatch(prompt: str, system_prompt: str):
        entered.set()
        assert release.wait(2.0)
        return original(prompt, system_prompt)

    monkeypatch.setattr(mock_provider_module, "_dispatch_mock_turn", blocked_dispatch)
    host, _, binding = _enabled_binding(tmp_path)
    authority = _authority()
    binding.invoke(
        {"operation": "open", "session_id": "serial", "goal": "test"},
        authority=authority,
    )
    def invoke_first():
        return binding.invoke(
            {
                "operation": "turn",
                "session_id": "serial",
                "prompt": "first",
                "turn_id": "turn-first",
            },
            authority=authority,
        )

    def invoke_while_busy(index: int) -> str:
        try:
            binding.invoke(
                    {
                        "operation": "turn",
                        "session_id": "serial",
                        "prompt": f"turn-{index}",
                        "turn_id": f"turn-{index}",
                    },
                    authority=authority,
            )
        except PluginInvocationError as exc:
            return str(exc)
        return "unexpected success"

    with ThreadPoolExecutor(max_workers=16) as pool:
        first = pool.submit(invoke_first)
        assert entered.wait(1.0)
        started = time.monotonic()
        rejected = list(pool.map(invoke_while_busy, range(64)))
        elapsed = time.monotonic() - started
        release.set()
        result = first.result(timeout=1.0)
    assert elapsed < 1.0
    assert set(rejected) == {"session is busy with another turn"}
    assert result["total_turns"] == 1
    replay = binding.invoke(
        {
            "operation": "turn",
            "session_id": "serial",
            "prompt": "first",
            "turn_id": "turn-first",
        },
        authority=authority,
    )
    assert replay["replayed"] is True
    assert replay["total_turns"] == 1


def test_inflight_turn_is_not_reaped_by_idle_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": 100.0}
    entered = threading.Event()
    release = threading.Event()
    original = mock_provider_module._dispatch_mock_turn

    class FakeTime:
        @staticmethod
        def monotonic() -> float:
            return clock["now"]

    def blocked_dispatch(prompt: str, system_prompt: str):
        entered.set()
        assert release.wait(2.0)
        return original(prompt, system_prompt)

    monkeypatch.setattr(mock_provider_module, "time", FakeTime)
    monkeypatch.setattr(mock_provider_module, "_dispatch_mock_turn", blocked_dispatch)
    host, _, binding = _enabled_binding(tmp_path)
    authority = _authority()
    binding.invoke(
        {"operation": "open", "session_id": "long-turn", "goal": "test"},
        authority=authority,
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            binding.invoke,
            {
                "operation": "turn",
                "session_id": "long-turn",
                "prompt": "long",
                "timeout_ms": 3_600_000,
                "turn_id": "long-turn-1",
            },
            authority=authority,
        )
        assert entered.wait(1.0)
        clock["now"] += 901.0
        binding.invoke(
            {"operation": "open", "session_id": "reaper-trigger", "goal": "test"},
            authority=authority,
        )
        release.set()
        result = future.result(timeout=1.0)
    assert result["finish_reason"] == "stop"
    assert result["total_turns"] == 1


def test_cancel_is_idempotent_for_absent_session(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    result = binding.invoke(
        {"operation": "cancel", "session_id": "never-opened"},
        authority=_authority(),
    )
    assert result["state"] == "cancelled"
    assert result["final_status"] == "interrupted"
    assert result["total_turns"] == 0


def test_disable_revokes_binding_and_cancels_open_sessions(tmp_path: Path) -> None:
    host, item, binding = _enabled_binding(tmp_path)
    binding.invoke(
        {"operation": "open", "session_id": "open", "goal": "test"},
        authority=_authority(),
    )
    assert host.disable(item.plugin_id) is True
    with pytest.raises(PluginInvocationError, match="disabled or stale"):
        binding.invoke({"operation": "probe"}, authority=_authority())


def test_turn_timeout_is_enforced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = mock_provider_module._dispatch_mock_turn

    def slow_dispatch(prompt: str, system_prompt: str):
        time.sleep(0.12)
        return original(prompt, system_prompt)

    monkeypatch.setattr(mock_provider_module, "_dispatch_mock_turn", slow_dispatch)
    host, _, binding = _enabled_binding(tmp_path)
    authority = _authority()
    binding.invoke(
        {"operation": "open", "session_id": "deadline", "goal": "test"},
        authority=authority,
    )
    result = binding.invoke(
        {
            "operation": "turn",
            "session_id": "deadline",
            "prompt": "hello",
            "timeout_ms": 100,
            "turn_id": "deadline-turn",
        },
        authority=authority,
    )
    assert result["finish_reason"] == "timeout"
    assert result["error"] == "mock turn exceeded timeout_ms"
    assert host.status(binding.plugin_id).state == "enabled"


def test_cancel_does_not_wait_for_turn_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = threading.Event()
    release = threading.Event()
    original = mock_provider_module._dispatch_mock_turn

    def blocked_dispatch(prompt: str, system_prompt: str):
        entered.set()
        assert release.wait(1.0)
        return original(prompt, system_prompt)

    monkeypatch.setattr(mock_provider_module, "_dispatch_mock_turn", blocked_dispatch)
    host, _, binding = _enabled_binding(tmp_path)
    authority = _authority()
    binding.invoke(
        {"operation": "open", "session_id": "cancel-now", "goal": "test"},
        authority=authority,
    )
    errors = []

    def run_turn() -> None:
        try:
            binding.invoke(
                {
                    "operation": "turn",
                    "session_id": "cancel-now",
                    "prompt": "wait",
                    "turn_id": "blocked-turn",
                },
                authority=authority,
            )
        except PluginInvocationError as exc:
            errors.append(str(exc))

    thread = threading.Thread(target=run_turn)
    thread.start()
    assert entered.wait(1.0)
    started = time.monotonic()
    result = binding.invoke(
        {"operation": "cancel", "session_id": "cancel-now"},
        authority=authority,
    )
    assert time.monotonic() - started < 0.1
    assert result["state"] == "cancelled"
    release.set()
    thread.join(1.0)
    assert errors == ["session was cancelled during turn"]
    assert host.status(binding.plugin_id).state == "enabled"


def test_turn_id_replay_returns_cached_result_without_reexecution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    original = mock_provider_module._dispatch_mock_turn

    def counted_dispatch(prompt: str, system_prompt: str):
        nonlocal calls
        calls += 1
        return original(prompt, system_prompt)

    monkeypatch.setattr(mock_provider_module, "_dispatch_mock_turn", counted_dispatch)
    host, _, binding = _enabled_binding(tmp_path)
    authority = _authority()
    binding.invoke(
        {"operation": "open", "session_id": "dedupe", "goal": "test"},
        authority=authority,
    )
    payload = {
        "operation": "turn",
        "session_id": "dedupe",
        "prompt": "once",
        "turn_id": "turn-once",
    }
    first = binding.invoke(payload, authority=authority)
    replay = binding.invoke(payload, authority=authority)
    assert calls == 1
    assert first["replayed"] is False
    assert replay["replayed"] is True
    assert first["total_turns"] == replay["total_turns"] == 1
    assert host.status(binding.plugin_id).state == "enabled"


def test_turn_id_cannot_be_rebound_to_different_input(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    authority = _authority()
    binding.invoke(
        {"operation": "open", "session_id": "binding", "goal": "test"},
        authority=authority,
    )
    binding.invoke(
        {
            "operation": "turn",
            "session_id": "binding",
            "prompt": "original",
            "turn_id": "fixed-id",
        },
        authority=authority,
    )
    with pytest.raises(PluginInvocationError, match="different input"):
        binding.invoke(
            {
                "operation": "turn",
                "session_id": "binding",
                "prompt": "changed",
                "turn_id": "fixed-id",
            },
            authority=authority,
        )
    assert host.status(binding.plugin_id).state == "enabled"


def test_plugin_backend_close_cancels_active_provider_session(tmp_path: Path) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    backend = PluginAgentBackend(
        binding,
        authority=_authority(),
        backend_id="mock",
    )
    backend.start_session(SessionConfig(session_id="detach", goal="test"))
    backend.close()
    with pytest.raises(RuntimeError, match="not active"):
        backend.send_turn("after close")
    with pytest.raises(PluginInvocationError, match="not active"):
        binding.invoke(
            {"operation": "status", "session_id": "detach"},
            authority=_authority(),
        )
    host.disable(binding.plugin_id)


def test_attach_accepts_plugin_agent_backend_without_a_parallel_facade(
    tmp_path: Path,
) -> None:
    host, _, binding = _enabled_binding(tmp_path)
    backend = PluginAgentBackend(
        binding,
        authority=_authority("attached-agent"),
        backend_id="mock",
    )
    session = nth.attach(
        "attached-agent",
        backend=backend,
        workspace=tmp_path,
        start_heartbeat=False,
    )
    try:
        assert session.backend is backend
        assert session.backend_id == "mock"
    finally:
        session.detach()
        host.disable(binding.plugin_id)
