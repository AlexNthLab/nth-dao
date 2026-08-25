"""Adversarial tests for the fixed-target supervised Agent Provider."""

from __future__ import annotations

import ast
from dataclasses import replace
import json
from pathlib import Path
import threading

import pytest

import nth_dao.plugins.builtin.supervised_agent_provider as provider_module
from nth_dao.identity import AgentIdentity
from nth_dao.plugins import (
    AGENT_SESSION_CAPABILITY_ID,
    InvocationAuthority,
    PluginAuthorizationError,
    PluginHost,
    PluginHostPolicy,
    PluginInvocationError,
    PluginLifecycleError,
)
from nth_dao.plugins.agent_backend_adapter import PluginAgentBackend
from nth_dao.plugins.builtin import (
    SUPERVISED_AGENT_SESSION_CONTRACT,
    SupervisedAgentCapabilities,
    SupervisedAgentOutcomeUnknown,
    SupervisedAgentProbe,
    SupervisedAgentTarget,
    SupervisedAgentTurnResult,
    register_supervised_agent_provider,
    supervised_agent_manifest,
    supervised_agent_plugin_id,
)
from team_layer.backends import SessionConfig


def _target(label: str = "supervised") -> SupervisedAgentTarget:
    identity = AgentIdentity.generate(label=label)
    return SupervisedAgentTarget(
        agent_id=label,
        agent_did=identity.as_did(),
        backend_id="test-supervised",
        execution_target_revision="1" * 64,
    )


def _authority(principal: str = "operator") -> InvocationAuthority:
    return InvocationAuthority(
        principal=principal,
        capability_ids=frozenset({AGENT_SESSION_CAPABILITY_ID}),
    )


class FakeInvoker:
    def __init__(self) -> None:
        self.turns = []
        self.cancel_calls = []
        self.cancel_confirmed = True
        self.entered = threading.Event()
        self.release = threading.Event()
        self.block = False
        self.malformed = False
        self.malformed_tools = False
        self.malformed_receipt = False
        self.missing_receipt = False
        self.outcome_unknown = False

    def probe(self, target, *, timeout_ms):
        assert isinstance(target, SupervisedAgentTarget)
        assert timeout_ms > 0
        return SupervisedAgentProbe(
            ready=True,
            capabilities=SupervisedAgentCapabilities(
                supports_multi_turn=True,
                supports_system_prompt=False,
                supports_temperature=True,
                max_context_tokens=100_000,
                notes="Fake supervised target.",
            ),
        )

    def turn(self, target, request):
        self.turns.append((target, request))
        self.entered.set()
        if self.outcome_unknown:
            raise SupervisedAgentOutcomeUnknown("dispatch crossed")
        if self.block:
            assert self.release.wait(2.0)
        if self.malformed:
            return {"content": "not a typed result"}
        if self.malformed_tools:
            return SupervisedAgentTurnResult(
                content="unsafe tool",
                finish_reason="tool_call",
                tool_calls=(None,),  # type: ignore[arg-type]
            )
        return SupervisedAgentTurnResult(
            content=f"supervised: {request.prompt}",
            finish_reason="stop",
            input_tokens=2,
            output_tokens=3,
            latency_ms=1,
            receipt_content_hash=(
                "not-a-hash"
                if self.malformed_receipt
                else ("" if self.missing_receipt else "2" * 64)
            ),
            receipt_id="" if self.missing_receipt else "receipt-test",
        )

    def cancel(self, target, *, session_id, turn_id):
        self.cancel_calls.append((target, session_id, turn_id))
        if self.cancel_confirmed:
            self.release.set()
        return self.cancel_confirmed


def _enabled(tmp_path: Path, target=None, invoker=None):
    chosen_target = target or _target()
    chosen_invoker = invoker or FakeInvoker()
    host = PluginHost(
        policy=PluginHostPolicy(
            allowed_permissions=frozenset({"network.client"}),
            max_risk_tier=3,
        ),
        workspace_root=tmp_path,
    )
    item = register_supervised_agent_provider(
        host,
        chosen_target,
        chosen_invoker,
    )
    host.authorize(item.plugin_id, {"network.client"})
    return host, item, host.enable(item.plugin_id)[0], chosen_invoker


def test_manifest_is_stably_bound_to_one_target_did() -> None:
    first = _target("first")
    second = _target("second")
    first_id = supervised_agent_plugin_id(first.agent_did)
    assert first_id == supervised_agent_plugin_id(first.agent_did)
    assert first_id != supervised_agent_plugin_id(second.agent_did)
    manifest = supervised_agent_manifest(first)
    assert manifest.plugin_id == first_id
    assert manifest.permissions == ("network.client",)
    assert manifest.provides[0].effects == ("network-read", "network-write")
    assert manifest.risk_tier == 3


def test_manifest_digest_binds_additional_production_bridge_sources() -> None:
    target = _target()
    base = supervised_agent_manifest(target)
    production = supervised_agent_manifest(
        target,
        reviewed_artifact_paths=("nth_dao/web/supervised_agent_plugin.py",),
    )
    assert production.artifact_digest != base.artifact_digest
    with pytest.raises(ValueError, match="safe relative"):
        supervised_agent_manifest(
            target,
            reviewed_artifact_paths=("../outside.py",),
        )


def test_provider_is_installed_disabled_and_requires_explicit_network_policy(
    tmp_path: Path,
) -> None:
    target = _target()
    host = PluginHost(policy=PluginHostPolicy(), workspace_root=tmp_path)
    item = register_supervised_agent_provider(host, target, FakeInvoker())
    assert host.status(item.plugin_id).state == "installed"
    assert host.resolve(AGENT_SESSION_CAPABILITY_ID) == ()
    with pytest.raises(PluginAuthorizationError, match="forbids"):
        host.authorize(item.plugin_id, {"network.client"})


def test_plugin_agent_backend_round_trip_uses_fixed_target(tmp_path: Path) -> None:
    target = _target()
    host, item, binding, invoker = _enabled(tmp_path, target=target)
    backend = PluginAgentBackend(
        binding,
        authority=_authority(),
        backend_id=target.backend_id,
    )
    assert backend.preflight_check().ok is True
    backend.start_session(
        SessionConfig(
            session_id="round-trip",
            goal="review",
            max_tokens=128,
            timeout=10,
        )
    )
    result = backend.send_turn("inspect this")
    assert result.content == "supervised: inspect this"
    assert invoker.turns[0][0] == target
    assert invoker.turns[0][1].principal == "operator"
    assert invoker.turns[0][1].goal == "review"
    assert invoker.turns[0][1].temperature_milli is None
    assert result.metadata["receipt_content_hash"] == "2" * 64
    assert result.metadata["receipt_id"] == "receipt-test"
    assert backend.end_session().total_turns == 1
    assert host.disable(item.plugin_id) is True


@pytest.mark.parametrize("mode", ["missing_receipt", "malformed_receipt"])
def test_success_without_valid_verified_receipt_is_downgraded_to_error(
    tmp_path: Path,
    mode: str,
) -> None:
    invoker = FakeInvoker()
    setattr(invoker, mode, True)
    host, _, binding, _ = _enabled(tmp_path, invoker=invoker)
    authority = _authority()
    binding.invoke(
        {
            "operation": "open",
            "session_id": mode,
            "goal": "test",
            "max_tokens": 16,
        },
        authority=authority,
    )

    result = binding.invoke(
        {
            "operation": "turn",
            "session_id": mode,
            "turn_id": "turn-1",
            "prompt": "hello",
        },
        authority=authority,
    )

    assert result["finish_reason"] == "error"
    assert result["receipt_content_hash"] == ""
    assert result["receipt_id"] == ""
    assert host.status(binding.plugin_id).state == "enabled"


def test_unsupported_system_prompt_does_not_reach_invoker(tmp_path: Path) -> None:
    host, _, binding, invoker = _enabled(tmp_path)
    authority = _authority()
    binding.invoke(
        {
            "operation": "open",
            "session_id": "system-prompt",
            "goal": "test",
            "max_tokens": 16,
        },
        authority=authority,
    )
    result = binding.invoke(
        {
            "operation": "turn",
            "session_id": "system-prompt",
            "turn_id": "turn-system",
            "prompt": "hello",
            "system_prompt": "secret policy",
        },
        authority=authority,
    )
    assert result["finish_reason"] == "error"
    assert "does not support" in result["error"]
    assert invoker.turns == []
    assert host.status(binding.plugin_id).state == "enabled"


def test_open_rejects_budget_below_real_backend_minimum(tmp_path: Path) -> None:
    host, _, binding, _ = _enabled(tmp_path)
    with pytest.raises(PluginInvocationError, match="between 16 and"):
        binding.invoke(
            {
                "operation": "open",
                "session_id": "too-small",
                "goal": "test",
                "max_tokens": 15,
            },
            authority=_authority(),
        )
    assert host.status(binding.plugin_id).state == "enabled"


def test_provider_rejects_unsupported_temperature_override(tmp_path: Path) -> None:
    invoker = FakeInvoker()
    original_probe = invoker.probe

    def probe_without_temperature(target, *, timeout_ms):
        result = original_probe(target, timeout_ms=timeout_ms)
        return SupervisedAgentProbe(
            ready=result.ready,
            capabilities=replace(
                result.capabilities,
                supports_temperature=False,
            ),
        )

    invoker.probe = probe_without_temperature
    _host, _item, binding, _ = _enabled(tmp_path, invoker=invoker)
    with pytest.raises(PluginInvocationError, match="temperature control"):
        binding.invoke(
            {
                "operation": "open",
                "session_id": "temperature",
                "goal": "test",
                "temperature_milli": 700,
            },
            authority=_authority(),
        )


def test_provider_rejects_content_over_conservative_output_budget(
    tmp_path: Path,
) -> None:
    invoker = FakeInvoker()

    def oversized_turn(target, request):
        del target, request
        return SupervisedAgentTurnResult(
            content="x" * 17,
            finish_reason="stop",
            output_tokens=1,
        )

    invoker.turn = oversized_turn
    _host, _item, binding, _ = _enabled(tmp_path, invoker=invoker)
    authority = _authority()
    binding.invoke(
        {
            "operation": "open",
            "session_id": "budget",
            "goal": "test",
            "max_tokens": 16,
            "temperature_milli": 700,
        },
        authority=authority,
    )
    result = binding.invoke(
        {
            "operation": "turn",
            "session_id": "budget",
            "turn_id": "too-large",
            "prompt": "execute",
        },
        authority=authority,
    )
    assert result["finish_reason"] == "error"
    assert "over-budget" in result["error"]
    assert result["content"] == ""


def test_provider_redacts_untrusted_probe_and_turn_errors(tmp_path: Path) -> None:
    invoker = FakeInvoker()
    private_detail = (
        r"C:\sensitive\private-data.txt bearer=TEST_CANARY_DO_NOT_USE"
    )

    def unavailable_probe(target, *, timeout_ms):
        del target, timeout_ms
        return SupervisedAgentProbe(
            ready=False,
            capabilities=SupervisedAgentCapabilities(),
            detail=private_detail,
        )

    invoker.probe = unavailable_probe
    _host, _item, binding, _ = _enabled(tmp_path, invoker=invoker)
    probe = binding.invoke(
        {"operation": "probe", "timeout_ms": 100},
        authority=_authority(),
    )
    assert probe["detail"] == "supervised target reported unavailable"
    assert "TEST_CANARY_DO_NOT_USE" not in json.dumps(probe)

    invoker.probe = lambda target, *, timeout_ms: SupervisedAgentProbe(
        ready=True,
        capabilities=SupervisedAgentCapabilities(supports_multi_turn=True),
        detail=private_detail,
    )
    invoker.turn = lambda target, request: SupervisedAgentTurnResult(
        content="",
        finish_reason="error",
        error=private_detail,
    )
    binding.invoke(
        {"operation": "open", "session_id": "redacted", "goal": "test"},
        authority=_authority(),
    )
    turn = binding.invoke(
        {
            "operation": "turn",
            "session_id": "redacted",
            "turn_id": "turn-redacted",
            "prompt": "execute",
        },
        authority=_authority(),
    )
    assert turn["error"] == "supervised agent execution failed"
    assert "TEST_CANARY_DO_NOT_USE" not in json.dumps(turn)


def test_turn_replay_is_at_most_once_and_cannot_be_rebound(tmp_path: Path) -> None:
    host, _, binding, invoker = _enabled(tmp_path)
    authority = _authority()
    binding.invoke(
        {
            "operation": "open",
            "session_id": "replay",
            "goal": "test",
            "max_tokens": 128,
        },
        authority=authority,
    )
    payload = {
        "operation": "turn",
        "session_id": "replay",
        "turn_id": "turn-1",
        "prompt": "once",
    }
    first = binding.invoke(payload, authority=authority)
    replay = binding.invoke(payload, authority=authority)
    assert first["replayed"] is False
    assert replay["replayed"] is True
    assert len(invoker.turns) == 1
    with pytest.raises(PluginInvocationError, match="different input"):
        binding.invoke(
            {**payload, "prompt": "changed"},
            authority=authority,
        )
    assert host.status(binding.plugin_id).state == "enabled"


def test_unknown_outcome_is_not_cached_and_same_turn_can_reconcile(
    tmp_path: Path,
) -> None:
    invoker = FakeInvoker()
    invoker.outcome_unknown = True
    host, _, binding, _ = _enabled(tmp_path, invoker=invoker)
    authority = _authority()
    binding.invoke(
        {"operation": "open", "session_id": "unknown", "goal": "test"},
        authority=authority,
    )
    payload = {
        "operation": "turn",
        "session_id": "unknown",
        "turn_id": "same-turn",
        "prompt": "execute once",
    }

    for _ in range(2):
        with pytest.raises(PluginInvocationError, match="outcome is unknown"):
            binding.invoke(payload, authority=authority)

    assert len(invoker.turns) == 2
    status = binding.invoke(
        {"operation": "status", "session_id": "unknown"},
        authority=authority,
    )
    assert status["total_turns"] == 0
    assert host.status(binding.plugin_id).state == "enabled"


def test_single_turn_target_allows_replay_but_rejects_second_turn(
    tmp_path: Path,
) -> None:
    invoker = FakeInvoker()
    original_probe = invoker.probe

    def single_turn_probe(target, *, timeout_ms):
        result = original_probe(target, timeout_ms=timeout_ms)
        return SupervisedAgentProbe(
            ready=result.ready,
            capabilities=replace(
                result.capabilities,
                supports_multi_turn=False,
            ),
        )

    invoker.probe = single_turn_probe
    _host, _item, binding, _ = _enabled(tmp_path, invoker=invoker)
    authority = _authority()
    binding.invoke(
        {
            "operation": "open",
            "session_id": "single-turn",
            "goal": "test",
            "max_tokens": 128,
        },
        authority=authority,
    )
    first_payload = {
        "operation": "turn",
        "session_id": "single-turn",
        "turn_id": "first",
        "prompt": "once",
    }
    binding.invoke(first_payload, authority=authority)
    assert binding.invoke(first_payload, authority=authority)["replayed"] is True
    with pytest.raises(PluginInvocationError, match="multiple turns"):
        binding.invoke(
            {
                "operation": "turn",
                "session_id": "single-turn",
                "turn_id": "second",
                "prompt": "again",
            },
            authority=authority,
        )
    assert len(invoker.turns) == 1


def test_session_ownership_is_scoped_to_invocation_principal(tmp_path: Path) -> None:
    host, _, binding, _ = _enabled(tmp_path)
    binding.invoke(
        {"operation": "open", "session_id": "private", "goal": "test"},
        authority=_authority("alice"),
    )
    with pytest.raises(PluginInvocationError, match="not active for this principal"):
        binding.invoke(
            {"operation": "status", "session_id": "private"},
            authority=_authority("bob"),
        )
    assert host.status(binding.plugin_id).state == "enabled"


def test_malformed_invoker_result_is_cached_as_error_not_reexecuted(
    tmp_path: Path,
) -> None:
    invoker = FakeInvoker()
    invoker.malformed = True
    host, _, binding, _ = _enabled(tmp_path, invoker=invoker)
    authority = _authority()
    binding.invoke(
        {"operation": "open", "session_id": "malformed", "goal": "test"},
        authority=authority,
    )
    payload = {
        "operation": "turn",
        "session_id": "malformed",
        "turn_id": "typed-only",
        "prompt": "execute",
    }
    first = binding.invoke(payload, authority=authority)
    replay = binding.invoke(payload, authority=authority)
    assert first["finish_reason"] == "error"
    assert "invalid turn result" in first["error"]
    assert replay["replayed"] is True
    assert len(invoker.turns) == 1
    assert host.status(binding.plugin_id).state == "enabled"


def test_malformed_tool_call_is_cached_without_reexecution(tmp_path: Path) -> None:
    invoker = FakeInvoker()
    invoker.malformed_tools = True
    host, _, binding, _ = _enabled(tmp_path, invoker=invoker)
    authority = _authority()
    binding.invoke(
        {"operation": "open", "session_id": "bad-tool", "goal": "test"},
        authority=authority,
    )
    payload = {
        "operation": "turn",
        "session_id": "bad-tool",
        "turn_id": "tool-once",
        "prompt": "execute",
    }
    first = binding.invoke(payload, authority=authority)
    replay = binding.invoke(payload, authority=authority)
    assert first["finish_reason"] == "error"
    assert "tool-call metadata" in first["error"]
    assert replay["replayed"] is True
    assert len(invoker.turns) == 1
    assert host.status(binding.plugin_id).state == "enabled"


def test_inflight_cancel_fails_closed_until_invoker_confirms(tmp_path: Path) -> None:
    invoker = FakeInvoker()
    invoker.block = True
    invoker.cancel_confirmed = False
    host, _, binding, _ = _enabled(tmp_path, invoker=invoker)
    authority = _authority()
    binding.invoke(
        {"operation": "open", "session_id": "cancel", "goal": "test"},
        authority=authority,
    )
    turn_errors = []

    def run_turn() -> None:
        try:
            binding.invoke(
                {
                    "operation": "turn",
                    "session_id": "cancel",
                    "turn_id": "inflight",
                    "prompt": "block",
                },
                authority=authority,
            )
        except PluginInvocationError as exc:
            turn_errors.append(str(exc))

    thread = threading.Thread(target=run_turn)
    thread.start()
    assert invoker.entered.wait(1.0)
    with pytest.raises(PluginInvocationError, match="did not confirm"):
        binding.invoke(
            {"operation": "cancel", "session_id": "cancel"},
            authority=authority,
        )
    assert binding.invoke(
        {"operation": "status", "session_id": "cancel"},
        authority=authority,
    )["state"] == "active"
    invoker.cancel_confirmed = True
    cancelled = binding.invoke(
        {"operation": "cancel", "session_id": "cancel"},
        authority=authority,
    )
    assert cancelled["state"] == "cancelled"
    thread.join(1.0)
    assert not thread.is_alive()
    assert turn_errors == ["supervised agent session was cancelled during turn"]
    assert len(invoker.cancel_calls) == 2


def test_cancel_cannot_race_a_new_turn_past_remote_confirmation(
    tmp_path: Path,
) -> None:
    from collections import defaultdict

    host, item, binding, invoker = _enabled(tmp_path)
    authority = _authority()
    binding.invoke(
        {"operation": "open", "session_id": "cancel-race", "goal": "test"},
        authority=authority,
    )
    provider = host._records[item.plugin_id].runtime._provider
    assert provider is not None

    class GateLock:
        def __init__(self) -> None:
            self._lock = threading.RLock()
            self._counts: defaultdict[str, int] = defaultdict(int)
            self.cancel_second = threading.Event()
            self.allow_cancel_second = threading.Event()

        def __enter__(self):
            name = threading.current_thread().name
            self._counts[name] += 1
            if name == "cancel-thread" and self._counts[name] == 2:
                self.cancel_second.set()
                assert self.allow_cancel_second.wait(2.0)
            self._lock.acquire()
            return self

        def __exit__(self, *args):
            del args
            self._lock.release()

    gate = GateLock()
    provider._lock = gate
    results = {}

    def cancel() -> None:
        results["cancel"] = binding.invoke(
            {"operation": "cancel", "session_id": "cancel-race"},
            authority=authority,
        )

    def turn() -> None:
        try:
            results["turn"] = binding.invoke(
                {
                    "operation": "turn",
                    "session_id": "cancel-race",
                    "turn_id": "turn-race",
                    "prompt": "must not dispatch",
                },
                authority=authority,
            )
        except Exception as exc:  # noqa: BLE001 - captured for race assertion
            results["turn_error"] = str(exc)

    cancel_thread = threading.Thread(target=cancel, name="cancel-thread")
    cancel_thread.start()
    assert gate.cancel_second.wait(1.0)
    turn_thread = threading.Thread(target=turn, name="turn-thread")
    turn_thread.start()
    turn_thread.join(1.0)
    assert not turn_thread.is_alive()
    assert "no longer active" in results["turn_error"]
    assert invoker.turns == []
    gate.allow_cancel_second.set()
    cancel_thread.join(1.0)
    assert not cancel_thread.is_alive()
    assert results["cancel"]["state"] == "cancelled"
    assert invoker.cancel_calls == []
    assert host.status(binding.plugin_id).state == "enabled"


def test_failed_disable_retains_provider_for_cleanup_retry(tmp_path: Path) -> None:
    invoker = FakeInvoker()
    invoker.block = True
    invoker.cancel_confirmed = False
    target = _target()
    host = PluginHost(
        policy=PluginHostPolicy(
            allowed_permissions=frozenset({"network.client"}),
            max_risk_tier=3,
        ),
        workspace_root=tmp_path,
        lifecycle_timeout_s=1.0,
    )
    item = register_supervised_agent_provider(host, target, invoker)
    host.authorize(item.plugin_id, {"network.client"})
    binding = host.enable(item.plugin_id)[0]
    authority = _authority()
    binding.invoke(
        {"operation": "open", "session_id": "cleanup", "goal": "test"},
        authority=authority,
    )
    turn_results = []

    def run_turn() -> None:
        turn_results.append(
            binding.invoke(
                {
                    "operation": "turn",
                    "session_id": "cleanup",
                    "turn_id": "cleanup-turn",
                    "prompt": "block",
                },
                authority=authority,
            )
        )

    thread = threading.Thread(target=run_turn)
    thread.start()
    assert invoker.entered.wait(1.0)
    with pytest.raises(PluginLifecycleError, match="cleanup failed"):
        host.disable(item.plugin_id)
    assert host.status(item.plugin_id).state == "cleanup-failed"
    invoker.release.set()
    thread.join(1.0)
    assert not thread.is_alive()
    assert turn_results[0]["finish_reason"] == "stop"
    assert host.disable(item.plugin_id) is True
    assert host.status(item.plugin_id).state == "authorized"


def test_provider_source_does_not_import_legacy_backend_package() -> None:
    source = Path(provider_module.__file__).read_text(encoding="utf-8")
    imports = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
    assert all(not name.startswith("team_layer") for name in imports)


def test_supervised_agent_conformance_vector_matches_runtime() -> None:
    vector_path = (
        Path(provider_module.__file__).parents[1]
        / "vectors"
        / "supervised-agent-session-capability-v2.json"
    )
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    assert vector["format"] == "nth-dao-plugin-capability-conformance-v1"
    assert vector["schema_version"] == 2
    assert vector["capability"] == SUPERVISED_AGENT_SESSION_CONTRACT.to_dict()
    assert vector["expected_digest"] == SUPERVISED_AGENT_SESSION_CONTRACT.digest
    assert vector["capability"]["retention"] == "durable"
    binding = vector["target_binding"]
    assert supervised_agent_plugin_id(binding["agent_did"]) == binding["plugin_id"]
    assert binding["caller_selectable"] is False
    assert vector["permissions"] == ["network.client"]
    assert vector["runtime_requirements"][
        "receipt_must_be_verified_and_persisted_before_success"
    ] is True
