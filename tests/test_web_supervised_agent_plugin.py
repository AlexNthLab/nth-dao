"""Receipt binding and lifecycle tests for the Web supervised bridge."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import threading
import time

import pytest
from fastapi.testclient import TestClient

import nth_dao.web.supervised_agent_plugin as supervised_plugin_module

from nth_dao.plugins import (
    AGENT_SESSION_CAPABILITY_ID,
    InvocationAuthority,
    PluginHost,
    PluginHostPolicy,
    PluginInvocationError,
)
from nth_dao.plugins.agent_backend_adapter import PluginAgentBackend
from nth_dao.plugins.builtin import (
    SupervisedAgentOutcomeUnknown,
    SupervisedAgentTarget,
    SupervisedAgentTurnRequest,
    SupervisedAgentTurnResult,
)
from nth_dao.web.supervised_agent_plugin import (
    WebSupervisedAgentInvoker,
    _execution_request_sha256,
    _execution_target_revision,
    _run_coroutine,
    _turn_binding_id,
    disable_supervised_agent_plugins,
    ensure_supervised_agent_plugin,
    retire_supervised_agent_plugin,
)
from team_layer.backends import SessionConfig


def _target(did: str) -> SupervisedAgentTarget:
    return SupervisedAgentTarget(
        agent_id="child",
        agent_did=did,
        backend_id="supervised-a2a",
        execution_target_revision="1" * 64,
    )


def _request() -> SupervisedAgentTurnRequest:
    return SupervisedAgentTurnRequest(
        principal="operator",
        session_id="session",
        turn_id="turn",
        goal="test",
        prompt="hello",
        system_prompt="",
        model="",
        max_output_tokens=16,
        temperature_milli=None,
        timeout_ms=5_000,
    )


def _workspace_app(tmp_path: Path, *, receipts=None):
    return SimpleNamespace(
        state=SimpleNamespace(
            nth=SimpleNamespace(workspace=tmp_path, receipts=receipts),
        )
    )


def test_run_coroutine_times_out_without_running_loop() -> None:
    async def slow() -> None:
        await asyncio.sleep(1.0)

    started = time.monotonic()
    with pytest.raises(TimeoutError):
        _run_coroutine(slow(), timeout_s=0.02)
    assert time.monotonic() - started < 0.5


def test_run_coroutine_times_out_inside_running_loop() -> None:
    async def invoke_sync_bridge() -> None:
        ticks = 0
        running = True

        async def ticker() -> None:
            nonlocal ticks
            while running:
                ticks += 1
                await asyncio.sleep(0.001)

        task = asyncio.create_task(ticker())
        await asyncio.sleep(0)
        with pytest.raises(RuntimeError, match="event-loop thread"):
            _run_coroutine(asyncio.sleep(1.0), timeout_s=0.02)
        await asyncio.sleep(0.01)
        running = False
        await task
        assert ticks > 1

    started = time.monotonic()
    asyncio.run(invoke_sync_bridge())
    assert time.monotonic() - started < 0.5


def test_run_coroutine_hard_boundary_survives_cancel_suppression() -> None:
    release = threading.Event()

    async def stubborn() -> None:
        try:
            await asyncio.sleep(10.0)
        except asyncio.CancelledError:
            while not release.is_set():
                await asyncio.sleep(0.005)

    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError, match="bridge timeout"):
            _run_coroutine(stubborn(), timeout_s=0.02)
        assert time.monotonic() - started < 0.5
    finally:
        release.set()


def test_run_coroutine_rejects_non_finite_timeout() -> None:
    async def immediate() -> None:
        return None

    with pytest.raises(ValueError, match=r"in \(0, 3600\]"):
        _run_coroutine(immediate(), timeout_s=float("nan"))


def _success_envelope(target, request, *, response="world", mutate=None):
    payload = {
        "agent_did": target.agent_did,
        "agent_link_job_id": _turn_binding_id(target, request),
        "elapsed_ms": 4,
        "execution_request_sha256": _execution_request_sha256(target, request),
        "input_tokens": 2,
        "method": "ask",
        "output_tokens": 3,
        "request_sha256": hashlib.sha256(request.prompt.encode()).hexdigest(),
        "requested_model": request.model,
        "response_sha256": hashlib.sha256(response.strip().encode()).hexdigest(),
        "stop_reason": "stop",
    }
    if mutate is not None:
        mutate(payload)
    receipt = {
        "content_hash": "2" * 64,
        "receipt_id": "receipt-1",
        "timeline": [
            {
                "type": "nth.a2a_ask_executed",
                "payload": payload,
            }
        ]
    }
    return {
        "result": {
            "response": response,
            "receipt": receipt,
        }
    }


def test_web_invoker_requires_verified_persisted_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity
    from nth_dao.web import v2_api

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    request = _request()
    record = SimpleNamespace(
        did=did,
        agent_id="child",
        a2a_port=1234,
        alive=True,
    )

    async def fake_drive(*args, **kwargs):
        del args, kwargs
        return 200, _success_envelope(target, request), record, None

    monkeypatch.setattr(v2_api, "_drive_supervised_agent_ask", fake_drive)
    monkeypatch.setattr(v2_api, "_verify_agent_receipt", lambda **kwargs: None)
    invoker = WebSupervisedAgentInvoker(
        _workspace_app(tmp_path),
        SimpleNamespace(list_agents=lambda: [record]),
    )
    with pytest.raises(RuntimeError, match="verified persisted Receipt"):
        invoker.turn(target, request)


def test_web_invoker_redacts_child_error_before_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity
    from nth_dao.web import v2_api

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    request = _request()
    record = SimpleNamespace(
        did=did,
        agent_id="child",
        a2a_port=1234,
        alive=True,
    )
    private_detail = (
        r"C:\sensitive\private-data.txt bearer=TEST_CANARY_DO_NOT_USE"
    )

    async def fake_drive(*args, **kwargs):
        del args, kwargs
        return (
            502,
            {"error": {"code": "backend-failed", "message": private_detail}},
            record,
            None,
        )

    monkeypatch.setattr(v2_api, "_drive_supervised_agent_ask", fake_drive)
    monkeypatch.setattr(v2_api, "_verify_agent_receipt", lambda **kwargs: None)
    invoker = WebSupervisedAgentInvoker(
        _workspace_app(tmp_path),
        SimpleNamespace(list_agents=lambda: [record]),
    )
    result = invoker.turn(target, request)
    assert result.error == "supervised Agent request failed (backend-failed)"
    assert "TEST_CANARY_DO_NOT_USE" not in json.dumps(result.error)


def test_web_invoker_does_not_expose_unrecognized_child_error_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity
    from nth_dao.web import v2_api

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    request = _request()
    record = SimpleNamespace(
        did=did,
        agent_id="child",
        a2a_port=1234,
        alive=True,
    )
    async def fake_drive(*args, **kwargs):
        del args, kwargs
        return (
            502,
            {
                "error": {
                    "code": "customer-token-7f13c9",
                    "message": "private detail",
                }
            },
            record,
            None,
        )

    monkeypatch.setattr(v2_api, "_drive_supervised_agent_ask", fake_drive)
    monkeypatch.setattr(v2_api, "_verify_agent_receipt", lambda **kwargs: None)
    invoker = WebSupervisedAgentInvoker(
        _workspace_app(tmp_path),
        SimpleNamespace(list_agents=lambda: [record]),
    )
    result = invoker.turn(target, request)
    assert result.error == "supervised Agent request failed (upstream-error)"
    assert "customer-token" not in result.error


def test_turn_binding_is_structured_not_delimiter_ambiguous() -> None:
    from nth_dao.identity import AgentIdentity

    target = _target(AgentIdentity.generate().as_did())
    original = _request()
    first = replace(original, principal="alpha\nbeta", session_id="gamma")
    second = replace(original, principal="alpha", session_id="beta\ngamma")
    assert _turn_binding_id(target, first) != _turn_binding_id(target, second)


def test_execution_target_revision_ignores_port_but_binds_execution_scope() -> None:
    from nth_dao.identity import AgentIdentity

    did = AgentIdentity.generate().as_did()

    def record(
        *,
        port: int,
        revision: str,
        kind: str = "codex",
        capabilities: tuple[str, ...] = ("code:review",),
    ):
        return SimpleNamespace(
            agent_id="child",
            did=did,
            kind=kind,
            capabilities=capabilities,
            a2a_port=port,
            work_scope=SimpleNamespace(
                root="X:/reviewed-workspace",
                access="workspace-write",
                revision=revision,
            ),
        )

    original = _execution_target_revision(record(port=1001, revision="a" * 40))
    assert original == _execution_target_revision(
        record(port=2002, revision="a" * 40)
    )
    assert original != _execution_target_revision(
        record(port=1001, revision="b" * 40)
    )
    assert original != _execution_target_revision(
        record(port=1001, revision="a" * 40, kind="hermes")
    )
    assert original != _execution_target_revision(
        record(
            port=1001,
            revision="a" * 40,
            capabilities=("code:review", "filesystem:write"),
        )
    )


def test_durable_turn_refuses_recovery_after_execution_target_revision_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity

    did = AgentIdentity.generate().as_did()
    original_target = _target(did)
    changed_target = replace(
        original_target,
        execution_target_revision="2" * 64,
    )
    request = _request()
    assert _turn_binding_id(original_target, request) == _turn_binding_id(
        changed_target, request
    )
    assert _execution_request_sha256(
        original_target, request
    ) != _execution_request_sha256(changed_target, request)
    invoker = WebSupervisedAgentInvoker(
        _workspace_app(tmp_path),
        SimpleNamespace(list_agents=lambda: []),
    )
    binding_id = _turn_binding_id(original_target, request)
    state_path = invoker._turn_state_path(binding_id)
    assert state_path is not None
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(
            {
                "agent_did": did,
                "binding_id": binding_id,
                "execution_request_sha256": _execution_request_sha256(
                    original_target, request
                ),
                "execution_target_revision": (
                    original_target.execution_target_revision
                ),
                "format": "nth-dao-supervised-turn-state-v3",
                "result": {
                    "content": "",
                    "error": "provider unavailable",
                    "finish_reason": "error",
                    "input_tokens": 0,
                    "latency_ms": 1,
                    "output_tokens": 0,
                    "receipt_content_hash": "",
                    "receipt_id": "",
                    "tool_calls": [],
                },
                "state": "completed",
            }
        ),
        encoding="utf-8",
    )
    called = []
    monkeypatch.setattr(
        WebSupervisedAgentInvoker,
        "_turn_once",
        lambda *args, **kwargs: called.append((args, kwargs)),
    )

    with pytest.raises(RuntimeError, match="execution_request_sha256"):
        invoker.turn(changed_target, request)

    assert called == []


def test_web_invoker_rejects_receipt_rebound_to_another_turn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity
    from nth_dao.web import v2_api

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    request = _request()
    content = _success_envelope(
        target,
        request,
        mutate=lambda payload: payload.update(agent_link_job_id="other-turn"),
    )

    record = SimpleNamespace(
        did=did,
        agent_id="child",
        a2a_port=1234,
        alive=True,
    )

    async def fake_drive(*args, **kwargs):
        del args, kwargs
        return 200, content, record, {
            "nth_receipt_id": "receipt-1",
            "nth_receipt_content_hash": "2" * 64,
        }

    monkeypatch.setattr(v2_api, "_drive_supervised_agent_ask", fake_drive)
    monkeypatch.setattr(v2_api, "_verify_agent_receipt", lambda **kwargs: None)
    invoker = WebSupervisedAgentInvoker(
        _workspace_app(tmp_path),
        SimpleNamespace(list_agents=lambda: [record]),
    )
    with pytest.raises(RuntimeError, match="agent_link_job_id"):
        invoker.turn(target, request)


def test_web_invoker_rejects_receipt_with_different_execution_controls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity
    from nth_dao.web import v2_api

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    request = replace(_request(), model="review-model", max_output_tokens=64)
    content = _success_envelope(
        target,
        request,
        mutate=lambda payload: payload.update(
            execution_request_sha256="0" * 64,
        ),
    )
    record = SimpleNamespace(
        did=did,
        agent_id="child",
        a2a_port=1234,
        alive=True,
    )

    async def fake_drive(*args, **kwargs):
        del args, kwargs
        return 200, content, record, {
            "nth_receipt_id": "receipt-1",
            "nth_receipt_content_hash": "2" * 64,
        }

    monkeypatch.setattr(v2_api, "_drive_supervised_agent_ask", fake_drive)
    monkeypatch.setattr(v2_api, "_verify_agent_receipt", lambda **kwargs: None)
    invoker = WebSupervisedAgentInvoker(
        _workspace_app(tmp_path),
        SimpleNamespace(list_agents=lambda: [record]),
    )
    with pytest.raises(RuntimeError, match="execution_request_sha256"):
        invoker.turn(target, request)


def test_web_invoker_accepts_only_fully_bound_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity
    from nth_dao.web import v2_api

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    request = _request()

    record = SimpleNamespace(
        did=did,
        agent_id="child",
        a2a_port=1234,
        alive=True,
    )

    async def fake_drive(*args, **kwargs):
        del args
        on_dispatch = kwargs.pop("on_dispatch")
        assert kwargs == {
            "expected_agent_id": "child",
            "expected_a2a_port": 1234,
        }
        on_dispatch()
        return (
            200,
            _success_envelope(target, request),
            record,
            {
                "nth_receipt_id": "receipt-1",
                "nth_receipt_content_hash": "2" * 64,
            },
        )

    monkeypatch.setattr(v2_api, "_drive_supervised_agent_ask", fake_drive)
    monkeypatch.setattr(v2_api, "_verify_agent_receipt", lambda **kwargs: None)
    invoker = WebSupervisedAgentInvoker(
        _workspace_app(tmp_path),
        SimpleNamespace(list_agents=lambda: [record]),
    )
    result = invoker.turn(target, request)
    assert result.content == "world"
    assert result.input_tokens == 2
    assert result.output_tokens == 3
    assert result.finish_reason == "stop"
    assert invoker.cancel(target, session_id="session", turn_id="turn") is False


def test_web_invoker_rejects_response_before_persisting_over_budget_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity
    from nth_dao.web import v2_api

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    request = _request()
    response = "x" * (request.max_output_tokens + 1)
    record = SimpleNamespace(
        did=did,
        agent_id="child",
        a2a_port=1234,
        alive=True,
    )
    calls = 0

    async def fake_drive(*args, **kwargs):
        nonlocal calls
        del args
        calls += 1
        kwargs.pop("on_dispatch")()
        return (
            200,
            _success_envelope(target, request, response=response),
            record,
            {
                "nth_receipt_id": "receipt-1",
                "nth_receipt_content_hash": "2" * 64,
            },
        )

    monkeypatch.setattr(v2_api, "_drive_supervised_agent_ask", fake_drive)
    monkeypatch.setattr(v2_api, "_verify_agent_receipt", lambda **kwargs: None)
    invoker = WebSupervisedAgentInvoker(
        _workspace_app(tmp_path),
        SimpleNamespace(list_agents=lambda: [record]),
    )

    with pytest.raises(RuntimeError, match="output budget"):
        invoker.turn(target, request)

    state_path = invoker._turn_state_path(_turn_binding_id(target, request))
    assert state_path is not None
    tombstone_path = invoker._turn_tombstone_path(state_path)
    assert not state_path.exists()
    persisted = tombstone_path.read_text(encoding="utf-8")
    assert response not in persisted
    assert json.loads(persisted)["state"] == "rejected"
    with pytest.raises(RuntimeError, match="response was rejected"):
        invoker.turn(target, request)
    assert calls == 1


def test_durable_error_result_replays_without_second_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity

    did = AgentIdentity.generate().as_did()
    record = SimpleNamespace(
        did=did,
        agent_id="child",
        a2a_port=1234,
        alive=True,
    )
    supervisor = SimpleNamespace(list_agents=lambda: [record])
    app = SimpleNamespace(
        state=SimpleNamespace(
            nth=SimpleNamespace(workspace=tmp_path, receipts=None),
        )
    )
    calls = []

    def fail_once(self, target, request, **kwargs):
        del self, target, request, kwargs
        calls.append("executed")
        return SupervisedAgentTurnResult(
            content="",
            finish_reason="error",
            error="provider unavailable",
        )

    monkeypatch.setattr(WebSupervisedAgentInvoker, "_turn_once", fail_once)
    first = WebSupervisedAgentInvoker(app, supervisor).turn(_target(did), _request())
    replay = WebSupervisedAgentInvoker(app, supervisor).turn(_target(did), _request())
    assert first == replay
    assert calls == ["executed"]


def test_interrupted_durable_turn_refuses_reexecution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity

    did = AgentIdentity.generate().as_did()
    record = SimpleNamespace(
        did=did,
        agent_id="child",
        a2a_port=1234,
        alive=True,
    )
    app = SimpleNamespace(
        state=SimpleNamespace(
            nth=SimpleNamespace(workspace=tmp_path, receipts=None),
        )
    )
    invoker = WebSupervisedAgentInvoker(
        app,
        SimpleNamespace(list_agents=lambda: [record]),
    )
    request = _request()
    binding_id = _turn_binding_id(_target(did), request)
    state_path = invoker._turn_state_path(binding_id)
    assert state_path is not None
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(
            {
                "agent_did": did,
                "binding_id": binding_id,
                "execution_request_sha256": _execution_request_sha256(
                    _target(did), request
                ),
                "format": "nth-dao-supervised-turn-state-v1",
                "state": "started",
            }
        ),
        encoding="utf-8",
    )
    called = []
    monkeypatch.setattr(
        WebSupervisedAgentInvoker,
        "_turn_once",
        lambda *args, **kwargs: called.append((args, kwargs)),
    )
    with pytest.raises(RuntimeError, match="outcome is unknown"):
        invoker.turn(_target(did), request)
    assert called == []


def test_expired_durable_result_is_redacted_and_never_reexecuted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    request = _request()
    invoker = WebSupervisedAgentInvoker(
        SimpleNamespace(
            state=SimpleNamespace(
                nth=SimpleNamespace(workspace=tmp_path, receipts=None),
            )
        ),
        SimpleNamespace(list_agents=lambda: []),
    )
    binding_id = _turn_binding_id(target, request)
    state_path = invoker._turn_state_path(binding_id)
    assert state_path is not None
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(
            {
                "agent_did": did,
                "binding_id": binding_id,
                "created_at_epoch": 1,
                "completed_at_epoch": 2,
                "execution_request_sha256": _execution_request_sha256(
                    target, request
                ),
                "format": "nth-dao-supervised-turn-state-v1",
                "result": {
                    "content": "TOP-SECRET-RESULT",
                    "error": "PRIVATE-UPSTREAM-ERROR",
                    "finish_reason": "error",
                    "input_tokens": 0,
                    "latency_ms": 1,
                    "output_tokens": 0,
                    "receipt_content_hash": "",
                    "receipt_id": "",
                    "tool_calls": [],
                },
                "result_expires_at_epoch": 3,
                "state": "completed",
            }
        ),
        encoding="utf-8",
    )
    called = []
    monkeypatch.setattr(
        WebSupervisedAgentInvoker,
        "_turn_once",
        lambda *args, **kwargs: called.append((args, kwargs)),
    )

    with pytest.raises(RuntimeError, match="retention expired"):
        invoker.turn(target, request)

    tombstone_path = invoker._turn_tombstone_path(state_path)
    assert not state_path.exists()
    persisted = tombstone_path.read_text(encoding="utf-8")
    assert "TOP-SECRET-RESULT" not in persisted
    assert "PRIVATE-UPSTREAM-ERROR" not in persisted
    assert json.loads(persisted)["state"] == "expired"
    assert called == []


def test_missing_v2_retention_metadata_redacts_result_fail_closed(
    tmp_path: Path,
) -> None:
    from nth_dao.identity import AgentIdentity

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    request = _request()
    invoker = WebSupervisedAgentInvoker(
        _workspace_app(tmp_path),
        SimpleNamespace(list_agents=lambda: []),
    )
    binding_id = _turn_binding_id(target, request)
    state_path = invoker._turn_state_path(binding_id)
    assert state_path is not None
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(
            {
                "agent_did": did,
                "binding_id": binding_id,
                "execution_request_sha256": _execution_request_sha256(
                    target, request
                ),
                "format": "nth-dao-supervised-turn-state-v2",
                "result": {
                    "content": "MUST-NOT-SURVIVE",
                    "error": "",
                    "finish_reason": "error",
                    "input_tokens": 0,
                    "latency_ms": 0,
                    "output_tokens": 0,
                    "receipt_content_hash": "",
                    "receipt_id": "",
                    "tool_calls": [],
                },
                "state": "completed",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="retention expired"):
        invoker.turn(target, request)

    tombstone_path = invoker._turn_tombstone_path(state_path)
    assert not state_path.exists()
    persisted = tombstone_path.read_text(encoding="utf-8")
    assert "MUST-NOT-SURVIVE" not in persisted
    assert json.loads(persisted)["state"] == "expired"


def test_legacy_completed_state_gets_bounded_retention_metadata(
    tmp_path: Path,
) -> None:
    from nth_dao.identity import AgentIdentity

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    request = _request()
    invoker = WebSupervisedAgentInvoker(
        _workspace_app(tmp_path),
        SimpleNamespace(list_agents=lambda: []),
    )
    binding_id = _turn_binding_id(target, request)
    state_path = invoker._turn_state_path(binding_id)
    assert state_path is not None
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(
            {
                "agent_did": did,
                "binding_id": binding_id,
                "execution_request_sha256": _execution_request_sha256(
                    target, request
                ),
                "format": "nth-dao-supervised-turn-state-v1",
                "result": {
                    "content": "",
                    "error": "provider unavailable",
                    "finish_reason": "error",
                    "input_tokens": 0,
                    "latency_ms": 1,
                    "output_tokens": 0,
                    "receipt_content_hash": "",
                    "receipt_id": "",
                    "tool_calls": [],
                },
                "state": "completed",
            }
        ),
        encoding="utf-8",
    )

    restored = invoker.turn(target, request)

    assert restored.finish_reason == "error"
    migrated = json.loads(state_path.read_text(encoding="utf-8"))
    assert type(migrated["completed_at_epoch"]) is int
    assert migrated["result_expires_at_epoch"] == (
        migrated["completed_at_epoch"] + 7 * 24 * 60 * 60
    )


def test_durable_turn_store_capacity_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    request = _request()
    invoker = WebSupervisedAgentInvoker(
        SimpleNamespace(
            state=SimpleNamespace(
                nth=SimpleNamespace(workspace=tmp_path, receipts=None),
            )
        ),
        SimpleNamespace(list_agents=lambda: []),
    )
    state_path = invoker._turn_state_path(_turn_binding_id(target, request))
    assert state_path is not None
    state_path.parent.mkdir(parents=True, exist_ok=True)
    (state_path.parent / "existing.json").write_text(
        json.dumps({"state": "prepared"}),
        encoding="utf-8",
    )
    monkeypatch.setattr(supervised_plugin_module, "_MAX_DURABLE_TURN_STATES", 1)
    called = []
    monkeypatch.setattr(
        WebSupervisedAgentInvoker,
        "_turn_once",
        lambda *args, **kwargs: called.append((args, kwargs)),
    )

    with pytest.raises(RuntimeError, match="at capacity"):
        invoker.turn(target, request)
    assert not state_path.exists()
    assert called == []


def test_completed_result_is_evicted_to_tombstone_when_hot_cache_is_full(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    request = _request()
    record = SimpleNamespace(
        did=did,
        agent_id="child",
        a2a_port=1234,
        alive=True,
    )
    invoker = WebSupervisedAgentInvoker(
        _workspace_app(tmp_path),
        SimpleNamespace(list_agents=lambda: [record]),
    )
    state_path = invoker._turn_state_path(_turn_binding_id(target, request))
    assert state_path is not None
    state_path.parent.mkdir(parents=True, exist_ok=True)
    existing = state_path.parent / ("a" * 64 + ".json")
    now = int(time.time())
    existing.write_text(
        json.dumps(
            {
                "agent_did": did,
                "binding_id": "plugin-existing",
                "completed_at_epoch": now,
                "execution_request_sha256": "1" * 64,
                "format": "nth-dao-supervised-turn-state-v2",
                "result": {
                    "content": "cached result",
                    "error": "",
                    "finish_reason": "stop",
                    "input_tokens": 1,
                    "latency_ms": 1,
                    "output_tokens": 1,
                    "receipt_content_hash": "2" * 64,
                    "receipt_id": "receipt-existing",
                    "tool_calls": [],
                },
                "result_expires_at_epoch": now + 7 * 24 * 60 * 60,
                "state": "completed",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(supervised_plugin_module, "_MAX_DURABLE_TURN_STATES", 1)

    def execute(*args, **kwargs):
        del args, kwargs
        return SupervisedAgentTurnResult(
            content="",
            finish_reason="error",
            error="provider unavailable",
        )

    monkeypatch.setattr(WebSupervisedAgentInvoker, "_turn_once", execute)

    assert invoker.turn(target, request).finish_reason == "error"
    tombstone = invoker._turn_tombstone_path(existing)
    assert not existing.exists()
    archived = json.loads(tombstone.read_text(encoding="utf-8"))
    assert archived["state"] == "evicted"
    assert archived["result_sha256"]
    assert "result" not in archived
    assert state_path.exists()


def test_preflight_failure_does_not_poison_durable_turn_retry(
    tmp_path: Path,
) -> None:
    from nth_dao.identity import AgentIdentity

    target = _target(AgentIdentity.generate().as_did())
    request = _request()
    invoker = WebSupervisedAgentInvoker(
        SimpleNamespace(
            state=SimpleNamespace(
                nth=SimpleNamespace(workspace=tmp_path, receipts=None),
            )
        ),
        SimpleNamespace(list_agents=lambda: []),
    )
    state_path = invoker._turn_state_path(_turn_binding_id(target, request))
    assert state_path is not None

    with pytest.raises(RuntimeError, match="no live supervised"):
        invoker.turn(target, request)

    assert not state_path.exists()


def test_missing_workspace_refuses_non_durable_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity

    did = AgentIdentity.generate().as_did()
    called = []
    invoker = WebSupervisedAgentInvoker(
        SimpleNamespace(state=SimpleNamespace()),
        SimpleNamespace(list_agents=lambda: []),
    )
    monkeypatch.setattr(
        WebSupervisedAgentInvoker,
        "_turn_once",
        lambda *args, **kwargs: called.append((args, kwargs)),
    )

    with pytest.raises(RuntimeError, match="durable.*unavailable"):
        invoker.turn(_target(did), _request())

    assert called == []


def test_event_loop_caller_is_rejected_before_state_or_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    request = _request()
    record = SimpleNamespace(
        did=did,
        agent_id="child",
        a2a_port=1234,
        alive=True,
    )
    called = []
    invoker = WebSupervisedAgentInvoker(
        _workspace_app(tmp_path),
        SimpleNamespace(list_agents=lambda: [record]),
    )
    monkeypatch.setattr(
        WebSupervisedAgentInvoker,
        "_turn_once",
        lambda *args, **kwargs: called.append((args, kwargs)),
    )

    async def invoke_on_loop() -> None:
        with pytest.raises(RuntimeError, match="event-loop thread"):
            invoker.probe(target, timeout_ms=100)
        with pytest.raises(RuntimeError, match="event-loop thread"):
            invoker.turn(target, request)

    asyncio.run(invoke_on_loop())

    state_path = invoker._turn_state_path(_turn_binding_id(target, request))
    assert state_path is not None
    assert not state_path.exists()
    assert called == []


def test_bridge_timeout_is_unknown_and_same_turn_only_reconciles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity
    from nth_dao.web import v2_api

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    request = _request()
    record = SimpleNamespace(
        did=did,
        agent_id="child",
        a2a_port=1234,
        alive=True,
    )
    calls = 0

    async def pending_result():
        await asyncio.sleep(0)

    def fake_drive(*args, **kwargs):
        nonlocal calls
        del args
        calls += 1
        kwargs.pop("on_dispatch")()
        return pending_result()

    def time_out(coroutine, *, timeout_s):
        del timeout_s
        coroutine.close()
        raise TimeoutError("bridge timed out")

    monkeypatch.setattr(v2_api, "_drive_supervised_agent_ask", fake_drive)
    monkeypatch.setattr(supervised_plugin_module, "_run_coroutine", time_out)
    invoker = WebSupervisedAgentInvoker(
        _workspace_app(tmp_path),
        SimpleNamespace(list_agents=lambda: [record]),
    )

    for _ in range(2):
        with pytest.raises(SupervisedAgentOutcomeUnknown):
            invoker.turn(target, request)

    state_path = invoker._turn_state_path(_turn_binding_id(target, request))
    assert state_path is not None
    assert json.loads(state_path.read_text(encoding="utf-8"))["state"] == (
        "dispatched"
    )
    assert calls == 1


def test_worker_capacity_failure_stays_prepared_and_can_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity
    from nth_dao.web import v2_api

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    request = _request()
    record = SimpleNamespace(
        did=did,
        agent_id="child",
        a2a_port=1234,
        alive=True,
    )
    dispatches = 0

    async def fake_drive(*args, **kwargs):
        nonlocal dispatches
        del args
        kwargs.pop("on_dispatch")()
        dispatches += 1
        return (
            200,
            _success_envelope(target, request),
            record,
            {
                "nth_receipt_id": "receipt-1",
                "nth_receipt_content_hash": "2" * 64,
            },
        )

    class NoWorkerSlot:
        @staticmethod
        def acquire(*, blocking):
            assert blocking is False
            return False

    monkeypatch.setattr(v2_api, "_drive_supervised_agent_ask", fake_drive)
    monkeypatch.setattr(v2_api, "_verify_agent_receipt", lambda **kwargs: None)
    original_slots = supervised_plugin_module._BRIDGE_WORKER_SLOTS
    monkeypatch.setattr(
        supervised_plugin_module,
        "_BRIDGE_WORKER_SLOTS",
        NoWorkerSlot(),
    )
    invoker = WebSupervisedAgentInvoker(
        _workspace_app(tmp_path),
        SimpleNamespace(list_agents=lambda: [record]),
    )

    with pytest.raises(SupervisedAgentOutcomeUnknown):
        invoker.turn(target, request)

    state_path = invoker._turn_state_path(_turn_binding_id(target, request))
    assert state_path is not None
    assert json.loads(state_path.read_text(encoding="utf-8"))["state"] == (
        "prepared"
    )
    assert dispatches == 0

    monkeypatch.setattr(
        supervised_plugin_module,
        "_BRIDGE_WORKER_SLOTS",
        original_slots,
    )
    assert invoker.turn(target, request).finish_reason == "stop"
    assert dispatches == 1
    assert json.loads(state_path.read_text(encoding="utf-8"))["state"] == (
        "completed"
    )


def test_prepared_turn_is_safe_to_resume_before_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    request = _request()
    record = SimpleNamespace(
        did=did,
        agent_id="child",
        a2a_port=1234,
        alive=True,
    )
    invoker = WebSupervisedAgentInvoker(
        SimpleNamespace(
            state=SimpleNamespace(
                nth=SimpleNamespace(workspace=tmp_path, receipts=None),
            )
        ),
        SimpleNamespace(list_agents=lambda: [record]),
    )
    binding_id = _turn_binding_id(target, request)
    state_path = invoker._turn_state_path(binding_id)
    assert state_path is not None
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(
            {
                "agent_did": did,
                "agent_id": "child",
                "a2a_port": 1234,
                "binding_id": binding_id,
                "created_at_epoch": 1,
                "execution_request_sha256": _execution_request_sha256(
                    target, request
                ),
                "format": "nth-dao-supervised-turn-state-v2",
                "state": "prepared",
            }
        ),
        encoding="utf-8",
    )

    def execute(self, received_target, received_request, **kwargs):
        del self, received_target, received_request
        assert kwargs["expected_record"] is record
        kwargs["on_dispatch"]()
        assert json.loads(state_path.read_text(encoding="utf-8"))["state"] == (
            "dispatched"
        )
        return SupervisedAgentTurnResult(
            content="",
            finish_reason="error",
            error="provider unavailable",
        )

    monkeypatch.setattr(WebSupervisedAgentInvoker, "_turn_once", execute)
    result = invoker.turn(target, request)
    assert result.finish_reason == "error"
    assert json.loads(state_path.read_text(encoding="utf-8"))["state"] == (
        "completed"
    )


def test_dispatched_turn_reconciles_verified_receipt_without_live_agent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity
    from nth_dao.web import v2_api

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    request = _request()
    binding_id = _turn_binding_id(target, request)
    execution_digest = _execution_request_sha256(target, request)
    receipt = _success_envelope(target, request)["result"]["receipt"]

    class Receipts:
        def list_ids(self):
            return ["receipt-1"]

        def load(self, receipt_id):
            assert receipt_id == "receipt-1"
            return receipt

    invoker = WebSupervisedAgentInvoker(
        SimpleNamespace(
            state=SimpleNamespace(
                nth=SimpleNamespace(workspace=tmp_path, receipts=Receipts()),
            )
        ),
        SimpleNamespace(list_agents=lambda: []),
    )
    state_path = invoker._turn_state_path(binding_id)
    assert state_path is not None
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(
            {
                "agent_did": did,
                "agent_id": "child",
                "a2a_port": 1234,
                "binding_id": binding_id,
                "created_at_epoch": 1,
                "dispatched_at_epoch": 2,
                "execution_request_sha256": execution_digest,
                "format": "nth-dao-supervised-turn-state-v2",
                "state": "dispatched",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(v2_api, "_verify_agent_receipt", lambda **kwargs: None)
    called = []
    monkeypatch.setattr(
        WebSupervisedAgentInvoker,
        "_turn_once",
        lambda *args, **kwargs: called.append((args, kwargs)),
    )

    with pytest.raises(RuntimeError, match="verified Receipt"):
        invoker.turn(target, request)

    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    assert persisted["state"] == "receipt-reconciled"
    assert persisted["receipt_id"] == "receipt-1"
    assert called == []


def test_completed_turn_recovers_from_receipt_while_agent_is_offline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity
    from nth_dao.web import v2_api

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    request = _request()
    binding_id = _turn_binding_id(target, request)
    execution_digest = _execution_request_sha256(target, request)
    receipt = _success_envelope(target, request)["result"]["receipt"]
    completed_at = int(time.time())

    class Receipts:
        def load(self, receipt_id):
            assert receipt_id == "receipt-1"
            return receipt

    invoker = WebSupervisedAgentInvoker(
        SimpleNamespace(
            state=SimpleNamespace(
                nth=SimpleNamespace(workspace=tmp_path, receipts=Receipts()),
            )
        ),
        SimpleNamespace(list_agents=lambda: []),
    )
    state_path = invoker._turn_state_path(binding_id)
    assert state_path is not None
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(
            {
                "agent_did": did,
                "agent_id": "child",
                "a2a_port": 1234,
                "binding_id": binding_id,
                "completed_at_epoch": completed_at,
                "created_at_epoch": 1,
                "execution_request_sha256": execution_digest,
                "format": "nth-dao-supervised-turn-state-v2",
                "result": {
                    "content": "world",
                    "error": "",
                    "finish_reason": "stop",
                    "input_tokens": 2,
                    "latency_ms": 4,
                    "output_tokens": 3,
                    "receipt_content_hash": "2" * 64,
                    "receipt_id": "receipt-1",
                    "tool_calls": [],
                },
                "result_expires_at_epoch": completed_at + 7 * 24 * 60 * 60,
                "state": "completed",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(v2_api, "_verify_agent_receipt", lambda **kwargs: None)

    recovered = invoker.turn(target, request)

    assert recovered.content == "world"
    assert recovered.receipt_id == "receipt-1"
    tampered = json.loads(state_path.read_text(encoding="utf-8"))
    tampered["result"]["input_tokens"] = 999
    state_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(RuntimeError, match="input_tokens mismatch"):
        invoker.turn(target, request)


def test_shutdown_helper_only_disables_fixed_did_providers() -> None:
    calls = []
    statuses = (
        SimpleNamespace(
            plugin_id="org.nth-dao.agent.s" + "a" * 24,
            state="enabled",
        ),
        SimpleNamespace(
            plugin_id="org.nth-dao.agent.mock",
            state="enabled",
        ),
        SimpleNamespace(
            plugin_id="org.nth-dao.agent.s" + "b" * 24,
            state="installed",
        ),
    )

    class Host:
        def list_status(self):
            return statuses

        def disable(self, plugin_id):
            calls.append(plugin_id)

    app = SimpleNamespace(
        state=SimpleNamespace(
            nth=SimpleNamespace(
                plugin_host=Host(),
                plugin_lifecycle_lock=None,
            )
        )
    )
    outcomes = disable_supervised_agent_plugins(app)
    assert calls == ["org.nth-dao.agent.s" + "a" * 24]
    assert outcomes == {
        "org.nth-dao.agent.s" + "a" * 24: "disabled",
        "org.nth-dao.agent.s" + "b" * 24: "installed",
    }


def test_existing_fixed_did_plugin_rebinds_when_supervised_endpoint_changes(
    tmp_path: Path,
) -> None:
    from nth_dao.identity import AgentIdentity

    did = AgentIdentity.generate().as_did()
    first_record = SimpleNamespace(
        did=did,
        agent_id="first-child",
        a2a_port=1001,
        alive=True,
    )
    current_records = [first_record]
    supervisor = SimpleNamespace(list_agents=lambda: list(current_records))
    host = PluginHost(
        policy=PluginHostPolicy(
            allowed_permissions=frozenset({"network.client"}),
            max_risk_tier=3,
        ),
        workspace_root=tmp_path,
    )
    app = SimpleNamespace(
        state=SimpleNamespace(
            nth=SimpleNamespace(
                plugin_host=host,
                plugin_lifecycle_lock=threading.RLock(),
            )
        )
    )
    plugin_id = ensure_supervised_agent_plugin(app, supervisor, first_record)
    host.authorize(plugin_id, {"network.client"})
    old_binding = host.enable(plugin_id)[0]
    second_record = SimpleNamespace(
        did=did,
        agent_id="second-child",
        a2a_port=2002,
        alive=True,
    )
    current_records[:] = [second_record]

    assert ensure_supervised_agent_plugin(app, supervisor, second_record) == plugin_id

    status = host.status(plugin_id)
    assert status.state == "enabled"
    new_binding = host.resolve(AGENT_SESSION_CAPABILITY_ID)[0]
    assert new_binding.generation != old_binding.generation
    with pytest.raises(PluginInvocationError, match="stale|uninstalled"):
        old_binding.invoke(
            {"operation": "probe"},
            authority=InvocationAuthority(
                principal="operator",
                capability_ids=frozenset({AGENT_SESSION_CAPABILITY_ID}),
            ),
        )
    assert ensure_supervised_agent_plugin(app, supervisor, second_record) == plugin_id
    assert host.resolve(AGENT_SESSION_CAPABILITY_ID)[0] is new_binding


def test_retire_uninstalls_ephemeral_but_keeps_persistent_provider() -> None:
    calls = []
    status = SimpleNamespace(state="authorized")

    class Host:
        def status(self, plugin_id):
            calls.append(("status", plugin_id))
            return status

        def uninstall(self, plugin_id):
            calls.append(("uninstall", plugin_id))

    app = SimpleNamespace(
        state=SimpleNamespace(
            nth=SimpleNamespace(plugin_host=Host(), plugin_lifecycle_lock=None),
        )
    )
    from nth_dao.identity import AgentIdentity

    did = AgentIdentity.generate().as_did()
    plugin_id, outcome = retire_supervised_agent_plugin(
        app,
        did,
        keep_installed=False,
    )
    assert outcome == "uninstalled"
    assert calls[-1] == ("uninstall", plugin_id)
    calls.clear()
    assert retire_supervised_agent_plugin(
        app,
        did,
        keep_installed=True,
    ) == (plugin_id, "authorized")
    assert all(item[0] != "uninstall" for item in calls)


def test_web_invoker_rejects_persisted_receipt_metadata_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity
    from nth_dao.web import v2_api

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    request = _request()

    record = SimpleNamespace(
        did=did,
        agent_id="child",
        a2a_port=1234,
        alive=True,
    )

    async def fake_drive(*args, **kwargs):
        del args, kwargs
        return (
            200,
            _success_envelope(target, request),
            record,
            {
                "nth_receipt_id": "different-receipt",
            "nth_receipt_content_hash": "3" * 64,
            },
        )

    monkeypatch.setattr(v2_api, "_drive_supervised_agent_ask", fake_drive)
    invoker = WebSupervisedAgentInvoker(
        _workspace_app(tmp_path),
        SimpleNamespace(list_agents=lambda: [record]),
    )
    with pytest.raises(RuntimeError, match="persisted Receipt metadata"):
        invoker.turn(target, request)


def test_web_invoker_rejects_ambiguous_live_target_before_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity
    from nth_dao.web import v2_api

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    records = [
        SimpleNamespace(did=did, agent_id="child", a2a_port=1, alive=True),
        SimpleNamespace(did=did, agent_id="child", a2a_port=2, alive=True),
    ]
    called = False

    async def fake_drive(*args, **kwargs):
        nonlocal called
        del args, kwargs
        called = True
        raise AssertionError("ambiguous target must not dispatch")

    monkeypatch.setattr(v2_api, "_drive_supervised_agent_ask", fake_drive)
    invoker = WebSupervisedAgentInvoker(
        _workspace_app(tmp_path),
        SimpleNamespace(list_agents=lambda: records),
    )
    with pytest.raises(RuntimeError, match="multiple live Agents"):
        invoker.turn(target, _request())
    assert called is False


def test_web_invoker_rejects_same_did_with_wrong_agent_id_before_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.identity import AgentIdentity
    from nth_dao.web import v2_api

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    record = SimpleNamespace(
        did=did,
        agent_id="another-agent",
        a2a_port=1234,
        alive=True,
    )

    async def fake_drive(*args, **kwargs):
        del args, kwargs
        raise AssertionError("wrong Agent ID must not dispatch")

    monkeypatch.setattr(v2_api, "_drive_supervised_agent_ask", fake_drive)
    invoker = WebSupervisedAgentInvoker(
        _workspace_app(tmp_path),
        SimpleNamespace(list_agents=lambda: [record]),
    )
    with pytest.raises(RuntimeError, match="no live supervised"):
        invoker.turn(target, _request())


def test_web_invoker_pins_registration_generation_port(tmp_path: Path) -> None:
    from nth_dao.identity import AgentIdentity

    did = AgentIdentity.generate().as_did()
    target = _target(did)
    record = SimpleNamespace(
        did=did,
        agent_id="child",
        a2a_port=2002,
        alive=True,
    )
    invoker = WebSupervisedAgentInvoker(
        _workspace_app(tmp_path),
        SimpleNamespace(list_agents=lambda: [record]),
        expected_agent_id="child",
        expected_a2a_port=1001,
    )

    with pytest.raises(RuntimeError, match="no live supervised"):
        invoker.turn(target, _request())


@pytest.mark.parametrize("port", [None, True, False, 0, 65_536, "1234"])
def test_supervised_plugin_registration_rejects_invalid_port(port: object) -> None:
    from nth_dao.identity import AgentIdentity

    record = SimpleNamespace(
        did=AgentIdentity.generate().as_did(),
        agent_id="child",
        a2a_port=port,
        alive=True,
    )
    with pytest.raises(ValueError, match="localhost A2A port"):
        ensure_supervised_agent_plugin(
            SimpleNamespace(),
            SimpleNamespace(list_agents=lambda: [record]),
            record,
        )


def test_real_mock_spawn_registers_and_runs_disabled_provider_plugin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("NTH_V2_WORKSPACE_ONLY", "true")
    from nth_dao.web import create_app

    app = create_app(workspace=tmp_path / "workspace", require_console_auth=False)
    with TestClient(app) as client:
        spawned = client.post(
            "/api/v2/agents/spawn",
            json={
                "kind": "mock",
                "label": "plugin-integration",
                "capabilities": ["a2a:message_send"],
                "persist": False,
            },
        )
        assert spawned.status_code == 201, spawned.text
        document = spawned.json()
        plugin_id = document["provider_plugin_id"]
        assert plugin_id
        host = app.state.nth.plugin_host
        assert host.status(plugin_id).state == "installed"
        host.authorize(plugin_id, {"network.client"})
        bindings = host.enable(plugin_id)
        assert len(bindings) == 1
        backend = PluginAgentBackend(
            bindings[0],
            authority=InvocationAuthority(
                principal="integration-operator",
                capability_ids=frozenset({AGENT_SESSION_CAPABILITY_ID}),
            ),
            backend_id="supervised-a2a",
            max_session_tokens=128,
            max_timeout_s=30,
        )
        for _ in range(20):
            if backend.preflight_check(timeout=1).ok:
                break
            time.sleep(0.1)
        else:
            pytest.fail("supervised mock Agent never became A2A-ready")
        backend.start_session(
            SessionConfig(
                session_id="real-bridge",
                goal="test",
                max_tokens=128,
                timeout=30,
            )
        )
        response = backend.send_turn("hello through plugin")
        assert "hello through plugin" in response.content
        assert response.finish_reason == "stop"
        assert response.metadata["receipt_id"]
        assert len(response.metadata["receipt_content_hash"]) == 64
        record = next(
            item
            for item in app.state.v2_supervisor.list_agents()
            if item.did == document["did"]
        )
        recovered = WebSupervisedAgentInvoker(
            app,
            app.state.v2_supervisor,
        ).turn(
            SupervisedAgentTarget(
                agent_id=record.agent_id,
                agent_did=record.did,
                backend_id="supervised-a2a",
                execution_target_revision=_execution_target_revision(record),
            ),
            SupervisedAgentTurnRequest(
                principal="integration-operator",
                session_id="real-bridge",
                turn_id=str(response.metadata["turn_id"]),
                goal="test",
                prompt="hello through plugin",
                system_prompt="",
                model="",
                max_output_tokens=128,
                temperature_milli=None,
                timeout_ms=30_000,
            ),
        )
        assert recovered.content == response.content
        assert backend.end_session().total_turns == 1
        stopped = client.post(f"/api/v2/agents/{document['agent_id']}/stop")
        assert stopped.status_code == 200, stopped.text
        assert stopped.json()["provider_plugin_cleanup"] == "uninstalled"
        with pytest.raises(KeyError):
            host.status(plugin_id)
        with pytest.raises(PluginInvocationError, match="uninstalled"):
            bindings[0].invoke(
                {"operation": "probe"},
                authority=InvocationAuthority(
                    principal="integration-operator",
                    capability_ids=frozenset({AGENT_SESSION_CAPABILITY_ID}),
                ),
            )
