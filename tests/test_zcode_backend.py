"""Fail-closed supervision contract for the local ZCode backend."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from nth_dao.web import dummy_agent


def test_zcode_is_registered_and_never_resolves_to_hermes() -> None:
    assert "zcode" in dummy_agent.KNOWN_BACKEND_KINDS
    backend = dummy_agent._resolve_ask_backend("zcode")
    assert isinstance(backend, dummy_agent._ZCodeCliAskBackend)
    assert not isinstance(backend, dummy_agent._HermesAskBackend)


def test_zcode_requires_its_own_unattended_credential(monkeypatch) -> None:
    monkeypatch.delenv("NTH_ZCODE_API_KEY", raising=False)
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_credential_profile_present",
        staticmethod(lambda: False),
    )

    with pytest.raises(RuntimeError, match="Hermes fallback is disabled"):
        dummy_agent._ZCodeCliAskBackend().ask({"prompt": "inspect"}, 30.0)


def _write_desktop_provider(
    home: Path,
    *,
    api_key: str = "desktop-coding-plan-key",
    enabled: bool = True,
    base_url: str = "https://open.bigmodel.cn/api/anthropic",
    model: str = "GLM-5.3-Flash",
) -> Path:
    path = home / ".zcode" / "v2" / "config.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({
        "provider": {
            "builtin:bigmodel-coding-plan": {
                "name": "BigModel - Coding Plan",
                "kind": "anthropic",
                "enabled": enabled,
                "source": "custom",
                "options": {"apiKey": api_key, "baseURL": base_url},
                "models": {model: {"reasoning": {"enabled": True}}},
            },
        },
    }), encoding="utf-8")
    return path


def _write_model_attestation(
    root: Path,
    *,
    session_id: str = "sess_test_12345678",
    provider_id: str = "bigmodel",
    model_id: str = "glm-5.3-flash",
    calls: int = 1,
) -> Path:
    path = root / f"model-io-{session_id}.jsonl"
    root.mkdir(parents=True, exist_ok=True)
    rows = [
        {
            "sessionId": session_id,
            "model": {
                "providerId": provider_id,
                "modelId": model_id,
                "source": "config",
            },
        }
        for _ in range(calls)
    ]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return path


def test_zcode_accepts_exact_desktop_coding_plan_profile(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.delenv("NTH_ZCODE_API_KEY", raising=False)
    monkeypatch.delenv("NTH_ZCODE_DESKTOP_CONFIG", raising=False)
    monkeypatch.setattr(dummy_agent.Path, "home", staticmethod(lambda: tmp_path))
    _write_desktop_provider(tmp_path)

    backend = dummy_agent._ZCodeCliAskBackend

    assert backend._credential_profile_present() is True
    env = backend._subprocess_env()
    assert env["ANTHROPIC_API_KEY"] == "desktop-coding-plan-key"
    assert env["ZCODE_MODEL"] == "bigmodel/glm-5.3-flash"


@pytest.mark.parametrize(
    ("overrides"),
    [
        {"enabled": False},
        {"base_url": "https://api.z.ai/api/anthropic"},
        {"model": "GLM-5.3"},
        {"api_key": "   "},
    ],
)
def test_zcode_rejects_wrong_desktop_provider_profile(
    tmp_path: Path, monkeypatch, overrides: dict[str, object],
) -> None:
    monkeypatch.delenv("NTH_ZCODE_API_KEY", raising=False)
    monkeypatch.delenv("NTH_ZCODE_DESKTOP_CONFIG", raising=False)
    monkeypatch.setattr(dummy_agent.Path, "home", staticmethod(lambda: tmp_path))
    _write_desktop_provider(tmp_path, **overrides)

    assert dummy_agent._ZCodeCliAskBackend._credential_profile_present() is False
    assert "ANTHROPIC_API_KEY" not in dummy_agent._ZCodeCliAskBackend._subprocess_env()


def test_zcode_does_not_accept_unrelated_cli_profile(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.delenv("NTH_ZCODE_API_KEY", raising=False)
    monkeypatch.setattr(dummy_agent.Path, "home", staticmethod(lambda: tmp_path))
    cli_config = tmp_path / ".zcode" / "cli" / "config.json"
    cli_config.parent.mkdir(parents=True)
    cli_config.write_text(
        json.dumps({"model": {"main": "zai/glm-5.1"}}),
        encoding="utf-8",
    )

    assert dummy_agent._ZCodeCliAskBackend._credential_profile_present() is False


def test_zcode_rejects_empty_desktop_model_definition(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.delenv("NTH_ZCODE_API_KEY", raising=False)
    monkeypatch.setattr(dummy_agent.Path, "home", staticmethod(lambda: tmp_path))
    path = _write_desktop_provider(tmp_path)
    config = json.loads(path.read_text(encoding="utf-8"))
    config["provider"]["builtin:bigmodel-coding-plan"]["models"][
        "GLM-5.3-Flash"
    ] = None
    path.write_text(json.dumps(config), encoding="utf-8")

    assert dummy_agent._ZCodeCliAskBackend._credential_profile_present() is False


def test_zcode_explicit_key_precedes_desktop_profile(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setattr(dummy_agent.Path, "home", staticmethod(lambda: tmp_path))
    _write_desktop_provider(tmp_path, api_key="desktop-key")
    monkeypatch.setenv("NTH_ZCODE_API_KEY", "operator-key")

    env = dummy_agent._ZCodeCliAskBackend._subprocess_env()

    assert env["ANTHROPIC_API_KEY"] == "operator-key"


@pytest.mark.parametrize("field", ["api_key", "token", "credential", "base_url"])
def test_zcode_rejects_request_supplied_secrets(field: str) -> None:
    with pytest.raises(ValueError, match="cannot carry"):
        dummy_agent._ZCodeCliAskBackend().ask(
            {"prompt": "inspect", field: "secret"}, 30.0,
        )


def test_zcode_rejects_model_override() -> None:
    with pytest.raises(ValueError, match="pinned"):
        dummy_agent._ZCodeCliAskBackend().ask(
            {"prompt": "inspect", "model": "other/model"}, 30.0,
        )


def test_zcode_uses_fixed_model_safe_mode_and_workdir(
    tmp_path: Path, monkeypatch,
) -> None:
    captured: dict = {}

    class Result:
        returncode = 0
        stderr = ""
        stdout = json.dumps({"response": "checked", "sessionId": "sess_test_12345678"})

    def fake_run(argv, **kwargs):
        captured["argv"] = list(argv)
        captured["kwargs"] = kwargs
        prompt_path = Path(argv[argv.index("--attach") + 1])
        captured["prompt_path"] = prompt_path
        captured["attached_prompt"] = prompt_path.read_text(encoding="utf-8")
        return Result()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NTH_ZCODE_API_KEY", "not-logged")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "must-not-leak")
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-leak")
    monkeypatch.setenv("NTH_AGENT_WORK_ACCESS", "workspace-write")
    rollout_dir = tmp_path / "rollout"
    monkeypatch.setenv("NTH_ZCODE_ROLLOUT_DIR", str(rollout_dir))
    rollout_path = _write_model_attestation(rollout_dir, calls=2)
    rollout_bytes = rollout_path.read_bytes()
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_resolve_launcher",
        classmethod(lambda cls: ["node", "zcode.cjs"]),
    )
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_cli_contract_preflight",
        classmethod(lambda cls, launcher: (True, "", "zcode 0.16.5")),
    )
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_run_cli",
        classmethod(lambda cls, argv, **kwargs: fake_run(argv, **kwargs)),
    )

    result = dummy_agent._ZCodeCliAskBackend().ask(
        {"prompt": "inspect only"}, 42.0,
    )

    argv = captured["argv"]
    env = captured["kwargs"]["env"]
    execution = result.pop("execution")
    assert result == {
        "response": "checked",
        "backend": "zcode",
        "model": "bigmodel/glm-5.3-flash",
        "model_attestation": {
            "session_id": "sess_test_12345678",
            "provider_ids": ["bigmodel"],
            "model_ids": ["glm-5.3-flash"],
            "sources": ["config"],
            "call_count": 2,
            "rollout_sha256": hashlib.sha256(rollout_bytes).hexdigest(),
            "rollout_size_bytes": len(rollout_bytes),
        },
        "exit_code": 0,
    }
    assert execution["call_id"].startswith("zcall_")
    assert execution["task_id"] == execution["call_id"]
    assert execution["timeout_s"] == 42.0
    assert execution["completed_at_ms"] >= execution["started_at_ms"]
    assert execution["duration_ms"] >= 0
    assert argv[argv.index("--mode") + 1] == "edit"
    assert argv[argv.index("--cwd") + 1] == str(tmp_path.resolve())
    assert "--disallowed-tools" in argv
    denied = argv[argv.index("--disallowed-tools") + 1]
    assert "Agent" in denied
    assert "Bash(git push *)" in denied
    assert "Bash(git reset *)" in denied
    assert "yolo" not in argv
    assert "hermes" not in " ".join(argv).lower()
    assert "inspect only" not in argv
    assert captured["attached_prompt"] == "inspect only"
    assert captured["prompt_path"].parent != tmp_path.resolve()
    assert not Path(argv[argv.index("--attach") + 1]).exists()
    assert env["ZCODE_MODEL"] == "bigmodel/glm-5.3-flash"
    assert env["ZCODE_BASE_URL"] == "https://open.bigmodel.cn/api/anthropic"
    assert env["ANTHROPIC_API_KEY"] == "not-logged"
    assert env["ZCODE_TOOL_ENV_PASSTHROUGH_JSON"] == "{}"
    assert "NTH_ZCODE_API_KEY" not in env
    assert "OPENAI_API_KEY" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert captured["kwargs"]["timeout"] == 42.0


def test_zcode_mandatory_denials_cannot_be_cleared(tmp_path: Path, monkeypatch) -> None:
    captured: list[str] = []

    class Result:
        returncode = 0
        stderr = ""
        stdout = '{"response":"ok","sessionId":"sess_test_12345678"}'

    def fake_run(argv, **_kwargs):
        captured.extend(argv)
        return Result()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NTH_ZCODE_API_KEY", "configured")
    monkeypatch.setenv("NTH_ZCODE_EXTRA_DENIED_TOOLS", "")
    rollout_dir = tmp_path / "rollout"
    monkeypatch.setenv("NTH_ZCODE_ROLLOUT_DIR", str(rollout_dir))
    _write_model_attestation(rollout_dir)
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_resolve_launcher",
        classmethod(lambda cls: ["zcode"]),
    )
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_cli_contract_preflight",
        classmethod(lambda cls, launcher: (True, "", "zcode 0.16.5")),
    )
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_run_cli",
        classmethod(lambda cls, argv, **kwargs: fake_run(argv, **kwargs)),
    )

    dummy_agent._ZCodeCliAskBackend().ask({"prompt": "audit"}, 30.0)

    denied = captured[captured.index("--disallowed-tools") + 1]
    assert all(
        item in denied for item in dummy_agent._ZCodeCliAskBackend.MANDATORY_DENIED_TOOLS
    )


def test_zcode_read_only_scope_uses_plan_mode(tmp_path: Path, monkeypatch) -> None:
    captured: list[str] = []

    class Result:
        returncode = 0
        stderr = ""
        stdout = '{"result":"read-only report","sessionId":"sess_test_12345678"}'

    def fake_run(argv, **_kwargs):
        captured.extend(argv)
        return Result()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NTH_ZCODE_API_KEY", "configured")
    monkeypatch.setenv("NTH_AGENT_WORK_ACCESS", "read-only")
    rollout_dir = tmp_path / "rollout"
    monkeypatch.setenv("NTH_ZCODE_ROLLOUT_DIR", str(rollout_dir))
    _write_model_attestation(rollout_dir)
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_resolve_launcher",
        classmethod(lambda cls: ["zcode"]),
    )
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_cli_contract_preflight",
        classmethod(lambda cls, launcher: (True, "", "zcode 0.16.5")),
    )
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_run_cli",
        classmethod(lambda cls, argv, **kwargs: fake_run(argv, **kwargs)),
    )

    result = dummy_agent._ZCodeCliAskBackend().ask({"prompt": "audit"}, 30.0)

    assert captured[captured.index("--mode") + 1] == "plan"
    assert result["response"] == "read-only report"


def test_zcode_rejects_a_second_concurrent_cli_call(
    tmp_path: Path, monkeypatch,
) -> None:
    """One supervised ZCode agent owns at most one CLI process at a time."""
    started = threading.Event()
    release = threading.Event()
    calls = 0
    errors: list[BaseException] = []

    class Result:
        returncode = 0
        stderr = ""
        stdout = '{"response":"checked","sessionId":"sess_test_12345678"}'

    def fake_run(_argv, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            started.set()
            assert release.wait(2.0)
        return Result()

    monkeypatch.setenv("NTH_ZCODE_API_KEY", "configured")
    rollout_dir = tmp_path / "rollout"
    monkeypatch.setenv("NTH_ZCODE_ROLLOUT_DIR", str(rollout_dir))
    _write_model_attestation(rollout_dir)
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_resolve_launcher",
        classmethod(lambda cls: ["zcode"]),
    )
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_cli_contract_preflight",
        classmethod(lambda cls, launcher: (True, "", "zcode 0.16.5")),
    )
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_run_cli",
        classmethod(lambda cls, argv, **kwargs: fake_run(argv, **kwargs)),
    )
    backend = dummy_agent._ZCodeCliAskBackend(
        workdir=tmp_path,
        work_access="read-only",
    )

    def first_call() -> None:
        try:
            backend.ask({"prompt": "first"}, 30.0)
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    thread = threading.Thread(target=first_call)
    thread.start()
    assert started.wait(1.0)
    try:
        with pytest.raises(dummy_agent.BackendBusyError, match="already executing"):
            backend.ask({"prompt": "second"}, 30.0)
    finally:
        release.set()
        thread.join(3.0)

    assert thread.is_alive() is False
    assert errors == []
    assert calls == 1


def test_zcode_releases_single_flight_lock_after_failure(monkeypatch) -> None:
    backend = dummy_agent._ZCodeCliAskBackend()
    calls = 0

    def fake_once(_params, _timeout_s):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TimeoutError("simulated timeout")
        return {"response": "recovered", "backend": "zcode"}

    monkeypatch.setattr(backend, "_ask_once", fake_once)

    with pytest.raises(TimeoutError, match="simulated timeout"):
        backend.ask({"prompt": "first"}, 30.0)
    assert backend.ask({"prompt": "retry"}, 30.0)["response"] == "recovered"


def test_zcode_activity_initialization_failure_does_not_poison_state_or_lock(
    monkeypatch,
) -> None:
    backend = dummy_agent._ZCodeCliAskBackend()
    original_start = backend._start_activity
    attempts = 0

    def flaky_start(params, timeout_s):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("activity store unavailable")
        return original_start(params, timeout_s)

    monkeypatch.setattr(backend, "_start_activity", flaky_start)
    monkeypatch.setattr(
        backend,
        "_ask_once",
        lambda _params, _timeout_s: {"response": "recovered", "backend": "zcode"},
    )

    with pytest.raises(RuntimeError, match="activity store unavailable"):
        backend.ask({"prompt": "first"}, 30.0)
    assert backend.activity_snapshot() == {"active": False, "phase": "idle"}
    assert backend.ask({"prompt": "retry"}, 30.0)["response"] == "recovered"


def test_zcode_reports_bounded_activity_and_execution_metadata(monkeypatch) -> None:
    backend = dummy_agent._ZCodeCliAskBackend()
    during: dict = {}
    job_id = "1" * 32

    def fake_once(_params, _timeout_s):
        during.update(backend.activity_snapshot())
        return {"response": "checked", "backend": "zcode"}

    monkeypatch.setattr(backend, "_ask_once", fake_once)
    result = backend.ask(
        {"prompt": "private prompt", "agent_link_job_id": job_id},
        42.0,
    )

    assert during["active"] is True
    assert during["phase"] == "starting"
    assert during["task_id"] == job_id
    assert "prompt" not in repr(during).lower()
    final = backend.activity_snapshot()
    assert final["active"] is False
    assert final["phase"] == "succeeded"
    assert final["task_id"] == job_id
    assert result["execution"]["call_id"] == final["call_id"]
    assert result["execution"]["task_id"] == job_id
    assert result["execution"]["duration_ms"] >= 0


def test_zcode_activity_retains_safe_timeout_diagnostic(monkeypatch) -> None:
    backend = dummy_agent._ZCodeCliAskBackend()
    monkeypatch.setattr(
        backend,
        "_ask_once",
        lambda _params, _timeout_s: (_ for _ in ()).throw(TimeoutError("secret detail")),
    )

    with pytest.raises(TimeoutError, match="secret detail"):
        backend.ask(
            {"prompt": "private prompt", "agent_link_job_id": "2" * 32},
            5.0,
        )

    final = backend.activity_snapshot()
    assert final["active"] is False
    assert final["phase"] == "timed_out"
    assert final["error_code"] == "timeout"
    assert "private prompt" not in repr(final)
    assert "secret detail" not in repr(final)


def test_zcode_cancel_terminates_matching_active_process(monkeypatch) -> None:
    backend = dummy_agent._ZCodeCliAskBackend()
    started = threading.Event()
    killed = threading.Event()
    errors: list[BaseException] = []
    job_id = "7" * 32

    class FakeProcess:
        pid = 1234

        def poll(self):
            return 1 if killed.is_set() else None

    process = FakeProcess()

    def fake_terminate(_cls, candidate):
        assert candidate is process
        killed.set()
        return True

    def fake_once(_params, _timeout_s):
        backend._register_active_process(process)
        started.set()
        try:
            assert killed.wait(2.0)
            raise dummy_agent.BackendCancelledError("cancelled in test")
        finally:
            backend._clear_active_process(process)

    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_terminate_process_tree",
        classmethod(fake_terminate),
    )
    monkeypatch.setattr(backend, "_ask_once", fake_once)

    def execute() -> None:
        try:
            backend.ask(
                {"prompt": "must not survive", "agent_link_job_id": job_id},
                30.0,
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    thread = threading.Thread(target=execute)
    thread.start()
    assert started.wait(1.0)
    outcome = backend.cancel(job_id)
    thread.join(3.0)

    assert outcome == {
        "accepted": True,
        "active_match": True,
        "pre_cancelled": False,
        "termination_confirmed": True,
        "target_id": job_id,
    }
    assert thread.is_alive() is False
    assert len(errors) == 1
    assert isinstance(errors[0], dummy_agent.BackendCancelledError)
    assert backend.activity_snapshot()["phase"] == "cancelled"
    assert backend.activity_snapshot()["active"] is False


def test_zcode_pre_cancel_prevents_queued_job_from_starting(monkeypatch) -> None:
    backend = dummy_agent._ZCodeCliAskBackend()
    job_id = "8" * 32
    ask_once = pytest.fail
    monkeypatch.setattr(backend, "_ask_once", ask_once)

    outcome = backend.cancel(job_id)
    with pytest.raises(
        dummy_agent.BackendCancelledError,
        match="cancelled before execution",
    ):
        backend.ask(
            {"prompt": "must not execute", "agent_link_job_id": job_id},
            30.0,
        )

    assert outcome["accepted"] is True
    assert outcome["pre_cancelled"] is True
    assert outcome["termination_confirmed"] is False
    assert backend.activity_snapshot()["phase"] == "cancelled"


def test_zcode_cancel_rejects_unbound_identifiers() -> None:
    backend = dummy_agent._ZCodeCliAskBackend()
    with pytest.raises(ValueError, match="valid AgentLink job_id"):
        backend.cancel("../../arbitrary")

    outcome = backend.cancel(f"zcall_{'9' * 32}")
    assert outcome["accepted"] is False
    assert outcome["active_match"] is False
    assert outcome["pre_cancelled"] is False
    assert outcome["termination_confirmed"] is False


def test_zcode_cancel_never_reopens_a_concurrently_finished_activity(
    monkeypatch,
) -> None:
    backend = dummy_agent._ZCodeCliAskBackend()
    job_id = "a" * 32
    backend._start_activity(
        {"prompt": "bounded", "agent_link_job_id": job_id},
        30.0,
    )

    original_terminate = backend._terminate_process_tree

    class FakeProcess:
        pid = 4321

        @staticmethod
        def poll():
            return 0

    process = FakeProcess()
    backend._active_process = process

    def finish_during_termination(_candidate):
        backend._mark_activity(
            "cancelled", active=False, error_code="cancelled",
        )
        return True

    monkeypatch.setattr(backend, "_terminate_process_tree", finish_during_termination)
    try:
        assert backend.cancel(job_id)["active_match"] is True
    finally:
        monkeypatch.setattr(backend, "_terminate_process_tree", original_terminate)

    final = backend.activity_snapshot()
    assert final["active"] is False
    assert final["phase"] == "cancelled"


def test_zcode_a2a_cancel_is_authenticated_and_latches_queued_job() -> None:
    import urllib.request

    pytest.importorskip("nacl")
    from nth_dao.cap_token import (
        CAP_A2A_MESSAGE_SEND,
        encode_authorization_header,
        sign_cap_token,
    )
    from nth_dao.identity import AgentIdentity

    issuer = AgentIdentity.generate(label="cancel-issuer")
    child = AgentIdentity.generate(label="cancel-child")
    peer = AgentIdentity.generate(label="cancel-peer")
    holder = dummy_agent._CapTokenHolder()
    holder.set(sign_cap_token(
        issuer=issuer,
        subject_did=child.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
    ))
    peer_token = sign_cap_token(
        issuer=issuer,
        subject_did=peer.as_did(),
        capabilities=[CAP_A2A_MESSAGE_SEND],
    )
    backend = dummy_agent._ZCodeCliAskBackend()
    job_id = "e" * 32
    port, server = dummy_agent._start_a2a_server(
        {
            "agent_id": "cancel-child",
            "kind": "zcode",
            "did": child.as_did(),
            "pubkey_hex": child.pubkey_hex,
            "started_at": int(time.time() * 1000),
        },
        holder,
        backend,
    )
    assert port is not None and server is not None
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/a2a/cancel",
            data=json.dumps({"task_id": job_id}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": (
                    "CapToken " + encode_authorization_header(peer_token)
                ),
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=3.0) as response:  # noqa: S310
            body = json.loads(response.read().decode("utf-8"))
        assert body["result"]["accepted"] is True
        assert body["result"]["pre_cancelled"] is True
        with pytest.raises(dummy_agent.BackendCancelledError):
            backend.ask(
                {"prompt": "must not run", "agent_link_job_id": job_id},
                30.0,
            )
    finally:
        server.shutdown()
        server.server_close()


def test_zcode_model_attestation_rejects_wrong_or_mixed_model(
    tmp_path: Path, monkeypatch,
) -> None:
    rollout_dir = tmp_path / "rollout"
    monkeypatch.setenv("NTH_ZCODE_ROLLOUT_DIR", str(rollout_dir))
    path = _write_model_attestation(rollout_dir, calls=2)
    path.write_text(
        path.read_text(encoding="utf-8")
        + json.dumps({
            "sessionId": "sess_test_12345678",
            "model": {
                "providerId": "bigmodel",
                "modelId": "glm-5.3",
                "source": "config",
            },
        })
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="outside the pinned policy"):
        dummy_agent._ZCodeCliAskBackend._verify_model_attestation(
            "sess_test_12345678",
        )


def test_zcode_model_attestation_rejects_missing_or_mismatched_session(
    tmp_path: Path, monkeypatch,
) -> None:
    rollout_dir = tmp_path / "rollout"
    monkeypatch.setenv("NTH_ZCODE_ROLLOUT_DIR", str(rollout_dir))

    with pytest.raises(RuntimeError, match="unavailable"):
        dummy_agent._ZCodeCliAskBackend._verify_model_attestation(
            "sess_missing_12345678",
        )

    path = _write_model_attestation(rollout_dir)
    record = json.loads(path.read_text(encoding="utf-8"))
    record["sessionId"] = "sess_other_12345678"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="session mismatch"):
        dummy_agent._ZCodeCliAskBackend._verify_model_attestation(
            "sess_test_12345678",
        )


def test_zcode_model_attestation_rejects_invalid_session_id() -> None:
    with pytest.raises(RuntimeError, match="invalid session identity"):
        dummy_agent._ZCodeCliAskBackend._verify_model_attestation("../secret")


def test_zcode_timeout_terminates_windows_process_tree(monkeypatch, tmp_path: Path) -> None:
    taskkill_calls: list[list[str]] = []

    class Process:
        pid = 4321
        returncode = None

        def __init__(self) -> None:
            self.communicate_calls = 0
            self.killed = False

        def communicate(self, *, timeout):
            self.communicate_calls += 1
            if self.communicate_calls == 1:
                raise subprocess.TimeoutExpired(["zcode"], timeout)
            return "", ""

        def poll(self):
            return -9 if self.killed else None

        def kill(self) -> None:
            self.killed = True

    process = Process()

    def fake_run(argv, **_kwargs):
        taskkill_calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr("subprocess.Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr(dummy_agent.sys, "platform", "win32")

    with pytest.raises(subprocess.TimeoutExpired):
        dummy_agent._ZCodeCliAskBackend._run_cli(
            ["zcode"],
            timeout=0.01,
            env={"PATH": "test"},
            cwd=str(tmp_path),
        )

    assert taskkill_calls == [["taskkill", "/PID", "4321", "/T", "/F"]]
    assert process.killed is True


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows process-tree test")
def test_zcode_timeout_reaps_real_windows_child_process(tmp_path: Path) -> None:
    pid_file = tmp_path / "process-tree-pids.txt"
    child_program = "import time; time.sleep(60)"
    parent_program = (
        "import os, pathlib, subprocess, sys, time; "
        f"child = subprocess.Popen([sys.executable, '-c', {child_program!r}]); "
        f"pathlib.Path({str(pid_file)!r}).write_text("
        "f'{os.getpid()} {child.pid}', encoding='utf-8'); "
        "time.sleep(60)"
    )

    with pytest.raises(subprocess.TimeoutExpired):
        dummy_agent._ZCodeCliAskBackend._run_cli(
            [sys.executable, "-c", parent_program],
            timeout=1.0,
            env=dict(os.environ),
            cwd=str(tmp_path),
        )

    parent_pid, child_pid = (
        int(value) for value in pid_file.read_text(encoding="utf-8").split()
    )

    def is_running(pid: int) -> bool:
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5.0,
            check=False,
        )
        return f'"{pid}"' in result.stdout

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and (
        is_running(parent_pid) or is_running(child_pid)
    ):
        time.sleep(0.05)

    assert not is_running(parent_pid)
    assert not is_running(child_pid)


@pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows process-tree test")
def test_zcode_cancel_confirms_real_windows_child_process_exit(tmp_path: Path) -> None:
    pid_file = tmp_path / "cancel-process-tree-pids.txt"
    child_program = "import time; time.sleep(60)"
    parent_program = (
        "import os, pathlib, subprocess, sys, time; "
        f"child = subprocess.Popen([sys.executable, '-c', {child_program!r}]); "
        f"pathlib.Path({str(pid_file)!r}).write_text("
        "f'{os.getpid()} {child.pid}', encoding='utf-8'); "
        "time.sleep(60)"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", parent_program],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=str(tmp_path),
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    backend = dummy_agent._ZCodeCliAskBackend()
    job_id = "f" * 32

    def is_running(pid: int) -> bool:
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5.0,
            check=False,
        )
        return f'"{pid}"' in result.stdout

    try:
        deadline = time.monotonic() + 3.0
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert pid_file.exists()
        parent_pid, child_pid = (
            int(value) for value in pid_file.read_text(encoding="utf-8").split()
        )
        backend._start_activity(
            {"prompt": "cancel real tree", "agent_link_job_id": job_id},
            30.0,
        )
        backend._register_active_process(process)

        outcome = backend.cancel(job_id)

        assert outcome["accepted"] is True
        assert outcome["active_match"] is True
        assert outcome["termination_confirmed"] is True
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and (
            is_running(parent_pid) or is_running(child_pid)
        ):
            time.sleep(0.05)
        assert not is_running(parent_pid)
        assert not is_running(child_pid)
    finally:
        backend._clear_active_process(process)
        if process.poll() is None:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                timeout=5.0,
                check=False,
            )


def test_zcode_rejects_exit_zero_error_payload(tmp_path: Path, monkeypatch) -> None:
    class Result:
        returncode = 0
        stderr = "Error: Turn execution failed"
        stdout = '{"status":"failed","error":"provider unavailable"}'

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NTH_ZCODE_API_KEY", "configured")
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_resolve_launcher",
        classmethod(lambda cls: ["zcode"]),
    )
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_cli_contract_preflight",
        classmethod(lambda cls, launcher: (True, "", "zcode 0.16.5")),
    )
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_run_cli",
        classmethod(lambda cls, *_args, **_kwargs: Result()),
    )

    with pytest.raises(RuntimeError, match="ZCode CLI failed"):
        dummy_agent._ZCodeCliAskBackend().ask({"prompt": "audit"}, 30.0)


def test_zcode_accepts_successful_response_that_discusses_auth_errors(
    tmp_path: Path, monkeypatch,
) -> None:
    response = "The audit discusses unauthorized and authentication failed outcomes."

    class Result:
        returncode = 0
        stderr = ""
        stdout = json.dumps({
            "response": response,
            "sessionId": "sess_test_12345678",
        })

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NTH_ZCODE_API_KEY", "configured")
    rollout_dir = tmp_path / "rollout"
    monkeypatch.setenv("NTH_ZCODE_ROLLOUT_DIR", str(rollout_dir))
    _write_model_attestation(rollout_dir)
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_resolve_launcher",
        classmethod(lambda cls: ["zcode"]),
    )
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_cli_contract_preflight",
        classmethod(lambda cls, launcher: (True, "", "zcode 0.16.5")),
    )
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_run_cli",
        classmethod(lambda cls, *_args, **_kwargs: Result()),
    )

    result = dummy_agent._ZCodeCliAskBackend().ask({"prompt": "audit"}, 30.0)

    assert result["response"] == response


def test_zcode_failure_redacts_explicit_secret(tmp_path: Path, monkeypatch) -> None:
    secret = "secret-zcode-key-value"

    class Result:
        returncode = 1
        stdout = ""
        stderr = f"authorization: {secret} was rejected"

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NTH_ZCODE_API_KEY", secret)
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_resolve_launcher",
        classmethod(lambda cls: ["zcode"]),
    )
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_cli_contract_preflight",
        classmethod(lambda cls, launcher: (True, "", "zcode 0.16.5")),
    )
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_run_cli",
        classmethod(lambda cls, *_args, **_kwargs: Result()),
    )

    with pytest.raises(RuntimeError) as exc_info:
        dummy_agent._ZCodeCliAskBackend().ask({"prompt": "audit"}, 30.0)

    assert secret not in str(exc_info.value)
    assert "[REDACTED]" in str(exc_info.value)


def test_zcode_json_error_payload_redacts_explicit_secret(monkeypatch) -> None:
    secret = "secret-zcode-json-error-key"
    monkeypatch.setenv("NTH_ZCODE_API_KEY", secret)

    with pytest.raises(RuntimeError) as exc_info:
        dummy_agent._ZCodeCliAskBackend._parse_response(
            json.dumps({"error": f"provider rejected key={secret}"}),
        )

    assert secret not in str(exc_info.value)
    assert "[REDACTED]" in str(exc_info.value)


def test_zcode_diagnostic_redacts_unknown_bearer_json_and_plain_secrets() -> None:
    secrets = (
        "unknown-bearer",
        "unknown-basic",
        "unknown-json",
        "unknown-plain",
    )
    diagnostic = (
        f"Authorization: Bearer {secrets[0]}; "
        f"Authorization=Basic {secrets[1]}; "
        f'{{"access_token": "{secrets[2]}"}}; api_key={secrets[3]}'
    )

    redacted = dummy_agent._ZCodeCliAskBackend._redact_diagnostic(diagnostic)

    assert all(secret not in redacted for secret in secrets)
    assert redacted.count("[REDACTED]") == 4


def test_zcode_status_is_non_secret_and_reports_fixed_model(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(dummy_agent.Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_resolve_launcher",
        classmethod(lambda cls: [r"C:\Secret\node.exe", r"C:\Secret\zcode.cjs"]),
    )
    monkeypatch.setattr(
        dummy_agent._ZCodeCliAskBackend,
        "_cli_contract_preflight",
        classmethod(lambda cls, launcher: (True, "", "zcode 0.16.5")),
    )
    monkeypatch.setattr(
        dummy_agent._CodexCliAskBackend,
        "_resolve_binary",
        lambda self: (_ for _ in ()).throw(RuntimeError("missing")),
    )

    status = dummy_agent.backend_runtime_status()["zcode"]

    assert status["ready"] is False
    assert status["available"] is True
    assert status["model"] == "bigmodel/glm-5.3-flash"
    assert status["provider_verified"] is False
    rendered = repr(status)
    assert "C:\\Secret" not in rendered
    assert "API_KEY" not in rendered


def test_zcode_contract_preflight_requires_supervised_flags(monkeypatch) -> None:
    class Result:
        returncode = 0
        stderr = ""

        def __init__(self, stdout: str):
            self.stdout = stdout

    def fake_run(argv, **_kwargs):
        return Result("zcode 0.1\n--prompt --cwd --mode --json")

    monkeypatch.setattr("subprocess.run", fake_run)
    dummy_agent._ZCodeCliAskBackend._clear_preflight_cache()

    ok, reason, version = dummy_agent._ZCodeCliAskBackend._cli_contract_preflight(
        ["node", "zcode.cjs"],
    )

    assert ok is False
    assert "required supervised flags" in reason
    assert version == "zcode 0.1"


def test_zcode_contract_preflight_caches_only_success(monkeypatch) -> None:
    calls = 0

    class Result:
        returncode = 0
        stderr = ""

        def __init__(self, stdout: str):
            self.stdout = stdout

    def fake_run(argv, **_kwargs):
        nonlocal calls
        calls += 1
        return Result(
            "zcode 0.16.5\n"
            "--prompt --attach --cwd --mode --json --disallowed-tools"
        )

    monkeypatch.setattr("subprocess.run", fake_run)
    backend = dummy_agent._ZCodeCliAskBackend
    backend._clear_preflight_cache()

    first = backend._cli_contract_preflight(["node", "zcode.cjs"])
    second = backend._cli_contract_preflight(["node", "zcode.cjs"])

    assert first == second == (True, "", "zcode 0.16.5")
    assert calls == 1
    backend._clear_preflight_cache()
