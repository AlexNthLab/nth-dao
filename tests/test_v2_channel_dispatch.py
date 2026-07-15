"""P2 端到端:频道里的 agent 监听并自动回帖。

起真子进程 mock agent → 加进频道(按 did)→ 人类发消息 → 断言该 agent
用自己的 did 自动回帖到频道。同时验证防环:agent 的回帖不再触发新一轮。
"""
from __future__ import annotations

import time
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.web import create_app


def test_channel_target_helpers_require_explicit_mentions() -> None:
    from nth_dao.web import v2_api as _v2

    explicit = SimpleNamespace(
        body="Hermes, do not receive this",
        metadata={"target_agent_dids": ["did:key:zCodex", "did:key:zCodex"]},
    )
    assert _v2._channel_message_target_dids(explicit) == ["did:key:zCodex"]
    assert _v2._channel_message_target_kind(explicit) == ""
    assert _v2._channel_message_target_kind(
        SimpleNamespace(body="@CODEX/chatgpt, fix the report", metadata={}),
    ) == "codex"
    assert _v2._channel_message_target_kind(
        SimpleNamespace(body="@Claude Code review this", metadata={}),
    ) == "claude-code"
    assert _v2._channel_message_target_kind(
        SimpleNamespace(body="The codex format is documented", metadata={}),
    ) == ""
    assert _v2._channel_message_mentions(
        SimpleNamespace(body="@hermes and @claude-code review this", metadata={}),
    ) == ["hermes", "claude-code"]
    assert _v2._channel_message_mentions(
        SimpleNamespace(
            body="please repair this:\n@dataclass\nclass Example: pass",
            metadata={},
        ),
    ) == []
    assert _v2._channel_message_mentions(
        SimpleNamespace(body="discuss @alice's finding", metadata={}),
    ) == []
    assert _v2._channel_message_mentions(
        SimpleNamespace(body="  @hermes, @codex repair this", metadata={}),
    ) == ["hermes", "codex"]


def test_channel_mentions_resolve_provider_groups_labels_and_all() -> None:
    from nth_dao.web import v2_api as _v2

    records = [
        SimpleNamespace(
            did="did:key:zHermesOne", kind="hermes",
            agent_id="hermes-1", label="Hermes Primary",
            alive=True, a2a_ready=True, a2a_port=41001,
            cap_token_id="cap-hermes-1",
            provider_state="ready", started_at="2026-07-13T10:00:00Z",
        ),
        SimpleNamespace(
            did="did:key:zHermesTwo", kind="hermes",
            agent_id="hermes-2", label="Hermes Reviewer",
            alive=True, a2a_ready=True, a2a_port=41002,
            cap_token_id="cap-hermes-2",
            provider_state="degraded", started_at="2026-07-13T11:00:00Z",
        ),
        SimpleNamespace(
            did="did:key:zHermesNoToken", kind="hermes",
            agent_id="hermes-3", label="Hermes Missing Token",
            alive=True, a2a_ready=True, a2a_port=41004,
            cap_token_id=None,
            provider_state="ready", started_at="2026-07-13T12:00:00Z",
        ),
        SimpleNamespace(
            did="did:key:zCodex", kind="codex",
            agent_id="codex-1", label="Code Fixer",
            alive=True, a2a_ready=True, a2a_port=41003,
            cap_token_id="cap-codex-1",
            provider_state="ready", started_at="2026-07-13T10:00:00Z",
        ),
    ]
    members = {record.did for record in records}

    dids, unresolved, targeted = _v2._resolve_channel_message_target_dids(
        SimpleNamespace(body="@hermes fix this", metadata={}),
        records,
        members,
    )
    assert dids == {"did:key:zHermesOne"}
    assert unresolved == []
    assert targeted is True

    dids, unresolved, targeted = _v2._resolve_channel_message_target_dids(
        SimpleNamespace(body="@Code-Fixer check this", metadata={}),
        records,
        members,
    )
    assert dids == {"did:key:zCodex"}
    assert unresolved == []
    assert targeted is True

    dids, unresolved, targeted = _v2._resolve_channel_message_target_dids(
        SimpleNamespace(body="@codex-1 check this", metadata={}),
        records,
        members,
    )
    assert dids == {"did:key:zCodex"}
    assert unresolved == []
    assert targeted is True

    dids, unresolved, targeted = _v2._resolve_channel_message_target_dids(
        SimpleNamespace(body="@all work together", metadata={}),
        records,
        members,
    )
    assert dids == set()
    assert unresolved == []
    assert targeted is True


def test_dispatch_semaphore_is_bounded() -> None:
    # 审查隐患①修复:派发并发有界。能 acquire 到上限,满了非阻塞返回 False,
    # 归还后恢复 —— 证明信号量是 BoundedSemaphore 且配额可回收。
    from nth_dao.web.v2_api import (
        _CHANNEL_DISPATCH_MAX, _CHANNEL_DISPATCH_SEM,
    )

    acquired = [_CHANNEL_DISPATCH_SEM.acquire(blocking=False)
                for _ in range(_CHANNEL_DISPATCH_MAX)]
    try:
        assert all(acquired)
        assert _CHANNEL_DISPATCH_SEM.acquire(blocking=False) is False  # 满了→丢弃
    finally:
        for _ in range(_CHANNEL_DISPATCH_MAX):
            _CHANNEL_DISPATCH_SEM.release()
    # 全部归还后,配额恢复。
    assert _CHANNEL_DISPATCH_SEM.acquire(blocking=False) is True
    _CHANNEL_DISPATCH_SEM.release()


def test_dispatch_error_cooldown_blocks_repeated_failure_posts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.web import v2_api as _v2

    channel_id = "ops"
    did = "did:key:z6MkBrokenCodex"

    monkeypatch.setattr(_v2, "_CHANNEL_DISPATCH_ERROR_COOLDOWN_S", 10.0)
    with _v2._CHANNEL_DISPATCH_ERROR_LOCK:
        _v2._CHANNEL_DISPATCH_ERROR_UNTIL.clear()
        _v2._CHANNEL_DISPATCH_IN_FLIGHT.clear()

    try:
        assert _v2._channel_dispatch_error_in_cooldown(
            channel_id, did, now=100.0,
        ) is False
        assert _v2._channel_dispatch_note_error(
            channel_id, did, now=100.0,
        ) is True
        assert _v2._channel_dispatch_error_in_cooldown(
            channel_id, did, now=105.0,
        ) is True
        assert _v2._channel_dispatch_note_error(
            channel_id, did, now=105.0,
        ) is False
        assert _v2._channel_dispatch_error_in_cooldown(
            channel_id, did, now=111.0,
        ) is False
    finally:
        with _v2._CHANNEL_DISPATCH_ERROR_LOCK:
            _v2._CHANNEL_DISPATCH_ERROR_UNTIL.clear()
            _v2._CHANNEL_DISPATCH_IN_FLIGHT.clear()


def test_dispatch_try_begin_blocks_duplicate_inflight_calls() -> None:
    from nth_dao.web import v2_api as _v2

    channel_id = "ops"
    did = "did:key:z6MkBusyCodex"
    with _v2._CHANNEL_DISPATCH_ERROR_LOCK:
        _v2._CHANNEL_DISPATCH_ERROR_UNTIL.clear()
        _v2._CHANNEL_DISPATCH_IN_FLIGHT.clear()

    try:
        assert _v2._channel_dispatch_try_begin(channel_id, did) is True
        assert _v2._channel_dispatch_try_begin(channel_id, did) is False
        _v2._channel_dispatch_end(channel_id, did)
        assert _v2._channel_dispatch_try_begin(channel_id, did) is True
    finally:
        _v2._channel_dispatch_end(channel_id, did)
        with _v2._CHANNEL_DISPATCH_ERROR_LOCK:
            _v2._CHANNEL_DISPATCH_ERROR_UNTIL.clear()
            _v2._CHANNEL_DISPATCH_IN_FLIGHT.clear()


def test_channel_dispatch_kind_allowlist_is_env_driven(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.web import v2_api as _v2

    monkeypatch.delenv("NTH_CHANNEL_AGENT_KINDS", raising=False)
    assert _v2._channel_dispatch_kind_allowed("hermes") is True

    monkeypatch.setenv("NTH_CHANNEL_AGENT_KINDS", "codex,mock")
    assert _v2._channel_dispatch_kind_allowed("codex") is True
    assert _v2._channel_dispatch_kind_allowed("mock") is True
    assert _v2._channel_dispatch_kind_allowed("hermes") is False
    assert _v2._channel_dispatch_kind_allowed("") is False


def test_channel_dispatch_failure_persists_terminal_phase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.web import v2_api as _v2

    class FakeGroups:
        def __init__(self) -> None:
            self.posts = []

        def post_message(self, channel_id, sender_id, body, **kwargs):
            self.posts.append({
                "channel_id": channel_id,
                "sender_id": sender_id,
                "body": body,
                **kwargs,
            })

    def fail_urlopen(*args, **kwargs):
        raise _v2.urllib.error.URLError("provider unavailable")

    groups = FakeGroups()
    monkeypatch.setattr(_v2.urllib.request, "urlopen", fail_urlopen)
    with _v2._CHANNEL_DISPATCH_ERROR_LOCK:
        _v2._CHANNEL_DISPATCH_ERROR_UNTIL.clear()
        _v2._CHANNEL_DISPATCH_IN_FLIGHT.clear()
    assert _v2._CHANNEL_DISPATCH_SEM.acquire(blocking=False)
    try:
        _v2._channel_ask_and_reply(
            groups,
            {},
            "did:key:zFailureAgent",
            1234,
            "ops",
            "run the check",
            request_message_id="request-1",
        )
    finally:
        with _v2._CHANNEL_DISPATCH_ERROR_LOCK:
            _v2._CHANNEL_DISPATCH_ERROR_UNTIL.clear()
            _v2._CHANNEL_DISPATCH_PROVIDER_RECOVERY_UNTIL.clear()
            _v2._CHANNEL_DISPATCH_IN_FLIGHT.clear()

    assert [
        post["metadata"]["dispatch_phase"] for post in groups.posts
    ] == ["executing", "failed"]
    failed = groups.posts[-1]
    assert failed["metadata"]["dispatch_phase"] == "failed"
    assert failed["reply_to"] == "request-1"
    assert "agent error" in failed["body"]


def test_degraded_provider_gets_a_half_open_recovery_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.web import v2_api as _v2

    channel_id = "ops-recovery"
    did = "did:key:z6MkRecoverableHermes"
    monkeypatch.setattr(_v2, "_CHANNEL_DISPATCH_PROVIDER_RECOVERY_COOLDOWN_S", 10.0)
    with _v2._CHANNEL_DISPATCH_ERROR_LOCK:
        _v2._CHANNEL_DISPATCH_ERROR_UNTIL.clear()
        _v2._CHANNEL_DISPATCH_PROVIDER_RECOVERY_UNTIL.clear()
        _v2._CHANNEL_DISPATCH_IN_FLIGHT.clear()
    try:
        assert _v2._channel_dispatch_note_error(channel_id, did, now=100.0) is True
        assert _v2._channel_dispatch_provider_recovery_in_cooldown(
            channel_id, did, now=109.0,
        ) is True
        assert _v2._channel_dispatch_provider_recovery_in_cooldown(
            channel_id, did, now=110.0,
        ) is False
        # A successful probe clears both the public error and recovery gate.
        _v2._channel_dispatch_clear_error(channel_id, did)
        assert _v2._channel_dispatch_provider_recovery_in_cooldown(
            channel_id, did, now=111.0,
        ) is False
    finally:
        with _v2._CHANNEL_DISPATCH_ERROR_LOCK:
            _v2._CHANNEL_DISPATCH_ERROR_UNTIL.clear()
            _v2._CHANNEL_DISPATCH_PROVIDER_RECOVERY_UNTIL.clear()
            _v2._CHANNEL_DISPATCH_IN_FLIGHT.clear()

def test_channel_dispatch_marks_provider_degraded_after_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.web import v2_api as _v2

    class FakeGroups:
        def __init__(self) -> None:
            self.posts = []

        def post_message(self, channel_id, sender_id, body, **kwargs):
            self.posts.append({"body": body, **kwargs})

    class FakeSupervisor:
        def __init__(self) -> None:
            self.states = []

        def mark_provider_state(self, agent_id, state):
            self.states.append((agent_id, state))

    def fail_urlopen(*args, **kwargs):
        raise _v2.urllib.error.URLError("provider unavailable")

    groups = FakeGroups()
    supervisor = FakeSupervisor()
    monkeypatch.setattr(_v2.urllib.request, "urlopen", fail_urlopen)
    with _v2._CHANNEL_DISPATCH_ERROR_LOCK:
        _v2._CHANNEL_DISPATCH_ERROR_UNTIL.clear()
        _v2._CHANNEL_DISPATCH_IN_FLIGHT.clear()
    assert _v2._CHANNEL_DISPATCH_SEM.acquire(blocking=False)
    try:
        _v2._channel_ask_and_reply(
            groups,
            {},
            "did:key:z6MkProviderFailure",
            1234,
            "ops",
            "run the check",
            agent_id="hermes-1",
            request_message_id="request-provider-failure",
            supervisor=supervisor,
        )
    finally:
        with _v2._CHANNEL_DISPATCH_ERROR_LOCK:
            _v2._CHANNEL_DISPATCH_ERROR_UNTIL.clear()
            _v2._CHANNEL_DISPATCH_IN_FLIGHT.clear()

    assert supervisor.states == [("hermes-1", "degraded")]


def test_channel_dispatch_passes_backend_kind_to_forward_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.web import v2_api as _v2

    class FakeGroups:
        def __init__(self) -> None:
            self.posts = []

        def post_message(self, channel_id, sender_id, body, **kwargs):
            self.posts.append({"body": body, **kwargs})

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({"result": {"response": "ok"}}).encode("utf-8")

    seen = {}

    def fake_timeout(method, body_bytes, *, backend_kind=None):
        seen["method"] = method
        seen["backend_kind"] = backend_kind
        return 1.0

    monkeypatch.setattr(_v2, "_a2a_forward_timeout", fake_timeout)
    monkeypatch.setattr(_v2.urllib.request, "urlopen", lambda *args, **kwargs: FakeResponse())
    groups = FakeGroups()
    with _v2._CHANNEL_DISPATCH_ERROR_LOCK:
        _v2._CHANNEL_DISPATCH_ERROR_UNTIL.clear()
        _v2._CHANNEL_DISPATCH_IN_FLIGHT.clear()
    assert _v2._CHANNEL_DISPATCH_SEM.acquire(blocking=False)
    try:
        _v2._channel_ask_and_reply(
            groups,
            {},
            "did:key:zHermesAgent",
            1234,
            "ops",
            "run the check",
            backend_kind="hermes",
            request_message_id="request-hermes",
        )
    finally:
        with _v2._CHANNEL_DISPATCH_ERROR_LOCK:
            _v2._CHANNEL_DISPATCH_ERROR_UNTIL.clear()
            _v2._CHANNEL_DISPATCH_IN_FLIGHT.clear()

    assert seen == {"method": "ask", "backend_kind": "hermes"}
    assert [
        post["metadata"]["dispatch_phase"] for post in groups.posts
    ] == ["executing", "completed"]


def test_channel_dispatch_uses_work_scope_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.web import v2_api as _v2

    class FakeGroups:
        def __init__(self) -> None:
            self.posts = []

        def post_message(self, channel_id, sender_id, body, **kwargs):
            self.posts.append({"body": body, **kwargs})

    request = object()
    record = object()
    seen = {}

    class BlockedLease:
        def __enter__(self):
            seen["request"] = request
            seen["record"] = record
            raise _v2.WorkScopeBusy("scope already has a writer")

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(
        _v2,
        "_work_scope_lease",
        lambda actual_request, actual_record: BlockedLease(),
    )
    monkeypatch.setattr(
        _v2.urllib.request,
        "urlopen",
        lambda *args, **kwargs: pytest.fail("provider must not run without the lease"),
    )
    groups = FakeGroups()
    outcome = _v2._channel_ask_and_reply(
        groups,
        {},
        "did:key:zScopedAgent",
        1234,
        "ops",
        "modify the project",
        request_message_id="request-scoped",
        semaphore_acquired=False,
        request=request,
        work_record=record,
    )

    assert seen == {"request": request, "record": record}
    assert "scope already has a writer" in outcome["error"]
    assert groups.posts[-1]["metadata"]["dispatch_phase"] == "failed"

def test_a2a_timeout_hint_is_scoped_to_the_failing_backend() -> None:
    from nth_dao.web import v2_api as _v2

    payload = {
        "error": {
            "code": "backend-timeout",
            "message": "provider did not respond within 90s",
        },
    }

    codex = _v2._a2a_http_error_message(504, payload, backend_kind="codex")
    hermes = _v2._a2a_http_error_message(504, payload, backend_kind="hermes")
    generic = _v2._a2a_http_error_message(504, payload)

    assert "Hermes" not in codex
    assert "NTH_CODEX" in codex
    assert "Hermes" in hermes
    assert "NTH_HERMES_ASK_TIMEOUT_S" in hermes
    assert "Hermes" not in generic
    assert "NTH_HERMES" not in generic


def test_codex_channel_timeout_allows_cli_http_fallback() -> None:
    from nth_dao.web import v2_api as _v2

    assert _v2._channel_dispatch_ask_timeout("codex") == 240.0
    body = json.dumps({"prompt": "probe", "timeout_s": 240.0}).encode("utf-8")
    assert _v2._a2a_forward_timeout("ask", body, backend_kind="codex") >= 245.0


def test_channel_dispatch_cooldown_persists_terminal_failure(
    tmp_path: Path,
) -> None:
    from nth_dao.web import v2_api as _v2

    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    sp = client.post(
        "/api/v2/agents/spawn",
        json={"kind": "mock", "label": "cooldown-agent", "capabilities": []},
    )
    assert sp.status_code in (200, 201), sp.text
    agent = sp.json()
    try:
        assert client.post(
            "/api/v2/channels", json={"name": "cooldown-room"},
        ).status_code == 200
        assert client.post(
            "/api/v2/channels/cooldown-room/join",
            json={"agent_id": agent["did"]},
        ).status_code == 200
        with _v2._CHANNEL_DISPATCH_ERROR_LOCK:
            _v2._CHANNEL_DISPATCH_ERROR_UNTIL["cooldown-room", agent["did"]] = (
                time.time() + 300
            )
        posted = client.post(
            "/api/v2/channels/cooldown-room/messages",
            json={"agent_id": "admin", "body": "try while cooling"},
        )
        assert posted.status_code == 200, posted.text
        request_id = posted.json()["message_id"]
        messages = client.get(
            "/api/v2/channels/cooldown-room/messages",
        ).json()
        assert any(
            m.get("request_message_id") == request_id
            and m.get("dispatch_phase") == "failed"
            for m in messages
        )
    finally:
        with _v2._CHANNEL_DISPATCH_ERROR_LOCK:
            _v2._CHANNEL_DISPATCH_ERROR_UNTIL.clear()
            _v2._CHANNEL_DISPATCH_IN_FLIGHT.clear()
        client.post(f"/api/v2/agents/{agent['agent_id']}/stop")


def test_channel_dispatch_saturation_persists_terminal_failure(
    tmp_path: Path,
) -> None:
    from nth_dao.web import v2_api as _v2

    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    sp = client.post(
        "/api/v2/agents/spawn",
        json={"kind": "mock", "label": "saturated-agent", "capabilities": []},
    )
    assert sp.status_code in (200, 201), sp.text
    agent = sp.json()
    acquired = [
        _v2._CHANNEL_DISPATCH_SEM.acquire(blocking=False)
        for _ in range(_v2._CHANNEL_DISPATCH_MAX)
    ]
    try:
        assert all(acquired)
        assert client.post(
            "/api/v2/channels", json={"name": "saturated-room"},
        ).status_code == 200
        assert client.post(
            "/api/v2/channels/saturated-room/join",
            json={"agent_id": agent["did"]},
        ).status_code == 200
        posted = client.post(
            "/api/v2/channels/saturated-room/messages",
            json={"agent_id": "admin", "body": "try while saturated"},
        )
        assert posted.status_code == 200, posted.text
        request_id = posted.json()["message_id"]
        messages = client.get(
            "/api/v2/channels/saturated-room/messages",
        ).json()
        assert any(
            m.get("request_message_id") == request_id
            and m.get("dispatch_phase") == "failed"
            for m in messages
        )
    finally:
        for _ in range(sum(acquired)):
            _v2._CHANNEL_DISPATCH_SEM.release()
        with _v2._CHANNEL_DISPATCH_ERROR_LOCK:
            _v2._CHANNEL_DISPATCH_ERROR_UNTIL.clear()
            _v2._CHANNEL_DISPATCH_IN_FLIGHT.clear()
        client.post(f"/api/v2/agents/{agent['agent_id']}/stop")


def test_channel_status_declares_hub_source() -> None:
    from nth_dao.web import v2_api as _v2

    class FakeGroups:
        def __init__(self) -> None:
            self.posts = []

        def post_message(self, channel_id, sender_id, body, **kwargs):
            self.posts.append({"body": body, **kwargs})

    groups = FakeGroups()
    assert _v2._post_channel_dispatch_status(
        groups,
        "ops",
        "did:key:zAgent",
        "request-1",
        "processing",
        "Processing instruction.",
    ) is True
    assert groups.posts[0]["metadata"]["status_source"] == "hub"


def test_channel_message_helper_supports_legacy_signature() -> None:
    from nth_dao.web import v2_api as _v2

    class LegacyGroups:
        def __init__(self) -> None:
            self.posts = []

        def post_message(self, channel_id, sender_id, body, metadata=None):
            self.posts.append({
                "channel_id": channel_id,
                "sender_id": sender_id,
                "body": body,
                "metadata": metadata,
            })

    groups = LegacyGroups()
    _v2._post_channel_message(
        groups,
        "ops",
        sender_id="admin",
        body="Processing instruction.",
        kind="system",
        reply_to="request-legacy",
        metadata={"request_message_id": "request-legacy"},
    )
    assert groups.posts[0]["metadata"] == {
        "request_message_id": "request-legacy",
    }


def test_channel_without_agents_persists_hub_failure(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)

    posted = client.post(
        "/api/v2/channels/general/messages",
        json={"agent_id": "admin", "body": "run without agents"},
    )
    assert posted.status_code == 200, posted.text
    request_id = posted.json()["message_id"]
    messages = client.get("/api/v2/channels/general/messages").json()
    assert any(
        m.get("request_message_id") == request_id
        and m.get("dispatch_phase") == "failed"
        and m.get("status_source") == "hub"
        and m.get("metadata", {}).get("agent_did") == ""
        for m in messages
    )


def test_channel_dispatch_recovery_closes_stale_processing(tmp_path: Path) -> None:
    from nth_dao.web import v2_api as _v2

    app = create_app(tmp_path, require_console_auth=False)
    groups = app.state.nth.groups
    request_id = "request-stale-1"
    assert _v2._post_channel_dispatch_status(
        groups,
        "general",
        "did:key:z6MkStaleAgent",
        request_id,
        "processing",
        "Processing instruction.",
    ) is True

    assert _v2._recover_incomplete_channel_dispatches(groups) == 1
    # Recovery is idempotent: the terminal failed status prevents a second
    # recovery message for the same request.
    assert _v2._recover_incomplete_channel_dispatches(groups) == 0
    messages = groups.list_messages("general", actor_id="")
    recovered = [
        m for m in messages
        if m.metadata.get("request_message_id") == request_id
        and m.metadata.get("dispatch_phase") == "failed"
    ]
    assert len(recovered) == 1
    assert recovered[0].metadata.get("recovery") == "hub-restart"


def test_channel_dispatch_startup_projects_uncertain_agent_link(tmp_path: Path) -> None:
    from nth_dao.web.agent_link import AgentLinkStore

    first = AgentLinkStore(tmp_path)
    job = first.create(
        agent_id="stale-agent",
        agent_did="did:key:z6MkStaleAgent",
        idempotency_key="request-link-stale",
        request_hash="request-hash",
        prompt_sha256="prompt-hash",
        channel_id="general",
        request_message_id="request-link-stale",
    )

    app = create_app(tmp_path, require_console_auth=False)
    messages = app.state.nth.groups.list_messages("general", actor_id="")
    recovered = [
        message for message in messages
        if message.metadata.get("request_message_id") == "request-link-stale"
        and message.metadata.get("dispatch_phase") == "failed"
    ]
    assert len(recovered) == 1
    assert recovered[0].metadata.get("link_job_id") == job.job_id
    assert recovered[0].metadata.get("recovery") == "agent-link-delivery-unknown"

    # A second process startup sees the terminal Channel projection and does
    # not append another failure for the same durable request.
    second_app = create_app(tmp_path, require_console_auth=False)
    second_messages = second_app.state.nth.groups.list_messages(
        "general", actor_id="",
    )
    assert sum(
        message.metadata.get("request_message_id") == "request-link-stale"
        and message.metadata.get("dispatch_phase") == "failed"
        for message in second_messages
    ) == 1


def test_channel_agent_listens_and_replies(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)

    sp = client.post(
        "/api/v2/agents/spawn",
        json={"kind": "mock", "label": "chatter", "capabilities": []},
    )
    assert sp.status_code in (200, 201), sp.text
    agent = sp.json()
    agent_id = agent["agent_id"]
    agent_did = agent["did"]
    assert agent.get("a2a_port"), "spawned agent must expose an a2a_port"

    try:
        # 建频道 + 把 agent 按 did 加进成员。
        client.post("/api/v2/channels", json={"name": "engineering"})
        j = client.post(
            "/api/v2/channels/engineering/join", json={"agent_id": agent_did},
        )
        assert j.status_code == 200, j.text
        assert agent_did in j.json()["member_ids"]

        def channel_messages() -> list:
            msgs = client.get("/api/v2/channels/engineering/messages").json()
            return msgs

        # 人类发消息会触发派发(后台)。agent spawn 后需 ~1 tick 载入 cap_token
        # 才能被驱动;反复发 + 轮询,直到出现该 agent 的回帖。
        got = []
        for _ in range(20):
            client.post(
                "/api/v2/channels/engineering/messages",
                json={"agent_id": "admin", "body": "hello agents"},
            )
            for _ in range(6):
                time.sleep(0.5)
                got = channel_messages()
                if any(m.get("dispatch_phase") == "completed" for m in got):
                    break
            if any(m.get("dispatch_phase") == "completed" for m in got):
                break

        assert got, "channel agent did not reply within timeout"
        # Status messages are Hub-authored; only the final response is
        # attributed to the Agent DID.
        completed = next(
            (
                m for m in got
                if m.get("dispatch_phase") == "completed"
                and m.get("sender_id") == agent_did
            ),
            None,
        )
        assert completed is not None, "channel dispatch did not persist a final phase"
        assert completed["body"].strip() != ""
        request_id = completed.get("request_message_id")
        assert request_id, "dispatch result must bind to the user message"
        lifecycle = [
            m.get("dispatch_phase")
            for m in got
            if m.get("request_message_id") == request_id
        ]
        assert lifecycle == ["queued", "executing", "completed"]
        hub_statuses = [
            m for m in got
            if m.get("request_message_id") == request_id
            and m.get("dispatch_phase") in {"queued", "executing"}
        ]
        assert [m.get("status_source") for m in hub_statuses] == ["hub", "hub"]
        assert all(m.get("sender_id") != agent_did for m in hub_statuses)
        assert not any(
            m.get("request_message_id") == request_id
            and m.get("dispatch_phase") in {"received", "processing"}
            for m in got
        )
        assert completed.get("metadata", {}).get("link_job_id")
        assert all(
            m.get("reply_to") == request_id
            for m in got
            if m.get("request_message_id") == request_id
        )

        # 防环:agent 的回帖经内部 API 落盘,不走 HTTP 端点 → 不再触发派发。
        # 等一会儿,确认 agent 回帖数没有失控增长(没有 agent↔agent 刷屏)。
        n1 = len([
            m for m in channel_messages() if m.get("sender_id") == agent_did
        ])
        time.sleep(2.0)
        n2 = len([
            m for m in channel_messages() if m.get("sender_id") == agent_did
        ])
        assert n2 - n1 <= 1, f"runaway agent replies: {n1} -> {n2}"
    finally:
        client.post(f"/api/v2/agents/{agent_id}/stop")


def test_two_channel_agents_reply_without_runaway_loop(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)

    spawned = []
    try:
        for label in ("codex-mock", "hermes-mock"):
            sp = client.post(
                "/api/v2/agents/spawn",
                json={"kind": "mock", "label": label, "capabilities": []},
            )
            assert sp.status_code in (200, 201), sp.text
            agent = sp.json()
            assert agent.get("a2a_port"), "spawned agent must expose an a2a_port"
            spawned.append(agent)

        client.post("/api/v2/channels", json={"name": "debug-room"})
        for agent in spawned:
            j = client.post(
                "/api/v2/channels/debug-room/join",
                json={"agent_id": agent["did"]},
            )
            assert j.status_code == 200, j.text

        def replies_by_agent() -> dict[str, list]:
            msgs = client.get("/api/v2/channels/debug-room/messages").json()
            out = {agent["did"]: [] for agent in spawned}
            for msg in msgs:
                if msg["sender_id"] in out:
                    out[msg["sender_id"]].append(msg)
            return out

        got: dict[str, list] = {}
        for _ in range(20):
            client.post(
                "/api/v2/channels/debug-room/messages",
                json={"agent_id": "admin", "body": "triage bug 111"},
            )
            for _ in range(8):
                time.sleep(0.5)
                got = replies_by_agent()
                if all(got[agent["did"]] for agent in spawned):
                    break
            if all(got[agent["did"]] for agent in spawned):
                break

        assert all(got[agent["did"]] for agent in spawned), got
        for agent in spawned:
            first = got[agent["did"]][0]
            assert first["sender_id"] == agent["did"]
            assert first["body"].strip()

        before = {did: len(rows) for did, rows in replies_by_agent().items()}
        time.sleep(2.0)
        after = {did: len(rows) for did, rows in replies_by_agent().items()}
        for did in before:
            assert after[did] - before[did] <= 1, (
                f"runaway replies for {did}: {before[did]} -> {after[did]}"
            )
    finally:
        for agent in spawned:
            client.post(f"/api/v2/agents/{agent['agent_id']}/stop")


def test_channel_mentions_route_group_and_exact_label(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nth_dao.web import v2_api as _v2

    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    spawned = []
    try:
        for label in ("target-agent", "bystander-agent"):
            response = client.post(
                "/api/v2/agents/spawn",
                json={"kind": "mock", "label": label, "capabilities": []},
            )
            assert response.status_code in (200, 201), response.text
            spawned.append(response.json())

        assert client.post(
            "/api/v2/channels", json={"name": "targeted-room"},
        ).status_code == 200
        for agent in spawned:
            assert client.post(
                "/api/v2/channels/targeted-room/join",
                json={"agent_id": agent["did"]},
            ).status_code == 200

        monkeypatch.setitem(_v2._CHANNEL_AGENT_KIND_ALIASES, "mock", "mock")
        ready_dids = set()
        for _ in range(40):
            rows = client.get("/api/v2/agents").json()
            ready_dids = {
                row.get("did")
                for row in rows
                if row.get("a2a_ready") is True and row.get("alive") is True
            }
            if all(agent["did"] in ready_dids for agent in spawned):
                break
            time.sleep(0.1)
        assert all(agent["did"] in ready_dids for agent in spawned), rows

        unknown = client.post(
            "/api/v2/channels/targeted-room/messages",
            json={"agent_id": "admin", "body": "@missing-agent run this"},
        )
        assert unknown.status_code == 200
        unknown_id = unknown.json()["message_id"]
        unknown_messages = client.get(
            "/api/v2/channels/targeted-room/messages",
        ).json()
        assert any(
            row.get("request_message_id") == unknown_id
            and row.get("dispatch_phase") == "failed"
            and "No channel Agent matches @missing-agent" in row.get("body", "")
            for row in unknown_messages
        )
        assert not any(
            row.get("request_message_id") == unknown_id
            and row.get("dispatch_phase") in {
                "received", "processing", "queued", "executing", "completed"
            }
            for row in unknown_messages
        )

        provider_group = client.post(
            "/api/v2/channels/targeted-room/messages",
            json={"agent_id": "admin", "body": "@mock run this"},
        )
        assert provider_group.status_code == 200
        provider_group_id = provider_group.json()["message_id"]
        provider_messages = []
        for _ in range(60):
            time.sleep(0.25)
            provider_messages = client.get(
                "/api/v2/channels/targeted-room/messages",
            ).json()
            completions = [
                row for row in provider_messages
                if row.get("request_message_id") == provider_group_id
                and row.get("dispatch_phase") == "completed"
            ]
            if len(completions) == 1:
                break
        assert len(completions) == 1, provider_messages
        assert completions[0]["sender_id"] in {
            agent["did"] for agent in spawned
        }
        assert not any(
            row.get("request_message_id") == provider_group_id
            and row.get("dispatch_phase") == "failed"
            for row in provider_messages
        )

        target, bystander = spawned
        supervisor = app.state.v2_supervisor
        target_record = next(
            rec for rec in supervisor.list_agents() if rec.did == target["did"]
        )
        old_token_id = target_record.cap_token_id
        token_store = app.state.nth.cap_tokens
        expired = token_store.get(old_token_id)
        assert isinstance(expired, dict)
        expired["not_after"] = 0
        token_store.record(expired)

        posted = client.post(
            "/api/v2/channels/targeted-room/messages",
            json={
                "agent_id": "admin",
                "body": "@target-agent run only once",
            },
        )
        assert posted.status_code == 200, posted.text
        request_id = posted.json()["message_id"]
        assert not posted.json().get("metadata", {}).get("target_agent_dids")

        messages = []
        for _ in range(30):
            time.sleep(0.25)
            messages = client.get(
                "/api/v2/channels/targeted-room/messages",
            ).json()
            if any(
                row.get("request_message_id") == request_id
                and row.get("dispatch_phase") == "completed"
                for row in messages
            ):
                break

        completions = [
            row for row in messages
            if row.get("request_message_id") == request_id
            and row.get("dispatch_phase") == "completed"
        ]
        assert [row["sender_id"] for row in completions] == [target["did"]]
        assert not any(
            row.get("request_message_id") == request_id
            and row.get("sender_id") == bystander["did"]
            for row in messages
        )
        refreshed_record = next(
            rec for rec in supervisor.list_agents() if rec.did == target["did"]
        )
        assert refreshed_record.cap_token_id != old_token_id
    finally:
        for agent in spawned:
            client.post(f"/api/v2/agents/{agent['agent_id']}/stop")
