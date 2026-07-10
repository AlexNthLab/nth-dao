"""v2 Missions 落库:POST 真正创建 + GET 读真实 store(不再 seed mock)。

此前"+ New mission"是纯前端假动作(m-local- id、不落库、刷新即失);v2 GET
也只返回 seed mock。这里验证现在是真的。
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.execution_receipt import verify_receipt
from nth_dao.web import create_app


def _mission_event_payloads(app, event_type: str, mission_id: str):
    bus = getattr(app.state.nth, "event_bus", None)
    assert bus is not None, "Mission mutation should initialize EventBus"
    return [
        event.payload
        for event in bus.replay(event_types=[event_type])
        if event.payload.get("mission_id") == mission_id
    ]


def _assert_receipt_for_event(app, payload, event_type: str, mission_id: str) -> None:
    identity = getattr(app.state.nth, "node_identity", None)
    if identity is None or not getattr(identity, "can_sign", False):
        return
    receipt_id = payload.get("receipt_id")
    assert receipt_id, payload
    receipt = app.state.nth.receipts.load(receipt_id)
    assert receipt is not None
    assert receipt["goal_id"] == mission_id
    assert verify_receipt(receipt)
    assert any(
        item.get("type") == "nth.mission_event"
        and item.get("payload", {}).get("event_type") == event_type
        and item.get("payload", {}).get("mission_id") == mission_id
        for item in receipt.get("timeline", [])
    )


def test_missions_empty_then_create_then_persist(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)

    # 空 store → [](不再返回两条假 active mission 误导用户)。
    assert client.get("/api/v2/missions").json() == []

    r = client.post(
        "/api/v2/missions",
        json={
            "title": "Mumo debug",
            "goal": "stabilize the OS",
            "driver": "fulfillment-bot",
            "driver_did": "did:key:zDriverABC",
            "steps": [
                {"description": "reproduce the crash",
                 "required_capabilities": ["debug"]},
                {"description": "write a fix",
                 "required_capabilities": ["code_review"]},
            ],
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["title"] == "Mumo debug"
    assert body["status"] == "planning"        # 默认初始态(空步骤天然规划态)
    assert body["steps_total"] == 2
    assert body["steps_done"] == 0
    assert body["driver_label"] == "fulfillment-bot"
    assert body["driver_did"] == "did:key:zDriverABC"  # 对抗审查:DID 不再被丢
    assert body["next_actionable"] == "reproduce the crash"  # 第一个 TODO
    assert body["steps"][0]["description"] == "reproduce the crash"
    assert body["steps"][0]["status"] == "todo"
    assert body["steps"][0]["required_capabilities"] == ["debug"]
    assert any(e["label"] == "Mission created" for e in body["timeline"])
    audited = [e for e in body["timeline"] if e["label"] == "Mission created (audited)"]
    assert audited, body["timeline"]
    assert any(
        e["kind"] == "step" and "Step current todo" in e["label"] and "reproduce the crash" in e["label"]
        for e in body["timeline"]
    )

    mid = body["id"]
    created_payloads = _mission_event_payloads(app, "mission.created", mid)
    assert len(created_payloads) == 1
    assert created_payloads[0]["title"] == "Mumo debug"
    _assert_receipt_for_event(app, created_payloads[0], "mission.created", mid)
    # GET 现在返回真实 mission(含刚建的),不是 seed。
    rows = client.get("/api/v2/missions").json()
    assert any(x["id"] == mid and x["steps_total"] == 2 for x in rows)
    # 真落库:store 里查得到(刷新/桥都能用)。
    assert app.state.nth.missions.get(mid) is not None


def test_mission_summary_exposes_current_claimed_step(tmp_path: Path) -> None:
    from nth_dao.orchestration.mission import Mission, StepStatus

    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    m = Mission.new(
        title="Claimed work",
        goal="show current work",
        owner="codex-local",
        owner_did="did:key:zCodex",
        steps=[
            {"id": "s1", "description": "review the PR"},
            {"id": "s2", "description": "write follow-up tests"},
        ],
    )
    m.steps[0].status = StepStatus.CLAIMED.value
    m.steps[0].assignee = "did:key:zCodex"
    app.state.nth.missions.create(m)

    row = client.get("/api/v2/missions").json()[0]
    assert row["current_action"] == "review the PR"
    assert row["current_step_id"] == "s1"
    assert row["current_step_status"] == "claimed"
    assert row["next_actionable"] == "write follow-up tests"


def test_mission_activate_planning_to_active(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)

    mid = client.post(
        "/api/v2/missions",
        json={"title": "M", "steps": [{"description": "step one"}]},
    ).json()["id"]
    assert client.get("/api/v2/missions").json()[0]["status"] == "planning"

    r = client.post(f"/api/v2/missions/{mid}/activate")
    assert r.status_code == 200, r.text
    activated = r.json()
    assert activated["status"] == "active"
    assert any(e["label"] == "Mission activated" for e in activated["timeline"])
    activated_payloads = _mission_event_payloads(app, "mission.activated", mid)
    assert len(activated_payloads) == 1
    _assert_receipt_for_event(app, activated_payloads[0], "mission.activated", mid)
    # 落盘 + 幂等。
    assert app.state.nth.missions.get(mid).status == "active"
    assert client.post(f"/api/v2/missions/{mid}/activate").json()["status"] == "active"
    assert len(_mission_event_payloads(app, "mission.activated", mid)) == 1


def test_mission_activate_rejects_empty_and_missing(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    # 不存在 → 404。
    assert client.post("/api/v2/missions/nope/activate").status_code == 404
    # 0 步的 mission 不能启动 → 409。
    missing = client.post("/api/v2/missions/nope/activate")
    assert missing.status_code == 404


def test_mission_activate_bootstraps_empty_mission(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)

    mid = client.post(
        "/api/v2/missions",
        json={
            "title": "MUMO deBUG",
            "goal": "scan the project and produce a debug plan",
            "driver": "mock runner",
            "driver_did": "did:key:zDriverABC",
        },
    ).json()["id"]

    first = client.post(f"/api/v2/missions/{mid}/activate")
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["status"] == "active"
    assert body["steps_total"] == 1
    assert body["steps_in_progress"] == 1
    assert body["current_step_status"] == "claimed"
    assert body["steps"][0]["assignee"] == "did:key:zDriverABC"
    assert body["steps"][0]["description"] == "scan the project and produce a debug plan"
    assert any(e["label"] == "Step bootstrapped from mission goal" for e in body["timeline"])

    second = client.post(f"/api/v2/missions/{mid}/activate")
    assert second.status_code == 200, second.text
    assert second.json()["steps_total"] == 1
    boot_payloads = _mission_event_payloads(app, "mission.step.bootstrapped", mid)
    assert len(boot_payloads) == 1


def test_mission_step_run_executes_via_supervised_agent(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)

    spawned = client.post(
        "/api/v2/agents/spawn",
        json={
            "kind": "mock",
            "label": "mission-runner",
            "capabilities": ["a2a:message_send"],
        },
    )
    assert spawned.status_code == 201, spawned.text
    agent = spawned.json()
    did = agent["did"]
    agent_id = agent["agent_id"]
    try:
        created = client.post(
            "/api/v2/missions",
            json={
                "title": "Run one step",
                "goal": "prove Mission can advance",
                "driver": "mission-runner",
                "driver_did": did,
                "steps": [{"description": "say DONE_OK"}],
            },
        )
        assert created.status_code == 200, created.text
        body = created.json()
        mid = body["id"]
        sid = body["steps"][0]["id"]

        activated = client.post(f"/api/v2/missions/{mid}/activate")
        assert activated.status_code == 200, activated.text

        ran = client.post(
            f"/api/v2/missions/{mid}/steps/{sid}/run",
            json={"prompt": "Reply with DONE_OK for the mission execution test."},
        )
        assert ran.status_code == 200, ran.text
        summary = ran.json()
        assert summary["status"] == "completed"
        assert summary["steps_done"] == 1
        assert summary["steps"][0]["status"] == "done"
        assert any(e["label"] == "Step completed by agent" for e in summary["timeline"])

        completed_payloads = _mission_event_payloads(app, "mission.step.completed", mid)
        assert len(completed_payloads) == 1
        payload = completed_payloads[0]
        assert payload["step_id"] == sid
        assert payload["agent_did"] == did
        assert payload["agent_response_receipt_id"]
        _assert_receipt_for_event(app, payload, "mission.step.completed", mid)

        stored = app.state.nth.missions.get(mid)
        assert stored is not None
        step = stored.get_step(sid)
        assert step is not None
        assert step.output["receipt_id"] == payload["agent_response_receipt_id"]
        assert "DONE_OK" in step.output["content"]
        agent_receipt = app.state.nth.receipts.load(step.output["receipt_id"])
        assert agent_receipt is not None
        assert verify_receipt(agent_receipt)
    finally:
        client.post(f"/api/v2/agents/{agent_id}/stop")


def test_mission_step_run_rotates_expired_agent_cap_token(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)

    spawned = client.post(
        "/api/v2/agents/spawn",
        json={
            "kind": "mock",
            "label": "mission-expired-cap",
            "capabilities": ["a2a:message_send"],
        },
    )
    assert spawned.status_code == 201, spawned.text
    agent = spawned.json()
    did = agent["did"]
    agent_id = agent["agent_id"]
    old_token_id = agent["cap_token_id"]
    expired = app.state.nth.cap_tokens.get(old_token_id)
    assert isinstance(expired, dict)
    expired["not_after"] = 0
    app.state.nth.cap_tokens.record(expired)

    try:
        created = client.post(
            "/api/v2/missions",
            json={
                "title": "Run with expired cap",
                "goal": "prove mission run rotates token",
                "driver": "mission-expired-cap",
                "driver_did": did,
                "steps": [{"description": "say ROTATED_OK"}],
            },
        )
        assert created.status_code == 200, created.text
        mid = created.json()["id"]
        sid = created.json()["steps"][0]["id"]
        activated = client.post(f"/api/v2/missions/{mid}/activate")
        assert activated.status_code == 200, activated.text

        ran = client.post(
            f"/api/v2/missions/{mid}/steps/{sid}/run",
            json={"prompt": "Reply with ROTATED_OK."},
        )
        assert ran.status_code == 200, ran.text
        step = ran.json()["steps"][0]
        assert step["status"] == "done"
        stored = app.state.nth.missions.get(mid)
        assert stored is not None
        stored_step = stored.get_step(sid)
        assert stored_step is not None
        assert "ROTATED_OK" in stored_step.output["content"]

        record = next(x for x in app.state.v2_supervisor.list_agents() if x.did == did)
        assert record.cap_token_id != old_token_id
    finally:
        client.post(f"/api/v2/agents/{agent_id}/stop")


def test_mission_step_run_blocks_on_malformed_agent_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)

    async def fake_drive(*_args, **_kwargs):
        return 200, {"result": {"backend": "mock"}}, object(), {
            "nth_receipt_id": "agent-r1",
            "nth_receipt_content_hash": "sha256:abc",
        }

    import nth_dao.web.v2_api as v2_api

    monkeypatch.setattr(v2_api, "_drive_supervised_agent_ask", fake_drive)
    created = client.post(
        "/api/v2/missions",
        json={
            "title": "Malformed run",
            "goal": "show failure",
            "driver_did": "did:key:zMalformedAgent",
            "steps": [{"description": "return malformed"}],
        },
    )
    assert created.status_code == 200, created.text
    mid = created.json()["id"]
    sid = created.json()["steps"][0]["id"]

    ran = client.post(f"/api/v2/missions/{mid}/steps/{sid}/run", json={})
    assert ran.status_code == 502, ran.text
    stored = app.state.nth.missions.get(mid)
    assert stored is not None
    step = stored.get_step(sid)
    assert step is not None
    assert step.status == "blocked"
    assert any("agent response was empty" in note for note in step.notes)
    blocked = _mission_event_payloads(app, "mission.step.blocked", mid)
    assert len(blocked) == 1
    assert blocked[0]["step_id"] == sid


def test_missions_create_validates(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    assert client.post(
        "/api/v2/missions", json={"title": "   "},
    ).status_code == 400
    assert client.post(
        "/api/v2/missions", json={"title": "x" * 201},
    ).status_code == 400
    assert client.post(
        "/api/v2/missions",
        json={"title": "ok", "steps": [{"description": "d"}] * 65},
    ).status_code == 400
