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
    mid = client.post("/api/v2/missions", json={"title": "empty"}).json()["id"]
    assert client.post(f"/api/v2/missions/{mid}/activate").status_code == 409


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
