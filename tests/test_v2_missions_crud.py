"""v2 Missions 落库:POST 真正创建 + GET 读真实 store(不再 seed mock)。

此前"+ New mission"是纯前端假动作(m-local- id、不落库、刷新即失);v2 GET
也只返回 seed mock。这里验证现在是真的。
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.web import create_app


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
    assert body["next_actionable"] == "reproduce the crash"  # 第一个 TODO

    mid = body["id"]
    # GET 现在返回真实 mission(含刚建的),不是 seed。
    rows = client.get("/api/v2/missions").json()
    assert any(x["id"] == mid and x["steps_total"] == 2 for x in rows)
    # 真落库:store 里查得到(刷新/桥都能用)。
    assert app.state.nth.missions.get(mid) is not None


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
