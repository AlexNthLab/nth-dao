"""Phase 2b:announce 端点经 app 接线到 spine 单例(影子双写)的集成测试。

证明:走 HTTP /api/v2/market/announce 发布后,app.state.nth.spine 真拿到事件、
链完好、投影重建出与 /api/v2/market/open 一致的开放视图。
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("nacl")

from fastapi.testclient import TestClient

from nth_dao.market.projection import MarketAnnounceProjection
from nth_dao.spine import replay
from nth_dao.web import create_app


def test_announce_dual_writes_to_workspace_spine(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)

    r = client.post(
        "/api/v2/market/announce",
        json={"title": "spine-wired", "capability_set": ["code_review"],
              "reward_minor": 7},
    )
    assert r.status_code == 200, r.text
    aid = r.json()["announcement_id"]

    # spine 单例在 bootstrap 后就绪,并拿到了这条公告。
    spine = app.state.nth.spine
    assert spine is not None, "spine 应在 _bootstrap 后就绪(node_identity 可签)"
    ok, why = spine.verify_chain()
    assert ok, why

    proj = MarketAnnounceProjection()
    replay(spine.read_all(), proj)
    assert proj.get(aid) is not None

    # 投影开放视图与 /market/open 一致(都含该公告)。
    open_ids = {
        a["announcement_id"] for a in client.get("/api/v2/market/open").json()
    }
    assert aid in open_ids
    assert aid in {a.announcement_id for a in proj.open()}


def test_announce_still_works_when_spine_absent(tmp_path: Path) -> None:
    # 降级:即便 spine 缺失(手动置 None),发布与 /market/open 照常。
    app = create_app(tmp_path, require_console_auth=False)
    app.state.nth.spine = None
    client = TestClient(app)
    r = client.post(
        "/api/v2/market/announce",
        json={"title": "no-spine", "capability_set": ["x"], "reward_minor": 0},
    )
    assert r.status_code == 200, r.text
    aid = r.json()["announcement_id"]
    open_ids = {
        a["announcement_id"] for a in client.get("/api/v2/market/open").json()
    }
    assert aid in open_ids
