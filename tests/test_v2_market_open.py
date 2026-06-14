"""任务广场后端读路径:GET /api/v2/market/open 列出未认领、未过期的公告。

把此前完全没接进 UI 的 nth_dao.market 任务市场暴露给前端"发现可认领的活"。
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.identity import AgentIdentity, crypto_available
from nth_dao.web import create_app


pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="PyNaCl not installed (announcement signing)"
)


def _publish(ws: Path, **kw):
    from nth_dao.market.announcement import sign_announcement
    from nth_dao.market.feed import MarketFeed

    pub = AgentIdentity.generate(label="pub")
    ann = sign_announcement(publisher=pub, **kw)
    MarketFeed(ws).publish(ann)
    return ann


def test_market_open_lists_unclaimed_excludes_claimed(tmp_path: Path) -> None:
    a = _publish(tmp_path, title="task-A", capability_set=["code_review"], reward_minor=10)
    b = _publish(tmp_path, title="task-B", capability_set=["research"], reward_minor=5)

    # 把 b 标记为已认领(直接写 claim 记录,绕过完整 cap_token 流程)。
    from nth_dao.market.claim import CLAIM_STATUS_CLAIMED, ClaimStore
    from nth_dao.util.io import atomic_write_json

    cs = ClaimStore(tmp_path)
    atomic_write_json(
        cs._path(b.announcement_id),
        {"status": CLAIM_STATUS_CLAIMED, "claimant_did": "did:key:zClaimed"},
    )

    client = TestClient(create_app(tmp_path, require_console_auth=False))
    r = client.get("/api/v2/market/open")
    assert r.status_code == 200
    titles = {x["title"] for x in r.json()}
    assert "task-A" in titles            # 未认领 → 出现
    assert "task-B" not in titles        # 已认领 → 排除
    # 返回体带可认领标记 + 经济字段,供前端渲染。
    row = next(x for x in r.json() if x["title"] == "task-A")
    assert row["claimed"] is False
    assert row["reward_minor"] == 10
    assert row["announcement_id"] == a.announcement_id


def test_market_open_empty_when_no_feed(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    r = client.get("/api/v2/market/open")
    assert r.status_code == 200
    assert r.json() == []


def test_market_open_read_has_no_filesystem_side_effects(tmp_path: Path) -> None:
    # 自审回归:只读 GET 不该在从不用市场的节点工作区里造出市场目录。
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    assert client.get("/api/v2/market/open").status_code == 200
    assert not (tmp_path / "market_feed").exists()
    assert not (tmp_path / "market_claims").exists()


def test_market_announce_then_open_shows_it(tmp_path: Path) -> None:
    # publish 路径:announce 一条 → 广场(/market/open)立刻能发现它。
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    r = client.post(
        "/api/v2/market/announce",
        json={
            "title": "review PR 42",
            "capability_set": ["code_review"],
            "reward_minor": 50,
        },
    )
    assert r.status_code == 200, r.text
    ann_id = r.json()["announcement_id"]
    assert ann_id

    rows = client.get("/api/v2/market/open").json()
    hit = next((x for x in rows if x["announcement_id"] == ann_id), None)
    assert hit is not None
    assert hit["title"] == "review PR 42"
    assert hit["reward_minor"] == 50
    assert hit["claimed"] is False


def test_market_announce_rejects_empty_title(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    r = client.post("/api/v2/market/announce", json={"title": "   "})
    assert r.status_code == 400


def test_market_announce_rejects_negative_reward(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    r = client.post(
        "/api/v2/market/announce",
        json={"title": "x", "reward_minor": -1},
    )
    assert r.status_code == 422  # pydantic ge=0


def test_market_open_filters_and_categories(tmp_path: Path) -> None:
    # 分类/检索:按 context / capability / min_reward / q 过滤 + 类别分面。
    client = TestClient(create_app(tmp_path, require_console_auth=False))

    def announce(**kw):
        r = client.post("/api/v2/market/announce", json=kw)
        assert r.status_code == 200, r.text

    announce(title="review the auth PR", capability_set=["code_review"],
             context="code_review", reward_minor=100)
    announce(title="research market sizing", capability_set=["research"],
             context="research", reward_minor=10)
    announce(title="review small typo", capability_set=["code_review"],
             context="code_review", reward_minor=5)

    def titles(**params):
        return {x["title"] for x in client.get(
            "/api/v2/market/open", params=params).json()}

    assert len(titles()) == 3
    # 按类别。
    assert titles(context="research") == {"research market sizing"}
    # 按能力(与认领同套归一)。
    assert titles(capability="code_review") == {
        "review the auth PR", "review small typo"}
    # 按赏金下限。
    assert titles(min_reward=50) == {"review the auth PR"}
    # 文本搜索。
    assert titles(q="typo") == {"review small typo"}
    # 组合(交集):code_review 类 + 赏金>=50。
    assert titles(context="code_review", min_reward=50) == {"review the auth PR"}

    # 类别分面带计数。
    cats = {c["context"]: c["count"] for c in
            client.get("/api/v2/market/categories").json()}
    assert cats == {"code_review": 2, "research": 1}


def test_mission_step_announce_bridge(tmp_path: Path) -> None:
    # Mission↔Task 之桥:把真实 mission 的 step 发成市场 Task,带 mission_id 回链。
    from nth_dao.orchestration.mission import Mission

    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    m = Mission.new(
        title="Launch",
        goal="ship v1",
        owner="admin",
        steps=[{
            "id": "s1",
            "description": "review the auth PR",
            "required_capabilities": ["code_review"],
        }],
    )
    app.state.nth.missions.create(m)

    r = client.post(
        f"/api/v2/missions/{m.id}/steps/s1/announce",
        json={"reward_minor": 25},
    )
    assert r.status_code == 200, r.text
    assert r.json()["mission_id"] == m.id
    assert r.json()["already_announced"] is False
    ann_id = r.json()["announcement_id"]

    # 出现在广场,带 mission_id + 取自 step 的能力。
    rows = client.get("/api/v2/market/open").json()
    hit = next((x for x in rows if x["announcement_id"] == ann_id), None)
    assert hit is not None
    assert hit["mission_id"] == m.id
    assert "code_review" in hit["capability_set"]
    assert hit["reward_minor"] == 25

    # 幂等:再发同一 step 不重复(确定性 announcement_id)。
    r2 = client.post(
        f"/api/v2/missions/{m.id}/steps/s1/announce", json={"reward_minor": 25},
    )
    assert r2.status_code == 200
    assert r2.json()["already_announced"] is True
    rows2 = client.get("/api/v2/market/open").json()
    assert sum(1 for x in rows2 if x["announcement_id"] == ann_id) == 1

    # 不存在的 mission / step → 404。
    assert client.post(
        "/api/v2/missions/nope/steps/s1/announce", json={},
    ).status_code == 404
    assert client.post(
        f"/api/v2/missions/{m.id}/steps/nope/announce", json={},
    ).status_code == 404


def test_market_announce_caps_oversized_input(tmp_path: Path) -> None:
    # 对抗审查回归:超大输入会被签名+永久追加进 feed,必须在边界封顶。
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    assert client.post(
        "/api/v2/market/announce", json={"title": "x" * 201},
    ).status_code == 400
    assert client.post(
        "/api/v2/market/announce",
        json={"title": "ok", "description": "d" * 4001},
    ).status_code == 400
    assert client.post(
        "/api/v2/market/announce",
        json={"title": "ok", "capability_set": [f"c{i}" for i in range(33)]},
    ).status_code == 400
    # 一个超长能力名也要拒。
    assert client.post(
        "/api/v2/market/announce",
        json={"title": "ok", "capability_set": ["x" * 101]},
    ).status_code == 400
