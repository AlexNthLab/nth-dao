"""认领闭环端到端(切片B):spawn 真子进程 agent → 发任务 → 认领 →
验证 agent 用**自己的 DID** 亲签了 ClaimReceipt。

hub 不持有 agent 私钥,认领必须由 agent 自己签(谁干谁签)。本测试用真
subprocess agent 跑通:hub 铸 cap_token + 派发 → agent /a2a/claim 自签。
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.identity import crypto_available
from nth_dao.web import create_app

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="PyNaCl needed (agent signs claim)"
)


def test_claim_closed_loop_agent_self_signs(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)

    sp = client.post(
        "/api/v2/agents/spawn",
        json={"kind": "mock", "label": "worker", "capabilities": []},
    )
    assert sp.status_code in (200, 201), sp.text
    agent = sp.json()
    agent_id = agent["agent_id"]
    agent_did = agent["did"]
    assert agent.get("a2a_port"), "spawned agent must expose an a2a_port"

    try:
        an = client.post(
            "/api/v2/market/announce",
            json={
                "title": "review PR",
                "capability_set": ["code_review"],
                "reward_minor": 10,
            },
        )
        assert an.status_code == 200, an.text
        ann_id = an.json()["announcement_id"]

        # spawn 后 agent 需 ~1 tick 轮询载入自己的 cap_token 才能鉴权调用方
        # (与 ask/summarize 同款 "not-yet-authorized" 启动时序),轮询重试。
        cl = client.post(
            f"/api/v2/market/{ann_id}/claim", json={"agent_did": agent_did},
        )
        for _ in range(20):
            if "not-yet-authorized" not in cl.text:
                break
            time.sleep(0.5)
            cl = client.post(
                f"/api/v2/market/{ann_id}/claim", json={"agent_did": agent_did},
            )
        assert cl.status_code == 200, cl.text
        result = cl.json().get("result") or {}
        assert result.get("claimed") is True, cl.text
        # 关键:认领方 DID == 这个 agent —— 它用自己的私钥签的(谁干谁签)。
        assert result.get("claimant_did") == agent_did
        assert result.get("receipt_id")

        # 已认领 → 不再出现在开放广场。
        open_ids = {
            x["announcement_id"]
            for x in client.get("/api/v2/market/open").json()
        }
        assert ann_id not in open_ids

        # 幂等:同一 agent 再认领同一条 → 仍 200、仍是它(claim_announcement 幂等)。
        cl2 = client.post(
            f"/api/v2/market/{ann_id}/claim", json={"agent_did": agent_did},
        )
        assert cl2.status_code == 200, cl2.text
        assert (cl2.json().get("result") or {}).get("claimant_did") == agent_did
    finally:
        client.post(f"/api/v2/agents/{agent_id}/stop")


def test_claim_reflects_to_mission_step(tmp_path: Path) -> None:
    # 目标↔市场回流:mission step → 发上广场 → 认领 → step 自动标 CLAIMED。
    from nth_dao.orchestration.mission import Mission

    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)

    sp = client.post(
        "/api/v2/agents/spawn",
        json={"kind": "mock", "label": "w", "capabilities": []},
    )
    assert sp.status_code in (200, 201), sp.text
    agent_did = sp.json()["did"]
    agent_id = sp.json()["agent_id"]

    try:
        m = Mission.new(
            title="M", goal="g", owner="admin",
            steps=[{
                "id": "s1", "description": "review",
                "required_capabilities": ["code_review"],
            }],
        )
        app.state.nth.missions.create(m)

        an = client.post(
            f"/api/v2/missions/{m.id}/steps/s1/announce",
            json={"reward_minor": 5},
        )
        assert an.status_code == 200, an.text
        assert an.json()["mission_id"] == m.id
        ann_id = an.json()["announcement_id"]
        # step 此刻仍是 todo。
        assert app.state.nth.missions.get(m.id).get_step("s1").status == "todo"

        cl = client.post(
            f"/api/v2/market/{ann_id}/claim", json={"agent_did": agent_did},
        )
        for _ in range(20):
            if "not-yet-authorized" not in cl.text:
                break
            time.sleep(0.5)
            cl = client.post(
                f"/api/v2/market/{ann_id}/claim", json={"agent_did": agent_did},
            )
        assert cl.status_code == 200, cl.text
        assert (cl.json().get("result") or {}).get("claimed") is True

        # 回流:对应 mission step 现在 CLAIMED + assignee = 该 agent。
        step = app.state.nth.missions.get(m.id).get_step("s1")
        assert step.status == "claimed", step.status
        assert step.assignee == agent_did

        # 对抗审查回归:step 推进到 done 后,幂等重认领不得把它倒退回 claimed。
        m2 = app.state.nth.missions.get(m.id)
        m2.get_step("s1").status = "done"
        app.state.nth.missions.save(m2)
        cl2 = client.post(
            f"/api/v2/market/{ann_id}/claim", json={"agent_did": agent_did},
        )
        assert cl2.status_code == 200, cl2.text  # 认领仍幂等成功
        assert app.state.nth.missions.get(m.id).get_step("s1").status == "done"
    finally:
        client.post(f"/api/v2/agents/{agent_id}/stop")


def test_claim_unknown_agent_404(tmp_path: Path) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=False))
    an = client.post(
        "/api/v2/market/announce",
        json={"title": "x", "capability_set": ["code_review"]},
    )
    assert an.status_code == 200, an.text
    ann_id = an.json()["announcement_id"]
    r = client.post(
        f"/api/v2/market/{ann_id}/claim", json={"agent_did": "did:key:znope"},
    )
    assert r.status_code == 404
