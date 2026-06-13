"""MUMOLAWOS A2A-native 协调 keystone(根本方案传输平面)。

证明协调者**只经 A2A 够 worker** —— 把 MUMOLAWOS debug DAG 跑通,每个
step 经 ``POST /api/v2/agents/{did}/ask``(hub 注入 cap_token → 子端
``/a2a/ask``)派给一个**真·被监管子进程** A2A peer。协调者代码不碰
subprocess、不区分本地/远程:peer 的 ``dispatch`` 回调是唯一对外动作。
本地 mock peer 与远程 8081 节点因此同构 —— relay 从代码里消失。

退出门槛:
  - 4-step DAG 全程经 A2A 派活,DONE 4/4;
  - 每步回应来自子端 mock backend(证明确实过了 A2A,不是本地直算);
  - 能力路由 + depends_on 门控仍由 mission 层把关(协调不变)。
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

pytest.importorskip("nacl")
pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.web import create_app
from nth_dao.orchestration.mission import Mission, MissionStep, MissionStatus
from nth_dao.orchestration.mission_store import MissionStore
from nth_dao.orchestration.a2a_coordinator import A2ACoordinator, A2APeer


# MUMOLAWOS 成员角色 → (label, 任务能力)。能力是 mission 路由用的 skill,
# 与 cap_token 的 a2a:message_send 解耦。
ROLES = [
    ("mumo-hermes", ["repro", "analysis"]),
    ("mumo-codex", ["codegen"]),
    ("mumo-claude", ["review"]),
]
KEY_FOR = {"S1-repro": "repro_steps", "S2-root": "root_cause",
           "S3-patch": "patch", "S4-review": "verdict"}


def _build_mission() -> Mission:
    steps = [
        MissionStep(id="S1-repro", description="复现结算双付竞态",
                    required_capabilities=["repro"],
                    inputs={"bug": "settle_trade TOCTOU"},
                    acceptance_criteria={"required_keys": ["repro_steps"], "min_length": 5}),
        MissionStep(id="S2-root", description="定位根因", required_capabilities=["analysis"],
                    depends_on=["S1-repro"],
                    acceptance_criteria={"required_keys": ["root_cause"], "min_length": 5}),
        MissionStep(id="S3-patch", description="出两阶段提交补丁",
                    required_capabilities=["codegen"], depends_on=["S2-root"],
                    acceptance_criteria={"required_keys": ["patch"], "min_length": 5}),
        MissionStep(id="S4-review", description="对抗评审补丁",
                    required_capabilities=["review"], depends_on=["S3-patch"],
                    acceptance_criteria={"required_keys": ["verdict"], "min_length": 5}),
    ]
    return Mission(id="mumolawos-a2a-001", title="MUMOLAWOS A2A debug",
                   goal="经 A2A 协调修复结算双付",
                   status=MissionStatus.ACTIVE.value, steps=steps)


def _make_dispatch(client: TestClient, did: str):
    """构造一个**纯 A2A** dispatch:打 hub /ask(hub 注入 cap_token →
    子端 /a2a/ask)。轮询等子端 authorized(加载 cap_token 需一瞬)。"""
    def dispatch(prompt: str) -> str:
        last = ""
        for _ in range(20):
            r = client.post(f"/api/v2/agents/{did}/ask", json={"prompt": prompt})
            if r.status_code == 200 and "not-yet-authorized" not in r.text:
                body = r.json()
                # 证明确实过了 A2A 到子端 mock backend
                assert body["result"]["backend"] == "mock"
                return str(body["result"]["response"])
            last = f"{r.status_code}: {r.text[:120]}"
            time.sleep(0.5)
        raise RuntimeError(f"peer {did} 始终未就绪: {last}")
    return dispatch


def test_mumolawos_runs_mission_purely_over_a2a(tmp_path: Path) -> None:
    app = create_app(workspace=tmp_path, require_console_auth=False)
    client = TestClient(app)

    # 1) 把每个成员 spawn 成真·被监管 A2A 子进程(本地 peer)。
    peers = []
    agent_ids = []
    try:
        for label, caps in ROLES:
            r = client.post("/api/v2/agents/spawn", json={
                "kind": "mock", "label": label,
                "capabilities": ["a2a:message_send"],  # cap_token scope
            })
            assert r.status_code == 201, r.text
            did = r.json()["did"]
            agent_ids.append(r.json()["agent_id"])
            peers.append(A2APeer(did=did, capabilities=caps,
                                 dispatch=_make_dispatch(client, did), label=label))

        # 2) 协调状态放独立 MissionStore(协调与传输分离)。
        store = MissionStore(root=str(tmp_path / "missions"))
        store.create(_build_mission())

        # 3) 协调者只经 A2A 跑完 DAG。
        coord = A2ACoordinator(store, peers)
        result = coord.run_mission("mumolawos-a2a-001",
                                   output_key_for=lambda sid: KEY_FOR.get(sid))

        # 退出门槛:4/4 DONE,且每步都有来自 A2A peer 的回应。
        assert result.complete, f"未跑完: {result.done}/{result.total} {[s.__dict__ for s in result.steps]}"
        assert result.done == 4
        assert all(s.ok for s in result.steps), [s.__dict__ for s in result.steps]
        # 每步回应来自子端 mock(过了 A2A,不是本地直算)
        assert all("(mock) ack" in s.response for s in result.steps)
        # 能力路由对:S1/S2→hermes、S3→codex、S4→claude
        by_step = {s.step_id: s.peer_did for s in result.steps}
        dids = {p.label: p.did for p in peers}
        assert by_step["S1-repro"] == dids["mumo-hermes"]
        assert by_step["S3-patch"] == dids["mumo-codex"]
        assert by_step["S4-review"] == dids["mumo-claude"]
    finally:
        for aid in agent_ids:
            try:
                client.post(f"/api/v2/agents/{aid}/stop")
            except Exception:
                pass
