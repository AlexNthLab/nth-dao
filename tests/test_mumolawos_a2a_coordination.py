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
from nth_dao.orchestration.a2a_coordinator import (
    A2ACoordinator, A2APeer, PeerResponse,
)


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
    子端 /a2a/ask)。轮询等子端 authorized(加载 cap_token 需一瞬)。
    返回 PeerResponse,带子端签名的 receipt(协调者据此验签)。"""
    def dispatch(prompt: str) -> PeerResponse:
        last = ""
        for _ in range(20):
            r = client.post(f"/api/v2/agents/{did}/ask", json={"prompt": prompt})
            if r.status_code == 200 and "not-yet-authorized" not in r.text:
                res = r.json()["result"]
                assert res["backend"] == "mock"  # 确过 A2A 到子端 mock
                return PeerResponse(text=str(res["response"]),
                                    receipt=res.get("receipt"),
                                    agent_did=str(res.get("agent_did", "")))
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

        # 每步的完成都有签名 receipt 作凭据,且 signer == 干活的 peer DID
        from nth_dao.execution_receipt import verify_receipt
        store2 = store
        for s in store2.get("mumolawos-a2a-001").steps:
            rcpt = (s.output or {}).get("receipt")
            assert isinstance(rcpt, dict), f"{s.id} 完成缺签名 receipt"
            assert verify_receipt(rcpt), f"{s.id} receipt 验签不过"
            assert rcpt.get("signer_did") == by_step[s.id], \
                f"{s.id} receipt signer 与干活 peer 不符"
    finally:
        for aid in agent_ids:
            try:
                client.post(f"/api/v2/agents/{aid}/stop")
            except Exception:
                pass


def test_unsigned_work_is_rejected(tmp_path: Path) -> None:
    """安全回归:peer 回了文本但**无签名 receipt** —— verify_receipts=True
    的协调者拒绝把该 step 记完成(unverified work)。这正是去中心/远程
    peer 场景下,防一个 peer 谎称干完活骗信誉/报酬的那道闸。"""
    store = MissionStore(root=str(tmp_path / "m"))
    store.create(Mission(
        id="m-unsigned", title="t", goal="g", status=MissionStatus.ACTIVE.value,
        steps=[MissionStep(id="s1", description="d", required_capabilities=["x"],
                           acceptance_criteria={"min_length": 1})]))

    # 一个"撒谎"的 peer:回文本但不带 receipt。
    liar = A2APeer(did="did:key:zLiar", capabilities=["x"],
                   dispatch=lambda _p: PeerResponse(text="我干完了(其实没有)", receipt=None))
    coord = A2ACoordinator(store, [liar])  # verify_receipts 默认 True
    result = coord.run_mission("m-unsigned", output_key_for=lambda _s: None)

    assert not result.complete and result.done == 0
    assert result.steps and not result.steps[0].ok
    assert "unverified" in result.steps[0].detail
