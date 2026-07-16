"""认领闭环端到端(切片B):spawn 真子进程 agent → 发任务 → 认领 →
验证 agent 用**自己的 DID** 亲签了 ClaimReceipt。

hub 不持有 agent 私钥,认领必须由 agent 自己签(谁干谁签)。本测试用真
subprocess agent 跑通:hub 铸 cap_token + 派发 → agent /a2a/claim 自签。
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.execution_receipt import verify_receipt
from nth_dao.identity import crypto_available
from nth_dao.web import create_app

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="PyNaCl needed (agent signs claim)"
)


def _mission_event_payloads(app, event_type: str, mission_id: str):
    bus = getattr(app.state.nth, "event_bus", None)
    assert bus is not None, "Mission mutation should initialize EventBus"
    return [
        event.payload
        for event in bus.replay(event_types=[event_type])
        if event.payload.get("mission_id") == mission_id
    ]


def _assert_receipt_for_event(app, payload, event_type: str, mission_id: str) -> None:
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
        mission_id = result.get("mission_id")
        process_id = result.get("process_id")
        assert mission_id, cl.text
        assert process_id, cl.text
        mission = app.state.nth.missions.get(mission_id)
        assert mission is not None
        assert mission.metadata["source_announcement_id"] == ann_id
        assert mission.metadata["process_id"] == process_id
        assert mission.owner_did == agent_did
        assert mission.steps[0].assignee == agent_did
        process = app.state.nth.blackboard.get(process_id, "shared")
        assert process is not None
        assert process.metadata["mission_id"] == mission_id
        assert process.metadata["source_announcement_id"] == ann_id
        mission_rows = client.get("/api/v2/missions").json()
        mission_row = next(x for x in mission_rows if x["id"] == mission_id)
        assert mission_row["source_announcement_id"] == ann_id
        assert mission_row["process_id"] == process_id

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
        result2 = cl2.json().get("result") or {}
        assert result2.get("claimant_did") == agent_did
        assert result2.get("mission_id") == mission_id
        matching = [
            m for m in app.state.nth.missions.list_all()
            if m.metadata.get("source_announcement_id") == ann_id
        ]
        assert len(matching) == 1
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
        announced_payloads = _mission_event_payloads(app, "mission.step.announced", m.id)
        assert len(announced_payloads) == 1
        assert announced_payloads[0]["announcement_id"] == ann_id
        _assert_receipt_for_event(
            app, announced_payloads[0], "mission.step.announced", m.id,
        )
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
        result = cl.json().get("result") or {}
        assert result.get("claimed") is True
        assert result.get("mission_id") == m.id
        assert result.get("mission_reflected") is True
        assert result.get("mission_reflect_reason") == "reflected"
        assert result.get("visibility_status") == "ok"
        claimed_payloads = _mission_event_payloads(app, "mission.step.claimed", m.id)
        assert len(claimed_payloads) == 1
        assert claimed_payloads[0]["announcement_id"] == ann_id
        assert claimed_payloads[0]["claimant_did"] == agent_did
        assert claimed_payloads[0]["agent_claim_receipt_id"] == result.get("receipt_id")
        _assert_receipt_for_event(
            app, claimed_payloads[0], "mission.step.claimed", m.id,
        )

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
        result2 = cl2.json().get("result") or {}
        assert result2.get("mission_id") == m.id
        assert result2.get("mission_reflected") is False
        assert result2.get("mission_reflect_reason") == "already_same_claimant"
        assert result2.get("visibility_status") == "ok"
        assert app.state.nth.missions.get(m.id).get_step("s1").status == "done"
    finally:
        client.post(f"/api/v2/agents/{agent_id}/stop")


def test_linked_claim_overrides_agent_supplied_mission_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
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

    class _FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _size: int = -1):
            return json.dumps({
                "result": {
                    "claimed": True,
                    "claimant_did": agent_did,
                    "receipt_id": "receipt-fake",
                    "mission_id": "evil-mission-from-agent",
                    "visibility_status": "ok",
                },
            }).encode("utf-8")

    try:
        m = Mission.new(
            title="M", goal="g", owner="admin",
            steps=[{"id": "s1", "description": "review"}],
        )
        app.state.nth.missions.create(m)
        an = client.post(
            f"/api/v2/missions/{m.id}/steps/s1/announce",
            json={"reward_minor": 5},
        )
        assert an.status_code == 200, an.text
        ann_id = an.json()["announcement_id"]

        monkeypatch.setattr("urllib.request.urlopen", lambda *_args, **_kwargs: _FakeResponse())
        cl = client.post(
            f"/api/v2/market/{ann_id}/claim", json={"agent_did": agent_did},
        )
        assert cl.status_code == 200, cl.text
        result = cl.json().get("result") or {}
        assert result.get("mission_id") == m.id
        assert result.get("mission_id") != "evil-mission-from-agent"
        assert result.get("mission_reflect_reason") == "reflected"
        assert result.get("visibility_status") == "ok"
    finally:
        client.post(f"/api/v2/agents/{agent_id}/stop")



def test_standalone_claim_visibility_is_idempotent_under_concurrency(
    tmp_path: Path,
) -> None:
    from nth_dao.web.v2_api import _ensure_claim_execution_visible

    app = create_app(tmp_path, require_console_auth=False)
    req = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(nth=app.state.nth)))
    ann = SimpleNamespace(
        mission_id="",
        title="review PR",
        description="review the auth PR",
        capability_set=["code_review"],
        publisher_did="did:key:zPublisher",
        reward_minor=10,
        reward_asset="credit",
    )
    ann_id = "ann-concurrent-visible"
    claimant = "did:key:zWorker"

    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(
            lambda _: _ensure_claim_execution_visible(req, ann, ann_id, claimant),
            range(16),
        ))

    assert {r["visibility_status"] for r in rows} == {"ok"}
    mission_ids = {r["mission_id"] for r in rows}
    process_ids = {r["process_id"] for r in rows}
    assert len(mission_ids) == 1
    assert len(process_ids) == 1
    matching = [
        m for m in app.state.nth.missions.list_all()
        if m.metadata.get("source_announcement_id") == ann_id
    ]
    assert len(matching) == 1
    assert matching[0].id == next(iter(mission_ids))
    assert len(app.state.nth.blackboard.history(next(iter(process_ids)))) == 1
    visible_payloads = _mission_event_payloads(
        app, "mission.market_claim.visible", next(iter(mission_ids)),
    )
    assert len(visible_payloads) == 1
    assert visible_payloads[0]["source_announcement_id"] == ann_id
    assert visible_payloads[0]["claimant_did"] == claimant
    _assert_receipt_for_event(
        app, visible_payloads[0], "mission.market_claim.visible", next(iter(mission_ids)),
    )


class _BrokenMissionStore:
    def __init__(self, root: Path) -> None:
        self.root = root / "broken_missions"
        self.root.mkdir()

    def get(self, _mission_id: str):
        return None

    def list_all(self):
        return []

    def create(self, _mission):
        raise RuntimeError("mission disk is read-only")


class _BrokenBlackboard:
    def __init__(self, root: Path) -> None:
        self.root = root / "broken_blackboard"
        self.root.mkdir()

    def get(self, _entry_id: str, _scope: str = "shared"):
        return None

    def post(self, **_kwargs):
        raise RuntimeError("blackboard disk is read-only")


def test_claim_visibility_reports_persistence_failures(tmp_path: Path) -> None:
    from nth_dao.web.v2_api import _ensure_claim_execution_visible

    app = create_app(tmp_path, require_console_auth=False)
    app.state.nth.missions = _BrokenMissionStore(tmp_path)
    app.state.nth.blackboard = _BrokenBlackboard(tmp_path)
    req = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(nth=app.state.nth)))
    ann = SimpleNamespace(
        mission_id="",
        title="x",
        description="x",
        capability_set=[],
        publisher_did="did:key:zPublisher",
        reward_minor=0,
        reward_asset="credit",
    )

    out = _ensure_claim_execution_visible(req, ann, "ann-fails", "did:key:zWorker")
    assert out["visibility_status"] == "failed"
    assert out["visibility_warnings"] == [
        "mission_visibility_failed",
        "blackboard_visibility_failed",
    ]


def test_linked_claim_reflect_reports_missing_or_mismatched_mission(
    tmp_path: Path,
) -> None:
    from nth_dao.orchestration.mission import Mission
    from nth_dao.web.v2_api import _reflect_claim_to_mission

    app = create_app(tmp_path, require_console_auth=False)
    req = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(nth=app.state.nth)))

    missing = _reflect_claim_to_mission(
        req,
        SimpleNamespace(mission_id="missing-mission"),
        "ann-missing",
        "did:key:zWorker",
    )
    assert missing == {"reflected": False, "reason": "mission_missing"}

    m = Mission.new(
        title="M", goal="g", owner="admin",
        steps=[{"id": "s1", "description": "review"}],
    )
    app.state.nth.missions.create(m)
    mismatched = _reflect_claim_to_mission(
        req,
        SimpleNamespace(mission_id=m.id),
        "ann-does-not-match-step",
        "did:key:zWorker",
    )
    assert mismatched == {"reflected": False, "reason": "step_missing"}


def test_linked_claim_reflect_distinguishes_existing_assignee(
    tmp_path: Path,
) -> None:
    from nth_dao.orchestration.market_coordinator import announcement_id_for
    from nth_dao.orchestration.mission import Mission, StepStatus
    from nth_dao.web.v2_api import _reflect_claim_to_mission

    app = create_app(tmp_path, require_console_auth=False)
    req = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(nth=app.state.nth)))
    m = Mission.new(
        title="M", goal="g", owner="admin",
        steps=[{"id": "s1", "description": "review"}],
    )
    m.steps[0].status = StepStatus.CLAIMED.value
    m.steps[0].assignee = "did:key:zOther"
    app.state.nth.missions.create(m)
    ann_id = announcement_id_for(m.id, "s1")

    other = _reflect_claim_to_mission(
        req, SimpleNamespace(mission_id=m.id), ann_id, "did:key:zWorker",
    )
    assert other["reason"] == "already_claimed_by_other"
    assert other["reflected"] is False

    same = _reflect_claim_to_mission(
        req, SimpleNamespace(mission_id=m.id), ann_id, "did:key:zOther",
    )
    assert same["reason"] == "already_same_claimant"
    assert same["reflected"] is False



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
