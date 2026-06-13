"""发现平面 keystone:把发现到的 peer 解析成 A2APeer 给协调者驱动。

证明 ``A2APeer 来源 = 发现``(而非本地 spawn),协调者代码不变:
  - resolve_a2a_peers 过滤无 DID 的 legacy peer、按能力筛、去重;
  - make_http_dispatch 把对端 {result:{response,receipt}} 解析成
    PeerResponse,且自带超时;
  - 端到端:用一条**发现形状的记录**(did+caps,非 spawn 响应)经 resolver
    驱动一个真 agent,signed-receipt 校验仍生效。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import pytest

pytest.importorskip("nacl")
pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.web import create_app
from nth_dao.orchestration.mission import Mission, MissionStep, MissionStatus
from nth_dao.orchestration.mission_store import MissionStore
from nth_dao.orchestration.a2a_coordinator import A2ACoordinator, PeerResponse
from nth_dao.discovery.a2a_resolve import (
    resolve_a2a_peers, make_http_dispatch,
)


@dataclass
class _FakePeer:
    """模拟发现记录(LANPeer 的最小形状)。"""
    did: str
    capabilities: List[str] = field(default_factory=list)
    label: str = ""


# ── resolver 纯逻辑 ──


def test_resolver_filters_didless_dedups_and_caps_filter() -> None:
    discovered = [
        _FakePeer(did="did:key:zA", capabilities=["repro", "analysis"], label="A"),
        _FakePeer(did="", capabilities=["repro"], label="legacy-no-did"),  # 滤掉
        _FakePeer(did="did:key:zB", capabilities=["review"], label="B"),
        _FakePeer(did="did:key:zA", capabilities=["repro"], label="A-dup"),  # 去重
        _FakePeer(did="did:key:zC", capabilities=["idle"], label="C"),  # 能力不符
    ]
    peers = resolve_a2a_peers(
        discovered,
        dispatch_for=lambda p: (lambda _prompt: PeerResponse(text="x")),
        want_capabilities=["repro", "review"],
    )
    dids = [p.did for p in peers]
    assert dids == ["did:key:zA", "did:key:zB"]  # 无DID/重复/能力不符 全滤
    assert peers[0].capabilities == ["repro", "analysis"]


def test_make_http_dispatch_parses_receipt_and_raises_on_non200() -> None:
    # 注入假 post:回带 receipt 的 result。
    def fake_ok(url, body, headers):
        assert body["prompt"] == "hi"
        return 200, {"result": {"response": "done", "receipt": {"signer_did": "did:key:zA"},
                                "agent_did": "did:key:zA"}}
    d = make_http_dispatch("http://peer/a2a/ask", post=fake_ok)
    resp = d("hi")
    assert resp.text == "done" and resp.receipt == {"signer_did": "did:key:zA"}
    assert resp.agent_did == "did:key:zA"

    def fake_401(url, body, headers):
        return 401, {"detail": "cap-token-required"}
    d2 = make_http_dispatch("http://peer/a2a/ask", post=fake_401)
    with pytest.raises(RuntimeError, match="401"):
        d2("hi")


# ── 端到端:发现记录 → resolver → 协调者驱动真 agent ──


def test_discovered_record_drives_real_agent(tmp_path: Path) -> None:
    app = create_app(workspace=tmp_path, require_console_auth=False)
    client = TestClient(app)
    agent_id = None
    try:
        # spawn 一个真 agent(模拟它已在网上跑着)。
        r = client.post("/api/v2/agents/spawn", json={
            "kind": "mock", "label": "net-peer", "capabilities": ["a2a:message_send"]})
        assert r.status_code == 201, r.text
        did = r.json()["did"]
        agent_id = r.json()["agent_id"]

        # 关键:用一条**发现形状的记录**构造 peer(不碰 spawn 响应的其它字段),
        # 任务能力 = ["solo"](发现层声明的 skill,与 cap_token 解耦)。
        discovered = [_FakePeer(did=did, capabilities=["solo"], label="net-peer")]

        # dispatch_for:把"够到对端"接到 hub /ask 代理(本地可达即同构 peer)。
        def dispatch_for(peer):
            def dispatch(prompt: str) -> PeerResponse:
                for _ in range(20):
                    rr = client.post(f"/api/v2/agents/{peer.did}/ask",
                                     json={"prompt": prompt})
                    if rr.status_code == 200 and "not-yet-authorized" not in rr.text:
                        res = rr.json()["result"]
                        return PeerResponse(text=str(res["response"]),
                                            receipt=res.get("receipt"),
                                            agent_did=str(res.get("agent_did", "")))
                    time.sleep(0.5)
                raise RuntimeError("peer 未就绪")
            return dispatch

        peers = resolve_a2a_peers(discovered, dispatch_for=dispatch_for)
        assert len(peers) == 1 and peers[0].did == did

        # 协调者(签名工作证据校验默认开)驱动这个"发现来的" peer。
        store = MissionStore(root=str(tmp_path / "m"))
        store.create(Mission(
            id="disc-1", title="discovered drive", goal="g",
            status=MissionStatus.ACTIVE.value,
            steps=[MissionStep(id="s1", description="干一件事",
                               required_capabilities=["solo"],
                               acceptance_criteria={"required_keys": ["out"], "min_length": 3})]))
        coord = A2ACoordinator(store, peers)
        result = coord.run_mission("disc-1", output_key_for=lambda _s: "out")

        assert result.complete and result.steps[0].ok
        # 完成附签名 receipt,signer == 发现到的 peer DID
        from nth_dao.execution_receipt import verify_receipt
        rcpt = store.get("disc-1").steps[0].output.get("receipt")
        assert isinstance(rcpt, dict) and verify_receipt(rcpt)
        assert rcpt.get("signer_did") == did
    finally:
        if agent_id:
            try:
                client.post(f"/api/v2/agents/{agent_id}/stop")
            except Exception:
                pass
