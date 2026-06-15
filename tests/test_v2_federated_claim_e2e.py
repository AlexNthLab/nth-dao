"""XDAO-3 capstone:跨 DAO 认领端到端(真双节点)。

源 DAO 起一个**真 uvicorn 服务**(发布任务 + 收 /claim-foreign);编排 DAO 用
TestClient + spawn 真子进程 agent + 注入联邦缓存(来源=源 DAO 真 URL)。一键
打 /market/federated/claim → 本地 agent claim-sign → 转投源 DAO 落 CAS。

这条链把 XDAO-1/2/3 串起来验:agent 自签(真子进程)+ 跨节点 HTTP + 源 DAO 的
CAS 落盘。也补上 agent claim-sign 方法的 e2e。
"""
from __future__ import annotations

import socket
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("nacl")
uvicorn = pytest.importorskip("uvicorn")

from fastapi.testclient import TestClient

from nth_dao.identity import crypto_available
from nth_dao.market import ClaimStore
from nth_dao.market.announcement import TaskAnnouncement
from nth_dao.web import create_app
from nth_dao.web.market_federation_poll import FederationCache

pytestmark = pytest.mark.skipif(
    not crypto_available(), reason="PyNaCl needed (signing across nodes)"
)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _BgServer:
    """在后台线程跑一个真 uvicorn(给跨节点 HTTP 提供真 socket)。"""

    def __init__(self, app, port: int) -> None:
        self._server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def start(self) -> None:
        self._thread.start()
        for _ in range(200):
            if self._server.started:
                return
            time.sleep(0.05)
        raise RuntimeError("source server did not start in time")

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=5)


def test_cross_dao_claim_full_loop(tmp_path: Path) -> None:
    # ── 源 DAO:真服务 + 发布一个任务 ──
    src_ws = tmp_path / "source"
    src_app = create_app(src_ws, require_console_auth=False)
    src_port = _free_port()
    src = _BgServer(src_app, src_port)
    src.start()
    src_url = f"http://127.0.0.1:{src_port}"
    try:
        # 经同一 app 的 TestClient 发布(与运行中的服务共享 workspace/feed)。
        ann = TestClient(src_app).post(
            "/api/v2/market/announce",
            json={"title": "cross-dao", "capability_set": ["code_review"], "reward_minor": 9},
        ).json()
        aid = ann["announcement_id"]

        # ── 编排 DAO:spawn agent + 注入联邦缓存(来源=源 DAO 真 URL)──
        orch_app = create_app(tmp_path / "orch", require_console_auth=False)
        orch = TestClient(orch_app)
        sp = orch.post(
            "/api/v2/agents/spawn",
            json={"kind": "mock", "label": "claimer", "capabilities": []},
        ).json()
        did, agent_id = sp["did"], sp["agent_id"]

        cache = FederationCache()
        cache.replace_all({
            aid: {"ann": TaskAnnouncement.from_dict(ann), "source": src_url},
        })
        orch_app.state.market_fed_cache = cache

        try:
            # ── 一键跨 DAO 认领(agent 启动时序 → not-yet-authorized 退避重试)──
            r = orch.post(
                "/api/v2/market/federated/claim",
                json={"announcement_id": aid, "agent_did": did},
            )
            for _ in range(20):
                if "not-yet-authorized" not in r.text:
                    break
                time.sleep(0.5)
                r = orch.post(
                    "/api/v2/market/federated/claim",
                    json={"announcement_id": aid, "agent_did": did},
                )
            assert r.status_code == 200, r.text
            assert r.json()["claimed"] is True
            # 认领方 = 编排节点的 agent(它用自己私钥签的)。
            assert r.json()["claimant_did"] == did
            # 关键:**源 DAO** 的 ClaimStore 真落了这条认领(权威在主 DAO)。
            assert ClaimStore(src_ws).is_claimed(aid)
        finally:
            orch.post(f"/api/v2/agents/{agent_id}/stop")
    finally:
        src.stop()
