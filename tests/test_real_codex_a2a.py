"""真 backend 集成测试(门控,默认跳过)。

验证真·子进程 codex agent 经真 A2A /a2a/ask 干活 + 真签名 receipt + 协调
闭环。这是"真实测试"的固定版 —— 默认跳过,因为它需要:
  - codex CLI 在 PATH + 有可用额度;
  - 起真子进程 + 真 LLM 往返(慢,~20-40s)。
开关:环境变量 NTH_REAL_BACKEND_TEST=1。

断言只到**架构层**(回应非空 + receipt 三绑校验 + 协调 complete),不断言
LLM 输出质量(那是 backend/prompt 工程的事,与协调架构正交)。

历史:首次真实测试(2026-06-13)暴露并修复了 codex backend 的 Windows
GBK 解码崩溃(d7950da)—— mock 测不出,真实测试才暴露。
"""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

import pytest

pytest.importorskip("nacl")
pytest.importorskip("fastapi")

if not os.environ.get("NTH_REAL_BACKEND_TEST"):
    pytest.skip("真 backend 测试默认跳过;置 NTH_REAL_BACKEND_TEST=1 开启",
                allow_module_level=True)
if shutil.which("codex") is None:
    pytest.skip("codex CLI 不在 PATH", allow_module_level=True)

from fastapi.testclient import TestClient

from nth_dao.web import create_app
from nth_dao.orchestration.a2a_coordinator import (
    A2ACoordinator, A2APeer, PeerResponse, verify_work_receipt,
)
from nth_dao.orchestration.mission import Mission, MissionStep, MissionStatus
from nth_dao.orchestration.mission_store import MissionStore

TASK = "用一句话指出这段 Python 的 bug：def add(a, b): return a - b"


def _drive(client: TestClient, did: str, prompt: str, *, tries: int = 40) -> dict:
    for _ in range(tries):
        r = client.post(f"/api/v2/agents/{did}/ask", json={"prompt": prompt})
        if r.status_code == 200 and "not-yet-authorized" not in r.text:
            return r.json()["result"]
        time.sleep(2)
    raise AssertionError(f"agent {did[:16]} 未在窗口内就绪")


def test_real_codex_over_a2a_with_signed_receipt(tmp_path: Path) -> None:
    app = create_app(workspace=tmp_path, require_console_auth=False)
    client = TestClient(app)
    agent_id = None
    try:
        r = client.post("/api/v2/agents/spawn", json={
            "kind": "codex", "label": "real-codex",
            "capabilities": ["a2a:message_send"]})
        assert r.status_code == 201, r.text
        did = r.json()["did"]
        agent_id = r.json()["agent_id"]

        # 1) 真 codex 经真 A2A 干活,回应非空(GBK 崩溃回归:崩了就是空)。
        result = _drive(client, did, TASK)
        assert result.get("backend") == "codex"
        assert result.get("response", "").strip(), "真 codex 回应不应为空"

        # 2) 真签名工作 receipt 三绑校验(signer==agent + 请求/回应哈希)。
        ok, why = verify_work_receipt(
            result.get("receipt"), expected_signer=did,
            prompt=TASK, response=result.get("response", ""))
        assert ok, f"工作 receipt 校验失败: {why}"

        # 3) A2ACoordinator 把真 codex 当 peer 跑一步 mission 闭环。
        def dispatch(prompt: str) -> PeerResponse:
            res = _drive(client, did, prompt)
            return PeerResponse(text=res["response"], receipt=res.get("receipt"),
                                agent_did=res.get("agent_did", ""))
        peer = A2APeer(did=did, capabilities=["debug"], dispatch=dispatch)
        store = MissionStore(root=str(tmp_path / "m"))
        store.create(Mission(
            id="rt", title="real", goal="g", status=MissionStatus.ACTIVE.value,
            steps=[MissionStep(id="s1", description=TASK,
                               required_capabilities=["debug"],
                               acceptance_criteria={"min_length": 3})]))
        res = A2ACoordinator(store, [peer]).run_mission(
            "rt", output_key_for=lambda _s: None)
        assert res.complete and res.steps[0].ok
    finally:
        if agent_id:
            try:
                client.post(f"/api/v2/agents/{agent_id}/stop")
            except Exception:
                pass
