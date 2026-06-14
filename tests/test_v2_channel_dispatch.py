"""P2 端到端:频道里的 agent 监听并自动回帖。

起真子进程 mock agent → 加进频道(按 did)→ 人类发消息 → 断言该 agent
用自己的 did 自动回帖到频道。同时验证防环:agent 的回帖不再触发新一轮。
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.web import create_app


def test_dispatch_semaphore_is_bounded() -> None:
    # 审查隐患①修复:派发并发有界。能 acquire 到上限,满了非阻塞返回 False,
    # 归还后恢复 —— 证明信号量是 BoundedSemaphore 且配额可回收。
    from nth_dao.web.v2_api import (
        _CHANNEL_DISPATCH_MAX, _CHANNEL_DISPATCH_SEM,
    )

    acquired = [_CHANNEL_DISPATCH_SEM.acquire(blocking=False)
                for _ in range(_CHANNEL_DISPATCH_MAX)]
    try:
        assert all(acquired)
        assert _CHANNEL_DISPATCH_SEM.acquire(blocking=False) is False  # 满了→丢弃
    finally:
        for _ in range(_CHANNEL_DISPATCH_MAX):
            _CHANNEL_DISPATCH_SEM.release()
    # 全部归还后,配额恢复。
    assert _CHANNEL_DISPATCH_SEM.acquire(blocking=False) is True
    _CHANNEL_DISPATCH_SEM.release()


def test_channel_agent_listens_and_replies(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)

    sp = client.post(
        "/api/v2/agents/spawn",
        json={"kind": "mock", "label": "chatter", "capabilities": []},
    )
    assert sp.status_code in (200, 201), sp.text
    agent = sp.json()
    agent_id = agent["agent_id"]
    agent_did = agent["did"]
    assert agent.get("a2a_port"), "spawned agent must expose an a2a_port"

    try:
        # 建频道 + 把 agent 按 did 加进成员。
        client.post("/api/v2/channels", json={"name": "engineering"})
        j = client.post(
            "/api/v2/channels/engineering/join", json={"agent_id": agent_did},
        )
        assert j.status_code == 200, j.text
        assert agent_did in j.json()["member_ids"]

        def agent_replies() -> list:
            msgs = client.get("/api/v2/channels/engineering/messages").json()
            return [m for m in msgs if m["sender_id"] == agent_did]

        # 人类发消息会触发派发(后台)。agent spawn 后需 ~1 tick 载入 cap_token
        # 才能被驱动;反复发 + 轮询,直到出现该 agent 的回帖。
        got = []
        for _ in range(20):
            client.post(
                "/api/v2/channels/engineering/messages",
                json={"agent_id": "admin", "body": "hello agents"},
            )
            for _ in range(6):
                time.sleep(0.5)
                got = agent_replies()
                if got:
                    break
            if got:
                break

        assert got, "channel agent did not reply within timeout"
        # 关键:回帖的 sender 就是这个 agent(它自己回的)。
        assert got[0]["sender_id"] == agent_did
        assert got[0]["body"].strip() != ""

        # 防环:agent 的回帖经内部 API 落盘,不走 HTTP 端点 → 不再触发派发。
        # 等一会儿,确认 agent 回帖数没有失控增长(没有 agent↔agent 刷屏)。
        n1 = len(agent_replies())
        time.sleep(2.0)
        n2 = len(agent_replies())
        assert n2 - n1 <= 1, f"runaway agent replies: {n1} -> {n2}"
    finally:
        client.post(f"/api/v2/agents/{agent_id}/stop")
