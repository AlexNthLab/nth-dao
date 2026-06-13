"""温层端点 /api/v2/agents/{did}/summarize:服务端签名摘要 + 验签。

spawn 真子进程 agent → POST 一段对话 → 拿回 SummaryRecord,verified=True
(signer==agent + 绑定确切原文/摘要)。这是 UI 触发温层压缩的后端 keystone。
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

pytest.importorskip("nacl")
pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.web import create_app

MSGS = [
    {"message_id": "1", "sender_label": "you", "body": "settle_trade 有并发问题吗"},
    {"message_id": "2", "sender_label": "agent", "body": "有,双付 TOCTOU"},
    {"message_id": "3", "sender_label": "you", "body": "怎么修"},
    {"message_id": "4", "sender_label": "agent", "body": "行级锁 + 同事务标记已处理"},
]


def test_summarize_returns_verified_signed_summary(tmp_path: Path) -> None:
    app = create_app(workspace=tmp_path, require_console_auth=False)
    client = TestClient(app)
    agent_id = None
    try:
        r = client.post("/api/v2/agents/spawn", json={
            "kind": "mock", "label": "summarizer",
            "capabilities": ["a2a:message_send"]})
        assert r.status_code == 201, r.text
        did = r.json()["did"]
        agent_id = r.json()["agent_id"]

        # 轮询等 agent authorized(端点本身不轮询,和 /ask 一致;
        # not-yet-authorized 期间端点回 401)。
        body = None
        for _ in range(20):
            rr = client.post(f"/api/v2/agents/{did}/summarize",
                             json={"messages": MSGS, "conversation_id": "dm-x"})
            if rr.status_code == 200:
                body = rr.json()
                break
            if "not-yet-authorized" in rr.text:
                time.sleep(0.5)
                continue
            assert False, f"unexpected {rr.status_code}: {rr.text}"
        assert body is not None, "summarize 未在窗口内返回"

        # 服务端验签通过(mock 也签真 receipt)。
        assert body["verified"] is True, body.get("reason")
        assert body["covered_message_ids"] == ["1", "2", "3", "4"]
        assert body["agent_did"] == did
        assert body["summary_text"]  # 非空(mock ack)
        assert len(body["transcript_sha256"]) == 64
        assert isinstance(body["receipt"], dict)

        # 拿回的 receipt 可被独立重验(同后端工具)。
        from nth_dao.conversation.summary import verify_summary
        ok, why = verify_summary(
            body["receipt"], summary_text=body["summary_text"],
            messages=MSGS, expected_signer=did, instruction=body["instruction"])
        assert ok, why
    finally:
        if agent_id:
            try:
                client.post(f"/api/v2/agents/{agent_id}/stop")
            except Exception:
                pass
