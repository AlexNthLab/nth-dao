"""v2 频道端点(P1:收编 8765 群聊到 /api/v2)。

只覆盖 P1 的 CRUD 数据层:建频道 / 发消息 / 列频道 / 列消息 / 加成员,
以及错误路径。P2 的 agent 监听派发另测。
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.web import create_app


def _client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(tmp_path, require_console_auth=False))


def test_channel_crud_roundtrip(tmp_path: Path) -> None:
    c = _client(tmp_path)

    r = c.post("/api/v2/channels", json={"name": "general", "topic": "Team chat"})
    assert r.status_code == 200, r.text
    cid = r.json()["channel_id"]
    assert cid == "general"

    r = c.post(f"/api/v2/channels/{cid}/messages", json={"agent_id": "admin", "body": "hello"})
    assert r.status_code == 200, r.text
    assert r.json()["body"] == "hello"
    assert r.json()["sender_id"] == "admin"

    assert "general" in {x["channel_id"] for x in c.get("/api/v2/channels").json()}
    assert [m["body"] for m in c.get(f"/api/v2/channels/{cid}/messages").json()] == ["hello"]


def test_channel_join_adds_member(tmp_path: Path) -> None:
    c = _client(tmp_path)
    c.post("/api/v2/channels", json={"name": "general"})
    r = c.post("/api/v2/channels/general/join", json={"agent_id": "did:key:zWorker"})
    assert r.status_code == 200, r.text
    assert "did:key:zWorker" in r.json()["member_ids"]
    # 幂等:再加一次仍 200、不重复。
    r2 = c.post("/api/v2/channels/general/join", json={"agent_id": "did:key:zWorker"})
    assert r2.status_code == 200
    assert r2.json()["member_ids"].count("did:key:zWorker") == 1


def test_recreate_channel_does_not_clobber(tmp_path: Path) -> None:
    # 对抗审查回归:重复建同名频道不得冲掉已加入成员 / 已设 topic。
    # 用全新频道名(create_app 会预置 "general",避开它才测得准)。
    c = _client(tmp_path)
    r0 = c.post("/api/v2/channels", json={"name": "engineering", "topic": "v1"})
    assert r0.status_code == 200, r0.text
    assert r0.json()["topic"] == "v1"  # 全新频道,topic 确实落了
    c.post("/api/v2/channels/engineering/join", json={"agent_id": "did:key:zA"})
    # 同名重建 → 幂等返回既有,成员/topic 原样保留(不被重置)。
    r = c.post("/api/v2/channels", json={"name": "engineering", "topic": "v2-attempt"})
    assert r.status_code == 200, r.text
    assert "did:key:zA" in r.json()["member_ids"]
    assert r.json()["topic"] == "v1"
    ch = c.get("/api/v2/channels/engineering").json()
    assert "did:key:zA" in ch["member_ids"]
    assert ch["topic"] == "v1"


def test_channel_error_paths(tmp_path: Path) -> None:
    c = _client(tmp_path)
    # 不存在的频道发消息 → 404。
    assert c.post("/api/v2/channels/nope/messages",
                  json={"agent_id": "admin", "body": "x"}).status_code == 404
    # 不存在的频道 get → 404。
    assert c.get("/api/v2/channels/nope").status_code == 404
    # 空 body → 400。
    c.post("/api/v2/channels", json={"name": "general"})
    assert c.post("/api/v2/channels/general/messages",
                  json={"agent_id": "admin", "body": "   "}).status_code == 400
    # 空 name → 400。
    assert c.post("/api/v2/channels", json={"name": "  "}).status_code == 400
    # 加成员到不存在频道 → 404。
    assert c.post("/api/v2/channels/nope/join",
                  json={"agent_id": "did:key:zX"}).status_code == 404
