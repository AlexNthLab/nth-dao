"""v2 频道端点(P1:收编 8765 群聊到 /api/v2)。

只覆盖 P1 的 CRUD 数据层:建频道 / 发消息 / 列频道 / 列消息 / 加成员,
以及错误路径。P2 的 agent 监听派发另测。
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from nth_dao.cap_token import CAP_NTH_RECEIPT_SIGN, sign_cap_token
from nth_dao.execution_receipt import TimelineEntry, now_ms, sign_receipt
from nth_dao.identity import AgentIdentity
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
    messages = c.get(f"/api/v2/channels/{cid}/messages").json()
    assert messages[0]["body"] == "hello"
    assert any(
        message.get("dispatch_phase") == "failed"
        and message.get("status_source") == "hub"
        for message in messages[1:]
    )


def test_channel_listing_projects_linked_task_scope(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    created = client.post(
        "/api/v2/channels",
        json={"name": "checkout-debug", "topic": "Repair checkout"},
    )
    assert created.status_code == 200, created.text
    task = app.state.nth.groups.create_task(
        "Checkout repair",
        created_by="admin",
        channel_id="checkout-debug",
    )

    channels = client.get("/api/v2/channels").json()
    channel = next(row for row in channels if row["channel_id"] == "checkout-debug")

    assert channel["metadata"]["task_id"] == task.task_id
    assert channel["metadata"]["task_label"] == "Checkout repair"
    assert channel["metadata"]["dao_id"] == "home"


def test_channel_messages_page_backwards_without_overlap(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    groups = app.state.nth.groups
    groups.create_channel("history", created_by="admin")
    for index in range(205):
        groups.post_message("history", "admin", f"message-{index:03d}")

    latest = client.get(
        "/api/v2/channels/history/messages", params={"limit": 101},
    )
    assert latest.status_code == 200, latest.text
    latest_rows = latest.json()
    assert len(latest_rows) == 101
    assert latest_rows[0]["body"] == "message-104"
    assert latest_rows[-1]["body"] == "message-204"

    earlier = client.get(
        "/api/v2/channels/history/messages",
        params={
            "limit": 101,
            "before_message_id": latest_rows[0]["message_id"],
        },
    )
    assert earlier.status_code == 200, earlier.text
    earlier_rows = earlier.json()
    assert len(earlier_rows) == 101
    assert earlier_rows[0]["body"] == "message-003"
    assert earlier_rows[-1]["body"] == "message-103"
    assert {
        row["message_id"] for row in latest_rows
    }.isdisjoint(row["message_id"] for row in earlier_rows)

    missing = client.get(
        "/api/v2/channels/history/messages",
        params={"before_message_id": "missing-message"},
    )
    assert missing.status_code == 404


def test_channel_attachments_large_text_and_replies(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    assert client.post(
        "/api/v2/channels", json={"name": "documents"},
    ).status_code == 200

    uploaded = client.post(
        "/api/v2/channels/documents/attachments",
        params={"filename": "../evidence.txt", "actor_id": "admin"},
        content=b"signed evidence\n",
        headers={"content-type": "text/plain"},
    )
    assert uploaded.status_code == 200, uploaded.text
    attachment = uploaded.json()
    assert attachment["filename"] == "evidence.txt"
    assert attachment["size"] == len(b"signed evidence\n")
    assert len(attachment["sha256"]) == 64

    attachment_only = client.post(
        "/api/v2/channels/documents/messages",
        json={
            "agent_id": "admin",
            "body": "",
            "attachment_ids": [attachment["attachment_id"]],
        },
    )
    assert attachment_only.status_code == 200, attachment_only.text
    assert attachment_only.json()["attachments"] == [attachment]
    assert attachment_only.json()["body"] == ""

    downloaded = client.get(
        f"/api/v2/channels/documents/attachments/{attachment['attachment_id']}",
        params={"actor_id": "admin"},
    )
    assert downloaded.status_code == 200, downloaded.text
    assert downloaded.content == b"signed evidence\n"

    long_body = "A" * 20_000
    long_message = client.post(
        "/api/v2/channels/documents/messages",
        json={"agent_id": "admin", "body": long_body},
    )
    assert long_message.status_code == 200, long_message.text
    assert long_message.json()["body"] == long_body

    reply = client.post(
        "/api/v2/channels/documents/messages",
        json={
            "agent_id": "admin",
            "body": "Reply with evidence",
            "reply_to_message_id": attachment_only.json()["message_id"],
        },
    )
    assert reply.status_code == 200, reply.text
    assert reply.json()["reply_to"] == attachment_only.json()["message_id"]

    invalid_reply = client.post(
        "/api/v2/channels/documents/messages",
        json={
            "agent_id": "admin",
            "body": "bad reply",
            "reply_to_message_id": "not-in-this-channel",
        },
    )
    assert invalid_reply.status_code == 400


def test_channel_attachment_limits_and_membership(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    assert client.post(
        "/api/v2/channels", json={"name": "upload-limits"},
    ).status_code == 200

    oversized = client.post(
        "/api/v2/channels/upload-limits/attachments",
        params={"filename": "large.bin", "actor_id": "admin"},
        content=b"small",
        headers={"content-length": str(25 * 1024 * 1024 + 1)},
    )
    assert oversized.status_code == 413

    outsider = client.post(
        "/api/v2/channels/upload-limits/attachments",
        params={"filename": "private.txt", "actor_id": "outsider"},
        content=b"no access",
    )
    assert outsider.status_code == 403


def test_channel_messages_promote_receipt_metadata(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    c = TestClient(app)

    r = c.post("/api/v2/channels", json={"name": "general"})
    assert r.status_code == 200, r.text
    app.state.nth.groups.post_message(
        "general",
        sender_id="admin",
        body="receipt-backed reply",
        metadata={
            "nth_receipt_id": "r-channel-1",
            "nth_receipt_content_hash": "abc123",
        },
    )

    messages = c.get("/api/v2/channels/general/messages").json()
    signed = [m for m in messages if m["body"] == "receipt-backed reply"][0]
    assert signed["metadata"]["nth_receipt_id"] == "r-channel-1"
    assert signed["nth_receipt_id"] == "r-channel-1"
    assert signed["nth_receipt_content_hash"] == "abc123"


def test_receipt_detail_endpoint_returns_raw_receipt(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    c = TestClient(app)
    issuer = AgentIdentity.generate(label="issuer")
    signer = AgentIdentity.generate(label="agent")
    cap = sign_cap_token(
        issuer=issuer,
        subject_did=signer.as_did(),
        capabilities=[CAP_NTH_RECEIPT_SIGN],
        scope_task_id="mission-channel-1",
        scope_dao="home",
        scope_model_allowlist=["mock-model"],
        ttl_ms=60_000,
        token_id="cap-channel-detail-1",
    )
    receipt = sign_receipt(
        [
            TimelineEntry(
                timestamp=now_ms(),
                type="nth.agent_response",
                payload={"ok": True},
            )
        ],
        signer,
        goal_id="mission-channel-1",
        receipt_id="r-channel-detail-1",
        authorizing_cap_token=cap,
    )
    app.state.nth.receipts.save(receipt)

    no_token = c.get("/api/v2/receipts/r-channel-detail-1")
    assert no_token.status_code == 401, no_token.text

    headers = {"Authorization": f"Bearer {app.state.nth_console_token}"}
    r = c.get("/api/v2/receipts/r-channel-detail-1", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["receipt"]["receipt_id"] == "r-channel-detail-1"
    assert data["receipt"]["timeline"][0]["payload"]["ok"] is True
    assert data["verification"] == {
        "verified": True,
        "status": "verified",
        "reason": "",
    }
    assert data["summary"]["signer_did"] == signer.as_did()
    assert data["summary"]["goal_id"] == "mission-channel-1"
    assert data["summary"]["cap_scope"]["present"] is True
    assert data["summary"]["cap_scope"]["token_id"] == "cap-channel-detail-1"
    assert data["summary"]["cap_scope"]["capabilities"] == [CAP_NTH_RECEIPT_SIGN]
    assert data["summary"]["cap_scope"]["scope_task_id"] == "mission-channel-1"
    assert data["summary"]["cap_scope"]["scope_dao"] == "home"
    assert data["summary"]["cap_scope"]["scope_model_allowlist"] == ["mock-model"]

    assert c.get("/api/v2/receipts/no-such-receipt", headers=headers).status_code == 404
    assert c.get("/api/v2/receipts/..%2Fsecret", headers=headers).status_code == 404


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


def test_targeted_channel_message_rejects_non_member(tmp_path: Path) -> None:
    c = _client(tmp_path)
    c.post("/api/v2/channels", json={"name": "general"})
    response = c.post(
        "/api/v2/channels/general/messages",
        json={
            "agent_id": "admin",
            "body": "private instruction",
            "target_agent_dids": ["did:key:zNotAChannelMember"],
        },
    )
    assert response.status_code == 403
    messages = c.get("/api/v2/channels/general/messages").json()
    assert not any(m["body"] == "private instruction" for m in messages)
