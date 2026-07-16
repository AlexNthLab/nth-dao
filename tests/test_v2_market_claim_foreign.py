"""XDAO-2:跨 DAO 认领·来源 DAO 侧 HTTP 端点 /market/{id}/claim-foreign。

源端点是关键安全面 —— 外部节点匿名提交预签认领。用 TestClient 直接签收据
(模拟外部 agent)打这个端点:记录成功 / auth ON 也匿名放行 / 伪造拒 / 冲突。
(agent 的 claim-sign a2a 方法 e2e 留到 XDAO-3 编排就位一起测。)
"""
from __future__ import annotations

from pathlib import Path
import asyncio
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("nacl")

from fastapi.testclient import TestClient

from nth_dao.cap_token import CAP_NTH_RECEIPT_SIGN, sign_cap_token
from nth_dao.identity import AgentIdentity
from nth_dao.market import MarketFeed, sign_announcement
from nth_dao.market.announcement import TaskAnnouncement
from nth_dao.market.claim import sign_claim_receipt
from nth_dao.market.claim_ack import verify_authority_claim_ack
from nth_dao.web import create_app
from nth_dao.web import _FederationBodyLimitMiddleware


def _sign_foreign(ann_dict, caps=("code_review",)):
    """模拟外部 agent:自签 cap_token + ClaimReceipt。"""
    agent = AgentIdentity.generate(label="foreign-agent")
    ann = TaskAnnouncement.from_dict(ann_dict)
    cap = sign_cap_token(
        issuer=agent, subject_did=agent.as_did(),
        capabilities=[*caps, CAP_NTH_RECEIPT_SIGN],
    )
    return agent, cap, sign_claim_receipt(ann, agent, cap)


def test_claim_foreign_records(tmp_path: Path) -> None:
    c = TestClient(create_app(tmp_path, require_console_auth=False))
    ann = c.post(
        "/api/v2/market/announce",
        json={"title": "t", "capability_set": ["code_review"], "reward_minor": 5},
    ).json()
    aid = ann["announcement_id"]
    agent, cap, receipt = _sign_foreign(ann)

    r = c.post(
        f"/api/v2/market/{aid}/claim-foreign",
        json={"cap_token": cap, "receipt": receipt},
    )
    assert r.status_code == 200, r.text
    assert r.json()["claimed"] is True
    assert r.json()["claimant_did"] == agent.as_did()
    assert r.json()["foreign"] is True
    authority_ack = r.json()["authority_ack"]
    assert r.json()["authority_ack_id"] == authority_ack["ack_id"]
    assert verify_authority_claim_ack(
        authority_ack,
        expected_authority_did=c.app.state.nth.node_identity.as_did(),
        expected_claimant_did=agent.as_did(),
        expected_claim_receipt=receipt,
    ) == (True, "ok")
    # 已认领 → 不再出现在开放广场。
    open_ids = {x["announcement_id"] for x in c.get("/api/v2/market/open").json()}
    assert aid not in open_ids


def test_claim_foreign_anonymous_when_auth_on(tmp_path: Path) -> None:
    # 关键:auth ON 时,claim-foreign 仍**匿名放行**(外部节点没本地 token)。
    app = create_app(tmp_path, require_console_auth=True)
    c = TestClient(app)
    # 直接经 feed 发布(绕过 HTTP 写鉴权),造一条公告。
    pub = AgentIdentity.generate(label="pub")
    ann = sign_announcement(
        publisher=pub,
        authority_did=app.state.nth.node_identity.as_did(),
        title="t",
        capability_set=["code_review"],
        reward_minor=5,
    )
    MarketFeed(tmp_path).publish(ann)
    _, cap, receipt = _sign_foreign(ann.to_dict())
    # 不带任何 Authorization → 仍应 200(中间件对本路径豁免)。
    r = c.post(
        f"/api/v2/market/{ann.announcement_id}/claim-foreign",
        json={"cap_token": cap, "receipt": receipt},
    )
    assert r.status_code == 200, r.text


def test_claim_foreign_rejects_valid_but_undelegated_mirror_feed(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    publisher = AgentIdentity.generate(label="external-publisher")
    announcement = sign_announcement(
        publisher=publisher,
        title="not delegated to this node",
        capability_set=["code_review"],
    )
    MarketFeed(tmp_path).publish(announcement)
    _, cap_token, receipt = _sign_foreign(announcement.to_dict())

    response = client.post(
        f"/api/v2/market/{announcement.announcement_id}/claim-foreign",
        json={"cap_token": cap_token, "receipt": receipt},
    )

    assert response.status_code == 409
    assert "not the signed authority" in response.text


def test_claim_foreign_rejects_forged(tmp_path: Path) -> None:
    c = TestClient(create_app(tmp_path, require_console_auth=False))
    ann = c.post(
        "/api/v2/market/announce",
        json={"title": "t", "capability_set": ["code_review"]},
    ).json()
    _, cap, receipt = _sign_foreign(ann)
    receipt["timeline"][0]["payload"]["reward_minor"] = 999_999  # 篡改签名体
    r = c.post(
        f"/api/v2/market/{ann['announcement_id']}/claim-foreign",
        json={"cap_token": cap, "receipt": receipt},
    )
    assert r.status_code == 403, r.text


def test_claim_foreign_conflict(tmp_path: Path) -> None:
    c = TestClient(create_app(tmp_path, require_console_auth=False))
    ann = c.post(
        "/api/v2/market/announce",
        json={"title": "t", "capability_set": ["code_review"]},
    ).json()
    aid = ann["announcement_id"]
    _, capA, recA = _sign_foreign(ann)
    assert c.post(
        f"/api/v2/market/{aid}/claim-foreign",
        json={"cap_token": capA, "receipt": recA},
    ).status_code == 200
    _, capB, recB = _sign_foreign(ann)  # 不同 agent
    r = c.post(
        f"/api/v2/market/{aid}/claim-foreign",
        json={"cap_token": capB, "receipt": recB},
    )
    assert r.status_code == 409, r.text


def test_claim_foreign_rejects_oversized_body_before_json_parsing(
    tmp_path: Path,
) -> None:
    client = TestClient(create_app(tmp_path, require_console_auth=True))
    body = b'{"cap_token":{"padding":"' + (b"x" * (257 * 1024)) + b'"}}'

    response = client.post(
        "/api/v2/market/missing/claim-foreign",
        content=body,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert "256 KiB" in response.text


def test_claim_foreign_chunked_body_is_bounded_without_content_length() -> None:
    async def drain(_scope, receive, send):
        while True:
            message = await receive()
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    chunks = [
        {"type": "http.request", "body": b"x" * (200 * 1024), "more_body": True},
        {"type": "http.request", "body": b"x" * (60 * 1024), "more_body": False},
    ]
    sent: list[dict] = []

    async def receive():
        return chunks.pop(0)

    async def send(message):
        sent.append(message)

    asyncio.run(_FederationBodyLimitMiddleware(drain)(
        {
            "type": "http", "method": "POST",
            "path": "/api/v2/market/missing/claim-foreign", "headers": [],
        },
        receive,
        send,
    ))

    assert sent[0]["status"] == 413


def test_federation_hello_body_is_bounded_before_json_parsing() -> None:
    async def drain(_scope, receive, send):
        while True:
            message = await receive()
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    chunks = [{
        "type": "http.request",
        "body": b"x" * (17 * 1024),
        "more_body": False,
    }]
    sent: list[dict] = []

    async def receive():
        return chunks.pop(0)

    async def send(message):
        sent.append(message)

    asyncio.run(_FederationBodyLimitMiddleware(drain)(
        {
            "type": "http", "method": "POST",
            "path": "/api/v2/market/federation/hello", "headers": [],
        },
        receive,
        send,
    ))

    assert sent[0]["status"] == 413


def test_claim_foreign_has_per_source_and_global_rate_limit(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    app.state.market_fed_foreign_claim_limiter = SimpleNamespace(
        check=lambda _key: SimpleNamespace(
            allowed=False, retry_after_seconds=7.2,
        ),
    )
    app.state.market_fed_foreign_claim_global_limiter = SimpleNamespace(
        check=lambda _key: SimpleNamespace(
            allowed=True, retry_after_seconds=0.0,
        ),
    )

    response = TestClient(app).post(
        "/api/v2/market/missing/claim-foreign",
        json={"cap_token": {}, "receipt": {}},
    )

    assert response.status_code == 429
    assert response.headers["retry-after"] == "7"


def test_claim_foreign_global_denial_short_circuits_per_source_limiter(
    tmp_path: Path,
) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    app.state.market_fed_foreign_claim_global_limiter = SimpleNamespace(
        check=lambda _key: SimpleNamespace(
            allowed=False, retry_after_seconds=9.0,
        ),
    )
    app.state.market_fed_foreign_claim_limiter = SimpleNamespace(
        check=lambda _key: (_ for _ in ()).throw(
            AssertionError("per-source limiter should not be touched"),
        ),
    )

    response = TestClient(app).post(
        "/api/v2/market/missing/claim-foreign",
        json={"cap_token": {}, "receipt": {}},
    )

    assert response.status_code == 429
    assert response.headers["retry-after"] == "9"


def test_claim_foreign_rejects_unknown_request_fields(tmp_path: Path) -> None:
    response = TestClient(create_app(tmp_path, require_console_auth=False)).post(
        "/api/v2/market/missing/claim-foreign",
        json={"cap_token": {}, "receipt": {}, "unexpected": True},
    )

    assert response.status_code == 422
