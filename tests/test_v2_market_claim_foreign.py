"""XDAO-2:跨 DAO 认领·来源 DAO 侧 HTTP 端点 /market/{id}/claim-foreign。

源端点是关键安全面 —— 外部节点匿名提交预签认领。用 TestClient 直接签收据
(模拟外部 agent)打这个端点:记录成功 / auth ON 也匿名放行 / 伪造拒 / 冲突。
(agent 的 claim-sign a2a 方法 e2e 留到 XDAO-3 编排就位一起测。)
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("nacl")

from fastapi.testclient import TestClient

from nth_dao.cap_token import CAP_NTH_RECEIPT_SIGN, sign_cap_token
from nth_dao.identity import AgentIdentity
from nth_dao.market import MarketFeed, sign_announcement
from nth_dao.market.announcement import TaskAnnouncement
from nth_dao.market.claim import sign_claim_receipt
from nth_dao.web import create_app


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
        publisher=pub, title="t", capability_set=["code_review"], reward_minor=5)
    MarketFeed(tmp_path).publish(ann)
    _, cap, receipt = _sign_foreign(ann.to_dict())
    # 不带任何 Authorization → 仍应 200(中间件对本路径豁免)。
    r = c.post(
        f"/api/v2/market/{ann.announcement_id}/claim-foreign",
        json={"cap_token": cap, "receipt": receipt},
    )
    assert r.status_code == 200, r.text


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
