"""信誉端点:/api/v2/reputation 从 spine 派生(发布计入 publisher)。"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("nacl")

from fastapi.testclient import TestClient

from nth_dao.web import create_app


def test_reputation_endpoint(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    for title in ("t1", "t2"):
        r = client.post("/api/v2/market/announce", json={
            "title": title, "capability_set": ["x"], "reward_minor": 0})
        assert r.status_code == 200, r.text

    lst = client.get("/api/v2/reputation").json()
    # 发布者 = 本节点身份 → tasks_published == 2。
    assert any(x["tasks_published"] == 2 for x in lst)
    assert all("score" in x for x in lst)

    one = client.get("/api/v2/reputation/did:key:zNobody").json()
    assert one["score"] == 0 and one["tasks_claimed"] == 0


def test_reputation_empty(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    assert client.get("/api/v2/reputation").json() == []


def test_accept_endpoint_lifts_reputation_to_delivery(tmp_path: Path) -> None:
    from nth_dao.cap_token import CAP_NTH_RECEIPT_SIGN, sign_cap_token
    from nth_dao.identity import AgentIdentity
    from nth_dao.market import ClaimStore, MarketFeed, claim_announcement

    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    # node 发布。
    r = client.post("/api/v2/market/announce", json={
        "title": "deliverable", "capability_set": ["code_review"], "reward_minor": 1})
    aid = r.json()["announcement_id"]

    # agent 认领(进程内,带 spine 双写 → market.claim 入 spine)。
    issuer, agent = AgentIdentity.generate(), AgentIdentity.generate()
    token = sign_cap_token(
        issuer=issuer, subject_did=agent.as_did(),
        capabilities=["code_review", CAP_NTH_RECEIPT_SIGN])
    claim_announcement(
        MarketFeed(tmp_path), ClaimStore(tmp_path), aid,
        claimant=agent, cap_token=token, spine=app.state.nth.spine)

    # 发布方(node)验收。
    ap = client.post(f"/api/v2/market/{aid}/accept",
                     json={"completer_did": agent.as_did()})
    assert ap.status_code == 200, ap.text

    rep = {x["did"]: x for x in client.get("/api/v2/reputation").json()}
    me = rep[agent.as_did()]
    assert me["tasks_claimed"] == 1
    assert me["tasks_accepted"] == 1
    assert me["score"] == 1                       # 交付被验收 → 计分

    # 给没认领的人验收 → 409。
    other = AgentIdentity.generate()
    assert client.post(f"/api/v2/market/{aid}/accept",
                       json={"completer_did": other.as_did()}).status_code == 409


def test_self_acceptance_rejected(tmp_path: Path) -> None:
    # 防 self-dealing:发布方给自己验收 → 400。
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    r = client.post("/api/v2/market/announce", json={
        "title": "t", "capability_set": ["x"], "reward_minor": 0})
    aid = r.json()["announcement_id"]
    pub_did = r.json()["publisher_did"]
    assert client.post(f"/api/v2/market/{aid}/accept",
                       json={"completer_did": pub_did}).status_code == 400
