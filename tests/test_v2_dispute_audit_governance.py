"""Phase 4c:dispute / audit / governance 端点接 hub spine 的集成测试。

走 HTTP 把整条竖切跑通:发任务 → 开争议 → 列争议 → 裁决 → 证据回放 → 读策略。
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("nacl")

from fastapi.testclient import TestClient

from nth_dao.dispute import sign_dispute_statement
from nth_dao.identity import AgentIdentity
from nth_dao.web import create_app


def test_dispute_audit_governance_vertical(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)

    r = client.post("/api/v2/market/announce", json={
        "title": "争议目标", "capability_set": ["code_review"], "reward_minor": 4})
    assert r.status_code == 200, r.text
    aid = r.json()["announcement_id"]

    opener = AgentIdentity.generate()
    arbiter = AgentIdentity.generate()

    opened = sign_dispute_statement(
        signer=opener, statement_type="open", announcement_id=aid,
        body={"reason": "未交付"})
    ro = client.post("/api/v2/disputes", json={"statement": opened})
    assert ro.status_code == 200, ro.text
    did = ro.json()["dispute_id"]
    assert did == opened["dispute_id"]

    lst = client.get("/api/v2/disputes").json()
    assert any(d["dispute_id"] == did and d["status"] == "open" for d in lst)

    resolved = sign_dispute_statement(
        signer=arbiter, statement_type="resolve", announcement_id=aid,
        dispute_id=did, body={"ruling": "rejected"})
    rr = client.post("/api/v2/disputes", json={"statement": resolved})
    assert rr.status_code == 200, rr.text

    rec = {d["dispute_id"]: d for d in client.get("/api/v2/disputes").json()}[did]
    assert rec["status"] == "resolved"
    assert rec["arbiter_did"] == arbiter.as_did()
    assert rec["arbiter_authorized"] is None   # 未立宪 → 无从判定授权

    # 证据链:announce + dispute.open + dispute.resolve,逐项全验。
    ev = client.get(f"/api/v2/market/{aid}/evidence").json()
    assert ev["all_verified"] is True
    types = [i["type"] for i in ev["items"]]
    assert "market.announce" in types
    assert "dispute.open" in types
    assert "dispute.resolve" in types

    gov = client.get("/api/v2/governance/policy").json()
    assert gov["established"] is False and gov["version"] == 0

    # 无效声明(篡改签名)→ 400,不落 spine。
    bad = dict(opened)
    bad["sig"] = "tampered"
    rb = client.post("/api/v2/disputes", json={"statement": bad})
    assert rb.status_code == 400


def test_empty_views_without_data(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    assert client.get("/api/v2/disputes").json() == []
    assert client.get("/api/v2/market/nonexistent/evidence").json()["items"] == []
    gov = client.get("/api/v2/governance/policy").json()
    assert gov["established"] is False
