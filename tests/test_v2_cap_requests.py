"""授权收件箱端点:HTTP 请求→列→批准/拒绝 + 不泄露 cap_token 全文。"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("nacl")

from fastapi.testclient import TestClient

from nth_dao.authz import sign_cap_request
from nth_dao.identity import AgentIdentity
from nth_dao.web import create_app


def _by_id(client):
    return {x["request_id"]: x for x in client.get("/api/v2/cap-requests").json()}


def test_request_approve_flow_no_token_leak(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    agent = AgentIdentity.generate()
    req = sign_cap_request(
        requester=agent, capabilities=["market:claim"], reason="认领任务")
    r = client.post("/api/v2/cap-requests", json={"statement": req})
    assert r.status_code == 200, r.text
    rid = r.json()["request_id"]
    assert rid == req["request_id"]

    rec = _by_id(client)[rid]
    assert rec["status"] == "pending"
    assert rec["requester_did"] == agent.as_did()
    assert "cap_token" not in rec          # 待批也不含全文

    ap = client.post(f"/api/v2/cap-requests/{rid}/approve")
    assert ap.status_code == 200, ap.text
    assert ap.json()["subject_did"] == agent.as_did()
    tid = ap.json()["token_id"]
    assert tid

    rec2 = _by_id(client)[rid]
    assert rec2["status"] == "granted"
    assert rec2["token_id"] == tid
    assert "cap_token" not in rec2         # 关键:绝不泄露 bearer 全文
    assert rec2.get("token_not_after", 0) > 0

    # 二次批准 → 409。
    assert client.post(f"/api/v2/cap-requests/{rid}/approve").status_code == 409


def test_deny_and_invalid_and_notfound(tmp_path: Path) -> None:
    app = create_app(tmp_path, require_console_auth=False)
    client = TestClient(app)
    agent = AgentIdentity.generate()
    req = sign_cap_request(requester=agent, capabilities=["x"])
    client.post("/api/v2/cap-requests", json={"statement": req})
    rid = req["request_id"]

    d = client.post(f"/api/v2/cap-requests/{rid}/deny", json={"reason": "untrusted"})
    assert d.status_code == 200
    assert _by_id(client)[rid]["status"] == "denied"

    bad = dict(req)
    bad["sig"] = "tampered"
    assert client.post(
        "/api/v2/cap-requests", json={"statement": bad}).status_code == 400
    assert client.post("/api/v2/cap-requests/nope/approve").status_code == 404
