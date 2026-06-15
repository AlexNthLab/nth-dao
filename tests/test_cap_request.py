"""授权收件箱(consent 层):cap 授予请求签验 + 生命周期 + 防张冠李戴。"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.authz import (
    CapRequestProjection,
    deny_cap_request,
    grant_cap_request,
    record_cap_request,
    sign_cap_request,
    verify_cap_request,
)
from nth_dao.cap_token import CAP_NTH_RECEIPT_SIGN, sign_cap_token, verify_cap_token
from nth_dao.identity import AgentIdentity
from nth_dao.spine import SignedEventLog, replay


def _id() -> AgentIdentity:
    return AgentIdentity.generate()


def _project(spine: SignedEventLog) -> CapRequestProjection:
    p = CapRequestProjection()
    replay(spine.read_all(), p)
    return p


def test_request_sign_verify_tamper() -> None:
    agent = _id()
    req = sign_cap_request(
        requester=agent, capabilities=["market:claim"], reason="claim task")
    ok, why = verify_cap_request(req)
    assert ok, why
    assert req["requester_did"] == agent.as_did()
    req["capabilities"] = ["admin:everything"]   # 篡改求权
    bad, _ = verify_cap_request(req)
    assert not bad


def test_lifecycle_request_then_grant(tmp_path: Path) -> None:
    node, agent = _id(), _id()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    req = sign_cap_request(
        requester=agent, capabilities=["market:claim", CAP_NTH_RECEIPT_SIGN],
        reason="认领任务 #x")
    record_cap_request(spine, req)
    rid = req["request_id"]

    rec = _project(spine).get(rid)
    assert rec is not None and rec.status == "pending"
    assert rec.requester_did == agent.as_did()

    token = grant_cap_request(
        spine, issuer=node, request_id=rid,
        requester_did=rec.requester_did, capabilities=rec.capabilities)
    assert verify_cap_token(token)[0]
    assert token["subject_did"] == agent.as_did()

    ok, why = spine.verify_chain()
    assert ok, why

    p2 = _project(spine)
    rec2 = p2.get(rid)
    assert rec2.status == "granted"
    assert rec2.cap_token["token_id"] == token["token_id"]
    assert rec2.decided_by_did == node.as_did()
    assert p2.pending() == []


def test_deny(tmp_path: Path) -> None:
    node, agent = _id(), _id()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    req = sign_cap_request(requester=agent, capabilities=["x"])
    record_cap_request(spine, req)
    deny_cap_request(spine, decider=node, request_id=req["request_id"],
                     reason="not trusted")
    rec = _project(spine).get(req["request_id"])
    assert rec.status == "denied" and rec.reason == "not trusted"


def test_record_rejects_invalid(tmp_path: Path) -> None:
    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    req = sign_cap_request(requester=_id(), capabilities=["x"])
    req["sig"] = "tampered"
    with pytest.raises(ValueError, match="invalid cap request"):
        record_cap_request(spine, req)


def test_grant_for_other_subject_not_adopted(tmp_path: Path) -> None:
    # 防张冠李戴:cap.grant 内嵌 token 的 subject 必须 == requester,否则不采纳。
    node, agent, other = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    req = sign_cap_request(requester=agent, capabilities=["x"])
    record_cap_request(spine, req)
    bad_token = sign_cap_token(
        issuer=node, subject_did=other.as_did(), capabilities=["x"])
    spine.append("cap.grant", {
        "request_id": req["request_id"], "cap_token": bad_token,
        "decided_by_did": node.as_did(), "decided_at_ms": 1})
    assert _project(spine).get(req["request_id"]).status == "pending"
