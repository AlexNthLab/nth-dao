"""Phase 3:争议声明签名/验签 + DisputeProjection 生命周期 + record_dispute。"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.dispute import (
    DisputeProjection,
    STATUS_OPEN,
    STATUS_RESOLVED,
    record_dispute,
    sign_dispute_statement,
    verify_dispute_statement,
)
from nth_dao.identity import AgentIdentity
from nth_dao.spine import SignedEventLog, replay


def _id() -> AgentIdentity:
    return AgentIdentity.generate()


def test_statement_sign_verify_and_tamper() -> None:
    party = _id()
    stmt = sign_dispute_statement(
        signer=party, statement_type="open", announcement_id="ann1",
        body={"reason": "未交付"},
    )
    ok, why = verify_dispute_statement(stmt)
    assert ok, why
    assert stmt["signer_did"] == party.as_did()
    # 篡改 body → 验签失败。
    stmt["body"]["reason"] = "改口"
    bad, _ = verify_dispute_statement(stmt)
    assert not bad


def test_projection_open_to_resolved(tmp_path: Path) -> None:
    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    opener = _id()
    arbiter = _id()

    opened = sign_dispute_statement(
        signer=opener, statement_type="open", announcement_id="annX",
        body={"reason": "交付不达标"},
    )
    did = opened["dispute_id"]
    record_dispute(spine, opened)
    record_dispute(spine, sign_dispute_statement(
        signer=opener, statement_type="evidence", announcement_id="annX",
        dispute_id=did, body={"note": "日志见附件"}))
    record_dispute(spine, sign_dispute_statement(
        signer=arbiter, statement_type="resolve", announcement_id="annX",
        dispute_id=did, body={"ruling": "upheld", "rationale": "证据充分"}))

    ok, why = spine.verify_chain()
    assert ok, why

    proj = DisputeProjection()
    replay(spine.read_all(), proj)
    rec = proj.get(did)
    assert rec is not None
    assert rec.status == STATUS_RESOLVED
    assert rec.opener_did == opener.as_did()
    assert rec.arbiter_did == arbiter.as_did()
    assert rec.ruling["ruling"] == "upheld"
    assert len(rec.statements) == 3
    assert proj.for_announcement("annX")[0].dispute_id == did


def test_record_dispute_rejects_invalid(tmp_path: Path) -> None:
    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    stmt = sign_dispute_statement(
        signer=_id(), statement_type="open", announcement_id="a")
    stmt["sig"] = "tampered"
    with pytest.raises(ValueError, match="invalid dispute"):
        record_dispute(spine, stmt)


def test_evidence_without_open_is_dropped(tmp_path: Path) -> None:
    # evidence/resolve 没有对应 open → 投影丢弃(归不到组)。
    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    party = _id()
    record_dispute(spine, sign_dispute_statement(
        signer=party, statement_type="evidence", announcement_id="a",
        dispute_id="ghost", body={"note": "孤儿证据"}))
    proj = DisputeProjection()
    replay(spine.read_all(), proj)
    assert proj.get("ghost") is None
    assert proj.all() == []
