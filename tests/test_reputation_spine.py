"""信誉层:从 spine 事件派生可验证贡献 + 争议归属(顺序无关)。"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.dispute import record_dispute, sign_dispute_statement
from nth_dao.identity import AgentIdentity
from nth_dao.market.announcement import sign_announcement
from nth_dao.reputation_spine import ReputationProjection
from nth_dao.spine import SignedEventLog, replay


def _id() -> AgentIdentity:
    return AgentIdentity.generate()


def _claim_payload(aid, claimant, pub):
    return {
        "announcement_id": aid, "claimant_did": claimant.as_did(),
        "publisher_did": pub.as_did(),
    }


def test_reputation_from_spine(tmp_path: Path) -> None:
    node, pub, agent = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    a1 = sign_announcement(publisher=pub, title="t1", capability_set=["x"])
    a2 = sign_announcement(publisher=pub, title="t2", capability_set=["x"])
    spine.append("market.announce", a1.to_dict())
    spine.append("market.announce", a2.to_dict())
    spine.append("market.claim", _claim_payload(a1.announcement_id, agent, pub))
    spine.append("market.claim", _claim_payload(a2.announcement_id, agent, pub))
    record_dispute(spine, sign_dispute_statement(
        signer=pub, statement_type="open", announcement_id=a1.announcement_id,
        body={"reason": "x"}))

    ok, why = spine.verify_chain()
    assert ok, why
    proj = ReputationProjection()
    replay(spine.read_all(), proj)

    ar = proj.get(agent.as_did())
    assert ar.tasks_claimed == 2
    assert ar.disputed_claims == 1
    assert ar.score == 1

    pr = proj.get(pub.as_did())
    assert pr.tasks_published == 2
    assert pr.tasks_claimed == 0

    top = proj.top()
    assert top[0].did == agent.as_did()      # score 1 > pub score 0


def test_order_independent_dispute_before_claim(tmp_path: Path) -> None:
    node, pub, agent = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    a1 = sign_announcement(publisher=pub, title="t", capability_set=["x"])
    spine.append("market.announce", a1.to_dict())
    # 争议先到、认领后到 —— 集合交集法仍正确归属。
    record_dispute(spine, sign_dispute_statement(
        signer=pub, statement_type="open", announcement_id=a1.announcement_id))
    spine.append("market.claim", _claim_payload(a1.announcement_id, agent, pub))

    proj = ReputationProjection()
    replay(spine.read_all(), proj)
    ar = proj.get(agent.as_did())
    assert ar.tasks_claimed == 1 and ar.disputed_claims == 1 and ar.score == 0


def test_published_and_claimed_dedup_by_announcement(tmp_path: Path) -> None:
    # 对抗审查修复:同一公告出现两条 announce / claim 事件 → 各只计一次(对称去重)。
    node, pub, agent = _id(), _id(), _id()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    a1 = sign_announcement(publisher=pub, title="t", capability_set=["x"])
    spine.append("market.announce", a1.to_dict())
    spine.append("market.announce", a1.to_dict())                       # 重复 announce
    spine.append("market.claim", _claim_payload(a1.announcement_id, agent, pub))
    spine.append("market.claim", _claim_payload(a1.announcement_id, agent, pub))  # 重复 claim

    proj = ReputationProjection()
    replay(spine.read_all(), proj)
    assert proj.get(pub.as_did()).tasks_published == 1
    assert proj.get(agent.as_did()).tasks_claimed == 1


def test_unknown_did_zero(tmp_path: Path) -> None:
    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    proj = ReputationProjection()
    replay(spine.read_all(), proj)
    r = proj.get("did:key:zNobody")
    assert r.tasks_claimed == 0 and r.score == 0
    assert proj.all() == []
