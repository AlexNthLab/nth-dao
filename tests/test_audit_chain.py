"""Phase 3:证据链回放 —— announce + claim + dispute 的有序、可验证重建。"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.audit import reconstruct_evidence
from nth_dao.dispute import record_dispute, sign_dispute_statement
from nth_dao.identity import AgentIdentity
from nth_dao.market.announcement import sign_announcement
from nth_dao.market.feed import MarketFeed
from nth_dao.market.projection import EVENT_MARKET_CLAIM
from nth_dao.spine import SignedEventLog


def _id() -> AgentIdentity:
    return AgentIdentity.generate()


def test_reconstruct_full_chain_all_verified(tmp_path: Path) -> None:
    node = _id()
    pub = _id()
    opener = _id()
    arbiter = _id()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    feed = MarketFeed(tmp_path / "ws", spine=spine)

    ann = sign_announcement(
        publisher=pub, title="审计目标", capability_set=["code_review"],
        reward_minor=3)
    feed.publish(ann)                                   # market.announce
    aid = ann.announcement_id

    spine.append(EVENT_MARKET_CLAIM, {                  # market.claim(元数据)
        "announcement_id": aid, "claimant_did": "did:key:zClaimant"})

    opened = sign_dispute_statement(
        signer=opener, statement_type="open", announcement_id=aid,
        body={"reason": "未交付"})
    record_dispute(spine, opened)                       # dispute.open
    record_dispute(spine, sign_dispute_statement(
        signer=arbiter, statement_type="resolve", announcement_id=aid,
        dispute_id=opened["dispute_id"], body={"ruling": "rejected"}))

    ok, why = spine.verify_chain()
    assert ok, why

    chain = reconstruct_evidence(spine.read_all(), aid)
    types = [i.type for i in chain.items]
    assert types == [
        "market.announce", "market.claim", "dispute.open", "dispute.resolve"]
    assert [i.seq for i in chain.items] == sorted(i.seq for i in chain.items)
    assert chain.all_verified, [(i.type, i.verified) for i in chain.items]


def test_other_announcement_excluded(tmp_path: Path) -> None:
    node = _id()
    pub = _id()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    feed = MarketFeed(tmp_path / "ws", spine=spine)
    a1 = sign_announcement(publisher=pub, title="A", capability_set=["x"])
    a2 = sign_announcement(publisher=pub, title="B", capability_set=["y"])
    feed.publish(a1)
    feed.publish(a2)
    chain = reconstruct_evidence(spine.read_all(), a1.announcement_id)
    assert len(chain.items) == 1
    assert chain.items[0].detail["announcement_id"] == a1.announcement_id


def test_tampered_dispute_statement_marked_unverified(tmp_path: Path) -> None:
    # 落盘后的 dispute 声明被改 → 该证据项 verified=False(整链不再 all_verified)。
    node = _id()
    pub = _id()
    opener = _id()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    feed = MarketFeed(tmp_path / "ws", spine=spine)
    ann = sign_announcement(publisher=pub, title="t", capability_set=["x"])
    feed.publish(ann)
    opened = sign_dispute_statement(
        signer=opener, statement_type="open", announcement_id=ann.announcement_id,
        body={"reason": "orig"})
    record_dispute(spine, opened)

    # 直接拿事件、改 body 再重建(模拟事件内嵌声明被篡改但 spine 行未动验证前)。
    events = list(spine.read_all())
    for ev in events:
        if ev.type == "dispute.open":
            ev.payload["body"]["reason"] = "tampered"
    chain = reconstruct_evidence(events, ann.announcement_id)
    open_item = [i for i in chain.items if i.type == "dispute.open"][0]
    assert open_item.verified is False
    assert chain.all_verified is False
