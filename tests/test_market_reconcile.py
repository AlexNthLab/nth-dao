"""Phase 2d:市场事实源迁移 —— backfill(旧→spine)+ reconcile(新旧对账)。"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.cap_token import CAP_NTH_RECEIPT_SIGN, sign_cap_token
from nth_dao.identity import AgentIdentity
from nth_dao.market import ClaimStore, MarketFeed, claim_announcement, sign_announcement
from nth_dao.market.reconcile import backfill_market_to_spine, reconcile_market
from nth_dao.spine import SignedEventLog


def _id() -> AgentIdentity:
    return AgentIdentity.generate()


def _ann(pub, title, caps=("code_review",)):
    return sign_announcement(
        publisher=pub, title=title, capability_set=list(caps), reward_minor=1)


def test_backfill_then_reconcile_in_sync(tmp_path: Path) -> None:
    pub = _id()
    feed = MarketFeed(tmp_path / "ws")          # 旧数据(无 spine,模拟 pre-spine)
    store = ClaimStore(tmp_path / "ws")
    a1 = _ann(pub, "t1")
    a2 = _ann(pub, "t2", caps=["x"])
    feed.publish(a1)
    feed.publish(a2)
    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())

    # 切前对账:全在 feed、不在 spine。
    r0 = reconcile_market(feed, store, spine)
    assert not r0["in_sync"]
    assert set(r0["only_in_feed"]) == {a1.announcement_id, a2.announcement_id}

    stats = backfill_market_to_spine(feed, store, spine)
    assert stats["announcements_added"] == 2
    ok, why = spine.verify_chain()
    assert ok, why

    r1 = reconcile_market(feed, store, spine)
    assert r1["in_sync"], r1
    assert r1["spine_open"] == 2

    # 幂等:再 backfill 不重复。
    assert backfill_market_to_spine(feed, store, spine)["announcements_added"] == 0


def test_backfill_carries_claims_excluded_from_open(tmp_path: Path) -> None:
    pub, issuer, claimant = _id(), _id(), _id()
    feed = MarketFeed(tmp_path / "ws")
    store = ClaimStore(tmp_path / "ws")
    a1 = _ann(pub, "t")
    feed.publish(a1)
    token = sign_cap_token(
        issuer=issuer, subject_did=claimant.as_did(),
        capabilities=["code_review", CAP_NTH_RECEIPT_SIGN])
    claim_announcement(feed, store, a1.announcement_id,
                       claimant=claimant, cap_token=token)

    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    stats = backfill_market_to_spine(feed, store, spine)
    assert stats["announcements_added"] == 1
    assert stats["claims_added"] == 1

    r = reconcile_market(feed, store, spine)
    assert r["in_sync"], r
    assert r["feed_open"] == 0 and r["spine_open"] == 0   # 已认领 → 都不 open


def test_dualwrite_already_in_sync(tmp_path: Path) -> None:
    # 经双写路径写入的,无需 backfill 即 in_sync。
    pub = _id()
    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    feed = MarketFeed(tmp_path / "ws", spine=spine)
    store = ClaimStore(tmp_path / "ws")
    feed.publish(_ann(pub, "t"))
    r = reconcile_market(feed, store, spine)
    assert r["in_sync"], r
    assert r["spine_open"] == 1


def test_reconcile_detects_only_in_spine(tmp_path: Path) -> None:
    pub = _id()
    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    feed = MarketFeed(tmp_path / "ws")
    store = ClaimStore(tmp_path / "ws")
    ghost = _ann(pub, "ghost")
    spine.append("market.announce", ghost.to_dict())   # 只进 spine
    r = reconcile_market(feed, store, spine)
    assert not r["in_sync"]
    assert r["only_in_spine"] == [ghost.announcement_id]
    assert r["only_in_feed"] == []
