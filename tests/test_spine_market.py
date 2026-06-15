"""Phase 2:MarketFeed → spine 影子双写 + MarketAnnounceProjection 一致性。

证明:publish 时 feed 与 spine 双写;spine 事件流经投影能重建出与 feed.poll
**一致**的开放公告视图。且不传 spine 时 feed 行为完全不变(回归)。
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.cap_token import CAP_NTH_RECEIPT_SIGN, sign_cap_token
from nth_dao.identity import AgentIdentity
from nth_dao.market import ClaimStore, claim_announcement
from nth_dao.market.announcement import sign_announcement
from nth_dao.market.feed import MarketFeed
from nth_dao.market.projection import (
    EVENT_MARKET_CLAIM,
    MarketAnnounceProjection,
)
from nth_dao.spine import SignedEventLog, replay

_FUTURE = 10_000_000_000_000   # 远未来 ms,用来判过期


def _ann(pub: AgentIdentity, title: str, *, not_after: int = 0):
    return sign_announcement(
        publisher=pub, title=title, capability_set=["code_review"],
        reward_minor=1, not_after=not_after,
    )


def test_feed_shadow_writes_to_spine_and_projects(tmp_path: Path) -> None:
    node = AgentIdentity.generate()
    pub = AgentIdentity.generate()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    feed = MarketFeed(tmp_path / "ws", spine=spine)

    a1 = _ann(pub, "t1")
    a2 = _ann(pub, "t2")
    a_exp = _ann(pub, "old", not_after=1)   # not_after=1ms → 远未来视角已过期
    for a in (a1, a2, a_exp):
        feed.publish(a)

    # feed 视图(现有行为):非过期 2 条。
    feed_ids = {
        a.announcement_id
        for a in feed.poll(now_ms_override=_FUTURE).announcements
    }
    assert feed_ids == {a1.announcement_id, a2.announcement_id}

    # spine 链完好。
    ok, why = spine.verify_chain()
    assert ok, why

    # spine 投影重建出**同一**开放视图。
    proj = MarketAnnounceProjection()
    replay(spine.read_all(), proj)
    proj_ids = {a.announcement_id for a in proj.open(now_ms_override=_FUTURE)}
    assert proj_ids == feed_ids
    assert proj.get(a1.announcement_id) is not None
    assert proj.get(a_exp.announcement_id) is not None   # 在册但 open 不含


def test_feed_without_spine_unchanged(tmp_path: Path) -> None:
    # 回归:不传 spine,行为与从前一致,且不产生 spine 文件。
    pub = AgentIdentity.generate()
    feed = MarketFeed(tmp_path / "ws")
    a1 = _ann(pub, "t")
    feed.publish(a1)
    got = feed.get(a1.announcement_id)
    assert got is not None
    assert got.announcement_id == a1.announcement_id


def test_claim_event_excludes_from_open(tmp_path: Path) -> None:
    # claim 事件让公告从 open 排除(Phase 2b claim 双写的预留口径)。
    node = AgentIdentity.generate()
    pub = AgentIdentity.generate()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    feed = MarketFeed(tmp_path / "ws", spine=spine)
    a1 = _ann(pub, "t")
    feed.publish(a1)
    spine.append(EVENT_MARKET_CLAIM, {"announcement_id": a1.announcement_id})

    proj = MarketAnnounceProjection()
    replay(spine.read_all(), proj)
    assert proj.open() == []
    assert proj.open(include_claimed=True)[0].announcement_id == a1.announcement_id


def test_real_claim_dual_writes_and_projection_excludes(tmp_path: Path) -> None:
    # Phase 2c:真实认领(claim_announcement)在 CAS 成功后双写 market.claim;
    # spine 重建出"announce 后被 claim 排除"的开放视图。
    node = AgentIdentity.generate()
    issuer = AgentIdentity.generate()
    pub = AgentIdentity.generate()
    claimant = AgentIdentity.generate()
    spine = SignedEventLog(tmp_path / "spine.jsonl", node)
    feed = MarketFeed(tmp_path / "ws", spine=spine)
    store = ClaimStore(tmp_path / "ws")

    a1 = _ann(pub, "claimable")
    feed.publish(a1)   # market.announce → spine

    token = sign_cap_token(
        issuer=issuer, subject_did=claimant.as_did(),
        capabilities=["code_review", CAP_NTH_RECEIPT_SIGN],
    )
    out = claim_announcement(
        feed, store, a1.announcement_id,
        claimant=claimant, cap_token=token, spine=spine,
    )
    assert out.claim_record["status"] == "claimed"

    ok, why = spine.verify_chain()
    assert ok, why
    assert [e.type for e in spine.read_all()] == ["market.announce", "market.claim"]

    proj = MarketAnnounceProjection()
    replay(spine.read_all(), proj)
    assert proj.open() == []   # 已认领 → 不在 open
    assert proj.open(include_claimed=True)[0].announcement_id == a1.announcement_id
