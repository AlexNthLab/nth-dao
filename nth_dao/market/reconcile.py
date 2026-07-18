"""市场事实源迁移工具:backfill(旧 store → spine)+ reconcile(新旧对账)。

Phase 2d:把 ``/market/open`` 的读路径从 feed+ClaimStore 切到 spine 投影**之前**,
先 (1) backfill 把既有公告/认领补进 spine(幂等),(2) reconcile 证明两者的 open
集合一致。教科书式"shadow-compare before flip":对账 ``in_sync`` 后再切读、且可
随时秒回退。

口径与 ``/market/open`` 一致:open = 未过期 ∩ 未认领。
"""
from __future__ import annotations

from typing import Any, Dict, Set, Tuple

from nth_dao.market.claim import CLAIM_STATUS_CLAIMED
from nth_dao.market.projection import (
    EVENT_MARKET_ANNOUNCE,
    EVENT_MARKET_CLAIM,
    MarketAnnounceProjection,
)


def _spine_known(spine: Any) -> Tuple[Set[str], Set[str]]:
    """spine 上已有的 (announce ids, claim ids)。"""
    anns: Set[str] = set()
    claims: Set[str] = set()
    for ev in spine.read_all():
        payload = ev.payload if isinstance(ev.payload, dict) else {}
        aid = payload.get("announcement_id")
        if not isinstance(aid, str):
            continue
        if ev.type == EVENT_MARKET_ANNOUNCE:
            anns.add(aid)
        elif ev.type == EVENT_MARKET_CLAIM:
            claims.add(aid)
    return anns, claims


def backfill_market_to_spine(feed: Any, claim_store: Any, spine: Any) -> Dict[str, int]:
    """把 feed 的公告 + ClaimStore 的认领补进 spine(幂等:已在则跳过)。

    使 spine 成为市场的**完整**事实源,为切读做准备。最好在迁移时一次性运行
    (并发写入下重复 append 仍无害:投影对同 id 只认首条,对账按集合比较)。
    返回补入统计。
    """
    known_anns, known_claims = _spine_known(spine)
    added_anns = 0
    added_claims = 0

    # 公告(含过期 —— 审计要完整;open 过滤在读时做)。
    for ann in feed.poll(
        since_seq=-1, limit=None, include_expired=True,
    ).announcements:
        if ann.announcement_id in known_anns:
            continue
        spine.append(EVENT_MARKET_ANNOUNCE, ann.to_dict())
        known_anns.add(ann.announcement_id)
        added_anns += 1

    # 认领。
    for rec in claim_store.all_records():
        if rec.get("status") != CLAIM_STATUS_CLAIMED:
            continue
        aid = rec.get("announcement_id")
        if not isinstance(aid, str) or aid in known_claims:
            continue
        spine.append(EVENT_MARKET_CLAIM, {
            "announcement_id": aid,
            "claimant_did": rec.get("claimant_did", ""),
            "publisher_did": rec.get("publisher_did", ""),
            "cap_token_id": rec.get("cap_token_id", ""),
            "claimed_at_ms": int(rec.get("claimed_at_ms", 0)),
        })
        known_claims.add(aid)
        added_claims += 1

    return {"announcements_added": added_anns, "claims_added": added_claims}


def reconcile_market(
    feed: Any, claim_store: Any, spine: Any, *, now_ms_override: int = 0,
) -> Dict[str, Any]:
    """对账:feed+ClaimStore 的 open 集 vs spine 投影的 open 集(同口径)。

    返回差异明细 + ``in_sync``(两侧零差异 → 可安全切读)。
    """
    feed_open: Set[str] = set()
    for ann in feed.poll(
        since_seq=-1, limit=None, now_ms_override=now_ms_override,
    ).announcements:
        if claim_store.is_unavailable(ann.announcement_id):
            continue
        feed_open.add(ann.announcement_id)

    proj = MarketAnnounceProjection()
    for ev in spine.read_all():
        proj.apply(ev)
    spine_open_raw = {
        a.announcement_id for a in proj.open(now_ms_override=now_ms_override)
    }
    occupied = {
        ann.announcement_id
        for ann in feed.poll(
            since_seq=-1, limit=None, include_expired=True,
            now_ms_override=now_ms_override,
        ).announcements
        if claim_store.is_unavailable(ann.announcement_id)
    }
    corrupt_claim_slots = sorted(
        aid for aid in occupied if claim_store.get(aid) is None
    )
    _, spine_claims = _spine_known(spine)
    claim_projection_gaps = sorted(
        aid for aid in occupied
        if claim_store.get(aid) is not None and aid not in spine_claims
    )
    spine_open = spine_open_raw - occupied

    only_feed = sorted(feed_open - spine_open)
    only_spine = sorted(spine_open - feed_open)
    return {
        "feed_open": len(feed_open),
        "spine_open": len(spine_open),
        "in_both": len(feed_open & spine_open),
        "only_in_feed": only_feed,
        "only_in_spine": only_spine,
        "corrupt_claim_slots": corrupt_claim_slots,
        "claim_projection_gaps": claim_projection_gaps,
        "in_sync": (
            not only_feed
            and not only_spine
            and not corrupt_claim_slots
            and not claim_projection_gaps
        ),
    }
