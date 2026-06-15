"""市场视图投影 —— 把 spine 上的 market.* 事件折叠成开放公告视图(Phase 2)。

迁移第一刀:``MarketFeed.publish`` 在写自己 jsonl 的同时,向 spine append 一条
``market.announce`` 事件(影子双写,feed 仍是当前事实源)。本投影证明"spine 事件流
能重建出与 feed 一致的开放公告视图",为后续把读路径切到 spine 铺路。

口径与 ``MarketFeed`` 对齐:嵌入事件的公告必须**独立验签**通过才采信(验不过丢弃);
过期在**读时**(``open``)过滤,不在折叠时丢(与 ``feed.poll`` 一致)。``market.claim``
事件记入已认领集合,``open`` 据此排除(为 Phase 2b claim 双写预留)。
"""
from __future__ import annotations

from typing import Dict, List, Optional, Set

from nth_dao.market.announcement import TaskAnnouncement, verify_announcement
from nth_dao.spine.event import SpineEvent
from nth_dao.spine.projection import Projection

EVENT_MARKET_ANNOUNCE = "market.announce"
EVENT_MARKET_CLAIM = "market.claim"


class MarketAnnounceProjection(Projection):
    """折叠 ``market.announce`` / ``market.claim`` → 开放公告视图。"""

    def __init__(self) -> None:
        self._anns: Dict[str, TaskAnnouncement] = {}
        self._claimed: Set[str] = set()

    def reset(self) -> None:
        self._anns.clear()
        self._claimed.clear()

    def apply(self, event: SpineEvent) -> None:
        if event.type == EVENT_MARKET_ANNOUNCE:
            try:
                ann = TaskAnnouncement.from_dict(event.payload)
            except (TypeError, ValueError):
                return
            ok, _ = verify_announcement(ann)
            # append-only:同 id 只认最早一条(与 feed.get 的 FIFO 一致)。
            if ok and ann.announcement_id not in self._anns:
                self._anns[ann.announcement_id] = ann
        elif event.type == EVENT_MARKET_CLAIM:
            aid = event.payload.get("announcement_id")
            if isinstance(aid, str):
                self._claimed.add(aid)

    def get(self, announcement_id: str) -> Optional[TaskAnnouncement]:
        return self._anns.get(announcement_id)

    def open(
        self, *, now_ms_override: int = 0, include_claimed: bool = False,
    ) -> List[TaskAnnouncement]:
        """开放公告:未过期、(默认)未认领。过期在此过滤,与 feed.poll 一致。"""
        out: List[TaskAnnouncement] = []
        for aid, ann in self._anns.items():
            if not include_claimed and aid in self._claimed:
                continue
            if ann.is_expired(now_ms_override):
                continue
            out.append(ann)
        return out
