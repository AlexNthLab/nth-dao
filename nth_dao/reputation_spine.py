"""spine 原生信誉 —— 从签名事件流派生可验证贡献与信誉(最后一根支柱)。

愿景:"积累可验证的贡献与信誉"。这里把信誉做成 spine 的**确定性投影**(不是中心
打分):每个 DID 的贡献直接从签名的 ``market.claim``(承接的任务)/ ``market.announce``
(发布的任务)数出来,``dispute.*`` 作为减分上下文。任何节点回放同一日志得同一信誉
→ 可迁移、可复算、不可否认。与既有 ``reputation.py`` / ``market/reputation.py``(从
ClaimStore 文件聚合)并存,这是其 spine 版。

诚实口径:claim = **承接**(非交付证明 —— 交付/完成事件是后续细化);disputed_claims
= 承接的任务里被开过争议的;``score = tasks_claimed − disputed_claims``(净未争议贡献),
透明、可解释、确定性。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Set

from nth_dao.dispute.projection import (
    EVENT_DISPUTE_EVIDENCE,
    EVENT_DISPUTE_OPEN,
    EVENT_DISPUTE_RESOLVE,
)
from nth_dao.market.projection import EVENT_MARKET_ANNOUNCE, EVENT_MARKET_CLAIM
from nth_dao.spine.event import SpineEvent
from nth_dao.spine.projection import Projection

_DISPUTE_EVENTS = (
    EVENT_DISPUTE_OPEN, EVENT_DISPUTE_EVIDENCE, EVENT_DISPUTE_RESOLVE,
)


@dataclass
class ReputationRecord:
    did: str
    tasks_claimed: int = 0
    tasks_published: int = 0
    disputed_claims: int = 0

    @property
    def score(self) -> int:
        """净未争议贡献(透明公式:承接数 − 被争议承接数)。"""
        return self.tasks_claimed - self.disputed_claims


class ReputationProjection(Projection):
    """折叠 market.* / dispute.* → 每个 DID 的可验证贡献与信誉。

    用集合而非计数器累计承接的 announcement_id,故"争议归属"在查询时用集合交集
    算 → **与事件顺序无关**(争议先于认领到达也正确)。
    """

    def __init__(self) -> None:
        # 承接 / 发布都按 announcement_id **集合**累计 → 同一公告重复事件只计一次
        # (幂等、两侧对称;计数器会被重复 announce/claim 事件重复计数)。
        self._claimed: Dict[str, Set[str]] = {}     # did → {announcement_id}
        self._published: Dict[str, Set[str]] = {}   # did → {announcement_id}
        self._disputed_anns: Set[str] = set()

    def reset(self) -> None:
        self._claimed.clear()
        self._published.clear()
        self._disputed_anns.clear()

    def apply(self, event: SpineEvent) -> None:
        p = event.payload if isinstance(event.payload, dict) else {}
        aid = p.get("announcement_id")
        if not (isinstance(aid, str) and aid):
            return
        if event.type == EVENT_MARKET_CLAIM:
            cl = p.get("claimant_did")
            if isinstance(cl, str) and cl:
                self._claimed.setdefault(cl, set()).add(aid)
        elif event.type == EVENT_MARKET_ANNOUNCE:
            pub = p.get("publisher_did")
            if isinstance(pub, str) and pub:
                self._published.setdefault(pub, set()).add(aid)
        elif event.type in _DISPUTE_EVENTS:
            self._disputed_anns.add(aid)

    def _record(self, did: str) -> ReputationRecord:
        claimed = self._claimed.get(did, set())
        return ReputationRecord(
            did=did,
            tasks_claimed=len(claimed),
            tasks_published=len(self._published.get(did, set())),
            disputed_claims=len(claimed & self._disputed_anns),
        )

    def get(self, did: str) -> ReputationRecord:
        return self._record(did)

    def all(self) -> List[ReputationRecord]:
        dids = set(self._claimed) | set(self._published)
        return [self._record(d) for d in dids]

    def top(self, n: int = 50) -> List[ReputationRecord]:
        """按 score → 承接数 → did 排序(确定性)。"""
        return sorted(
            self.all(),
            key=lambda r: (-r.score, -r.tasks_claimed, r.did),
        )[: max(0, n)]
