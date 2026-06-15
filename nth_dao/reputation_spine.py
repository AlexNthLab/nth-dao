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
from nth_dao.market.acceptance import verify_acceptance
from nth_dao.market.projection import (
    EVENT_MARKET_ACCEPTANCE,
    EVENT_MARKET_ANNOUNCE,
    EVENT_MARKET_CLAIM,
)
from nth_dao.spine.event import SpineEvent
from nth_dao.spine.projection import Projection

_DISPUTE_EVENTS = (
    EVENT_DISPUTE_OPEN, EVENT_DISPUTE_EVIDENCE, EVENT_DISPUTE_RESOLVE,
)


@dataclass
class ReputationRecord:
    did: str
    tasks_claimed: int = 0       # 承接(自证)
    tasks_accepted: int = 0      # 交付且被发布方验收(真工作量证明)
    tasks_published: int = 0
    disputed_claims: int = 0     # 承接里被开过争议的
    score: int = 0               # 净信誉 = 被验收交付 − 被争议的被验收交付


class ReputationProjection(Projection):
    """折叠 market.* / dispute.* → 每个 DID 的可验证贡献与信誉。

    用集合而非计数器累计承接的 announcement_id,故"争议归属"在查询时用集合交集
    算 → **与事件顺序无关**(争议先于认领到达也正确)。
    """

    def __init__(self) -> None:
        # 承接 / 发布都按 announcement_id **集合**累计 → 同一公告重复事件只计一次
        # (幂等、两侧对称;计数器会被重复 announce/claim 事件重复计数)。
        self._claimed: Dict[str, Set[str]] = {}     # did → {announcement_id}
        self._accepted: Dict[str, Set[str]] = {}    # completer did → {announcement_id}
        self._published: Dict[str, Set[str]] = {}   # did → {announcement_id}
        self._ann_publisher: Dict[str, str] = {}    # announcement_id → 真发布方 did
        self._disputed_anns: Set[str] = set()

    def reset(self) -> None:
        self._claimed.clear()
        self._accepted.clear()
        self._published.clear()
        self._ann_publisher.clear()
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
                self._ann_publisher.setdefault(aid, pub)   # 首条 announce 定发布方
        elif event.type == EVENT_MARKET_ACCEPTANCE:
            cp = p.get("completer_did")
            ok, _ = verify_acceptance(p)
            # 防伪造刷分(尤其联邦回放):验收签名有效 + 验收人确为该公告**真发布
            # 方** + completer 确实**认领过**该公告(三者皆备才计交付)。
            if (
                ok and isinstance(cp, str) and cp
                and self._ann_publisher.get(aid) == p.get("publisher_did")
                and aid in self._claimed.get(cp, set())
            ):
                self._accepted.setdefault(cp, set()).add(aid)
        elif event.type in _DISPUTE_EVENTS:
            self._disputed_anns.add(aid)

    def _record(self, did: str) -> ReputationRecord:
        claimed = self._claimed.get(did, set())
        accepted = self._accepted.get(did, set())
        # 净信誉 = 被验收交付 − 被验收交付里被争议的(恒 ≥0)。承接不计入 score
        # (接了不等于交付),仅作 tasks_claimed 上下文展示。
        disputed_accepted = len(accepted & self._disputed_anns)
        return ReputationRecord(
            did=did,
            tasks_claimed=len(claimed),
            tasks_accepted=len(accepted),
            tasks_published=len(self._published.get(did, set())),
            disputed_claims=len(claimed & self._disputed_anns),
            score=len(accepted) - disputed_accepted,
        )

    def get(self, did: str) -> ReputationRecord:
        return self._record(did)

    def all(self) -> List[ReputationRecord]:
        dids = set(self._claimed) | set(self._published) | set(self._accepted)
        return [self._record(d) for d in dids]

    def top(self, n: int = 50) -> List[ReputationRecord]:
        """按 score → 交付数 → 承接数 → did 排序(确定性)。"""
        return sorted(
            self.all(),
            key=lambda r: (-r.score, -r.tasks_accepted, -r.tasks_claimed, r.did),
        )[: max(0, n)]
