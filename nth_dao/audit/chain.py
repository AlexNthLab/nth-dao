"""证据链回放 —— 从 spine 重建一条公告的完整、可验证证据时间线(Phase 3)。

给定**已 verify_chain** 的事件流 + ``announcement_id``,按 spine 顺序收集与之相关的
``market.announce`` / ``market.claim`` / ``dispute.*`` 事件,逐项**独立重验**:
  - announce → ``verify_announcement``(publisher_sig)
  - dispute  → ``verify_dispute_statement``(当事方签名)
  - claim    → 无独立内嵌签名(收据未入此事件),其完整性靠调用方对整链
    ``verify_chain``;此处标 verified=True 表示"链已验 + 结构完整"。

返回有序 ``EvidenceChain`` —— 争议复盘 / 审计的依据。纯读、无副作用。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List

from nth_dao.dispute.projection import (
    EVENT_DISPUTE_EVIDENCE,
    EVENT_DISPUTE_OPEN,
    EVENT_DISPUTE_RESOLVE,
)
from nth_dao.dispute.statement import verify_dispute_statement
from nth_dao.market.announcement import TaskAnnouncement, verify_announcement
from nth_dao.market.projection import EVENT_MARKET_ANNOUNCE, EVENT_MARKET_CLAIM
from nth_dao.spine.event import SpineEvent

_DISPUTE_EVENTS = (
    EVENT_DISPUTE_OPEN, EVENT_DISPUTE_EVIDENCE, EVENT_DISPUTE_RESOLVE,
)


@dataclass
class EvidenceItem:
    seq: int
    type: str
    author_did: str
    ts_ms: int
    verified: bool
    summary: str
    detail: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceChain:
    announcement_id: str
    items: List[EvidenceItem] = field(default_factory=list)

    @property
    def all_verified(self) -> bool:
        return all(i.verified for i in self.items)


def _ann_id(ev: SpineEvent) -> str:
    p = ev.payload if isinstance(ev.payload, dict) else {}
    return str(p.get("announcement_id", ""))


def reconstruct_evidence(
    events: Iterable[SpineEvent], announcement_id: str,
) -> EvidenceChain:
    """重建 ``announcement_id`` 的证据链(调用方应已对来源 ``verify_chain``)。"""
    chain = EvidenceChain(announcement_id=announcement_id)
    for ev in events:
        if _ann_id(ev) != announcement_id:
            continue
        payload = ev.payload if isinstance(ev.payload, dict) else {}

        if ev.type == EVENT_MARKET_ANNOUNCE:
            verified = False
            summary = "announced"
            try:
                ann = TaskAnnouncement.from_dict(payload)
                verified, _ = verify_announcement(ann)
                summary = f"announced: {ann.title}"
            except Exception:  # noqa: BLE001
                verified = False
            chain.items.append(EvidenceItem(
                ev.seq, ev.type, ev.author_did, ev.ts_ms,
                verified, summary, dict(payload)))

        elif ev.type == EVENT_MARKET_CLAIM:
            claimant = str(payload.get("claimant_did", ""))
            chain.items.append(EvidenceItem(
                ev.seq, ev.type, ev.author_did, ev.ts_ms,
                True, f"claimed by {claimant[:20]}", dict(payload)))

        elif ev.type in _DISPUTE_EVENTS:
            ok, _ = verify_dispute_statement(payload)
            stype = str(payload.get("type", "?"))
            signer = str(payload.get("signer_did", ""))
            chain.items.append(EvidenceItem(
                ev.seq, ev.type, ev.author_did, ev.ts_ms,
                ok, f"dispute {stype} by {signer[:20]}", dict(payload)))

    return chain
