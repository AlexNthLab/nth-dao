"""争议视图投影 —— 把 spine 的 dispute.* 事件折叠成争议记录(Phase 3)。

每条声明独立验签(verify_dispute_statement),验不过丢弃。生命周期:
``open`` 建记录 → ``evidence`` 追加 → ``resolve`` 置 resolved + 记裁决。
仲裁者授权(谁有权 resolve)是 Phase 4 治理的事;本层只记录 arbiter_did、不做准入。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from nth_dao.dispute.statement import verify_dispute_statement
from nth_dao.spine.event import SpineEvent
from nth_dao.spine.projection import Projection

EVENT_DISPUTE_OPEN = "dispute.open"
EVENT_DISPUTE_EVIDENCE = "dispute.evidence"
EVENT_DISPUTE_RESOLVE = "dispute.resolve"
_DISPUTE_EVENTS = (
    EVENT_DISPUTE_OPEN, EVENT_DISPUTE_EVIDENCE, EVENT_DISPUTE_RESOLVE,
)

STATUS_OPEN = "open"
STATUS_RESOLVED = "resolved"


@dataclass
class DisputeRecord:
    dispute_id: str
    announcement_id: str = ""
    opener_did: str = ""
    status: str = STATUS_OPEN
    ruling: Dict[str, Any] = field(default_factory=dict)
    arbiter_did: str = ""
    statements: List[Dict[str, Any]] = field(default_factory=list)


class DisputeProjection(Projection):
    """折叠 dispute.open/evidence/resolve → {dispute_id: DisputeRecord}。"""

    def __init__(self) -> None:
        self._disputes: Dict[str, DisputeRecord] = {}

    def reset(self) -> None:
        self._disputes.clear()

    def apply(self, event: SpineEvent) -> None:
        if event.type not in _DISPUTE_EVENTS:
            return
        stmt = event.payload
        ok, _ = verify_dispute_statement(stmt)
        if not ok:
            return
        did = stmt["dispute_id"]
        rec = self._disputes.get(did)

        if event.type == EVENT_DISPUTE_OPEN:
            if rec is None:   # 只认第一条 open(FIFO,防 dispute_id 抢注覆盖)
                rec = DisputeRecord(
                    dispute_id=did,
                    announcement_id=stmt["announcement_id"],
                    opener_did=stmt["signer_did"],
                )
                rec.statements.append(stmt)
                self._disputes[did] = rec
            return

        # evidence / resolve 必须挂在已存在的 open 上,且同一公告。
        if rec is None or stmt["announcement_id"] != rec.announcement_id:
            return
        rec.statements.append(stmt)
        if event.type == EVENT_DISPUTE_RESOLVE and rec.status != STATUS_RESOLVED:
            rec.status = STATUS_RESOLVED
            rec.ruling = dict(stmt.get("body", {}))
            rec.arbiter_did = stmt["signer_did"]

    def get(self, dispute_id: str) -> Optional[DisputeRecord]:
        return self._disputes.get(dispute_id)

    def all(self) -> List[DisputeRecord]:
        return list(self._disputes.values())

    def for_announcement(self, announcement_id: str) -> List[DisputeRecord]:
        return [
            r for r in self._disputes.values()
            if r.announcement_id == announcement_id
        ]
