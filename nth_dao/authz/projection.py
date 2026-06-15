"""授权收件箱投影 —— 把 spine 的 cap.* 事件折叠成"授予请求"记录。

生命周期:``cap.request`` 建待批记录 → ``cap.grant`` 置 granted + 挂签发的
cap_token → ``cap.deny`` 置 denied。请求独立验签;grant 内嵌的 cap_token 校验
subject == requester 才采信(防张冠李戴)。批准/拒绝**授权**(谁能签发)是治理
(Phase 4 引擎)的事,本层记 decided_by_did、不做准入。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from nth_dao.authz.request import verify_cap_request
from nth_dao.cap_token import verify_cap_token
from nth_dao.spine.event import SpineEvent
from nth_dao.spine.projection import Projection

EVENT_CAP_REQUEST = "cap.request"
EVENT_CAP_GRANT = "cap.grant"
EVENT_CAP_DENY = "cap.deny"
_CAP_EVENTS = (EVENT_CAP_REQUEST, EVENT_CAP_GRANT, EVENT_CAP_DENY)

STATUS_PENDING = "pending"
STATUS_GRANTED = "granted"
STATUS_DENIED = "denied"


@dataclass
class CapRequestRecord:
    request_id: str
    requester_did: str = ""
    capabilities: List[str] = field(default_factory=list)
    reason: str = ""
    scope: Dict[str, Any] = field(default_factory=dict)
    status: str = STATUS_PENDING
    cap_token: Optional[Dict[str, Any]] = None
    decided_by_did: str = ""
    decided_at_ms: int = 0


class CapRequestProjection(Projection):
    """折叠 cap.request/grant/deny → {request_id: CapRequestRecord}。"""

    def __init__(self) -> None:
        self._reqs: Dict[str, CapRequestRecord] = {}

    def reset(self) -> None:
        self._reqs.clear()

    def apply(self, event: SpineEvent) -> None:
        if event.type not in _CAP_EVENTS:
            return
        payload = event.payload if isinstance(event.payload, dict) else {}
        rid = payload.get("request_id")
        if not isinstance(rid, str) or not rid:
            return

        if event.type == EVENT_CAP_REQUEST:
            ok, _ = verify_cap_request(payload)
            if ok and rid not in self._reqs:        # 首条请求胜(防 id 抢注)
                self._reqs[rid] = CapRequestRecord(
                    request_id=rid,
                    requester_did=payload["requester_did"],
                    capabilities=list(payload.get("capabilities", [])),
                    reason=str(payload.get("reason", "")),
                    scope=dict(payload.get("scope", {})),
                )
            return

        rec = self._reqs.get(rid)
        if rec is None or rec.status != STATUS_PENDING:
            return   # 决议必须挂在待批请求上(幂等:已决不再变)

        if event.type == EVENT_CAP_GRANT:
            token = payload.get("cap_token")
            if not isinstance(token, dict):
                return
            tok_ok, _ = verify_cap_token(token)
            # 防张冠李戴:签发的 token 必须确实授给该 requester。
            if not tok_ok or token.get("subject_did") != rec.requester_did:
                return
            rec.status = STATUS_GRANTED
            rec.cap_token = token
            rec.decided_by_did = str(payload.get("decided_by_did", ""))
            rec.decided_at_ms = int(payload.get("decided_at_ms", 0))
        elif event.type == EVENT_CAP_DENY:
            rec.status = STATUS_DENIED
            rec.decided_by_did = str(payload.get("decided_by_did", ""))
            rec.decided_at_ms = int(payload.get("decided_at_ms", 0))
            rec.reason = str(payload.get("reason", "")) or rec.reason

    def get(self, request_id: str) -> Optional[CapRequestRecord]:
        return self._reqs.get(request_id)

    def pending(self) -> List[CapRequestRecord]:
        return [r for r in self._reqs.values() if r.status == STATUS_PENDING]

    def all(self) -> List[CapRequestRecord]:
        return list(self._reqs.values())
