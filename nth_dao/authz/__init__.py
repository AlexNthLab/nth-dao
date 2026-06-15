"""Nth DAO 授权收件箱(consent 层)。

人在环上的能力授予:agent 签名请求 → node(operator)审批 → 批准签发 cap_token /
拒绝。全程 spine 原生记录(cap.request/grant/deny),可审计、不可否认。这是愿景的
旗舰 UX —— 让"Agent 想做什么、人批准了什么"可见、可控、可回溯。
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from nth_dao.authz.projection import (
    EVENT_CAP_DENY,
    EVENT_CAP_GRANT,
    EVENT_CAP_REQUEST,
    STATUS_DENIED,
    STATUS_GRANTED,
    STATUS_PENDING,
    CapRequestProjection,
    CapRequestRecord,
)
from nth_dao.authz.request import (
    CAP_REQUEST_KIND,
    sign_cap_request,
    verify_cap_request,
)
from nth_dao.cap_token import sign_cap_token
from nth_dao.execution_receipt import now_ms


def record_cap_request(spine: Any, statement: Dict[str, Any]) -> Any:
    """把一条已签能力授予请求落入 ``spine``(``cap.request`` 事件)。fail-closed。"""
    ok, why = verify_cap_request(statement)
    if not ok:
        raise ValueError(f"refusing to record invalid cap request: {why}")
    return spine.append(EVENT_CAP_REQUEST, statement)


def grant_cap_request(
    spine: Any,
    *,
    issuer: Any,
    request_id: str,
    requester_did: str,
    capabilities: Iterable[str],
    scope: Optional[Dict[str, Any]] = None,
    now_ms_override: int = 0,
) -> Dict[str, Any]:
    """批准:由 ``issuer``(本节点)签发 cap_token 给 requester,记 ``cap.grant``。

    返回签发的 cap_token。授权(谁能批)由调用方/治理把控;本函数只做签发+记录。
    """
    scope = scope or {}
    token = sign_cap_token(
        issuer=issuer,
        subject_did=requester_did,
        capabilities=list(capabilities),
        scope_task_id=str(scope.get("task_id", "")),
        scope_dao=str(scope.get("dao", "")),
    )
    spine.append(EVENT_CAP_GRANT, {
        "request_id": request_id,
        "requester_did": requester_did,
        "capabilities": sorted({str(c) for c in capabilities}),
        "cap_token": token,
        "decided_by_did": issuer.as_did(),
        "decided_at_ms": int(now_ms_override or now_ms()),
    })
    return token


def deny_cap_request(
    spine: Any,
    *,
    decider: Any,
    request_id: str,
    reason: str = "",
    now_ms_override: int = 0,
) -> Any:
    """拒绝:记 ``cap.deny``(决策者签名身份在案,可审计)。"""
    return spine.append(EVENT_CAP_DENY, {
        "request_id": request_id,
        "decided_by_did": decider.as_did(),
        "reason": str(reason),
        "decided_at_ms": int(now_ms_override or now_ms()),
    })


__all__ = [
    "CAP_REQUEST_KIND",
    "sign_cap_request",
    "verify_cap_request",
    "record_cap_request",
    "grant_cap_request",
    "deny_cap_request",
    "CapRequestProjection",
    "CapRequestRecord",
    "EVENT_CAP_REQUEST",
    "EVENT_CAP_GRANT",
    "EVENT_CAP_DENY",
    "STATUS_PENDING",
    "STATUS_GRANTED",
    "STATUS_DENIED",
]
