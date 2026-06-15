"""签名能力授予请求 —— 授权收件箱(consent 层)的请求单元。

agent 签名声明"我(did:X)请求能力 [A,B](原因/范围)";node(operator)在收件箱
审批 → 批准则签发 cap_token(``cap.grant``)/ 拒绝(``cap.deny``)。请求自验证
(requester 签名),与 dispute / governance 声明同构:谁请求谁签、node 记录 + 决策。
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, Optional, Tuple

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.execution_receipt import now_ms
from nth_dao.identity import AgentIdentity

CAP_REQUEST_KIND = "nth-cap-request-v1"


def _signing_body(stmt: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in stmt.items() if k != "sig"}


def sign_cap_request(
    *,
    requester: AgentIdentity,
    capabilities: Any,
    reason: str = "",
    scope: Optional[Dict[str, Any]] = None,
    request_id: str = "",
    issued_at_ms: int = 0,
) -> Dict[str, Any]:
    """构造并由 ``requester`` 签名一条能力授予请求(自验证 dict)。

    Raises:
        ValueError —— capabilities 为空 / 含非字符串空串。
    """
    caps = [str(c).strip() for c in (capabilities or []) if str(c).strip()]
    if not caps:
        raise ValueError("capabilities required (non-empty strings)")
    stmt: Dict[str, Any] = {
        "kind": CAP_REQUEST_KIND,
        "request_id": request_id or uuid.uuid4().hex,
        "requester_did": requester.as_did(),
        "capabilities": sorted(set(caps)),
        "reason": str(reason),
        "scope": dict(scope or {}),
        "issued_at_ms": int(issued_at_ms or now_ms()),
    }
    stmt["sig"] = b64u_encode(requester.sign(canonical_json(_signing_body(stmt))))
    return stmt


def verify_cap_request(stmt: Dict[str, Any]) -> Tuple[bool, str]:
    """校验:结构合法 + ``requester_did`` 签名有效。fail-closed。"""
    if not isinstance(stmt, dict):
        return False, "not a dict"
    if stmt.get("kind") != CAP_REQUEST_KIND:
        return False, "wrong kind"
    caps = stmt.get("capabilities")
    if not isinstance(caps, list) or not caps or not all(
        isinstance(c, str) and c for c in caps
    ):
        return False, "missing/invalid capabilities"
    for f in ("request_id", "requester_did", "sig"):
        v = stmt.get(f)
        if not isinstance(v, str) or not v:
            return False, f"missing/invalid {f}"
    try:
        verifier = AgentIdentity.from_did(stmt["requester_did"])
        sig = b64u_decode(stmt["sig"])
        body = canonical_json(_signing_body(stmt))
    except Exception as exc:  # noqa: BLE001
        return False, f"bad encoding: {exc}"
    if not verifier.verify(body, sig):
        return False, "signature invalid"
    return True, "ok"
