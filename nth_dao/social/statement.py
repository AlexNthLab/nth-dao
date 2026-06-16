"""签名社交声明 —— 关注/好友关系的不可否认单元(Phase 社交)。

第一性:**慕强有基座,但成为熟人要对方确认**,故两类边不对称——
  - 关注 follow:**单签、单向、免确认**。A 签"我关注 B"即成立,B 无需同意。
    可随时 unfollow。这是"慕强"的基座:你能关注任何强者。
  - 好友 friend:**双签、双向、需确认**。A 签 friend_request 只是意向;必须 B 再签
    一条 friend_accept(引用 A 的请求)才成熟人。任一方可 friend_remove 解除。

每条声明由**发起方**签名,自验证(``actor_did`` + ``sig`` over canonical 签名体),
与 dispute / claim 的"谁干谁签、node 记录"完全同构。projection 层据双方的签名链
重建关系——好友态必然同时存在双方签名,**无法被单方伪造**。

签名体 = 除 ``sig`` 外全部字段。``sig = signer.sign(canonical_json(签名体))``。
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.execution_receipt import now_ms
from nth_dao.identity import AgentIdentity

SOCIAL_STATEMENT_KIND = "nth-social-statement-v1"

FOLLOW = "follow"
UNFOLLOW = "unfollow"
FRIEND_REQUEST = "friend_request"
FRIEND_ACCEPT = "friend_accept"
FRIEND_DECLINE = "friend_decline"
FRIEND_REMOVE = "friend_remove"
_TYPES = (
    FOLLOW, UNFOLLOW,
    FRIEND_REQUEST, FRIEND_ACCEPT, FRIEND_DECLINE, FRIEND_REMOVE,
)


def _signing_body(stmt: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in stmt.items() if k != "sig"}


def sign_social_statement(
    *,
    signer: AgentIdentity,
    statement_type: str,
    target_did: str,
    body: Optional[Dict[str, Any]] = None,
    issued_at_ms: int = 0,
) -> Dict[str, Any]:
    """构造并由 ``signer``(发起方)签名一条社交声明(返回自验证 dict)。

    ``actor_did`` 取自签名者;``target_did`` 是关系对象。关注/好友都不允许指向自己。

    Raises:
        ValueError —— 类型未知 / target_did 为空 / 指向自己。
        TypeError —— body 含 canonical_json 不接受的值(如 float)。
    """
    if statement_type not in _TYPES:
        raise ValueError(f"unknown social statement type: {statement_type!r}")
    if not target_did:
        raise ValueError("target_did required")
    actor_did = signer.as_did()
    if actor_did == target_did:
        raise ValueError("cannot follow/friend yourself")
    stmt: Dict[str, Any] = {
        "kind": SOCIAL_STATEMENT_KIND,
        "type": statement_type,
        "actor_did": actor_did,
        "target_did": target_did,
        "issued_at_ms": int(issued_at_ms or now_ms()),
        "body": dict(body or {}),
    }
    stmt["sig"] = b64u_encode(signer.sign(canonical_json(_signing_body(stmt))))
    return stmt


def verify_social_statement(stmt: Dict[str, Any]) -> Tuple[bool, str]:
    """校验:结构合法 + ``actor_did`` 签名有效 + 非自指。fail-closed。"""
    if not isinstance(stmt, dict):
        return False, "not a dict"
    if stmt.get("kind") != SOCIAL_STATEMENT_KIND:
        return False, "wrong kind"
    if stmt.get("type") not in _TYPES:
        return False, "unknown type"
    for f in ("actor_did", "target_did", "sig"):
        v = stmt.get(f)
        if not isinstance(v, str) or not v:
            return False, f"missing/invalid {f}"
    if stmt["actor_did"] == stmt["target_did"]:
        return False, "self-relationship not allowed"
    try:
        verifier = AgentIdentity.from_did(stmt["actor_did"])
        sig = b64u_decode(stmt["sig"])
        body = canonical_json(_signing_body(stmt))
    except Exception as exc:  # noqa: BLE001
        return False, f"bad encoding: {exc}"
    if not verifier.verify(body, sig):
        return False, "signature invalid"
    return True, "ok"
