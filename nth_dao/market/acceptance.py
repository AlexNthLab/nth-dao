"""签名验收 —— 发布方确认某 agent 完成了任务(交付证明)。

claim = **承接**(自证,弱);acceptance = **发布方签名**确认"X 完成了 Y" —— 非自证、
不可伪造(只有发布方能验收自己发的任务)。reputation 据此把信誉从"接了多少活"
升级为"交付了多少被认可的活"(真工作量证明信号)。

自验证(与 announcement / dispute 同构):``publisher_did`` + ``sig`` over canonical 体。
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.execution_receipt import now_ms
from nth_dao.identity import AgentIdentity

ACCEPTANCE_KIND = "nth-task-acceptance-v1"


def _signing_body(stmt: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in stmt.items() if k != "sig"}


def sign_acceptance(
    *,
    publisher: AgentIdentity,
    announcement_id: str,
    completer_did: str,
    accepted_at_ms: int = 0,
) -> Dict[str, Any]:
    """发布方签名一条验收(确认 ``completer_did`` 完成了 ``announcement_id``)。"""
    if not announcement_id or not completer_did:
        raise ValueError("announcement_id and completer_did required")
    stmt: Dict[str, Any] = {
        "kind": ACCEPTANCE_KIND,
        "announcement_id": announcement_id,
        "completer_did": completer_did,
        "publisher_did": publisher.as_did(),
        "accepted_at_ms": int(accepted_at_ms or now_ms()),
    }
    stmt["sig"] = b64u_encode(publisher.sign(canonical_json(_signing_body(stmt))))
    return stmt


def verify_acceptance(stmt: Dict[str, Any]) -> Tuple[bool, str]:
    """校验:结构合法 + ``publisher_did`` 签名有效。fail-closed。"""
    if not isinstance(stmt, dict):
        return False, "not a dict"
    if stmt.get("kind") != ACCEPTANCE_KIND:
        return False, "wrong kind"
    for f in ("announcement_id", "completer_did", "publisher_did", "sig"):
        v = stmt.get(f)
        if not isinstance(v, str) or not v:
            return False, f"missing/invalid {f}"
    try:
        verifier = AgentIdentity.from_did(stmt["publisher_did"])
        sig = b64u_decode(stmt["sig"])
        body = canonical_json(_signing_body(stmt))
    except Exception as exc:  # noqa: BLE001
        return False, f"bad encoding: {exc}"
    if not verifier.verify(body, sig):
        return False, "signature invalid"
    return True, "ok"
