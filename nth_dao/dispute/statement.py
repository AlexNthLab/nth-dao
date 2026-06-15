"""签名争议声明 —— 争议生命周期的不可否认证据单元(Phase 3)。

每条声明由**当事方**(开争议者 / 提证者 / 仲裁者)签名,自验证(``signer_did`` +
``sig`` over canonical 签名体)。spine 把它作为 ``dispute.*`` 事件落入统一日志
(node 记录、party 签名 —— 与 execution_receipt / claim 的"谁干谁签、权威记录"
同构)。

声明类型:
  - ``open``     开启争议(body: reason、respondent_did、evidence_refs)
  - ``evidence`` 追加证据(body: note、evidence_refs、可内嵌自验收据)
  - ``resolve``  仲裁裁决(body: ruling、rationale)—— 仲裁者签名

签名体 = 除 ``sig`` 外全部字段。``sig = signer.sign(canonical_json(签名体))``。
完全沿用既有原语(canonical_json / identity / b64u),不引外来风格。
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, Optional, Tuple

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.execution_receipt import now_ms
from nth_dao.identity import AgentIdentity

DISPUTE_STATEMENT_KIND = "nth-dispute-statement-v1"

DISPUTE_OPEN = "open"
DISPUTE_EVIDENCE = "evidence"
DISPUTE_RESOLVE = "resolve"
_TYPES = (DISPUTE_OPEN, DISPUTE_EVIDENCE, DISPUTE_RESOLVE)


def _signing_body(stmt: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in stmt.items() if k != "sig"}


def sign_dispute_statement(
    *,
    signer: AgentIdentity,
    statement_type: str,
    announcement_id: str,
    body: Optional[Dict[str, Any]] = None,
    dispute_id: str = "",
    issued_at_ms: int = 0,
) -> Dict[str, Any]:
    """构造并由 ``signer`` 签名一条争议声明(返回自验证 dict)。

    ``open`` 不传 dispute_id 时自动生成;``evidence`` / ``resolve`` 必须引用已存在
    的 dispute_id(否则投影归不到组、被丢弃)。

    Raises:
        ValueError —— 类型未知 / announcement_id 为空。
        TypeError —— body 含 canonical_json 不接受的值(如 float)。
    """
    if statement_type not in _TYPES:
        raise ValueError(f"unknown dispute statement type: {statement_type!r}")
    if not announcement_id:
        raise ValueError("announcement_id required")
    stmt: Dict[str, Any] = {
        "kind": DISPUTE_STATEMENT_KIND,
        "type": statement_type,
        "dispute_id": dispute_id or uuid.uuid4().hex,
        "announcement_id": announcement_id,
        "signer_did": signer.as_did(),
        "issued_at_ms": int(issued_at_ms or now_ms()),
        "body": dict(body or {}),
    }
    stmt["sig"] = b64u_encode(signer.sign(canonical_json(_signing_body(stmt))))
    return stmt


def verify_dispute_statement(stmt: Dict[str, Any]) -> Tuple[bool, str]:
    """校验:结构合法 + ``signer_did`` 签名有效。fail-closed。"""
    if not isinstance(stmt, dict):
        return False, "not a dict"
    if stmt.get("kind") != DISPUTE_STATEMENT_KIND:
        return False, "wrong kind"
    if stmt.get("type") not in _TYPES:
        return False, "unknown type"
    for f in ("dispute_id", "announcement_id", "signer_did", "sig"):
        v = stmt.get(f)
        if not isinstance(v, str) or not v:
            return False, f"missing/invalid {f}"
    try:
        verifier = AgentIdentity.from_did(stmt["signer_did"])
        sig = b64u_decode(stmt["sig"])
        body = canonical_json(_signing_body(stmt))
    except Exception as exc:  # noqa: BLE001
        return False, f"bad encoding: {exc}"
    if not verifier.verify(body, sig):
        return False, "signature invalid"
    return True, "ok"
