"""签名治理声明 —— 立宪 / 修宪的不可否认记录(Phase 4b)。

治理决策本身进入统一签名日志:``genesis`` 立初始策略、``amend`` 提交新策略,均由
当事方签名、自验证(与 dispute / receipt 同构)。``PolicyProjection`` 回放这些事件,
**修宪必须被当时生效的策略授权**,从而实现自治、自修订、可审计的治理历史。

声明携带 ``policy``(完整新策略 = ``Policy.to_dict()``),全量替换式 —— 每个版本都是
一份完整可签的"宪法",审计链上一目了然。签名体 = 除 ``sig`` 外全部字段。
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.execution_receipt import now_ms
from nth_dao.identity import AgentIdentity

GOVERNANCE_STATEMENT_KIND = "nth-governance-statement-v1"

GOV_GENESIS = "genesis"
GOV_AMEND = "amend"
_TYPES = (GOV_GENESIS, GOV_AMEND)


def _signing_body(stmt: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in stmt.items() if k != "sig"}


def sign_governance_statement(
    *,
    signer: AgentIdentity,
    statement_type: str,
    policy: Dict[str, Any],
    dao_id: str = "",
    issued_at_ms: int = 0,
) -> Dict[str, Any]:
    """构造并由 ``signer`` 签名一条治理声明(``genesis`` / ``amend``)。

    ``policy`` 是完整新策略(``Policy.to_dict()`` 的输出)。

    Raises:
        ValueError —— 类型未知 / policy 非 dict。
        TypeError —— policy 含 canonical_json 不接受的值(如 float)。
    """
    if statement_type not in _TYPES:
        raise ValueError(f"unknown governance statement type: {statement_type!r}")
    if not isinstance(policy, dict):
        raise ValueError("policy must be a dict (Policy.to_dict())")
    stmt: Dict[str, Any] = {
        "kind": GOVERNANCE_STATEMENT_KIND,
        "type": statement_type,
        "dao_id": str(dao_id),
        "signer_did": signer.as_did(),
        "issued_at_ms": int(issued_at_ms or now_ms()),
        "policy": dict(policy),
    }
    stmt["sig"] = b64u_encode(signer.sign(canonical_json(_signing_body(stmt))))
    return stmt


def verify_governance_statement(stmt: Dict[str, Any]) -> Tuple[bool, str]:
    """校验:结构合法 + ``signer_did`` 签名有效。fail-closed。"""
    if not isinstance(stmt, dict):
        return False, "not a dict"
    if stmt.get("kind") != GOVERNANCE_STATEMENT_KIND:
        return False, "wrong kind"
    if stmt.get("type") not in _TYPES:
        return False, "unknown type"
    if not isinstance(stmt.get("policy"), dict):
        return False, "missing/invalid policy"
    for f in ("signer_did", "sig"):
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
