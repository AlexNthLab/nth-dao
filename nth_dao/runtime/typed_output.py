"""类型化执行交付 —— 可验证的结构化输出(轻 schema)。

CrewAI 的 ``output_pydantic`` 强制结构化输出;对 Nth DAO 有信任价值的是**可验证的
结构化交付**:执行者签一条"我交付了这个 output、声称它满足这个 schema"。``verify``
会**重新校验** output 是否真满足 schema —— 伪造者无法对不合 schema 的 output 签
``schema_ok=True``。可直接喂给争议/审计/信誉("交付了什么"机器可核)。

轻 schema(无外部依赖,且与 canonical_json 的"拒浮点"一致):
    schema = {字段: "str" | "int" | "bool" | "list" | "dict"}
    output 必须含每个字段且类型匹配。

自验证(与 receipt / checkpoint 同构):``signer_did`` + ``sig`` over canonical 体。
可选 ``receipt_id`` 把交付绑定到一份 execution_receipt(不改 receipt 线格式)。
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Tuple

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.execution_receipt import now_ms
from nth_dao.identity import AgentIdentity

TYPED_OUTPUT_KIND = "nth-typed-output-v1"
EVENT_EXEC_OUTPUT = "exec.output"

_CHECKS: Dict[str, Callable[[Any], bool]] = {
    "str": lambda v: isinstance(v, str),
    "int": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "bool": lambda v: isinstance(v, bool),
    "list": lambda v: isinstance(v, list),
    "dict": lambda v: isinstance(v, dict),
}


def validate_against_schema(
    output: Any, schema: Any,
) -> Tuple[bool, str]:
    """轻校验:schema 每个字段都在 output 里且类型匹配。未知类型名 → 不通过。"""
    if not isinstance(output, dict) or not isinstance(schema, dict):
        return False, "output/schema must be dicts"
    for field, type_name in schema.items():
        check = _CHECKS.get(type_name)
        if check is None:
            return False, f"unknown type {type_name!r} for {field!r}"
        if field not in output:
            return False, f"missing field {field!r}"
        if not check(output[field]):
            return False, f"field {field!r} not {type_name}"
    return True, "ok"


def _signing_body(stmt: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in stmt.items() if k != "sig"}


def sign_typed_output(
    *,
    signer: AgentIdentity,
    execution_id: str,
    output: Dict[str, Any],
    schema: Dict[str, Any],
    receipt_id: str = "",
    issued_at_ms: int = 0,
) -> Dict[str, Any]:
    """执行者签名一条类型化交付。``schema_ok`` 由本函数校验得出并签入(不可事后篡改)。"""
    if not execution_id:
        raise ValueError("execution_id required")
    ok, _ = validate_against_schema(output, schema)
    stmt: Dict[str, Any] = {
        "kind": TYPED_OUTPUT_KIND,
        "execution_id": str(execution_id),
        "receipt_id": str(receipt_id),
        "output": dict(output),
        "schema": dict(schema),
        "schema_ok": bool(ok),
        "signer_did": signer.as_did(),
        "issued_at_ms": int(issued_at_ms or now_ms()),
    }
    stmt["sig"] = b64u_encode(signer.sign(canonical_json(_signing_body(stmt))))
    return stmt


def verify_typed_output(stmt: Dict[str, Any]) -> Tuple[bool, str]:
    """校验:结构 + 签名有效 + **重算 schema_ok 与签入值一致**(防谎报合规)。"""
    if not isinstance(stmt, dict):
        return False, "not a dict"
    if stmt.get("kind") != TYPED_OUTPUT_KIND:
        return False, "wrong kind"
    if not isinstance(stmt.get("output"), dict) or not isinstance(stmt.get("schema"), dict):
        return False, "missing/invalid output|schema"
    for f in ("execution_id", "signer_did", "sig"):
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
    recomputed_ok, _ = validate_against_schema(stmt["output"], stmt["schema"])
    if bool(stmt.get("schema_ok")) != recomputed_ok:
        return False, "schema_ok does not match output (forged compliance)"
    return True, "ok"
