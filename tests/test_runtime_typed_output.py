"""类型化交付:schema 校验、签验、防谎报合规、record fail-closed。"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("nacl")

from nth_dao.b64u import b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.identity import AgentIdentity
from nth_dao.runtime import (
    record_typed_output,
    sign_typed_output,
    validate_against_schema,
    verify_typed_output,
)
from nth_dao.spine import SignedEventLog


def _id() -> AgentIdentity:
    return AgentIdentity.generate()


def test_validate_schema() -> None:
    schema = {"title": "str", "count": "int", "items": "list"}
    assert validate_against_schema({"title": "x", "count": 3, "items": []}, schema)[0]
    assert not validate_against_schema({"title": "x", "count": 3}, schema)[0]    # 缺 items
    assert not validate_against_schema({"count": "3"}, {"count": "int"})[0]       # str 非 int
    assert not validate_against_schema({"b": True}, {"b": "int"})[0]              # bool 非 int
    assert not validate_against_schema({"x": 1}, {"x": "weird"})[0]               # 未知类型名


def test_sign_verify_typed_output() -> None:
    ex = _id()
    schema = {"summary": "str", "passed": "bool"}
    good = sign_typed_output(
        signer=ex, execution_id="run1",
        output={"summary": "done", "passed": True}, schema=schema)
    ok, why = verify_typed_output(good)
    assert ok, why
    assert good["schema_ok"] is True

    # 诚实的 schema_ok=False(缺字段)仍可验(签名有效 + 一致)。
    flagged = sign_typed_output(
        signer=ex, execution_id="run1",
        output={"summary": "done"}, schema=schema)
    assert flagged["schema_ok"] is False
    assert verify_typed_output(flagged)[0]


def test_verify_rejects_forged_compliance() -> None:
    # 手工签:output 不合 schema 却谎称 schema_ok=True → verify 必拒。
    ex = _id()
    stmt = {
        "kind": "nth-typed-output-v1", "execution_id": "run1", "receipt_id": "",
        "output": {"summary": "x"},
        "schema": {"summary": "str", "passed": "bool"},
        "schema_ok": True, "signer_did": ex.as_did(), "issued_at_ms": 1,
    }
    stmt["sig"] = b64u_encode(ex.sign(
        canonical_json({k: v for k, v in stmt.items() if k != "sig"})))
    ok, why = verify_typed_output(stmt)
    assert not ok and "forged compliance" in why


def test_record_fail_closed(tmp_path: Path) -> None:
    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    stmt = sign_typed_output(
        signer=_id(), execution_id="r", output={"a": "b"}, schema={"a": "str"})
    stmt["sig"] = "forged"
    with pytest.raises(ValueError, match="invalid typed output"):
        record_typed_output(spine, stmt)
