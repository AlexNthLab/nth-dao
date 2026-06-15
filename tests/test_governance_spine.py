"""Phase 4b:治理事件 + PolicyProjection —— 自治、自修订、带授权的治理历史。"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

pytest.importorskip("nacl")

from nth_dao.governance import (
    ACTION_DISPUTE_RESOLVE,
    ACTION_POLICY_AMEND,
    Policy,
    PolicyProjection,
    can,
    record_governance,
    sign_governance_statement,
    verify_governance_statement,
)
from nth_dao.identity import AgentIdentity
from nth_dao.spine import SignedEventLog, replay


def _id() -> AgentIdentity:
    return AgentIdentity.generate()


def _owner_policy(owner_did: str) -> Dict[str, Any]:
    return Policy.from_dict({
        "roles": {owner_did: ["owner"]},
        "grants": {"owner": ["*"]},
        "constraints": {},
    }).to_dict()


def _project(spine: SignedEventLog) -> PolicyProjection:
    proj = PolicyProjection()
    replay(spine.read_all(), proj)
    return proj


def test_genesis_then_authorized_amend(tmp_path: Path) -> None:
    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    owner = _id()
    arb = _id()

    record_governance(spine, sign_governance_statement(
        signer=owner, statement_type="genesis",
        policy=_owner_policy(owner.as_did())))

    proj = _project(spine)
    assert proj.established and proj.version == 1
    assert proj.founder_did == owner.as_did()
    assert can(proj.policy, owner.as_did(), ACTION_POLICY_AMEND).allowed

    # owner 修宪:加一个授权仲裁者。
    new_policy = Policy.from_dict({
        "roles": {owner.as_did(): ["owner"], arb.as_did(): ["arbiter"]},
        "grants": {"owner": ["*"], "arbiter": ["dispute.*"]},
        "constraints": {},
    }).to_dict()
    record_governance(spine, sign_governance_statement(
        signer=owner, statement_type="amend", policy=new_policy))

    proj2 = _project(spine)
    assert proj2.version == 2
    # 闭合 Phase 3↔4↔4b:修订后的策略让新仲裁者可 dispute.resolve。
    assert can(proj2.policy, arb.as_did(), ACTION_DISPUTE_RESOLVE).allowed
    ok, why = spine.verify_chain()
    assert ok, why


def test_unauthorized_amend_recorded_but_not_adopted(tmp_path: Path) -> None:
    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    owner = _id()
    stranger = _id()
    record_governance(spine, sign_governance_statement(
        signer=owner, statement_type="genesis",
        policy=_owner_policy(owner.as_did())))

    # 路人(无 policy.amend 权)试图夺权 → 记入日志但**不采纳**。
    evil = Policy.from_dict({
        "roles": {stranger.as_did(): ["owner"]},
        "grants": {"owner": ["*"]},
    }).to_dict()
    record_governance(spine, sign_governance_statement(
        signer=stranger, statement_type="amend", policy=evil))

    proj = _project(spine)
    assert proj.version == 1                          # 策略未变
    assert proj.founder_did == owner.as_did()
    assert not can(proj.policy, stranger.as_did(), ACTION_POLICY_AMEND).allowed
    # 但尝试本身可审计("谁试图夺权")。
    assert any(e.type == "governance.amend" for e in spine.read_all())


def test_first_genesis_wins_and_amend_before_genesis_ignored(tmp_path: Path) -> None:
    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    a = _id()
    b = _id()
    # amend 在 genesis 前 → 忽略(尚无宪法)。
    record_governance(spine, sign_governance_statement(
        signer=a, statement_type="amend", policy=_owner_policy(a.as_did())))
    assert not _project(spine).established
    # 两条 genesis,第一条胜。
    record_governance(spine, sign_governance_statement(
        signer=a, statement_type="genesis", policy=_owner_policy(a.as_did())))
    record_governance(spine, sign_governance_statement(
        signer=b, statement_type="genesis", policy=_owner_policy(b.as_did())))
    proj = _project(spine)
    assert proj.established and proj.version == 1
    assert proj.founder_did == a.as_did()


def test_statement_tamper_and_record_rejects_invalid(tmp_path: Path) -> None:
    owner = _id()
    stmt = sign_governance_statement(
        signer=owner, statement_type="genesis",
        policy=_owner_policy(owner.as_did()))
    ok, _ = verify_governance_statement(stmt)
    assert ok
    stmt["policy"]["grants"]["owner"] = ["nothing"]   # 篡改策略
    bad, _ = verify_governance_statement(stmt)
    assert not bad

    spine = SignedEventLog(tmp_path / "spine.jsonl", _id())
    with pytest.raises(ValueError, match="invalid governance"):
        record_governance(spine, stmt)
