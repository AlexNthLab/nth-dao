"""Phase 4:声明式治理引擎 —— 确定性 can / 法定人数 / 约束 / Phase 3 仲裁授权。"""
from __future__ import annotations

import pytest

from nth_dao.governance import (
    ACTION_DISPUTE_RESOLVE,
    ACTION_FUND_AUTHORIZE,
    ACTION_MEMBER_ADMIT,
    ACTION_MEMBER_REMOVE,
    Policy,
    can,
    evaluate_quorum,
    granted_actions,
)


def _policy() -> Policy:
    return Policy.from_dict({
        "roles": {
            "did:owner": ["owner"],
            "did:admin": ["admin"],
            "did:arb": ["arbiter"],
            "did:bob": ["member"],
        },
        "grants": {
            "owner": ["*"],
            "admin": ["member.admit", "fund.authorize"],
            "arbiter": ["dispute.*"],
            "member": ["task.accept"],
        },
        "constraints": {
            "fund.authorize": {"max_minor": 1000},
            "member.remove": {"quorum": {"role": "admin", "threshold": 2}},
        },
    })


def test_roles_and_granted_actions() -> None:
    p = _policy()
    assert p.roles_of("did:admin") == {"admin"}
    assert p.roles_of("did:nobody") == set()
    assert "member.admit" in granted_actions(p, "did:admin")
    assert granted_actions(p, "did:owner") == {"*"}


def test_can_role_and_wildcards() -> None:
    p = _policy()
    assert can(p, "did:admin", ACTION_MEMBER_ADMIT).allowed
    assert not can(p, "did:bob", ACTION_MEMBER_ADMIT).allowed
    # owner "*" 放行一切
    assert can(p, "did:owner", "anything.at.all").allowed
    # arbiter "dispute.*" 放行 dispute.resolve,但不放行别的域
    assert can(p, "did:arb", ACTION_DISPUTE_RESOLVE).allowed
    assert not can(p, "did:arb", ACTION_MEMBER_ADMIT).allowed
    # 无角色 → 拒
    assert not can(p, "did:ghost", ACTION_DISPUTE_RESOLVE).allowed


def test_fund_constraint_max_minor() -> None:
    p = _policy()
    assert can(p, "did:admin", ACTION_FUND_AUTHORIZE,
               {"amount_minor": 1000}).allowed
    assert not can(p, "did:admin", ACTION_FUND_AUTHORIZE,
                   {"amount_minor": 1001}).allowed
    # 缺 amount_minor → 拒(约束需要的输入缺失)
    assert not can(p, "did:admin", ACTION_FUND_AUTHORIZE).allowed
    # bool 不算 int
    assert not can(p, "did:admin", ACTION_FUND_AUTHORIZE,
                   {"amount_minor": True}).allowed


def test_quorum_action() -> None:
    p = _policy()
    # 单主体 can() 一律拒(法定人数动作)
    assert not can(p, "did:admin", ACTION_MEMBER_REMOVE).allowed
    # 两个不同 admin → 达标
    assert evaluate_quorum(p, ACTION_MEMBER_REMOVE,
                           ["did:admin", "did:admin2"]).allowed is False  # admin2 无角色
    p2 = Policy.from_dict({
        "roles": {"a": ["admin"], "b": ["admin"], "c": ["member"]},
        "grants": {"admin": ["member.remove"]},
        "constraints": {"member.remove": {"quorum": {"role": "admin", "threshold": 2}}},
    })
    assert evaluate_quorum(p2, "member.remove", ["a", "b"]).allowed
    # 重复同一人不重复计票
    assert not evaluate_quorum(p2, "member.remove", ["a", "a"]).allowed
    # member 不算 admin
    assert not evaluate_quorum(p2, "member.remove", ["a", "c"]).allowed
    # 非法定人数动作走 quorum → 拒
    assert not evaluate_quorum(p2, "task.accept", ["a", "b"]).allowed


def test_determinism() -> None:
    p = _policy()
    d1 = can(p, "did:admin", ACTION_FUND_AUTHORIZE, {"amount_minor": 500})
    d2 = can(p, "did:admin", ACTION_FUND_AUTHORIZE, {"amount_minor": 500})
    assert (d1.allowed, d1.reason) == (d2.allowed, d2.reason)


def test_closes_phase3_arbiter_gap() -> None:
    # Phase 3 缺口:任意 DID 都能 resolve。Phase 4 用策略判定授权仲裁者。
    p = _policy()
    assert can(p, "did:arb", ACTION_DISPUTE_RESOLVE).allowed       # 授权仲裁者
    assert not can(p, "did:bob", ACTION_DISPUTE_RESOLVE).allowed   # 普通成员不可
    assert not can(p, "did:random", ACTION_DISPUTE_RESOLVE).allowed  # 路人不可


def test_policy_roundtrip_and_bad_input() -> None:
    p = _policy()
    assert Policy.from_dict(p.to_dict()).roles_of("did:arb") == {"arbiter"}
    with pytest.raises(TypeError):
        Policy.from_dict({"roles": {"x": "not-a-list"}})
    with pytest.raises(TypeError):
        Policy.from_dict([])
