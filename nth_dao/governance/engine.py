"""治理评估引擎 —— 对 Policy 做确定性判定(Phase 4)。

纯函数、无 I/O、无 wall-clock、无随机:同 (policy, principal, action, context) 必得
同 Decision → 跨节点一致(任何节点都能独立复算同一治理判定)。

  - ``can(policy, did, action, context)``         单主体能否做某动作
  - ``evaluate_quorum(policy, action, approvers)`` 需法定人数的动作是否够票

动作匹配:授予 ``"*"`` 放行一切;``"dispute.*"`` 放行 ``dispute.`` 前缀;否则精确匹配。
约束:``max_minor`` 校验 ``context["amount_minor"]`` 不超额;``quorum`` 标记该动作必须
走 ``evaluate_quorum``(单主体 ``can`` 一律拒)。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from nth_dao.governance.policy import Policy

# 常用治理动作(字符串即契约;此处仅为文档/复用)。
ACTION_MEMBER_ADMIT = "member.admit"
ACTION_MEMBER_REMOVE = "member.remove"
ACTION_ROLE_ASSIGN = "role.assign"
ACTION_FUND_AUTHORIZE = "fund.authorize"
ACTION_DISPUTE_RESOLVE = "dispute.resolve"
ACTION_TASK_ACCEPT = "task.accept"
ACTION_POLICY_AMEND = "policy.amend"
ACTION_HANDOFF_RESPOND = "handoff.respond"


@dataclass
class Decision:
    allowed: bool
    reason: str

    def __bool__(self) -> bool:
        return self.allowed


def _action_matches(pattern: str, action: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith(".*"):
        prefix = pattern[:-1]          # "dispute." (含点)
        return action.startswith(prefix)
    return pattern == action


def granted_actions(policy: Policy, did: str) -> Set[str]:
    """``did`` 经其各角色获得的动作 pattern 并集。"""
    out: Set[str] = set()
    for role in policy.roles_of(did):
        out.update(policy.grants.get(role, []) or [])
    return out


def _grants_action(policy: Policy, did: str, action: str) -> bool:
    return any(_action_matches(p, action) for p in granted_actions(policy, did))


def can(
    policy: Policy, did: str, action: str,
    context: Optional[Dict[str, Any]] = None,
) -> Decision:
    """单主体 ``did`` 能否执行 ``action``(可带 ``context`` 供约束校验)。"""
    context = context or {}
    roles = policy.roles_of(did)
    if not roles:
        return Decision(False, "principal has no roles")
    if not _grants_action(policy, did, action):
        return Decision(
            False, f"roles {sorted(roles)} grant no match for {action!r}")

    c = policy.constraints.get(action, {})
    if "quorum" in c:
        return Decision(
            False, f"{action!r} requires quorum; use evaluate_quorum()")
    if "max_minor" in c:
        amount = context.get("amount_minor")
        if not isinstance(amount, int) or isinstance(amount, bool):
            return Decision(
                False, f"{action!r} needs int context['amount_minor']")
        if amount > int(c["max_minor"]):
            return Decision(
                False, f"amount {amount} exceeds max {c['max_minor']}")
    return Decision(True, "ok")


def evaluate_quorum(
    policy: Policy, action: str, approvers: List[str],
    context: Optional[Dict[str, Any]] = None,
) -> Decision:
    """需法定人数的动作:统计**不同**且具备 quorum 角色的批准者是否达阈值。"""
    c = policy.constraints.get(action, {})
    q = c.get("quorum")
    if not isinstance(q, dict):
        return Decision(False, f"{action!r} is not a quorum action")
    role = str(q.get("role", ""))
    threshold = int(q.get("threshold", 0))
    if threshold < 1:
        return Decision(False, "quorum threshold must be >= 1")
    qualified = {d for d in approvers if role in policy.roles_of(d)}
    if len(qualified) >= threshold:
        return Decision(
            True, f"{len(qualified)}/{threshold} {role!r} approvals")
    return Decision(
        False, f"need {threshold} {role!r} approvals, got {len(qualified)}")
