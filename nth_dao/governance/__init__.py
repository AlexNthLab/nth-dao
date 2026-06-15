"""Nth DAO 治理子系统(Phase 4)。

声明式策略(``Policy``)+ 确定性评估引擎(``can`` / ``evaluate_quorum``)。把原先
散落在 membership.JoinPolicy / guardian quorum / 各处 if 判断里的治理决策,收敛成
一套**纯函数、跨节点可复算**的规则评估。

也为 Phase 3 的缺口补位:``can(policy, arbiter_did, "dispute.resolve")`` 即可判定一条
仲裁裁决是否出自被授权的仲裁者。

策略修订记入 spine(governance 事件)+ 投影、以及接进 endpoint,是 Phase 4b。
"""
from nth_dao.governance.engine import (
    ACTION_DISPUTE_RESOLVE,
    ACTION_FUND_AUTHORIZE,
    ACTION_MEMBER_ADMIT,
    ACTION_MEMBER_REMOVE,
    ACTION_POLICY_AMEND,
    ACTION_ROLE_ASSIGN,
    ACTION_TASK_ACCEPT,
    Decision,
    can,
    evaluate_quorum,
    granted_actions,
)
from nth_dao.governance.policy import Policy

__all__ = [
    "Policy",
    "Decision",
    "can",
    "evaluate_quorum",
    "granted_actions",
    "ACTION_MEMBER_ADMIT",
    "ACTION_MEMBER_REMOVE",
    "ACTION_ROLE_ASSIGN",
    "ACTION_FUND_AUTHORIZE",
    "ACTION_DISPUTE_RESOLVE",
    "ACTION_TASK_ACCEPT",
    "ACTION_POLICY_AMEND",
]
