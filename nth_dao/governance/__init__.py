"""Nth DAO 治理子系统(Phase 4)。

声明式策略(``Policy``)+ 确定性评估引擎(``can`` / ``evaluate_quorum``)。把原先
散落在 membership.JoinPolicy / guardian quorum / 各处 if 判断里的治理决策,收敛成
一套**纯函数、跨节点可复算**的规则评估。

也为 Phase 3 的缺口补位:``can(policy, arbiter_did, "dispute.resolve")`` 即可判定一条
仲裁裁决是否出自被授权的仲裁者。

策略修订记入 spine(governance 事件)+ 投影、以及接进 endpoint,是 Phase 4b。
"""
from typing import Any, Dict

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
from nth_dao.governance.projection import (
    EVENT_GOV_AMEND,
    EVENT_GOV_GENESIS,
    PolicyProjection,
)
from nth_dao.governance.statement import (
    GOV_AMEND,
    GOV_GENESIS,
    sign_governance_statement,
    verify_governance_statement,
)


def record_governance(spine: Any, statement: Dict[str, Any]) -> Any:
    """把一条已签治理声明落入 ``spine``(``governance.<type>`` 事件),返回 SpineEvent。

    治理是 spine 原生权威记录,故**非** best-effort:声明无效则拒(fail-closed)。
    注意:这里只校验**签名**有效;修宪**授权**(签名者是否有权)由
    ``PolicyProjection`` 回放时据当时策略判定 —— 未授权的 amend 会被记入日志(可审计
    "谁尝试过")但**不被采纳**。
    """
    ok, why = verify_governance_statement(statement)
    if not ok:
        raise ValueError(f"refusing to record invalid governance statement: {why}")
    return spine.append(f"governance.{statement['type']}", statement)


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
    "GOV_GENESIS",
    "GOV_AMEND",
    "sign_governance_statement",
    "verify_governance_statement",
    "record_governance",
    "PolicyProjection",
    "EVENT_GOV_GENESIS",
    "EVENT_GOV_AMEND",
]
