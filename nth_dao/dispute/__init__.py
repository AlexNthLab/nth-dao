"""Nth DAO 争议子系统(Phase 3)。

争议是 **spine 原生** 记录:无旧 store、无影子,spine 即其唯一事实源。当事方签名
声明(open/evidence/resolve),node 经 ``record_dispute`` 落入统一日志;
``DisputeProjection`` 折叠出争议记录;审计层(``nth_dao.audit``)据此回放证据链。
"""
from typing import Any, Dict

from nth_dao.dispute.projection import (
    EVENT_DISPUTE_EVIDENCE,
    EVENT_DISPUTE_OPEN,
    EVENT_DISPUTE_RESOLVE,
    STATUS_OPEN,
    STATUS_RESOLVED,
    DisputeProjection,
    DisputeRecord,
)
from nth_dao.dispute.statement import (
    DISPUTE_EVIDENCE,
    DISPUTE_OPEN,
    DISPUTE_RESOLVE,
    sign_dispute_statement,
    verify_dispute_statement,
)


def record_dispute(spine: Any, statement: Dict[str, Any]) -> Any:
    """把一条已签争议声明落入 ``spine``(``dispute.<type>`` 事件),返回 SpineEvent。

    争议是 spine 原生记录,故**非** best-effort:声明无效则拒(fail-closed),不把
    垃圾写进权威日志。
    """
    ok, why = verify_dispute_statement(statement)
    if not ok:
        raise ValueError(f"refusing to record invalid dispute statement: {why}")
    return spine.append(f"dispute.{statement['type']}", statement)


__all__ = [
    "DISPUTE_OPEN",
    "DISPUTE_EVIDENCE",
    "DISPUTE_RESOLVE",
    "sign_dispute_statement",
    "verify_dispute_statement",
    "EVENT_DISPUTE_OPEN",
    "EVENT_DISPUTE_EVIDENCE",
    "EVENT_DISPUTE_RESOLVE",
    "STATUS_OPEN",
    "STATUS_RESOLVED",
    "DisputeProjection",
    "DisputeRecord",
    "record_dispute",
]
