"""Nth DAO 执行运行时·信任原语。

不是编排器(那是 agent runtime / CrewAI / LangGraph 的活);这里只补**信任邻接**的
执行原语,且都复用 spine / 收据:
  - checkpoint:基于 spine 的签名检查点 → 中断恢复 + 可验证(不可篡改)。
  - typed_output:类型化交付校验 → "交付了什么"可机器核验,喂给争议/审计/信誉。
"""
from typing import Any, Dict

from nth_dao.runtime.checkpoint import (
    CHECKPOINT_KIND,
    EVENT_EXEC_CHECKPOINT,
    CheckpointProjection,
    ExecutionState,
    sign_checkpoint,
    verify_checkpoint,
)
from nth_dao.runtime.typed_output import (
    EVENT_EXEC_OUTPUT,
    TYPED_OUTPUT_KIND,
    sign_typed_output,
    validate_against_schema,
    verify_typed_output,
)


def record_checkpoint(spine: Any, statement: Dict[str, Any]) -> Any:
    """把一条已签检查点落入 spine(``exec.checkpoint``)。fail-closed。"""
    ok, why = verify_checkpoint(statement)
    if not ok:
        raise ValueError(f"refusing to record invalid checkpoint: {why}")
    return spine.append(EVENT_EXEC_CHECKPOINT, statement)


def record_typed_output(spine: Any, statement: Dict[str, Any]) -> Any:
    """把一条已签类型化交付落入 spine(``exec.output``)。fail-closed(签名 + schema 都验)。"""
    ok, why = verify_typed_output(statement)
    if not ok:
        raise ValueError(f"refusing to record invalid typed output: {why}")
    return spine.append(EVENT_EXEC_OUTPUT, statement)


__all__ = [
    "CHECKPOINT_KIND",
    "EVENT_EXEC_CHECKPOINT",
    "CheckpointProjection",
    "ExecutionState",
    "sign_checkpoint",
    "verify_checkpoint",
    "record_checkpoint",
    "TYPED_OUTPUT_KIND",
    "EVENT_EXEC_OUTPUT",
    "sign_typed_output",
    "verify_typed_output",
    "validate_against_schema",
    "record_typed_output",
]
