"""签名执行检查点 —— 中断恢复 + 可验证(基于 spine)。

CrewAI 的 ``checkpoint=True`` 自动快照恢复;而签名因果日志本就是天然 checkpoint。
执行者每推进到一个可恢复点就签一条 checkpoint(``execution_id`` + ``step`` 进度标记 +
``state`` 快照),落 spine。中断后回放 spine → 取该 execution 的**最新有效** checkpoint →
从 ``state`` 恢复。每条 checkpoint 执行者签名、且被 spine 链锚定 → 恢复点**不可伪造、
不可篡改**(强于明文快照)。

自验证(与 receipt / dispute 同构):``executor_did`` + ``sig`` over canonical 体。
归属锁:同一 execution_id 的首条 checkpoint 定 owner,后续只认同一 executor —— 防
他人伪造检查点劫持/回退别人的执行。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from nth_dao.b64u import b64u_decode, b64u_encode
from nth_dao.canonical_json import canonical_json
from nth_dao.execution_receipt import now_ms
from nth_dao.identity import AgentIdentity
from nth_dao.spine.event import SpineEvent
from nth_dao.spine.projection import Projection

CHECKPOINT_KIND = "nth-exec-checkpoint-v1"
EVENT_EXEC_CHECKPOINT = "exec.checkpoint"


def _signing_body(stmt: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in stmt.items() if k != "sig"}


def sign_checkpoint(
    *,
    executor: AgentIdentity,
    execution_id: str,
    step: Any,
    state: Optional[Dict[str, Any]] = None,
    issued_at_ms: int = 0,
) -> Dict[str, Any]:
    """执行者签名一条检查点。``step`` 是进度标记(int/str),``state`` 是恢复用快照。"""
    if not execution_id:
        raise ValueError("execution_id required")
    stmt: Dict[str, Any] = {
        "kind": CHECKPOINT_KIND,
        "execution_id": str(execution_id),
        "step": step,
        "state": dict(state or {}),
        "executor_did": executor.as_did(),
        "issued_at_ms": int(issued_at_ms or now_ms()),
    }
    stmt["sig"] = b64u_encode(executor.sign(canonical_json(_signing_body(stmt))))
    return stmt


def verify_checkpoint(stmt: Dict[str, Any]) -> Tuple[bool, str]:
    """校验:结构合法 + ``executor_did`` 签名有效。fail-closed。"""
    if not isinstance(stmt, dict):
        return False, "not a dict"
    if stmt.get("kind") != CHECKPOINT_KIND:
        return False, "wrong kind"
    for f in ("execution_id", "executor_did", "sig"):
        v = stmt.get(f)
        if not isinstance(v, str) or not v:
            return False, f"missing/invalid {f}"
    try:
        verifier = AgentIdentity.from_did(stmt["executor_did"])
        sig = b64u_decode(stmt["sig"])
        body = canonical_json(_signing_body(stmt))
    except Exception as exc:  # noqa: BLE001
        return False, f"bad encoding: {exc}"
    if not verifier.verify(body, sig):
        return False, "signature invalid"
    return True, "ok"


@dataclass
class ExecutionState:
    execution_id: str
    executor_did: str
    step: Any = None
    state: Dict[str, Any] = field(default_factory=dict)
    checkpoints: int = 0


class CheckpointProjection(Projection):
    """折叠 ``exec.checkpoint`` → 每个 execution 的**最新有效**恢复点。

    归属锁:首条 checkpoint 定 executor_did,后续只认同一执行者(防他人回退/劫持)。
    last-wins(spine 序):最后一条同执行者 checkpoint 即恢复点(按 spine 顺序,不假设
    ``step`` 可比较)。

    ⚠️ **接线假设(对抗审查标注)**:first-wins 仅当"首条记录者就是合法执行者"才安全。
    它**挡不住抢跑**——恶意方对别人正跑的 execution_id 抢先签一条即可占 owner、把真
    执行者锁在外面。所以接线层(未来的 record 端点)**必须**保证只有合法执行者能记录:
    execution_id 由任务/认领系统发给认领者,且端点认证调用者 DID == executor_did。
    本投影只做密码学层面的"同一执行者"约束,合法性绑定在上游。
    """

    def __init__(self) -> None:
        self._owner: Dict[str, str] = {}
        self._latest: Dict[str, ExecutionState] = {}

    def reset(self) -> None:
        self._owner.clear()
        self._latest.clear()

    def apply(self, event: SpineEvent) -> None:
        if event.type != EVENT_EXEC_CHECKPOINT:
            return
        stmt = event.payload if isinstance(event.payload, dict) else {}
        ok, _ = verify_checkpoint(stmt)
        if not ok:
            return
        eid = stmt["execution_id"]
        did = stmt["executor_did"]
        owner = self._owner.setdefault(eid, did)
        if owner != did:
            return   # 非首个执行者 → 拒(防伪造检查点劫持别人的执行)
        rec = self._latest.get(eid)
        if rec is None:
            rec = ExecutionState(execution_id=eid, executor_did=did)
            self._latest[eid] = rec
        rec.step = stmt.get("step")
        rec.state = dict(stmt.get("state", {}))
        rec.checkpoints += 1

    def resume_point(self, execution_id: str) -> Optional[ExecutionState]:
        """该执行的最新恢复点;无则 None(从头开始)。"""
        return self._latest.get(execution_id)

    def all_executions(self) -> List[ExecutionState]:
        return list(self._latest.values())
