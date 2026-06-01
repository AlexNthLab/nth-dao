"""
MissionRunner — per-agent driver loop for picking up and executing mission steps.

Lifecycle:
    1. find_work()  — discover the next step that matches my capabilities and
                      whose dependencies are satisfied
    2. claim()      — atomic CAS claim (other agents will get ClaimConflict)
    3. execute()    — caller drives the LLM backend (this class doesn't)
    4. complete() / handoff() / fail() / block()

Handoff:
    handoff(step_id, to_agent_id, note)
        step.status = handed_off, step.assignee = to_agent_id
        to_agent_id's next find_work() will surface this step.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, List, Optional

from .mission import MissionStep, MissionStatus, StepStatus
from .mission_store import ClaimConflict, MissionStore


@dataclass
class RunnerOutcome:
    """ claim+execute """
    success: bool
    mission_id: str
    step_id: str
    note: str = ""
    output: Optional[dict] = None


class MissionRunner:
    """ Agent """

    def __init__(
        self,
        store: MissionStore,
        agent_id: str,
        capabilities: Optional[List[str]] = None,
        registry=None,  # 可选 AgentRegistry —— 让 handoff 能验证目标 alive
    ):
        self.store = store
        self.agent_id = agent_id
        self.capabilities = capabilities or []
        self.registry = registry

    #  1.

    def find_work(
        self,
        prefer_mission_id: Optional[str] = None,
        prefer_handoff_to_me: bool = True,
    ) -> Optional[tuple]:
        """
         Mission  step

            1.  handoff  Agent  step
            2. prefer_mission_id  Mission
            3. capability  +  TODO

        Returns:
            (mission, step)  None
        """
        relevant = self.store.list_for_agent(
            self.agent_id, self.capabilities, include_team=True
        )

        # handed_off  me
        if prefer_handoff_to_me:
            for m in relevant:
                for s in m.steps:
                    if (
                        s.status == StepStatus.HANDED_OFF.value
                        and s.assignee == self.agent_id
                    ):
                        return m, s

        #  mission
        if prefer_mission_id:
            m = self.store.get(prefer_mission_id)
            if m:
                actionable = m.next_actionable(self.capabilities)
                if actionable:
                    return m, actionable[0]

        #  TODO +
        for m in relevant:
            actionable = m.next_actionable(self.capabilities)
            if actionable:
                return m, actionable[0]

        return None

    #  2. claim

    def claim(self, mission_id: str, step_id: str) -> Optional[MissionStep]:
        """原子 claim —— 被别人抢走时返回 None（不再 silent overwrite）。

        与之前版本的兼容性：返回 MissionStep 或 None。
        要拿到具体冲突原因，调用 store.try_claim 自己 catch ClaimConflict。
        """
        try:
            return self.store.try_claim(
                mission_id=mission_id,
                step_id=step_id,
                agent_id=self.agent_id,
                capabilities=self.capabilities,
            )
        except ClaimConflict:
            return None

    #  3.

    def complete(
        self,
        mission_id: str,
        step_id: str,
        output: Optional[dict] = None,
        note: str = "",
    ) -> RunnerOutcome:
        """ step"""
        step = self.store.update_step(
            mission_id=mission_id,
            step_id=step_id,
            status=StepStatus.DONE.value,
            output=output,
            note=note or "completed",
            note_author=self.agent_id,
        )
        return RunnerOutcome(
            success=step is not None,
            mission_id=mission_id,
            step_id=step_id,
            note=note,
            output=output,
        )

    def handoff(
        self,
        mission_id: str,
        step_id: str,
        to_agent_id: str,
        note: str = "",
        require_alive: bool = True,
    ) -> RunnerOutcome:
        """把 step 转交给另一个 agent。

        前置条件：
            - to_agent_id 非空且不等于 self.agent_id
            - 当前 step 必须由 self.agent_id 持有（ACTIVE 且 assignee==self）
            - require_alive=True 且注入了 registry → 目标必须在线（否则 step
              会挂死给一个不存在的 agent_id）
        """
        if not to_agent_id:
            raise ValueError("handoff requires a non-empty to_agent_id")
        if to_agent_id == self.agent_id:
            raise ValueError("cannot handoff to yourself")

        if require_alive and self.registry is not None:
            target = self.registry.get(to_agent_id)
            if target is None:
                return RunnerOutcome(
                    success=False, mission_id=mission_id, step_id=step_id,
                    note=f"handoff refused: target '{to_agent_id}' not registered",
                )
            if not target.is_alive():
                return RunnerOutcome(
                    success=False, mission_id=mission_id, step_id=step_id,
                    note=f"handoff refused: target '{to_agent_id}' not alive "
                         f"(last_seen={target.last_seen})",
                )

        handoff_note = note or f"handed off from {self.agent_id} to {to_agent_id}"
        try:
            step = self.store.update_step(
                mission_id=mission_id,
                step_id=step_id,
                status=StepStatus.HANDED_OFF.value,
                assignee=to_agent_id,
                note=handoff_note,
                note_author=self.agent_id,
                expect_assignee_in=[self.agent_id],
            )
        except ClaimConflict as e:
            return RunnerOutcome(
                success=False, mission_id=mission_id, step_id=step_id,
                note=f"handoff refused: {e}",
            )
        return RunnerOutcome(
            success=step is not None,
            mission_id=mission_id,
            step_id=step_id,
            note=handoff_note,
        )

    def fail(
        self,
        mission_id: str,
        step_id: str,
        reason: str,
    ) -> RunnerOutcome:
        step = self.store.update_step(
            mission_id=mission_id,
            step_id=step_id,
            status=StepStatus.FAILED.value,
            note=f"FAILED: {reason}",
            note_author=self.agent_id,
        )
        return RunnerOutcome(
            success=False,
            mission_id=mission_id,
            step_id=step_id,
            note=reason,
        )

    def block(self, mission_id: str, step_id: str, reason: str) -> RunnerOutcome:
        """ step"""
        step = self.store.update_step(
            mission_id=mission_id,
            step_id=step_id,
            status=StepStatus.BLOCKED.value,
            note=f"BLOCKED: {reason}",
            note_author=self.agent_id,
        )
        return RunnerOutcome(
            success=step is not None,
            mission_id=mission_id,
            step_id=step_id,
            note=reason,
        )

    #  4.

    def my_active_steps(self) -> List[tuple]:
        """ Agent  step (mission, step)"""
        out = []
        for m in self.store.list_active():
            for s in m.steps:
                if s.assignee == self.agent_id and s.status == StepStatus.ACTIVE.value:
                    out.append((m, s))
        return out
