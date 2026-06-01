"""
Mission & MissionStep — long-running multi-step tasks that relay across
sessions / terminals / agents.

Mission states:
    planning  →  active  →  completed
                         →  failed
                         →  paused
                         →  cancelled

Step states:
    todo  →  claimed  →  active  →  done
                                 →  failed
                                 →  handed_off  (transfer to another agent)
                                 →  blocked
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class MissionStatus(str, Enum):
    PLANNING = "planning"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepStatus(str, Enum):
    TODO = "todo"
    CLAIMED = "claimed"      #  Agent
    ACTIVE = "active"        #  Agent
    DONE = "done"
    FAILED = "failed"
    HANDED_OFF = "handed_off"  #  Agent  Agent
    BLOCKED = "blocked"


@dataclass
class MissionStep:
    """ Mission """
    id: str
    description: str
    status: str = StepStatus.TODO.value

    #
    required_capabilities: List[str] = field(default_factory=list)
    inputs: Dict[str, Any] = field(default_factory=dict)
    output: Optional[Dict[str, Any]] = None

    #
    depends_on: List[str] = field(default_factory=list)   #  step id
    assignee: Optional[str] = None                         #  owner agent_id
    previous_assignees: List[str] = field(default_factory=list)  #

    #
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None

    #  /
    notes: List[str] = field(default_factory=list)

    def add_note(self, note: str, author: str = "system") -> None:
        ts = datetime.now().isoformat()
        self.notes.append(f"[{ts[:19]}] {author}: {note}")
        self.updated_at = ts

    def can_start(self, completed_step_ids: set) -> bool:
        """ step """
        return set(self.depends_on).issubset(completed_step_ids)

    @property
    def is_terminal(self) -> bool:
        return self.status in (
            StepStatus.DONE.value,
            StepStatus.FAILED.value,
            StepStatus.HANDED_OFF.value,
        )

    @property
    def is_open(self) -> bool:
        """ claim"""
        return self.status in (StepStatus.TODO.value, StepStatus.HANDED_OFF.value, StepStatus.BLOCKED.value)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "MissionStep":
        fields = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in fields})


@dataclass
class Mission:
    """"""
    id: str
    title: str
    goal: str
    status: str = MissionStatus.PLANNING.value
    owner: str = ""                          #  Agent
    scope: str = "shared"                    #  Blackboard scope  / group:X / private:X

    steps: List[MissionStep] = field(default_factory=list)

    #
    deadline: Optional[str] = None
    priority: str = "normal"  # low / normal / high / critical
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ── template linkage (v0.9.3) ──
    # When set, this mission was instantiated from a template; template_lock
    # captures publisher_sig at instantiation time so the mission stays
    # reproducible even if the template is later modified or deprecated.
    template_id: Optional[str] = None
    template_version: Optional[str] = None
    template_lock: Dict[str, Any] = field(default_factory=dict)

    # ── reserved fields (v0.9.3, not yet implemented) ──
    # Filled in by future versions; default values are inert. Keeping the
    # field names stable now lets a later release populate them without
    # breaking on-disk format.
    owner_did: str = ""
    legal_jurisdiction: str = ""
    governing_arbiter: str = ""
    credentials_required: List[str] = field(default_factory=list)

    #
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None

    @classmethod
    def new(
        cls,
        title: str,
        goal: str,
        owner: str,
        scope: str = "shared",
        steps: Optional[List[dict]] = None,
        **kwargs,
    ) -> "Mission":
        """ Missionsteps  dict """
        m = cls(
            id=uuid.uuid4().hex[:12],
            title=title,
            goal=goal,
            owner=owner,
            scope=scope,
            **kwargs,
        )
        if steps:
            for s in steps:
                step = MissionStep(
                    id=s.get("id") or uuid.uuid4().hex[:8],
                    description=s["description"],
                    required_capabilities=s.get("required_capabilities", []),
                    depends_on=s.get("depends_on", []),
                    inputs=s.get("inputs", {}),
                )
                m.steps.append(step)
        return m

    def to_dict(self) -> dict:
        return {
            **{k: v for k, v in asdict(self).items() if k != "steps"},
            "steps": [s.to_dict() for s in self.steps],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Mission":
        fields = {f for f in cls.__dataclass_fields__}
        # 不 mutate 入参；之前用 data.pop 会把调用方的 dict 改坏
        steps_data = data.get("steps", [])
        m = cls(**{k: v for k, v in data.items() if k in fields and k != "steps"})
        m.steps = [MissionStep.from_dict(s) for s in steps_data]
        return m

    #

    def get_step(self, step_id: str) -> Optional[MissionStep]:
        for s in self.steps:
            if s.id == step_id:
                return s
        return None

    def completed_step_ids(self) -> set:
        return {s.id for s in self.steps if s.status == StepStatus.DONE.value}

    def next_actionable(self, agent_capabilities: Optional[List[str]] = None) -> List[MissionStep]:
        """ claim  step + capability """
        done_ids = self.completed_step_ids()
        candidates = []
        for s in self.steps:
            if not s.is_open:
                continue
            if not s.can_start(done_ids):
                continue
            # capability
            if agent_capabilities is not None and s.required_capabilities:
                if not set(s.required_capabilities).issubset(set(agent_capabilities)):
                    continue
            candidates.append(s)
        return candidates

    def progress(self) -> dict:
        """"""
        total = len(self.steps)
        if total == 0:
            return {"total": 0, "done": 0, "active": 0, "open": 0, "failed": 0, "percent": 0.0}
        done = sum(1 for s in self.steps if s.status == StepStatus.DONE.value)
        active = sum(1 for s in self.steps if s.status == StepStatus.ACTIVE.value)
        open_ = sum(1 for s in self.steps if s.is_open)
        failed = sum(1 for s in self.steps if s.status == StepStatus.FAILED.value)
        return {
            "total": total,
            "done": done,
            "active": active,
            "open": open_,
            "failed": failed,
            "percent": round(done / total * 100, 1),
        }

    def is_finished(self) -> bool:
        """所有 step 都 DONE / HANDED_OFF 终态？空 step list = False（待规划）。"""
        if not self.steps:
            return False
        # HANDED_OFF 算"我方做完了"，新 owner 会继续推进
        terminal_ok = {StepStatus.DONE.value, StepStatus.HANDED_OFF.value}
        return all(s.status in terminal_ok for s in self.steps)

    def short(self) -> str:
        p = self.progress()
        return (
            f"[{self.status:9s}] {self.id} '{self.title}'  "
            f"{p['done']}/{p['total']} done ({p['percent']}%), "
            f"{p['active']} active, {p['failed']} failed"
        )
