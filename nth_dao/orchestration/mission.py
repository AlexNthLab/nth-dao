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

import re as _re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple


# ===== G-4 defence-in-depth caps for regex rule =====

_REGEX_PATTERN_MAX = 1024
_REGEX_CONTENT_MAX = 65536


# ===== G-11: acceptance_criteria rule registry =====
#
# Each rule is extracted to a module-level checker so it can be
# unit-tested in isolation and so MissionStep.evaluate() stays a
# small dispatcher. The registry is an ordered list of (rule_name,
# checker) pairs - order matters because the aggregated reason
# string (G-10) reads top-down for human reviewers.
#
# Checker contract:
#   _check_<name>(rule_value, output, content) -> Optional[str]
#     rule_value:  the value from acceptance_criteria[rule_name]
#     output:      the full output dict (for rules like required_keys
#                  / max_tokens that don't live in output["content"])
#     content:    str(output.get("content", "")) — precomputed once
#   Returns None on pass, the failure-reason fragment on fail.
#
# Each fragment MUST contain the rule name as a substring so existing
# tests like ``assert "min_length" in reason`` keep working.


def _check_required_keys(
    rule_value: Any, output: Dict[str, Any], content: str,
) -> Optional[str]:
    missing = [k for k in rule_value if k not in output]
    if missing:
        return f"output missing required_keys: {missing}"
    return None


def _check_min_length(
    rule_value: Any, output: Dict[str, Any], content: str,
) -> Optional[str]:
    if len(content) < rule_value:
        return (
            f"content length {len(content)} < min_length {rule_value}"
        )
    return None


def _check_must_contain(
    rule_value: Any, output: Dict[str, Any], content: str,
) -> Optional[str]:
    absent = [s for s in rule_value if s not in content]
    if absent:
        return f"content missing must_contain tokens: {absent}"
    return None


def _check_forbidden(
    rule_value: Any, output: Dict[str, Any], content: str,
) -> Optional[str]:
    present = [s for s in rule_value if s in content]
    if present:
        return f"content contains forbidden tokens: {present}"
    return None


def _check_regex(
    rule_value: Any, output: Dict[str, Any], content: str,
) -> Optional[str]:
    """G-4: ReDoS defence-in-depth caps + compile-error reporting."""
    if not isinstance(rule_value, str):
        return f"regex rule must be a string, got {type(rule_value).__name__}"
    if len(rule_value) > _REGEX_PATTERN_MAX:
        return (
            f"regex pattern exceeds {_REGEX_PATTERN_MAX}-char cap "
            f"(got {len(rule_value)}); this is a security cap, see "
            f"MissionStep.evaluate docstring"
        )
    try:
        compiled = _re.compile(rule_value)
    except _re.error as exc:
        return f"regex compile failed: {exc}"
    sample = content[:_REGEX_CONTENT_MAX]
    if not compiled.search(sample):
        return f"content does not match regex {rule_value!r}"
    return None


def _check_max_tokens(
    rule_value: Any, output: Dict[str, Any], content: str,
) -> Optional[str]:
    """G-3: tokens_used coercion safety."""
    raw_used = output.get("tokens_used", 0)
    try:
        used = int(raw_used)
    except (TypeError, ValueError):
        return (
            f"tokens_used field is not numeric: {raw_used!r} "
            f"(expected int / castable when max_tokens rule is set)"
        )
    if used > rule_value:
        return f"tokens_used {used} > max_tokens {rule_value}"
    return None


# Public so tests + future extension points can inspect the registry.
# Tuple-of-tuples is intentional: immutability prevents downstream code
# from monkey-patching the list at runtime, which would let an unknown
# rule sneak into evaluation.
ACCEPTANCE_RULE_REGISTRY: Tuple[
    Tuple[str, Callable[[Any, Dict[str, Any], str], Optional[str]]], ...
] = (
    ("required_keys", _check_required_keys),
    ("min_length",    _check_min_length),
    ("must_contain",  _check_must_contain),
    ("forbidden",     _check_forbidden),
    ("regex",         _check_regex),
    ("max_tokens",    _check_max_tokens),
)


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
    # PR-3: output validated against acceptance_criteria FAILED but
    # the work itself wasn't a structural FAILURE - the human-readable
    # output didn't meet the criteria (too short, missing required
    # tokens, etc.). Distinct from FAILED so the orchestrator can
    # route NEEDS_REVIEW into a handoff/escalation flow without
    # losing the original output for the reviewer to inspect.
    NEEDS_REVIEW = "needs_review"
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
    # PR-2: env-platform allow-list. Empty list = no platform
    # restriction (current/legacy behaviour); ["linux", "darwin"] =
    # only Linux or macOS agents may claim this step. Windows-only
    # steps go in as ["windows"]. The orchestrator filters via
    # ``next_actionable(agent_platform=...)``.
    required_platform: List[str] = field(default_factory=list)
    # G-15: optional OS+CPU architecture allow-list. Empty list =
    # no runtime restriction. Values are lowercase compound keys such
    # as ``linux-x86_64``, ``linux-arm64``, ``darwin-arm64`` or
    # ``windows-amd64``. This complements, rather than replaces,
    # required_platform: the former is OS-only, this is exact runtime
    # shape for binary / local-LLM workloads.
    required_runtime: List[str] = field(default_factory=list)
    inputs: Dict[str, Any] = field(default_factory=dict)
    output: Optional[Dict[str, Any]] = None
    # PR-3: optional output-quality rules. None = no automated check
    # (current/legacy behaviour); dict = rules described in
    # ``evaluate()`` below. Schema is intentionally a free-form dict
    # so individual mission templates can layer in domain-specific
    # rules without changing the MissionStep schema.
    acceptance_criteria: Optional[Dict[str, Any]] = None
    # G-2 (Voss audit): append-only review trail. Every NEEDS_REVIEW
    # transition pushes the rejected output here so the original
    # submitter's work is preserved when a second agent re-claims
    # and overwrites ``output``. Each entry shape:
    #
    #     {
    #         "ts": ISO-8601,
    #         "by": agent_id,
    #         "output": <whatever output was submitted>,
    #         "reason": <evaluate failure reason>,
    #     }
    #
    # The list is APPEND-ONLY by convention (no API to delete entries
    # from individual MissionRunner methods). Reviewers reading the
    # step see the full chain of failed attempts plus the reason for
    # each, which is the whole point of NTH DAO's "audit by default"
    # posture - we don't silently drop work.
    review_trail: List[Dict[str, Any]] = field(default_factory=list)

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
        return self.status in (
            StepStatus.TODO.value,
            StepStatus.HANDED_OFF.value,
            StepStatus.BLOCKED.value,
            # PR-3: NEEDS_REVIEW is open for a different agent (or the
            # same agent re-trying) to take over - the prior output is
            # preserved for inspection.
            StepStatus.NEEDS_REVIEW.value,
        )

    def evaluate(self, output: Optional[Dict[str, Any]]) -> tuple[bool, str]:
        """PR-3: validate ``output`` against ``acceptance_criteria``.

        Returns ``(ok, reason)``. ``reason`` is ``"ok"`` when ok=True.

        Supported rules (all optional):

          min_length: int          output["content"] character lower bound
          must_contain: list[str]  output["content"] must include each
          forbidden: list[str]     output["content"] must include none
          regex: str               output["content"] must match (re.search)
          required_keys: list[str] output dict must carry each top-level key
          max_tokens: int          output.get("tokens_used") upper bound

        Missing or None ``acceptance_criteria`` → always passes (the
        backward-compatible no-rules behaviour). A non-dict ``output``
        when criteria are set fails immediately (structural prereq,
        cannot apply per-rule checks to a non-dict).

        AGGREGATION (G-10):
            When several rules fail, ALL their failures are reported
            in the reason string, joined by ``"; "``. The previous
            short-circuit design returned only the first failure, so a
            re-submitting agent would fix one problem only to discover
            on the next round that two more existed. Aggregating gives
            the resubmitter a complete punch-list on the first NEEDS_REVIEW
            trip - one of the explicit goals of PR-3.

            Per-rule fragments still each contain the rule name (so
            existing substring assertions like ``"min_length" in reason``
            keep working). Order of fragments matches the rule listing
            above: required_keys → min_length → must_contain → forbidden
            → regex → max_tokens.

        SECURITY NOTE (G-4):
            ``acceptance_criteria`` is TRUSTED input. It MUST come
            from the mission owner / template author, NEVER from an
            untrusted runtime caller. Python's ``re`` engine has no
            timeout and is vulnerable to ReDoS via patterns like
            ``(a+)+`` on adversarial input. As defence-in-depth this
            method enforces:
              * pattern length <= 1024 chars (catches the most absurd
                hand-crafted bombs)
              * content evaluated against the regex truncated to 64 KiB
            For full protection a deployment should either reject any
            mission template whose acceptance_criteria.regex came from
            an untrusted source, or swap re for an re2 binding.
        """
        if self.acceptance_criteria is None:
            return True, ""
        if not isinstance(output, dict):
            # Structural prereq: per-rule checks all assume a dict
            # output. Short-circuit here is intentional, not aggregated.
            return False, "output must be a dict when acceptance_criteria is set"

        rules = self.acceptance_criteria
        content = str(output.get("content", "")) if "content" in output else ""
        # G-10: accumulate failures, do NOT short-circuit.
        # G-11: dispatch via ACCEPTANCE_RULE_REGISTRY for testability
        #       and order stability.
        failures: List[str] = []
        for rule_name, checker in ACCEPTANCE_RULE_REGISTRY:
            if rule_name not in rules:
                continue
            fragment = checker(rules[rule_name], output, content)
            if fragment is not None:
                failures.append(fragment)

        if failures:
            return False, "; ".join(failures)
        return True, "ok"

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
                    # PR-2: forward the platform allow-list from the
                    # template dict so callers building from JSON
                    # mission specs don't have to manipulate the
                    # dataclass directly.
                    required_platform=s.get("required_platform", []),
                    # G-15: OS+architecture allow-list, e.g.
                    # ["linux-x86_64", "darwin-arm64"].
                    required_runtime=s.get("required_runtime", []),
                    depends_on=s.get("depends_on", []),
                    inputs=s.get("inputs", {}),
                    # PR-3: forward acceptance_criteria same as above.
                    acceptance_criteria=s.get("acceptance_criteria"),
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

    def next_actionable(
        self,
        agent_capabilities: Optional[List[str]] = None,
        agent_platform: Optional[str] = None,
        agent_runtime: Optional[str] = None,
    ) -> List[MissionStep]:
        """Step claimable by the calling agent.

        PR-2: ``agent_platform`` is a new optional filter (defaults
        to None = no platform restriction, fully backward compatible).
        Pass the value from ``_capture_env_metadata()["platform"]``
        on the calling side. Steps whose ``required_platform`` list
        is non-empty AND does not contain the agent's platform are
        skipped - the orchestrator never offers Linux-only work to
        a Windows agent.

        G-15: ``agent_runtime`` is an optional OS+architecture key
        (for example ``linux-x86_64``). When supplied, steps whose
        ``required_runtime`` list is non-empty and does not contain
        the key are skipped. When omitted, runtime filtering is
        inactive for backward compatibility with older callers.
        """
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
            # PR-2 platform filter
            if agent_platform is not None and s.required_platform:
                if agent_platform.lower() not in [
                    p.lower() for p in s.required_platform
                ]:
                    continue
            # G-15 runtime filter (OS + CPU architecture)
            if agent_runtime is not None and s.required_runtime:
                if agent_runtime.lower() not in [
                    r.lower() for r in s.required_runtime
                ]:
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
        """All steps delivered work; a handoff is still awaiting the next agent."""
        if not self.steps:
            return False
        return all(s.status == StepStatus.DONE.value for s in self.steps)

    def short(self) -> str:
        p = self.progress()
        return (
            f"[{self.status:9s}] {self.id} '{self.title}'  "
            f"{p['done']}/{p['total']} done ({p['percent']}%), "
            f"{p['active']} active, {p['failed']} failed"
        )
