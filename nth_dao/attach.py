"""
attach() — one-line integration API.

Join any agent framework to NTH DAO:

    import nth_dao as nth
    team = nth.attach(
        agent_id="my-agent",
        backend="mock",                # str (registry id) or AgentBackend instance
        capabilities=["python", "web"],
        groups=["frontend"],
        workspace="./my-team-workspace",
    )

    # The TeamSession exposes:
    team.memory                # TeamMemoryManager (4 providers, injected into system prompt)
    team.blackboard            # Blackboard (shared workspace)
    team.runner                # MissionRunner (claim / handoff / complete)
    team.finder                # PeerFinder (capability-based teammate lookup)
    team.discover()            # list_alive agents
    team.start_mission(...)    # publish a multi-step mission
    team.detach()              # flush ledger, unregister, close backend

Design:
- attach() wires up 4 memory providers + Blackboard + Discovery + Mission store
- TeamSession is a thin façade combining them
- detach() flushes the ledger and releases resources (idempotent)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Union, runtime_checkable

from team_layer import TeamAgent, TeamMemoryManager
from team_layer.backends import AgentBackend, default_registry
from team_layer.blackboard import Blackboard, BlackboardProvider
from team_layer.memory_providers import (
    LedgerProvider,
    SoulProvider,
    UserModelProvider,
    VectorProvider,
)

from .discovery import AgentRegistry, PeerFinder
from .orchestration import Mission, MissionRunner, MissionStore
from .membership import MembershipManager
from .identity import AgentIdentity
from .event_bus import EventBus
from .groups import GroupManager

logger = logging.getLogger("nth_dao.attach")


@runtime_checkable
class _Closeable(Protocol):
    """Structural protocol for backends that have explicit resource release.

    A backend may implement any one of `close`, `stop`, or `shutdown`
    (in that priority order). detach() will call the first one it finds.
    """

    def close(self) -> Any: ...  # pragma: no cover — protocol stub


def _owner_or_none(agent_identity: Optional[AgentIdentity], config) -> Optional[AgentIdentity]:
    """Return agent_identity if it matches the team's pinned owner_pubkey.

    Ensures only the legitimate owner re-signs team.json. Any other agent
    sees `owner_identity=None` on their MembershipManager, so their saves
    won't carry signatures — which will then fail load_config() on other
    nodes (preventing tamper-via-git-sync).
    """
    if agent_identity is None or not getattr(agent_identity, "can_sign", False):
        return None
    pinned = getattr(config, "owner_pubkey", "")
    if pinned and pinned == agent_identity.pubkey_hex:
        return agent_identity
    # Fresh team with no owner pinned yet → can't act as owner via attach().
    # Use `MembershipManager(workspace).enable_signed_owner(identity, actor_id=...)`
    # explicitly to bootstrap.
    return None


def _close_backend(backend: Optional[Any]) -> None:
    """Best-effort backend release, tolerant to ducks of varying species."""
    if backend is None:
        return
    for closer in ("close", "stop", "shutdown"):
        fn = getattr(backend, closer, None)
        if callable(fn):
            try:
                fn()
            except Exception as e:
                logger.warning("backend.%s raised during detach: %s", closer, e)
            return
    logger.debug(
        "backend %r has no close/stop/shutdown method; skipping",
        type(backend).__name__,
    )


@dataclass
class TeamSession:
    """Façade returned by attach(); aggregates the full NTH DAO runtime for one agent."""
    agent_id: str
    backend_id: str
    workspace: Path

    agent: TeamAgent
    memory: TeamMemoryManager
    blackboard: Blackboard
    registry: AgentRegistry
    finder: PeerFinder
    mission_store: MissionStore
    runner: MissionRunner
    membership: MembershipManager
    groups: Optional[GroupManager] = None
    event_bus: Optional[EventBus] = None
    identity: Optional[AgentIdentity] = None
    backend: Optional[AgentBackend] = None
    capabilities: List[str] = field(default_factory=list)
    groups_list: List[str] = field(default_factory=list)
    _detached: bool = False

    #

    def discover(self) -> List:
        """List currently alive agents (including self)."""
        return self.registry.list_alive()

    def discover_others(self) -> List:
        """List currently alive agents excluding self."""
        return [r for r in self.registry.list_alive() if r.agent_id != self.agent_id]

    def find_teammate(
        self,
        capability: Optional[str] = None,
        needed_capabilities: Optional[List[str]] = None,
        group: Optional[str] = None,
    ):
        """Find one teammate by capability / capability-set / group.

        Note: return type varies by branch — `needed_capabilities` returns a
        `MatchResult` (with .score), the other two return an `AgentRecord`.
        For type-consistent code use `team.finder` directly.
        """
        if needed_capabilities:
            return self.finder.best_match(
                needed_capabilities=needed_capabilities,
                prefer_idle=True,
                exclude_agent_ids=[self.agent_id],
            )
        if capability:
            results = self.finder.find(
                capability=capability,
                exclude_agent_ids=[self.agent_id],
            )
            return results[0] if results else None
        if group:
            results = self.finder.find(
                group=group,
                exclude_agent_ids=[self.agent_id],
            )
            return results[0] if results else None
        return None

    def start_mission(
        self,
        title: str,
        goal: str,
        steps: List[dict],
        scope: str = "shared",
        deadline: Optional[str] = None,
        priority: str = "normal",
        tags: Optional[List[str]] = None,
    ) -> Mission:
        """Publish a new mission to the store and post a Kanban card to the blackboard."""
        m = Mission.new(
            title=title,
            goal=goal,
            owner=self.agent_id,
            scope=scope,
            steps=steps,
            deadline=deadline,
            priority=priority,
            tags=tags or [],
        )
        self.mission_store.create(m)

        # Surface the mission on the blackboard Kanban
        self.blackboard.post(
            topic=f"[MISSION] {title}",
            author=self.agent_id,
            scope=scope,
            status="doing",
            content=goal,
            metadata={"mission_id": m.id, "type": "mission"},
        )

        # Mark this agent as the mission owner in the registry
        self.registry.update_status(current_mission=m.id)

        return m

    def take_next_work(self) -> Optional[Mission]:
        """Find a claimable step and atomically claim it; returns the parent mission."""
        found = self.runner.find_work()
        if not found:
            return None
        mission, step = found
        self.runner.claim(mission.id, step.id)
        self.registry.update_status(status="busy", current_mission=mission.id)
        return mission

    def detach(self) -> None:
        """完成所有清理：agent.finalize、registry.unregister、backend.close。

        任何一步失败都不阻断后续；统一 log warn。
        """
        if self._detached:
            return
        # agent finalize（落盘 ledger 等）
        try:
            self.agent.finalize()
        except Exception as e:
            logger.warning("agent.finalize raised during detach: %s", e)
        # registry 注销心跳
        try:
            self.registry.unregister()
        except Exception as e:
            logger.warning("registry.unregister raised during detach: %s", e)
        # backend 关停（subprocess / HTTP session 等）
        _close_backend(self.backend)
        self._detached = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.detach()


#
# attach()
#

def attach(
    agent_id: str,
    backend: Union[str, AgentBackend, None] = None,
    backend_kwargs: Optional[Dict[str, Any]] = None,
    capabilities: Optional[List[str]] = None,
    groups: Optional[List[str]] = None,
    workspace: Union[str, Path] = ".",
    metadata: Optional[Dict[str, Any]] = None,
    soul_path: str = "skills/TEAM-SOUL.md",
    user_model_path: str = "memory/user-model.json",
    vector_dir: str = "skills/registry",
    ledger_path: str = "sidechain/ledger.jsonl",
    blackboard_root: str = "blackboard",
    agents_dir: str = "team_agents",
    missions_dir: str = "missions",
    compression_threshold: float = 0.75,
    start_heartbeat: bool = True,
    join_token: str = "",
    identity: Optional[AgentIdentity] = None,
) -> TeamSession:
    """One-line integration: wire up an agent's NTH DAO runtime.

    Args:
        agent_id: Stable identifier for this agent.
        backend: One of: a backend id (str) registered in default_registry,
                 an AgentBackend instance, or None (no LLM backend).
        backend_kwargs: ctor kwargs passed to the backend factory when `backend` is a str.
        capabilities: e.g. ["python", "web", "codegen"]
        groups: e.g. ["frontend", "ops"]
        workspace: Directory that holds the NTH DAO runtime artifacts.

    Returns:
        TeamSession — façade combining agent + memory + blackboard + discovery +
        mission store + runner + membership; works as a context manager
        (with-statement) that calls detach() on exit.

    Raises:
        PermissionError: when the team's join_policy denies this agent_id (and
        no valid join_token / approval is present).
    """
    workspace = Path(workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=True)

    capabilities = capabilities or []
    groups = groups or []
    agent_identity = identity or AgentIdentity.from_string(agent_id, label=agent_id)
    # MembershipManager: if the agent identity has signing keys *and* the
    # existing team.json was signed by this same pubkey, this agent acts as
    # owner (signs subsequent saves). Otherwise the owner-signing layer is
    # inactive (legacy behavior).
    membership = MembershipManager(workspace, owner_identity=_owner_or_none(
        agent_identity, MembershipManager(workspace).load_config(),
    ))

    # 1. 先做 membership gate —— 不通过则连 backend 都不创建（避免 subprocess 泄漏）
    allowed, reason = membership.ensure_member(agent_id, token=join_token)
    if not allowed:
        raise PermissionError(
            f"Agent '{agent_id}' cannot attach to this team: {reason}. "
            "Submit a join request or ask a team admin for approval/invite."
        )

    # 2. 创建/挂载 backend
    backend_instance: Optional[AgentBackend] = None
    backend_id_str = "none"
    if isinstance(backend, AgentBackend):
        backend_instance = backend
        backend_id_str = backend.backend_id
    elif isinstance(backend, str):
        backend_instance = default_registry.create(backend, **(backend_kwargs or {}))
        backend_id_str = backend

    # 2. 4+1  Provider
    providers = [
        SoulProvider(str(workspace / soul_path)),
        UserModelProvider(str(workspace / user_model_path)),
        VectorProvider(str(workspace / vector_dir)),
        LedgerProvider(str(workspace / ledger_path)),
        BlackboardProvider(
            agent_id=agent_id,
            blackboard_root=str(workspace / blackboard_root),
            groups=groups,
        ),
    ]

    # 3. TeamMemoryManager + TeamAgent
    mem = TeamMemoryManager(providers, session_id=f"{agent_id}_session")
    mem.initialize({"agent_id": agent_id, "capabilities": capabilities})
    team_agent = TeamAgent(
        agent_id=agent_id,
        team_memory_manager=mem,
        compression_threshold=compression_threshold,
    )

    # 4. Blackboard
    blackboard = Blackboard(workspace / blackboard_root)

    # 5. Discovery   +
    registry = AgentRegistry(agents_dir=str(workspace / agents_dir))
    registry_metadata = dict(metadata or {})
    registry_metadata.setdefault("identity", agent_identity.public_dict())

    registry.register(
        agent_id=agent_id,
        backend_id=backend_id_str,
        capabilities=capabilities,
        groups=groups,
        metadata=registry_metadata,
        start_heartbeat=start_heartbeat,
    )

    # 6. PeerFinder
    finder = PeerFinder(registry)

    # 7. Mission Orchestration
    mission_store = MissionStore(str(workspace / missions_dir))
    runner = MissionRunner(
        store=mission_store,
        agent_id=agent_id,
        capabilities=capabilities,
        registry=registry,  # 让 handoff 能检查目标 alive
    )

    # 8. EventBus — unified team-level signed event stream (L0)
    event_bus = EventBus(workspace, identity=agent_identity)

    # 9. GroupManager — channels, messages, tasks, audit (with EventBus routing)
    group_mgr = GroupManager(
        workspace,
        membership=membership,
        event_bus=event_bus,
        identity=agent_identity if agent_identity.can_sign else None,
    )

    return TeamSession(
        agent_id=agent_id,
        backend_id=backend_id_str,
        workspace=workspace,
        agent=team_agent,
        memory=mem,
        blackboard=blackboard,
        registry=registry,
        finder=finder,
        mission_store=mission_store,
        runner=runner,
        membership=membership,
        groups=group_mgr,
        event_bus=event_bus,
        identity=agent_identity,
        backend=backend_instance,
        capabilities=capabilities,
        groups_list=groups,
    )
