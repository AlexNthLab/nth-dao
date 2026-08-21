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
import os
import platform as _platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    List,
    Optional,
    Protocol,
    Union,
    runtime_checkable,
)

from .discovery import AgentRegistry, PeerFinder
from .groups import GroupManager, Message, MessageKind
from .identity import AgentIdentity
from .membership import MembershipManager
from .orchestration import Mission, MissionRunner, MissionStore

class _RuntimeAgentBackend(Protocol):
    backend_id: str

    def preflight_check(self, *, timeout: float = 5.0) -> Any: ...


class _RuntimeBlackboard(Protocol):
    def post(self, **kwargs: Any) -> Any: ...


class _RuntimeTeamAgent(Protocol):
    def finalize(self) -> Any: ...


class _RuntimeTeamMemoryManager(Protocol):
    def initialize(self, context: Dict[str, Any]) -> Any: ...


if TYPE_CHECKING:
    from team_layer import TeamAgent, TeamMemoryManager
    from team_layer.backends import AgentBackend
    from team_layer.blackboard import Blackboard
else:
    # Preserve useful runtime annotations without importing the optional
    # legacy backend package. attach() uses concrete local imports only when a
    # session is actually constructed.
    AgentBackend = _RuntimeAgentBackend
    Blackboard = _RuntimeBlackboard
    TeamAgent = _RuntimeTeamAgent
    TeamMemoryManager = _RuntimeTeamMemoryManager


def _detect_gpu() -> Dict[str, Any]:
    """G-14 (Voss audit): best-effort GPU detection.

    Strategy (in order):
      1. ``pynvml`` if importable - the most reliable NVIDIA path
      2. ``nvidia-smi`` binary on PATH - fallback for hosts without
         the Python binding
      3. Default to ``{"gpu_available": False, "gpu_name": None}``

    NEVER raises - GPU detection is purely informational and must
    not crash attach() on a CPU-only or sandboxed host. AMD / Intel
    GPUs are not detected (returns False); upgrading this to use
    ``rocm-smi`` etc. is a future deployment-specific concern.
    """
    # Path 1: pynvml
    try:
        import pynvml  # type: ignore
        try:
            pynvml.nvmlInit()
            count = pynvml.nvmlDeviceGetCount()
            if count > 0:
                handle = pynvml.nvmlDeviceGetHandleByIndex(0)
                name = pynvml.nvmlDeviceGetName(handle)
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")
                try:
                    pynvml.nvmlShutdown()
                except Exception:  # noqa: BLE001
                    pass
                return {
                    "gpu_available": True,
                    "gpu_name": name,
                    "gpu_count": count,
                    "gpu_source": "pynvml",
                }
        except Exception:  # noqa: BLE001
            # nvml init failed (no driver, no GPU). Fall through.
            pass
    except ImportError:
        pass

    # Path 2: nvidia-smi
    nvidia_smi = shutil.which("nvidia-smi")
    if nvidia_smi:
        try:
            out = subprocess.run(
                [nvidia_smi, "--query-gpu=name", "--format=csv,noheader"],
                capture_output=True, text=True, timeout=2.0,
            )
            if out.returncode == 0 and out.stdout.strip():
                names = [
                    line.strip()
                    for line in out.stdout.splitlines()
                    if line.strip()
                ]
                if names:
                    return {
                        "gpu_available": True,
                        "gpu_name": names[0],
                        "gpu_count": len(names),
                        "gpu_source": "nvidia-smi",
                    }
        except (subprocess.TimeoutExpired, OSError):
            pass

    return {
        "gpu_available": False,
        "gpu_name": None,
        "gpu_count": 0,
        "gpu_source": None,
    }


def _detect_memory_gb() -> Optional[float]:
    """G-14: total system memory in GiB, or None if unavailable.

    Uses ``psutil`` when available. Returns None silently otherwise -
    memory is informational, not a gate.
    """
    try:
        import psutil  # type: ignore
        total_bytes = psutil.virtual_memory().total
        return round(total_bytes / (1024 ** 3), 2)
    except Exception:  # noqa: BLE001
        return None


def _capture_env_metadata() -> Dict[str, Any]:
    """PR-2: snapshot the agent's environment for mission filtering.

    Mission steps with ``required_platform`` use this to refuse work
    on incompatible agents (failure mode #1 in the COLLABORATION
    doc: a Linux-only step landing on a Windows agent that the
    orchestrator didn't know was Windows). Schema is intentionally
    flat - the registry stores it under metadata.env without further
    nesting so consumers can filter by single keys.

    G-14 (Voss audit): the original PR-2 schema captured only
    platform/architecture/python_version/runtime. That's enough for
    OS-level filtering but not enough for GPU-required ML steps or
    memory-bound large-context steps. We extend the schema with:

      * cpu_count        always available via os.cpu_count()
      * memory_gb        None if psutil missing
      * gpu_available    bool, never raises
      * gpu_name         GPU model name or None
      * gpu_count        int, 0 when no GPU
      * gpu_source       "pynvml" / "nvidia-smi" / None - lets a
                         dashboard report HOW we detected

      * runtime_key       G-15 OS+architecture key, e.g.
                          linux-x86_64 or darwin-arm64

    Adding keys is backward compatible: PR-2 callers using just the
    original four keys still see them unchanged. New filtering
    primitives can opt in.
    """
    platform = _platform.system().lower()
    architecture = _platform.machine().lower()
    env: Dict[str, Any] = {
        "platform": platform,       # linux / darwin / windows
        "architecture": architecture,  # x86_64 / arm64 / ...
        "runtime_key": f"{platform}-{architecture}",
        "python_version": ".".join(map(str, sys.version_info[:3])),
        "runtime": (
            "cpython" if sys.implementation.name == "cpython"
            else sys.implementation.name
        ),
        # G-14 additions
        "cpu_count": os.cpu_count() or 0,
        "memory_gb": _detect_memory_gb(),
    }
    env.update(_detect_gpu())
    return env

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
    group_manager: GroupManager
    identity: Optional[AgentIdentity] = None
    backend: Optional[AgentBackend] = None
    capabilities: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    _detached: bool = False

    # v0.9.8 (P4): lazily-constructed agent collaboration primitives.
    # Built on first access via the methods below so attach() stays
    # fast for callers that only need discovery / blackboard.
    _action_router: Any = field(default=None, repr=False)
    _subscriptions: Any = field(default=None, repr=False)
    _fault_isolator: Any = field(default=None, repr=False)
    _event_bus: Any = field(default=None, repr=False)
    _profile: Any = field(default=None, repr=False)

    #

    def discover(self) -> List:
        """List currently alive agents (including self)."""
        return self.registry.list_alive()

    def discover_others(self) -> List:
        """List currently alive agents excluding self."""
        return [r for r in self.registry.list_alive() if r.agent_id != self.agent_id]

    # ====================================================================
    # v0.9.8 (P4): agent collaboration primitives, lazily constructed.
    # The first call instantiates and caches; subsequent calls return the
    # cached instance. attach() does NOT eagerly build these because most
    # callers (discover-only, blackboard-only, mission-only) don't need
    # them and we want attach to stay cheap.
    # ====================================================================

    def event_bus(self):
        """Get the team-level signed EventBus.

        Used by FaultIsolator, SubscriptionManager, and any caller who
        wants to publish or replay team-wide audit events. The bus is
        shared across this TeamSession so all primitives see the same
        chain.
        """
        if self._event_bus is None:
            from .event_bus import EventBus
            self._event_bus = EventBus(self.workspace, identity=self.identity)
        return self._event_bus

    def subscriptions(self):
        """Per-cursor pub/sub over the EventBus.

        Subscribers register a glob pattern + callback; poll() delivers
        every new matching event since the last call.
        """
        if self._subscriptions is None:
            from .event_subscriptions import SubscriptionManager
            self._subscriptions = SubscriptionManager(self.event_bus())
        return self._subscriptions

    def fault_isolator(self):
        """Circuit breaker + signed audit events for cross-agent
        interactions.

        Failures and state transitions emit signed events to the team
        EventBus so an auditor can detect a peer being repeatedly
        forced into OPEN state (potential censorship).
        """
        if self._fault_isolator is None:
            from .fault_isolation import FaultIsolator
            self._fault_isolator = FaultIsolator(
                workspace=self.workspace, event_bus=self.event_bus(),
            )
        return self._fault_isolator

    def action_router(self, *, allow_unsigned_dev: bool = False):
        """Signed cross-agent action dispatch with TTL + nonce replay
        protection.

        Construction REFUSES unless either (identity AND a pubkey
        lookup are wired up) OR allow_unsigned_dev=True is set
        explicitly. The default routes the pubkey lookup through
        AgentRegistry's records.
        """
        if self._action_router is not None:
            return self._action_router

        from .action_routing import ActionRouter

        def lookup(aid: str):
            record = self.registry.get(aid)
            if record is None:
                return None
            # AgentRegistry stores the pubkey in record.metadata or as
            # an attribute depending on version; tolerate both. attach()
            # stores AgentIdentity.public_dict() under metadata["identity"],
            # whose field is named "pubkey".
            metadata = record.metadata or {}
            identity_meta = metadata.get("identity") or {}
            if not isinstance(identity_meta, dict):
                identity_meta = {}
            return (
                getattr(record, "pubkey_hex", "")
                or metadata.get("pubkey_hex", "")
                or metadata.get("pubkey", "")
                or identity_meta.get("pubkey_hex", "")
                or identity_meta.get("pubkey", "")
            ) or None

        if allow_unsigned_dev:
            self._action_router = ActionRouter(
                agent_id=self.agent_id,
                workspace=self.workspace,
                allow_unsigned_dev=True,
            )
        elif self.identity is None or not self.identity.can_sign:
            raise ValueError(
                "TeamSession.action_router() requires a signing identity. "
                "Pass identity=AgentIdentity.generate(...) to attach(), or "
                "call action_router(allow_unsigned_dev=True) for local smoke "
                "tests only."
            )
        else:
            self._action_router = ActionRouter(
                agent_id=self.agent_id,
                identity=self.identity,
                pubkey_lookup=lookup,
                workspace=self.workspace,
            )
        return self._action_router

    def profile(self):
        """Read-time aggregated view of this agent for UI display."""
        from .agent_profile import AgentProfile
        record = self.registry.get(self.agent_id)
        return AgentProfile.build(
            self.agent_id,
            identity=self.identity if (self.identity and self.identity.pubkey_hex) else None,
            record=record if record is not None else None,
            health=self._fault_isolator,
        )

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

    def send_message(
        self,
        channel_id: str,
        body: str,
        kind: Union[str, "MessageKind"] = "text",
        reply_to: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "Message":
        """Post a message to a channel via GroupManager."""
        return self.group_manager.post_message(
            channel_id=channel_id,
            sender_id=self.agent_id,
            body=body,
            kind=kind,
            reply_to=reply_to,
            metadata=metadata,
        )

    def read_messages(
        self,
        channel_id: str = "general",
        limit: Optional[int] = 50,
    ) -> list:
        """Read recent messages from a channel."""
        return self.group_manager.list_messages(
            channel_id=channel_id,
            actor_id=self.agent_id,
            limit=limit,
        )

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
    skip_preflight: bool = False,
    preflight_timeout: float = 5.0,
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
    # The legacy backend runtime is deliberately loaded only when callers
    # construct a TeamSession. Importing ``nth_dao`` or the language-neutral
    # plugin protocol must not execute backend registration or import optional
    # CLI integrations as a side effect.
    from team_layer import TeamAgent, TeamMemoryManager
    from team_layer.backends import AgentBackend, default_registry
    from team_layer.blackboard import Blackboard, BlackboardProvider
    from team_layer.memory_providers import (
        LedgerProvider,
        SoulProvider,
        UserModelProvider,
        VectorProvider,
    )

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

    # PR-1 / G-1 (Voss audit): pre-flight check.
    #
    # Catches the "claude auth login crashed" / "codex hangs" failure
    # modes BEFORE the agent commits to any work. The full lifecycle:
    #   1. Run preflight_check on the backend.
    #   2. Eagerly create the EventBus (skipping its lazy init in
    #      TeamSession) and emit ``agent.preflight`` so the audit
    #      chain captures the attempt regardless of outcome.
    #   3. If preflight failed, raise BackendUnavailableError so the
    #      caller can fall back to another backend or abort.
    #
    # The eager EventBus instantiation here is the fix for the G-1
    # finding: previously the comment claimed the event would fire
    # but the code never reached an emit() call before raising.
    preflight = None
    if backend_instance is not None and not skip_preflight:
        preflight = backend_instance.preflight_check(timeout=preflight_timeout)

        # Always emit, success or failure - the audit chain must show
        # WHY the attach succeeded or refused, not just attaches that
        # went through.
        from .event_bus import EventBus
        _audit_bus = EventBus(workspace, identity=agent_identity)
        _audit_bus.emit(
            "agent.preflight",
            {
                "agent_id": agent_id,
                "backend_id": preflight.backend_id,
                "ok": preflight.ok,
                "detail": preflight.detail[:500],
                "duration_ms": preflight.duration_ms,
                "checked_at": preflight.checked_at,
                "structured": preflight.structured,
            },
            identity=agent_identity,
        )

        if not preflight.ok:
            from team_layer.backends.base import BackendUnavailableError
            raise BackendUnavailableError(
                f"preflight failed for backend {preflight.backend_id!r}: "
                f"{preflight.detail}"
            )

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
    # PR-2: env metadata so the orchestrator can filter mission steps
    # by required_platform. Stored under metadata["env"] so it stays
    # alongside identity and other discovery-time facts without
    # changing the registry schema.
    registry_metadata.setdefault("env", _capture_env_metadata())

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

    # Group layer — channels, messages, tasks
    group_mgr = GroupManager(workspace, membership=membership)

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
        group_manager=group_mgr,
        identity=agent_identity,
        backend=backend_instance,
        capabilities=capabilities,
        groups=groups,
    )
