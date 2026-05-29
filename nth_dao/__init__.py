"""
NTH DAO   Agent

 Agent Hermes / Claude Code / OpenClaw / Codex / OpenHands /
 attach()

    >>> import nth_dao as nth
    >>> team = nth.attach(agent_id="my-agent", backend="mock")
    >>> team.discover()                      #  Agent
    >>> team.blackboard.post("task", "...")  #
    >>> team.start_mission("ship feature X") #

 team_layer  PR 1-7
    - 4  ProviderSOUL / User / Vector / Ledger
    - Blackboard  Agent
    - 5
    - EvoLoop  backend
    - Git-backed
    - 6 backend

 PR 8
    - Agent Discovery + Git
    - Mission Orchestration session//Agent
    - attach()  Agent  3

pyproject.toml: nth-dao
: nth_dao
"""

__version__ = "0.9.0"
__author__ = "NTH DAO Project"

#
# Facade team_layer  API
#  PR 1-7  nth_dao
#

# PR 1-2:  + 4  Provider
from team_layer import TeamAgent, TeamMemoryManager
from team_layer.memory_providers import (
    SoulProvider,
    UserModelProvider,
    VectorProvider,
    LedgerProvider,
)

# PR 3:
from team_layer.compression import CompressionPipeline, CompressionStage

# PR 4: EvoLoop
from team_layer.evolution import (
    EvoLoop,
    EvoTrigger,
    Reflector,
    Verifier,
    EvolutionGate,
)

# PR 5:
from team_layer.git_sync import (
    SyncConfig,
    LogCollector,
    SkillLoader,
    CentralAggregator,
)

# PR 6: Blackboard
from team_layer.blackboard import (
    Blackboard,
    BlackboardEntry,
    BlackboardProvider,
    Scope,
    render_kanban,
    render_table,
)

# PR 7: AgentBackend ABC
from team_layer.backends import (
    AgentBackend,
    BackendCapabilities,
    BackendRegistry,
    BackendUnavailableError,
    SessionConfig,
    SessionSummary,
    TokenUsage,
    TurnResponse,
    default_registry,
)

#
# PR 8:   Discovery + Orchestration + Attach
#

from .discovery import AgentRegistry, AgentRecord, PeerFinder
from .orchestration import Mission, MissionStep, MissionStore, MissionRunner, MissionStatus
from .membership import (
    JoinPolicy,
    RequestStatus,
    JoinRequest,
    MembershipRequest,
    TeamConfig,
    TeamRole,
    MembershipManager,
)
from .groups import (
    Announcement,
    AuditEvent,
    Channel,
    GroupManager,
    Message,
    MessageKind,
    Task,
    TaskStatus,
    TrustHint,
)
from .identity import (
    AgentID,
    AgentIdentity,
    crypto_available,
    default_identity_path,
    load_or_generate,
)
# A2A modules (originally proposed by @andy1868 in PR #3#6, cherry-picked
# against current main; identity.py kept as the existing membership-gated
# version, these 4 new modules use the same AgentIdentity API and add zero
# third-party deps  all stdlib).
from .channel import ChannelMessage, TeamChannel
from .reputation import ReputationEntry, ReputationScore, ReputationManager
from .gossip import PeerInfo, GossipNode
from .marketplace import OrderStatus, TaskOrder, TaskMarketplace
from .attach import attach, TeamSession

__all__ = [
    # FacadePR 1-7
    "TeamAgent",
    "TeamMemoryManager",
    "SoulProvider",
    "UserModelProvider",
    "VectorProvider",
    "LedgerProvider",
    "CompressionPipeline",
    "CompressionStage",
    "EvoLoop",
    "EvoTrigger",
    "Reflector",
    "Verifier",
    "EvolutionGate",
    "SyncConfig",
    "LogCollector",
    "SkillLoader",
    "CentralAggregator",
    "Blackboard",
    "BlackboardEntry",
    "BlackboardProvider",
    "Scope",
    "render_kanban",
    "render_table",
    "AgentBackend",
    "BackendCapabilities",
    "BackendRegistry",
    "BackendUnavailableError",
    "SessionConfig",
    "SessionSummary",
    "TokenUsage",
    "TurnResponse",
    "default_registry",
    # PR 8
    "AgentRegistry",
    "AgentRecord",
    "PeerFinder",
    "Mission",
    "MissionStep",
    "MissionStatus",
    "MissionStore",
    "MissionRunner",
    "attach",
    "TeamSession",
    # MembershipPR 9: /
    "JoinPolicy",
    "RequestStatus",
    "JoinRequest",
    "MembershipRequest",
    "TeamConfig",
    "TeamRole",
    "MembershipManager",
    # Local-first group layer: channels, messages, tasks, audit, trust
    "Announcement",
    "AuditEvent",
    "Channel",
    "GroupManager",
    "Message",
    "MessageKind",
    "Task",
    "TaskStatus",
    "TrustHint",
    # Identity: stable agent profile + optional Ed25519 signing
    "AgentID",
    "AgentIdentity",
    "crypto_available",
    "default_identity_path",
    "load_or_generate",
    # A2A modules cherry-picked from @andy1868 PR #3#6 (stdlib only)
    "ChannelMessage",   # PR #3 signed A2A messaging
    "TeamChannel",
    "ReputationEntry",  # PR #4 subjective reputation
    "ReputationScore",
    "ReputationManager",
    "PeerInfo",         # PR #5 P2P gossip
    "GossipNode",
    "OrderStatus",      # PR #6 task marketplace
    "TaskOrder",
    "TaskMarketplace",
]
