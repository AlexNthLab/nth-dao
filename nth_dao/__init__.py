"""
NTH DAO — pluggable team-collaboration layer for AI agents.

Any agent framework (Hermes / Claude Code / OpenClaw / Codex / OpenHands /
custom) can join the team with a single call:

    >>> import nth_dao as nth
    >>> team = nth.attach(agent_id="my-agent", backend="mock")
    >>> team.discover()                       # find other live agents
    >>> team.blackboard.post("task", "...")   # post to shared workspace
    >>> team.start_mission("ship feature X")  # start a long-lived mission

Core capabilities (inherited from team_layer PR 1–7):
    - 4 memory providers (SOUL / User / Vector / Ledger)
    - Blackboard multi-agent shared workspace
    - 5-stage context compression pipeline
    - EvoLoop self-evolution across backends
    - Git-backed multi-terminal sync
    - 6 unified agent backends

PR 8 additions:
    - Agent Discovery: heartbeat-file based peer discovery + Git sync
    - Mission Orchestration: long-running tasks that relay across sessions /
      terminals / agents
    - attach(): 3-line integration for any agent framework

Distribution name (pyproject.toml): nth-dao
Import name: nth_dao
"""

__author__ = "NTH DAO Project"

# 单一版本号来源：pyproject.toml。退化到字符串字面量以便源码树独立使用时仍有值。
try:
    from importlib.metadata import version as _pkg_version, PackageNotFoundError
    try:
        __version__ = _pkg_version("nth-dao")
    except PackageNotFoundError:
        __version__ = "0.9.5+source"
except ImportError:
    __version__ = "0.9.5+source"

#
# Facade — re-export all team_layer public APIs.
# Backward-compatible: existing PR 1–7 code keeps working under nth_dao.
#

# PR 1–2: core runtime + 4 memory providers
from team_layer import TeamAgent, TeamMemoryManager
from team_layer.memory_providers import (
    SoulProvider,
    UserModelProvider,
    VectorProvider,
    LedgerProvider,
)

# PR 3: 5-stage context compression pipeline
from team_layer.compression import CompressionPipeline, CompressionStage

# PR 4: EvoLoop self-evolution
from team_layer.evolution import (
    EvoLoop,
    EvoTrigger,
    Reflector,
    Verifier,
    EvolutionGate,
)

# PR 5: multi-terminal sync
from team_layer.git_sync import (
    SyncConfig,
    LogCollector,
    SkillLoader,
    CentralAggregator,
)

# PR 6: Blackboard shared workspace
from team_layer.blackboard import (
    Blackboard,
    BlackboardEntry,
    BlackboardProvider,
    Scope,
    render_kanban,
    render_table,
)

# PR 7: AgentBackend ABC + 6 built-in backends
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
# PR 8: new — Discovery + Orchestration + attach()
#

from .discovery import (
    AgentRegistry,
    AgentRecord,
    PeerFinder,
    LANDiscovery,
    LANPeer,
)
from .orchestration import (
    Mission,
    MissionStep,
    MissionStore,
    MissionRunner,
    MissionStatus,
    # v0.9.3 additions
    MissionTemplate,
    TemplateType,
    IOField,
    StepSkeleton,
    mint_template,
    MissionReview,
    TemplateStats,
    mint_review,
    TemplatePublishError,
)
from .membership import (
    JoinPolicy,
    RequestStatus,
    JoinRequest,
    MembershipRequest,
    TeamConfig,
    TeamRole,
    MembershipManager,
    TamperedTeamConfigError,
)
# 注意：与 .channel.TeamChannel/ChannelMessage 是 *两套不同语义* 的概念。
#   - .groups.Channel: GroupManager 维护的"话题频道"，可私有、有 member_ids
#   - .channel.TeamChannel: 跨节点 A2A 消息广播器，append-only jsonl
# 在 __init__ 里把 .groups.Channel re-export 为 Channel，把 .groups.Message 为
# Message；A2A 那边的类全名是 TeamChannel/ChannelMessage，不重名。
from .groups import (
    Announcement,
    AuditEvent,
    Channel,                  # GroupChannel 语义
    GroupManager,
    Message,
    MessageKind,
    Task,
    TaskStatus,
    TrustHint,
)
# 显式别名，让需要消歧义的代码读起来不困惑
from .groups import Channel as GroupChannel  # noqa: F401
from .identity import (
    AgentID,
    AgentIdentity,
    crypto_available,
    default_identity_path,
    load_or_generate,
)
# v0.9.5: W3C did:key standard alignment
from .did_key import (
    DIDKeyError,
    encode_ed25519_did_key,
    encode_ed25519_did_key_hex,
    decode_ed25519_did_key,
    decode_ed25519_did_key_hex,
    is_did_key,
    parse_did,
)
# A2A modules (originally proposed by @andy1868 in PR #3#6, cherry-picked
# against current main; identity.py kept as the existing membership-gated
# version, these 4 new modules use the same AgentIdentity API and add zero
# third-party deps  all stdlib).
from .channel import ChannelMessage, TeamChannel
from .reputation import ReputationEntry, ReputationScore, ReputationManager
from .gossip import PeerInfo, GossipNode
from .marketplace import OrderStatus, TaskOrder, TaskMarketplace
from .event_bus import BusEvent, EventBus, VerificationResult
from .attach import attach, TeamSession
from .web_of_trust import (
    Endorsement,
    Revocation,
    TrustGraph,
    issue_endorsement,
    issue_revocation,
)
from .invitation import Invitation, InvitationError
# v0.9.4: Encrypted recovery kits — restore an identity from a passphrase-protected blob
from .key_recovery import (
    RecoveryKit,
    KeyRecoveryError,
    export_recovery_kit,
    import_recovery_kit,
)
# v0.9.5: AgentLedger persistence
from .agent_ledger import AgentLedger, LedgerEvent
# v0.9.5: Guardian-based social recovery (N-of-M peers re-bind agent_id → new pubkey)
from .guardian import (
    GuardianSet,
    GuardianSignature,
    GuardianStore,
    KeyReplacementProof,
    begin_key_replacement,
    publish_guardian_set,
    sign_replacement,
    verify_replacement,
)
# v0.9.5: A2A boundary translation primitives (server lives in a separate package)
from . import a2a as a2a_adapter  # noqa: F401

__all__ = [
    # Facade re-exports (team_layer PR 1–7)
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
    # PR 8 — Discovery + Orchestration + attach()
    "AgentRegistry",
    "AgentRecord",
    "PeerFinder",
    "LANDiscovery",
    "LANPeer",
    "Mission",
    "MissionStep",
    "MissionStatus",
    "MissionStore",
    "MissionRunner",
    # v0.9.3 — Mission templates + reviews
    "MissionTemplate",
    "TemplateType",
    "IOField",
    "StepSkeleton",
    "mint_template",
    "MissionReview",
    "TemplateStats",
    "mint_review",
    "TemplatePublishError",
    "attach",
    "TeamSession",
    # Membership (PR 9): join requests / approvals / roles
    "JoinPolicy",
    "RequestStatus",
    "JoinRequest",
    "MembershipRequest",
    "TeamConfig",
    "TeamRole",
    "MembershipManager",
    "TamperedTeamConfigError",
    # Local-first group layer: channels, messages, tasks, audit, trust
    "Announcement",
    "AuditEvent",
    "Channel",
    "GroupChannel",  # alias of groups.Channel for disambiguation
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
    # Web-of-Trust (P4 + P6): endorsement-based multi-hop trust with revocation
    "Endorsement",
    "Revocation",
    "TrustGraph",
    "issue_endorsement",
    "issue_revocation",
    # Invitation (P6): one-scan team bootstrap (QR / URL / paste)
    "Invitation",
    "InvitationError",
    # Key recovery (v0.9.4): passphrase-protected identity export / import
    "RecoveryKit",
    "KeyRecoveryError",
    "export_recovery_kit",
    "import_recovery_kit",
    # W3C did:key (v0.9.5)
    "DIDKeyError",
    "encode_ed25519_did_key",
    "encode_ed25519_did_key_hex",
    "decode_ed25519_did_key",
    "decode_ed25519_did_key_hex",
    "is_did_key",
    "parse_did",
    # AgentLedger (v0.9.5)
    "AgentLedger",
    "LedgerEvent",
    # EventBus (v0.9.6): unified team-level signed event stream (L0)
    "BusEvent",
    "EventBus",
    "VerificationResult",
    # Guardian recovery (v0.9.5)
    "GuardianSet",
    "GuardianSignature",
    "GuardianStore",
    "KeyReplacementProof",
    "begin_key_replacement",
    "publish_guardian_set",
    "sign_replacement",
    "verify_replacement",
]
