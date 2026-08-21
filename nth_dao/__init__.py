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
        __version__ = "0.10.0b1+source"
except ImportError:
    __version__ = "0.10.0b1+source"

#
# Facade — re-export all team_layer public APIs.
# Backward-compatible: existing PR 1–7 code keeps working under nth_dao.
#

# Legacy runtime exports are resolved lazily below. Importing a protocol-only
# module must not execute backend package initializers or probe local CLIs.

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
# Web-of-Trust: endorsement-based multi-hop trust propagation
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
# v0.9.7: EventBus — team-level signed hash-chained event stream
# (orthogonal to AgentLedger: per-agent vs per-team)
from .event_bus import (
    BusEvent,
    CorrectionType,
    EventBus,
    VerificationResult as EventBusVerificationResult,
    # v0.10 T-5 reserved Mandate-lifecycle event types
    MANDATE_CART_RECEIVED,
    MANDATE_INTENT_ISSUED,
    MANDATE_LIFECYCLE_EVENT_TYPES,
    MANDATE_PAYMENT_AUTHORISED,
    SETTLEMENT_COMPLETED,
)
# v0.9.8: Agent collaboration primitives (P4 facade entry points).
# These five modules together form the cross-agent dispatch layer:
#   - AgentProfile     read-time aggregated view for UI
#   - ActionRouter     signed dispatch with TTL + nonce + target gate
#   - SubscriptionManager  per-cursor pub/sub on the EventBus
#   - FaultIsolator    circuit breaker with signed audit events
from .agent_profile import AgentProfile
from .action_routing import (
    ActionRequest,
    ActionResponse,
    ActionRouter,
    ActionStatus,
    HandlerInfo,
    PubkeyLookup,
    RouteStrategy,
)
from .event_subscriptions import Subscription, SubscriptionManager
from .fault_isolation import (
    AgentHealth,
    CircuitState,
    FailureRecord,
    FaultIsolator,
)
# Runtime handoff primitives: signed, evidence-pinned, refutable agent handoff.
from .runtime import (
    EVENT_EXEC_HANDOFF,
    EVENT_EXEC_HANDOFF_LEGACY,
    EVENT_EXEC_HANDOFF_PROPOSED,
    EVENT_EXEC_HANDOFF_REFUTED,
    EVENT_EXEC_HANDOFF_SUPERSEDED,
    HANDOFF_CAPSULE_KIND,
    HANDOFF_RESPONSE_KIND,
    HANDOFF_RESPONSE_KIND_V1,
    HANDOFF_RESPONSE_KIND_V2,
    HandoffProjection,
    HandoffRecord,
    record_handoff,
    record_handoff_response,
    record_handoff_response_checked,
    sign_handoff_capsule,
    sign_handoff_response,
    source_evidence_from_git,
    verify_source_evidence,
    verify_source_evidence_report,
    verify_handoff_capsule,
    verify_handoff_response,
)
# v0.10 Sprint Zero (T-1): Mandate primitives - AP2-shape signed
# authorisation, will be joined by Cart (T-2) and Payment (T-3).
from .mandate import (
    build_intent_mandate,
    intent_mandate_digest,
    is_intent_expired,
    sign_intent_mandate,
    verify_intent_mandate,
    # T-2 CartMandate primitives
    build_cart_mandate,
    cart_mandate_digest,
    cart_satisfies_intent,
    is_cart_expired,
    sign_cart_mandate,
    verify_cart_mandate,
    # T-3 PaymentMandate primitives + end-to-end triad gate
    build_payment_mandate,
    complete_triad_chain,
    is_payment_expired,
    payment_mandate_digest,
    payment_satisfies_cart,
    sign_payment_mandate,
    verify_payment_mandate,
    # T-5 Mandate-lifecycle EventBus emit helpers
    emit_cart_received,
    emit_intent_issued,
    emit_payment_authorised,
    emit_settlement_completed,
)
# v0.10 T-7: A2A Agent Card generator (well-known/agent.json)
# v0.10 T-8: A2A JSON-RPC 2.0 server skeleton
from .a2a import (
    A2A_METHODS_IMPLEMENTED,
    A2A_METHODS_PLANNED,
    A2A_PROTOCOL_VERSION,
    A2A_TASK_NOT_FOUND,
    A2A_WELL_KNOWN_PATH,
    JsonRpcError,
    build_agent_card,
    build_agent_card_from_session,
    create_a2a_app,
    validate_agent_card,
    write_agent_card,
)
# v0.9.6: AchievementCredential reducer — month-folded W3C VC over the ledger
from .achievement import (
    build_credential as build_achievement_credential,
    credential_digest as achievement_credential_digest,
    list_periods as list_achievement_periods,
    reduce_period as reduce_achievement_period,
    sign_credential as sign_achievement_credential,
    verify_credential as verify_achievement_credential,
)
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
# v0.9.6: workspace-unique group names + governance votes
from . import group_registry  # noqa: F401
from .group_registry import (
    GroupPolicy,
    GroupRecord,
    GroupRegistry,
    GroupRegistryError,
    PolicyChangeProposal,
    cast_vote as group_cast_vote,
    create_group,
    propose_policy_change,
    resolve_proposal,
    apply_proposal,
    normalize_group_name,
)
from .attach import TeamSession, attach

_LAZY_EXPORTS = {
    "TeamAgent": ("team_layer", "TeamAgent"),
    "TeamMemoryManager": ("team_layer", "TeamMemoryManager"),
    "SoulProvider": ("team_layer.memory_providers", "SoulProvider"),
    "UserModelProvider": ("team_layer.memory_providers", "UserModelProvider"),
    "VectorProvider": ("team_layer.memory_providers", "VectorProvider"),
    "LedgerProvider": ("team_layer.memory_providers", "LedgerProvider"),
    "CompressionPipeline": ("team_layer.compression", "CompressionPipeline"),
    "CompressionStage": ("team_layer.compression", "CompressionStage"),
    "EvoLoop": ("team_layer.evolution", "EvoLoop"),
    "EvoTrigger": ("team_layer.evolution", "EvoTrigger"),
    "Reflector": ("team_layer.evolution", "Reflector"),
    "Verifier": ("team_layer.evolution", "Verifier"),
    "EvolutionGate": ("team_layer.evolution", "EvolutionGate"),
    "SyncConfig": ("team_layer.git_sync", "SyncConfig"),
    "LogCollector": ("team_layer.git_sync", "LogCollector"),
    "SkillLoader": ("team_layer.git_sync", "SkillLoader"),
    "CentralAggregator": ("team_layer.git_sync", "CentralAggregator"),
    "Blackboard": ("team_layer.blackboard", "Blackboard"),
    "BlackboardEntry": ("team_layer.blackboard", "BlackboardEntry"),
    "BlackboardProvider": ("team_layer.blackboard", "BlackboardProvider"),
    "Scope": ("team_layer.blackboard", "Scope"),
    "render_kanban": ("team_layer.blackboard", "render_kanban"),
    "render_table": ("team_layer.blackboard", "render_table"),
    "AgentBackend": ("team_layer.backends", "AgentBackend"),
    "BackendCapabilities": ("team_layer.backends", "BackendCapabilities"),
    "BackendRegistry": ("team_layer.backends", "BackendRegistry"),
    "BackendUnavailableError": ("team_layer.backends", "BackendUnavailableError"),
    "SessionConfig": ("team_layer.backends", "SessionConfig"),
    "SessionSummary": ("team_layer.backends", "SessionSummary"),
    "TokenUsage": ("team_layer.backends", "TokenUsage"),
    "TurnResponse": ("team_layer.backends", "TurnResponse"),
    "default_registry": ("team_layer.backends", "default_registry"),
    "AgentDaemon": ("nth_dao.agent_daemon", "AgentDaemon"),
    "DaemonConfig": ("nth_dao.agent_daemon", "DaemonConfig"),
}


def __getattr__(name):
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    module_name, attribute = target
    value = getattr(import_module(module_name), attribute)
    globals()[name] = value
    return value

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
    "AgentDaemon",
    "DaemonConfig",
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
    # EventBus (v0.9.7) — team-level signed hash-chained event stream
    "BusEvent",
    "EventBus",
    "EventBusVerificationResult",
    "CorrectionType",
    # v0.9.8 Agent collaboration primitives (P4 facade)
    "AgentProfile",
    "ActionRequest",
    "ActionResponse",
    "ActionRouter",
    "ActionStatus",
    "HandlerInfo",
    "PubkeyLookup",
    "RouteStrategy",
    "Subscription",
    "SubscriptionManager",
    "AgentHealth",
    "CircuitState",
    "FailureRecord",
    "FaultIsolator",
    # Runtime handoff capsules
    "HANDOFF_CAPSULE_KIND",
    "HANDOFF_RESPONSE_KIND",
    "HANDOFF_RESPONSE_KIND_V1",
    "HANDOFF_RESPONSE_KIND_V2",
    "EVENT_EXEC_HANDOFF",
    "EVENT_EXEC_HANDOFF_LEGACY",
    "EVENT_EXEC_HANDOFF_PROPOSED",
    "EVENT_EXEC_HANDOFF_REFUTED",
    "EVENT_EXEC_HANDOFF_SUPERSEDED",
    "HandoffProjection",
    "HandoffRecord",
    "sign_handoff_capsule",
    "source_evidence_from_git",
    "verify_source_evidence",
    "verify_source_evidence_report",
    "verify_handoff_capsule",
    "record_handoff",
    "sign_handoff_response",
    "verify_handoff_response",
    "record_handoff_response",
    "record_handoff_response_checked",
    # v0.10 T-1 Mandate primitives
    "build_intent_mandate",
    "intent_mandate_digest",
    "is_intent_expired",
    "sign_intent_mandate",
    "verify_intent_mandate",
    # v0.10 T-2 CartMandate primitives
    "build_cart_mandate",
    "cart_mandate_digest",
    "cart_satisfies_intent",
    "is_cart_expired",
    "sign_cart_mandate",
    "verify_cart_mandate",
    # v0.10 T-3 PaymentMandate primitives + end-to-end gate
    "build_payment_mandate",
    "complete_triad_chain",
    "is_payment_expired",
    "payment_mandate_digest",
    "payment_satisfies_cart",
    "sign_payment_mandate",
    "verify_payment_mandate",
    # v0.10 T-5 reserved Mandate-lifecycle event types + emit helpers
    "MANDATE_INTENT_ISSUED",
    "MANDATE_CART_RECEIVED",
    "MANDATE_PAYMENT_AUTHORISED",
    "SETTLEMENT_COMPLETED",
    "MANDATE_LIFECYCLE_EVENT_TYPES",
    "emit_intent_issued",
    "emit_cart_received",
    "emit_payment_authorised",
    "emit_settlement_completed",
    # v0.10 T-7 A2A Agent Card generator
    "A2A_PROTOCOL_VERSION",
    "A2A_WELL_KNOWN_PATH",
    "build_agent_card",
    "build_agent_card_from_session",
    "validate_agent_card",
    "write_agent_card",
    # v0.10 T-8 A2A JSON-RPC 2.0 server
    "A2A_METHODS_IMPLEMENTED",
    "A2A_METHODS_PLANNED",
    "A2A_TASK_NOT_FOUND",
    "JsonRpcError",
    "create_a2a_app",
    # AchievementCredential (v0.9.6) — monthly W3C VC reducer over ledger
    "build_achievement_credential",
    "achievement_credential_digest",
    "list_achievement_periods",
    "reduce_achievement_period",
    "sign_achievement_credential",
    "verify_achievement_credential",
    # Guardian recovery (v0.9.5)
    "GuardianSet",
    "GuardianSignature",
    "GuardianStore",
    "KeyReplacementProof",
    "begin_key_replacement",
    "publish_guardian_set",
    "sign_replacement",
    "verify_replacement",
    # GroupRegistry (v0.9.6) — workspace-unique group names + governance
    "GroupPolicy",
    "GroupRecord",
    "GroupRegistry",
    "GroupRegistryError",
    "PolicyChangeProposal",
    "create_group",
    "propose_policy_change",
    "resolve_proposal",
    "apply_proposal",
    "normalize_group_name",
    "group_cast_vote",
]
