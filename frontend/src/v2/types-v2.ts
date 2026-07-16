/**
 * v2 UI-side types.
 *
 * These are the shapes the new UI consumes. They're NOT yet emitted
 * by the backend in some cases — see `mock.ts` for the dev seeds.
 * The contract: when the backend grows endpoints to emit these
 * shapes, the mock module is the only file that needs to flip.
 */

import type { Member, DaoSummary, Summary } from "../types";

/** Five-tier UI-side decision priority. Drives sidebar ordering
 *  and "impact" pill color in the decision card. */
export type DecisionImpact = "low" | "medium" | "high";

/** A queued decision the human user must approve or reject.
 *  This is the central object the new UI revolves around. */
export interface Decision {
  id: string;
  /** What the AI agent is asking permission to do. Imperative
   *  voice — "Sign mandate for Acme, ¥3500" rather than
   *  "Mandate signing requested". */
  title: string;
  /** Why the agent thinks this is the right call. One short
   *  paragraph max — long context goes to the JSON inspector. */
  rationale: string;
  /** "low" = routine / well within cap_token scope.
   *  "medium" = on-policy but worth a glance.
   *  "high" = outside cap_token scope OR financial OR cross-DAO. */
  impact: DecisionImpact;
  /** DID of the AI that proposes the action. */
  proposer_did: string;
  /** Human label for the proposer ("helper-1", "claude-cli", etc.). */
  proposer_label: string;
  /** Optional Mission this decision belongs to. */
  mission_id?: string;
  /** Receipt that would be emitted upon approval — preview only;
   *  the real receipt is signed after the user clicks Approve. */
  preview_receipt: Record<string, unknown>;
  /** When the AI raised this decision. ISO string. */
  raised_at: string;
  /** When the cap_token authorizing the proposed action expires.
   *  Drives the urgency badge on the sidebar item. */
  cap_expires_at?: string;

  /* Multi-user routing fields (audit pass#4 fix C2, 2026-06-10):
   * In a 50-person deployment "whose queue is this?" must have an
   * answer at the type level. v1 mock data leaves these undefined
   * so a single-user shell still renders everything; v1.x with
   * real backend MUST populate them.                              */
  /** Which human user must approve. When omitted, the decision is
   *  visible to every approver of the org (legacy single-user
   *  behaviour). When set, the queue filters by current identity. */
  assignee_user_did?: string;
  /** Routing model: "personal" = only assignee_user_did sees it;
   *  "any-approver" = anyone with the cap can approve;
   *  "specific-role" = filtered by role membership. */
  routing_policy?: "personal" | "any-approver" | "specific-role";
  /** Optional version / etag for optimistic-lock collision detect.
   *  When another user resolves the decision the server-stamped
   *  version moves forward; submitting a stale version returns 409. */
  version?: number;

  /** Phase 3d (2026-06-11): where the decision came from.
   *  ``operator`` = seed / hand-raised by a human.
   *  ``agent``    = a hub-supervised child emitted ``decision_raised``;
   *                 the hub stamped attribution from the AgentRecord
   *                 lookup so the proposer_did is the agent's real
   *                 did:key, NOT something the child could spoof. */
  source?: {
    type: "agent" | "operator";
    agent_id?: string;
  };
}

export interface MissionStepView {
  id: string;
  description: string;
  status: "todo" | "claimed" | "active" | "done" | "needs_review" | "failed" | "handed_off" | "blocked" | string;
  required_capabilities: string[];
  depends_on?: string[];
  assignee?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  completed_at?: string | null;
  notes?: string[];
  notes_count?: number;
}

export interface MissionTimelineEvent {
  id: string;
  kind: "mission" | "step" | "receipt" | "audit" | "handoff" | "warning" | string;
  label: string;
  detail?: string | null;
  at?: string | null;
  status?: string | null;
  agent_did?: string | null;
  receipt_id?: string | null;
  announcement_id?: string | null;
  source_announcement_id?: string | null;
  process_id?: string | null;
  capsule_hash?: string | null;
  refutation_count?: number;
  authorized_refutation_count?: number;
  authorization_reasons?: string[];
  evidence_count?: number;
  verification_status?: string | null;
  next_action?: string | null;
  superseded_by?: string | null;
}

export interface HandoffEvidenceVerification {
  status: string;
  reason?: string;
  kind?: string;
  path?: string;
  commit?: string;
  content_hash?: string;
  source?: Record<string, unknown>;
  resolver?: {
    type?: string;
    repo_id?: string;
    repo_url?: string;
    commit?: string;
    path?: string;
    content_hash?: string;
    source_present?: boolean;
    matched_by?: string;
  };
  local_reachable?: boolean;
  commit_reachable?: boolean;
  blob_reachable?: boolean;
  content_match?: boolean;
}

export interface HandoffDetail {
  capsule_hash: string;
  mission_id: string;
  step_id: string;
  finding: string;
  root_cause_hypothesis: string;
  verification_status: string;
  author_did: string;
  status: string;
  evidence_count: number;
  test_count: number;
  risk_count: number;
  refutation_count: number;
  superseded_by: string;
  evidence?: Record<string, unknown>[];
  evidence_verification?: HandoffEvidenceVerification[];
  review_packet?: Record<string, unknown>;
  changed_files?: string[];
  tests?: string[];
  next_actions?: string[];
  risks?: string[];
  refutations?: Record<string, unknown>[];
  supersessions?: Record<string, unknown>[];
}

/** A running Mission as the UI cares about it.
 *  Aligns with nth_dao/orchestration/mission.py at the field level
 *  but flattens for sidebar display. */
export interface MissionSummary {
  id: string;
  title: string;
  goal: string;
  status: "planning" | "active" | "paused" | "completed" | "failed" | "cancelled";
  /** Step counters for the progress badge. */
  steps_total: number;
  steps_done: number;
  steps_in_progress: number;
  /** Who's primarily executing — usually a delegated ephemeral DID. */
  driver_label: string;
  driver_did: string;
  /** Cap_token authorizing the driver, if any. */
  cap_token_id?: string;
  /** Market announcement this mission was claimed from, if any. */
  source_announcement_id?: string | null;
  /** Blackboard process card mirroring this mission, if any. */
  process_id?: string | null;
  started_at: string;
  /** Optional next actionable step description (the bridge already
   *  exposes this via tasks/get enrichment). */
  next_actionable?: string;
  /** Current in-flight/claimed/blocked step, if one exists. */
  current_action?: string;
  /** Stable locator for the current step, when current_action is present. */
  current_step_id?: string | null;
  current_step_status?: string | null;
  /** Step-level execution state. Present on live v2 backend; optional
   *  so older mock/demo payloads still render safely. */
  steps?: MissionStepView[];
  /** Human-readable execution-state snapshot derived from persisted
   *  Mission state. It is display data only; Audit/Receipt/EventBus
   *  remain canonical history. */
  timeline?: MissionTimelineEvent[];
  /** Which human user initiated / owns this mission (audit pass#4
   *  fix I2, 2026-06-10). At N=50 the mission board shows missions
   *  driven by various people — without an owner, accountability
   *  is ambiguous and cancellation authority is unclear. v1 mock
   *  leaves it undefined; v1.x populates from the originating
   *  POST /api/missions request. */
  owner_user_did?: string;
}

/** Past receipt as the UI summarizes for the audit feed. */
export interface ReceiptSummary {
  id: string;
  signer_did: string;
  signer_label: string;
  goal_id: string;
  content_hash: string;
  prev_content_hash: string;
  has_cap_token: boolean;
  /** Free-form one-liner describing the work, derived from the
   *  timeline's leading entry. */
  summary: string;
  issued_at: string;
  /** Human user on whose behalf the agent acted (audit pass#4 fix
   *  I4, 2026-06-10). At N=50 the same `billing-helper` agent may
   *  sign receipts for many users on the same day. Without this
   *  field the audit feed can't answer "show me only receipts
   *  issued on my behalf". The signing chain itself is unchanged;
   *  this is a UI / filter affordance derived from the cap_token
   *  used to sign. */
  principal_user_did?: string;
}

export interface ReceiptCapScopeSummary {
  present: boolean;
  token_id?: string;
  issuer_did?: string;
  subject_did?: string;
  capabilities?: string[];
  scope_task_id?: string;
  scope_dao?: string;
  scope_model_allowlist?: string[] | null;
  not_before?: number;
  not_after?: number;
}

export interface ReceiptDetail {
  receipt: Record<string, unknown>;
  summary: {
    receipt_id: string;
    signer_did: string;
    goal_id: string;
    issued_at: string;
    content_hash: string;
    prev_content_hash: string;
    kind: string;
    cap_scope: ReceiptCapScopeSummary;
  };
  verification: {
    verified: boolean;
    status: "verified" | "failed" | string;
    reason: string;
  };
}

/** Cap_token row for the Delegate panel. */
export interface CapTokenSummary {
  token_id: string;
  subject_did: string;
  subject_label: string;
  capabilities: string[];
  scope_task_id: string;
  not_before: number;
  not_after: number;
  revoked: boolean;
  use_count: number;
}

/** Top-bar identity slug — minimal info shown next to the brand. */
export interface IdentityHeader {
  agent_id: string;
  did: string;
  code: string;
}

/** Status bar field set — always visible. */
export interface StatusBarState {
  agent_id: string;
  code: string;
  did: string;
  active_caps: number;
  caps_expiring_soon: number;
  chain_head_short: string;
  active_missions: number;
  pending_decisions: number;
}

/** What the IconNav can navigate to.
 *
 *  Ordering reflects the dual-era philosophy:
 *  - In autopilot mode (target steady state, ~Q4 2026): the
 *    Blackboard is the user's primary screen; Decisions exists
 *    only as an exception/alert inbox.
 *  - In manual mode (now): users still hit Decisions every day.
 *    The visual priority via `decisionCount` badge handles that
 *    without reordering the nav.
 */
export type NavId =
  | "blackboard"
  | "inbox"
  | "missions"
  | "tasks"
  | "rules"
  | "agents"
  | "channels"
  | "audit"
  | "governance"
  | "reputation"
  | "contacts"
  | "chat";

/** 频道(收编自 8765 群聊,/api/v2/channels)。 */
export interface Channel {
  channel_id: string;
  name: string;
  topic: string;
  created_by: string;
  is_private: boolean;
  member_ids: string[];
  created_at: string;
  metadata?: {
    task_id?: string;
    mission_id?: string;
    process_id?: string;
    task_label?: string;
    mission_label?: string;
    dao_id?: string;
    scope_dao?: string;
    dao_label?: string;
    scope_label?: string;
    [key: string]: unknown;
  };
}

/** 频道消息(/api/v2/channels/{id}/messages 一行)。 */
export interface ChannelMessage {
  message_id: string;
  channel_id: string;
  sender_id: string;
  body: string;
  kind: string;
  created_at: string;
  metadata?: Record<string, unknown>;
  nth_receipt_id?: string;
  nth_receipt_content_hash?: string;
  /** Durable non-streaming channel workflow phase. */
  dispatch_phase?: "received" | "processing" | "completed" | "failed" | string;
  request_message_id?: string;
  status_source?: "hub" | string;
}

/** 任务广场公告(/api/v2/market/open 返回的一行)。发现态:可认领的活。 */
export interface TaskAnnouncement {
  announcement_id: string;
  /** Content-bound key used to disambiguate equal local ids across DAOs. */
  federation_key?: string;
  publisher_did: string;
  title: string;
  listing_type?: "task" | "service" | "product";
  description?: string;
  input_schema?: Record<string, unknown>;
  capability_set: string[];
  context: string;
  reward_minor: number;
  reward_asset: string;
  mission_id?: string;
  published_at_ms?: number;
  not_after?: number;
  claimed?: boolean;
  /** FED-2:经联邦从对端 DAO 发现的公告(非本地发布)。 */
  federated?: boolean;
  /** 该联邦公告来自哪个 peer hub(base URL)。 */
  source_peer?: string;
  federation_stale?: boolean;
  federation_verified_at_ms?: number;
}

/** 类别分面(/api/v2/market/categories)。 */
export interface TaskCategory {
  context: string;
  count: number;
}

export interface FederationStatus {
  peers: string[];
  seed_peers?: string[];
  learned_peers?: Record<string, FederationLearnedPeer>;
  file_peers: string[];
  env_peers: string[];
  poller_started: boolean;
  cached_announcements: number;
  stale_announcements?: number;
  last_refresh_ms: number;
  last_error: string;
  last_peer_count: number;
  refreshed?: boolean;
  updated?: boolean;
  peer_url?: string;
  action?: string;
  verified_peers?: Record<string, FederationVerifiedPeer>;
  discovered?: boolean;
  identity_verified_peers?: string[];
  discovered_peers?: FederationDiscoveredPeer[];
  imported_peers?: string[];
  skipped_peers?: FederationDiscoveredPeer[];
  discovery_errors?: string[];
  public_peer_url?: string;
  reverse_discovery_enabled?: boolean;
}

export interface FederationLearnedPeer {
  did: string;
  pubkey_prefix: string;
  last_verified_ms: number;
  expires_at_ms: number;
}

export interface FederationDiscoveredPeer {
  agent_id: string;
  label?: string;
  did?: string;
  capabilities?: string[];
  groups?: string[];
  ws_url?: string;
  source_addr?: string;
  federation_peer_url?: string;
  metadata?: Record<string, unknown>;
  identity_verified?: boolean;
  identity_url?: string;
  peer_did?: string;
  pubkey_prefix?: string;
  identity_error?: string;
}

export interface FederationVerifiedPeer {
  did: string;
  pubkey_prefix: string;
  verified_at: string;
  identity_url: string;
}

/** 发布任务的请求体(POST /api/v2/market/announce)。 */
export interface AnnounceTaskInput {
  title: string;
  listing_type?: "task" | "service" | "product";
  description?: string;
  capability_set?: string[];
  reward_minor?: number;
  reward_asset?: string;
  context?: string;
  mission_id?: string;
  not_after?: number;
}

/** Agent directory entry — for both local helpers and discovered
 *  peers. The shape unifies three discovery sources (LAN mDNS,
 *  ContactBook, A2A AgentCard) into a single row the UI can render
 *  homogeneously. */
export type AgentSource = "local" | "contact" | "lan" | "a2a";

export interface AgentEntry {
  did: string;
  code: string;
  label: string;
  source: AgentSource;
  /** A2A skill IDs advertised by the agent (from
   *  /.well-known/agent.json::skills[].id). */
  capabilities: string[];
  /** Optional last-seen timestamp (ISO). */
  last_seen?: string;
  /** Whether we have an active cap_token issued to this agent. */
  has_active_cap: boolean;
  /** Full A2A AgentCard JSON if we fetched it. */
  agent_card?: Record<string, unknown>;

  /* ── Phase 3a/3b/3d hub-supervised additions (2026-06-11) ──
   * These are populated for agents the local hub spawned via
   * /api/v2/agents/spawn. For ContactBook / LAN / disk-only
   * agents they're undefined. The UI uses them to show a "live"
   * badge, hide stop-buttons for non-local agents, and route
   * /ping + /a2a/echo through the hub proxy. */

  /** True when the agent is under hub supervision (we have a
   *  process handle for it). Distinct from "alive" — supervised
   *  agents can be dead if their subprocess crashed. */
  supervised?: boolean;
  /** Whether the supervised subprocess is currently running.
   *  Updates within ~1s of process death via the supervisor's
   *  is_alive check on each /api/v2/agents response. */
  alive?: boolean;
  /** Backend kind label the operator chose at spawn time
   *  ("mock", "claude-code", "codex", "hermes", ...). */
  kind?: string;
  /** Effective child execution timeout selected by the hub for this backend. */
  ask_timeout_s?: number;
  work_scope_id?: string;
  work_access?: "read-only" | "workspace-write" | string;
  work_revision?: string;
  /** Supervisor-local id used for stop/restart actions. */
  agent_id?: string;
  /** Ephemeral localhost port where the child serves its A2A
   *  HTTP surface (GET /ping, POST /a2a/<method>). Undefined when
   *  the child failed to bind (degraded state) or for non-local
   *  agents. */
  a2a_port?: number;
  /** True only after the child has loaded and verified its cap token. */
  a2a_ready?: boolean;
  /** Provider execution state; transport readiness alone is not a live model guarantee. */
  provider_state?: "unknown" | "ready" | "degraded" | string;
  provider_checked_at?: string;
  /** Phase G (Phase 6b cap_token scope, frontend integration):
   *  the cap_token's `scope_model_allowlist` joined into the agent
   *  listing. Wire semantics (matches the cap_token wire field):
   *    - undefined  — no per-token scope; backend MODEL_ALLOWLIST
   *                   is the only gate (or token was issued pre-6b).
   *    - []         — empty list, token forbids ALL `params['model']`
   *                   overrides.
   *    - [...]      — explicit allowed model names. */
  scope_model_allowlist?: string[];
}

/** A single chat message inside a conversation. Aligns with the
 *  backend's existing /api/messages payload shape. */
export interface ChatMessage {
  message_id: string;
  sender_id: string;
  sender_label: string;
  body: string;
  created_at: string;
  /** When the sender is an AI agent and the message was signed
   *  via a cap_token, the receipt id is here for the {} viewer. */
  nth_receipt_id?: string;
}

/** 温层:一条签名对话摘要(后端 /summarize 产出 + 验签)。前端只展示,
 *  不自己验签(JS 做不了加密);verified 由后端给。 */
export interface ConversationSummary {
  conversation_id: string;
  covered_message_ids: string[];
  transcript_sha256: string;
  summary_text: string;
  agent_did: string;
  instruction: string;
  verified: boolean;
  reason: string;
  receipt?: Record<string, unknown> | null;
  /** 前端产出时间(后端不返,前端补)。 */
  created_at: string;
}

/** Conversation summary — what the sidebar of the Chat view
 *  shows. A conversation is either a channel inside a DAO, or a
 *  direct line with a helper agent. */
export interface Conversation {
  id: string;
  /** "#general", "DM: helper-A", etc. */
  title: string;
  subtitle: string;
  /** Most recent message preview. */
  last_preview: string;
  last_at: string;
  unread: number;
  kind: "channel" | "dm";
  /** Participant DIDs — humans + agents (audit pass#4 fix M1,
   *  2026-06-10). At N=50 the Chat surface needs to enforce DM
   *  privacy: user A must NOT see user B's DM with their HR
   *  helper agent even when both DMs sit on the same shared
   *  Conversations server. Frontend treats this as authoritative
   *  filter input; backend MUST also enforce on the wire — never
   *  trust client-side filtering as a security boundary. */
  participant_dids?: string[];
}

/** Blackboard operational state — what a one-person company's
 *  process pipeline looks like at a glance. */
export type ProcessStage =
  | "received"
  | "in_progress"
  | "awaiting_external"
  | "done"
  | "blocked";

export interface ProcessCard {
  id: string;
  /** e.g. "Order #1247", "Refund #88", "Onboard candidate" */
  title: string;
  /** Free-form one-line context. */
  subtitle: string;
  /** Workflow this process belongs to (e.g. "shopping",
   *  "support", "hiring"). Drives swim-lane grouping. */
  workflow: string;
  /** Pipeline state. */
  stage: ProcessStage;
  /** Agent label currently driving the process. */
  current_agent: string;
  /** Optional next agent in the relay. */
  next_agent?: string;
  /** Cap_token authorizing the current step. */
  cap_token_id?: string;
  /** Money in play, if applicable. ("¥3500" / "$420") */
  amount?: string;
  /** ISO timestamp of last state change. */
  updated_at: string;
  /** True when this process consumed a Rule and skipped Decision
   *  Queue. Drives the "auto" badge. */
  auto: boolean;
}

/** A user-defined Rule that turns approval-required actions into
 *  auto-executed ones, bounded by a permanent (or long-lived)
 *  cap_token. */
export interface Rule {
  id: string;
  /** Imperative title — "Auto-pack orders under ¥1000". */
  title: string;
  /** When the rule fires — short natural-language condition. */
  when: string;
  /** What the rule causes — short natural-language action. */
  then: string;
  /** Workflow this rule belongs to. */
  workflow: string;
  /** Linked cap_token (the rule's authority anchor). */
  cap_token_id: string;
  /** Status — "active" = currently auto-executing, "draft" = saved
   *  but not in force, "paused" = user temporarily disabled. */
  status: "active" | "draft" | "paused";
  /** How many times this rule has fired in the trailing 30 days. */
  fired_30d: number;
  /** When the user last updated the rule. */
  updated_at: string;
  /** Author of the rule (audit pass#4 fix M2, 2026-06-10).
   *  At N=50 rules are shared org policy — accountability needs
   *  to be attached. Editing UI also needs to know who's
   *  allowed to modify ("you created this, you can edit"). */
  created_by_user_did?: string;
  /** Optimistic-lock version. Edit form opens at version=N;
   *  submitting at version<server returns 409 conflict. v1.x
   *  edit flow MUST read this on open and send it on PATCH. */
  version?: number;
}

/** Cmd+K command definition. */
export interface CommandItem {
  id: string;
  title: string;
  hint?: string;
  /** ``Cmd+J`` / ``↵`` etc. — visual hint only. */
  shortcut?: string;
  run: () => void | Promise<void>;
}

/** Re-exports for convenience. */
export type { Member, DaoSummary, Summary };
