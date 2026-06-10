/**
 * Mock seeds for the v2 UI until backend endpoints emit these shapes.
 *
 * Single source of truth for "fake but realistic" data. When the
 * backend grows ``/api/decisions``, ``/api/missions/active`` etc.,
 * the replacement happens here ONLY — components consume the same
 * types.
 *
 * ╔═══════════════════════ DRIFT WATCH ═══════════════════════╗
 * ║  This file MUST stay structurally aligned with the Python ║
 * ║  ``_seed_*`` functions in ``nth_dao/web/v2_api.py``.      ║
 * ║                                                           ║
 * ║  Why: the v2 console renders mock.ts when the hub is      ║
 * ║  unreachable, AND renders the Python seed when the hub is ║
 * ║  up but the disk readers find no live data. If the two    ║
 * ║  diverge (different ids, different titles, different      ║
 * ║  ordering) a user toggling hub up/down sees different     ║
 * ║  "demo data" in the same view — a trust hit.              ║
 * ║                                                           ║
 * ║  Drift class confined to structural fields (id / title /  ║
 * ║  DID / array order). Timestamps differ by design —        ║
 * ║  Date.now() here, datetime.now() server-side.             ║
 * ║                                                           ║
 * ║  Phase 2 plan: extract this data to ``seed.json`` and     ║
 * ║  have both Python and TypeScript import it. Tracking:     ║
 * ║  review pass#1 finding N1 (2026-06-10).                   ║
 * ╚═══════════════════════════════════════════════════════════╝
 */

import type {
  Decision,
  MissionSummary,
  ReceiptSummary,
  CapTokenSummary,
  ProcessCard,
  Rule,
  AgentEntry,
  ChatMessage,
  Conversation,
} from "./types-v2";

// Self-consistency fix 2026-06-10 (review pass#2 finding): this
// const was previously `…GwjeFm56811A` while every literal use of
// the same agent elsewhere in this file (mockAgents[0].did, the
// sender_id of billing-helper's chat messages) was `…GwjeFm568311A`
// — a 1-char drift hidden inside mock.ts itself. The Python seed
// in nth_dao/web/v2_api.py mirrors the longer form, so the const
// is realigned to match. Any DID-equality check between the helperA
// var and the agent record would have silently failed before this.
const helperA = "did:key:z6MkqHKGkA1NXG2DWjsa7GAgrn4D7Dm57GwjeFm568311A";
const helperB = "did:key:z6MkpQ8eF1xRzL3tJyN5sWvD9XbA2C7uYkP4hM8kT6f3B";

export const mockDecisions: Decision[] = [
  {
    id: "dec-001",
    title: "Sign payment mandate to Acme Cloud — ¥3,500",
    rationale:
      "Monthly compute bill for the launch infrastructure. Within "
      + "budget envelope of ¥5,000/mo set in mission charter. Acme "
      + "is in the verified vendor list. No anomaly in the invoice "
      + "amount versus last 3 months.",
    impact: "medium",
    proposer_did: helperA,
    proposer_label: "billing-helper",
    mission_id: "mission-launch-2026",
    preview_receipt: {
      kind: "nth-execution-receipt-v1",
      signer_did: helperA,
      goal_id: "mission-launch-2026",
      timeline: [
        {
          timestamp: 1717840800000,
          type: "nth.mandate_signed",
          payload: {
            vendor: "acme-cloud",
            amount_cny: 3500,
            mandate_id: "mandate-2026-06-09-001",
          },
        },
      ],
    },
    raised_at: "2026-06-09T18:42:00Z",
    cap_expires_at: "2026-06-10T02:42:00Z",
  },
  {
    id: "dec-002",
    title: "Delegate code-refactor task to helper-B for 4 hours",
    rationale:
      "Backlog item BL-1247 hit blocker. helper-B specialises in "
      + "refactoring with a 92% acceptance rate on similar tasks in "
      + "the last 30 days. Requested cap_token: a2a:message_send + "
      + "nth:receipt_sign, scope_task_id=task-bl-1247, ttl=4h.",
    impact: "low",
    proposer_did: helperA,
    proposer_label: "planner",
    preview_receipt: {
      kind: "nth-cap-token-v1",
      subject_did: helperB,
      capabilities: ["a2a:message_send", "nth:receipt_sign"],
      scope_task_id: "task-bl-1247",
      ttl_ms: 14_400_000,
    },
    raised_at: "2026-06-09T17:15:00Z",
  },
  {
    id: "dec-003",
    title: "Cross-DAO vote: ratify governance proposal in mumolawos",
    rationale:
      "Outside your home DAO — voting in mumolawos consortium on "
      + "proposal MGV-2026-07: adopt motebit execution-ledger@1.0 "
      + "as wire-format standard. Aligns with our DESIGN_TRADE_OFFS "
      + "§2 commitment. Other 4 founders have signed. Your vote "
      + "tips quorum.",
    impact: "high",
    proposer_did: "did:key:z6MkmRxmBi9p9ziBz2JzBwd8Y5iMzzhPXAi95MPZiLEJJqjL",
    proposer_label: "self-prompt",
    preview_receipt: {
      kind: "nth-vote-receipt-v1",
      proposal_id: "MGV-2026-07",
      vote: "yes",
      cross_dao: "mumolawos",
    },
    raised_at: "2026-06-09T14:08:00Z",
  },
];

export const mockMissions: MissionSummary[] = [
  {
    id: "mission-launch-2026",
    title: "NTH DAO 1.0 launch",
    goal: "Ship 1.0 with announce + post-mortem doc",
    status: "active",
    steps_total: 3,
    steps_done: 1,
    steps_in_progress: 1,
    driver_label: "billing-helper",
    driver_did: helperA,
    cap_token_id: "cap-bnHs82Lq",
    started_at: "2026-06-08T09:00:00Z",
    next_actionable: "Send draft to early users for review",
  },
  {
    id: "mission-refactor-billing",
    title: "Refactor billing module",
    goal: "Replace BL-1247 + companion fixtures",
    status: "active",
    steps_total: 5,
    steps_done: 0,
    steps_in_progress: 2,
    driver_label: "code-helper",
    driver_did: helperB,
    cap_token_id: "cap-3xQ1pTaM",
    started_at: "2026-06-09T15:30:00Z",
    next_actionable: "Extract pricing service from monolith",
  },
];

export const mockReceipts: ReceiptSummary[] = [
  {
    id: "rcpt-aaa1",
    signer_did: helperA,
    signer_label: "billing-helper",
    goal_id: "mission-launch-2026",
    content_hash: "0a9c0bf3e89b6901cdab12345678cafe...",
    prev_content_hash: "",
    has_cap_token: true,
    summary: "Drafted launch announcement v1",
    issued_at: "2026-06-09T11:20:00Z",
  },
  {
    id: "rcpt-aaa2",
    signer_did: helperA,
    signer_label: "billing-helper",
    goal_id: "mission-launch-2026",
    content_hash: "a7f8ab3c5b93c83a...",
    prev_content_hash: "0a9c0bf3e89b6901cdab12345678cafe...",
    has_cap_token: true,
    summary: "Sent to 3 early users",
    issued_at: "2026-06-09T13:45:00Z",
  },
];

/** Blackboard seeds — the autopilot-era "one-person company"
 *  operational dashboard. Concrete demo: a small e-commerce shop
 *  where the seller (the user) sleeps while agents handle orders. */
export const mockProcesses: ProcessCard[] = [
  {
    id: "ord-1247",
    title: "Order #1247",
    subtitle: "2× Mechanical keyboard · Tokyo",
    workflow: "shopping",
    stage: "in_progress",
    current_agent: "fulfillment-bot",
    next_agent: "shipping-bot",
    cap_token_id: "cap-bnHs82Lq",
    amount: "¥3,400",
    updated_at: new Date(Date.now() - 22 * 60_000).toISOString(),
    auto: true,
  },
  {
    id: "ord-1248",
    title: "Order #1248",
    subtitle: "1× Standing desk · Osaka",
    workflow: "shopping",
    stage: "received",
    current_agent: "intake-bot",
    next_agent: "fulfillment-bot",
    cap_token_id: "cap-bnHs82Lq",
    amount: "¥8,900",
    updated_at: new Date(Date.now() - 4 * 60_000).toISOString(),
    auto: true,
  },
  {
    id: "ord-1246",
    title: "Order #1246",
    subtitle: "1× Cable kit · Kyoto",
    workflow: "shopping",
    stage: "done",
    current_agent: "shipping-bot",
    amount: "¥240",
    updated_at: new Date(Date.now() - 2 * 3600_000).toISOString(),
    auto: true,
  },
  {
    id: "ord-1244",
    title: "Order #1244 — refund request",
    subtitle: "Customer claims damaged on arrival",
    workflow: "support",
    stage: "awaiting_external",
    current_agent: "support-bot",
    next_agent: "refund-bot",
    cap_token_id: "cap-supportLong",
    amount: "¥1,200",
    updated_at: new Date(Date.now() - 35 * 60_000).toISOString(),
    auto: true,
  },
  {
    id: "ord-1240",
    title: "Order #1240 — chargeback flagged",
    subtitle: "Bank dispute received, needs manual review",
    workflow: "support",
    stage: "blocked",
    current_agent: "support-bot",
    cap_token_id: "cap-supportLong",
    amount: "¥4,500",
    updated_at: new Date(Date.now() - 12 * 3600_000).toISOString(),
    auto: false,
  },
];

export const mockRules: Rule[] = [
  {
    id: "rule-001",
    title: "Auto-pack and ship orders under ¥5,000",
    when: "New order received, amount < ¥5,000, item in stock",
    then: "fulfillment-bot packs → shipping-bot dispatches → "
      + "notification-bot mails tracking number",
    workflow: "shopping",
    cap_token_id: "cap-bnHs82Lq",
    status: "active",
    fired_30d: 87,
    updated_at: "2026-05-15T10:00:00Z",
  },
  {
    id: "rule-002",
    title: "Auto-refund within 30 days of purchase",
    when: "Refund request received, within 30d, no fraud flag",
    then: "support-bot confirms → refund-bot processes → "
      + "ledger-bot reconciles",
    workflow: "support",
    cap_token_id: "cap-supportLong",
    status: "active",
    fired_30d: 12,
    updated_at: "2026-05-20T14:30:00Z",
  },
  {
    id: "rule-003",
    title: "Hold chargebacks for manual review",
    when: "Bank chargeback notification received",
    then: "Raise Decision (do not auto-process)",
    workflow: "support",
    cap_token_id: "cap-supportLong",
    status: "active",
    fired_30d: 1,
    updated_at: "2026-05-22T09:15:00Z",
  },
  {
    id: "rule-004",
    title: "Auto-sign vendor invoices from verified vendors",
    when: "Mandate request from vendor in verified-list, amount "
      + "< ¥10,000",
    then: "mandate-bot signs → ledger-bot records",
    workflow: "finance",
    cap_token_id: "cap-financeLong",
    status: "draft",
    fired_30d: 0,
    updated_at: "2026-06-08T18:00:00Z",
  },
];

export const mockCapTokens: CapTokenSummary[] = [
  {
    token_id: "cap-bnHs82Lq",
    subject_did: helperA,
    subject_label: "billing-helper",
    capabilities: ["a2a:message_send", "nth:receipt_sign"],
    scope_task_id: "mission-launch-2026",
    not_before: Date.now() - 9 * 3600_000,
    not_after: Date.now() + 3 * 3600_000,
    revoked: false,
    use_count: 12,
  },
  {
    token_id: "cap-3xQ1pTaM",
    subject_did: helperB,
    subject_label: "code-helper",
    capabilities: [
      "a2a:message_send",
      "a2a:task_split",
      "nth:receipt_sign",
    ],
    scope_task_id: "task-bl-1247",
    not_before: Date.now() - 2 * 3600_000,
    not_after: Date.now() + 2 * 3600_000,
    revoked: false,
    use_count: 4,
  },
];

/** Agent directory seeds — three sources (local helpers,
 *  ContactBook entries, LAN-discovered peers) merged into one
 *  flat list for the AgentDirectoryView. */
export const mockAgents: AgentEntry[] = [
  {
    did: "did:key:z6MkqHKGkA1NXG2DWjsa7GAgrn4D7Dm57GwjeFm568311A",
    code: "7e3a-91b2",
    label: "billing-helper",
    source: "local",
    capabilities: ["nth-dao.chat", "nth-dao.mandate"],
    last_seen: new Date(Date.now() - 5 * 60_000).toISOString(),
    has_active_cap: true,
  },
  {
    did: "did:key:z6MkpQ8eF1xRzL3tJyN5sWvD9XbA2C7uYkP4hM8kT6f3B",
    code: "1f9c-44de",
    label: "code-helper",
    source: "local",
    capabilities: ["nth-dao.chat", "nth-dao.tasks"],
    last_seen: new Date(Date.now() - 30 * 60_000).toISOString(),
    has_active_cap: true,
  },
  {
    did: "did:key:z6MkrTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
    code: "a3d8-c5fa",
    label: "Alice (Acme Cloud rep)",
    source: "contact",
    capabilities: ["nth-dao.chat", "nth-dao.mandate"],
    last_seen: new Date(Date.now() - 2 * 86400_000).toISOString(),
    has_active_cap: false,
  },
  {
    did: "did:key:z6Mk5p1H3kT9YqXqMpL7Wm2N6bV8jK4cD5fE3hQ9rZxAtPq",
    code: "62b1-08e4",
    label: "mumolawos-coordinator",
    source: "lan",
    capabilities: [
      "nth-dao.chat",
      "nth-dao.dao-management",
      "nth-dao.governance",
      "nth-dao.a2a-protocol",
    ],
    last_seen: new Date(Date.now() - 12 * 60_000).toISOString(),
    has_active_cap: false,
  },
  {
    did: "did:key:z6MkjyN3aP2qLkR8wEsTvB4nMc6dF9gXuYhAvKkH7tQ4rPsM",
    code: "ff04-7c3b",
    label: "fulfillment-bot",
    source: "local",
    capabilities: ["nth-dao.chat", "nth-dao.tasks"],
    last_seen: new Date(Date.now() - 90_000).toISOString(),
    has_active_cap: true,
  },
];

/** Conversation seeds — channel + DM mix to show the Chat view
 *  can host both DAO governance threads and direct lines to
 *  helpers. */
export const mockConversations: Conversation[] = [
  {
    id: "ch-general",
    title: "#general",
    subtitle: "Home DAO · 4 members",
    last_preview:
      "billing-helper: Acme invoice queued for your approval — see Decisions",
    last_at: new Date(Date.now() - 8 * 60_000).toISOString(),
    unread: 1,
    kind: "channel",
  },
  {
    id: "dm-billing-helper",
    title: "DM: billing-helper",
    subtitle: "Direct line to your AI accountant",
    last_preview:
      "I drafted the launch announcement. Receipt id 0a9c0bf3…",
    last_at: new Date(Date.now() - 22 * 60_000).toISOString(),
    unread: 0,
    kind: "dm",
  },
  {
    id: "dm-code-helper",
    title: "DM: code-helper",
    subtitle: "Refactor sessions",
    last_preview:
      "Pricing service extracted. Tests pass. Ready for review.",
    last_at: new Date(Date.now() - 4 * 3600_000).toISOString(),
    unread: 0,
    kind: "dm",
  },
  {
    id: "ch-launch",
    title: "#launch",
    subtitle: "Home DAO · 3 members",
    last_preview: "you: shipping it Friday. final QA tonight.",
    last_at: new Date(Date.now() - 86400_000).toISOString(),
    unread: 0,
    kind: "channel",
  },
];

export const mockChatMessages: Record<string, ChatMessage[]> = {
  "ch-general": [
    {
      message_id: "m-1",
      sender_id: "admin",
      sender_label: "you",
      body: "morning. anyone seen the Acme invoice come through?",
      created_at: new Date(Date.now() - 45 * 60_000).toISOString(),
    },
    {
      message_id: "m-2",
      sender_id: "did:key:z6MkqHKGkA1NXG2DWjsa7GAgrn4D7Dm57GwjeFm568311A",
      sender_label: "billing-helper",
      body:
        "Yes — landed at 09:42. ¥3,500. Within your vendor allowlist. "
        + "I queued it as a Decision so you can approve when ready.",
      created_at: new Date(Date.now() - 8 * 60_000).toISOString(),
      nth_receipt_id: "0a9c0bf3e89b6901cdab12345678cafe",
    },
  ],
  "dm-billing-helper": [
    {
      message_id: "m-10",
      sender_id: "admin",
      sender_label: "you",
      body: "draft the launch announcement, low-key tone please",
      created_at: new Date(Date.now() - 80 * 60_000).toISOString(),
    },
    {
      message_id: "m-11",
      sender_id: "did:key:z6MkqHKGkA1NXG2DWjsa7GAgrn4D7Dm57GwjeFm568311A",
      sender_label: "billing-helper",
      body:
        "Drafted v1. Receipt id 0a9c0bf3… signed under your "
        + "cap_token cap-bnHs82Lq. Want me to ping 3 early users?",
      created_at: new Date(Date.now() - 22 * 60_000).toISOString(),
      nth_receipt_id: "0a9c0bf3e89b6901cdab12345678cafe",
    },
  ],
  "dm-code-helper": [],
  "ch-launch": [],
};
