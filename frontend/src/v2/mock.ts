/**
 * Mock seeds for the v2 UI until backend endpoints emit these shapes.
 *
 * Single source of truth for "fake but realistic" data. When the
 * backend grows ``/api/decisions``, ``/api/missions/active`` etc.,
 * the replacement happens here ONLY — components consume the same
 * types.
 */

import type {
  Decision,
  MissionSummary,
  ReceiptSummary,
  CapTokenSummary,
} from "./types-v2";

const helperA = "did:key:z6MkqHKGkA1NXG2DWjsa7GAgrn4D7Dm57GwjeFm56811A";
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
