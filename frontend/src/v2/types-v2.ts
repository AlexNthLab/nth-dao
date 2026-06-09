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
  started_at: string;
  /** Optional next actionable step description (the bridge already
   *  exposes this via tasks/get enrichment). */
  next_actionable?: string;
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

/** What the IconNav can navigate to. */
export type NavId =
  | "inbox"
  | "missions"
  | "audit"
  | "governance"
  | "delegate"
  | "chat";

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
