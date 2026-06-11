/**
 * The DecisionCard is the central UI primitive of NTH DAO v2.
 *
 * Every interaction with an AI agent eventually becomes one of
 * these cards: the agent proposes an action, the human gates it,
 * the signed receipt manifests on Approve.
 *
 * Layout:
 *   ┌────────────────────────────────────────────┐
 *   │ Title (imperative voice)            [PILL] │
 *   │ proposer · time · cap_token expiry         │
 *   │                                            │
 *   │ ▌ Rationale (one paragraph, accent border) │
 *   │                                            │
 *   │ time · receipt preview · mission link      │
 *   │ ─────────────────────────────────────────  │
 *   │ [Approve ⌘J]  [Reject]  [Defer 24h]  [{}]  │
 *   └────────────────────────────────────────────┘
 *
 * The `{}` button toggles raw signature inspection inline.
 */

import { useState } from "react";
import { IconBraces, IconCheck, IconClock, IconX } from "./Icons";
import { SignaturePanel } from "./SignaturePanel";
import { relativeFuture, relativeTime } from "../utils/time";
import type { Decision } from "../types-v2";

export interface DecisionCardProps {
  decision: Decision;
  onApprove: (id: string) => Promise<void> | void;
  onReject: (id: string) => Promise<void> | void;
  onDefer: (id: string) => Promise<void> | void;
}

export function DecisionCard({ decision, onApprove, onReject, onDefer }: DecisionCardProps) {
  const [showJson, setShowJson] = useState(false);

  return (
    <article className="decision-card">
      <div className="decision-card-head">
        <div>
          <h3 className="decision-card-title">
            {decision.title}
            {/* Phase 3f (2026-06-11): attribution badge for
                child-raised decisions. The hub stamps source.type
                from the decision_raiser closure, so this badge
                proves attribution at the API layer — the child
                can't spoof it (Phase 3d H-1 fix). */}
            {decision.source?.type === "agent" && (
              <span
                className="pill dim"
                title={
                  "Raised by a supervised agent (not by the operator). " +
                  "Hub-stamped attribution — proposer_did matches the " +
                  "agent's real did:key from the AgentRecord."
                }
                style={{ marginLeft: 8, fontSize: 10 }}
              >
                agent
              </span>
            )}
          </h3>
          <div className="decision-card-subject">
            <span>{decision.proposer_label}</span>
            <span className="muted">·</span>
            <code title={decision.proposer_did}>
              {decision.proposer_did.slice(0, 18)}…
            </code>
            <span className="muted">·</span>
            <span>{relativeTime(decision.raised_at)}</span>
          </div>
        </div>
        <span className={`decision-card-impact ${decision.impact}`}>
          {decision.impact === "high"
            ? "High impact"
            : decision.impact === "medium"
              ? "On-policy"
              : "Routine"}
        </span>
      </div>

      <p className="decision-card-rationale">{decision.rationale}</p>

      <div className="decision-card-meta">
        {decision.mission_id && (
          <span>
            mission <code>{decision.mission_id}</code>
          </span>
        )}
        {decision.cap_expires_at && (
          <span title="When the authorizing cap_token expires">
            <IconClock size={11} style={{ verticalAlign: "-1px" }} />{" "}
            cap {relativeFuture(decision.cap_expires_at)}
          </span>
        )}
      </div>

      {showJson && (
        <SignaturePanel
          value={decision.preview_receipt}
          title="Preview receipt (would be signed on Approve)"
        />
      )}

      <div className="decision-card-actions">
        <button
          className="btn btn-primary"
          onClick={() => onApprove(decision.id)}
        >
          <IconCheck size={14} /> Approve <kbd>⌘J</kbd>
        </button>
        <button
          className="btn btn-secondary"
          onClick={() => onDefer(decision.id)}
        >
          Defer 24h
        </button>
        <button
          className="btn btn-danger"
          onClick={() => onReject(decision.id)}
        >
          <IconX size={14} /> Reject
        </button>
        <span style={{ flex: 1 }} />
        <button
          className="btn btn-ghost"
          onClick={() => setShowJson((v) => !v)}
          title="Toggle signature inspector"
        >
          <IconBraces size={14} />
          {showJson ? "Hide JSON" : "Show JSON"}
        </button>
      </div>
    </article>
  );
}
