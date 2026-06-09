/**
 * Decision Queue main view.
 *
 * Composes:
 *   - Sidebar: ordered list of pending decisions (impact-sorted)
 *   - Main: header + currently-selected DecisionCard
 *   - Detail rail: signature inspector + side context
 *
 * The "currently selected" decision is the one the user is
 * working on. Approve / Reject / Defer remove it from the queue
 * and auto-select the next.
 */

import { useEffect, useMemo, useState } from "react";
import { DecisionCard } from "./DecisionCard";
import { SignaturePanel } from "./SignaturePanel";
import { IconInbox } from "./Icons";
import type { Decision } from "../types-v2";

export interface DecisionQueueProps {
  decisions: Decision[];
  onApprove: (id: string) => Promise<void> | void;
  onReject: (id: string) => Promise<void> | void;
  onDefer: (id: string) => Promise<void> | void;
}

const IMPACT_ORDER: Record<Decision["impact"], number> = {
  high: 0,
  medium: 1,
  low: 2,
};

export function DecisionQueue({ decisions, onApprove, onReject, onDefer }: DecisionQueueProps) {
  const sorted = useMemo(
    () =>
      decisions.slice().sort(
        (a, b) =>
          IMPACT_ORDER[a.impact] - IMPACT_ORDER[b.impact] ||
          a.raised_at.localeCompare(b.raised_at),
      ),
    [decisions],
  );

  const [selectedId, setSelectedId] = useState<string | null>(
    sorted[0]?.id ?? null,
  );

  // Keep selected valid after queue mutations.
  useEffect(() => {
    if (!sorted.some((d) => d.id === selectedId)) {
      setSelectedId(sorted[0]?.id ?? null);
    }
  }, [sorted, selectedId]);

  const selected = sorted.find((d) => d.id === selectedId) ?? null;

  return (
    <>
      <aside className="sidebar">
        <div className="sidebar-head">
          <span className="sidebar-title">Pending decisions</span>
          <span className="sidebar-count">{sorted.length}</span>
        </div>
        <div className="sidebar-list">
          {sorted.length === 0 && (
            <p className="muted" style={{ padding: "12px 14px" }}>
              Inbox zero. The agents are all on-policy.
            </p>
          )}
          {sorted.map((d) => (
            <button
              key={d.id}
              className={`sidebar-item ${selectedId === d.id ? "active" : ""}`}
              onClick={() => setSelectedId(d.id)}
            >
              <div className="sidebar-item-title">
                <span className={`pill ${
                  d.impact === "high" ? "bad" :
                    d.impact === "medium" ? "wait" : "ok"
                }`}>{d.impact}</span>
                <span className="truncate">{d.title}</span>
              </div>
              <div className="sidebar-item-meta">
                <span>{d.proposer_label}</span>
              </div>
            </button>
          ))}
        </div>
      </aside>

      <section className="main">
        <div className="main-head">
          <p className="main-eyebrow">Decisions</p>
          <h1 className="main-title">Approve, reject, or defer</h1>
          <p className="main-subtitle">
            Each card is a request from an AI agent acting on your
            behalf. Approving signs a receipt; the cryptographic chain
            preserves the audit trail forever.
          </p>
        </div>

        <div className="main-body">
          {selected ? (
            <DecisionCard
              decision={selected}
              onApprove={onApprove}
              onReject={onReject}
              onDefer={onDefer}
            />
          ) : (
            <div className="main-empty" style={{ minHeight: 200 }}>
              <div className="main-empty-icon">
                <IconInbox size={36} />
              </div>
              <p>Inbox zero.</p>
              <p className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                Every agent action right now is within the cap_tokens
                you've already issued.
              </p>
            </div>
          )}
        </div>
      </section>

      <aside className="detail">
        <div className="detail-head">
          <span className="detail-title">Context</span>
        </div>
        <div className="detail-body">
          {selected ? (
            <>
              <div className="detail-section">
                <div className="detail-section-label">Action target</div>
                <div className="detail-row">
                  <span className="key">Impact</span>
                  <span className="value">{selected.impact}</span>
                </div>
                <div className="detail-row">
                  <span className="key">Proposer</span>
                  <span className="value">{selected.proposer_label}</span>
                </div>
                <div className="detail-row">
                  <span className="key">Proposer DID</span>
                  <span className="value">
                    {selected.proposer_did.slice(0, 20)}…
                  </span>
                </div>
                {selected.mission_id && (
                  <div className="detail-row">
                    <span className="key">Mission</span>
                    <span className="value">{selected.mission_id}</span>
                  </div>
                )}
                <div className="detail-row">
                  <span className="key">Raised at</span>
                  <span className="value">
                    {new Date(selected.raised_at).toLocaleString()}
                  </span>
                </div>
              </div>

              <SignaturePanel
                value={selected.preview_receipt}
                title="Preview receipt"
              />
            </>
          ) : (
            <p className="muted">Select a decision to inspect.</p>
          )}
        </div>
      </aside>
    </>
  );
}
