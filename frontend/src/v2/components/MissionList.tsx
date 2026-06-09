/**
 * Mission list / cockpit view.
 *
 * Shows running missions with progress bars, their driver agents,
 * and the cap_token authorizing each driver. Side rail shows the
 * full Mission detail of whatever's selected.
 *
 * In v1 this is the "what is the AI doing for me right now" view.
 * In v2 this might gain real-time streaming of receipts and a
 * "pause / step / cancel" controls.
 */

import { useState } from "react";
import { IconTarget } from "./Icons";
import { SignaturePanel } from "./SignaturePanel";
import type { MissionSummary } from "../types-v2";

export interface MissionListProps {
  missions: MissionSummary[];
}

function pct(m: MissionSummary): number {
  if (m.steps_total === 0) return 0;
  return Math.round((m.steps_done / m.steps_total) * 100);
}

function statusPill(s: MissionSummary["status"]): "ok" | "wait" | "bad" | "dim" {
  switch (s) {
    case "active":   return "ok";
    case "planning": return "wait";
    case "paused":   return "wait";
    case "failed":   return "bad";
    case "cancelled": return "dim";
    case "completed": return "dim";
  }
}

export function MissionList({ missions }: MissionListProps) {
  const [selectedId, setSelectedId] = useState<string | null>(
    missions[0]?.id ?? null,
  );
  const selected = missions.find((m) => m.id === selectedId) ?? null;

  return (
    <>
      <aside className="sidebar">
        <div className="sidebar-head">
          <span className="sidebar-title">Active missions</span>
          <span className="sidebar-count">{missions.length}</span>
        </div>
        <div className="sidebar-list">
          {missions.length === 0 && (
            <p className="muted" style={{ padding: "12px 14px" }}>
              No missions in flight.
            </p>
          )}
          {missions.map((m) => (
            <button
              key={m.id}
              className={`sidebar-item ${selectedId === m.id ? "active" : ""}`}
              onClick={() => setSelectedId(m.id)}
            >
              <div className="sidebar-item-title">
                <span className={`pill ${statusPill(m.status)}`}>{m.status}</span>
                <span className="truncate">{m.title}</span>
              </div>
              <div className="sidebar-item-meta">
                <span>{m.driver_label}</span>
                <span className="muted">·</span>
                <span>{m.steps_done}/{m.steps_total}</span>
              </div>
            </button>
          ))}
        </div>
      </aside>

      <section className="main">
        <div className="main-head">
          <p className="main-eyebrow">Missions</p>
          <h1 className="main-title">What the agents are doing</h1>
          <p className="main-subtitle">
            Each mission represents a structured goal an AI agent is
            executing on your behalf, bounded by a cap_token.
          </p>
        </div>

        <div className="main-body">
          {missions.length === 0 ? (
            <div className="main-empty" style={{ minHeight: 200 }}>
              <div className="main-empty-icon">
                <IconTarget size={36} />
              </div>
              <p>No active missions.</p>
            </div>
          ) : (
            <div className="stack">
              {missions.map((m) => (
                <article
                  key={m.id}
                  className="decision-card"
                  onClick={() => setSelectedId(m.id)}
                  style={{ cursor: "pointer" }}
                >
                  <div className="decision-card-head">
                    <div>
                      <h3 className="decision-card-title">{m.title}</h3>
                      <div className="decision-card-subject">
                        <span>by {m.driver_label}</span>
                        <span className="muted">·</span>
                        <code>{m.driver_did.slice(0, 20)}…</code>
                      </div>
                    </div>
                    <span className={`pill ${statusPill(m.status)}`}>{m.status}</span>
                  </div>

                  <div style={{ margin: "12px 0 16px" }}>
                    <div
                      style={{
                        height: 6,
                        background: "var(--bg-elevated)",
                        borderRadius: 3,
                        overflow: "hidden",
                      }}
                    >
                      <div
                        style={{
                          width: `${pct(m)}%`,
                          height: "100%",
                          background:
                            m.status === "failed"
                              ? "var(--status-bad)"
                              : "var(--accent)",
                          transition: "width var(--m-fast) var(--ease)",
                        }}
                      />
                    </div>
                    <div className="decision-card-meta" style={{ marginTop: 8 }}>
                      <span>
                        {m.steps_done} done · {m.steps_in_progress} in
                        progress · {m.steps_total} total
                      </span>
                      {m.cap_token_id && (
                        <span>
                          cap_token <code>{m.cap_token_id}</code>
                        </span>
                      )}
                    </div>
                  </div>

                  {m.next_actionable && (
                    <div className="decision-card-rationale">
                      <span className="muted" style={{ fontSize: 11 }}>
                        Next:
                      </span>{" "}
                      {m.next_actionable}
                    </div>
                  )}
                </article>
              ))}
            </div>
          )}
        </div>
      </section>

      <aside className="detail">
        <div className="detail-head">
          <span className="detail-title">Mission detail</span>
        </div>
        <div className="detail-body">
          {selected ? (
            <>
              <div className="detail-section">
                <div className="detail-section-label">Identity</div>
                <div className="detail-row">
                  <span className="key">Driver</span>
                  <span className="value">{selected.driver_label}</span>
                </div>
                <div className="detail-row">
                  <span className="key">Cap_token</span>
                  <span className="value">{selected.cap_token_id || "—"}</span>
                </div>
                <div className="detail-row">
                  <span className="key">Started</span>
                  <span className="value">
                    {new Date(selected.started_at).toLocaleString()}
                  </span>
                </div>
              </div>
              <SignaturePanel
                value={selected}
                title="Mission shape"
              />
            </>
          ) : (
            <p className="muted">Select a mission to inspect.</p>
          )}
        </div>
      </aside>
    </>
  );
}
