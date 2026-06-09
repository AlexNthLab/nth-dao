/**
 * Blackboard — the autopilot-era main screen.
 *
 * This is the operational dashboard of a one-person company: a
 * Kanban-style board where each card is a process (an order, a
 * support ticket, an invoice) and each column is a workflow stage.
 *
 * Why Kanban, not list:
 *   - Spatial layout shows the flow of work at a glance — the
 *     user immediately sees where work is queued vs done
 *   - Color-coded ⚡ badge marks auto-executed processes (no
 *     decision queue interruption) — the "rule mode is working"
 *     signal
 *   - Blocked / awaiting-external columns visually surface
 *     exceptions that DO need attention
 *
 * Sidebar shows workflow filters; detail rail shows the selected
 * process card's full state including which agent is currently
 * driving and which cap_token authorizes them.
 */

import { useMemo, useState } from "react";
import { IconLayout, IconZap } from "./Icons";
import { SignaturePanel } from "./SignaturePanel";
import type { ProcessCard, ProcessStage } from "../types-v2";

export interface BlackboardViewProps {
  processes: ProcessCard[];
}

const COLUMNS: { id: ProcessStage; label: string; pill: "ok" | "wait" | "bad" | "dim" }[] = [
  { id: "received",           label: "Intake",   pill: "wait" },
  { id: "in_progress",        label: "Working",  pill: "ok"   },
  { id: "awaiting_external",  label: "Awaiting", pill: "wait" },
  { id: "blocked",            label: "Blocked",  pill: "bad"  },
  { id: "done",               label: "Done",     pill: "dim"  },
];

function relativeTime(iso: string): string {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h`;
  return `${Math.floor(diff / 86400)}d`;
}

export function BlackboardView({ processes }: BlackboardViewProps) {
  const workflows = useMemo(
    () => Array.from(new Set(processes.map((p) => p.workflow))).sort(),
    [processes],
  );

  const [activeWorkflow, setActiveWorkflow] = useState<string>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const filtered = useMemo(
    () =>
      activeWorkflow === "all"
        ? processes
        : processes.filter((p) => p.workflow === activeWorkflow),
    [processes, activeWorkflow],
  );

  const byStage = useMemo(() => {
    const map = new Map<ProcessStage, ProcessCard[]>();
    for (const col of COLUMNS) map.set(col.id, []);
    for (const p of filtered) {
      map.get(p.stage)?.push(p);
    }
    // Recent-first within each column
    for (const [k, v] of map) {
      map.set(k, v.slice().sort((a, b) => b.updated_at.localeCompare(a.updated_at)));
    }
    return map;
  }, [filtered]);

  const selected = filtered.find((p) => p.id === selectedId) ?? null;

  const autoPct = useMemo(() => {
    if (filtered.length === 0) return 0;
    const auto = filtered.filter((p) => p.auto).length;
    return Math.round((auto / filtered.length) * 100);
  }, [filtered]);

  return (
    <>
      <aside className="sidebar">
        <div className="sidebar-head">
          <span className="sidebar-title">Workflows</span>
          <span className="sidebar-count">{processes.length}</span>
        </div>
        <div className="sidebar-list">
          <button
            className={`sidebar-item ${activeWorkflow === "all" ? "active" : ""}`}
            onClick={() => setActiveWorkflow("all")}
          >
            <div className="sidebar-item-title">
              <span>All workflows</span>
            </div>
            <div className="sidebar-item-meta">
              <span>{processes.length} processes</span>
            </div>
          </button>
          {workflows.map((wf) => {
            const count = processes.filter((p) => p.workflow === wf).length;
            return (
              <button
                key={wf}
                className={`sidebar-item ${activeWorkflow === wf ? "active" : ""}`}
                onClick={() => setActiveWorkflow(wf)}
              >
                <div className="sidebar-item-title">
                  <span style={{ textTransform: "capitalize" }}>{wf}</span>
                </div>
                <div className="sidebar-item-meta">
                  <span>{count}</span>
                </div>
              </button>
            );
          })}
        </div>
      </aside>

      <section className="main">
        <div className="main-head">
          <p className="main-eyebrow">Blackboard</p>
          <h1 className="main-title">
            {activeWorkflow === "all"
              ? "Operations"
              : activeWorkflow[0].toUpperCase() + activeWorkflow.slice(1)}
          </h1>
          <p className="main-subtitle">
            What every agent is doing right now.{" "}
            <span style={{ color: "var(--accent)" }}>
              {autoPct}% of active processes are running on autopilot
              (Rule-authorized).
            </span>
          </p>
        </div>

        <div
          className="main-body"
          style={{ paddingRight: 24 }}
        >
          <div
            style={{
              display: "grid",
              gridTemplateColumns: `repeat(${COLUMNS.length}, minmax(220px, 1fr))`,
              gap: 12,
              overflowX: "auto",
            }}
          >
            {COLUMNS.map((col) => {
              const items = byStage.get(col.id) ?? [];
              return (
                <div key={col.id}>
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      marginBottom: 8,
                      padding: "0 4px",
                    }}
                  >
                    <span className={`pill ${col.pill}`}>{col.label}</span>
                    <span className="muted mono" style={{ fontSize: 11 }}>
                      {items.length}
                    </span>
                  </div>
                  <div className="stack" style={{ minHeight: 60 }}>
                    {items.map((p) => (
                      <article
                        key={p.id}
                        className="decision-card"
                        onClick={() => setSelectedId(p.id)}
                        style={{
                          padding: 14,
                          margin: 0,
                          cursor: "pointer",
                          borderColor:
                            selectedId === p.id
                              ? "var(--accent)"
                              : "var(--border)",
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            alignItems: "flex-start",
                            justifyContent: "space-between",
                            gap: 8,
                          }}
                        >
                          <h4
                            style={{
                              margin: 0,
                              fontSize: 13,
                              fontWeight: 600,
                              letterSpacing: "-0.005em",
                            }}
                          >
                            {p.title}
                          </h4>
                          {p.auto && (
                            <span
                              title="Rule-authorized auto-execute"
                              style={{
                                color: "var(--accent)",
                                display: "flex",
                                alignItems: "center",
                              }}
                            >
                              <IconZap size={12} />
                            </span>
                          )}
                        </div>
                        <p
                          style={{
                            margin: "4px 0 8px",
                            fontSize: 11,
                            color: "var(--fg-secondary)",
                          }}
                        >
                          {p.subtitle}
                        </p>
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "space-between",
                            fontSize: 11,
                            color: "var(--fg-tertiary)",
                          }}
                        >
                          <span>{p.current_agent}</span>
                          {p.amount && (
                            <span className="mono">{p.amount}</span>
                          )}
                        </div>
                        <div
                          style={{
                            marginTop: 6,
                            fontSize: 10,
                            color: "var(--fg-tertiary)",
                          }}
                        >
                          {relativeTime(p.updated_at)}
                        </div>
                      </article>
                    ))}
                    {items.length === 0 && (
                      <div
                        style={{
                          padding: 12,
                          fontSize: 11,
                          color: "var(--fg-tertiary)",
                          textAlign: "center",
                          border: "1px dashed var(--border)",
                          borderRadius: "var(--r-sm)",
                        }}
                      >
                        empty
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {filtered.length === 0 && (
            <div className="main-empty" style={{ minHeight: 200, marginTop: 24 }}>
              <div className="main-empty-icon">
                <IconLayout size={36} />
              </div>
              <p>No processes in this workflow.</p>
            </div>
          )}
        </div>
      </section>

      <aside className="detail">
        <div className="detail-head">
          <span className="detail-title">Process detail</span>
        </div>
        <div className="detail-body">
          {selected ? (
            <>
              <div className="detail-section">
                <div className="detail-section-label">State</div>
                <div className="detail-row">
                  <span className="key">Stage</span>
                  <span className="value">{selected.stage}</span>
                </div>
                <div className="detail-row">
                  <span className="key">Workflow</span>
                  <span className="value">{selected.workflow}</span>
                </div>
                <div className="detail-row">
                  <span className="key">Current agent</span>
                  <span className="value">{selected.current_agent}</span>
                </div>
                {selected.next_agent && (
                  <div className="detail-row">
                    <span className="key">Next agent</span>
                    <span className="value">{selected.next_agent}</span>
                  </div>
                )}
                {selected.cap_token_id && (
                  <div className="detail-row">
                    <span className="key">Cap_token</span>
                    <span className="value">{selected.cap_token_id}</span>
                  </div>
                )}
                {selected.amount && (
                  <div className="detail-row">
                    <span className="key">Amount</span>
                    <span className="value">{selected.amount}</span>
                  </div>
                )}
                <div className="detail-row">
                  <span className="key">Last update</span>
                  <span className="value">
                    {new Date(selected.updated_at).toLocaleString()}
                  </span>
                </div>
                <div className="detail-row">
                  <span className="key">Mode</span>
                  <span className="value">
                    {selected.auto ? "autopilot ⚡" : "manual"}
                  </span>
                </div>
              </div>
              <SignaturePanel
                value={selected}
                title="Process snapshot"
              />
            </>
          ) : (
            <p className="muted">Select a card to inspect.</p>
          )}
        </div>
      </aside>
    </>
  );
}
