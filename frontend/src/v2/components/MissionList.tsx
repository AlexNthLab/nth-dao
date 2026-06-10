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
 *
 * New-mission entry (audit fix 2026-06-10, "需要有添加/发起任务功能"):
 * Even though NTH DAO is AI-agent-driven (the user is the approval
 * gate, not the originator), there has to be SOME way for the user
 * to kick off a goal — "draft the launch announcement", "audit Q2
 * vendor invoices". This view's main-head now carries a primary
 * "+ New mission" button; the inline form collects title + goal +
 * driver + optional cap_token and emits onCreate. Mission goes to
 * status "planning" — the driver agent advances it from there.
 */

import { useEffect, useState } from "react";
import { IconPlus, IconTarget } from "./Icons";
import { SignaturePanel } from "./SignaturePanel";
import { progressColor, progressPct } from "../utils/mission";
import type { AgentEntry, MissionSummary } from "../types-v2";

export interface MissionListProps {
  missions: MissionSummary[];
  /** Optional: when wired, the head carries a "New mission" button
   *  that opens the inline form. v1 captures locally; backend wires
   *  to POST /api/missions on integration. */
  onCreate?: (draft: NewMissionDraft) => void;
  /** Agents the user can pick as driver — populates the form's
   *  dropdown. Pass mockAgents in v1; /api/agents/list in v1.x. */
  driverOptions?: AgentEntry[];
  /** When set, MissionList force-selects this mission id on next
   *  effect tick, then calls `onFocusConsumed`. Used by App.tsx
   *  to auto-focus a freshly-created mission so the user sees the
   *  detail rail populate immediately. Null disables. */
  focusId?: string | null;
  onFocusConsumed?: () => void;
}

/** Minimal shape the create form emits. The receiver hydrates into
 *  a full MissionSummary (id, started_at, steps_*=0, status=
 *  "planning") before pushing onto state. */
export interface NewMissionDraft {
  title: string;
  goal: string;
  driver_did: string;
  driver_label: string;
  cap_token_id?: string;
}

// (pct() / status-color logic moved to ../utils/mission, audit L4)

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

export function MissionList({
  missions, onCreate, driverOptions, focusId, onFocusConsumed,
}: MissionListProps) {
  const [selectedId, setSelectedId] = useState<string | null>(
    missions[0]?.id ?? null,
  );
  const [createOpen, setCreateOpen] = useState(false);
  const selected = missions.find((m) => m.id === selectedId) ?? null;

  // Auto-follow App's focus signal (set when the user creates a
  // new mission). Effect-based instead of inline so React batches
  // the state update with the parent re-render — no double paint.
  useEffect(() => {
    if (focusId) {
      setSelectedId(focusId);
      onFocusConsumed?.();
    }
  }, [focusId, onFocusConsumed]);

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
        <div
          className="main-head"
          style={{
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: 16,
          }}
        >
          <div style={{ flex: 1, minWidth: 0 }}>
            <p className="main-eyebrow">Missions</p>
            <h1 className="main-title">What the agents are doing</h1>
            <p className="main-subtitle">
              Each mission represents a structured goal an AI agent is
              executing on your behalf, bounded by a cap_token.
            </p>
          </div>
          {onCreate && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => setCreateOpen(true)}
              title="Start a new mission — picks a driver agent"
              style={{ marginTop: 4, flexShrink: 0 }}
            >
              <IconPlus size={14} /> New mission
            </button>
          )}
        </div>

        <div className="main-body">
          {createOpen && onCreate && (
            <NewMissionForm
              drivers={driverOptions ?? []}
              onCancel={() => setCreateOpen(false)}
              onSubmit={(draft) => {
                onCreate(draft);
                setCreateOpen(false);
              }}
            />
          )}

          {missions.length === 0 ? (
            <div className="main-empty" style={{ minHeight: 200 }}>
              <div className="main-empty-icon">
                <IconTarget size={36} />
              </div>
              <p>No active missions.</p>
              {onCreate && (
                <p className="muted" style={{ fontSize: 12, marginTop: 8 }}>
                  Press <kbd>+ New mission</kbd> above to start one.
                </p>
              )}
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
                          width: `${progressPct(m)}%`,
                          height: "100%",
                          background: progressColor(m),
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

/* ── NewMissionForm ──────────────────────────────────────────────
 * Inline drawer in the main-body. Required: title + goal +
 * driver (selected from the agent directory). Optional cap_token
 * — when omitted, the mission is "manual mode" and each step
 * generates a Decision; when set, the driver acts under the
 * cap_token's authority until it expires or is revoked.
 */
interface NewMissionFormProps {
  drivers: AgentEntry[];
  onCancel: () => void;
  onSubmit: (draft: NewMissionDraft) => void;
}

function NewMissionForm({ drivers, onCancel, onSubmit }: NewMissionFormProps) {
  const [title, setTitle] = useState("");
  const [goal, setGoal] = useState("");
  const [driverDid, setDriverDid] = useState(drivers[0]?.did ?? "");
  const [capToken, setCapToken] = useState("");

  /* Reset driverDid when the active value disappears from drivers
   * (audit pass#3 finding I2, 2026-06-10). useState captures
   * drivers[0]?.did only at mount; if the parent later replaces
   * the agent list (LAN scan finds new peers, an existing agent
   * gets revoked, the directory refreshes from /api/agents/list)
   * the selected DID can drop out of the options array while the
   * <select> still shows it. The select displays the first option
   * visually but driverDid holds the stale string, producing a
   * "phantom selection" — the dropdown looks fine but the
   * submission would carry a DID no longer in the directory. */
  useEffect(() => {
    if (drivers.length > 0 && !drivers.some((d) => d.did === driverDid)) {
      setDriverDid(drivers[0].did);
    }
  }, [drivers, driverDid]);

  const driver = drivers.find((d) => d.did === driverDid);

  const canSubmit =
    title.trim().length > 0 &&
    goal.trim().length > 0 &&
    (driver !== undefined || driverDid.trim().length > 0);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    onSubmit({
      title: title.trim(),
      goal: goal.trim(),
      driver_did: driverDid,
      driver_label: driver?.label ?? driverDid.slice(0, 16),
      cap_token_id: capToken.trim() || undefined,
    });
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="decision-card"
      style={{
        padding: 16,
        marginBottom: 16,
        borderColor: "var(--accent-muted)",
      }}
    >
      <h3
        style={{
          margin: "0 0 4px",
          fontSize: 14,
          fontWeight: 600,
          color: "var(--accent)",
        }}
      >
        Start a new mission
      </h3>
      <p
        className="muted"
        style={{ margin: "0 0 12px", fontSize: 11 }}
      >
        The driver agent will plan steps and request your approval —
        unless you scope a cap_token, in which case it executes
        autonomously within those bounds.
      </p>

      <div className="stack" style={{ gap: 10 }}>
        <div>
          <label
            style={{
              display: "block",
              fontSize: 11,
              color: "var(--fg-tertiary)",
              marginBottom: 4,
              textTransform: "uppercase",
              letterSpacing: "0.04em",
            }}
          >
            Title
          </label>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="e.g. Draft Q3 launch announcement"
            required
            autoFocus
            style={{ width: "100%" }}
          />
        </div>

        <div>
          <label
            style={{
              display: "block",
              fontSize: 11,
              color: "var(--fg-tertiary)",
              marginBottom: 4,
              textTransform: "uppercase",
              letterSpacing: "0.04em",
            }}
          >
            Goal
          </label>
          <textarea
            value={goal}
            onChange={(e) => setGoal(e.target.value)}
            placeholder="Describe the outcome you want, not the steps."
            required
            rows={3}
            style={{ width: "100%", resize: "vertical" }}
          />
        </div>

        <div>
          <label
            style={{
              display: "block",
              fontSize: 11,
              color: "var(--fg-tertiary)",
              marginBottom: 4,
              textTransform: "uppercase",
              letterSpacing: "0.04em",
            }}
          >
            Driver agent
          </label>
          {drivers.length > 0 ? (
            <select
              value={driverDid}
              onChange={(e) => setDriverDid(e.target.value)}
              style={{ width: "100%" }}
            >
              {drivers.map((d) => (
                <option key={d.did} value={d.did}>
                  {d.label}{" "}
                  {d.capabilities.length > 0
                    ? `· ${d.capabilities.slice(0, 2).join(", ")}`
                    : ""}
                </option>
              ))}
            </select>
          ) : (
            <input
              type="text"
              value={driverDid}
              onChange={(e) => setDriverDid(e.target.value)}
              placeholder="did:key:…"
              required
              style={{ width: "100%" }}
            />
          )}
        </div>

        <div>
          <label
            style={{
              display: "block",
              fontSize: 11,
              color: "var(--fg-tertiary)",
              marginBottom: 4,
              textTransform: "uppercase",
              letterSpacing: "0.04em",
            }}
          >
            Cap_token (optional, enables autopilot for this mission)
          </label>
          <input
            type="text"
            value={capToken}
            onChange={(e) => setCapToken(e.target.value)}
            placeholder="cap-marketingLong"
            style={{ width: "100%" }}
          />
        </div>
      </div>

      <div
        style={{
          display: "flex",
          gap: 8,
          marginTop: 16,
          justifyContent: "flex-end",
        }}
      >
        <button
          type="button"
          className="btn"
          onClick={onCancel}
        >
          Cancel
        </button>
        <button
          type="submit"
          className="btn btn-primary"
          disabled={!canSubmit}
        >
          Start mission
        </button>
      </div>
    </form>
  );
}
