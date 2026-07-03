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
 * New-mission entry (audit fix 2026-06-10):
 * Even though NTH DAO is AI-agent-driven (the user is the approval
 * gate, not the originator), there has to be SOME way for the user
 * to kick off a goal: "draft the launch announcement", "audit Q2
 * vendor invoices". This view's main-head now carries a primary
 * "+ New mission" button; the inline form collects title + goal +
 * driver + optional cap_token and emits onCreate. Mission goes to
 * status "planning"; the driver agent advances it from there.
 */

import { useEffect, useState } from "react";
import { IconPlus, IconTarget } from "./Icons";
import { SignaturePanel } from "./SignaturePanel";
import { fetchMissionHandoffs } from "../api";
import { progressColor, progressPct } from "../utils/mission";
import { useLang } from "../i18n";
import type {
  AgentEntry,
  HandoffDetail,
  MissionSummary,
  MissionTimelineEvent,
} from "../types-v2";

export interface MissionListProps {
  missions: MissionSummary[];
  /** Optional: when wired, the head carries a "New mission" button
   *  that opens the inline form. v1 captures locally; backend wires
   *  to POST /api/missions on integration. */
  onCreate?: (draft: NewMissionDraft) => void;
  /** Optional hook to activate a planning mission. */
  onActivate?: (id: string) => void;
  /** Agents the user can pick as driver; populates the form's
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
  /** Optional initial steps. Empty missions remain in planning. */
  steps?: string[];
}

// (pct() / status-color logic moved to ../utils/mission, audit L4)

const MAX_DETAIL_TIMELINE_EVENTS = 20;
const MAX_DETAIL_STEPS = 64;

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

function stepPill(status: string): "ok" | "wait" | "bad" | "dim" {
  switch (status) {
    case "done":
    case "handed_off":
      return "ok";
    case "active":
    case "claimed":
    case "needs_review":
      return "wait";
    case "failed":
    case "blocked":
      return "bad";
    default:
      return "dim";
  }
}

function handoffPill(status?: string | null): "ok" | "wait" | "bad" | "dim" {
  switch (status) {
    case "refuted":
    case "superseded":
      return "ok";
    case "contested":
      return "bad";
    case "supersession_proposed":
    case "proposed":
      return "wait";
    default:
      return "dim";
  }
}

function stepDisplayRank(status: string): number {
  switch (status) {
    case "active":
    case "claimed":
    case "needs_review":
    case "blocked":
    case "failed":
      return 0;
    case "todo":
      return 1;
    case "done":
    case "handed_off":
      return 2;
    default:
      return 1;
  }
}

function formatTime(value?: string | null): string {
  if (!value) return "-";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

function shortValue(value?: string | null, size = 19): string {
  if (!value) return "";
  return value.length > size ? value.slice(0, size) : value;
}

function HandoffDetailRows({ detail }: { detail?: HandoffDetail }) {
  if (!detail) return null;
  const evidence = detail.evidence_verification ?? [];
  const responseReceipts = [
    ...(detail.refutations ?? []),
    ...(detail.supersessions ?? []),
  ]
    .map((item) => {
      const receiptId = item.receipt_id;
      const hash = item.receipt_content_hash;
      if (typeof receiptId !== "string" || receiptId.length === 0) return "";
      return typeof hash === "string" && hash.length > 0
        ? `${receiptId} (${shortValue(hash, 12)})`
        : receiptId;
    })
    .filter(Boolean);
  return (
    <div
      className="muted"
      style={{
        marginTop: 8,
        paddingTop: 8,
        borderTop: "1px solid var(--border)",
        display: "grid",
        gap: 6,
        fontSize: 11,
      }}
    >
      <span>
        Author: <code>{shortValue(detail.author_did, 28)}</code>
      </span>
      {detail.root_cause_hypothesis && (
        <span>Hypothesis: {detail.root_cause_hypothesis}</span>
      )}
      {evidence.length > 0 && (
        <div style={{ display: "grid", gap: 4 }}>
          <span style={{ color: "var(--fg-secondary)", fontWeight: 600 }}>
            Evidence verification
          </span>
          {evidence.slice(0, 4).map((item, index) => (
            <span key={`${detail.capsule_hash}-evidence-${index}`}>
              <span className={`pill ${item.status === "verified" ? "ok" : "wait"}`}>
                {item.status || "unknown"}
              </span>{" "}
              {item.path || item.kind || "evidence"}
              {item.commit ? ` @ ${shortValue(item.commit, 10)}` : ""}
              {item.reason ? ` - ${item.reason}` : ""}
            </span>
          ))}
          {evidence.length > 4 && (
            <span>{evidence.length - 4} more evidence check(s)</span>
          )}
        </div>
      )}
      {(detail.next_actions ?? []).length > 0 && (
        <span>Next actions: {(detail.next_actions ?? []).slice(0, 3).join("; ")}</span>
      )}
      {(detail.risks ?? []).length > 0 && (
        <span>Risks: {(detail.risks ?? []).slice(0, 3).join("; ")}</span>
      )}
      {(detail.refutations ?? []).length > 0 && (
        <span>Signed responses: {(detail.refutations ?? []).length}</span>
      )}
      {responseReceipts.length > 0 && (
        <span>Response receipt(s): {responseReceipts.slice(0, 3).join(", ")}</span>
      )}
    </div>
  );
}

function timelineDotColor(
  event: MissionTimelineEvent,
  selected: MissionSummary,
): string {
  if (event.kind === "handoff") return "var(--accent-hover)";
  if (event.kind === "warning") return "var(--warn, #d97706)";
  if (event.kind === "audit" || event.kind === "receipt") return "var(--accent)";
  return progressColor({ ...selected, status: selected.status });
}

export function MissionList({
  missions, onCreate, onActivate, driverOptions, focusId, onFocusConsumed,
}: MissionListProps) {
  const { t } = useLang();
  const [selectedId, setSelectedId] = useState<string | null>(
    missions[0]?.id ?? null,
  );
  const [createOpen, setCreateOpen] = useState(false);
  const selected = missions.find((m) => m.id === selectedId) ?? null;
  const timelineEvents = selected?.timeline ?? [];
  const handoffEvents = timelineEvents.filter((event) => event.kind === "handoff");
  const visibleTimelineEvents = timelineEvents.slice(-MAX_DETAIL_TIMELINE_EVENTS);
  const hiddenTimelineEvents = Math.max(
    0, timelineEvents.length - visibleTimelineEvents.length,
  );
  const allSteps = selected?.steps ?? [];
  const stepRows = allSteps
    .map((step, index) => ({ step, index }))
    .sort(
      (a, b) => stepDisplayRank(a.step.status) - stepDisplayRank(b.step.status)
        || a.index - b.index,
    )
    .slice(0, MAX_DETAIL_STEPS);
  const hiddenStepRows = Math.max(0, allSteps.length - stepRows.length);
  const handoffHashKey = handoffEvents
    .map((event) => event.capsule_hash || event.id)
    .join("|");
  const [handoffDetails, setHandoffDetails] = useState<Record<string, HandoffDetail>>({});
  const [handoffDetailsStatus, setHandoffDetailsStatus] = useState<
    "idle" | "loading" | "ready" | "error"
  >("idle");
  const [handoffDetailsError, setHandoffDetailsError] = useState("");

  useEffect(() => {
    if (!selected?.id || handoffEvents.length === 0) {
      setHandoffDetails({});
      setHandoffDetailsStatus("idle");
      setHandoffDetailsError("");
      return undefined;
    }
    const ctl = new AbortController();
    setHandoffDetailsStatus("loading");
    setHandoffDetailsError("");
    fetchMissionHandoffs(selected.id, true, ctl.signal)
      .then((rows) => {
        const next: Record<string, HandoffDetail> = {};
        for (const row of rows) {
          if (row.capsule_hash) next[row.capsule_hash] = row;
        }
        setHandoffDetails(next);
        setHandoffDetailsStatus("ready");
      })
      .catch((err: unknown) => {
        if ((err as { name?: string })?.name === "AbortError") return;
        setHandoffDetails({});
        setHandoffDetailsStatus("error");
        setHandoffDetailsError(err instanceof Error ? err.message : String(err));
      });
    return () => ctl.abort();
  }, [selected?.id, handoffEvents.length, handoffHashKey]);

  // Auto-follow App's focus signal (set when the user creates a
  // new mission). Effect-based instead of inline so React batches
  // the state update with the parent re-render; no double paint.
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
          <span className="sidebar-title">{t("Active missions", "Active missions")}</span>
          <span className="sidebar-count">{missions.length}</span>
        </div>
        <div className="sidebar-list">
          {missions.length === 0 && (
            <p className="muted" style={{ padding: "12px 14px" }}>
              {t("No missions in flight.", "No missions in flight.")}
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
                <span className="muted">-</span>
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
            <h1 className="main-title">{t("What the agents are doing", "What the agents are doing")}</h1>
            <p className="main-subtitle">
              {t(
                "Each mission represents a structured goal an AI agent is executing on your behalf, bounded by a cap_token.",
                "Each mission represents a structured goal an AI agent is executing on your behalf, bounded by a cap_token.",
              )}
            </p>
          </div>
          {onCreate && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => setCreateOpen(true)}
              title={t("Start a new mission - picks a driver agent", "Start a new mission - picks a driver agent")}
              style={{ marginTop: 4, flexShrink: 0 }}
            >
              <IconPlus size={14} /> {t("New mission", "New mission")}
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
              <p>{t("No active missions.", "No active missions.")}</p>
              {onCreate && (
                <p className="muted" style={{ fontSize: 12, marginTop: 8 }}>
                  {t("Press", "Press")} <kbd>{t("+ New mission", "+ New mission")}</kbd> {t("above to start one.", "above to start one.")}
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
                        <span>{t("by", "by")} {m.driver_label}</span>
                        <span className="muted">-</span>
                        <code>{m.driver_did.slice(0, 20)}</code>
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
                        {t(
                          `${m.steps_done} done - ${m.steps_in_progress} in progress - ${m.steps_total} total`,
                          `${m.steps_done} done - ${m.steps_in_progress} in progress - ${m.steps_total} total`,
                        )}
                      </span>
                      {m.cap_token_id && (
                        <span>
                          cap_token <code>{m.cap_token_id}</code>
                        </span>
                      )}
                    </div>
                  </div>

                  {(m.current_action || m.next_actionable) && (
                    <div className="decision-card-rationale">
                      <span className="muted" style={{ fontSize: 11 }}>
                         {m.current_action ? t("Current:", "Current:") : t("Next:", "Next:")}
                      </span>{" "}
                      {m.current_action || m.next_actionable}
                    </div>
                  )}

                  {onActivate && m.status === "planning" && (
                    <div style={{ marginTop: 12 }}>
                      <button
                        type="button"
                        className="btn btn-primary"
                        disabled={m.steps_total === 0}
                        title={
                          m.steps_total === 0
                            ? t("Add steps before starting (an empty mission has nothing to do)", "Add steps before starting (an empty mission has nothing to do)")
                            : t("Start executing this mission (planning -> active)", "Start executing this mission (planning -> active)")
                        }
                        onClick={(e) => {
                          e.stopPropagation();
                          onActivate(m.id);
                        }}
                      >
                         {t("Start", "Start")}
                      </button>
                      {m.steps_total === 0 && (
                        <span
                          className="muted"
                          style={{ fontSize: 11, marginLeft: 8 }}
                        >
                          {t("No steps - can't start", "No steps - can't start")}
                        </span>
                      )}
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
          <span className="detail-title">{t("Mission detail", "Mission detail")}</span>
        </div>
        <div className="detail-body">
          {selected ? (
            <>
              <div className="detail-section">
                <div className="detail-section-label">{t("Identity", "Identity")}</div>
                <div className="detail-row">
                  <span className="key">{t("Driver", "Driver")}</span>
                  <span className="value">{selected.driver_label}</span>
                </div>
                <div className="detail-row">
                  <span className="key">Cap_token</span>
                  <span className="value">{selected.cap_token_id || "-"}</span>
                </div>
                <div className="detail-row">
                  <span className="key">{t("Started", "Started")}</span>
                  <span className="value">{formatTime(selected.started_at)}</span>
                </div>
              </div>

              <div className="detail-section">
                <div className="detail-section-label">{t("Execution state", "Execution state")}</div>
                {timelineEvents.length === 0 ? (
                  <p className="muted" style={{ fontSize: 12, margin: 0 }}>
                    {t("No execution state yet.", "No execution state yet.")}
                  </p>
                ) : (
                  <ol
                    style={{
                      listStyle: "none",
                      margin: 0,
                      padding: 0,
                      display: "grid",
                      gap: 10,
                    }}
                  >
                    {visibleTimelineEvents.map((event) => (
                      <li
                        key={event.id}
                        style={{
                          display: "grid",
                          gridTemplateColumns: "10px minmax(0, 1fr)",
                          gap: 10,
                          alignItems: "start",
                        }}
                      >
                        <span
                          aria-hidden="true"
                          style={{
                            width: 8,
                            height: 8,
                            marginTop: 5,
                            borderRadius: "50%",
                            background: timelineDotColor(event, selected),
                          }}
                        />
                        <span style={{ minWidth: 0 }}>
                          <span
                            style={{
                              display: "block",
                              fontSize: 12,
                              fontWeight: 600,
                              color: "var(--fg-primary)",
                              overflowWrap: "anywhere",
                            }}
                          >
                            {event.label}
                          </span>
                          <span
                            className="muted"
                            style={{
                              display: "block",
                              fontSize: 11,
                              overflowWrap: "anywhere",
                            }}
                          >
                            {formatTime(event.at)}
                            {event.detail ? ` - ${event.detail}` : ""}
                          </span>
                          {event.agent_did && (
                            <code style={{ fontSize: 10, overflowWrap: "anywhere" }}>
                              {event.agent_did}
                            </code>
                          )}
                          {event.receipt_id && (
                            <code style={{ fontSize: 10, overflowWrap: "anywhere", display: "block" }}>
                              receipt {event.receipt_id.slice(0, 16)}
                            </code>
                          )}
                          {event.capsule_hash && (
                            <code style={{ fontSize: 10, overflowWrap: "anywhere", display: "block" }}>
                              capsule {event.capsule_hash.slice(0, 19)}
                            </code>
                          )}
                          {(event.refutation_count ?? 0) > 0 && (
                            <span className="muted" style={{ display: "block", fontSize: 10 }}>
                              {event.refutation_count} refutation(s)
                            </span>
                          )}
                          {event.superseded_by && (
                            <code style={{ fontSize: 10, overflowWrap: "anywhere", display: "block" }}>
                              superseded by {event.superseded_by.slice(0, 19)}
                            </code>
                          )}
                        </span>
                      </li>
                    ))}
                  </ol>
                )}
                {hiddenTimelineEvents > 0 && (
                  <p className="muted" style={{ fontSize: 11, margin: "8px 0 0" }}>
                    {t(
                      `${hiddenTimelineEvents} earlier state item(s) hidden`,
                      `${hiddenTimelineEvents} earlier state item(s) hidden`,
                    )}
                  </p>
                )}
              </div>

              <div className="detail-section">
                <div className="detail-section-label">Handoff workbench</div>
                {handoffEvents.length === 0 ? (
                  <p className="muted" style={{ fontSize: 12, margin: 0 }}>
                    No agent handoff capsules yet.
                  </p>
                ) : (
                  <div className="stack" style={{ gap: 8 }}>
                    <p className="muted" style={{ fontSize: 11, margin: 0 }}>
                      Signed handoff is a claim, not a verified fact. Re-check
                      pinned evidence before acting.
                    </p>
                    {handoffDetailsStatus === "loading" && (
                      <p className="muted" style={{ fontSize: 11, margin: 0 }}>
                        Loading signed handoff details...
                      </p>
                    )}
                    {handoffDetailsStatus === "error" && (
                      <p style={{ fontSize: 11, margin: 0, color: "var(--warn, #d97706)" }}>
                        Handoff details unavailable: {handoffDetailsError}
                      </p>
                    )}
                    {handoffEvents.map((event) => {
                      const detail = event.capsule_hash
                        ? handoffDetails[event.capsule_hash]
                        : undefined;
                      return (
                      <div
                        key={`workbench-${event.id}`}
                        style={{
                          border: "1px solid var(--border)",
                          borderRadius: 8,
                          padding: 10,
                          background: "var(--bg-elevated)",
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            gap: 8,
                            alignItems: "flex-start",
                            justifyContent: "space-between",
                          }}
                        >
                          <strong
                            style={{
                              minWidth: 0,
                              fontSize: 12,
                              fontWeight: 600,
                              overflowWrap: "anywhere",
                            }}
                          >
                            {event.label}
                          </strong>
                          <span className={`pill ${handoffPill(event.status)}`}>
                            {event.status || "unknown"}
                          </span>
                        </div>
                        <div
                          className="muted"
                          style={{
                            marginTop: 6,
                            display: "grid",
                            gap: 4,
                            fontSize: 11,
                          }}
                        >
                          {event.capsule_hash && (
                            <span>
                              Capsule <code>{event.capsule_hash.slice(0, 19)}</code>
                            </span>
                          )}
                          <span>
                            Evidence: {event.evidence_count ?? 0} pointer(s)
                            {event.verification_status
                              ? ` - ${event.verification_status}`
                              : ""}
                          </span>
                          {(event.refutation_count ?? 0) > 0 && (
                            <span>
                              Refutations: {event.refutation_count}
                              {typeof event.authorized_refutation_count === "number"
                                ? ` - authorized ${event.authorized_refutation_count}`
                                : ""}
                            </span>
                          )}
                          {event.authorization_reasons && event.authorization_reasons.length > 0 && (
                            <span>
                              Authority: {event.authorization_reasons.join(", ")}
                            </span>
                          )}
                          {event.superseded_by && (
                            <span>
                              Superseded by <code>{event.superseded_by.slice(0, 19)}</code>
                            </span>
                          )}
                          {event.next_action && (
                            <span>Next: {event.next_action}</span>
                          )}
                        </div>
                        <HandoffDetailRows detail={detail} />
                      </div>
                      );
                    })}
                  </div>
                )}
              </div>

              <div className="detail-section">
                <div className="detail-section-label">Steps</div>
                {(selected.steps ?? []).length === 0 ? (
                  <p className="muted" style={{ fontSize: 12, margin: 0 }}>
                    {t("No steps yet.", "No steps yet.")}
                  </p>
                ) : (
                  <div className="stack" style={{ gap: 8 }}>
                    {stepRows.map(({ step, index }) => (
                      <div
                        key={step.id}
                        style={{
                          border: "1px solid var(--border)",
                          borderRadius: 8,
                          padding: 10,
                          background: "var(--bg-elevated)",
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            gap: 8,
                            alignItems: "flex-start",
                            justifyContent: "space-between",
                          }}
                        >
                          <strong
                            style={{
                              minWidth: 0,
                              fontSize: 12,
                              fontWeight: 600,
                              overflowWrap: "anywhere",
                            }}
                          >
                            {index + 1}. {step.description}
                          </strong>
                          <span className={`pill ${stepPill(step.status)}`}>
                            {step.status}
                          </span>
                        </div>
                        <div
                          className="muted"
                          style={{
                            marginTop: 6,
                            display: "grid",
                            gap: 4,
                            fontSize: 11,
                          }}
                        >
                          <span>{t("Updated", "Updated")}: {formatTime(step.updated_at)}</span>
                          {step.assignee && <span>{t("Agent", "Agent")}: <code>{step.assignee}</code></span>}
                          {step.required_capabilities.length > 0 && (
                            <span>
                              {t("Capabilities", "Capabilities")}: {step.required_capabilities.join(", ")}
                            </span>
                          )}
                          {(step.notes_count ?? 0) > 0 && (
                            <span>{t("Notes", "Notes")}: {step.notes_count}</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
                {hiddenStepRows > 0 && (
                  <p className="muted" style={{ fontSize: 11, margin: "8px 0 0" }}>
                    {t(
                      `${hiddenStepRows} more step(s) hidden`,
                      `${hiddenStepRows} more step(s) hidden`,
                    )}
                  </p>
                )}
              </div>

              <SignaturePanel
                value={selected}
                title={t("Mission shape", "Mission shape")}
              />
            </>
          ) : (
            <p className="muted">{t("Select a mission to inspect.", "Select a mission to inspect.")}</p>
          )}
        </div>
      </aside>
    </>
  );
}

/*
 * NewMissionForm inline drawer. Required: title + goal + driver
 * (selected from the agent directory). Optional cap_token. When
 * omitted, the mission is "manual mode" and each step generates a
 * Decision; when set, the driver acts under the cap_token's authority
 * until it expires or is revoked.
 */
interface NewMissionFormProps {
  drivers: AgentEntry[];
  onCancel: () => void;
  onSubmit: (draft: NewMissionDraft) => void;
}

function NewMissionForm({ drivers, onCancel, onSubmit }: NewMissionFormProps) {
  const { t } = useLang();
  const [title, setTitle] = useState("");
  const [goal, setGoal] = useState("");
  const [stepsText, setStepsText] = useState("");
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
   * "phantom selection"; the dropdown looks fine but the
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
      steps: stepsText
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean),
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
        {t("Start a new mission", "Start a new mission")}
      </h3>
      <p
        className="muted"
        style={{ margin: "0 0 12px", fontSize: 11 }}
      >
        {t(
          "The driver agent will plan steps and request your approval unless you scope a cap_token, in which case it executes autonomously within those bounds.",
          "The driver agent will plan steps and request your approval unless you scope a cap_token, in which case it executes autonomously within those bounds.",
        )}
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
            {t("Title", "Title")}
          </label>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder={t("e.g. Draft Q3 launch announcement", "e.g. Draft Q3 launch announcement")}
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
            {t("Goal", "Goal")}
          </label>
          <textarea
            value={goal}
            onChange={(e) => setGoal(e.target.value)}
            placeholder={t("Describe the outcome you want, not the steps.", "Describe the outcome you want, not the steps.")}
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
            {t("Steps (one per line, optional)", "Steps (one per line, optional)")}
          </label>
          <textarea
            value={stepsText}
            onChange={(e) => setStepsText(e.target.value)}
            placeholder={t(
              "One step per line, e.g.:\nreproduce the crash\nwrite a fix\nverify on staging",
              "One step per line, e.g.:\nreproduce the crash\nwrite a fix\nverify on staging",
            )}
            rows={3}
            style={{ width: "100%", resize: "vertical" }}
          />
          <p className="muted" style={{ margin: "4px 0 0", fontSize: 11 }}>
            {t(
              "A mission with no steps stays in planning (empty plan); add steps to advance it or post to the market.",
              "A mission with no steps stays in planning (empty plan); add steps to advance it or post to the market.",
            )}
          </p>
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
            {t("Driver agent", "Driver agent")}
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
                    ? ` - ${d.capabilities.slice(0, 2).join(", ")}`
                    : ""}
                </option>
              ))}
            </select>
          ) : (
            <input
              type="text"
              value={driverDid}
              onChange={(e) => setDriverDid(e.target.value)}
              placeholder="did:key:..."
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
            {t("Cap_token (optional, enables autopilot for this mission)", "Cap_token (optional, enables autopilot for this mission)")}
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
          {t("Cancel", "Cancel")}
        </button>
        <button
          type="submit"
          className="btn btn-primary"
          disabled={!canSubmit}
        >
          {t("Start mission", "Start mission")}
        </button>
      </div>
    </form>
  );
}
