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
import { useLang } from "../i18n";
import type { AgentEntry, MissionSummary, MissionTimelineEvent } from "../types-v2";

export interface MissionListProps {
  missions: MissionSummary[];
  /** Optional: when wired, the head carries a "New mission" button
   *  that opens the inline form. v1 captures locally; backend wires
   *  to POST /api/missions on integration. */
  onCreate?: (draft: NewMissionDraft) => void;
  /** 启动一个 planning 的 mission(→active)。补齐"创建后卡 planning"。 */
  onActivate?: (id: string) => void;
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
  /** 步骤描述列表(每行一个);有步骤的 mission 才能进入执行/发上市场,
   *  否则生来就是空的 planning。 */
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
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
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
          <span className="sidebar-title">{t("进行中的 mission", "Active missions")}</span>
          <span className="sidebar-count">{missions.length}</span>
        </div>
        <div className="sidebar-list">
          {missions.length === 0 && (
            <p className="muted" style={{ padding: "12px 14px" }}>
              {t("没有进行中的 mission。", "No missions in flight.")}
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
            <h1 className="main-title">{t("agent 正在做什么", "What the agents are doing")}</h1>
            <p className="main-subtitle">
              {t(
                "每个 mission 是一个 AI agent 代你执行的结构化目标,受 cap_token 约束。",
                "Each mission represents a structured goal an AI agent is executing on your behalf, bounded by a cap_token.",
              )}
            </p>
          </div>
          {onCreate && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => setCreateOpen(true)}
              title={t("发起一个新 mission —— 选一个驱动 agent", "Start a new mission — picks a driver agent")}
              style={{ marginTop: 4, flexShrink: 0 }}
            >
              <IconPlus size={14} /> {t("新 mission", "New mission")}
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
              <p>{t("没有进行中的 mission。", "No active missions.")}</p>
              {onCreate && (
                <p className="muted" style={{ fontSize: 12, marginTop: 8 }}>
                  {t("点上方", "Press")} <kbd>{t("+ 新 mission", "+ New mission")}</kbd> {t("开始一个。", "above to start one.")}
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
                        <span>{t("驱动", "by")} {m.driver_label}</span>
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
                        {t(
                          `${m.steps_done} 完成 · ${m.steps_in_progress} 进行中 · 共 ${m.steps_total}`,
                          `${m.steps_done} done · ${m.steps_in_progress} in progress · ${m.steps_total} total`,
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
                        {m.current_action ? t("当前:", "Current:") : t("下一步:", "Next:")}
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
                            ? t("先加步骤再启动(空 mission 没活可干)", "Add steps before starting (an empty mission has nothing to do)")
                            : t("开始执行这个 mission(planning → active)", "Start executing this mission (planning → active)")
                        }
                        onClick={(e) => {
                          e.stopPropagation();
                          onActivate(m.id);
                        }}
                      >
                        {t("启动", "Start")}
                      </button>
                      {m.steps_total === 0 && (
                        <span
                          className="muted"
                          style={{ fontSize: 11, marginLeft: 8 }}
                        >
                          {t("没有步骤,无法启动", "No steps — can't start")}
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
          <span className="detail-title">{t("Mission 详情", "Mission detail")}</span>
        </div>
        <div className="detail-body">
          {selected ? (
            <>
              <div className="detail-section">
                <div className="detail-section-label">{t("身份", "Identity")}</div>
                <div className="detail-row">
                  <span className="key">{t("驱动", "Driver")}</span>
                  <span className="value">{selected.driver_label}</span>
                </div>
                <div className="detail-row">
                  <span className="key">Cap_token</span>
                  <span className="value">{selected.cap_token_id || "—"}</span>
                </div>
                <div className="detail-row">
                  <span className="key">{t("开始于", "Started")}</span>
                  <span className="value">{formatTime(selected.started_at)}</span>
                </div>
              </div>

              <div className="detail-section">
                <div className="detail-section-label">{t("执行状态", "Execution state")}</div>
                {timelineEvents.length === 0 ? (
                  <p className="muted" style={{ fontSize: 12, margin: 0 }}>
                    {t("还没有执行状态。", "No execution state yet.")}
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
                            {event.detail ? ` · ${event.detail}` : ""}
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
                      `还有 ${hiddenTimelineEvents} 条较早状态未展开`,
                      `${hiddenTimelineEvents} earlier state item(s) hidden`,
                    )}
                  </p>
                )}
              </div>

              <div className="detail-section">
                <div className="detail-section-label">Handoff workbench</div>
                {handoffEvents.length === 0 ? (
                  <p className="muted" style={{ fontSize: 12, margin: 0 }}>
                    {t(
                      "还没有 agent 交接 capsule。",
                      "No agent handoff capsules yet.",
                    )}
                  </p>
                ) : (
                  <div className="stack" style={{ gap: 8 }}>
                    {handoffEvents.map((event) => (
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
                              ? ` · ${event.verification_status}`
                              : ""}
                          </span>
                          {(event.refutation_count ?? 0) > 0 && (
                            <span>
                              Refutations: {event.refutation_count}
                              {typeof event.authorized_refutation_count === "number"
                                ? ` · authorized ${event.authorized_refutation_count}`
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
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="detail-section">
                <div className="detail-section-label">Steps</div>
                {(selected.steps ?? []).length === 0 ? (
                  <p className="muted" style={{ fontSize: 12, margin: 0 }}>
                    {t("还没有步骤。", "No steps yet.")}
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
                          <span>{t("更新", "Updated")}: {formatTime(step.updated_at)}</span>
                          {step.assignee && <span>{t("执行者", "Agent")}: <code>{step.assignee}</code></span>}
                          {step.required_capabilities.length > 0 && (
                            <span>
                              {t("能力", "Capabilities")}: {step.required_capabilities.join(", ")}
                            </span>
                          )}
                          {(step.notes_count ?? 0) > 0 && (
                            <span>{t("备注", "Notes")}: {step.notes_count}</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
                {hiddenStepRows > 0 && (
                  <p className="muted" style={{ fontSize: 11, margin: "8px 0 0" }}>
                    {t(
                      `还有 ${hiddenStepRows} 个步骤未展开`,
                      `${hiddenStepRows} more step(s) hidden`,
                    )}
                  </p>
                )}
              </div>

              <SignaturePanel
                value={selected}
                title={t("Mission 结构", "Mission shape")}
              />
            </>
          ) : (
            <p className="muted">{t("选择一个 mission 查看。", "Select a mission to inspect.")}</p>
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
        {t("发起一个新 mission", "Start a new mission")}
      </h3>
      <p
        className="muted"
        style={{ margin: "0 0 12px", fontSize: 11 }}
      >
        {t(
          "驱动 agent 会规划步骤并请你审批 —— 除非你给一个 cap_token,那它就在该授权范围内自主执行。",
          "The driver agent will plan steps and request your approval — unless you scope a cap_token, in which case it executes autonomously within those bounds.",
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
            {t("标题", "Title")}
          </label>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder={t("例如:起草 Q3 发布公告", "e.g. Draft Q3 launch announcement")}
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
            {t("目标", "Goal")}
          </label>
          <textarea
            value={goal}
            onChange={(e) => setGoal(e.target.value)}
            placeholder={t("描述你想要的结果,而不是步骤。", "Describe the outcome you want, not the steps.")}
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
            {t("Steps(每行一个,可留空)", "Steps (one per line, optional)")}
          </label>
          <textarea
            value={stepsText}
            onChange={(e) => setStepsText(e.target.value)}
            placeholder={t(
              "每行一个步骤,例如:\nreproduce the crash\nwrite a fix\nverify on staging",
              "One step per line, e.g.:\nreproduce the crash\nwrite a fix\nverify on staging",
            )}
            rows={3}
            style={{ width: "100%", resize: "vertical" }}
          />
          <p className="muted" style={{ margin: "4px 0 0", fontSize: 11 }}>
            {t(
              "没有步骤的 mission 会停在 planning(空规划态);加了步骤才能推进/发上市场。",
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
            {t("驱动 agent", "Driver agent")}
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
            {t("Cap_token(可选,给本 mission 开启自动驾驶)", "Cap_token (optional, enables autopilot for this mission)")}
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
          {t("取消", "Cancel")}
        </button>
        <button
          type="submit"
          className="btn btn-primary"
          disabled={!canSubmit}
        >
          {t("启动 mission", "Start mission")}
        </button>
      </div>
    </form>
  );
}
