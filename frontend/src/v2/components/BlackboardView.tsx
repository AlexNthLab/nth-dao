/**
 * Blackboard — the autopilot-era main screen.
 *
 * This is the operational dashboard of a one-person company: each
 * card is a process (an order, a support ticket, an invoice) and
 * each section is a workflow stage. Stages are stacked vertically
 * so the user scrolls top→bottom from Intake to Done — Chinese-
 * keyboard mental model (per user audit 2026-06-10): "竖排适合用户
 * 习惯". The earlier horizontal Kanban created an unnatural left↔
 * right scroll axis on narrower screens and made the Done column
 * (least-interesting) consume the same visual budget as Intake
 * (most-interesting).
 *
 * Vertical layout invariants:
 *   - Stage sections are ordered by lifecycle: Intake → Working →
 *     Awaiting → Blocked → Done. Eye flow matches reading order.
 *   - The stage header (pill + count) is sticky so the user
 *     always knows what stage they're scrolling through.
 *   - Each card uses full main-body width — no 220px squeeze.
 *   - Blocked / Awaiting still visually pop because their pill
 *     colors carry through; nothing needs spatial isolation.
 *
 * Sidebar shows workflow filters; detail rail shows the selected
 * process card's full state including which agent is currently
 * driving and which cap_token authorizes them.
 */

import { useEffect, useMemo, useState } from "react";
import { IconLayout, IconPlus, IconZap } from "./Icons";
import { SignaturePanel } from "./SignaturePanel";
import { relativeTimeShort } from "../utils/time";
import { useLang } from "../i18n";
import type { ProcessCard, ProcessStage } from "../types-v2";

/** 阶段名中文(COLUMNS 在模块级,渲染时用 t(STAGE_ZH[id], col.label))。 */
const STAGE_ZH: Record<ProcessStage, string> = {
  received: "待接收",
  in_progress: "进行中",
  awaiting_external: "等待外部",
  blocked: "受阻",
  done: "完成",
};

export interface BlackboardViewProps {
  processes: ProcessCard[];
  /** Optional: when wired, the Blackboard head shows a "New process"
   *  button that opens an inline form. v1 captures locally; backend
   *  integration drops the result into /api/processes. */
  onCreate?: (draft: NewProcessDraft) => void;
  /** Workflow choices to seed the create-form dropdown. If omitted
   *  the form derives them from existing processes. */
  workflowOptions?: string[];
}

/** Minimal shape the create-process form emits. The receiver
 *  (App.tsx for v1, /api/processes for v1.x) is responsible for
 *  hydrating into a full ProcessCard (id, updated_at, etc). */
export interface NewProcessDraft {
  title: string;
  workflow: string;
  subtitle?: string;
  current_agent: string;
}

const COLUMNS: { id: ProcessStage; label: string; pill: "ok" | "wait" | "bad" | "dim" }[] = [
  { id: "received",           label: "Intake",   pill: "wait" },
  { id: "in_progress",        label: "Working",  pill: "ok"   },
  { id: "awaiting_external",  label: "Awaiting", pill: "wait" },
  { id: "blocked",            label: "Blocked",  pill: "bad"  },
  { id: "done",               label: "Done",     pill: "dim"  },
];

// (was a local relativeTime() — moved to ../utils/time, audit M3)

export function BlackboardView({
  processes, onCreate, workflowOptions,
}: BlackboardViewProps) {
  const { t } = useLang();
  const workflows = useMemo(
    () => Array.from(new Set(processes.map((p) => p.workflow))).sort(),
    [processes],
  );

  const [activeWorkflow, setActiveWorkflow] = useState<string>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);

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
          <span className="sidebar-title">{t("工作流", "Workflows")}</span>
          <span className="sidebar-count">{processes.length}</span>
        </div>
        <div className="sidebar-list">
          <button
            className={`sidebar-item ${activeWorkflow === "all" ? "active" : ""}`}
            onClick={() => setActiveWorkflow("all")}
          >
            <div className="sidebar-item-title">
              <span>{t("全部工作流", "All workflows")}</span>
            </div>
            <div className="sidebar-item-meta">
              <span>{processes.length} {t("个流程", "processes")}</span>
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
            <p className="main-eyebrow">Blackboard</p>
            <h1 className="main-title">
              {activeWorkflow === "all"
                ? t("运营总览", "Operations")
                : activeWorkflow[0].toUpperCase() + activeWorkflow.slice(1)}
            </h1>
            <p className="main-subtitle">
              {t("每个 agent 此刻在做什么。", "What every agent is doing right now.")}{" "}
              <span style={{ color: "var(--accent)" }}>
                {t(
                  `${autoPct}% 的活跃流程在自动驾驶(规则授权)。`,
                  `${autoPct}% of active processes are running on autopilot (Rule-authorized).`,
                )}
              </span>
            </p>
          </div>
          {onCreate && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => setCreateOpen(true)}
              title={t("发起一个新流程 —— 落入待接收", "Start a new process — drops into Intake")}
              style={{ marginTop: 4, flexShrink: 0 }}
            >
              <IconPlus size={14} /> {t("新流程", "New process")}
            </button>
          )}
        </div>

        <div
          className="main-body"
          style={{ paddingRight: 24 }}
        >
          {createOpen && onCreate && (
            <NewProcessForm
              workflowOptions={
                workflowOptions && workflowOptions.length > 0
                  ? workflowOptions
                  : workflows
              }
              onCancel={() => setCreateOpen(false)}
              onSubmit={(draft) => {
                onCreate(draft);
                setCreateOpen(false);
              }}
            />
          )}

          {/* Stages stacked top→bottom. Each stage is a section with
              a sticky header pill + the cards listed vertically
              underneath at full main-body width. */}
          <div className="stack" style={{ gap: 24 }}>
            {COLUMNS.map((col) => {
              const items = byStage.get(col.id) ?? [];
              return (
                <section key={col.id}>
                  {/* Sticky stage header. z-index coupling: this sits
                      INSIDE .main-body. .main-head is a sibling DOM
                      node (also z-index 1), but distinct stacking
                      contexts — they do not overlap because .main-
                      head is fixed at the top via the layout grid
                      and these stickies live in scrollable content.
                      Background must match .main-body's background
                      (var(--bg-root)) or cards bleed through. */}
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      marginBottom: 8,
                      padding: "6px 4px",
                      position: "sticky",
                      top: 0,
                      background: "var(--bg-root)",
                      zIndex: 1,
                      borderBottom: "1px solid var(--border)",
                    }}
                  >
                    <span className={`pill ${col.pill}`}>{t(STAGE_ZH[col.id], col.label)}</span>
                    <span className="muted mono" style={{ fontSize: 11 }}>
                      {items.length}
                    </span>
                  </div>
                  <div className="stack" style={{ gap: 8 }}>
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
                          <span style={{ display: "flex", gap: 12 }}>
                            {p.amount && (
                              <span className="mono">{p.amount}</span>
                            )}
                            <span>{relativeTimeShort(p.updated_at)}</span>
                          </span>
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
                        {t("空", "empty")}
                      </div>
                    )}
                  </div>
                </section>
              );
            })}
          </div>

          {filtered.length === 0 && (
            <div className="main-empty" style={{ minHeight: 200, marginTop: 24 }}>
              <div className="main-empty-icon">
                <IconLayout size={36} />
              </div>
              <p>{t("这个工作流暂无流程。", "No processes in this workflow.")}</p>
            </div>
          )}
        </div>
      </section>

      <aside className="detail">
        <div className="detail-head">
          <span className="detail-title">{t("流程详情", "Process detail")}</span>
        </div>
        <div className="detail-body">
          {selected ? (
            <>
              <div className="detail-section">
                <div className="detail-section-label">{t("状态", "State")}</div>
                <div className="detail-row">
                  <span className="key">{t("阶段", "Stage")}</span>
                  <span className="value">{selected.stage}</span>
                </div>
                <div className="detail-row">
                  <span className="key">{t("工作流", "Workflow")}</span>
                  <span className="value">{selected.workflow}</span>
                </div>
                <div className="detail-row">
                  <span className="key">{t("当前 agent", "Current agent")}</span>
                  <span className="value">{selected.current_agent}</span>
                </div>
                {selected.next_agent && (
                  <div className="detail-row">
                    <span className="key">{t("下一个 agent", "Next agent")}</span>
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
                    <span className="key">{t("金额", "Amount")}</span>
                    <span className="value">{selected.amount}</span>
                  </div>
                )}
                <div className="detail-row">
                  <span className="key">{t("最近更新", "Last update")}</span>
                  <span className="value">
                    {new Date(selected.updated_at).toLocaleString()}
                  </span>
                </div>
                <div className="detail-row">
                  <span className="key">{t("模式", "Mode")}</span>
                  <span className="value">
                    {selected.auto ? t("自动驾驶 ⚡", "autopilot ⚡") : t("手动", "manual")}
                  </span>
                </div>
              </div>
              <SignaturePanel
                value={selected}
                title={t("流程快照", "Process snapshot")}
              />
            </>
          ) : (
            <p className="muted">{t("选择一张卡片查看。", "Select a card to inspect.")}</p>
          )}
        </div>
      </aside>
    </>
  );
}

/* ── NewProcessForm ──────────────────────────────────────────────
 * Inline drawer at the top of main-body. Kept inline (not modal)
 * so the user can still see the Operations stack behind it — the
 * very thing they're adding to. Mirrors the AddByDidForm pattern
 * in AgentDirectoryView for consistency.
 *
 * Required fields: title + workflow (so the new process can be
 * routed to its lane) + current_agent (who's driving). Subtitle
 * is optional one-liner. New processes always land in `received`
 * stage — promotion is the agent's job.
 */
interface NewProcessFormProps {
  workflowOptions: string[];
  onCancel: () => void;
  onSubmit: (draft: NewProcessDraft) => void;
}

function NewProcessForm({
  workflowOptions, onCancel, onSubmit,
}: NewProcessFormProps) {
  const { t } = useLang();
  const [title, setTitle] = useState("");
  const [workflow, setWorkflow] = useState(workflowOptions[0] ?? "");
  const [customWorkflow, setCustomWorkflow] = useState("");
  const [subtitle, setSubtitle] = useState("");
  const [agent, setAgent] = useState("self-prompt");

  /* Symmetric to NewMissionForm (audit pass#3 finding I2 bonus,
   * 2026-06-10): if workflowOptions changes identity while the
   * form is open and the active selection drops out, reset to the
   * first valid option. v1 passes a static literal so this is
   * latent — v1.x will read from /api/workflows where the list
   * can refresh under the open form. The "__new__" sentinel is
   * NOT in workflowOptions so it always falls through the guard
   * and stays selected — correct behaviour. */
  useEffect(() => {
    if (workflow === "__new__") return;
    if (workflowOptions.length > 0 && !workflowOptions.includes(workflow)) {
      setWorkflow(workflowOptions[0]);
    }
  }, [workflowOptions, workflow]);

  const usingCustom = workflow === "__new__";
  const effectiveWorkflow = usingCustom
    ? customWorkflow.trim().toLowerCase()
    : workflow;

  const canSubmit =
    title.trim().length > 0 &&
    effectiveWorkflow.length > 0 &&
    agent.trim().length > 0;

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    onSubmit({
      title: title.trim(),
      workflow: effectiveWorkflow,
      subtitle: subtitle.trim() || undefined,
      current_agent: agent.trim(),
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
        {t("发起一个新流程", "Start a new process")}
      </h3>
      <p
        className="muted"
        style={{ margin: "0 0 12px", fontSize: 11 }}
      >
        {t("它会落入", "It drops into")} <strong>{t("待接收", "Intake")}</strong>
        {t("。驱动 agent 会在下一轮接手。", ". The driver agent will pick it up on the next loop.")}
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
            placeholder={t("例如:退款订单 #4521", "e.g. Refund order #4521")}
            required
            autoFocus
            style={{ width: "100%" }}
          />
        </div>

        <div style={{ display: "flex", gap: 8 }}>
          <div style={{ flex: 1 }}>
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
              {t("工作流", "Workflow")}
            </label>
            <select
              value={workflow}
              onChange={(e) => setWorkflow(e.target.value)}
              style={{ width: "100%" }}
            >
              {workflowOptions.map((wf) => (
                <option key={wf} value={wf}>
                  {wf}
                </option>
              ))}
              <option value="__new__">{t("+ 新工作流…", "+ New workflow…")}</option>
            </select>
          </div>
          {usingCustom && (
            <div style={{ flex: 1 }}>
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
                {t("新工作流名", "New workflow name")}
              </label>
              <input
                type="text"
                value={customWorkflow}
                onChange={(e) => setCustomWorkflow(e.target.value)}
                placeholder={t("如:财务", "finance")}
                required={usingCustom}
                style={{ width: "100%" }}
              />
            </div>
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
            {t("驱动 agent", "Driver agent")}
          </label>
          <input
            type="text"
            value={agent}
            onChange={(e) => setAgent(e.target.value)}
            placeholder="self-prompt | billing-helper | …"
            required
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
            {t("副标题(可选)", "Subtitle (optional)")}
          </label>
          <input
            type="text"
            value={subtitle}
            onChange={(e) => setSubtitle(e.target.value)}
            placeholder={t("一句话上下文", "one-line context")}
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
          {t("创建流程", "Create process")}
        </button>
      </div>
    </form>
  );
}
