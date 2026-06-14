/**
 * Rules — the manual-mode → autopilot-mode transition surface.
 *
 * Each Rule = (trigger condition, action, status, cap_token).
 * Active rules cause processes to flow through Blackboard
 * without ever raising a Decision. Drafts let the user think
 * through a rule before activating it.
 *
 * UI structure mirrors the Decision/Mission views (sidebar list
 * + main detail + signature inspector) so the user's eye
 * already knows where things are.
 */

import { useMemo, useState } from "react";
import { IconSliders, IconZap } from "./Icons";
import { SignaturePanel } from "./SignaturePanel";
import { useLang } from "../i18n";
import type { Rule } from "../types-v2";

export interface RulesViewProps {
  rules: Rule[];
  /* Action handlers (audit fix 2026-06-10, finding C1: six buttons
   * in the Rules detail card were rendered without onClick — the
   * autopilot story collapses if Pause/Activate/Resume don't do
   * anything). Each handler receives the rule id and is responsible
   * for the state transition.
   *
   * All optional so existing callers (and tests) continue to work;
   * a missing handler simply hides its button. The App.tsx wiring
   * supplies every one. */
  onPause?: (id: string) => void;
  onResume?: (id: string) => void;
  onActivate?: (id: string) => void;
  onDiscard?: (id: string) => void;
  onEdit?: (id: string) => void;
  onViewCap?: (capTokenId: string) => void;
}

function statusPill(s: Rule["status"]): "ok" | "wait" | "dim" {
  if (s === "active") return "ok";
  if (s === "paused") return "wait";
  return "dim";
}

export function RulesView({
  rules, onPause, onResume, onActivate, onDiscard, onEdit, onViewCap,
}: RulesViewProps) {
  const { t } = useLang();
  const sorted = useMemo(
    () =>
      rules.slice().sort((a, b) => {
        // Active first, then draft, then paused. Within group, by
        // most-recently-updated.
        const order: Record<Rule["status"], number> = {
          active: 0, draft: 1, paused: 2,
        };
        return (
          order[a.status] - order[b.status] ||
          b.updated_at.localeCompare(a.updated_at)
        );
      }),
    [rules],
  );

  const [selectedId, setSelectedId] = useState<string | null>(
    sorted[0]?.id ?? null,
  );
  const selected = sorted.find((r) => r.id === selectedId) ?? null;

  const activeCount = rules.filter((r) => r.status === "active").length;
  const totalFires = rules.reduce((sum, r) => sum + r.fired_30d, 0);

  return (
    <>
      <aside className="sidebar">
        <div className="sidebar-head">
          <span className="sidebar-title">{t("规则", "Rules")}</span>
          <span className="sidebar-count">{rules.length}</span>
        </div>
        <div className="sidebar-list">
          {sorted.map((r) => (
            <button
              key={r.id}
              className={`sidebar-item ${selectedId === r.id ? "active" : ""}`}
              onClick={() => setSelectedId(r.id)}
            >
              <div className="sidebar-item-title">
                <span className={`pill ${statusPill(r.status)}`}>
                  {r.status}
                </span>
                <span className="truncate">{r.title}</span>
              </div>
              <div className="sidebar-item-meta">
                <span style={{ textTransform: "capitalize" }}>{r.workflow}</span>
                <span className="muted">·</span>
                <span>{r.fired_30d}× / 30d</span>
              </div>
            </button>
          ))}
        </div>
      </aside>

      <section className="main">
        <div className="main-head">
          <p className="main-eyebrow">Rules</p>
          <h1 className="main-title">{t("设定你公司的边界", "Set your company boundaries")}</h1>
          <p className="main-subtitle">
            {t(
              "规则把「需审批」的动作变成「自动执行」。每条规则受一个长效 cap_token 约束 —— 你所委派权限的密码学锚点。",
              "Rules turn approval-required actions into auto-execute ones. Each rule is bounded by a long-lived cap_token — the cryptographic anchor of the authority you delegate.",
            )}
            {" "}
            <span style={{ color: "var(--accent)" }}>
              {t(
                `${activeCount} 条生效 · 近 30 天触发 ${totalFires} 次`,
                `${activeCount} active · ${totalFires} fires in last 30d`,
              )}
            </span>
          </p>
        </div>

        <div className="main-body">
          {selected ? (
            <>
              <article className="decision-card">
                <div className="decision-card-head">
                  <div>
                    <h3 className="decision-card-title">
                      {selected.status === "active" && (
                        <span
                          style={{
                            color: "var(--accent)",
                            display: "inline-flex",
                            alignItems: "center",
                            marginRight: 8,
                          }}
                        >
                          <IconZap size={16} />
                        </span>
                      )}
                      {selected.title}
                    </h3>
                    <div className="decision-card-subject">
                      <span style={{ textTransform: "capitalize" }}>
                        {selected.workflow}
                      </span>
                      <span className="muted">·</span>
                      <span>cap_token <code>{selected.cap_token_id}</code></span>
                    </div>
                  </div>
                  <span className={`pill ${statusPill(selected.status)}`}>
                    {selected.status}
                  </span>
                </div>

                <div style={{ display: "grid", gap: 12, margin: "16px 0" }}>
                  <div>
                    <div className="detail-section-label">{t("当", "When")}</div>
                    <p className="decision-card-rationale" style={{ marginTop: 4 }}>
                      {selected.when}
                    </p>
                  </div>
                  <div>
                    <div className="detail-section-label">{t("则", "Then")}</div>
                    <p className="decision-card-rationale" style={{ marginTop: 4 }}>
                      {selected.then}
                    </p>
                  </div>
                </div>

                <div className="decision-card-meta">
                  <span>{t("近 30 天触发", "fired")} <code>{selected.fired_30d}×</code>{t("", " in last 30 days")}</span>
                  <span>
                    {t("最近更新", "last updated")}{" "}
                    {new Date(selected.updated_at).toLocaleDateString()}
                  </span>
                </div>

                <div className="decision-card-actions">
                  {selected.status === "active" ? (
                    <>
                      {onPause && (
                        <button
                          type="button"
                          className="btn btn-secondary"
                          onClick={() => onPause(selected.id)}
                        >
                          {t("暂停", "Pause")}
                        </button>
                      )}
                      {onEdit && (
                        <button
                          type="button"
                          className="btn btn-ghost"
                          onClick={() => onEdit(selected.id)}
                        >
                          {t("编辑", "Edit")}
                        </button>
                      )}
                    </>
                  ) : selected.status === "draft" ? (
                    <>
                      {onActivate && (
                        <button
                          type="button"
                          className="btn btn-primary"
                          onClick={() => onActivate(selected.id)}
                        >
                          <IconZap size={14} /> {t("启用", "Activate")}
                        </button>
                      )}
                      {onEdit && (
                        <button
                          type="button"
                          className="btn btn-ghost"
                          onClick={() => onEdit(selected.id)}
                        >
                          {t("编辑", "Edit")}
                        </button>
                      )}
                      {onDiscard && (
                        <button
                          type="button"
                          className="btn btn-danger"
                          onClick={() => onDiscard(selected.id)}
                        >
                          {t("丢弃", "Discard")}
                        </button>
                      )}
                    </>
                  ) : (
                    <>
                      {onResume && (
                        <button
                          type="button"
                          className="btn btn-primary"
                          onClick={() => onResume(selected.id)}
                        >
                          {t("恢复", "Resume")}
                        </button>
                      )}
                      {onEdit && (
                        <button
                          type="button"
                          className="btn btn-ghost"
                          onClick={() => onEdit(selected.id)}
                        >
                          {t("编辑", "Edit")}
                        </button>
                      )}
                    </>
                  )}
                  <span style={{ flex: 1 }} />
                  {onViewCap && (
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={() => onViewCap(selected.cap_token_id)}
                    >
                      {t("查看关联 cap_token", "View linked cap_token")}
                    </button>
                  )}
                </div>
              </article>
            </>
          ) : (
            <div className="main-empty" style={{ minHeight: 200 }}>
              <div className="main-empty-icon">
                <IconSliders size={36} />
              </div>
              <p>{t("还没有规则。", "No rules yet.")}</p>
              <p className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                {t(
                  "创建第一条规则,开始把常规决策交给自动驾驶。",
                  "Create your first rule to start moving routine decisions to autopilot.",
                )}
              </p>
            </div>
          )}
        </div>
      </section>

      <aside className="detail">
        <div className="detail-head">
          <span className="detail-title">{t("规则详情", "Rule detail")}</span>
        </div>
        <div className="detail-body">
          {selected ? (
            <SignaturePanel
              value={selected}
              title={t("规则定义", "Rule definition")}
            />
          ) : (
            <p className="muted">{t("选择一条规则查看。", "Select a rule to inspect.")}</p>
          )}
        </div>
      </aside>
    </>
  );
}
