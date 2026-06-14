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
import { useLang } from "../i18n";
import type { Decision } from "../types-v2";

export interface DecisionQueueProps {
  decisions: Decision[];
  onApprove: (id: string) => Promise<void> | void;
  onReject: (id: string) => Promise<void> | void;
  onDefer: (id: string) => Promise<void> | void;
  /** S5 fix (2026-06-10): decision ids currently in flight to the
   *  hub. Used to render a small banner so the operator gets visual
   *  feedback during the optimistic-remove → success-toast window.
   *  Optional so existing callers (and the v1 mock-only path)
   *  continue to compile. */
  resolvingIds?: Set<string>;
}

const IMPACT_ORDER: Record<Decision["impact"], number> = {
  high: 0,
  medium: 1,
  low: 2,
};

export function DecisionQueue({
  decisions, onApprove, onReject, onDefer, resolvingIds,
}: DecisionQueueProps) {
  const { t } = useLang();
  const inflight = resolvingIds ? resolvingIds.size : 0;
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

  // Keep selected valid after queue mutations (audit fix 2026-
  // 06-10, finding M7): the previous deps `[sorted, selectedId]`
  // re-fired the effect on every selectedId change, causing a
  // double render. The functional updater reads the previous
  // selectedId from React's state queue without participating in
  // the deps list — effect now fires only when `sorted` changes.
  useEffect(() => {
    setSelectedId((prev) =>
      prev && sorted.some((d) => d.id === prev)
        ? prev
        : sorted[0]?.id ?? null,
    );
  }, [sorted]);

  const selected = sorted.find((d) => d.id === selectedId) ?? null;

  return (
    <>
      <aside className="sidebar">
        <div className="sidebar-head">
          <span className="sidebar-title">{t("待处理决策", "Pending decisions")}</span>
          <span className="sidebar-count">{sorted.length}</span>
        </div>
        <div className="sidebar-list">
          {sorted.length === 0 && (
            <p className="muted" style={{ padding: "12px 14px" }}>
              {t("收件箱已清空,所有 agent 都在策略内。", "Inbox zero. The agents are all on-policy.")}
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
          <h1 className="main-title">{t("批准、拒绝,或延后", "Approve, reject, or defer")}</h1>
          <p className="main-subtitle">
            {t(
              "每张卡片都是某个 AI agent 代你行动的请求。批准即签发一张回执;密码学链条永久保存审计轨迹。",
              "Each card is a request from an AI agent acting on your behalf. Approving signs a receipt; the cryptographic chain preserves the audit trail forever.",
            )}
          </p>
          {/* S5 banner — visible while the hub is signing one or more
              receipts. Closes the optimistic-remove → success-toast
              gap that otherwise looks like silent UI. aria-live so
              screen readers announce the pending action. */}
          {inflight > 0 && (
            <div
              role="status"
              aria-live="polite"
              style={{
                marginTop: 8,
                padding: "6px 12px",
                background: "var(--accent-muted)",
                color: "var(--accent)",
                borderRadius: 6,
                fontSize: 12,
                fontFamily: "var(--t-mono)",
                display: "inline-block",
              }}
            >
              {t(`正在签发 ${inflight} 张回执…`, `Signing ${inflight} receipt${inflight === 1 ? "" : "s"}…`)}
            </div>
          )}
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
              <p>{t("收件箱已清空。", "Inbox zero.")}</p>
              <p className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                {t(
                  "此刻每个 agent 的动作都在你已签发的 cap_token 范围内。",
                  "Every agent action right now is within the cap_tokens you've already issued.",
                )}
              </p>
            </div>
          )}
        </div>
      </section>

      <aside className="detail">
        <div className="detail-head">
          <span className="detail-title">{t("上下文", "Context")}</span>
        </div>
        <div className="detail-body">
          {selected ? (
            <>
              <div className="detail-section">
                <div className="detail-section-label">{t("动作对象", "Action target")}</div>
                <div className="detail-row">
                  <span className="key">{t("影响", "Impact")}</span>
                  <span className="value">{selected.impact}</span>
                </div>
                <div className="detail-row">
                  <span className="key">{t("提议者", "Proposer")}</span>
                  <span className="value">{selected.proposer_label}</span>
                </div>
                <div className="detail-row">
                  <span className="key">{t("提议者 DID", "Proposer DID")}</span>
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
                  <span className="key">{t("提出于", "Raised at")}</span>
                  <span className="value">
                    {new Date(selected.raised_at).toLocaleString()}
                  </span>
                </div>
              </div>

              <SignaturePanel
                value={selected.preview_receipt}
                title={t("回执预览", "Preview receipt")}
              />
            </>
          ) : (
            <p className="muted">{t("选择一个决策查看。", "Select a decision to inspect.")}</p>
          )}
        </div>
      </aside>
    </>
  );
}
