/**
 * ReputationView — 信誉(Phase 5 / 最后一根支柱)。把 spine 派生的可验证贡献做成
 * 排行榜:每个 DID 的承接数、发布数、被争议数、净分。非中心打分 —— 任何节点回放
 * 同一日志得同一信誉。消费 /api/v2/reputation。
 */
import { useEffect, useState } from "react";
import { listReputation, type ReputationRecord } from "../api";
import { useLang } from "../i18n";

const MUTED = "var(--color-text-tertiary, #888)";

export function ReputationView() {
  const { t } = useLang();
  const [rows, setRows] = useState<ReputationRecord[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const ac = new AbortController();
    setLoading(true);
    listReputation(ac.signal)
      .then(setRows)
      .catch(() => setRows([]))
      .finally(() => setLoading(false));
    return () => ac.abort();
  }, []);

  return (
    <>
      <aside className="sidebar">
        <div className="sidebar-head">
          <span className="sidebar-title">{t("信誉", "Reputation")}</span>
          <span className="muted" style={{ fontSize: 12 }}>{rows.length}</span>
        </div>
        <div className="sidebar-list">
          <p className="muted" style={{ padding: "12px 14px", fontSize: 13, lineHeight: 1.6 }}>
            {t("从签名的承接 / 发布 / 争议事件直接派生 —— 非中心打分,任何节点回放同一日志得同一信誉,可迁移、可复算。",
              "Derived directly from signed claim / publish / dispute events — not a central score. Any node replaying the same log gets the same reputation: portable and recomputable.")}
          </p>
        </div>
      </aside>

      <section className="main">
        <div className="main-head">
          <p className="main-eyebrow">{t("信誉 · 可验证贡献", "Reputation · verifiable contribution")}</p>
          <h1 className="main-title">{t("信誉榜", "Leaderboard")}</h1>
          <p className="main-subtitle">
            {t("净分 = 被发布方验收的交付数 − 被争议的交付数(承接≠交付;只有被验收的交付才计分)。",
              "Score = publisher-accepted deliveries − disputed deliveries (claiming ≠ delivering; only accepted deliveries count).")}
          </p>
        </div>
        <div className="main-body">
          {loading && <p className="muted">{t("加载中…", "Loading…")}</p>}
          {!loading && rows.length === 0 && (
            <div className="main-empty" style={{ minHeight: 160 }}>
              <p className="muted">{t("暂无信誉数据(还没有承接 / 发布)。", "No reputation yet (no claims / publishes).")}</p>
            </div>
          )}
          {rows.length > 0 && (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
              <thead>
                <tr style={{ textAlign: "left", color: MUTED, fontSize: 12 }}>
                  <th style={{ padding: "8px 6px", width: 36 }}>#</th>
                  <th style={{ padding: "8px 6px" }}>{t("DID", "DID")}</th>
                  <th style={{ padding: "8px 6px", textAlign: "right" }}>{t("净分", "Score")}</th>
                  <th style={{ padding: "8px 6px", textAlign: "right" }}>{t("交付", "Delivered")}</th>
                  <th style={{ padding: "8px 6px", textAlign: "right" }}>{t("承接", "Claimed")}</th>
                  <th style={{ padding: "8px 6px", textAlign: "right" }}>{t("发布", "Published")}</th>
                  <th style={{ padding: "8px 6px", textAlign: "right" }}>{t("被争议", "Disputed")}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r, i) => (
                  <tr key={r.did} style={{ borderTop: "1px solid var(--color-border-tertiary, rgba(0,0,0,0.08))" }}>
                    <td style={{ padding: "8px 6px", color: MUTED }}>{i + 1}</td>
                    <td style={{ padding: "8px 6px", fontFamily: "var(--font-mono)", fontSize: 12, wordBreak: "break-all" }}>{r.did}</td>
                    <td style={{ padding: "8px 6px", textAlign: "right", fontWeight: 500 }}>{r.score}</td>
                    <td style={{ padding: "8px 6px", textAlign: "right", color: r.tasks_accepted ? "var(--color-text-success,#1d9e75)" : MUTED }}>{r.tasks_accepted}</td>
                    <td style={{ padding: "8px 6px", textAlign: "right" }}>{r.tasks_claimed}</td>
                    <td style={{ padding: "8px 6px", textAlign: "right" }}>{r.tasks_published}</td>
                    <td style={{ padding: "8px 6px", textAlign: "right", color: r.disputed_claims ? "var(--color-text-danger,#e24b4a)" : MUTED }}>{r.disputed_claims}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>
    </>
  );
}
