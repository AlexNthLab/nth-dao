/**
 * AuditView — 审计 / 争议(Phase 5)。把 spine 的争议 + 证据链回放成"信任可见"
 * 的界面:左栏列争议(状态 + 仲裁授权徽标),选中后主区按 spine 序回放证据链,
 * 每项带**独立验证勾**。消费 4c 端点 /disputes 与 /market/{id}/evidence。
 *
 * 自取数(import api),不经 App 状态,视图自洽。
 */
import { useEffect, useState } from "react";
import {
  getEvidence,
  listDisputes,
  type DisputeSummary,
  type EvidenceChain,
} from "../api";
import { useLang } from "../i18n";

const OK = "var(--color-text-success, #1d9e75)";
const BAD = "var(--color-text-danger, #e24b4a)";
const MUTED = "var(--color-text-tertiary, #888)";

function Pill({ tone, children }: { tone: "ok" | "warn" | "bad"; children: React.ReactNode }) {
  const c = tone === "ok" ? OK : tone === "bad" ? BAD : "var(--color-text-warning, #ba7517)";
  return (
    <span style={{
      fontSize: 12, padding: "2px 8px", borderRadius: 999,
      border: `1px solid ${c}`, color: c, whiteSpace: "nowrap",
    }}>{children}</span>
  );
}

export function AuditView() {
  const { t } = useLang();
  const [disputes, setDisputes] = useState<DisputeSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<DisputeSummary | null>(null);
  const [chain, setChain] = useState<EvidenceChain | null>(null);
  const [chainLoading, setChainLoading] = useState(false);

  useEffect(() => {
    const ac = new AbortController();
    setLoading(true);
    listDisputes(ac.signal)
      .then(setDisputes)
      .catch(() => setDisputes([]))
      .finally(() => setLoading(false));
    return () => ac.abort();
  }, []);

  useEffect(() => {
    if (!selected) { setChain(null); return; }
    const ac = new AbortController();
    setChainLoading(true);
    getEvidence(selected.announcement_id, ac.signal)
      .then(setChain)
      .catch(() => setChain(null))
      .finally(() => setChainLoading(false));
    return () => ac.abort();
  }, [selected]);

  return (
    <>
      <aside className="sidebar">
        <div className="sidebar-head">
          <span className="sidebar-title">{t("争议", "Disputes")}</span>
          <span className="muted" style={{ fontSize: 12 }}>{disputes.length}</span>
        </div>
        <div className="sidebar-list">
          {loading && (
            <p className="muted" style={{ padding: "12px 14px" }}>{t("加载中…", "Loading…")}</p>
          )}
          {!loading && disputes.length === 0 && (
            <p className="muted" style={{ padding: "12px 14px" }}>{t("暂无争议", "No disputes yet")}</p>
          )}
          {disputes.map((d) => (
            <button
              key={d.dispute_id}
              onClick={() => setSelected(d)}
              style={{
                display: "flex", justifyContent: "space-between", alignItems: "center",
                gap: 8, width: "100%", textAlign: "left", padding: "10px 14px",
                background: selected?.dispute_id === d.dispute_id
                  ? "var(--color-background-secondary, rgba(0,0,0,0.04))" : "transparent",
                border: "none", borderBottom: "1px solid var(--color-border-tertiary, rgba(0,0,0,0.08))",
                cursor: "pointer", color: "inherit",
              }}
            >
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, overflow: "hidden", textOverflow: "ellipsis" }}>
                {d.announcement_id.slice(0, 12)}…
              </span>
              <Pill tone={d.status === "resolved" ? "ok" : "warn"}>
                {d.status === "resolved" ? t("已裁决", "resolved") : t("进行中", "open")}
              </Pill>
            </button>
          ))}
        </div>
      </aside>

      <section className="main">
        <div className="main-head">
          <p className="main-eyebrow">{t("审计 · 证据链", "Audit · evidence chain")}</p>
          <h1 className="main-title">{selected ? t("证据链回放", "Evidence replay") : t("审计", "Audit")}</h1>
          <p className="main-subtitle">
            {t("每条证据独立验签,整链由 spine 不可篡改地记录。",
              "Each item is independently verified; the whole chain is recorded tamper-evident in the spine.")}
          </p>
        </div>
        <div className="main-body">
          {!selected && (
            <div className="main-empty" style={{ minHeight: 200 }}>
              <p className="muted">{t("从左侧选择一个争议查看证据链。", "Select a dispute to replay its evidence chain.")}</p>
            </div>
          )}
          {selected && (
            <div style={{ padding: "4px 2px" }}>
              <div style={{
                border: "1px solid var(--color-border-tertiary, rgba(0,0,0,0.08))",
                borderRadius: 12, padding: 14, marginBottom: 14,
              }}>
                <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <Pill tone={selected.status === "resolved" ? "ok" : "warn"}>
                    {selected.status === "resolved" ? t("已裁决", "resolved") : t("进行中", "open")}
                  </Pill>
                  {selected.status === "resolved" && selected.arbiter_authorized !== null && (
                    <Pill tone={selected.arbiter_authorized ? "ok" : "bad"}>
                      {selected.arbiter_authorized
                        ? t("仲裁者已授权", "arbiter authorized")
                        : t("仲裁者未授权", "arbiter NOT authorized")}
                    </Pill>
                  )}
                  {typeof selected.ruling?.ruling === "string" && (
                    <span className="muted" style={{ fontSize: 13 }}>
                      {t("裁决", "ruling")}: {String(selected.ruling.ruling)}
                    </span>
                  )}
                </div>
                <p style={{ marginTop: 8, fontFamily: "var(--font-mono)", fontSize: 12, color: MUTED }}>
                  {t("公告", "announcement")} {selected.announcement_id}
                </p>
              </div>

              {chainLoading && <p className="muted">{t("加载证据链…", "Loading evidence…")}</p>}
              {chain && (
                <>
                  <ol style={{ listStyle: "none", padding: 0, margin: 0 }}>
                    {chain.items.map((it) => (
                      <li key={it.seq} style={{
                        display: "flex", gap: 10, alignItems: "baseline", padding: "9px 0",
                        borderBottom: "1px solid var(--color-border-tertiary, rgba(0,0,0,0.08))",
                      }}>
                        <span aria-hidden style={{ color: it.verified ? OK : BAD, fontWeight: 500 }}>
                          {it.verified ? "✓" : "✗"}
                        </span>
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, minWidth: 132 }}>{it.type}</span>
                        <span className="muted" style={{ fontSize: 13 }}>{it.summary}</span>
                      </li>
                    ))}
                    {chain.items.length === 0 && (
                      <li className="muted" style={{ padding: "9px 0" }}>{t("无证据项", "No evidence items")}</li>
                    )}
                  </ol>
                  <p style={{ marginTop: 12, fontSize: 13, color: chain.all_verified ? OK : BAD }}>
                    {chain.all_verified
                      ? t("整链验证通过 ✓", "Whole chain verified ✓")
                      : t("⚠ 整链存在未验证项", "⚠ chain has unverified items")}
                  </p>
                </>
              )}
            </div>
          )}
        </div>
      </section>
    </>
  );
}
