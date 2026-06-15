/**
 * GovernanceView — 治理(Phase 5)。读 4c 端点 /governance/policy:从 spine 的
 * governance 事件回放出"当前生效策略"——版本、founder、角色→成员、角色→授权动作。
 * 治理本身是一段签名历史,这里把它呈现成可读的"宪法当前态"。
 */
import { useEffect, useState } from "react";
import { getGovernancePolicy, type GovernancePolicyView } from "../api";
import { useLang } from "../i18n";

const MUTED = "var(--color-text-tertiary, #888)";
const CARD = "1px solid var(--color-border-tertiary, rgba(0,0,0,0.08))";

export function GovernanceView() {
  const { t } = useLang();
  const [pol, setPol] = useState<GovernancePolicyView | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const ac = new AbortController();
    setLoading(true);
    getGovernancePolicy(ac.signal)
      .then(setPol)
      .catch(() => setPol(null))
      .finally(() => setLoading(false));
    return () => ac.abort();
  }, []);

  const roles = pol?.policy.roles ?? {};
  const grants = pol?.policy.grants ?? {};

  return (
    <>
      <aside className="sidebar">
        <div className="sidebar-head">
          <span className="sidebar-title">{t("治理", "Governance")}</span>
        </div>
        <div className="sidebar-list">
          <div style={{ padding: "12px 14px", fontSize: 13 }}>
            <p style={{ margin: "0 0 6px" }}>
              {t("状态", "Status")}:{" "}
              {pol?.established
                ? <span style={{ color: "var(--color-text-success,#1d9e75)" }}>{t("已立宪", "established")}</span>
                : <span className="muted">{t("未立宪", "not established")}</span>}
            </p>
            <p style={{ margin: "0 0 6px", color: MUTED }}>{t("版本", "Version")} v{pol?.version ?? 0}</p>
            {pol?.founder_did && (
              <p style={{ margin: 0, fontFamily: "var(--font-mono)", fontSize: 11, color: MUTED, wordBreak: "break-all" }}>
                {t("创始", "founder")} {pol.founder_did}
              </p>
            )}
          </div>
        </div>
      </aside>

      <section className="main">
        <div className="main-head">
          <p className="main-eyebrow">{t("治理 · 当前策略", "Governance · current policy")}</p>
          <h1 className="main-title">{t("策略", "Policy")}</h1>
          <p className="main-subtitle">
            {t("从 spine 的签名治理历史回放得出;修宪须被当时策略授权。",
              "Replayed from the signed governance history in the spine; amendments must be authorized by the policy in effect.")}
          </p>
        </div>
        <div className="main-body">
          {loading && <p className="muted">{t("加载中…", "Loading…")}</p>}
          {!loading && !pol?.established && (
            <div className="main-empty" style={{ minHeight: 160 }}>
              <p className="muted">{t("本节点尚未立宪(无 governance 事件)。", "This node has no constitution yet (no governance events).")}</p>
            </div>
          )}
          {!loading && pol?.established && (
            <div style={{ padding: "4px 2px", display: "grid", gap: 14 }}>
              <div style={{ border: CARD, borderRadius: 12, padding: 14 }}>
                <h2 style={{ fontSize: 15, margin: "0 0 10px" }}>{t("角色 → 成员", "Roles → members")}</h2>
                {Object.keys(roles).length === 0 && <p className="muted" style={{ fontSize: 13 }}>—</p>}
                {Object.entries(roles).map(([did, rs]) => (
                  <div key={did} style={{ display: "flex", gap: 8, alignItems: "baseline", padding: "5px 0", flexWrap: "wrap" }}>
                    {rs.map((r) => (
                      <span key={r} style={{
                        fontSize: 12, padding: "2px 8px", borderRadius: 6,
                        background: "var(--color-background-secondary, rgba(0,0,0,0.04))",
                      }}>{r}</span>
                    ))}
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: MUTED, wordBreak: "break-all" }}>{did}</span>
                  </div>
                ))}
              </div>

              <div style={{ border: CARD, borderRadius: 12, padding: 14 }}>
                <h2 style={{ fontSize: 15, margin: "0 0 10px" }}>{t("角色 → 授权动作", "Roles → granted actions")}</h2>
                {Object.entries(grants).map(([role, actions]) => (
                  <div key={role} style={{ display: "flex", gap: 8, alignItems: "baseline", padding: "5px 0", flexWrap: "wrap" }}>
                    <span style={{ fontSize: 13, minWidth: 80, fontWeight: 500 }}>{role}</span>
                    {actions.map((a) => (
                      <span key={a} style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: MUTED }}>{a}</span>
                    ))}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </section>
    </>
  );
}
