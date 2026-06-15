/**
 * DelegateView — 授权收件箱(consent 层 / Phase 5)。愿景旗舰 UX:把"Agent 想要
 * 什么能力、人批准了什么"变成可见、可控、可回溯的界面。
 *
 * 待批请求:展示申请者 DID、请求的能力(精确切片)、理由 → 一键批准(本节点签发
 * cap_token)/ 拒绝。已决:状态 + 决策者 + 令牌 id(不含 bearer 全文)。
 * 消费 /cap-requests 读 + /approve、/deny 写(token-gated,postJson 自带 Bearer)。
 */
import { useEffect, useState } from "react";
import {
  approveCapRequest,
  denyCapRequest,
  listCapRequests,
  type CapRequestSummary,
} from "../api";
import { useLang } from "../i18n";
import { useToast } from "./Toast";

const MUTED = "var(--color-text-tertiary, #888)";
const CARD = "1px solid var(--color-border-tertiary, rgba(0,0,0,0.08))";

function Chip({ children }: { children: React.ReactNode }) {
  return (
    <span style={{
      fontSize: 12, padding: "2px 8px", borderRadius: 6,
      background: "var(--color-background-secondary, rgba(0,0,0,0.04))",
      fontFamily: "var(--font-mono)",
    }}>{children}</span>
  );
}

export function DelegateView() {
  const { t } = useLang();
  const toast = useToast();
  const [reqs, setReqs] = useState<CapRequestSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [busyId, setBusyId] = useState("");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const ac = new AbortController();
    setLoading(true);
    listCapRequests(ac.signal)
      .then(setReqs)
      .catch(() => setReqs([]))
      .finally(() => setLoading(false));
    return () => ac.abort();
  }, [reloadKey]);

  const pending = reqs.filter((r) => r.status === "pending");
  const decided = reqs.filter((r) => r.status !== "pending");

  async function act(id: string, kind: "approve" | "deny") {
    setBusyId(id);
    try {
      if (kind === "approve") {
        const r = await approveCapRequest(id);
        toast.push(
          `${t("已批准 · 签发令牌", "Approved · token issued")} ${r.token_id.slice(0, 8)}`,
          "success");
      } else {
        await denyCapRequest(id, "");
        toast.push(t("已拒绝", "Denied"), "info");
      }
      setReloadKey((k) => k + 1);
    } catch {
      toast.push(
        t("操作失败 —— 需要写入令牌(右下角设置)",
          "Action failed — needs a write token (set it bottom-right)"),
        "error");
    } finally {
      setBusyId("");
    }
  }

  return (
    <>
      <aside className="sidebar">
        <div className="sidebar-head">
          <span className="sidebar-title">{t("授权收件箱", "Authorization inbox")}</span>
          <span className="muted" style={{ fontSize: 12 }}>{pending.length}</span>
        </div>
        <div className="sidebar-list">
          <p className="muted" style={{ padding: "12px 14px", fontSize: 13, lineHeight: 1.6 }}>
            {t("Agent 请求能力,你在这里逐项批准或拒绝。批准即由本节点签发精确切片的 cap_token,全程记入 spine、可审计。",
              "Agents request capabilities; you approve or deny each. Approval issues a narrowly-scoped cap_token signed by this node — recorded in the spine, fully auditable.")}
          </p>
        </div>
      </aside>

      <section className="main">
        <div className="main-head">
          <p className="main-eyebrow">{t("授权 · 人在环上", "Authorization · human in the loop")}</p>
          <h1 className="main-title">{t("授权收件箱", "Authorization inbox")}</h1>
          <p className="main-subtitle">
            {t("每个 Agent 动作背后的能力,都由你显式授予。",
              "Every capability behind an agent action is something you explicitly grant.")}
          </p>
        </div>
        <div className="main-body">
          {loading && <p className="muted">{t("加载中…", "Loading…")}</p>}

          {!loading && pending.length === 0 && (
            <div className="main-empty" style={{ minHeight: 140 }}>
              <p className="muted">{t("没有待批请求。", "No pending requests.")}</p>
            </div>
          )}

          {pending.map((r) => (
            <div key={r.request_id} style={{ border: CARD, borderRadius: 12, padding: 14, marginBottom: 12 }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 8 }}>
                <span style={{ fontSize: 14 }}>{t("请求能力", "Requests")}</span>
                {r.capabilities.map((c) => <Chip key={c}>{c}</Chip>)}
              </div>
              {r.reason && (
                <p style={{ margin: "0 0 8px", fontSize: 13 }}>{t("理由", "Reason")}: {r.reason}</p>
              )}
              <p style={{ margin: "0 0 12px", fontFamily: "var(--font-mono)", fontSize: 11, color: MUTED, wordBreak: "break-all" }}>
                {t("申请者", "requester")} {r.requester_did}
              </p>
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  disabled={busyId === r.request_id}
                  onClick={() => act(r.request_id, "approve")}
                  style={{
                    fontSize: 13, padding: "7px 14px", borderRadius: 8, cursor: "pointer",
                    border: "1px solid var(--color-border-success, #1d9e75)",
                    background: "var(--color-background-success, rgba(29,158,117,0.1))",
                    color: "var(--color-text-success, #1d9e75)",
                  }}>
                  {t("批准", "Approve")}
                </button>
                <button
                  disabled={busyId === r.request_id}
                  onClick={() => act(r.request_id, "deny")}
                  style={{
                    fontSize: 13, padding: "7px 14px", borderRadius: 8, cursor: "pointer",
                    border: "1px solid var(--color-border-danger, #e24b4a)",
                    background: "transparent", color: "var(--color-text-danger, #e24b4a)",
                  }}>
                  {t("拒绝", "Deny")}
                </button>
              </div>
            </div>
          ))}

          {decided.length > 0 && (
            <div style={{ marginTop: 18 }}>
              <h2 style={{ fontSize: 15, margin: "0 0 10px", color: MUTED }}>{t("已决", "Decided")}</h2>
              {decided.map((r) => (
                <div key={r.request_id} style={{
                  display: "flex", gap: 10, alignItems: "baseline", padding: "8px 0",
                  borderBottom: CARD, flexWrap: "wrap",
                }}>
                  <span style={{
                    fontSize: 12, padding: "2px 8px", borderRadius: 999,
                    color: r.status === "granted" ? "var(--color-text-success,#1d9e75)" : "var(--color-text-danger,#e24b4a)",
                    border: `1px solid ${r.status === "granted" ? "var(--color-text-success,#1d9e75)" : "var(--color-text-danger,#e24b4a)"}`,
                  }}>
                    {r.status === "granted" ? t("已批准", "granted") : t("已拒绝", "denied")}
                  </span>
                  <span style={{ fontSize: 13 }}>{r.capabilities.join(", ")}</span>
                  {r.token_id && (
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: MUTED }}>
                      token {r.token_id.slice(0, 10)}
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </section>
    </>
  );
}
