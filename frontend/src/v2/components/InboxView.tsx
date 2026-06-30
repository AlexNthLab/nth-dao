/**
 * InboxView — 统一「待办」(Step②)。AI-first 下人的首屏中枢:把所有"需要你拍板
 * 的事"收成**一个**列表,而非散在 Decisions / Delegate 两个收件箱。
 *
 * 三类混排:
 *   - 决策(Decision):agent 请求批准某动作 → 批准 / 拒绝 / 稍后(走 App 传入的
 *     handler,/api/v2/decisions)。
 *   - 授权请求(cap.request):agent 求能力 → 批准签发 cap_token / 拒绝(spine 真数据)。
 *   - 待裁争议(dispute open):只读提醒,前往「审计」看证据链。
 *
 * 决策走父级传入的 props;授权 / 争议自取数(spine 投影)。
 */
import { useEffect, useState } from "react";
import {
  approveCapRequest,
  blockDid,
  denyCapRequest,
  fetchSocialMe,
  friendAccept,
  friendDecline,
  listCapRequests,
  listDisputes,
  type CapRequestSummary,
  type DisputeSummary,
} from "../api";
import type { Decision } from "../types-v2";
import { useLang } from "../i18n";
import { useToast } from "./Toast";

const MUTED = "var(--color-text-tertiary, #888)";
const CARD = "1px solid var(--color-border-tertiary, rgba(0,0,0,0.08))";
const OK = "var(--color-text-success, #1d9e75)";
const BAD = "var(--color-text-danger, #e24b4a)";

type InboxItem =
  | { kind: "decision"; key: string; title: string; data: Decision }
  | { kind: "cap"; key: string; title: string; data: CapRequestSummary }
  | { kind: "dispute"; key: string; title: string; data: DisputeSummary }
  | { kind: "friend"; key: string; title: string; data: { did: string } };

export interface InboxViewProps {
  decisions: Decision[];
  onApprove: (id: string) => Promise<void> | void;
  onReject: (id: string) => Promise<void> | void;
  onDefer: (id: string) => Promise<void> | void;
  resolvingIds: Set<string>;
}

function chip(tone: string, text: string) {
  return (
    <span style={{
      fontSize: 11, padding: "2px 7px", borderRadius: 999,
      border: `1px solid ${tone}`, color: tone, whiteSpace: "nowrap",
    }}>{text}</span>
  );
}

export function InboxView(props: InboxViewProps) {
  const { decisions, onApprove, onReject, onDefer, resolvingIds } = props;
  const { t } = useLang();
  const toast = useToast();
  const [caps, setCaps] = useState<CapRequestSummary[]>([]);
  const [disputes, setDisputes] = useState<DisputeSummary[]>([]);
  const [friendReqs, setFriendReqs] = useState<string[]>([]);
  const [selKey, setSelKey] = useState<string>("");
  const [busy, setBusy] = useState("");
  const [reload, setReload] = useState(0);

  useEffect(() => {
    const ac = new AbortController();
    Promise.allSettled([
      listCapRequests(ac.signal), listDisputes(ac.signal), fetchSocialMe(ac.signal),
    ]).then(([c, d, s]) => {
      if (c.status === "fulfilled") setCaps(c.value);
      if (d.status === "fulfilled") setDisputes(d.value);
      if (s.status === "fulfilled") setFriendReqs(s.value.pending_incoming ?? []);
    });
    return () => ac.abort();
  }, [reload]);

  const items: InboxItem[] = [
    ...decisions.map((d): InboxItem => ({
      kind: "decision", key: `decision:${d.id}`, title: d.title, data: d })),
    ...caps.filter((c) => c.status === "pending").map((c): InboxItem => ({
      kind: "cap", key: `cap:${c.request_id}`,
      title: `${t("授权", "Grant")}: ${c.capabilities.join(", ")}`, data: c })),
    ...disputes.filter((x) => x.status === "open").map((x): InboxItem => ({
      kind: "dispute", key: `dispute:${x.dispute_id}`,
      title: `${t("争议", "Dispute")}: ${x.announcement_id.slice(0, 12)}…`, data: x })),
    ...friendReqs.map((did): InboxItem => ({
      kind: "friend", key: `friend:${did}`,
      title: `${t("好友请求", "Friend request")}: ${did.slice(0, 16)}…`, data: { did } })),
  ];
  const sel = items.find((i) => i.key === selKey) ?? items[0];

  async function capAct(id: string, kind: "approve" | "deny") {
    setBusy(id);
    try {
      if (kind === "approve") {
        const r = await approveCapRequest(id);
        toast.push(`${t("已批准 · 签发令牌", "Approved · token issued")} ${r.token_id.slice(0, 8)}`, "success");
      } else {
        await denyCapRequest(id, "");
        toast.push(t("已拒绝", "Denied"), "info");
      }
      setSelKey("");
      setReload((n) => n + 1);
    } catch {
      toast.push(t("操作失败 —— 需要写入令牌(右下角设置)", "Action failed — needs a write token"), "error");
    } finally {
      setBusy("");
    }
  }

  async function friendAct(did: string, kind: "accept" | "decline" | "block") {
    setBusy(did);
    try {
      if (kind === "accept") {
        await friendAccept(did);
        toast.push(t("已成为好友", "Now friends"), "success");
      } else if (kind === "block") {
        await blockDid(did);
        toast.push(t("已屏蔽", "Blocked"), "info");
      } else {
        await friendDecline(did);
        toast.push(t("已拒绝", "Declined"), "info");
      }
      setSelKey("");
      setReload((n) => n + 1);
    } catch {
      toast.push(t("操作失败 —— 需要写入令牌(右下角设置)", "Action failed — needs a write token"), "error");
    } finally {
      setBusy("");
    }
  }

  return (
    <>
      <aside className="sidebar">
        <div className="sidebar-head">
          <span className="sidebar-title">{t("待办", "Inbox")}</span>
          <span className="muted" style={{ fontSize: 12 }}>{items.length}</span>
        </div>
        <div className="sidebar-list">
          {items.length === 0 && (
            <p className="muted" style={{ padding: "12px 14px" }}>{t("没有待办 —— 一切就绪。", "Nothing pending — all clear.")}</p>
          )}
          {items.map((it) => (
            <button
              key={it.key}
              onClick={() => setSelKey(it.key)}
              style={{
                display: "flex", flexDirection: "column", gap: 4, width: "100%",
                textAlign: "left", padding: "10px 14px", cursor: "pointer",
                background: sel?.key === it.key ? "var(--color-background-secondary, rgba(0,0,0,0.04))" : "transparent",
                border: "none", borderBottom: CARD, color: "inherit",
              }}
            >
              <span style={{ display: "flex", gap: 6, alignItems: "center" }}>
                {it.kind === "decision" && chip("var(--color-text-info,#378add)", t("决策", "Decision"))}
                {it.kind === "cap" && chip("var(--color-text-warning,#ba7517)", t("授权", "Grant"))}
                {it.kind === "dispute" && chip(BAD, t("争议", "Dispute"))}
                {it.kind === "friend" && chip("var(--color-text-info,#378add)", t("好友", "Friend"))}
              </span>
              <span style={{ fontSize: 13, overflow: "hidden", textOverflow: "ellipsis" }}>{it.title}</span>
            </button>
          ))}
        </div>
      </aside>

      <section className="main">
        <div className="main-head">
          <p className="main-eyebrow">{t("待办 · 需要你拍板", "Inbox · needs your call")}</p>
          <h1 className="main-title">{t("待办", "Inbox")}</h1>
          <p className="main-subtitle">
            {t("决策、授权请求、待裁争议 —— 都在这一个地方。",
              "Decisions, authorization requests, open disputes — all in one place.")}
          </p>
        </div>
        <div className="main-body">
          {!sel && (
            <div className="main-empty" style={{ minHeight: 160 }}>
              <p className="muted">{t("没有待办。", "Nothing pending.")}</p>
            </div>
          )}

          {sel?.kind === "decision" && (
            <div style={{ border: CARD, borderRadius: 12, padding: 16 }}>
              <h2 style={{ fontSize: 16, margin: "0 0 8px" }}>{sel.data.title}</h2>
              <p style={{ margin: "0 0 8px", fontSize: 14 }}>{sel.data.rationale}</p>
              <p style={{ margin: "0 0 14px", fontSize: 12, color: MUTED }}>
                {t("提案者", "Proposer")}: {sel.data.proposer_label} · {t("影响", "impact")}: {sel.data.impact}
              </p>
              <div style={{ display: "flex", gap: 8 }}>
                <button disabled={resolvingIds.has(sel.data.id)} onClick={() => onApprove(sel.data.id)}
                  style={{ fontSize: 13, padding: "7px 14px", borderRadius: 8, cursor: "pointer", border: `1px solid ${OK}`, background: "var(--color-background-success, rgba(29,158,117,0.1))", color: OK }}>
                  {t("批准", "Approve")}
                </button>
                <button disabled={resolvingIds.has(sel.data.id)} onClick={() => onReject(sel.data.id)}
                  style={{ fontSize: 13, padding: "7px 14px", borderRadius: 8, cursor: "pointer", border: `1px solid ${BAD}`, background: "transparent", color: BAD }}>
                  {t("拒绝", "Reject")}
                </button>
                <button disabled={resolvingIds.has(sel.data.id)} onClick={() => onDefer(sel.data.id)}
                  style={{ fontSize: 13, padding: "7px 14px", borderRadius: 8, cursor: "pointer", border: CARD, background: "transparent", color: MUTED }}>
                  {t("稍后", "Defer")}
                </button>
              </div>
            </div>
          )}

          {sel?.kind === "cap" && (
            <div style={{ border: CARD, borderRadius: 12, padding: 16 }}>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 10 }}>
                <span style={{ fontSize: 14 }}>{t("请求能力", "Requests")}</span>
                {sel.data.capabilities.map((c) => (
                  <span key={c} style={{ fontSize: 12, padding: "2px 8px", borderRadius: 6, background: "var(--color-background-secondary, rgba(0,0,0,0.04))", fontFamily: "var(--font-mono)" }}>{c}</span>
                ))}
              </div>
              {sel.data.reason && <p style={{ margin: "0 0 8px", fontSize: 13 }}>{t("理由", "Reason")}: {sel.data.reason}</p>}
              <p style={{ margin: "0 0 14px", fontFamily: "var(--font-mono)", fontSize: 11, color: MUTED, wordBreak: "break-all" }}>
                {t("申请者", "requester")} {sel.data.requester_did}
              </p>
              <div style={{ display: "flex", gap: 8 }}>
                <button disabled={busy === sel.data.request_id} onClick={() => capAct(sel.data.request_id, "approve")}
                  style={{ fontSize: 13, padding: "7px 14px", borderRadius: 8, cursor: "pointer", border: `1px solid ${OK}`, background: "var(--color-background-success, rgba(29,158,117,0.1))", color: OK }}>
                  {t("批准", "Approve")}
                </button>
                <button disabled={busy === sel.data.request_id} onClick={() => capAct(sel.data.request_id, "deny")}
                  style={{ fontSize: 13, padding: "7px 14px", borderRadius: 8, cursor: "pointer", border: `1px solid ${BAD}`, background: "transparent", color: BAD }}>
                  {t("拒绝", "Deny")}
                </button>
              </div>
            </div>
          )}

          {sel?.kind === "dispute" && (
            <div style={{ border: CARD, borderRadius: 12, padding: 16 }}>
              <div style={{ marginBottom: 10 }}>{chip(BAD, t("争议进行中", "open dispute"))}</div>
              <p style={{ margin: "0 0 8px", fontFamily: "var(--font-mono)", fontSize: 12, color: MUTED, wordBreak: "break-all" }}>
                {t("公告", "announcement")} {sel.data.announcement_id}
              </p>
              <p className="muted" style={{ fontSize: 13 }}>
                {t("到「审计」查看完整证据链并裁决。", "Open Audit to replay the full evidence chain and resolve.")}
              </p>
            </div>
          )}

          {sel?.kind === "friend" && (
            <div style={{ border: CARD, borderRadius: 12, padding: 16 }}>
              <div style={{ marginBottom: 10 }}>{chip("var(--color-text-info,#378add)", t("好友请求", "friend request"))}</div>
              <p style={{ margin: "0 0 14px", fontFamily: "var(--font-mono)", fontSize: 11, color: MUTED, wordBreak: "break-all" }}>
                {sel.data.did}
              </p>
              <p className="muted" style={{ margin: "0 0 14px", fontSize: 13 }}>
                {t("接受后双方互为好友(双方签名,任一方可解除)。", "Accepting makes you mutual friends (both signed; either side can remove).")}
              </p>
              <div style={{ display: "flex", gap: 8 }}>
                <button disabled={busy === sel.data.did} onClick={() => friendAct(sel.data.did, "accept")}
                  style={{ fontSize: 13, padding: "7px 14px", borderRadius: 8, cursor: "pointer", border: `1px solid ${OK}`, background: "var(--color-background-success, rgba(29,158,117,0.1))", color: OK }}>
                  {t("接受", "Accept")}
                </button>
                <button disabled={busy === sel.data.did} onClick={() => friendAct(sel.data.did, "decline")}
                  style={{ fontSize: 13, padding: "7px 14px", borderRadius: 8, cursor: "pointer", border: `1px solid ${BAD}`, background: "transparent", color: BAD }}>
                  {t("拒绝", "Decline")}
                </button>
                <button disabled={busy === sel.data.did} onClick={() => friendAct(sel.data.did, "block")}
                  style={{ fontSize: 13, padding: "7px 14px", borderRadius: 8, cursor: "pointer", border: `1px solid ${MUTED}`, background: "transparent", color: MUTED }}>
                  {t("屏蔽", "Block")}
                </button>
              </div>
            </div>
          )}
        </div>
      </section>
    </>
  );
}
