/**
 * ContactsView — 社交名册(Phase 社交)。关注(单向、免确认)+ 好友(双向、需对方
 * 确认)的不对称社交层。消费 /api/v2/social/*:
 *   - 粘 DID → 关注 / 发好友请求
 *   - 好友 / 关注中 / 粉丝 / 已发送(待对方确认)分区列出 + 行内动作
 * 待我确认的好友请求(pending_incoming)在统一「待办」里 accept/decline,这里也
 * 镜像一份方便就地处理。所有关系都是 spine 上的签名声明,非中心、可复算。
 */
import { useCallback, useEffect, useState } from "react";
import {
  fetchSocialMe,
  followDid,
  friendAccept,
  friendDecline,
  friendRemove,
  friendRequest,
  unfollowDid,
  type SocialRoster,
} from "../api";
import { useLang } from "../i18n";
import { useToast } from "./Toast";

const MUTED = "var(--color-text-tertiary, #888)";
const CARD = "1px solid var(--color-border-tertiary, rgba(0,0,0,0.08))";
const OK = "var(--color-text-success, #1d9e75)";
const BAD = "var(--color-text-danger, #e24b4a)";
const INFO = "var(--color-text-info, #378add)";

const EMPTY: SocialRoster = {
  did: "", following: [], followers: [], friends: [],
  pending_incoming: [], pending_outgoing: [],
};

function didShort(did: string): string {
  return did.length > 26 ? `${did.slice(0, 18)}…${did.slice(-6)}` : did;
}

export function ContactsView() {
  const { t } = useLang();
  const toast = useToast();
  const [roster, setRoster] = useState<SocialRoster>(EMPTY);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState("");
  const [reload, setReload] = useState(0);

  useEffect(() => {
    const ac = new AbortController();
    fetchSocialMe(ac.signal).then(setRoster).catch(() => setRoster(EMPTY));
    return () => ac.abort();
  }, [reload]);

  const act = useCallback(
    async (key: string, label: string, fn: () => Promise<unknown>) => {
      setBusy(key);
      try {
        await fn();
        toast.push(`${label} ✓`, "success");
        setReload((n) => n + 1);
      } catch {
        toast.push(
          t("操作失败 —— 需要写入令牌(右下角设置)", "Action failed — needs a write token"),
          "error",
        );
      } finally {
        setBusy("");
      }
    },
    [toast, t],
  );

  function addBy(kind: "follow" | "friend") {
    const did = draft.trim();
    if (!did) return;
    if (did === roster.did) {
      toast.push(t("不能关注/加自己", "Can't follow/friend yourself"), "error");
      return;
    }
    const label = kind === "follow" ? t("已关注", "Followed") : t("已发出好友请求", "Friend request sent");
    void act(`add:${did}`, label, () =>
      (kind === "follow" ? followDid(did) : friendRequest(did))).then(() => setDraft(""));
  }

  function row(did: string, actions: React.ReactNode) {
    return (
      <div key={did} style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        gap: 10, padding: "9px 12px", borderBottom: CARD,
      }}>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, wordBreak: "break-all" }}>
          {didShort(did)}
        </span>
        <span style={{ display: "flex", gap: 6, flexShrink: 0 }}>{actions}</span>
      </div>
    );
  }

  function btn(text: string, tone: string, key: string, onClick: () => void) {
    return (
      <button disabled={busy === key} onClick={onClick} style={{
        fontSize: 12, padding: "4px 10px", borderRadius: 7, cursor: "pointer",
        border: `1px solid ${tone}`, background: "transparent", color: tone,
        opacity: busy === key ? 0.5 : 1,
      }}>{text}</button>
    );
  }

  function section(title: string, hint: string, dids: string[], render: (d: string) => React.ReactNode) {
    return (
      <div style={{ marginBottom: 22 }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 6 }}>
          <h2 style={{ fontSize: 14, margin: 0 }}>{title}</h2>
          <span style={{ fontSize: 12, color: MUTED }}>{dids.length}</span>
        </div>
        {dids.length === 0
          ? <p className="muted" style={{ fontSize: 13, margin: "2px 0 0" }}>{hint}</p>
          : <div style={{ border: CARD, borderRadius: 10, overflow: "hidden" }}>{dids.map(render)}</div>}
      </div>
    );
  }

  const counts = `${roster.friends.length} ${t("好友", "friends")} · ${roster.following.length} ${t("关注", "following")} · ${roster.followers.length} ${t("粉丝", "followers")}`;

  return (
    <>
      <aside className="sidebar">
        <div className="sidebar-head">
          <span className="sidebar-title">{t("联系人", "Contacts")}</span>
          <span className="muted" style={{ fontSize: 12 }}>{roster.friends.length}</span>
        </div>
        <div className="sidebar-list">
          <p className="muted" style={{ padding: "12px 14px", fontSize: 13, lineHeight: 1.6 }}>
            {t("关注是单向的(对方无需同意);成为好友需要对方确认。所有关系都是 spine 上的签名声明 —— 谁是谁好友无法单方伪造。",
              "Following is one-way (no confirmation needed); becoming friends needs the other side to accept. Every relationship is a signed statement on the spine — no one can forge a friendship single-handedly.")}
          </p>
        </div>
      </aside>

      <section className="main">
        <div className="main-head">
          <p className="main-eyebrow">{t("联系人 · 社交图", "Contacts · social graph")}</p>
          <h1 className="main-title">{t("联系人", "Contacts")}</h1>
          <p className="main-subtitle">{counts}</p>
        </div>
        <div className="main-body">
          {/* 粘 DID 添加 */}
          <div style={{ display: "flex", gap: 8, marginBottom: 20, flexWrap: "wrap" }}>
            <input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder={t("粘贴对方 DID（did:key:…）", "Paste a DID (did:key:…)")}
              style={{
                flex: "1 1 320px", minWidth: 220, fontSize: 13, padding: "8px 11px",
                borderRadius: 8, border: CARD, background: "transparent",
                color: "inherit", fontFamily: "var(--font-mono)",
              }}
            />
            {btn(t("＋ 关注", "＋ Follow"), INFO, `add:${draft.trim()}`, () => addBy("follow"))}
            {btn(t("＋ 加好友", "＋ Add friend"), OK, `add:${draft.trim()}`, () => addBy("friend"))}
          </div>

          {section(
            t("好友", "Friends"),
            t("还没有好友。发出请求并等对方确认。", "No friends yet. Send a request and wait for them to accept."),
            roster.friends,
            (d) => row(d, btn(t("解除", "Remove"), BAD, `rm:${d}`,
              () => void act(`rm:${d}`, t("已解除好友", "Unfriended"), () => friendRemove(d)))),
          )}

          {section(
            t("待我确认", "Pending — your call"),
            t("没有待确认的好友请求。", "No incoming friend requests."),
            roster.pending_incoming,
            (d) => row(d, <>
              {btn(t("接受", "Accept"), OK, `ac:${d}`,
                () => void act(`ac:${d}`, t("已成为好友", "Now friends"), () => friendAccept(d)))}
              {btn(t("拒绝", "Decline"), BAD, `de:${d}`,
                () => void act(`de:${d}`, t("已拒绝", "Declined"), () => friendDecline(d)))}
            </>),
          )}

          {section(
            t("已发送（待对方确认）", "Sent (awaiting accept)"),
            t("没有待对方确认的请求。", "No outgoing requests pending."),
            roster.pending_outgoing,
            (d) => row(d, btn(t("撤回", "Withdraw"), MUTED, `rm:${d}`,
              () => void act(`rm:${d}`, t("已撤回", "Withdrawn"), () => friendRemove(d)))),
          )}

          {section(
            t("关注中", "Following"),
            t("还没关注任何人。粘 DID 关注强者。", "Not following anyone yet. Paste a DID to follow."),
            roster.following,
            (d) => row(d, btn(t("取消关注", "Unfollow"), MUTED, `uf:${d}`,
              () => void act(`uf:${d}`, t("已取消关注", "Unfollowed"), () => unfollowDid(d)))),
          )}

          {section(
            t("粉丝", "Followers"),
            t("还没有粉丝。", "No followers yet."),
            roster.followers,
            (d) => row(d, roster.friends.includes(d)
              ? <span style={{ fontSize: 12, color: OK }}>{t("已是好友", "friend")}</span>
              : btn(t("加好友", "Add friend"), OK, `fr:${d}`,
                () => void act(`fr:${d}`, t("已发出好友请求", "Friend request sent"), () => friendRequest(d)))),
          )}
        </div>
      </section>
    </>
  );
}
