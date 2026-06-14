/**
 * Chat — minimum-viable conversation surface.
 *
 * Per the AI-driven design philosophy, NTH DAO is not a chat-first
 * tool. But the user still needs a way to:
 *   - Send arbitrary instructions to a helper agent ("draft a
 *     launch announcement, low-key tone please")
 *   - Read replies that aren't structured enough to surface as
 *     Decisions or Mission updates
 *   - Communicate with humans in the DAO when governance asks
 *     for context
 *
 * Layout: 3 columns, like Slack/Discord but slimmer.
 *   Sidebar: conversation list (channels + DMs to agents) with
 *            unread badges
 *   Main:    transcript + composer
 *   Detail:  signature of the most recent agent message + the
 *            participant identity panel
 *
 * Messages from AI agents that were signed via a cap_token carry
 * a "verified" affordance (small {} button) to inspect the
 * receipt. This is the literal manifestation of NTH DAO's "every
 * action is signed" promise inside a chat surface.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { IconChat, IconSend } from "./Icons";
import { SignaturePanel } from "./SignaturePanel";
import { useToast } from "./Toast";
import { useLang } from "../i18n";
import { relativeTimeShort } from "../utils/time";
import type {
  ChatMessage, Conversation, ConversationSummary,
} from "../types-v2";

export interface ChatViewProps {
  conversations: Conversation[];
  messagesByConv: Record<string, ChatMessage[]>;
  /** 温层(切片2b):每会话的签名摘要,展示在消息区顶部。 */
  summariesByConv?: Record<string, ConversationSummary[]>;
  /** 4C:会话级"思考中"态。为 true 时在该会话底部显示三点指示器,
   *  与历史消息解耦——不靠 body 文本判断。 */
  typingByConv?: Record<string, boolean>;
  onSend: (convId: string, body: string) => Promise<void> | void;
  /** Lets the parent hydrate message history when a conversation
   *  becomes active. */
  onConversationSelect?: (convId: string) => Promise<void> | void;
  /** Used by the Agents directory to open a specific agent DM. */
  focusConversationId?: string | null;
  /** Whose perspective is this view rendered from? Used to right-
   *  align messages where sender_id === currentUserId. Defaulted
   *  to "admin" for backwards compat with v1 single-user mock,
   *  but App.tsx now passes the real identity (audit pass#4 fix
   *  I3, 2026-06-10): previously hardcoded comparison `=== "admin"`
   *  styled every non-admin user's own messages as incoming. */
  currentUserId?: string;
}

// (was a local relTime() — moved to ../utils/time, audit M3)

export function ChatView({
  conversations,
  messagesByConv,
  summariesByConv,
  typingByConv,
  onSend,
  onConversationSelect,
  focusConversationId,
  currentUserId = "admin",
}: ChatViewProps) {
  const { t } = useLang();
  const [summariesOpen, setSummariesOpen] = useState(true);
  const sorted = useMemo(
    () => conversations.slice().sort(
      (a, b) => b.last_at.localeCompare(a.last_at),
    ),
    [conversations],
  );

  const [selectedId, setSelectedId] = useState<string | null>(
    sorted[0]?.id ?? null,
  );
  const selected = sorted.find((c) => c.id === selectedId) ?? null;
  const messages = selectedId ? messagesByConv[selectedId] ?? [] : [];
  const summaries = selectedId ? summariesByConv?.[selectedId] ?? [] : [];
  const isTyping = selectedId ? !!typingByConv?.[selectedId] : false;
  // 6C:纤细头部用的展示名 + 头像首字。DM 去掉 "DM: " 前缀,频道保留 #。
  const headName = selected
    ? selected.kind === "dm"
      ? selected.title.replace(/^DM:\s*/i, "")
      : selected.title
    : "";
  const headInitial = headName.replace(/^#/, "").charAt(0).toUpperCase() || "·";

  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const transcriptRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLTextAreaElement | null>(null);

  // 5A:输入框随内容自适应高度(iMessage 行为)。先归零再取 scrollHeight,
  // CSS 的 max-height 负责封顶、超出后内部滚动。依赖 draft,故发送后清空
  // 也会收回一行,切换会话亦然。
  useEffect(() => {
    const el = inputRef.current;
    if (!el) return;
    el.style.height = "auto";
    // border-box 下 scrollHeight 不含 border,直接设会矮 2px → 单行也冒
    // 一条发丝级滚动条。补上 border 高度差(offsetHeight-clientHeight)。
    const border = el.offsetHeight - el.clientHeight;
    el.style.height = `${el.scrollHeight + border}px`;
  }, [draft, selectedId]);
  const toast = useToast();

  useEffect(() => {
    if (
      focusConversationId &&
      conversations.some((c) => c.id === focusConversationId)
    ) {
      setSelectedId(focusConversationId);
    }
  }, [focusConversationId, conversations]);

  useEffect(() => {
    if (!selectedId || !conversations.some((c) => c.id === selectedId)) {
      setSelectedId(sorted[0]?.id ?? null);
    }
  }, [selectedId, conversations, sorted]);

  useEffect(() => {
    if (selectedId) void onConversationSelect?.(selectedId);
  }, [selectedId, onConversationSelect]);

  // Auto-scroll to the bottom when messages change or conversation
  // switches. 依赖里带上最后一条的 body:流式回复时长度不变、只是
  // 内容在增长,若只依赖 length 会在长回复中途"卡住"不跟随。
  const lastBody = messages.length ? messages[messages.length - 1].body : "";
  useEffect(() => {
    const el = transcriptRef.current;
    if (el) el.scrollTop = el.scrollHeight;
    // isTyping 也触发滚动,让底部的三点指示器进入视野。
  }, [selectedId, messages.length, lastBody, isTyping]);

  /* Send handler (audit fix 2026-06-10, finding C4 + review#1):
   *   Original bug: setDraft("") fired BEFORE await onSend(); if
   *   onSend() throws (network error, signing-key unavailable),
   *   the user's typed message disappeared into the void with no
   *   visual signal. Fix: clear the draft optimistically, capture
   *   the body, run onSend inside try/catch. On failure, restore
   *   the draft and emit an error toast so the user can retry.
   *
   *   `doSend()` is the pure mutation; `handleSend()` is the form
   *   binding. Keeping them split avoids a structural type lie
   *   where the same function was called with both FormEvent and
   *   KeyboardEvent. */
  async function doSend() {
    if (!draft.trim() || !selectedId || sending) return;
    const body = draft;
    setDraft("");
    setSending(true);
    try {
      await onSend(selectedId, body);
    } catch (err) {
      // Restore the draft so the user can retry without retyping.
      setDraft(body);
      const msg = err instanceof Error ? err.message : String(err);
      toast.push(`Send failed: ${msg}`, "error");
    } finally {
      setSending(false);
    }
  }

  function handleSend(e: React.FormEvent) {
    e.preventDefault();
    void doSend();
  }

  // Last AI-agent message in the current conversation — the
  // detail rail's "what did the agent just sign" panel.
  const lastAgentMsg = useMemo(() => {
    for (let i = messages.length - 1; i >= 0; i--) {
      const m = messages[i];
      if (m.nth_receipt_id) return m;
    }
    return null;
  }, [messages]);

  return (
    <>
      <aside className="sidebar">
        <div className="sidebar-head">
          <span className="sidebar-title">{t("对话", "Conversations")}</span>
          <span className="sidebar-count">{sorted.length}</span>
        </div>
        <div className="sidebar-list">
          {sorted.map((c) => (
            <button
              key={c.id}
              className={`sidebar-item ${selectedId === c.id ? "active" : ""}`}
              onClick={() => setSelectedId(c.id)}
            >
              <div className="sidebar-item-title">
                <span className="truncate">{c.title}</span>
                {c.unread > 0 && (
                  <span
                    className="pill bad"
                    style={{ marginLeft: "auto", fontSize: 10 }}
                  >
                    {c.unread}
                  </span>
                )}
              </div>
              <div className="sidebar-item-meta">
                <span className="truncate" style={{ flex: 1 }}>
                  {c.last_preview}
                </span>
              </div>
            </button>
          ))}
        </div>
      </aside>

      <section
        className="main"
        style={{ display: "flex", flexDirection: "column" }}
      >
        {/* 6C:iMessage 式纤细头部——头像 + 名字 + 在线点。kind / DID /
            最近活动 / 签名等"可验证"细节都在右侧 detail 栏,这里只留
            最轻的身份锚点。 */}
        <div className="chat-head">
          {selected ? (
            <>
              <div className="chat-head-avatar" aria-hidden="true">
                {headInitial}
              </div>
              <div className="chat-head-meta">
                <h1 className="chat-head-name">{headName}</h1>
                <span className="chat-head-sub">
                  {selected.kind === "dm" ? (
                    <>
                      <span className="chat-presence" aria-hidden="true" />
                      {t("在线", "Online")}
                    </>
                  ) : (
                    t("频道", "Channel")
                  )}
                </span>
              </div>
            </>
          ) : (
            <span className="chat-head-name">{t("选择一个对话", "Select a conversation")}</span>
          )}
        </div>

        {selected ? (
          <>
            <div
              ref={transcriptRef}
              className="chat-thread"
              style={{ flex: 1, overflowY: "auto" }}
            >
              {summaries.length > 0 && (
                <div className="chat-system">
                  <button
                    onClick={() => setSummariesOpen((o) => !o)}
                    className="chat-system-toggle"
                    style={{
                      background: "none",
                      border: "none",
                      cursor: "pointer",
                      font: "inherit",
                      padding: 0,
                    }}
                  >
                    📜 {t("对话摘要", "Summary")} ({summaries.length}) {summariesOpen ? "▾" : "▸"}
                  </button>
                  {summariesOpen &&
                    summaries.map((s, i) => (
                      <div
                        key={`${s.transcript_sha256}-${i}`}
                        style={{ marginTop: 8, textAlign: "left" }}
                      >
                        <div style={{ whiteSpace: "pre-wrap" }}>{s.summary_text}</div>
                        <div style={{ fontSize: 11, marginTop: 4, color: "var(--fg-tertiary)" }}>
                          {s.verified
                            ? t("✓ 已验签", "✓ Verified")
                            : `${t("⚠️ 未验签", "⚠️ Unverified")}(${s.reason})`}{" "}
                          · {t("概括", "covers")}{" "}
                          {s.covered_message_ids.length} {t("条", "msgs")} · signer{" "}
                          {s.agent_did.slice(0, 14)}…
                        </div>
                      </div>
                    ))}
                </div>
              )}
              {messages.length === 0 ? (
                <div className="main-empty" style={{ minHeight: 200 }}>
                  <div className="main-empty-icon">
                    <IconChat size={36} />
                  </div>
                  <p>{t("还没有消息。", "No messages yet.")}</p>
                  <p className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                    {t("在下面开始对话。", "Start the conversation below.")}
                  </p>
                </div>
              ) : (
                messages.map((m, i) => {
                  const isYou = m.sender_id === currentUserId;
                  const prev = messages[i - 1];
                  const next = messages[i + 1];
                  // iMessage 式"成组":同一人、≤5min 内的相邻消息收紧间距
                  // 并贴合圆角,视觉上"连"成一串。
                  const GAP_MS = 5 * 60 * 1000;
                  const tMs = new Date(m.created_at).getTime();
                  const contFromPrev =
                    !!prev &&
                    prev.sender_id === m.sender_id &&
                    tMs - new Date(prev.created_at).getTime() <= GAP_MS;
                  const contToNext =
                    !!next &&
                    next.sender_id === m.sender_id &&
                    new Date(next.created_at).getTime() - tMs <= GAP_MS;
                  // pop-in 只给最新一条:打开会话时不让整段历史一起抖。
                  // 若正在 typing,把 is-last 让给底部的三点行。
                  const isLast = i === messages.length - 1 && !isTyping;
                  const rowClass = [
                    "chat-row",
                    isYou ? "out" : "in",
                    contFromPrev ? "grp-top" : "group-start",
                    contToNext ? "grp-bottom" : "",
                    isLast ? "is-last" : "",
                  ]
                    .filter(Boolean)
                    .join(" ");
                  // 1:1 DM 不显示发送者名(对象明确);频道里才在组首显示。
                  const showName =
                    !isYou && !contFromPrev && selected.kind !== "dm";
                  return (
                    <div key={m.message_id} className={rowClass}>
                      <div className="chat-col">
                        {showName && <div className="chat-name">{m.sender_label}</div>}
                        <div className="chat-bubble">{m.body}</div>
                        {m.nth_receipt_id && (
                          <div
                            className="chat-receipt"
                            title="Signed via authorizing cap_token"
                          >
                            ✓ receipt {m.nth_receipt_id.slice(0, 12)}…
                          </div>
                        )}
                        <span className="chat-time">
                          {relativeTimeShort(m.created_at)}
                        </span>
                      </div>
                    </div>
                  );
                })
              )}
              {isTyping && (
                <div className="chat-row in is-last" aria-live="polite">
                  <div className="chat-col">
                    <div className="chat-bubble">
                      <span className="typing-dots" aria-label={t("对方正在输入", "typing")}>
                        <span />
                        <span />
                        <span />
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            <form onSubmit={handleSend} className="chat-composer">
              <textarea
                ref={inputRef}
                className="chat-input"
                rows={1}
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    void doSend();
                  }
                }}
                placeholder={`${t("发消息给", "Message")} ${selected.title}…`}
              />
              <button
                type="submit"
                className="chat-send"
                disabled={!draft.trim() || sending}
                aria-label={sending ? t("发送中", "Sending message") : t("发送", "Send message")}
              >
                <IconSend size={16} />
              </button>
            </form>
          </>
        ) : (
          <div className="main-body">
            <div className="main-empty" style={{ minHeight: 200 }}>
              <div className="main-empty-icon">
                <IconChat size={36} />
              </div>
              <p>{t("未选择对话。", "No conversation selected.")}</p>
            </div>
          </div>
        )}
      </section>

      <aside className="detail">
        <div className="detail-head">
          <span className="detail-title">{t("已签名材料", "Signed material")}</span>
        </div>
        <div className="detail-body">
          {selected ? (
            <>
              <div className="detail-section">
                <div className="detail-section-label">{t("对话", "Conversation")}</div>
                <div className="detail-row">
                  <span className="key">{t("类型", "Kind")}</span>
                  <span className="value">{selected.kind}</span>
                </div>
                <div className="detail-row">
                  <span className="key">{t("最近活动", "Last activity")}</span>
                  <span className="value">
                    {new Date(selected.last_at).toLocaleString()}
                  </span>
                </div>
                <div className="detail-row">
                  <span className="key">{t("未读", "Unread")}</span>
                  <span className="value">{selected.unread}</span>
                </div>
              </div>
              {lastAgentMsg && lastAgentMsg.nth_receipt_id ? (
                <SignaturePanel
                  value={{
                    receipt_id: lastAgentMsg.nth_receipt_id,
                    signer_label: lastAgentMsg.sender_label,
                    signer_id: lastAgentMsg.sender_id,
                    message_id: lastAgentMsg.message_id,
                    body: lastAgentMsg.body,
                    issued_at: lastAgentMsg.created_at,
                  }}
                  title={t("本对话最近一条已签名消息", "Last signed message in this conversation")}
                />
              ) : (
                <p className="muted" style={{ fontSize: 12 }}>
                  {t(
                    "本对话还没有已签名的消息。当有授权 cap_token 在作用域内时,agent 的回复会被签名。",
                    "No signed messages in this conversation yet. Agent replies are signed when an authorizing cap_token is in scope.",
                  )}
                </p>
              )}
            </>
          ) : (
            <p className="muted">Select a conversation.</p>
          )}
        </div>
      </aside>
    </>
  );
}
