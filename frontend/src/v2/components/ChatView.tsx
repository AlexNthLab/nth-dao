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
import { relativeTimeShort } from "../utils/time";
import type { ChatMessage, Conversation } from "../types-v2";

export interface ChatViewProps {
  conversations: Conversation[];
  messagesByConv: Record<string, ChatMessage[]>;
  /** Wired to /api/messages once backend integration lands. The
   *  v2 implementation drops the message into local state for now. */
  onSend: (convId: string, body: string) => Promise<void> | void;
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
  conversations, messagesByConv, onSend, currentUserId = "admin",
}: ChatViewProps) {
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

  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const transcriptRef = useRef<HTMLDivElement | null>(null);
  const toast = useToast();

  // Auto-scroll to the bottom when messages change or conversation
  // switches. Behaviour matches every chat app users know.
  useEffect(() => {
    const el = transcriptRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [selectedId, messages.length]);

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
          <span className="sidebar-title">Conversations</span>
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
        <div className="main-head" style={{ position: "static" }}>
          {selected ? (
            <>
              <p className="main-eyebrow">
                {selected.kind === "dm" ? "Direct message" : "Channel"}
              </p>
              <h1 className="main-title">{selected.title}</h1>
              <p className="main-subtitle">{selected.subtitle}</p>
            </>
          ) : (
            <>
              <p className="main-eyebrow">Chat</p>
              <h1 className="main-title">Pick a conversation</h1>
            </>
          )}
        </div>

        {selected ? (
          <>
            <div
              ref={transcriptRef}
              style={{
                flex: 1,
                overflowY: "auto",
                padding: "16px 32px",
              }}
            >
              {messages.length === 0 ? (
                <div className="main-empty" style={{ minHeight: 200 }}>
                  <div className="main-empty-icon">
                    <IconChat size={36} />
                  </div>
                  <p>No messages yet.</p>
                  <p className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                    Start the conversation below.
                  </p>
                </div>
              ) : (
                <div className="stack" style={{ gap: 16 }}>
                  {messages.map((m) => {
                    const isYou = m.sender_id === currentUserId;
                    return (
                      <article
                        key={m.message_id}
                        style={{
                          maxWidth: "70%",
                          marginLeft: isYou ? "auto" : 0,
                          background: isYou
                            ? "var(--accent-muted)"
                            : "var(--bg-panel)",
                          border: "1px solid var(--border)",
                          borderRadius: "var(--r-md)",
                          padding: "10px 14px",
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "space-between",
                            gap: 12,
                            marginBottom: 4,
                            fontSize: 11,
                            color: "var(--fg-tertiary)",
                          }}
                        >
                          <strong
                            style={{
                              color: isYou
                                ? "var(--accent)"
                                : "var(--fg-primary)",
                              fontWeight: 500,
                              fontSize: 12,
                            }}
                          >
                            {m.sender_label}
                          </strong>
                          <span>{relativeTimeShort(m.created_at)}</span>
                        </div>
                        <p
                          style={{
                            margin: 0,
                            fontSize: 13,
                            lineHeight: 1.55,
                            color: "var(--fg-primary)",
                          }}
                        >
                          {m.body}
                        </p>
                        {m.nth_receipt_id && (
                          <div
                            style={{
                              marginTop: 6,
                              fontSize: 10,
                              color: "var(--fg-tertiary)",
                              fontFamily: "var(--t-mono)",
                            }}
                            title="Signed via authorizing cap_token"
                          >
                            ✓ receipt {m.nth_receipt_id.slice(0, 12)}…
                          </div>
                        )}
                      </article>
                    );
                  })}
                </div>
              )}
            </div>

            <form
              onSubmit={handleSend}
              style={{
                padding: "12px 32px 20px",
                borderTop: "1px solid var(--border)",
                display: "flex",
                gap: 8,
                alignItems: "flex-end",
              }}
            >
              <textarea
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    void doSend();
                  }
                }}
                placeholder={`Message ${selected.title}…`}
                style={{
                  flex: 1,
                  minHeight: 42,
                  maxHeight: 160,
                  resize: "vertical",
                }}
              />
              <button
                type="submit"
                className="btn btn-primary"
                disabled={!draft.trim() || sending}
                aria-label={sending ? "Sending message" : "Send message"}
              >
                <IconSend size={14} /> {sending ? "Sending…" : "Send"}
              </button>
            </form>
          </>
        ) : (
          <div className="main-body">
            <div className="main-empty" style={{ minHeight: 200 }}>
              <div className="main-empty-icon">
                <IconChat size={36} />
              </div>
              <p>No conversation selected.</p>
            </div>
          </div>
        )}
      </section>

      <aside className="detail">
        <div className="detail-head">
          <span className="detail-title">Signed material</span>
        </div>
        <div className="detail-body">
          {selected ? (
            <>
              <div className="detail-section">
                <div className="detail-section-label">Conversation</div>
                <div className="detail-row">
                  <span className="key">Kind</span>
                  <span className="value">{selected.kind}</span>
                </div>
                <div className="detail-row">
                  <span className="key">Last activity</span>
                  <span className="value">
                    {new Date(selected.last_at).toLocaleString()}
                  </span>
                </div>
                <div className="detail-row">
                  <span className="key">Unread</span>
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
                  title="Last signed message in this conversation"
                />
              ) : (
                <p className="muted" style={{ fontSize: 12 }}>
                  No signed messages in this conversation yet. Agent
                  replies are signed when an authorizing cap_token is
                  in scope.
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
