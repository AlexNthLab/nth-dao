/**
 * Channels — 群聊收编进 v2 的原生 View(P3)。
 *
 * 取代独立的 8765 群聊脚本:同一套暗色 iMessage 风格(复用 chat-* 类)、
 * 同一套 i18n、同一套 agent 运行时。后端 /api/v2/channels(P1)+ 频道
 * agent 监听派发(P2)。本视图自取数据 + 3s 轮询(与旧 8765 同节奏)。
 *
 * 功能:
 *   - 左栏:频道列表 + 新建频道
 *   - 中栏:消息流(本人右/他人左)+ 输入;发消息后若频道有可驱动 agent,
 *     显示"思考中"指示(补 P2 审查隐患②:失败/等待对用户可见),30s 超时撤下
 *   - 右栏:成员 + 把 agent 加进频道(从 agent 目录选)
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { IconChat, IconPlus, IconSend, IconUserPlus } from "./Icons";
import { useToast } from "./Toast";
import { useLang } from "../i18n";
import { relativeTimeShort } from "../utils/time";
import {
  createChannel, fetchAgents, joinChannel, listChannelMessages,
  listChannels, postChannelMessage,
} from "../api";
import type { AgentEntry, Channel, ChannelMessage } from "../types-v2";

const ME = "admin";  // 当前人类用户(与后端发消息的默认 sender 一致)

const DEFAULT_AGENT_REPLY_WAIT_MS = 30_000;
const AGENT_REPLY_WAIT_MS_BY_KIND: Record<string, number> = {
  mock: 30_000,
  codex: 100_000,
  hermes: 180_000,
  "claude-code": 130_000,
};

export function agentReplyWaitMs(agents: AgentEntry[]): number {
  if (agents.length === 0) return DEFAULT_AGENT_REPLY_WAIT_MS;
  return Math.max(
    DEFAULT_AGENT_REPLY_WAIT_MS,
    ...agents.map((a) => AGENT_REPLY_WAIT_MS_BY_KIND[a.kind || ""] ?? DEFAULT_AGENT_REPLY_WAIT_MS),
  );
}

export function ChannelsView() {
  const { t } = useLang();
  const toast = useToast();
  const [channels, setChannels] = useState<Channel[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChannelMessage[]>([]);
  const [agents, setAgents] = useState<AgentEntry[]>([]);
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [joinDid, setJoinDid] = useState("");
  const [awaiting, setAwaiting] = useState(false);
  const [awaitTimedOut, setAwaitTimedOut] = useState(false);
  const awaitTimer = useRef<number | null>(null);
  const threadRef = useRef<HTMLDivElement | null>(null);

  const selected = channels.find((c) => c.channel_id === selectedId) ?? null;
  const channelAgentMembers = useMemo(
    () => {
      if (!selected) return [];
      const memberIds = new Set(
        selected.member_ids.filter((m) => m !== ME && m.startsWith("did:")),
      );
      return agents.filter((a) => a.did && memberIds.has(a.did));
    },
    [selected, agents],
  );
  const drivableChannelAgents = useMemo(
    () => channelAgentMembers.filter(
      (a) => a.supervised === true
        && a.alive === true
        && a.has_active_cap === true
        && typeof a.a2a_port === "number",
    ),
    [channelAgentMembers],
  );
  const hasAgentMember = drivableChannelAgents.length > 0;
  const agentWaitMs = useMemo(
    () => agentReplyWaitMs(drivableChannelAgents),
    [drivableChannelAgents],
  );
  const agentWaitSeconds = Math.round(agentWaitMs / 1000);

  // 频道列表 + agent 目录:初次 + 3s 轮询。
  useEffect(() => {
    let cancelled = false;
    async function loadChannels() {
      try {
        const cs = await listChannels();
        if (cancelled) return;
        setChannels(cs);
        setSelectedId((cur) => cur ?? cs[0]?.channel_id ?? null);
      } catch { /* hub 离线 — 保留现状 */ }
    }
    async function loadAgents() {
      try {
        const rows = await fetchAgents();
        if (!cancelled) setAgents(rows);
      } catch { /* hub 离线 — 保留现状 */ }
    }
    loadChannels();
    loadAgents();
    const id = window.setInterval(() => {
      void loadChannels();
      void loadAgents();
    }, 3000);
    return () => { cancelled = true; window.clearInterval(id); };
  }, []);

  // 选中频道的消息:切换即拉 + 3s 轮询。
  useEffect(() => {
    if (!selectedId) { setMessages([]); return; }
    setAwaiting(false);
    setAwaitTimedOut(false);  // 切频道清掉上一个频道的等待态
    let cancelled = false;
    const cid = selectedId;
    async function loadMsgs() {
      try {
        const ms = await listChannelMessages(cid);
        if (!cancelled) setMessages(ms);
      } catch { /* 保留 */ }
    }
    loadMsgs();
    const id = window.setInterval(loadMsgs, 3000);
    return () => { cancelled = true; window.clearInterval(id); };
  }, [selectedId]);

  // 收到新消息且最新一条非本人 → agent 回帖到了,撤"思考中"。
  useEffect(() => {
    if (!awaiting) return;
    const last = messages[messages.length - 1];
    if (last && last.sender_id !== ME) {
      setAwaiting(false);
      setAwaitTimedOut(false);  // agent 回帖到了,不是超时
      if (awaitTimer.current) window.clearTimeout(awaitTimer.current);
    }
  }, [messages, awaiting]);

  // 自动滚到底。
  useEffect(() => {
    const el = threadRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages, awaiting, selectedId]);

  // 卸载清掉计时器。
  useEffect(() => () => {
    if (awaitTimer.current) window.clearTimeout(awaitTimer.current);
  }, []);

  function senderLabel(id: string): string {
    if (id === ME) return t("我", "you");
    const a = agents.find((x) => x.did === id);
    if (a && a.label) return a.label;
    return id.length > 14 ? `${id.slice(0, 14)}…` : id;
  }

  async function send() {
    const body = draft.trim();
    if (!body || !selectedId || sending) return;
    setDraft("");
    setSending(true);
    setAwaitTimedOut(false);
    try {
      await postChannelMessage(selectedId, body, ME);
      if (hasAgentMember) {
        setAwaiting(true);
        if (awaitTimer.current) window.clearTimeout(awaitTimer.current);
        // Slow backends (Hermes/Codex/Claude) can legitimately exceed
        // the old 30s UI window; use the same backend-aware budget the
        // hub uses for A2A ask forwarding.
        awaitTimer.current = window.setTimeout(() => {
          setAwaiting(false);
          setAwaitTimedOut(true);
        }, agentWaitMs);
      } else if (channelAgentMembers.length > 0) {
        setAwaitTimedOut(true);
      }
      const ms = await listChannelMessages(selectedId);
      setMessages(ms);
    } catch (e) {
      setDraft(body);  // 失败回填,可重试
      toast.push(
        `${t("发送失败", "Send failed")}: ${e instanceof Error ? e.message : String(e)}`,
        "error",
      );
    } finally {
      setSending(false);
    }
  }

  async function create() {
    const name = newName.trim();
    if (!name) return;
    try {
      const ch = await createChannel(name);
      setNewName("");
      setCreateOpen(false);
      setChannels(await listChannels());
      setSelectedId(ch.channel_id);
    } catch (e) {
      toast.push(
        `${t("建频道失败", "Create channel failed")}: ${e instanceof Error ? e.message : String(e)}`,
        "error",
      );
    }
  }

  async function join() {
    if (!selectedId || !joinDid) return;
    try {
      const ch = await joinChannel(selectedId, joinDid);
      setChannels((cs) => cs.map((c) => (c.channel_id === ch.channel_id ? ch : c)));
      setJoinDid("");
      toast.push(t("已加入频道", "Added to channel"), "success");
    } catch (e) {
      toast.push(
        `${t("加入失败", "Join failed")}: ${e instanceof Error ? e.message : String(e)}`,
        "error",
      );
    }
  }

  const joinable = agents.filter(
    (a) => a.did && !(selected?.member_ids ?? []).includes(a.did),
  );

  return (
    <>
      <aside className="sidebar">
        <div className="sidebar-head">
          <span className="sidebar-title">{t("频道", "Channels")}</span>
          <span className="sidebar-count">{channels.length}</span>
        </div>
        <div style={{ padding: "8px 12px" }}>
          {createOpen ? (
            <div style={{ display: "flex", gap: 6 }}>
              <input
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") void create(); }}
                placeholder={t("频道名", "channel name")}
                autoFocus
                style={{ flex: 1, minWidth: 0 }}
              />
              <button className="btn btn-primary" onClick={() => void create()}>
                {t("建", "Add")}
              </button>
            </div>
          ) : (
            <button
              className="btn btn-ghost"
              onClick={() => setCreateOpen(true)}
              style={{ width: "100%" }}
            >
              <IconPlus size={14} /> {t("新频道", "New channel")}
            </button>
          )}
        </div>
        <div className="sidebar-list">
          {channels.length === 0 && (
            <p className="muted" style={{ padding: "12px 14px" }}>
              {t("还没有频道。", "No channels yet.")}
            </p>
          )}
          {channels.map((c) => (
            <button
              key={c.channel_id}
              className={`sidebar-item ${selectedId === c.channel_id ? "active" : ""}`}
              onClick={() => setSelectedId(c.channel_id)}
            >
              <div className="sidebar-item-title">
                <span className="truncate"># {c.name}</span>
              </div>
              <div className="sidebar-item-meta">
                <span>{c.member_ids.length} {t("成员", "members")}</span>
              </div>
            </button>
          ))}
        </div>
      </aside>

      <section className="main" style={{ display: "flex", flexDirection: "column" }}>
        <div className="chat-head">
          {selected ? (
            <>
              <div className="chat-head-avatar" aria-hidden="true">
                {(selected.name[0] || "#").toUpperCase()}
              </div>
              <div className="chat-head-meta">
                <h1 className="chat-head-name"># {selected.name}</h1>
                <span className="chat-head-sub">
                  {selected.topic || `${selected.member_ids.length} ${t("成员", "members")}`}
                </span>
              </div>
            </>
          ) : (
            <span className="chat-head-name">{t("选择一个频道", "Select a channel")}</span>
          )}
        </div>

        {selected ? (
          <>
            <div ref={threadRef} className="chat-thread" style={{ flex: 1, overflowY: "auto" }}>
              {messages.length === 0 ? (
                <div className="main-empty" style={{ minHeight: 200 }}>
                  <div className="main-empty-icon"><IconChat size={36} /></div>
                  <p>{t("还没有消息。", "No messages yet.")}</p>
                  <p className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                    {t("在下面开聊。频道里若有在线 agent,会自动回复。",
                       "Start below. Online agents in this channel will reply.")}
                  </p>
                </div>
              ) : (
                messages.map((m, i) => {
                  const isYou = m.sender_id === ME;
                  const prev = messages[i - 1];
                  const showName = !isYou && (!prev || prev.sender_id !== m.sender_id);
                  return (
                    <div key={m.message_id} className={`chat-row ${isYou ? "out" : "in"}`}>
                      <div className="chat-col">
                        {showName && <div className="chat-name">{senderLabel(m.sender_id)}</div>}
                        <div className="chat-bubble">{m.body}</div>
                        <span className="chat-time">{relativeTimeShort(m.created_at)}</span>
                      </div>
                    </div>
                  );
                })
              )}
              {awaiting && (
                <div className="chat-row in" aria-live="polite">
                  <div className="chat-col">
                    <div className="chat-bubble">
                      <span className="typing-dots" aria-label={t("agent 思考中", "agent thinking")}>
                        <span /><span /><span />
                      </span>
                    </div>
                  </div>
                </div>
              )}
              {awaitTimedOut && (
                <div className="chat-system" style={{ fontSize: 11 }} aria-live="polite">
                  {t(
                    `agent 未在 ${agentWaitSeconds}s 内回复(可能没有可驱动 agent、它出错了,或仍在运行)。`,
                    `No agent reply after ${agentWaitSeconds}s - no drivable agent, it errored, or it is still running.`,
                  )}
                </div>
              )}
            </div>

            <form
              className="chat-composer"
              onSubmit={(e) => { e.preventDefault(); void send(); }}
            >
              <textarea
                className="chat-input"
                rows={1}
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); void send(); }
                }}
                placeholder={`${t("发消息到", "Message")} #${selected.name}…`}
              />
              <button
                type="submit"
                className="chat-send"
                disabled={!draft.trim() || sending}
                aria-label={t("发送", "Send")}
              >
                <IconSend size={16} />
              </button>
            </form>
          </>
        ) : (
          <div className="main-body">
            <div className="main-empty" style={{ minHeight: 200 }}>
              <div className="main-empty-icon"><IconChat size={36} /></div>
              <p>{t("未选择频道。", "No channel selected.")}</p>
            </div>
          </div>
        )}
      </section>

      <aside className="detail">
        <div className="detail-head">
          <span className="detail-title">{t("成员与 agent", "Members & agents")}</span>
        </div>
        <div className="detail-body">
          {selected ? (
            <>
              <div className="detail-section">
                <div className="detail-section-label">
                  {t("成员", "Members")} ({selected.member_ids.length})
                </div>
                {selected.member_ids.map((mid) => (
                  <div className="detail-row" key={mid}>
                    <span className="value truncate">{senderLabel(mid)}</span>
                    {mid.startsWith("did:") && (
                      <span className="pill dim" style={{ fontSize: 10 }}>agent</span>
                    )}
                  </div>
                ))}
              </div>

              <div className="detail-section">
                <div className="detail-section-label">
                  {t("把 agent 加进频道", "Add an agent")}
                </div>
                {joinable.length > 0 ? (
                  <div style={{ display: "flex", gap: 6 }}>
                    <select
                      value={joinDid}
                      onChange={(e) => setJoinDid(e.target.value)}
                      style={{ flex: 1, minWidth: 0 }}
                    >
                      <option value="">{t("选一个 agent…", "pick an agent…")}</option>
                      {joinable.map((a) => (
                        <option key={a.did} value={a.did}>
                          {a.label || a.did.slice(0, 16)}
                        </option>
                      ))}
                    </select>
                    <button
                      className="btn btn-primary"
                      disabled={!joinDid}
                      onClick={() => void join()}
                    >
                      <IconUserPlus size={12} /> {t("加入", "Add")}
                    </button>
                  </div>
                ) : (
                  <p className="muted" style={{ fontSize: 12 }}>
                    {t("没有可加的 agent —— 先在 Agents 里 spawn 一个。",
                       "No agents to add — spawn one under Agents first.")}
                  </p>
                )}
              </div>
            </>
          ) : (
            <p className="muted">{t("选择一个频道查看成员。", "Select a channel to see members.")}</p>
          )}
        </div>
      </aside>
    </>
  );
}
