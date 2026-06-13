/**
 * NTH DAO v2 App shell.
 *
 * Architecture:
 *   - Topbar (top)            48px — brand, identity, Cmd+K
 *   - IconNav (left)          56px — 6 primary destinations
 *   - Sidebar (left+1)       240px — contextual list (decisions /
 *                                    missions / receipts / …)
 *   - Main (center)         flex   — primary work surface
 *   - Detail (right)        320px — signature inspector + context
 *   - StatusBar (bottom)     28px — ambient state, always visible
 *
 * The app is keyboard-driven: Cmd+K opens the command palette
 * which exposes every action available in the current view. The
 * status bar is the eye line for "what's true right now" without
 * having to dig.
 *
 * v1 of this app reads mock data from `./mock.ts`. The contract:
 * when the backend grows the matching endpoints (/api/decisions,
 * /api/missions/active, /api/receipts, /api/cap_tokens), the mock
 * module is the only file that needs to flip.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  a2aEchoApi, askAgentStream, fetchAgents, fetchCapTokens,
  fetchConversations, fetchDecisions, fetchMessages, fetchMissions,
  fetchProcesses, fetchReceipts, pingAgentApi, probeHub,
  resolveDecisionApi, summarizeAgent,
} from "./api";
import { loadChat, saveChat } from "./chatStore";
import { loadSummaries, appendSummary } from "./summaryStore";
import { AgentDirectoryView } from "./components/AgentDirectoryView";
import { BlackboardView, type NewProcessDraft } from "./components/BlackboardView";
import { ChatView } from "./components/ChatView";
import { CommandPalette } from "./components/CommandPalette";
import { DecisionQueue } from "./components/DecisionQueue";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { IconNav } from "./components/IconNav";
import { MissionList, type NewMissionDraft } from "./components/MissionList";
import { RulesView } from "./components/RulesView";
import { StatusBar } from "./components/StatusBar";
import { ToastProvider, useToast } from "./components/Toast";
import { Topbar } from "./components/Topbar";
import {
  mockAgents, mockCapTokens, mockChatMessages, mockConversations,
  mockDecisions, mockMissions, mockProcesses, mockReceipts, mockRules,
} from "./mock";
import type {
  AgentEntry,
  CapTokenSummary,
  ChatMessage,
  CommandItem,
  Conversation,
  ConversationSummary,
  Decision,
  IdentityHeader,
  MissionSummary,
  NavId,
  ProcessCard,
  ReceiptSummary,
  StatusBarState,
} from "./types-v2";

import "./styles.css";

/* ── Identity bootstrap (placeholder — wires to /api/identity later) */
const MOCK_IDENTITY: IdentityHeader = {
  agent_id: "admin",
  did: "did:key:z6MkmRxmBi9p9ziBz2JzBwd8Y5iMzzhPXAi95MPZiLEJJqjL",
  code: "a3ff-62eb",
};

/* Default-export App wraps the inner shell in ErrorBoundary (audit
 * fix M4) + ToastProvider (audit fix M14/M15/C4). Doing the wrap
 * at this layer keeps AppInner free to call useToast() — hooks
 * can't appear in the same component that provides the context.
 *
 * The boundary is OUTSIDE the toast provider so a crash in the
 * toast viewport itself still triggers the recovery UI. */
export default function App() {
  return (
    <ErrorBoundary>
      <ToastProvider>
        <AppInner />
      </ToastProvider>
    </ErrorBoundary>
  );
}

function AppInner() {
  /* Default landing = Blackboard per the autopilot-mode philosophy
   * (DESIGN_TRADE_OFFS extension): the operational dashboard is
   * the steady-state home screen; Decisions is consulted only when
   * the badge calls. In manual mode (early V1) users will quickly
   * switch to Decisions; the badge + Cmd+K make that one keypress. */
  const [active, setActive] = useState<NavId>("blackboard");
  const [decisions, setDecisions] = useState<Decision[]>(mockDecisions);
  /* S5 fix (2026-06-10): track in-flight resolves by id and pass
   * the Set down to DecisionQueue so the main-head renders a
   * "Signing N receipt(s)…" banner during the optimistic-remove
   * → success-toast gap. aria-live polite on the banner so
   * screen readers announce the pending action without
   * interrupting other speech. */
  const [resolvingIds, setResolvingIds] = useState<Set<string>>(
    () => new Set(),
  );
  const [cmdkOpen, setCmdkOpen] = useState(false);
  // Chat state — local-only for v1; flips to /api/messages on
  // backend integration. The shape (Record<convId, Message[]>)
  // matches the mock seed so the swap is a one-liner.
  /* 切片1(2026-06-14):chatMessages 从热层(localStorage)水合 —— 持久的
   * 本地消息覆盖 mock 种子,使刷新/导航后对话**不消失**。热层带 TTL,过期
   * 蒸发,不签名/不联邦/无长期负担(见 chatStore + 对话方案)。 */
  const [chatMessages, setChatMessages] = useState<Record<string, ChatMessage[]>>(
    () => ({ ...mockChatMessages, ...loadChat().messages }),
  );
  /** 当前选中的会话(持久 + 刷新后恢复)。 */
  const [chatSelectedId, setChatSelectedId] = useState<string | null>(
    () => loadChat().selectedId,
  );
  /* Review fix C1 (2026-06-10): conversations was previously not
   * given a setter — the bootstrap fetched the list but had no way
   * to apply it, so the Chat sidebar was permanently stuck on the
   * 4 mock conversations even when the hub returned more or fewer.
   * Lifted to state with a setter and applied in the boot effect. */
  const [conversations, setConversations] =
    useState<Conversation[]>(mockConversations);
  /* Review fix C2 (2026-06-10): cap_tokens + receipts now lifted
   * so the status bar reflects live hub data. Previously the bar
   * permanently sourced from mockCapTokens / mockReceipts and lied
   * about active cap count + chain head whenever the hub was up. */
  const [capTokens, setCapTokens] =
    useState<CapTokenSummary[]>(mockCapTokens);
  const [receipts, setReceipts] =
    useState<ReceiptSummary[]>(mockReceipts);
  /* Lifted for symmetry with the bootstrap fetcher — agents stayed
   * mock before because the boot effect only toasted on success
   * without applying. */
  const [agents, setAgents] = useState<AgentEntry[]>(mockAgents);
  // Missions + processes lifted to state to support the "+ New
  // mission" / "+ New process" entry points (user audit 2026-06-10).
  // Local-only mutation in v1 — pointing at the matching backend
  // endpoints is a one-line swap inside the handlers.
  const [missions, setMissions] = useState<MissionSummary[]>(mockMissions);
  const [processes, setProcesses] = useState<ProcessCard[]>(mockProcesses);
  /** Drives MissionList's selectedId on next render — set by the
   *  create handler so the user immediately sees the new mission
   *  selected in the sidebar + detail rail. MissionList resets it
   *  back to null after consuming. */
  const [focusMissionId, setFocusMissionId] = useState<string | null>(null);
  /* 切片1:初始 focus = 热层持久的选中会话,刷新后 ChatView 恢复到上次的
   * 对话(而非每次回到第一个)。 */
  const [focusChatConversationId, setFocusChatConversationId] =
    useState<string | null>(() => loadChat().selectedId);
  const loadedChatConversations = useRef(new Set<string>());

  // Toast hook (audit M14/M15) — used by the agent-directory
  // handlers, the LAN scan, rule transitions, and the keyboard
  // shortcut feedback paths.
  const toast = useToast();

  /* Hub bootstrap (Phase 1 of the local-hub plan, 2026-06-10):
   * On mount, probe ``/api/v2/health``. If reachable, fetch every
   * read endpoint and replace the local mock state. If unreachable
   * (hub not running, dev session with vite only) the mock data
   * stays — UI works either way.
   *
   * Why a single useEffect with sequential fetches rather than
   * SWR/Tanstack-Query: Phase 1 needs the surface, not the cache.
   * Phase 2's WebSocket subscription will replace the pull model
   * entirely. Adding a cache library now would be premature.
   *
   * Per-view fetch failures are tolerated — if /api/v2/decisions
   * 500s but /api/v2/missions succeeds, we keep mock decisions
   * and live missions side-by-side. The toast banner makes the
   * partial-failure visible.                                      */
  const [hubReady, setHubReady] = useState<boolean | null>(null);
  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();
    (async () => {
      const reachable = await probeHub(undefined, ctrl.signal);
      if (cancelled) return;
      setHubReady(reachable);
      if (!reachable) return;

      // Fan out — but don't bail the whole batch on one failure.
      // Order MUST match the destructuring below.
      const settled = await Promise.allSettled([
        fetchDecisions(ctrl.signal),
        fetchMissions(ctrl.signal),
        fetchProcesses(ctrl.signal),
        fetchAgents(ctrl.signal),
        fetchConversations(ctrl.signal),
        fetchCapTokens(ctrl.signal),
        fetchReceipts(ctrl.signal),
      ]);
      if (cancelled) return;
      const [
        decRes, misRes, procRes, agRes, convRes, capRes, recRes,
      ] = settled;
      if (decRes.status === "fulfilled")  setDecisions(decRes.value);
      if (misRes.status === "fulfilled")  setMissions(misRes.value);
      if (procRes.status === "fulfilled") setProcesses(procRes.value);
      if (agRes.status === "fulfilled")   setAgents(agRes.value);
      if (convRes.status === "fulfilled") setConversations(convRes.value);
      if (capRes.status === "fulfilled")  setCapTokens(capRes.value);
      if (recRes.status === "fulfilled")  setReceipts(recRes.value);

      const failures = settled.filter((r) => r.status === "rejected").length;
      const totalEndpoints = settled.length;

      /* Review fix N2 + P9 (2026-06-10): branch on failure count
       * AND show "—" instead of "0" for any rejected fetch so the
       * user can distinguish "endpoint returned empty" from
       * "endpoint errored". A real 0 and a network-failure 0 used
       * to render identically.
       *
       *   all-failed  → error  (hub reachable but broken)
       *   some-failed → warn   (partial data, "—" marks the gap)
       *   none-failed → success
       */
      const fmt = (r: PromiseSettledResult<{ length: number }>) =>
        r.status === "fulfilled" ? String(r.value.length) : "—";
      const procStr = fmt(procRes);
      const agStr   = fmt(agRes);
      if (failures === totalEndpoints) {
        toast.push(
          `Hub reachable but all ${totalEndpoints} read endpoints failed — ` +
          `showing mock data. Check the hub log.`,
          "error",
        );
      } else if (failures > 0) {
        toast.push(
          `Hub online · ${failures}/${totalEndpoints} endpoints failed · ` +
          `${agStr} agents · ${procStr} processes`,
          "warn",
        );
      } else {
        toast.push(
          `Hub online · ${agStr} agents · ${procStr} processes`,
          "success",
        );
      }

      if (convRes.status === "fulfilled" && convRes.value.length > 0) {
        // Hydrate per-conversation messages lazily on first selection.
        // Phase 1 ships seed conversations + ChatView uses local state
        // on send, so we accept eventual-consistency here.
        try {
          const first = convRes.value[0];
          if (first) {
            const msgs = await fetchMessages(first.id, ctrl.signal);
            if (!cancelled) {
              loadedChatConversations.current.add(first.id);
              // 切片1:合并而非覆盖 —— 别把热层水合的本地消息冲掉。
              setChatMessages((prev) => {
                const local = prev[first.id] ?? [];
                const ids = new Set(msgs.map((m) => m.message_id));
                return {
                  ...prev,
                  [first.id]: [
                    ...msgs,
                    ...local.filter((m) => !ids.has(m.message_id)),
                  ],
                };
              });
            }
          }
        } catch { /* swallow — mock messages stay */ }
      }
    })();
    return () => {
      cancelled = true;
      ctrl.abort();
    };
    // Intentionally empty deps — boot once. Phase 2's WS will
    // handle live updates.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* ── decision handlers (declared early so the keyboard handler
   *    below can reference them) ───────────────────────────────
   *
   * Multi-user race safety (audit pass#4 fix C1, 2026-06-10):
   * the optimistic UI update (`filter out the id`) lands first so
   * the queue feels responsive; the backend call is wrapped in
   * try/catch. On failure (HTTP 409 because another approver
   * already resolved it, 403 because the user lost cap, 500 etc.),
   * we restore the original list snapshot AND surface an error
   * toast — the user knows their action did NOT take effect.
   *
   * In v1 the TODO branch is a no-op so the catch path is
   * unreachable. The scaffold is in place so backend integration
   * is a single-line swap (replace the comment with `await fetch
   * (...)`) without revisiting race semantics.   */
  // Past-tense lookup for error toast grammar — the verb-to-
  // participle map avoids "rejectd" / "deferd" from naive
  // ${transition}d interpolation (review pass#4 follow-up).
  const TRANSITION_PAST = {
    approve: "approved",
    reject:  "rejected",
    defer:   "deferred",
  } as const;

  async function resolveDecision(
    id: string,
    transition: "approve" | "reject" | "defer",
  ) {
    // Capture the specific decision being removed (not the whole
    // array) so rollback only re-inserts THIS item — concurrent
    // resolveDecision calls on other ids stay independent. Walks
    // back the concurrency hazard flagged in review pass#4:
    // a whole-array snapshot would restore items another in-flight
    // call already optimistically removed.
    const target = decisions.find((d) => d.id === id);
    if (!target) return;

    setResolvingIds((prev) => {
      const next = new Set(prev);
      next.add(id);
      return next;
    });
    setDecisions((prev) => prev.filter((d) => d.id !== id));
    try {
      /* Phase 2 (2026-06-10): real POST instead of Promise.resolve.
       * The hub signs a chain-linked receipt on approve, returns it,
       * and the frontend splices it into receipts state so the
       * StatusBar's chain_head_short updates without a refetch. */
      const result = await resolveDecisionApi(id, transition);
      // Extract receipt to a local so TS narrows it inside the
      // setReceipts callback without a non-null assertion (review
      // pass#2 polish 2026-06-10).
      const receipt = result.receipt;
      if (result.signed && receipt) {
        setReceipts((prev) => [...prev, receipt]);
        // R1 fix (2026-06-10): content_hash is typed `string` but a
        // server bug could return "" — slice produces "" and the
        // toast reads "Receipt  signed." with a stray double space.
        // Fallback to "(no hash)" so the user sees something useful.
        const shortHash = receipt.content_hash.slice(0, 12) || "(no hash)";
        toast.push(
          `Approved. Receipt ${shortHash} signed.`,
          "success",
        );
      }
    } catch (err) {
      // Re-insert only if it isn't already back (e.g., a server
      // push notification reverted the removal in the meantime).
      setDecisions((prev) =>
        prev.some((d) => d.id === id) ? prev : [...prev, target],
      );
      const msg = err instanceof Error ? err.message : String(err);
      toast.push(
        `Decision ${id} could not be ${TRANSITION_PAST[transition]}: ${msg}. ` +
        `It may have already been resolved by another user.`,
        "error",
      );
    } finally {
      // S5 cleanup: clear the inflight marker on success AND error
      // so a retry can re-enter the flow.
      setResolvingIds((prev) => {
        if (!prev.has(id)) return prev;
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  }
  function handleApprove(id: string) { void resolveDecision(id, "approve"); }
  function handleReject(id: string)  { void resolveDecision(id, "reject"); }
  function handleDefer(id: string)   { void resolveDecision(id, "defer"); }

  /* U7 (audit fix 2026-06-10): Cmd+J / Cmd+D shortcuts on the
   * Decisions view used to be decorative kbd hints — now they
   * actually fire. Falls through to default browser behavior on
   * non-Decisions views (Cmd+R reload remains, Cmd+D bookmark
   * remains) so we never hijack a global Ctrl+R reload in dev.
   *
   * Additional audit fixes 2026-06-10:
   *   M11 — event.repeat guard: holding Cmd+J would fire approve
   *        on every key-repeat event, allowing a single held
   *        keystroke to silently consume the entire queue. Bail
   *        early so each press requires a release.
   *   M12 — sort moved INSIDE the j/d branch. The previous code
   *        sorted decisions on EVERY Cmd+anything press (including
   *        the Cmd+K palette open path), wasting O(n log n) per
   *        keystroke even when no decision action would fire. */
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      // Auto-repeat key events (held keys) carry e.repeat=true.
      // For destructive actions (approve/defer/reject) we want one
      // press = one action, never an accidental hold-to-spam.
      if (e.repeat) return;

      // Cmd+K → command palette (works on every view)
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCmdkOpen(true);
        return;
      }
      // Cmd+J/D on Decisions view only.
      if (active !== "inbox") return;
      if (!(e.metaKey || e.ctrlKey)) return;
      const k = e.key.toLowerCase();
      if (k !== "j" && k !== "d") return;

      // Only NOW do we pay the sort cost — and only for the keys
      // that actually use the result.
      const sorted = decisions.slice().sort((a, b) => {
        const rank: Record<Decision["impact"], number> = {
          high: 0, medium: 1, low: 2,
        };
        return rank[a.impact] - rank[b.impact] ||
          a.raised_at.localeCompare(b.raised_at);
      });
      const top = sorted[0];
      if (!top) return;

      e.preventDefault();
      if (k === "j") handleApprove(top.id);
      else handleDefer(top.id);
      // Note: we deliberately do NOT bind Cmd+R for Reject —
      // it collides with browser reload and would cause real
      // pain in dev. Reject stays a click-only action.
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [active, decisions]);

  // Status bar facts — derived state, no separate source of truth.
  const statusBar: StatusBarState = useMemo(
    () => ({
      agent_id: MOCK_IDENTITY.agent_id,
      code: MOCK_IDENTITY.code,
      did: MOCK_IDENTITY.did,
      // Review fix C2 (2026-06-10): read from lifted state, not
      // module-scope mocks. When the hub is online these track
      // live caps + chain head; when offline they fall through to
      // the same mocks because the state was seeded with them.
      active_caps: capTokens.filter((c) => !c.revoked).length,
      caps_expiring_soon: capTokens.filter(
        (c) => !c.revoked && c.not_after - Date.now() < 4 * 3600_000,
      ).length,
      chain_head_short:
        receipts[receipts.length - 1]?.content_hash.slice(0, 12) ?? "",
      active_missions: missions.filter(
        (m) => m.status === "active" || m.status === "planning",
      ).length,
      pending_decisions: decisions.length,
    }),
    [decisions, missions, capTokens, receipts],
  );

  // Command palette items — flat list, substring search.
  const commands: CommandItem[] = useMemo(
    () => [
      { id: "nav-blackboard", title: "Go to Blackboard",  shortcut: "G B", run: () => setActive("blackboard") },
      { id: "nav-inbox",      title: "Go to Decisions",   shortcut: "G I", run: () => setActive("inbox") },
      { id: "nav-missions",   title: "Go to Missions",    shortcut: "G M", run: () => setActive("missions") },
      { id: "nav-rules",      title: "Go to Rules",       shortcut: "G R", run: () => setActive("rules") },
      { id: "nav-agents",     title: "Go to Agents",      shortcut: "G P", run: () => setActive("agents") },
      { id: "nav-audit",      title: "Go to Audit",       shortcut: "G A", run: () => setActive("audit") },
      { id: "nav-governance", title: "Go to Governance",  shortcut: "G V", run: () => setActive("governance") },
      { id: "nav-delegate",   title: "Go to Delegate",    shortcut: "G D", run: () => setActive("delegate") },
      { id: "nav-chat",       title: "Go to Chat",        shortcut: "G C", run: () => setActive("chat") },
      {
        id: "new-mission",
        title: "Start a new mission",
        hint: "Kick off a goal for an agent to drive",
        run: () => setActive("missions"),
      },
      {
        id: "new-process",
        title: "Start a new process",
        hint: "Drop a work item into the Operations intake column",
        run: () => setActive("blackboard"),
      },
      {
        id: "new-rule",
        title: "Create a new Rule",
        hint: "Move an approval flow to autopilot",
        run: () => setActive("rules"),
      },
      {
        id: "add-agent",
        title: "Add agent by DID",
        hint: "Paste a did:key to add to your contacts",
        run: () => setActive("agents"),
      },
      {
        id: "scan-lan",
        title: "Scan LAN for nearby agents",
        hint: "Use mDNS to discover other NTH DAO nodes",
        run: () => setActive("agents"),
      },
      {
        id: "issue-cap",
        title: "Issue cap_token to a helper agent",
        hint: "Delegate scoped authority for the next N hours",
        run: () => setActive("delegate"),
      },
      {
        id: "verify-receipt",
        title: "Verify a receipt by ID",
        hint: "Look up the signed receipt and run verify_receipt",
        run: () => setActive("audit"),
      },
      {
        id: "show-card",
        title: "Show this node's A2A AgentCard",
        hint: "Fetch /.well-known/agent.json and inspect the JWS",
        run: () => { window.open("/.well-known/agent.json", "_blank"); },
      },
      {
        id: "show-native-card",
        title: "Show NTH-native identity card",
        run: () => { window.open("/.well-known/nth-dao/identity.json", "_blank"); },
      },
    ],
    [],
  );

  /* ── chat send handler (local-only for v1) ──────────────────
   * Audit pass#4 fix I3 (2026-06-10): sender_id now derived from
   * the bootstrapped identity rather than the literal "admin", so
   * a 50-user deployment shows each user's own messages on the
   * right of the transcript. */
  /* 2026-06-13(修订):把被监管 agent 派生成 Chat 侧栏的 DM 会话。用
   * **useMemo 派生**而非往 conversations state 注入 —— 否则 boot 的会话
   * fetch 可能在 agent 之后覆盖掉注入的 DM(竞态)。chatConversations =
   * 种子会话 + 每个可驱动 agent 一条 DM(去重)。 */
  const chatConversations = useMemo<Conversation[]>(() => {
    const have = new Set(conversations.map((c) => c.id));
    const dms = agents
      .filter((a) => a.supervised && a.alive && typeof a.a2a_port === "number")
      .map((a) => ({
        id: `dm-${a.did}`,
        title: `DM: ${a.label || a.did.slice(0, 12)}`,
        subtitle: a.kind ? `${a.kind} agent` : "agent",
        last_preview: "",
        last_at: "",
        unread: 0,
        kind: "dm" as const,
        participant_dids: [MOCK_IDENTITY.did, a.did],
      }))
      .filter((d) => !have.has(d.id));
    return dms.length ? [...conversations, ...dms] : conversations;
  }, [conversations, agents]);

  const handleChatConversationSelect = useCallback(async (convId: string) => {
    setChatSelectedId(convId); // 切片1:记住选中会话(持久),在 fetch 守卫之前
    if (!hubReady || loadedChatConversations.current.has(convId)) return;
    loadedChatConversations.current.add(convId);
    try {
      const messages = await fetchMessages(convId);
      setChatMessages((prev) => {
        const local = prev[convId] ?? [];
        const serverIds = new Set(messages.map((message) => message.message_id));
        return {
          ...prev,
          [convId]: [
            ...messages,
            ...local.filter((message) => !serverIds.has(message.message_id)),
          ],
        };
      });
    } catch (error) {
      loadedChatConversations.current.delete(convId);
      toast.push(
        `Could not load this conversation: ${
          error instanceof Error ? error.message : String(error)
        }`,
        "error",
      );
    }
  }, [hubReady, toast]);

  /** 给一个会话挑一个可驱动 agent(supervised+alive+a2a_port):
   *  1) 优先会话 participants 里的;
   *  2) 兜底:全节点**恰好一个**可驱动 agent 时用它 —— 这样在**任何**会话
   *     /频道直接发消息都能聊到那个明显的 agent(用户在 channel 发也有回复);
   *  3) 多 agent 且无匹配 → null(提示用户去选某 agent 的 DM)。 */
  function pickAgentForConv(conv: Conversation | undefined): AgentEntry | null {
    const drivable = agents.filter(
      (a) =>
        a.did !== MOCK_IDENTITY.did &&
        a.supervised &&
        a.alive &&
        typeof a.a2a_port === "number",
    );
    if (conv?.participant_dids) {
      const m = drivable.find((a) => conv.participant_dids!.includes(a.did));
      if (m) return m;
    }
    return drivable.length === 1 ? drivable[0] : null;
  }

  /* 切片1:消息 / 选中会话一变就落盘到热层(localStorage)。带 TTL+截断,
   * 详见 chatStore。这是消除"对话消失"的关键 —— 状态不再只活在内存。 */
  useEffect(() => {
    saveChat(chatMessages, chatSelectedId);
  }, [chatMessages, chatSelectedId]);

  /* 切片2b:温层签名摘要。热窗口累积超阈值时,自动让该会话的 agent 把**尚未
   * 被概括**的较老消息(除最近 KEEP_RECENT 外)压成一条**签名摘要**(后端
   * /summarize:make+verify),存进温层。原文留在热层供展开,过 TTL 自然蒸发。 */
  const [summaries, setSummaries] = useState<Record<string, ConversationSummary[]>>(
    () => loadSummaries(),
  );
  const summarizingRef = useRef<Set<string>>(new Set());
  useEffect(() => {
    const convId = chatSelectedId;
    if (!convId) return;
    const THRESHOLD = 12, KEEP_RECENT = 6, MIN_CHUNK = 4;
    const msgs = chatMessages[convId] ?? [];
    if (msgs.length < THRESHOLD || summarizingRef.current.has(convId)) return;
    const agent = pickAgentForConv(chatConversations.find((c) => c.id === convId));
    if (!agent) return;
    const covered = new Set(
      (summaries[convId] ?? []).flatMap((s) => s.covered_message_ids),
    );
    const candidate = msgs
      .slice(0, msgs.length - KEEP_RECENT)
      .filter((m) => !covered.has(m.message_id) && m.sender_id !== "system");
    if (candidate.length < MIN_CHUNK) return;
    summarizingRef.current.add(convId);
    void (async () => {
      try {
        const rec = await summarizeAgent(agent.did, candidate, convId);
        setSummaries((prev) => appendSummary(prev, convId, rec));
      } catch {
        /* 摘要失败不打扰用户;下次阈值再试 */
      } finally {
        summarizingRef.current.delete(convId);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [chatMessages, chatSelectedId, summaries, chatConversations, agents]);

  async function handleChatSend(convId: string, body: string) {
    const msg: ChatMessage = {
      message_id: `m-local-${Date.now()}`,
      sender_id: MOCK_IDENTITY.agent_id,
      sender_label: "you",
      body,
      created_at: new Date().toISOString(),
    };
    setChatMessages((prev) => ({
      ...prev,
      [convId]: [...(prev[convId] ?? []), msg],
    }));

    // 2026-06-13(修订):任何会话(channel 或 DM)只要能挑出一个可驱动
    // agent,就真去 ask 它,把流式回复写进会话。挑不到 → 给可见系统消息
    // (而非静默),用户永远有反馈。这才让"在 channel 发消息也有回复"成立。
    const conv = chatConversations.find((c) => c.id === convId);
    const agent = pickAgentForConv(conv);
    if (!agent) {
      const hasAny = agents.some(
        (a) => a.supervised && a.alive && typeof a.a2a_port === "number",
      );
      setChatMessages((prev) => ({
        ...prev,
        [convId]: [
          ...(prev[convId] ?? []),
          {
            message_id: `m-sys-${Date.now()}`,
            sender_id: "system",
            sender_label: "system",
            body: hasAny
              ? "⚠️ 本会话没绑定具体 agent,且节点上有多个可驱动 agent。请在 Agents 里选某个 agent 的 DM 再发。"
              : "⚠️ 节点上没有可驱动的 agent(需 supervised + alive + a2a_port)。先在 Agents 里 spawn 一个。",
            created_at: new Date().toISOString(),
          },
        ],
      }));
      return;
    }

    // 随机后缀防同毫秒双发撞 id(审查修复 C)。
    const replyId = `m-agent-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    let acc = "";
    setChatMessages((prev) => ({
      ...prev,
      [convId]: [
        ...(prev[convId] ?? []),
        {
          message_id: replyId,
          sender_id: agent.did,
          sender_label: agent.label || "agent",
          body: "Agent is thinking...",
          created_at: new Date().toISOString(),
        },
      ],
    }));
    const patch = (text: string) =>
      setChatMessages((prev) => ({
        ...prev,
        [convId]: (prev[convId] ?? []).map((m) =>
          m.message_id === replyId ? { ...m, body: text } : m,
        ),
      }));
    try {
      const res = await askAgentStream(agent.did, body, (delta) => {
        acc += delta;
        patch(acc);
      });
      patch(acc || res.text || "(空回复)");
    } catch (e) {
      patch(`⚠️ ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  /* ── agent directory handlers (audit fix M14/M15 2026-06-10):
   *    silent console.log replaced with user-visible toasts. ─── */
  function handleAddAgent(did: string, label: string) {
    // TODO: POST /api/agents/add with {target_did, label}
    toast.push(
      `Added ${label || did.slice(0, 16) + "…"} to your contacts.`,
      "success",
    );
  }
  /* LAN scan handler (audit fix M14/M15 + review#N2 2026-06-10):
   *   The setTimeout-based mock outcome used to fire-and-forget,
   *   so rapid double-clicks of "Scan LAN" produced duplicate
   *   "complete" toasts even though the button was disabled
   *   client-side. Converting to an actual Promise that resolves
   *   at the simulated scan deadline lets AgentDirectoryView's
   *   own `scanning` state (await-gated) correctly disable the
   *   button for the full window, and centralises debouncing.
   *   When the backend integration lands, the body becomes a
   *   single `await fetch("/api/agents/lan_discover")`. */
  async function handleScanLan() {
    toast.push("Scanning LAN for nearby agents…", "info");
    await new Promise<void>((resolve) => window.setTimeout(resolve, 1500));
    toast.push("LAN scan complete. No new peers found.", "info");
  }
  function handleIssueCap(did: string) {
    setActive("delegate");
    toast.push(
      `Pivoting to Delegate to issue cap_token for ${did.slice(0, 16)}…`,
      "info",
    );
  }
  function handleSendToAgent(did: string) {
    setFocusChatConversationId(`dm-${did}`);
    setActive("chat");
  }

  /* ── rules handlers (audit fix C1 2026-06-10) ─────────────── */
  function transitionRule(id: string, msg: string, kind: "success" | "info") {
    // TODO: POST /api/rules/{id}/{transition}. In v1 we don't yet
    // hold rules in state, so the visible signal is the toast.
    toast.push(msg, kind);
  }
  function handlePauseRule(id: string)    { transitionRule(id, `Rule ${id} paused.`,    "success"); }
  function handleResumeRule(id: string)   { transitionRule(id, `Rule ${id} resumed.`,   "success"); }
  function handleActivateRule(id: string) { transitionRule(id, `Rule ${id} activated.`, "success"); }
  function handleDiscardRule(id: string)  { transitionRule(id, `Rule ${id} discarded.`, "success"); }
  function handleEditRule(id: string)     { toast.push(`Edit Rule ${id} (form coming in v1.x).`, "info"); }
  function handleViewCap(capId: string)   { toast.push(`Cap_token ${capId} — opening Delegate view.`, "info"); setActive("delegate"); }

  /* ── create-task handlers (audit fix 2026-06-10:
   *    "需要有添加/发起任务功能") ───────────────────────────────── */

  /** New mission — drops in as "planning". The driver agent is
   *  expected to pick it up on the next runner loop and emit step
   *  receipts; that's why steps_total starts at 0.
   *
   *  Auto-selects the newly-created mission so the detail rail
   *  immediately shows what was just submitted (review note 6:
   *  otherwise the sidebar selection lags one mission behind).
   *  The selection is a child-state concern; v1 sidestep via a
   *  `selectedMissionId` lifted to App.tsx is overkill — we use
   *  a `pendingFocusMissionId` to nudge MissionList instead. */
  function handleCreateMission(draft: NewMissionDraft) {
    const m: MissionSummary = {
      id: `m-local-${Date.now()}`,
      title: draft.title,
      goal: draft.goal,
      status: "planning",
      steps_total: 0,
      steps_done: 0,
      steps_in_progress: 0,
      driver_label: draft.driver_label || "unknown",
      driver_did: draft.driver_did,
      cap_token_id: draft.cap_token_id,
      started_at: new Date().toISOString(),
    };
    setMissions((prev) => [m, ...prev]);
    setFocusMissionId(m.id);
    // TODO: POST /api/missions with the draft; reconcile id on
    // response. Until then the local id (m-local-*) is fine.
  }

  /** New process — drops in "received". Matches the Kanban Intake
   *  column and the autopilot dashboard's "what just arrived"
   *  visual cue. */
  function handleCreateProcess(draft: NewProcessDraft) {
    const p: ProcessCard = {
      id: `p-local-${Date.now()}`,
      title: draft.title,
      subtitle: draft.subtitle ?? "",
      workflow: draft.workflow,
      stage: "received",
      current_agent: draft.current_agent,
      auto: false,
      updated_at: new Date().toISOString(),
    };
    setProcesses((prev) => [p, ...prev]);
    // TODO: POST /api/processes
  }

  /* ── current view ── */
  let view: React.ReactNode;
  if (active === "blackboard") {
    view = (
      <BlackboardView
        processes={processes}
        onCreate={handleCreateProcess}
        // Stable seed so the form still offers choices even after
        // every process is filtered out. The derived fallback
        // inside BlackboardView covers the case where new workflows
        // get introduced via the "+ New workflow…" option.
        workflowOptions={["shopping", "support", "finance", "hiring"]}
      />
    );
  } else if (active === "inbox") {
    view = (
      <DecisionQueue
        decisions={decisions}
        onApprove={handleApprove}
        onReject={handleReject}
        onDefer={handleDefer}
        resolvingIds={resolvingIds}
      />
    );
  } else if (active === "missions") {
    view = (
      <MissionList
        missions={missions}
        onCreate={handleCreateMission}
        driverOptions={agents}
        focusId={focusMissionId}
        onFocusConsumed={() => setFocusMissionId(null)}
      />
    );
  } else if (active === "rules") {
    view = (
      <RulesView
        rules={mockRules}
        onPause={handlePauseRule}
        onResume={handleResumeRule}
        onActivate={handleActivateRule}
        onDiscard={handleDiscardRule}
        onEdit={handleEditRule}
        onViewCap={handleViewCap}
      />
    );
  } else if (active === "agents") {
    view = (
      <AgentDirectoryView
        agents={agents}
        onAddByDid={handleAddAgent}
        onScanLan={handleScanLan}
        onIssueCap={handleIssueCap}
        onSendMessage={handleSendToAgent}
        /* Phase 3f: route ping + a2a/echo through the typed
           fetchers. Both return {status, body} regardless of HTTP
           status so the UI can color-code 404/502/etc separately
           (R1 BUG-2 fix). The signal lets the component cancel
           on unmount / re-test (R1 BUG-3 fix). */
        onPingAgent={(did, signal) => pingAgentApi(did, signal)}
        onA2AEcho={(did, params, signal) =>
          a2aEchoApi(did, params, { signal })
        }
        /* UI 集成（2026-06-13）：派任务 + 流式输出。hub 替操作员注入
           cap_token（浏览器无签名私钥）。 */
        onAskAgent={(did, prompt, onDelta, signal, onStatus) =>
          askAgentStream(did, prompt, onDelta, signal, onStatus)
        }
      />
    );
  } else if (active === "chat") {
    view = (
      <ChatView
        summariesByConv={summaries}
        conversations={chatConversations}
        messagesByConv={chatMessages}
        onSend={handleChatSend}
        onConversationSelect={handleChatConversationSelect}
        focusConversationId={focusChatConversationId}
        currentUserId={MOCK_IDENTITY.agent_id}
      />
    );
  } else {
    view = (
      <>
        <aside className="sidebar">
          <div className="sidebar-head">
            <span className="sidebar-title">{labelFor(active)}</span>
          </div>
          <div className="sidebar-list">
            <p className="muted" style={{ padding: "12px 14px" }}>
              Coming next: this view will host the {labelFor(active)} panel.
            </p>
          </div>
        </aside>
        <section className="main">
          <div className="main-head">
            <p className="main-eyebrow">{labelFor(active)}</p>
            <h1 className="main-title">{labelFor(active)} — coming soon</h1>
            <p className="main-subtitle">
              This v2 build ships the Decisions and Missions surfaces
              first. {labelFor(active)} migrates from the v1 panels in
              the next iteration.
            </p>
          </div>
          <div className="main-body">
            <div className="main-empty" style={{ minHeight: 200 }}>
              <p className="muted">Press <kbd>⌘K</kbd> to navigate.</p>
            </div>
          </div>
        </section>
        <aside className="detail">
          <div className="detail-head">
            <span className="detail-title">Context</span>
          </div>
          <div className="detail-body" />
        </aside>
      </>
    );
  }

  return (
    <div className="app-shell">
      <Topbar identity={MOCK_IDENTITY} onCmdK={() => setCmdkOpen(true)} />

      <IconNav
        active={active}
        decisionCount={decisions.length}
        onNav={setActive}
      />

      {view}

      <StatusBar state={statusBar} />

      <CommandPalette
        open={cmdkOpen}
        items={commands}
        onClose={() => setCmdkOpen(false)}
      />
    </div>
  );
}

function labelFor(id: NavId): string {
  switch (id) {
    case "blackboard": return "Blackboard";
    case "inbox":      return "Decisions";
    case "missions":   return "Missions";
    case "rules":      return "Rules";
    case "agents":     return "Agents";
    case "audit":      return "Audit";
    case "governance": return "Governance";
    case "delegate":   return "Delegate";
    case "chat":       return "Chat";
  }
}
