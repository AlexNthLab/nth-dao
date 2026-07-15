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
  a2aEchoApi, activateMission, addAgentByDid, createMission, createProcess,
  discoverLanAgents, fetchAgents, fetchBackendStatus, fetchCapTokens, fetchIdentity,
  fetchConversations, fetchDecisions, fetchMessages, fetchMissions,
  fetchProcesses, fetchReceipts, fetchSocialMe, listCapRequests, listDisputes, pingAgentApi, probeHub,
  getAgentLink, reconcileAgentLink, resolveDecisionApi, runMissionStep, spawnAgent, stopAgent,
  submitAgentLink, summarizeAgent,
} from "./api";
import type { AgentLinkJob, BackendStatus } from "./api";
import { loadChat, saveChat } from "./chatStore";
import { loadSummaries, appendSummary } from "./summaryStore";
import { AgentDirectoryView } from "./components/AgentDirectoryView";
import { TasksView } from "./components/TasksView";
import { BlackboardView, type NewProcessDraft } from "./components/BlackboardView";
import { ChatView } from "./components/ChatView";
import { ChannelsView } from "./components/ChannelsView";
import { CommandPalette } from "./components/CommandPalette";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { LangProvider, useLang } from "./i18n";
import { IconNav } from "./components/IconNav";
import { MissionList, type NewMissionDraft } from "./components/MissionList";
import { RulesView } from "./components/RulesView";
import { AuditView } from "./components/AuditView";
import { GovernanceView } from "./components/GovernanceView";
import { ReputationView } from "./components/ReputationView";
import { ContactsView } from "./components/ContactsView";
import { InboxView } from "./components/InboxView";
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
      <LangProvider>
        <ToastProvider>
          <AppInner />
        </ToastProvider>
      </LangProvider>
    </ErrorBoundary>
  );
}

/** 页签持久化的 localStorage 键(每 origin 私有)。 */
const ACTIVE_NAV_KEY = "nth.v2.activeNav";

/** 合法 NavId 白名单——存进来的脏值/旧版本遗留值一律不认,降级默认页。 */
const VALID_NAV_IDS: ReadonlySet<NavId> = new Set<NavId>([
  "blackboard", "inbox", "missions", "tasks", "rules",
  "agents", "channels", "audit", "governance", "reputation", "contacts", "chat",
]);

/** 从 localStorage 读回上次页签;无值/脏值/禁读一律降级默认页。 */
function loadActiveNav(): NavId {
  try {
    const v = localStorage.getItem(ACTIVE_NAV_KEY);
    if (v && VALID_NAV_IDS.has(v as NavId)) return v as NavId;
  } catch {
    /* 隐私模式禁读 —— 降级默认值 */
  }
  return DEFAULT_NAV;
}

/** 默认落地:Blackboard。UI 给人看,首屏先呈现当前工作状态,再让用户进入 Missions / Tasks / Channels。 */
const DEFAULT_NAV: NavId = "blackboard";

function agentKindForDid(agents: AgentEntry[], did: string): string {
  return agents.find((agent) => agent.did === did)?.kind || "";
}

export function agentBackendTimeoutS(
  agents: AgentEntry[],
  did: string,
): number | undefined {
  const value = agents.find((agent) => agent.did === did)?.ask_timeout_s;
  return typeof value === "number" && Number.isFinite(value) && value > 0
    ? value
    : undefined;
}

export function agentLinkExecutionDeadline(
  job: Pick<AgentLinkJob, "state" | "updated_at">,
  backendTimeoutS: number,
  nowMs = Date.now(),
): number | undefined {
  if (job.state !== "processing") return undefined;
  const updatedAtMs = Date.parse(job.updated_at);
  const startedAtMs = Number.isFinite(updatedAtMs) ? updatedAtMs : nowMs;
  return startedAtMs + Math.max(5, backendTimeoutS + 15) * 1000;
}

function AppInner() {
  /* Default landing = Blackboard (2026-06-14 重定:A2A 任务优先).
   * 项目第一性原则是 A2A 任务协调,落地页给"运行态总览"——每个 agent
   * 正在推进什么任务,而非聊天。Chat 是低频沟通入口,在 IconNav 里按
   * 频次下沉,不再是首屏。 */
  /* 当前页签持久化(2026-06-14 修):刷新前把 active 落 localStorage,刷新后
   * 水合回来——否则刷新一律重置回 blackboard,用户在 Tasks 找活刷一下就被
   * 踢回首屏。校验合法 NavId,脏值/旧值降级 blackboard,绝不让坏值崩渲染。 */
  const { t } = useLang();
  const [active, setActive] = useState<NavId>(loadActiveNav);
  useEffect(() => {
    try {
      localStorage.setItem(ACTIVE_NAV_KEY, active);
    } catch {
      /* 配额满 / 隐私模式禁写 —— 静默降级,不影响导航本身 */
    }
  }, [active]);
  const [decisions, setDecisions] = useState<Decision[]>(mockDecisions);
  // 待办角标的额外计数 = 待批授权请求 + 开放争议(统一「待办」也含这两类)。
  const [inboxExtra, setInboxExtra] = useState(0);
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
  /* 4C(2026-06-14):typing 是会话级临时态,不再当成一条占位消息塞进
   * 历史。等待首个 token 期间在该会话底部显示三点;首 token 到达即清除,
   * 真实流式气泡接管。不持久化——刷新后不会残留"思考中"。 */
  const [typingConvs, setTypingConvs] = useState<Record<string, boolean>>({});
  const [agentLinkStatusConvs, setAgentLinkStatusConvs] = useState<Record<string, string>>({});
  const [agentLinkRefsByConv, setAgentLinkRefsByConv] = useState<Record<string, {
    did: string;
    jobId: string;
    replyId: string;
  }>>({});
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
  const [identity, setIdentity] =
    useState<IdentityHeader>(MOCK_IDENTITY);
  /* Lifted for symmetry with the bootstrap fetcher — agents stayed
   * mock before because the boot effect only toasted on success
   * without applying. */
  const [agents, setAgents] = useState<AgentEntry[]>(mockAgents);
  const [backendStatuses, setBackendStatuses] =
    useState<Record<string, BackendStatus>>({});
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
  const chatLinkAbortRef = useRef<Record<string, AbortController>>({});
  const activeChatLinkRef = useRef<Record<string, string>>({});

  useEffect(() => () => {
    Object.values(chatLinkAbortRef.current).forEach((controller) => controller.abort());
  }, []);

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
        fetchIdentity(ctrl.signal),
        fetchDecisions(ctrl.signal),
        fetchMissions(ctrl.signal),
        fetchProcesses(ctrl.signal),
        fetchAgents(ctrl.signal),
        fetchBackendStatus(ctrl.signal),
        fetchConversations(ctrl.signal),
        fetchCapTokens(ctrl.signal),
        fetchReceipts(ctrl.signal),
        // 统一「待办」角标:授权请求(待批)+ 争议(开放)+ 好友请求(待确认)
        // 也算"需要你拍板"。
        listCapRequests(ctrl.signal),
        listDisputes(ctrl.signal),
        fetchSocialMe(ctrl.signal),
      ]);
      if (cancelled) return;
      const [
        idRes, decRes, misRes, procRes, agRes, backendRes, convRes, capRes, recRes,
        capReqRes, dispRes, socialRes,
      ] = settled;
      if (idRes.status === "fulfilled")   setIdentity(idRes.value);
      if (decRes.status === "fulfilled")  setDecisions(decRes.value);
      if (misRes.status === "fulfilled")  setMissions(misRes.value);
      if (procRes.status === "fulfilled") setProcesses(procRes.value);
      if (agRes.status === "fulfilled")   setAgents(agRes.value);
      if (backendRes.status === "fulfilled") setBackendStatuses(backendRes.value.backends);
      if (convRes.status === "fulfilled") setConversations(convRes.value);
      if (capRes.status === "fulfilled")  setCapTokens(capRes.value);
      if (recRes.status === "fulfilled")  setReceipts(recRes.value);
      // 待办额外计数 = 待批授权 + 开放争议(取数失败则记 0,不阻断)。
      const pendingCaps = capReqRes.status === "fulfilled"
        ? capReqRes.value.filter((c) => c.status === "pending").length : 0;
      const openDisputes = dispRes.status === "fulfilled"
        ? dispRes.value.filter((d) => d.status === "open").length : 0;
      const friendReqs = socialRes.status === "fulfilled"
        ? socialRes.value.pending_incoming.length : 0;
      setInboxExtra(pendingCaps + openDisputes + friendReqs);

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
      agent_id: identity.agent_id,
      code: identity.code,
      did: identity.did,
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
    [identity, decisions, missions, capTokens, receipts],
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
      { id: "nav-delegate",   title: "Go to Authorizations (Inbox)", shortcut: "G D", run: () => setActive("inbox") },
      { id: "nav-reputation", title: "Go to Reputation",  shortcut: "G E", run: () => setActive("reputation") },
      { id: "nav-contacts",   title: "Go to Contacts",    shortcut: "G F", run: () => setActive("contacts") },
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
        run: () => setActive("inbox"),
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
        participant_dids: [identity.did, a.did],
      }))
      .filter((d) => !have.has(d.id));
    return dms.length ? [...conversations, ...dms] : conversations;
  }, [conversations, agents, identity.did]);

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
        a.did !== identity.did &&
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
  // 审查修复:摘要失败后的冷却时间(convId -> 不早于此 ms 再试)。否则
  // agent 持续失败时,每来一条新消息就重试一次 → 刷屏式失败调用。
  const summaryCooldownRef = useRef<Map<string, number>>(new Map());
  useEffect(() => {
    const convId = chatSelectedId;
    if (!convId) return;
    const THRESHOLD = 12, KEEP_RECENT = 6, MIN_CHUNK = 4;
    const msgs = chatMessages[convId] ?? [];
    if (msgs.length < THRESHOLD || summarizingRef.current.has(convId)) return;
    if (Date.now() < (summaryCooldownRef.current.get(convId) ?? 0)) return; // 冷却中
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
        summaryCooldownRef.current.delete(convId); // 成功 → 清冷却
      } catch {
        // 失败 → 冷却 90s,别每条新消息都重试(审查修复 B)。
        summaryCooldownRef.current.set(convId, Date.now() + 90_000);
      } finally {
        summarizingRef.current.delete(convId);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [chatMessages, chatSelectedId, summaries, chatConversations, agents]);

  async function handleChatSend(convId: string, body: string) {
    const msg: ChatMessage = {
      message_id: `m-local-${Date.now()}`,
      sender_id: identity.agent_id,
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
              ? t(
                  "⚠️ 本会话没绑定具体 agent,且节点上有多个可驱动 agent。请在 Agents 里选某个 agent 的 DM 再发。",
                  "⚠️ This conversation isn't bound to a specific agent, and the node has multiple drivable agents. Open a specific agent's DM under Agents and send there.",
                )
              : t(
                  "⚠️ 节点上没有可驱动的 agent(需 supervised + alive + a2a_port)。先在 Agents 里 spawn 一个。",
                  "⚠️ No drivable agent on this node (needs supervised + alive + a2a_port). Spawn one under Agents first.",
                ),
            created_at: new Date().toISOString(),
          },
        ],
      }));
      return;
    }

    // 随机后缀防同毫秒双发撞 id(审查修复 C)。
    const replyId = `m-agent-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    chatLinkAbortRef.current[convId]?.abort();
    const linkAbort = new AbortController();
    chatLinkAbortRef.current[convId] = linkAbort;
    activeChatLinkRef.current[convId] = replyId;
    // 先点亮"思考中",不插占位消息。
    setTypingConvs((prev) => ({ ...prev, [convId]: true }));
    const clearTyping = () =>
      setTypingConvs((prev) => {
        if (!prev[convId]) return prev;
        const next = { ...prev };
        delete next[convId];
        return next;
      });
    // 幂等 upsert:首次创建回复消息,之后按 id 改写 body。不依赖外部
    // 标志位,StrictMode 双调用也安全。
    const upsert = (text: string) =>
      setChatMessages((prev) => {
        const list = prev[convId] ?? [];
        if (list.some((m) => m.message_id === replyId)) {
          return {
            ...prev,
            [convId]: list.map((m) =>
              m.message_id === replyId ? { ...m, body: text } : m,
            ),
          };
        }
        return {
          ...prev,
          [convId]: [
            ...list,
            {
              message_id: replyId,
              sender_id: agent.did,
              sender_label: agent.label || "agent",
              body: text,
              created_at: new Date().toISOString(),
            },
          ],
        };
      });
    let lastLinkState = "";
    try {
      const backendTimeoutS = agentBackendTimeoutS(agents, agent.did) ?? 120;
      const link = await submitAgentLink(
        agent.did,
        body,
        replyId,
        undefined,
      );
      setAgentLinkRefsByConv((prev) => ({
        ...prev,
        [convId]: { did: agent.did, jobId: link.job_id, replyId },
      }));
      lastLinkState = link.state;
      if (activeChatLinkRef.current[convId] === replyId) {
        setAgentLinkStatusConvs((prev) => ({ ...prev, [convId]: link.state }));
      }
      let executionDeadline: number | undefined;
      let job = await getAgentLink(agent.did, link.job_id, linkAbort.signal);
      while (!new Set(["completed", "completed_unverified", "failed", "delivery_unknown"]).has(job.state)) {
        lastLinkState = job.state;
        if (activeChatLinkRef.current[convId] === replyId) {
          setAgentLinkStatusConvs((prev) => ({ ...prev, [convId]: job.state }));
        }
        executionDeadline ??= agentLinkExecutionDeadline(job, backendTimeoutS);
        if (executionDeadline !== undefined && Date.now() >= executionDeadline) {
          throw new Error("agent execution timed out while waiting for the result");
        }
        await new Promise((resolve) => setTimeout(resolve, 1000));
        job = await getAgentLink(agent.did, link.job_id, linkAbort.signal);
      }
      lastLinkState = job.state;
      if (activeChatLinkRef.current[convId] === replyId) {
        setAgentLinkStatusConvs((prev) => ({ ...prev, [convId]: job.state }));
      }
      if (job.state === "failed") {
        throw new Error(job.error || "agent link failed");
      }
      if (job.state === "delivery_unknown") {
        throw new Error(
          job.error || "delivery outcome is unknown; reconcile before retrying",
        );
      }
      clearTyping();
      const replyText = job.response?.trim() || t("(空回复)", "(empty reply)");
      upsert(replyText);
      setChatMessages((prev) => {
        const list = prev[convId] ?? [];
        return {
          ...prev,
          [convId]: list.map((m) =>
            m.message_id === replyId
              ? { ...m, nth_receipt_id: job.receipt_id || undefined }
              : m,
          ),
        };
      });
    } catch (e) {
      if ((e as Error)?.name === "AbortError") return;
      clearTyping();
      if (activeChatLinkRef.current[convId] === replyId) {
        setAgentLinkStatusConvs((prev) => ({
          ...prev,
          [convId]: lastLinkState === "delivery_unknown" ? "delivery_unknown" : "failed",
        }));
        upsert(`⚠️ ${e instanceof Error ? e.message : String(e)}`);
      }
    } finally {
      if (chatLinkAbortRef.current[convId] === linkAbort) {
        delete chatLinkAbortRef.current[convId];
      }
    }
  }

  async function handleReconcileAgentLink(
    convId: string,
    receiptText: string,
    responseText: string,
  ) {
    const ref = agentLinkRefsByConv[convId];
    if (!ref) {
      throw new Error("No recoverable AgentLink job is attached to this conversation");
    }
    let receipt: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(receiptText);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("receipt must be a JSON object");
      }
      receipt = parsed as Record<string, unknown>;
    } catch (error) {
      throw new Error(
        `Invalid signed receipt JSON: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    const job = await reconcileAgentLink(
      ref.did,
      ref.jobId,
      receipt,
      responseText,
    );
    setAgentLinkStatusConvs((prev) => ({ ...prev, [convId]: job.state }));
    setChatMessages((prev) => {
      const list = prev[convId] ?? [];
      return {
        ...prev,
        [convId]: list.map((message) =>
          message.message_id === ref.replyId
            ? {
                ...message,
                body: job.response || responseText.trim(),
                nth_receipt_id: job.receipt_id || undefined,
              }
            : message,
        ),
      };
    });
  }

  async function handleAgentDirectoryAsk(
    did: string,
    prompt: string,
    onDelta: (delta: string) => void,
    signal?: AbortSignal,
    onStatus?: (status: string) => void,
  ) {
    const idempotencyKey = `directory-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    const backendTimeoutS = agentBackendTimeoutS(agents, did) ?? 120;
    const link = await submitAgentLink(
      did,
      prompt,
      idempotencyKey,
      signal,
    );
    onStatus?.(link.state);
    let executionDeadline: number | undefined;
    let job = await getAgentLink(did, link.job_id, signal);
      while (!new Set(["completed", "completed_unverified", "failed", "delivery_unknown"]).has(job.state)) {
      onStatus?.(job.state);
      executionDeadline ??= agentLinkExecutionDeadline(job, backendTimeoutS);
      if (executionDeadline !== undefined && Date.now() >= executionDeadline) {
        throw new Error("agent execution timed out while waiting for the result");
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
      job = await getAgentLink(did, link.job_id, signal);
    }
    onStatus?.(job.state);
    if (job.state === "failed" || job.state === "delivery_unknown") {
      throw new Error(
        job.error ||
          (job.state === "delivery_unknown"
            ? "delivery outcome is unknown; reconcile before retrying"
            : "agent link failed"),
      );
    }
    const text = job.response?.trim() || "(empty reply)";
    onDelta(text);
    onStatus?.("done");
    return {
      text,
      backend: agentKindForDid(agents, did),
    };
  }

  /* ── agent directory handlers (audit fix M14/M15 2026-06-10):
   *    silent console.log replaced with user-visible toasts. ─── */
  async function handleSpawnBackend(kind: string) {
    try {
      const res = await spawnAgent({
        kind,
        label: `${kind} helper`,
        capabilities: ["a2a:message_send"],
        persist: true,
      });
      setAgents((prev) => [
        res.agent,
        ...prev.filter((a) => a.did !== res.agent.did),
      ]);
      toast.push(`Started ${res.label || kind}.`, "success");
    } catch (e) {
      toast.push(
        `Could not start ${kind}: ${e instanceof Error ? e.message : String(e)}`,
        "error",
      );
    }
  }

  async function handleStopAgent(agentId: string) {
    try {
      await stopAgent(agentId);
      setAgents((prev) => prev.filter((a) => a.agent_id !== agentId));
      toast.push("Agent stopped.", "success");
    } catch (e) {
      toast.push(
        `Could not stop agent: ${e instanceof Error ? e.message : String(e)}`,
        "error",
      );
    }
  }

  async function handleAddAgent(did: string, label: string) {
    const res = await addAgentByDid({
      actorId: identity.agent_id,
      didOrAgentId: did,
      label,
    });
    const entryDid = res.did || did.trim() || res.agent_id;
    setAgents((prev) => [
      {
        did: entryDid,
        code: res.agent_id.slice(0, 8),
        label: res.label || label || res.agent_id,
        source: "contact",
        capabilities: [],
        has_active_cap: false,
        agent_id: res.agent_id,
      },
      ...prev.filter((a) => a.did !== entryDid && a.agent_id !== res.agent_id),
    ]);
    toast.push(
      `Added ${res.label || label || entryDid.slice(0, 16) + "…"} to your contacts.`,
      "success",
    );
  }
  /* LAN scan handler: v2 now calls the hardened legacy discovery
   * endpoint instead of a simulated timeout. AgentDirectoryView still
   * owns the disabled/scanning state, while App owns merging newly
   * discovered peers into the shared Agents list. */
  async function handleScanLan() {
    toast.push("Scanning LAN for nearby agents…", "info");
    const peers = await discoverLanAgents({
      actorId: identity.agent_id,
      timeoutSeconds: 2,
    });
    setAgents((prev) => {
      const seen = new Set(peers.map((p) => p.did));
      return [
        ...peers,
        ...prev.filter((a) => !seen.has(a.did)),
      ];
    });
    toast.push(
      peers.length
        ? `LAN scan complete. Found ${peers.length} peer(s).`
        : "LAN scan complete. No new peers found.",
      "info",
    );
  }
  function handleIssueCap(did: string) {
    setActive("inbox");
    toast.push(
      `Opening Inbox to authorize cap_token for ${did.slice(0, 16)}…`,
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
  function handleViewCap(capId: string)   { toast.push(`Cap_token ${capId} — opening Inbox.`, "info"); setActive("inbox"); }

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
  async function handleCreateMission(draft: NewMissionDraft) {
    // 2026-06-14:真正落后端(替掉此前纯前端 m-local- 假动作 —— 那种刷新
    // 即失、不进 store、用不了 Mission↔Task 桥)。后端返回真实 summary
    // (含真 id + 步骤计数 + planning/active),前置进列表并聚焦。
    try {
      const created = await createMission({
        title: draft.title,
        goal: draft.goal,
        driver: draft.driver_label,
        driverDid: draft.driver_did,
        steps: draft.steps,
      });
      setMissions((prev) => [created, ...prev]);
      setFocusMissionId(created.id);
    } catch (e) {
      toast.push(
        `${t("创建 mission 失败", "Failed to create mission")}:${e instanceof Error ? e.message : String(e)}`,
        "error",
      );
    }
  }

  /** 启动 mission(planning→active)。补齐"创建后卡 planning"的流转。 */
  async function handleActivateMission(id: string) {
    try {
      const updated = await activateMission(id);
      setMissions((prev) => prev.map((m) => (m.id === id ? updated : m)));
      toast.push(t("Mission 已进入执行视图", "Mission moved into execution"), "success");
    } catch (e) {
      toast.push(
        `${t("启动 mission 失败", "Failed to start mission")}:${e instanceof Error ? e.message : String(e)}`,
        "error",
      );
    }
  }
  /** New process — persists to the live Blackboard. The returned
   *  ProcessCard has the real Blackboard id and timestamp, so refresh
   *  and agent context see the same work item. */
  async function handleRunMissionStep(
    missionId: string,
    stepId: string,
    agentDid?: string,
  ) {
    try {
      const updated = await runMissionStep(missionId, stepId, { agentDid });
      setMissions((prev) => prev.map((m) => (m.id === missionId ? updated : m)));
      toast.push(t("Step 执行完成，Receipt 已写入", "Step completed; receipt persisted"), "success");
    } catch (e) {
      try {
        const refreshed = await fetchMissions();
        setMissions(refreshed);
      } catch {
        // Preserve the original execution error as the visible failure.
      }
      toast.push(
        `${t("Step 执行失败", "Step run failed")}:${e instanceof Error ? e.message : String(e)}`,
        "error",
      );
    }
  }

  async function handleCreateProcess(draft: NewProcessDraft): Promise<boolean> {
    try {
      const created = await createProcess({
        title: draft.title,
        workflow: draft.workflow,
        subtitle: draft.subtitle,
        current_agent: draft.current_agent,
      });
      setProcesses((prev) => [
        created,
        ...prev.filter((p) => p.id !== created.id),
      ]);
      toast.push(t("流程已写入 Blackboard", "Process saved to Blackboard"), "success");
      return true;
    } catch (e) {
      toast.push(
        `${t("创建流程失败", "Failed to create process")}:${e instanceof Error ? e.message : String(e)}`,
        "error",
      );
      return false;
    }
  }

  /* ── current view ── */
  let view: React.ReactNode;
  if (active === "blackboard") {
    view = (
      <BlackboardView
        processes={processes}
        onCreate={handleCreateProcess}
        onNavigate={(target) => setActive(target)}
        // Stable seed so the form still offers choices even after
        // every process is filtered out. The derived fallback
        // inside BlackboardView covers the case where new workflows
        // get introduced via the "+ New workflow…" option.
        workflowOptions={["shopping", "support", "finance", "hiring"]}
      />
    );
  } else if (active === "inbox") {
    view = (
      <InboxView
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
        onActivate={handleActivateMission}
        onRunStep={handleRunMissionStep}
        driverOptions={agents}
        focusId={focusMissionId}
        onFocusConsumed={() => setFocusMissionId(null)}
        onNavigate={(target) => setActive(target)}
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
  } else if (active === "tasks") {
    view = <TasksView />;
  } else if (active === "agents") {
    view = (
      <AgentDirectoryView
        agents={agents}
        backendStatuses={backendStatuses}
        onAddByDid={handleAddAgent}
        onSpawnBackend={handleSpawnBackend}
        onStopAgent={handleStopAgent}
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
        onAskAgent={handleAgentDirectoryAsk}
      />
    );
  } else if (active === "chat") {
    view = (
      <ChatView
        summariesByConv={summaries}
        conversations={chatConversations}
        messagesByConv={chatMessages}
        typingByConv={typingConvs}
        agentLinkStatusByConv={agentLinkStatusConvs}
        onReconcileAgentLink={handleReconcileAgentLink}
        onSend={handleChatSend}
        onConversationSelect={handleChatConversationSelect}
        focusConversationId={focusChatConversationId}
        currentUserId={identity.agent_id}
      />
    );
  } else if (active === "channels") {
    view = <ChannelsView />;
  } else if (active === "audit") {
    view = <AuditView />;
  } else if (active === "governance") {
    view = <GovernanceView />;
  } else if (active === "reputation") {
    view = <ReputationView />;
  } else if (active === "contacts") {
    view = <ContactsView />;
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
      <Topbar identity={identity} onCmdK={() => setCmdkOpen(true)} />

      <IconNav
        active={active}
        decisionCount={decisions.length + inboxExtra}
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
    case "tasks":      return "Tasks";
    case "rules":      return "Rules";
    case "agents":     return "Agents";
    case "channels":   return "Channels";
    case "audit":      return "Audit";
    case "governance": return "Governance";
    case "reputation": return "Reputation";
    case "contacts":   return "Contacts";
    case "chat":       return "Chat";
  }
}
