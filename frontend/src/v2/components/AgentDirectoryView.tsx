/**
 * Agent Directory — add + discover + manage AI helpers.
 *
 * Three sources unified into one homogeneous list:
 *   1. ``local``    — helpers you've delegated cap_tokens to
 *                     (the "my agents" set)
 *   2. ``contact``  — DIDs you've added by hand
 *                     (the ContactBook from v1 — /api/agents/add)
 *   3. ``lan``      — peers discovered on the local network via
 *                     mDNS (/api/agents/lan_discover)
 *   4. ``a2a``      — peers fetched via their A2A AgentCard
 *
 * Top of main carries the ADD form (paste DID) and the SCAN LAN
 * button. The sidebar filter narrows by source.
 *
 * This is the surface that fills the v1-noted gap: NTH DAO is
 * useful only when you have agents to delegate work to, so the
 * "where do agents come from" answer must be one click away.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import {
  IconSearch, IconSend, IconUserPlus, IconUsers, IconWifi, IconZap,
} from "./Icons";
import { SignaturePanel } from "./SignaturePanel";
import { relativeTimeShort } from "../utils/time";
import { useLang } from "../i18n";
import type { BackendStatus } from "../api";
import type { AgentEntry, AgentSource } from "../types-v2";

export interface AgentDirectoryViewProps {
  agents: AgentEntry[];
  backendStatuses?: Record<string, BackendStatus>;
  /** Wired to /api/agents/add once the backend integration lands. */
  onAddByDid: (did: string, label: string) => Promise<void> | void;
  /** Wired to /api/agents/lan_discover. */
  onScanLan: () => Promise<void> | void;
  /** Issue cap_token to this agent — pivots to Delegate view. */
  onIssueCap: (did: string) => void;
  onSpawnBackend?: (kind: string) => Promise<void> | void;
  onStopAgent?: (agentId: string) => Promise<void> | void;
  /** Send a chat message to this agent — pivots to Chat view with
   *  the right conversation pre-selected (audit fix 2026-06-10,
   *  finding C5: "Send message" button was decorative). When
   *  omitted the button is hidden rather than render a no-op. */
  onSendMessage?: (did: string) => void;
  /** Phase 3f (2026-06-11): ping a supervised agent via the hub
   *  proxy (GET /api/v2/agents/{did}/ping). Returns ``{status,
   *  body}`` regardless of HTTP status so the UI can color-code
   *  404 vs 502 vs success separately (BUG-2 fix R1). The signal
   *  cancels the in-flight fetch on unmount / re-test (BUG-3
   *  fix R1). The button is hidden when omitted OR when the
   *  agent isn't supervised. */
  onPingAgent?: (did: string, signal?: AbortSignal) =>
    Promise<{ status: number; body: unknown }>;
  /** Phase 3f: call /a2a/echo on a supervised agent via the hub
   *  proxy. The frontend sends without Authorization (no access to
   *  the hub's signing key from the browser); the demonstrated
   *  outcome is a 401 from the child's auth check. The UI renders
   *  both 200 and 401 paths so the operator can see the wire +
   *  the auth rejection. */
  onA2AEcho?: (
    did: string,
    params: Record<string, unknown>,
    signal?: AbortSignal,
  ) => Promise<{ status: number; body: unknown }>;
  /** UI 集成（2026-06-13）：给一个 supervised agent 派一个任务，**流式**
   *  接收输出。hub 替操作员注入 cap_token（浏览器无签名私钥）。omitted
   *  或 agent 非 supervised 时工作面板隐藏。onDelta 逐块回调，onStatus
   *  报告阶段。返回拼好的全文 + backend/model。 */
  onAskAgent?: (
    did: string,
    prompt: string,
    onDelta: (delta: string) => void,
    signal?: AbortSignal,
    onStatus?: (status: string) => void,
  ) => Promise<{ text: string; backend?: string; model?: string }>;
}

const SOURCE_LABEL: Record<AgentSource, string> = {
  local: "Local",
  contact: "Contact",
  lan: "LAN",
  a2a: "A2A peer",
};

const SOURCE_PILL: Record<AgentSource, "ok" | "wait" | "bad" | "dim"> = {
  local: "ok",
  contact: "wait",
  lan: "dim",
  a2a: "dim",
};

type Filter = "all" | AgentSource;

// (was a local relTime() — moved to ../utils/time, audit M3)

export function AgentDirectoryView({
  agents, backendStatuses = {}, onAddByDid, onScanLan, onIssueCap,
  onSpawnBackend, onStopAgent, onSendMessage,
  onPingAgent, onA2AEcho, onAskAgent,
}: AgentDirectoryViewProps) {
  const { t } = useLang();
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  const [addOpen, setAddOpen] = useState(false);
  const [newDid, setNewDid] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [addError, setAddError] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState("");
  const [spawningKind, setSpawningKind] = useState<string | null>(null);
  const [stoppingAgentId, setStoppingAgentId] = useState<string | null>(null);
  const [selectedDid, setSelectedDid] = useState<string | null>(
    agents[0]?.did ?? null,
  );
  /** Phase 3f: per-agent test result — last /ping or /a2a/echo outcome.
   *  Keyed by DID so each row's button has its own state without us
   *  carrying an "active row" ref. The Map is replaced (not mutated)
   *  so React sees a referentially-new value and re-renders. */
  type ProbeResult = {
    kind: "ping" | "echo";
    status: number;
    body: unknown;
    at: number;
  };
  const [probes, setProbes] = useState<Map<string, ProbeResult>>(
    new Map(),
  );
  /** BUG-1 fix (review round Phase 3f R1): SET of busy DIDs, not a
   *  single string. The previous single-value state allowed a click
   *  on agent B's button to "free" agent A's still-in-flight ping,
   *  re-enabling A's button mid-request. With a Set, each agent has
   *  its own busy lifecycle. */
  const [busyDids, setBusyDids] = useState<Set<string>>(new Set());
  /** BUG-3 fix (review round Phase 3f R1): one AbortController per
   *  agent so unmount / re-test cancels the in-flight request
   *  instead of leaking a setState into a dead component. The ref
   *  lifetime equals the component's; effect-time cleanup aborts
   *  everything outstanding. */
  const inflight = useRef<Map<string, AbortController>>(new Map());
  /** UI 集成：工作面板状态（给选中 agent 派任务，流式收输出）。 */
  const [workPrompt, setWorkPrompt] = useState("");
  const [workOutput, setWorkOutput] = useState("");
  const [workStatus, setWorkStatus] = useState<
    "idle" | "running" | "done" | "error"
  >("idle");
  const [workMeta, setWorkMeta] = useState("");
  const [workError, setWorkError] = useState("");
  const workAbort = useRef<AbortController | null>(null);
  useEffect(() => {
    const map = inflight.current;
    return () => {
      for (const ctrl of map.values()) ctrl.abort();
      map.clear();
      workAbort.current?.abort();
    };
  }, []);

  function describeWorkStatus(status: string) {
    if (status === "authorizing") {
      return t("正在授权 agent…", "Authorizing agent…");
    }
    if (status === "waiting") {
      return t("等待 agent 接入…", "Waiting for agent…");
    }
    if (status === "streaming") {
      return t("正在流式输出…", "Streaming response…");
    }
    if (status === "done") return "";
    if (status.startsWith("warming:")) {
      const attempt = status.slice("warming:".length);
      return t(
        `Hermes 正在冷启动/加载凭证（第 ${attempt} 次尝试）…`,
        `Hermes is warming up (attempt ${attempt})…`,
      );
    }
    return status;
  }

  async function runAgentWork(did: string) {
    if (!onAskAgent || !workPrompt.trim()) return;
    workAbort.current?.abort();
    const ctrl = new AbortController();
    workAbort.current = ctrl;
    setWorkOutput("");
    setWorkError("");
    setWorkMeta("");
    setWorkStatus("running");
    try {
      const res = await onAskAgent(
        did,
        workPrompt.trim(),
        (delta) => setWorkOutput((cur) => cur + delta),
        ctrl.signal,
        (status) => setWorkMeta(describeWorkStatus(status)),
      );
      if (res.text && res.text.length > 0) setWorkOutput(res.text);
      setWorkMeta(
        [res.backend && `backend: ${res.backend}`, res.model && `model: ${res.model}`]
          .filter(Boolean)
          .join(" · "),
      );
      setWorkStatus("done");
    } catch (e) {
      if ((e as Error)?.name === "AbortError") return; // 取消不算错
      setWorkError((e as Error)?.message ?? String(e));
      setWorkStatus("error");
    }
  }

  function markBusy(did: string, busy: boolean) {
    setBusyDids((s) => {
      const next = new Set(s);
      if (busy) next.add(did);
      else next.delete(did);
      return next;
    });
  }

  function setProbe(did: string, p: ProbeResult) {
    setProbes((m) => {
      const next = new Map(m);
      next.set(did, p);
      return next;
    });
  }

  async function handlePing(did: string) {
    if (!onPingAgent) return;
    // Cancel any previous in-flight probe for this same DID so a
    // double-click doesn't race two responses into setProbe.
    inflight.current.get(did)?.abort();
    const ctrl = new AbortController();
    inflight.current.set(did, ctrl);
    markBusy(did, true);
    try {
      const result = await onPingAgent(did, ctrl.signal);
      if (ctrl.signal.aborted) return;
      setProbe(did, {
        kind: "ping",
        status: result.status,
        body: result.body,
        at: Date.now(),
      });
    } catch (e) {
      if (ctrl.signal.aborted) return;
      setProbe(did, {
        kind: "ping",
        status: 0,
        body: { error: String(e) },
        at: Date.now(),
      });
    } finally {
      // N-1 fix (review round Phase 3f R2): markBusy(false) must
      // ALSO be gated on still-owning the slot. The original code
      // ran it unconditionally, which under double-click sequences
      // re-enabled the button while the new request was still in
      // flight. Now both the slot delete AND the busy clear only
      // happen when we still own the controller.
      if (inflight.current.get(did) === ctrl) {
        inflight.current.delete(did);
        markBusy(did, false);
      }
    }
  }

  async function handleA2A(did: string) {
    if (!onA2AEcho) return;
    inflight.current.get(did)?.abort();
    const ctrl = new AbortController();
    inflight.current.set(did, ctrl);
    markBusy(did, true);
    try {
      const { status, body } = await onA2AEcho(
        did,
        { hello: "from-v2-console", at: new Date().toISOString() },
        ctrl.signal,
      );
      if (ctrl.signal.aborted) return;
      setProbe(did, { kind: "echo", status, body, at: Date.now() });
    } catch (e) {
      if (ctrl.signal.aborted) return;
      setProbe(did, {
        kind: "echo",
        status: 0,
        body: { error: String(e) },
        at: Date.now(),
      });
    } finally {
      // N-1 fix (review round Phase 3f R2): same as handlePing —
      // gate the busy clear on still-owning the slot, otherwise
      // a stale finally from the previous request re-enables the
      // button while the newer one is still in flight.
      if (inflight.current.get(did) === ctrl) {
        inflight.current.delete(did);
        markBusy(did, false);
      }
    }
  }

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return agents.filter((a) => {
      if (filter !== "all" && a.source !== filter) return false;
      if (!q) return true;
      return (
        a.label.toLowerCase().includes(q) ||
        a.did.toLowerCase().includes(q) ||
        a.code.includes(q)
      );
    });
  }, [agents, filter, query]);

  const selected = filtered.find((a) => a.did === selectedDid) ?? null;

  const counts = useMemo(() => {
    const m: Record<AgentSource, number> = {
      local: 0, contact: 0, lan: 0, a2a: 0,
    };
    for (const a of agents) m[a.source]++;
    return m;
  }, [agents]);

  const backendOrder = ["mock", "claude-code", "codex", "hermes"];
  const backendCards = backendOrder
    .map((kind) => backendStatuses[kind])
    .filter((b): b is BackendStatus => Boolean(b));

  async function handleSpawn(kind: string) {
    if (!onSpawnBackend) return;
    setSpawningKind(kind);
    try {
      await onSpawnBackend(kind);
    } finally {
      setSpawningKind(null);
    }
  }

  async function handleStop(agentId: string) {
    if (!onStopAgent) return;
    setStoppingAgentId(agentId);
    try {
      await onStopAgent(agentId);
    } finally {
      setStoppingAgentId(null);
    }
  }

  async function handleAdd(e: React.FormEvent) {
    e.preventDefault();
    if (!newDid.trim()) return;
    setAddError("");
    try {
      await onAddByDid(newDid.trim(), newLabel.trim());
      setNewDid("");
      setNewLabel("");
      setAddOpen(false);
    } catch (err) {
      setAddError(err instanceof Error ? err.message : String(err));
    }
  }

  async function handleScan() {
    setScanning(true);
    setScanError("");
    try {
      await onScanLan();
    } catch (err) {
      setScanError(err instanceof Error ? err.message : String(err));
    } finally {
      setScanning(false);
    }
  }

  return (
    <>
      <aside className="sidebar">
        <div className="sidebar-head">
          <span className="sidebar-title">{t("Agents", "Agents")}</span>
          <span className="sidebar-count">{agents.length}</span>
        </div>
        <div className="sidebar-list">
          <button
            className={`sidebar-item ${filter === "all" ? "active" : ""}`}
            onClick={() => setFilter("all")}
          >
            <div className="sidebar-item-title">
              <span>{t("全部 agent", "All agents")}</span>
            </div>
            <div className="sidebar-item-meta">
              <span>{agents.length}</span>
            </div>
          </button>
          {(["local", "contact", "lan", "a2a"] as AgentSource[]).map((s) => (
            <button
              key={s}
              className={`sidebar-item ${filter === s ? "active" : ""}`}
              onClick={() => setFilter(s)}
            >
              <div className="sidebar-item-title">
                <span className={`pill ${SOURCE_PILL[s]}`}>{SOURCE_LABEL[s]}</span>
              </div>
              <div className="sidebar-item-meta">
                <span>{counts[s]}</span>
              </div>
            </button>
          ))}
        </div>
      </aside>

      <section className="main">
        <div className="main-head">
          <p className="main-eyebrow">Agents</p>
          <h1 className="main-title">{t("谁能为你干活", "Who's available to work for you")}</h1>
          <p className="main-subtitle">
            {t(
              "本地助手、手动添加的联系人,以及在你网络里发现的对等节点。签发 cap_token 即可委派工作;点一行查看它的 A2A 能力。",
              "Local helpers, hand-added contacts, and peers discovered on your network. Issue a cap_token to delegate work; tap a row to inspect their A2A capabilities.",
            )}
          </p>
        </div>

        <div className="main-body">
          {/* Action row — add by DID + scan LAN + search */}
          <div
            style={{
              display: "flex",
              gap: 8,
              marginBottom: 16,
              alignItems: "center",
            }}
          >
            <button
              className="btn btn-primary"
              onClick={() => setAddOpen((v) => !v)}
            >
              <IconUserPlus size={14} /> {t("按 DID 添加", "Add by DID")}
            </button>
            <button
              className="btn btn-secondary"
              onClick={handleScan}
              disabled={scanning}
            >
              <IconWifi size={14} /> {scanning ? t("扫描中…", "Scanning…") : t("扫描局域网", "Scan LAN")}
            </button>
            <div
              style={{
                flex: 1,
                position: "relative",
                marginLeft: 8,
              }}
            >
              <span
                style={{
                  position: "absolute",
                  left: 12,
                  top: "50%",
                  transform: "translateY(-50%)",
                  color: "var(--fg-tertiary)",
                  pointerEvents: "none",
                }}
              >
                <IconSearch size={14} />
              </span>
              <input
                style={{ paddingLeft: 36, width: "100%" }}
                placeholder={t("按标签、DID 或代号搜索…", "Search by label, DID, or code…")}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                spellCheck={false}
              />
            </div>
          </div>
          {scanError && (
            <p style={{ fontSize: 12, color: "var(--warn, #d97706)", margin: "-8px 0 14px" }}>
              {t("局域网扫描失败:", "LAN scan failed:")} {scanError}
            </p>
          )}


          {backendCards.length > 0 && (
            <div
              style={{
                background: "var(--bg-panel)",
                border: "1px solid var(--border)",
                borderRadius: "var(--r-md)",
                padding: 14,
                marginBottom: 16,
              }}
            >
              <div className="detail-section-label">Local backend startup</div>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                  gap: 10,
                  marginTop: 8,
                }}
              >
                {backendCards.map((b) => {
                  const running = agents.some(
                    (a) => a.kind === b.kind && a.supervised && a.alive,
                  );
                  return (
                    <div
                      key={b.kind}
                      style={{
                        border: "1px solid var(--border)",
                        borderRadius: 6,
                        padding: 10,
                        background: "var(--bg-elevated)",
                        minWidth: 0,
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                        <strong style={{ fontSize: 13 }}>{b.label}</strong>
                        <span className={`pill ${b.ready ? "ok" : "wait"}`} style={{ fontSize: 10 }}>
                          {b.ready ? "ready" : "setup needed"}
                        </span>
                      </div>
                      <p className="muted" style={{ fontSize: 11, margin: "8px 0", lineHeight: 1.35 }}>
                        {b.detail}
                      </p>
                      {b.warning && (
                        <p style={{ fontSize: 11, margin: "0 0 8px", color: "var(--warn, #d97706)", lineHeight: 1.35 }}>
                          {b.warning}
                        </p>
                      )}
                      <button
                        type="button"
                        className={b.ready ? "btn btn-primary" : "btn btn-secondary"}
                        disabled={!onSpawnBackend || !b.ready || spawningKind === b.kind}
                        onClick={() => void handleSpawn(b.kind)}
                        title={b.ready ? `Spawn ${b.label}` : b.detail}
                      >
                        {spawningKind === b.kind ? "Starting..." : running ? "Start another" : "Start"}
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {addOpen && (
            <div
              style={{
                background: "var(--bg-panel)",
                border: "1px solid var(--border)",
                borderRadius: "var(--r-md)",
                padding: 14,
                marginBottom: 16,
              }}
            >
              <form onSubmit={handleAdd} style={{ display: "grid", gap: 8 }}>
                <div className="detail-section-label">{t("按 DID 添加 agent", "Add agent by DID")}</div>
                <input
                  placeholder={t("did:key:z6Mk…(粘贴 agent 的 DID)", "did:key:z6Mk… (paste the agent's DID)")}
                  value={newDid}
                  onChange={(e) => setNewDid(e.target.value)}
                  spellCheck={false}
                  className="mono"
                  style={{ fontFamily: "var(--t-mono)", fontSize: 12 }}
                />
                <input
                  placeholder={t("标签(你给这个 agent 起的名)", "Label (your own name for this agent)")}
                  value={newLabel}
                  onChange={(e) => setNewLabel(e.target.value)}
                />
                <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
                  <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={!newDid.trim()}
                  >
                    {t("添加", "Add")}
                  </button>
                  <button
                    type="button"
                    className="btn btn-ghost"
                    onClick={() => setAddOpen(false)}
                  >
                    {t("取消", "Cancel")}
                  </button>
                </div>
                <p className="muted" style={{ fontSize: 11, marginTop: 4 }}>
                  {t("该 agent 会立即出现在", "The agent will appear under")}{" "}
                  <strong>{t("联系人", "Contacts")}</strong>
                  {t("下。要授权,去 Delegate 页签签发一个 cap_token。", " immediately. To grant authority, issue a cap_token from the Delegate tab.")}
                </p>
                {addError && (
                  <p style={{ fontSize: 12, color: "var(--warn, #d97706)", margin: 0 }}>
                    {t("添加失败:", "Add failed:")} {addError}
                  </p>
                )}
              </form>
            </div>
          )}

          {/* Directory rows */}
          <div className="stack">
            {filtered.length === 0 && (
              <div className="main-empty" style={{ minHeight: 120 }}>
                <div className="main-empty-icon">
                  <IconUsers size={28} />
                </div>
                <p>
                  {query
                    ? t("没有匹配该搜索的 agent。", "No agent matches that search.")
                    : t("这个类别还没有 agent。", "No agents in this category yet.")}
                </p>
              </div>
            )}
            {filtered.map((a) => (
              <article
                key={a.did}
                className="decision-card"
                onClick={() => setSelectedDid(a.did)}
                style={{
                  padding: 16,
                  cursor: "pointer",
                  borderColor:
                    selectedDid === a.did
                      ? "var(--accent)"
                      : "var(--border)",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    justifyContent: "space-between",
                    gap: 16,
                  }}
                >
                  <div>
                    <h3
                      style={{
                        margin: 0,
                        fontSize: 14,
                        fontWeight: 600,
                        display: "flex",
                        alignItems: "center",
                        gap: 8,
                      }}
                    >
                      {a.label || t("(未命名)", "(unlabeled)")}
                      {a.has_active_cap && (
                        <span
                          title="Active cap_token issued"
                          style={{
                            color: "var(--accent)",
                            display: "inline-flex",
                          }}
                        >
                          <IconZap size={12} />
                        </span>
                      )}
                      {/* Phase 3f live badges — only meaningful for
                          hub-supervised agents. Three independent
                          signals: supervised (we own the process),
                          alive (it's actually running), a2a_port
                          (HTTP surface is reachable). Each is its
                          own pill so the operator can spot a
                          "supervised but dead" or "supervised but
                          A2A-bind-failed" agent at a glance. */}
                      {a.supervised && a.alive && (
                        <span
                          className="pill ok"
                          title="Subprocess is alive"
                          style={{ fontSize: 10 }}
                        >
                          live
                        </span>
                      )}
                      {a.supervised && a.alive === false && (
                        <span
                          className="pill bad"
                          title="Subprocess has died"
                          style={{ fontSize: 10 }}
                        >
                          dead
                        </span>
                      )}
                      {a.kind && (
                        <span
                          className="pill dim"
                          title={`Backend kind: ${a.kind}`}
                          style={{ fontSize: 10 }}
                        >
                          {a.kind}
                        </span>
                      )}
                      {/* Phase G: cap_token scope_model_allowlist
                          badge. Three rendered states reflect the
                          three wire semantics:
                            • field absent  → no badge (unscoped /
                              legacy; backend allowlist is the only
                              gate, no per-token signal to show)
                            • []            → "scope: closed" pill
                              (token explicitly forbids overrides)
                            • [m1, m2, …]   → "scope: m1, m2" pill
                              with full list in the tooltip if it
                              grows past two entries. */}
                      {Array.isArray(a.scope_model_allowlist) && (
                        a.scope_model_allowlist.length === 0 ? (
                          <span
                            // ``wait`` (yellow) not ``bad`` (red) —
                            // self-audit G-3: a closed scope is a
                            // deliberate operator policy choice (safest
                            // config from cost-control POV), worth
                            // drawing the eye to but NOT an error.
                            // The styles.css palette uses ``.pill.wait``
                            // for "needs attention" yellow; ``.pill.warn``
                            // is not a defined variant.
                            className="pill wait"
                            title={
                              "cap_token scope_model_allowlist=[] — " +
                              "this token forbids all params['model'] " +
                              "overrides. The agent will only ever run " +
                              "its backend's DEFAULT_MODEL."
                            }
                            style={{ fontSize: 10 }}
                          >
                            scope: closed
                          </span>
                        ) : (
                          <span
                            className="pill ok"
                            title={
                              "cap_token scope_model_allowlist " +
                              "(per-token model policy): " +
                              a.scope_model_allowlist.join(", ")
                            }
                            style={{ fontSize: 10 }}
                          >
                            scope: {
                              a.scope_model_allowlist.length <= 2
                                ? a.scope_model_allowlist.join(", ")
                                : `${a.scope_model_allowlist[0]} +${a.scope_model_allowlist.length - 1}`
                            }
                          </span>
                        )
                      )}
                      {typeof a.a2a_port === "number" && (
                        <code
                          className="mono"
                          title="Localhost A2A port the child is serving on"
                          style={{
                            fontSize: 10,
                            color: "var(--fg-tertiary)",
                          }}
                        >
                          :{a.a2a_port}
                        </code>
                      )}
                    </h3>
                    <div
                      style={{
                        marginTop: 4,
                        fontSize: 11,
                        color: "var(--fg-tertiary)",
                        display: "flex",
                        gap: 10,
                        alignItems: "center",
                      }}
                    >
                      <code className="mono">{a.code}</code>
                      <span>·</span>
                      <code className="mono">
                        {a.did.slice(0, 20)}…
                      </code>
                      <span>·</span>
                      <span>last seen {relativeTimeShort(a.last_seen)}</span>
                    </div>
                  </div>
                  <span className={`pill ${SOURCE_PILL[a.source]}`}>
                    {SOURCE_LABEL[a.source]}
                  </span>
                </div>

                <div
                  style={{
                    marginTop: 12,
                    display: "flex",
                    flexWrap: "wrap",
                    gap: 6,
                  }}
                >
                  {a.capabilities.map((c) => (
                    <span
                      key={c}
                      style={{
                        fontSize: 11,
                        padding: "2px 8px",
                        borderRadius: 4,
                        background: "var(--bg-elevated)",
                        color: "var(--fg-secondary)",
                        fontFamily: "var(--t-mono)",
                      }}
                    >
                      {c}
                    </span>
                  ))}
                </div>

                <div
                  style={{
                    marginTop: 12,
                    paddingTop: 12,
                    borderTop: "1px solid var(--border)",
                    display: "flex",
                    gap: 8,
                  }}
                >
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={(e) => {
                      e.stopPropagation();
                      onIssueCap(a.did);
                    }}
                  >
                    <IconZap size={12} /> {t("签发 cap_token", "Issue cap_token")}
                  </button>
                  {onSendMessage && a.supervised && a.alive
                   && typeof a.a2a_port === "number" && (
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={(e) => {
                        e.stopPropagation();
                        onSendMessage(a.did);
                      }}
                      aria-label={`Send a message to ${a.label || a.did}`}
                    >
                      <IconSend size={12} /> {t("发消息", "Send message")}
                    </button>
                  )}
                  {/* Phase 3f: live wire test buttons. Only shown
                      for supervised agents that have an a2a_port —
                      contact / LAN / disk-only agents don't have a
                      hub-routable HTTP surface. */}
                  {onPingAgent && a.supervised && a.alive
                   && typeof a.a2a_port === "number" && (
                    <button
                      type="button"
                      className="btn btn-ghost"
                      disabled={busyDids.has(a.did)}
                      onClick={(e) => {
                        e.stopPropagation();
                        void handlePing(a.did);
                      }}
                      title="GET /api/v2/agents/{did}/ping"
                    >
                      {t("探活", "Ping")}
                    </button>
                  )}
                  {onA2AEcho && a.supervised && a.alive
                   && typeof a.a2a_port === "number" && (
                    <button
                      type="button"
                      className="btn btn-ghost"
                      disabled={busyDids.has(a.did)}
                      onClick={(e) => {
                        e.stopPropagation();
                        void handleA2A(a.did);
                      }}
                      title={
                        "POST /api/v2/agents/{did}/a2a/echo " +
                        "(no Authorization — expect 401 to prove " +
                        "the auth check is live)"
                      }
                    >
                      {t("A2A echo", "A2A echo")}
                    </button>
                  )}

                  {onStopAgent && a.supervised && a.agent_id && (
                    <button
                      type="button"
                      className="btn btn-ghost"
                      disabled={stoppingAgentId === a.agent_id}
                      onClick={(e) => {
                        e.stopPropagation();
                        void handleStop(a.agent_id as string);
                      }}
                      title="Stop this supervised local agent"
                    >
                      {stoppingAgentId === a.agent_id ? "Stopping..." : "Stop"}
                    </button>
                  )}
                </div>

                {/* Phase 3f: probe result preview. Color-coded by
                    HTTP status so the operator can scan the wire
                    state without opening the inspector. */}
                {probes.get(a.did) && (
                  <div
                    style={{
                      marginTop: 8,
                      padding: 8,
                      borderTop: "1px solid var(--border)",
                      fontSize: 11,
                      fontFamily: "var(--t-mono)",
                    }}
                  >
                    {(() => {
                      const p = probes.get(a.did)!;
                      const okStatus = p.status >= 200 && p.status < 300;
                      const color = okStatus
                        ? "var(--ok, #2ea44f)"
                        : p.status >= 400 && p.status < 500
                          ? "var(--warn, #d97706)"
                          : "var(--danger, #cf222e)";
                      return (
                        <>
                          <span
                            className="mono"
                            style={{ color, fontWeight: 600 }}
                          >
                            {p.kind} {p.status || "ERR"}
                          </span>
                          <span
                            className="muted"
                            style={{ marginLeft: 8 }}
                          >
                            {new Date(p.at).toLocaleTimeString()}
                          </span>
                          <pre
                            style={{
                              marginTop: 6,
                              marginBottom: 0,
                              maxHeight: 120,
                              overflow: "auto",
                              background: "var(--bg-elevated)",
                              padding: 6,
                              borderRadius: 4,
                              fontSize: 10,
                            }}
                          >
                            {JSON.stringify(p.body, null, 2)}
                          </pre>
                        </>
                      );
                    })()}
                  </div>
                )}
              </article>
            ))}
          </div>
        </div>
      </section>

      <aside className="detail">
        <div className="detail-head">
          <span className="detail-title">{t("Agent 详情", "Agent detail")}</span>
        </div>
        <div className="detail-body">
          {selected ? (
            <>
              <div className="detail-section">
                <div className="detail-section-label">{t("身份", "Identity")}</div>
                <div className="detail-row">
                  <span className="key">{t("标签", "Label")}</span>
                  <span className="value">{selected.label || "—"}</span>
                </div>
                <div className="detail-row">
                  <span className="key">{t("代号", "Code")}</span>
                  <span className="value">{selected.code}</span>
                </div>
                <div className="detail-row">
                  <span className="key">{t("来源", "Source")}</span>
                  <span className="value">{SOURCE_LABEL[selected.source]}</span>
                </div>
                <div className="detail-row">
                  <span className="key">{t("有生效 cap", "Has active cap")}</span>
                  <span className="value">
                    {selected.has_active_cap ? t("是", "yes") : t("否", "no")}
                  </span>
                </div>
              </div>
              {/* UI 集成（2026-06-13）：派任务 + 流式输出。只对有 a2a_port
                  的 supervised 在线 agent 显示（hub 可路由 + 注入 cap_token）。 */}
              {onAskAgent && selected.supervised && selected.alive
               && typeof selected.a2a_port === "number" && (
                <div className="detail-section">
                  <div className="detail-section-label">
                    {t("派任务", "Run task")} {selected.kind ? `· ${selected.kind}` : ""}
                  </div>
                  <textarea
                    value={workPrompt}
                    onChange={(e) => setWorkPrompt(e.target.value)}
                    placeholder={t("给这个 agent 派一个任务（prompt）…", "Assign a task (prompt) to this agent…")}
                    rows={3}
                    style={{
                      width: "100%", resize: "vertical", fontSize: 12,
                      fontFamily: "var(--t-mono)", padding: 8,
                      borderRadius: 6, border: "1px solid var(--border)",
                      background: "var(--bg-elevated)", color: "var(--fg)",
                    }}
                  />
                  <div style={{ display: "flex", gap: 8, marginTop: 6, alignItems: "center" }}>
                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={workStatus === "running" || !workPrompt.trim()}
                      onClick={() => void runAgentWork(selected.did)}
                    >
                      {workStatus === "running" ? t("运行中…", "Running…") : t("运行", "Run")}
                    </button>
                    {workStatus === "running" && (
                      <button
                        type="button"
                        className="btn btn-ghost"
                        onClick={() => workAbort.current?.abort()}
                      >
                        {t("停止", "Stop")}
                      </button>
                    )}
                    {workMeta && (
                      <span className="muted" style={{ fontSize: 11 }}>{workMeta}</span>
                    )}
                  </div>
                  {(workOutput || workStatus !== "idle") && (
                    <pre
                      style={{
                        marginTop: 8, marginBottom: 0, maxHeight: 280,
                        overflow: "auto", whiteSpace: "pre-wrap",
                        wordBreak: "break-word",
                        background: "var(--bg-elevated)", padding: 8,
                        borderRadius: 6, fontSize: 12,
                        fontFamily: "var(--t-mono)",
                      }}
                    >
                      {workOutput || (workStatus === "running" ? (workMeta || "…") : "")}
                    </pre>
                  )}
                  {workStatus === "error" && (
                    <div
                      className="mono"
                      style={{ marginTop: 6, fontSize: 11, color: "var(--danger, #cf222e)" }}
                    >
                      {workError}
                    </div>
                  )}
                </div>
              )}
              <SignaturePanel
                value={{
                  did: selected.did,
                  code: selected.code,
                  label: selected.label,
                  source: selected.source,
                  capabilities: selected.capabilities,
                  last_seen: selected.last_seen,
                  has_active_cap: selected.has_active_cap,
                  ...(selected.agent_card
                    ? { agent_card: selected.agent_card }
                    : {}),
                }}
                title={t("Agent 身份记录", "Agent identity record")}
              />
            </>
          ) : (
            <p className="muted">{t("选择一个 agent 查看。", "Select an agent to inspect.")}</p>
          )}
        </div>
      </aside>
    </>
  );
}
