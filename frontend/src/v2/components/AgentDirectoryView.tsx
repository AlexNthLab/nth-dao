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
import type { AgentEntry, AgentSource } from "../types-v2";

export interface AgentDirectoryViewProps {
  agents: AgentEntry[];
  /** Wired to /api/agents/add once the backend integration lands. */
  onAddByDid: (did: string, label: string) => Promise<void> | void;
  /** Wired to /api/agents/lan_discover. */
  onScanLan: () => Promise<void> | void;
  /** Issue cap_token to this agent — pivots to Delegate view. */
  onIssueCap: (did: string) => void;
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
  agents, onAddByDid, onScanLan, onIssueCap, onSendMessage,
  onPingAgent, onA2AEcho,
}: AgentDirectoryViewProps) {
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  const [addOpen, setAddOpen] = useState(false);
  const [newDid, setNewDid] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [scanning, setScanning] = useState(false);
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
  useEffect(() => {
    const map = inflight.current;
    return () => {
      for (const ctrl of map.values()) ctrl.abort();
      map.clear();
    };
  }, []);

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
      // Only clear the slot if it still points at OUR controller —
      // a newer call may have replaced it.
      if (inflight.current.get(did) === ctrl) {
        inflight.current.delete(did);
      }
      markBusy(did, false);
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
      if (inflight.current.get(did) === ctrl) {
        inflight.current.delete(did);
      }
      markBusy(did, false);
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

  async function handleAdd(e: React.FormEvent) {
    e.preventDefault();
    if (!newDid.trim()) return;
    await onAddByDid(newDid.trim(), newLabel.trim());
    setNewDid("");
    setNewLabel("");
    setAddOpen(false);
  }

  async function handleScan() {
    setScanning(true);
    try {
      await onScanLan();
    } finally {
      setScanning(false);
    }
  }

  return (
    <>
      <aside className="sidebar">
        <div className="sidebar-head">
          <span className="sidebar-title">Agents</span>
          <span className="sidebar-count">{agents.length}</span>
        </div>
        <div className="sidebar-list">
          <button
            className={`sidebar-item ${filter === "all" ? "active" : ""}`}
            onClick={() => setFilter("all")}
          >
            <div className="sidebar-item-title">
              <span>All agents</span>
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
          <h1 className="main-title">Who's available to work for you</h1>
          <p className="main-subtitle">
            Local helpers, hand-added contacts, and peers discovered
            on your network. Issue a cap_token to delegate work; tap a
            row to inspect their A2A capabilities.
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
              <IconUserPlus size={14} /> Add by DID
            </button>
            <button
              className="btn btn-secondary"
              onClick={handleScan}
              disabled={scanning}
            >
              <IconWifi size={14} /> {scanning ? "Scanning…" : "Scan LAN"}
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
                placeholder="Search by label, DID, or code…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                spellCheck={false}
              />
            </div>
          </div>

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
                <div className="detail-section-label">Add agent by DID</div>
                <input
                  placeholder="did:key:z6Mk… (paste the agent's DID)"
                  value={newDid}
                  onChange={(e) => setNewDid(e.target.value)}
                  spellCheck={false}
                  className="mono"
                  style={{ fontFamily: "var(--t-mono)", fontSize: 12 }}
                />
                <input
                  placeholder="Label (your own name for this agent)"
                  value={newLabel}
                  onChange={(e) => setNewLabel(e.target.value)}
                />
                <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
                  <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={!newDid.trim()}
                  >
                    Add
                  </button>
                  <button
                    type="button"
                    className="btn btn-ghost"
                    onClick={() => setAddOpen(false)}
                  >
                    Cancel
                  </button>
                </div>
                <p className="muted" style={{ fontSize: 11, marginTop: 4 }}>
                  The agent will appear under <strong>Contacts</strong>{" "}
                  immediately. To grant authority, issue a cap_token from
                  the Delegate tab.
                </p>
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
                    ? "No agent matches that search."
                    : "No agents in this category yet."}
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
                      {a.label || "(unlabeled)"}
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
                    <IconZap size={12} /> Issue cap_token
                  </button>
                  {onSendMessage && (
                    <button
                      type="button"
                      className="btn btn-ghost"
                      onClick={(e) => {
                        e.stopPropagation();
                        onSendMessage(a.did);
                      }}
                      aria-label={`Send a message to ${a.label || a.did}`}
                    >
                      <IconSend size={12} /> Send message
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
                      Ping
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
                      A2A echo
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
          <span className="detail-title">Agent detail</span>
        </div>
        <div className="detail-body">
          {selected ? (
            <>
              <div className="detail-section">
                <div className="detail-section-label">Identity</div>
                <div className="detail-row">
                  <span className="key">Label</span>
                  <span className="value">{selected.label || "—"}</span>
                </div>
                <div className="detail-row">
                  <span className="key">Code</span>
                  <span className="value">{selected.code}</span>
                </div>
                <div className="detail-row">
                  <span className="key">Source</span>
                  <span className="value">{SOURCE_LABEL[selected.source]}</span>
                </div>
                <div className="detail-row">
                  <span className="key">Has active cap</span>
                  <span className="value">
                    {selected.has_active_cap ? "yes" : "no"}
                  </span>
                </div>
              </div>
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
                title="Agent identity record"
              />
            </>
          ) : (
            <p className="muted">Select an agent to inspect.</p>
          )}
        </div>
      </aside>
    </>
  );
}
