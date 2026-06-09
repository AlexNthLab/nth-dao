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

import { useMemo, useState } from "react";
import {
  IconSearch, IconUserPlus, IconUsers, IconWifi, IconZap,
} from "./Icons";
import { SignaturePanel } from "./SignaturePanel";
import type { AgentEntry, AgentSource } from "../types-v2";

export interface AgentDirectoryViewProps {
  agents: AgentEntry[];
  /** Wired to /api/agents/add once the backend integration lands. */
  onAddByDid: (did: string, label: string) => Promise<void> | void;
  /** Wired to /api/agents/lan_discover. */
  onScanLan: () => Promise<void> | void;
  /** Issue cap_token to this agent — pivots to Delegate view. */
  onIssueCap: (did: string) => void;
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

function relTime(iso?: string): string {
  if (!iso) return "—";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export function AgentDirectoryView({
  agents, onAddByDid, onScanLan, onIssueCap,
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
                      <span>last seen {relTime(a.last_seen)}</span>
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
                  <button
                    type="button"
                    className="btn btn-ghost"
                    onClick={(e) => e.stopPropagation()}
                  >
                    Send message
                  </button>
                </div>
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
