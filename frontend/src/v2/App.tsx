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

import { useEffect, useMemo, useState } from "react";

import { AgentDirectoryView } from "./components/AgentDirectoryView";
import { BlackboardView } from "./components/BlackboardView";
import { ChatView } from "./components/ChatView";
import { CommandPalette } from "./components/CommandPalette";
import { DecisionQueue } from "./components/DecisionQueue";
import { IconNav } from "./components/IconNav";
import { MissionList } from "./components/MissionList";
import { RulesView } from "./components/RulesView";
import { StatusBar } from "./components/StatusBar";
import { Topbar } from "./components/Topbar";
import {
  mockAgents, mockCapTokens, mockChatMessages, mockConversations,
  mockDecisions, mockMissions, mockProcesses, mockReceipts, mockRules,
} from "./mock";
import type {
  ChatMessage,
  CommandItem,
  Conversation,
  Decision,
  IdentityHeader,
  NavId,
  StatusBarState,
} from "./types-v2";

import "./styles.css";

/* ── Identity bootstrap (placeholder — wires to /api/identity later) */
const MOCK_IDENTITY: IdentityHeader = {
  agent_id: "admin",
  did: "did:key:z6MkmRxmBi9p9ziBz2JzBwd8Y5iMzzhPXAi95MPZiLEJJqjL",
  code: "a3ff-62eb",
};

export default function App() {
  /* Default landing = Blackboard per the autopilot-mode philosophy
   * (DESIGN_TRADE_OFFS extension): the operational dashboard is
   * the steady-state home screen; Decisions is consulted only when
   * the badge calls. In manual mode (early V1) users will quickly
   * switch to Decisions; the badge + Cmd+K make that one keypress. */
  const [active, setActive] = useState<NavId>("blackboard");
  const [decisions, setDecisions] = useState<Decision[]>(mockDecisions);
  const [cmdkOpen, setCmdkOpen] = useState(false);
  // Chat state — local-only for v1; flips to /api/messages on
  // backend integration. The shape (Record<convId, Message[]>)
  // matches the mock seed so the swap is a one-liner.
  const [chatMessages, setChatMessages] = useState<Record<string, ChatMessage[]>>(
    mockChatMessages,
  );
  const [conversations] = useState<Conversation[]>(mockConversations);

  /* ── decision handlers (declared early so the keyboard handler
   *    below can reference them) ─────────────────────────────── */
  function handleApprove(id: string) {
    setDecisions((prev) => prev.filter((d) => d.id !== id));
    // TODO: POST /api/decisions/{id}/approve
  }
  function handleReject(id: string) {
    setDecisions((prev) => prev.filter((d) => d.id !== id));
    // TODO: POST /api/decisions/{id}/reject
  }
  function handleDefer(id: string) {
    setDecisions((prev) => prev.filter((d) => d.id !== id));
    // TODO: POST /api/decisions/{id}/defer
  }

  /* U7 (audit fix 2026-06-10): Cmd+J / Cmd+R / Cmd+D shortcuts on
   * Decisions view used to be decorative kbd hints — now they
   * actually fire. Falls through to default browser behavior on
   * non-Decisions views (Cmd+R reload remains, Cmd+D bookmark
   * remains) so we never hijack a global Ctrl+R reload in dev. */
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      // Cmd+K → command palette (works on every view)
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCmdkOpen(true);
        return;
      }
      // Cmd+J/R/D on Decisions view only — operate on the first
      // pending decision after impact-sorted order. Refusing to
      // hijack Cmd+R on other views is a deliberate constraint.
      if (active === "inbox" && (e.metaKey || e.ctrlKey)) {
        const sorted = decisions.slice().sort((a, b) => {
          const rank: Record<Decision["impact"], number> = {
            high: 0, medium: 1, low: 2,
          };
          return rank[a.impact] - rank[b.impact] ||
            a.raised_at.localeCompare(b.raised_at);
        });
        const top = sorted[0];
        if (!top) return;
        const k = e.key.toLowerCase();
        if (k === "j") {
          e.preventDefault();
          handleApprove(top.id);
        } else if (k === "d") {
          e.preventDefault();
          handleDefer(top.id);
        }
        // Note: we deliberately do NOT bind Cmd+R for Reject —
        // it collides with browser reload and would cause real
        // pain in dev. Reject stays a click-only action.
      }
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
      active_caps: mockCapTokens.filter((c) => !c.revoked).length,
      caps_expiring_soon: mockCapTokens.filter(
        (c) => !c.revoked && c.not_after - Date.now() < 4 * 3600_000,
      ).length,
      chain_head_short:
        mockReceipts[mockReceipts.length - 1]?.content_hash.slice(0, 12) ?? "",
      active_missions: mockMissions.filter(
        (m) => m.status === "active" || m.status === "planning",
      ).length,
      pending_decisions: decisions.length,
    }),
    [decisions],
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

  /* ── chat send handler (local-only for v1) ────────────────── */
  async function handleChatSend(convId: string, body: string) {
    const msg: ChatMessage = {
      message_id: `m-local-${Date.now()}`,
      sender_id: "admin",
      sender_label: "you",
      body,
      created_at: new Date().toISOString(),
    };
    setChatMessages((prev) => ({
      ...prev,
      [convId]: [...(prev[convId] ?? []), msg],
    }));
    // TODO: POST /api/messages with {channel_id, body}
  }

  /* ── agent directory handlers (local-only for v1) ─────────── */
  function handleAddAgent(did: string, label: string) {
    // TODO: POST /api/agents/add with {target_did, label}
    console.log("[v2] add agent placeholder:", did, label);
  }
  function handleScanLan() {
    // TODO: POST /api/agents/lan_discover and refresh list
    console.log("[v2] LAN scan placeholder");
  }
  function handleIssueCap(did: string) {
    setActive("delegate");
    console.log("[v2] pivot to Delegate to issue cap for:", did);
  }

  /* ── current view ── */
  let view: React.ReactNode;
  if (active === "blackboard") {
    view = <BlackboardView processes={mockProcesses} />;
  } else if (active === "inbox") {
    view = (
      <DecisionQueue
        decisions={decisions}
        onApprove={handleApprove}
        onReject={handleReject}
        onDefer={handleDefer}
      />
    );
  } else if (active === "missions") {
    view = <MissionList missions={mockMissions} />;
  } else if (active === "rules") {
    view = <RulesView rules={mockRules} />;
  } else if (active === "agents") {
    view = (
      <AgentDirectoryView
        agents={mockAgents}
        onAddByDid={handleAddAgent}
        onScanLan={handleScanLan}
        onIssueCap={handleIssueCap}
      />
    );
  } else if (active === "chat") {
    view = (
      <ChatView
        conversations={conversations}
        messagesByConv={chatMessages}
        onSend={handleChatSend}
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
