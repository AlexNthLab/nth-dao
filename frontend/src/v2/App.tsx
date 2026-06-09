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

import { BlackboardView } from "./components/BlackboardView";
import { CommandPalette } from "./components/CommandPalette";
import { DecisionQueue } from "./components/DecisionQueue";
import { IconNav } from "./components/IconNav";
import { MissionList } from "./components/MissionList";
import { RulesView } from "./components/RulesView";
import { StatusBar } from "./components/StatusBar";
import { Topbar } from "./components/Topbar";
import {
  mockCapTokens, mockDecisions, mockMissions, mockProcesses,
  mockReceipts, mockRules,
} from "./mock";
import type {
  CommandItem,
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

  // Global keyboard: Cmd/Ctrl+K opens the command palette.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setCmdkOpen(true);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

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
      { id: "nav-audit",      title: "Go to Audit",       shortcut: "G A", run: () => setActive("audit") },
      { id: "nav-governance", title: "Go to Governance",  shortcut: "G V", run: () => setActive("governance") },
      { id: "nav-delegate",   title: "Go to Delegate",    shortcut: "G D", run: () => setActive("delegate") },
      { id: "nav-chat",       title: "Go to DAO Chat",    shortcut: "G C", run: () => setActive("chat") },
      {
        id: "new-rule",
        title: "Create a new Rule",
        hint: "Move an approval flow to autopilot",
        run: () => setActive("rules"),
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

  /* ── decision handlers (mock — to be wired to /api/decisions) ── */
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
    case "audit":      return "Audit";
    case "governance": return "Governance";
    case "delegate":   return "Delegate";
    case "chat":       return "DAO Chat";
  }
}
