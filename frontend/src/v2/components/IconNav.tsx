/**
 * Left vertical primary navigation, 56px wide.
 *
 * Ordering reflects the UI philosophy: Decisions first (because the
 * user's primary job is approval gate), Missions second (because
 * "what is the AI doing for me right now" is the second most
 * important question), Audit third (read-only verification),
 * Governance fourth (cross-user politics), Delegate fifth (the
 * setup screen for AI permissions), Chat last (deprioritized
 * intentionally — see DESIGN_TRADE_OFFS messaging).
 *
 * Hovering a button reveals a tooltip with the long label; the
 * stripe icon style keeps the surface restrained.
 */

import {
  IconChat, IconInbox, IconKey, IconLayout, IconScale, IconScroll,
  IconSliders, IconTarget, IconUsers,
} from "./Icons";
import type { NavId } from "../types-v2";

/* Ordering rationale (DESIGN_TRADE_OFFS extension, autopilot vision):
 *
 *   Blackboard 1st — the autopilot-era main screen: operational
 *   dashboard of every process every agent is driving. As Rules
 *   mature, Decisions Queue shrinks and Blackboard becomes the
 *   eye line for "is my one-person company running smoothly?".
 *
 *   Decisions 2nd — exceptions inbox (manual mode + autopilot
 *   alerts). Has a badge for unread, so it's visually loud when
 *   work is pending and quiet when on-policy.
 *
 *   Missions 3rd — long-running goals (still useful when a single
 *   AI is executing a multi-step plan that doesn't fit a Rule).
 *
 *   Rules 4th — where users transition manual approvals to
 *   autopilot. Each rule pins to a long-lived cap_token.
 *
 *   Audit 5th — read-only verification of the past.
 *
 *   Governance 6th — cross-DAO politics.
 *
 *   Delegate 7th — raw cap_token management (advanced users).
 *
 *   DAO Chat last — deprioritized; NTH DAO is not Slack.
 */
const ITEMS: { id: NavId; icon: React.ComponentType<{ size?: number }>; label: string }[] = [
  { id: "blackboard", icon: IconLayout,  label: "Blackboard" },
  { id: "inbox",      icon: IconInbox,   label: "Decisions" },
  { id: "missions",   icon: IconTarget,  label: "Missions" },
  { id: "rules",      icon: IconSliders, label: "Rules" },
  { id: "agents",     icon: IconUsers,   label: "Agents" },
  { id: "audit",      icon: IconScroll,  label: "Audit" },
  { id: "governance", icon: IconScale,   label: "Governance" },
  { id: "delegate",   icon: IconKey,     label: "Delegate" },
];

const SECONDARY: { id: NavId; icon: React.ComponentType<{ size?: number }>; label: string }[] = [
  { id: "chat", icon: IconChat, label: "Chat" },
];

export interface IconNavProps {
  active: NavId;
  decisionCount: number;
  onNav: (id: NavId) => void;
}

export function IconNav({ active, decisionCount, onNav }: IconNavProps) {
  return (
    <nav className="icon-nav">
      {ITEMS.map(({ id, icon: Icon, label }) => (
        <button
          key={id}
          className={`icon-nav-btn ${active === id ? "active" : ""}`}
          onClick={() => onNav(id)}
        >
          <Icon size={18} />
          {id === "inbox" && decisionCount > 0 && (
            <span className="icon-nav-badge">{decisionCount}</span>
          )}
          <span className="icon-nav-tooltip">{label}</span>
        </button>
      ))}

      <div className="icon-nav-spacer" />

      {SECONDARY.map(({ id, icon: Icon, label }) => (
        <button
          key={id}
          className={`icon-nav-btn ${active === id ? "active" : ""}`}
          onClick={() => onNav(id)}
        >
          <Icon size={18} />
          <span className="icon-nav-tooltip">{label}</span>
        </button>
      ))}
    </nav>
  );
}
