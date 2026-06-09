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
  IconChat, IconInbox, IconKey, IconScale, IconScroll, IconTarget,
} from "./Icons";
import type { NavId } from "../types-v2";

const ITEMS: { id: NavId; icon: React.ComponentType<{ size?: number }>; label: string }[] = [
  { id: "inbox",      icon: IconInbox,  label: "Decisions" },
  { id: "missions",   icon: IconTarget, label: "Missions" },
  { id: "audit",      icon: IconScroll, label: "Audit" },
  { id: "governance", icon: IconScale,  label: "Governance" },
  { id: "delegate",   icon: IconKey,    label: "Delegate" },
];

const SECONDARY: { id: NavId; icon: React.ComponentType<{ size?: number }>; label: string }[] = [
  { id: "chat", icon: IconChat, label: "DAO Chat" },
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
