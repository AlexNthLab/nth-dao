/**
 * Left vertical primary navigation, 56px wide.
 *
 * UI is for humans; agents use API surfaces. Keep the existing public
 * names, but order the main rail by the human workflow:
 *   Blackboard -> Missions -> Tasks -> Channels -> Agents -> Inbox
 * The "More" drawer keeps audit/governance surfaces close without making
 * the first screen feel like a protocol control panel.
 */

import { useState } from "react";
import {
  IconBriefcase, IconChat, IconHash, IconInbox, IconLayout, IconScale,
  IconScroll, IconSliders, IconStar, IconTarget, IconUserPlus, IconUsers,
} from "./Icons";
import type { NavId } from "../types-v2";

type Item = {
  id: NavId;
  icon: React.ComponentType<{ size?: number }>;
  label: string;
};

const PRIMARY: Item[] = [
  { id: "blackboard", icon: IconLayout,    label: "Blackboard" },
  { id: "missions",   icon: IconTarget,    label: "Missions" },
  { id: "tasks",      icon: IconBriefcase, label: "Tasks" },
  { id: "channels",   icon: IconHash,      label: "Channels" },
  { id: "agents",     icon: IconUsers,     label: "Agents" },
  { id: "inbox",      icon: IconInbox,     label: "Inbox" },
];

const MORE: Item[] = [
  { id: "audit",      icon: IconScroll,    label: "Audit" },
  { id: "rules",      icon: IconSliders,   label: "Rules" },
  { id: "governance", icon: IconScale,     label: "Governance" },
  { id: "reputation", icon: IconStar,      label: "Reputation" },
  { id: "contacts",   icon: IconUserPlus,  label: "Contacts" },
  { id: "chat",       icon: IconChat,      label: "Chat" },
];

export interface IconNavProps {
  active: NavId;
  decisionCount: number;
  onNav: (id: NavId) => void;
}

export function IconNav({ active, decisionCount, onNav }: IconNavProps) {
  const [showMore, setShowMore] = useState(false);
  const moreActive = MORE.some((m) => m.id === active);
  const expanded = showMore || moreActive;

  function renderBtn({ id, icon: Icon, label }: Item) {
    const isActive = active === id;
    const announcement =
      id === "inbox" && decisionCount > 0
        ? `${label}, ${decisionCount} pending`
        : label;
    return (
      <button
        key={id}
        type="button"
        className={`icon-nav-btn ${isActive ? "active" : ""}`}
        onClick={() => onNav(id)}
        aria-label={announcement}
        aria-current={isActive ? "page" : undefined}
        title={label}
      >
        <Icon size={18} />
        {id === "inbox" && decisionCount > 0 && (
          <span className="icon-nav-badge" aria-hidden="true">
            {decisionCount}
          </span>
        )}
        <span className="icon-nav-tooltip" aria-hidden="true">{label}</span>
      </button>
    );
  }

  return (
    <nav className="icon-nav" aria-label="Primary navigation">
      {PRIMARY.map(renderBtn)}
      <button
        type="button"
        className="icon-nav-btn"
        onClick={() => setShowMore((v) => !v)}
        aria-label={expanded ? "Collapse more" : "More"}
        aria-expanded={expanded}
        title={expanded ? "收起" : "更多"}
      >
        <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
          <circle cx="5" cy="12" r="2" />
          <circle cx="12" cy="12" r="2" />
          <circle cx="19" cy="12" r="2" />
        </svg>
        <span className="icon-nav-tooltip" aria-hidden="true">
          {expanded ? "收起" : "更多"}
        </span>
      </button>
      {expanded && MORE.map(renderBtn)}
    </nav>
  );
}
