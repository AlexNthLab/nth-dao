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

import { useState } from "react";
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
// 简化(2026-06-14):聊天优先。首屏只放 Chat + Agents(联系人),其余 7 个
// 专业视图收进"更多",降级不删除(用户决策:全部降级进更多)。NTH DAO
// 启动阶段就是"带着 agent 来聊天",传统聊天软件式低学习成本。
const PRIMARY: { id: NavId; icon: React.ComponentType<{ size?: number }>; label: string }[] = [
  { id: "chat",   icon: IconChat,  label: "Chat" },
  { id: "agents", icon: IconUsers, label: "Agents" },
];

const MORE: { id: NavId; icon: React.ComponentType<{ size?: number }>; label: string }[] = [
  { id: "blackboard", icon: IconLayout,  label: "Blackboard" },
  { id: "inbox",      icon: IconInbox,   label: "Decisions" },
  { id: "missions",   icon: IconTarget,  label: "Missions" },
  { id: "rules",      icon: IconSliders, label: "Rules" },
  { id: "audit",      icon: IconScroll,  label: "Audit" },
  { id: "governance", icon: IconScale,   label: "Governance" },
  { id: "delegate",   icon: IconKey,     label: "Delegate" },
];

export interface IconNavProps {
  active: NavId;
  decisionCount: number;
  onNav: (id: NavId) => void;
}

export function IconNav({ active, decisionCount, onNav }: IconNavProps) {
  const [showMore, setShowMore] = useState(false);
  // 若当前正停在某个"更多"里的视图,自动展开,免得它被藏起来。
  const expanded = showMore || MORE.some((m) => m.id === active);
  // A11y (audit fix 2026-06-10, finding C2): every icon-only nav
  // button needs an aria-label so screen readers can announce the
  // destination. The visual tooltip span exists only for sighted
  // users on hover — assistive tech reads the aria-label instead.
  // Also expose `aria-current="page"` on the active item so screen
  // readers say "current page" — standard nav-landmark idiom.
  const renderItem = (
    { id, icon: Icon, label }: { id: NavId; icon: React.ComponentType<{ size?: number }>; label: string },
  ) => {
    const isActive = active === id;
    const announcement =
      id === "inbox" && decisionCount > 0 ? `${label}, ${decisionCount} pending` : label;
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
        <span className="icon-nav-tooltip" aria-hidden="true">
          {label}
        </span>
      </button>
    );
  };

  // 折叠时,若"更多"里有待办(Decisions 未读),在切换按钮上汇总成一个角标,
  // 免得降级后用户错过审批。展开时各项自带角标,无需汇总。
  const moreBadge = !expanded && decisionCount > 0 ? decisionCount : 0;

  return (
    <nav className="icon-nav" aria-label="Primary navigation">
      {PRIMARY.map(renderItem)}

      <div className="icon-nav-spacer" />

      <button
        type="button"
        className={`icon-nav-btn ${expanded ? "active" : ""}`}
        onClick={() => setShowMore((m) => !m)}
        aria-label="更多"
        aria-expanded={expanded}
        title="更多"
      >
        <span aria-hidden="true" style={{ fontSize: 18, lineHeight: 1 }}>⋯</span>
        {moreBadge > 0 && (
          <span className="icon-nav-badge" aria-hidden="true">
            {moreBadge}
          </span>
        )}
        <span className="icon-nav-tooltip" aria-hidden="true">更多</span>
      </button>

      {expanded && MORE.map(renderItem)}
    </nav>
  );
}
