/**
 * Left vertical primary navigation, 56px wide.
 *
 * 排序原则(2026 重排,第一性):UI 是给**人**的(agent 走 API/MCP,本就无 UI)。
 * 故按**人的注意力**排,而非按"是不是 AI":
 *   主导航(常驻)= 人需要"拍板 / 主动做 / 经常查"的面:
 *     Decisions  — 审批闸口(Push:需要你拍板),带未读角标
 *     Delegate   — 授权收件箱(Push:批准 agent 求权)
 *     Tasks      — 任务市场(主动:发布 / 承接)
 *     Agents     — 协作对象目录
 *     Audit      — 证据链 / 争议(按需核验)
 *     Governance — 立宪 / 治理(罕配)
 *   「更多」抽屉(按需展开)= Ambient 监控 + 低频沟通 + 待并入面:
 *     Blackboard(实时监控,降级)/ Missions / Rules / Reputation / Channels / Chat
 *
 * 降级 ≠ 删除:监控 / 审计是"trust=可见+可控"的命根,收进按需、出事可调出。
 * 当前活动项若在抽屉里,抽屉自动展开,避免选中项不可见。
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
  { id: "inbox",      icon: IconInbox,     label: "Inbox" },
  { id: "tasks",      icon: IconBriefcase, label: "Tasks" },
  { id: "agents",     icon: IconUsers,     label: "Agents" },
  { id: "audit",      icon: IconScroll,    label: "Audit" },
  { id: "governance", icon: IconScale,     label: "Governance" },
];

const MORE: Item[] = [
  { id: "blackboard", icon: IconLayout,    label: "Blackboard" },
  { id: "missions",   icon: IconTarget,    label: "Missions" },
  { id: "rules",      icon: IconSliders,   label: "Rules" },
  { id: "reputation", icon: IconStar,      label: "Reputation" },
  { id: "contacts",   icon: IconUserPlus,  label: "Contacts" },
  { id: "channels",   icon: IconHash,      label: "Channels" },
  { id: "chat",       icon: IconChat,      label: "Chat" },
];

export interface IconNavProps {
  active: NavId;
  decisionCount: number;
  onNav: (id: NavId) => void;
}

export function IconNav({ active, decisionCount, onNav }: IconNavProps) {
  const [showMore, setShowMore] = useState(false);
  // 当前活动项在抽屉里 → 自动展开,避免选中项不可见(命令面板可直达抽屉项)。
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
