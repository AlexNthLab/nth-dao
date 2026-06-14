/**
 * Left vertical primary navigation, 56px wide.
 *
 * 排序原则(2026-06-14 重定):项目第一性原则是 A2A 任务协调便利,所有
 * 视图围绕"任务管理 / 任务建设推进"。因此按使用频次平铺九项、不再用
 * "更多"抽屉折叠;任务态在前,Chat(用户间沟通)是低频沟通入口、下沉。
 *
 * 频次顺序:
 *   Blackboard — 运行态总览(每个 agent 在推进什么),默认落地
 *   Missions   — 任务(建设/推进的核心载体)
 *   Decisions  — 审批闸口(任务推进中的例外),带未读角标
 *   Agents     — 被协调的 worker 目录
 *   Rules      — 把人工审批转自动驾驶的策略
 *   Chat       — 用户间沟通(低频,友好但非主线)
 *   Audit      — 只读核验
 *   Governance — 跨 DAO 治理
 *   Delegate   — cap_token 高级管理
 *
 * 悬停露出长标签 tooltip;图标条保持克制。
 */

import {
  IconBriefcase, IconChat, IconHash, IconInbox, IconKey, IconLayout, IconScale,
  IconScroll, IconSliders, IconTarget, IconUsers,
} from "./Icons";
import type { NavId } from "../types-v2";

const ITEMS: { id: NavId; icon: React.ComponentType<{ size?: number }>; label: string }[] = [
  { id: "blackboard", icon: IconLayout,     label: "Blackboard" },
  { id: "missions",   icon: IconTarget,     label: "Missions" },
  { id: "tasks",      icon: IconBriefcase,  label: "Tasks" },
  { id: "inbox",      icon: IconInbox,      label: "Decisions" },
  { id: "agents",     icon: IconUsers,   label: "Agents" },
  { id: "channels",   icon: IconHash,    label: "Channels" },
  { id: "rules",      icon: IconSliders, label: "Rules" },
  { id: "chat",       icon: IconChat,    label: "Chat" },
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
  // A11y (audit fix 2026-06-10, finding C2): every icon-only nav
  // button needs an aria-label so screen readers can announce the
  // destination. The visual tooltip span exists only for sighted
  // users on hover — assistive tech reads the aria-label instead.
  // Also expose `aria-current="page"` on the active item so screen
  // readers say "current page" — standard nav-landmark idiom.
  return (
    <nav className="icon-nav" aria-label="Primary navigation">
      {ITEMS.map(({ id, icon: Icon, label }) => {
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
            <span className="icon-nav-tooltip" aria-hidden="true">
              {label}
            </span>
          </button>
        );
      })}
    </nav>
  );
}
