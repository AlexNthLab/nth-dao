/**
 * 对话「热层」本地持久(切片1)。
 *
 * 设计(见对话):热层 = 最近的工作记忆,**不签名、不联邦、带 TTL**。它只
 * 解决一件事 —— 刷新/切频道/换 agent 后对话别消失。它**不是**永久存储:
 * 大部分闲聊本就无长期价值,过 TTL 即蒸发,零长期负担。真正值得留的(签名
 * 摘要 / 承诺收据)是后续「温/冷」层的事,不在这里。
 *
 * 落点:浏览器 localStorage(每 origin 私有、廉价、可过期)。配额满 / 隐私
 * 模式下尽力而为,失败不抛(热层丢一点可接受,冷层才是底线)。
 */

import type { ChatMessage } from "./types-v2";

const KEY = "nth.chat.v1";
const TTL_MS = 7 * 24 * 60 * 60 * 1000; // 热层保留 7 天(按会话最后活动算)
const MAX_PER_CONV = 200; // 每会话热窗口上限;更老的交给「温」层签名摘要(切片2)
// 审查修复 B:封顶会话**数量**,只留最近活动的 N 个。否则会话数无界 →
// 单个大 blob 撑爆 localStorage 配额 → setItem 抛错被静默吞掉 → **全部**
// 持久失效(all-or-nothing)→ 又退回"对话消失"。
const MAX_CONVS = 60;

// ⚠️ 隐私边界(诚实):热层是**明文** localStorage,同源任意脚本(XSS)+
// 同机其他用户可读。敏感对话不应只靠它;静态加密 / 多用户隔离是后续的事。
// 热层定位就是"廉价、易耗、本地"——别往里放需要保密的东西。

interface Persisted {
  messages: Record<string, ChatMessage[]>;
  /** 每会话最后活动时间(TTL 判据)。 */
  updatedAt: Record<string, number>;
  selectedId: string | null;
  savedAt: number;
}

export interface LoadedChat {
  messages: Record<string, ChatMessage[]>;
  selectedId: string | null;
}

/** 会话最后活动时间 = **所有**消息里最大的有效时间戳(审查修复 A:不能
 *  只看最后一条 —— 最后一条若时间戳坏了会把整会话判为 epoch 0 → 立即过期
 *  → 消失。扫全部取 max,坏的忽略)。一个有效的都没有 → 返回 0,由调用方
 *  兜底成"现在"。 */
function lastActivityMs(msgs: ChatMessage[]): number {
  let max = 0;
  for (const m of msgs) {
    const t = Date.parse(m?.created_at ?? "");
    if (Number.isFinite(t) && t > max) max = t;
  }
  return max;
}

/** 从 localStorage 加载;丢弃 TTL 过期的会话,每会话只留热窗口。 */
export function loadChat(): LoadedChat {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { messages: {}, selectedId: null };
    const p = JSON.parse(raw) as Persisted;
    const now = Date.now();
    const messages: Record<string, ChatMessage[]> = {};
    for (const [cid, msgs] of Object.entries(p.messages || {})) {
      const last = p.updatedAt?.[cid] ?? lastActivityMs(msgs || []);
      // 只有**已知**过老才蒸发;last<=0(年龄未知)→ 保留,绝不因时间戳
      // 缺失而误删(审查修复 A)。
      if (last > 0 && now - last > TTL_MS) continue;
      messages[cid] = (msgs || []).slice(-MAX_PER_CONV);
    }
    return { messages, selectedId: p.selectedId ?? null };
  } catch {
    return { messages: {}, selectedId: null };
  }
}

/** 落盘(带每会话活动时间 + 热窗口截断)。失败静默 —— 热层尽力而为。 */
export function saveChat(
  messages: Record<string, ChatMessage[]>,
  selectedId: string | null,
): void {
  try {
    const now = Date.now();
    // 收集非空会话 + 其活动时间(坏时间戳兜底为 now,审查修复 A:绝不让
    // 时间戳问题把刚用过的会话判过期)。
    const entries = Object.entries(messages)
      .filter(([, m]) => m && m.length)
      .map(([cid, m]) => {
        const capped = m.slice(-MAX_PER_CONV);
        return { cid, msgs: capped, act: lastActivityMs(capped) || now };
      });
    // 审查修复 B:按活动时间降序,只留最近 MAX_CONVS 个,封顶 blob 大小。
    entries.sort((a, b) => b.act - a.act);
    const kept = entries.slice(0, MAX_CONVS);
    const capped: Record<string, ChatMessage[]> = {};
    const updatedAt: Record<string, number> = {};
    for (const e of kept) {
      capped[e.cid] = e.msgs;
      updatedAt[e.cid] = e.act;
    }
    const p: Persisted = {
      messages: capped,
      updatedAt,
      selectedId,
      savedAt: now,
    };
    localStorage.setItem(KEY, JSON.stringify(p));
  } catch {
    /* 配额满 / 隐私模式 → 忽略 */
  }
}
