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

function lastActivityMs(msgs: ChatMessage[]): number {
  const last = msgs[msgs.length - 1];
  const t = last ? Date.parse(last.created_at) : 0;
  return Number.isFinite(t) ? t : 0;
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
      if (now - last > TTL_MS) continue; // 过期 → 蒸发,不加载
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
    const capped: Record<string, ChatMessage[]> = {};
    const updatedAt: Record<string, number> = {};
    for (const [cid, msgs] of Object.entries(messages)) {
      if (!msgs || !msgs.length) continue;
      capped[cid] = msgs.slice(-MAX_PER_CONV);
      updatedAt[cid] = lastActivityMs(capped[cid]); // 按真实活动算 TTL,非保存时刻
    }
    const p: Persisted = {
      messages: capped,
      updatedAt,
      selectedId,
      savedAt: Date.now(),
    };
    localStorage.setItem(KEY, JSON.stringify(p));
  } catch {
    /* 配额满 / 隐私模式 → 忽略 */
  }
}
