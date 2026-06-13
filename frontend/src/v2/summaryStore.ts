/**
 * 温层本地存储(切片2b):签名对话摘要的保留层。
 *
 * 摘要是**有价值的残留**(小、签名、可独立验)——所以比热层(易耗、TTL 7天)
 * 保留更久。但仍封顶,防膨胀:每会话最多 MAX_PER_CONV 条摘要、总会话数封顶。
 * 注:这是前端本地缓存层;真正的"可验持久"靠 receipt 本身(谁拿到都能后端
 * 重验),localStorage 只是顺手留一份给 UI 展示。
 */

import type { ConversationSummary } from "./types-v2";

const KEY = "nth.chat.summaries.v1";
const TTL_MS = 30 * 24 * 60 * 60 * 1000; // 温层保留 30 天(>热层 7 天)
const MAX_PER_CONV = 20;
const MAX_CONVS = 80;

type Store = Record<string, ConversationSummary[]>;

function activityMs(list: ConversationSummary[]): number {
  let max = 0;
  for (const s of list) {
    const t = Date.parse(s?.created_at ?? "");
    if (Number.isFinite(t) && t > max) max = t;
  }
  return max;
}

export function loadSummaries(): Store {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return {};
    const all = JSON.parse(raw) as Store;
    const now = Date.now();
    const out: Store = {};
    for (const [cid, list] of Object.entries(all)) {
      if (!Array.isArray(list) || !list.length) continue;
      const act = activityMs(list);
      if (act > 0 && now - act > TTL_MS) continue; // 过老 → 蒸发
      out[cid] = list.slice(-MAX_PER_CONV);
    }
    return out;
  } catch {
    return {};
  }
}

export function saveSummaries(store: Store): void {
  try {
    const now = Date.now();
    const entries = Object.entries(store)
      .filter(([, l]) => Array.isArray(l) && l.length)
      .map(([cid, l]) => ({ cid, list: l.slice(-MAX_PER_CONV), act: activityMs(l) || now }));
    entries.sort((a, b) => b.act - a.act);
    const kept: Store = {};
    for (const e of entries.slice(0, MAX_CONVS)) kept[e.cid] = e.list;
    localStorage.setItem(KEY, JSON.stringify(kept));
  } catch {
    /* 配额满 → 忽略 */
  }
}

/** 追加一条摘要并落盘(去重:同一组 covered_message_ids 不重复存)。 */
export function appendSummary(
  store: Store,
  convId: string,
  summary: ConversationSummary,
): Store {
  const prev = store[convId] ?? [];
  const key = summary.covered_message_ids.join(",");
  if (prev.some((s) => s.covered_message_ids.join(",") === key)) return store;
  const next: Store = { ...store, [convId]: [...prev, summary].slice(-MAX_PER_CONV) };
  saveSummaries(next);
  return next;
}
