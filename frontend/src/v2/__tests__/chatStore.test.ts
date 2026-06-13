// @vitest-environment jsdom
/** 热层持久(chatStore)回归:round-trip / TTL 蒸发 / 热窗口截断。 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadChat, saveChat } from "../chatStore";
import type { ChatMessage } from "../types-v2";

function msg(id: string, atMs: number): ChatMessage {
  return {
    message_id: id,
    sender_id: "u",
    sender_label: "you",
    body: id,
    created_at: new Date(atMs).toISOString(),
  };
}

// jsdom 提供 localStorage;每例清空。
beforeEach(() => localStorage.clear());
afterEach(() => vi.useRealTimers());

describe("chatStore 热层持久", () => {
  it("round-trip:存了能读回(含选中会话)", () => {
    const now = Date.now();
    saveChat({ "dm-a": [msg("m1", now), msg("m2", now)] }, "dm-a");
    const got = loadChat();
    expect(got.selectedId).toBe("dm-a");
    expect(got.messages["dm-a"].map((m) => m.message_id)).toEqual(["m1", "m2"]);
  });

  it("TTL:超 7 天无活动的会话加载时蒸发", () => {
    const old = Date.now() - 8 * 24 * 60 * 60 * 1000; // 8 天前
    saveChat({ "dm-old": [msg("x", old)] }, null);
    expect(loadChat().messages["dm-old"]).toBeUndefined();
  });

  it("TTL:近期活动的会话保留", () => {
    const recent = Date.now() - 60_000;
    saveChat({ "dm-new": [msg("y", recent)] }, null);
    expect(loadChat().messages["dm-new"].length).toBe(1);
  });

  it("热窗口:每会话只留最近 200 条", () => {
    const now = Date.now();
    const many = Array.from({ length: 250 }, (_, i) => msg(`m${i}`, now));
    saveChat({ "dm-big": many }, null);
    const got = loadChat().messages["dm-big"];
    expect(got.length).toBe(200);
    expect(got[0].message_id).toBe("m50"); // 砍掉最旧 50 条
    expect(got[199].message_id).toBe("m249");
  });

  it("空/坏数据:不抛,返回空", () => {
    localStorage.setItem("nth.chat.v1", "{ not json");
    expect(loadChat()).toEqual({ messages: {}, selectedId: null });
  });

  it("审查A:消息时间戳损坏的会话**不会**被误判过期消失", () => {
    const bad: ChatMessage = {
      message_id: "b", sender_id: "u", sender_label: "you",
      body: "x", created_at: "not-a-date",
    };
    saveChat({ "dm-bad": [bad] }, "dm-bad");
    // 坏时间戳兜底为"现在" → 不过期 → 仍能读回(否则就是又一次"消失")。
    expect(loadChat().messages["dm-bad"]).toBeDefined();
    expect(loadChat().messages["dm-bad"].length).toBe(1);
  });

  it("审查B:会话数封顶 MAX_CONVS,只留最近活动的", () => {
    const now = Date.now();
    const all: Record<string, ChatMessage[]> = {};
    // 70 个会话,活动时间 now-0 .. now-69 分钟(越小越新)。
    for (let i = 0; i < 70; i++) {
      all[`c${i}`] = [msg(`m${i}`, now - i * 60_000)];
    }
    saveChat(all, null);
    const kept = Object.keys(loadChat().messages);
    expect(kept.length).toBe(60); // MAX_CONVS
    expect(kept).toContain("c0"); // 最新的留
    expect(kept).not.toContain("c69"); // 最旧的砍
  });
});
