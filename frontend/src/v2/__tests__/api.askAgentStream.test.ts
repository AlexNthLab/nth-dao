/**
 * UI 集成回归（2026-06-13）：askAgentStream 的 SSE 解析。
 *
 * 这是流式客户端最易出错的部分 —— 把分块到达的 ``data: {...}\n\n`` 事件
 * 正确切分、累积 delta、捕获 done 的 backend/model、对 error 抛错。用一个
 * 假 fetch（ReadableStream）喂入故意跨 chunk 切断的字节，验证解析鲁棒。
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { askAgentStream } from "../api";

function streamFrom(chunks: string[]): Response {
  const enc = new TextEncoder();
  let i = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (i < chunks.length) {
        controller.enqueue(enc.encode(chunks[i++]));
      } else {
        controller.close();
      }
    },
  });
  return new Response(body, {
    status: 200,
    headers: { "Content-Type": "text/event-stream" },
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("askAgentStream", () => {
  it("累积 delta、捕获 done 的 backend/model（含跨 chunk 切断）", async () => {
    // 故意把一个事件切到两个 chunk 里，验证 buffer 拼接。
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(streamFrom([
      'data: {"delta":"Hel',
      'lo"}\n\n',
      'data: {"delta":" world"}\n\n',
      'data: {"done":true,"backend":"hermes","model":"deepseek-v4-pro"}\n\n',
    ])));

    const deltas: string[] = [];
    const res = await askAgentStream("did:key:zX", "hi", (d) => deltas.push(d));
    expect(deltas).toEqual(["Hello", " world"]);
    expect(res.text).toBe("Hello world");
    expect(res.backend).toBe("hermes");
    expect(res.model).toBe("deepseek-v4-pro");
  });

  it("error 事件 → 抛错", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(streamFrom([
      'data: {"error":{"code":"backend-failed","message":"boom"}}\n\n',
    ])));
    await expect(
      askAgentStream("did:key:zX", "hi", () => {}),
    ).rejects.toThrow(/backend-failed/);
  });

  it("非 2xx → 抛错带可读消息", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ detail: "agent has no cap_token" }), {
        status: 409, headers: { "Content-Type": "application/json" },
      }),
    ));
    await expect(
      askAgentStream("did:key:zX", "hi", () => {}),
    ).rejects.toThrow(/cap_token/);
  });

  it("onStatus 报告阶段", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(streamFrom([
      'data: {"delta":"x"}\n\n',
      'data: {"done":true}\n\n',
    ])));
    const statuses: string[] = [];
    await askAgentStream("did:key:zX", "hi", () => {}, undefined, (s) => statuses.push(s));
    expect(statuses).toContain("streaming");
    expect(statuses).toContain("done");
  });
});
