import { afterEach, describe, expect, it, vi } from "vitest";
import { askAgentStream } from "../api";

// 传输层兜底:后端永久挂起(连响应头都不给)时,空闲超时应 abort 并抛
// 出可读的"超时"错误,而不是让上层的"思考中"永远转下去。
describe("askAgentStream 空闲超时", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("流挂起 → idleTimeoutMs 后 abort 抛超时", async () => {
    vi.useFakeTimers();
    // fetch 永不 resolve,但尊重传入的 abort signal(真实 fetch 行为)。
    const fetchMock = vi.fn(
      (_url: string, init: { signal: AbortSignal }) =>
        new Promise((_resolve, reject) => {
          init.signal.addEventListener("abort", () =>
            reject(new DOMException("aborted", "AbortError")),
          );
        }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const p = askAgentStream("did:key:z", "hi", () => {}, undefined, undefined, 1000);
    // 捕获 rejection,避免 unhandled;推进假计时器越过空闲阈值。
    const assertion = expect(p).rejects.toThrow(/timed out/);
    await vi.advanceTimersByTimeAsync(1100);
    await assertion;
    expect(fetchMock).toHaveBeenCalledOnce();
  });
});
