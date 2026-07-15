// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ToastProvider } from "../components/Toast";
import { LangProvider } from "../i18n";

const firstMessage = {
  message_id: "m1",
  channel_id: "general",
  sender_id: "admin",
  body: "first",
  kind: "text",
  created_at: "2026-07-13T00:00:00Z",
};
const secondMessage = {
  ...firstMessage,
  message_id: "m2",
  sender_id: "did:key:zAgent",
  body: "new reply",
};

vi.mock("../api", () => ({
  listChannels: vi.fn().mockResolvedValue([{
    channel_id: "general",
    name: "general",
    topic: "Team chat",
    created_by: "admin",
    is_private: false,
    member_ids: ["admin", "did:key:zAgent"],
    created_at: "2026-07-13T00:00:00Z",
    metadata: {},
  }]),
  listChannelMessages: vi.fn(),
  postChannelMessage: vi.fn(),
  createChannel: vi.fn(),
  joinChannel: vi.fn(),
  fetchAgents: vi.fn().mockResolvedValue([]),
  fetchReceiptDetail: vi.fn(),
}));

import { listChannelMessages } from "../api";
import { ChannelsView } from "../components/ChannelsView";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe("ChannelsView history scrolling", () => {
  it("keeps the reader's position when polling adds a message above the fold", async () => {
    vi.useFakeTimers();
    let reads = 0;
    vi.mocked(listChannelMessages).mockImplementation(async () => {
      reads += 1;
      return reads === 1 ? [firstMessage] : [firstMessage, secondMessage];
    });

    const { container } = render(
      <LangProvider>
        <ToastProvider>
          <ChannelsView />
        </ToastProvider>
      </LangProvider>,
    );
    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });

    const thread = container.querySelector(".chat-thread") as HTMLDivElement;
    expect(thread).toBeTruthy();
    expect(screen.getByText("first")).toBeTruthy();
    Object.defineProperty(thread, "scrollHeight", { configurable: true, value: 1000 });
    Object.defineProperty(thread, "clientHeight", { configurable: true, value: 300 });
    await act(async () => {
      vi.advanceTimersByTime(20);
      await Promise.resolve();
    });
    expect(thread.scrollTop).toBe(1000);
    thread.scrollTop = 200;
    fireEvent.scroll(thread);

    await act(async () => {
      vi.advanceTimersByTime(3000);
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(screen.getByText("new reply")).toBeTruthy();
    expect(thread.scrollTop).toBe(200);
    const latest = screen.getByRole("button", { name: /Latest|最新消息/ });
    fireEvent.click(latest);
    expect(thread.scrollTop).toBe(1000);
  });

  it("loads earlier pages by cursor without replacing the current page", async () => {
    const initial = Array.from({ length: 101 }, (_, index) => ({
      ...firstMessage,
      message_id: `m${index}`,
      body: `body-${index}`,
    }));
    const older = [{
      ...firstMessage,
      message_id: "m-older",
      body: "oldest loaded message",
    }];
    vi.mocked(listChannelMessages).mockImplementation(
      async (_channelId, _signal, beforeMessageId) => (
        beforeMessageId ? older : initial
      ),
    );

    render(
      <LangProvider>
        <ToastProvider>
          <ChannelsView />
        </ToastProvider>
      </LangProvider>,
    );

    const loadEarlier = await screen.findByRole("button", {
      name: /Load earlier messages|加载更早消息/,
    });
    expect(screen.queryByText("body-0")).toBeNull();
    expect(screen.getByText("body-1")).toBeTruthy();
    fireEvent.click(loadEarlier);

    await waitFor(() => expect(listChannelMessages).toHaveBeenCalledWith(
      "general",
      undefined,
      "m1",
      101,
    ));
    expect(await screen.findByText("oldest loaded message")).toBeTruthy();
    expect(screen.getByText("body-100")).toBeTruthy();
  });
});
