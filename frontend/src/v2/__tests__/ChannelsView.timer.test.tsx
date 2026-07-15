// @vitest-environment jsdom
import { act, cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ToastProvider } from "../components/Toast";
import { LangProvider } from "../i18n";

vi.mock("../api", () => ({
  listChannels: vi.fn().mockResolvedValue([
    {
      channel_id: "general",
      name: "general",
      topic: "Team chat",
      created_by: "admin",
      is_private: false,
      member_ids: ["admin", "did:key:zAgent"],
      created_at: new Date().toISOString(),
    },
  ]),
  listChannelMessages: vi.fn(),
  postChannelMessage: vi.fn(),
  createChannel: vi.fn(),
  joinChannel: vi.fn(),
  fetchAgents: vi.fn().mockResolvedValue([
    {
      did: "did:key:zAgent",
      code: "mock",
      label: "Mock Agent",
      source: "local",
      capabilities: [],
      has_active_cap: true,
      supervised: true,
      alive: true,
      a2a_port: 1234,
      kind: "mock",
    },
  ]),
  fetchReceiptDetail: vi.fn(),
}));

import {
  listChannelMessages,
  postChannelMessage,
} from "../api";
import { ChannelsView } from "../components/ChannelsView";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe("ChannelsView dispatch timeout lifecycle", () => {
  it("does not show a timeout after a terminal completed phase", async () => {
    vi.useFakeTimers();
    let sent = false;
    let firstPostRead = true;
    const userMessage = {
      message_id: "m-command",
      channel_id: "general",
      sender_id: "admin",
      body: "run the check",
      kind: "text",
      created_at: new Date().toISOString(),
    };
    const received = {
      ...userMessage,
      message_id: "m-received",
      sender_id: "did:key:zAgent",
      body: "Received instruction.",
      kind: "system",
      dispatch_phase: "received",
      request_message_id: "m-command",
    };
    const processing = {
      ...received,
      message_id: "m-processing",
      body: "Processing instruction.",
      dispatch_phase: "processing",
    };
    const completed = {
      ...received,
      message_id: "m-completed",
      body: "completed body",
      kind: "text",
      dispatch_phase: "completed",
    };
    vi.mocked(listChannelMessages).mockImplementation(async () => {
      if (!sent) return [];
      if (firstPostRead) {
        firstPostRead = false;
        return [userMessage, received];
      }
      return [userMessage, received, processing, completed];
    });
    vi.mocked(postChannelMessage).mockImplementation(async () => {
      sent = true;
      return userMessage;
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
      await Promise.resolve();
    });
    const input = container.querySelector("textarea");
    const form = container.querySelector("form");
    expect(input).toBeTruthy();
    expect(form).toBeTruthy();

    await act(async () => {
      fireEvent.change(input as HTMLTextAreaElement, {
        target: { value: "run the check" },
      });
      fireEvent.submit(form as HTMLFormElement);
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(container.querySelector(".chat-dispatch-received")).toBeTruthy();

    await act(async () => {
      vi.advanceTimersByTime(3000);
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(container.querySelector(".chat-dispatch-completed")).toBeTruthy();

    await act(async () => {
      vi.advanceTimersByTime(30000);
      await Promise.resolve();
    });
    expect(container.querySelector(".chat-system")).toBeNull();
  });
});
