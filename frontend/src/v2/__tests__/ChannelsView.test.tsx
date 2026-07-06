// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
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
  listChannelMessages: vi.fn().mockResolvedValue([
    {
      message_id: "m1",
      channel_id: "general",
      sender_id: "admin",
      body: "hello channel",
      kind: "text",
      created_at: new Date().toISOString(),
    },
  ]),
  postChannelMessage: vi.fn(),
  createChannel: vi.fn(),
  joinChannel: vi.fn(),
  fetchAgents: vi.fn().mockResolvedValue([]),
}));

import { ChannelsView, agentReplyWaitMs } from "../components/ChannelsView";

afterEach(cleanup);

describe("ChannelsView", () => {
  it("uses slow-backend wait budgets for model agents", () => {
    expect(agentReplyWaitMs([])).toBe(30_000);
    expect(agentReplyWaitMs([
      {
        did: "did:test-hermes",
        code: "hermes",
        label: "Hermes",
        source: "local",
        capabilities: [],
        has_active_cap: true,
        supervised: true,
        alive: true,
        a2a_port: 1,
        kind: "hermes",
      },
    ])).toBe(180_000);
    expect(agentReplyWaitMs([
      {
        did: "did:test-mock",
        code: "mock",
        label: "Mock",
        source: "local",
        capabilities: [],
        has_active_cap: true,
        supervised: true,
        alive: true,
        a2a_port: 1,
        kind: "mock",
      },
      {
        did: "did:test-codex",
        code: "codex",
        label: "Codex",
        source: "local",
        capabilities: [],
        has_active_cap: true,
        supervised: true,
        alive: true,
        a2a_port: 2,
        kind: "codex",
      },
    ])).toBe(100_000);
  });

  it("渲染频道、消息流、主题", async () => {
    render(
      <LangProvider>
        <ToastProvider>
          <ChannelsView />
        </ToastProvider>
      </LangProvider>,
    );
    // 消息体(唯一)。
    expect(await screen.findByText("hello channel")).toBeTruthy();
    // 频道主题出现在纤细头部(唯一)。
    expect(screen.getByText("Team chat")).toBeTruthy();
  });
});
