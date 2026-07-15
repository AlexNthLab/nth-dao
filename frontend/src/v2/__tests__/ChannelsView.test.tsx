// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
    {
      message_id: "m2",
      channel_id: "general",
      sender_id: "did:key:zAgent",
      body: "agent reply",
      kind: "text",
      created_at: new Date().toISOString(),
      nth_receipt_id: "r-channel-1234567890",
      nth_receipt_content_hash: "abc123",
    },
  ]),
  postChannelMessage: vi.fn(),
  createChannel: vi.fn(),
  joinChannel: vi.fn(),
  fetchAgents: vi.fn().mockResolvedValue([]),
  fetchReceiptDetail: vi.fn().mockResolvedValue({
    receipt: {
      receipt_id: "r-channel-1234567890",
      signer_did: "did:key:zAgent",
      content_hash: "abc123",
      timeline: [{ type: "nth.agent_response" }],
    },
    summary: {
      receipt_id: "r-channel-1234567890",
      signer_did: "did:key:zAgent",
      goal_id: "mission-channel-1",
      issued_at: "2026-07-06T08:00:00+00:00",
      content_hash: "abc123",
      prev_content_hash: "",
      kind: "nth-execution-receipt-v1",
      cap_scope: {
        present: true,
        token_id: "cap-channel-123",
        issuer_did: "did:key:zIssuer",
        subject_did: "did:key:zAgent",
        capabilities: ["nth:receipt_sign"],
        scope_task_id: "mission-channel-1",
        scope_dao: "home",
        scope_model_allowlist: ["mock-model"],
        not_before: 1,
        not_after: 1_789_000_000_000,
      },
    },
    verification: {
      verified: true,
      status: "verified",
      reason: "",
    },
  }),
}));

import {
  ChannelsView,
  agentReplyWaitMs,
  groupChannels,
  visibleGroupChannels,
} from "../components/ChannelsView";
import { fetchReceiptDetail } from "../api";

beforeEach(() => {
  vi.useRealTimers();
  localStorage.clear();
});

afterEach(cleanup);

describe("ChannelsView", () => {
  it("groups channels by DAO and linked task metadata", () => {
    const base = {
      topic: "",
      created_by: "admin",
      is_private: false,
      member_ids: ["admin"],
      created_at: "2026-07-13T00:00:00Z",
    };
    const groups = groupChannels([
      { ...base, channel_id: "general", name: "general", metadata: {} },
      {
        ...base,
        channel_id: "debug",
        name: "debug",
        metadata: { task_id: "task-42", task_label: "Checkout repair" },
      },
      {
        ...base,
        channel_id: "review",
        name: "review",
        metadata: { task_id: "task-42", task_label: "Checkout repair" },
      },
      {
        ...base,
        channel_id: "remote",
        name: "remote",
        metadata: { dao_id: "dao-remote", dao_label: "Remote DAO" },
      },
      {
        ...base,
        channel_id: "scratch",
        name: "scratch",
        metadata: { dao_id: "home", dao_label: "NTH DAO" },
      },
    ]);

    expect(groups.map((group) => [group.key, group.channels.length])).toEqual([
      ["dao:home", 1],
      ["dao:dao-remote", 1],
      ["task:home:task-42", 2],
      ["history:home", 1],
    ]);
    expect(groups[2].label).toBe("Task: Checkout repair");
    expect(groups[3].label).toBe("Unlinked channels");
  });

  it("limits large history groups while keeping the selected channel visible", () => {
    const group = {
      key: "history:home",
      label: "Unlinked channels",
      kind: "history" as const,
      channels: Array.from({ length: 12 }, (_, index) => ({
        channel_id: `history-${index}`,
        name: `history-${index}`,
        topic: "",
        created_by: "admin",
        is_private: false,
        member_ids: ["admin"],
        created_at: `2026-07-13T00:${String(59 - index).padStart(2, "0")}:00Z`,
        metadata: { dao_id: "home" },
      })),
    };

    const collapsed = visibleGroupChannels(group, "history-11", false);
    expect(collapsed).toHaveLength(6);
    expect(collapsed[0].channel_id).toBe("history-11");
    expect(collapsed.map((channel) => channel.channel_id)).toContain("history-0");
    expect(visibleGroupChannels(group, "history-11", true)).toHaveLength(12);
  });

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
    ])).toBe(330_000);
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
    ])).toBe(195_000);
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
    expect(await screen.findByText(/receipt r-channel-1/)).toBeTruthy();
    // 频道主题出现在纤细头部(唯一)。
    expect(screen.getByText("Team chat")).toBeTruthy();
  });

  it("opens channel reply receipts in the detail rail", async () => {
    render(
      <LangProvider>
        <ToastProvider>
          <ChannelsView />
        </ToastProvider>
      </LangProvider>,
    );

    const receiptButton = await screen.findByRole("button", {
      name: /receipt r-channel-1/,
    });
    fireEvent.click(receiptButton);

    await waitFor(() => {
      expect(fetchReceiptDetail).toHaveBeenCalledWith("r-channel-1234567890");
    });
    expect(await screen.findByText(/Receipt 摘要|Receipt summary/)).toBeTruthy();
    expect(await screen.findByText(/已验证|verified/)).toBeTruthy();
    expect(await screen.findByText("Signer DID")).toBeTruthy();
    expect(screen.getAllByText("did:key:zAgent").length).toBeGreaterThan(0);
    expect(screen.getAllByText("mission-channel-1").length).toBeGreaterThan(0);
    expect(await screen.findByText("cap-channel-123")).toBeTruthy();
    expect(await screen.findByText("nth:receipt_sign")).toBeTruthy();
    expect(await screen.findByText("mock-model")).toBeTruthy();
    expect(await screen.findByText(/原始签名 receipt|Raw signed receipt/)).toBeTruthy();
    expect(screen.getAllByText(/r-channel-1234567890/).length).toBeGreaterThan(0);
  });
});
