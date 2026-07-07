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

import { ChannelsView, agentReplyWaitMs } from "../components/ChannelsView";
import { fetchReceiptDetail } from "../api";

beforeEach(() => {
  vi.useRealTimers();
  localStorage.clear();
});

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
