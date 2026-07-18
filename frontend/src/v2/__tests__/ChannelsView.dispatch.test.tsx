// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
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
      message_id: "m-command",
      channel_id: "general",
      sender_id: "admin",
      body: "run the check",
      kind: "text",
      created_at: new Date().toISOString(),
    },
    ...(["received", "processing", "completed"] as const).map((phase) => ({
      message_id: `m-${phase}`,
      channel_id: "general",
      sender_id: "did:key:zAgent",
      body: `${phase} body`,
      kind: phase === "completed" ? "text" : "system",
      created_at: new Date().toISOString(),
      dispatch_phase: phase,
      request_message_id: "m-command",
      status_source: "hub",
    })),
    {
      message_id: "m-hub-failed",
      channel_id: "general",
      sender_id: "admin",
      body: "No online Agent is available.",
      kind: "system",
      created_at: new Date().toISOString(),
      dispatch_phase: "failed",
      request_message_id: "m-other-command",
      status_source: "hub",
    },
  ]),
  postChannelMessage: vi.fn(),
  createChannel: vi.fn(),
  joinChannel: vi.fn(),
  fetchAgents: vi.fn().mockResolvedValue([]),
  fetchReceiptDetail: vi.fn(),
}));

import { ChannelsView } from "../components/ChannelsView";
import { fetchAgents, postChannelMessage } from "../api";

afterEach(cleanup);

describe("ChannelsView durable dispatch phases", () => {
  it("shows received, processing, and completed without streaming output", async () => {
    const { container } = render(
      <LangProvider>
        <ToastProvider>
          <ChannelsView />
        </ToastProvider>
      </LangProvider>,
    );

    expect(await screen.findByText(/已收到|Received/)).toBeTruthy();
    expect(await screen.findByText(/处理中|Processing/)).toBeTruthy();
    expect(await screen.findByText(/已完成|Completed/)).toBeTruthy();
    expect(screen.getByText("completed body")).toBeTruthy();
    expect(container.querySelector(".chat-dispatch-received")).toBeTruthy();
    expect(container.querySelector(".chat-dispatch-processing")).toBeTruthy();
    expect(container.querySelector(".chat-dispatch-completed")).toBeTruthy();
    expect(container.querySelector(".chat-dispatch-source-hub")).toBeTruthy();
    expect(container.querySelector(".chat-row.in .chat-dispatch-failed")).toBeTruthy();
  });

  it("keeps a degraded provider retryable for channel dispatch", async () => {
    vi.mocked(fetchAgents).mockResolvedValueOnce([{
      did: "did:key:zAgent",
      code: "hermes",
      label: "Hermes",
      source: "local",
      capabilities: [],
      has_active_cap: true,
      supervised: true,
      alive: true,
      a2a_port: 43120,
      a2a_ready: true,
      provider_state: "degraded",
      kind: "hermes",
    }]);
    vi.mocked(postChannelMessage).mockResolvedValueOnce({
      message_id: "m-new",
      channel_id: "general",
      sender_id: "admin",
      body: "new instruction",
      kind: "text",
      created_at: new Date().toISOString(),
    });

    render(
      <LangProvider>
        <ToastProvider>
          <ChannelsView />
        </ToastProvider>
      </LangProvider>,
    );
    const input = await screen.findByPlaceholderText(/#general/);
    fireEvent.change(input, { target: { value: "new instruction" } });
    fireEvent.submit(input.closest("form") as HTMLFormElement);

    await waitFor(() => expect(postChannelMessage).toHaveBeenCalled());
    expect(screen.queryByText(/No agent reply after/)).toBeNull();
    expect(await screen.findByLabelText("agent thinking")).toBeTruthy();
  });

  it("uses message mentions instead of a separate recipient selector", async () => {
    vi.mocked(fetchAgents).mockResolvedValue([{
      did: "did:key:zAgent",
      code: "codex",
      label: "Codex",
      source: "local",
      capabilities: [],
      has_active_cap: false,
      supervised: true,
      alive: true,
      a2a_port: 43120,
      a2a_ready: true,
      provider_state: "ready",
      kind: "codex",
    }]);
    vi.mocked(postChannelMessage).mockResolvedValueOnce({
      message_id: "m-targeted",
      channel_id: "general",
      sender_id: "admin",
      body: "@Codex fix the report",
      kind: "text",
      created_at: new Date().toISOString(),
    });

    render(
      <LangProvider>
        <ToastProvider>
          <ChannelsView />
        </ToastProvider>
      </LangProvider>,
    );

    expect(screen.queryByLabelText(/消息收件人|Message recipient/)).toBeNull();
    const input = await screen.findByPlaceholderText(/#general/);
    fireEvent.change(input, { target: { value: "@Codex fix the report" } });
    fireEvent.submit(input.closest("form") as HTMLFormElement);

    await waitFor(() => expect(postChannelMessage).toHaveBeenCalledWith(
      "general",
      "@Codex fix the report",
      "admin",
    ));
  });
});
