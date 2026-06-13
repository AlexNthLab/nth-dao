import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ChatView } from "../components/ChatView";
import { ToastProvider } from "../components/Toast";
import type { Conversation } from "../types-v2";

// 测试隔离:本文件两个 render 测试间需卸载,否则第二个会看到第一个残留的
// ChatView → "Found multiple elements"(无全局 cleanup 配置时手动加)。
afterEach(cleanup);

const conversations: Conversation[] = [
  {
    id: "ch-general",
    title: "#general",
    subtitle: "channel",
    last_preview: "",
    last_at: "2026-06-13T10:00:00Z",
    unread: 0,
    kind: "channel",
  },
  {
    id: "dm-did:key:zAgent",
    title: "DM: test-agent",
    subtitle: "mock agent",
    last_preview: "",
    last_at: "2026-06-13T09:00:00Z",
    unread: 0,
    kind: "dm",
    participant_dids: ["did:key:zUser", "did:key:zAgent"],
  },
];

function renderChat(props: Partial<React.ComponentProps<typeof ChatView>> = {}) {
  const onSend = vi.fn().mockResolvedValue(undefined);
  const onConversationSelect = vi.fn().mockResolvedValue(undefined);
  render(
    <ToastProvider>
      <ChatView
        conversations={conversations}
        messagesByConv={{}}
        onSend={onSend}
        onConversationSelect={onConversationSelect}
        currentUserId="admin"
        {...props}
      />
    </ToastProvider>,
  );
  return { onSend, onConversationSelect };
}

describe("ChatView agent integration", () => {
  it("focuses the agent DM requested by the directory", async () => {
    const { onConversationSelect } = renderChat({
      focusConversationId: "dm-did:key:zAgent",
    });

    expect(await screen.findByRole("heading", { name: "DM: test-agent" }))
      .toBeTruthy();
    await waitFor(() => {
      expect(onConversationSelect).toHaveBeenCalledWith("dm-did:key:zAgent");
    });
  });

  it("sends the composer text to the selected agent conversation", async () => {
    const { onSend } = renderChat({
      focusConversationId: "dm-did:key:zAgent",
    });

    const composer = await screen.findByPlaceholderText(
      "Message DM: test-agent…",
    );
    fireEvent.change(composer, { target: { value: "run the task" } });
    fireEvent.click(screen.getByRole("button", { name: "Send message" }));

    await waitFor(() => {
      expect(onSend).toHaveBeenCalledWith(
        "dm-did:key:zAgent",
        "run the task",
      );
    });
  });
});
