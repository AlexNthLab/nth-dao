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
      "发消息给 DM: test-agent…",
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

describe("ChatView iMessage 风格渲染", () => {
  const msgs = {
    "dm-did:key:zAgent": [
      {
        message_id: "m1",
        sender_id: "admin",
        sender_label: "You",
        body: "hi",
        created_at: "2026-06-13T10:00:00Z",
      },
      {
        message_id: "m2",
        sender_id: "admin",
        sender_label: "You",
        body: "再补一句",
        created_at: "2026-06-13T10:00:30Z", // 30s 后,同人 → 成组
      },
      {
        message_id: "m3",
        sender_id: "did:key:zAgent",
        sender_label: "agent",
        body: "Agent is thinking...",
        created_at: "2026-06-13T10:01:00Z",
      },
    ],
  };

  it("思考中渲染三点指示器而非字面文本", async () => {
    const { container } = render(
      <ToastProvider>
        <ChatView
          conversations={conversations}
          messagesByConv={msgs}
          onSend={vi.fn()}
          onConversationSelect={vi.fn()}
          focusConversationId="dm-did:key:zAgent"
          currentUserId="admin"
        />
      </ToastProvider>,
    );
    await screen.findByText("再补一句");
    expect(container.querySelector(".typing-dots")).toBeTruthy();
    // 字面占位串不得直接显示给用户。
    expect(screen.queryByText("Agent is thinking...")).toBeNull();
  });

  it("连发成组 + 仅最新一条带入场动画类", async () => {
    const { container } = render(
      <ToastProvider>
        <ChatView
          conversations={conversations}
          messagesByConv={msgs}
          onSend={vi.fn()}
          onConversationSelect={vi.fn()}
          focusConversationId="dm-did:key:zAgent"
          currentUserId="admin"
        />
      </ToastProvider>,
    );
    await screen.findByText("再补一句");
    const rows = container.querySelectorAll(".chat-row");
    expect(rows.length).toBe(3);
    // 第 1 条:组首;第 2 条:同人续发(贴合上沿);第 3 条:换人组首 + 最新。
    expect(rows[0].className).toContain("group-start");
    expect(rows[1].className).toContain("grp-top");
    expect(rows[2].className).toContain("is-last");
    // is-last 只有一条。
    expect(container.querySelectorAll(".chat-row.is-last").length).toBe(1);
  });
});
