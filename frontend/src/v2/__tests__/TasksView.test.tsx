// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ToastProvider } from "../components/Toast";

vi.mock("../api", () => ({
  listOpenTasks: vi.fn().mockResolvedValue([
    {
      announcement_id: "a1",
      publisher_did: "did:key:zPublisherXYZ",
      title: "review the auth PR",
      description: "look at the token check",
      capability_set: ["code_review"],
      context: "code_review",
      reward_minor: 50,
      reward_asset: "credit",
      published_at_ms: Date.now(),
      claimed: false,
    },
  ]),
  listTaskCategories: vi.fn().mockResolvedValue([
    { context: "code_review", count: 1 },
  ]),
  announceTask: vi.fn(),
}));

import { TasksView } from "../components/TasksView";

afterEach(cleanup);

describe("TasksView", () => {
  it("板子渲染任务、发布按钮、认领占位禁用", async () => {
    render(
      <ToastProvider>
        <TasksView />
      </ToastProvider>,
    );
    // 公告卡片
    expect(await screen.findByText("review the auth PR")).toBeTruthy();
    expect(screen.getByText("look at the token check")).toBeTruthy();
    // 发布入口
    expect(screen.getByText("+ 发布任务")).toBeTruthy();
    // 认领按钮先占位禁用(切片B 未建)
    const claim = screen.getByText("认领(建设中)") as HTMLButtonElement;
    expect(claim.disabled).toBe(true);
  });
});
