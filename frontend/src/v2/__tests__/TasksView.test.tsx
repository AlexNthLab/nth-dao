// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ToastProvider } from "../components/Toast";
import { LangProvider } from "../i18n";

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
  fetchAgents: vi.fn().mockResolvedValue([]),
  claimTask: vi.fn(),
}));

import { claimTask, fetchAgents } from "../api";
import { TasksView } from "../components/TasksView";

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("TasksView", () => {
  it("板子渲染任务、发布按钮、认领占位禁用", async () => {
    render(
      <LangProvider>
        <ToastProvider>
          <TasksView />
        </ToastProvider>
      </LangProvider>,
    );
    expect(screen.getByText(/认领成功后会进入 Missions/)).toBeTruthy();
    // 公告卡片
    expect(await screen.findByText("review the auth PR")).toBeTruthy();
    expect(screen.getByText("look at the token check")).toBeTruthy();
    // 发布入口
    expect(screen.getByText("+ 发布任务")).toBeTruthy();
    // 认领按钮:无可用 agent(fetchAgents 返回 [])→ 禁用。
    const claim = screen.getByText("认领") as HTMLButtonElement;
    expect(claim.disabled).toBe(true);
  });

  it("认领成功但执行视图落库不完整时给 warning toast", async () => {
    vi.mocked(fetchAgents).mockResolvedValueOnce([
      {
        did: "did:key:zWorker",
        code: "WORKER",
        label: "worker",
        source: "local",
        capabilities: ["code_review"],
        has_active_cap: true,
        supervised: true,
        alive: true,
        a2a_port: 18081,
      },
    ]);
    vi.mocked(claimTask).mockResolvedValueOnce({
      status: 200,
      body: {
        result: {
          claimed: true,
          receipt_id: "receipt-1234567890",
          mission_id: "claim-abc123456789",
          visibility_status: "partial",
          visibility_warnings: [
            "mission_visibility_failed",
            "blackboard_visibility_failed",
          ],
        },
      },
    });

    render(
      <LangProvider>
        <ToastProvider>
          <TasksView />
        </ToastProvider>
      </LangProvider>,
    );

    await screen.findByText("review the auth PR");
    fireEvent.click(screen.getByText("认领"));
    expect(await screen.findByText(/执行视图未完全写入/)).toBeTruthy();
    expect(await screen.findByText(/Mission 执行视图写入失败/)).toBeTruthy();
    expect(await screen.findByText(/Blackboard 协作现场写入失败/)).toBeTruthy();
  });
});
