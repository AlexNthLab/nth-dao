// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
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
  getFederationStatus: vi.fn().mockResolvedValue({
    peers: [],
    file_peers: [],
    env_peers: [],
    poller_started: false,
    cached_announcements: 0,
    last_refresh_ms: 0,
    last_error: "",
    last_peer_count: 0,
  }),
  refreshFederation: vi.fn().mockResolvedValue({
    peers: [],
    file_peers: [],
    env_peers: [],
    poller_started: false,
    cached_announcements: 0,
    last_refresh_ms: 0,
    last_error: "",
    last_peer_count: 0,
    refreshed: true,
  }),
  updateFederationPeer: vi.fn(),
  discoverFederationPeers: vi.fn().mockResolvedValue({
    peers: [],
    file_peers: [],
    env_peers: [],
    poller_started: false,
    cached_announcements: 0,
    last_refresh_ms: 0,
    last_error: "",
    last_peer_count: 0,
    discovered: true,
    imported_peers: [],
    skipped_peers: [],
    discovery_errors: [],
  }),
  announceTask: vi.fn(),
  fetchAgents: vi.fn().mockResolvedValue([]),
  claimTask: vi.fn(),
  claimFederatedTask: vi.fn(),
}));

import {
  claimFederatedTask,
  claimTask,
  discoverFederationPeers,
  fetchAgents,
  refreshFederation,
  updateFederationPeer,
} from "../api";
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

  it("uses the content-bound key when claiming a federated task", async () => {
    const { listOpenTasks } = await import("../api");
    vi.mocked(listOpenTasks).mockResolvedValueOnce([{
      announcement_id: "shared-id",
      federation_key: "nth-ann-sha256:abc123",
      publisher_did: "did:key:zRemote",
      title: "remote task",
      capability_set: [],
      context: "general",
      reward_minor: 0,
      reward_asset: "credit",
      claimed: false,
      federated: true,
      source_peer: "https://remote.example",
    }]);
    vi.mocked(fetchAgents).mockResolvedValueOnce([{
      did: "did:key:zWorker",
      code: "WORKER",
      label: "worker",
      source: "local",
      capabilities: [],
      has_active_cap: true,
      supervised: true,
      alive: true,
      a2a_port: 18081,
    }]);
    vi.mocked(claimFederatedTask).mockResolvedValueOnce({
      status: 409,
      body: { detail: "test stop" },
    });

    render(
      <LangProvider>
        <ToastProvider>
          <TasksView />
        </ToastProvider>
      </LangProvider>,
    );
    await screen.findByText("remote task");
    fireEvent.click(screen.getByText("跨 DAO 认领"));

    await waitFor(() => expect(claimFederatedTask).toHaveBeenCalledWith(
      "shared-id",
      "did:key:zWorker",
      "nth-ann-sha256:abc123",
    ));
  });

  it("allows adding a federation seed peer from the Tasks sidebar", async () => {
    vi.mocked(updateFederationPeer).mockResolvedValueOnce({
      peers: ["http://192.168.1.20:8080"],
      file_peers: ["http://192.168.1.20:8080"],
      env_peers: [],
      poller_started: true,
      cached_announcements: 0,
      last_refresh_ms: 0,
      last_error: "",
      last_peer_count: 1,
      updated: true,
      peer_url: "http://192.168.1.20:8080",
      action: "add",
    });
    vi.mocked(refreshFederation).mockResolvedValueOnce({
      peers: ["http://192.168.1.20:8080"],
      file_peers: ["http://192.168.1.20:8080"],
      env_peers: [],
      poller_started: true,
      cached_announcements: 1,
      last_refresh_ms: 123,
      last_error: "",
      last_peer_count: 1,
      refreshed: true,
    });

    render(
      <LangProvider>
        <ToastProvider>
          <TasksView />
        </ToastProvider>
      </LangProvider>,
    );

    fireEvent.change(screen.getByPlaceholderText("http://192.168.1.20:8080"), {
      target: { value: "http://192.168.1.20:8080" },
    });
    fireEvent.click(screen.getByText("Add"));

    await waitFor(() => {
      expect(updateFederationPeer).toHaveBeenCalledWith(
        "http://192.168.1.20:8080",
        "add",
      );
    });
    expect(refreshFederation).toHaveBeenCalled();
  });

  it("discovers nearby DAO federation peers from the Tasks sidebar", async () => {
    vi.mocked(discoverFederationPeers).mockResolvedValueOnce({
      peers: ["http://192.168.1.20:8080"],
      file_peers: ["http://192.168.1.20:8080"],
      env_peers: [],
      poller_started: true,
      cached_announcements: 1,
      last_refresh_ms: 123,
      last_error: "",
      last_peer_count: 1,
      discovered: true,
      imported_peers: ["http://192.168.1.20:8080"],
      skipped_peers: [],
      discovery_errors: [],
    });

    render(
      <LangProvider>
        <ToastProvider>
          <TasksView />
        </ToastProvider>
      </LangProvider>,
    );

    fireEvent.click(screen.getByText("Discover nearby DAOs"));

    await waitFor(() => {
      expect(discoverFederationPeers).toHaveBeenCalledWith({
        actorId: "admin",
        timeoutSeconds: 2,
        add: true,
        refresh: true,
      });
    });
    expect(await screen.findByText(/Imported 1 verified DAO peer/)).toBeTruthy();
  });

  it("shows durable mesh peer sources and reverse discovery readiness", async () => {
    const { getFederationStatus } = await import("../api");
    vi.mocked(getFederationStatus).mockResolvedValueOnce({
      peers: ["https://seed.example", "https://learned.example"],
      seed_peers: ["https://seed.example"],
      learned_peers: {
        "https://learned.example": {
          did: "did:key:zLearned",
          pubkey_prefix: "0123456789abcdef",
          last_verified_ms: 1,
          expires_at_ms: 2,
        },
      },
      file_peers: ["https://seed.example"],
      env_peers: [],
      poller_started: true,
      cached_announcements: 0,
      last_refresh_ms: 0,
      last_error: "",
      last_peer_count: 2,
      public_peer_url: "https://self.example",
      reverse_discovery_enabled: true,
    });

    render(
      <LangProvider>
        <ToastProvider>
          <TasksView />
        </ToastProvider>
      </LangProvider>,
    );

    expect(await screen.findByText(/Seeds: 1/)).toBeTruthy();
    expect(screen.getByText(/Learned: 1/)).toBeTruthy();
    expect(screen.getByText(/Reverse discovery: ready/)).toBeTruthy();
  });
});
