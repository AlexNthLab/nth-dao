/**
 * Phase 3g/4 debt R1 — first vitest in the v2 tree.
 *
 * Smoke test for Phase G's per-agent scope_model_allowlist badge:
 * the cap_token's per-token model policy must render visibly on the
 * agent card so the operator sees at a glance which agents are
 * scoped vs unscoped, and which are hard-locked (`[]`) vs allowed
 * an explicit list.
 *
 * Scope:
 *   • One render per scope state (absent / empty / list).
 *   • Assertions on visible text + tooltip wording, not on CSS
 *     classnames (those are an implementation detail that styling
 *     refactors should be free to change without breaking tests).
 */

import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AgentDirectoryView } from "../components/AgentDirectoryView";
import { LangProvider } from "../i18n";
import type { AgentEntry } from "../types-v2";

const baseAgent = (
  did: string,
  overrides: Partial<AgentEntry> = {},
): AgentEntry => ({
  did,
  code: did.slice(-8),
  label: "test-agent",
  source: "local",
  capabilities: [],
  has_active_cap: true,
  supervised: true,
  alive: true,
  kind: "mock",
  a2a_port: 51000,
  ...overrides,
});

const noopProps = {
  onAddByDid: () => undefined,
  onScanLan: () => undefined,
  onIssueCap: () => undefined,
};

afterEach(() => {
  cleanup();
});

describe("AgentDirectoryView — Phase G scope badge", () => {
  it("renders no scope pill when scope_model_allowlist is absent", () => {
    const agents = [
      baseAgent("did:key:z6MkNoScope", {
        scope_model_allowlist: undefined,
      }),
    ];
    render(<LangProvider><AgentDirectoryView agents={agents} {...noopProps} /></LangProvider>);
    // The agent's kind pill ("mock") is always visible; the scope
    // pill text "scope: …" must NOT be.
    expect(screen.queryByText(/^scope:/)).toBeNull();
  });

  it("renders 'scope: closed' pill when scope is an empty array", () => {
    const agents = [
      baseAgent("did:key:z6MkClosedScope", {
        label: "closed-agent",
        scope_model_allowlist: [],
      }),
    ];
    render(<LangProvider><AgentDirectoryView agents={agents} {...noopProps} /></LangProvider>);
    const pill = screen.getByText("scope: closed");
    expect(pill).toBeTruthy();
    // Tooltip must explain WHY closed is a policy choice, not an
    // error — operators reading the badge cold need this hint.
    expect(pill.getAttribute("title")).toContain("forbids all");
  });

  it("renders inline list for ≤2 allowed models", () => {
    const agents = [
      baseAgent("did:key:z6MkSmallScope", {
        label: "two-model-agent",
        scope_model_allowlist: ["claude-haiku-4-5", "claude-sonnet-4-6"],
      }),
    ];
    render(<LangProvider><AgentDirectoryView agents={agents} {...noopProps} /></LangProvider>);
    // Both models are listed inline (joined by ", ").
    const pill = screen.getByText(
      "scope: claude-haiku-4-5, claude-sonnet-4-6",
    );
    expect(pill).toBeTruthy();
    // Tooltip mirrors the full list verbatim.
    expect(pill.getAttribute("title")).toContain("claude-haiku-4-5");
    expect(pill.getAttribute("title")).toContain("claude-sonnet-4-6");
  });

  it("collapses to '+N' when the scope has >2 entries", () => {
    const agents = [
      baseAgent("did:key:z6MkBigScope", {
        label: "many-model-agent",
        scope_model_allowlist: [
          "claude-haiku-4-5",
          "claude-sonnet-4-6",
          "deepseek-v4-pro",
          "gpt-5",
        ],
      }),
    ];
    render(<LangProvider><AgentDirectoryView agents={agents} {...noopProps} /></LangProvider>);
    // Shows first entry + count of the rest. 4 entries → "first +3".
    const pill = screen.getByText("scope: claude-haiku-4-5 +3");
    expect(pill).toBeTruthy();
    // Tooltip carries the full set so the operator can hover for
    // the complete picture.
    const title = pill.getAttribute("title") || "";
    expect(title).toContain("deepseek-v4-pro");
    expect(title).toContain("gpt-5");
  });
});

it("shows detected backends and requires an explicit join", () => {
  const onSpawnBackend = vi.fn();
  render(
    <LangProvider>
      <AgentDirectoryView
        agents={[]}
        {...noopProps}
        onSpawnBackend={onSpawnBackend}
        backendStatuses={{
          "claude-code": {
            kind: "claude-code",
            label: "Claude Code",
            ready: false,
            available: true,
            runtime: "cli-needs-conpty",
            detail: "Claude CLI detected, but Windows non-interactive A2A calls need a ConPTY wrapper.",
            warning: "Install pywinpty/winpty before spawning Claude Code.",
          },
          codex: {
            kind: "codex",
            label: "Codex",
            ready: true,
            available: true,
            runtime: "node-shim",
            detail: "Codex npm shim, Node runtime, and local profile detected.",
            warning: "Codex is routed through an npm Node shim.",
          },
          hermes: {
            kind: "hermes",
            label: "Hermes",
            ready: false,
            available: true,
            detail: "Install hermes-agent and configure its local profile.",
            warning: "Hermes runs in-process.",
          },
        }}
      />
    </LangProvider>,
  );

  expect(screen.getByText("Detected on this PC")).toBeTruthy();
  expect(screen.getByText(/Nothing joins automatically/)).toBeTruthy();
  expect(screen.queryByText("Mock")).toBeNull();
  expect(screen.getByText("Claude Code")).toBeTruthy();
  expect(screen.getByText("runtime: cli-needs-conpty")).toBeTruthy();
  expect(screen.getByText("Codex")).toBeTruthy();
  expect(screen.getByText("runtime: node-shim")).toBeTruthy();
  expect(screen.getByText("Hermes")).toBeTruthy();
  expect(screen.getAllByText("setup needed")).toHaveLength(2);
  expect(screen.getByText("Hermes runs in-process.")).toBeTruthy();

  const joinButtons = screen.getAllByText("Join NTH DAO");
  const enabledJoin = joinButtons.find((button) => !button.hasAttribute("disabled"));
  expect(enabledJoin).toBeTruthy();
  fireEvent.click(enabledJoin!);
  expect(onSpawnBackend).toHaveBeenCalledWith("codex");

  const disabledHermes = joinButtons.find((b) => b.hasAttribute("disabled"));
  expect(disabledHermes).toBeTruthy();
  const disabledClaude = screen.getByTitle(/ConPTY wrapper/);
  expect(disabledClaude.hasAttribute("disabled")).toBe(true);
});

it("does not start a duplicate local backend that is already running", () => {
  const onSpawnBackend = vi.fn();
  render(
    <LangProvider>
      <AgentDirectoryView
        agents={[baseAgent("did:key:z6MkRunningHermes", { kind: "hermes" })]}
        {...noopProps}
        onSpawnBackend={onSpawnBackend}
        backendStatuses={{
          hermes: {
            kind: "hermes",
            label: "Hermes",
            ready: true,
            available: true,
            detail: "Ready.",
          },
        }}
      />
    </LangProvider>,
  );

  const running = screen.getByRole("button", { name: "Joined" });
  expect(running.hasAttribute("disabled")).toBe(true);
  fireEvent.click(running);
  expect(onSpawnBackend).not.toHaveBeenCalled();
});

it("passes an explicit project folder and access policy when starting", () => {
  const onSpawnBackend = vi.fn();
  render(
    <LangProvider>
      <AgentDirectoryView
        agents={[]}
        {...noopProps}
        onSpawnBackend={onSpawnBackend}
        backendStatuses={{
          codex: {
            kind: "codex",
            label: "Codex",
            ready: true,
            available: true,
            detail: "Ready.",
          },
        }}
      />
    </LangProvider>,
  );

  fireEvent.change(screen.getByLabelText("Agent project folder"), {
    target: { value: "C:\\Workspaces\\sample-project" },
  });
  fireEvent.change(screen.getByLabelText("Agent project access"), {
    target: { value: "read-only" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Join NTH DAO" }));

  expect(onSpawnBackend).toHaveBeenCalledWith("codex", {
    projectWorkdir: "C:\\Workspaces\\sample-project",
    workAccess: "read-only",
  });
});

it("shows the effective project boundary for a supervised agent", () => {
  const project = "C:\\Workspaces\\sample-project";
  render(
    <LangProvider>
      <AgentDirectoryView
        agents={[baseAgent("did:key:z6MkScoped", {
          supervised: true,
          work_scope_root: project,
          work_access: "workspace-write",
        })]}
        {...noopProps}
      />
    </LangProvider>,
  );

  expect(screen.getByTitle(project).textContent).toBe(project);
  expect(screen.getByText("workspace-write")).toBeTruthy();
});

it("surfaces Hermes warmup status while an agent task is starting", async () => {
  let finishAsk!: (value: { text: string; backend: string; model: string }) => void;
  const onAskAgent = vi.fn((
    _did: string,
    _prompt: string,
    _onDelta: (delta: string) => void,
    _signal?: AbortSignal,
    onStatus?: (status: string) => void,
  ) => {
    onStatus?.("warming:2");
    return new Promise<{ text: string; backend: string; model: string }>((resolve) => {
      finishAsk = resolve;
    });
  });

  render(
    <LangProvider>
      <AgentDirectoryView
        agents={[baseAgent("did:key:z6MkHermesWarmup", { kind: "hermes", label: "Hermes" })]}
        {...noopProps}
        onAskAgent={onAskAgent}
      />
    </LangProvider>,
  );

  fireEvent.change(screen.getByPlaceholderText(/派一个任务|Assign a task/), {
    target: { value: "say hello" },
  });
  const runButton = screen.getByRole("button", { name: /运行|Run/ });
  await waitFor(() => {
    expect(runButton.hasAttribute("disabled")).toBe(false);
  });
  fireEvent.click(runButton);

  await waitFor(() => {
    expect(onAskAgent).toHaveBeenCalled();
  });
  await waitFor(() => {
    expect(screen.getAllByText(/Hermes 正在冷启动|Hermes is warming up/).length).toBeGreaterThan(0);
  });
  await act(async () => {
    finishAsk({ text: "Hermes online.", backend: "hermes", model: "deepseek-v4-pro" });
  });
  await waitFor(() => {
    expect(screen.getByText("Hermes online.")).toBeTruthy();
  });
});

it("keeps agent task backend failures visible in the work panel", async () => {
  const onAskAgent = vi.fn(async () => {
    throw new Error(
      "agent error: backend-failed - codex CLI usage limit reached",
    );
  });

  render(
    <LangProvider>
      <AgentDirectoryView
        agents={[baseAgent("did:key:z6MkCodexQuota", { kind: "codex", label: "Codex" })]}
        {...noopProps}
        onAskAgent={onAskAgent}
      />
    </LangProvider>,
  );

  fireEvent.change(screen.getByPlaceholderText(/派一个任务|Assign a task/), {
    target: { value: "say hello" },
  });
  const runButton = screen.getByRole("button", { name: /运行|Run/ });
  fireEvent.click(runButton);

  await waitFor(() => {
    expect(onAskAgent).toHaveBeenCalled();
  });
  expect(
    await screen.findByText(/codex CLI usage limit reached/),
  ).toBeTruthy();
});
