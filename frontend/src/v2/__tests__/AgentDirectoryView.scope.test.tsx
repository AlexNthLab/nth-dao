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

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
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

it("renders backend startup guide and gates unavailable backends", () => {
  const onSpawnBackend = vi.fn();
  render(
    <LangProvider>
      <AgentDirectoryView
        agents={[]}
        {...noopProps}
        onSpawnBackend={onSpawnBackend}
        backendStatuses={{
          mock: {
            kind: "mock",
            label: "Mock",
            ready: true,
            available: true,
            detail: "Built-in smoke backend.",
          },
          hermes: {
            kind: "hermes",
            label: "Hermes",
            ready: false,
            available: false,
            detail: "Install hermes-agent and configure its local profile.",
            warning: "Hermes runs in-process.",
          },
        }}
      />
    </LangProvider>,
  );

  expect(screen.getByText("Local backend startup")).toBeTruthy();
  expect(screen.getByText("Mock")).toBeTruthy();
  expect(screen.getByText("Hermes")).toBeTruthy();
  expect(screen.getByText("setup needed")).toBeTruthy();
  expect(screen.getByText("Hermes runs in-process.")).toBeTruthy();

  const startButtons = screen.getAllByText("Start");
  fireEvent.click(startButtons[0]);
  expect(onSpawnBackend).toHaveBeenCalledWith("mock");

  const disabledHermes = startButtons.find((b) => b.hasAttribute("disabled"));
  expect(disabledHermes).toBeTruthy();
});
