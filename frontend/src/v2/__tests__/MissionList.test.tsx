// @vitest-environment jsdom
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { LangProvider } from "../i18n";
import { MissionList } from "../components/MissionList";
import type { MissionSummary } from "../types-v2";

afterEach(cleanup);

const mission: MissionSummary = {
  id: "m-vis-1",
  title: "Debug login crash",
  goal: "Find and fix the login crash",
  status: "active",
  steps_total: 2,
  steps_done: 0,
  steps_in_progress: 1,
  driver_label: "codex-local",
  driver_did: "did:key:zCodexLocal",
  started_at: "2026-07-02T08:00:00Z",
  next_actionable: "write a fix",
  current_action: "reproduce the crash",
  steps: [
    {
      id: "s1",
      description: "reproduce the crash",
      status: "active",
      required_capabilities: ["debug"],
      assignee: "did:key:zCodexLocal",
      updated_at: "2026-07-02T08:05:00Z",
      notes_count: 1,
    },
    {
      id: "s2",
      description: "write a fix",
      status: "todo",
      required_capabilities: ["code"],
      updated_at: "2026-07-02T08:06:00Z",
    },
  ],
  timeline: [
    {
      id: "m-vis-1:created",
      kind: "mission",
      label: "Mission created",
      detail: "Find and fix the login crash",
      at: "2026-07-02T08:00:00Z",
      status: "active",
      agent_did: "did:key:zCodexLocal",
      receipt_id: "receipt-created-1234567890",
    },
    {
      id: "m-vis-1:s1:status",
      kind: "step",
      label: "Step current active: reproduce the crash",
      detail: "current state snapshot; requires debug",
      at: "2026-07-02T08:05:00Z",
      status: "active",
      agent_did: "did:key:zCodexLocal",
    },
    {
      id: "handoff:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      kind: "handoff",
      label: "Handoff contested: suspected root cause",
      detail: "hypothesis: wrong branch; claimed evidence: 2 pointer(s)",
      at: "2026-07-02T08:07:00Z",
      status: "contested",
      agent_did: "did:key:zHermesLocal",
      capsule_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      refutation_count: 1,
      authorized_refutation_count: 0,
      evidence_count: 2,
      verification_status: "unverified",
      next_action: "ask a second agent to verify pinned evidence",
    },
  ],
};

describe("MissionList", () => {
  it("shows step-level execution flow in the detail rail", () => {
    render(
      <LangProvider>
        <MissionList missions={[mission]} />
      </LangProvider>,
    );

    expect(screen.getByText("执行状态")).toBeTruthy();
    expect(screen.getByText("Step current active: reproduce the crash")).toBeTruthy();
    expect(screen.getAllByText("Handoff contested: suspected root cause")).toHaveLength(2);
    expect(screen.getByText("capsule sha256:aaaaaaaaaaaa")).toBeTruthy();
    expect(screen.getByText("1 refutation(s)")).toBeTruthy();
    expect(screen.getByText("receipt receipt-created-")).toBeTruthy();
    expect(screen.getByText("Handoff workbench")).toBeTruthy();
    expect(screen.getByText(/Evidence: 2 pointer\(s\) · unverified/)).toBeTruthy();
    expect(screen.getByText(/Refutations: 1 · authorized 0/)).toBeTruthy();
    expect(screen.getByText(/Next: ask a second agent/)).toBeTruthy();

    const stepsSection = screen.getByText("Steps").closest(".detail-section");
    expect(stepsSection).toBeTruthy();
    const scoped = within(stepsSection as HTMLElement);
    expect(scoped.getByText("1. reproduce the crash")).toBeTruthy();
    expect(scoped.getByText(/能力: debug/)).toBeTruthy();
    expect(scoped.getByText(/执行者:/)).toBeTruthy();
  });

  it("caps large execution snapshots so the detail rail stays responsive", () => {
    const bigMission: MissionSummary = {
      ...mission,
      steps_total: 70,
      steps: Array.from({ length: 70 }, (_, i) => ({
        id: `s${i + 1}`,
        description: `step ${i + 1}`,
        status: i === 69 ? "active" : "todo",
        required_capabilities: [],
        updated_at: "2026-07-02T08:06:00Z",
      })),
      timeline: Array.from({ length: 25 }, (_, i) => ({
        id: `e${i + 1}`,
        kind: "step",
        label: `state ${i + 1}`,
        at: "2026-07-02T08:06:00Z",
      })),
    };

    render(
      <LangProvider>
        <MissionList missions={[bigMission]} />
      </LangProvider>,
    );

    expect(screen.queryByText("state 1")).toBeNull();
    expect(screen.getByText("state 25")).toBeTruthy();
    expect(screen.getByText(/还有 5 条较早状态未展开/)).toBeTruthy();
    expect(screen.getByText("70. step 70")).toBeTruthy();
    expect(screen.queryByText("64. step 64")).toBeNull();
    expect(screen.getByText(/还有 6 个步骤未展开/)).toBeTruthy();
  });
});
