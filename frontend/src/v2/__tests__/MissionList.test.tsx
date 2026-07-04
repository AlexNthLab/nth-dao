// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LangProvider } from "../i18n";
import { MissionList } from "../components/MissionList";
import type { MissionSummary } from "../types-v2";

vi.mock("../api", () => ({
  fetchMissionHandoffs: vi.fn(),
}));

import { fetchMissionHandoffs } from "../api";

const capsuleHash =
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

beforeEach(() => {
  localStorage.setItem("nth.v2.lang", "en");
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: {
      writeText: vi.fn().mockResolvedValue(undefined),
    },
  });
  vi.mocked(fetchMissionHandoffs).mockResolvedValue([
    {
      capsule_hash: capsuleHash,
      mission_id: "m-vis-1",
      step_id: "s1",
      finding: "suspected root cause",
      root_cause_hypothesis: "wrong branch",
      verification_status: "unverified",
      author_did: "did:key:zHermesLocal",
      status: "contested",
      evidence_count: 2,
      test_count: 1,
      risk_count: 1,
      refutation_count: 1,
      superseded_by: "",
      evidence_verification: [
        {
          status: "verified",
          path: "nth_dao/web/v2_api.py",
          commit: "0123456789abcdef0123456789abcdef01234567",
          content_hash:
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          resolver: {
            type: "git",
            repo_id: "github.com/nth-dao/example",
            repo_url: "https://github.com/nth-dao/example.git",
            commit: "0123456789abcdef0123456789abcdef01234567",
            path: "nth_dao/web/v2_api.py",
            content_hash:
              "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            source_present: true,
            matched_by: "github.com/nth-dao/example",
          },
          commit_reachable: true,
          blob_reachable: true,
          reason: "content hash matches",
        },
      ],
      review_packet: {
        packet_kind: "nth-handoff-review-packet-v1",
        packet_version: 1,
        packet_is_signed: false,
        is_truth_verdict: false,
        warning: "Signed handoff is a claim, not a verified fact.",
        goal: "Server-issued packet: use the least context needed to re-check this handoff.",
        capsule_hash: capsuleHash,
        evidence_summary: {
          total: 1,
          verified: 1,
        },
        evidence_verification: [{
          status: "verified",
          reason: "content hash matches",
        }],
        risks: ["capsule hypothesis may still be wrong"],
        required_review_steps: [
          "Verify each evidence pointer against its pinned commit and content hash.",
          "If the claim is wrong, sign a refutation or superseding handoff with a receipt.",
        ],
      },
      next_actions: ["ask a second agent to verify pinned evidence"],
      risks: ["capsule hypothesis may still be wrong"],
      refutations: [{
        author_did: "did:key:zReviewer",
        authorized: false,
        receipt_id: "receipt-review-1",
        receipt_content_hash:
          "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      }],
    },
  ]);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  localStorage.clear();
});

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
  source_announcement_id: "ann-debug-111",
  process_id: "process-debug-111",
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
      source_announcement_id: "ann-debug-111",
      process_id: "process-debug-111",
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
      id: `handoff:${capsuleHash}`,
      kind: "handoff",
      label: "Handoff contested: suspected root cause",
      detail: "hypothesis: wrong branch; claimed evidence: 2 pointer(s)",
      at: "2026-07-02T08:07:00Z",
      status: "contested",
      agent_did: "did:key:zHermesLocal",
      capsule_hash: capsuleHash,
      refutation_count: 1,
      authorized_refutation_count: 0,
      evidence_count: 2,
      verification_status: "unverified",
      next_action: "ask a second agent to verify pinned evidence",
    },
  ],
};

describe("MissionList", () => {
  it("shows step-level execution flow and signed handoff details", async () => {
    const onNavigate = vi.fn();
    render(
      <LangProvider>
        <MissionList missions={[mission]} onNavigate={onNavigate} />
      </LangProvider>,
    );

    expect(screen.getByText("Work links")).toBeTruthy();
    const workLinks = screen.getByText("Work links").closest(".detail-section");
    expect(workLinks).toBeTruthy();
    const linkScope = within(workLinks as HTMLElement);
    expect(linkScope.getByText("ann-debug-111")).toBeTruthy();
    expect(linkScope.getByText("process-debug-111")).toBeTruthy();
    expect(linkScope.getAllByText("1").length).toBeGreaterThanOrEqual(2);
    fireEvent.click(linkScope.getByRole("button", { name: "Tasks" }));
    expect(onNavigate).toHaveBeenCalledWith("tasks");

    expect(screen.getByText("Execution state")).toBeTruthy();
    expect(screen.getByText("Step current active: reproduce the crash")).toBeTruthy();
    expect(screen.getAllByText("Handoff contested: suspected root cause")).toHaveLength(2);
    expect(screen.getByText("capsule sha256:aaaaaaaaaaaa")).toBeTruthy();
    expect(screen.getByText("1 refutation(s)")).toBeTruthy();
    expect(screen.getByText("receipt receipt-created-")).toBeTruthy();
    expect(screen.getByText("Handoff workbench")).toBeTruthy();
    expect(screen.getByText(/Signed handoff is a claim, not a verified fact/)).toBeTruthy();
    expect(screen.getByText(/Evidence: 2 pointer\(s\) - unverified/)).toBeTruthy();
    expect(screen.getByText(/Refutations: 1 - authorized 0/)).toBeTruthy();
    expect(screen.getByText(/Next: ask a second agent/)).toBeTruthy();
    expect(await screen.findByText("Evidence verification")).toBeTruthy();
    expect(screen.getByText(/nth_dao\/web\/v2_api.py @ 0123456789/)).toBeTruthy();
    expect(screen.getByText(/source github.com\/nth-dao\/example/)).toBeTruthy();
    expect(screen.getByText(/mapped github.com\/nth-dao\/examp/)).toBeTruthy();
    expect(screen.getByText(/commit ok/)).toBeTruthy();
    expect(screen.getByText(/blob ok/)).toBeTruthy();
    expect(screen.getAllByText(/content hash matches/).length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText(/capsule hypothesis may still be wrong/).length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText(/Response receipt\(s\): receipt-review-1/)).toBeTruthy();
    expect(screen.getByText("Review packet")).toBeTruthy();
    expect(screen.getByText(/Server-issued packet/)).toBeTruthy();
    expect(screen.getByText(/least context needed to re-check/)).toBeTruthy();
    expect(screen.getByText(/Verify each evidence pointer/)).toBeTruthy();
    expect(screen.getByText(/sign a refutation or superseding handoff/)).toBeTruthy();
    fireEvent.click(screen.getByText("Copy packet"));
    expect(navigator.clipboard.writeText).toHaveBeenCalledTimes(1);
    const copied = vi.mocked(navigator.clipboard.writeText).mock.calls[0][0];
    expect(copied).toContain("nth-handoff-review-packet-v1");
    expect(copied).toContain("Signed handoff is a claim, not a verified fact.");
    expect(await screen.findByText("Copied")).toBeTruthy();

    const stepsSection = screen.getByText("Steps").closest(".detail-section");
    expect(stepsSection).toBeTruthy();
    const scoped = within(stepsSection as HTMLElement);
    expect(scoped.getByText("1. reproduce the crash")).toBeTruthy();
    expect(scoped.getByText(/Capabilities: debug/)).toBeTruthy();
    expect(scoped.getByText(/Agent:/)).toBeTruthy();
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
    expect(screen.getByText(/5 earlier state item\(s\) hidden/)).toBeTruthy();
    expect(screen.getByText("70. step 70")).toBeTruthy();
    expect(screen.queryByText("64. step 64")).toBeNull();
    expect(screen.getByText(/6 more step\(s\) hidden/)).toBeTruthy();
  });
});
