import { describe, expect, it } from "vitest";

import { agentBackendTimeoutS, agentLinkExecutionDeadline } from "../App";
import type { AgentEntry } from "../types-v2";

describe("AgentLink timeout selection", () => {
  it("allows Codex enough time to complete its HTTP fallback", () => {
    const did = "did:key:z6MkCodexTimeout";
    const agents = [{ did, kind: "codex", ask_timeout_s: 275 }] as AgentEntry[];

    expect(agentBackendTimeoutS(agents, did)).toBe(275);
  });

  it("does not spend the execution budget while a durable job is queued", () => {
    expect(agentLinkExecutionDeadline(
      { state: "accepted", updated_at: "2026-07-15T00:00:00.000Z" },
      240,
      Date.parse("2026-07-15T01:00:00.000Z"),
    )).toBeUndefined();
  });

  it("starts the deadline from the persisted processing transition", () => {
    expect(agentLinkExecutionDeadline(
      { state: "processing", updated_at: "2026-07-15T00:00:00.000Z" },
      240,
    )).toBe(Date.parse("2026-07-15T00:04:15.000Z"));
  });
});
