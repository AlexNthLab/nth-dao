// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  getRecordedSourceCompletion,
  SourceCompletionLookupState,
  recordSourceCompletionProof,
  verifySourceCompletionProof,
} from "../api";
import recorded from "./fixtures/source-completion-response.json";

const claimId = "a".repeat(64);
const head = `sha256:${"b".repeat(64)}`;
const rawProof = JSON.stringify({
  kind: "nth-market-claim-completion-proof", version: 1,
  source_claim_id: claimId,
  nonce: "n".repeat(24), intent: { nonce: "n".repeat(24) }, claim_receipt: {},
  authority_ack: { ack_id: claimId },
  announcement: { reward_minor: "SIGNED_INTEGER" },
  completion_chain: [{ completion_record: { version: 1 }, execution_receipt: {} }],
}).replace('"SIGNED_INTEGER"', "9007199254740993");
const check = {
  verified: true, reason: "ok", verification_scope: "source_claim_binding_only",
  source_claim_id: claimId, completion_head_digest: head,
  proof_digest: `sha256:${"c".repeat(64)}`,
  mission_id: "mission-1", outcome: "succeeded", revision: 0,
  nonce_authenticated: false, recorded: false, accepted: false, settled: false,
};

afterEach(() => vi.unstubAllGlobals());

describe("source completion proof API", () => {
  it("preflights the original JSON without silently changing signed integers", async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify(check), { status: 200 }));
    vi.stubGlobal("fetch", fetcher);
    await expect(verifySourceCompletionProof(rawProof)).resolves.toMatchObject(check);
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0][0]).toBe("/api/v2/market/completion-proofs/verify-source");
    expect(fetcher.mock.calls[0][1]).toEqual(expect.objectContaining({
      method: "POST", credentials: "same-origin",
      body: `{"proof":${rawProof}}`,
    }));
  });

  it("records only an explicit proof and binds its source receipt to the checked head", async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify(recorded), { status: 200 }));
    vi.stubGlobal("fetch", fetcher);
    await expect(recordSourceCompletionProof(rawProof, claimId, head))
      .resolves.toMatchObject({ source_claim_id: claimId, completion_head_digest: head });
    expect(fetcher.mock.calls[0][0]).toBe("/api/v2/market/completion-proofs/record-source"
      + `?expected_source_claim_id=${claimId}&expected_head_digest=${encodeURIComponent(head)}`);
    expect(fetcher.mock.calls[0][1].body).toBe(`{"proof":${rawProof}}`);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("returns original receipt JSON after an exact source-side recheck", async () => {
    const raw = JSON.stringify(recorded);
    const fetcher = vi.fn().mockResolvedValueOnce(new Response(raw, { status: 200 }));
    vi.stubGlobal("fetch", fetcher);
    await expect(getRecordedSourceCompletion(claimId, head)).resolves.toEqual({ raw, summary: recorded });
    expect(fetcher.mock.calls[0][0]).toBe(
      `/api/v2/market/completion-proofs/source/${claimId}/${head.slice(7)}`,
    );
    expect(fetcher.mock.calls[0][1]).toEqual(expect.objectContaining({ cache: "no-store" }));
  });

  it.each([
    [404, "source completion proof not recorded", "absent"],
    [409, "source proof is pending audit", "pending_audit"],
  ] as const)("recognizes only explicit source lookup state %s", async (status, detail, state) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response(
      JSON.stringify({ detail }), { status },
    )));
    const error = await getRecordedSourceCompletion(claimId, head).catch((cause: unknown) => cause);
    expect(error).toBeInstanceOf(SourceCompletionLookupState);
    expect(error).toMatchObject({ state, status });
  });

  it.each([404, 409])("does not turn a generic HTTP %s into retry permission", async (status) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response(
      JSON.stringify({ detail: "route unavailable" }), { status },
    )));
    const error = await getRecordedSourceCompletion(claimId, head).catch((cause: unknown) => cause);
    expect(error).not.toBeInstanceOf(SourceCompletionLookupState);
    expect(error).toMatchObject({ status });
  });

  it("rejects an inconsistent receipt without trusting unsigned response fields", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response(
      JSON.stringify({ ...recorded, source_receipt_event: {
        ...recorded.source_receipt_event,
        payload: { source_claim_id: "e".repeat(64), completion_head_digest: head },
      } }), { status: 200 },
    )));
    await expect(getRecordedSourceCompletion(claimId, head))
      .rejects.toThrow(/Invalid source completion receipt/);
  });

  it("rejects invalid or oversized local files before transport", async () => {
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);
    await expect(verifySourceCompletionProof("[]")).rejects.toThrow(/Invalid portable completion proof/);
    await expect(verifySourceCompletionProof("x".repeat(20 * 1024 * 1024 + 1)))
      .rejects.toThrow(/size limit/);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("checks the selected claim before a mutating request", async () => {
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);
    await expect(recordSourceCompletionProof(rawProof, "e".repeat(64), head))
      .rejects.toThrow(/Invalid selected/);
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects a record response for a different checked proof digest", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response(
      JSON.stringify(recorded), { status: 200 },
    )));
    await expect(recordSourceCompletionProof(rawProof, claimId, head, `sha256:${"e".repeat(64)}`))
      .rejects.toThrow(/proof digest/);
  });

  it.each(["sig", "author_did", "prev_hash", "seq", "ts_ms", "type"])(
    "rejects a source response without the signed event field %s", async (field) => {
      const event: Record<string, unknown> = { ...recorded.source_receipt_event };
      delete event[field];
      vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response(
        JSON.stringify({ ...recorded, source_receipt_event: event }), { status: 200 },
      )));
      await expect(getRecordedSourceCompletion(claimId, head)).rejects.toThrow(/Invalid source completion receipt/);
    },
  );

  it("rejects receipt responses that claim work acceptance", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response(
      JSON.stringify({ ...recorded, accepted: true }), { status: 200 },
    )));
    await expect(getRecordedSourceCompletion(claimId, head)).rejects.toThrow(/Invalid source completion receipt/);
  });

  it("keeps a recorded receipt readable while a different head is pending audit", async () => {
    const pending = { ...recorded, lineage_state: "pending_audit", lineage_heads: [],
      single_retained_head_digest: null, pending_head_digests: [`sha256:${"e".repeat(64)}`] };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response(JSON.stringify(pending), { status: 200 })));
    await expect(getRecordedSourceCompletion(claimId, head)).resolves.toMatchObject({ summary: pending });
  });

  it("rejects a false single-head assertion when another head is pending", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({
      ...recorded, pending_head_digests: [`sha256:${"e".repeat(64)}`],
    }), { status: 200 })));
    await expect(getRecordedSourceCompletion(claimId, head)).rejects.toThrow(/Invalid source completion receipt/);
  });

  it("preserves a negative preflight and never records it automatically", async () => {
    const negative = { ...check, verified: false, reason: "invalid signature" };
    const fetcher = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify(negative), { status: 200 }));
    vi.stubGlobal("fetch", fetcher);
    await expect(verifySourceCompletionProof(rawProof)).resolves.toMatchObject(negative);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
});
