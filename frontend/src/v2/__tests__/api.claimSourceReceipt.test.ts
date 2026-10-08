import { afterEach, describe, expect, it, vi } from "vitest";

import {
  getClaimSourceReceiptStatus,
  getRecordedClaimCompletion,
  importClaimSourceReceipt,
  reconcileClaimSourceReceipt,
} from "../api";

const nonce = "n".repeat(24);
const head = `sha256:${"a".repeat(64)}`;
const responseDigest = `sha256:${"b".repeat(64)}`;
const sourceClaimId = "c".repeat(64);

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status, headers: { "Content-Type": "application/json" },
  });
}

const status = {
  source_claim_id: sourceClaimId,
  completion_head_digest: head,
  expected_response_digest: responseDigest,
  receipt_verified: true,
  pending: true,
  observed_locally: false,
  local_observation_event_id: null,
  accepted: false,
  settled: false,
};

const observation = {
  receipt_key: `${sourceClaimId}:${head}`,
  source_claim_id: sourceClaimId,
  completion_head_digest: head,
  source_receipt_event_id: "e".repeat(64),
  claimant_did: "did:key:zClaimant",
  source_did: "did:key:zSource",
  nonce_authenticated: false,
  response_digest: responseDigest,
  receipt_verified: true,
  observed_locally: true,
  local_observation_event_id: "d".repeat(64),
  verification_scope: "source_statement_and_proof_binding",
  accepted: false,
  settled: false,
  already_observed: false,
};

afterEach(() => vi.unstubAllGlobals());

describe("claimant source receipt API", () => {
  it("keeps older completion summaries readable without inventing a head", async () => {
    const summary = {
      nonce, recorded: true, verification_scope: "signed_evidence_only",
      source_claim_id: sourceClaimId, nonce_authenticated: false,
      mission_id: "mission-1", outcome: "succeeded",
      completed_at_ms: 1_780_000_000_000, revision: 0,
      evidence_digest: responseDigest,
    };
    vi.stubGlobal("fetch", vi.fn()
      .mockResolvedValueOnce(jsonResponse(summary))
      .mockResolvedValueOnce(jsonResponse({ ...summary, completion_head_digest: head })));
    await expect(getRecordedClaimCompletion(nonce)).resolves.toEqual(summary);
    await expect(getRecordedClaimCompletion(nonce)).resolves.toEqual({
      ...summary, completion_head_digest: head,
    });
  });

  it("distinguishes no retained receipt from a verified pending one", async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ detail: "claimant receipt is not retained" }, 404))
      .mockResolvedValueOnce(jsonResponse(status));
    vi.stubGlobal("fetch", fetcher);
    await expect(getClaimSourceReceiptStatus(nonce, head)).resolves.toBeNull();
    await expect(getClaimSourceReceiptStatus(nonce, head)).resolves.toEqual(status);
    expect(fetcher).toHaveBeenCalledWith(
      expect.stringContaining(`/claim-intents/${nonce}/completion/source-receipt/pending?head_digest=`),
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("does not mistake an older server's missing route for an absent receipt", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(
      jsonResponse({ detail: "Not Found" }, 404),
    ));
    await expect(getClaimSourceReceiptStatus(nonce, head))
      .rejects.toThrow(/does not support source receipt checks/);
  });

  it("fails closed on contradictory or mismatched status and server errors", async () => {
    vi.stubGlobal("fetch", vi.fn()
      .mockResolvedValueOnce(jsonResponse({ ...status, observed_locally: true }))
      .mockResolvedValueOnce(jsonResponse({ ...status, completion_head_digest: responseDigest }))
      .mockResolvedValueOnce(jsonResponse({ detail: "unavailable" }, 503)));
    await expect(getClaimSourceReceiptStatus(nonce, head)).rejects.toThrow(/Invalid source receipt status/);
    await expect(getClaimSourceReceiptStatus(nonce, head)).rejects.toThrow(/Invalid source receipt status/);
    await expect(getClaimSourceReceiptStatus(nonce, head)).rejects.toThrow(/503/);
  });

  it("imports only an observed source statement and sends no raw receipt to reconcile", async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(jsonResponse(observation))
      .mockResolvedValueOnce(jsonResponse(observation));
    vi.stubGlobal("fetch", fetcher);
    const signed = { source_receipt_event: { content_hash: "signed" } };
    const controller = new AbortController();
    await expect(importClaimSourceReceipt(
      nonce, head, sourceClaimId, JSON.stringify(signed), controller.signal,
    ))
      .resolves.toEqual(observation);
    await expect(reconcileClaimSourceReceipt(
      nonce, head, sourceClaimId, responseDigest, controller.signal,
    ))
      .resolves.toEqual(observation);
    expect(JSON.parse(fetcher.mock.calls[0][1].body)).toEqual({ source_response: signed });
    expect(fetcher.mock.calls[0][1].signal).toBe(controller.signal);
    expect(fetcher.mock.calls[1][1]).not.toHaveProperty("body");
    expect(fetcher.mock.calls[1][1].signal).toBe(controller.signal);
  });

  it("does not accept a response that claims acceptance or another source claim", async () => {
    vi.stubGlobal("fetch", vi.fn()
      .mockResolvedValueOnce(jsonResponse({ ...observation, accepted: true }))
      .mockResolvedValueOnce(jsonResponse({ ...observation, source_claim_id: "e".repeat(64) })));
    await expect(importClaimSourceReceipt(nonce, head, sourceClaimId, "{}"))
      .rejects.toThrow(/Invalid source receipt observation/);
    await expect(reconcileClaimSourceReceipt(nonce, head, sourceClaimId, responseDigest))
      .rejects.toThrow(/Invalid source receipt observation/);
  });

  it("preserves duplicate keys in raw imported JSON for server rejection", async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(jsonResponse(observation));
    vi.stubGlobal("fetch", fetcher);
    const raw = `{"payload":{"source_claim_id":"other","source_claim_id":"${sourceClaimId}",` +
      `"completion_head_digest":"${head}"}}`;
    await importClaimSourceReceipt(nonce, head, sourceClaimId, raw);
    expect(fetcher.mock.calls[0][1].body).toBe(`{"source_response":${raw}}`);
  });

  it("rejects non-object or trailing JSON before constructing the request", async () => {
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);
    for (const raw of ['{} ,"extra":true', "[]", "null", "{"]) {
      await expect(importClaimSourceReceipt(nonce, head, sourceClaimId, raw))
        .rejects.toThrow(/Invalid source receipt JSON/);
    }
    expect(fetcher).not.toHaveBeenCalled();
  });
});
