import { afterEach, describe, expect, it, vi } from "vitest";

import {
  acceptTradeProposal,
  createTradeReceiptReview,
  deliverTradeReceiptReview,
  deliverTradeExecutionReceipt,
  fetchTradeProposals,
  fetchTradeOrders,
  fetchTradeRulePackages,
  getTradeRulePackage,
  getTradeExecutionReceipts,
  getTradeReceiptReview,
  getTradeOfferInspection,
  getTradeOrder,
  getTradeProposal,
  importCachedTradeOffer,
  importTradeRulePackage,
  importTradeRuleRecognitions,
  fetchTradeRuleRecognitionImports,
  fetchTradeRuleRecognitionImportBatch,
} from "../api";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const digest = `sha256:${"a".repeat(64)}`;
const packageDigest = `sha256:${"c".repeat(64)}`;
const resourceDigest = `sha256:${"d".repeat(64)}`;
const publisherDid = "did:key:z6Mkrd94r9yJpgZ1HEtiXs25L67fCj4bRLBpynwc6rsnTpTE";
const proofValue = "jHMmFycGKYwl_rO8cURbBQdZFvO2ux3VWCgmhb8Jkyr94kMR1O3P1PDREi_JZbH_K1DzXFaNwBhpOGkQWrI8AA";

function tradeSkillCatalogItem() {
  return {
    package_digest: packageDigest,
    rule_id: "org.nthdao.rules/delivery",
    version: "1.0.0",
    publisher_did: publisherDid,
    summary: "Signed delivery terms",
    applies_to: ["service"],
    families: ["fulfillment"],
    published_at: "2026-08-01T00:00:00Z",
    not_after: "2026-09-01T00:00:00Z",
    execution: { mode: "declarative", permissions: [] },
    required_capabilities: [],
    resource_count: 1,
    resource_bytes: 18,
    dependency_count: 0,
    conflict_count: 0,
    verification: {
      status: "verified-cache",
      publisher_signature: true,
      resource_digests: true,
    },
    import_audit: {
      status: "not-applicable",
      proposed_count: 0,
      anchored_count: 0,
      incomplete_count: 0,
    },
    provenance: {
      status: "explicit",
      sources: ["local"],
    },
    trust: {
      status: "not-evaluated",
      advisory: true,
      execution_authorized: false,
    },
  } as const;
}

function tradeSkillDetail() {
  const item = tradeSkillCatalogItem();
  return {
    ...item,
    manifest: {
      kind: "org.nthdao.trade.rule-manifest",
      protocol_version: "1.0",
      rule_id: item.rule_id,
      version: item.version,
      publisher_did: item.publisher_did,
      summary: item.summary,
      applies_to: [...item.applies_to],
      families: [...item.families],
      resources: [{
        purpose: "terms",
        media_type: "application/json",
        digest: resourceDigest,
        size: 18,
      }],
      dependencies: [],
      conflicts: [],
      required_capabilities: [],
      hook_contracts: [],
      execution: { mode: "declarative", permissions: [] },
      published_at: item.published_at,
      not_after: item.not_after,
      extensions: {},
      proof: {
        type: "NthEd25519SignatureV1",
        created: "2026-08-01T00:00:00Z",
        verification_method: `${publisherDid}#${publisherDid.slice("did:key:".length)}`,
        proof_purpose: "assertionMethod",
        proof_value: proofValue,
      },
    },
  };
}
const offer = {
  kind: "org.nthdao.trade.offer",
  protocol_version: "2.0",
  offer_id: "org.nthdao.tests/swap",
  revision: 1,
  previous_offer_digest: null,
  state: "active",
  publisher_did: "did:key:zPublisher",
  title: "Compute for review",
  summary: "Exchange one service for another.",
  provides: [],
  requests: [],
  rule_refs: [],
  published_at: "2026-08-01T00:00:00Z",
  not_after: "2026-08-02T00:00:00Z",
  extensions: {},
  proof: {},
};

afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllGlobals();
  delete (window as unknown as { __NTH_CONSOLE_TOKEN__?: string })
    .__NTH_CONSOLE_TOKEN__;
});

describe("Trade Offer inspection API wiring", () => {
  it("uses the server-derived authority for a stored Offer", async () => {
    const localInspection = {
      digest,
      offer,
      discoveries: [],
      verification: {
        offer_signature_valid: true,
        announcement_binding_valid: null,
        source_did_bound: null,
        recent_source_verified: null,
        head_chain_valid: null,
        publisher_head_claim_valid: null,
      },
      authority: "remote-publisher",
      storage_provenance: {
        source_kind: "federation-cache",
        source_id: "did:key:zImporter",
      },
      head_claim: null,
      actionable: false,
      warning: "A valid signature proves authorship, not availability.",
    };
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(localInspection));
    vi.stubGlobal("fetch", fetchMock);

    const result = await getTradeOfferInspection(digest, false);

    expect(fetchMock).toHaveBeenCalledWith(
      `/api/v2/trade/offers/${encodeURIComponent(digest)}`,
      expect.objectContaining({ credentials: "same-origin" }),
    );
    expect(result).toEqual(localInspection);
  });

  it("returns the server-reverified remote inspection unchanged", async () => {
    const remote = {
      digest,
      offer,
      discoveries: [{
        announcement_id: "offer-announcement",
        federation_key: "nth-ann-sha256:announcement",
        source_peer: "https://publisher.example",
        source_did: "did:key:zPublisher",
        stale: false,
        last_verified_ms: 1,
      }],
      verification: {
        offer_signature_valid: true,
        announcement_binding_valid: true,
        source_did_bound: true,
        recent_source_verified: true,
        head_chain_valid: true,
        publisher_head_claim_valid: true,
      },
      authority: "remote-publisher",
      storage_provenance: null,
      head_claim: {
        publisher_claim_verified: true,
        disclosed_chain_complete: true,
        globally_latest_proven: false,
        head_revision: 1,
        chain_length: 1,
        chain_digests: [digest],
        claimed_at_ms: 1,
        expires_at_ms: 2,
      },
      actionable: false,
      warning: "A valid signature proves authorship, not availability.",
    };
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(remote));
    vi.stubGlobal("fetch", fetchMock);

    const result = await getTradeOfferInspection(digest, true);

    expect(fetchMock).toHaveBeenCalledWith(
      `/api/v2/trade/federation/cached-offers/${encodeURIComponent(digest)}`,
      expect.objectContaining({ credentials: "same-origin" }),
    );
    expect(result).toEqual(remote);
  });

  it("posts an authenticated exact-digest durable import request", async () => {
    const persisted = {
      digest,
      appended: true,
      persisted: true,
      classification: "canonical",
      entry_hash: `sha256:${"b".repeat(64)}`,
      source_kind: "federation-cache",
      source_id: "did:key:zPublisher",
      audit_event_id: "c".repeat(64),
      audit_event_ids: ["c".repeat(64)],
      imported_revisions: 1,
      appended_revisions: 1,
      discovery_sources: 1,
      trusted: false,
      actionable: false,
      warning: "Saved locally as a signed claim.",
    };
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(persisted));
    vi.stubGlobal("fetch", fetchMock);
    (window as unknown as { __NTH_CONSOLE_TOKEN__?: string })
      .__NTH_CONSOLE_TOKEN__ = "console-secret";

    const result = await importCachedTradeOffer(digest);

    expect(fetchMock).toHaveBeenCalledWith(
      `/api/v2/trade/federation/cached-offers/${encodeURIComponent(digest)}/import`,
      expect.objectContaining({
        method: "POST",
        credentials: "same-origin",
        headers: expect.objectContaining({
          Authorization: "Bearer console-secret",
        }),
      }),
    );
    expect(result).toEqual(persisted);
  });

  it.each([
    ["non-array event ids", { audit_event_ids: "not-an-array" }],
    [
      "duplicate event ids",
      {
        audit_event_ids: ["c".repeat(64), "c".repeat(64)],
        imported_revisions: 2,
      },
    ],
    ["primary event outside event set", { audit_event_id: "d".repeat(64) }],
    [
      "primary event is not the imported head revision",
      {
        audit_event_ids: ["c".repeat(64), "d".repeat(64)],
        imported_revisions: 2,
      },
    ],
    ["unsafe trust flag", { trusted: true }],
  ])("rejects an invalid import response: %s", async (_label, mutation) => {
    const persisted = {
      digest,
      appended: true,
      persisted: true,
      classification: "canonical",
      entry_hash: `sha256:${"b".repeat(64)}`,
      source_kind: "federation-cache",
      source_id: "did:key:zPublisher",
      audit_event_id: "c".repeat(64),
      audit_event_ids: ["c".repeat(64)],
      imported_revisions: 1,
      appended_revisions: 1,
      discovery_sources: 1,
      trusted: false,
      actionable: false,
      warning: "Saved locally as a signed claim.",
      ...mutation,
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse(persisted)),
    );

    await expect(importCachedTradeOffer(digest)).rejects.toThrow(
      "server returned an invalid persistence result",
    );
  });

  it("accepts a recovered chain when the head already existed", async () => {
    const recovered = {
      digest,
      appended: false,
      persisted: true,
      classification: "canonical",
      entry_hash: `sha256:${"b".repeat(64)}`,
      source_kind: "federation-cache",
      source_id: "did:key:zPublisher",
      audit_event_id: "d".repeat(64),
      audit_event_ids: ["c".repeat(64), "d".repeat(64)],
      imported_revisions: 2,
      appended_revisions: 1,
      discovery_sources: 1,
      trusted: false,
      actionable: false,
      warning: "Saved locally as a signed claim.",
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse(recovered)),
    );

    await expect(importCachedTradeOffer(digest)).resolves.toEqual(recovered);
  });

  it("uses authenticated operator reads for Proposal list and detail", async () => {
    const summary = {
      proposal_digest: digest,
      offer_digest: `sha256:${"b".repeat(64)}`,
      offer_id: "org.nthdao.tests/swap",
      offer_revision: 1,
      maker_did: "did:key:zMaker",
      taker_did: "did:key:zTaker",
      created_at: "2026-08-01T00:00:00Z",
      not_after: "2026-08-02T00:00:00Z",
      rule_bindings_count: 1,
      status: "retained-unaccepted",
      audit_verified: true,
      audit_event_id: "c".repeat(64),
    };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ items: [summary], next_cursor: "" }))
      .mockResolvedValueOnce(jsonResponse({ ...summary, proposal: {} }))
      .mockResolvedValueOnce(jsonResponse({
        status: "accepted-and-delivered",
        order: { order_id: "nth-trade-order-sha256:" + "d".repeat(64) },
        order_digest: "sha256:" + "d".repeat(64),
        local_audit_event_id: "e".repeat(64),
        delivery_digest: "sha256:" + "f".repeat(64),
        remote_intake_receipt: {},
        remote_intake_receipt_digest: "sha256:" + "1".repeat(64),
      }));
    vi.stubGlobal("fetch", fetchMock);
    (window as unknown as { __NTH_CONSOLE_TOKEN__?: string })
      .__NTH_CONSOLE_TOKEN__ = "console-secret";

    await expect(fetchTradeProposals()).resolves.toEqual({
      items: [summary],
      next_cursor: "",
    });
    await expect(getTradeProposal(digest)).resolves.toEqual({
      ...summary,
      proposal: {},
    });
    await expect(
      acceptTradeProposal(digest, "http://peer.example:8080"),
    ).resolves.toMatchObject({ status: "accepted-and-delivered" });
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "/api/v2/trade/proposals?limit=100",
      expect.objectContaining({
        credentials: "same-origin",
        headers: expect.objectContaining({
          Authorization: "Bearer console-secret",
        }),
      }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      `/api/v2/trade/proposals/${encodeURIComponent(digest)}`,
      expect.objectContaining({ credentials: "same-origin" }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      3,
      `/api/v2/trade/proposals/${encodeURIComponent(digest)}/accept`,
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ target_url: "http://peer.example:8080" }),
      }),
    );
  });

  it("uses authenticated operator reads for accepted Order list and detail", async () => {
    const summary = {
      order_digest: digest,
      order_id: `nth:trade:order:${"b".repeat(64)}`,
      proposal_digest: `sha256:${"c".repeat(64)}`,
      acceptance_digest: `sha256:${"d".repeat(64)}`,
      offer_digest: `sha256:${"e".repeat(64)}`,
      maker_did: "did:key:zMaker",
      taker_did: "did:key:zTaker",
      created_at: "2026-08-01T00:00:00Z",
      audit_status: "anchored",
      audit_event_id: "f".repeat(64),
      audit_attempts: 0,
      last_error_code: "",
      delivery_or_payment_proven: false,
    };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ items: [summary], next_cursor: "" }))
      .mockResolvedValueOnce(jsonResponse({ ...summary, order: {} }));
    vi.stubGlobal("fetch", fetchMock);
    (window as unknown as { __NTH_CONSOLE_TOKEN__?: string })
      .__NTH_CONSOLE_TOKEN__ = "console-secret";

    await expect(fetchTradeOrders()).resolves.toEqual({
      items: [summary],
      next_cursor: "",
    });
    await expect(getTradeOrder(digest)).resolves.toEqual({
      ...summary,
      order: {},
    });
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "/api/v2/trade/orders?limit=100",
      expect.objectContaining({
        credentials: "same-origin",
        headers: expect.objectContaining({
          Authorization: "Bearer console-secret",
        }),
      }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      `/api/v2/trade/orders/${encodeURIComponent(digest)}`,
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("requests older execution Receipts with a stable Spine cursor", async () => {
    const page = {
      status: "available",
      items: [],
      has_more: false,
      next_cursor: null,
      error_code: "",
    };
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse(page));
    vi.stubGlobal("fetch", fetchMock);

    await expect(getTradeExecutionReceipts(digest, 42)).resolves.toEqual(page);
    expect(fetchMock).toHaveBeenCalledWith(
      `/api/v2/trade/orders/${encodeURIComponent(digest)}/execution-receipts?limit=100&before_seq=42`,
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("delivers one signed execution Receipt to an operator-selected peer", async () => {
    const executionId = `nth-trade-execution-sha256:${"e".repeat(64)}`;
    const result = {
      status: "execution-receipt-delivered",
      order_digest: digest,
      execution_id: executionId,
      receipt_digest: `sha256:${"f".repeat(64)}`,
      delivery_digest: `sha256:${"1".repeat(64)}`,
      acknowledgement_digest: `sha256:${"2".repeat(64)}`,
      remote_audit_event_id: "3".repeat(64),
      remote_received_at: "2026-09-01T00:02:00Z",
      acknowledgement_persisted: true,
      delivery_or_payment_proven: false,
    } as const;
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse(result));
    vi.stubGlobal("fetch", fetchMock);

    await expect(deliverTradeExecutionReceipt(
      digest,
      executionId,
      "https://peer.example",
    )).resolves.toEqual(result);
    expect(fetchMock).toHaveBeenCalledWith(
      `/api/v2/trade/orders/${encodeURIComponent(digest)}`
        + `/execution-receipts/${encodeURIComponent(executionId)}/deliver`,
      expect.objectContaining({
        body: JSON.stringify({ target_url: "https://peer.example" }),
        credentials: "same-origin",
        method: "POST",
      }),
    );
  });

  it("reads, signs, and delivers the counterparty Receipt Review", async () => {
    const executionId = `nth-trade-execution-sha256:${"e".repeat(64)}`;
    const reviewId = `nth-trade-review-sha256:${"f".repeat(64)}`;
    const reviewState = {
      status: "not-reviewed",
      review_id: reviewId,
      review: null,
      retained_review_digests: [],
      federation: { status: "local-only" },
    } as const;
    const created = {
      status: "review-signed",
      review_id: reviewId,
      review_digest: `sha256:${"1".repeat(64)}`,
    };
    const delivered = {
      status: "receipt-review-delivered",
      review_id: reviewId,
      remote_audit_event_id: "2".repeat(64),
    };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(reviewState))
      .mockResolvedValueOnce(jsonResponse(created, 201))
      .mockResolvedValueOnce(jsonResponse(delivered));
    vi.stubGlobal("fetch", fetchMock);

    await expect(getTradeReceiptReview(digest, executionId)).resolves.toEqual(reviewState);
    await expect(createTradeReceiptReview(
      digest,
      executionId,
      "disputed",
      ["result.invalid", "result.mismatch"],
    )).resolves.toEqual(created);
    await expect(deliverTradeReceiptReview(
      digest,
      executionId,
      reviewId,
      "https://peer.example",
    )).resolves.toEqual(delivered);

    const base = `/api/v2/trade/orders/${encodeURIComponent(digest)}`
      + `/execution-receipts/${encodeURIComponent(executionId)}/reviews`;
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      base,
      expect.objectContaining({ credentials: "same-origin" }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      base,
      expect.objectContaining({
        body: JSON.stringify({
          decision: "disputed",
          reason_codes: ["result.invalid", "result.mismatch"],
        }),
        credentials: "same-origin",
        method: "POST",
      }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      3,
      `${base}/${encodeURIComponent(reviewId)}/deliver`,
      expect.objectContaining({
        body: JSON.stringify({ target_url: "https://peer.example" }),
        credentials: "same-origin",
        method: "POST",
      }),
    );
  });

  it("imports one exact Order-bound Rule Package from an operator peer", async () => {
    const result = {
      status: "installed",
      installed: true,
      offer_digest: `sha256:${"b".repeat(64)}`,
      package_digest: `sha256:${"c".repeat(64)}`,
      rule_id: "org.nthdao.rules/delivery",
      version: "1.0.0",
      publisher_did: publisherDid,
      audit_event_id: "a".repeat(64),
      audit_created: true,
      resource_count: 2,
      resource_bytes: 42,
      trust_granted: false,
      execution_authority_granted: false,
      warning: "Cached only",
    } as const;
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse(result));
    vi.stubGlobal("fetch", fetchMock);
    const controller = new AbortController();

    await expect(importTradeRulePackage(
      digest,
      result.package_digest,
      "http://peer-host:8080",
      controller.signal,
    )).resolves.toEqual(result);
    expect(fetchMock).toHaveBeenCalledWith(
      `/api/v2/trade/orders/${encodeURIComponent(digest)}/rule-packages/${encodeURIComponent(result.package_digest)}/import`,
      expect.objectContaining({
        method: "POST",
        signal: controller.signal,
        body: JSON.stringify({ peer_url: "http://peer-host:8080" }),
      }),
    );
  });

  it.each([
    ["wrong package", { package_digest: `sha256:${"d".repeat(64)}` }],
    ["unsafe trust", { trust_granted: true }],
    ["status mismatch", { status: "already-installed", installed: true }],
    ["invalid audit event", { audit_event_id: "not-an-event" }],
    ["invalid audit creation flag", { audit_created: "yes" }],
    ["non-Ed25519 publisher DID", { publisher_did: "did:key:zPublisher" }],
    ["oversized resource count", { resource_count: 129 }],
    ["unknown field", { unexpected: true }],
  ])("rejects an invalid Trade Skill import response: %s", async (_label, mutation) => {
    const packageDigest = `sha256:${"c".repeat(64)}`;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResponse({
      status: "installed",
      installed: true,
      offer_digest: `sha256:${"b".repeat(64)}`,
      package_digest: packageDigest,
      rule_id: "org.nthdao.rules/delivery",
      version: "1.0.0",
      publisher_did: publisherDid,
      audit_event_id: "a".repeat(64),
      audit_created: true,
      resource_count: 2,
      resource_bytes: 42,
      trust_granted: false,
      execution_authority_granted: false,
      warning: "Cached only",
      ...mutation,
    })));

    await expect(importTradeRulePackage(
      digest,
      packageDigest,
      "http://peer-host:8080",
    )).rejects.toThrow("invalid Trade Skill import result");
  });

  it("imports a paged signed Recognition observation without granting authority", async () => {
    const importedDigest = `sha256:${"e".repeat(64)}`;
    const headsDigest = `sha256:${"f".repeat(64)}`;
    const result = {
      status: "imported",
      proof_protocol_version: "2",
      offer_digest: `sha256:${"b".repeat(64)}`,
      package_digest: packageDigest,
      proof_digests: [
        `sha256:${"1".repeat(64)}`,
        `sha256:${"2".repeat(64)}`,
      ],
      observation_digest: `sha256:${"3".repeat(64)}`,
      observed_heads_digest: headsDigest,
      page_count: 2,
      page_imports: ["4", "5"].map((value, index) => ({
        import_id: value.repeat(64),
        source_origin: "http://peer-host:8080",
        proposal_event_id: String(6 + index * 2).repeat(64),
        completion_event_id: String(7 + index * 2).repeat(64),
        observed_heads_digest: headsDigest,
      })),
      observed_statement_count: 129,
      imported_statement_count: 1,
      reconciled_anchor_count: 0,
      imported_recognition_digests: [importedDigest],
      audit_event_ids: ["a".repeat(64)],
      global_freshness_proven: false,
      issuer_trust_granted: false,
      local_policy_changed: false,
      execution_authority_granted: false,
      warning: "Observed evidence only",
    } as const;
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse(result));
    vi.stubGlobal("fetch", fetchMock);
    const controller = new AbortController();

    await expect(importTradeRuleRecognitions(
      digest,
      packageDigest,
      "http://peer-host:8080",
      controller.signal,
    )).resolves.toEqual(result);
    expect(fetchMock).toHaveBeenCalledWith(
      `/api/v2/trade/orders/${encodeURIComponent(digest)}/rule-packages/${encodeURIComponent(packageDigest)}/recognitions/import`,
      expect.objectContaining({
        method: "POST",
        signal: controller.signal,
        body: JSON.stringify({ peer_url: "http://peer-host:8080" }),
      }),
    );
  });

  it.each([
    ["unsafe authority", { execution_authority_granted: true }],
    ["wrong package", { package_digest: `sha256:${"9".repeat(64)}` }],
    ["page count mismatch", { page_count: 3 }],
    ["overlapping imported and reconciled counts", {
      status: "imported",
      imported_statement_count: 1,
      reconciled_anchor_count: 129,
      imported_recognition_digests: [`sha256:${"e".repeat(64)}`],
      audit_event_ids: ["8".repeat(64)],
    }],
    ["duplicate page audit", {
      page_imports: ["4", "4"].map((value, index) => ({
        import_id: value.repeat(64),
        source_origin: "http://peer-host:8080",
        proposal_event_id: String(6 + index * 2).repeat(64),
        completion_event_id: String(7 + index * 2).repeat(64),
        observed_heads_digest: `sha256:${"f".repeat(64)}`,
      })),
    }],
    ["mixed page sources", {
      page_imports: ["4", "5"].map((value, index) => ({
        import_id: value.repeat(64),
        source_origin: index === 0
          ? "http://peer-host:8080"
          : "http://other-peer:8080",
        proposal_event_id: String(6 + index * 2).repeat(64),
        completion_event_id: String(7 + index * 2).repeat(64),
        observed_heads_digest: `sha256:${"f".repeat(64)}`,
      })),
    }],
    ["reused page audit event", {
      page_imports: ["4", "5"].map((value, index) => ({
        import_id: value.repeat(64),
        source_origin: "http://peer-host:8080",
        proposal_event_id: "6".repeat(64),
        completion_event_id: String(7 + index * 2).repeat(64),
        observed_heads_digest: `sha256:${"f".repeat(64)}`,
      })),
    }],
    ["statement audit reuses page event", {
      status: "imported",
      imported_statement_count: 1,
      imported_recognition_digests: [`sha256:${"e".repeat(64)}`],
      audit_event_ids: ["8".repeat(64)],
    }],
    ["unknown field", { accepted: true }],
  ])("rejects an invalid Recognition page import: %s", async (_label, mutation) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResponse({
      status: "already-observed",
      proof_protocol_version: "2",
      offer_digest: `sha256:${"b".repeat(64)}`,
      package_digest: packageDigest,
      proof_digests: [`sha256:${"1".repeat(64)}`, `sha256:${"2".repeat(64)}`],
      observation_digest: `sha256:${"3".repeat(64)}`,
      observed_heads_digest: `sha256:${"f".repeat(64)}`,
      page_count: 2,
      page_imports: ["4", "5"].map((value, index) => ({
        import_id: value.repeat(64),
        source_origin: "http://peer-host:8080",
        proposal_event_id: String(6 + index * 2).repeat(64),
        completion_event_id: String(7 + index * 2).repeat(64),
        observed_heads_digest: `sha256:${"f".repeat(64)}`,
      })),
      observed_statement_count: 129,
      imported_statement_count: 0,
      reconciled_anchor_count: 0,
      imported_recognition_digests: [],
      audit_event_ids: [],
      global_freshness_proven: false,
      issuer_trust_granted: false,
      local_policy_changed: false,
      execution_authority_granted: false,
      warning: "Observed evidence only",
      ...mutation,
    })));

    await expect(importTradeRuleRecognitions(
      digest,
      packageDigest,
      "http://peer-host:8080",
    )).rejects.toThrow("invalid Recognition import result");
  });

  it("rejects a legacy Recognition response that reuses a Spine event", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResponse({
      status: "imported",
      offer_digest: `sha256:${"b".repeat(64)}`,
      package_digest: packageDigest,
      proof_digest: `sha256:${"1".repeat(64)}`,
      observed_heads_digest: `sha256:${"2".repeat(64)}`,
      import_id: "3".repeat(64),
      source_origin: "http://peer-host:8080",
      import_proposal_event_id: "4".repeat(64),
      import_completion_event_id: "5".repeat(64),
      observed_statement_count: 1,
      imported_statement_count: 1,
      reconciled_anchor_count: 0,
      imported_recognition_digests: [`sha256:${"6".repeat(64)}`],
      audit_event_ids: ["4".repeat(64)],
      global_freshness_proven: false,
      issuer_trust_granted: false,
      local_policy_changed: false,
      execution_authority_granted: false,
      warning: "Observed evidence only",
    })));

    await expect(importTradeRuleRecognitions(
      digest,
      packageDigest,
      "http://peer-host:8080",
    )).rejects.toThrow("invalid Recognition import result");
  });

  it("loads strict per-page Recognition evidence status", async () => {
    const headsDigest = `sha256:${"f".repeat(64)}`;
    const status = {
      order_digest: digest,
      package_digest: packageDigest,
      total: 2,
      returned: 2,
      items: [0, 1].map((pageIndex) => ({
        import_id: String(pageIndex + 1).repeat(64),
        status: "completed",
        proof_digest: `sha256:${String(pageIndex + 3).repeat(64)}`,
        observer_did: publisherDid,
        observed_heads_digest: headsDigest,
        source_origin: "http://peer-host:8080",
        statement_count: pageIndex === 0 ? 128 : 1,
        evidence_status: "verified",
        proposal_event_id: String(6 + pageIndex * 2).repeat(64),
        completion_event_id: String(7 + pageIndex * 2).repeat(64),
        proof_protocol_version: "2",
        observation_digest: `sha256:${"8".repeat(64)}`,
        page_index: pageIndex,
        page_count: 2,
        total_statement_count: 129,
        statement_set_digest: `sha256:${"9".repeat(64)}`,
      })),
    } as const;
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse(status));
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchTradeRuleRecognitionImports(
      digest,
      packageDigest,
    )).resolves.toEqual(status);
    expect(fetchMock).toHaveBeenCalledWith(
      `/api/v2/trade/orders/${encodeURIComponent(digest)}/rule-packages/${encodeURIComponent(packageDigest)}/recognitions/imports?limit=100`,
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("accepts a valid historical origin spelling after server-side retention", async () => {
    const status = {
      order_digest: digest,
      package_digest: packageDigest,
      total: 1,
      returned: 1,
      items: [{
        import_id: "1".repeat(64),
        status: "completed",
        proof_digest: `sha256:${"3".repeat(64)}`,
        observer_did: publisherDid,
        observed_heads_digest: `sha256:${"f".repeat(64)}`,
        source_origin: "http://Peer.Example:80",
        statement_count: 1,
        evidence_status: "verified",
        proposal_event_id: "6".repeat(64),
        completion_event_id: "7".repeat(64),
      }],
    } as const;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResponse(status)));

    await expect(fetchTradeRuleRecognitionImports(
      digest,
      packageDigest,
    )).resolves.toEqual(status);
  });

  it("loads multiple Recognition statuses through one authenticated batch", async () => {
    const secondPackage = `sha256:${"d".repeat(64)}`;
    const page = (packageDigestValue: string) => ({
      order_digest: digest,
      package_digest: packageDigestValue,
      total: 0,
      returned: 0,
      items: [],
    });
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse({
      order_digest: digest,
      package_count: 2,
      items: [page(secondPackage), page(packageDigest)],
    }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchTradeRuleRecognitionImportBatch(
      digest,
      [packageDigest, secondPackage],
    )).resolves.toEqual([page(packageDigest), page(secondPackage)]);
    const path = fetchMock.mock.calls[0][0] as string;
    expect(path).toContain(`/trade/orders/${encodeURIComponent(digest)}/recognitions/imports?`);
    expect(path).toContain(`package_digest=${encodeURIComponent(packageDigest)}`);
    expect(path).toContain(`package_digest=${encodeURIComponent(secondPackage)}`);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("rejects an incomplete Recognition status batch", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResponse({
      order_digest: digest,
      package_count: 1,
      items: [],
    })));

    await expect(fetchTradeRuleRecognitionImportBatch(
      digest,
      [packageDigest],
    )).rejects.toThrow("invalid Recognition status batch");
  });

  it.each(["import_id", "proposal_event_id", "completion_event_id"])(
    "rejects Recognition status batches that reuse %s across packages",
    async (field) => {
      const secondPackage = `sha256:${"d".repeat(64)}`;
      const hex = (value: number) => value.toString(16).repeat(64);
      const item = (seed: number) => ({
        import_id: hex(seed),
        status: "completed",
        proof_digest: `sha256:${hex(seed + 1)}`,
        observer_did: publisherDid,
        observed_heads_digest: `sha256:${hex(seed + 2)}`,
        source_origin: "http://peer-host:8080",
        statement_count: 1,
        evidence_status: "verified",
        proposal_event_id: hex(seed + 3),
        completion_event_id: hex(seed + 4),
      });
      const first = item(1);
      const second = {
        ...item(6),
        [field]: first[field as keyof typeof first],
      };
      const page = (packageDigestValue: string, statusItem: typeof first) => ({
        order_digest: digest,
        package_digest: packageDigestValue,
        total: 1,
        returned: 1,
        items: [statusItem],
      });
      vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResponse({
        order_digest: digest,
        package_count: 2,
        items: [page(packageDigest, first), page(secondPackage, second)],
      })));

      await expect(fetchTradeRuleRecognitionImportBatch(
        digest,
        [packageDigest, secondPackage],
      )).rejects.toThrow("invalid Recognition status batch");
    },
  );

  it.each([
    ["reused Spine event", { proposal_event_id: "6".repeat(64) }],
    ["inconsistent statement set", {
      statement_set_digest: `sha256:${"a".repeat(64)}`,
    }],
    ["duplicate page index", { page_index: 0 }],
  ])("rejects incoherent Recognition status pages: %s", async (_label, mutation) => {
    const items = [0, 1].map((pageIndex) => ({
      import_id: String(pageIndex + 1).repeat(64),
      status: "completed",
      proof_digest: `sha256:${String(pageIndex + 3).repeat(64)}`,
      observer_did: publisherDid,
      observed_heads_digest: `sha256:${"f".repeat(64)}`,
      source_origin: "http://peer-host:8080",
      statement_count: pageIndex === 0 ? 128 : 1,
      evidence_status: "verified",
      proposal_event_id: String(6 + pageIndex * 2).repeat(64),
      completion_event_id: String(7 + pageIndex * 2).repeat(64),
      proof_protocol_version: "2",
      observation_digest: `sha256:${"8".repeat(64)}`,
      page_index: pageIndex,
      page_count: 2,
      total_statement_count: 129,
      statement_set_digest: `sha256:${"9".repeat(64)}`,
    }));
    items[1] = { ...items[1], ...mutation };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResponse({
      order_digest: digest,
      package_digest: packageDigest,
      total: 2,
      returned: 2,
      items,
    })));

    await expect(fetchTradeRuleRecognitionImports(
      digest,
      packageDigest,
    )).rejects.toThrow("invalid Recognition import status");
  });

  it.each([
    ["pending completion", { status: "pending", completion_event_id: "7".repeat(64) }],
    ["page out of bounds", { page_index: 2 }],
    ["unsafe source", { source_origin: "http://user:pass@peer-host:8080" }],
    ["normalized dot path", { source_origin: "http://peer-host:8080/foo/.." }],
    ["encoded dot path", { source_origin: "http://peer-host:8080/%2e" }],
    ["backslash path", { source_origin: "http://peer-host:8080\\foo\\.." }],
    ["unknown evidence", { evidence_status: "trusted" }],
    ["unknown field", { trusted: true }],
  ])("rejects invalid Recognition import status: %s", async (_label, mutation) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResponse({
      order_digest: digest,
      package_digest: packageDigest,
      total: 1,
      returned: 1,
      items: [{
        import_id: "1".repeat(64),
        status: "completed",
        proof_digest: `sha256:${"3".repeat(64)}`,
        observer_did: publisherDid,
        observed_heads_digest: `sha256:${"f".repeat(64)}`,
        source_origin: "http://peer-host:8080",
        statement_count: 1,
        evidence_status: "verified",
        proposal_event_id: "6".repeat(64),
        completion_event_id: "7".repeat(64),
        ...mutation,
      }],
    })));

    await expect(fetchTradeRuleRecognitionImports(
      digest,
      packageDigest,
    )).rejects.toThrow("invalid Recognition import status");
  });

  it("rejects a Recognition status page that omits records within its fixed limit", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResponse({
      order_digest: digest,
      package_digest: packageDigest,
      total: 2,
      returned: 1,
      items: [{
        import_id: "1".repeat(64),
        status: "completed",
        proof_digest: `sha256:${"3".repeat(64)}`,
        observer_did: publisherDid,
        observed_heads_digest: `sha256:${"f".repeat(64)}`,
        source_origin: "http://peer-host:8080",
        statement_count: 1,
        evidence_status: "verified",
        proposal_event_id: "6".repeat(64),
        completion_event_id: "7".repeat(64),
      }],
    })));

    await expect(fetchTradeRuleRecognitionImports(
      digest,
      packageDigest,
    )).rejects.toThrow("invalid Recognition import status");
  });

  it("lists and inspects verified-cache Trade Skills through bounded endpoints", async () => {
    const page = {
      items: [tradeSkillCatalogItem()],
      next_cursor: "",
      cache_only: true,
      execution_authorized: false,
    } as const;
    const detail = tradeSkillDetail();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(page))
      .mockResolvedValueOnce(jsonResponse(detail));
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchTradeRulePackages()).resolves.toEqual(page);
    await expect(getTradeRulePackage(packageDigest)).resolves.toEqual(detail);
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "/api/v2/trade/rule-packages?limit=100",
      expect.objectContaining({ credentials: "same-origin" }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      `/api/v2/trade/rule-packages/${encodeURIComponent(packageDigest)}`,
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("accepts a verified Trade Skill with no expiry", async () => {
    const item = { ...tradeSkillCatalogItem(), not_after: null };
    const detail = {
      ...tradeSkillDetail(),
      ...item,
      manifest: { ...tradeSkillDetail().manifest, not_after: null },
    };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({
        items: [item],
        next_cursor: "",
        cache_only: true,
        execution_authorized: false,
      }))
      .mockResolvedValueOnce(jsonResponse(detail));
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchTradeRulePackages()).resolves.toEqual({
      items: [item],
      next_cursor: "",
      cache_only: true,
      execution_authorized: false,
    });
    await expect(getTradeRulePackage(packageDigest)).resolves.toEqual(detail);
  });

  it.each([
    ["execution authority", { execution_authorized: true }],
    ["unknown page field", { unexpected: true }],
    ["invalid cursor", { next_cursor: "not-a-digest" }],
    ["cursor not bound to last item", { next_cursor: `sha256:${"f".repeat(64)}` }],
  ])("rejects unsafe Trade Skill catalog pages: %s", async (_label, mutation) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResponse({
      items: [tradeSkillCatalogItem()],
      next_cursor: "",
      cache_only: true,
      execution_authorized: false,
      ...mutation,
    })));
    await expect(fetchTradeRulePackages()).rejects.toThrow(
      "invalid Trade Skill catalog page",
    );
  });

  it.each([
    ["status/count mismatch", {
      status: "anchored", proposed_count: 0, anchored_count: 0, incomplete_count: 0,
    }],
    ["final anchor without intent", {
      status: "anchored", proposed_count: 0, anchored_count: 1, incomplete_count: 0,
    }],
    ["unsafe count", {
      status: "incomplete",
      proposed_count: Number.MAX_SAFE_INTEGER + 1,
      anchored_count: 0,
      incomplete_count: Number.MAX_SAFE_INTEGER + 1,
    }],
  ])("rejects invalid Trade Skill import audit: %s", async (_label, importAudit) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResponse({
      items: [{ ...tradeSkillCatalogItem(), import_audit: importAudit }],
      next_cursor: "",
      cache_only: true,
      execution_authorized: false,
    })));
    await expect(fetchTradeRulePackages()).rejects.toThrow(
      "invalid Trade Skill catalog item",
    );
  });

  it.each([
    ["status/source mismatch", { status: "explicit", sources: [] }],
    ["unknown source", { status: "explicit", sources: ["peer"] }],
    ["unsorted sources", { status: "explicit", sources: ["local", "federated"] }],
    ["duplicate sources", { status: "explicit", sources: ["local", "local"] }],
  ])("rejects invalid Trade Skill provenance: %s", async (_label, provenance) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResponse({
      items: [{ ...tradeSkillCatalogItem(), provenance }],
      next_cursor: "",
      cache_only: true,
      execution_authorized: false,
    })));
    await expect(fetchTradeRulePackages()).rejects.toThrow(
      "invalid Trade Skill catalog item",
    );
  });

  it.each([
    ["wrong digest", { package_digest: `sha256:${"e".repeat(64)}` }],
    ["unsafe trust", { trust: { status: "not-evaluated", advisory: true, execution_authorized: true } }],
    ["unknown resource field", {
      manifest: {
        ...tradeSkillDetail().manifest,
        resources: [{
          ...tradeSkillDetail().manifest.resources[0],
          content: "<script>alert(1)</script>",
        }],
      },
    }],
    ["resource byte total mismatch", { resource_bytes: 17 }],
    ["invalid proof", {
      manifest: {
        ...tradeSkillDetail().manifest,
        proof: { ...tradeSkillDetail().manifest.proof, proof_purpose: "authentication" },
      },
    }],
    ["invalid SemVer", { version: "latest" }],
    ["invalid namespaced token", { applies_to: ["Service Name"] }],
    ["unknown hook field", {
      manifest: {
        ...tradeSkillDetail().manifest,
        hook_contracts: [{
          name: "fulfillment.deliver",
          version: "1",
          input_schema_digest: resourceDigest,
          output_schema_digest: resourceDigest,
          side_effect: "none",
          permissions: [],
          unexpected: true,
        }],
      },
    }],
  ])("rejects malformed Trade Skill details: %s", async (_label, mutation) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValueOnce(jsonResponse({
      ...tradeSkillDetail(),
      ...mutation,
    })));
    await expect(getTradeRulePackage(packageDigest)).rejects.toThrow(
      "invalid Trade Skill detail",
    );
  });
});
