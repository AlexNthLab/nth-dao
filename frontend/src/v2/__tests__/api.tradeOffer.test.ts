import { afterEach, describe, expect, it, vi } from "vitest";

import { getTradeOfferInspection, importCachedTradeOffer } from "../api";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const digest = `sha256:${"a".repeat(64)}`;
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
      },
      authority: "remote-publisher",
      storage_provenance: {
        source_kind: "federation-cache",
        source_id: "did:key:zImporter",
      },
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
      },
      authority: "remote-publisher",
      storage_provenance: null,
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
      audit_event_id: "event-imported",
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
});
