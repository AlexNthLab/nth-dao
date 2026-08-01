import { afterEach, describe, expect, it, vi } from "vitest";

import { getTradeOfferInspection } from "../api";

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
});

describe("Trade Offer inspection API wiring", () => {
  it("wraps a verified local Offer as a non-actionable inspection", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ digest, offer }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await getTradeOfferInspection(digest, false);

    expect(fetchMock).toHaveBeenCalledWith(
      `/api/v2/trade/offers/${encodeURIComponent(digest)}`,
      expect.objectContaining({ credentials: "same-origin" }),
    );
    expect(result).toMatchObject({
      digest,
      offer,
      authority: "local-publisher",
      actionable: false,
      discoveries: [],
      verification: {
        offer_signature_valid: true,
        announcement_binding_valid: null,
        source_did_bound: null,
        recent_source_verified: null,
      },
    });
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
});
