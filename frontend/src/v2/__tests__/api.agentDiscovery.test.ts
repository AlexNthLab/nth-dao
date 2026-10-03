import { afterEach, describe, expect, it, vi } from "vitest";
import {
  addAgentByDid,
  discoverLanAgents,
  discoverFederationPeers,
  fetchReceiptDetail,
  getFederationStatus,
  announceTask,
  claimFederatedTask,
  getClaimEvidence,
  listClaimIntents,
  reconcileClaimIntent,
  listOpenTasks,
  publishMarketOffer,
  searchMarket,
  refreshFederation,
  updateFederationPeer,
} from "../api";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

describe("v2 agent discovery API wiring", () => {
  it("loads the durable cross-DAO claim intent projection", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      items: [],
      stats: { pending: 0 },
    }));
    vi.stubGlobal("fetch", fetchMock);

    const page = await listClaimIntents(25);

    expect(page.items).toEqual([]);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v2/market/claim-intents?limit=25",
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("encodes the claim cursor when requesting older records", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      items: [], stats: {}, next_cursor: null,
    }));
    vi.stubGlobal("fetch", fetchMock);
    await listClaimIntents(100, undefined, `1700000000000:${"a".repeat(24)}`);
    expect(fetchMock).toHaveBeenCalledWith(
      `/api/v2/market/claim-intents?limit=100&cursor=1700000000000%3A${"a".repeat(24)}`,
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("posts a durable claim intent reconciliation request", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      state: "confirmed",
      authority_ack_id: "ack-1",
    }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await reconcileClaimIntent("a".repeat(24));

    expect(result.status).toBe(200);
    expect(result.body.state).toBe("confirmed");
    expect(fetchMock).toHaveBeenCalledWith(
      `/api/v2/market/claim-intents/${"a".repeat(24)}/reconcile`,
      expect.objectContaining({ method: "POST", credentials: "same-origin" }),
    );
  });

  it("fetches a bounded verified claim summary by nonce", async () => {
    const nonce = "a".repeat(24);
    const summary = {
      nonce, evidence_verified: true, verification_scope: "signed_claim_only",
      claim_receipt_id: "receipt-1", authority_ack_id: "ack-1",
      claimant_did: "did:key:zClaimant", source_did: "did:key:zSource",
      mission_id: "mission-1",
    };
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(summary));
    vi.stubGlobal("fetch", fetchMock);

    await expect(getClaimEvidence(nonce)).resolves.toEqual(summary);
    expect(fetchMock).toHaveBeenCalledWith(
      `/api/v2/market/claim-intents/${nonce}/evidence`,
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it.each([
    ["m".repeat(200), true],
    ["m".repeat(256), true],
    ["m".repeat(257), false],
    ["é".repeat(128), true],
    ["é".repeat(129), false],
  ])("enforces the signed announcement's UTF-8 mission ID bound", async (missionId, valid) => {
    const nonce = "a".repeat(24);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({
      nonce, evidence_verified: true, verification_scope: "signed_claim_only",
      claim_receipt_id: "receipt-1", authority_ack_id: "ack-1",
      claimant_did: "did:key:zClaimant", source_did: "did:key:zSource",
      mission_id: missionId,
    })));
    if (valid) {
      await expect(getClaimEvidence(nonce)).resolves.toMatchObject({ mission_id: missionId });
    } else {
      await expect(getClaimEvidence(nonce)).rejects.toThrow("Invalid claim evidence summary");
    }
  });

  it.each([
    { nonce: "b".repeat(24), evidence_verified: true, verification_scope: "signed_claim_only" },
    { nonce: "a".repeat(24), evidence_verified: false, verification_scope: "signed_claim_only" },
    { nonce: "a".repeat(24), evidence_verified: true, verification_scope: "mission_completed" },
  ])("rejects a misbound claim summary: %o", async (override) => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      claim_receipt_id: "receipt-1", authority_ack_id: "ack-1",
      claimant_did: "did:key:zClaimant", source_did: "did:key:zSource",
      mission_id: "",
      ...override,
    }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(getClaimEvidence("a".repeat(24))).rejects.toThrow(
      "Invalid claim evidence summary",
    );
  });

  it.each([
    [409, "Claim is unconfirmed or signed evidence is missing"],
    [503, "Claim evidence storage is temporarily unavailable"],
    [403, "Console access is required to verify claim evidence"],
    [404, "This server does not support claim evidence checks"],
  ])("explains claim evidence HTTP %i without exposing a raw route", async (status, message) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({}, status)));
    await expect(getClaimEvidence("a".repeat(24))).rejects.toThrow(message);
  });

  it("adds a pasted DID through the hardened legacy add endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      ok: true,
      agent_id: "agent-from-did",
      did: "did:key:z6MkPeer",
      label: "peer",
    }));
    vi.stubGlobal("fetch", fetchMock);

    const res = await addAgentByDid({
      actorId: "admin",
      didOrAgentId: "did:key:z6MkPeer",
      label: "peer",
    });

    expect(res.agent_id).toBe("agent-from-did");
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v2/agents/add",
      expect.objectContaining({ method: "POST" }),
    );
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(String(init.body))).toEqual({
      actor_id: "admin",
      target_agent_id: "",
      target_did: "did:key:z6MkPeer",
      label: "peer",
    });
  });

  it("discovers LAN peers through the hardened legacy discovery endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      peers: [{
        agent_id: "lan-peer",
        label: "LAN Peer",
        capabilities: ["code_review"],
        groups: ["general"],
        ws_url: "ws://127.0.0.1:8765",
        pubkey_hex: "a".repeat(64),
        pubkey_prefix: "aaaaaaaaaaaaaaaa",
        did: "did:key:z6MkLan",
        source_addr: "192.168.1.10:9999",
        rtt_ms: 12,
      }],
    }));
    vi.stubGlobal("fetch", fetchMock);

    const peers = await discoverLanAgents({
      actorId: "admin",
      timeoutSeconds: 3,
      wantedCapabilities: ["code_review"],
    });

    expect(peers).toHaveLength(1);
    expect(peers[0]).toMatchObject({
      did: "did:key:z6MkLan",
      label: "LAN Peer",
      source: "lan",
      capabilities: ["code_review"],
      has_active_cap: false,
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v2/agents/lan_discover",
      expect.objectContaining({ method: "POST" }),
    );
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(String(init.body))).toEqual({
      actor_id: "admin",
      timeout_seconds: 3,
      wanted_capabilities: ["code_review"],
    });
  });

  it("sends console bearer token when fetching raw receipt details", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      receipt: {
        receipt_id: "r-channel-1",
        content_hash: "abc123",
      },
      summary: {
        receipt_id: "r-channel-1",
        signer_did: "did:key:zAgent",
        goal_id: "mission-1",
        issued_at: "",
        content_hash: "abc123",
        prev_content_hash: "",
        kind: "nth-execution-receipt-v1",
        cap_scope: { present: false },
      },
      verification: {
        verified: true,
        status: "verified",
        reason: "",
      },
    }));
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("window", { __NTH_CONSOLE_TOKEN__: "secret-token" });

    const receipt = await fetchReceiptDetail("r-channel-1");

    expect(receipt.summary.receipt_id).toBe("r-channel-1");
    expect(receipt.verification.verified).toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v2/receipts/r-channel-1",
      expect.objectContaining({ credentials: "same-origin" }),
    );
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(init.headers).toMatchObject({
      Accept: "application/json",
      Authorization: "Bearer secret-token",
    });
  });
});

describe("v2 federation API wiring", () => {
  it("sends the content-bound key for federated claims", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ claimed: true }));
    vi.stubGlobal("fetch", fetchMock);

    await claimFederatedTask(
      "shared-id",
      "did:key:zWorker",
      "nth-ann-sha256:abc123",
    );

    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(String(init.body))).toEqual({
      announcement_id: "shared-id",
      federation_key: "nth-ann-sha256:abc123",
      agent_did: "did:key:zWorker",
    });
  });

  it("loads operator federation status", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      peers: ["http://127.0.0.1:8081"],
      file_peers: ["http://127.0.0.1:8081"],
      env_peers: [],
      poller_started: true,
      cached_announcements: 2,
      last_refresh_ms: 123,
      last_error: "",
      last_peer_count: 1,
    }));
    vi.stubGlobal("fetch", fetchMock);

    const status = await getFederationStatus();

    expect(status.cached_announcements).toBe(2);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v2/market/federation/status",
      expect.objectContaining({ credentials: "same-origin" }),
    );
  });

  it("adds a seed peer with console auth attached", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      peers: ["http://127.0.0.1:8081"],
      file_peers: ["http://127.0.0.1:8081"],
      env_peers: [],
      poller_started: true,
      cached_announcements: 0,
      last_refresh_ms: 0,
      last_error: "",
      last_peer_count: 1,
      updated: true,
      peer_url: "http://127.0.0.1:8081",
      action: "add",
    }));
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("window", { __NTH_CONSOLE_TOKEN__: "operator-secret" });

    await updateFederationPeer("http://127.0.0.1:8081", "add");

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v2/market/federation/peers",
      expect.objectContaining({ method: "POST" }),
    );
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(init.headers).toMatchObject({
      Authorization: "Bearer operator-secret",
    });
    expect(JSON.parse(String(init.body))).toEqual({
      peer_url: "http://127.0.0.1:8081",
      action: "add",
    });
  });

  it("refreshes federation through the explicit refresh endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      peers: [],
      file_peers: [],
      env_peers: [],
      poller_started: false,
      cached_announcements: 0,
      last_refresh_ms: 0,
      last_error: "",
      last_peer_count: 0,
      refreshed: true,
    }));
    vi.stubGlobal("fetch", fetchMock);

    const status = await refreshFederation();

    expect(status.refreshed).toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v2/market/federation/refresh",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("discovers nearby federation peers with import enabled", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      peers: ["http://192.168.1.20:8080"],
      file_peers: ["http://192.168.1.20:8080"],
      env_peers: [],
      poller_started: true,
      cached_announcements: 1,
      last_refresh_ms: 123,
      last_error: "",
      last_peer_count: 1,
      discovered: true,
      imported_peers: ["http://192.168.1.20:8080"],
      skipped_peers: [],
      discovery_errors: [],
    }));
    vi.stubGlobal("fetch", fetchMock);

    const status = await discoverFederationPeers({
      actorId: "admin",
      timeoutSeconds: 3,
      add: true,
      refresh: true,
    });

    expect(status.imported_peers).toEqual(["http://192.168.1.20:8080"]);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v2/market/federation/discover",
      expect.objectContaining({ method: "POST" }),
    );
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(String(init.body))).toEqual({
      actor_id: "admin",
      timeout_seconds: 3,
      add: true,
      refresh: true,
    });
  });
});

describe("v2 market listing type API wiring", () => {
  it("keeps legacy read filters while publishing Tasks and Offers separately", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse([]))
      .mockResolvedValueOnce(jsonResponse({
        announcement_id: "ann-task",
        publisher_did: "did:key:zPublisher",
        title: "inspect hardware key",
        listing_type: "task",
        capability_set: [],
        context: "hardware",
        reward_minor: 9900,
        reward_asset: "credit",
        claimed: false,
      }))
      .mockResolvedValueOnce(jsonResponse({ digest: "sha256:x" }));
    vi.stubGlobal("fetch", fetchMock);

    await listOpenTasks({ listingType: "product" });
    await announceTask({ title: "inspect hardware key", listing_type: "task" });
    await publishMarketOffer({
      idempotency_key: "0123456789abcdef",
      intent: "provide",
      category: "products",
      title: "hardware key",
      provides: [{
        leg_id: "provide-1",
        category: "products",
        resource_type: "product",
        resource_id: "urn:nthdao:product:hardware-key",
        quantity: "1",
        unit: "item",
      }],
    });

    expect(fetchMock.mock.calls[0][0]).toBe(
      "/api/v2/market/open?listing_type=product",
    );
    const publishInit = fetchMock.mock.calls[1][1] as RequestInit;
    expect(JSON.parse(String(publishInit.body))).toEqual({
      title: "inspect hardware key",
      listing_type: "task",
    });
    expect(fetchMock.mock.calls[2][0]).toBe("/api/v2/market/offers");
    const offerInit = fetchMock.mock.calls[2][1] as RequestInit;
    expect(JSON.parse(String(offerInit.body))).toEqual(expect.objectContaining({
      intent: "provide",
      category: "products",
      title: "hardware key",
    }));
  });

  it("passes unified market projection filters without changing source facts", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      items: [],
      count: 0,
      truncated: false,
      facets: [],
      projection_only: true,
      warning: "projection",
    }));
    vi.stubGlobal("fetch", fetchMock);

    await searchMarket({
      q: "design",
      category: "services",
      intent: "provide",
      context: "commerce",
      capability: "code_review",
      minValue: 25,
      valueAsset: "USDC",
      limit: 50,
    });

    expect(fetchMock.mock.calls[0][0]).toBe(
      "/api/v2/market/search?q=design&category=services&intent=provide&context=commerce&capability=code_review&min_value=25&value_asset=USDC&limit=50",
    );
    expect((fetchMock.mock.calls[0][1] as RequestInit).method).toBeUndefined();
  });
});
