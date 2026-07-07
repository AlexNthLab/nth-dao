import { afterEach, describe, expect, it, vi } from "vitest";
import {
  addAgentByDid,
  discoverLanAgents,
  fetchReceiptDetail,
  getFederationStatus,
  announceTask,
  listOpenTasks,
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
});

describe("v2 market listing type API wiring", () => {
  it("passes listing_type filters and publish bodies", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse([]))
      .mockResolvedValueOnce(jsonResponse({
        announcement_id: "ann-product",
        publisher_did: "did:key:zPublisher",
        title: "hardware key",
        listing_type: "product",
        capability_set: [],
        context: "hardware",
        reward_minor: 9900,
        reward_asset: "credit",
        claimed: false,
      }));
    vi.stubGlobal("fetch", fetchMock);

    await listOpenTasks({ listingType: "product" });
    await announceTask({ title: "hardware key", listing_type: "product" });

    expect(fetchMock.mock.calls[0][0]).toBe(
      "/api/v2/market/open?listing_type=product",
    );
    const publishInit = fetchMock.mock.calls[1][1] as RequestInit;
    expect(JSON.parse(String(publishInit.body))).toEqual({
      title: "hardware key",
      listing_type: "product",
    });
  });
});
