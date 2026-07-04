import { afterEach, describe, expect, it, vi } from "vitest";
import { addAgentByDid, discoverLanAgents } from "../api";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  vi.restoreAllMocks();
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
      "/api/agents/add",
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
      "/api/agents/lan_discover",
      expect.objectContaining({ method: "POST" }),
    );
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(String(init.body))).toEqual({
      actor_id: "admin",
      timeout_seconds: 3,
      wanted_capabilities: ["code_review"],
    });
  });
});
