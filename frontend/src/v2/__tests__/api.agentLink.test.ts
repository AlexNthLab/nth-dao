import { describe, expect, it, vi } from "vitest";
import { getAgentLink, submitAgentLink } from "../api";

describe("AgentLink API", () => {
  it("submits immediately and polls a durable job shape", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        job_id: "job-1", agent_did: "did:key:z", state: "accepted",
      }), { status: 202 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        job_id: "job-1", agent_id: "a", agent_did: "did:key:z",
        state: "processing", created_at: "now", updated_at: "now",
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        job_id: "job-1", agent_id: "a", agent_did: "did:key:z",
        state: "completed", created_at: "now", updated_at: "now",
        response: "done", receipt_id: "receipt-1",
      }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const accepted = await submitAgentLink(
      "did:key:z", "hello", "m-1", undefined, 180,
    );
    const processing = await getAgentLink("did:key:z", accepted.job_id);
    const completed = await getAgentLink("did:key:z", accepted.job_id);

    expect(accepted.state).toBe("accepted");
    expect(processing.state).toBe("processing");
    expect(completed.response).toBe("done");
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[0][1].method).toBe("POST");
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toMatchObject({
      prompt: "hello", idempotency_key: "m-1", timeout_s: 180,
    });
  });
});
