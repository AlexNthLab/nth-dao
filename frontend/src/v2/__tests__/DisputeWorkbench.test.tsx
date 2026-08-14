// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type {
  TradeDisputeGraphResult,
  TradeDisputeStatementPage,
  TradeExecutionHistoryItem,
} from "../types-v2";

vi.mock("../api", () => ({
  getTradeDisputeStatements: vi.fn(),
  getTradeDisputeProjection: vi.fn(),
  createTradeDisputeStatement: vi.fn(),
  deliverTradeDisputeStatement: vi.fn(),
}));

import {
  createTradeDisputeStatement,
  deliverTradeDisputeStatement,
  getTradeDisputeProjection,
  getTradeDisputeStatements,
} from "../api";
import { DisputeWorkbench } from "../components/DisputeWorkbench";
import { ToastProvider } from "../components/Toast";

const orderDigest = `sha256:${"1".repeat(64)}`;
const executionId = `nth-trade-execution-sha256:${"2".repeat(64)}`;
const reviewId = `nth-trade-review-sha256:${"3".repeat(64)}`;
const reviewDigest = `sha256:${"4".repeat(64)}`;
const disputeId = `nth-trade-dispute-sha256:${"5".repeat(64)}`;
const peerDid = "did:key:z6MknzKxotsMLrcVzDz1N1ChUPadVWbzUoXA4bs4surRJDup";

const receipt: TradeExecutionHistoryItem = {
  execution_id: executionId,
  receipt_digest: `sha256:${"6".repeat(64)}`,
  audit_event_id: "7".repeat(64),
  audit_seq: 12,
  executor_did: "did:key:z6Mkrd94r9yJpgZ1HEtiXs25L67fCj4bRLBpynwc6rsnTpTE",
  executor_role: "maker",
  operation_id: "deliver-service",
  hook_name: "fulfillment.deliver",
  side_effect: "none",
  adapter_id: "org.nthdao.adapter/declarative",
  adapter_version: "1.0.0",
  execution_mode: "declarative",
  outcome: "succeeded",
  started_at: "2026-08-14T00:00:00Z",
  completed_at: "2026-08-14T00:01:00Z",
  federation_status: "local-only",
  dispatch_target_url: "",
  dispatch_attempts: 0,
  dispatch_last_error: "",
  dispatch_generation: 0,
  dispatch_superseded_deliveries: 0,
  remote_acknowledgement_digest: "",
  remote_receiver_did: "",
  remote_audit_event_id: "",
  remote_received_at: "",
};

function emptyPage(): TradeDisputeStatementPage {
  return {
    status: "dispute-statements-listed",
    order_digest: orderDigest,
    execution_id: executionId,
    review_id: reviewId,
    items: [],
    snapshot_token: `v2:${"8".repeat(64)}`,
    next_cursor: null,
    graph_endpoint: "/api/v2/trade/dispute-statements/graph",
    claims_adjudicated_or_proven_true: false,
  };
}

function emptyGraph(): TradeDisputeGraphResult {
  return {
    status: "dispute-statement-graph-projected",
    order_digest: orderDigest,
    execution_id: executionId,
    review_id: reviewId,
    graph: {
      snapshot_token: `v2:${"8".repeat(64)}`,
      graph_status: "complete",
      review_digest: reviewDigest,
      dispute_id: disputeId,
      statement_count: 0,
      root_digests: [],
      root_count: 0,
      tip_digests: [],
      tip_count: 0,
      topological_digests: [],
      topological_count: 0,
      unresolved_parent_digests: [],
      unresolved_parent_count: 0,
      non_dag_digests: [],
      non_dag_count: 0,
      issues: [],
      issue_count: 0,
      nodes: [],
      node_count: 0,
      items_truncated: false,
      adjudicated_or_proven_true: false,
    },
    claims_adjudicated_or_proven_true: false,
  };
}

function renderWorkbench(localRole: "maker" | "taker" | "observer" | "unavailable" = "maker") {
  return render(<ToastProvider><DisputeWorkbench
    orderDigest={orderDigest}
    receipt={receipt}
    reviewId={reviewId}
    reviewDigest={reviewDigest}
    localRole={localRole}
    reviewerDid={peerDid}
    peerUrl="https://peer.example"
  /></ToastProvider>);
}

beforeEach(() => {
  vi.mocked(getTradeDisputeStatements).mockReset().mockResolvedValue(emptyPage());
  vi.mocked(getTradeDisputeProjection).mockReset().mockResolvedValue({
    page: emptyPage(),
    graph: emptyGraph(),
  });
  vi.mocked(createTradeDisputeStatement).mockReset();
  vi.mocked(deliverTradeDisputeStatement).mockReset();
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("Dispute Workbench", () => {
  it("labels signed claims as unverified and limits completeness to the local snapshot", async () => {
    const graph = emptyGraph();
    graph.graph.graph_status = "incomplete";
    graph.graph.unresolved_parent_digests = [`sha256:${"9".repeat(64)}`];
    graph.graph.unresolved_parent_count = 1;
    graph.graph.issues = [{
      statement_digest: `sha256:${"a".repeat(64)}`,
      parent_digest: `sha256:${"9".repeat(64)}`,
      reason: "parent.missing",
    }];
    graph.graph.issue_count = 1;
    vi.mocked(getTradeDisputeProjection).mockResolvedValueOnce({
      page: emptyPage(), graph,
    });

    renderWorkbench();

    expect(await screen.findByText(/Signed statements are claims, not verified facts/i)).toBeTruthy();
    expect(screen.getByText(/Do not infer global dispute state/i)).toBeTruthy();
    expect(screen.getByText(/parent.missing/)).toBeTruthy();
  });

  it("rejects a page and graph bound to different signed Reviews", async () => {
    const graph = emptyGraph();
    graph.graph.review_digest = `sha256:${"b".repeat(64)}`;
    vi.mocked(getTradeDisputeProjection).mockResolvedValueOnce({
      page: emptyPage(), graph,
    });

    renderWorkbench();

    expect(await screen.findByText(/bound to a different Receipt Review/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Retry dispute view" })).toBeTruthy();
  });

  it("loads the atomic page and graph projection with one request", async () => {
    renderWorkbench();

    expect(await screen.findByText("Local DAG complete")).toBeTruthy();
    expect(getTradeDisputeProjection).toHaveBeenCalledTimes(1);
    expect(getTradeDisputeStatements).not.toHaveBeenCalled();
  });

  it("never selects a graph tip that is absent from the visible page", async () => {
    const graph = emptyGraph();
    graph.graph.tip_digests = [`sha256:${"a".repeat(64)}`];
    graph.graph.tip_count = 1;
    vi.mocked(getTradeDisputeProjection).mockResolvedValueOnce({
      page: emptyPage(), graph,
    });

    renderWorkbench();

    await screen.findByText("Local DAG complete");
    expect((screen.getByLabelText("Parent claim") as HTMLSelectElement).value).toBe("");
  });

  it("loads the next snapshot-bound Statement page without replacing visible claims", async () => {
    const first = emptyPage();
    first.next_cursor = `v1:${"b".repeat(64)}:${"c".repeat(64)}`;
    vi.mocked(getTradeDisputeProjection).mockResolvedValueOnce({
      page: first,
      graph: emptyGraph(),
    });
    vi.mocked(getTradeDisputeStatements).mockResolvedValueOnce(emptyPage());

    renderWorkbench();
    fireEvent.click(await screen.findByRole("button", { name: "Load more signed claims" }));

    await waitFor(() => expect(getTradeDisputeStatements).toHaveBeenCalledTimes(1));
    expect(vi.mocked(getTradeDisputeStatements).mock.calls[0][4]).toBe(first.next_cursor);
    expect(screen.queryByRole("button", { name: "Load more signed claims" })).toBeNull();
  });

  it("delivers a locally authored signed claim and displays the peer ACK", async () => {
    const statementDigest = `sha256:${"d".repeat(64)}`;
    const page = emptyPage();
    page.items = [{
      statement_digest: statementDigest,
      statement: {
        review_digest: reviewDigest,
        dispute_id: disputeId,
        author_role: "maker",
        author_did: receipt.executor_did,
        statement_type: "evidence",
        reason_codes: [],
        claim: null,
        evidence: [],
      },
      claim_status: "signed-unadjudicated-claim",
      audit_status: "anchored",
      audit_event_id: "7".repeat(64),
    } as never];
    const graph = emptyGraph();
    graph.graph.statement_count = 1;
    graph.graph.node_count = 1;
    graph.graph.root_count = 1;
    graph.graph.tip_count = 1;
    graph.graph.topological_count = 1;
    graph.graph.root_digests = [statementDigest];
    graph.graph.tip_digests = [statementDigest];
    graph.graph.topological_digests = [statementDigest];
    graph.graph.nodes = [{
      statement_digest: statementDigest,
      parent_statement_digests: [],
      ancestry_status: "complete",
      depth: 0,
    }];
    vi.mocked(getTradeDisputeProjection).mockResolvedValueOnce({ page, graph });
    vi.mocked(deliverTradeDisputeStatement).mockResolvedValueOnce({
      acknowledgement_digest: `sha256:${"e".repeat(64)}`,
    } as never);

    renderWorkbench();
    fireEvent.click(await screen.findByRole("button", { name: "Deliver / retry claim" }));

    await waitFor(() => expect(deliverTradeDisputeStatement).toHaveBeenCalledTimes(1));
    expect(deliverTradeDisputeStatement).toHaveBeenCalledWith(
      orderDigest,
      executionId,
      reviewId,
      statementDigest,
      receipt.receipt_digest,
      reviewDigest,
      receipt.executor_did,
      peerDid,
      "https://peer.example",
      expect.any(AbortSignal),
    );
    expect(await screen.findByText(/Peer ACK sha256:/i)).toBeTruthy();
  });

  it("blocks malformed content references before requesting a signature", async () => {
    renderWorkbench();
    await screen.findByText("Local DAG complete");

    fireEvent.change(screen.getByLabelText("Reason codes"), {
      target: { value: "result.mismatch" },
    });
    fireEvent.change(screen.getByLabelText("Content SHA-256 digest"), {
      target: { value: "sha256:NOT-A-DIGEST" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign unadjudicated claim" }));

    expect(await screen.findByText(/pinned by a lowercase sha256 digest/i)).toBeTruthy();
    expect(createTradeDisputeStatement).not.toHaveBeenCalled();
  });

  it("signs an executor response with a retry-stable idempotency key and reloads", async () => {
    vi.mocked(createTradeDisputeStatement).mockResolvedValueOnce({
      statement_digest: `sha256:${"c".repeat(64)}`,
    } as never);
    renderWorkbench();
    await screen.findByText("Local DAG complete");

    fireEvent.change(screen.getByLabelText("Reason codes"), {
      target: { value: "result.mismatch" },
    });
    fireEvent.change(screen.getByLabelText("Content SHA-256 digest"), {
      target: { value: `sha256:${"d".repeat(64)}` },
    });
    fireEvent.change(screen.getByLabelText("Content size in bytes"), {
      target: { value: "42" },
    });
    const signButton = screen.getByRole("button", { name: "Sign unadjudicated claim" });
    fireEvent.click(signButton);
    fireEvent.click(signButton);

    await waitFor(() => expect(createTradeDisputeStatement).toHaveBeenCalledTimes(1));
    const call = vi.mocked(createTradeDisputeStatement).mock.calls[0];
    expect(call[0]).toBe(orderDigest);
    expect(call[1]).toBe(executionId);
    expect(call[2]).toBe(reviewId);
    expect(call[3]).toEqual({
      statement_type: "response",
      parent_statement_digests: [],
      reason_codes: ["result.mismatch"],
      claim: {
        claim_type: "response.summary",
        media_type: "application/json",
        digest: `sha256:${"d".repeat(64)}`,
        size: 42,
        schema_digest: null,
      },
      evidence: [],
      rule_action: null,
    });
    expect(call[4]).toMatch(/^dispute-ui-[0-9a-f]{32}$/);
    expect(call[5]).toBeInstanceOf(AbortSignal);
    await waitFor(() => expect(getTradeDisputeProjection).toHaveBeenCalledTimes(2));
    expect(await screen.findByText(/remains unadjudicated/i)).toBeTruthy();
  });

  it("changes the idempotency key when the signed Review binding changes", async () => {
    vi.mocked(createTradeDisputeStatement)
      .mockRejectedValueOnce(new Error("temporary failure"))
      .mockResolvedValueOnce({
        statement_digest: `sha256:${"c".repeat(64)}`,
      } as never);
    const view = renderWorkbench();
    await screen.findByText("Local DAG complete");
    fireEvent.change(screen.getByLabelText("Reason codes"), {
      target: { value: "result.mismatch" },
    });
    fireEvent.change(screen.getByLabelText("Content SHA-256 digest"), {
      target: { value: `sha256:${"d".repeat(64)}` },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign unadjudicated claim" }));
    await waitFor(() => expect(createTradeDisputeStatement).toHaveBeenCalledTimes(1));
    const firstKey = vi.mocked(createTradeDisputeStatement).mock.calls[0][4];

    const nextReviewId = `nth-trade-review-sha256:${"a".repeat(64)}`;
    const nextReviewDigest = `sha256:${"b".repeat(64)}`;
    const nextGraph = emptyGraph();
    nextGraph.review_id = nextReviewId;
    nextGraph.graph.review_digest = nextReviewDigest;
    vi.mocked(getTradeDisputeProjection).mockResolvedValueOnce({
      page: { ...emptyPage(), review_id: nextReviewId },
      graph: nextGraph,
    });
    view.rerender(<ToastProvider><DisputeWorkbench
      orderDigest={orderDigest}
      receipt={receipt}
      reviewId={nextReviewId}
      reviewDigest={nextReviewDigest}
      localRole="maker"
      reviewerDid={peerDid}
      peerUrl="https://peer.example"
    /></ToastProvider>);
    await waitFor(() => expect(getTradeDisputeProjection).toHaveBeenCalledTimes(2));
    await screen.findByText("Local DAG complete");
    fireEvent.click(screen.getByRole("button", { name: "Sign unadjudicated claim" }));

    await waitFor(() => expect(createTradeDisputeStatement).toHaveBeenCalledTimes(2));
    const secondKey = vi.mocked(createTradeDisputeStatement).mock.calls[1][4];
    expect(secondKey).not.toBe(firstKey);
  });

  it("keeps observers read-only", async () => {
    renderWorkbench("observer");

    expect(await screen.findByText(/Observer access is read-only/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Sign unadjudicated claim" })).toBeNull();
  });
});
