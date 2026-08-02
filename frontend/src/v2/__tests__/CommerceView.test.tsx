// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { order } = vi.hoisted(() => ({ order: {
  order_id: "nth-order-sha256:" + "a".repeat(64),
  role: "buyer" as const,
  state: "delivered",
  buyer_did: "did:key:zBuyer",
  seller_did: "did:key:zSeller",
  listing_id: "review-v1",
  listing_digest: "sha256:" + "b".repeat(64),
  listing_type: "service" as const,
  title: "Adversarial review",
  amount_minor: 7_500_000,
  currency: "NTH-TEST" as const,
  settlement_method: "manual:nth_test" as const,
  created_at_ms: 1_900_000_000_000,
  binding: "verified",
  events: [{
    seq: 0, type: "order_created", actor_did: "did:key:zBuyer",
    state: "created", created_at_ms: 1_900_000_000_000,
    receipt_id: "sha256:" + "c".repeat(64),
  }, {
    seq: 1, type: "delivery_submitted", actor_did: "did:key:zSeller",
    state: "delivered", created_at_ms: 1_900_000_001_000,
    receipt_id: "sha256:" + "e".repeat(64),
    details: { delivery: { summary: "Signed report", artifact_digest: "sha256:" + "d".repeat(64) } },
  }],
} }));

vi.mock("../api", () => ({
  ApiHttpError: class ApiHttpError extends Error {
    status: number;
    path: string;
    constructor(_method: string, path: string, status: number) {
      super(`HTTP ${status}`);
      this.status = status;
      this.path = path;
    }
  },
  fetchCommerceListings: vi.fn().mockResolvedValue([]),
  fetchCommerceOrders: vi.fn().mockResolvedValue([order]),
  fetchTradeProposals: vi.fn().mockResolvedValue({ items: [], next_cursor: "" }),
  fetchTradeOrders: vi.fn().mockResolvedValue({ items: [], next_cursor: "" }),
  getTradeProposal: vi.fn().mockResolvedValue(null),
  acceptTradeProposal: vi.fn().mockResolvedValue({
    status: "accepted-and-delivered",
    order: { order_id: "nth-trade-order-sha256:" + "f".repeat(64) },
    order_digest: "sha256:" + "f".repeat(64),
    local_audit_event_id: "a".repeat(64),
    delivery_digest: "sha256:" + "d".repeat(64),
    remote_intake_receipt: {},
    remote_intake_receipt_digest: "sha256:" + "e".repeat(64),
  }),
  getTradeOrder: vi.fn().mockResolvedValue(null),
  listOpenTasks: vi.fn().mockResolvedValue([]),
  publishCommerceListing: vi.fn().mockResolvedValue({ digest: "sha256:x", warning: "" }),
  remoteCommerceCheckout: vi.fn().mockResolvedValue({ order, delivery: { status: "acknowledged" }, warning: "" }),
  submitCommerceDelivery: vi.fn(),
  verifyCommerceDelivery: vi.fn().mockResolvedValue({ order: { ...order, state: "verified" }, warning: "" }),
  settleCommerceOrder: vi.fn(),
  disputeCommerceOrder: vi.fn(),
  resolveCommerceDispute: vi.fn(),
  dispatchCommerceOutbox: vi.fn().mockResolvedValue([]),
}));

import {
  ApiHttpError,
  fetchCommerceOrders,
  fetchTradeProposals,
  fetchTradeOrders,
  getTradeOrder,
  getTradeProposal,
  acceptTradeProposal,
  dispatchCommerceOutbox,
  listOpenTasks,
  publishCommerceListing,
  remoteCommerceCheckout,
  resolveCommerceDispute,
  verifyCommerceDelivery,
} from "../api";
import { CommerceView } from "../components/CommerceView";
import { ToastProvider } from "../components/Toast";

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  vi.clearAllMocks();
});

describe("CommerceView", () => {
  it("shows purchases, signed timeline, and buyer verification actions", async () => {
    render(<ToastProvider><CommerceView /></ToastProvider>);
    expect(await screen.findAllByText("Adversarial review")).not.toHaveLength(0);
    expect(screen.getByText("manual / NTH-TEST")).toBeTruthy();
    expect(screen.getByText("order_created")).toBeTruthy();
    expect(screen.getByText(/Signed report/)).toBeTruthy();
    expect(screen.getByText(/does not prove the work is correct/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Accept" }));
    await waitFor(() => expect(verifyCommerceDelivery).toHaveBeenCalledWith(
      order.order_id, "pass", { reviewed: true }, "",
    ));
  });

  it("warns when a signed action remains pending in the durable outbox", async () => {
    vi.mocked(verifyCommerceDelivery).mockResolvedValueOnce({
      order: { ...order, state: "verified" }, warning: "",
      queued: { message_id: "sha256:pending", status: "pending", error: "peer unavailable" },
    });
    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "Accept" }));
    expect(await screen.findByText(/still awaiting peer acknowledgement/)).toBeTruthy();
  });

  it("turns a federated signed service summary into a prefilled checkout", async () => {
    vi.mocked(listOpenTasks).mockResolvedValueOnce([{
      announcement_id: "ann-1", publisher_did: "did:key:zSeller", title: "Remote review",
      listing_type: "service", capability_set: [], context: "commerce",
      reward_minor: 2_000_000, reward_asset: "NTH-TEST", federated: true,
      source_peer: "https://seller.example", offer_digest: "sha256:" + "f".repeat(64),
      price_minor: 2_000_000, price_asset: "NTH-TEST",
    }]);
    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /My services/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Buy" }));
    expect((screen.getByLabelText("Peer URL") as HTMLInputElement).value).toBe("https://seller.example");
    expect((screen.getByLabelText("Listing digest") as HTMLInputElement).value).toBe("sha256:" + "f".repeat(64));
  });

  it("lets the bound buyer resolve a disputed no-money order", async () => {
    vi.mocked(fetchCommerceOrders).mockResolvedValueOnce([{ ...order, state: "disputed" }]);
    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "Refund buyer" }));
    await waitFor(() => expect(resolveCommerceDispute).toHaveBeenCalledWith(
      order.order_id, "refund", "",
    ));
  });

  it("publishes only the fixed no-money service shape", async () => {
    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Publish service" }));
    fireEvent.change(screen.getByLabelText("Service ID"), { target: { value: "svc-1" } });
    fireEvent.change(screen.getByLabelText("Title"), { target: { value: "Review" } });
    fireEvent.change(screen.getByLabelText("Price in NTH-TEST"), { target: { value: "2" } });
    fireEvent.click(screen.getByRole("button", { name: "Publish" }));
    await waitFor(() => expect(publishCommerceListing).toHaveBeenCalledWith({
      listingId: "svc-1", title: "Review", description: "", priceValue: "2",
    }));
  });

  it("starts one-click checkout with a configured peer and digest", async () => {
    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Buy from peer" }));
    fireEvent.change(screen.getByLabelText("Peer URL"), { target: { value: "https://seller.example" } });
    fireEvent.change(screen.getByLabelText("Listing digest"), { target: { value: "sha256:" + "d".repeat(64) } });
    fireEvent.click(screen.getByRole("button", { name: "Verify and order" }));
    await waitFor(() => expect(remoteCommerceCheckout).toHaveBeenCalledWith({
      targetUrl: "https://seller.example",
      listingDigest: "sha256:" + "d".repeat(64),
      purpose: "Purchase one digital service",
      idempotencyKey: expect.any(String),
    }));
  });

  it("reuses one idempotency key for a failed network attempt and its retry", async () => {
    vi.mocked(remoteCommerceCheckout)
      .mockRejectedValueOnce(new Error("response lost"))
      .mockResolvedValueOnce({ order, delivery: { status: "acknowledged" }, warning: "" });
    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Buy from peer" }));
    fireEvent.change(screen.getByLabelText("Peer URL"), { target: { value: "https://seller.example" } });
    fireEvent.change(screen.getByLabelText("Listing digest"), { target: { value: "sha256:" + "9".repeat(64) } });
    const submit = screen.getByRole("button", { name: "Verify and order" });
    fireEvent.click(submit);
    await waitFor(() => expect(remoteCommerceCheckout).toHaveBeenCalledTimes(1));
    fireEvent.click(submit);
    await waitFor(() => expect(remoteCommerceCheckout).toHaveBeenCalledTimes(2));
    const first = vi.mocked(remoteCommerceCheckout).mock.calls[0][0].idempotencyKey;
    const second = vi.mocked(remoteCommerceCheckout).mock.calls[1][0].idempotencyKey;
    expect(first).toBeTruthy();
    expect(second).toBe(first);
  });

  it("reports a retry as pending instead of claiming success", async () => {
    vi.mocked(dispatchCommerceOutbox).mockResolvedValueOnce([{
      message_id: "sha256:" + "8".repeat(64),
      status: "pending",
      error: "peer unavailable",
    }]);
    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "Retry pending Outbox" }));
    expect(await screen.findByText(/still pending/)).toBeTruthy();
    expect(screen.queryByText("Outbox retry completed")).toBeNull();
  });

  it("shows inbound Proposals as signed claims, never accepted trades", async () => {
    const digest = "sha256:" + "7".repeat(64);
    const summary = {
      proposal_digest: digest,
      offer_digest: "sha256:" + "6".repeat(64),
      offer_id: "org.nthdao.tests/review-swap",
      offer_revision: 2,
      maker_did: "did:key:zMaker",
      taker_did: "did:key:zTaker",
      created_at: "2026-08-02T00:00:00Z",
      not_after: "2026-08-03T00:00:00Z",
      rule_bindings_count: 1,
      status: "retained-unaccepted" as const,
      audit_verified: true,
      audit_event_id: "a".repeat(64),
    };
    vi.mocked(fetchTradeProposals).mockResolvedValueOnce({
      items: [summary],
      next_cursor: "",
    });
    const detail = {
      ...summary,
      proposal: {
        kind: "nth.dao.trade.proposal",
        protocol_version: "1",
        offer_publisher_did: summary.maker_did,
        offer_id: summary.offer_id,
        offer_revision: 2,
        offer_digest: summary.offer_digest,
        canonical_chain_digests: ["sha256:" + "5".repeat(64), summary.offer_digest],
        maker_did: summary.maker_did,
        taker_did: summary.taker_did,
        rule_bindings: [{ rule_id: "org.nthdao.rules/delivery", digest: "sha256:" + "4".repeat(64) }],
        taker_policy_digest: "sha256:" + "3".repeat(64),
        taker_policy: {},
        terms: { requested_quantity: "1" },
        created_at: summary.created_at,
        not_after: summary.not_after,
        proof: {},
      },
    };
    vi.mocked(getTradeProposal)
      .mockResolvedValueOnce(detail)
      .mockResolvedValueOnce({
        ...detail,
        audit_verified: false,
        audit_event_id: "",
      });

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Proposals/ }));

    expect(await screen.findByText("Inbound negotiation")).toBeTruthy();
    expect(screen.getAllByText("Pending review").length).toBeGreaterThan(0);
    expect(screen.getByText(/It is not acceptance/)).toBeTruthy();
    expect(screen.getByText(/requested_quantity/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Accept and send" }).hasAttribute("disabled")).toBe(true);
    expect(getTradeProposal).toHaveBeenCalledWith(digest, expect.any(AbortSignal));

    vi.mocked(fetchTradeProposals).mockRejectedValueOnce(
      new Error("temporary Proposal outage"),
    );
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(await screen.findByText(/showing last known data/)).toBeTruthy();
    expect(screen.getByText(/requested_quantity/)).toBeTruthy();
    await waitFor(() => expect(getTradeProposal).toHaveBeenCalledTimes(2));
    expect(screen.getByText("Missing")).toBeTruthy();
  });

  it("accepts an audited Proposal after a taker DAO URL is provided", async () => {
    const digest = "sha256:" + "8".repeat(64);
    const summary = {
      proposal_digest: digest,
      offer_digest: "sha256:" + "6".repeat(64),
      offer_id: "org.nthdao.tests/review-swap",
      offer_revision: 2,
      maker_did: "did:key:zMaker",
      taker_did: "did:key:zTaker",
      created_at: "2026-08-02T00:00:00Z",
      not_after: "2026-08-03T00:00:00Z",
      rule_bindings_count: 1,
      status: "retained-unaccepted" as const,
      audit_verified: true,
      audit_event_id: "a".repeat(64),
    };
    vi.mocked(fetchTradeProposals).mockResolvedValueOnce({
      items: [summary],
      next_cursor: "",
    });
    vi.mocked(getTradeProposal).mockResolvedValueOnce({
      ...summary,
      proposal: {
        kind: "nth.dao.trade.proposal",
        protocol_version: "1",
        offer_publisher_did: summary.maker_did,
        offer_id: summary.offer_id,
        offer_revision: summary.offer_revision,
        offer_digest: summary.offer_digest,
        canonical_chain_digests: [summary.offer_digest],
        maker_did: summary.maker_did,
        taker_did: summary.taker_did,
        rule_bindings: [{
          rule_id: "org.nthdao.rules/delivery",
          digest: "sha256:" + "4".repeat(64),
        }],
        taker_policy_digest: "sha256:" + "3".repeat(64),
        taker_policy: {},
        terms: { requested_quantity: "1" },
        created_at: summary.created_at,
        not_after: summary.not_after,
        proof: {},
      },
    });

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Proposals/ }));
    const target = await screen.findByPlaceholderText("http://peer-host:8080");
    fireEvent.change(target, {
      target: { value: "http://peer.example:8080" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Accept and send" }));

    await waitFor(() => expect(acceptTradeProposal).toHaveBeenCalledWith(
      digest,
      "http://peer.example:8080",
    ));
  });

  it("shows accepted agreements without claiming delivery or payment", async () => {
    const digest = "sha256:" + "1".repeat(64);
    const summary = {
      order_digest: digest,
      order_id: "nth:trade:order:" + "2".repeat(64),
      proposal_digest: "sha256:" + "3".repeat(64),
      acceptance_digest: "sha256:" + "4".repeat(64),
      offer_digest: "sha256:" + "5".repeat(64),
      maker_did: "did:key:zMaker",
      taker_did: "did:key:zTaker",
      created_at: "2026-08-02T00:00:00Z",
      audit_status: "anchored" as const,
      audit_event_id: "6".repeat(64),
      audit_attempts: 0,
      last_error_code: "",
      delivery_or_payment_proven: false as const,
    };
    vi.mocked(fetchTradeOrders).mockResolvedValueOnce({
      items: [summary],
      next_cursor: "",
    });
    vi.mocked(getTradeOrder).mockResolvedValueOnce({
      ...summary,
      order: {
        kind: "nth.dao.trade.order",
        snapshot: { proposal: { terms: { requested_quantity: "1" } } },
      },
    });

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Agreements/ }));

    expect(await screen.findByText("Bilateral acceptance")).toBeTruthy();
    expect(screen.getByText(/does not prove delivery, payment, quality, or completion/i)).toBeTruthy();
    expect(screen.getByText("Not proven")).toBeTruthy();
    expect(screen.getByText(/requested_quantity/)).toBeTruthy();
    expect(getTradeOrder).toHaveBeenCalledWith(digest, expect.any(AbortSignal));
  });

  it("shows durable pending delivery state and retries with the server target", async () => {
    const digest = "sha256:" + "1".repeat(64);
    const summary = {
      order_digest: digest,
      order_id: "nth:trade:order:" + "2".repeat(64),
      proposal_digest: "sha256:" + "3".repeat(64),
      acceptance_digest: "sha256:" + "4".repeat(64),
      offer_digest: "sha256:" + "5".repeat(64),
      maker_did: "did:key:zMaker",
      taker_did: "did:key:zTaker",
      created_at: "2026-08-02T00:00:00Z",
      audit_status: "anchored" as const,
      audit_event_id: "6".repeat(64),
      audit_attempts: 0,
      last_error_code: "",
      delivery_or_payment_proven: false as const,
      dispatch_pending: true,
      dispatch_target_url: "http://peer.example:8080",
      dispatch_attempts: 2,
      dispatch_generation: 2,
      dispatch_superseded_deliveries: 1,
      dispatch_last_error: "peer unavailable",
      remote_acknowledged: false,
    };
    vi.mocked(fetchTradeOrders).mockResolvedValueOnce({
      items: [summary],
      next_cursor: "",
    });
    vi.mocked(getTradeOrder).mockResolvedValueOnce({
      ...summary,
      order: { kind: "nth.dao.trade.order" },
    });

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Agreements/ }));

    expect(await screen.findByText("Delivery pending")).toBeTruthy();
    expect(screen.getByText("Last attempt: peer unavailable")).toBeTruthy();
    expect(screen.getByText(/Delivery generation: 2/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Retry delivery" }));
    await waitFor(() => expect(acceptTradeProposal).toHaveBeenCalledWith(
      summary.proposal_digest,
      summary.dispatch_target_url,
    ));
  });

  it("loads Proposal rows beyond the first 100-item page", async () => {
    const makeSummary = (index: number) => ({
      proposal_digest: `sha256:${index.toString(16).padStart(64, "0")}`,
      offer_digest: "sha256:" + "6".repeat(64),
      offer_id: `org.nthdao.tests/page-${index}`,
      offer_revision: 1,
      maker_did: "did:key:zMaker",
      taker_did: "did:key:zTaker",
      created_at: "2026-08-02T00:00:00Z",
      not_after: "2026-08-03T00:00:00Z",
      rule_bindings_count: 1,
      status: "retained-unaccepted" as const,
      audit_verified: true,
      audit_event_id: "a".repeat(64),
    });
    const firstPage = Array.from({ length: 100 }, (_, index) => makeSummary(index));
    vi.mocked(fetchTradeProposals)
      .mockResolvedValueOnce({ items: firstPage, next_cursor: "cursor-100" })
      .mockResolvedValueOnce({ items: [makeSummary(100)], next_cursor: "" });

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Proposals/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Load more" }));

    expect(await screen.findByText("org.nthdao.tests/page-100")).toBeTruthy();
    expect(fetchTradeProposals).toHaveBeenNthCalledWith(2, "cursor-100");
    expect(screen.queryByRole("button", { name: "Load more" })).toBeNull();
  });

  it("clears all cached Proposal pages when pagination loses authorization", async () => {
    const summary = {
      proposal_digest: "sha256:" + "8".repeat(64),
      offer_digest: "sha256:" + "7".repeat(64),
      offer_id: "org.nthdao.tests/private-page",
      offer_revision: 1,
      maker_did: "did:key:zMaker",
      taker_did: "did:key:zTaker",
      created_at: "2026-08-02T00:00:00Z",
      not_after: "2026-08-03T00:00:00Z",
      rule_bindings_count: 1,
      status: "retained-unaccepted" as const,
      audit_verified: true,
      audit_event_id: "a".repeat(64),
    };
    vi.mocked(fetchTradeProposals)
      .mockResolvedValueOnce({ items: [summary], next_cursor: "private-next" })
      .mockRejectedValueOnce(
        new ApiHttpError("GET", "/api/v2/trade/proposals", 403),
      );

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Proposals/ }));
    expect(await screen.findByText(summary.offer_id)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Load more" }));

    expect(await screen.findByText(/cached data cleared/)).toBeTruthy();
    expect(screen.queryByText(summary.offer_id)).toBeNull();
    expect(screen.queryByText(/showing last known data/)).toBeNull();
  });

  it("does not let an older Proposal refresh overwrite a newer result", async () => {
    const summary = (name: string, digit: string) => ({
      proposal_digest: `sha256:${digit.repeat(64)}`,
      offer_digest: "sha256:" + "6".repeat(64),
      offer_id: name,
      offer_revision: 1,
      maker_did: "did:key:zMaker",
      taker_did: "did:key:zTaker",
      created_at: "2026-08-02T00:00:00Z",
      not_after: "2026-08-03T00:00:00Z",
      rule_bindings_count: 1,
      status: "retained-unaccepted" as const,
      audit_verified: true,
      audit_event_id: "a".repeat(64),
    });
    let resolveOld!: (value: { items: ReturnType<typeof summary>[]; next_cursor: string }) => void;
    let resolveNew!: (value: { items: ReturnType<typeof summary>[]; next_cursor: string }) => void;
    vi.mocked(fetchTradeProposals)
      .mockReturnValueOnce(new Promise((resolve) => { resolveOld = resolve; }))
      .mockReturnValueOnce(new Promise((resolve) => { resolveNew = resolve; }));

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(screen.getByRole("tab", { name: /Proposals/ }));
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    resolveNew({ items: [summary("new-result", "9")], next_cursor: "" });
    expect(await screen.findByText("new-result")).toBeTruthy();
    resolveOld({ items: [summary("old-result", "8")], next_cursor: "" });
    await Promise.resolve();

    expect(screen.queryByText("old-result")).toBeNull();
    expect(screen.getByText("new-result")).toBeTruthy();
  });

  it("does not append an old pagination response after a newer refresh", async () => {
    const summary = (name: string, digit: string) => ({
      proposal_digest: `sha256:${digit.repeat(64)}`,
      offer_digest: "sha256:" + "6".repeat(64),
      offer_id: name,
      offer_revision: 1,
      maker_did: "did:key:zMaker",
      taker_did: "did:key:zTaker",
      created_at: "2026-08-02T00:00:00Z",
      not_after: "2026-08-03T00:00:00Z",
      rule_bindings_count: 1,
      status: "retained-unaccepted" as const,
      audit_verified: true,
      audit_event_id: "a".repeat(64),
    });
    let resolveOldPage!: (value: {
      items: ReturnType<typeof summary>[];
      next_cursor: string;
    }) => void;
    const oldPage = new Promise<{
      items: ReturnType<typeof summary>[];
      next_cursor: string;
    }>((resolve) => { resolveOldPage = resolve; });
    vi.mocked(fetchTradeProposals)
      .mockResolvedValueOnce({
        items: [summary("first-page", "1")],
        next_cursor: "old-next",
      })
      .mockReturnValueOnce(oldPage)
      .mockResolvedValueOnce({
        items: [summary("fresh-page", "2")],
        next_cursor: "",
      });

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Proposals/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Load more" }));
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(await screen.findByText("fresh-page")).toBeTruthy();
    resolveOldPage({ items: [summary("stale-page", "3")], next_cursor: "" });
    await Promise.resolve();

    expect(screen.queryByText("first-page")).toBeNull();
    expect(screen.queryByText("stale-page")).toBeNull();
  });

  it("labels retained detail as last-known when its refresh fails", async () => {
    const digest = "sha256:" + "9".repeat(64);
    const summary = {
      proposal_digest: digest,
      offer_digest: "sha256:" + "6".repeat(64),
      offer_id: "org.nthdao.tests/detail-cache",
      offer_revision: 1,
      maker_did: "did:key:zMaker",
      taker_did: "did:key:zTaker",
      created_at: "2026-08-02T00:00:00Z",
      not_after: "2026-08-03T00:00:00Z",
      rule_bindings_count: 1,
      status: "retained-unaccepted" as const,
      audit_verified: true,
      audit_event_id: "a".repeat(64),
    };
    vi.mocked(fetchTradeProposals).mockResolvedValue({
      items: [summary],
      next_cursor: "",
    });
    vi.mocked(getTradeProposal)
      .mockResolvedValueOnce({
        ...summary,
        proposal: {
          kind: "nth.dao.trade.proposal",
          protocol_version: "1",
          offer_publisher_did: summary.maker_did,
          offer_id: summary.offer_id,
          offer_revision: summary.offer_revision,
          offer_digest: summary.offer_digest,
          canonical_chain_digests: [summary.offer_digest],
          maker_did: summary.maker_did,
          taker_did: summary.taker_did,
          rule_bindings: [{
            rule_id: "org.nthdao.rules/delivery",
            digest: "sha256:" + "4".repeat(64),
          }],
          taker_policy_digest: "sha256:" + "3".repeat(64),
          taker_policy: {},
          terms: { requested_quantity: "1" },
          created_at: summary.created_at,
          not_after: summary.not_after,
          proof: {},
        },
      })
      .mockRejectedValueOnce(new Error("detail endpoint unavailable"));

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Proposals/ }));
    expect(await screen.findByText(/requested_quantity/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    expect(await screen.findByText(/showing last known data/)).toBeTruthy();
    expect(screen.getByText(/requested_quantity/)).toBeTruthy();
  });

  it("keeps existing Market orders usable when Proposal inbox is unavailable", async () => {
    vi.mocked(fetchTradeProposals).mockRejectedValueOnce(
      new Error("signed receiver unavailable"),
    );

    render(<ToastProvider><CommerceView /></ToastProvider>);
    expect(await screen.findAllByText("Adversarial review")).not.toHaveLength(0);
    fireEvent.click(screen.getByRole("tab", { name: /Proposals/ }));

    expect(await screen.findByText(/Proposal inbox unavailable/)).toBeTruthy();
    expect(screen.getByText(/signed receiver unavailable/)).toBeTruthy();
  });

  it("clears cached Proposal data when console authorization is rejected", async () => {
    const summary = {
      proposal_digest: "sha256:" + "4".repeat(64),
      offer_digest: "sha256:" + "5".repeat(64),
      offer_id: "org.nthdao.tests/private-proposal",
      offer_revision: 1,
      maker_did: "did:key:zMaker",
      taker_did: "did:key:zTaker",
      created_at: "2026-08-02T00:00:00Z",
      not_after: "2026-08-03T00:00:00Z",
      rule_bindings_count: 1,
      status: "retained-unaccepted" as const,
      audit_verified: true,
      audit_event_id: "a".repeat(64),
    };
    vi.mocked(fetchTradeProposals)
      .mockResolvedValueOnce({ items: [summary], next_cursor: "" })
      .mockRejectedValueOnce(Object.assign(new Error("HTTP 401"), { status: 401 }));

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Proposals/ }));
    expect(await screen.findByText(summary.offer_id)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    expect(await screen.findByText(/cached data cleared/)).toBeTruthy();
    expect(screen.queryByText(summary.offer_id)).toBeNull();
    expect(screen.queryByText(/showing last known data/)).toBeNull();
  });

  it("updates Proposals even when an unrelated commerce endpoint fails", async () => {
    const summary = {
      proposal_digest: "sha256:" + "3".repeat(64),
      offer_digest: "sha256:" + "2".repeat(64),
      offer_id: "org.nthdao.tests/independent-proposal",
      offer_revision: 1,
      maker_did: "did:key:zMaker",
      taker_did: "did:key:zTaker",
      created_at: "2026-08-02T00:00:00Z",
      not_after: "2026-08-03T00:00:00Z",
      rule_bindings_count: 1,
      status: "retained-unaccepted" as const,
      audit_verified: true,
      audit_event_id: "a".repeat(64),
    };
    const api = await import("../api");
    vi.mocked(api.fetchCommerceListings).mockRejectedValueOnce(
      new Error("listing store unavailable"),
    );
    vi.mocked(fetchTradeProposals).mockResolvedValueOnce({
      items: [summary], next_cursor: "",
    });

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Proposals/ }));

    expect(await screen.findByText(summary.offer_id)).toBeTruthy();
  });
});
