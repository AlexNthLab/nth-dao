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
  fetchCommerceListings: vi.fn().mockResolvedValue([]),
  fetchCommerceOrders: vi.fn().mockResolvedValue([order]),
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
  fetchCommerceOrders,
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
});
