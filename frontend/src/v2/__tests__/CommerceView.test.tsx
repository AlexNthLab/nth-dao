// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { TradeExecutionView } from "../types-v2";

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

function executionProjection(): TradeExecutionView {
  const packageDigest = "sha256:" + "7".repeat(64);
  return {
    order_digest: "sha256:" + "1".repeat(64),
    source_offer_digest: "sha256:" + "5".repeat(64),
    status: "blocked" as const,
    error_code: "",
    coordinator: {
      available: true,
      status: "healthy" as const,
      receipt_persistence_available: true,
      recovery_pending: false,
      error_code: "",
      execution_endpoint_enabled: false as const,
    },
    local_executor: {
      did: "did:key:zMaker",
      role: "maker" as const,
      authorized_operation_count: 1,
    },
    skills: [{
      package_digest: packageDigest,
      rule_id: "org.nthdao.rules/delivery",
      version: "1.0.0",
      publisher_did: "did:key:zPublisher",
      summary: "Signed digital delivery Skill",
      execution_mode: "declarative",
      installed: true,
      current: true,
      status: "available" as const,
      reason: "active",
    }],
    operation_grants: [{
      operation_id: "deliver-service",
      rule_id: "org.nthdao.rules/delivery",
      package_digest: packageDigest,
      hook_name: "fulfillment.deliver",
      hook_version: "1",
      executor_role: "maker" as const,
      local_executor: true,
      contract_available: true,
      input_schema_content_available: true,
      output_schema_content_available: true,
      side_effect: "none" as const,
      permissions: [],
      funds_execution_enabled: false as const,
    }],
    executor_policy: {
      configured: true,
      status: "ready" as const,
      digest: "sha256:" + "8".repeat(64),
      reason: "Current local policy revalidated the Agreement",
      readiness: {},
    },
    adapter: {
      configured: true,
      status: "selection-required" as const,
      policy_digest: "sha256:" + "9".repeat(64),
      accepted_adapter_count: 1,
    },
    content: {
      resolver_configured: true,
      contract_schema_content_available: true,
      runtime_payloads_ready: false as const,
      status: "awaiting-operation-input" as const,
    },
    funds: {
      enabled: false as const,
      grant_count: 0,
      reason: "Real-funds execution is disabled",
    },
    history: {
      status: "available" as const,
      has_more: false,
      next_cursor: null,
      error_code: "",
      items: [{
        execution_id: "nth-trade-execution-sha256:" + "a".repeat(64),
        receipt_digest: "sha256:" + "b".repeat(64),
        audit_event_id: "c".repeat(64),
        audit_seq: 42,
        executor_did: "did:key:zMaker",
        executor_role: "maker" as const,
        operation_id: "deliver-service",
        hook_name: "fulfillment.deliver",
        side_effect: "none" as const,
        adapter_id: "org.nthdao.adapter/declarative",
        adapter_version: "1.0.0",
        execution_mode: "declarative",
        outcome: "succeeded" as const,
        started_at: "2026-08-03T00:00:00Z",
        completed_at: "2026-08-03T00:01:00Z",
      }],
    },
    blocking_reasons: ["An exact approved Adapter must be selected per operation"],
    evaluated_at: "2026-08-03T00:00:00Z",
  };
}

function agreementSummary() {
  return {
    order_digest: "sha256:" + "1".repeat(64),
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
}

function tradeSkillSummary(suffix = "7") {
  return {
    package_digest: "sha256:" + suffix.repeat(64),
    rule_id: `org.nthdao.rules/delivery-${suffix}`,
    version: "1.0.0",
    publisher_did: "did:key:zPublisher",
    summary: "Signed delivery behavior",
    applies_to: ["service"],
    families: ["fulfillment"],
    published_at: "2026-08-01T00:00:00Z",
    not_after: "2026-09-01T00:00:00Z",
    execution: { mode: "declarative" as const, permissions: [] },
    required_capabilities: [],
    resource_count: 1,
    resource_bytes: 24,
    dependency_count: 0,
    conflict_count: 0,
    verification: {
      status: "verified-cache" as const,
      publisher_signature: true as const,
      resource_digests: true as const,
    },
    import_audit: {
      status: "anchored" as const,
      proposed_count: 1,
      anchored_count: 1,
      incomplete_count: 0,
    },
    provenance: {
      status: "explicit" as const,
      sources: ["federated" as const],
    },
    trust: {
      status: "not-evaluated" as const,
      advisory: true as const,
      execution_authorized: false as const,
    },
  };
}

function tradeSkillDetail(suffix = "7") {
  const summary = tradeSkillSummary(suffix);
  return {
    ...summary,
    manifest: {
      resources: [{
        purpose: "terms",
        media_type: "application/json",
        digest: "sha256:" + "8".repeat(64),
        size: 24,
      }],
      dependencies: [],
      hook_contracts: [],
    },
  };
}

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
  fetchTradeRulePackages: vi.fn().mockResolvedValue({
    items: [], next_cursor: "", cache_only: true, execution_authorized: false,
  }),
  fetchTradeRuleRecognitionImports: vi.fn().mockResolvedValue({
    order_digest: "sha256:" + "1".repeat(64),
    package_digest: "sha256:" + "7".repeat(64),
    total: 0,
    returned: 0,
    items: [],
  }),
  fetchTradeRuleRecognitionImportBatch: vi.fn().mockResolvedValue([{
    order_digest: "sha256:" + "1".repeat(64),
    package_digest: "sha256:" + "7".repeat(64),
    total: 0,
    returned: 0,
    items: [],
  }]),
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
  getTradeRulePackage: vi.fn().mockResolvedValue(null),
  getTradeExecutionReceipts: vi.fn().mockResolvedValue({
    status: "available",
    items: [],
    has_more: false,
    next_cursor: null,
    error_code: "",
  }),
  importTradeRulePackage: vi.fn().mockResolvedValue({
    status: "installed",
    installed: true,
    offer_digest: "sha256:" + "5".repeat(64),
    package_digest: "sha256:" + "7".repeat(64),
    rule_id: "org.nthdao.rules/delivery",
    version: "1.0.0",
    publisher_did: "did:key:zPublisher",
    audit_event_id: "b".repeat(64),
    audit_created: true,
    resource_count: 1,
    resource_bytes: 10,
    trust_granted: false,
    execution_authority_granted: false,
    warning: "Cached only",
  }),
  importTradeRuleRecognitions: vi.fn().mockResolvedValue({
    status: "already-observed",
    offer_digest: "sha256:" + "5".repeat(64),
    package_digest: "sha256:" + "7".repeat(64),
    proof_digest: "sha256:" + "8".repeat(64),
    observed_heads_digest: "sha256:" + "9".repeat(64),
    import_id: "a".repeat(64),
    source_origin: "http://peer.example:8080",
    import_proposal_event_id: "b".repeat(64),
    import_completion_event_id: "c".repeat(64),
    observed_statement_count: 1,
    imported_statement_count: 0,
    reconciled_anchor_count: 0,
    imported_recognition_digests: [],
    audit_event_ids: [],
    global_freshness_proven: false,
    issuer_trust_granted: false,
    local_policy_changed: false,
    execution_authority_granted: false,
    warning: "Observed evidence only",
  }),
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
  fetchTradeRulePackages,
  fetchTradeRuleRecognitionImportBatch,
  getTradeOrder,
  getTradeExecutionReceipts,
  getTradeProposal,
  getTradeRulePackage,
  importTradeRulePackage,
  importTradeRuleRecognitions,
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

beforeEach(() => {
  vi.mocked(fetchCommerceOrders).mockReset().mockResolvedValue([order]);
  vi.mocked(fetchTradeProposals).mockReset().mockResolvedValue({
    items: [], next_cursor: "",
  });
  vi.mocked(fetchTradeOrders).mockReset().mockResolvedValue({
    items: [], next_cursor: "",
  });
  vi.mocked(fetchTradeRulePackages).mockReset().mockResolvedValue({
    items: [], next_cursor: "", cache_only: true, execution_authorized: false,
  });
  vi.mocked(fetchTradeRuleRecognitionImportBatch).mockReset().mockResolvedValue([{
    order_digest: "sha256:" + "1".repeat(64),
    package_digest: "sha256:" + "7".repeat(64),
    total: 0,
    returned: 0,
    items: [],
  }]);
  vi.mocked(getTradeOrder).mockReset().mockResolvedValue(null as never);
  vi.mocked(getTradeExecutionReceipts).mockReset().mockResolvedValue({
    status: "available",
    items: [],
    has_more: false,
    next_cursor: null,
    error_code: "",
  });
  vi.mocked(getTradeProposal).mockReset().mockResolvedValue(null as never);
  vi.mocked(getTradeRulePackage).mockReset().mockResolvedValue(null as never);
  vi.mocked(importTradeRulePackage).mockReset().mockResolvedValue({
    status: "installed",
    installed: true,
    offer_digest: "sha256:" + "5".repeat(64),
    package_digest: "sha256:" + "7".repeat(64),
    rule_id: "org.nthdao.rules/delivery",
    version: "1.0.0",
    publisher_did: "did:key:zPublisher",
    audit_event_id: "b".repeat(64),
    audit_created: true,
    resource_count: 1,
    resource_bytes: 10,
    trust_granted: false,
    execution_authority_granted: false,
    warning: "Cached only",
  });
  vi.mocked(importTradeRuleRecognitions).mockReset().mockResolvedValue({
    status: "already-observed",
    offer_digest: "sha256:" + "5".repeat(64),
    package_digest: "sha256:" + "7".repeat(64),
    proof_digest: "sha256:" + "8".repeat(64),
    observed_heads_digest: "sha256:" + "9".repeat(64),
    import_id: "a".repeat(64),
    source_origin: "http://peer.example:8080",
    import_proposal_event_id: "b".repeat(64),
    import_completion_event_id: "c".repeat(64),
    observed_statement_count: 1,
    imported_statement_count: 0,
    reconciled_anchor_count: 0,
    imported_recognition_digests: [],
    audit_event_ids: [],
    global_freshness_proven: false,
    issuer_trust_granted: false,
    local_policy_changed: false,
    execution_authority_granted: false,
    warning: "Observed evidence only",
  });
  vi.mocked(acceptTradeProposal).mockReset().mockResolvedValue({
    status: "accepted-and-delivered",
    order: { order_id: "nth-trade-order-sha256:" + "f".repeat(64) },
    order_digest: "sha256:" + "f".repeat(64),
    local_audit_event_id: "a".repeat(64),
    delivery_digest: "sha256:" + "d".repeat(64),
    remote_intake_receipt: {},
    remote_intake_receipt_digest: "sha256:" + "e".repeat(64),
    remote_audit_event_id: "f".repeat(64),
    acknowledgement_persisted: true,
  });
  vi.mocked(dispatchCommerceOutbox).mockReset().mockResolvedValue([]);
  vi.mocked(listOpenTasks).mockReset().mockResolvedValue([]);
  vi.mocked(publishCommerceListing).mockReset().mockResolvedValue({
    digest: "sha256:x", listing: {}, warning: "",
  });
  vi.mocked(remoteCommerceCheckout).mockReset().mockResolvedValue({
    order, delivery: { status: "acknowledged" }, warning: "",
  });
  vi.mocked(resolveCommerceDispute).mockReset();
  vi.mocked(verifyCommerceDelivery).mockReset().mockResolvedValue({
    order: { ...order, state: "verified" }, warning: "",
  });
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  vi.restoreAllMocks();
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

  it("shows verified-cache Trade Skills without claiming trust or execution", async () => {
    const summary = tradeSkillSummary();
    const detail = tradeSkillDetail();
    vi.mocked(fetchTradeRulePackages).mockResolvedValueOnce({
      items: [summary],
      next_cursor: "",
      cache_only: true,
      execution_authorized: false,
    });
    vi.mocked(getTradeRulePackage).mockResolvedValueOnce(detail);

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Trade Skills/ }));

    expect(await screen.findByRole("heading", { name: summary.rule_id })).toBeTruthy();
    expect(screen.getByText(/do not prove the rule is fair/)).toBeTruthy();
    expect(screen.getByText("Not evaluated")).toBeTruthy();
    expect(screen.getByText("Anchored (1/1)")).toBeTruthy();
    expect(screen.getByText("Not authorized")).toBeTruthy();
    expect(screen.getByText("application/json")).toBeTruthy();
    expect(screen.queryByText(/<script>/)).toBeNull();
    expect(getTradeRulePackage).toHaveBeenCalledWith(
      summary.package_digest,
      expect.any(AbortSignal),
    );
  });

  it.each([
    ["incomplete", { status: "incomplete" as const, proposed_count: 1, anchored_count: 0, incomplete_count: 1 }, "Incomplete (0/1)"],
    ["mixed", { status: "mixed" as const, proposed_count: 2, anchored_count: 1, incomplete_count: 1 }, "Mixed (1/2)"],
  ])("warns when a Trade Skill import audit is %s", async (_case, importAudit, label) => {
    const summary = tradeSkillSummary();
    vi.mocked(fetchTradeRulePackages).mockResolvedValueOnce({
      items: [summary],
      next_cursor: "",
      cache_only: true,
      execution_authorized: false,
    });
    vi.mocked(getTradeRulePackage).mockResolvedValueOnce({
      ...tradeSkillDetail(),
      import_audit: importAudit,
    });

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Trade Skills/ }));

    expect(await screen.findByText(label)).toBeTruthy();
    expect(screen.getByText(/missing its final Spine anchor/)).toBeTruthy();
  });

  it("distinguishes explicit local provenance from an unclassified cache", async () => {
    const summary = tradeSkillSummary();
    vi.mocked(fetchTradeRulePackages).mockResolvedValueOnce({
      items: [summary],
      next_cursor: "",
      cache_only: true,
      execution_authorized: false,
    });
    vi.mocked(getTradeRulePackage).mockResolvedValueOnce({
      ...tradeSkillDetail(),
      import_audit: {
        status: "not-applicable",
        proposed_count: 0,
        anchored_count: 0,
        incomplete_count: 0,
      },
      provenance: { status: "explicit", sources: ["local"] },
    });

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Trade Skills/ }));

    expect(await screen.findByText("No signed import audit")).toBeTruthy();
    expect(screen.getByText("Local install")).toBeTruthy();
    expect(screen.queryByText(/predates persisted acquisition provenance/)).toBeNull();
  });

  it("warns for unclassified and unaudited federated provenance", async () => {
    const summary = tradeSkillSummary();
    vi.mocked(fetchTradeRulePackages)
      .mockResolvedValueOnce({
        items: [summary],
        next_cursor: "",
        cache_only: true,
        execution_authorized: false,
      })
      .mockResolvedValueOnce({
        items: [summary],
        next_cursor: "",
        cache_only: true,
        execution_authorized: false,
      });
    vi.mocked(getTradeRulePackage)
      .mockResolvedValueOnce({
        ...tradeSkillDetail(),
        import_audit: {
          status: "not-applicable",
          proposed_count: 0,
          anchored_count: 0,
          incomplete_count: 0,
        },
        provenance: { status: "unclassified", sources: [] },
      })
      .mockResolvedValueOnce({
        ...tradeSkillDetail(),
        import_audit: {
          status: "not-applicable",
          proposed_count: 0,
          anchored_count: 0,
          incomplete_count: 0,
        },
        provenance: { status: "explicit", sources: ["federated"] },
      });

    const first = render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Trade Skills/ }));
    expect(await screen.findByText(/predates persisted acquisition provenance/)).toBeTruthy();
    first.unmount();

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Trade Skills/ }));
    expect(await screen.findByText(/Federated provenance has no signed import anchor/)).toBeTruthy();
  });

  it("clears stale Trade Skill details while switching packages", async () => {
    const first = tradeSkillSummary("7");
    const second = tradeSkillSummary("9");
    let resolveSecond!: (value: ReturnType<typeof tradeSkillDetail>) => void;
    vi.mocked(fetchTradeRulePackages).mockResolvedValueOnce({
      items: [first, second],
      next_cursor: "",
      cache_only: true,
      execution_authorized: false,
    });
    vi.mocked(getTradeRulePackage)
      .mockResolvedValueOnce(tradeSkillDetail("7"))
      .mockImplementationOnce(() => new Promise((resolve) => { resolveSecond = resolve; }));

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Trade Skills/ }));
    expect(await screen.findByRole("heading", { name: first.rule_id })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: new RegExp(second.rule_id) }));
    expect(screen.queryByRole("heading", { name: first.rule_id })).toBeNull();
    expect(screen.getByText("Select a Trade Skill to inspect its signed manifest.")).toBeTruthy();
    resolveSecond(tradeSkillDetail("9"));
    expect(await screen.findByRole("heading", { name: second.rule_id })).toBeTruthy();
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
    const summary = agreementSummary();
    const digest = summary.order_digest;
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
      execution: executionProjection(),
    });

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Agreements/ }));

    expect(await screen.findByText("Bilateral acceptance")).toBeTruthy();
    expect(screen.getByText(/does not prove delivery, payment, quality, or completion/i)).toBeTruthy();
    expect(screen.getByText("Not proven")).toBeTruthy();
    expect(screen.getByText(/requested_quantity/)).toBeTruthy();
    expect(screen.getByText("Execution readiness")).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Trade Skills" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Recognition evidence" })).toBeTruthy();
    expect(screen.getAllByText("org.nthdao.rules/delivery")).toHaveLength(2);
    expect(screen.getAllByText("deliver-service")).toHaveLength(2);
    expect(screen.getByText("Execution Receipts")).toBeTruthy();
    expect(screen.getByText("Succeeded")).toBeTruthy();
    expect(screen.getByText(/CAS Receipt bytes.*signed Spine anchor/i)).toBeTruthy();
    expect(screen.getByText("Runtime health")).toBeTruthy();
    expect(screen.getByText("Healthy")).toBeTruthy();
    expect(screen.getByText("Selection Required")).toBeTruthy();
    expect(screen.getAllByText("Disabled").length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: "Execute" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Pay" })).toBeNull();
    expect(getTradeOrder).toHaveBeenCalledWith(digest, expect.any(AbortSignal));
    await waitFor(() => expect(fetchTradeRuleRecognitionImportBatch).toHaveBeenCalledWith(
      digest,
      [executionProjection().skills[0].package_digest],
      expect.any(AbortSignal),
    ));
  });

  it("shows verified Recognition evidence as an observed claim, not trust", async () => {
    const summary = agreementSummary();
    const projection = executionProjection();
    const packageDigest = projection.skills[0].package_digest;
    vi.mocked(fetchTradeOrders).mockResolvedValueOnce({ items: [summary], next_cursor: "" });
    vi.mocked(getTradeOrder).mockResolvedValueOnce({
      ...summary,
      order: { kind: "nth.dao.trade.order" },
      execution: projection,
    });
    vi.mocked(fetchTradeRuleRecognitionImportBatch).mockResolvedValueOnce([{
      order_digest: summary.order_digest,
      package_digest: packageDigest,
      total: 1,
      returned: 1,
      items: [{
        import_id: "1".repeat(64),
        status: "completed",
        proof_digest: "sha256:" + "2".repeat(64),
        observer_did: "did:key:z6Mkrd94r9yJpgZ1HEtiXs25L67fCj4bRLBpynwc6rsnTpTE",
        observed_heads_digest: "sha256:" + "3".repeat(64),
        source_origin: "http://peer.example:8080",
        statement_count: 1,
        evidence_status: "verified",
        proposal_event_id: "4".repeat(64),
        completion_event_id: "5".repeat(64),
      }],
    }]);

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Agreements/ }));

    expect(await screen.findByText("Evidence verified")).toBeTruthy();
    expect(screen.getByText(/does not prove global freshness, fairness, local trust, or execution authority/i)).toBeTruthy();
    expect(screen.getByText("Retained proof records shown: 1 of 1 / verified completions shown: 1")).toBeTruthy();
    expect(screen.queryByText(/^Trusted$/)).toBeNull();
  });

  it("loads all Recognition statuses through one bounded batch", async () => {
    const summary = agreementSummary();
    const projection = executionProjection();
    const baseSkill = projection.skills[0];
    projection.skills = Array.from({ length: 6 }, (_, index) => ({
      ...baseSkill,
      package_digest: "sha256:" + index.toString(16).repeat(64),
      rule_id: `org.nthdao.rules/delivery-${index}`,
    }));
    vi.mocked(fetchTradeOrders).mockResolvedValueOnce({ items: [summary], next_cursor: "" });
    vi.mocked(getTradeOrder).mockResolvedValueOnce({
      ...summary,
      order: { kind: "nth.dao.trade.order" },
      execution: projection,
    });
    let resolveBatch!: (
      value: Awaited<ReturnType<typeof fetchTradeRuleRecognitionImportBatch>>,
    ) => void;
    vi.mocked(fetchTradeRuleRecognitionImportBatch).mockImplementationOnce(
      () => new Promise((resolve) => { resolveBatch = resolve; }),
    );

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Agreements/ }));

    const packageDigests = projection.skills.map((skill) => skill.package_digest).sort();
    await waitFor(() => expect(fetchTradeRuleRecognitionImportBatch).toHaveBeenCalledWith(
      summary.order_digest,
      packageDigests,
      expect.any(AbortSignal),
    ));
    expect(fetchTradeRuleRecognitionImportBatch).toHaveBeenCalledTimes(1);
    resolveBatch(packageDigests.map((packageDigest) => ({
      order_digest: summary.order_digest,
      package_digest: packageDigest,
      total: 0,
      returned: 0,
      items: [],
    })));
    expect(await screen.findAllByText("Not imported")).toHaveLength(6);
  });

  it("does not call a bounded Recognition status page fully verified", async () => {
    const summary = agreementSummary();
    const projection = executionProjection();
    const packageDigest = projection.skills[0].package_digest;
    vi.mocked(fetchTradeOrders).mockResolvedValueOnce({ items: [summary], next_cursor: "" });
    vi.mocked(getTradeOrder).mockResolvedValueOnce({
      ...summary,
      order: { kind: "nth.dao.trade.order" },
      execution: projection,
    });
    vi.mocked(fetchTradeRuleRecognitionImportBatch).mockResolvedValueOnce([{
      order_digest: summary.order_digest,
      package_digest: packageDigest,
      total: 101,
      returned: 100,
      items: Array.from({ length: 100 }, (_, index) => ({
        import_id: index.toString(16).padStart(64, "0"),
        status: "completed",
        proof_digest: "sha256:" + (index + 100).toString(16).padStart(64, "0"),
        observer_did: "did:key:z6Mkrd94r9yJpgZ1HEtiXs25L67fCj4bRLBpynwc6rsnTpTE",
        observed_heads_digest: "sha256:" + "3".repeat(64),
        source_origin: "http://peer.example:8080",
        statement_count: 1,
        evidence_status: "verified",
        proposal_event_id: (index + 200).toString(16).padStart(64, "0"),
        completion_event_id: (index + 300).toString(16).padStart(64, "0"),
      })),
    }]);

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Agreements/ }));

    expect(await screen.findByText("Partial evidence")).toBeTruthy();
    expect(screen.getByText(/did not revalidate every retained proof record/)).toBeTruthy();
    expect(screen.queryByText("Evidence verified")).toBeNull();
  });

  it("fails closed when Recognition status cannot be verified", async () => {
    const summary = agreementSummary();
    vi.mocked(fetchTradeOrders).mockResolvedValueOnce({ items: [summary], next_cursor: "" });
    vi.mocked(getTradeOrder).mockResolvedValueOnce({
      ...summary,
      order: { kind: "nth.dao.trade.order" },
      execution: executionProjection(),
    });
    vi.mocked(fetchTradeRuleRecognitionImportBatch).mockRejectedValueOnce(
      new Error("Spine integrity unavailable"),
    );

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Agreements/ }));

    expect(await screen.findByText("Unavailable")).toBeTruthy();
    expect(screen.getByText(/Status could not be verified: Spine integrity unavailable/)).toBeTruthy();
    expect(screen.queryByText("Not imported")).toBeNull();
  });

  it("fetches Order-bound Recognition evidence and reloads its verified status", async () => {
    const recognitionPeer = "http://recognition.example:8080";
    const summary = {
      ...agreementSummary(),
      dispatch_target_url: "",
    };
    const projection = executionProjection();
    const packageDigest = projection.skills[0].package_digest;
    const detail = {
      ...summary,
      order: { kind: "nth.dao.trade.order" },
      execution: projection,
    };
    vi.mocked(fetchTradeOrders).mockResolvedValueOnce({ items: [summary], next_cursor: "" });
    vi.mocked(getTradeOrder)
      .mockResolvedValueOnce(detail)
      .mockResolvedValueOnce(detail);
    vi.mocked(fetchTradeRuleRecognitionImportBatch)
      .mockResolvedValueOnce([{
        order_digest: summary.order_digest,
        package_digest: packageDigest,
        total: 0,
        returned: 0,
        items: [],
      }])
      .mockResolvedValueOnce([{
        order_digest: summary.order_digest,
        package_digest: packageDigest,
        total: 1,
        returned: 1,
        items: [{
          import_id: "1".repeat(64),
          status: "completed",
          proof_digest: "sha256:" + "2".repeat(64),
          observer_did: "did:key:z6Mkrd94r9yJpgZ1HEtiXs25L67fCj4bRLBpynwc6rsnTpTE",
          observed_heads_digest: "sha256:" + "3".repeat(64),
          source_origin: recognitionPeer,
          statement_count: 1,
          evidence_status: "verified",
          proposal_event_id: "4".repeat(64),
          completion_event_id: "5".repeat(64),
        }],
      }]);
    vi.mocked(importTradeRuleRecognitions).mockResolvedValueOnce({
      status: "already-observed",
      offer_digest: summary.offer_digest,
      package_digest: packageDigest,
      proof_digest: "sha256:" + "2".repeat(64),
      observed_heads_digest: "sha256:" + "3".repeat(64),
      import_id: "1".repeat(64),
      source_origin: recognitionPeer,
      import_proposal_event_id: "4".repeat(64),
      import_completion_event_id: "5".repeat(64),
      observed_statement_count: 1,
      imported_statement_count: 0,
      reconciled_anchor_count: 0,
      imported_recognition_digests: [],
      audit_event_ids: [],
      global_freshness_proven: false,
      issuer_trust_granted: false,
      local_policy_changed: false,
      execution_authority_granted: false,
      warning: "Observed evidence only",
    });

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Agreements/ }));
    await screen.findByText("Not imported");
    const source = await screen.findByLabelText("NTH DAO source URL");
    const fetchButton = await screen.findByRole("button", { name: "Fetch signed evidence" });
    expect((source as HTMLInputElement).value).toBe("");
    expect((fetchButton as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(source, { target: { value: `  ${recognitionPeer}  ` } });
    fireEvent.blur(source);
    expect((source as HTMLInputElement).value).toBe(recognitionPeer);
    expect(window.localStorage.getItem(
      `nth-trade-skill-peer:${summary.order_digest}`,
    )).toBe(recognitionPeer);
    fireEvent.click(fetchButton);

    await waitFor(() => expect(importTradeRuleRecognitions).toHaveBeenCalledWith(
      summary.order_digest,
      packageDigest,
      recognitionPeer,
      expect.any(AbortSignal),
    ));
    expect(await screen.findByText(/no new Recognition statements were added/)).toBeTruthy();
    expect(screen.getByText("Recognition proof verified; no new statements")).toBeTruthy();
    await waitFor(() => expect(fetchTradeRuleRecognitionImportBatch).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(getTradeOrder).toHaveBeenCalledTimes(2));
    expect(await screen.findByText("Evidence verified")).toBeTruthy();
  });

  it("blocks automatic replacement of corrupt Recognition proof bytes", async () => {
    const summary = {
      ...agreementSummary(),
      dispatch_target_url: "http://peer.example:8080",
    };
    const projection = executionProjection();
    const packageDigest = projection.skills[0].package_digest;
    vi.mocked(fetchTradeOrders).mockResolvedValueOnce({ items: [summary], next_cursor: "" });
    vi.mocked(getTradeOrder).mockResolvedValueOnce({
      ...summary,
      order: { kind: "nth.dao.trade.order" },
      execution: projection,
    });
    vi.mocked(fetchTradeRuleRecognitionImportBatch).mockResolvedValueOnce([{
      order_digest: summary.order_digest,
      package_digest: packageDigest,
      total: 2,
      returned: 1,
      items: [{
        import_id: "1".repeat(64),
        status: "completed",
        proof_digest: "sha256:" + "2".repeat(64),
        observer_did: "did:key:z6Mkrd94r9yJpgZ1HEtiXs25L67fCj4bRLBpynwc6rsnTpTE",
        observed_heads_digest: "sha256:" + "3".repeat(64),
        source_origin: summary.dispatch_target_url,
        statement_count: 1,
        evidence_status: "missing-or-corrupt",
        proposal_event_id: "4".repeat(64),
        completion_event_id: "5".repeat(64),
      }],
    }]);

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Agreements/ }));

    expect(await screen.findByText("Evidence damaged")).toBeTruthy();
    expect(screen.queryByText("Partial evidence")).toBeNull();
    expect((screen.getByRole("button", {
      name: "Check for newer evidence",
    }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/repair requires the exact signed proof document/i)).toBeTruthy();
    expect(importTradeRuleRecognitions).not.toHaveBeenCalled();
  });

  it("lets the operator fetch and verify a missing Order-bound Trade Skill", async () => {
    const summary = {
      ...agreementSummary(),
      dispatch_target_url: "http://peer.example:8080",
    };
    const missing = executionProjection();
    missing.skills = [{
      ...missing.skills[0],
      installed: false,
      current: false,
      status: "missing" as const,
      reason: "Exact signed Rule Package is not installed locally",
    }];
    vi.mocked(fetchTradeOrders).mockResolvedValueOnce({
      items: [summary],
      next_cursor: "",
    });
    vi.mocked(getTradeOrder)
      .mockResolvedValueOnce({
        ...summary,
        order: { kind: "nth.dao.trade.order" },
        execution: missing,
      })
      .mockResolvedValueOnce({
        ...summary,
        order: { kind: "nth.dao.trade.order" },
        execution: executionProjection(),
      });

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Agreements/ }));
    const source = await screen.findByLabelText("NTH DAO source URL");
    expect((source as HTMLInputElement).value).toBe("http://peer.example:8080");
    fireEvent.click(screen.getByRole("button", { name: "Fetch and verify" }));

    await waitFor(() => expect(importTradeRulePackage).toHaveBeenCalledWith(
      summary.order_digest,
      missing.skills[0].package_digest,
      summary.dispatch_target_url,
      expect.any(AbortSignal),
    ));
    await waitFor(() => expect(getTradeOrder).toHaveBeenCalledTimes(2));
    expect(await screen.findByText("Trade Skill verified and cached")).toBeTruthy();
    expect(screen.getByText(/signed in Spine/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Execute" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Pay" })).toBeNull();
  });

  it("states when an existing cache entry only repaired its signed audit", async () => {
    const summary = {
      ...agreementSummary(),
      dispatch_target_url: "http://peer.example:8080",
    };
    const missing = executionProjection();
    missing.skills = [{
      ...missing.skills[0],
      installed: false,
      current: false,
      status: "unavailable" as const,
      reason: "Trade Rule Package import audit is incomplete",
    }];
    vi.mocked(fetchTradeOrders).mockResolvedValueOnce({
      items: [summary],
      next_cursor: "",
    });
    vi.mocked(getTradeOrder)
      .mockResolvedValueOnce({
        ...summary,
        order: { kind: "nth.dao.trade.order" },
        execution: missing,
      })
      .mockResolvedValueOnce({
        ...summary,
        order: { kind: "nth.dao.trade.order" },
        execution: executionProjection(),
      });
    vi.mocked(importTradeRulePackage).mockResolvedValueOnce({
      status: "already-installed",
      installed: false,
      offer_digest: "sha256:" + "5".repeat(64),
      package_digest: missing.skills[0].package_digest,
      rule_id: missing.skills[0].rule_id,
      version: "1.0.0",
      publisher_did: "did:key:z6Mkrd94r9yJpgZ1HEtiXs25L67fCj4bRLBpynwc6rsnTpTE",
      audit_event_id: "d".repeat(64),
      audit_created: true,
      resource_count: 1,
      resource_bytes: 10,
      trust_granted: false,
      execution_authority_granted: false,
      warning: "Cached only",
    });

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Agreements/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Repair signed audit" }));

    expect(await screen.findByText(/missing signed audit was repaired/)).toBeTruthy();
    expect(screen.queryByText(/cached locally and signed in Spine/)).toBeNull();
  });

  it("does not carry a Trade Skill peer URL across Agreements", async () => {
    const first = {
      ...agreementSummary(),
      dispatch_target_url: "http://first.example:8080",
    };
    const second = {
      ...agreementSummary(),
      order_digest: "sha256:" + "8".repeat(64),
      order_id: "nth:trade:order:" + "9".repeat(64),
      dispatch_target_url: "http://second.example:8080",
    };
    const missing = executionProjection();
    missing.skills = [{
      ...missing.skills[0],
      installed: false,
      current: false,
      status: "missing" as const,
      reason: "Exact signed Rule Package is not installed locally",
    }];
    vi.mocked(fetchTradeOrders).mockResolvedValueOnce({
      items: [first, second],
      next_cursor: "",
    });
    vi.mocked(getTradeOrder).mockImplementation(async (digest) => ({
      ...(digest === second.order_digest ? second : first),
      order: { kind: "nth.dao.trade.order" },
      execution: { ...missing, order_digest: digest },
    }));

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Agreements/ }));
    expect((await screen.findByLabelText("NTH DAO source URL") as HTMLInputElement).value)
      .toBe(first.dispatch_target_url);
    const rows = await screen.findAllByText("Accepted terms");
    fireEvent.click(rows[1].closest("button") as HTMLButtonElement);
    await waitFor(() => expect(
      (screen.getByLabelText("NTH DAO source URL") as HTMLInputElement).value,
    ).toBe(second.dispatch_target_url));
  });

  it("aborts a stale Trade Skill import when the Agreement changes", async () => {
    const first = {
      ...agreementSummary(),
      dispatch_target_url: "http://first.example:8080",
    };
    const second = {
      ...agreementSummary(),
      order_digest: "sha256:" + "8".repeat(64),
      order_id: "nth:trade:order:" + "9".repeat(64),
      dispatch_target_url: "http://second.example:8080",
    };
    const missing = executionProjection();
    missing.skills = [{
      ...missing.skills[0],
      installed: false,
      current: false,
      status: "missing" as const,
      reason: "Exact signed Rule Package is not installed locally",
    }];
    vi.mocked(fetchTradeOrders).mockResolvedValueOnce({
      items: [first, second],
      next_cursor: "",
    });
    vi.mocked(getTradeOrder).mockImplementation(async (digest) => ({
      ...(digest === second.order_digest ? second : first),
      order: { kind: "nth.dao.trade.order" },
      execution: { ...missing, order_digest: digest },
    }));
    let resolveImport!: (value: Awaited<ReturnType<typeof importTradeRulePackage>>) => void;
    vi.mocked(importTradeRulePackage).mockImplementationOnce(
      () => new Promise((resolve) => { resolveImport = resolve; }),
    );

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Agreements/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Fetch and verify" }));
    const signal = vi.mocked(importTradeRulePackage).mock.calls[0][3];
    const rows = await screen.findAllByText("Accepted terms");
    fireEvent.click(rows[1].closest("button") as HTMLButtonElement);
    await waitFor(() => expect(signal?.aborted).toBe(true));
    resolveImport({
      status: "installed",
      installed: true,
      offer_digest: "sha256:" + "5".repeat(64),
      package_digest: missing.skills[0].package_digest,
      rule_id: missing.skills[0].rule_id,
      version: "1.0.0",
      publisher_did: "did:key:zPublisher",
      audit_event_id: "c".repeat(64),
      audit_created: true,
      resource_count: 1,
      resource_bytes: 10,
      trust_granted: false,
      execution_authority_granted: false,
      warning: "Cached only",
    });

    await waitFor(() => expect(
      (screen.getByLabelText("NTH DAO source URL") as HTMLInputElement).value,
    ).toBe(second.dispatch_target_url));
    expect(screen.queryByText("Trade Skill verified and cached")).toBeNull();
  });

  it("does not report a verified import as failed when preference storage fails", async () => {
    const summary = {
      ...agreementSummary(),
      dispatch_target_url: "http://peer.example:8080",
    };
    const missing = executionProjection();
    missing.skills = [{
      ...missing.skills[0],
      installed: false,
      current: false,
      status: "missing" as const,
      reason: "Exact signed Rule Package is not installed locally",
    }];
    vi.mocked(fetchTradeOrders).mockResolvedValueOnce({ items: [summary], next_cursor: "" });
    vi.mocked(getTradeOrder)
      .mockResolvedValueOnce({
        ...summary,
        order: { kind: "nth.dao.trade.order" },
        execution: missing,
      })
      .mockResolvedValueOnce({
        ...summary,
        order: { kind: "nth.dao.trade.order" },
        execution: executionProjection(),
      });
    vi.spyOn(Storage.prototype, "setItem").mockImplementationOnce(() => {
      throw new DOMException("storage disabled", "SecurityError");
    });

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Agreements/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Fetch and verify" }));

    expect(await screen.findByText(/cached locally and signed in Spine/)).toBeTruthy();
    expect(screen.queryByText(/storage disabled/i)).toBeNull();
  });

  it("loads older verified execution receipts with the stable cursor", async () => {
    const summary = agreementSummary();
    const projection = executionProjection();
    projection.history.has_more = true;
    projection.history.next_cursor = 42;
    vi.mocked(fetchTradeOrders).mockResolvedValueOnce({
      items: [summary],
      next_cursor: "",
    });
    vi.mocked(getTradeOrder).mockResolvedValueOnce({
      ...summary,
      order: { kind: "nth.dao.trade.order" },
      execution: projection,
    });
    vi.mocked(getTradeExecutionReceipts).mockResolvedValueOnce({
      status: "available",
      has_more: false,
      next_cursor: null,
      error_code: "",
      items: [{
        ...projection.history.items[0],
        execution_id: "nth-trade-execution-sha256:" + "d".repeat(64),
        audit_event_id: "e".repeat(64),
        audit_seq: 17,
        operation_id: "prepare-service",
      }],
    });

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Agreements/ }));
    fireEvent.click(await screen.findByRole("button", {
      name: "Load earlier Receipts",
    }));

    await waitFor(() => expect(getTradeExecutionReceipts).toHaveBeenCalledWith(
      summary.order_digest,
      42,
    ));
    expect(await screen.findByText("prepare-service")).toBeTruthy();
    expect(screen.getAllByText("deliver-service")).toHaveLength(2);
    expect(screen.queryByRole("button", {
      name: "Load earlier Receipts",
    })).toBeNull();
  });

  it("keeps verified receipts visible when older history loading fails", async () => {
    const summary = agreementSummary();
    const projection = executionProjection();
    projection.history.has_more = true;
    projection.history.next_cursor = 42;
    vi.mocked(fetchTradeOrders).mockResolvedValueOnce({
      items: [summary],
      next_cursor: "",
    });
    vi.mocked(getTradeOrder).mockResolvedValueOnce({
      ...summary,
      order: { kind: "nth.dao.trade.order" },
      execution: projection,
    });
    vi.mocked(getTradeExecutionReceipts).mockRejectedValueOnce(
      new Error("history backend unavailable"),
    );

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Agreements/ }));
    fireEvent.click(await screen.findByRole("button", {
      name: "Load earlier Receipts",
    }));

    expect(await screen.findByText(/history backend unavailable/)).toBeTruthy();
    expect(screen.getByText(/Existing verified Receipts remain visible/)).toBeTruthy();
    expect(screen.getAllByText("deliver-service")).toHaveLength(2);
  });

  it("makes degraded execution and unverifiable history explicit", async () => {
    const summary = agreementSummary();
    const projection = executionProjection();
    vi.mocked(fetchTradeOrders).mockResolvedValueOnce({
      items: [summary],
      next_cursor: "",
    });
    vi.mocked(getTradeOrder).mockResolvedValueOnce({
      ...summary,
      order: { kind: "nth.dao.trade.order" },
      execution: {
        ...projection,
        status: "unavailable" as const,
        error_code: "projection-failed",
        coordinator: {
          ...projection.coordinator,
          status: "degraded" as const,
          receipt_persistence_available: false,
          recovery_pending: true,
          error_code: "startup-recovery-failed",
        },
        history: {
          status: "unavailable" as const,
          items: [],
          has_more: false,
          next_cursor: null,
          error_code: "receipt-history-verification-failed",
        },
      },
    });

    render(<ToastProvider><CommerceView /></ToastProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /Agreements/ }));

    expect(await screen.findByText("Degraded")).toBeTruthy();
    expect(screen.getByText(/Execution projection unavailable/)).toBeTruthy();
    expect(screen.getByText(/empty list must not be treated as proof/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Execute" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Pay" })).toBeNull();
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
