import { useCallback, useEffect, useMemo, useState } from "react";

import {
  dispatchCommerceOutbox,
  disputeCommerceOrder,
  fetchCommerceListings,
  fetchCommerceOrders,
  listOpenTasks,
  publishCommerceListing,
  remoteCommerceCheckout,
  resolveCommerceDispute,
  settleCommerceOrder,
  submitCommerceDelivery,
  verifyCommerceDelivery,
} from "../api";
import type { CommerceListingRow, CommerceOrderView, TaskAnnouncement } from "../types-v2";
import { useToast } from "./Toast";

type Scope = "purchases" | "sales" | "offers";

function short(value: string, size = 18) {
  return value.length <= size ? value : `${value.slice(0, size - 5)}...${value.slice(-4)}`;
}

function formatTime(ms: number) {
  if (!ms) return "-";
  return new Date(ms).toLocaleString();
}

async function sha256Text(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
  return `sha256:${hex}`;
}

export function CommerceView() {
  const toast = useToast();
  const [scope, setScope] = useState<Scope>("purchases");
  const [listings, setListings] = useState<CommerceListingRow[]>([]);
  const [orders, setOrders] = useState<CommerceOrderView[]>([]);
  const [discovered, setDiscovered] = useState<TaskAnnouncement[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [busy, setBusy] = useState(false);
  const [showPublish, setShowPublish] = useState(false);
  const [showBuy, setShowBuy] = useState(false);
  const [peerUrl, setPeerUrl] = useState("");
  const [listingDigest, setListingDigest] = useState("");
  const [purpose, setPurpose] = useState("Purchase one digital service");
  const [title, setTitle] = useState("");
  const [listingId, setListingId] = useState("");
  const [description, setDescription] = useState("");
  const [price, setPrice] = useState("");
  const [delivery, setDelivery] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [disputeReason, setDisputeReason] = useState("");
  const [checkoutAttemptKey, setCheckoutAttemptKey] = useState("");

  const refresh = useCallback(async (signal?: AbortSignal) => {
    const [nextListings, nextOrders, marketRows] = await Promise.all([
      fetchCommerceListings(signal), fetchCommerceOrders(undefined, signal),
      listOpenTasks({ context: "commerce", listingType: "service" }, signal),
    ]);
    setListings(nextListings);
    setOrders(nextOrders);
    setDiscovered(marketRows.filter((row) => Boolean(
      row.federated && !row.federation_stale && row.source_peer
      && row.offer_digest && row.price_asset === "NTH-TEST",
    )));
    setSelectedId((current) =>
      current && nextOrders.some((row) => row.order_id === current)
        ? current
        : nextOrders[0]?.order_id ?? "",
    );
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    refresh(controller.signal).catch((error) => {
      if (!(error instanceof DOMException && error.name === "AbortError")) {
        toast.push(error instanceof Error ? error.message : String(error), "error");
      }
    });
    return () => controller.abort();
  }, [refresh, toast]);

  const visibleOrders = useMemo(() => orders.filter((order) =>
    scope === "purchases" ? order.role === "buyer" : scope === "sales" ? order.role === "seller" : false,
  ), [orders, scope]);
  const selected = orders.find((order) => order.order_id === selectedId) ?? null;

  async function run(action: () => Promise<unknown>, success: string) {
    if (busy) return;
    setBusy(true);
    try {
      const result = await action();
      await refresh();
      if (result && typeof result === "object" && "warning" in result) {
        const warning = (result as { warning?: unknown }).warning;
        if (typeof warning === "string" && warning) toast.push(warning, "warn");
      }
      if (result && typeof result === "object" && "queued" in result) {
        const queued = (result as { queued?: unknown }).queued;
        if (queued && typeof queued === "object") {
          const status = (queued as { status?: unknown }).status;
          if (status !== "acknowledged") {
            toast.push("Signed update is safe in Outbox and still awaiting peer acknowledgement.", "warn");
          }
        }
      }
      if (Array.isArray(result)) {
        const pending = result.filter((item) =>
          item && typeof item === "object" && (item as { status?: unknown }).status !== "acknowledged",
        ).length;
        if (pending > 0) {
          toast.push(`Outbox retry finished with ${pending} update(s) still pending.`, "warn");
          return;
        }
      }
      toast.push(success, "success");
    } catch (error) {
      toast.push(error instanceof Error ? error.message : String(error), "error");
    } finally {
      setBusy(false);
    }
  }

  async function publish(event: React.FormEvent) {
    event.preventDefault();
    await run(async () => {
      await publishCommerceListing({
        listingId: listingId.trim(), title: title.trim(),
        description: description.trim(), priceValue: price.trim(),
      });
      setListingId(""); setTitle(""); setDescription(""); setPrice("");
      setShowPublish(false); setScope("offers");
    }, "Signed NTH-TEST service published");
  }

  async function buy(event: React.FormEvent) {
    event.preventDefault();
    await run(async () => {
      const result = await remoteCommerceCheckout({
        targetUrl: peerUrl.trim(), listingDigest: listingDigest.trim(), purpose: purpose.trim(),
        idempotencyKey: checkoutAttemptKey,
      });
      setSelectedId(result.order.order_id);
      setTargetUrl(peerUrl.trim());
      window.localStorage.setItem(`nth-commerce-peer:${result.order.order_id}`, peerUrl.trim());
      setShowBuy(false); setScope("purchases");
      setCheckoutAttemptKey("");
      if (result.delivery.status !== "acknowledged") {
        toast.push("Order is safe in Outbox and still awaiting peer acknowledgement.", "warn");
      }
    }, "Signed order created");
  }

  useEffect(() => {
    if (!selectedId) return;
    setTargetUrl(window.localStorage.getItem(`nth-commerce-peer:${selectedId}`) ?? "");
  }, [selectedId]);

  function selectDiscovered(row: TaskAnnouncement) {
    setPeerUrl(row.source_peer ?? "");
    setListingDigest(row.offer_digest ?? "");
    setPurpose(`Purchase ${row.title}`);
    setCheckoutAttemptKey(crypto.randomUUID());
    setShowPublish(false);
    setShowBuy(true);
  }

  async function submitDelivery() {
    if (!selected || !delivery.trim()) return;
    const text = delivery.trim();
    await run(async () => {
      await submitCommerceDelivery(selected.order_id, {
        summary: text,
        artifact_digest: await sha256Text(text),
      }, targetUrl.trim());
      setDelivery("");
    }, "Signed delivery submitted");
  }

  return (
    <>
      <aside className="sidebar commerce-sidebar">
        <div className="sidebar-head">
          <span className="sidebar-title">Market</span>
        </div>
        <div className="commerce-scope" role="tablist" aria-label="Commerce views">
          {(["purchases", "sales", "offers"] as Scope[]).map((item) => (
            <button key={item} type="button" role="tab" aria-selected={scope === item}
              className={scope === item ? "active" : ""} onClick={() => setScope(item)}>
              {item === "purchases" ? "Purchases" : item === "sales" ? "Seller orders" : "My services"}
              <span>{item === "offers" ? listings.length + discovered.length : orders.filter((o) => o.role === (item === "purchases" ? "buyer" : "seller")).length}</span>
            </button>
          ))}
        </div>
        <div className="sidebar-list">
          {scope !== "offers" && visibleOrders.map((order) => (
            <button key={order.order_id} className={`sidebar-item ${selectedId === order.order_id ? "active" : ""}`}
              onClick={() => setSelectedId(order.order_id)}>
              <div className="sidebar-item-title"><span className="truncate">{order.title}</span></div>
              <div className="sidebar-item-meta"><span>{order.state}</span><span>{order.amount_minor / 1_000_000} NTH-TEST</span></div>
            </button>
          ))}
          {scope === "offers" && listings.map((row) => (
            <div key={row.digest} className="commerce-offer-row">
              <strong>{row.listing.title}</strong>
              <span>{row.listing.price_value} NTH-TEST</span>
              <code title={row.digest}>{short(row.digest, 24)}</code>
            </div>
          ))}
          {scope === "offers" && discovered.map((row) => (
            <div key={`${row.source_peer}:${row.offer_digest}`} className="commerce-offer-row commerce-federated-offer">
              <strong>{row.title}</strong>
              <span>{(row.price_minor ?? 0) / 1_000_000} NTH-TEST</span>
              <small title={row.source_peer}>Federated from {short(row.source_peer ?? "", 24)}</small>
              <button className="btn btn-secondary" type="button" onClick={() => selectDiscovered(row)}>Buy</button>
            </div>
          ))}
          {((scope === "offers" && listings.length + discovered.length === 0) || (scope !== "offers" && visibleOrders.length === 0)) &&
            <p className="muted" style={{ padding: "12px 14px" }}>Nothing here yet.</p>}
        </div>
      </aside>

      <section className="main">
        <div className="main-head commerce-head">
          <div>
            <p className="main-eyebrow">A2A Commerce</p>
            <h1 className="main-title">Digital services</h1>
            <p className="main-subtitle">Signed orders, verifiable delivery, and manual NTH-TEST settlement. No real funds.</p>
          </div>
          <div className="commerce-head-actions">
            <button className="btn btn-secondary" onClick={() => {
              setShowBuy((value) => {
                if (!value) setCheckoutAttemptKey(crypto.randomUUID());
                return !value;
              });
            }}>Buy from peer</button>
            <button className="btn btn-primary" onClick={() => setShowPublish((value) => !value)}>Publish service</button>
          </div>
        </div>
        <div className="main-body commerce-main">
          {showPublish && <form className="commerce-form" onSubmit={publish}>
            <h2>Publish a signed service</h2>
            <div className="commerce-form-grid">
              <label>Service ID<input value={listingId} onChange={(e) => setListingId(e.target.value)} required maxLength={128} /></label>
              <label>Title<input value={title} onChange={(e) => setTitle(e.target.value)} required maxLength={200} /></label>
              <label>Price in NTH-TEST<input value={price} onChange={(e) => setPrice(e.target.value)} required inputMode="decimal" /></label>
              <label className="wide">Description<textarea value={description} onChange={(e) => setDescription(e.target.value)} maxLength={4000} /></label>
            </div>
            <div className="commerce-form-actions"><button type="button" className="btn btn-secondary" onClick={() => setShowPublish(false)}>Cancel</button><button className="btn btn-primary" disabled={busy}>Publish</button></div>
          </form>}

          {showBuy && <form className="commerce-form" onSubmit={buy}>
            <h2>Buy from a configured DAO peer</h2>
            <p className="muted">The node verifies the seller Listing and Cart before creating one idempotent order.</p>
            <div className="commerce-form-grid">
              <label>Peer URL<input type="url" value={peerUrl} onChange={(e) => setPeerUrl(e.target.value)} placeholder="https://seller.example" required /></label>
              <label>Listing digest<input value={listingDigest} onChange={(e) => setListingDigest(e.target.value)} placeholder="sha256:..." required /></label>
              <label className="wide">Purpose<input value={purpose} onChange={(e) => setPurpose(e.target.value)} required /></label>
            </div>
            <div className="commerce-form-actions"><button type="button" className="btn btn-secondary" onClick={() => { setShowBuy(false); setCheckoutAttemptKey(""); }}>Cancel</button><button className="btn btn-primary" disabled={busy || !checkoutAttemptKey}>Verify and order</button></div>
          </form>}

          {!showPublish && !showBuy && scope === "offers" && <div className="main-empty">
            <p>Your signed service catalog is shown on the left.</p>
            <p className="muted">Its discovery summaries federate through the existing Tasks network.</p>
          </div>}
          {!showPublish && !showBuy && scope !== "offers" && !selected && <div className="main-empty"><p>Select an order or create a purchase.</p></div>}
          {!showPublish && !showBuy && scope !== "offers" && selected && <OrderWorkbench order={selected} busy={busy}
            targetUrl={targetUrl} setTargetUrl={(value) => {
              setTargetUrl(value);
              window.localStorage.setItem(`nth-commerce-peer:${selected.order_id}`, value);
            }} delivery={delivery} setDelivery={setDelivery}
            disputeReason={disputeReason} setDisputeReason={setDisputeReason}
            onDeliver={submitDelivery}
            onVerify={(verdict) => run(() => verifyCommerceDelivery(selected.order_id, verdict, { reviewed: true }, targetUrl.trim()), verdict === "pass" ? "Delivery accepted" : "Delivery rejected")}
            onSettle={() => run(() => settleCommerceOrder(selected.order_id, targetUrl.trim()), "Manual NTH-TEST settlement recorded")}
            onDispute={() => run(() => disputeCommerceOrder(selected.order_id, disputeReason.trim(), targetUrl.trim()), "Dispute opened")}
            onResolve={(resolution) => run(() => resolveCommerceDispute(selected.order_id, resolution, targetUrl.trim()), resolution === "settle" ? "Dispute settled for seller" : "Dispute refunded")}
            onRetry={() => run(() => dispatchCommerceOutbox(), "Outbox retry completed")}
          />}
        </div>
      </section>

      <aside className="detail">
        <div className="detail-head"><span className="detail-title">Order audit</span></div>
        <div className="detail-body">
          {selected ? <>
            <div className="detail-section">
              <div className="detail-section-label">Identity</div>
              <div className="detail-row"><span className="key">Order</span><code className="value" title={selected.order_id}>{short(selected.order_id, 22)}</code></div>
              <div className="detail-row"><span className="key">Role</span><span className="value">{selected.role}</span></div>
              <div className="detail-row"><span className="key">Binding</span><span className="value">{selected.binding}</span></div>
              <div className="detail-row"><span className="key">Rail</span><span className="value">manual / NTH-TEST</span></div>
            </div>
            <div className="detail-section"><div className="detail-section-label">Signed timeline</div>
              <ol className="commerce-timeline">{selected.events.map((event) => <li key={event.receipt_id}><strong>{event.type}</strong><span>{event.state} - {formatTime(event.created_at_ms)}</span><code title={event.receipt_id}>{short(event.receipt_id, 24)}</code></li>)}</ol>
            </div>
          </> : <p className="muted">Select an order to inspect signed receipts.</p>}
        </div>
      </aside>
    </>
  );
}

function OrderWorkbench(props: {
  order: CommerceOrderView; busy: boolean; targetUrl: string; setTargetUrl: (value: string) => void;
  delivery: string; setDelivery: (value: string) => void; disputeReason: string; setDisputeReason: (value: string) => void;
  onDeliver: () => void; onVerify: (verdict: "pass" | "fail") => void; onSettle: () => void; onDispute: () => void; onRetry: () => void;
  onResolve: (resolution: "settle" | "refund") => void;
}) {
  const { order } = props;
  const delivery = [...order.events].reverse().find(
    (event) => event.type === "delivery_submitted",
  )?.details?.delivery;
  const deliveryObject = delivery !== null && typeof delivery === "object"
    ? delivery as Record<string, unknown>
    : null;
  return <div className="commerce-workbench">
    <div className="commerce-order-heading"><div><p className="main-eyebrow">{order.role === "buyer" ? "Purchase" : "Seller order"}</p><h2>{order.title}</h2></div><span className={`pill ${order.state === "settled" ? "ok" : "wait"}`}>{order.state}</span></div>
    <dl className="commerce-facts"><div><dt>Amount</dt><dd>{order.amount_minor / 1_000_000} NTH-TEST</dd></div><div><dt>Counterparty</dt><dd><code>{short(order.role === "buyer" ? order.seller_did : order.buyer_did, 28)}</code></dd></div><div><dt>Created</dt><dd>{formatTime(order.created_at_ms)}</dd></div></dl>
    <label className="commerce-target">Peer URL for this response (optional)<input type="url" value={props.targetUrl} onChange={(e) => props.setTargetUrl(e.target.value)} placeholder="Configured federation peer URL" /></label>
    {deliveryObject && <div className="commerce-action commerce-delivery-claim"><h3>Signed delivery claim</h3><p className="muted">The signature proves who submitted these bytes and that they were not changed. It does not prove the work is correct.</p><pre>{JSON.stringify(deliveryObject, null, 2)}</pre></div>}
    {order.role === "seller" && order.state === "executing" && <div className="commerce-action"><h3>Submit delivery</h3><textarea value={props.delivery} onChange={(e) => props.setDelivery(e.target.value)} placeholder="Result summary or artifact content" /><button className="btn btn-primary" disabled={props.busy || !props.delivery.trim()} onClick={props.onDeliver}>Sign delivery</button></div>}
    {order.role === "buyer" && order.state === "delivered" && <div className="commerce-action"><h3>Review delivery</h3><div className="commerce-form-actions"><button className="btn btn-secondary" disabled={props.busy} onClick={() => props.onVerify("fail")}>Reject</button><button className="btn btn-primary" disabled={props.busy} onClick={() => props.onVerify("pass")}>Accept</button></div></div>}
    {order.role === "buyer" && order.state === "verified" && <div className="commerce-action"><h3>Record settlement</h3><p className="muted">This records a signed manual receipt. It moves no money.</p><button className="btn btn-primary" disabled={props.busy} onClick={props.onSettle}>Settle with NTH-TEST</button></div>}
    {order.role === "buyer" && order.state === "disputed" && <div className="commerce-action"><h3>Resolve dispute</h3><p className="muted">Both outcomes are signed manual NTH-TEST records and move no funds.</p><div className="commerce-form-actions"><button className="btn btn-secondary" disabled={props.busy} onClick={() => props.onResolve("refund")}>Refund buyer</button><button className="btn btn-primary" disabled={props.busy} onClick={() => props.onResolve("settle")}>Pay seller</button></div></div>}
    {["delivered", "verified", "failed"].includes(order.state) && <div className="commerce-action"><h3>Open dispute</h3><input value={props.disputeReason} onChange={(e) => props.setDisputeReason(e.target.value)} placeholder="Reason" /><button className="btn btn-secondary" disabled={props.busy || !props.disputeReason.trim()} onClick={props.onDispute}>Sign dispute</button></div>}
    <button className="btn btn-secondary" disabled={props.busy} onClick={props.onRetry}>Retry pending Outbox</button>
  </div>;
}
