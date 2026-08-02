import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  acceptTradeProposal,
  ApiHttpError,
  dispatchCommerceOutbox,
  disputeCommerceOrder,
  fetchCommerceListings,
  fetchCommerceOrders,
  fetchTradeProposals,
  fetchTradeOrders,
  getTradeOrder,
  getTradeProposal,
  listOpenTasks,
  publishCommerceListing,
  remoteCommerceCheckout,
  resolveCommerceDispute,
  settleCommerceOrder,
  submitCommerceDelivery,
  verifyCommerceDelivery,
} from "../api";
import type {
  CommerceListingRow,
  CommerceOrderView,
  TaskAnnouncement,
  TradeProposalDetail,
  TradeProposalSummary,
  TradeOrderDetail,
  TradeOrderSummary,
} from "../types-v2";
import { useToast } from "./Toast";

type Scope = "purchases" | "sales" | "offers" | "proposals" | "agreements";

function short(value: string, size = 18) {
  return value.length <= size ? value : `${value.slice(0, size - 5)}...${value.slice(-4)}`;
}

function formatTime(ms: number) {
  if (!ms) return "-";
  return new Date(ms).toLocaleString();
}

function httpStatus(error: unknown): number | undefined {
  if (error instanceof ApiHttpError) return error.status;
  if (error && typeof error === "object" && "status" in error) {
    const status = (error as { status?: unknown }).status;
    return typeof status === "number" ? status : undefined;
  }
  return undefined;
}

function isAbort(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
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
  const [proposals, setProposals] = useState<TradeProposalSummary[]>([]);
  const [proposalNextCursor, setProposalNextCursor] = useState("");
  const [proposalPageBusy, setProposalPageBusy] = useState(false);
  const [proposalDetailVersion, setProposalDetailVersion] = useState(0);
  const refreshSequence = useRef(0);
  const [proposalError, setProposalError] = useState("");
  const [proposalDataPreserved, setProposalDataPreserved] = useState(false);
  const [selectedProposalDigest, setSelectedProposalDigest] = useState("");
  const [selectedProposal, setSelectedProposal] = useState<TradeProposalDetail | null>(null);
  const [proposalTargetUrl, setProposalTargetUrl] = useState("");
  const [agreements, setAgreements] = useState<TradeOrderSummary[]>([]);
  const [agreementNextCursor, setAgreementNextCursor] = useState("");
  const [agreementPageBusy, setAgreementPageBusy] = useState(false);
  const [agreementDetailVersion, setAgreementDetailVersion] = useState(0);
  const [agreementError, setAgreementError] = useState("");
  const [agreementDataPreserved, setAgreementDataPreserved] = useState(false);
  const [selectedAgreementDigest, setSelectedAgreementDigest] = useState("");
  const [selectedAgreement, setSelectedAgreement] = useState<TradeOrderDetail | null>(null);
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
    const sequence = ++refreshSequence.current;
    const [listingResult, orderResult, marketResult, proposalResult, agreementResult] = await Promise.allSettled([
      fetchCommerceListings(signal), fetchCommerceOrders(undefined, signal),
      listOpenTasks({ context: "commerce", listingType: "service" }, signal),
      fetchTradeProposals("", signal),
      fetchTradeOrders("", signal),
    ]);
    if (signal?.aborted || sequence !== refreshSequence.current) return;
    if (listingResult.status === "fulfilled") setListings(listingResult.value);
    if (orderResult.status === "fulfilled") {
      const nextOrders = orderResult.value;
      setOrders(nextOrders);
      setSelectedId((current) =>
        current && nextOrders.some((row) => row.order_id === current)
          ? current
          : nextOrders[0]?.order_id ?? "",
      );
    }
    if (marketResult.status === "fulfilled") {
      setDiscovered(marketResult.value.filter((row) => Boolean(
        row.federated && !row.federation_stale && row.source_peer
        && row.offer_digest && row.price_asset === "NTH-TEST",
      )));
    }
    for (const result of [listingResult, orderResult, marketResult]) {
      if (result.status === "rejected" && !isAbort(result.reason)) {
        toast.push(
          result.reason instanceof Error ? result.reason.message : String(result.reason),
          "error",
        );
      }
    }
    if (proposalResult.status === "fulfilled") {
      const nextProposals = proposalResult.value.items;
      setProposalError("");
      setProposalDataPreserved(false);
      setProposals(nextProposals);
      setProposalNextCursor(proposalResult.value.next_cursor);
      setSelectedProposalDigest((current) =>
        current && nextProposals.some((row) => row.proposal_digest === current)
          ? current
          : nextProposals[0]?.proposal_digest ?? "",
      );
    } else if (!isAbort(proposalResult.reason)) {
      const error = proposalResult.reason;
      setProposalError(error instanceof Error ? error.message : String(error));
      if ([401, 403].includes(httpStatus(error) ?? 0)) {
        setProposalDataPreserved(false);
        setProposals([]);
        setProposalNextCursor("");
        setSelectedProposalDigest("");
        setSelectedProposal(null);
      } else {
        setProposalDataPreserved(true);
      }
    }
    if (agreementResult.status === "fulfilled") {
      const nextAgreements = agreementResult.value.items;
      setAgreementError("");
      setAgreementDataPreserved(false);
      setAgreements(nextAgreements);
      setAgreementNextCursor(agreementResult.value.next_cursor);
      setSelectedAgreementDigest((current) =>
        current && nextAgreements.some((row) => row.order_digest === current)
          ? current
          : nextAgreements[0]?.order_digest ?? "",
      );
    } else if (!isAbort(agreementResult.reason)) {
      const error = agreementResult.reason;
      setAgreementError(error instanceof Error ? error.message : String(error));
      if ([401, 403].includes(httpStatus(error) ?? 0)) {
        setAgreementDataPreserved(false);
        setAgreements([]);
        setAgreementNextCursor("");
        setSelectedAgreementDigest("");
        setSelectedAgreement(null);
      } else {
        setAgreementDataPreserved(true);
      }
    }
  }, [toast]);

  const loadMoreProposals = useCallback(async () => {
    if (!proposalNextCursor || proposalPageBusy) return;
    const sequence = refreshSequence.current;
    setProposalPageBusy(true);
    try {
      const page = await fetchTradeProposals(proposalNextCursor);
      if (sequence !== refreshSequence.current) return;
      setProposals((current) => {
        const known = new Set(current.map((item) => item.proposal_digest));
        return current.concat(
          page.items.filter((item) => !known.has(item.proposal_digest)),
        );
      });
      setProposalNextCursor(page.next_cursor);
    } catch (error) {
      if (sequence !== refreshSequence.current) return;
      setProposalError(error instanceof Error ? error.message : String(error));
      if ([401, 403].includes(httpStatus(error) ?? 0)) {
        setProposalDataPreserved(false);
        setProposals([]);
        setProposalNextCursor("");
        setSelectedProposalDigest("");
        setSelectedProposal(null);
      } else {
        setProposalDataPreserved(true);
      }
      toast.push(error instanceof Error ? error.message : String(error), "error");
    } finally {
      setProposalPageBusy(false);
    }
  }, [proposalNextCursor, proposalPageBusy, toast]);

  const loadMoreAgreements = useCallback(async () => {
    if (!agreementNextCursor || agreementPageBusy) return;
    const sequence = refreshSequence.current;
    setAgreementPageBusy(true);
    try {
      const page = await fetchTradeOrders(agreementNextCursor);
      if (sequence !== refreshSequence.current) return;
      setAgreements((current) => {
        const known = new Set(current.map((item) => item.order_digest));
        return current.concat(
          page.items.filter((item) => !known.has(item.order_digest)),
        );
      });
      setAgreementNextCursor(page.next_cursor);
    } catch (error) {
      if (sequence !== refreshSequence.current) return;
      setAgreementError(error instanceof Error ? error.message : String(error));
      if ([401, 403].includes(httpStatus(error) ?? 0)) {
        setAgreementDataPreserved(false);
        setAgreements([]);
        setAgreementNextCursor("");
        setSelectedAgreementDigest("");
        setSelectedAgreement(null);
      } else {
        setAgreementDataPreserved(true);
      }
      toast.push(error instanceof Error ? error.message : String(error), "error");
    } finally {
      setAgreementPageBusy(false);
    }
  }, [agreementNextCursor, agreementPageBusy, toast]);

  useEffect(() => {
    const controller = new AbortController();
    refresh(controller.signal).catch((error) => {
      if (!(error instanceof DOMException && error.name === "AbortError")) {
        toast.push(error instanceof Error ? error.message : String(error), "error");
      }
    });
    return () => controller.abort();
  }, [refresh, toast]);

  useEffect(() => {
    if (scope !== "proposals" || !selectedProposalDigest) {
      if (!selectedProposalDigest) setSelectedProposal(null);
      return;
    }
    const controller = new AbortController();
    let active = true;
    getTradeProposal(selectedProposalDigest, controller.signal)
      .then((value) => {
        if (active) setSelectedProposal(value);
      })
      .catch((error) => {
        if (active && !isAbort(error)) {
          if ([401, 403].includes(httpStatus(error) ?? 0)) {
            setProposals([]);
            setProposalNextCursor("");
            setSelectedProposalDigest("");
            setSelectedProposal(null);
            setProposalDataPreserved(false);
            setProposalError(
              error instanceof Error ? error.message : String(error),
            );
          } else {
            setProposalDataPreserved(true);
            setProposalError(
              error instanceof Error ? error.message : String(error),
            );
          }
          toast.push(error instanceof Error ? error.message : String(error), "error");
        }
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [scope, selectedProposalDigest, proposalDetailVersion, toast]);

  useEffect(() => {
    if (!selectedProposalDigest) {
      setProposalTargetUrl("");
      return;
    }
    setProposalTargetUrl(
      window.localStorage.getItem(
        `nth-trade-proposal-peer:${selectedProposalDigest}`,
      ) ?? "",
    );
  }, [selectedProposalDigest]);

  useEffect(() => {
    if (scope !== "agreements" || !selectedAgreementDigest) {
      if (!selectedAgreementDigest) setSelectedAgreement(null);
      return;
    }
    const controller = new AbortController();
    let active = true;
    getTradeOrder(selectedAgreementDigest, controller.signal)
      .then((value) => {
        if (active) setSelectedAgreement(value);
      })
      .catch((error) => {
        if (active && !isAbort(error)) {
          if ([401, 403].includes(httpStatus(error) ?? 0)) {
            setAgreements([]);
            setAgreementNextCursor("");
            setSelectedAgreementDigest("");
            setSelectedAgreement(null);
            setAgreementDataPreserved(false);
          } else {
            setAgreementDataPreserved(true);
          }
          setAgreementError(error instanceof Error ? error.message : String(error));
          toast.push(error instanceof Error ? error.message : String(error), "error");
        }
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [scope, selectedAgreementDigest, agreementDetailVersion, toast]);

  const visibleOrders = useMemo(() => orders.filter((order) =>
    scope === "purchases" ? order.role === "buyer" : scope === "sales" ? order.role === "seller" : false,
  ), [orders, scope]);
  const selected = orders.find((order) => order.order_id === selectedId) ?? null;
  const isProtocolInbox = scope === "proposals" || scope === "agreements";

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

  async function acceptSelectedProposal() {
    if (!selectedProposal || !proposalTargetUrl.trim()) return;
    const target = proposalTargetUrl.trim();
    window.localStorage.setItem(
      `nth-trade-proposal-peer:${selectedProposal.proposal_digest}`,
      target,
    );
    await run(async () => {
      const result = await acceptTradeProposal(
        selectedProposal.proposal_digest,
        target,
      );
      setSelectedAgreementDigest(result.order_digest);
      setScope("agreements");
      return result;
    }, "Signed agreement delivered and acknowledged");
  }

  async function retrySelectedAgreementDispatch() {
    if (!selectedAgreement?.dispatch_target_url) return;
    const target = selectedAgreement.dispatch_target_url;
    await run(async () => {
      const result = await acceptTradeProposal(
        selectedAgreement.proposal_digest,
        target,
      );
      setAgreementDetailVersion((value) => value + 1);
      return result;
    }, "Signed agreement delivered and acknowledged");
  }

  return (
    <>
      <aside className="sidebar commerce-sidebar">
        <div className="sidebar-head">
          <span className="sidebar-title">Market</span>
        </div>
        <div className="commerce-scope" role="tablist" aria-label="Commerce views">
          {(["purchases", "sales", "offers", "proposals", "agreements"] as Scope[]).map((item) => (
            <button key={item} type="button" role="tab" aria-selected={scope === item}
              className={scope === item ? "active" : ""} onClick={() => setScope(item)}>
              {item === "purchases" ? "Purchases" : item === "sales" ? "Seller orders" : item === "offers" ? "My services" : item === "proposals" ? "Proposals" : "Agreements"}
              <span>{item === "offers" ? listings.length + discovered.length : item === "proposals" ? proposals.length : item === "agreements" ? agreements.length : orders.filter((o) => o.role === (item === "purchases" ? "buyer" : "seller")).length}</span>
            </button>
          ))}
        </div>
        <div className="sidebar-list">
          {(scope === "purchases" || scope === "sales") && visibleOrders.map((order) => (
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
          {scope === "proposals" && proposals.map((proposal) => (
            <button key={proposal.proposal_digest} className={`sidebar-item ${selectedProposalDigest === proposal.proposal_digest ? "active" : ""}`}
              onClick={() => { setSelectedProposal(null); setSelectedProposalDigest(proposal.proposal_digest); }}>
              <div className="sidebar-item-title"><span className="truncate">{proposal.offer_id}</span></div>
              <div className="sidebar-item-meta"><span>Pending review</span><span>{proposal.audit_verified ? "Audited" : "Audit missing"}</span></div>
            </button>
          ))}
          {scope === "proposals" && proposalNextCursor && (
            <button
              className="btn btn-secondary commerce-load-more"
              type="button"
              disabled={proposalPageBusy}
              onClick={loadMoreProposals}
            >{proposalPageBusy ? "Loading..." : "Load more"}</button>
          )}
          {scope === "agreements" && agreements.map((agreement) => (
            <button key={agreement.order_digest} className={`sidebar-item ${selectedAgreementDigest === agreement.order_digest ? "active" : ""}`}
              onClick={() => { setSelectedAgreement(null); setSelectedAgreementDigest(agreement.order_digest); }}>
              <div className="sidebar-item-title"><span className="truncate">{short(agreement.order_id, 32)}</span></div>
              <div className="sidebar-item-meta"><span>Accepted terms</span><span>{agreement.audit_status}</span></div>
            </button>
          ))}
          {scope === "agreements" && agreementNextCursor && (
            <button className="btn btn-secondary commerce-load-more" type="button"
              disabled={agreementPageBusy} onClick={loadMoreAgreements}>
              {agreementPageBusy ? "Loading..." : "Load more"}
            </button>
          )}
          {((scope === "offers" && listings.length + discovered.length === 0) || (scope === "proposals" && proposals.length === 0) || (scope === "agreements" && agreements.length === 0) || (!(["offers", "proposals", "agreements"] as Scope[]).includes(scope) && visibleOrders.length === 0)) &&
            <p className="muted" style={{ padding: "12px 14px" }}>Nothing here yet.</p>}
        </div>
      </aside>

      <section className="main">
        <div className="main-head commerce-head">
          <div>
            <p className="main-eyebrow">A2A Commerce</p>
            <h1 className="main-title">{scope === "proposals" ? "Trade proposals" : scope === "agreements" ? "Accepted agreements" : "Digital services"}</h1>
            <p className="main-subtitle">{scope === "proposals" ? "Signed inbound negotiation claims awaiting independent review." : scope === "agreements" ? "Bilateral signed terms retained by this DAO. Delivery and payment remain separate." : "Signed orders, verifiable delivery, and manual NTH-TEST settlement. No real funds."}</p>
          </div>
          {!isProtocolInbox && <div className="commerce-head-actions">
            <button className="btn btn-secondary" onClick={() => {
              setShowBuy((value) => {
                if (!value) setCheckoutAttemptKey(crypto.randomUUID());
                return !value;
              });
            }}>Buy from peer</button>
            <button className="btn btn-primary" onClick={() => setShowPublish((value) => !value)}>Publish service</button>
          </div>}
          {isProtocolInbox && <div className="commerce-head-actions">
            <button className="btn btn-secondary" type="button" onClick={() => {
              refresh()
                .then(() => {
                  setProposalDetailVersion((value) => value + 1);
                  setAgreementDetailVersion((value) => value + 1);
                })
                .catch((error) => {
                  toast.push(error instanceof Error ? error.message : String(error), "error");
                });
            }}>Refresh</button>
          </div>}
        </div>
        <div className="main-body commerce-main">
          {!isProtocolInbox && showPublish && <form className="commerce-form" onSubmit={publish}>
            <h2>Publish a signed service</h2>
            <div className="commerce-form-grid">
              <label>Service ID<input value={listingId} onChange={(e) => setListingId(e.target.value)} required maxLength={128} /></label>
              <label>Title<input value={title} onChange={(e) => setTitle(e.target.value)} required maxLength={200} /></label>
              <label>Price in NTH-TEST<input value={price} onChange={(e) => setPrice(e.target.value)} required inputMode="decimal" /></label>
              <label className="wide">Description<textarea value={description} onChange={(e) => setDescription(e.target.value)} maxLength={4000} /></label>
            </div>
            <div className="commerce-form-actions"><button type="button" className="btn btn-secondary" onClick={() => setShowPublish(false)}>Cancel</button><button className="btn btn-primary" disabled={busy}>Publish</button></div>
          </form>}

          {!isProtocolInbox && showBuy && <form className="commerce-form" onSubmit={buy}>
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
          {scope === "proposals" && !selectedProposal && <div className="main-empty"><p>Select a signed Proposal to inspect its claims.</p></div>}
          {scope === "proposals" && proposalError && <p className="trade-proposal-warning" role="status">{proposalDataPreserved ? "Proposal inbox unavailable; showing last known data" : "Proposal authorization failed; cached data cleared"}: {proposalError}</p>}
          {scope === "proposals" && selectedProposal && <ProposalWorkbench
            proposal={selectedProposal}
            busy={busy}
            targetUrl={proposalTargetUrl}
            setTargetUrl={setProposalTargetUrl}
            onAccept={acceptSelectedProposal}
          />}
          {scope === "agreements" && !selectedAgreement && <div className="main-empty"><p>Select an accepted agreement to inspect its signed snapshot.</p></div>}
          {scope === "agreements" && agreementError && <p className="trade-proposal-warning" role="status">{agreementDataPreserved ? "Agreement store unavailable; showing last known data" : "Agreement authorization failed; cached data cleared"}: {agreementError}</p>}
          {scope === "agreements" && selectedAgreement && <AgreementWorkbench
            agreement={selectedAgreement}
            busy={busy}
            onRetryDispatch={retrySelectedAgreementDispatch}
          />}
          {!showPublish && !showBuy && !(["offers", "proposals", "agreements"] as Scope[]).includes(scope) && !selected && <div className="main-empty"><p>Select an order or create a purchase.</p></div>}
          {!showPublish && !showBuy && !(["offers", "proposals", "agreements"] as Scope[]).includes(scope) && selected && <OrderWorkbench order={selected} busy={busy}
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
        <div className="detail-head"><span className="detail-title">{scope === "proposals" ? "Proposal audit" : scope === "agreements" ? "Agreement audit" : "Order audit"}</span></div>
        <div className="detail-body">
          {scope === "proposals" ? (selectedProposal ? <>
            <div className="detail-section">
              <div className="detail-section-label">Signed claim</div>
              <div className="detail-row"><span className="key">Signer</span><code className="value" title={selectedProposal.taker_did}>{short(selectedProposal.taker_did, 24)}</code></div>
              <div className="detail-row"><span className="key">Status</span><span className="value">Pending review</span></div>
              <div className="detail-row"><span className="key">Spine</span><span className="value">{selectedProposal.audit_verified ? "Verified" : "Missing"}</span></div>
              <div className="detail-row"><span className="key">Rules</span><span className="value">{selectedProposal.rule_bindings_count}</span></div>
            </div>
          </> : <p className="muted">Select a Proposal to inspect signer and audit status.</p>) : scope === "agreements" ? (selectedAgreement ? <>
            <div className="detail-section">
              <div className="detail-section-label">Signed agreement</div>
              <div className="detail-row"><span className="key">Maker</span><code className="value" title={selectedAgreement.maker_did}>{short(selectedAgreement.maker_did, 24)}</code></div>
              <div className="detail-row"><span className="key">Taker</span><code className="value" title={selectedAgreement.taker_did}>{short(selectedAgreement.taker_did, 24)}</code></div>
              <div className="detail-row"><span className="key">Audit</span><span className="value">{selectedAgreement.audit_status}</span></div>
              <div className="detail-row"><span className="key">Fulfilment</span><span className="value">Not proven</span></div>
            </div>
          </> : <p className="muted">Select an agreement to inspect parties and audit status.</p>) : selected ? <>
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

function ProposalWorkbench({
  proposal,
  busy,
  targetUrl,
  setTargetUrl,
  onAccept,
}: {
  proposal: TradeProposalDetail;
  busy: boolean;
  targetUrl: string;
  setTargetUrl: (value: string) => void;
  onAccept: () => void;
}) {
  return <div className="commerce-workbench trade-proposal-workbench">
    <div className="commerce-order-heading">
      <div><p className="main-eyebrow">Inbound negotiation</p><h2>{proposal.offer_id}</h2></div>
      <span className="pill wait">Pending review</span>
    </div>
    <p className="trade-proposal-warning">A valid signature proves who made this claim and that its bytes were retained unchanged. It is not acceptance and does not prove the terms are correct or safe.</p>
    <dl className="commerce-facts">
      <div><dt>Proposer</dt><dd><code title={proposal.taker_did}>{short(proposal.taker_did, 28)}</code></dd></div>
      <div><dt>Offer revision</dt><dd>{proposal.offer_revision}</dd></div>
      <div><dt>Expires</dt><dd>{new Date(proposal.not_after).toLocaleString()}</dd></div>
    </dl>
    <div className="commerce-action">
      <h3>Signed terms</h3>
      <pre>{JSON.stringify(proposal.proposal.terms, null, 2)}</pre>
    </div>
    <div className="commerce-action">
      <h3>Rule bindings</h3>
      <ul className="trade-proposal-rules">
        {proposal.proposal.rule_bindings.map((binding) => <li key={`${binding.rule_id}:${binding.digest}`}><strong>{binding.rule_id}</strong><code title={binding.digest}>{short(binding.digest, 28)}</code></li>)}
      </ul>
    </div>
    <div className="commerce-action">
      <h3>Accept and return agreement</h3>
      <p className="muted">The node replays current Offer and Rule state, signs the Acceptance locally, retains the Order, and requires a signed receipt from the taker.</p>
      <label className="commerce-target">Taker NTH DAO URL<input type="url" value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} placeholder="http://peer-host:8080" /></label>
      <button className="btn btn-primary" disabled={busy || !targetUrl.trim() || !proposal.audit_verified} onClick={onAccept}>Accept and send</button>
    </div>
  </div>;
}

function AgreementWorkbench({
  agreement,
  busy,
  onRetryDispatch,
}: {
  agreement: TradeOrderDetail;
  busy: boolean;
  onRetryDispatch: () => void;
}) {
  return <div className="commerce-workbench trade-proposal-workbench">
    <div className="commerce-order-heading">
      <div><p className="main-eyebrow">Bilateral acceptance</p><h2>{short(agreement.order_id, 48)}</h2></div>
      <span className={`pill ${agreement.audit_status === "anchored" ? "ok" : "wait"}`}>{agreement.audit_status}</span>
    </div>
    <p className="trade-proposal-warning">Both parties signed the agreement snapshot. This does not prove delivery, payment, quality, or completion.</p>
    <dl className="commerce-facts">
      <div><dt>Maker</dt><dd><code title={agreement.maker_did}>{short(agreement.maker_did, 28)}</code></dd></div>
      <div><dt>Taker</dt><dd><code title={agreement.taker_did}>{short(agreement.taker_did, 28)}</code></dd></div>
      <div><dt>Accepted</dt><dd>{new Date(agreement.created_at).toLocaleString()}</dd></div>
      <div><dt>Remote acknowledgement</dt><dd>{agreement.remote_acknowledged ? "Persisted" : "Not observed"}</dd></div>
    </dl>
    {agreement.remote_acknowledged && <div className="commerce-action">
      <h3>Receiver-signed acknowledgement</h3>
      <p className="muted">This proves the receiver signed a retention claim. It does not independently prove the receiver's filesystem or Spine contents.</p>
      <code title={agreement.remote_receipt_digest ?? ""}>{short(agreement.remote_receipt_digest ?? "", 32)}</code>
      <div className="muted">Received {new Date(agreement.remote_received_at ?? "").toLocaleString()}</div>
    </div>}
    {agreement.dispatch_pending && !agreement.remote_acknowledged && <div className="commerce-action">
      <h3>Delivery pending</h3>
      <p className="muted">The signed Order and peer target are retained by this node. Retrying reuses the same accepted agreement.</p>
      <div className="muted">Attempts: {agreement.dispatch_attempts ?? 0}</div>
      <div className="muted">Delivery generation: {agreement.dispatch_generation ?? 1}{(agreement.dispatch_superseded_deliveries ?? 0) > 0 ? ` (${agreement.dispatch_superseded_deliveries} expired envelope(s) superseded)` : ""}</div>
      {agreement.dispatch_last_error && <div className="trade-proposal-warning" role="status">Last attempt: {agreement.dispatch_last_error}</div>}
      <code title={agreement.dispatch_target_url ?? ""}>{agreement.dispatch_target_url}</code>
      <button className="btn btn-primary" type="button" disabled={busy || !agreement.dispatch_target_url} onClick={onRetryDispatch}>Retry delivery</button>
    </div>}
    <div className="commerce-action">
      <h3>Signed Order snapshot</h3>
      <pre>{JSON.stringify(agreement.order, null, 2)}</pre>
    </div>
  </div>;
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
