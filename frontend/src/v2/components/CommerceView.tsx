import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  acceptTradeProposal,
  announceTask,
  ApiHttpError,
  dispatchCommerceOutbox,
  disputeCommerceOrder,
  fetchCommerceOrders,
  fetchTradeProposals,
  fetchTradeOrders,
  fetchTradeRuleRecognitionImportBatch,
  fetchTradeRulePackages,
  getTradeOfferInspection,
  getTradeExecutionReceipts,
  getTradeOrder,
  getTradeProposal,
  getTradeRulePackage,
  importCachedTradeOffer,
  importTradeRulePackage,
  importTradeRuleRecognitions,
  publishMarketOffer,
  remoteCommerceCheckout,
  resolveCommerceDispute,
  settleCommerceOrder,
  submitCommerceDelivery,
  searchMarket,
  verifyCommerceDelivery,
} from "../api";
import type {
  CommerceOrderView,
  MarketSearchCategory,
  MarketSearchEntry,
  TradeProposalDetail,
  TradeProposalSummary,
  TradeOrderDetail,
  TradeOrderSummary,
  TradeRuleRecognitionImportStatusPage,
  TradeExecutionSkillView,
  TradeOfferInspection,
  TradeRulePackageCatalogItem,
  TradeRulePackageDetail,
} from "../types-v2";
import { useToast } from "./Toast";
import { MarketPublishForm, type MarketPublication } from "./MarketPublishForm";
import { MarketFederationPanel } from "./MarketFederationPanel";
import { ResourceProfilesPanel } from "./ResourceProfilesPanel";

type Scope = "discover" | "purchases" | "offers" | "proposals" | "agreements" | "skills";

interface CommerceViewProps {
  actorId?: string;
  openPublisher?: boolean;
  onPublisherOpened?: () => void;
}

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

function canOrderMarketEntry(entry: MarketSearchEntry): boolean {
  return (
    entry.protocol_kind === "commerce-listing-announcement"
    && entry.source === "federated"
    && !entry.stale
    && Boolean(entry.source_peer)
    && Boolean(entry.target.offer_digest)
    && entry.value.asset === "NTH-TEST"
  );
}

function marketOfferSelectionKey(entry: MarketSearchEntry): string {
  return `${entry.entry_id}:${entry.target.offer_digest}`;
}

function tradeOfferSourceCount(inspection: TradeOfferInspection): number {
  return new Set(inspection.discoveries.map(
    (item) => `${item.source_did}\u0000${item.source_peer}`,
  )).size;
}

async function sha256Text(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
  return `sha256:${hex}`;
}

export function CommerceView({
  actorId = "admin",
  openPublisher = false,
  onPublisherOpened,
}: CommerceViewProps) {
  const toast = useToast();
  const [scope, setScope] = useState<Scope>("discover");
  const [marketEntries, setMarketEntries] = useState<MarketSearchEntry[]>([]);
  const [marketQuery, setMarketQuery] = useState("");
  const [marketCategory, setMarketCategory] = useState<MarketSearchCategory | "">("");
  const [marketLoading, setMarketLoading] = useState(false);
  const [marketPageBusy, setMarketPageBusy] = useState(false);
  const [marketError, setMarketError] = useState("");
  const [marketCount, setMarketCount] = useState(0);
  const [marketTruncated, setMarketTruncated] = useState(false);
  const [marketVersion, setMarketVersion] = useState(0);
  const [myMarketEntries, setMyMarketEntries] = useState<MarketSearchEntry[]>([]);
  const [myMarketCount, setMyMarketCount] = useState(0);
  const [myMarketTruncated, setMyMarketTruncated] = useState(false);
  const [myMarketLoading, setMyMarketLoading] = useState(false);
  const [myMarketError, setMyMarketError] = useState("");
  const [offerInspection, setOfferInspection] = useState<TradeOfferInspection | null>(null);
  const [offerInspectionKey, setOfferInspectionKey] = useState("");
  const [offerInspectionError, setOfferInspectionError] = useState("");
  const [offerImportBusyDigest, setOfferImportBusyDigest] = useState("");
  const [offerImportError, setOfferImportError] = useState("");
  const marketSearchSequence = useRef(0);
  const myMarketSearchSequence = useRef(0);
  const offerInspectionSequence = useRef(0);
  const offerInspectionAbort = useRef<AbortController | null>(null);
  const [orders, setOrders] = useState<CommerceOrderView[]>([]);
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
  const [skills, setSkills] = useState<TradeRulePackageCatalogItem[]>([]);
  const [skillNextCursor, setSkillNextCursor] = useState("");
  const [skillPageBusy, setSkillPageBusy] = useState(false);
  const [skillError, setSkillError] = useState("");
  const [skillDataPreserved, setSkillDataPreserved] = useState(false);
  const [selectedSkillDigest, setSelectedSkillDigest] = useState("");
  const [selectedSkill, setSelectedSkill] = useState<TradeRulePackageDetail | null>(null);
  const [selectedId, setSelectedId] = useState("");
  const [busy, setBusy] = useState(false);
  const [showPublish, setShowPublish] = useState(openPublisher);
  const [showBuy, setShowBuy] = useState(false);

  useEffect(() => {
    if (!openPublisher) return;
    setScope("discover");
    setShowBuy(false);
    setShowPublish(true);
    onPublisherOpened?.();
  }, [openPublisher, onPublisherOpened]);
  const [peerUrl, setPeerUrl] = useState("");
  const [listingDigest, setListingDigest] = useState("");
  const [purpose, setPurpose] = useState("Purchase one digital service");
  const [delivery, setDelivery] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [disputeReason, setDisputeReason] = useState("");
  const [checkoutAttemptKey, setCheckoutAttemptKey] = useState("");

  useEffect(() => () => offerInspectionAbort.current?.abort(), []);

  const refresh = useCallback(async (signal?: AbortSignal) => {
    const sequence = ++refreshSequence.current;
    const [orderResult, proposalResult, agreementResult, skillResult] = await Promise.allSettled([
      fetchCommerceOrders(undefined, signal),
      fetchTradeProposals("", signal),
      fetchTradeOrders("", signal),
      fetchTradeRulePackages("", signal),
    ]);
    if (signal?.aborted || sequence !== refreshSequence.current) return;
    if (orderResult.status === "fulfilled") {
      const nextOrders = orderResult.value;
      setOrders(nextOrders);
      setSelectedId((current) =>
        current && nextOrders.some((row) => row.order_id === current)
          ? current
          : nextOrders[0]?.order_id ?? "",
      );
    }
    for (const result of [orderResult]) {
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
    if (skillResult.status === "fulfilled") {
      const nextSkills = skillResult.value.items;
      setSkillError("");
      setSkillDataPreserved(false);
      setSkills(nextSkills);
      setSkillNextCursor(skillResult.value.next_cursor);
      setSelectedSkillDigest((current) =>
        current && nextSkills.some((row) => row.package_digest === current)
          ? current
          : nextSkills[0]?.package_digest ?? "",
      );
    } else if (!isAbort(skillResult.reason)) {
      const error = skillResult.reason;
      setSkillError(error instanceof Error ? error.message : String(error));
      if ([401, 403].includes(httpStatus(error) ?? 0)) {
        setSkillDataPreserved(false);
        setSkills([]);
        setSkillNextCursor("");
        setSelectedSkillDigest("");
        setSelectedSkill(null);
      } else {
        setSkillDataPreserved(true);
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

  const loadMoreSkills = useCallback(async () => {
    if (!skillNextCursor || skillPageBusy) return;
    const sequence = refreshSequence.current;
    setSkillPageBusy(true);
    try {
      const page = await fetchTradeRulePackages(skillNextCursor);
      if (sequence !== refreshSequence.current) return;
      setSkills((current) => {
        const known = new Set(current.map((item) => item.package_digest));
        return current.concat(
          page.items.filter((item) => !known.has(item.package_digest)),
        );
      });
      setSkillNextCursor(page.next_cursor);
      setSkillError("");
      setSkillDataPreserved(false);
    } catch (error) {
      if (sequence !== refreshSequence.current) return;
      setSkillError(error instanceof Error ? error.message : String(error));
      if ([401, 403].includes(httpStatus(error) ?? 0)) {
        setSkills([]);
        setSkillNextCursor("");
        setSelectedSkillDigest("");
        setSelectedSkill(null);
        setSkillDataPreserved(false);
      } else {
        setSkillDataPreserved(true);
      }
      toast.push(error instanceof Error ? error.message : String(error), "error");
    } finally {
      setSkillPageBusy(false);
    }
  }, [skillNextCursor, skillPageBusy, toast]);

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
    const controller = new AbortController();
    const sequence = ++marketSearchSequence.current;
    const timer = window.setTimeout(() => {
      setMarketPageBusy(false);
      setMarketLoading(true);
      searchMarket(
        { q: marketQuery.trim(), category: marketCategory, limit: 200 },
        controller.signal,
      )
        .then((page) => {
          if (
            controller.signal.aborted
            || sequence !== marketSearchSequence.current
          ) return;
          setMarketEntries(page.items);
          setMarketCount(page.count);
          setMarketTruncated(page.truncated);
          setMarketError("");
        })
        .catch((error) => {
          if (
            sequence === marketSearchSequence.current
            && !isAbort(error)
          ) {
            setMarketError(error instanceof Error ? error.message : String(error));
          }
        })
        .finally(() => {
          if (
            !controller.signal.aborted
            && sequence === marketSearchSequence.current
          ) setMarketLoading(false);
        });
    }, 250);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [marketCategory, marketQuery, marketVersion]);

  useEffect(() => {
    if (scope !== "offers") return;
    const controller = new AbortController();
    const sequence = ++myMarketSearchSequence.current;
    setMyMarketLoading(true);
    searchMarket(
      { source: "local", offset: 0, limit: 100 },
      controller.signal,
    )
      .then((page) => {
        if (controller.signal.aborted || sequence !== myMarketSearchSequence.current) return;
        setMyMarketEntries(page.items);
        setMyMarketCount(page.count);
        setMyMarketTruncated(page.truncated);
        setMyMarketError("");
      })
      .catch((error) => {
        if (sequence === myMarketSearchSequence.current && !isAbort(error)) {
          setMyMarketError(error instanceof Error ? error.message : String(error));
        }
      })
      .finally(() => {
        if (!controller.signal.aborted && sequence === myMarketSearchSequence.current) {
          setMyMarketLoading(false);
        }
      });
    return () => controller.abort();
  }, [marketVersion, scope]);

  async function loadMoreMarket() {
    if (marketPageBusy || !marketTruncated) return;
    const sequence = ++marketSearchSequence.current;
    setMarketPageBusy(true);
    try {
      const page = await searchMarket({
        q: marketQuery.trim(),
        category: marketCategory,
        offset: marketEntries.length,
        limit: 200,
      });
      if (sequence !== marketSearchSequence.current) return;
      setMarketEntries((current) => [...current, ...page.items]);
      setMarketCount(page.count);
      setMarketTruncated(page.truncated);
      setMarketError("");
    } catch (error) {
      if (sequence === marketSearchSequence.current) {
        setMarketError(error instanceof Error ? error.message : String(error));
      }
    } finally {
      if (sequence === marketSearchSequence.current) setMarketPageBusy(false);
    }
  }

  async function loadMoreMyMarket() {
    if (myMarketLoading || !myMarketTruncated) return;
    const sequence = ++myMarketSearchSequence.current;
    setMyMarketLoading(true);
    try {
      const page = await searchMarket({
        source: "local",
        offset: myMarketEntries.length,
        limit: 100,
      });
      if (sequence !== myMarketSearchSequence.current) return;
      setMyMarketEntries((current) => [...current, ...page.items]);
      setMyMarketCount(page.count);
      setMyMarketTruncated(page.truncated);
      setMyMarketError("");
    } catch (error) {
      if (sequence === myMarketSearchSequence.current) {
        setMyMarketError(error instanceof Error ? error.message : String(error));
      }
    } finally {
      if (sequence === myMarketSearchSequence.current) setMyMarketLoading(false);
    }
  }

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

  useEffect(() => {
    if (scope !== "skills" || !selectedSkillDigest) {
      if (!selectedSkillDigest) setSelectedSkill(null);
      return;
    }
    const controller = new AbortController();
    let active = true;
    setSelectedSkill(null);
    getTradeRulePackage(selectedSkillDigest, controller.signal)
      .then((value) => {
        if (active) {
          setSelectedSkill(value);
          setSkillError("");
          setSkillDataPreserved(false);
        }
      })
      .catch((error) => {
        if (active && !isAbort(error)) {
          if ([401, 403].includes(httpStatus(error) ?? 0)) {
            setSkills([]);
            setSkillNextCursor("");
            setSelectedSkillDigest("");
            setSelectedSkill(null);
            setSkillDataPreserved(false);
          } else {
            setSkillDataPreserved(true);
          }
          setSkillError(error instanceof Error ? error.message : String(error));
          toast.push(error instanceof Error ? error.message : String(error), "error");
        }
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [scope, selectedSkillDigest, toast]);

  const visibleOrders = useMemo(
    () => (scope === "purchases" ? orders : []),
    [orders, scope],
  );
  const selected = orders.find((order) => order.order_id === selectedId) ?? null;
  const isProtocolInbox = scope === "proposals" || scope === "agreements" || scope === "skills";

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

  async function publish(publication: MarketPublication) {
    await run(async () => {
      const result = publication.kind === "task"
        ? await announceTask(publication.body)
        : await publishMarketOffer(publication.body);
      setShowPublish(false);
      setShowBuy(false);
      setMarketQuery("");
      setMarketCategory("");
      setMarketVersion((value) => value + 1);
      setScope(publication.kind === "task" ? "discover" : "offers");
      return result;
    }, publication.kind === "task" ? "Signed Task published" : "Signed Offer published");
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

  function selectMarketEntry(entry: MarketSearchEntry) {
    if (!canOrderMarketEntry(entry)) return;
    setPeerUrl(entry.source_peer);
    setListingDigest(entry.target.offer_digest);
    setPurpose(`Purchase ${entry.title}`);
    setCheckoutAttemptKey(crypto.randomUUID());
    setShowPublish(false);
    setShowBuy(true);
  }

  async function inspectMarketOffer(entry: MarketSearchEntry) {
    const digest = entry.target.offer_digest;
    if (!digest || entry.protocol_kind !== "trade-offer-announcement") return;
    const selectionKey = marketOfferSelectionKey(entry);
    if (selectionKey === offerInspectionKey && offerInspection) {
      offerInspectionAbort.current?.abort();
      offerInspectionSequence.current += 1;
      setOfferInspection(null);
      setOfferInspectionKey("");
      setOfferInspectionError("");
      setOfferImportError("");
      return;
    }
    offerInspectionAbort.current?.abort();
    const controller = new AbortController();
    offerInspectionAbort.current = controller;
    const sequence = ++offerInspectionSequence.current;
    setOfferInspectionKey(selectionKey);
    setOfferInspection(null);
    setOfferInspectionError("");
    setOfferImportError("");
    try {
      const detail = await getTradeOfferInspection(
        digest,
        entry.source === "federated",
        controller.signal,
      );
      if (sequence === offerInspectionSequence.current) setOfferInspection(detail);
    } catch (error) {
      if (sequence !== offerInspectionSequence.current || isAbort(error)) return;
      setOfferInspectionError(error instanceof Error ? error.message : String(error));
    }
  }

  async function saveRemoteMarketOffer(digest: string) {
    if (!digest || offerImportBusyDigest) return;
    setOfferImportBusyDigest(digest);
    setOfferImportError("");
    try {
      const result = await importCachedTradeOffer(digest);
      setOfferInspection((current) => current?.digest === digest ? {
        ...current,
        storage_provenance: {
          source_kind: result.source_kind,
          source_id: result.source_id,
        },
      } : current);
      toast.push(
        result.appended_revisions > 0
          ? `Saved ${result.imported_revisions} signed Offer revision(s) locally`
          : "Signed Offer was already saved locally",
        "success",
      );
    } catch (error) {
      setOfferImportError(error instanceof Error ? error.message : String(error));
    } finally {
      setOfferImportBusyDigest("");
    }
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
          {(["discover", "purchases", "offers", "skills"] as Scope[]).map((item) => (
            <button key={item} type="button" role="tab" aria-selected={scope === item}
              className={scope === item ? "active" : ""} onClick={() => setScope(item)}>
              {item === "discover" ? "Discover" : item === "purchases" ? "Orders" : item === "offers" ? "My listings" : "Trade Skills"}
              <span>{item === "discover" ? marketCount : item === "offers" ? myMarketCount : item === "skills" ? skills.length : orders.length}</span>
            </button>
          ))}
          <div className="commerce-scope-label">Advanced protocol</div>
          {(["proposals", "agreements"] as Scope[]).map((item) => (
            <button key={item} type="button" role="tab" aria-selected={scope === item}
              className={scope === item ? "active" : ""} onClick={() => setScope(item)}>
              {item === "proposals" ? "Proposals" : "Agreements"}
              <span>{item === "proposals" ? proposals.length : agreements.length}</span>
            </button>
          ))}
        </div>
        <div className="sidebar-list">
          {scope === "purchases" && visibleOrders.map((order) => (
            <button key={order.order_id} className={`sidebar-item ${selectedId === order.order_id ? "active" : ""}`}
              onClick={() => setSelectedId(order.order_id)}>
              <div className="sidebar-item-title"><span className="truncate">{order.title}</span></div>
              <div className="sidebar-item-meta"><span>{order.state}</span><span>{order.amount_minor / 1_000_000} NTH-TEST</span></div>
            </button>
          ))}
          {scope === "offers" && myMarketEntries.map((entry) => (
            <div key={entry.entry_id} className="commerce-offer-row">
              <strong>{entry.title}</strong>
              <span>{entry.category} / {entry.market_intent}</span>
              <code title={entry.target.offer_digest || entry.target.announcement_id}>{short(entry.target.offer_digest || entry.target.announcement_id, 24)}</code>
            </div>
          ))}
          {scope === "offers" && myMarketTruncated && (
            <button className="btn btn-secondary commerce-load-more" type="button"
              disabled={myMarketLoading} onClick={() => void loadMoreMyMarket()}>
              {myMarketLoading ? "Loading..." : "Load more"}
            </button>
          )}
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
          {scope === "skills" && skills.map((skill) => (
            <button key={skill.package_digest} className={`sidebar-item ${selectedSkillDigest === skill.package_digest ? "active" : ""}`}
              onClick={() => { setSelectedSkill(null); setSelectedSkillDigest(skill.package_digest); }}>
              <div className="sidebar-item-title"><span className="truncate">{skill.rule_id}</span></div>
              <div className="sidebar-item-meta"><span>v{skill.version}</span><span>{skill.execution.mode}</span></div>
            </button>
          ))}
          {scope === "skills" && skillNextCursor && (
            <button className="btn btn-secondary commerce-load-more" type="button"
              disabled={skillPageBusy} onClick={loadMoreSkills}>
              {skillPageBusy ? "Loading..." : "Load more"}
            </button>
          )}
          {((scope === "discover" && marketEntries.length === 0) || (scope === "offers" && myMarketEntries.length === 0) || (scope === "proposals" && proposals.length === 0) || (scope === "agreements" && agreements.length === 0) || (scope === "skills" && skills.length === 0) || (scope === "purchases" && visibleOrders.length === 0)) &&
            <p className="muted" style={{ padding: "12px 14px" }}>Nothing here yet.</p>}
        </div>
        {scope === "discover" && <MarketFederationPanel
          actorId={actorId}
          onUpdated={() => setMarketVersion((value) => value + 1)}
        />}
      </aside>

      <section className="main">
        <div className="main-head commerce-head">
          <div>
            <p className="main-eyebrow">A2A Commerce</p>
            <h1 className="main-title">{scope === "discover" ? "Market" : scope === "purchases" ? "Orders" : scope === "offers" ? "My listings" : scope === "proposals" ? "Trade proposals" : scope === "agreements" ? "Accepted agreements" : "Trade Skills"}</h1>
            <p className="main-subtitle">{scope === "discover" ? "Search signed task and offer discovery claims from this DAO and verified peers." : scope === "purchases" ? "Purchases and sales with signed delivery, acknowledgement, and audit history." : scope === "offers" ? "Resources published by this DAO. Product and service are broad facets, not fixed protocol types." : scope === "proposals" ? "Signed inbound negotiation claims awaiting independent review." : scope === "agreements" ? "Bilateral signed terms retained by this DAO. Delivery and payment remain separate." : "Verified local Rule Packages that define optional transaction behavior."}</p>
          </div>
          {!isProtocolInbox && <div className="commerce-head-actions">
            <button className="btn btn-secondary" onClick={() => {
              setShowBuy((value) => {
                if (!value) setCheckoutAttemptKey(crypto.randomUUID());
                return !value;
              });
            }}>Buy from peer</button>
            <button className="btn btn-primary" onClick={() => {
              setShowPublish((value) => !value);
              setShowBuy(false);
            }}>Publish</button>
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
          {!isProtocolInbox && showPublish && <MarketPublishForm
            busy={busy}
            onCancel={() => setShowPublish(false)}
            onPublish={publish}
          />}

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

          {!showPublish && !showBuy && scope === "discover" && <section className="commerce-discover">
            <div className="commerce-discover-tools">
              <input
                aria-label="Search market"
                value={marketQuery}
                onChange={(event) => setMarketQuery(event.target.value)}
                placeholder="Search tasks, products, services, or exchanges"
                maxLength={200}
              />
              <div className="commerce-market-facets" aria-label="Market categories">
                {([
                  ["", "All"],
                  ["tasks", "Tasks"],
                  ["products", "Products"],
                  ["services", "Services"],
                  ["digital-assets", "Digital assets"],
                  ["exchanges", "Exchanges"],
                  ["other", "Other"],
                ] as const).map(([value, label]) => (
                  <button
                    key={value || "all"}
                    type="button"
                    className={`btn ${marketCategory === value ? "btn-primary" : "btn-ghost"}`}
                    onClick={() => setMarketCategory(value)}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
            <p className="trade-proposal-warning">
              Search results are signed discovery claims, not proof of availability,
              ownership, fairness, or execution authority.
            </p>
            {marketError && <p role="alert" className="trade-proposal-warning">Market search unavailable: {marketError}</p>}
            {marketLoading && <p className="muted">Searching verified local projections...</p>}
            {!marketLoading && marketEntries.length === 0 && <div className="main-empty">
              <p>No matching market entries.</p>
              <p className="muted">Add a verified federation peer or publish a Task or Offer.</p>
            </div>}
            <div className="commerce-market-grid">
              {marketEntries.map((entry) => {
                const offerSelected = (
                  offerInspectionKey === marketOfferSelectionKey(entry)
                );
                return <article key={entry.entry_id} className="commerce-market-card">
                  <div className="commerce-market-entry-head">
                    <span className="pill dim">{entry.category}</span>
                    <span className="pill dim">{entry.market_intent}</span>
                    {entry.source === "federated" && <span className="pill">federated</span>}
                    {entry.stale && <span className="pill wait">stale</span>}
                  </div>
                  <h2>{entry.title}</h2>
                  {entry.summary && <p>{entry.summary}</p>}
                  <div className="commerce-market-card-meta">
                    <span>{entry.value.amount_minor > 0
                      ? `${entry.value.amount_minor} ${entry.value.asset} minor units`
                      : "Terms in signed source"}</span>
                    <code title={entry.publisher_did}>{short(entry.publisher_did, 28)}</code>
                  </div>
                  {entry.legacy && <p className="trade-proposal-warning">Legacy claimable Task label; this is not a signed Trade Offer.</p>}
                  <div className="commerce-market-card-action">
                    {canOrderMarketEntry(entry)
                      ? <button className="btn btn-primary" type="button" onClick={() => selectMarketEntry(entry)}>Review order</button>
                      : entry.protocol_kind === "trade-offer-announcement" && entry.target.offer_digest
                        ? <button className="btn btn-secondary" type="button" onClick={() => void inspectMarketOffer(entry)}>
                          {offerSelected && !offerInspection && !offerInspectionError
                            ? "Inspecting..."
                            : offerSelected && offerInspection
                              ? "Close terms"
                              : "Inspect offer"}
                        </button>
                      : <span className="muted">{entry.entry_kind === "task"
                        ? "Open Tasks to claim this work request."
                        : "Resolve and inspect the exact signed Offer before agreement."}</span>}
                  </div>
                  {offerSelected && offerInspectionError && <p role="alert" className="trade-proposal-warning">
                    Could not inspect this signed Offer. {offerInspectionError}
                  </p>}
                  {offerSelected && offerInspection && <MarketOfferInspection
                    inspection={offerInspection}
                    importBusy={offerImportBusyDigest === offerInspection.digest}
                    importError={offerImportError}
                    onSave={() => void saveRemoteMarketOffer(offerInspection.digest)}
                  />}
                </article>
              })}
            </div>
            {marketTruncated && <button
              className="btn btn-secondary commerce-load-more"
              type="button"
              disabled={marketPageBusy}
              onClick={() => void loadMoreMarket()}
            >{marketPageBusy ? "Loading..." : `Load more (${marketEntries.length} of ${marketCount})`}</button>}
          </section>}

          {!showPublish && !showBuy && scope === "offers" && <div className="main-empty">
            <p>Your local Task and Offer discovery claims are shown on the left.</p>
            <p className="muted">Each row retains an exact source pointer. Discovery is not proof of availability or execution authority.</p>
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
            onRefresh={() => setAgreementDetailVersion((value) => value + 1)}
          />}
          {scope === "skills" && skillError && <p className="trade-proposal-warning" role="status">{skillDataPreserved ? "Trade Skill catalog unavailable; showing last known data" : "Trade Skill authorization failed; cached UI data cleared"}: {skillError}</p>}
          {scope === "skills" && <ResourceProfilesPanel />}
          {scope === "skills" && !selectedSkill && <div className="main-empty"><p>{skills.length > 0 ? "Select a Trade Skill to inspect its signed manifest." : "No verified Trade Skills are cached locally."}</p></div>}
          {scope === "skills" && selectedSkill && <TradeSkillWorkbench skill={selectedSkill} />}
          {!showPublish && !showBuy && scope === "purchases" && !selected && <div className="main-empty"><p>Select an order or create a purchase.</p></div>}
          {!showPublish && !showBuy && scope === "purchases" && selected && <OrderWorkbench order={selected} busy={busy}
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
        <div className="detail-head"><span className="detail-title">{scope === "discover" ? "Discovery safety" : scope === "proposals" ? "Proposal audit" : scope === "agreements" ? "Agreement audit" : scope === "skills" ? "Skill verification" : scope === "offers" ? "Listing integrity" : "Order audit"}</span></div>
        <div className="detail-body">
          {scope === "discover" ? <div className="detail-section">
            <div className="detail-section-label">Projection boundary</div>
            <div className="detail-row"><span className="key">Entries</span><span className="value">{marketEntries.length}</span></div>
            <div className="detail-row"><span className="key">Source</span><span className="value">Signed discovery</span></div>
            <div className="detail-row"><span className="key">Truth</span><span className="value">Not proven</span></div>
            <div className="detail-row"><span className="key">Real funds</span><span className="value">Disabled</span></div>
          </div> : scope === "proposals" ? (selectedProposal ? <>
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
              <div className="detail-row"><span className="key">Executor</span><span className="value">{selectedAgreement.execution?.local_executor.role ?? "Unavailable"}</span></div>
              <div className="detail-row"><span className="key">Execution</span><span className="value">{selectedAgreement.execution?.status ?? "Unavailable"}</span></div>
              <div className="detail-row"><span className="key">Real funds</span><span className="value">Disabled</span></div>
            </div>
          </> : <p className="muted">Select an agreement to inspect parties and audit status.</p>) : scope === "skills" ? (selectedSkill ? <>
            <div className="detail-section">
              <div className="detail-section-label">Local cache claim</div>
              <div className="detail-row"><span className="key">Signature</span><span className="value">Verified</span></div>
              <div className="detail-row"><span className="key">Resources</span><span className="value">Verified</span></div>
              <div className="detail-row"><span className="key">Recognition</span><span className="value">Not evaluated</span></div>
              <div className="detail-row"><span className="key">Execution</span><span className="value">Not authorized</span></div>
            </div>
            <div className="detail-section">
              <div className="detail-section-label">Content address</div>
              <code title={selectedSkill.package_digest}>{short(selectedSkill.package_digest, 30)}</code>
            </div>
          </> : <p className="muted">Select a Trade Skill to inspect verification status.</p>) : scope === "offers" ? <div className="detail-section">
            <div className="detail-section-label">Publication boundary</div>
            <div className="detail-row"><span className="key">Listings</span><span className="value">{myMarketCount}</span></div>
            <div className="detail-row"><span className="key">Discovery</span><span className="value">Signed summary</span></div>
            <div className="detail-row"><span className="key">Execution</span><span className="value">Separate agreement</span></div>
            {myMarketError && <p role="alert" className="trade-proposal-warning">My listings unavailable: {myMarketError}</p>}
          </div> : selected ? <>
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

function MarketOfferInspection({
  inspection,
  importBusy,
  importError,
  onSave,
}: {
  inspection: TradeOfferInspection;
  importBusy: boolean;
  importError: string;
  onSave: () => void;
}) {
  const verification = inspection.verification;
  return <section className="market-offer-inspection" aria-label="Signed Offer terms">
    <div className="market-offer-inspection-head">
      <strong>Signed Offer terms</strong>
      <span className={`pill ${verification.offer_signature_valid ? "ok" : "wait"}`}>
        {verification.offer_signature_valid ? "Signature verified" : "Signature rejected"}
      </span>
    </div>
    <p className="trade-proposal-warning">{inspection.warning}</p>
    <div className="market-offer-verification">
      <span>{verification.announcement_binding_valid === true ? "Announcement bound" : "Announcement binding unavailable"}</span>
      <span>{verification.source_did_bound === true ? "Source DID bound" : "Source DID binding unavailable"}</span>
      {inspection.authority === "remote-publisher" && <span>
        {verification.recent_source_verified ? "Remote source recently verified" : "Remote source is not recently verified"}
        {` / ${tradeOfferSourceCount(inspection)} source(s)`}
      </span>}
      {inspection.head_claim && <span>
        {`Disclosed ${inspection.head_claim.chain_length}-revision chain verified; global latest revision is not proven`}
      </span>}
    </div>
    <p className="muted">
      Revision {inspection.offer.revision} / {inspection.offer.state}
      {inspection.offer.not_after ? ` / expires ${inspection.offer.not_after}` : " / no declared expiry"}
    </p>
    <div className="market-offer-legs">
      {([
        ["Provides", inspection.offer.provides],
        ["Requests", inspection.offer.requests],
      ] as const).map(([label, legs]) => <div key={label}>
        <strong>{label}</strong>
        {legs.length === 0
          ? <p className="muted">None declared</p>
          : legs.map((leg) => <div className="market-offer-leg" key={`${label}-${leg.leg_id}`}>
            <span>{leg.quantity} {leg.unit} / {leg.resource_type}</span>
            <code title={leg.resource_id}>{leg.resource_id}</code>
            <code title={leg.descriptor_digest}>descriptor {short(leg.descriptor_digest, 30)}</code>
          </div>)}
      </div>)}
    </div>
    <div className="market-offer-descriptors">
      <strong>Resource descriptors</strong>
      <p className="trade-proposal-warning">{inspection.resource_descriptors.warning}</p>
      <p className="muted">
        {inspection.resource_descriptors.verified_inline_count} of {inspection.resource_descriptors.referenced_count} referenced inline descriptors have matching content hashes.
      </p>
      <p className="muted">
        {inspection.resource_descriptors.profile_packages_recognized} Profile Skills are recognized locally; {inspection.resource_descriptors.profile_packages_applicable} also validate their descriptor attributes.
      </p>
      {inspection.resource_descriptors.items.map((item) => <details key={item.digest}>
        <summary>
          <span>{item.leg_ids.length > 0 ? item.leg_ids.join(", ") : "Unreferenced descriptor"}</span>
          <span className={`pill ${item.content_hash_valid ? "ok" : "wait"}`}>
            {item.content_hash_valid ? "Hash verified" : "Hash mismatch"}
          </span>
        </summary>
        <code title={item.digest}>{item.digest}</code>
        <div className="market-offer-profile-status">
          {item.profile_ref.digest ? <>
            <span className={`pill ${item.profile_schema_valid === true ? "ok" : "wait"}`}>
              {{
                unresolved: "Profile resolver unavailable",
                "missing-local": "Profile not cached locally",
                "verified-local": "Profile verified, not recognized",
                "recognized-local": item.profile_schema_valid === false
                  ? "Profile recognized; attributes invalid"
                  : "Profile recognized; attributes valid",
                "not-yet-active": "Profile not active yet",
                expired: "Profile expired",
                "invalid-local": "Local Profile invalid",
                "not-declared": "Profile not declared",
              }[item.profile_resolution]}
            </span>
            <code title={item.profile_ref.digest}>{item.profile_ref.rule_id} / {item.profile_ref.digest}</code>
            {item.mapped_market_category
              && <span className="muted">Mapped Market category: {item.mapped_market_category}</span>}
            {item.profile_mapping_reason && !item.mapped_market_category
              && <span className="muted">Category mapping: {item.profile_mapping_reason}</span>}
            {item.profile_error
              && <span role="alert" className="trade-proposal-warning">{item.profile_error}</span>}
          </> : <span className="muted">No Resource Profile Skill reference declared.</span>}
        </div>
        <pre>{JSON.stringify(item.descriptor.attributes ?? {}, null, 2)}</pre>
      </details>)}
      {inspection.resource_descriptors.items.length === 0
        && <p className="muted">No inline resource descriptors are present.</p>}
    </div>
    <div className="market-offer-signer">
      <span>Signer</span><code title={inspection.offer.publisher_did}>{inspection.offer.publisher_did}</code>
    </div>
    {inspection.offer.rule_refs.length > 0 ? <div className="market-offer-rules">
      <strong>Trade Skill references</strong>
      {inspection.offer.rule_refs.map((rule) => <code key={`${rule.rule_id}-${rule.digest}`} title={rule.digest}>
        {rule.rule_id} / {rule.digest}
      </code>)}
    </div> : <p className="muted">No Trade Skill references declared.</p>}
    {inspection.authority === "remote-publisher" && <div className="market-offer-save">
      <button
        type="button"
        className="btn btn-secondary"
        disabled={importBusy || inspection.storage_provenance !== null}
        onClick={onSave}
      >
        {inspection.storage_provenance !== null
          ? "Saved locally"
          : importBusy
            ? "Saving..."
            : "Save locally"}
      </button>
      <p className="muted">Saving retains exact signed bytes. It does not accept the Offer, trust the publisher, or authorize execution.</p>
      {importError && <p role="alert" className="trade-proposal-warning">Could not save this signed Offer. {importError}</p>}
    </div>}
  </section>;
}

function TradeSkillWorkbench({ skill }: { skill: TradeRulePackageDetail }) {
  const resources = Array.isArray(skill.manifest.resources)
    ? skill.manifest.resources as Array<Record<string, unknown>>
    : [];
  const dependencies = Array.isArray(skill.manifest.dependencies)
    ? skill.manifest.dependencies as Array<Record<string, unknown>>
    : [];
  const hooks = Array.isArray(skill.manifest.hook_contracts)
    ? skill.manifest.hook_contracts as Array<Record<string, unknown>>
    : [];
  const importAuditLabel = skill.import_audit.status === "not-applicable"
    ? "No signed import audit"
    : `${skill.import_audit.status[0].toUpperCase()}${skill.import_audit.status.slice(1)} (${skill.import_audit.anchored_count}/${skill.import_audit.proposed_count})`;
  const provenanceLabel = skill.provenance.status === "unclassified"
    ? "Unclassified"
    : skill.provenance.sources.map((source) => source === "local" ? "Local install" : "Federated import").join(" + ");
  return <div className="commerce-workbench trade-skill-workbench">
    <div className="commerce-order-heading">
      <div><p className="main-eyebrow">Verified local package</p><h2>{skill.rule_id}</h2></div>
      <span className="pill ok">Signature verified</span>
    </div>
    <p>{skill.summary}</p>
    <p className="trade-proposal-warning">Verified bytes prove publisher authorship and package integrity. They do not prove the rule is fair, recognized, safe to execute, or suitable for this trade.</p>
    <dl className="commerce-facts">
      <div><dt>Version</dt><dd>{skill.version}</dd></div>
      <div><dt>Mode</dt><dd>{skill.execution.mode}</dd></div>
      <div><dt>Resources</dt><dd>{skill.resource_count} / {skill.resource_bytes.toLocaleString()} bytes</dd></div>
      <div><dt>Expires</dt><dd>{skill.not_after ? new Date(skill.not_after).toLocaleString() : "No expiry"}</dd></div>
      <div><dt>Import audit</dt><dd>{importAuditLabel}</dd></div>
      <div><dt>Acquisition</dt><dd>{provenanceLabel}</dd></div>
    </dl>
    {(skill.import_audit.status === "incomplete" || skill.import_audit.status === "mixed")
      && <p className="trade-proposal-warning" role="status">A signed import intent is missing its final Spine anchor. Treat this cache entry as incomplete until the import audit is repaired.</p>}
    {skill.provenance.status === "unclassified"
      && <p className="trade-proposal-warning" role="status">This package predates persisted acquisition provenance or was installed without an explicit source. It may be inspected, but execution must remain blocked.</p>}
    {skill.provenance.sources.includes("federated") && skill.import_audit.status === "not-applicable"
      && <p className="trade-proposal-warning" role="status">Federated provenance has no signed import anchor. Execution must remain blocked until the audit is repaired.</p>}
    <div className="trade-execution-column">
      <h3>Publisher and content address</h3>
      <code title={skill.publisher_did}>Publisher {short(skill.publisher_did, 48)}</code>
      <code title={skill.package_digest}>Package {short(skill.package_digest, 48)}</code>
    </div>
    <div className="trade-execution-column">
      <h3>Declared scope</h3>
      <p>{skill.applies_to.join(", ")} · {skill.families.join(", ")}</p>
      {skill.required_capabilities.length > 0
        ? <code>{skill.required_capabilities.join(", ")}</code>
        : <p className="muted">No additional capabilities declared.</p>}
      {skill.execution.permissions.length > 0
        ? <p className="trade-proposal-warning">Requested permissions: {skill.execution.permissions.join(", ")}</p>
        : <p className="muted">No execution permissions requested.</p>}
    </div>
    <div className="trade-execution-column">
      <h3>Content-addressed resources</h3>
      <ul className="trade-proposal-rules">
        {resources.map((resource) => <li key={`${String(resource.purpose)}:${String(resource.digest)}`}>
          <div className="trade-execution-row"><strong>{String(resource.purpose)}</strong><span>{String(resource.media_type)}</span></div>
          <span className="muted">{Number(resource.size).toLocaleString()} bytes</span>
          <code title={String(resource.digest)}>{short(String(resource.digest), 42)}</code>
        </li>)}
      </ul>
    </div>
    {dependencies.length > 0 && <div className="trade-execution-column">
      <h3>Exact dependencies</h3>
      <ul className="trade-proposal-rules">{dependencies.map((dependency) => <li key={String(dependency.digest)}>
        <strong>{String(dependency.rule_id)}</strong>
        <code title={String(dependency.digest)}>{short(String(dependency.digest), 42)}</code>
      </li>)}</ul>
    </div>}
    {hooks.length > 0 && <div className="trade-execution-column">
      <h3>Hook contracts</h3>
      <ul className="trade-proposal-rules">{hooks.map((hook) => <li key={`${String(hook.name)}:${String(hook.version)}`}>
        <div className="trade-execution-row"><strong>{String(hook.name)}</strong><span>v{String(hook.version)}</span></div>
        <span className="muted">Side effect: {String(hook.side_effect)}</span>
      </li>)}</ul>
    </div>}
  </div>;
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
  onRefresh,
}: {
  agreement: TradeOrderDetail;
  busy: boolean;
  onRetryDispatch: () => void;
  onRefresh: () => void;
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
    <AgreementExecutionReadiness
      key={`${agreement.order_digest}:${agreement.dispatch_target_url ?? ""}`}
      agreement={agreement}
      onRefresh={onRefresh}
    />
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

function readinessLabel(value: string) {
  return value.split("-").map((part) => (
    part ? `${part[0].toUpperCase()}${part.slice(1)}` : part
  )).join(" ");
}

function loadTradeSkillPeer(orderDigest: string, dispatchTarget?: string | null) {
  if (dispatchTarget) return dispatchTarget;
  try {
    return window.localStorage.getItem(`nth-trade-skill-peer:${orderDigest}`) ?? "";
  } catch {
    return "";
  }
}

function rememberTradeSkillPeer(orderDigest: string, peerUrl: string) {
  try {
    const key = `nth-trade-skill-peer:${orderDigest}`;
    const normalized = peerUrl.trim();
    if (normalized) window.localStorage.setItem(key, normalized);
    else window.localStorage.removeItem(key);
  } catch {
    // Preference persistence must not turn a verified import into a failure.
  }
}

function AgreementExecutionReadiness({
  agreement,
  onRefresh,
}: {
  agreement: TradeOrderDetail;
  onRefresh: () => void;
}) {
  const toast = useToast();
  const execution = agreement.execution;
  const initialHistoryKey = execution
    ? `${execution.order_digest}:${execution.history.items.map((item) => item.execution_id).join(",")}`
    : "";
  const [historyItems, setHistoryItems] = useState(
    execution?.history.items ?? [],
  );
  const [historyHasMore, setHistoryHasMore] = useState(
    execution?.history.has_more ?? false,
  );
  const [historyCursor, setHistoryCursor] = useState<number | null>(
    execution?.history.next_cursor ?? null,
  );
  const [historyBusy, setHistoryBusy] = useState(false);
  const [historyError, setHistoryError] = useState("");
  const [skillPeerUrl, setSkillPeerUrl] = useState(() => loadTradeSkillPeer(
    agreement.order_digest,
    agreement.dispatch_target_url,
  ));
  const [importingSkill, setImportingSkill] = useState("");
  const [skillImportMessages, setSkillImportMessages] = useState<Record<string, string>>({});
  const [skillImportErrors, setSkillImportErrors] = useState<Record<string, boolean>>({});
  const skillImportAbort = useRef<AbortController | null>(null);
  const skillImportGeneration = useRef(0);

  useEffect(() => {
    setHistoryItems(execution?.history.items ?? []);
    setHistoryHasMore(execution?.history.has_more ?? false);
    setHistoryCursor(execution?.history.next_cursor ?? null);
    setHistoryError("");
  }, [initialHistoryKey, execution?.history.has_more, execution?.history.next_cursor]);

  useEffect(() => (
    () => {
      skillImportGeneration.current += 1;
      skillImportAbort.current?.abort();
      skillImportAbort.current = null;
    }
  ), []);

  if (!execution) {
    return <div className="commerce-action">
      <h3>Execution readiness</h3>
      <p className="trade-proposal-warning" role="status">This node did not return an execution readiness projection. No execution should be attempted.</p>
    </div>;
  }
  const executionDigest = execution.order_digest;
  async function loadOlderReceipts() {
    if (historyBusy || historyCursor === null) return;
    setHistoryBusy(true);
    setHistoryError("");
    try {
      const page = await getTradeExecutionReceipts(
        executionDigest,
        historyCursor,
      );
      if (page.status !== "available") {
        setHistoryError(
          `Receipt history unavailable (${page.error_code || "verification-failed"}).`,
        );
        return;
      }
      setHistoryItems((current) => {
        const known = new Set(current.map((item) => item.execution_id));
        return [
          ...page.items.filter((item) => !known.has(item.execution_id)),
          ...current,
        ];
      });
      setHistoryHasMore(page.has_more);
      setHistoryCursor(page.next_cursor);
    } catch (error) {
      setHistoryError(
        error instanceof Error
          ? error.message
          : "Receipt history request failed.",
      );
    } finally {
      setHistoryBusy(false);
    }
  }
  async function fetchMissingSkill(packageDigest: string) {
    const peerUrl = skillPeerUrl.trim();
    if (!peerUrl || importingSkill) return;
    const generation = skillImportGeneration.current;
    const agreementDigest = agreement.order_digest;
    const controller = new AbortController();
    skillImportAbort.current?.abort();
    skillImportAbort.current = controller;
    const isCurrent = () => (
      !controller.signal.aborted
      && skillImportGeneration.current === generation
      && agreement.order_digest === agreementDigest
    );
    setImportingSkill(packageDigest);
    setSkillImportMessages((current) => ({ ...current, [packageDigest]: "" }));
    setSkillImportErrors((current) => ({ ...current, [packageDigest]: false }));
    try {
      const result = await importTradeRulePackage(
        executionDigest,
        packageDigest,
        peerUrl,
        controller.signal,
      );
      if (!isCurrent()) return;
      rememberTradeSkillPeer(agreement.order_digest, peerUrl);
      const message = result.installed
        ? `Signature and content verified; cached locally and signed in Spine ${short(result.audit_event_id, 20)}. Not trusted or executed.`
        : result.audit_created
          ? `Exact verified package was already cached; its missing signed audit was repaired in Spine ${short(result.audit_event_id, 20)}.`
          : `Exact verified package and Spine audit ${short(result.audit_event_id, 20)} already exist; no network retry was needed.`;
      setSkillImportMessages((current) => ({
        ...current,
        [packageDigest]: message,
      }));
      toast.push(result.installed ? "Trade Skill verified and cached" : "Trade Skill already cached", "success");
      onRefresh();
    } catch (error) {
      if (isAbort(error) || !isCurrent()) return;
      const message = error instanceof Error ? error.message : "Trade Skill import failed.";
      setSkillImportMessages((current) => ({ ...current, [packageDigest]: message }));
      setSkillImportErrors((current) => ({ ...current, [packageDigest]: true }));
      toast.push(message, "error");
    } finally {
      if (isCurrent()) {
        skillImportAbort.current = null;
        setImportingSkill("");
      }
    }
  }
  return <div className="commerce-action trade-execution-readiness">
    <div className="commerce-order-heading">
      <h3>Execution readiness</h3>
      <span className={`pill ${execution.status === "ready" ? "ok" : "wait"}`}>{readinessLabel(execution.status)}</span>
    </div>
    <p className="trade-proposal-warning">Readiness is a current local projection, not a promise that an operation is correct or safe. Real-funds execution is disabled.</p>
    <dl className="commerce-facts">
      <div><dt>Local role</dt><dd>{readinessLabel(execution.local_executor.role)}</dd></div>
      <div><dt>Runtime health</dt><dd>{readinessLabel(execution.coordinator.status)}</dd></div>
      <div><dt>Receipt audit</dt><dd>{execution.coordinator.receipt_persistence_available ? "Connected" : "Unavailable"}</dd></div>
      <div><dt>Local policy</dt><dd>{readinessLabel(execution.executor_policy.status)}</dd></div>
      <div><dt>Adapter</dt><dd>{readinessLabel(execution.adapter.status)}</dd></div>
      <div><dt>Content</dt><dd>{readinessLabel(execution.content.status)}</dd></div>
      <div><dt>Real funds</dt><dd>Disabled</dd></div>
    </dl>
    <code title={execution.order_digest}>{short(execution.order_digest, 42)}</code>
    {execution.error_code && <p className="trade-proposal-warning" role="status">Execution projection unavailable ({execution.error_code}). The signed Agreement remains readable, but no operation is authorized.</p>}
    <div className="trade-execution-column">
      <h3>Trade Skills</h3>
      {execution.skills.length > 0 && <div className="commerce-action">
        <label className="commerce-target">NTH DAO source URL
          <input
            type="url"
            value={skillPeerUrl}
            onChange={(event) => setSkillPeerUrl(event.target.value)}
            onBlur={(event) => {
              const normalized = event.currentTarget.value.trim();
              setSkillPeerUrl(normalized);
              rememberTradeSkillPeer(agreement.order_digest, normalized);
            }}
            placeholder="http://peer-host:8080"
          />
        </label>
        <p className="muted">Package and Recognition fetching is operator-directed. The node verifies signed content and its accepted Order binding before retention. Neither caching nor Recognition evidence grants trust or execution authority.</p>
      </div>}
      {execution.skills.length === 0 ? <p className="muted">No signed Rule Packages are bound to this Agreement.</p> : <ul className="trade-proposal-rules">
        {execution.skills.map((skill) => <li key={skill.package_digest}>
          <div className="trade-execution-row"><strong>{skill.rule_id}</strong><span className={`pill ${skill.status === "available" ? "ok" : "wait"}`}>{readinessLabel(skill.status)}</span></div>
          {skill.summary && <span>{skill.summary}</span>}
          <span className="muted">{skill.version ? `v${skill.version} · ` : ""}{skill.execution_mode ?? "mode unavailable"}</span>
          <code title={skill.package_digest}>{short(skill.package_digest, 34)}</code>
          {skill.status !== "available" && <span className="trade-proposal-warning">{skill.reason}</span>}
          {(skill.status === "missing"
            || skill.reason === "Trade Rule Package import audit is incomplete") && <button
            className="btn btn-secondary"
            type="button"
            disabled={!skillPeerUrl.trim() || Boolean(importingSkill)}
            onClick={() => fetchMissingSkill(skill.package_digest)}
          >{importingSkill === skill.package_digest
              ? "Verifying..."
              : skill.status === "missing"
                ? "Fetch and verify"
                : "Repair signed audit"}</button>}
          {skillImportMessages[skill.package_digest] && <span className={skillImportErrors[skill.package_digest] ? "trade-proposal-warning" : "muted"} role="status">{skillImportMessages[skill.package_digest]}</span>}
        </li>)}
      </ul>}
    </div>
    <AgreementRecognitionEvidence
      orderDigest={agreement.order_digest}
      skills={execution.skills}
      peerUrl={skillPeerUrl}
      onRefresh={onRefresh}
    />
    <div className="trade-execution-column">
      <h3>Operation grants</h3>
      {execution.operation_grants.length === 0 ? <p className="muted">No signed operations were granted.</p> : <ul className="trade-proposal-rules">
        {execution.operation_grants.map((grant) => <li key={grant.operation_id}>
          <div className="trade-execution-row"><strong>{grant.operation_id}</strong><span className="pill wait">{grant.local_executor ? "Role match" : readinessLabel(grant.executor_role)}</span></div>
          <span>{grant.hook_name} · {grant.side_effect}</span>
          <span className="muted">Schema content: {grant.input_schema_content_available && grant.output_schema_content_available ? "available" : "missing"} · Local role: {grant.local_executor ? "authorized" : "not authorized"}</span>
          {grant.permissions.length > 0 && <code>{grant.permissions.join(", ")}</code>}
          {grant.side_effect === "funds" && <span className="trade-proposal-warning">Funds grant retained as signed intent only; execution remains disabled.</span>}
        </li>)}
      </ul>}
    </div>
    {execution.blocking_reasons.length > 0 && <div className="trade-execution-column">
      <h3>Before execution</h3>
      <ul className="trade-readiness-blockers">{execution.blocking_reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
    </div>}
    <div className="trade-execution-column">
      <h3>Execution Receipts</h3>
      <p className="muted">Each item revalidates retained CAS Receipt bytes against its signed Spine anchor. It proves the recorded claim and signer, not delivery quality or payment truth.</p>
      {execution.history.status === "unavailable" && <p className="trade-proposal-warning" role="status">Receipt history unavailable ({execution.history.error_code}). An empty list must not be treated as proof that no execution occurred.</p>}
      {execution.history.status === "available" && historyItems.length === 0 && <p className="muted">No verified execution Receipt is retained for this Agreement.</p>}
      {execution.history.status === "available" && historyItems.length > 0 && <ul className="trade-proposal-rules">
        {historyItems.map((item) => <li key={item.execution_id}>
          <div className="trade-execution-row"><strong>{item.operation_id}</strong><span className={`pill ${item.outcome === "succeeded" ? "ok" : "wait"}`}>{readinessLabel(item.outcome)}</span></div>
          <span>{item.hook_name} · {item.side_effect} · {item.executor_role}</span>
          <span className="muted">Completed {new Date(item.completed_at).toLocaleString()} · Adapter {item.adapter_id} v{item.adapter_version}</span>
          <code title={item.executor_did}>Signer {short(item.executor_did, 30)}</code>
          <code title={item.receipt_digest}>Receipt {short(item.receipt_digest, 34)}</code>
          <code title={item.audit_event_id}>Spine {short(item.audit_event_id, 34)}</code>
        </li>)}
      </ul>}
      {historyError && <p className="trade-proposal-warning" role="status">{historyError} Existing verified Receipts remain visible.</p>}
      {execution.history.status === "available" && historyHasMore && historyCursor !== null && <button className="btn btn-secondary" type="button" disabled={historyBusy} onClick={loadOlderReceipts}>{historyBusy ? "Loading..." : "Load earlier Receipts"}</button>}
    </div>
  </div>;
}

type RecognitionEvidenceLoad =
  | { status: "loading" }
  | { status: "ready"; page: TradeRuleRecognitionImportStatusPage }
  | { status: "error"; error: string };

function recognitionEvidenceLabel(value: RecognitionEvidenceLoad): {
  label: string;
  tone: "ok" | "wait";
} {
  if (value.status === "loading") return { label: "Checking", tone: "wait" };
  if (value.status === "error") return { label: "Unavailable", tone: "wait" };
  const items = value.page?.items ?? [];
  if (items.length === 0) return { label: "Not imported", tone: "wait" };
  if (items.some((item) => item.status === "pending")) {
    return { label: "Recovery pending", tone: "wait" };
  }
  if (items.some((item) => item.evidence_status !== "verified")) {
    return { label: "Evidence damaged", tone: "wait" };
  }
  if (value.page && value.page.returned < value.page.total) {
    return { label: "Partial evidence", tone: "wait" };
  }
  return { label: "Evidence verified", tone: "ok" };
}

function AgreementRecognitionEvidence({
  orderDigest,
  skills,
  peerUrl,
  onRefresh,
}: {
  orderDigest: string;
  skills: TradeExecutionSkillView[];
  peerUrl: string;
  onRefresh: () => void;
}) {
  const toast = useToast();
  const packageDigests = useMemo(
    () => [...new Set(skills.map((skill) => skill.package_digest))].sort(),
    [skills],
  );
  const packageKey = packageDigests.join(",");
  const skillByDigest = useMemo(
    () => new Map(skills.map((skill) => [skill.package_digest, skill])),
    [skills],
  );
  const [loads, setLoads] = useState<Record<string, RecognitionEvidenceLoad>>({});
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [importing, setImporting] = useState("");
  const [importMessages, setImportMessages] = useState<Record<string, string>>({});
  const [importErrors, setImportErrors] = useState<Record<string, boolean>>({});
  const importAbort = useRef<AbortController | null>(null);
  const importGeneration = useRef(0);

  useEffect(() => {
    const controller = new AbortController();
    if (packageDigests.length === 0) {
      setLoads({});
      return () => controller.abort();
    }
    setLoads(Object.fromEntries(packageDigests.map((digest) => [
      digest,
      { status: "loading" as const },
    ])));
    void fetchTradeRuleRecognitionImportBatch(
      orderDigest,
      packageDigests,
      controller.signal,
    ).then((pages) => {
      if (controller.signal.aborted) return;
      setLoads(Object.fromEntries(pages.map((page) => [
        page.package_digest,
        { status: "ready" as const, page },
      ])));
    }).catch((error) => {
      if (isAbort(error) || controller.signal.aborted) return;
      const message = error instanceof Error
        ? error.message
        : "Recognition evidence status failed.";
      setLoads(Object.fromEntries(packageDigests.map((digest) => [
        digest,
        { status: "error" as const, error: message },
      ])));
    });
    return () => controller.abort();
  }, [orderDigest, packageKey, refreshVersion]);

  useEffect(() => {
    importGeneration.current += 1;
    importAbort.current?.abort();
    importAbort.current = null;
    setImporting("");
    setImportMessages({});
    setImportErrors({});
    return () => {
      importGeneration.current += 1;
      importAbort.current?.abort();
      importAbort.current = null;
    };
  }, [orderDigest, packageKey]);

  async function fetchRecognitionEvidence(packageDigest: string) {
    const source = peerUrl.trim();
    const load = loads[packageDigest];
    const skill = skillByDigest.get(packageDigest);
    if (
      !source
      || importing
      || load?.status !== "ready"
      || skill?.status !== "available"
    ) return;
    const damaged = load.page?.items.some(
      (item) => item.evidence_status !== "verified",
    );
    if (damaged) return;
    const generation = importGeneration.current;
    const controller = new AbortController();
    importAbort.current?.abort();
    importAbort.current = controller;
    const isCurrent = () => (
      !controller.signal.aborted
      && importGeneration.current === generation
    );
    setImporting(packageDigest);
    setImportMessages((current) => ({ ...current, [packageDigest]: "" }));
    setImportErrors((current) => ({ ...current, [packageDigest]: false }));
    try {
      const result = await importTradeRuleRecognitions(
        orderDigest,
        packageDigest,
        source,
        controller.signal,
      );
      if (!isCurrent()) return;
      const pageCount = "page_count" in result ? result.page_count : 1;
      const message = result.status === "imported"
        ? `Retained ${result.imported_statement_count} new signed statement(s) from ${pageCount} proof page(s). No trust or execution authority was granted.`
        : `Verified the signed proof across ${pageCount} proof page(s); no new Recognition statements were added. No trust or execution authority was granted.`;
      setImportMessages((current) => ({ ...current, [packageDigest]: message }));
      toast.push(
        result.status === "imported"
          ? "Recognition evidence verified and retained"
          : "Recognition proof verified; no new statements",
        "success",
      );
      setRefreshVersion((value) => value + 1);
      onRefresh();
    } catch (error) {
      if (isAbort(error) || !isCurrent()) return;
      const message = error instanceof Error
        ? error.message
        : "Recognition evidence import failed.";
      setImportMessages((current) => ({ ...current, [packageDigest]: message }));
      setImportErrors((current) => ({ ...current, [packageDigest]: true }));
      toast.push(message, "error");
    } finally {
      if (isCurrent()) {
        importAbort.current = null;
        setImporting("");
      }
    }
  }

  return <div className="trade-execution-column trade-recognition-evidence">
    <h3>Recognition evidence</h3>
    <p className="muted">A verified proof preserves who published an observed Recognition chain and its exact bytes. It does not prove global freshness, fairness, local trust, or execution authority.</p>
    {packageDigests.length === 0 ? <p className="muted">No signed Rule Packages are bound to this Agreement.</p> : <ul className="trade-proposal-rules">
      {packageDigests.map((packageDigest) => {
        const load = loads[packageDigest] ?? { status: "loading" as const };
        const label = recognitionEvidenceLabel(load);
        const skill = skillByDigest.get(packageDigest);
        const items = load.status === "ready" ? load.page.items : [];
        const latest = items.length > 0 ? items[items.length - 1] : undefined;
        const verified = items.filter((item) => (
          item.status === "completed" && item.evidence_status === "verified"
        )).length;
        const pending = items.some((item) => item.status === "pending");
        const damaged = items.some((item) => item.evidence_status !== "verified");
        const canFetch = load.status === "ready"
          && skill?.status === "available"
          && !damaged
          && Boolean(peerUrl.trim());
        const actionLabel = importing === packageDigest
          ? "Verifying..."
          : pending
            ? "Resume evidence import"
            : items.length > 0
              ? "Check for newer evidence"
              : "Fetch signed evidence";
        return <li key={packageDigest}>
          <div className="trade-execution-row">
            <strong>{skill?.rule_id ?? "Bound Trade Skill"}</strong>
            <span className={`pill ${label.tone}`}>{label.label}</span>
          </div>
          <code title={packageDigest}>{short(packageDigest, 34)}</code>
          {load.status === "ready" && <span className="muted">Retained proof records shown: {items.length} of {load.page.total} / verified completions shown: {verified}</span>}
          {latest && <>
            <code title={latest.observer_did}>Signer {short(latest.observer_did, 30)}</code>
            <span className="muted">Source {latest.source_origin}</span>
          </>}
          {load.status === "error" && <span className="trade-proposal-warning" role="status">Status could not be verified: {load.error}</span>}
          {load.status === "ready" && load.page.returned < load.page.total && <span className="trade-proposal-warning" role="status">This bounded status view did not revalidate every retained proof record. Hidden records may be pending or damaged.</span>}
          {items.some((item) => item.status === "pending") && <span className="trade-proposal-warning" role="status">A write-ahead import exists without a completion event. Recovery must finish before this evidence can be used.</span>}
          {items.some((item) => item.evidence_status !== "verified") && <span className="trade-proposal-warning" role="status">Retained proof bytes are missing, corrupt, or no longer match their signed import binding.</span>}
          {damaged && <span className="muted">Automatic refetch is blocked because repair requires the exact signed proof document committed by the audit.</span>}
          {load.status === "ready" && <button
            className="btn btn-secondary"
            type="button"
            disabled={!canFetch || Boolean(importing)}
            onClick={() => fetchRecognitionEvidence(packageDigest)}
          >{actionLabel}</button>}
          {!peerUrl.trim() && <span className="muted">Enter the Agreement peer URL above before fetching evidence.</span>}
          {skill?.status !== "available" && <span className="muted">Verify and cache the exact Trade Skill before importing its Recognition evidence.</span>}
          {importMessages[packageDigest] && <span className={importErrors[packageDigest] ? "trade-proposal-warning" : "muted"} role="status">{importMessages[packageDigest]}</span>}
        </li>;
      })}
    </ul>}
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
