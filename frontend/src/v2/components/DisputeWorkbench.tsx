import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  createTradeDisputeStatement,
  deliverTradeDisputeStatement,
  getTradeDisputeProjection,
  getTradeDisputeStatements,
} from "../api";
import type {
  CreateTradeDisputeStatementInput,
  TradeDisputeGraphResult,
  TradeDisputeStatementItem,
  TradeDisputeStatementPage,
  TradeExecutionHistoryItem,
} from "../types-v2";
import { useToast } from "./Toast";

type LocalRole = "maker" | "taker" | "observer" | "unavailable";
type StatementType = "response" | "evidence" | "remedy-proposal";

class ProjectionSnapshotChanged extends Error {}

type WorkbenchLoad =
  | { status: "loading" }
  | {
    status: "ready";
    page: TradeDisputeStatementPage;
    graph: TradeDisputeGraphResult;
  }
  | { status: "error"; message: string };

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const TOKEN = /^[a-z][a-z0-9._:/-]{0,127}$/;
const REASON = /^[a-z][a-z0-9._:-]{0,127}$/;
const MEDIA_TYPE = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/;
const MAX_CONTENT_BYTES = 16 * 1024 * 1024;

function short(value: string, size = 26) {
  return value.length <= size ? value : `${value.slice(0, size - 7)}...${value.slice(-4)}`;
}

function reasonCodes(value: string): string[] {
  return [...new Set(value.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean))]
    .sort();
}

function newIdempotencyKey(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return `dispute-ui-${Array.from(
    bytes,
    (value) => value.toString(16).padStart(2, "0"),
  ).join("")}`;
}

function validateProjectionBinding(
  page: TradeDisputeStatementPage,
  graph: TradeDisputeGraphResult,
  expectedReviewDigest: string,
) {
  if (graph.graph.review_digest !== expectedReviewDigest) {
    throw new Error("Dispute graph is bound to a different Receipt Review.");
  }
  if (page.snapshot_token !== graph.graph.snapshot_token) {
    throw new ProjectionSnapshotChanged(
      "Dispute statements changed while the local projection was loading.",
    );
  }
  if (page.items.some((item) => (
    item.statement.review_digest !== expectedReviewDigest
    || item.statement.dispute_id !== graph.graph.dispute_id
  ))) {
    throw new Error("Dispute statements and graph do not share one signed dispute binding.");
  }
  if (!graph.graph.items_truncated) {
    const graphDigests = new Set(graph.graph.nodes.map((node) => node.statement_digest));
    if (page.items.some((item) => !graphDigests.has(item.statement_digest))) {
      throw new Error("Dispute graph omits a locally listed statement.");
    }
  }
}

function orderedStatements(
  page: TradeDisputeStatementPage,
  graph: TradeDisputeGraphResult,
): TradeDisputeStatementItem[] {
  const byDigest = new Map(page.items.map((item) => [item.statement_digest, item]));
  const ordered = graph.graph.topological_digests
    .map((digest) => byDigest.get(digest))
    .filter((item): item is TradeDisputeStatementItem => Boolean(item));
  const included = new Set(ordered.map((item) => item.statement_digest));
  return [...ordered, ...page.items.filter((item) => !included.has(item.statement_digest))];
}

export function DisputeWorkbench({
  orderDigest,
  receipt,
  reviewId,
  reviewDigest,
  localRole,
  reviewerDid,
  peerUrl,
}: {
  orderDigest: string;
  receipt: TradeExecutionHistoryItem;
  reviewId: string;
  reviewDigest: string;
  localRole: LocalRole;
  reviewerDid: string;
  peerUrl: string;
}) {
  const toast = useToast();
  const canSign = localRole === "maker" || localRole === "taker";
  const canRespond = canSign && localRole === receipt.executor_role;
  const expectedPeerDid = localRole === receipt.executor_role
    ? reviewerDid
    : receipt.executor_did;
  const [load, setLoad] = useState<WorkbenchLoad>({ status: "loading" });
  const [statementType, setStatementType] = useState<StatementType>(
    canRespond ? "response" : "evidence",
  );
  const [parentDigest, setParentDigest] = useState("");
  const [reasonText, setReasonText] = useState("");
  const [referenceToken, setReferenceToken] = useState(
    canRespond ? "response.summary" : "evidence.artifact",
  );
  const [mediaType, setMediaType] = useState("application/json");
  const [contentDigest, setContentDigest] = useState("");
  const [contentSize, setContentSize] = useState("0");
  const [busy, setBusy] = useState(false);
  const [paging, setPaging] = useState(false);
  const [deliveryBusy, setDeliveryBusy] = useState("");
  const [deliveryStatus, setDeliveryStatus] = useState<Record<string, string>>({});
  const [message, setMessage] = useState("");
  const [messageError, setMessageError] = useState(false);
  const loadAbort = useRef<AbortController | null>(null);
  const submitAbort = useRef<AbortController | null>(null);
  const pageAbort = useRef<AbortController | null>(null);
  const deliveryAbort = useRef<AbortController | null>(null);
  const submitInFlight = useRef(false);
  const generation = useRef(0);
  const idempotency = useRef<{ fingerprint: string; key: string } | null>(null);

  const reload = useCallback(async () => {
    generation.current += 1;
    const currentGeneration = generation.current;
    const controller = new AbortController();
    pageAbort.current?.abort();
    loadAbort.current?.abort();
    loadAbort.current = controller;
    setLoad({ status: "loading" });
    try {
      const projection = await getTradeDisputeProjection(
        orderDigest,
        receipt.execution_id,
        reviewId,
        controller.signal,
      );
      const { page, graph } = projection;
      validateProjectionBinding(page, graph, reviewDigest);
      if (!controller.signal.aborted && generation.current === currentGeneration) {
        setLoad({ status: "ready", page, graph });
        setParentDigest((current) => {
          if (current && page.items.some((item) => item.statement_digest === current)) {
            return current;
          }
          const visible = new Set(page.items.map((item) => item.statement_digest));
          return graph.graph.tip_digests.find((digest) => visible.has(digest)) ?? "";
        });
      }
    } catch (error) {
      if (controller.signal.aborted) return;
      if (generation.current === currentGeneration) {
        setLoad({
          status: "error",
          message: error instanceof Error ? error.message : "Dispute projection failed.",
        });
      }
    } finally {
      if (loadAbort.current === controller) loadAbort.current = null;
    }
  }, [orderDigest, receipt.execution_id, reviewDigest, reviewId]);

  useEffect(() => {
    void reload();
    return () => {
      generation.current += 1;
      loadAbort.current?.abort();
      submitAbort.current?.abort();
      pageAbort.current?.abort();
      deliveryAbort.current?.abort();
    };
  }, [reload]);

  async function loadMore() {
    if (paging || load.status !== "ready" || !load.page.next_cursor) return;
    const currentGeneration = generation.current;
    const controller = new AbortController();
    pageAbort.current?.abort();
    pageAbort.current = controller;
    setPaging(true);
    setMessage("");
    setMessageError(false);
    try {
      const next = await getTradeDisputeStatements(
        orderDigest,
        receipt.execution_id,
        reviewId,
        controller.signal,
        load.page.next_cursor,
      );
      if (controller.signal.aborted || generation.current !== currentGeneration) return;
      if (next.snapshot_token !== load.page.snapshot_token) {
        throw new ProjectionSnapshotChanged(
          "Dispute statements changed while loading the next page. Reload the projection.",
        );
      }
      const existing = new Set(load.page.items.map((item) => item.statement_digest));
      if (next.items.some((item) => existing.has(item.statement_digest))) {
        throw new Error("Dispute pagination returned a duplicate signed claim.");
      }
      setLoad({
        status: "ready",
        graph: load.graph,
        page: {
          ...load.page,
          items: [...load.page.items, ...next.items],
          next_cursor: next.next_cursor,
        },
      });
    } catch (error) {
      if (controller.signal.aborted || generation.current !== currentGeneration) return;
      setMessageError(true);
      setMessage(error instanceof Error ? error.message : "Dispute pagination failed.");
    } finally {
      if (pageAbort.current === controller) pageAbort.current = null;
      setPaging(false);
    }
  }

  async function deliverStatement(item: TradeDisputeStatementItem) {
    if (deliveryBusy || item.statement.author_role !== localRole) return;
    const targetUrl = peerUrl.trim();
    if (!targetUrl) {
      setMessageError(true);
      setMessage("Enter the Agreement peer URL before delivering this signed claim.");
      return;
    }
    const controller = new AbortController();
    deliveryAbort.current?.abort();
    deliveryAbort.current = controller;
    setDeliveryBusy(item.statement_digest);
    setMessage("");
    setMessageError(false);
    try {
      const result = await deliverTradeDisputeStatement(
        orderDigest,
        receipt.execution_id,
        reviewId,
        item.statement_digest,
        receipt.receipt_digest,
        reviewDigest,
        item.statement.author_did,
        expectedPeerDid,
        targetUrl,
        controller.signal,
      );
      if (controller.signal.aborted) return;
      setDeliveryStatus((current) => ({
        ...current,
        [item.statement_digest]: `Peer ACK ${short(result.acknowledgement_digest, 30)} retained locally.`,
      }));
      toast.push("Signed dispute claim acknowledged by peer", "success");
    } catch (error) {
      if (controller.signal.aborted) return;
      const detail = error instanceof Error ? error.message : "Dispute delivery failed.";
      setMessageError(true);
      setMessage(detail);
      toast.push(detail, "error");
    } finally {
      if (deliveryAbort.current === controller) deliveryAbort.current = null;
      setDeliveryBusy("");
    }
  }

  useEffect(() => {
    if (statementType === "response" && !canRespond) {
      setStatementType("evidence");
      setReferenceToken("evidence.artifact");
    }
  }, [canRespond, statementType]);

  const items = useMemo(
    () => load.status === "ready" ? orderedStatements(load.page, load.graph) : [],
    [load],
  );

  function changeStatementType(value: StatementType) {
    setStatementType(value);
    setReferenceToken(
      value === "response"
        ? "response.summary"
        : value === "evidence"
          ? "evidence.artifact"
          : "remedy.proposal",
    );
    setMessage("");
    setMessageError(false);
  }

  async function signStatement() {
    if (busy || submitInFlight.current || !canSign || load.status !== "ready") return;
    if (statementType === "response" && !canRespond) {
      setMessageError(true);
      setMessage("Only the Receipt executor can sign a response statement.");
      return;
    }
    const reasons = reasonCodes(reasonText);
    const parsedSize = Number(contentSize);
    if (!TOKEN.test(referenceToken)) {
      setMessageError(true);
      setMessage("Reference type must be a lowercase protocol token.");
      return;
    }
    if (!MEDIA_TYPE.test(mediaType) || mediaType.length > 127) {
      setMessageError(true);
      setMessage("Media type must be a lowercase type/subtype value.");
      return;
    }
    if (!DIGEST.test(contentDigest)) {
      setMessageError(true);
      setMessage("Content must be pinned by a lowercase sha256 digest.");
      return;
    }
    if (!/^(0|[1-9][0-9]*)$/.test(contentSize) || parsedSize > MAX_CONTENT_BYTES) {
      setMessageError(true);
      setMessage("Content size must be an integer from 0 to 16777216 bytes.");
      return;
    }
    if (
      reasons.length > 32
      || reasons.some((reason) => !REASON.test(reason))
      || (statementType !== "evidence" && reasons.length === 0)
    ) {
      setMessageError(true);
      setMessage(
        statementType === "evidence"
          ? "Evidence statements do not accept reason codes."
          : "Response and remedy statements require 1-32 lowercase reason codes.",
      );
      return;
    }
    const reference = {
      media_type: mediaType,
      digest: contentDigest,
      size: parsedSize,
    };
    const input: CreateTradeDisputeStatementInput = statementType === "evidence"
      ? {
        statement_type: "evidence",
        parent_statement_digests: parentDigest ? [parentDigest] : [],
        reason_codes: [],
        claim: null,
        evidence: [{ purpose: referenceToken, ...reference }],
        rule_action: null,
      }
      : {
        statement_type: statementType,
        parent_statement_digests: parentDigest ? [parentDigest] : [],
        reason_codes: reasons,
        claim: {
          claim_type: referenceToken,
          ...reference,
          schema_digest: null,
        },
        evidence: [],
        rule_action: null,
      };
    const fingerprint = JSON.stringify({
      order_digest: orderDigest,
      execution_id: receipt.execution_id,
      review_id: reviewId,
      input,
    });
    let key: string;
    try {
      if (!idempotency.current || idempotency.current.fingerprint !== fingerprint) {
        idempotency.current = { fingerprint, key: newIdempotencyKey() };
      }
      key = idempotency.current.key;
    } catch {
      setMessageError(true);
      setMessage("Secure browser randomness is unavailable; statement signing is disabled.");
      return;
    }
    const controller = new AbortController();
    submitInFlight.current = true;
    submitAbort.current?.abort();
    submitAbort.current = controller;
    setBusy(true);
    setMessage("");
    setMessageError(false);
    try {
      const result = await createTradeDisputeStatement(
        orderDigest,
        receipt.execution_id,
        reviewId,
        input,
        key,
        controller.signal,
      );
      if (controller.signal.aborted) return;
      idempotency.current = null;
      setMessage(
        `Signed claim ${short(result.statement_digest, 30)} retained and anchored. It remains unadjudicated.`,
      );
      toast.push("Dispute claim signed", "success");
      await reload();
    } catch (error) {
      if (controller.signal.aborted) return;
      const detail = error instanceof Error ? error.message : "Dispute statement failed.";
      setMessageError(true);
      setMessage(detail);
      toast.push(detail, "error");
    } finally {
      if (submitAbort.current === controller) submitAbort.current = null;
      submitInFlight.current = false;
      setBusy(false);
    }
  }

  return <section className="trade-dispute-workbench" aria-labelledby={`dispute-${reviewId}`}>
    <div className="trade-execution-row">
      <h4 id={`dispute-${reviewId}`}>Dispute statements</h4>
      {load.status === "ready" && <span className={`pill ${load.graph.graph.graph_status === "complete" ? "ok" : "wait"}`}>
        {load.graph.graph.graph_status === "complete" ? "Local DAG complete" : `Local DAG ${load.graph.graph.graph_status}`}
      </span>}
    </div>
    <p className="trade-dispute-caution" role="note">
      Signed statements are claims, not verified facts. Graph completeness only describes this node's current retained snapshot.
    </p>
    {load.status === "loading" && <p className="muted" role="status">Loading signed claims and local ancestry...</p>}
    {load.status === "error" && <p className="trade-proposal-warning" role="status">
      {load.message} <button className="btn btn-secondary" type="button" onClick={() => void reload()}>Retry dispute view</button>
    </p>}
    {load.status === "ready" && <>
      <div className="trade-dispute-summary" aria-label="Local dispute graph summary">
        <span><strong>{load.graph.graph.statement_count}</strong> signed claims</span>
        <span><strong>{load.graph.graph.tip_count}</strong> tips</span>
        <span><strong>{load.graph.graph.unresolved_parent_count}</strong> unresolved parents</span>
      </div>
      {(load.graph.graph.graph_status !== "complete" || load.graph.graph.items_truncated) && <p className="trade-proposal-warning" role="status">
        This local projection is incomplete{load.graph.graph.items_truncated ? " and truncated" : ""}. Do not infer global dispute state from it.
      </p>}
      {load.graph.graph.issues.length > 0 && <ul className="trade-dispute-issues" aria-label="Dispute graph issues">
        {load.graph.graph.issues.map((issue, index) => <li key={`${issue.statement_digest}:${issue.parent_digest}:${index}`}>
          {issue.reason}: <code>{short(issue.parent_digest, 30)}</code>
        </li>)}
      </ul>}
      {items.length === 0
        ? <p className="muted">No signed follow-up claims are retained on this node.</p>
        : <ol className="trade-dispute-statements" aria-label="Signed dispute statements">
          {items.map((item) => <li key={item.statement_digest}>
            <div className="trade-execution-row">
              <strong>{item.statement.statement_type}</strong>
              <span className={`pill ${item.audit_status === "anchored" ? "ok" : "wait"}`}>{item.audit_status}</span>
            </div>
            <code title={item.statement.author_did}>Signer {short(item.statement.author_did, 34)}</code>
            <code title={item.statement_digest}>Claim {short(item.statement_digest, 34)}</code>
            {item.statement.reason_codes.length > 0 && <span className="muted">Reasons: {item.statement.reason_codes.join(", ")}</span>}
            {item.statement.claim && <code title={item.statement.claim.digest}>Content {short(item.statement.claim.digest, 34)}</code>}
            {item.statement.evidence.map((evidence, index) => <code key={`${evidence.digest}:${index}`} title={evidence.digest}>
              Evidence {short(evidence.digest, 34)}
            </code>)}
            {item.statement.author_role === localRole && <button
              className="btn btn-secondary"
              type="button"
              disabled={Boolean(deliveryBusy) || !peerUrl.trim()}
              onClick={() => void deliverStatement(item)}
            >{deliveryBusy === item.statement_digest ? "Delivering claim..." : "Deliver / retry claim"}</button>}
            {deliveryStatus[item.statement_digest] && <span className="muted" role="status">
              {deliveryStatus[item.statement_digest]}
            </span>}
          </li>)}
        </ol>}
      {load.page.next_cursor && <button
        className="btn btn-secondary"
        type="button"
        disabled={paging}
        onClick={() => void loadMore()}
      >{paging ? "Loading claims..." : "Load more signed claims"}</button>}
      {canSign ? <div className="trade-dispute-form">
        <label>Statement type
          <select value={statementType} onChange={(event) => changeStatementType(event.target.value as StatementType)}>
            {canRespond && <option value="response">Response by Receipt executor</option>}
            <option value="evidence">Evidence reference</option>
            <option value="remedy-proposal">Remedy proposal</option>
          </select>
        </label>
        <label>Parent claim
          <select value={parentDigest} onChange={(event) => setParentDigest(event.target.value)}>
            <option value="">Start a new root</option>
            {load.page.items.map((item) => <option key={item.statement_digest} value={item.statement_digest}>
              {item.statement.statement_type} | {short(item.statement_digest, 28)}
            </option>)}
          </select>
        </label>
        {statementType !== "evidence" && <label>Reason codes
          <input value={reasonText} onChange={(event) => setReasonText(event.target.value)} placeholder="result.mismatch" />
        </label>}
        <label>{statementType === "evidence" ? "Evidence purpose" : "Claim type"}
          <input value={referenceToken} onChange={(event) => setReferenceToken(event.target.value)} />
        </label>
        <label>Content media type
          <input value={mediaType} onChange={(event) => setMediaType(event.target.value)} />
        </label>
        <label>Content SHA-256 digest
          <input value={contentDigest} onChange={(event) => setContentDigest(event.target.value)} placeholder="sha256:..." spellCheck={false} />
        </label>
        <label>Content size in bytes
          <input type="number" min="0" max={MAX_CONTENT_BYTES} step="1" value={contentSize} onChange={(event) => setContentSize(event.target.value)} />
        </label>
        <button className="btn btn-secondary" type="button" disabled={busy} onClick={() => void signStatement()}>
          {busy ? "Signing claim..." : "Sign unadjudicated claim"}
        </button>
      </div> : <p className="muted">Observer access is read-only. A local maker or taker identity is required to sign a claim.</p>}
    </>}
    {message && <p className={messageError ? "trade-proposal-warning" : "muted"} role="status">{message}</p>}
  </section>;
}
