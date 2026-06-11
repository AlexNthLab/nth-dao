/**
 * Phase 1 read API client — typed fetchers for the v2 console.
 *
 * Companion to ``nth_dao/web/v2_api.py``. Every function here
 * targets one endpoint and returns the same shape that lives in
 * ``types-v2.ts``. The frontend never needs to know whether the
 * server is serving from disk or from seed — the shape is the
 * same either way.
 *
 * Failure mode:
 *   Every fetcher throws on network failure or non-2xx status.
 *   Callers (App.tsx) wrap in try/catch and fall back to the local
 *   mock seed — so the UI keeps working when the hub is offline.
 *   This is by design: NTH DAO is local-first. The hub being down
 *   is a normal state, not an error state.
 *
 * Path scheme:
 *   All routes under ``/api/v2/*``. The vite.config.ts proxy
 *   forwards ``/api`` → ``http://127.0.0.1:8080``, so the same
 *   relative URL works in dev (vite) and prod (FastAPI serving
 *   the SPA bundle from ``nth_dao/web/static``).
 */

import type {
  AgentEntry,
  CapTokenSummary,
  ChatMessage,
  Conversation,
  Decision,
  IdentityHeader,
  MissionSummary,
  ProcessCard,
  ReceiptSummary,
  Rule,
} from "./types-v2";

const BASE = "/api/v2";

/** Generic helper. Throws on network error, on non-2xx, and on
 *  JSON parse error — caller decides what to do (typically: fall
 *  back to mock seed). */
async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    signal,
    headers: { Accept: "application/json" },
    credentials: "same-origin",
  });
  if (!res.ok) {
    throw new Error(`GET ${path} → HTTP ${res.status}`);
  }
  return (await res.json()) as T;
}

/** Health probe — returns true if the hub is reachable, false
 *  otherwise. Used to decide once at app boot whether to attempt
 *  the real fetches at all, and what to display in a banner.
 *
 *  Default timeout: 3000ms (P6 fix 2026-06-10). The previous 1200
 *  was an ambiguous middle value — too tight for cold-start (the
 *  FastAPI app's bootstrap reads workspace identity, loads
 *  blackboard, sets up cap_token store; locally this can take
 *  600-1000ms on a cold cache). 3000ms says "tolerate cold start,
 *  but don't pretend a dead server is alive for >3s of white
 *  screen." For localhost-already-warm the round trip is <5ms so
 *  3000ms only kicks in when the hub is genuinely slow or down.
 *
 *  Caller may optionally pass an outer ``signal`` (e.g. from the
 *  bootstrap effect's AbortController): when the caller aborts —
 *  typically on component unmount mid-boot — the probe aborts too
 *  instead of running to completion. */
export async function probeHub(
  timeoutMs = 3000,
  signal?: AbortSignal,
): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const onOuterAbort = () => controller.abort();
  signal?.addEventListener("abort", onOuterAbort);
  try {
    const res = await fetch(`${BASE}/health`, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });
    return res.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onOuterAbort);
  }
}

export const fetchIdentity      = (s?: AbortSignal) =>
  getJson<IdentityHeader>("/identity", s);
export const fetchDecisions     = (s?: AbortSignal) =>
  getJson<Decision[]>("/decisions", s);
export const fetchMissions      = (s?: AbortSignal) =>
  getJson<MissionSummary[]>("/missions", s);
export const fetchProcesses     = (s?: AbortSignal) =>
  getJson<ProcessCard[]>("/processes", s);
export const fetchReceipts      = (s?: AbortSignal) =>
  getJson<ReceiptSummary[]>("/receipts", s);
export const fetchRules         = (s?: AbortSignal) =>
  getJson<Rule[]>("/rules", s);
export const fetchAgents        = (s?: AbortSignal) =>
  getJson<AgentEntry[]>("/agents", s);
export const fetchCapTokens     = (s?: AbortSignal) =>
  getJson<CapTokenSummary[]>("/cap_tokens", s);
export const fetchConversations = (s?: AbortSignal) =>
  getJson<Conversation[]>("/conversations", s);
export const fetchMessages      = (convId: string, s?: AbortSignal) =>
  getJson<ChatMessage[]>(`/messages/${encodeURIComponent(convId)}`, s);

/* ── Phase 2: decision resolve POSTs ──────────────────────────
 * Approve / reject / defer. The hub signs a receipt on approve
 * (chain-linked to the operator's previous content_hash) and
 * returns a ReceiptSummary so the UI can splice it into its
 * receipts state without a /receipts refetch.
 *
 * The shape:
 *   { decision_id, removed: true, signed: true, receipt: ReceiptSummary }
 *   { decision_id, removed: true, signed: false }      // reject / defer
 *
 * Failure surfaces as a thrown Error with the HTTP status — the
 * caller's try/catch in App.tsx maps that to a rollback + toast.
 */
export interface ResolveDecisionResult {
  decision_id: string;
  removed: boolean;
  signed: boolean;
  receipt?: ReceiptSummary;
}

/** S1 fix (2026-06-10): originally this helper had no body
 *  parameter at all despite being named ``postJson``. The next
 *  contributor reading the signature would have reached for it to
 *  send a request body and gotten a silently-empty POST. Body is
 *  now optional but the helper sets ``Content-Type: application/json``
 *  + ``JSON.stringify`` when present, so the name is no longer a
 *  lie. Phase 2 endpoints don't carry a body (id is path param),
 *  but Phase 3 issue-cap / create-mission will. */
async function postJson<T>(path: string, body?: unknown): Promise<T> {
  const init: RequestInit = {
    method: "POST",
    credentials: "same-origin",
    headers: body === undefined
      ? { Accept: "application/json" }
      : { Accept: "application/json", "Content-Type": "application/json" },
  };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }
  const res = await fetch(`${BASE}${path}`, init);
  if (!res.ok) {
    let detail = `${res.status}`;
    try {
      const errBody = await res.json();
      detail = errBody?.detail ?? detail;
    } catch { /* body wasn't JSON; keep status */ }
    throw new Error(`POST ${path} → HTTP ${res.status}: ${detail}`);
  }
  return (await res.json()) as T;
}

export function resolveDecisionApi(
  id: string,
  transition: "approve" | "reject" | "defer",
): Promise<ResolveDecisionResult> {
  return postJson<ResolveDecisionResult>(
    `/decisions/${encodeURIComponent(id)}/${transition}`,
  );
}
