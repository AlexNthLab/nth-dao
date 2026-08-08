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
  AnnounceTaskInput,
  CapTokenSummary,
  Channel,
  ChannelMessage,
  ChatMessage,
  Conversation,
  ConversationSummary,
  CommerceListingRow,
  CommerceOrderView,
  Decision,
  HandoffDetail,
  IdentityHeader,
  FederationStatus,
  MarketSearchCategory,
  MarketSearchIntent,
  MarketSearchPage,
  MissionSummary,
  ReceiptDetail,
  ProcessCard,
  PublishMarketOfferInput,
  PublishMarketOfferResult,
  ReceiptSummary,
  ResourceProfileImportResult,
  ResourceProfilePage,
  ResourceProfileRecognitionResult,
  Rule,
  TaskAnnouncement,
  TaskCategory,
  TradeOfferImportResult,
  TradeOfferInspection,
  TradeProposalDetail,
  TradeProposalAcceptanceResult,
  TradeProposalPage,
  TradeExecutionHistoryPage,
  TradeOrderDetail,
  TradeOrderPage,
  TradeRuleRecognitionImportResult,
  TradeRuleRecognitionImportStatusItem,
  TradeRuleRecognitionImportStatusPage,
  TradeRuleRecognitionImportStatusBatch,
  TradeRulePackageImportResult,
  TradeRulePackageCatalogItem,
  TradeRulePackageCatalogPage,
  TradeRulePackageDetail,
} from "./types-v2";

const BASE = "/api/v2";
const TRADE_INBOX_PAGE_SIZE = "100";
const TRADE_INBOX_PAGE_LIMIT = Number(TRADE_INBOX_PAGE_SIZE);
const TRADE_RECOGNITION_STATUS_BATCH_SIZE = 64;
const TRADE_RECOGNITION_STATUS_MAX_PACKAGES = 256;

export class ApiHttpError extends Error {
  readonly status: number;
  readonly path: string;

  constructor(method: string, path: string, status: number) {
    super(`${method} ${path} -> HTTP ${status}`);
    this.name = "ApiHttpError";
    this.status = status;
    this.path = path;
  }
}

/** Console Bearer token, injected into the served HTML by the hub
 *  (``window.__NTH_CONSOLE_TOKEN__``). v2 READ endpoints are open
 *  (anonymous), but v2 ACTION endpoints (spawn / stop / ask) are
 *  gated on console auth when it's enabled (2026-06-13 hardening).
 *  Attaching the token on writes makes the v2 console work in a
 *  hardened (auth-on) deployment; in the local default (auth off)
 *  the server ignores it. Returns ``{}`` when no token is present
 *  so callers can spread it unconditionally. */
/** 温层(切片2b):请求服务端把一段对话压成**签名摘要**(后端 make+verify)。
 *  not-yet-authorized 窗口内自动重试。前端不验签 —— verified 由后端给。 */
export async function summarizeAgent(
  did: string,
  messages: ChatMessage[],
  conversationId: string,
  instruction?: string,
  tries = 20,
): Promise<ConversationSummary> {
  let last = "";
  for (let i = 0; i < tries; i++) {
    const res = await fetch(
      `${BASE}/agents/${encodeURIComponent(did)}/summarize`,
      {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          ...authHeader(),
        },
        body: JSON.stringify({
          messages,
          conversation_id: conversationId,
          ...(instruction ? { instruction } : {}),
        }),
      },
    );
    if (res.ok) {
      const rec = (await res.json()) as ConversationSummary;
      return { ...rec, created_at: new Date().toISOString() };
    }
    last = await res.text();
    if (last.includes("not-yet-authorized")) {
      await new Promise((r) => setTimeout(r, 600));
      continue;
    }
    throw new Error(`summarize → HTTP ${res.status}: ${last.slice(0, 160)}`);
  }
  throw new Error(`summarize: agent not ready (${last.slice(0, 80)})`);
}

function authHeader(): Record<string, string> {
  if (typeof window === "undefined") return {};
  const tok = (window as unknown as { __NTH_CONSOLE_TOKEN__?: string })
    .__NTH_CONSOLE_TOKEN__;
  return tok ? { Authorization: `Bearer ${tok}` } : {};
}

/** Generic helper. Throws on network error, on non-2xx, and on
 *  JSON parse error — caller decides what to do (typically: fall
 *  back to mock seed). */
async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    signal,
    headers: { Accept: "application/json", ...authHeader() },
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

/** 把 mission 从 planning/paused 推进到 active(开始执行)。返回新 summary。 */
export function fetchMissionHandoffs(
  missionId: string,
  includeDetails = true,
  signal?: AbortSignal,
): Promise<HandoffDetail[]> {
  const p = new URLSearchParams();
  p.set("mission_id", missionId);
  if (includeDetails) p.set("include_details", "true");
  return getJson<HandoffDetail[]>(`/handoffs?${p.toString()}`, signal);
}

export function fetchHandoffReviewPacket(
  capsuleHash: string,
  signal?: AbortSignal,
): Promise<Record<string, unknown>> {
  return getJson<Record<string, unknown>>(
    `/handoffs/${encodeURIComponent(capsuleHash)}/review_packet`,
    signal,
  );
}

export async function activateMission(id: string): Promise<MissionSummary> {
  return postJson<MissionSummary>(
    `/missions/${encodeURIComponent(id)}/activate`,
  );
}

export async function runMissionStep(
  missionId: string,
  stepId: string,
  input?: { agentDid?: string; prompt?: string },
): Promise<MissionSummary> {
  return postJson<MissionSummary>(
    `/missions/${encodeURIComponent(missionId)}/steps/${encodeURIComponent(stepId)}/run`,
    {
      agent_did: input?.agentDid ?? "",
      prompt: input?.prompt ?? "",
    },
  );
}

/** 真正创建一个 mission(落后端 store)。steps 是描述列表,每条转成
 *  {description, required_capabilities}。返回真实(非 m-local-)的 summary。 */
export async function createMission(input: {
  title: string;
  goal?: string;
  driver?: string;
  driverDid?: string;
  steps?: string[];
}): Promise<MissionSummary> {
  return postJson<MissionSummary>("/missions", {
    title: input.title,
    goal: input.goal ?? "",
    driver: input.driver ?? "",
    driver_did: input.driverDid ?? "",
    steps: (input.steps ?? []).map((d) => ({
      description: d,
      required_capabilities: [],
    })),
  });
}
export const fetchProcesses     = (s?: AbortSignal) =>
  getJson<ProcessCard[]>("/processes", s);
export async function createProcess(input: {
  title: string;
  workflow: string;
  subtitle?: string;
  current_agent: string;
}): Promise<ProcessCard> {
  return postJson<ProcessCard>("/processes", {
    title: input.title,
    workflow: input.workflow,
    subtitle: input.subtitle ?? "",
    current_agent: input.current_agent,
    stage: "received",
  });
}
export const fetchReceipts      = (s?: AbortSignal) =>
  getJson<ReceiptSummary[]>("/receipts", s);

export async function fetchReceiptDetail(
  receiptId: string,
  signal?: AbortSignal,
): Promise<ReceiptDetail> {
  const path = `/receipts/${encodeURIComponent(receiptId)}`;
  const res = await fetch(`${BASE}${path}`, {
    signal,
    headers: { Accept: "application/json", ...authHeader() },
    credentials: "same-origin",
  });
  if (!res.ok) {
    throw new ApiHttpError("GET", path, res.status);
  }
  return (await res.json()) as ReceiptDetail;
}
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

export const fetchCommerceListings = (s?: AbortSignal) =>
  getJson<CommerceListingRow[]>("/commerce/listings", s);

export const fetchCommerceOrders = (
  role?: "buyer" | "seller", signal?: AbortSignal,
) => getJson<CommerceOrderView[]>(
  `/commerce/orders${role ? `?role=${role}` : ""}`, signal,
);

export const fetchCommerceOrder = (orderId: string, signal?: AbortSignal) =>
  getJson<CommerceOrderView>(`/commerce/orders/${encodeURIComponent(orderId)}`, signal);

export function publishCommerceListing(input: {
  listingId: string;
  title: string;
  description?: string;
  priceValue: string;
  capabilities?: string[];
}) {
  return postJson<{ digest: string; listing: unknown; warning: string }>(
    "/commerce/listings",
    {
      listing_id: input.listingId,
      title: input.title,
      description: input.description ?? "",
      price_value: input.priceValue,
      capabilities: input.capabilities ?? [],
    },
  );
}

export function remoteCommerceCheckout(input: {
  targetUrl: string;
  listingDigest: string;
  purpose?: string;
  idempotencyKey: string;
}) {
  return postJson<{ order: CommerceOrderView; delivery: { status: string; error?: string }; warning: string }>(
    "/commerce/checkout/remote",
    {
      target_url: input.targetUrl,
      listing_digest: input.listingDigest,
      purpose: input.purpose ?? "purchase digital service",
      idempotency_key: input.idempotencyKey,
    },
  );
}

export function submitCommerceDelivery(
  orderId: string, delivery: Record<string, unknown>, targetUrl = "",
) {
  return postJson<CommerceActionResult>(
    `/commerce/orders/${encodeURIComponent(orderId)}/delivery`,
    { delivery, target_url: targetUrl },
  );
}

export function verifyCommerceDelivery(
  orderId: string, verdict: "pass" | "fail", result: Record<string, unknown>, targetUrl = "",
) {
  return postJson<CommerceActionResult>(
    `/commerce/orders/${encodeURIComponent(orderId)}/verify`,
    { verdict, result, target_url: targetUrl },
  );
}

export function settleCommerceOrder(orderId: string, targetUrl = "") {
  return postJson<CommerceActionResult>(
    `/commerce/orders/${encodeURIComponent(orderId)}/settle`,
    { target_url: targetUrl },
  );
}

export function disputeCommerceOrder(
  orderId: string, reason: string, targetUrl = "",
) {
  return postJson<CommerceActionResult>(
    `/commerce/orders/${encodeURIComponent(orderId)}/dispute`,
    { reason, evidence: {}, target_url: targetUrl },
  );
}

export function resolveCommerceDispute(
  orderId: string, resolution: "settle" | "refund", targetUrl = "",
) {
  return postJson<CommerceActionResult>(
    `/commerce/orders/${encodeURIComponent(orderId)}/resolve`,
    { resolution, rationale: "Operator decision", target_url: targetUrl },
  );
}

export interface CommerceActionResult {
  order: CommerceOrderView;
  warning: string;
  queued?: { message_id: string; status: string; error?: string } | null;
}

export function dispatchCommerceOutbox() {
  return postJson<Array<{ message_id: string; status: string; error?: string }>>(
    "/commerce/outbox/dispatch",
  );
}

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
async function postJson<T>(
  path: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  const init: RequestInit = {
    method: "POST",
    signal,
    credentials: "same-origin",
    headers: body === undefined
      ? { Accept: "application/json", ...authHeader() }
      : { Accept: "application/json", "Content-Type": "application/json", ...authHeader() },
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

/* ── Phase 3f: A2A proxy fetchers ─────────────────────────────
 * The hub at /api/v2/agents/{did}/{ping|a2a/<method>} forwards
 * to the child's localhost HTTP surface. /ping requires no auth
 * and returns the child's identity card. /a2a/echo (and future
 * methods) requires Authorization: CapToken; without it the
 * child returns 401 — which is itself a useful demonstration
 * that the auth wire is live.
 *
 * The frontend doesn't sign its OWN cap_token (no access to the
 * hub's private key from the browser), so the A2A test button
 * sends an unsigned request. The expected outcome is a 401 with
 * a structured error body; the UI renders both the success and
 * the rejection paths so the operator can see the auth flow.
 */

/** Result shape of GET /api/v2/agents/{did}/ping —
 *  the child's identity card with live uptime. */
export interface A2APingResult {
  agent_id: string;
  kind: string;
  did: string;
  pubkey_hex: string;
  started_at: number;
  uptime_ms: number;
}

/** Result shape of POST /api/v2/agents/{did}/a2a/echo —
 *  either ``result`` (200) or ``error`` (4xx/5xx forwarded). */
export interface A2AEchoEnvelope {
  /** Set when the call succeeded. */
  result?: {
    method: string;
    received_params: Record<string, unknown>;
    caller_did: string;
    agent_did: string;
  };
  /** Set when the child or hub rejected the call. */
  error?: {
    code: string;
    message: string;
  };
}

/** Shape of what ``a2aEchoApi`` resolves with — the parsed body
 *  + the HTTP status so the UI can color-code success vs auth-
 *  rejection vs upstream failure. */
export interface A2ACallResponse {
  status: number;
  body: A2AEchoEnvelope | Record<string, unknown>;
}

/** Phase 3f BUG-2 fix (review round R1): return ``{status, body}``
 *  rather than throwing on non-2xx — same shape as ``a2aEchoApi``
 *  so the UI handler can color-code 404/502/503 separately instead
 *  of collapsing all failures to "ping ERR" with status 0. The
 *  body parse is best-effort; on a non-JSON response we still
 *  surface the HTTP status. */
export async function pingAgentApi(
  did: string, signal?: AbortSignal,
): Promise<A2ACallResponse> {
  const res = await fetch(
    `${BASE}/agents/${encodeURIComponent(did)}/ping`,
    {
      signal,
      headers: { Accept: "application/json" },
      credentials: "same-origin",
    },
  );
  let body: A2AEchoEnvelope | Record<string, unknown>;
  try {
    // Both A2APingResult (success) and the hub's error envelope
    // are valid object shapes; cast through the union for the
    // typed return without per-field narrowing here.
    body = (await res.json()) as Record<string, unknown>;
  } catch {
    body = { error: { code: "parse-failed", message: "non-JSON response" } };
  }
  return { status: res.status, body };
}

/** Result of a completed agent task run. */
export interface AskAgentResult {
  text: string;
  backend?: string;
  model?: string;
}

export interface AgentLinkJob {
  job_id: string;
  agent_id: string;
  agent_did: string;
  state: "accepted" | "processing" | "completed" | "completed_unverified" | "failed" | "delivery_unknown" | string;
  created_at: string;
  updated_at: string;
  response?: string;
  receipt_id?: string;
  error?: string;
}

export const submitAgentLink = (
  did: string,
  prompt: string,
  idempotencyKey: string,
  signal?: AbortSignal,
  timeoutS?: number,
) => postJson<Pick<AgentLinkJob, "job_id" | "agent_did" | "state">>(
  `/agents/${encodeURIComponent(did)}/link`,
  {
    prompt,
    idempotency_key: idempotencyKey,
    ...(timeoutS === undefined ? {} : { timeout_s: timeoutS }),
  },
  signal,
);

export const getAgentLink = (did: string, jobId: string, signal?: AbortSignal) =>
  getJson<AgentLinkJob>(
    `/agents/${encodeURIComponent(did)}/link/${encodeURIComponent(jobId)}`,
    signal,
  );

export const reconcileAgentLink = (
  did: string,
  jobId: string,
  receipt: Record<string, unknown>,
  response: string,
  signal?: AbortSignal,
) => postJson<AgentLinkJob>(
  `/agents/${encodeURIComponent(did)}/link/${encodeURIComponent(jobId)}/reconcile`,
  { receipt, response },
  signal,
);

export interface BackendStatus {
  kind: string;
  label: string;
  ready: boolean;
  available: boolean;
  runtime?: string;
  detail: string;
  warning?: string;
  ask_timeout_s?: number;
  transport_ready?: boolean;
  provider_verified?: boolean;
  provider_state?: "unverified" | "ready" | "degraded" | string;
  last_provider_check_at?: string;
  version?: string;
}

export interface BackendStatusResponse {
  backends: Record<string, BackendStatus>;
}

export interface SpawnAgentRequest {
  kind: string;
  label?: string;
  capabilities?: string[];
  persist?: boolean;
  project_workdir?: string;
  work_access?: "read-only" | "workspace-write";
}

export interface SpawnAgentResponse {
  agent_id: string;
  did: string;
  kind: string;
  label: string;
  pid?: number | null;
  cap_token_id?: string;
  a2a_port?: number;
  agent: AgentEntry;
}

export interface AddAgentByDidResponse {
  ok: boolean;
  agent_id: string;
  did: string;
  label: string;
}

export interface LanPeer {
  agent_id: string;
  label: string;
  capabilities: string[];
  groups: string[];
  ws_url: string;
  pubkey_hex: string;
  pubkey_prefix?: string;
  did?: string;
  source_addr: string;
  rtt_ms: number;
}

export const fetchBackendStatus = (signal?: AbortSignal) =>
  getJson<BackendStatusResponse>("/agents/backends/status", signal);

export const spawnAgent = (body: SpawnAgentRequest) =>
  postJson<SpawnAgentResponse>("/agents/spawn", body);

export const stopAgent = (agentId: string) =>
  postJson<{ agent_id: string; stopped: boolean }>(`/agents/${encodeURIComponent(agentId)}/stop`);

export function addAgentByDid(input: {
  actorId: string;
  didOrAgentId: string;
  label?: string;
}): Promise<AddAgentByDidResponse> {
  const value = input.didOrAgentId.trim();
  const isDid = value.startsWith("did:key:");
  return postJson<AddAgentByDidResponse>("/agents/add", {
    actor_id: input.actorId,
    target_agent_id: isDid ? "" : value,
    target_did: isDid ? value : "",
    label: input.label ?? "",
  });
}

export async function discoverLanAgents(input: {
  actorId: string;
  timeoutSeconds?: number;
  wantedCapabilities?: string[];
}): Promise<AgentEntry[]> {
  const data = await postJson<{ peers: LanPeer[] }>("/agents/lan_discover", {
    actor_id: input.actorId,
    timeout_seconds: input.timeoutSeconds ?? 2,
    wanted_capabilities: input.wantedCapabilities ?? [],
  });
  return data.peers
    .filter((peer) => peer.did || peer.pubkey_hex || peer.agent_id)
    .map((peer) => {
      const stableId = peer.did || peer.agent_id || peer.pubkey_hex;
      return {
        did: stableId,
        code: peer.pubkey_prefix || peer.agent_id.slice(0, 8),
        label: peer.label || peer.agent_id || "LAN peer",
        source: "lan",
        capabilities: peer.capabilities ?? [],
        last_seen: new Date().toISOString(),
        has_active_cap: false,
        agent_card: {
          agent_id: peer.agent_id,
          groups: peer.groups ?? [],
          ws_url: peer.ws_url,
          source_addr: peer.source_addr,
          rtt_ms: peer.rtt_ms,
          pubkey_prefix: peer.pubkey_prefix,
          did: peer.did || "",
          pubkey_hex: peer.pubkey_hex,
        },
      };
    });
}

/** UI 集成（2026-06-13）：驱动一个 spawn 出来的 agent 跑一个任务，**流式**
 *  接收输出。打的是 hub 端点 ``POST /api/v2/agents/{did}/ask-stream`` ——
 *  hub 替操作员注入该 agent 的 cap_token（浏览器没有签名私钥，详见
 *  v2_api ``_agent_ask`` docstring）。
 *
 *  读 SSE 流：每个 ``data: {...}`` 事件 —— ``{delta}`` 调 onDelta 追加；
 *  ``{done,...}`` 收尾带 backend/model；``{error}`` 抛错。返回拼好的全文 +
 *  backend/model。
 */
export async function askAgentStream(
  did: string,
  prompt: string,
  onDelta: (delta: string) => void,
  signal?: AbortSignal,
  onStatus?: (status: string) => void,
  idleTimeoutMs = 120_000,
  backendTimeoutS?: number,
): Promise<AskAgentResult> {
  const maxWarmupAttempts = 6;
  const warmupDelayMs = 750;
  onStatus?.("authorizing");
  // 传输层兜底:在调用方 signal 之外再加"空闲超时"。收到响应头、以及每
  // 个数据块都重置计时;idleTimeoutMs 内毫无动静则 abort——否则后端永久
  // 挂起时 UI 的"思考中"三点会一直转(handleChatSend 捕获后清 typing+报错)。
  // 用空闲(而非总时长)阈值:只要还在出 token 的慢流不会被误杀。
  const ctl = new AbortController();
  const onExternalAbort = () => ctl.abort();
  if (signal) {
    if (signal.aborted) ctl.abort();
    else signal.addEventListener("abort", onExternalAbort, { once: true });
  }
  let timedOut = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const arm = () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      timedOut = true;
      ctl.abort();
    }, idleTimeoutMs);
  };
  const disarm = () => {
    if (timer) clearTimeout(timer);
    signal?.removeEventListener("abort", onExternalAbort);
  };

  class AskStreamEventError extends Error {
    code: string;
    constructor(code: string, message: string) {
      super(`agent error: ${code} — ${message}`);
      this.code = code;
    }
  }

  const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
  const isWarmupError = (err: unknown) => {
    if (!(err instanceof AskStreamEventError)) return false;
    return err.code === "upstream-401"
      || err.code === "upstream-502"
      || err.code === "proxy-failed";
  };

  arm();
  try {
    for (let attempt = 1; attempt <= maxWarmupAttempts; attempt += 1) {
      onStatus?.(attempt === 1 ? "authorizing" : `warming:${attempt}`);
      let text = "";
      let backend: string | undefined;
      let model: string | undefined;
      try {
        const body: Record<string, unknown> = { prompt };
        if (typeof backendTimeoutS === "number" && Number.isFinite(backendTimeoutS)) {
          body.timeout_s = backendTimeoutS;
        }
        const res = await fetch(
          `${BASE}/agents/${encodeURIComponent(did)}/ask-stream`,
          {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json", Accept: "text/event-stream", ...authHeader() },
            body: JSON.stringify(body),
            signal: ctl.signal,
          },
        );
        arm(); // 收到响应头 → 重置空闲计时
        if (!res.ok || !res.body) {
          // 非流式错误（404/409/502…）—— 读 JSON 错误体给出可读消息。
          let detail = `HTTP ${res.status}`;
          try {
            const j = (await res.json()) as Record<string, unknown>;
            detail = JSON.stringify(j).slice(0, 300);
          } catch { /* keep HTTP status */ }
          throw new Error(`ask-stream failed: ${detail}`);
        }

        onStatus?.(attempt === 1 ? "waiting" : `warming:${attempt}`);
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buf = "";

        const handleEvent = (raw: string) => {
          // 一个 SSE 事件可能有多行；只取 ``data:`` 行。
          const dataLines = raw
            .split("\n")
            .filter((l) => l.startsWith("data:"))
            .map((l) => l.slice(5).trim());
          if (dataLines.length === 0) return;
          const payloadStr = dataLines.join("\n");
          let ev: Record<string, unknown>;
          try {
            ev = JSON.parse(payloadStr) as Record<string, unknown>;
          } catch {
            return; // 半截/非 JSON 事件，忽略
          }
          if (typeof ev.delta === "string") {
            if (!text) onStatus?.("streaming");
            text += ev.delta;
            onDelta(ev.delta);
          } else if (ev.error) {
            const e = ev.error as Record<string, unknown>;
            throw new AskStreamEventError(
              String(e.code ?? "?"), String(e.message ?? ""),
            );
          } else if (ev.done) {
            if (typeof ev.backend === "string") backend = ev.backend;
            if (typeof ev.model === "string") model = ev.model;
          }
        };

        for (;;) {
          const { value, done } = await reader.read();
          arm(); // 有活动（含 done）→ 重置空闲计时
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          // SSE 事件以空行（\n\n）分隔。
          let idx: number;
          while ((idx = buf.indexOf("\n\n")) !== -1) {
            const evt = buf.slice(0, idx);
            buf = buf.slice(idx + 2);
            handleEvent(evt);
          }
        }
        if (buf.trim()) handleEvent(buf); // 收尾残留

        onStatus?.("done");
        return { text, backend, model };
      } catch (err) {
        if (!text && isWarmupError(err) && attempt < maxWarmupAttempts) {
          onStatus?.(`warming:${attempt + 1}`);
          await sleep(warmupDelayMs);
          continue;
        }
        throw err;
      }
    }
    throw new Error("ask-stream failed: warmup retries exhausted");
  } catch (e) {
    if (timedOut) {
      throw new Error(
        `ask-stream timed out: no response for ${Math.round(idleTimeoutMs / 1000)}s`,
      );
    }
    throw e;
  } finally {
    disarm();
  }
}

export async function a2aEchoApi(
  did: string,
  params: Record<string, unknown>,
  opts?: { authorization?: string; signal?: AbortSignal },
): Promise<A2ACallResponse> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    "Content-Type": "application/json",
  };
  if (opts?.authorization) {
    headers["Authorization"] = opts.authorization;
  }
  const res = await fetch(
    `${BASE}/agents/${encodeURIComponent(did)}/a2a/echo`,
    {
      method: "POST",
      credentials: "same-origin",
      headers,
      body: JSON.stringify(params),
      signal: opts?.signal,
    },
  );
  let body: A2AEchoEnvelope | Record<string, unknown>;
  try {
    body = (await res.json()) as A2AEchoEnvelope;
  } catch {
    body = { error: { code: "parse-failed", message: "non-JSON response" } };
  }
  return { status: res.status, body };
}

/** 任务广场:列开放公告(可选 context/capability/min_reward/q 过滤)。 */
export async function listOpenTasks(
  filters: {
    context?: string;
    capability?: string;
    listingType?: "task" | "service" | "product" | "exchange" | "";
    minReward?: number;
    q?: string;
  } = {},
  signal?: AbortSignal,
): Promise<TaskAnnouncement[]> {
  const p = new URLSearchParams();
  if (filters.context) p.set("context", filters.context);
  if (filters.capability) p.set("capability", filters.capability);
  if (filters.listingType) p.set("listing_type", filters.listingType);
  if (filters.minReward) p.set("min_reward", String(filters.minReward));
  if (filters.q) p.set("q", filters.q);
  const qs = p.toString();
  return getJson<TaskAnnouncement[]>(
    `/market/open${qs ? `?${qs}` : ""}`,
    signal,
  );
}

/** 任务类别分面(context + 计数),给"按类别筛选"的 chips 用。 */
export async function searchMarket(
  filters: {
    q?: string;
    category?: MarketSearchCategory | "";
    intent?: MarketSearchIntent | "";
    context?: string;
    capability?: string;
    minValue?: number;
    valueAsset?: string;
    source?: "local" | "federated" | "";
    offset?: number;
    limit?: number;
  } = {},
  signal?: AbortSignal,
): Promise<MarketSearchPage> {
  const p = new URLSearchParams();
  if (filters.q) p.set("q", filters.q);
  if (filters.category) p.set("category", filters.category);
  if (filters.intent) p.set("intent", filters.intent);
  if (filters.context) p.set("context", filters.context);
  if (filters.capability) p.set("capability", filters.capability);
  if (typeof filters.minValue === "number") {
    p.set("min_value", String(filters.minValue));
  }
  if (filters.valueAsset) p.set("value_asset", filters.valueAsset);
  if (filters.source) p.set("source", filters.source);
  if (typeof filters.offset === "number") p.set("offset", String(filters.offset));
  if (typeof filters.limit === "number") p.set("limit", String(filters.limit));
  const qs = p.toString();
  return getJson<MarketSearchPage>(
    `/market/search${qs ? `?${qs}` : ""}`,
    signal,
  );
}

export async function publishMarketOffer(
  body: PublishMarketOfferInput,
): Promise<PublishMarketOfferResult> {
  return postJson<PublishMarketOfferResult>("/market/offers", body);
}

export async function listTaskCategories(
  listingType: "task" | "service" | "product" | "exchange" | "" = "",
  signal?: AbortSignal,
): Promise<TaskCategory[]> {
  const suffix = listingType
    ? `?listing_type=${encodeURIComponent(listingType)}`
    : "";
  return getJson<TaskCategory[]>(`/market/categories${suffix}`, signal);
}

export async function getTradeOfferInspection(
  digest: string,
  federated: boolean,
  signal?: AbortSignal,
): Promise<TradeOfferInspection> {
  const encoded = encodeURIComponent(digest);
  if (federated) {
    return getJson<TradeOfferInspection>(
      `/trade/federation/cached-offers/${encoded}`,
      signal,
    );
  }
  return getJson<TradeOfferInspection>(`/trade/offers/${encoded}`, signal);
}

const TRADE_DIGEST = /^sha256:[0-9a-f]{64}$/;
const SPINE_EVENT_ID = /^[0-9a-f]{64}$/;

export function validateTradeOfferImportResult(
  value: unknown,
  expectedDigest: string,
): TradeOfferImportResult {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("server returned an invalid persistence result");
  }
  const result = value as Record<string, unknown>;
  const auditEventIds = result.audit_event_ids;
  const importedRevisions = result.imported_revisions;
  const appendedRevisions = result.appended_revisions;
  if (
    !TRADE_DIGEST.test(expectedDigest)
    || result.digest !== expectedDigest
    || result.persisted !== true
    || typeof result.appended !== "boolean"
    || typeof result.classification !== "string"
    || result.classification.length < 1
    || result.classification.length > 64
    || typeof result.entry_hash !== "string"
    || !TRADE_DIGEST.test(result.entry_hash)
    || !["federation-cache", "local-operator"].includes(
      String(result.source_kind),
    )
    || typeof result.source_id !== "string"
    || !result.source_id.startsWith("did:key:z")
    || result.source_id.length > 512
    || typeof result.audit_event_id !== "string"
    || !SPINE_EVENT_ID.test(result.audit_event_id)
    || !Array.isArray(auditEventIds)
    || !auditEventIds.every(
      (eventId) => typeof eventId === "string" && SPINE_EVENT_ID.test(eventId),
    )
    || new Set(auditEventIds).size !== auditEventIds.length
    || result.audit_event_id !== auditEventIds[auditEventIds.length - 1]
    || !Number.isInteger(importedRevisions)
    || (importedRevisions as number) < 1
    || (importedRevisions as number) > 64
    || !Number.isInteger(appendedRevisions)
    || (appendedRevisions as number) < 0
    || (appendedRevisions as number) > (importedRevisions as number)
    || auditEventIds.length !== importedRevisions
    || !Number.isInteger(result.discovery_sources)
    || (result.discovery_sources as number) < 1
    || (result.discovery_sources as number) > 100_000
    || result.trusted !== false
    || result.actionable !== false
    || typeof result.warning !== "string"
    || result.warning.length < 1
    || result.warning.length > 2_000
  ) {
    throw new Error("server returned an invalid persistence result");
  }
  return result as unknown as TradeOfferImportResult;
}

export async function importCachedTradeOffer(
  digest: string,
  signal?: AbortSignal,
): Promise<TradeOfferImportResult> {
  const result = await postJson<unknown>(
    `/trade/federation/cached-offers/${encodeURIComponent(digest)}/import`,
    undefined,
    signal,
  );
  return validateTradeOfferImportResult(result, digest);
}

export async function fetchTradeProposals(
  cursor = "",
  signal?: AbortSignal,
): Promise<TradeProposalPage> {
  const params = new URLSearchParams({ limit: TRADE_INBOX_PAGE_SIZE });
  if (cursor) params.set("cursor", cursor);
  return getJson<TradeProposalPage>(
    `/trade/proposals?${params.toString()}`,
    signal,
  );
}

export async function getTradeProposal(
  digest: string,
  signal?: AbortSignal,
): Promise<TradeProposalDetail> {
  return getJson<TradeProposalDetail>(
    `/trade/proposals/${encodeURIComponent(digest)}`,
    signal,
  );
}

export async function acceptTradeProposal(
  digest: string,
  targetUrl: string,
): Promise<TradeProposalAcceptanceResult> {
  return postJson<TradeProposalAcceptanceResult>(
    `/trade/proposals/${encodeURIComponent(digest)}/accept`,
    { target_url: targetUrl },
  );
}

export async function fetchTradeOrders(
  cursor = "",
  signal?: AbortSignal,
): Promise<TradeOrderPage> {
  const params = new URLSearchParams({ limit: TRADE_INBOX_PAGE_SIZE });
  if (cursor) params.set("cursor", cursor);
  return getJson<TradeOrderPage>(
    `/trade/orders?${params.toString()}`,
    signal,
  );
}

export async function getTradeOrder(
  digest: string,
  signal?: AbortSignal,
): Promise<TradeOrderDetail> {
  return getJson<TradeOrderDetail>(
    `/trade/orders/${encodeURIComponent(digest)}`,
    signal,
  );
}

export async function getTradeExecutionReceipts(
  digest: string,
  beforeSeq: number,
  signal?: AbortSignal,
): Promise<TradeExecutionHistoryPage> {
  const params = new URLSearchParams({
    limit: TRADE_INBOX_PAGE_SIZE,
    before_seq: String(beforeSeq),
  });
  return getJson<TradeExecutionHistoryPage>(
    `/trade/orders/${encodeURIComponent(digest)}/execution-receipts?${params.toString()}`,
    signal,
  );
}

export async function importTradeRulePackage(
  orderDigest: string,
  packageDigest: string,
  peerUrl: string,
  signal?: AbortSignal,
): Promise<TradeRulePackageImportResult> {
  const value = await postJson<unknown>(
    `/trade/orders/${encodeURIComponent(orderDigest)}/rule-packages/${encodeURIComponent(packageDigest)}/import`,
    { peer_url: peerUrl },
    signal,
  );
  return validateTradeRulePackageImportResult(value, packageDigest);
}

export async function importTradeRuleRecognitions(
  orderDigest: string,
  packageDigest: string,
  peerUrl: string,
  signal?: AbortSignal,
): Promise<TradeRuleRecognitionImportResult> {
  const value = await postJson<unknown>(
    `/trade/orders/${encodeURIComponent(orderDigest)}/rule-packages/${encodeURIComponent(packageDigest)}/recognitions/import`,
    { peer_url: peerUrl },
    signal,
  );
  return validateTradeRuleRecognitionImportResult(value, packageDigest);
}

export async function fetchTradeRuleRecognitionImports(
  orderDigest: string,
  packageDigest: string,
  signal?: AbortSignal,
): Promise<TradeRuleRecognitionImportStatusPage> {
  const value = await getJson<unknown>(
    `/trade/orders/${encodeURIComponent(orderDigest)}/rule-packages/${encodeURIComponent(packageDigest)}/recognitions/imports?limit=${TRADE_INBOX_PAGE_SIZE}`,
    signal,
  );
  return validateTradeRuleRecognitionImportStatusPage(
    value,
    orderDigest,
    packageDigest,
  );
}

export async function fetchTradeRuleRecognitionImportBatch(
  orderDigest: string,
  packageDigests: string[],
  signal?: AbortSignal,
): Promise<TradeRuleRecognitionImportStatusPage[]> {
  if (
    !TRADE_DIGEST.test(orderDigest)
    || packageDigests.length < 1
    || packageDigests.length > TRADE_RECOGNITION_STATUS_MAX_PACKAGES
    || packageDigests.some((digest) => !TRADE_DIGEST.test(digest))
    || new Set(packageDigests).size !== packageDigests.length
  ) {
    throw new Error("Recognition status batch request is invalid");
  }
  const pages: TradeRuleRecognitionImportStatusPage[] = [];
  for (
    let offset = 0;
    offset < packageDigests.length;
    offset += TRADE_RECOGNITION_STATUS_BATCH_SIZE
  ) {
    const batchDigests = packageDigests.slice(
      offset,
      offset + TRADE_RECOGNITION_STATUS_BATCH_SIZE,
    );
    const params = new URLSearchParams({ limit: TRADE_INBOX_PAGE_SIZE });
    for (const digest of batchDigests) params.append("package_digest", digest);
    const value = await getJson<unknown>(
      `/trade/orders/${encodeURIComponent(orderDigest)}/recognitions/imports?${params.toString()}`,
      signal,
    );
    pages.push(...validateTradeRuleRecognitionImportStatusBatch(
      value,
      orderDigest,
      batchDigests,
    ).items);
  }
  return pages;
}

export function validateTradeRulePackageImportResult(
  value: unknown,
  expectedPackageDigest: string,
): TradeRulePackageImportResult {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("server returned an invalid Trade Skill import result");
  }
  const result = value as Record<string, unknown>;
  const expectedFields = [
    "status",
    "installed",
    "offer_digest",
    "package_digest",
    "rule_id",
    "version",
    "publisher_did",
    "audit_event_id",
    "audit_created",
    "resource_count",
    "resource_bytes",
    "trust_granted",
    "execution_authority_granted",
    "warning",
  ].sort();
  const fields = Object.keys(result).sort();
  const statusValid = result.status === "installed"
    || result.status === "already-installed";
  if (
    fields.length !== expectedFields.length
    || fields.some((field, index) => field !== expectedFields[index])
    || !TRADE_DIGEST.test(expectedPackageDigest)
    || result.package_digest !== expectedPackageDigest
    || typeof result.offer_digest !== "string"
    || !TRADE_DIGEST.test(result.offer_digest)
    || !statusValid
    || typeof result.installed !== "boolean"
    || result.installed !== (result.status === "installed")
    || typeof result.rule_id !== "string"
    || result.rule_id.length < 3
    || result.rule_id.length > 160
    || typeof result.version !== "string"
    || result.version.length < 1
    || result.version.length > 64
    || typeof result.publisher_did !== "string"
    || !TRADE_RULE_DID.test(result.publisher_did)
    || typeof result.audit_event_id !== "string"
    || !SPINE_EVENT_ID.test(result.audit_event_id)
    || typeof result.audit_created !== "boolean"
    || !Number.isInteger(result.resource_count)
    || (result.resource_count as number) < 0
    || (result.resource_count as number) > 128
    || !Number.isInteger(result.resource_bytes)
    || (result.resource_bytes as number) < 0
    || (result.resource_bytes as number) > 16 * 1024 * 1024
    || result.trust_granted !== false
    || result.execution_authority_granted !== false
    || typeof result.warning !== "string"
    || result.warning.length < 1
    || result.warning.length > 2_000
  ) {
    throw new Error("server returned an invalid Trade Skill import result");
  }
  return result as unknown as TradeRulePackageImportResult;
}

const RECOGNITION_IMPORT_COMMON_FIELDS = [
  "status",
  "offer_digest",
  "package_digest",
  "observed_heads_digest",
  "observed_statement_count",
  "imported_statement_count",
  "reconciled_anchor_count",
  "imported_recognition_digests",
  "audit_event_ids",
  "global_freshness_proven",
  "issuer_trust_granted",
  "local_policy_changed",
  "execution_authority_granted",
  "warning",
];

function isBoundedCount(value: unknown, maximum: number): value is number {
  return Number.isSafeInteger(value)
    && (value as number) >= 0
    && (value as number) <= maximum;
}

function isHttpOrigin(value: unknown): value is string {
  if (
    typeof value !== "string"
    || value.length < 8
    || value.length > 2_048
    || value !== value.trim()
    || !/^https?:\/\/[^/\\?#]+$/i.test(value)
  ) {
    return false;
  }
  try {
    const parsed = new URL(value);
    return (parsed.protocol === "http:" || parsed.protocol === "https:")
      && parsed.username === ""
      && parsed.password === ""
      && parsed.pathname === "/"
      && parsed.search === ""
      && parsed.hash === "";
  } catch {
    return false;
  }
}

function isUniqueStringList(
  value: unknown,
  predicate: (item: string) => boolean,
  maximum: number,
): value is string[] {
  return Array.isArray(value)
    && value.length <= maximum
    && value.every((item) => typeof item === "string" && predicate(item))
    && new Set(value).size === value.length;
}

function validateRecognitionImportCommon(
  result: Record<string, unknown>,
  expectedPackageDigest: string,
  maximumStatements: number,
): void {
  const imported = result.imported_statement_count;
  const observed = result.observed_statement_count;
  const reconciled = result.reconciled_anchor_count;
  const importedDigests = result.imported_recognition_digests;
  const auditEvents = result.audit_event_ids;
  if (
    !TRADE_DIGEST.test(expectedPackageDigest)
    || result.package_digest !== expectedPackageDigest
    || typeof result.offer_digest !== "string"
    || !TRADE_DIGEST.test(result.offer_digest)
    || typeof result.observed_heads_digest !== "string"
    || !TRADE_DIGEST.test(result.observed_heads_digest)
    || (result.status !== "imported" && result.status !== "already-observed")
    || !isBoundedCount(observed, maximumStatements)
    || !isBoundedCount(imported, maximumStatements)
    || !isBoundedCount(reconciled, maximumStatements)
    || (imported as number) > (observed as number)
    || (reconciled as number) > (observed as number)
    || (imported as number) + (reconciled as number) > (observed as number)
    || result.status !== ((imported as number) > 0 ? "imported" : "already-observed")
    || !isUniqueStringList(importedDigests, (item) => TRADE_DIGEST.test(item), maximumStatements)
    || importedDigests.length !== imported
    || !isUniqueStringList(auditEvents, (item) => SPINE_EVENT_ID.test(item), maximumStatements)
    || auditEvents.length !== imported
    || result.global_freshness_proven !== false
    || result.issuer_trust_granted !== false
    || result.local_policy_changed !== false
    || result.execution_authority_granted !== false
    || typeof result.warning !== "string"
    || result.warning.length < 1
    || result.warning.length > 2_000
  ) {
    throw new Error("server returned an invalid Recognition import result");
  }
}

export function validateTradeRuleRecognitionImportResult(
  value: unknown,
  expectedPackageDigest: string,
): TradeRuleRecognitionImportResult {
  if (!isPlainRecord(value)) {
    throw new Error("server returned an invalid Recognition import result");
  }
  const paged = Object.prototype.hasOwnProperty.call(
    value,
    "proof_protocol_version",
  );
  if (!paged) {
    const legacyFields = [
      ...RECOGNITION_IMPORT_COMMON_FIELDS,
      "proof_digest",
      "import_id",
      "source_origin",
      "import_proposal_event_id",
      "import_completion_event_id",
    ];
    validateRecognitionImportCommon(value, expectedPackageDigest, 256);
    if (
      !hasExactFields(value, legacyFields)
      || typeof value.proof_digest !== "string"
      || !TRADE_DIGEST.test(value.proof_digest)
      || typeof value.import_id !== "string"
      || !SPINE_EVENT_ID.test(value.import_id)
      || !isHttpOrigin(value.source_origin)
      || typeof value.import_proposal_event_id !== "string"
      || !SPINE_EVENT_ID.test(value.import_proposal_event_id)
      || typeof value.import_completion_event_id !== "string"
      || !SPINE_EVENT_ID.test(value.import_completion_event_id)
      || new Set([
        value.import_proposal_event_id,
        value.import_completion_event_id,
        ...(value.audit_event_ids as string[]),
      ]).size !== 2 + (value.audit_event_ids as string[]).length
    ) {
      throw new Error("server returned an invalid Recognition import result");
    }
    return value as unknown as TradeRuleRecognitionImportResult;
  }
  const pageFields = [
    ...RECOGNITION_IMPORT_COMMON_FIELDS,
    "proof_protocol_version",
    "proof_digests",
    "observation_digest",
    "page_count",
    "page_imports",
  ];
  validateRecognitionImportCommon(value, expectedPackageDigest, 16_384);
  const pageCount = value.page_count;
  if (
    !hasExactFields(value, pageFields)
    || value.proof_protocol_version !== "2"
    || typeof value.observation_digest !== "string"
    || !TRADE_DIGEST.test(value.observation_digest)
    || !isBoundedCount(pageCount, 1_024)
    || pageCount === 0
    || !isUniqueStringList(value.proof_digests, (item) => TRADE_DIGEST.test(item), 1_024)
    || value.proof_digests.length !== pageCount
    || !Array.isArray(value.page_imports)
    || value.page_imports.length !== pageCount
  ) {
    throw new Error("server returned an invalid Recognition import result");
  }
  for (const audit of value.page_imports) {
    if (
      !isPlainRecord(audit)
      || !hasExactFields(audit, [
        "import_id",
        "source_origin",
        "proposal_event_id",
        "completion_event_id",
        "observed_heads_digest",
      ])
      || typeof audit.import_id !== "string"
      || !SPINE_EVENT_ID.test(audit.import_id)
      || !isHttpOrigin(audit.source_origin)
      || typeof audit.proposal_event_id !== "string"
      || !SPINE_EVENT_ID.test(audit.proposal_event_id)
      || typeof audit.completion_event_id !== "string"
      || !SPINE_EVENT_ID.test(audit.completion_event_id)
      || audit.observed_heads_digest !== value.observed_heads_digest
    ) {
      throw new Error("server returned an invalid Recognition import result");
    }
  }
  const pageImports = value.page_imports as Array<Record<string, unknown>>;
  const pageEventIds = pageImports.flatMap((audit) => [
    audit.proposal_event_id as string,
    audit.completion_event_id as string,
  ]);
  const allEventIds = [
    ...pageEventIds,
    ...(value.audit_event_ids as string[]),
  ];
  if (
    new Set(pageImports.map((audit) => audit.import_id)).size !== pageCount
    || new Set(pageImports.map((audit) => audit.source_origin)).size !== 1
    || new Set(allEventIds).size !== allEventIds.length
  ) {
    throw new Error("server returned an invalid Recognition import result");
  }
  return value as unknown as TradeRuleRecognitionImportResult;
}

const RECOGNITION_STATUS_COMMON_FIELDS = [
  "import_id",
  "status",
  "proof_digest",
  "observer_did",
  "observed_heads_digest",
  "source_origin",
  "statement_count",
  "evidence_status",
  "proposal_event_id",
  "completion_event_id",
];

function validateRecognitionImportStatusItem(
  value: unknown,
): TradeRuleRecognitionImportStatusItem {
  if (!isPlainRecord(value)) {
    throw new Error("server returned an invalid Recognition import status");
  }
  const paged = Object.prototype.hasOwnProperty.call(
    value,
    "proof_protocol_version",
  );
  const expectedFields = paged
    ? [
      ...RECOGNITION_STATUS_COMMON_FIELDS,
      "proof_protocol_version",
      "observation_digest",
      "page_index",
      "page_count",
      "total_statement_count",
      "statement_set_digest",
    ]
    : RECOGNITION_STATUS_COMMON_FIELDS;
  if (
    !hasExactFields(value, expectedFields)
    || typeof value.import_id !== "string"
    || !SPINE_EVENT_ID.test(value.import_id)
    || (value.status !== "pending" && value.status !== "completed")
    || typeof value.proof_digest !== "string"
    || !TRADE_DIGEST.test(value.proof_digest)
    || typeof value.observer_did !== "string"
    || !TRADE_RULE_DID.test(value.observer_did)
    || typeof value.observed_heads_digest !== "string"
    || !TRADE_DIGEST.test(value.observed_heads_digest)
    || !isHttpOrigin(value.source_origin)
    || !isBoundedCount(value.statement_count, paged ? 128 : 256)
    || !["verified", "binding-mismatch", "missing-or-corrupt"].includes(
      String(value.evidence_status),
    )
    || typeof value.proposal_event_id !== "string"
    || !SPINE_EVENT_ID.test(value.proposal_event_id)
    || (value.status === "pending" && value.completion_event_id !== null)
    || (value.status === "completed" && (
      typeof value.completion_event_id !== "string"
      || !SPINE_EVENT_ID.test(value.completion_event_id)
    ))
  ) {
    throw new Error("server returned an invalid Recognition import status");
  }
  if (paged && (
    value.proof_protocol_version !== "2"
    || typeof value.observation_digest !== "string"
    || !TRADE_DIGEST.test(value.observation_digest)
    || !isBoundedCount(value.page_count, 1_024)
    || value.page_count === 0
    || !isBoundedCount(value.page_index, 1_023)
    || (value.page_index as number) >= (value.page_count as number)
    || !isBoundedCount(value.total_statement_count, 16_384)
    || (value.statement_count as number) > (value.total_statement_count as number)
    || typeof value.statement_set_digest !== "string"
    || !TRADE_DIGEST.test(value.statement_set_digest)
  )) {
    throw new Error("server returned an invalid Recognition import status");
  }
  return value as unknown as TradeRuleRecognitionImportStatusItem;
}

export function validateTradeRuleRecognitionImportStatusPage(
  value: unknown,
  expectedOrderDigest: string,
  expectedPackageDigest: string,
): TradeRuleRecognitionImportStatusPage {
  if (
    !isPlainRecord(value)
    || !hasExactFields(value, [
      "order_digest",
      "package_digest",
      "total",
      "returned",
      "items",
    ])
    || !TRADE_DIGEST.test(expectedOrderDigest)
    || value.order_digest !== expectedOrderDigest
    || !TRADE_DIGEST.test(expectedPackageDigest)
    || value.package_digest !== expectedPackageDigest
    || !isBoundedCount(value.total, Number.MAX_SAFE_INTEGER)
    || !isBoundedCount(value.returned, 100)
    || !Array.isArray(value.items)
    || value.items.length !== value.returned
    || (value.returned as number) > (value.total as number)
    || value.returned !== Math.min(value.total as number, TRADE_INBOX_PAGE_LIMIT)
  ) {
    throw new Error("server returned an invalid Recognition import status");
  }
  const items = value.items.map(validateRecognitionImportStatusItem);
  const eventIds = items.flatMap((item) => item.completion_event_id === null
    ? [item.proposal_event_id]
    : [item.proposal_event_id, item.completion_event_id]);
  const pageGroups = new Map<string, {
    observerDid: string;
    observedHeadsDigest: string;
    pageCount: number;
    totalStatementCount: number;
    statementSetDigest: string;
    pageIndexes: Set<number>;
  }>();
  for (const item of items) {
    if (!("proof_protocol_version" in item)) continue;
    const key = `${item.observation_digest}\u0000${item.source_origin}`;
    const group = pageGroups.get(key);
    if (!group) {
      pageGroups.set(key, {
        observerDid: item.observer_did,
        observedHeadsDigest: item.observed_heads_digest,
        pageCount: item.page_count,
        totalStatementCount: item.total_statement_count,
        statementSetDigest: item.statement_set_digest,
        pageIndexes: new Set([item.page_index]),
      });
      continue;
    }
    if (
      group.observerDid !== item.observer_did
      || group.observedHeadsDigest !== item.observed_heads_digest
      || group.pageCount !== item.page_count
      || group.totalStatementCount !== item.total_statement_count
      || group.statementSetDigest !== item.statement_set_digest
      || group.pageIndexes.has(item.page_index)
    ) {
      throw new Error("server returned an invalid Recognition import status");
    }
    group.pageIndexes.add(item.page_index);
  }
  if (
    new Set(items.map((item) => item.import_id)).size !== items.length
    || new Set(eventIds).size !== eventIds.length
  ) {
    throw new Error("server returned an invalid Recognition import status");
  }
  return { ...value, items } as unknown as TradeRuleRecognitionImportStatusPage;
}

export function validateTradeRuleRecognitionImportStatusBatch(
  value: unknown,
  expectedOrderDigest: string,
  expectedPackageDigests: string[],
): TradeRuleRecognitionImportStatusBatch {
  if (
    !isPlainRecord(value)
    || !hasExactFields(value, ["order_digest", "package_count", "items"])
    || value.order_digest !== expectedOrderDigest
    || !Array.isArray(value.items)
    || !Number.isSafeInteger(value.package_count)
    || value.package_count !== expectedPackageDigests.length
    || value.items.length !== expectedPackageDigests.length
  ) {
    throw new Error("server returned an invalid Recognition status batch");
  }
  const expected = new Set(expectedPackageDigests);
  const pagesByDigest = new Map<string, TradeRuleRecognitionImportStatusPage>();
  const importIds = new Set<string>();
  const eventIds = new Set<string>();
  for (const rawPage of value.items) {
    if (!isPlainRecord(rawPage) || typeof rawPage.package_digest !== "string") {
      throw new Error("server returned an invalid Recognition status batch");
    }
    const packageDigest = rawPage.package_digest;
    if (!expected.has(packageDigest) || pagesByDigest.has(packageDigest)) {
      throw new Error("server returned an invalid Recognition status batch");
    }
    const page = validateTradeRuleRecognitionImportStatusPage(
      rawPage,
      expectedOrderDigest,
      packageDigest,
    );
    for (const item of page.items) {
      if (importIds.has(item.import_id) || eventIds.has(item.proposal_event_id)) {
        throw new Error("server returned an invalid Recognition status batch");
      }
      importIds.add(item.import_id);
      eventIds.add(item.proposal_event_id);
      if (item.completion_event_id !== null) {
        if (eventIds.has(item.completion_event_id)) {
          throw new Error("server returned an invalid Recognition status batch");
        }
        eventIds.add(item.completion_event_id);
      }
    }
    pagesByDigest.set(packageDigest, page);
  }
  if (pagesByDigest.size !== expectedPackageDigests.length) {
    throw new Error("server returned an invalid Recognition status batch");
  }
  return {
    order_digest: expectedOrderDigest,
    package_count: expectedPackageDigests.length,
    items: expectedPackageDigests.map((digest) => pagesByDigest.get(digest)!),
  };
}

const TRADE_RULE_MODES = new Set([
  "declarative",
  "adapter",
  "sandboxed_wasm",
  "external_service",
]);
const TRADE_RULE_TIME = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$/;
const TRADE_RULE_ID = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+(?:\/[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?)?$/;
const TRADE_RULE_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
const TRADE_RULE_TOKEN = /^[a-z0-9][a-z0-9._:/-]*$/;
const TRADE_RULE_MEDIA_TYPE = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/;
const TRADE_RULE_DID = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/;
const TRADE_RULE_PROOF = /^[A-Za-z0-9_-]{86}$/;

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactFields(value: Record<string, unknown>, fields: string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  return actual.length === expected.length
    && actual.every((field, index) => field === expected[index]);
}

function isBoundedStringArray(
  value: unknown,
  maximumItems: number,
  maximumLength = 160,
): value is string[] {
  return Array.isArray(value)
    && value.length <= maximumItems
    && value.every((item) => typeof item === "string"
      && item.length >= 1 && item.length <= maximumLength
      && TRADE_RULE_TOKEN.test(item))
    && new Set(value).size === value.length
    && value.every((item, index) => index === 0 || value[index - 1] < item);
}

function isRealTradeTime(value: string): boolean {
  if (!TRADE_RULE_TIME.test(value)) return false;
  const base = `${value.slice(0, 19)}Z`;
  return Number.isFinite(Date.parse(base));
}

function isValidTradeRuleImportAudit(value: unknown): boolean {
  if (!isPlainRecord(value) || !hasExactFields(value, [
    "status", "proposed_count", "anchored_count", "incomplete_count",
  ])) {
    return false;
  }
  const proposed = value.proposed_count;
  const anchored = value.anchored_count;
  const incomplete = value.incomplete_count;
  if (
    !Number.isSafeInteger(proposed)
    || !Number.isSafeInteger(anchored)
    || !Number.isSafeInteger(incomplete)
    || (proposed as number) < 0
    || (anchored as number) < 0
    || (incomplete as number) < 0
    || (anchored as number) + (incomplete as number) !== proposed
  ) {
    return false;
  }
  const expectedStatus = proposed === 0
    ? "not-applicable"
    : anchored === 0
      ? "incomplete"
      : incomplete === 0
        ? "anchored"
        : "mixed";
  return value.status === expectedStatus;
}

function isValidTradeRulePackageProvenance(value: unknown): boolean {
  if (!isPlainRecord(value) || !hasExactFields(value, ["status", "sources"])) {
    return false;
  }
  const sources = value.sources;
  if (!Array.isArray(sources)
    || sources.length > 2
    || sources.some((source) => source !== "federated" && source !== "local")
    || sources.some((source, index) => index > 0 && sources[index - 1] >= source)) {
    return false;
  }
  return value.status === (sources.length ? "explicit" : "unclassified");
}

export function validateTradeRulePackageCatalogItem(
  value: unknown,
): TradeRulePackageCatalogItem {
  const fields = [
    "package_digest", "rule_id", "version", "publisher_did", "summary",
    "applies_to", "families", "published_at", "not_after", "execution",
    "required_capabilities", "resource_count", "resource_bytes",
    "dependency_count", "conflict_count", "verification", "import_audit",
    "provenance", "trust",
  ];
  if (!isPlainRecord(value) || !hasExactFields(value, fields)) {
    throw new Error("server returned an invalid Trade Skill catalog item");
  }
  const execution = value.execution;
  const verification = value.verification;
  const importAudit = value.import_audit;
  const provenance = value.provenance;
  const trust = value.trust;
  const valid = TRADE_DIGEST.test(String(value.package_digest ?? ""))
    && typeof value.rule_id === "string"
    && value.rule_id.length >= 3 && value.rule_id.length <= 160
    && TRADE_RULE_ID.test(value.rule_id)
    && typeof value.version === "string"
    && value.version.length >= 5 && value.version.length <= 64
    && TRADE_RULE_VERSION.test(value.version)
    && typeof value.publisher_did === "string"
    && TRADE_RULE_DID.test(value.publisher_did)
    && typeof value.summary === "string"
    && value.summary.length >= 1 && value.summary.length <= 500
    && new TextEncoder().encode(value.summary).length <= 2_000
    && isBoundedStringArray(value.applies_to, 32)
    && isBoundedStringArray(value.families, 32)
    && typeof value.published_at === "string"
    && isRealTradeTime(value.published_at)
    && (value.not_after === null
      || (typeof value.not_after === "string" && isRealTradeTime(value.not_after)))
    && isPlainRecord(execution)
    && hasExactFields(execution, ["mode", "permissions"])
    && typeof execution.mode === "string"
    && TRADE_RULE_MODES.has(execution.mode)
    && isBoundedStringArray(execution.permissions, 64)
    && isBoundedStringArray(value.required_capabilities, 64)
    && Number.isInteger(value.resource_count)
    && (value.resource_count as number) >= 1
    && (value.resource_count as number) <= 128
    && Number.isInteger(value.resource_bytes)
    && (value.resource_bytes as number) >= 0
    && (value.resource_bytes as number) <= 16 * 1024 * 1024
    && Number.isInteger(value.dependency_count)
    && (value.dependency_count as number) >= 0
    && (value.dependency_count as number) <= 128
    && Number.isInteger(value.conflict_count)
    && (value.conflict_count as number) >= 0
    && (value.conflict_count as number) <= 128
    && isPlainRecord(verification)
    && hasExactFields(verification, [
      "status", "publisher_signature", "resource_digests",
    ])
    && verification.status === "verified-cache"
    && verification.publisher_signature === true
    && verification.resource_digests === true
    && isValidTradeRuleImportAudit(importAudit)
    && isValidTradeRulePackageProvenance(provenance)
    && isPlainRecord(trust)
    && hasExactFields(trust, ["status", "advisory", "execution_authorized"])
    && trust.status === "not-evaluated"
    && trust.advisory === true
    && trust.execution_authorized === false;
  if (!valid) {
    throw new Error("server returned an invalid Trade Skill catalog item");
  }
  return value as unknown as TradeRulePackageCatalogItem;
}

export function validateTradeRulePackageCatalogPage(
  value: unknown,
): TradeRulePackageCatalogPage {
  if (
    !isPlainRecord(value)
    || !hasExactFields(value, [
      "items", "next_cursor", "cache_only", "execution_authorized",
    ])
    || !Array.isArray(value.items)
    || value.items.length > 200
    || typeof value.next_cursor !== "string"
    || (value.next_cursor !== "" && !TRADE_DIGEST.test(value.next_cursor))
    || value.cache_only !== true
    || value.execution_authorized !== false
  ) {
    throw new Error("server returned an invalid Trade Skill catalog page");
  }
  const items = value.items.map(validateTradeRulePackageCatalogItem);
  const digests = items.map((item) => item.package_digest);
  if (
    new Set(digests).size !== items.length
    || digests.some((digest, index) => index > 0 && digests[index - 1] >= digest)
    || (value.next_cursor !== ""
      && (digests.length === 0 || value.next_cursor !== digests[digests.length - 1]))
  ) {
    throw new Error("server returned an invalid Trade Skill catalog page");
  }
  return { ...value, items } as TradeRulePackageCatalogPage;
}

function validateTradeRuleManifest(
  value: unknown,
  summary: TradeRulePackageCatalogItem,
): Record<string, unknown> {
  const fields = [
    "kind", "protocol_version", "rule_id", "version", "publisher_did",
    "summary", "applies_to", "families", "resources", "dependencies",
    "conflicts", "required_capabilities", "hook_contracts", "execution",
    "published_at", "not_after", "extensions", "proof",
  ];
  if (!isPlainRecord(value) || !hasExactFields(value, fields)) {
    throw new Error("server returned an invalid Trade Skill detail");
  }
  if (
    value.kind !== "org.nthdao.trade.rule-manifest"
    || value.protocol_version !== "1.0"
    || value.rule_id !== summary.rule_id
    || value.version !== summary.version
    || value.publisher_did !== summary.publisher_did
    || value.summary !== summary.summary
    || JSON.stringify(value.applies_to) !== JSON.stringify(summary.applies_to)
    || JSON.stringify(value.families) !== JSON.stringify(summary.families)
    || JSON.stringify(value.execution) !== JSON.stringify(summary.execution)
    || JSON.stringify(value.required_capabilities)
      !== JSON.stringify(summary.required_capabilities)
    || value.published_at !== summary.published_at
    || value.not_after !== summary.not_after
    || !Array.isArray(value.resources)
    || value.resources.length !== summary.resource_count
    || !Array.isArray(value.dependencies)
    || value.dependencies.length !== summary.dependency_count
    || !Array.isArray(value.conflicts)
    || value.conflicts.length !== summary.conflict_count
    || !Array.isArray(value.hook_contracts)
    || value.hook_contracts.length > 64
    || !isPlainRecord(value.extensions)
    || !isPlainRecord(value.proof)
  ) {
    throw new Error("server returned an invalid Trade Skill detail");
  }
  for (const resource of value.resources) {
    if (!isPlainRecord(resource)
      || !hasExactFields(resource, ["purpose", "media_type", "digest", "size"])
      || typeof resource.purpose !== "string"
      || resource.purpose.length < 1 || resource.purpose.length > 160
      || !TRADE_RULE_TOKEN.test(resource.purpose)
      || typeof resource.media_type !== "string"
      || resource.media_type.length < 3 || resource.media_type.length > 128
      || !TRADE_RULE_MEDIA_TYPE.test(resource.media_type)
      || !TRADE_DIGEST.test(String(resource.digest ?? ""))
      || !Number.isInteger(resource.size)
      || (resource.size as number) < 0
      || (resource.size as number) > 1024 * 1024) {
      throw new Error("server returned an invalid Trade Skill detail");
    }
  }
  const resourceKeys = value.resources.map((resource) => {
    const item = resource as Record<string, unknown>;
    return `${String(item.purpose)}\u0000${String(item.digest)}`;
  });
  const uniqueResourceBytes = new Map<string, number>();
  for (const resource of value.resources as Array<Record<string, unknown>>) {
    const digest = String(resource.digest);
    const size = Number(resource.size);
    const prior = uniqueResourceBytes.get(digest);
    if (prior !== undefined && prior !== size) {
      throw new Error("server returned an invalid Trade Skill detail");
    }
    uniqueResourceBytes.set(digest, size);
  }
  if (
    new Set(resourceKeys).size !== resourceKeys.length
    || resourceKeys.some((key, index) => index > 0 && resourceKeys[index - 1] >= key)
    || [...uniqueResourceBytes.values()].reduce((total, size) => total + size, 0)
      !== summary.resource_bytes
  ) {
    throw new Error("server returned an invalid Trade Skill detail");
  }
  for (const relations of [value.dependencies, value.conflicts]) {
    const relationKeys: string[] = [];
    for (const relation of relations) {
    if (!isPlainRecord(relation)
      || !hasExactFields(relation, ["rule_id", "digest"])
      || typeof relation.rule_id !== "string"
      || relation.rule_id.length < 3 || relation.rule_id.length > 160
      || !TRADE_RULE_ID.test(relation.rule_id)
      || !TRADE_DIGEST.test(String(relation.digest ?? ""))) {
      throw new Error("server returned an invalid Trade Skill detail");
    }
      relationKeys.push(`${relation.rule_id}\u0000${relation.digest}`);
    }
    if (new Set(relationKeys).size !== relationKeys.length
      || relationKeys.some((key, index) => index > 0 && relationKeys[index - 1] >= key)) {
      throw new Error("server returned an invalid Trade Skill detail");
    }
  }
  if (value.hook_contracts.length > 32) {
    throw new Error("server returned an invalid Trade Skill detail");
  }
  const sideEffects = new Set(["none", "local", "external", "funds"]);
  const hookKeys: string[] = [];
  for (const hook of value.hook_contracts) {
    if (!isPlainRecord(hook)
      || !hasExactFields(hook, [
        "name", "version", "input_schema_digest", "output_schema_digest",
        "side_effect", "permissions",
      ])
      || typeof hook.name !== "string"
      || hook.name.length < 1 || hook.name.length > 160
      || !TRADE_RULE_TOKEN.test(hook.name)
      || typeof hook.version !== "string"
      || hook.version.length < 1 || hook.version.length > 32
      || !TRADE_RULE_TOKEN.test(hook.version)
      || !TRADE_DIGEST.test(String(hook.input_schema_digest ?? ""))
      || !TRADE_DIGEST.test(String(hook.output_schema_digest ?? ""))
      || typeof hook.side_effect !== "string" || !sideEffects.has(hook.side_effect)
      || !isBoundedStringArray(hook.permissions, 64)) {
      throw new Error("server returned an invalid Trade Skill detail");
    }
    hookKeys.push(`${hook.name}\u0000${hook.version}`);
  }
  if (new Set(hookKeys).size !== hookKeys.length
    || hookKeys.some((key, index) => index > 0 && hookKeys[index - 1] >= key)) {
    throw new Error("server returned an invalid Trade Skill detail");
  }
  if (!hasExactFields(value.proof, [
    "type", "created", "verification_method", "proof_purpose", "proof_value",
  ])
    || value.proof.type !== "NthEd25519SignatureV1"
    || typeof value.proof.created !== "string"
    || !isRealTradeTime(value.proof.created)
    || typeof value.proof.verification_method !== "string"
    || value.proof.verification_method
      !== `${summary.publisher_did}#${summary.publisher_did.slice("did:key:".length)}`
    || value.proof.proof_purpose !== "assertionMethod"
    || typeof value.proof.proof_value !== "string"
    || !TRADE_RULE_PROOF.test(value.proof.proof_value)) {
    throw new Error("server returned an invalid Trade Skill detail");
  }
  return value;
}

export function validateTradeRulePackageDetail(
  value: unknown,
  expectedDigest: string,
): TradeRulePackageDetail {
  if (!isPlainRecord(value) || !hasExactFields(value, [
    "package_digest", "rule_id", "version", "publisher_did", "summary",
    "applies_to", "families", "published_at", "not_after", "execution",
    "required_capabilities", "resource_count", "resource_bytes",
    "dependency_count", "conflict_count", "verification", "import_audit",
    "provenance", "trust", "manifest",
  ])) {
    throw new Error("server returned an invalid Trade Skill detail");
  }
  const { manifest, ...catalogFields } = value;
  let summary: TradeRulePackageCatalogItem;
  try {
    summary = validateTradeRulePackageCatalogItem(catalogFields);
  } catch {
    throw new Error("server returned an invalid Trade Skill detail");
  }
  if (!TRADE_DIGEST.test(expectedDigest) || summary.package_digest !== expectedDigest) {
    throw new Error("server returned an invalid Trade Skill detail");
  }
  const verifiedManifest = validateTradeRuleManifest(manifest, summary);
  return { ...summary, manifest: verifiedManifest };
}

export async function fetchTradeRulePackages(
  cursor = "",
  signal?: AbortSignal,
): Promise<TradeRulePackageCatalogPage> {
  const params = new URLSearchParams({ limit: TRADE_INBOX_PAGE_SIZE });
  if (cursor) params.set("cursor", cursor);
  const value = await getJson<unknown>(
    `/trade/rule-packages?${params.toString()}`,
    signal,
  );
  return validateTradeRulePackageCatalogPage(value);
}

export async function getTradeRulePackage(
  packageDigest: string,
  signal?: AbortSignal,
): Promise<TradeRulePackageDetail> {
  const value = await getJson<unknown>(
    `/trade/rule-packages/${encodeURIComponent(packageDigest)}`,
    signal,
  );
  return validateTradeRulePackageDetail(value, packageDigest);
}

export async function getFederationStatus(
  signal?: AbortSignal,
): Promise<FederationStatus> {
  return getJson<FederationStatus>("/market/federation/status", signal);
}

export async function updateFederationPeer(
  peerUrl: string,
  action: "add" | "remove" = "add",
): Promise<FederationStatus> {
  return postJson<FederationStatus>("/market/federation/peers", {
    peer_url: peerUrl,
    action,
  });
}

export async function refreshFederation(): Promise<FederationStatus> {
  return postJson<FederationStatus>("/market/federation/refresh");
}

export async function discoverFederationPeers(input: {
  actorId?: string;
  timeoutSeconds?: number;
  add?: boolean;
  refresh?: boolean;
} = {}): Promise<FederationStatus> {
  return postJson<FederationStatus>("/market/federation/discover", {
    actor_id: input.actorId ?? "admin",
    timeout_seconds: input.timeoutSeconds ?? 2,
    add: input.add ?? true,
    refresh: input.refresh ?? true,
  });
}

export async function listResourceProfiles(
  signal?: AbortSignal,
  cursor = "",
  limit = 100,
): Promise<ResourceProfilePage> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (cursor) params.set("cursor", cursor);
  return getJson<ResourceProfilePage>(`/market/resource-profiles?${params}`, signal);
}

export async function importResourceProfile(
  document: Record<string, unknown>,
): Promise<ResourceProfileImportResult> {
  return postJson<ResourceProfileImportResult>(
    "/market/resource-profiles/import",
    { document },
  );
}

export async function setResourceProfileRecognition(
  digest: string,
  accepted: boolean,
  idempotencyKey: string,
): Promise<ResourceProfileRecognitionResult> {
  return postJson<ResourceProfileRecognitionResult>(
    `/market/resource-profiles/${encodeURIComponent(digest)}/recognition`,
    { accepted, idempotency_key: idempotencyKey },
  );
}

// ── Phase 4c/5:审计 / 争议 / 治理(消费 spine 投影端点)─────────────────

export interface DisputeSummary {
  dispute_id: string;
  announcement_id: string;
  opener_did: string;
  status: string;
  ruling: Record<string, unknown>;
  arbiter_did: string;
  arbiter_authorized: boolean | null;
  statement_count: number;
}

export interface EvidenceItem {
  seq: number;
  type: string;
  author_did: string;
  ts_ms: number;
  verified: boolean;
  summary: string;
}

export interface EvidenceChain {
  announcement_id: string;
  all_verified: boolean;
  items: EvidenceItem[];
}

export interface GovernancePolicyView {
  established: boolean;
  version: number;
  founder_did: string;
  policy: {
    roles: Record<string, string[]>;
    grants: Record<string, string[]>;
    constraints: Record<string, unknown>;
  };
}

/** 列出本节点 spine 上的争议(DisputeProjection 回放)。 */
export const listDisputes = (s?: AbortSignal) =>
  getJson<DisputeSummary[]>("/disputes", s);

/** 回放一条公告的证据链(逐项独立验证)。 */
export const getEvidence = (announcementId: string, s?: AbortSignal) =>
  getJson<EvidenceChain>(
    `/market/${encodeURIComponent(announcementId)}/evidence`,
    s,
  );

/** 当前生效治理策略(PolicyProjection 回放)。 */
export const getGovernancePolicy = (s?: AbortSignal) =>
  getJson<GovernancePolicyView>("/governance/policy", s);

// ── 授权收件箱(consent 层):cap-token 授予请求 ─────────────────────────

export interface CapRequestSummary {
  request_id: string;
  requester_did: string;
  capabilities: string[];
  reason: string;
  scope: Record<string, unknown>;
  status: string;
  decided_by_did: string;
  decided_at_ms: number;
  token_id?: string;
  token_not_after?: number;
}

/** 列出能力授予请求(已批准项只含 token_id 元数据,不含 token 全文)。 */
export const listCapRequests = (s?: AbortSignal) =>
  getJson<CapRequestSummary[]>("/cap-requests", s);

/** 批准:本节点签发 cap_token(token-gated,带 Bearer)。 */
export async function approveCapRequest(
  requestId: string,
): Promise<{ granted: boolean; token_id: string; subject_did: string }> {
  return postJson(`/cap-requests/${encodeURIComponent(requestId)}/approve`);
}

/** 拒绝(可带原因,token-gated)。 */
export async function denyCapRequest(
  requestId: string,
  reason = "",
): Promise<{ denied: boolean }> {
  return postJson(
    `/cap-requests/${encodeURIComponent(requestId)}/deny`, { reason });
}

// ── 信誉(spine 原生:从签名贡献派生)─────────────────────────────────

export interface ReputationRecord {
  did: string;
  score: number;
  tasks_claimed: number;
  tasks_accepted: number;
  tasks_published: number;
  disputed_claims: number;
}

/** 信誉榜(ReputationProjection 回放,top 排序)。 */
export const listReputation = (s?: AbortSignal) =>
  getJson<ReputationRecord[]>("/reputation", s);

/** 发布一条任务公告(本节点签名)。 */
export async function announceTask(
  body: AnnounceTaskInput,
): Promise<TaskAnnouncement> {
  return postJson<TaskAnnouncement>("/market/announce", body);
}

/** 让某个 supervised agent 认领一条任务(hub 铸 cap_token + 派发,agent 自签)。
 *  返回 {status, body} 而非 throw —— 调用方要据状态码/错误码区分"刚 spawn
 *  的 agent 还没载入 cap_token(401 not-yet-authorized,可重试)"与真失败。 */
export async function claimTask(
  announcementId: string,
  agentDid: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(
    `${BASE}/market/${encodeURIComponent(announcementId)}/claim`,
    {
      method: "POST",
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        ...authHeader(),
      },
      body: JSON.stringify({ agent_did: agentDid }),
    },
  );
  let body: Record<string, unknown>;
  try {
    body = (await res.json()) as Record<string, unknown>;
  } catch {
    body = {};
  }
  return { status: res.status, body };
}

/** 跨 DAO 认领(XDAO-3):联邦发现的任务,本地 hub 让本地 agent 自签 →
 *  转投到公告主 DAO 的 /claim-foreign 落 CAS。来源由 hub 从联邦缓存取。 */
export async function claimFederatedTask(
  announcementId: string,
  agentDid: string,
  federationKey = "",
): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(
    `${BASE}/market/federated/claim`,
    {
      method: "POST",
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        ...authHeader(),
      },
      body: JSON.stringify({
        announcement_id: announcementId,
        federation_key: federationKey,
        agent_did: agentDid,
      }),
    },
  );
  let body: Record<string, unknown>;
  try {
    body = (await res.json()) as Record<string, unknown>;
  } catch {
    body = {};
  }
  return { status: res.status, body };
}

// ── 社交(Phase 社交:关注单向免确认 / 好友双向需对方 accept)────────────

export interface SocialRoster {
  did: string;
  following: string[];
  followers: string[];
  friends: string[];
  pending_incoming: string[];
  pending_outgoing: string[];
  blocked: string[];
}

export interface SocialRelationship {
  following?: boolean;
  followed_by?: boolean;
  friend?: boolean;
  request_outgoing?: boolean;
  request_incoming?: boolean;
  blocked?: boolean;
  blocked_by?: boolean;
}

export interface SocialProfile {
  did: string;
  relationship: SocialRelationship;
  followers_count: number;
  friends_count: number;
}

interface SocialAck {
  recorded: boolean;
  type: string;
  target_did: string;
  seq: number;
}

/** 本节点社交名册:关注/粉丝/好友 + 待我确认的好友请求(进收件箱)。 */
export const fetchSocialMe = (s?: AbortSignal) =>
  getJson<SocialRoster>("/social/me", s);

/** 从本节点视角看与某 DID 的关系 + 该 DID 公开计数。 */
export const fetchSocialProfile = (did: string, s?: AbortSignal) =>
  getJson<SocialProfile>(`/social/${encodeURIComponent(did)}`, s);

/** 关注(单向、免对方确认,token-gated)。 */
export const followDid = (targetDid: string) =>
  postJson<SocialAck>("/social/follow", { target_did: targetDid });
/** 取消关注。 */
export const unfollowDid = (targetDid: string) =>
  postJson<SocialAck>("/social/unfollow", { target_did: targetDid });
/** 发好友请求(需对方 accept 才成好友)。 */
export const friendRequest = (targetDid: string) =>
  postJson<SocialAck>("/social/friend/request", { target_did: targetDid });
/** 接受某 DID 的好友请求 → 互为好友。 */
export const friendAccept = (targetDid: string) =>
  postJson<SocialAck>("/social/friend/accept", { target_did: targetDid });
/** 拒绝某 DID 的好友请求。 */
export const friendDecline = (targetDid: string) =>
  postJson<SocialAck>("/social/friend/decline", { target_did: targetDid });
/** 解除好友 / 撤回未决请求。 */
export const friendRemove = (targetDid: string) =>
  postJson<SocialAck>("/social/friend/remove", { target_did: targetDid });
/** 屏蔽某 DID(#3):清除既有关系 + 之后拒收其社交语句。 */
export const blockDid = (targetDid: string) =>
  postJson<SocialAck>("/social/block", { target_did: targetDid });
/** 解除屏蔽(不恢复旧关系)。 */
export const unblockDid = (targetDid: string) =>
  postJson<SocialAck>("/social/unblock", { target_did: targetDid });

/* ── 频道(收编自 8765 群聊,P3)──────────────────────────────── */
export const listChannels = (s?: AbortSignal) =>
  getJson<Channel[]>("/channels", s);

export const createChannel = (name: string, topic = "") =>
  postJson<Channel>("/channels", { name, topic });

export const listChannelMessages = (
  channelId: string,
  s?: AbortSignal,
  beforeMessageId = "",
  limit = 100,
) => {
  const query = new URLSearchParams({ limit: String(limit) });
  if (beforeMessageId) query.set("before_message_id", beforeMessageId);
  return getJson<ChannelMessage[]>(
    `/channels/${encodeURIComponent(channelId)}/messages?${query.toString()}`,
    s,
  );
};

export const postChannelMessage = (
  channelId: string,
  body: string,
  agentId = "admin",
  targetAgentDids: string[] = [],
) =>
  postJson<ChannelMessage>(
    `/channels/${encodeURIComponent(channelId)}/messages`,
    { agent_id: agentId, body, target_agent_dids: targetAgentDids },
  );

export const joinChannel = (channelId: string, agentId: string) =>
  postJson<Channel>(
    `/channels/${encodeURIComponent(channelId)}/join`,
    { agent_id: agentId },
  );
