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
  ConversationSummary,
  Decision,
  IdentityHeader,
  MissionSummary,
  ProcessCard,
  ReceiptSummary,
  Rule,
} from "./types-v2";

const BASE = "/api/v2";

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
  throw new Error(`summarize: agent 未就绪 (${last.slice(0, 80)})`);
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
): Promise<AskAgentResult> {
  onStatus?.("dispatching");
  const res = await fetch(
    `${BASE}/agents/${encodeURIComponent(did)}/ask-stream`,
    {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "text/event-stream", ...authHeader() },
      body: JSON.stringify({ prompt }),
      signal,
    },
  );
  if (!res.ok || !res.body) {
    // 非流式错误（404/409/502…）—— 读 JSON 错误体给出可读消息。
    let detail = `HTTP ${res.status}`;
    try {
      const j = (await res.json()) as Record<string, unknown>;
      detail = JSON.stringify(j).slice(0, 300);
    } catch { /* keep HTTP status */ }
    throw new Error(`ask-stream failed: ${detail}`);
  }

  onStatus?.("streaming");
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  let text = "";
  let backend: string | undefined;
  let model: string | undefined;

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
      text += ev.delta;
      onDelta(ev.delta);
    } else if (ev.error) {
      const e = ev.error as Record<string, unknown>;
      throw new Error(
        `agent error: ${String(e.code ?? "?")} — ${String(e.message ?? "")}`,
      );
    } else if (ev.done) {
      if (typeof ev.backend === "string") backend = ev.backend;
      if (typeof ev.model === "string") model = ev.model;
    }
  };

  for (;;) {
    const { value, done } = await reader.read();
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
