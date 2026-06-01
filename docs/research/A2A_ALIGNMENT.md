# A2A Alignment Report (v0.9.4)

**Subject**: Google's Agent2Agent (A2A) Protocol  
**Status**: open standard, Linux Foundation–hosted, Apache 2.0  
**As of**: April 2026 — 150+ supporting orgs (Google, Microsoft, AWS, Salesforce,
SAP, ServiceNow, Workday, IBM, …); A2A v1.0 production-grade released early 2026.

## Why we care

A2A is the closest-aligned external standard to what NTH DAO does. If the
industry collectively chooses A2A as **the** agent-to-agent transport, NTH
DAO must either be compatible-at-the-edges or end up as a niche island. This
document is the side-by-side comparison and our roadmap for partial alignment.

## What A2A is

A2A defines three things:

1. **Agent Cards** — how an agent advertises capabilities (JSON manifest at
   a well-known URL: `/.well-known/agent.json`).
2. **Tasks** — the unit of work passed between agents (request, lifecycle,
   status updates, results).
3. **Transport** — JSON-RPC 2.0 over HTTP/HTTPS for request-response,
   Server-Sent Events (SSE) for streaming, optional gRPC binding. TLS for
   security.

Of the 11 JSON-RPC methods in the spec, the foundational ones are:

- `SendMessage` — fire-and-forget message
- `SendStreamingMessage` — message with streamed updates
- `GetTask` / `SubscribeToTask` — poll or subscribe to task state
- `CreateTaskPushNotificationConfig` — webhook delivery

## Comparison: NTH DAO vs A2A

| Concern | NTH DAO | A2A | Alignment |
|---------|---------|-----|-----------|
| **Identity** | Ed25519 + did:key (simplified) | Agent Card URL + OAuth/OIDC token | ⚠️ Different — A2A leans on enterprise OAuth, we lean on Ed25519 signatures |
| **Discovery** | LAN UDP broadcast + AgentRegistry + WoT | `/.well-known/agent.json` HTTP endpoint | 🟡 Concept maps; transport differs |
| **Capability advertisement** | `AgentRecord.capabilities` list | Agent Card `skills` array with JSON Schema | 🟢 Easily bridgeable |
| **Task lifecycle** | Mission + MissionStep with state machine | Task with submitted/in_progress/completed states | 🟢 Same state machine |
| **Transport** | WebSocket (gossip) + local file (mission state) | HTTP/JSON-RPC + SSE | ⚠️ Wholly different; an adapter is needed for interop |
| **Trust** | WoT signed endorsements + revocation | Caller's OAuth identity | ⚠️ Different models; A2A delegates to enterprise SSO |
| **Streaming** | Append-only Channel jsonl | SSE | 🟡 Different transports, same effect |
| **Push notifications** | None (long-poll via gossip) | Webhook config built-in | ❌ A2A has, we don't |
| **Persistence** | local-first JSON files + git_sync | Server-side database (vendor's choice) | ⚠️ Different philosophies |
| **Auth** | per-message Ed25519 signature | bearer token / mTLS | ❌ Wholly different — must adapt at the edge |
| **Marketplace / Reviews** | MissionTemplate + MissionReview | not part of A2A | 🟢 We have something A2A doesn't |
| **Decentralization** | local-first, no central server | each agent runs an HTTP server with OAuth | ⚠️ A2A is "federated centralized"; we are P2P |

Legend: 🟢 alignment is natural · 🟡 alignment needs minor mapping ·
⚠️ alignment needs adapter · ❌ wholly different

## Strategic conclusions

### Our protocol layer cannot be A2A

The deep choices (Ed25519 per-message signature vs OAuth bearer; local-first
vs HTTP server per agent; gossip vs JSON-RPC) are not reconcilable as a
single protocol. We would have to choose, and choosing A2A means stripping
out NTH DAO's reason to exist: privacy-respecting, no-central-server,
crypto-anchored coordination.

**Decision**: NTH DAO keeps its own wire format. We do NOT rewrite gossip
or identity to be A2A-shaped.

### Our boundary layer SHOULD speak A2A

An agent that uses NTH DAO internally can speak A2A *to the outside world*
via an adapter:

```
┌────────────────────────────┐    A2A    ┌────────────────────┐
│  enterprise agent (A2A)    │ ───────→  │  A2A↔NTH DAO       │
│  (Google / IBM / SAP)      │           │  adapter (planned) │
└────────────────────────────┘           └─────────┬──────────┘
                                                   │ gossip / mission
                                                   ▼
                                         ┌────────────────────┐
                                         │  NTH DAO team      │
                                         │  (local-first P2P) │
                                         └────────────────────┘
```

This adapter would:

1. **Inbound A2A → NTH DAO**: A2A `SendMessage` → NTH DAO `MissionTemplate`
   instantiation. A2A `Agent Card` discovery → AgentRegistry record + LAN
   discovery hello.
2. **Outbound NTH DAO → A2A**: NTH DAO `Mission` claim by an A2A-only agent
   → adapter issues an A2A `SendMessage` to that agent's URL. Status updates
   stream back via SSE.

**Decision**: an `nth-dao-a2a-adapter` will be a separate package shipped
in v0.10.0+. It is NOT part of the v0.9.x core. The adapter takes on the
A2A wire format complexity so the core stays small.

### What we adopt today, for free

The Agent Card concept (well-known capability manifest with JSON Schema)
maps cleanly to our `MissionTemplate` schema. **Without changing any code**,
we can publish an Agent Card view of every signed `MissionTemplate`:

```
GET /.well-known/agent.json    →  derived from templates/*.json + team.json
```

This is a future addition in `nth_dao/web/` (TypeScript per the iron rule),
not the protocol layer. v0.9.5+ work.

### Naming alignment now

Adopt A2A's vocabulary in docs without changing types:

| NTH DAO term | A2A term | Both refer to |
|--------------|----------|---------------|
| `Mission` | Task | a unit of work |
| `MissionStep` | (no exact equivalent — A2A is flatter) | sub-step of a Task |
| `MissionTemplate` | Skill (in Agent Card) | reusable capability advertisement |
| `AgentRegistry record` | Agent Card | machine-readable capability manifest |
| `Endorsement` | (no equivalent) | signed cross-agent trust assertion |
| `WoT TrustGraph` | (no equivalent) | transitive trust resolution |

When we write user-facing docs that touch both worlds, we use the A2A term
in parentheses on first mention. Code stays NTH DAO-named.

## v0.10.0 deliverables (sketch — NOT v0.9.4)

- `nth-dao-a2a-adapter` separate package
  - exposes A2A JSON-RPC endpoints over HTTP
  - translates A2A Task ↔ NTH DAO Mission
  - bridges A2A bearer-token auth ↔ Ed25519 signature (where possible)
- `/.well-known/agent.json` view served by `nth_dao.web`
- Conformance vectors for the adapter's translation layer

## Risk if we don't act

If A2A becomes ubiquitous and we don't ship an adapter:

- NTH DAO becomes invisible to enterprise agents
- Adoption ceiling is "individual developers who already know about us"
- Marketplace template publishers won't reach 80%+ of the agent ecosystem

**Mitigation timeline**: adapter target = v0.10.0, ~3-6 months from v0.9.4.

## Sources

- A2A protocol official spec: https://a2a-protocol.org/latest/specification/
- Google Developers announcement: https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/
- IBM A2A overview: https://www.ibm.com/think/topics/agent2agent-protocol
- DEV.to walkthrough (2025): https://dev.to/agentsindex/googles-a2a-protocol-how-ai-agents-communicate-across-frameworks-52jj
- Galileo guide: https://galileo.ai/blog/google-agent2agent-a2a-protocol-guide
- 2026 complete guide: https://rapidclaw.dev/blog/a2a-protocol-complete-guide-2026
- Stellagent adoption data: https://stellagent.ai/insights/a2a-protocol-google-agent-to-agent

---

*Compiled 2026-05-31 for nth-dao v0.9.4. Will be revised when A2A 1.x ships
substantive changes.*
