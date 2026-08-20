# NTH DAO Plugin Architecture

Status: design contract for the first plugin-kernel implementation.

## Purpose

NTH DAO is not a model, an agent, a wallet, a marketplace operator, or a
universal chat application. It is a local-first protocol host for identity,
discovery, communication, coordination, authorization, fulfillment, evidence,
receipts, and disputes between humans and agents.

Plugins make transports and providers replaceable. They do not make the trust
model replaceable.

## Three Architectural Layers

### Constitution layer

The constitution contains invariants that every runtime and plugin must obey:

1. Identity keys remain under explicit owner or delegated custody.
2. Signed artifacts use the versioned canonicalization and verification rules.
3. Authority comes from mandates and capability grants, never from a plugin
   merely being installed or discovering an object.
4. Event, receipt, and dispute evidence remains append-only and verifiable.
5. Stateful transitions use the protocol's CAS, idempotency, and outbox rules.
6. Irreversible actions require deterministic validation and explicit commit
   authority.
7. Unknown fields, permissions, protocol versions, and signature algorithms
   fail closed at security boundaries.
8. A plugin may add policy but may not lower a host security ceiling.

The constitution is implementation-independent. A future Rust, TypeScript, or
WASI host must preserve the same invariants.

### Versioned protocol layer

This layer defines language-neutral envelopes and conformance vectors for:

- identity and capability grants;
- messages and collaboration events;
- tasks, missions, checkpoints, and handoffs;
- intents, agreements, mandates, and orders;
- deliveries, receipts, disputes, and governance decisions;
- plugin manifests and capability contracts.

Protocol objects are not Python class identities. Wire compatibility is based
on a versioned schema, canonical bytes, and conformance tests.

### Replaceable runtime layer

Runtime components may be replaced when their declared capability contracts
are compatible. Examples include agent providers, discovery transports,
message stores, market indexes, settlement adapters, and observability sinks.

## Plugin Kinds

The first host recognizes these namespaces:

| Kind | Responsibility |
| --- | --- |
| `agent.provider` | Invoke or supervise an external agent runtime. |
| `discovery.provider` | Produce untrusted or verified peer/listing hints. |
| `transport.provider` | Move protocol envelopes without changing authority. |
| `message.store` | Retain, expire, or delete collaboration messages. |
| `market.index` | Index signed listings; never become listing authority. |
| `commerce.connector` | Connect to an external commerce system. |
| `payment.rail` | Prepare or commit settlement through a payment provider. |
| `settlement.adapter` | Validate and translate settlement protocol objects. |
| `trade.execution` | Execute a signed Trade Rule operation within grants. |
| `intent.resolver` | Convert human or agent input into an unsigned draft. |
| `intent.solver` | Propose plans or offers for a reviewed intent. |
| `intent.policy` | Deterministically evaluate a proposal against policy. |
| `artifact.store` | Store content-addressed evidence or deliverables. |
| `identity.resolver` | Resolve identifiers without granting authority. |
| `observability.exporter` | Export bounded, redacted operational signals. |

These terms remain distinct:

- A **host plugin** extends the local NTH DAO runtime.
- An **A2A extension** negotiates an optional wire-protocol feature.
- A **Trade Rule Skill** defines transaction terms and execution rules.
- An **Agent Skill** describes an agent's advertised ability.

Installing one never implies installing or authorizing another.

## Manifest

Every plugin declares a bounded manifest before activation:

```json
{
  "manifest_version": 1,
  "plugin_id": "org.nth-dao.discovery.federation",
  "version": "1.0.0",
  "host_api": "1.0",
  "kind": "discovery.provider",
  "runtime": "builtin",
  "provides": [
    {
      "capability_id": "org.nth-dao.discovery.federation",
      "version": "1.0.0",
      "input_schema_digest": "sha256:<64 lowercase hex characters>",
      "output_schema_digest": "sha256:<64 lowercase hex characters>",
      "effects": ["filesystem-read", "filesystem-write", "network-read"],
      "consistency": "C1",
      "privacy": "workspace",
      "security": "verified-input",
      "cardinality": "many",
      "deterministic": false,
      "retention": "ephemeral",
      "failure_semantics": "retry-safe"
    }
  ],
  "requires": [],
  "permissions": [
    "filesystem.read.workspace",
    "filesystem.write.workspace",
    "network.client"
  ],
  "artifact_digest": "sha256:<64 lowercase hex characters>",
  "publisher_did": "",
  "proof": ""
}
```

The initial host accepts only statically registered `builtin` plugins. This is
intentional: an in-process Python import is arbitrary code execution, not a
sandbox. Signed third-party packages, entry-point discovery, subprocess RPC,
and WASI components are later protocol phases and must not be simulated by a
weak loader.

`publisher_did` and `proof` are reserved wire fields in Host API v1. The
built-in registration path rejects non-empty values because this release does
not yet define or verify an external package signature. A shaped proof is not
treated as authentication.

## Capability Contract

`provides` is more than a name. Each capability declares:

- capability identifier and semantic version;
- input and output schema digests;
- observable effects;
- consistency class;
- privacy and security class;
- provider cardinality;
- determinism, retention, and failure semantics.

The initial consistency classes are:

| Class | Meaning |
| --- | --- |
| `C0` | Ephemeral presence or best-effort chat. |
| `C1` | Mergeable collaboration state; duplicate-tolerant. |
| `C2` | Workflow state requiring CAS, idempotency, or an outbox. |
| `C3` | Economic state requiring authoritative receipts. |
| `C4` | Identity or governance state requiring versioned/quorum authority. |

A provider with a matching method name but a different effect, consistency,
privacy, or failure contract is not compatible.

Host API v1 accepts a strict, bounded JSON Schema subset. Object schemas must
reject undeclared properties, arbitrary regular expressions are unsupported,
and each invocation input and output is normalized through canonical JSON
with a 1 MiB document limit. These constraints keep schema metadata
enforceable at the call boundary rather than advisory.

## Lifecycle And Authorization

The lifecycle is deliberately split:

1. `install`: make a manifest and factory known to the host;
2. `authorize`: grant an explicit subset of its declared permissions;
3. `enable`: resolve dependencies and start the provider;
4. `disable`: remove capabilities first, then stop runtime effects;
5. `uninstall`: remove a disabled plugin and its grants.

`install != enable != authorize`. A plugin cannot self-grant permissions.
Unknown permissions are rejected. Missing required permissions prevent enable.
Profiles may select a set of plugins, but cannot expand host policy.

Risk tiers guide isolation:

| Tier | Examples | Minimum execution policy |
| --- | --- | --- |
| `T0` | Schemas and static metadata | Pure data validation. |
| `T1` | Deterministic transforms | In-process is acceptable. |
| `T2` | Workspace reads | Built-in initially; scoped read grants. |
| `T3` | Network, filesystem writes, subprocesses | Built-in initially; subprocess isolation before third-party support. |
| `T4` | Credentials, identity delegation, payment commit | Separate process or WASI-style isolation plus explicit mandate. |

Permission metadata does not sandbox in-process Python. Until an isolation
backend exists, only reviewed built-ins may run in process.

Lifecycle changes are written to a bounded, append-only local hash chain. It
detects truncation, malformed transitions, and ordinary record mutation, but
it is not signed and is not authoritative against an attacker who can rewrite
the entire workspace. The host restores grants and the desired state from this
projection but never auto-enables a plugin after restart.

A reviewed built-in whose manifest digest changes must use the explicit
upgrade registration path. The audit binds the previous and replacement
digests, then clears every grant and the desired-enabled flag. Code upgrades
therefore require fresh operator authorization instead of inheriting authority
from a different artifact.

In-process startup is also cooperative: Host API v1 keeps plugin code outside
the global registry lock, but Python cannot safely terminate a factory or
`start()` call that never returns. This is another reason third-party runtimes
require a subprocess or WASI isolation phase.

## Irreversible Effects

Runtime registration can be reversible; real-world side effects cannot. A
payment, message delivery, shipment, or remote deletion follows:

```text
observe -> propose -> prepare -> authorize -> commit -> receipt
                                                    -> compensate (optional)
```

Every commit binds an idempotency key, the applicable mandate and terms,
deadline/timeout policy, executor identity, and a durable receipt. A plugin
cannot describe a committed external effect as "rolled back" merely because it
was disabled.

Host API v1 rejects every capability classified as `irreversible`. Merely
requiring mandate and idempotency strings would not prevent a crash between an
external commit and local persistence. T4 commit execution remains disabled
until an isolated executor, durable idempotency ledger, prepare/commit recovery,
and receipt reconciliation are implemented and tested together.

## Failure And Recovery

- One malformed manifest must not prevent safe-mode startup.
- A failed plugin is quarantined with bounded diagnostic text.
- Capability registration is atomic: partial provider maps are never visible.
- Disable removes routing before invoking plugin cleanup.
- Startup and cleanup failures are auditable but cannot forge success.
- Plugins must declare whether retry is safe, best effort, at-most-once, or
  fail-closed.

## Reference Migration

The first reference plugin wraps existing federation discovery without
changing feed digests, peer identity verification, DNS/IP pinning, cache
limits, or wire endpoints. It proves host lifecycle and capability resolution;
it does not rewrite the federation protocol.

The web runtime statically registers this reviewed adapter and exposes its
status through `/api/plugins`. Registration deliberately does not authorize,
enable, or invoke network access. The existing federation poller remains the
production consumer until an operator activation API and a capability-based
consumer migration are reviewed; the reference plugin must not be described
as having replaced that path yet.

Migration order:

1. plugin manifest, capability contract, registry, and lifecycle tests;
2. federation discovery as a reviewed built-in provider;
3. optional curated registry discovery as an accelerator whose results are
   reverified by the trust kernel;
4. agent backends, then transport and message retention providers;
5. settlement and payment providers only after subprocess isolation and
   mandate-bound commit tests exist.
