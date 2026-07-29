# Trade Rule Protocol Boundary

Status: accepted for the first implementation slice
Scope: NTH DAO trade protocol v2

## Decision

NTH DAO will provide a stable, local-first protocol kernel for discovering,
negotiating, accepting, executing, and auditing trade rules. It will not encode
one universal commercial rulebook in the Core.

Third parties may publish signed, content-addressed Trade Rule Packages. Each
node decides locally whether to cache, install, trust, reject, or execute a
package. Final Orders bind exact package and dependency digests.

Manifest signature verification proves integrity and publisher-key control. It
does not prove that a rule is safe, trusted, currently acceptable, or suitable
for a trade. Expiry, recognition, revocation, and local policy remain separate
decisions.

## Stable Core

The Core owns:

- NTH Trade Canonical JSON;
- DID signatures and signature domain separation;
- principal-to-agent authority;
- strict Rule Manifest parsing and package digests;
- capability and exact-digest negotiation;
- proposal and acceptance;
- immutable Order snapshots;
- authorized append-only events;
- evidence and signed Receipts;
- replay, size, time, and resource limits;
- fail-closed handling of unsupported required rules.

## Tasks and Market Offers

Tasks remain the demand and collaboration entry point. A Task may be local,
federated, unpaid, or carry a bounty. Claiming a Task creates or links exactly
one Mission; the Mission owns execution state and the Blackboard exposes the
human-visible process.

Market Offers are separate. They describe products, services, or any mutually
accepted exchange without treating money as a privileged resource:

```text
free service          provides=[service]       requests=[]
paid product          provides=[product]       requests=[fiat or token]
barter                provides=[product]       requests=[product]
product for service   provides=[product]       requests=[service]
asset swap            provides=[bitcoin:btc]   requests=[solana:spl:<mint>]
```

Trade Offer v2 therefore uses signed `provides` and `requests` resource legs
rather than a mandatory price field. Resource types, identifiers, units, and
Rule IDs are open namespaced strings. Descriptors and selected Rule Packages
are bound by exact SHA-256 digest. UI categories such as Product and Service
are projections for people, not closed protocol enums.

Every resource leg requires a content-addressed descriptor. Resource IDs use a
bounded URI-like namespace and reject executable or local-path schemes. An
Offer is an immutable revision: revision 1 has no predecessor; each later
revision binds the exact previous Offer digest. `withdrawn` is terminal.
Registries key lifecycle chains by `(publisher_did, offer_id)` and must retain
forks as conflicts rather than silently applying last-write-wins.

The local Offer Store is an append-only JSONL fact source. It stores each
signature-valid content digest once and derives lifecycle views without
rewriting signed records. Out-of-order revisions remain `incomplete` until
their predecessor arrives. Equivocating roots or successors remain `forked`;
known-invalid edges remain `invalid`. No conflicted chain is promoted to a
canonical head. A malformed, oversized, empty, or duplicate stored line blocks
the projection instead of silently restoring an older active revision.

Each local envelope binds its sequence, predecessor envelope hash, Offer
digest, receipt time, and import provenance into a SHA-256 hash chain. A
durable checkpoint detects tail truncation; after a crash, a fully fsynced and
valid tail may advance a stale checkpoint. Record count, total bytes, and line
size are bounded. Local API imports also emit a signed
`trade.offer.imported` Spine event binding the exact sequence, envelope hash,
Offer digest, publisher, Offer ID, and source. Read APIs fail closed if an
existing signed import anchor no longer matches the Offer log.

These controls detect corruption, one-sided rollback, and many accidental
recovery errors. They are not external consensus or immutable storage. An
operator with write access who rolls back both the Offer log and the signed
Spine can still erase local history. Federation must retain and compare signed
heads across nodes before stronger rollback-resistance can be claimed.

An Offer is a signed claim, not proof that an item exists, a valuation is fair,
or settlement is safe. Publishing or verifying an Offer never transfers an
asset. Negotiation must later produce an immutable Order that binds the exact
Offer and Rule Package digests. Funds-capable execution requires a separately
installed, locally approved Adapter and a signed Mandate.

Signature integrity and current activity are separate decisions. Integrity
verification proves the publisher and immutable bytes. Activity evaluation
also checks publication time, expiry, and withdrawal state. Neither decision
grants local trust or confirms that referenced assets exist.

## Extension Boundary

Rule Packages may describe pricing, quantity, fulfillment, acceptance, payment,
dispute, rights, privacy, compliance, or future families. Family and applicable
subject identifiers are open, namespaced strings rather than a closed Core enum.

The manifest parser may preserve declarations for future `adapter`,
`sandboxed_wasm`, and `external_service` modes. Parsing such a declaration does
not make it installed, trusted, ready, or executable. The first implementation
executes nothing and supports only declarative interpretation. A package cannot
execute Python, JavaScript, shell commands, or remote code. Future executable
behavior must use a separately installed, locally approved Adapter implementing
a versioned Hook Contract.

JSON Schema is an interoperability aid, not the complete validator. The
protocol parser additionally enforces bounded canonical JSON, semantic timestamp
ordering, exact DID verification methods, canonical ordering for set-like
arrays, and contradictory-reference rejection.

Untrusted but structurally valid input uses `InspectedTradeRuleManifest` and an
`unverified-sha256:` inspection digest. Only `TradeRuleManifest` represents a
publisher-signature-verified snapshot and may produce the package identity
`sha256:` digest. Both Python and TypeScript verification freeze the exact
canonical bytes before any cryptographic operation.

## Trust and Recognition

Package trust is a local projection. A package cannot declare itself trusted.
Community, DAO, industry, or standards bodies may issue signed recognition,
deprecation, or revocation statements. Those statements inform local policy and
never become an unconditional Core whitelist.

## Compatibility

Existing Commerce v1 remains a separate compatibility profile:

```text
org.nthdao.legacy.single-paid-digital-service/1
```

Its signed wire format is not rewritten in place. Trade Rule Protocol v2 is
introduced through new modules and explicit versioned objects.

## Security Invariants

No Rule Package or Adapter may disable:

- signature and principal authority checks;
- exact digest binding;
- nonce and TTL replay protection;
- object and package resource limits;
- append-only event integrity;
- local execution permissions;
- private-key isolation;
- idempotency for side effects;
- signed Receipts;
- fail-closed required-rule negotiation.

## Delivered Protocol Slices

The reviewed protocol kernel currently contains:

- Rule Manifest v1;
- Trade Offer v2;
- NTH Trade Canonical JSON v1 validation;
- signing and verification;
- signed content digests;
- append-only local Offer storage and deterministic revision projections;
- strict local operator APIs for signed publish, paginated chain listing, and
  exact digest retrieval;
- schemas and deterministic conformance vectors;
- focused tests.

Package loading, Offer federation, negotiation, Orders, UI, payment, and
executable Adapters remain separate independently reviewed slices. The local
HTTP endpoints are not yet a federation protocol. Trade Offer v2 is
declarative only and cannot execute settlement.

## Deferred Repository Quality Sweep

The repository-wide Ruff baseline recorded on 2026-07-29 contains 319
historical findings, primarily in legacy examples and tests. The files changed
for the reviewed Offer Store slice pass their focused Ruff gate, and the full
Python and frontend test suites pass. After the transaction framework reaches
its planned protocol boundary, run a dedicated cleanup series that:

1. freezes and publishes the Ruff configuration used for the baseline;
2. fixes findings by module in reviewable commits, without mechanical behavior
   changes;
3. reruns each affected module's tests after every batch; and
4. makes repository-wide Ruff success a required merge gate.
