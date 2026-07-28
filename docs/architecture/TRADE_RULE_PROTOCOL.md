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

## Initial Delivery

The first code slice contains only:

- Rule Manifest v1;
- NTH Trade Canonical JSON v1 validation;
- signing and verification;
- signed-manifest digest;
- conformance vectors;
- focused tests.

Registry, federation, negotiation, Orders, UI, payment, and executable Adapters
are intentionally deferred to later independently reviewed slices.
