# NTH DAO Conformance Test Suite

A wire-protocol port (Rust, Go, TypeScript, …) is **wire-compatible** with
the Python reference implementation iff it produces zero failures when
its implementation of `run_all_vectors()` is run against
[`nth_dao/conformance/vectors.json`](../nth_dao/conformance/vectors.json).

This file is the contract. The vectors file is part of the wire-format spec.

## Why this exists

Wire-protocol specs in plain English (like `docs/PROTOCOLS.md`) tell you
*what* to implement. Conformance vectors tell you *whether you did it right*.

Without them, "I implemented the spec" is a guess. With them, "I pass all
39 vectors" is a checkmark.

## What's Covered

| Category | Count | Tests |
|----------|-------|-------|
| `canonical_json` | 8 | Encoder produces byte-identical output for the same input across implementations. Field-sort order, unicode, nested objects, arrays, booleans, null. |
| `channel_message_canonical` | 2 | Channel message signing payload canonical bytes. |
| `did_key_encoding` | 3 | did:key encoding for deterministic Ed25519 public keys. |
| `fingerprint` | 3 | `AgentIdentity.fingerprint()` = `SHA-256(pubkey_hex or agent_id)[:16]`. |
| `signature_verify` | 3 | Ed25519 verify with fixed test keys: valid signature accepted, wrong pubkey rejected, tampered signature rejected. |
| `endorsement_canonical_payload` | 2 | `Endorsement.signable_dict()` canonicalized produces stable bytes for two field combinations. |
| `invitation_canonical` | 1 | Invitation signing payload canonical bytes. |
| `lan_psk_tag` | 2 | LAN discovery PSK HMAC tag construction. |
| `team_config_canonical` | 1 | TeamConfig owner-signing payload canonical bytes. |
| `template_canonical_payload` | 1 | `MissionTemplate.signable_dict()` canonical bytes. |
| `mandate_intent_canonical` | 1 | IntentMandate canonical bytes. |
| `mandate_cart_canonical` | 1 | CartMandate canonical bytes. |
| `mandate_payment_canonical` | 1 | PaymentMandate canonical bytes. |
| `mandate_negative_binding` | 2 | Cart/payment binding attacks rejected with stable reason substrings. |
| `mandate_negative_expiry` | 1 | Intent expiry check with a fixed clock. |
| `replay_window` | 5 | gossip replay window boundaries (10-min past / 60-sec future drift). |
| `handoff_response_v2` | 1 | Signed handoff supersession response plus the canonical receipt timeline entry that binds target and replacement capsule hashes. |
| `handoff_review_packet_v1` | 1 | Derived handoff review packet canonical bytes, evidence summary, and explicit "not a truth verdict" flags. |
| `trade_offer_announcement_v1` | 6 | Exact signed Offer discovery binding plus title, digest, revision, lifetime, and publisher rejection cases. |
| `trade_offer_head_proof_v1` | 5 | Canonical disclosed revision chain plus missing-genesis, reordering, wrong-head, and expired-claim rejection cases. |

**Total: 51 vectors.** This grows with the protocol.

The Trade Rule Protocol also ships independently versioned vectors under
`nth_dao/trade_rules/vectors/`. Rule Recognition v1 includes canonical bytes,
domain-separated signing bytes, valid recognition/revocation chains, and
negative semantic cases. It also includes exact
`trade.rule.recognition.recorded` audit payloads whose statement digests and
field bindings are independently recomputed by the TypeScript verifier. Both
the Python reference tests and the TypeScript frontend verifier consume the
same checked-in vector. Negative audit vectors cover malformed Ed25519
`did:key` values, impossible calendar dates, and reversed validity intervals;
schema-only acceptance is not treated as semantic conformance.

Market extensions ship a separate deterministic vector at
`nth_dao/market/vectors/market-extensions-v1.json`. It fixes the canonical
inline Resource Descriptor and publication metadata bytes, descriptor content
digest, and negative field/profile/TTL cases. The same extension is embedded
inside the signed Trade Offer v2 vector, so ports must reproduce both the
extension semantics and the enclosing Offer signature/digest. Discovery TTL is
deliberately absent from signed Offer publication metadata because discovery
refresh and Offer validity are separate lifecycles.

Resource Profile Skills ship deterministic positive and tamper vectors at
`nth_dao/market/vectors/resource-profile-v1.json`. The fixture fixes the
publisher DID, domain-separated signature, profile digest, declarative field
schema, schema-validation positive/negative cases, and community-to-Market
category hint. Passing the vector proves wire compatibility only; it does not
recognize the publisher, activate the category mapping, authorize an Adapter,
or grant execution authority.
The vector also fixes the descriptor-reserved attribute field list; Profile v1
implementations must reject schemas that define `community_category`.
It additionally fixes the shared Profile ID grammar, the 190-character wire
limit, and negative non-string/uppercase cases. Implementations must not coerce
non-string Profile IDs before validation.

Plugin Host API v1 ships a separate deterministic vector at
`nth_dao/plugins/vectors/manifest-v1.json`. It fixes the byte-exact manifest,
capability-contract digest, schema digest, permission/effect binding, and
fail-closed negative cases. Passing the vector proves manifest compatibility;
it does not authenticate a publisher, authorize a permission, sandbox Python,
or allow third-party runtime loading. Host API v1 accepts reviewed built-ins
only. Runtime invocation additionally enforces strict input/output schemas,
canonical-JSON normalization, a 1 MiB document ceiling, revocable local
authority, and current permission grants; those runtime controls are covered
by Python tests and are not yet cross-language conformance vectors.

The federation discovery reference plugin separately freezes its capability
contract in `nth_dao/plugins/vectors/federation-discovery-capability-v2.json`.
Version 2 declares both network read and network write because reverse hello
announcements are observable outbound effects. Consumers must not treat the
earlier read-only capability shape as compatible with this contract.

The optional curated-registry accelerator freezes its distinct capability in
`nth_dao/plugins/vectors/curated-registry-capability-v1.json`. Registry index
wire format `nth-dao-peer-registry-v2` is an Ed25519-signed envelope bound to a
locally pinned publisher DID. Conforming consumers enforce its monotonic
version plus same-version envelope-digest equality, issued/expiry window,
response size, and row count before considering rows. An identical envelope
is retry-safe after partial failure; a lower version or same-version content
conflict is rejected. Rows remain hints, not authorities: consumers reject non-HTTPS
candidates, independently resolve and pin each candidate IP, verify its signed
DID identity card, compare any registry DID hint, and apply local learned-peer
admission limits before reporting success. DNS and HTTPS share bounded caller
deadlines; a resolver stall cannot hold the capability indefinitely.
`nth_dao/plugins/vectors/curated-registry-envelope-v2.json` freezes one public
signed envelope for byte-exact cross-implementation verification; it contains
no private key. Passing either vector alone does not prove runtime admission
checks; the negative and integration suites enforce them in the Python host.

The offline agent-provider reference freezes its current capability descriptor in
`agent-session-capability-v2.json`, with complete versioned input/output schemas
and operation cases in the adjacent `agent-session-*-v2.json` files. The original
v1 files remain immutable compatibility vectors; v1 lacks the explicit
`supports_temperature` capability flag and is validated against its own closed
output schema rather than a permissive union. The cases
bind operation-specific required/allowed fields, identifier lexical rules,
canonical bytes (including a Unicode vector), positive documents, negative
documents, the 1 MiB canonical-UTF-8 wire ceiling, and output state semantics.
A protocol digest covers the capability, both schemas, wire limits, and input/output
operation rules. Runtime
tests additionally prove principal-scoped ownership, global and per-principal
capacity, idle-lease reclamation, in-flight lease protection, fail-fast busy
handling, turn-ID deduplication, concurrent cancellation, semantic Host
validation, binding revocation, and host-controlled model/resource/tool policy.
A Node.js consumer independently verifies the frozen canonical bytes and hashes.
A real provider may
reuse the wire protocol only while declaring its process, network, filesystem,
and credential effects truthfully. These vectors prove neither model quality
nor safe external process isolation.

The supervised localhost A2A bridge freezes its effectful contract and fixed
target derivation in
`nth_dao/plugins/vectors/supervised-agent-session-capability-v2.json`. Its v1
descriptor is retained separately for compatibility. Unlike
the offline provider, it declares network read/write and requires the single
`network.client` permission. The target is an Ed25519 `did:key` selected when
the Host registers the plugin; an invocation cannot supply or replace it.
Runtime success additionally requires a verified, durably persisted signed
Receipt bound to the target DID, turn binding, method, request hash, response
hash, requested model, and a canonical digest of every Host-owned execution
control. A v2 turn response exposes the paired `receipt_id` and lowercase
SHA-256 `receipt_content_hash`; non-turn operations and v1 responses do not.
These are audit references, not a truth verdict. The bridge records `prepared`
only after target preflight and records
`dispatched` immediately before crossing the A2A boundary. Completed results
may be replayed after restart and are reverified against the same Receipt rules
as the live response. A dispatched turn is reconciled from a matching verified
Receipt when possible; otherwise it remains outcome-unknown. Retrying the same
turn performs reconciliation only and never dispatches it again. A response
which arrives but fails envelope, budget, or Receipt validation enters the
terminal `rejected` state and also cannot be re-executed. Result bodies have a
bounded replay lifetime, after which the
state is reduced to a hash/Receipt tombstone without permitting re-execution.
State v3 also binds the stable Agent/backend/work-scope revision while excluding
ephemeral localhost port changes.
This is local at-most-once dispatch, not distributed exactly-once execution.
A conforming implementation must report cancellation failure unless its
execution boundary confirms that the in-flight turn stopped.
Passing this descriptor vector alone does not prove those runtime properties;
the negative and real-child integration tests enforce them in Python.

Recognition federation also ships a deterministic multi-page v2 graph in
`rule-recognition-proof-pages-v2.json` and matching page/import schemas. It
covers 129 sequence-linked statements, byte-exact page canonicalization,
per-page digests and signatures, complete page-set reconstruction, and missing,
mixed-observation, and signature-tampered negative sets. The separate
`rule-recognition-proof-import-pages-v2.json` fixture binds every page to its
write-ahead proposal/completion audit payload. Ports must reject projection
unless page indexes are exactly `0..page_count-1`, all shared commitments agree,
and the union of page statement digests matches both `statement_count` and
`statement_set_digest`.

Agreement v1 also carries a deterministic Rule Package Bundle v1 fixture and
negative outer-binding, binding-signature, valid-but-unauthorized binding
signer, and unknown-field cases. Ports must
verify the Offer publisher's domain-separated Offer-to-Package assertion,
canonical base64url resource encoding, the signed Manifest, each resource
digest and size, the Package digest, and all caller-known expected values.
JSON Schema validation alone is insufficient, and a valid bundle grants no
local trust or execution authority.

Agreement v1 additionally fixes deterministic Receipt Review Delivery and
Acknowledgement envelopes. The positive vectors bind the exact Review,
Receipt, Order, reviewer Rule policy, Adapter policy, destination, TTL, nonce,
receiver, and remote Spine event. Negative vectors cover signed delivery
retargeting and ACK audit-event mutation. Ports MUST perform both JSON Schema
validation and the protocol validator's signature, digest, role, policy,
chronology, TTL, and destination checks. A valid ACK is a signed peer retention
claim, not evidence that the Review is true or that delivery, payment, or
settlement occurred.

The same Agreement v1 vector now includes a disputed Receipt Review and a
deterministic Trade Dispute Statement v1 response. Ports must reproduce its
content-derived case and statement identifiers, domain-separated signature,
Order/Receipt/Review bindings, executor response role, typed claim, bounded
evidence references, and exact Package/hook-version selector. In addition to a
signature-tamper case, correctly signed future-time and Review-rebinding cases
must fail for semantic reasons. The TypeScript/WebCrypto suite independently
reproduces the Python canonical and signing bytes, verifies the Python Ed25519
signatures, and demonstrates that source attribution is separate from semantic
validity. Its full statement verifier also checks content-derived IDs,
Order/Receipt/Review digests, party/executor roles, chronology, declared
evidence budgets, and the exact signed Rule Package resources and hook. The
Order, Receipt, and Review supplied as context must independently pass their
own protocol validators; this statement suite binds those artifacts but does
not replace their policy validation. Passing these vectors does not establish
parent-DAG completeness, claim or evidence truth, dispute resolution, or
settlement authority.

The TypeScript reference API enforces that boundary at runtime. Callers must
construct a frozen `VerifiedTradeDisputeArtifacts` bundle with
`createVerifiedTradeDisputeArtifacts()` and provide independent Order,
Execution Receipt, and Receipt Review validators. A structurally identical raw
object is rejected. This prevents a comment or type assertion from silently
standing in for protocol validation.

Agreement v1 also includes destination-bound Trade Dispute Statement Delivery,
receiver-signed Acknowledgement, and claim-not-fact Spine payload vectors. The
Delivery cases cover the intended recipient, exact artifact bindings, TTL,
future creation, retargeting, and signature mutation. The ACK cases bind the
exact Delivery digest, first durable receiver observation, receiver DID, and
remote audit event. Implementations must run semantic signature, role,
destination, chronology, and digest validation after JSON Schema validation.
The vector fixes both canonical envelope bytes and the complete
domain-separated signing input, so ports need not infer a Python-private
prefix. Transport-policy inputs are limited to 86,400 seconds in both
implementations; the shared cases include over-limit TTL, over-limit clock
skew, and an overflow-scale numeric input.
The status `retained-claim-not-adjudicated` is deliberately narrow: passing
these vectors proves wire compatibility, not evidence truth, adjudication,
payment, settlement, or execution authority.
Agreement v1 also fixes the sender-side
`trade.dispute.statement-acknowledged` Spine payload, including Delivery
generation and superseded Delivery digests. This event proves only that the
sender retained a verified receiver ACK; it does not prove the referenced
remote Spine event is retrievable or that the claim is true.

Recognition Policy v1 has a separate deterministic vector in the same
directory. It covers a node-signed genesis, a successor signed by a delegated
controller, byte-exact canonical JSON and domain-separated signing input, and
exact `trade.rule.recognition.policy.updated` Spine payloads. Negative vectors
include a signature-breaking mutation and correctly signed successors with an
unauthorized signer or wrong predecessor. Ports MUST run both structural JSON
Schema validation and semantic chain authorization; accepting a valid Ed25519
signature alone is non-conformant.

## What's NOT covered yet (planned for v0.9.5+)

- Channel message signature verification end-to-end
- Invitation URL round-trip
- TeamConfig owner signature verification end-to-end
- WoT BFS resolution outcomes

These will be added as vectors when their wire format is considered frozen.
Right now they're considered "stable-but-still-tunable".

## Test keys

Vectors use deterministic seed keys (NOT real production keys):

```
alice_seed = 00 00 00 ... 00 01    (32 bytes)
bob_seed   = 00 00 00 ... 00 02
carol_seed = 00 00 00 ... 00 03
```

Implementations MUST derive Ed25519 keypairs from these seeds. NaCl, Rust
`ed25519-dalek`, Go `crypto/ed25519`, and Node's `crypto.sign` will all
produce the same pubkey from the same seed — that's the whole point of
deterministic Ed25519.

## Running vectors from another language

The general pattern any port implements:

```pseudocode
vectors = load_json("vectors.json")
failures = []

for vector in vectors["vectors"]["canonical_json"]:
    expected = hex_decode(vector["expected_bytes_hex"])
    actual   = my_implementation.canonical_json(vector["input"])
    if actual != expected:
        failures.append((vector["id"], expected, actual))

# … same pattern for every category …

assert failures == [], failures
```

## Regenerating vectors (rare)

```bash
python -m nth_dao.conformance.regenerate
```

This OVERWRITES `nth_dao/conformance/vectors.json`. **Only do this when
you have explicitly changed the spec**. Once vectors are released in a
version, they MUST NOT change until the next minor (0.9.x → 0.10.x)
bump that legitimately revises the wire format.

A PR that touches `vectors.json` without `docs/PROTOCOLS.md` updates
should be rejected.

## Versioning

`vectors.json` carries:

- `format: "nth-dao-conformance-v1"` — the schema of the file itself
- `schema_version: 1` — bumped if the runner's expected fields change
- `generated_at` - a deterministic vector-set stamp, not wall-clock time

A port should read both and refuse to run against a vectors file with
mismatched schema. Wire-protocol version negotiation is separate — see
`docs/PROTOCOLS.md §1`.

## Disagreement resolution

If a port disagrees with the Python reference on a vector, **the
Python reference wins until the spec is clarified**. The reference is
the source of truth by definition. If the port's behavior is more
correct, the right move is a PR that updates Python + `vectors.json` +
`docs/PROTOCOLS.md` together.

This rule exists so we never get into a state where two implementations
each claim to be the "real" one. The Python implementation is "the real one"
operationally; the wire format is "the real one" semantically. When they
disagree, fix the bug in Python.
