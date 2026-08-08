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
