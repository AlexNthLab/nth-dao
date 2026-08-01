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

**Total: 39 vectors.** This grows with the protocol.

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
