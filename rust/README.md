# NTH DAO Rust kernel

An independent Rust port of the nth-dao wire-protocol layer, positioned per
[`docs/CONFORMANCE.md`](../docs/CONFORMANCE.md): a Rust/Go/TypeScript
implementation is **wire-compatible** with the Python reference iff its
conformance runner produces zero failures against
[`nth_dao/conformance/vectors.json`](../nth_dao/conformance/vectors.json).

The Python package under `nth_dao/` is the source of truth. This Rust tree
never edits it; everything lives under `rust/` so the risk radius of any PR
is confined to this directory.

## Status — Phase 1 (this PR)

The foundational, deterministic, pure-function layer:

| Module | What it ports | Python source |
|--------|---------------|---------------|
| `nth-core::canonical_json` | Canonical JSON byte contract (sorted keys, no whitespace, UTF-8, no floats) | `nth_dao/canonical_json.py` |
| `nth-core::identity` | Ed25519 sign/verify from deterministic seeds, SHA-256 fingerprints, agent IDs | `nth_dao/identity.py` |
| `nth-core::did_key` | W3C did:key encode/decode (base58btc + multicodec `ed01`) | `nth_dao/did_key.py` |
| `nth-conformance` | Rust conformance runner | `nth_dao/conformance/runner.py` (subset) |

### Conformance result

```
$ cargo run -p nth-conformance -- ../nth_dao/conformance/vectors.json
nth-dao Rust conformance runner — Phase 1
categories checked: canonical_json, fingerprint, signature_verify, did_key_encoding
17/17 checked vectors passed
20 vectors in 12 unsupported categories (deferred to Phase 2):
  replay_window (5), mandate_* (5), endorsement_canonical_payload (2), ...
overall coverage: 17/37 vectors (45%)
PASS: zero failures among checked categories — wire-compatible with Python reference on the covered subset
```

17 of the 37 conformance vectors are covered — every category whose output
is a pure function of its input (no wall-clock, no network, no Python object
model). The runner reports both the checked-vector result and the overall
coverage so a "17/17" line can't be mistaken for full-suite green. The
remaining categories (`replay_window`, mandate canonical payloads,
endorsement/template/invitation/team_config canonical, LAN PSK tag, mandate
binding/expiry) land in Phase 2 alongside the Rust wire types they depend on.

### Cross-language round-trip

Beyond the fixed conformance vectors, interop is checked in both directions
with fresh (non-vector) inputs:

- **Rust → Python**: `cargo run -p nth-core --example sign_for_python` emits a
  signature; `rust/tests/roundtrip.py` verifies it with PyNaCl and checks the
  derived pubkey matches byte-for-byte.
- **Python → Rust**: `identity::tests::verify_python_produced_signature`
  verifies a fixed PyNaCl-produced signature under `ed25519-dalek`.

Both directions pass. This is the strongest form of cross-language agreement:
the same seed yields the same keypair and signatures across implementations.

## Layout

```
rust/
├── Cargo.toml                 # workspace
├── crates/
│   ├── nth-core/              # wire-protocol primitives (library)
│   │   └── examples/sign_for_python.rs   # round-trip helper
│   └── nth-conformance/       # conformance runner (binary)
└── tests/
    └── roundtrip.py           # Rust→Python interop driver
```

## Running

```bash
# from rust/
cargo test                                # all unit tests
cargo run -p nth-conformance              # conformance (in-tree vectors)
cargo run -p nth-core --example sign_for_python   # emit a signature for Python
python3 tests/roundtrip.py target/debug/examples/sign_for_python
```

## Design rules

1. **Python is the source of truth.** When Rust disagrees with Python on a
   byte, Rust is wrong — fix it here, never touch `nth_dao/`.
2. **Deterministic seeds only.** Every test key derives from the seeds fixed
   in `docs/CONFORMANCE.md` (alice=`0x01`, bob=`0x02`, carol=`0x03`). RFC 8032
   Ed25519 is deterministic, so `ed25519-dalek` and PyNaCl agree byte-for-byte.
3. **No I/O in nth-core.** The library is pure functions over caller-supplied
   bytes — no network, no filesystem, no wall-clock. This keeps it trivially
   testable and is what makes the conformance vectors meaningful.
4. **Integer precision is exact.** `serde_json` is built with
   `arbitrary_precision` so a JSON integer of any magnitude (e.g. 2^64,
   2^128) stays an integer — matching Python's arbitrary-precision `int`.
   Without this, large integers would be silently downgraded to lossy `f64`
   and the byte contract would break on big amounts/timestamps.
5. **Phase 2 extends, never rewrites.** Each new wire type (mandates, gossip
   messages, etc.) adds a module and extends `_CHECKERS` in the runner; it
   does not revisit Phase 1 code.

## Roadmap

- **Phase 2** — wire protocol primitives: W3C VC Data Integrity proof, the
  three Mandates (Intent/Cart/Payment), ChannelMessage/Endorsement/
  Invitation/TeamConfig sign+verify, replay window. Extends conformance to
  all 37 vectors.
- **Phase 3** — AP protocol layer (`nth-ap`): HLC, Intent-Based Delta, Epoch,
  PACR conflict arbitration, with CRDT-backed state merging.
- **Phase 4** (optional) — PyO3 bindings as `nth-dao[fast]`, with the pure
  Python implementation retained as fallback.
- **Phase 5** (optional) — Tauri desktop shell reusing `frontend/`.
