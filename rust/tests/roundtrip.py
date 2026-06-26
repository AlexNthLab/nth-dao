#!/usr/bin/env python3
"""Cross-language round-trip test: Rust <-> Python Ed25519 interop.

This is the counterpart to `crates/nth-core/examples/sign_for_python.rs`.
It proves the two implementations interoperate in both directions:

  1. Rust signs (from alice_seed) -> Python verifies with PyNaCl.
  2. Python signs (from alice_seed) -> prints pubkey+sig for Rust to verify.

Run directly to execute the Rust->Python half and print the Python->Rust
payload. The Rust->Python half exits non-zero on failure so it can gate CI.

Usage:
    python3 rust/tests/roundtrip.py <path-to-rust-binary>
"""

import sys
import subprocess

from nacl.signing import SigningKey


def alice_seed() -> bytes:
    return (1).to_bytes(32, "big")


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: roundtrip.py <path-to-sign_for_python-binary>", file=sys.stderr)
        return 2

    rust_bin = sys.argv[1]

    # ── Direction 1: Rust signs, Python verifies ──────────────────────
    out = subprocess.run([rust_bin], capture_output=True, text=True, check=True)
    pk_hex, sig_hex, msg_hex = out.stdout.strip().splitlines()
    pk = bytes.fromhex(pk_hex)
    sig = bytes.fromhex(sig_hex)
    msg = bytes.fromhex(msg_hex)

    # Cross-check pubkey matches what Python derives from the same seed —
    # this is the deepest form of cross-language agreement.
    expected_pk = SigningKey(alice_seed()).verify_key.encode()
    if pk != expected_pk:
        print(f"FAIL: pubkey mismatch — Rust {pk_hex} vs Python {expected_pk.hex()}")
        return 1

    # Verify the Rust-produced signature under the Python-derived pubkey.
    try:
        SigningKey(alice_seed()).verify_key.verify(msg, sig)
    except Exception as e:
        print(f"FAIL: Python could not verify Rust signature: {e}")
        return 1
    print(f"OK direction 1: Rust signature verified by Python")
    print(f"   pubkey={pk_hex}")
    print(f"   sig   ={sig_hex}")

    # ── Direction 2: Python signs, writes payload for Rust to verify ───
    # Python signs a fresh message and writes the payload to a JSON file.
    # The Rust integration test `tests/roundtrip_rust.rs` reads this file
    # and verifies the signature under ed25519-dalek. This makes direction 2
    # a live, CI-generated check rather than a brittle hardcoded snapshot
    # (review round-2 P1#4): if either implementation diverges, the next
    # run of roundtrip.py regenerates a signature the Rust test will reject.
    import json
    import os
    msg2 = b"cross-language round-trip: Python signs, Rust verifies"
    sk = SigningKey(alice_seed())
    sig2 = sk.sign(msg2).signature
    out_path = os.environ.get("NTH_ROUNDTRIP_OUT", "/tmp/nth_roundtrip_d2.json")
    with open(out_path, "w") as f:
        json.dump({"msg_hex": msg2.hex(), "sig_hex": sig2.hex()}, f)
    print(f"OK direction 2: wrote Python-signed payload to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
