//! Cross-language round-trip helper: sign a fixed message with the alice seed
//! and print pubkey + signature as hex on stdout. Consumed by the Python side
//! of the round-trip test to prove Rust-produced signatures verify under PyNaCl.
//!
//! Not part of the library API; it exists solely to feed the integration test
//! at `rust/tests/roundtrip.py`. Run it via:
//!
//! ```text
//! cargo run -p nth-core --example sign_for_python
//! ```

use nth_core::signing_key_from_seed;

fn main() {
    // Alice's seed per CONFORMANCE.md: 0x000…01 (32 bytes big-endian).
    let mut seed = [0u8; 32];
    seed[31] = 1;
    let sk = signing_key_from_seed(&seed);
    let pk = sk.pubkey();
    // A message distinct from the conformance vector's, so this test isn't
    // just re-checking a known vector — it exercises fresh input.
    let msg = b"cross-language round-trip: Rust signs, Python verifies";
    let sig = sk.sign(msg);
    println!("{}", hex::encode(&pk));
    println!("{}", hex::encode(&sig));
    println!("{}", hex::encode(msg));
}
