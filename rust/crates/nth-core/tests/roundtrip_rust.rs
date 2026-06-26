//! Direction 2 of the cross-language round-trip, as a Rust integration test.
//!
//! `tests/roundtrip.py` runs direction 1 (Rust signs → Python verifies) and,
//! for direction 2, has Python sign a fresh message and write the payload to
//! a JSON file. This test reads that file and verifies the Python-produced
//! signature under `ed25519-dalek`. Running the Python script first makes
//! direction 2 a live check — no hardcoded signature snapshot — so any
//! divergence between PyNaCl and ed25519-dalek is caught on the next run
//! (review round-2 P1#4).
//!
//! This test requires `python3` + `pynacl` on PATH. It is skipped (not
//! failed) if either is unavailable, so it never blocks a Rust-only build.

use std::process::Command;

use nth_core::identity::{signing_key_from_seed, verify};
use serde_json::Value;

fn alice_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = 1;
    s
}

#[test]
fn direction2_python_signature_verifies_under_rust() {
    // CARGO_MANIFEST_DIR is crates/nth-core; roundtrip.py and target/ live
    // two levels up at the workspace root.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let script = format!("{manifest_dir}/../../tests/roundtrip.py");
    let rust_bin = format!(
        "{manifest_dir}/../../target/debug/examples/sign_for_python"
    );

    // Run the Python script: it runs direction 1 itself and writes the
    // direction-2 payload to NTH_ROUNDTRIP_OUT.
    let out_path = "/tmp/nth_roundtrip_d2.json";
    let status = Command::new("python3")
        .arg(&script)
        .arg(&rust_bin)
        .env("NTH_ROUNDTRIP_OUT", out_path)
        .output();

    let output = match status {
        Ok(o) => o,
        Err(_) => {
            eprintln!("skipped: python3 not on PATH");
            return;
        }
    };
    if !output.status.success() {
        // Direction 1 failed inside Python — that's a real failure, not a skip.
        // But if pynacl is missing, Python errors before direction 1. Detect
        // that case and skip rather than fail.
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No module named 'nacl'") {
            eprintln!("skipped: pynacl not installed");
            return;
        }
        panic!(
            "roundtrip.py failed: {}\n--- stderr ---\n{}",
            output.status,
            stderr
        );
    }

    let payload = std::fs::read_to_string(out_path)
        .expect("direction-2 payload file should exist after roundtrip.py");
    let v: Value = serde_json::from_str(&payload).expect("payload is valid JSON");
    let msg_hex = v["msg_hex"].as_str().expect("msg_hex present");
    let sig_hex = v["sig_hex"].as_str().expect("sig_hex present");

    let msg = hex::decode(msg_hex).expect("msg_hex is valid hex");
    let sig = hex::decode(sig_hex).expect("sig_hex is valid hex");

    let sk = signing_key_from_seed(&alice_seed());
    let pk = sk.pubkey();
    verify(&pk, &msg, &sig).expect("Python-produced signature must verify under Rust");
}
