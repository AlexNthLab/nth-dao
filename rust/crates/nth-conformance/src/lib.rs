//! Conformance check logic for nth-dao wire-format vectors.
//!
//! This is the Rust side of the contract in `docs/CONFORMANCE.md`: a Rust
//! implementation is wire-compatible with the Python reference iff running
//! [`run_vectors`] against `nth_dao/conformance/vectors.json` produces zero
//! failures.
//!
//! The check logic lives in a library (not in `main.rs`) so it is unit-
//! testable without spawning the binary, and so a future FFI layer or other
//! crate can reuse it (review round-1 P2#15).

use nth_core::canonical_json;
use nth_core::did_key;
use nth_core::identity::{fingerprint_of_agent_id, fingerprint_of_pubkey, verify_hex};
use serde_json::Value;

/// Categories the Phase-1 runner checks. Time-dependent and Python-object-model
/// categories (`replay_window`, mandates, endorsements, …) are deferred to
/// Phase 2.
pub const SUPPORTED_CATEGORIES: &[&str] = &[
    "canonical_json",
    "fingerprint",
    "signature_verify",
    "did_key_encoding",
];

/// Result of running the full suite against a parsed vectors file.
///
/// Fields are read via accessors rather than exposed `pub` (review round-2
/// P2#10): construction only happens inside [`run_vectors`], which preserves
/// the invariant that `total_checked == passed + failures.len()`.
#[derive(Debug)]
pub struct Report {
    total_checked: usize,
    passed: usize,
    failures: Vec<Failure>,
    unchecked: Vec<(String, usize)>, // (category, count)
}

#[derive(Debug)]
pub struct Failure {
    pub category: String,
    pub id: String,
    pub description: String,
    pub reason: String,
}

impl Report {
    pub fn is_ok(&self) -> bool {
        self.failures.is_empty()
    }
    pub fn total_checked(&self) -> usize {
        self.total_checked
    }
    pub fn passed(&self) -> usize {
        self.passed
    }
    pub fn failures(&self) -> &[Failure] {
        &self.failures
    }
    pub fn unchecked(&self) -> &[(String, usize)] {
        &self.unchecked
    }
}

/// Run all supported categories against `vectors_data`.
pub fn run_vectors(vectors_data: &Value) -> Report {
    let vectors = vectors_data
        .get("vectors")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    let mut total = 0usize;
    let mut passed = 0usize;
    let mut failures: Vec<Failure> = Vec::new();
    let mut unchecked: Vec<(String, usize)> = Vec::new();

    for (cat, items) in vectors.iter() {
        let count = items.as_array().map(|a| a.len()).unwrap_or(0);
        if count == 0 {
            continue;
        }
        if !SUPPORTED_CATEGORIES.contains(&cat.as_str()) {
            unchecked.push((cat.clone(), count));
            continue;
        }
        for v in items.as_array().unwrap() {
            total += 1;
            match check_one(cat, v) {
                Ok(()) => passed += 1,
                Err(reason) => {
                    let id = v
                        .get("id")
                        .and_then(|x| x.as_str())
                        .unwrap_or("?")
                        .to_string();
                    let description = v
                        .get("description")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    failures.push(Failure {
                        category: cat.clone(),
                        id,
                        description,
                        reason,
                    });
                }
            }
        }
    }

    Report {
        total_checked: total,
        passed,
        failures,
        unchecked,
    }
}

fn check_one(category: &str, vector: &Value) -> Result<(), String> {
    match category {
        "canonical_json" => check_canonical_json(vector),
        "fingerprint" => check_fingerprint(vector),
        "signature_verify" => check_signature_verify(vector),
        "did_key_encoding" => check_did_key_encoding(vector),
        _ => Err(format!("unsupported category {category:?}")),
    }
}

fn check_canonical_json(v: &Value) -> Result<(), String> {
    let input = v.get("input").ok_or("missing input")?;
    let expected_hex = v
        .get("expected_bytes_hex")
        .and_then(|x| x.as_str())
        .ok_or("missing expected_bytes_hex")?;
    let expected = hex::decode(expected_hex).map_err(|e| format!("bad expected hex: {e}"))?;
    let actual = canonical_json(input).map_err(|e| format!("canonical_json error: {e}"))?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "bytes differ — expected {} got {}",
            hex::encode(&expected),
            hex::encode(&actual)
        ))
    }
}

fn check_fingerprint(v: &Value) -> Result<(), String> {
    let input = v.get("input").ok_or("missing input")?;
    let expected = v
        .get("expected_fingerprint")
        .and_then(|x| x.as_str())
        .ok_or("missing expected_fingerprint")?;
    // Python: payload = pubkey_hex or agent_id (empty pubkey_hex → agent_id).
    let pubkey_hex = input
        .get("pubkey_hex")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let agent_id = input
        .get("agent_id")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    // The split API (review P1#4) makes the dispatch explicit: if a pubkey
    // is present, fingerprint the pubkey; otherwise fingerprint the agent_id.
    let actual = if !pubkey_hex.is_empty() {
        fingerprint_of_pubkey(pubkey_hex)
    } else {
        fingerprint_of_agent_id(agent_id)
    };
    if actual == expected {
        Ok(())
    } else {
        Err(format!("expected {expected} got {actual}"))
    }
}

fn check_signature_verify(v: &Value) -> Result<(), String> {
    let pubkey_hex = v
        .get("pubkey_hex")
        .and_then(|x| x.as_str())
        .ok_or("missing pubkey_hex")?;
    let message_hex = v
        .get("message_hex")
        .and_then(|x| x.as_str())
        .ok_or("missing message_hex")?;
    let signature_hex = v
        .get("signature_hex")
        .and_then(|x| x.as_str())
        .ok_or("missing signature_hex")?;
    let expected_valid = v
        .get("expected_valid")
        .and_then(|x| x.as_bool())
        .ok_or("missing expected_valid")?;
    let message = hex::decode(message_hex).map_err(|e| format!("bad message hex: {e}"))?;
    // verify_hex returns Err for structural problems (bad pubkey/signature
    // length, bad hex). A single malformed vector must NOT crash the whole
    // category — downgrade every Err to a per-vector failure so the runner
    // keeps checking the remaining vectors. (review round-2 P0#1: previously
    // these propagated via `?` and aborted the signature_verify category.)
    let actual = match verify_hex(pubkey_hex, &message, signature_hex) {
        Ok(b) => b,
        Err(e) => return Err(format!("verify error: {e}")),
    };
    if actual == expected_valid {
        Ok(())
    } else {
        Err(format!("expected valid={expected_valid} got valid={actual}"))
    }
}

fn check_did_key_encoding(v: &Value) -> Result<(), String> {
    let input = v.get("input").ok_or("missing input")?;
    let pubkey_hex = input
        .get("pubkey_hex")
        .and_then(|x| x.as_str())
        .ok_or("missing input.pubkey_hex")?;
    let expected = v
        .get("expected_did")
        .and_then(|x| x.as_str())
        .ok_or("missing expected_did")?;
    let actual = did_key::encode_ed25519_did_key_hex(pubkey_hex)
        .map_err(|e| format!("did_key encode error: {e}"))?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("expected {expected} got {actual}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_is_ok_with_no_failures() {
        let report = Report {
            total_checked: 3,
            passed: 3,
            failures: vec![],
            unchecked: vec![("replay_window".into(), 5)],
        };
        assert!(report.is_ok());
        assert_eq!(report.total_checked(), 3);
        assert_eq!(report.passed(), 3);
        assert_eq!(report.unchecked().len(), 1);
    }

    #[test]
    fn report_is_not_ok_with_failures() {
        let report = Report {
            total_checked: 1,
            passed: 0,
            failures: vec![Failure {
                category: "canonical_json".into(),
                id: "canon-001".into(),
                description: "Empty object".into(),
                reason: "bytes differ".into(),
            }],
            unchecked: vec![],
        };
        assert!(!report.is_ok());
        assert_eq!(report.failures().len(), 1);
    }

    #[test]
    fn run_vectors_classifies_unsupported_categories() {
        // A minimal vectors blob with one supported and one unsupported category.
        let data: Value = serde_json::json!({
            "format": "nth-dao-conformance-v1",
            "schema_version": 1,
            "vectors": {
                "canonical_json": [
                    {"id": "canon-x", "input": {}, "expected_bytes_hex": "7b7d"}
                ],
                "replay_window": [
                    {"id": "replay-x", "offset_seconds": 0, "expected_within_window": true}
                ]
            }
        });
        let report = run_vectors(&data);
        assert_eq!(report.total_checked(), 1);
        assert_eq!(report.passed(), 1);
        assert!(report.is_ok());
        assert_eq!(report.unchecked().len(), 1);
        assert_eq!(report.unchecked()[0].0, "replay_window");
        assert_eq!(report.unchecked()[0].1, 1);
    }
}
