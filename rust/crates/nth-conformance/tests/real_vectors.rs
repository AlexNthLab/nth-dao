//! Integration test that loads the REAL `nth_dao/conformance/vectors.json`
//! and runs `run_vectors` against it.
//!
//! The unit tests in `main.rs` use synthetic minimal blobs; this test guards
//! against the real vectors file changing shape (e.g. a new metadata field)
//! in a way that breaks the runner while synthetic tests stay green
//! (review round-2 P1#6).

use nth_conformance::run_vectors;
use serde_json::Value;

#[test]
fn real_vectors_file_passes_checked_categories() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    // crates/nth-conformance → crates → rust → project root
    let path = format!(
        "{manifest_dir}/../../../nth_dao/conformance/vectors.json"
    );
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read real vectors at {path}: {e}"));
    let parsed: Value = serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("real vectors file is not valid JSON: {e}"));

    let report = run_vectors(&parsed);

    // The four Phase-1 categories must all pass on the real file.
    assert!(
        report.is_ok(),
        "checked categories failed on the real vectors file: {:?}",
        report.failures()
    );
    // And we expect exactly the 17 Phase-1 vectors to be checked.
    assert_eq!(
        report.total_checked(),
        17,
        "Phase 1 should check 17 vectors on the real file; got {}",
        report.total_checked()
    );
    assert_eq!(report.passed(), 17);
    // The remaining categories are deferred, not absent — assert the file
    // still carries them so a future trim is caught.
    assert!(
        !report.unchecked().is_empty(),
        "expected unchecked (Phase 2) categories in the real file"
    );
}
