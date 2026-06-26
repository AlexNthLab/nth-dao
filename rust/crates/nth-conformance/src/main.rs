//! Command-line entry point for the nth-dao Rust conformance runner.
//!
//! The check logic lives in the library (`lib.rs`); this binary only handles
//! file I/O, argument parsing, and report printing.

use std::path::PathBuf;
use std::process::ExitCode;

use nth_conformance::{run_vectors, SUPPORTED_CATEGORIES};
use serde_json::Value;

fn main() -> ExitCode {
    let vectors_path: PathBuf = match std::env::args().nth(1) {
        Some(p) => PathBuf::from(p),
        None => {
            // Default to the in-tree vectors so `cargo run -p nth-conformance`
            // works from the workspace root without arguments.
            let default = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../nth_dao/conformance/vectors.json");
            if !default.exists() {
                eprintln!(
                    "usage: nth-conformance <path-to-vectors.json>\n\
                     (default path {default:?} not found)"
                );
                return ExitCode::from(2);
            }
            default
        }
    };

    let data = match std::fs::read_to_string(&vectors_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", vectors_path.display());
            return ExitCode::from(2);
        }
    };
    let parsed: Value = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: invalid JSON in {}: {e}", vectors_path.display());
            return ExitCode::from(2);
        }
    };

    let format = parsed
        .get("format")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if format != "nth-dao-conformance-v1" {
        eprintln!(
            "error: vectors file has format {format:?}, expected \"nth-dao-conformance-v1\""
        );
        return ExitCode::from(2);
    }

    let schema_version = parsed
        .get("schema_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if schema_version != 1 {
        eprintln!(
            "error: vectors file has schema_version {schema_version}, this runner supports 1"
        );
        return ExitCode::from(2);
    }

    let report = run_vectors(&parsed);

    println!("nth-dao Rust conformance runner — Phase 1");
    println!("vectors file: {}", vectors_path.display());
    println!(
        "categories checked: {}",
        SUPPORTED_CATEGORIES.join(", ")
    );
    println!(
        "{}/{} checked vectors passed",
        report.passed(),
        report.total_checked()
    );

    // Report coverage so 17/17 can't be mistaken for "all vectors pass".
    // (Review round-1 P1#6: the runner previously omitted the unchecked
    //  categories, which could mislead a reader into thinking the whole
    //  suite was green.)
    let total_vectors =
        report.total_checked() + report.unchecked().iter().map(|(_, n)| n).sum::<usize>();
    if !report.unchecked().is_empty() {
        let unchecked_count: usize = report.unchecked().iter().map(|(_, n)| n).sum();
        println!(
            "{} vectors in {} unsupported categor{} (deferred to Phase 2):",
            unchecked_count,
            report.unchecked().len(),
            if report.unchecked().len() == 1 { "y" } else { "ies" }
        );
        for (cat, n) in report.unchecked() {
            println!("  {cat} ({n})");
        }
        println!(
            "overall coverage: {}/{} vectors ({}%)",
            report.total_checked(),
            total_vectors,
            report.total_checked() * 100 / total_vectors.max(1)
        );
    }

    if report.is_ok() {
        println!("PASS: zero failures among checked categories — wire-compatible with Python reference on the covered subset");
        ExitCode::SUCCESS
    } else {
        println!("FAIL: {} failure(s):", report.failures().len());
        for f in report.failures() {
            // Include the description so a maintainer can find the vector in
            // vectors.json without a separate lookup (review round-1 P1#7).
            let desc = if f.description.is_empty() {
                String::new()
            } else {
                format!(" — {}", f.description)
            };
            println!("  [{}] {}{}: {}", f.category, f.id, desc, f.reason);
        }
        ExitCode::FAILURE
    }
}
