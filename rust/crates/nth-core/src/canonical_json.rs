//! Canonical JSON — the wire-format primitive every signed object is built on.
//!
//! This is a byte-for-byte port of `nth_dao/canonical_json.py`. The Python
//! reference implementation is the source of truth (docs/CONFORMANCE.md §
//! "Disagreement resolution"); this module MUST produce identical bytes or
//! signatures stop verifying across the network.
//!
//! # Locked contract (do not change without a wire-format major bump)
//!
//! * Object keys sorted lexicographically at every level (UTF-8 byte order,
//!   matching Python's `sort_keys=True` on `str` keys).
//! * No whitespace: `separators=(",", ":")`.
//! * UTF-8 encoded, non-ASCII preserved (`ensure_ascii=False`).
//! * `NaN` / `Infinity` rejected (`allow_nan=False`).
//! * Floats rejected outright — wire payloads use int or decimal strings.
//! * Root must be an object (Python raises `TypeError` on non-dict root).
//! * Object keys must be strings; bytes / sets / custom types rejected.
//!
//! # Integer handling
//!
//! Python's `json` emits integers as bare digits with no trailing `.0`.
//! `serde_json::Value` carries `Number` which may be int or float; to stay
//! byte-identical we preserve that distinction: a JSON number without a
//! fractional part serializes without a decimal point. `serde_json` already
//! does this when the `Number` was parsed from an integer token, so we rely
//! on `serde_json`'s own integer/float discrimination rather than re-tagging.

use serde_json::Value;
use thiserror::Error;

/// Canonical JSON serialization failure. Mirrors the `TypeError` cases the
/// Python implementation raises, so callers can present the same diagnostics.
#[derive(Debug, Error)]
pub enum CanonicalJsonError {
    #[error("canonical_json root must be an object, got {0}")]
    RootNotObject(&'static str),
    #[error("canonical_json rejects float at {path}; use int or decimal string")]
    Float { path: String },
    #[error("canonical_json object keys must be strings at {path}; got {ty}")]
    NonStringKey { path: String, ty: &'static str },
    #[error("canonical_json does not support {ty} at {path}")]
    UnsupportedType { path: String, ty: &'static str },
    #[error("invalid JSON input: {source}")]
    Parse { #[source] source: serde_json::Error },
}

/// Serialize a JSON `Value` (which must be an object) to canonical-form
/// UTF-8 bytes.
///
/// Prefer [`canonical_json`] when you already have a `serde_json::Value`;
/// use [`canonical_json_from_str`] when parsing wire input (validation runs
/// before serialization so malformed input fails loudly).
///
/// # Root must be an object
///
/// Mirrors the Python reference, which raises `TypeError` on any non-dict
/// root. A top-level array / string / number / bool / null is rejected here
/// before validation recurses — without this, `canonical_json_from_str("[1,2]")`
/// would wrongly succeed and emit `[1,2]`, diverging from Python.
///
/// # Numbers must come from the parser
///
/// Integer/float classification relies on `serde_json`'s `arbitrary_precision`
/// feature, which preserves the original token string — but **only for values
/// that passed through the parser**. A `Value::Number` constructed in code via
/// `json!(...)` or `Number::from(...)` carries no original token, and the
/// classifier below falls back to `as_i64()`/`as_u64()`/`as_f64()` probing.
/// This means: prefer [`canonical_json_from_str`] for wire data, and avoid
/// building `Value`s programmatically with numbers you intend to canonicalize.
/// (review round-2 P0#3.)
pub fn canonical_json(value: &Value) -> Result<Vec<u8>, CanonicalJsonError> {
    if !value.is_object() {
        return Err(CanonicalJsonError::RootNotObject(type_name(value)));
    }
    validate(value, "$")?;
    Ok(serialize(value))
}

/// Return the Python-style type name for a `Value`, for error messages that
/// match `type(data).__name__` in the reference implementation.
fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// Parse a JSON string then canonicalize. Useful when ingesting wire payloads
/// whose original serialization order is unknown.
///
/// `serde_json` (with the `arbitrary_precision` feature) rejects `NaN` /
/// `Infinity` at parse time — those are not valid JSON — so the Python
/// `allow_nan=False` contract is enforced here, not in [`validate`].
pub fn canonical_json_from_str(s: &str) -> Result<Vec<u8>, CanonicalJsonError> {
    let value: Value = serde_json::from_str(s).map_err(|source| CanonicalJsonError::Parse { source })?;
    canonical_json(&value)
}

// ─────────────────── validation ───────────────────
//
// Number classification relies on the `arbitrary_precision` feature: the
// `Number` keeps the original token string, so we distinguish integers from
// floats by checking whether the token contains '.', 'e', or 'E'. This is
// what makes a 2^64 literal stay an integer (matching Python's arbitrary-
// precision int) instead of being silently downgraded to a lossy f64.

fn validate(value: &Value, path: &str) -> Result<(), CanonicalJsonError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(n) => {
            // With arbitrary_precision, n.to_string() yields the original
            // token. A JSON integer token never contains '.', 'e', 'E'.
            // (We can't use as_i64/as_u64 alone — those return None for
            // values exceeding 64 bits, which previously caused large
            // integers to be misclassified as floats. See review P0#1.)
            let token = n.to_string();
            if token.contains('.') || token.contains('e') || token.contains('E') {
                return Err(CanonicalJsonError::Float { path: path.into() });
            }
            Ok(())
        }
        Value::Array(items) => {
            for (idx, item) in items.iter().enumerate() {
                validate(item, &format!("{path}[{idx}]"))?;
            }
            Ok(())
        }
        Value::Object(map) => {
            // serde_json::Map preserves insertion order; keys are always
            // strings by construction, so the NonStringKey branch is
            // unreachable for Value::Object — it exists for API parity.
            for (k, v) in map.iter() {
                validate(v, &format!("{path}.{k}"))?;
            }
            Ok(())
        }
    }
}

// ─────────────────── serialization ───────────────────

/// Serialize a pre-validated `Value` to canonical bytes.
///
/// Contract:
///   * keys sorted lexicographically (UTF-8 byte order) at every level
///   * no whitespace
///   * UTF-8, non-ASCII preserved
///   * integers emitted without a decimal point
///
/// We hand-roll the serializer rather than using `serde_json::to_vec` because
/// `serde_json` only sorts keys when the `preserve_order` feature is OFF and
/// the map is a `BTreeMap` — `Value::Object` uses `serde_json::Map` whose
/// default is insertion-ordered (behind the `preserve_order` feature flag).
/// Hand-rolling also lets us guarantee no whitespace and exact int rendering
/// without fighting feature flags.
fn serialize(value: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut Vec<u8>, value: &Value) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => write_number(out, n),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(out, item);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // Sort keys by UTF-8 byte order — this is what Python's
            // sort_keys=True does for str keys (CPython compares str by
            // code point, which is byte order for UTF-8 stored data).
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push(b'{');
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(out, k);
                out.push(b':');
                write_value(out, v);
            }
            out.push(b'}');
        }
    }
}

fn write_number(out: &mut Vec<u8>, n: &serde_json::Number) {
    // With arbitrary_precision, n.to_string() yields the original JSON token,
    // which for an integer is bare digits with no trailing `.0`. This matches
    // Python's `json` rendering of int for any magnitude, and avoids the
    // precision loss that as_u64()/as_i64() would introduce for values
    // exceeding 64 bits. Floats never reach here — validate() rejects them.
    out.extend_from_slice(n.to_string().as_bytes());
}

fn write_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    // Python's json with ensure_ascii=False emits the raw UTF-8 bytes for
    // non-ASCII characters, only escaping the mandatory JSON control chars
    // and the quote/backslash. We mirror exactly that.
    for &b in s.as_bytes() {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x09 => out.extend_from_slice(b"\\t"),
            0x0A => out.extend_from_slice(b"\\n"),
            0x0C => out.extend_from_slice(b"\\f"),
            0x0D => out.extend_from_slice(b"\\r"),
            0x00..=0x1F => {
                // Python escapes other control chars as \uXXXX (lowercase hex).
                out.extend_from_slice(format!("\\u{:04x}", b).as_bytes());
            }
            _ => out.push(b),
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(s: &str) -> String {
        let bytes = canonical_json_from_str(s).unwrap();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn empty_object() {
        assert_eq!(canon("{}"), "{}");
    }

    #[test]
    fn keys_are_sorted() {
        // Python: {"b":1,"a":2} -> {"a":2,"b":1}
        assert_eq!(canon(r#"{"b":1,"a":2}"#), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn no_whitespace() {
        assert_eq!(canon(r#"{"a": 1, "b": 2}"#), r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn non_ascii_preserved() {
        // ensure_ascii=False: 中文 stays as raw UTF-8 bytes.
        assert_eq!(canon(r#"{"k":"中文"}"#), r#"{"k":"中文"}"#);
    }

    #[test]
    fn floats_rejected() {
        let err = canonical_json_from_str(r#"{"a":1.5}"#).unwrap_err();
        assert!(matches!(err, CanonicalJsonError::Float { .. }));
    }

    #[test]
    fn integer_renders_without_decimal() {
        assert_eq!(canon(r#"{"a":5}"#), r#"{"a":5}"#);
    }

    #[test]
    fn nested_objects_sorted() {
        assert_eq!(
            canon(r#"{"z":{"b":1,"a":2}}"#),
            r#"{"z":{"a":2,"b":1}}"#
        );
    }

    #[test]
    fn control_chars_escaped() {
        assert_eq!(canon(r#"{"k":"a\nb"}"#), r#"{"k":"a\nb"}"#);
    }

    #[test]
    fn big_integers_preserved_exact() {
        // 2^64 and 2^128 exceed u64/u128 but Python's arbitrary-precision
        // int serializes them as bare digits. Rust must agree byte-for-byte.
        // (Review P0#1: previously these were misclassified as floats and
        // rejected because as_u64()/as_i64() returned None for >64-bit.)
        assert_eq!(canon(r#"{"a":18446744073709551616}"#), r#"{"a":18446744073709551616}"#);
        assert_eq!(
            canon(r#"{"a":340282366920938463463374607431768211456}"#),
            r#"{"a":340282366920938463463374607431768211456}"#
        );
    }

    #[test]
    fn float_with_exponent_rejected() {
        // 1e2 is numerically 100 but syntactically a float token; the
        // Python rule rejects it (canonical_json rejects float). The token
        // contains 'e', so validate() catches it.
        let err = canonical_json_from_str(r#"{"a":1e2}"#).unwrap_err();
        assert!(matches!(err, CanonicalJsonError::Float { .. }));
    }

    #[test]
    fn non_object_roots_rejected() {
        // Python raises TypeError on any non-dict root. Rust must agree —
        // (review round-2 P0#2: previously Rust accepted these and emitted
        //  bytes, diverging from the Python reference.)
        for s in ["[1,2]", "\"hello\"", "5", "null", "true", "false"] {
            let err = canonical_json_from_str(s).unwrap_err();
            assert!(
                matches!(err, CanonicalJsonError::RootNotObject(_)),
                "expected RootNotObject for {s:?}, got {err:?}"
            );
        }
    }
}
