//! NTH DAO wire-protocol primitives in Rust.
//!
//! This is the foundational layer of an independent Rust port of the nth-dao
//! wire protocol. It implements the byte-for-byte contract defined in
//! `docs/CONFORMANCE.md` and `docs/PROTOCOLS.md`: a Rust implementation is
//! wire-compatible with the Python reference iff the conformance runner
//! produces zero failures against `nth_dao/conformance/vectors.json`.
//!
//! # Modules
//!
//! * [`canonical_json`] — the wire serialization every signed object uses.
//! * [`identity`] — Ed25519 keypairs, agent IDs, fingerprints.
//! * [`did_key`] — W3C did:key encoding for Ed25519 pubkeys.
//!
//! # Design rule
//!
//! The Python reference implementation is the source of truth. When this
//! crate disagrees with Python on a byte, this crate is wrong — fix it here,
//! never touch `nth_dao/`.

pub mod canonical_json;
pub mod did_key;
pub mod identity;

// Re-export only the highest-level entry points. Submodule functions are
// reached via their module path (e.g. `nth_core::did_key::encode_ed25519_did_key`)
// so the crate root stays navigable as Phase 2 adds mandate/gossip modules.
// (Review P2#11: previously the root re-exported every symbol, which would
//  collapse into an unscannable flat list as the crate grows.)
pub use canonical_json::{canonical_json, canonical_json_from_str, CanonicalJsonError};
pub use identity::{signing_key_from_seed, signing_key_from_seed_hex, SigningKey};
