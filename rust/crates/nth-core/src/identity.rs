//! Agent identity primitives — Ed25519 keypairs, fingerprints, agent IDs.
//!
//! Port of `nth_dao/identity.py` (the crypto-bearing parts). The Python
//! module also owns canonical_json, but that lives in [`crate::canonical_json`]
//! here to keep the dependency direction flat.
//!
//! # Cross-language determinism
//!
//! CONFORMANCE.md fixes deterministic seed keys:
//!   alice_seed = 0x000…01 (32 bytes), bob_seed = 0x000…02, carol_seed = …03
//!
//! RFC 8032 Ed25519 is deterministic, so `ed25519-dalek` and PyNaCl produce
//! byte-identical pubkeys and signatures from the same seed. This is the
//! foundation that lets Rust sign and Python verify (and vice versa).
//!
//! # Private key hygiene
//!
//! `ed25519-dalek` is built with its `zeroize` feature (see the workspace
//! Cargo.toml), so the 32-byte secret inside [`SigningKey`] is overwritten
//! when the handle drops. Callers should hold keys via the [`SigningKey`]
//! wrapper rather than the raw dalek type: the wrapper centralizes the
//! hygiene contract and stays stable if dalek's zeroize mechanism changes
//! between versions.

use ed25519_dalek::{Signer, SigningKey as DalekSigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Length of the short cryptographic agent_id (first 12 hex chars of the
/// SHA-256 of the pubkey). Matches `AGENT_ID_SHORT_LEN` in identity.py.
pub const AGENT_ID_SHORT_LEN: usize = 12;

/// Length of the identity fingerprint (first 16 hex chars). Matches the
/// Python `fingerprint()` method.
pub const FINGERPRINT_LEN: usize = 16;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("pubkey must be 32 bytes; got {0}")]
    BadPubkeyLen(usize),
    #[error("seed must be 32 bytes; got {0}")]
    BadSeedLen(usize),
    #[error("invalid hex: {0}")]
    BadHex(String),
    #[error("signature verification failed")]
    VerifyFailed,
    #[error("signature must be 64 bytes; got {0}")]
    BadSignatureLen(usize),
    #[error("ed25519 error: {0}")]
    Ed25519(#[from] ed25519_dalek::SignatureError),
}

/// A signing key handle whose secret is zeroized on drop.
///
/// This wraps `ed25519_dalek::SigningKey` (built with the `zeroize` feature),
/// so the 32-byte secret is overwritten when the handle drops. Keeping keys
/// in this wrapper is the documented way to hold private material in this
/// crate.
#[derive(Debug)]
pub struct SigningKey(DalekSigningKey);

impl SigningKey {
    /// Construct from a 32-byte seed. The secret is zeroized on drop.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(DalekSigningKey::from_bytes(seed))
    }

    /// Public key bytes (32) corresponding to this signing key.
    pub fn pubkey(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Sign a message, returning the 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }

    /// Access the underlying dalek key for operations not exposed here.
    pub fn as_dalek(&self) -> &DalekSigningKey {
        &self.0
    }
}

/// A 32-byte Ed25519 public key fingerprint, stored as hex.
///
/// `agent_id` (cryptographic form) = `SHA-256(pubkey).hex()[:12]`.
pub fn agent_id_from_pubkey(pubkey: &[u8]) -> Result<String, IdentityError> {
    if pubkey.len() != 32 {
        return Err(IdentityError::BadPubkeyLen(pubkey.len()));
    }
    let hash = Sha256::digest(pubkey);
    Ok(hex::encode(&hash[..AGENT_ID_SHORT_LEN / 2]))
}

/// `agent_id` from a hex pubkey string.
pub fn agent_id_from_pubkey_hex(pubkey_hex: &str) -> Result<String, IdentityError> {
    let pubkey = hex::decode(pubkey_hex).map_err(|e| IdentityError::BadHex(e.to_string()))?;
    agent_id_from_pubkey(&pubkey)
}

/// Fingerprint of a pubkey: `SHA-256(pubkey_hex)[:16]` (hex).
///
/// Use this when you have a cryptographic identity's pubkey. For plain
/// (non-cryptographic) agent IDs that have no pubkey, use
/// [`fingerprint_of_agent_id`] instead. Splitting the two paths (review P1#4)
/// removes the footgun of the original `fingerprint(either)` signature, where
/// a caller could pass the wrong input and silently get a wrong fingerprint.
pub fn fingerprint_of_pubkey(pubkey_hex: &str) -> String {
    let hash = Sha256::digest(pubkey_hex.as_bytes());
    hex::encode(&hash[..FINGERPRINT_LEN / 2])
}

/// Fingerprint of a plain agent_id: `SHA-256(agent_id)[:16]` (hex).
///
/// This is the fallback path for identities without a cryptographic pubkey.
pub fn fingerprint_of_agent_id(agent_id: &str) -> String {
    let hash = Sha256::digest(agent_id.as_bytes());
    hex::encode(&hash[..FINGERPRINT_LEN / 2])
}

/// Derive a signing key from a 32-byte seed.
///
/// This is the cross-language bridge: CONFORMANCE.md fixes the seeds, and
/// both PyNaCl and ed25519-dalek derive the same keypair from them.
pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_seed(seed)
}

/// Derive a signing key from a hex seed string (64 hex chars).
pub fn signing_key_from_seed_hex(seed_hex: &str) -> Result<SigningKey, IdentityError> {
    let seed = hex::decode(seed_hex).map_err(|e| IdentityError::BadHex(e.to_string()))?;
    if seed.len() != 32 {
        return Err(IdentityError::BadSeedLen(seed.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&seed);
    Ok(SigningKey::from_seed(&arr))
}

/// Sign a canonical-JSON payload. The caller is responsible for producing
/// canonical bytes (see [`crate::canonical_json`]); this is a thin wrapper
/// so the sign-then-verify round trip mirrors `AgentIdentity.sign_json`.
pub fn sign_canonical(signing_key: &SigningKey, canonical_payload: &[u8]) -> String {
    hex::encode(signing_key.sign(canonical_payload))
}

/// Verify a signature against a pubkey.
///
/// Returns `Ok(())` if valid, `Err(VerifyFailed)` otherwise. Mirrors the
/// Python `verify()` method which returns bool — we return a Result so
/// callers can't silently ignore a failure (the iron rule on wire protocols
/// says verification failure MUST drop the message, never `pass`).
pub fn verify(pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<(), IdentityError> {
    let arr: [u8; 32] = pubkey
        .try_into()
        .map_err(|_| IdentityError::BadPubkeyLen(pubkey.len()))?;
    let vk = VerifyingKey::from_bytes(&arr)?;
    if signature.len() != 64 {
        return Err(IdentityError::BadSignatureLen(signature.len()));
    }
    let sig = ed25519_dalek::Signature::from_slice(signature)?;
    vk.verify(message, &sig).map_err(|_| IdentityError::VerifyFailed)
}

/// Verify a signature given hex-encoded pubkey, message, and signature.
///
/// This is the shape the conformance vectors use, so the runner calls it
/// directly.
pub fn verify_hex(
    pubkey_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<bool, IdentityError> {
    let pubkey = hex::decode(pubkey_hex).map_err(|e| IdentityError::BadHex(e.to_string()))?;
    let signature =
        hex::decode(signature_hex).map_err(|e| IdentityError::BadHex(e.to_string()))?;
    match verify(&pubkey, message, &signature) {
        Ok(()) => Ok(true),
        Err(IdentityError::VerifyFailed) => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note on zeroize hygiene (review round-2 P2#7): ed25519-dalek 2.x
    // implements key cleanup by holding its secret scalar inside a
    // `Zeroizing<...>` field, NOT by impl'ing `Zeroize` on `SigningKey`
    // itself. So a `DalekSigningKey: Zeroize` trait bound does NOT hold and
    // can't be used as a compile-time guard. The hygiene guarantee rests on
    // (a) the `zeroize` feature being enabled in the workspace Cargo.toml
    // and (b) dalek's internal `Zeroizing` wrapper running on drop. Both are
    // configuration-level facts; the doc comment on `SigningKey` records the
    // contract. A future dalek version that changes the mechanism must be
    // caught by review, not by the type system.

    // Alice's seed per CONFORMANCE.md: 0x000…01 (32 bytes big-endian).
    fn alice_seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        s[31] = 1;
        s
    }

    #[test]
    fn seed_derives_vector_pubkey() {
        // sig-001 / fp-001 fix this pubkey for alice_seed.
        let sk = signing_key_from_seed(&alice_seed());
        let pk = sk.pubkey();
        assert_eq!(
            hex::encode(pk),
            "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29"
        );
    }

    #[test]
    fn seed_signs_vector_message() {
        // sig-001 message and expected signature.
        let sk = signing_key_from_seed(&alice_seed());
        let msg = b"NTH DAO conformance test message";
        let sig = sk.sign(msg);
        assert_eq!(
            hex::encode(sig),
            "99b105d22a8c1dabf29611308e61763942494d347f695834f1809c838c46f55e936494829e49310db007ba1a0b3f5e51cb3a5768c735108dfd2ad600ddd6f006"
        );
    }

    #[test]
    fn fingerprint_of_pubkey_matches_vector() {
        // fp-001: fingerprint of the alice pubkey hex string.
        let pk_hex = "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29";
        assert_eq!(fingerprint_of_pubkey(pk_hex), "1a2f85ab3c2b5298");
    }

    #[test]
    fn fingerprint_both_functions_callable() {
        // P1#4 split fingerprint() into two named functions to make the
        // pubkey-vs-agent_id intent explicit at the call site. This is a
        // readability improvement only — neither function can *reject* a
        // misused input (both take &str), so there is no type-level guard
        // to assert here. This test only confirms both paths run and emit
        // the documented length. (review round-2 P1#5: the previous name
        // `fingerprint_paths_are_distinct` falsely implied a guard.)
        let s = "abc";
        assert_eq!(fingerprint_of_pubkey(s).len(), FINGERPRINT_LEN);
        assert_eq!(fingerprint_of_agent_id(s).len(), FINGERPRINT_LEN);
        // Same input → same hash (both SHA-256[:16]); documented, not a guard.
        assert_eq!(fingerprint_of_pubkey(s), fingerprint_of_agent_id(s));
    }

    #[test]
    fn agent_id_from_pubkey_is_sha256_prefix() {
        let pk_hex = "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29";
        let pk = hex::decode(pk_hex).unwrap();
        let aid = agent_id_from_pubkey(&pk).unwrap();
        // agent_id = SHA-256(pubkey).hex()[:12]
        let expected = hex::encode(&Sha256::digest(&pk)[..6]);
        assert_eq!(aid, expected);
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let sk = signing_key_from_seed(&alice_seed());
        let pk = sk.pubkey();
        let msg = b"hello";
        let mut sig = sk.sign(msg);
        sig[0] ^= 0xff; // flip bits
        assert!(verify(&pk, msg, &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_length_signature() {
        let sk = signing_key_from_seed(&alice_seed());
        let pk = sk.pubkey();
        // 63 bytes instead of 64 — must be a length error, not a panic.
        let short_sig = [0u8; 63];
        let err = verify(&pk, b"msg", &short_sig).unwrap_err();
        assert!(matches!(err, IdentityError::BadSignatureLen(63)));
    }

    #[test]
    fn verify_rejects_wrong_length_pubkey() {
        // 31 bytes instead of 32 — must be a length error, not a panic.
        let short_pk = [0u8; 31];
        let sig = [0u8; 64];
        let err = verify(&short_pk, b"msg", &sig).unwrap_err();
        assert!(matches!(err, IdentityError::BadPubkeyLen(31)));
    }

    #[test]
    fn bad_seed_hex_length_gives_seed_error() {
        // 16 bytes instead of 32 — must report BadSeedLen, not BadPubkeyLen
        // (review P2#9: the original code mislabeled this as a pubkey error).
        let short_seed_hex = "0011223344556677"; // 8 bytes
        let err = signing_key_from_seed_hex(short_seed_hex).unwrap_err();
        assert!(matches!(err, IdentityError::BadSeedLen(8)));
    }
}
