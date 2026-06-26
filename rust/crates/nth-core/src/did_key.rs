//! W3C did:key encoding/decoding for Ed25519 pubkeys.
//!
//! Byte-for-byte port of `nth_dao/did_key.py`. Pure byte juggling — no crypto
//! needed, so this module has no dependency on ed25519-dalek.
//!
//! # Wire format
//!
//! ```text
//! did:key:z<base58btc(multicodec_prefix || pubkey_bytes)>
//! ```
//! Where the multicodec prefix for Ed25519-pub is `0xed 0x01` and `z` is the
//! base58btc multibase prefix.

use thiserror::Error;

/// multicodec varint for Ed25519-pub = `0xed 0x01`.
const MULTICODEC_ED25519_PUB: &[u8] = &[0xed, 0x01];

/// Base58btc multibase prefix character.
const MULTIBASE_BASE58BTC: char = 'z';

const DID_KEY_PREFIX: &str = "did:key:";

/// Bitcoin base58 alphabet — identical to the Python implementation's
/// `_B58_ALPHABET` constant. Order matters: '1' = 0, '2' = 1, ... 'z' = 57.
const B58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#[derive(Debug, Error)]
pub enum DidKeyError {
    #[error("did string must start with {prefix:?}; got {got:?}")]
    BadPrefix { prefix: &'static str, got: String },
    #[error("only base58btc multibase ('z') is supported; got {0:?}")]
    BadMultibase(char),
    #[error("did:key body is empty after the multibase prefix")]
    EmptyBody,
    #[error("invalid base58 character {char:?} at position {position}")]
    InvalidBase58 { char: char, position: usize },
    #[error("multicodec prefix must be Ed25519-pub (ed01); got {0}")]
    BadMulticodec(String),
    #[error("decoded pubkey must be 32 bytes; got {0}")]
    BadPubkeyLen(usize),
    #[error("Ed25519 pubkey must be 32 bytes; got {0}")]
    BadInputLen(usize),
    #[error("pubkey_hex not valid hex: {0}")]
    BadHex(String),
    #[error("not a DID string: {0:?}")]
    NotADid(String),
    #[error("DID must have format did:<method>:<id>; got {0:?}")]
    BadDidShape(String),
}

// ─────────────────── base58btc ───────────────────
//
// Implemented over a Vec<u8> big-integer rather than a fixed-width integer
// type: did:key payloads are 34 bytes (2 multicodec prefix + 32 pubkey),
// which is 272 bits and would overflow u128. This mirrors what the Python
// reference does implicitly via Python's arbitrary-precision int.

/// Encode bytes to a base58btc string (Bitcoin alphabet).
///
/// Direct port of `_b58encode` in did_key.py: leading zero bytes become
/// leading '1's, then the big-endian integer is written least-significant
/// digit first and reversed.
pub fn b58encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }
    let n_zero = input.iter().take_while(|&&b| b == 0).count();
    // Work on a mutable big-endian byte vector, repeatedly dividing by 58.
    let mut digits: Vec<u8> = Vec::new();
    let mut num: Vec<u8> = input[n_zero..].to_vec();
    if !num.is_empty() {
        loop {
            // Divide num by 58; remainder is the next base58 digit.
            let mut rem: u32 = 0;
            let mut quotient: Vec<u8> = Vec::with_capacity(num.len());
            let mut nonzero_seen = false;
            for &byte in &num {
                let cur = (rem << 8) | byte as u32;
                let q = cur / 58;
                rem = cur % 58;
                if q != 0 {
                    nonzero_seen = true;
                }
                if nonzero_seen || q != 0 {
                    quotient.push(q as u8);
                }
            }
            digits.push(B58_ALPHABET[rem as usize]);
            if quotient.is_empty() || !nonzero_seen {
                break;
            }
            num = quotient;
        }
    }
    digits.reverse();
    let mut out = String::with_capacity(n_zero + digits.len());
    for _ in 0..n_zero {
        out.push('1');
    }
    for d in digits {
        out.push(d as char);
    }
    out
}

/// Decode a base58btc string to bytes.
///
/// Port of `_b58decode`. Leading '1's become leading zero bytes; the rest is
/// base58 → big integer → big-endian bytes.
///
/// Internally the big integer is accumulated little-endian (so carry from
/// `num * 58 + digit` propagates naturally toward higher indices), then
/// reversed to big-endian for output. This mirrors what Python does
/// implicitly with arbitrary-precision int + `to_bytes(..., 'big')`.
pub fn b58decode(s: &str) -> Result<Vec<u8>, DidKeyError> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    let n_zero = s.chars().take_while(|&c| c == '1').count();
    // num is little-endian: num[0] is the least significant byte.
    let mut num: Vec<u8> = Vec::new();
    for (position, c) in s.chars().enumerate() {
        let idx = B58_ALPHABET
            .iter()
            .position(|&b| b as char == c)
            .ok_or(DidKeyError::InvalidBase58 { char: c, position })?;
        // num = num * 58 + idx, carrying from low to high bytes.
        let mut carry = idx as u32;
        for byte in num.iter_mut() {
            let cur = (*byte as u32) * 58 + carry;
            *byte = (cur & 0xff) as u8;
            carry = cur >> 8;
        }
        while carry > 0 {
            num.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // Reverse little-endian → big-endian, then prepend the zero bytes that
    // leading '1's represent.
    num.reverse();
    let mut result = vec![0u8; n_zero];
    result.extend_from_slice(&num);
    Ok(result)
}

// ─────────────────── did:key encode / decode ───────────────────

/// Encode a 32-byte Ed25519 pubkey as a `did:key:z...` string.
pub fn encode_ed25519_did_key(pubkey: &[u8]) -> Result<String, DidKeyError> {
    if pubkey.len() != 32 {
        return Err(DidKeyError::BadInputLen(pubkey.len()));
    }
    let mut payload = Vec::with_capacity(MULTICODEC_ED25519_PUB.len() + pubkey.len());
    payload.extend_from_slice(MULTICODEC_ED25519_PUB);
    payload.extend_from_slice(pubkey);
    let encoded = b58encode(&payload);
    Ok(format!("{DID_KEY_PREFIX}{MULTIBASE_BASE58BTC}{encoded}"))
}

/// Encode a hex pubkey string as a did:key.
pub fn encode_ed25519_did_key_hex(pubkey_hex: &str) -> Result<String, DidKeyError> {
    let pubkey = hex::decode(pubkey_hex).map_err(|e| DidKeyError::BadHex(e.to_string()))?;
    encode_ed25519_did_key(&pubkey)
}

/// Decode a `did:key:z...` string back to the 32-byte Ed25519 pubkey.
pub fn decode_ed25519_did_key(did: &str) -> Result<Vec<u8>, DidKeyError> {
    if !did.starts_with(DID_KEY_PREFIX) {
        return Err(DidKeyError::BadPrefix {
            prefix: DID_KEY_PREFIX,
            got: did.into(),
        });
    }
    let body = &did[DID_KEY_PREFIX.len()..];
    let mut chars = body.chars();
    // body is "z..." — if it's empty (just "did:key:" with no multibase
    // char) report EmptyBody rather than smuggling a '\0' through BadMultibase.
    let mb = chars.next().ok_or(DidKeyError::EmptyBody)?;
    if mb != MULTIBASE_BASE58BTC {
        return Err(DidKeyError::BadMultibase(mb));
    }
    let encoded: String = chars.collect();
    let raw = b58decode(&encoded)?;
    if !raw.starts_with(MULTICODEC_ED25519_PUB) {
        return Err(DidKeyError::BadMulticodec(hex::encode(&raw[..2.min(raw.len())])));
    }
    let pubkey = &raw[MULTICODEC_ED25519_PUB.len()..];
    if pubkey.len() != 32 {
        return Err(DidKeyError::BadPubkeyLen(pubkey.len()));
    }
    Ok(pubkey.to_vec())
}

/// Decode a did:key into a 64-character hex pubkey string.
pub fn decode_ed25519_did_key_hex(did: &str) -> Result<String, DidKeyError> {
    Ok(hex::encode(decode_ed25519_did_key(did)?))
}

/// True iff `s` parses as a valid did:key Ed25519 string.
pub fn is_did_key(s: &str) -> bool {
    s.starts_with(DID_KEY_PREFIX) && decode_ed25519_did_key(s).is_ok()
}

/// Split a DID string into `(method, method_specific_id)`.
///
/// For `did:key:z6Mk...` returns `("key", "z6Mk...")`.
pub fn parse_did(s: &str) -> Result<(String, String), DidKeyError> {
    if !s.starts_with("did:") {
        return Err(DidKeyError::NotADid(s.into()));
    }
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err(DidKeyError::BadDidShape(s.into()));
    }
    let method = parts[1];
    let msid = parts[2];
    if method.is_empty() || msid.is_empty() {
        return Err(DidKeyError::BadDidShape(s.into()));
    }
    Ok((method.to_string(), msid.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_zero_pubkey() {
        // did-001 vector: 32 zero bytes.
        let pk = [0u8; 32];
        let did = encode_ed25519_did_key(&pk).unwrap();
        assert_eq!(
            did,
            "did:key:z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP"
        );
    }

    #[test]
    fn round_trip() {
        let pk: Vec<u8> = (0..32u8).collect();
        let did = encode_ed25519_did_key(&pk).unwrap();
        let decoded = decode_ed25519_did_key(&did).unwrap();
        assert_eq!(decoded, pk);
    }

    #[test]
    fn decode_rejects_bad_prefix() {
        assert!(decode_ed25519_did_key("did:web:foo").is_err());
    }

    #[test]
    fn parse_did_key() {
        let (m, id) = parse_did("did:key:z6Mkabc").unwrap();
        assert_eq!(m, "key");
        assert_eq!(id, "z6Mkabc");
    }

    #[test]
    fn decode_empty_body_gives_empty_body_error() {
        // "did:key:" with nothing after it — previously reported as a bogus
        // BadMultibase('\0'); now EmptyBody (review P2#8).
        let err = decode_ed25519_did_key("did:key:").unwrap_err();
        assert!(matches!(err, DidKeyError::EmptyBody));
    }
}
