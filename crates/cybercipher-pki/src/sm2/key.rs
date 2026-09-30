//! SM2 key generation, key material, and key-format handling (SEC1 raw
//! encodings) for CyberCipher.
//!
//! Transport shapes (both lowercase hex strings, the CyberCipher big-int
//! transport):
//! - private keys: fixed-width 32-byte big-endian scalar (zero and
//!   non-canonical scalars >= group order rejected);
//! - public keys: SEC1 encoded, compressed (`02/03||x`, 33 bytes) or
//!   uncompressed (`04||x||y`, 65 bytes). Uncompressed is the SM2 convention;
//!   compressed is accepted and produced for parity with the ECC module.
//!
//! PKCS#8/SPKI/PEM containers for SM2 are a later phase; this module covers
//! the raw key material the interactive operations need.

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sm2::elliptic_curve::sec1::ToEncodedPoint as _;

use super::{SM2_PUBLIC_COMPRESSED_LEN, SM2_PUBLIC_UNCOMPRESSED_LEN, SM2_SCALAR_LEN};
use crate::ecc::{
    decode_hex, decode_scalar_hex, invalid_key, invalid_point, wrong_curve, wrong_encoding,
    wrong_length,
};
use crate::error::PkiResult;
use crate::keys::to_hex;

// ---------------------------------------------------------------------------
// Transport structs (serde boundary)
// ---------------------------------------------------------------------------

/// Full SM2 private key material as hex strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sm2KeyPair {
    /// Secret scalar, 32-byte big-endian hex (64 hex chars).
    pub private_hex: String,
    /// SEC1 compressed public key (`02/03||x`, 33 bytes).
    pub public_compressed_hex: String,
    /// SEC1 uncompressed public key (`04||x||y`, 65 bytes) — the SM2
    /// convention.
    pub public_uncompressed_hex: String,
}

/// SM2 public-key material as hex strings (both SEC1 encodings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sm2PublicKeyMaterial {
    /// SEC1 compressed public key (`02/03||x`, 33 bytes).
    pub public_compressed_hex: String,
    /// SEC1 uncompressed public key (`04||x||y`, 65 bytes) — the SM2
    /// convention.
    pub public_uncompressed_hex: String,
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generate an SM2 keypair. Entropy comes from the OS RNG.
pub fn generate_sm2_keypair() -> PkiResult<Sm2KeyPair> {
    // Same proven entropy path as the NIST curves in `crate::ecc::curve`:
    // `SecretKey::random` yields a nonzero scalar in [1, n-1].
    let secret = sm2::SecretKey::random(&mut OsRng);
    keypair_from_secret(&secret)
}

/// Task-named entry point: parse a private key from a fixed-width 32-byte hex
/// scalar (shorter input is left-padded, longer input rejected) and derive the
/// public key. Rejects zero and non-canonical (>= group order) scalars.
pub fn parse_sm2_private_key(private_hex: &str) -> PkiResult<Sm2KeyPair> {
    let secret = secret_from_hex(private_hex)?;
    keypair_from_secret(&secret)
}

/// Task-named entry point: parse a public key from hex-encoded SEC1 bytes
/// (compressed or uncompressed) and validate the point is on the sm2p256v1
/// curve.
pub fn parse_sm2_public_key(public_hex: &str) -> PkiResult<Sm2PublicKeyMaterial> {
    let public = public_from_hex(public_hex)?;
    Ok(public_material_from_key(&public))
}

// ---------------------------------------------------------------------------
// Internal parse/serialize helpers (shared by sign + encrypt)
// ---------------------------------------------------------------------------

/// Parse a 32-byte big-endian private scalar from hex into a crate-level
/// `SecretKey`, rejecting zero and scalars >= the group order.
pub(crate) fn secret_from_hex(private_hex: &str) -> PkiResult<sm2::SecretKey> {
    // JWK-style short scalars strip leading zeros, which can produce
    // odd-length hex. Left-pad to even length before strict decoding —
    // a 63-char scalar is the same integer as the 64-char padded form.
    let padded = if !private_hex.len().is_multiple_of(2) {
        format!("0{private_hex}")
    } else {
        private_hex.to_string()
    };
    let bytes = decode_scalar_hex("private_key", &padded, SM2_SCALAR_LEN)?;
    let field = sm2::FieldBytes::clone_from_slice(&bytes);
    sm2::SecretKey::from_bytes(&field).map_err(|e| {
        invalid_key("invalid private key scalar: not in the SM2 curve group order range")
            .with_parameter("private_key")
            .with_details(e.to_string())
    })
}

/// Parse an SM2 public key from hex-encoded SEC1 bytes with the same
/// tag/length/on-curve validation as the NIST paths, plus wrong-curve length
/// hints. Note: P-256 SEC1 points have *exactly* the same encodings lengths as
/// SM2 (33/65 bytes), so a P-256 key cannot be told apart by size — the
/// on-curve check rejects it at parse time instead.
pub(crate) fn public_from_hex(public_hex: &str) -> PkiResult<sm2::PublicKey> {
    let bytes = decode_hex("public_key", public_hex)?;
    let compressed_len = SM2_PUBLIC_COMPRESSED_LEN;
    let uncompressed_len = SM2_PUBLIC_UNCOMPRESSED_LEN;
    if bytes.len() != compressed_len && bytes.len() != uncompressed_len {
        // Wrong-curve length hints for the encodable-but-different sizes.
        if bytes.len() == 32 {
            return Err(wrong_curve("sm2", "ed25519/x25519").with_details(
                "input length 32 bytes matches a raw Ed25519 or X25519 key, not a SEC1 SM2 point",
            ));
        }
        if bytes.len() == 49 || bytes.len() == 97 {
            return Err(wrong_curve("sm2", "p384").with_details(format!(
                "input length {} bytes matches a p384 key",
                bytes.len()
            )));
        }
        return Err(wrong_length(
            "public_key",
            format!(
                "{compressed_len} bytes (compressed) or {uncompressed_len} bytes (uncompressed)"
            ),
            format!("{} bytes", bytes.len()),
        ));
    }
    let first = bytes[0];
    let tag_ok = match first {
        0x02 | 0x03 => bytes.len() == compressed_len,
        0x04 => bytes.len() == uncompressed_len,
        _ => false,
    };
    if !tag_ok {
        return Err(wrong_encoding(format!(
            "invalid SEC1 point encoding: expected tag 0x02/0x03 with {compressed_len} bytes \
             or tag 0x04 with {uncompressed_len} bytes, found tag 0x{first:02x} with {} bytes",
            bytes.len()
        ))
        .with_parameter("public_key"));
    }
    sm2::PublicKey::from_sec1_bytes(&bytes).map_err(|e| {
        invalid_point(
            "sm2",
            format!(
                "SEC1 point rejected: {e} (coordinates may be non-canonical or the point may \
                 not satisfy the curve equation y^2 = x^3 + a*x + b)"
            ),
        )
    })
}

/// Hex-string material for a validated `SecretKey` (public key derived).
pub(crate) fn keypair_from_secret(secret: &sm2::SecretKey) -> PkiResult<Sm2KeyPair> {
    let public = secret.public_key();
    Ok(Sm2KeyPair {
        private_hex: to_hex(secret.to_bytes().as_slice()),
        public_compressed_hex: to_hex(public.to_encoded_point(true).as_bytes()),
        public_uncompressed_hex: to_hex(public.to_encoded_point(false).as_bytes()),
    })
}

/// Hex-string material for a validated `PublicKey` (both SEC1 encodings).
pub(crate) fn public_material_from_key(public: &sm2::PublicKey) -> Sm2PublicKeyMaterial {
    Sm2PublicKeyMaterial {
        public_compressed_hex: to_hex(public.to_encoded_point(true).as_bytes()),
        public_uncompressed_hex: to_hex(public.to_encoded_point(false).as_bytes()),
    }
}
