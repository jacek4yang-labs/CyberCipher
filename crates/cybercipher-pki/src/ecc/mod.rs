//! Elliptic-curve foundation: NIST P-256/P-384 (ECDSA + ECDH), secp256k1
//! (ECDSA + ECDH + Ethereum addresses), Ed25519, and X25519 for CyberCipher.
//!
//! All curve arithmetic comes from the mature RustCrypto crates (`p256`,
//! `p384`, `k256`, `elliptic-curve`, `ed25519-dalek`, `x25519-dalek`) —
//! nothing is implemented by hand. The SPKI/PKCS#8 layer is the same
//! `pkcs8` 0.10 / `spki` 0.7 / `der` 0.7 stack the RSA half of this crate
//! uses, so key formats interoperate (an OpenSSL-generated `openssl pkey
//! -text` EC key parses here and vice versa).
//!
//! The [`attacks`] module adds ECDSA attack helpers (duplicate-`r`
//! detection, nonce-reuse / known-`k` / bounded small-`k` private-key
//! recovery) with mandatory verification of every recovered key against the
//! provided public key; [`registry`] wires them into the operation registry
//! (`cybercipher_pki::ecc::register`).
//!
//! Conventions (shared with the rest of CyberCipher):
//! - Keys, points, and signatures cross the boundary as lowercase big-endian
//!   hex strings (the big-int transport); messages are raw bytes.
//! - Results are serde-serializable structs (snake_case).
//! - No panics on user input: every malformed key, point, signature, PEM, or
//!   DER input is a typed [`PkiError`].
//!
//! Typed error distinctions (by `ErrorKind` + message shape):
//! - invalid key material             -> `KeyError`
//! - wrong curve                      -> `InvalidInput` (expected / actual)
//! - wrong container encoding         -> `Decode`
//! - point not on the curve           -> `KeyError` ("point is not on the curve")
//! - wrong length                     -> `LengthMismatch`
//! - unknown algorithm / named curve  -> `Unsupported`
//!
//! Signature-verification failures are *results* (`valid: false` + a
//! `reason`), not errors — mirroring [`crate::ops::sign`].

pub mod attacks;
pub mod curve;
pub mod ecdh;
pub mod ecdsa;
pub mod ed25519;
pub mod eth;
pub mod registry;
pub mod x25519;

pub use attacks::{
    ecdsa_duplicate_r_detect, ecdsa_known_k_recover, ecdsa_nonce_reuse_recover,
    ecdsa_small_k_recover, EcdsaAttackSignature, EcdsaDuplicateRGroup, EcdsaDuplicateRPair,
    EcdsaDuplicateRReport, EcdsaKeyRecoveryReport, EcdsaPreimage, SMALL_K_DEFAULT,
    SMALL_K_HARD_CAP,
};
pub use curve::{
    ecc_private_key_from_pkcs8_der, ecc_private_key_from_pkcs8_pem, ecc_private_key_to_pkcs8_der,
    ecc_private_key_to_pkcs8_pem, ecc_public_key_from_spki_der, ecc_public_key_from_spki_pem,
    ecc_public_key_to_spki_der, ecc_public_key_to_spki_pem, generate_ecc_keypair, parse_ecc_curve,
    parse_ecc_private_key, parse_ecc_public_key, EccCurve, EccKeyPair, EccPublicKeyMaterial,
};
pub use ecdh::ecdh_shared_secret;
pub use ecdsa::{
    ecdsa_sign, ecdsa_signature_der_to_fixed, ecdsa_signature_fixed_to_der, ecdsa_verify,
    EcdsaDigest, EcdsaNonceMode, EcdsaSignatureFormat, EcdsaVerifyResult,
};
pub use ed25519::{ed25519_sign, ed25519_verify, Ed25519VerifyResult};
pub use eth::{
    eth_address_check, eth_address_from_private, eth_address_from_public, EthAddressCheck,
    ETH_ADDRESS_SIZE,
};
pub use registry::register;
pub use x25519::x25519_shared_secret;

use crate::error::PkiError;

// ---------------------------------------------------------------------------
// Shared hex-transport helpers (pub(crate); used by every ecc submodule)
// ---------------------------------------------------------------------------

/// Decode a hex string (optional `0x` prefix, upper or lower case) into raw
/// bytes. Empty, odd-length, or non-hex input is a typed `Decode` error.
pub(crate) fn decode_hex(parameter: &str, value: &str) -> crate::error::PkiResult<Vec<u8>> {
    let s = value.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.is_empty() {
        return Err(PkiError::decode("empty hex value")
            .with_parameter(parameter)
            .with_expected("non-empty hex string")
            .with_actual(crate::keys::preview(value, 24)));
    }
    if !s.len().is_multiple_of(2) {
        return Err(PkiError::decode("odd-length hex value")
            .with_parameter(parameter)
            .with_expected("even-length hex string")
            .with_actual(crate::keys::preview(value, 24)));
    }
    if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PkiError::decode("non-hex character in hex value")
            .with_parameter(parameter)
            .with_expected("hex characters [0-9a-fA-F]")
            .with_actual(crate::keys::preview(value, 24)));
    }
    let bytes = s
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| (hex_val(pair[0]) << 4) | hex_val(pair[1]))
        .collect::<Vec<u8>>();
    Ok(bytes)
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        // Validation in `decode_hex` guarantees only hex digits reach here.
        _ => b - b'A' + 10,
    }
}

/// Decode a hex string that must be *exactly* `expected_len` bytes long
/// (structured encodings: SEC1 points, signatures, Curve25519 key bytes).
/// No left-padding — leading zeros are significant in these encodings.
pub(crate) fn decode_fixed_hex(
    parameter: &str,
    value: &str,
    expected_len: usize,
) -> crate::error::PkiResult<Vec<u8>> {
    let bytes = decode_hex(parameter, value)?;
    if bytes.len() != expected_len {
        return Err(wrong_length(
            parameter,
            format!("{expected_len} bytes"),
            format!("{} bytes", bytes.len()),
        ));
    }
    Ok(bytes)
}

/// Decode a fixed-width private scalar: shorter hex input is left-padded with
/// zero bytes (JWK-style `d` values often drop leading zeros), longer input is
/// rejected. All-zero scalars are rejected here so callers get a uniform
/// error with the parameter name attached.
pub(crate) fn decode_scalar_hex(
    parameter: &str,
    value: &str,
    field_len: usize,
) -> crate::error::PkiResult<Vec<u8>> {
    let bytes = decode_hex(parameter, value)?;
    if bytes.len() > field_len {
        return Err(wrong_length(
            parameter,
            format!("at most {field_len} bytes"),
            format!("{} bytes", bytes.len()),
        ));
    }
    if bytes.iter().all(|&b| b == 0) {
        return Err(
            invalid_key("private key scalar is zero (not a valid key)").with_parameter(parameter)
        );
    }
    let mut padded = vec![0u8; field_len - bytes.len()];
    padded.extend_from_slice(&bytes);
    Ok(padded)
}

// ---------------------------------------------------------------------------
// Shared typed-error constructors (the five distinctions above)
// ---------------------------------------------------------------------------

/// The key material itself is malformed (bad scalar, zero key, inconsistent
/// bytes). `ErrorKind::KeyError`.
pub(crate) fn invalid_key(message: impl Into<String>) -> PkiError {
    PkiError::key(message)
}

/// The input belongs to a different curve than requested.
/// `ErrorKind::InvalidInput` with `expected` / `actual`.
pub(crate) fn wrong_curve(expected: &str, actual: &str) -> PkiError {
    PkiError::invalid_input("wrong curve: the supplied key material is not for the requested curve")
        .with_parameter("curve")
        .with_expected(expected)
        .with_actual(actual)
}

/// The bytes are well-formed hex but not a valid encoding of the requested
/// object (bad SEC1 tag, wrong PEM label, explicit EC parameters, ...).
/// `ErrorKind::Decode`.
pub(crate) fn wrong_encoding(message: impl Into<String>) -> PkiError {
    PkiError::decode(message)
}

/// The encoded point is not on the requested curve (or failed to decompress).
/// `ErrorKind::KeyError` with a stable "point is not on the curve" message.
pub(crate) fn invalid_point(curve: &str, detail: impl std::fmt::Display) -> PkiError {
    PkiError::key(format!("point is not on the {curve} curve: {detail}"))
        .with_parameter("public_key")
        .with_details(detail.to_string())
}

/// A length constraint on decoded key/signature bytes is violated.
/// `ErrorKind::LengthMismatch` with `expected` / `actual`.
pub(crate) fn wrong_length(parameter: &str, expected: String, actual: String) -> PkiError {
    PkiError::length(expected, actual, "wrong length").with_parameter(parameter)
}

/// Internal invariant violation (a crate returned data that should be
/// impossible). Never produced by user input.
pub(crate) fn internal(message: impl Into<String>) -> PkiError {
    PkiError::internal(message)
}
