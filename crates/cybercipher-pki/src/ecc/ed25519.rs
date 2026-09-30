//! Ed25519 signatures (RFC 8032) on `ed25519-dalek` 2.
//!
//! - Keys are the raw 32-byte forms: the seed as the private key and the
//!   compressed Edwards point as the public key.
//! - Signatures are 64 bytes (`R || S`).
//! - PKCS#8 (RFC 8410) and SPKI use `ed25519-dalek`'s own `pkcs8` trait
//!   impls, so OpenSSL-generated `BEGIN PRIVATE KEY` / `BEGIN PUBLIC KEY`
//!   PEMs interoperate.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use super::curve::{EccCurve, EccKeyPair, EccPublicKeyMaterial};
use super::{decode_fixed_hex, internal, invalid_point, wrong_encoding};
use crate::error::PkiResult;
use crate::keys::to_hex;

/// Size of every Ed25519 artifact: seed, public key, and signature.
pub const ED25519_KEY_SIZE: usize = 32;
/// Ed25519 signature size in bytes (`R || S`).
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// Result of an Ed25519 verification. `valid == false` (with a `reason`) is
/// a normal outcome; only malformed inputs produce errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519VerifyResult {
    /// Whether the signature verifies over the data with the given key.
    pub valid: bool,
    /// Why verification failed; `None` when `valid` is `true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Signing / verification
// ---------------------------------------------------------------------------

/// Ed25519 sign. The private key is the 32-byte seed as a hex string; the
/// signature is 64 bytes as a hex string.
pub fn ed25519_sign(private_hex: &str, data: &[u8]) -> PkiResult<String> {
    let signing = parse_signing_key(private_hex)?;
    let signature = signing.sign(data);
    Ok(to_hex(signature.to_bytes().as_ref()))
}

/// Ed25519 verify. The public key is the 32-byte compressed point as a hex
/// string and the signature is 64 bytes as a hex string. A malformed
/// signature length is a typed error; a signature that does not verify is
/// reported as `valid: false`.
pub fn ed25519_verify(
    public_hex: &str,
    data: &[u8],
    signature_hex: &str,
) -> PkiResult<Ed25519VerifyResult> {
    let verifying = parse_verifying_key(public_hex)?;
    let signature_bytes = decode_fixed_hex("signature", signature_hex, ED25519_SIGNATURE_SIZE)?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| {
        wrong_encoding("invalid Ed25519 signature: S must be canonical (< group order)")
            .with_parameter("signature")
    })?;
    Ok(match verifying.verify(data, &signature) {
        Ok(()) => Ed25519VerifyResult {
            valid: true,
            reason: None,
        },
        Err(e) => Ed25519VerifyResult {
            valid: false,
            reason: Some(format!(
                "Ed25519 verification failed (wrong key, tampered data/signature): {e}"
            )),
        },
    })
}

// ---------------------------------------------------------------------------
// Key handling (pub(crate) hooks used by `curve.rs`)
// ---------------------------------------------------------------------------

/// Generate an Ed25519 keypair (fresh random seed from the OS RNG).
pub(crate) fn generate() -> PkiResult<EccKeyPair> {
    let signing = SigningKey::generate(&mut OsRng);
    keypair_from_seed_bytes(signing.as_bytes())
}

/// Parse a 32-byte seed into a keypair with the derived public key.
pub(crate) fn parse_private(private_hex: &str) -> PkiResult<EccKeyPair> {
    let seed = decode_fixed_hex("private_key", private_hex, ED25519_KEY_SIZE)?;
    keypair_from_seed_bytes(
        seed.as_slice()
            .try_into()
            .map_err(|_| internal("seed length invariant violated after fixed-length decode"))?,
    )
}

/// Parse a 32-byte compressed Edwards point into public-key material,
/// validating the point.
pub(crate) fn public_material(public_hex: &str) -> PkiResult<EccPublicKeyMaterial> {
    let verifying = parse_verifying_key(public_hex)?;
    let hex = to_hex(verifying.as_bytes());
    Ok(EccPublicKeyMaterial {
        curve: EccCurve::Ed25519,
        public_compressed_hex: hex.clone(),
        public_uncompressed_hex: hex,
    })
}

/// Raw 32-byte public key (SPKI bit-string payload) into public-key material.
pub(crate) fn public_from_raw_bytes(bytes: &[u8]) -> PkiResult<EccPublicKeyMaterial> {
    let arr: [u8; ED25519_KEY_SIZE] = bytes
        .try_into()
        .map_err(|_| wrong_key_len(ED25519_KEY_SIZE, bytes.len()))?;
    let verifying = VerifyingKey::from_bytes(&arr).map_err(|e| {
        invalid_point(
            "ed25519",
            format!("point decompression failed: {e} (bytes may not be a valid Edwards point)"),
        )
    })?;
    let hex = to_hex(verifying.as_bytes());
    Ok(EccPublicKeyMaterial {
        curve: EccCurve::Ed25519,
        public_compressed_hex: hex.clone(),
        public_uncompressed_hex: hex,
    })
}

/// PKCS#8 `privateKey` OCTET STRING payload (RFC 8410: the raw seed) into a
/// keypair. The `ed25519-dalek` decode machinery has already validated the
/// outer `PrivateKeyInfo`.
pub(crate) fn private_from_pkcs8_octets(octets: &[u8]) -> PkiResult<EccKeyPair> {
    // RFC 8410 §7: the PKCS#8 privateKey OCTET STRING wraps a DER-encoded
    // OCTET STRING containing the raw 32-byte seed — strip the 2-byte header.
    let raw: &[u8] = if octets.len() == ED25519_KEY_SIZE + 2
        && octets[0] == 0x04
        && octets[1] == ED25519_KEY_SIZE as u8
    {
        &octets[2..]
    } else {
        octets
    };
    let seed: [u8; ED25519_KEY_SIZE] = raw
        .try_into()
        .map_err(|_| wrong_key_len(ED25519_KEY_SIZE, raw.len()))?;
    keypair_from_seed_bytes(&seed)
}

/// Build a `SigningKey` from a hex-encoded 32-byte seed (signing entry
/// point).
pub(crate) fn parse_signing_key(private_hex: &str) -> PkiResult<SigningKey> {
    let seed = decode_fixed_hex("private_key", private_hex, ED25519_KEY_SIZE)?;
    let arr: [u8; ED25519_KEY_SIZE] = seed
        .as_slice()
        .try_into()
        .map_err(|_| internal("seed length invariant violated after fixed-length decode"))?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Build a `VerifyingKey` from a hex-encoded 32-byte public key.
pub(crate) fn parse_verifying_key(public_hex: &str) -> PkiResult<VerifyingKey> {
    let bytes = decode_fixed_hex("public_key", public_hex, ED25519_KEY_SIZE)?;
    let arr: [u8; ED25519_KEY_SIZE] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| internal("public key length invariant violated after fixed-length decode"))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| {
        invalid_point(
            "ed25519",
            format!("point decompression failed: {e} (bytes may not be a valid Edwards point)"),
        )
    })
}

fn keypair_from_seed_bytes(seed: &[u8; ED25519_KEY_SIZE]) -> PkiResult<EccKeyPair> {
    let signing = SigningKey::from_bytes(seed);
    let public = signing.verifying_key();
    let public_hex = to_hex(public.as_bytes());
    Ok(EccKeyPair {
        curve: EccCurve::Ed25519,
        private_hex: to_hex(signing.as_bytes()),
        public_compressed_hex: public_hex.clone(),
        public_uncompressed_hex: public_hex,
    })
}

fn wrong_key_len(expected: usize, actual: usize) -> crate::error::PkiError {
    super::wrong_length(
        "private_key",
        format!("{expected} bytes"),
        format!("{actual} bytes"),
    )
}
