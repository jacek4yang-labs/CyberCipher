//! SM2 digital signatures (GB/T 32918.2 / GM/T 0003.2) via the RustCrypto
//! `sm2` crate's `dsa` module.
//!
//! ## ID / ZA handling
//!
//! Unlike ECDSA, an SM2 signature covers `ZA || M` where the user-identity
//! hash is
//!
//! ```text
//! ZA = SM3(ENTLa || IDa || a || b || xG || yG || xA || yA)
//! ```
//!
//! (`ENTLa` = ID bit length as a 16-bit big-endian prefix). The ID is
//! therefore part of the *key context*: signer and verifier must use the same
//! ID or verification fails. The standard default ID is
//! [`super::SM2_DEFAULT_USER_ID`] (`"1234567812345678"`); pass it explicitly
//! or `None` / `""` to select it, or a custom ID to interoperate with
//! counterparts that use one. The `sm2` 0.13 crate takes the ID at
//! key-construction time (`SigningKey::new(distid, ..)` /
//! `VerifyingKey::new(distid, ..)`), which this module maps to the `user_id`
//! parameter.
//!
//! ## Signature format
//!
//! Signatures are the raw fixed-size `r || s` encoding: exactly
//! [`super::SM2_SIGNATURE_LEN`] = 64 bytes = 128 hex chars, both components
//! zero-padded big-endian. (ASN.1 DER wrapping is not part of SM2 standards
//! tooling.)
//!
//! Error semantics (deliberate split, mirroring [`crate::ecc::ecdsa_sign`]):
//! - malformed *operation input* is a typed error (bad key, wrong point
//!   encoding, wrong signature length, non-canonical r/s);
//! - a signature that fails *cryptographic* verification is a normal
//!   [`Sm2VerifyResult`] with `valid: false` and a `reason`.

use serde::{Deserialize, Serialize};
use sm2::dsa::signature::{Signer as _, Verifier as _};
use sm2::elliptic_curve::sec1::ToEncodedPoint as _;

use super::{effective_user_id, SM2_SIGNATURE_LEN};
use crate::ecc::{decode_fixed_hex, decode_hex, internal, wrong_encoding, wrong_length};
use crate::error::PkiResult;
use crate::keys::to_hex;

/// Result of an SM2 signature verification. `valid == false` (with a
/// `reason`) is a normal outcome; only malformed inputs produce
/// [`PkiResult`] errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sm2VerifyResult {
    /// Whether the signature verifies over the data with the given key and
    /// user ID.
    pub valid: bool,
    /// Why verification failed; `None` when `valid` is `true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The effective user ID used for the ZA hash (default ID filled in).
    pub user_id: String,
}

/// SM2 sign a message. The signature is over `ZA || M` (see the module docs):
/// the ID in `user_id` (`None`/empty = the standard default
/// `"1234567812345678"`) must match the one used for verification.
///
/// Nonces are RFC 6979-style deterministic, derived from the private key and
/// the SM3 digest of `ZA || M` (the `sm2` crate default), so signing the same
/// message twice with the same key/ID produces the same signature.
///
/// Returns the signature as lowercase hex: raw 64-byte `r || s`
/// (r = bytes 0..32, s = bytes 32..64, both zero-padded big-endian).
pub fn sm2_sign(private_hex: &str, data: &[u8], user_id: Option<&str>) -> PkiResult<String> {
    let user_id = effective_user_id(user_id)?;
    let secret = super::key::secret_from_hex(private_hex)?;
    // Fails only if the ZA hash cannot be built (impossible for a validated
    // key); mapped to an internal error, never a panic.
    let signing = sm2::dsa::SigningKey::new(user_id, &secret).map_err(|e| {
        internal("SM2 signing key rejected a validated key").with_details(e.to_string())
    })?;
    let signature = signing
        .try_sign(data)
        .map_err(|e| internal("SM2 signing failed").with_details(e.to_string()))?;
    Ok(to_hex(signature.to_bytes().as_ref()))
}

/// SM2 verify a message signature. The public key is hex-encoded SEC1
/// (compressed or uncompressed) and validated to be on the curve; the
/// signature is 64 bytes of `r || s` as a hex string; `user_id` must be the
/// signer's ID (`None`/empty = the standard default).
///
/// A malformed signature is a typed error, while a signature that simply does
/// not verify (wrong key, tampered message/signature, or a different user ID)
/// is reported as `valid: false`.
pub fn sm2_verify(
    public_hex: &str,
    data: &[u8],
    signature_hex: &str,
    user_id: Option<&str>,
) -> PkiResult<Sm2VerifyResult> {
    let user_id = effective_user_id(user_id)?;
    let public = super::key::public_from_hex(public_hex)?;
    let signature_bytes = decode_fixed_hex("signature", signature_hex, SM2_SIGNATURE_LEN)?;
    let signature = sm2::dsa::Signature::from_slice(&signature_bytes).map_err(|_| {
        wrong_encoding("invalid SM2 signature: r and s must both be in 1..n")
            .with_parameter("signature")
    })?;
    let encoded = public.to_encoded_point(false);
    // Fails only for an invalid point or ZA overflow — the point was already
    // validated and the ID length-checked, so this is an internal invariant.
    let verifying =
        sm2::dsa::VerifyingKey::from_sec1_bytes(user_id, encoded.as_bytes()).map_err(|e| {
            internal("SM2 verifying key rejected a validated public key")
                .with_details(e.to_string())
        })?;
    Ok(match verifying.verify(data, &signature) {
        Ok(()) => Sm2VerifyResult {
            valid: true,
            reason: None,
            user_id: user_id.to_string(),
        },
        Err(e) => Sm2VerifyResult {
            valid: false,
            reason: Some(format!(
                "SM2 verification failed (wrong key, tampered data/signature, or mismatched user ID): {e}"
            )),
            user_id: user_id.to_string(),
        },
    })
}

/// Parse a raw `r || s` SM2 signature from bytes into its hex transport form
/// with full validation (exact length, r/s in 1..n). Exposed for callers that
/// hold the signature as bytes rather than hex.
pub fn sm2_signature_from_bytes(bytes: &[u8]) -> PkiResult<String> {
    if bytes.len() != SM2_SIGNATURE_LEN {
        return Err(wrong_length(
            "signature",
            format!("{SM2_SIGNATURE_LEN} bytes (r||s)"),
            format!("{} bytes", bytes.len()),
        ));
    }
    sm2::dsa::Signature::from_slice(bytes)
        .map(|s| to_hex(s.to_bytes().as_ref()))
        .map_err(|_| {
            wrong_encoding("invalid SM2 signature: r and s must both be in 1..n")
                .with_parameter("signature")
        })
}

/// Decode a hex SM2 signature into its raw 64-byte `r || s` form. Exposed for
/// callers that need the bytes; malformed hex/length/r/s are typed errors.
pub fn sm2_signature_to_bytes(signature_hex: &str) -> PkiResult<[u8; SM2_SIGNATURE_LEN]> {
    let bytes = decode_hex("signature", signature_hex)?;
    let mut out = [0u8; SM2_SIGNATURE_LEN];
    if bytes.len() != SM2_SIGNATURE_LEN {
        return Err(wrong_length(
            "signature",
            format!("{SM2_SIGNATURE_LEN} bytes (r||s)"),
            format!("{} bytes", bytes.len()),
        ));
    }
    out.copy_from_slice(&bytes);
    // Canonicality check (r, s in 1..n) without re-encoding.
    sm2::dsa::Signature::from_slice(&out).map_err(|_| {
        wrong_encoding("invalid SM2 signature: r and s must both be in 1..n")
            .with_parameter("signature")
    })?;
    Ok(out)
}
