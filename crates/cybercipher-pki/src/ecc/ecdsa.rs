//! ECDSA sign/verify for the NIST curves (FIPS 186-5):
//! - P-256 with SHA-256, P-384 with SHA-384 (the standard pairings — the
//!   `ecdsa` crate's digest API requires the digest output to match the field
//!   size, and cross-pairings are rare, questionable practice; a mismatched
//!   digest/curve combination is a typed `InvalidParam` error, not a guess);
//! - deterministic RFC 6979 nonces (the default) or randomized nonces;
//! - signatures in DER or fixed-size `r||s` (64 bytes on P-256, 96 on
//!   P-384) selected by an explicit `format` parameter.
//!
//! Error semantics (deliberate split, mirroring `crate::ops::sign`):
//! - malformed *operation input* is a typed error (bad key, wrong curve,
//!   wrong signature length, invalid DER);
//! - a signature that fails *cryptographic* verification is a normal
//!   [`EcdsaVerifyResult`] with `valid: false` and a `reason`.

use ecdsa::signature::{RandomizedSigner, Signer, Verifier};
use serde::{Deserialize, Serialize};

use super::curve::{parse_ecc_public_key, EccCurve};
use super::{decode_fixed_hex, decode_hex, decode_scalar_hex, internal, invalid_key, wrong_curve};
use crate::error::{invalid_der, PkiError, PkiResult};
use crate::keys::to_hex;

// ---------------------------------------------------------------------------
// Parameters (serde boundary)
// ---------------------------------------------------------------------------

/// Hash used for the ECDSA prehash. P-256 requires SHA-256 and P-384 requires
/// SHA-384; anything else is rejected with a typed error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EcdsaDigest {
    Sha256,
    Sha384,
}

impl EcdsaDigest {
    /// Canonical lowercase label (`"sha256"` / `"sha384"`).
    pub fn label(&self) -> &'static str {
        match self {
            EcdsaDigest::Sha256 => "sha256",
            EcdsaDigest::Sha384 => "sha384",
        }
    }
}

impl std::fmt::Display for EcdsaDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Nonce source for ECDSA signing. `Deterministic` is the default: RFC 6979
/// derives `k` from the private key and message hash, so signing the same
/// message twice produces the same signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EcdsaNonceMode {
    /// RFC 6979 deterministic k (default).
    Deterministic,
    /// Fresh random k per signature (hedging against side-channel leakage of
    /// the deterministic nonce; requires a trusted RNG).
    Random,
}

/// ECDSA signature wire format, always explicit — never guessed from the
/// input length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EcdsaSignatureFormat {
    /// ASN.1 `SEQUENCE { r INTEGER, s INTEGER }` (70-72 bytes on P-256).
    Der,
    /// Fixed-size `r || s` (64 bytes on P-256, 96 on P-384) — the format used
    /// by JWS, Bitcoin, and other wire protocols.
    Fixed,
}

impl EcdsaSignatureFormat {
    /// Canonical lowercase label (`"der"` / `"fixed"`).
    pub fn label(&self) -> &'static str {
        match self {
            EcdsaSignatureFormat::Der => "der",
            EcdsaSignatureFormat::Fixed => "fixed",
        }
    }
}

/// Result of an ECDSA verification. `valid == false` (with a `reason`) is a
/// normal outcome; only malformed inputs produce [`PkiResult`] errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcdsaVerifyResult {
    /// Whether the signature verifies over the data with the given key.
    pub valid: bool,
    /// Why verification failed; `None` when `valid` is `true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Curve the verification ran on.
    pub curve: EccCurve,
    /// Digest used, in canonical label form (`"sha256"` / `"sha384"`).
    pub digest: EcdsaDigest,
    /// Signature wire format that was parsed.
    pub signature_format: EcdsaSignatureFormat,
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// ECDSA sign with an explicit digest, nonce mode, and output format.
/// `EcdsaNonceMode::Deterministic` (RFC 6979) is the default behavior of the
/// underlying crate; pass `EcdsaNonceMode::Random` for a fresh random `k` per
/// call.
///
/// Returns the signature as a lowercase hex string in the requested format
/// (DER or fixed-size `r||s`).
pub fn ecdsa_sign(
    curve: EccCurve,
    private_hex: &str,
    data: &[u8],
    digest: EcdsaDigest,
    nonce: EcdsaNonceMode,
    format: EcdsaSignatureFormat,
) -> PkiResult<String> {
    check_digest_pairing(curve, digest)?;
    match curve {
        EccCurve::P256 => {
            let scalar = decode_scalar_hex("private_key", private_hex, 32)?;
            ecdsa_sign_curve::<p256::NistP256>(&scalar, data, nonce, format)
        }
        EccCurve::P384 => {
            let scalar = decode_scalar_hex("private_key", private_hex, 48)?;
            ecdsa_sign_curve::<p384::NistP384>(&scalar, data, nonce, format)
        }
        other => Err(ecdsa_requires_nist(other)),
    }
}

/// Per-curve sign. Generic over the NIST curve; the `Signer`/
/// `RandomizedSigner` impls on `ecdsa::SigningKey<C>` use the curve's native
/// digest (SHA-256 for P-256, SHA-384 for P-384) with deterministic RFC 6979
/// nonces, or a fresh random nonce in `Random` mode.
fn ecdsa_sign_curve<C>(
    scalar: &[u8],
    data: &[u8],
    nonce: EcdsaNonceMode,
    format: EcdsaSignatureFormat,
) -> PkiResult<String>
where
    C: elliptic_curve::PrimeCurve
        + elliptic_curve::CurveArithmetic
        + ecdsa::hazmat::DigestPrimitive,
    elliptic_curve::Scalar<C>: elliptic_curve::ops::Invert<
            Output = elliptic_curve::subtle::CtOption<elliptic_curve::Scalar<C>>,
        > + ecdsa::hazmat::SignPrimitive<C>,
    ecdsa::SignatureSize<C>: elliptic_curve::generic_array::ArrayLength<u8>,
    ecdsa::der::MaxSize<C>: elliptic_curve::generic_array::ArrayLength<u8>,
    elliptic_curve::FieldBytesSize<C>: core::ops::Add,
    <elliptic_curve::FieldBytesSize<C> as core::ops::Add>::Output:
        core::ops::Add<ecdsa::der::MaxOverhead> + elliptic_curve::generic_array::ArrayLength<u8>,
    ecdsa::SigningKey<C>: Signer<ecdsa::Signature<C>> + RandomizedSigner<ecdsa::Signature<C>>,
{
    let signing = ecdsa::SigningKey::<C>::from_slice(scalar).map_err(|_| {
        invalid_key("invalid private key scalar: not in the curve group order range")
            .with_parameter("private_key")
    })?;
    let signature = match nonce {
        EcdsaNonceMode::Deterministic => signing.sign(data),
        EcdsaNonceMode::Random => signing.sign_with_rng(&mut rand::rngs::OsRng, data),
    };
    let encoded = match format {
        EcdsaSignatureFormat::Der => to_hex(signature.to_der().to_bytes().as_ref()),
        EcdsaSignatureFormat::Fixed => to_hex(signature.to_bytes().as_slice()),
    };
    Ok(encoded)
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// ECDSA verify with an explicit digest and signature format. The public key
/// is hex-encoded SEC1 (compressed or uncompressed) and validated to be on
/// the curve; a malformed signature is a typed error, while a signature that
/// simply does not verify is reported as `valid: false`.
pub fn ecdsa_verify(
    curve: EccCurve,
    public_hex: &str,
    data: &[u8],
    digest: EcdsaDigest,
    format: EcdsaSignatureFormat,
    signature_hex: &str,
) -> PkiResult<EcdsaVerifyResult> {
    check_digest_pairing(curve, digest)?;
    // Validates hex + length + tag + on-curve, with wrong-curve length hints.
    let public = parse_ecc_public_key(curve, public_hex)?;
    let signature_bytes = decode_hex("signature", signature_hex)?;
    let outcome = match curve {
        EccCurve::P256 => {
            ecdsa_verify_curve::<p256::NistP256>(curve, &public, &signature_bytes, format, data)
        }
        EccCurve::P384 => {
            ecdsa_verify_curve::<p384::NistP384>(curve, &public, &signature_bytes, format, data)
        }
        other => return Err(ecdsa_requires_nist(other)),
    };
    match outcome {
        Ok(Ok(())) => Ok(EcdsaVerifyResult {
            valid: true,
            reason: None,
            curve,
            digest,
            signature_format: format,
        }),
        Ok(Err(reason)) => Ok(EcdsaVerifyResult {
            valid: false,
            reason: Some(reason),
            curve,
            digest,
            signature_format: format,
        }),
        Err(e) => Err(e),
    }
}

/// Per-curve verify. Returns `Ok(Ok(()))` on a valid signature,
/// `Ok(Err(reason))` on a well-formed signature that does not verify, and a
/// typed error for malformed input.
fn ecdsa_verify_curve<C>(
    curve: EccCurve,
    public: &super::curve::EccPublicKeyMaterial,
    signature_bytes: &[u8],
    format: EcdsaSignatureFormat,
    data: &[u8],
) -> PkiResult<Result<(), String>>
where
    C: elliptic_curve::PrimeCurve + elliptic_curve::CurveArithmetic,
    elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>
        + ecdsa::hazmat::VerifyPrimitive<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
    ecdsa::SignatureSize<C>: elliptic_curve::generic_array::ArrayLength<u8>,
    ecdsa::VerifyingKey<C>: Verifier<ecdsa::Signature<C>>,
    ecdsa::der::MaxSize<C>: elliptic_curve::generic_array::ArrayLength<u8>,
    <elliptic_curve::FieldBytesSize<C> as core::ops::Add>::Output:
        core::ops::Add<ecdsa::der::MaxOverhead> + elliptic_curve::generic_array::ArrayLength<u8>,
{
    // The material was already validated on-curve by parse_ecc_public_key;
    // failures here would be an internal inconsistency.
    let point_bytes = decode_hex("public_key", &public.public_uncompressed_hex)?;
    let verifying = ecdsa::VerifyingKey::<C>::from_sec1_bytes(&point_bytes).map_err(|e| {
        internal("validated public key rejected while building verifying key")
            .with_details(e.to_string())
    })?;
    let signature = parse_signature::<C>(curve, format, signature_bytes)?;
    Ok(verifying.verify(data, &signature).map_err(|e| {
        format!(
            "ECDSA verification failed (wrong key, tampered data/signature, or mismatched digest): {e}"
        )
    }))
}

/// Parse a hex-decoded signature of the requested format into a typed
/// `ecdsa::Signature`, mapping every failure to a precise error: wrong
/// length for `Fixed` (`LengthMismatch`), invalid DER or out-of-range r/s
/// for `Der` (`Decode`).
fn parse_signature<C>(
    curve: EccCurve,
    format: EcdsaSignatureFormat,
    bytes: &[u8],
) -> PkiResult<ecdsa::Signature<C>>
where
    C: elliptic_curve::PrimeCurve + elliptic_curve::CurveArithmetic,
    ecdsa::der::MaxSize<C>: elliptic_curve::generic_array::ArrayLength<u8>,
    elliptic_curve::FieldBytesSize<C>: core::ops::Add,
    <elliptic_curve::FieldBytesSize<C> as core::ops::Add>::Output:
        core::ops::Add<ecdsa::der::MaxOverhead> + elliptic_curve::generic_array::ArrayLength<u8>,
{
    match format {
        EcdsaSignatureFormat::Der => ecdsa::Signature::<C>::from_der(bytes)
            .map_err(|e| invalid_der("ECDSA DER signature", e).with_parameter("signature")),
        EcdsaSignatureFormat::Fixed => {
            let expected = 2 * curve.private_key_size();
            if bytes.len() != expected {
                return Err(super::wrong_length(
                    "signature",
                    format!("{expected} bytes (r||s)"),
                    format!("{} bytes", bytes.len()),
                ));
            }
            ecdsa::Signature::<C>::from_slice(bytes).map_err(|_| {
                super::wrong_encoding(
                    "invalid fixed-size ECDSA signature: r and s must both be in 1..n",
                )
                .with_parameter("signature")
            })
        }
    }
}

// ---------------------------------------------------------------------------
// DER <-> r||s conversion helpers
// ---------------------------------------------------------------------------

/// Convert a DER ECDSA signature to fixed-size `r||s` for `curve` (`r` and
/// `s` zero-padded to the scalar width). Malformed DER or out-of-range
/// components are typed errors.
pub fn ecdsa_signature_der_to_fixed(curve: EccCurve, der_hex: &str) -> PkiResult<String> {
    let bytes = decode_hex("signature", der_hex)?;
    match curve {
        EccCurve::P256 => Ok(to_hex(
            ecdsa::Signature::<p256::NistP256>::from_der(&bytes)
                .map_err(|e| invalid_der("ECDSA DER signature", e).with_parameter("signature"))?
                .to_bytes()
                .as_slice(),
        )),
        EccCurve::P384 => Ok(to_hex(
            ecdsa::Signature::<p384::NistP384>::from_der(&bytes)
                .map_err(|e| invalid_der("ECDSA DER signature", e).with_parameter("signature"))?
                .to_bytes()
                .as_slice(),
        )),
        other => Err(ecdsa_requires_nist(other)),
    }
}

/// Convert a fixed-size `r||s` ECDSA signature to DER for `curve`. Wrong
/// length or out-of-range components are typed errors.
pub fn ecdsa_signature_fixed_to_der(curve: EccCurve, fixed_hex: &str) -> PkiResult<String> {
    let bytes = decode_fixed_hex("signature", fixed_hex, 2 * curve.private_key_size())?;
    let to_der_error = |_: ecdsa::Error| {
        super::wrong_encoding("invalid fixed-size ECDSA signature: r and s must both be in 1..n")
            .with_parameter("signature")
    };
    match curve {
        EccCurve::P256 => Ok(to_hex(
            ecdsa::Signature::<p256::NistP256>::from_slice(&bytes)
                .map_err(to_der_error)?
                .to_der()
                .to_bytes()
                .as_ref(),
        )),
        EccCurve::P384 => Ok(to_hex(
            ecdsa::Signature::<p384::NistP384>::from_slice(&bytes)
                .map_err(to_der_error)?
                .to_der()
                .to_bytes()
                .as_ref(),
        )),
        other => Err(ecdsa_requires_nist(other)),
    }
}

// ---------------------------------------------------------------------------
// Shared guards
// ---------------------------------------------------------------------------

/// Enforce the digest/curve pairing: P-256 + SHA-256, P-384 + SHA-384.
/// Shared with `attacks.rs` (the attack ops enforce the identical rule).
pub(crate) fn check_digest_pairing(curve: EccCurve, digest: EcdsaDigest) -> PkiResult<()> {
    let expected = match curve {
        EccCurve::P256 => EcdsaDigest::Sha256,
        EccCurve::P384 => EcdsaDigest::Sha384,
        other => return Err(ecdsa_requires_nist(other)),
    };
    if digest != expected {
        return Err(PkiError::invalid_param(
            "digest",
            format!(
                "ECDSA on {curve} requires {} (digest output must match the field size)",
                expected.label()
            ),
        )
        .with_expected(expected.label())
        .with_actual(digest.label()));
    }
    Ok(())
}

fn ecdsa_requires_nist(curve: EccCurve) -> PkiError {
    wrong_curve("p256 or p384", curve.label())
        .with_details("ECDSA is only defined here for the NIST curves P-256 and P-384")
}
