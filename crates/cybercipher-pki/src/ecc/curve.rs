//! ECC key generation, key material, and key-format handling (SEC1, SPKI,
//! PKCS#8, PEM) for the curves CyberCipher supports: P-256, P-384, Ed25519,
//! X25519.
//!
//! Layout:
//! - P-256/P-384 use the `p256`/`p384` crate types (`SecretKey`, `PublicKey`)
//!   with the `elliptic-curve` pkcs8/spki machinery for the container formats.
//! - Ed25519 uses `ed25519-dalek`'s own PKCS#8/SPKI impls (RFC 8410).
//! - X25519 has no pkcs8 trait impls in `x25519-dalek`, so the RFC 8410
//!   `PrivateKeyInfo` / `SubjectPublicKeyInfo` wrappers are built here with
//!   the `pkcs8`/`spki` crates (still no hand-rolled curve arithmetic).
//!
//! Transport shapes (all hex strings):
//! - private keys: fixed-width big-endian scalar (P-256: 32 bytes, P-384:
//!   48 bytes) or the raw key byte string (Ed25519 seed, X25519 clamped
//!   little-endian scalar) — 32 bytes each;
//! - public keys: SEC1 encoded (compressed `02/03||x` and uncompressed
//!   `04||x||y`) for the NIST curves; for Ed25519/X25519 there is a single
//!   canonical 32-byte encoding, so `public_compressed_hex` and
//!   `public_uncompressed_hex` carry the same value.

use base64ct::Encoding as _;
use der::Decode as _;
use elliptic_curve::sec1::ToEncodedPoint as _;
use pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, EncodePublicKey as _};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use spki::ObjectIdentifier;

use super::{
    decode_fixed_hex, decode_hex, decode_scalar_hex, invalid_key, invalid_point, internal,
    wrong_curve, wrong_encoding, wrong_length,
};
use crate::error::{invalid_armor, invalid_der, PkiError, PkiResult};

// ---------------------------------------------------------------------------
// Object identifiers (RFC 5480 / RFC 8410)
// ---------------------------------------------------------------------------

/// id-ecPublicKey: 1.2.840.10045.2.1
pub(crate) const EC_PUBLIC_KEY_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// prime256v1 / secp256r1 (P-256): 1.2.840.10045.3.1.7
pub(crate) const P256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// secp384r1 (P-384): 1.3.132.0.34
pub(crate) const P384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
/// id-Ed25519: 1.3.101.112
pub(crate) const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
/// id-X25519: 1.3.101.110
pub(crate) const X25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

// ---------------------------------------------------------------------------
// Curve enum
// ---------------------------------------------------------------------------

/// Curves supported by the CyberCipher ECC module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EccCurve {
    /// NIST P-256 (secp256r1 / prime256v1) — ECDSA + ECDH.
    P256,
    /// NIST P-384 (secp384r1) — ECDSA + ECDH.
    P384,
    /// EdDSA signature curve (RFC 8032).
    Ed25519,
    /// Montgomery DH curve (RFC 7748).
    X25519,
}

impl EccCurve {
    /// Canonical lowercase label (`"p256"`, `"p384"`, `"ed25519"`,
    /// `"x25519"`).
    pub fn label(&self) -> &'static str {
        match self {
            EccCurve::P256 => "p256",
            EccCurve::P384 => "p384",
            EccCurve::Ed25519 => "ed25519",
            EccCurve::X25519 => "x25519",
        }
    }

    /// Parse a curve label, accepting common aliases (case-insensitive):
    /// `p256`/`p-256`/`secp256r1`/`prime256v1`, `p384`/`p-384`/`secp384r1`,
    /// `ed25519`, `x25519`/`curve25519`.
    pub fn from_label(label: &str) -> Option<EccCurve> {
        match label.trim().to_ascii_lowercase().as_str() {
            "p256" | "p-256" | "secp256r1" | "prime256v1" | "nistp256" => Some(EccCurve::P256),
            "p384" | "p-384" | "secp384r1" | "nistp384" => Some(EccCurve::P384),
            "ed25519" | "edwards25519" => Some(EccCurve::Ed25519),
            "x25519" | "curve25519" => Some(EccCurve::X25519),
            _ => None,
        }
    }

    /// Fixed-length private-key size in bytes (scalar for P-256/P-384 and
    /// X25519, seed for Ed25519).
    pub fn private_key_size(&self) -> usize {
        match self {
            EccCurve::P256 | EccCurve::Ed25519 | EccCurve::X25519 => 32,
            EccCurve::P384 => 48,
        }
    }

    /// Compressed public-key size in bytes (SEC1 for the NIST curves, raw
    /// 32-byte key for Ed25519/X25519).
    pub fn public_key_compressed_size(&self) -> usize {
        match self {
            EccCurve::P256 => 33,
            EccCurve::P384 => 49,
            EccCurve::Ed25519 | EccCurve::X25519 => 32,
        }
    }

    /// Uncompressed public-key size in bytes (SEC1 for the NIST curves, raw
    /// 32-byte key for Ed25519/X25519).
    pub fn public_key_uncompressed_size(&self) -> usize {
        match self {
            EccCurve::P256 => 65,
            EccCurve::P384 => 97,
            EccCurve::Ed25519 | EccCurve::X25519 => 32,
        }
    }
}

impl std::fmt::Display for EccCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Task-named entry point: resolve a curve label (with aliases) into an
/// [`EccCurve`].
pub fn parse_ecc_curve(label: &str) -> PkiResult<EccCurve> {
    EccCurve::from_label(label).ok_or_else(|| {
        PkiError::invalid_param("curve", format!("unknown curve '{label}'"))
            .with_expected("one of: p256, p384, ed25519, x25519 (common aliases accepted)")
            .with_actual(crate::keys::preview(label, 32))
    })
}

// ---------------------------------------------------------------------------
// Transport structs (serde boundary)
// ---------------------------------------------------------------------------

/// Full ECC private key material as hex strings. For Ed25519 and X25519 there
/// is a single canonical public encoding, so both public fields carry the same
/// 32-byte value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EccKeyPair {
    pub curve: EccCurve,
    /// Secret scalar (P-256: 32 B, P-384: 48 B big-endian) or raw private key
    /// (Ed25519 seed, X25519 clamped little-endian scalar) — 32 B each.
    pub private_hex: String,
    /// SEC1 compressed public key (`02/03||x`) for P-256/P-384; raw 32-byte
    /// public key for Ed25519/X25519.
    pub public_compressed_hex: String,
    /// SEC1 uncompressed public key (`04||x||y`) for P-256/P-384; raw 32-byte
    /// public key for Ed25519/X25519.
    pub public_uncompressed_hex: String,
}

/// ECC public-key material as hex strings (both SEC1 encodings; identical
/// values for Ed25519/X25519).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EccPublicKeyMaterial {
    pub curve: EccCurve,
    pub public_compressed_hex: String,
    pub public_uncompressed_hex: String,
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generate a keypair on the requested curve. Entropy comes from the OS RNG.
pub fn generate_ecc_keypair(curve: EccCurve) -> PkiResult<EccKeyPair> {
    match curve {
        EccCurve::P256 => nist_generate::<p256::NistP256>(curve),
        EccCurve::P384 => nist_generate::<p384::NistP384>(curve),
        EccCurve::Ed25519 => super::ed25519::generate(),
        EccCurve::X25519 => super::x25519::generate(),
    }
}

fn nist_generate<C>(curve: EccCurve) -> PkiResult<EccKeyPair>
where
    C: elliptic_curve::CurveArithmetic,
    elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    let secret = elliptic_curve::SecretKey::<C>::random(&mut OsRng);
    nist_keypair_from_secret(curve, &secret)
}

fn nist_keypair_from_secret<C>(
    curve: EccCurve,
    secret: &elliptic_curve::SecretKey<C>,
) -> PkiResult<EccKeyPair>
where
    C: elliptic_curve::CurveArithmetic,
    elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    let public = secret.public_key();
    let compressed = public.to_encoded_point(true);
    let uncompressed = public.to_encoded_point(false);
    Ok(EccKeyPair {
        curve,
        private_hex: crate::keys::to_hex(secret.to_bytes().as_slice()),
        public_compressed_hex: crate::keys::to_hex(compressed.as_bytes()),
        public_uncompressed_hex: crate::keys::to_hex(uncompressed.as_bytes()),
    })
}

// ---------------------------------------------------------------------------
// Parsing: private scalars and SEC1 public keys
// ---------------------------------------------------------------------------

/// Parse a private key for `curve` from a fixed-width hex scalar (shorter
/// input is left-padded, longer input rejected) and derive the public key.
/// Rejects zero and non-canonical (>= group order) scalars.
pub fn parse_ecc_private_key(curve: EccCurve, private_hex: &str) -> PkiResult<EccKeyPair> {
    match curve {
        EccCurve::P256 => {
            let bytes = decode_scalar_hex("private_key", private_hex, 32)?;
            let secret = parse_nist_secret::<p256::NistP256>(&bytes)?;
            nist_keypair_from_secret(curve, &secret)
        }
        EccCurve::P384 => {
            let bytes = decode_scalar_hex("private_key", private_hex, 48)?;
            let secret = parse_nist_secret::<p384::NistP384>(&bytes)?;
            nist_keypair_from_secret(curve, &secret)
        }
        EccCurve::Ed25519 => super::ed25519::parse_private(private_hex),
        EccCurve::X25519 => super::x25519::parse_private(private_hex),
    }
}

fn parse_nist_secret<C>(bytes: &[u8]) -> PkiResult<elliptic_curve::SecretKey<C>>
where
    C: elliptic_curve::CurveArithmetic,
{
    let field = elliptic_curve::FieldBytes::<C>::clone_from_slice(bytes);
    elliptic_curve::SecretKey::<C>::from_bytes(&field).map_err(|e| {
        invalid_key("invalid private key scalar: not in the curve group order range")
            .with_parameter("private_key")
            .with_details(e.to_string())
    })
}

/// Parse a public key for `curve` from hex-encoded SEC1 bytes (compressed or
/// uncompressed for the NIST curves; raw 32-byte key for Ed25519/X25519) and
/// validate the point is on the curve.
pub fn parse_ecc_public_key(curve: EccCurve, public_hex: &str) -> PkiResult<EccPublicKeyMaterial> {
    match curve {
        EccCurve::P256 => {
            nist_public_material::<p256::NistP256>(curve, public_hex, EccCurve::P384)
        }
        EccCurve::P384 => {
            nist_public_material::<p384::NistP384>(curve, public_hex, EccCurve::P256)
        }
        EccCurve::Ed25519 => super::ed25519::public_material(public_hex),
        EccCurve::X25519 => super::x25519::public_material(public_hex),
    }
}

/// NIST SEC1 parse with wrong-curve length hints: a hex blob whose length
/// matches the *other* supported NIST curve reports a `wrong curve` error
/// instead of a bare length mismatch.
fn nist_public_material<C>(
    curve: EccCurve,
    public_hex: &str,
    sibling: EccCurve,
) -> PkiResult<EccPublicKeyMaterial>
where
    C: elliptic_curve::CurveArithmetic,
    elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    let bytes = decode_hex("public_key", public_hex)?;
    let compressed_len = curve.public_key_compressed_size();
    let uncompressed_len = curve.public_key_uncompressed_size();
    if bytes.len() != compressed_len && bytes.len() != uncompressed_len {
        if [sibling.public_key_compressed_size(), sibling.public_key_uncompressed_size()]
            .contains(&bytes.len())
        {
            return Err(wrong_curve(curve.label(), sibling.label()).with_details(format!(
                "input length {} bytes matches a {} key",
                bytes.len(),
                sibling.label()
            )));
        }
        return Err(wrong_length(
            "public_key",
            format!("{compressed_len} bytes (compressed) or {uncompressed_len} bytes (uncompressed)"),
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
    let public = elliptic_curve::PublicKey::<C>::from_sec1_bytes(&bytes).map_err(|e| {
        invalid_point(
            curve.label(),
            format!("SEC1 point rejected: {e} (coordinates may be non-canonical or the point may not satisfy the curve equation)"),
        )
    })?;
    Ok(nist_public_from_key(curve, &public))
}

fn nist_public_from_key<C>(
    curve: EccCurve,
    public: &elliptic_curve::PublicKey<C>,
) -> EccPublicKeyMaterial
where
    C: elliptic_curve::CurveArithmetic,
    elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    let compressed = public.to_encoded_point(true);
    let uncompressed = public.to_encoded_point(false);
    EccPublicKeyMaterial {
        curve,
        public_compressed_hex: crate::keys::to_hex(compressed.as_bytes()),
        public_uncompressed_hex: crate::keys::to_hex(uncompressed.as_bytes()),
    }
}

/// Re-parse an already-validated uncompressed SEC1 hex string back into a
/// `PublicKey` (for the SPKI/PKCS#8 encode paths).
fn nist_public_from_material<C>(
    material: &EccPublicKeyMaterial,
) -> PkiResult<elliptic_curve::PublicKey<C>>
where
    C: elliptic_curve::CurveArithmetic,
    elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    let bytes = decode_hex("public_key", &material.public_uncompressed_hex)?;
    elliptic_curve::PublicKey::<C>::from_sec1_bytes(&bytes).map_err(|e| {
        invalid_point(material.curve.label(), format!("SEC1 point rejected: {e}"))
    })
}

// ---------------------------------------------------------------------------
// SPKI (public key) DER / PEM — encode
// ---------------------------------------------------------------------------

/// Encode a public key as SPKI `SubjectPublicKeyInfo` DER (RFC 5280; EC keys
/// are written uncompressed per the OpenSSL/SEC1 convention).
pub fn ecc_public_key_to_spki_der(curve: EccCurve, public_hex: &str) -> PkiResult<Vec<u8>> {
    match curve {
        EccCurve::P256 => {
            let material = nist_public_material::<p256::NistP256>(curve, public_hex, EccCurve::P384)?;
            let public = nist_public_from_material::<p256::NistP256>(&material)?;
            encode_spki_der(public.to_public_key_der())
        }
        EccCurve::P384 => {
            let material = nist_public_material::<p384::NistP384>(curve, public_hex, EccCurve::P256)?;
            let public = nist_public_from_material::<p384::NistP384>(&material)?;
            encode_spki_der(public.to_public_key_der())
        }
        EccCurve::Ed25519 => {
            let verifying = super::ed25519::parse_verifying_key(public_hex)?;
            encode_spki_der(verifying.to_public_key_der())
        }
        EccCurve::X25519 => {
            let bytes = decode_fixed_hex("public_key", public_hex, 32)?;
            let spki = spki::SubjectPublicKeyInfoRef {
                algorithm: spki::AlgorithmIdentifierRef {
                    oid: X25519_OID,
                    parameters: None,
                },
                subject_public_key: der::asn1::BitStringRef::from_bytes(&bytes)
                    .map_err(|e| invalid_der("SPKI SubjectPublicKeyInfo", e))?,
            };
            use der::Encode as _;
            spki.to_der()
                .map_err(|e| internal("X25519 SPKI DER encoding failed").with_details(e.to_string()))
        }
    }
}

/// Encode a public key as `-----BEGIN PUBLIC KEY-----` PEM (SPKI).
pub fn ecc_public_key_to_spki_pem(curve: EccCurve, public_hex: &str) -> PkiResult<String> {
    match curve {
        EccCurve::P256 => {
            let material = nist_public_material::<p256::NistP256>(curve, public_hex, EccCurve::P384)?;
            let public = nist_public_from_material::<p256::NistP256>(&material)?;
            encode_spki_pem(public.to_public_key_pem(der::pem::LineEnding::LF))
        }
        EccCurve::P384 => {
            let material = nist_public_material::<p384::NistP384>(curve, public_hex, EccCurve::P256)?;
            let public = nist_public_from_material::<p384::NistP384>(&material)?;
            encode_spki_pem(public.to_public_key_pem(der::pem::LineEnding::LF))
        }
        EccCurve::Ed25519 => {
            let verifying = super::ed25519::parse_verifying_key(public_hex)?;
            encode_spki_pem(verifying.to_public_key_pem(der::pem::LineEnding::LF))
        }
        EccCurve::X25519 => {
            let bytes = decode_fixed_hex("public_key", public_hex, 32)?;
            let spki = spki::SubjectPublicKeyInfoRef {
                algorithm: spki::AlgorithmIdentifierRef {
                    oid: X25519_OID,
                    parameters: None,
                },
                subject_public_key: der::asn1::BitStringRef::from_bytes(&bytes)
                    .map_err(|e| invalid_der("SPKI SubjectPublicKeyInfo", e))?,
            };
            use der::EncodePem as _;
            spki.to_pem(der::pem::LineEnding::LF)
                .map_err(|e| internal("X25519 SPKI PEM encoding failed").with_details(e.to_string()))
        }
    }
}

fn encode_spki_der(document: Result<pkcs8::Document, spki::Error>) -> PkiResult<Vec<u8>> {
    document
        .map(|doc| doc.as_bytes().to_vec())
        .map_err(|e| internal("SPKI DER encoding failed").with_details(e.to_string()))
}

fn encode_spki_pem(pem: Result<impl std::fmt::Display, spki::Error>) -> PkiResult<String> {
    pem.map(|s| s.to_string())
        .map_err(|e| internal("SPKI PEM encoding failed").with_details(e.to_string()))
}

// ---------------------------------------------------------------------------
// SPKI (public key) DER / PEM — decode with curve auto-detection
// ---------------------------------------------------------------------------

/// Decode an SPKI `SubjectPublicKeyInfo` DER blob, auto-detecting the curve
/// from the algorithm parameters (EC named curve, Ed25519, or X25519) and
/// validating the point. Unknown algorithms/named curves are `Unsupported`
/// errors.
pub fn ecc_public_key_from_spki_der(der: &[u8]) -> PkiResult<EccPublicKeyMaterial> {
    let spki = spki::SubjectPublicKeyInfoRef::from_der(der)
        .map_err(|e| invalid_der("SPKI SubjectPublicKeyInfo", e))?;
    let raw = spki.subject_public_key.as_bytes().ok_or_else(|| {
        invalid_der(
            "SPKI SubjectPublicKeyInfo",
            "subjectPublicKey BIT STRING has unused bits",
        )
    })?;
    match spki.algorithm.oid {
        EC_PUBLIC_KEY_OID => {
            let curve_oid: ObjectIdentifier = spki
                .algorithm
                .parameters
                .ok_or_else(|| {
                    wrong_encoding("EC public key is missing the named-curve parameter")
                        .with_expected("id-ecPublicKey with a namedCurve OID parameter")
                })?
                .decode_as()
                .map_err(|_| {
                    wrong_encoding(
                        "EC public key uses explicit curve parameters, which CyberCipher does not support",
                    )
                    .with_expected("a namedCurve OID parameter")
                })?;
            match curve_oid {
                P256_OID => nist_public_from_sec1(EccCurve::P256, raw),
                P384_OID => nist_public_from_sec1(EccCurve::P384, raw),
                other => Err(PkiError::unsupported(format!(
                    "unsupported EC named curve {other}"
                ))
                .with_expected("P-256 (prime256v1) or P-384 (secp384r1)")
                .with_actual(other.to_string())),
            }
        }
        ED25519_OID => super::ed25519::public_from_raw_bytes(raw),
        X25519_OID => super::x25519::public_from_raw_bytes(raw),
        other => Err(PkiError::unsupported(format!(
            "SPKI public key algorithm {other} is not supported (expected id-ecPublicKey, id-Ed25519, or id-X25519)"
        ))
        .with_actual(other.to_string())),
    }
}

/// Decode a `-----BEGIN PUBLIC KEY-----` PEM (SPKI) with curve
/// auto-detection.
pub fn ecc_public_key_from_spki_pem(pem: &str) -> PkiResult<EccPublicKeyMaterial> {
    let block = split_pem(pem, "PUBLIC KEY")?;
    ecc_public_key_from_spki_der(&block.der)
}

fn nist_public_from_sec1(curve: EccCurve, bytes: &[u8]) -> PkiResult<EccPublicKeyMaterial> {
    let compressed_len = curve.public_key_compressed_size();
    let uncompressed_len = curve.public_key_uncompressed_size();
    if bytes.len() != compressed_len && bytes.len() != uncompressed_len {
        return Err(wrong_length(
            "public_key",
            format!("{compressed_len} bytes (compressed) or {uncompressed_len} bytes (uncompressed)"),
            format!("{} bytes", bytes.len()),
        ));
    }
    match curve {
        EccCurve::P256 => {
            let public = elliptic_curve::PublicKey::<p256::NistP256>::from_sec1_bytes(bytes)
                .map_err(|e| invalid_point(curve.label(), format!("SEC1 point rejected: {e}")))?;
            Ok(nist_public_from_key(curve, &public))
        }
        EccCurve::P384 => {
            let public = elliptic_curve::PublicKey::<p384::NistP384>::from_sec1_bytes(bytes)
                .map_err(|e| invalid_point(curve.label(), format!("SEC1 point rejected: {e}")))?;
            Ok(nist_public_from_key(curve, &public))
        }
        _ => Err(internal("nist_public_from_sec1 called for a non-NIST curve")),
    }
}

// ---------------------------------------------------------------------------
// PKCS#8 (private key) DER / PEM — encode
// ---------------------------------------------------------------------------

/// Encode a private key as PKCS#8 `PrivateKeyInfo` DER (RFC 5958).
pub fn ecc_private_key_to_pkcs8_der(curve: EccCurve, private_hex: &str) -> PkiResult<Vec<u8>> {
    match curve {
        EccCurve::P256 => {
            let bytes = decode_scalar_hex("private_key", private_hex, 32)?;
            let secret = parse_nist_secret::<p256::NistP256>(&bytes)?;
            encode_pkcs8_der(secret.to_pkcs8_der())
        }
        EccCurve::P384 => {
            let bytes = decode_scalar_hex("private_key", private_hex, 48)?;
            let secret = parse_nist_secret::<p384::NistP384>(&bytes)?;
            encode_pkcs8_der(secret.to_pkcs8_der())
        }
        EccCurve::Ed25519 => {
            let signing = super::ed25519::parse_signing_key(private_hex)?;
            encode_pkcs8_der(signing.to_pkcs8_der())
        }
        EccCurve::X25519 => {
            let bytes = decode_fixed_hex("private_key", private_hex, 32)?;
            let key_info = x25519_key_info(&bytes)?;
            use der::Encode as _;
            key_info
                .to_der()
                .map_err(|e| internal("X25519 PKCS#8 DER encoding failed").with_details(e.to_string()))
        }
    }
}

/// Encode a private key as `-----BEGIN PRIVATE KEY-----` PEM (PKCS#8).
pub fn ecc_private_key_to_pkcs8_pem(curve: EccCurve, private_hex: &str) -> PkiResult<String> {
    match curve {
        EccCurve::P256 => {
            let bytes = decode_scalar_hex("private_key", private_hex, 32)?;
            let secret = parse_nist_secret::<p256::NistP256>(&bytes)?;
            encode_pkcs8_pem(secret.to_pkcs8_pem(der::pem::LineEnding::LF))
        }
        EccCurve::P384 => {
            let bytes = decode_scalar_hex("private_key", private_hex, 48)?;
            let secret = parse_nist_secret::<p384::NistP384>(&bytes)?;
            encode_pkcs8_pem(secret.to_pkcs8_pem(der::pem::LineEnding::LF))
        }
        EccCurve::Ed25519 => {
            let signing = super::ed25519::parse_signing_key(private_hex)?;
            encode_pkcs8_pem(signing.to_pkcs8_pem(der::pem::LineEnding::LF))
        }
        EccCurve::X25519 => {
            let bytes = decode_fixed_hex("private_key", private_hex, 32)?;
            let key_info = x25519_key_info(&bytes)?;
            use der::EncodePem as _;
            key_info
                .to_pem(der::pem::LineEnding::LF)
                .map_err(|e| internal("X25519 PKCS#8 PEM encoding failed").with_details(e.to_string()))
        }
    }
}

/// RFC 8410 `PrivateKeyInfo` wrapper for an X25519 private key (raw 32-byte
/// scalar in the OCTET STRING).
fn x25519_key_info(bytes: &[u8]) -> PkiResult<pkcs8::PrivateKeyInfo<'_>> {
    Ok(pkcs8::PrivateKeyInfo {
        algorithm: spki::AlgorithmIdentifierRef {
            oid: X25519_OID,
            parameters: None,
        },
        private_key: bytes,
        public_key: None,
    })
}

fn encode_pkcs8_der(document: Result<pkcs8::SecretDocument, pkcs8::Error>) -> PkiResult<Vec<u8>> {
    document
        .map(|doc| doc.as_bytes().to_vec())
        .map_err(|e| internal("PKCS#8 DER encoding failed").with_details(e.to_string()))
}

fn encode_pkcs8_pem(pem: pkcs8::Result<impl std::ops::Deref<Target = String>>) -> PkiResult<String> {
    pem.map(|s| (*s).clone())
        .map_err(|e| internal("PKCS#8 PEM encoding failed").with_details(e.to_string()))
}

// ---------------------------------------------------------------------------
// PKCS#8 (private key) DER / PEM — decode with curve auto-detection
// ---------------------------------------------------------------------------

/// Decode a PKCS#8 `PrivateKeyInfo` DER blob, auto-detecting the curve from
/// the algorithm identifier (EC named curve, Ed25519, X25519) and validating
/// the key. Returns the keypair including the derived public key.
pub fn ecc_private_key_from_pkcs8_der(der: &[u8]) -> PkiResult<EccKeyPair> {
    let key_info = pkcs8::PrivateKeyInfo::from_der(der)
        .map_err(|e| invalid_der("PKCS#8 PrivateKeyInfo", e))?;
    match key_info.algorithm.oid {
        EC_PUBLIC_KEY_OID => {
            let curve_oid: ObjectIdentifier = key_info
                .algorithm
                .parameters
                .ok_or_else(|| {
                    wrong_encoding("EC private key is missing the named-curve parameter")
                        .with_expected("id-ecPublicKey with a namedCurve OID parameter")
                })?
                .decode_as()
                .map_err(|_| {
                    wrong_encoding(
                        "EC private key uses explicit curve parameters, which CyberCipher does not support",
                    )
                    .with_expected("a namedCurve OID parameter")
                })?;
            match curve_oid {
                P256_OID => {
                    let secret = p256::SecretKey::from_pkcs8_der(der)
                        .map_err(|e| invalid_pkcs8_key("p256", e))?;
                    nist_keypair_from_secret(EccCurve::P256, &secret)
                }
                P384_OID => {
                    let secret = p384::SecretKey::from_pkcs8_der(der)
                        .map_err(|e| invalid_pkcs8_key("p384", e))?;
                    nist_keypair_from_secret(EccCurve::P384, &secret)
                }
                other => Err(PkiError::unsupported(format!(
                    "unsupported EC named curve {other}"
                ))
                .with_expected("P-256 (prime256v1) or P-384 (secp384r1)")
                .with_actual(other.to_string())),
            }
        }
        ED25519_OID => super::ed25519::private_from_pkcs8_octets(key_info.private_key),
        X25519_OID => super::x25519::private_from_pkcs8_octets(key_info.private_key),
        other => Err(PkiError::unsupported(format!(
            "PKCS#8 private key algorithm {other} is not supported (expected id-ecPublicKey, id-Ed25519, or id-X25519)"
        ))
        .with_actual(other.to_string())),
    }
}

/// Decode a `-----BEGIN PRIVATE KEY-----` PEM (PKCS#8) with curve
/// auto-detection.
pub fn ecc_private_key_from_pkcs8_pem(pem: &str) -> PkiResult<EccKeyPair> {
    let block = split_pem(pem, "PRIVATE KEY")?;
    ecc_private_key_from_pkcs8_der(&block.der)
}

fn invalid_pkcs8_key(curve: &str, e: pkcs8::Error) -> PkiError {
    invalid_key(format!("invalid {curve} PKCS#8 private key")).with_details(e.to_string())
}

// ---------------------------------------------------------------------------
// PEM armor (mirrors keys::pem conventions; RSA-aware parts omitted)
// ---------------------------------------------------------------------------

struct EccPemBlock {
    #[allow(dead_code)]
    label: String,
    der: Vec<u8>,
}

/// Split PEM armor and require the given label. Recognizes the standard
/// certificate labels for the "wrong object type" hint and rejects encrypted
/// keys with the same "not supported yet" error as the RSA paths.
fn split_pem(input: &str, expected_label: &str) -> PkiResult<EccPemBlock> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(invalid_armor("empty PEM input")
            .with_parameter("pem")
            .with_expected("PEM with BEGIN/END armor lines"));
    }
    let begin = trimmed.lines().next().unwrap_or_default();
    let rest = begin.trim_start().strip_prefix("-----BEGIN ").ok_or_else(|| {
        invalid_armor("missing '-----BEGIN ...-----' armor header")
            .with_parameter("pem")
            .with_actual(crate::keys::preview(begin, 48))
    })?;
    let label = rest.strip_suffix("-----").ok_or_else(|| {
        invalid_armor("BEGIN header is not terminated by '-----'")
            .with_parameter("pem")
            .with_actual(crate::keys::preview(begin, 48))
    })?;

    // Recognize certificates/CSRs up front for the clearer wrong-object error.
    if matches!(
        label,
        "CERTIFICATE" | "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" | "X509 CRL"
    ) {
        return Err(crate::error::wrong_object_type(label));
    }
    if label == "ENCRYPTED PRIVATE KEY" {
        return Err(PkiError::unsupported(
            "encrypted keys are not supported yet: the PEM contains an encrypted key",
        )
        .with_expected("an unencrypted key PEM"));
    }

    let end_marker = format!("-----END {label}-----");
    let mut base64 = String::new();
    let mut saw_end = false;
    let mut headers: Vec<String> = Vec::new();
    for line in trimmed.lines().skip(1) {
        let line = line.trim();
        if line == end_marker {
            saw_end = true;
            break;
        }
        if line.contains(':') {
            headers.push(line.to_ascii_uppercase());
            continue;
        }
        base64.push_str(line);
    }
    if !saw_end {
        return Err(invalid_armor(format!(
            "missing '-----END {label}-----' terminator"
        ))
        .with_parameter("pem"));
    }
    if headers
        .iter()
        .any(|h| h.starts_with("PROC-TYPE:") && h.contains("ENCRYPTED"))
        || headers.iter().any(|h| h.starts_with("DEK-INFO:"))
    {
        return Err(PkiError::unsupported(
            "encrypted keys are not supported yet: the PEM contains an encrypted key",
        )
        .with_expected("an unencrypted key PEM"));
    }

    if label != expected_label {
        return Err(wrong_encoding(format!(
            "wrong PEM object type: expected '{expected_label}', found '{label}'"
        ))
        .with_parameter("pem")
        .with_expected(expected_label)
        .with_actual(label));
    }

    let der = base64ct::Base64::decode_vec(&base64).map_err(|e| {
        invalid_armor("invalid base64 payload in PEM body").with_details(e.to_string())
    })?;
    Ok(EccPemBlock {
        label: label.to_string(),
        der,
    })
}
