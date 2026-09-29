//! RSA key generation and canonical key-material handling.
//!
//! Conventions (shared with the rest of CyberCipher):
//! - Big integers never cross the boundary as numbers or serde-encoded
//!   bignums. Every component is transported as a lowercase big-endian hex
//!   string (`n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `qinv`).
//! - Results are serde-serializable structs; failures are typed
//!   [`PkiError`] (= `cybercipher_core::OperationError`).
//! - No panics on user input: every malformed key, PEM, DER, or JWK is a
//!   typed error.

pub mod jwk;
pub mod pem;

pub use jwk::{
    jwk_to_json, jwk_to_keypair, jwk_to_public_material, jwks_to_json, keypair_to_jwk, parse_jwk,
    parse_jwks, public_material_to_jwk, RsaJwk,
};
pub use pem::{
    inspect_der, inspect_pem, parse_pem, parse_pkcs1_private_der, parse_pkcs1_public_der,
    parse_pkcs8_private_der, parse_spki_public_der, ParsedKey,
};

use num_bigint_dig::BigUint;
use rand::rngs::OsRng;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use serde::{Deserialize, Serialize};

use crate::error::{inconsistent_key, PkiError, PkiResult};

/// Key sizes accepted by [`generate_rsa_keypair`]. 1024 is accepted but
/// flagged as legacy; anything above [`MAX_KEYGEN_BITS`] is rejected.
pub const SUPPORTED_KEY_BITS: [usize; 4] = [1024, 2048, 3072, 4096];

/// Upper bound for key generation. Larger moduli take minutes-to-hours and
/// belong in dedicated tooling, not an interactive workbench.
pub const MAX_KEYGEN_BITS: usize = 4096;

/// Default RSA public exponent (65537), in hex per the transport convention.
pub const DEFAULT_EXPONENT_HEX: &str = "010001";

// ---------------------------------------------------------------------------
// Hex / byte-size transport helpers
// ---------------------------------------------------------------------------

/// Lowercase big-endian hex of a byte string (the CyberCipher big-int
/// transport format).
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode a hex string (optional `0x` prefix, upper or lower case) into a
/// `BigUint`. Empty, odd-length, or non-hex input is a typed error.
pub(crate) fn biguint_from_hex(hex: &str) -> PkiResult<BigUint> {
    let s = hex.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.is_empty() {
        return Err(PkiError::decode("empty hex value")
            .with_expected("non-empty hex string")
            .with_actual(preview(hex, 24)));
    }
    if !s.len().is_multiple_of(2) {
        return Err(PkiError::decode("odd-length hex value")
            .with_expected("even-length hex string")
            .with_actual(preview(hex, 24)));
    }
    if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PkiError::decode("non-hex character in hex value")
            .with_expected("hex characters [0-9a-fA-F]")
            .with_actual(preview(hex, 24)));
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().as_chunks::<2>().0 {
        let hi = (pair[0] as char).to_digit(16).unwrap_or(0) as u8;
        let lo = (pair[1] as char).to_digit(16).unwrap_or(0) as u8;
        bytes.push((hi << 4) | lo);
    }
    Ok(BigUint::from_bytes_be(&bytes))
}

/// Minimal big-endian hex encoding of a `BigUint` (zero encodes as `00`).
pub(crate) fn biguint_to_hex(v: &BigUint) -> String {
    let bytes = v.to_bytes_be();
    if bytes.is_empty() {
        return "00".to_string();
    }
    to_hex(&bytes)
}

/// Bit length of a big-endian byte string (leading zero bytes ignored).
pub(crate) fn bytes_bit_length(bytes: &[u8]) -> usize {
    let mut i = 0;
    while i < bytes.len() && bytes[i] == 0 {
        i += 1;
    }
    if i == bytes.len() {
        return 0;
    }
    (bytes.len() - i - 1) * 8 + (8 - bytes[i].leading_zeros() as usize)
}

/// Bit length of a hex string produced by [`to_hex`] / [`biguint_to_hex`].
pub(crate) fn hex_bit_length(hex: &str) -> usize {
    let stripped = hex.trim_start_matches('0');
    if stripped.is_empty() {
        return 0;
    }
    let nibble = (stripped.as_bytes()[0] as char).to_digit(16).unwrap_or(0) as u8;
    if nibble == 0 {
        return 0;
    }
    (stripped.len() - 1) * 4 + (8 - nibble.leading_zeros() as usize)
}

/// Truncate long values for `actual` fields in error reports.
pub(crate) fn preview(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max).collect();
        format!("{head}...({} chars)", s.chars().count())
    }
}

// ---------------------------------------------------------------------------
// Transport structs (serde boundary)
// ---------------------------------------------------------------------------

/// Full RSA private-key material as hex strings. This is the serde-serializable
/// shape of a generated or parsed private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaKeyMaterial {
    pub n: String,
    pub e: String,
    pub d: String,
    pub p: String,
    pub q: String,
    pub dp: String,
    pub dq: String,
    pub qinv: String,
}

/// RSA public-key material as hex strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaPublicKeyMaterial {
    pub n: String,
    pub e: String,
}

// ---------------------------------------------------------------------------
// Keypair
// ---------------------------------------------------------------------------

/// An RSA private key with its full CRT component set.
///
/// `dp`, `dq`, and `qinv` are always derived canonically from `(d, p, q)` —
/// including for keys parsed from PKCS#1/PKCS#8/JWK — so the component set is
/// self-consistent by construction.
#[derive(Clone)]
pub struct RsaKeypair {
    key: rsa::RsaPrivateKey,
    n: BigUint,
    e: BigUint,
    d: BigUint,
    p: BigUint,
    q: BigUint,
    dp: BigUint,
    dq: BigUint,
    qinv: BigUint,
}

impl std::fmt::Debug for RsaKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print private material.
        f.debug_struct("RsaKeypair")
            .field("bits", &self.bits())
            .field("e", &biguint_to_hex(&self.e))
            .finish_non_exhaustive()
    }
}

impl RsaKeypair {
    /// Generate an RSA keypair of `bits` (one of 1024/2048/3072/4096) with the
    /// public exponent given as a hex string (`"010001"` = 65537).
    pub fn generate(bits: usize, exponent_hex: &str) -> PkiResult<Self> {
        validate_bits(bits)?;
        let e = biguint_from_hex(exponent_hex).map_err(|err| err.with_parameter("e"))?;
        validate_exponent(&e, bits, "e")?;
        let key = rsa::RsaPrivateKey::new_with_exp(&mut OsRng, bits, &e).map_err(|err| {
            PkiError::internal(format!("RSA {bits}-bit key generation failed"))
                .with_parameter("bits")
                .with_actual(bits.to_string())
                .with_details(err.to_string())
        })?;
        Self::from_rsa_key(key)
    }

    /// Build (and validate) a keypair from raw components. Used by the PEM,
    /// DER, and JWK parse paths; all inputs are treated as untrusted.
    pub(crate) fn from_biguints(
        n: BigUint,
        e: BigUint,
        d: BigUint,
        p: BigUint,
        q: BigUint,
    ) -> PkiResult<Self> {
        let err = |message: String| inconsistent_key(message);
        if n.bits() == 0 || e.bits() == 0 || d.bits() == 0 || p.bits() == 0 || q.bits() == 0 {
            return Err(err("RSA key components must all be non-zero".to_string())
                .with_expected("non-zero n, e, d, p, q"));
        }
        let three = BigUint::from(3u32);
        if p < three || q < three {
            return Err(err("RSA primes must be >= 3".to_string()));
        }
        if p == q {
            return Err(err("RSA primes must differ (p != q)".to_string()));
        }
        if &p * &q != n {
            return Err(err("RSA modulus mismatch: p * q != n".to_string()));
        }
        let key = rsa::RsaPrivateKey::from_components(
            n.clone(),
            e.clone(),
            d.clone(),
            vec![p.clone(), q.clone()],
        )
        .map_err(|e| {
            err("RSA key failed consistency validation".to_string()).with_details(e.to_string())
        })?;
        let (dp, dq, qinv) = derive_crt(&d, &p, &q);
        Ok(Self {
            key,
            n,
            e,
            d,
            p,
            q,
            dp,
            dq,
            qinv,
        })
    }

    /// Build (and validate) a keypair from raw big-endian byte components.
    /// Used by the JWK parse path; all inputs are treated as untrusted.
    pub(crate) fn from_parts_bytes(
        n: &[u8],
        e: &[u8],
        d: &[u8],
        p: &[u8],
        q: &[u8],
    ) -> PkiResult<Self> {
        Self::from_biguints(
            BigUint::from_bytes_be(n),
            BigUint::from_bytes_be(e),
            BigUint::from_bytes_be(d),
            BigUint::from_bytes_be(p),
            BigUint::from_bytes_be(q),
        )
    }

    /// Adopt a freshly generated `rsa` crate key.
    pub(crate) fn from_rsa_key(key: rsa::RsaPrivateKey) -> PkiResult<Self> {
        let primes = key.primes();
        if primes.len() != 2 {
            return Err(PkiError::unsupported(format!(
                "multi-prime RSA keys ({} primes) are not supported yet",
                primes.len()
            ))
            .with_expected("2 primes")
            .with_actual(primes.len().to_string()));
        }
        let n = key.n().clone();
        let e = key.e().clone();
        let d = key.d().clone();
        let p = primes[0].clone();
        let q = primes[1].clone();
        let (dp, dq, qinv) = derive_crt(&d, &p, &q);
        Ok(Self {
            key,
            n,
            e,
            d,
            p,
            q,
            dp,
            dq,
            qinv,
        })
    }

    /// Modulus size in bits.
    pub fn bits(&self) -> usize {
        self.n.bits()
    }

    /// Hex-string material for transport/serialization.
    pub fn material(&self) -> RsaKeyMaterial {
        RsaKeyMaterial {
            n: biguint_to_hex(&self.n),
            e: biguint_to_hex(&self.e),
            d: biguint_to_hex(&self.d),
            p: biguint_to_hex(&self.p),
            q: biguint_to_hex(&self.q),
            dp: biguint_to_hex(&self.dp),
            dq: biguint_to_hex(&self.dq),
            qinv: biguint_to_hex(&self.qinv),
        }
    }

    /// Public half as hex-string material.
    pub fn public_material(&self) -> RsaPublicKeyMaterial {
        RsaPublicKeyMaterial {
            n: biguint_to_hex(&self.n),
            e: biguint_to_hex(&self.e),
        }
    }

    /// The underlying `rsa` crate private key (for crypto operations such as
    /// OAEP/signatures in later phases).
    pub fn rsa_private_key(&self) -> rsa::RsaPrivateKey {
        self.key.clone()
    }

    /// The public half as an `rsa` crate key.
    pub fn rsa_public_key(&self) -> rsa::RsaPublicKey {
        self.key.to_public_key()
    }

    // -- DER / PEM serialization (PKCS#1 + PKCS#8 private, PKCS#1 + SPKI public)

    /// RSAPrivateKey DER (PKCS#1, RFC 8017).
    pub fn to_pkcs1_der(&self) -> PkiResult<Vec<u8>> {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        encode_err(
            self.key.to_pkcs1_der().map(|doc| doc.as_bytes().to_vec()),
            "PKCS#1 RSAPrivateKey",
        )
    }

    /// PrivateKeyInfo DER (PKCS#8, RFC 5958).
    pub fn to_pkcs8_der(&self) -> PkiResult<Vec<u8>> {
        use rsa::pkcs8::EncodePrivateKey;
        encode_err(
            self.key.to_pkcs8_der().map(|doc| doc.as_bytes().to_vec()),
            "PKCS#8 PrivateKeyInfo",
        )
    }

    /// `-----BEGIN RSA PRIVATE KEY-----` PEM (PKCS#1).
    pub fn to_pkcs1_pem(&self) -> PkiResult<String> {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        self.key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .map(|s| s.to_string())
            .map_err(|e| encode_failure("PKCS#1 RSAPrivateKey PEM", e))
    }

    /// `-----BEGIN PRIVATE KEY-----` PEM (PKCS#8).
    pub fn to_pkcs8_pem(&self) -> PkiResult<String> {
        use rsa::pkcs8::EncodePrivateKey;
        self.key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map(|s| s.to_string())
            .map_err(|e| encode_failure("PKCS#8 PrivateKeyInfo PEM", e))
    }

    /// RSAPublicKey DER (PKCS#1, RFC 8017).
    pub fn to_public_pkcs1_der(&self) -> PkiResult<Vec<u8>> {
        use rsa::pkcs1::EncodeRsaPublicKey;
        encode_err(
            self.key
                .to_public_key()
                .to_pkcs1_der()
                .map(|doc| doc.as_bytes().to_vec()),
            "PKCS#1 RSAPublicKey",
        )
    }

    /// SubjectPublicKeyInfo DER (SPKI, RFC 5280).
    pub fn to_public_spki_der(&self) -> PkiResult<Vec<u8>> {
        use rsa::pkcs8::EncodePublicKey;
        encode_err(
            self.key
                .to_public_key()
                .to_public_key_der()
                .map(|doc| doc.as_bytes().to_vec()),
            "SPKI SubjectPublicKeyInfo",
        )
    }

    /// `-----BEGIN RSA PUBLIC KEY-----` PEM (PKCS#1).
    pub fn to_public_pkcs1_pem(&self) -> PkiResult<String> {
        use rsa::pkcs1::EncodeRsaPublicKey;
        self.key
            .to_public_key()
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| encode_failure("PKCS#1 RSAPublicKey PEM", e))
    }

    /// `-----BEGIN PUBLIC KEY-----` PEM (SPKI).
    pub fn to_public_spki_pem(&self) -> PkiResult<String> {
        use rsa::pkcs8::EncodePublicKey;
        self.key
            .to_public_key()
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| encode_failure("SPKI SubjectPublicKeyInfo PEM", e))
    }
}

/// Task-named entry point: generate an RSA keypair.
pub fn generate_rsa_keypair(bits: usize, exponent_hex: &str) -> PkiResult<RsaKeypair> {
    RsaKeypair::generate(bits, exponent_hex)
}

/// Map a DER-encoding `Result` that already produced bytes into a typed error.
fn encode_err(
    result: Result<Vec<u8>, impl std::fmt::Display>,
    context: &str,
) -> PkiResult<Vec<u8>> {
    result.map_err(|e| {
        PkiError::internal(format!("{context} DER encoding failed")).with_details(e.to_string())
    })
}

fn encode_failure(context: &str, source: impl std::fmt::Display) -> PkiError {
    PkiError::internal(format!("{context} encoding failed")).with_details(source.to_string())
}

fn validate_bits(bits: usize) -> PkiResult<()> {
    match bits {
        1024 | 2048 | 3072 | 4096 => Ok(()),
        b if b < 1024 => Err(PkiError::invalid_param(
            "bits",
            "RSA key generation requires at least 1024 bits",
        )
        .with_expected("one of 1024 (legacy), 2048, 3072, 4096")
        .with_actual(b.to_string())),
        b if b > MAX_KEYGEN_BITS => Err(PkiError::invalid_param(
            "bits",
            format!("key generation is capped at {MAX_KEYGEN_BITS} bits: larger moduli take far too long to generate interactively"),
        )
        .with_expected("one of 1024 (legacy), 2048, 3072, 4096")
        .with_actual(b.to_string())
        .with_details(
            "for analyzing large existing moduli use the factoring/attack tooling instead of keygen",
        )),
        b => Err(PkiError::invalid_param(
            "bits",
            format!("unsupported RSA key size {b}"),
        )
        .with_expected("one of 1024 (legacy), 2048, 3072, 4096")
        .with_actual(b.to_string())),
    }
}

fn validate_exponent(e: &BigUint, bits: usize, parameter: &str) -> PkiResult<()> {
    let actual = preview(&biguint_to_hex(e), 24);
    if e.bits() == 0 || *e < BigUint::from(3u32) {
        return Err(PkiError::invalid_param(
            parameter,
            "RSA public exponent must be an odd integer >= 3",
        )
        .with_expected("odd integer >= 3 (typically 65537 = hex 010001)")
        .with_actual(actual));
    }
    let lsb = e.to_bytes_le().first().copied().unwrap_or(0);
    if lsb & 1 == 0 {
        return Err(
            PkiError::invalid_param(parameter, "RSA public exponent must be odd")
                .with_expected("odd integer")
                .with_actual(actual),
        );
    }
    if e.bits() >= bits {
        return Err(PkiError::invalid_param(
            parameter,
            "RSA public exponent must be smaller than the modulus",
        )
        .with_expected(format!("exponent < {bits} bits"))
        .with_actual(format!("{} bits", e.bits())));
    }
    Ok(())
}

/// Derive `dp = d mod (p-1)`, `dq = d mod (q-1)`, `qinv = q^-1 mod p`.
///
/// `qinv` uses Fermat's little theorem (`q^(p-2) mod p`), valid because `p`
/// is prime and coprime to `q`. Callers must ensure `p, q >= 3` (all
/// construction paths do) so the subtractions cannot underflow.
fn derive_crt(d: &BigUint, p: &BigUint, q: &BigUint) -> (BigUint, BigUint, BigUint) {
    let dp = d % (p - 1u32);
    let dq = d % (q - 1u32);
    let qinv = q.modpow(&(p - 2u32), p);
    (dp, dq, qinv)
}

/// Static strength classification shown in inspection results.
pub fn strength_note(bits: usize) -> &'static str {
    match bits {
        0..=1023 => "unknown",
        1024 => "legacy (deprecated): 1024-bit RSA is considered weak",
        2048 => "standard: acceptable for general use",
        3072 => "strong",
        _ => "very strong",
    }
}

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

/// What kind of key an inspection describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    RsaPrivate,
    RsaPublic,
}

/// The container format a key was parsed from (or `Raw` for freshly
/// generated keys).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyFormat {
    Raw,
    Pkcs1,
    Pkcs8,
    Spki,
    Jwk,
}

impl KeyFormat {
    pub fn label(&self) -> &'static str {
        match self {
            KeyFormat::Raw => "raw",
            KeyFormat::Pkcs1 => "pkcs1",
            KeyFormat::Pkcs8 => "pkcs8",
            KeyFormat::Spki => "spki",
            KeyFormat::Jwk => "jwk",
        }
    }
}

/// Structured inspection result: key type, container format, bit length, the
/// components present (hex strings), a strength note, and a human-readable
/// summary. Serde-serializable (snake_case) for the GUI/CLI layers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyInspection {
    pub key_type: KeyType,
    pub format: KeyFormat,
    pub bit_length: usize,
    pub n: String,
    pub e: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dq: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qinv: Option<String>,
    pub strength: String,
    pub summary: String,
}

/// Anything inspectable.
pub trait InspectKey {
    fn inspect(&self) -> PkiResult<KeyInspection>;
}

impl InspectKey for RsaKeypair {
    fn inspect(&self) -> PkiResult<KeyInspection> {
        let m = self.material();
        let bits = self.bits();
        let summary = format!(
            "RSA private key ({}, {} bits, e = {}){}",
            KeyFormat::Raw.label(),
            bits,
            m.e,
            legacy_suffix(bits)
        );
        Ok(KeyInspection {
            key_type: KeyType::RsaPrivate,
            format: KeyFormat::Raw,
            bit_length: bits,
            n: m.n,
            e: m.e,
            d: Some(m.d),
            p: Some(m.p),
            q: Some(m.q),
            dp: Some(m.dp),
            dq: Some(m.dq),
            qinv: Some(m.qinv),
            strength: strength_note(bits).to_string(),
            summary,
        })
    }
}

impl InspectKey for RsaPublicKeyMaterial {
    fn inspect(&self) -> PkiResult<KeyInspection> {
        let bits = hex_bit_length(&self.n);
        let summary = format!(
            "RSA public key ({}, {} bits, e = {}){}",
            KeyFormat::Raw.label(),
            bits,
            self.e,
            legacy_suffix(bits)
        );
        Ok(KeyInspection {
            key_type: KeyType::RsaPublic,
            format: KeyFormat::Raw,
            bit_length: bits,
            n: self.n.clone(),
            e: self.e.clone(),
            d: None,
            p: None,
            q: None,
            dp: None,
            dq: None,
            qinv: None,
            strength: strength_note(bits).to_string(),
            summary,
        })
    }
}

pub(crate) fn legacy_suffix(bits: usize) -> String {
    if bits <= 1024 {
        " [legacy: 1024-bit RSA is deprecated, use 2048+ bits]".to_string()
    } else {
        String::new()
    }
}
