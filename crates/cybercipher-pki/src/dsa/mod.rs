//! DSA (Digital Signature Algorithm, FIPS 186-4/5) for CyberCipher.
//!
//! All DSA arithmetic comes from the RustCrypto [`dsa`] crate — parameter
//! generation, key construction, RFC 6979 deterministic signing, and
//! verification. Nothing is implemented by hand. The crate sits on the same
//! `pkcs8` 0.10 / `spki` 0.7 / `der` 0.7 stack as the rest of this module
//! tree, so generated keys export to standard PKCS#8 (private) and SPKI
//! (public) PEM containers.
//!
//! Conventions (shared with the rest of CyberCipher):
//! - Domain parameters (p, q, g) and key components (x, y) cross the boundary
//!   as lowercase big-endian hex strings (the big-int transport).
//! - Messages are raw bytes (hex); digests are prehashed bytes (hex) used
//!   as-is. `hash` names the digest function for both paths (RFC 6979 uses
//!   the same hash for the deterministic nonce).
//! - Results are serde-serializable structs (snake_case).
//! - No panics on user input: malformed parameters are typed [`PkiError`]s.
//! - Signature-verification failures are *results* (`valid: false` + a
//!   `reason`), not errors — mirroring [`crate::ops::sign`].
//!
//! Key sizes follow FIPS 186-4 (L = |p|, N = |q|):
//! - `1024/160` — legacy (SHA-1 pairing),
//! - `2048/224`, `2048/256` — current baseline,
//! - `3072/256` — highest strength.
//!
//! [`registry`] wires the operations (`dsa-keygen`, `dsa-sign`,
//! `dsa-verify`) into the operation registry.

mod registry;

pub use registry::register;

use digest::core_api::BlockSizeUser;
use digest::{Digest, FixedOutputReset};
use dsa::Components as DsaComponents;
use num_bigint_dig::BigUint;
use num_traits::Zero;
use pkcs8::{EncodePrivateKey as _, LineEnding};
use serde::{Deserialize, Serialize};
use signature::{hazmat::PrehashVerifier as _, DigestSigner as _, DigestVerifier as _};
use spki::EncodePublicKey as _;

use crate::ecc::decode_hex;
use crate::error::{PkiError, PkiResult};
use crate::keys::to_hex;

/// Digest functions paired with DSA signing/verification. FIPS 186-4 §4.2
/// recommends N (the q bit size) match the digest output; the registry
/// defaults to SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DsaHash {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl DsaHash {
    /// Parse a hash label (`sha256`, `SHA-256`, ...).
    pub fn parse(label: &str) -> PkiResult<Self> {
        match label.to_ascii_lowercase().replace('-', "").as_str() {
            "sha1" => Ok(DsaHash::Sha1),
            "sha224" => Ok(DsaHash::Sha224),
            "sha256" => Ok(DsaHash::Sha256),
            "sha384" => Ok(DsaHash::Sha384),
            "sha512" => Ok(DsaHash::Sha512),
            other => Err(
                PkiError::unsupported(format!("unsupported DSA hash `{other}`"))
                    .with_parameter("hash")
                    .with_expected("sha1 | sha224 | sha256 | sha384 | sha512")
                    .with_actual(label),
            ),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            DsaHash::Sha1 => "sha1",
            DsaHash::Sha224 => "sha224",
            DsaHash::Sha256 => "sha256",
            DsaHash::Sha384 => "sha384",
            DsaHash::Sha512 => "sha512",
        }
    }
}

/// FIPS 186-4 parameter sizes (L = |p|, N = |q|).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DsaKeySize {
    Dsa1024_160,
    Dsa2048_224,
    Dsa2048_256,
    Dsa3072_256,
}

impl DsaKeySize {
    /// Parse a size label: `1024/160`, `dsa_2048_256`, `2048-256`, ...
    pub fn parse(label: &str) -> PkiResult<Self> {
        let normalized = label.to_ascii_lowercase().replace(['-', ' '], "_");
        match normalized.as_str() {
            "1024/160" | "dsa_1024_160" | "dsa1024_160" => Ok(DsaKeySize::Dsa1024_160),
            "2048/224" | "dsa_2048_224" | "dsa2048_224" => Ok(DsaKeySize::Dsa2048_224),
            "2048/256" | "dsa_2048_256" | "dsa2048_256" => Ok(DsaKeySize::Dsa2048_256),
            "3072/256" | "dsa_3072_256" | "dsa3072_256" => Ok(DsaKeySize::Dsa3072_256),
            other => Err(
                PkiError::invalid_input(format!("unknown DSA key size `{other}`"))
                    .with_parameter("size")
                    .with_expected("1024/160 | 2048/224 | 2048/256 | 3072/256")
                    .with_actual(label),
            ),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            DsaKeySize::Dsa1024_160 => "1024/160",
            DsaKeySize::Dsa2048_224 => "2048/224",
            DsaKeySize::Dsa2048_256 => "2048/256",
            DsaKeySize::Dsa3072_256 => "3072/256",
        }
    }

    fn key_size(self) -> dsa::KeySize {
        match self {
            // SP 800-57 marks this size as under 112 bits; it stays opt-in
            // (never a default) for legacy/CTF material interop.
            #[allow(deprecated)]
            DsaKeySize::Dsa1024_160 => dsa::KeySize::DSA_1024_160,
            DsaKeySize::Dsa2048_224 => dsa::KeySize::DSA_2048_224,
            DsaKeySize::Dsa2048_256 => dsa::KeySize::DSA_2048_256,
            DsaKeySize::Dsa3072_256 => dsa::KeySize::DSA_3072_256,
        }
    }
}

/// A complete DSA key pair: domain parameters plus private/public components.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DsaKeyPair {
    /// FIPS parameter size label, e.g. `2048/256`.
    pub size: String,
    /// Domain parameters, hex.
    pub p: String,
    pub q: String,
    pub g: String,
    /// Private component x, hex.
    pub private_key: String,
    /// Public component y = g^x mod p, hex.
    pub public_key: String,
    /// PKCS#8 PEM of the private key.
    pub private_key_pem: String,
    /// SPKI PEM of the public key.
    pub public_key_pem: String,
}

/// A DSA signature (r, s), hex.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DsaSignature {
    pub r: String,
    pub s: String,
}

/// DSA verification result. A bad signature is a *result*, not an error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DsaVerifyResult {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// What is being signed/verified: a raw message (hashed internally with the
/// chosen `hash`) or a precomputed digest (used as-is).
#[derive(Debug, Clone, PartialEq)]
pub enum DsaPreimage {
    /// Hex of the raw message bytes.
    Message(String),
    /// Hex of the digest bytes.
    Digest(String),
}

// ---------------------------------------------------------------------------
// Key generation / construction
// ---------------------------------------------------------------------------

/// Generate a fresh DSA key pair with FIPS 186-4 parameter generation
/// (probable primes) at the requested size. Note: parameter generation for
/// 2048/3072-bit moduli can take seconds — this is inherent to DSA keygen.
pub fn dsa_generate_keypair(size: DsaKeySize) -> PkiResult<DsaKeyPair> {
    let mut rng = rand::rngs::OsRng;
    let components = DsaComponents::generate(&mut rng, size.key_size());
    let signing_key = dsa::SigningKey::generate(&mut rng, components);
    keypair_from_signing_key(signing_key, size.label().to_string())
}

/// Build a validated key pair from explicit components (p, q, g, x as hex).
/// The public component is derived (y = g^x mod p); the crate's own key
/// constructors enforce 0 < x < q and y^q ≡ 1 (mod p).
pub fn dsa_keypair_from_components(
    p_hex: &str,
    q_hex: &str,
    g_hex: &str,
    x_hex: &str,
) -> PkiResult<DsaKeyPair> {
    let p = parse_component("p", p_hex)?;
    let q = parse_component("q", q_hex)?;
    let g = parse_component("g", g_hex)?;
    let x = parse_component("private_key", x_hex)?;
    let signing_key = signing_key_from_components(p, q, g, x.clone())?;
    let size = classify_size(
        signing_key.verifying_key().components().p(),
        signing_key.verifying_key().components().q(),
    );
    keypair_from_signing_key(signing_key, size)
}

// ---------------------------------------------------------------------------
// Signing / verification
// ---------------------------------------------------------------------------

/// Sign with RFC 6979 deterministic nonces (same key + message + hash ⇒ the
/// same signature). `preimage` is a raw message (hashed with `hash`) or a
/// precomputed digest (used as-is).
pub fn dsa_sign(
    p_hex: &str,
    q_hex: &str,
    g_hex: &str,
    x_hex: &str,
    preimage: &DsaPreimage,
    hash: DsaHash,
) -> PkiResult<DsaSignature> {
    let p = parse_component("p", p_hex)?;
    let q = parse_component("q", q_hex)?;
    let g = parse_component("g", g_hex)?;
    let x = parse_component("private_key", x_hex)?;
    let signing_key = signing_key_from_components(p, q, g, x)?;
    match preimage {
        DsaPreimage::Message(hex) => {
            let bytes = decode_hex("message", hex)?;
            match hash {
                DsaHash::Sha1 => sign_message::<sha1::Sha1>(&signing_key, &bytes),
                DsaHash::Sha224 => sign_message::<sha2::Sha224>(&signing_key, &bytes),
                DsaHash::Sha256 => sign_message::<sha2::Sha256>(&signing_key, &bytes),
                DsaHash::Sha384 => sign_message::<sha2::Sha384>(&signing_key, &bytes),
                DsaHash::Sha512 => sign_message::<sha2::Sha512>(&signing_key, &bytes),
            }
        }
        DsaPreimage::Digest(hex) => {
            let bytes = decode_hex("digest", hex)?;
            match hash {
                DsaHash::Sha1 => sign_prehashed::<sha1::Sha1>(&signing_key, &bytes),
                DsaHash::Sha224 => sign_prehashed::<sha2::Sha224>(&signing_key, &bytes),
                DsaHash::Sha256 => sign_prehashed::<sha2::Sha256>(&signing_key, &bytes),
                DsaHash::Sha384 => sign_prehashed::<sha2::Sha384>(&signing_key, &bytes),
                DsaHash::Sha512 => sign_prehashed::<sha2::Sha512>(&signing_key, &bytes),
            }
        }
    }
}

/// Verify a DSA signature. Malformed inputs (bad hex, inconsistent domain
/// parameters, invalid y) are typed errors; a well-formed signature that
/// does not verify is a `valid: false` result.
#[allow(clippy::too_many_arguments)] // explicit key material + payload + signature, mirrors ecdsa_verify
pub fn dsa_verify(
    p_hex: &str,
    q_hex: &str,
    g_hex: &str,
    y_hex: &str,
    preimage: &DsaPreimage,
    hash: DsaHash,
    r_hex: &str,
    s_hex: &str,
) -> PkiResult<DsaVerifyResult> {
    let p = parse_component("p", p_hex)?;
    let q = parse_component("q", q_hex)?;
    let g = parse_component("g", g_hex)?;
    let y = parse_component("public_key", y_hex)?;
    let r = parse_component("r", r_hex)?;
    let s = parse_component("s", s_hex)?;
    let components = DsaComponents::from_components(p, q, g).map_err(|_| {
        PkiError::key("invalid DSA domain parameters (need p, q ≥ 2 and 0 < g ≤ p)")
            .with_parameter("p/q/g")
    })?;
    let verifying_key = dsa::VerifyingKey::from_components(components, y).map_err(|_| {
        PkiError::key("invalid DSA public key: y must satisfy y^q ≡ 1 (mod p) with y ≥ 2")
            .with_parameter("public_key")
    })?;
    let signature = dsa::Signature::from_components(r, s).map_err(|_| {
        PkiError::key("invalid DSA signature: r and s must be non-zero").with_parameter("r/s")
    })?;
    match preimage {
        DsaPreimage::Message(hex) => {
            let bytes = decode_hex("message", hex)?;
            match hash {
                DsaHash::Sha1 => verify_message::<sha1::Sha1>(&verifying_key, &bytes, &signature),
                DsaHash::Sha224 => {
                    verify_message::<sha2::Sha224>(&verifying_key, &bytes, &signature)
                }
                DsaHash::Sha256 => {
                    verify_message::<sha2::Sha256>(&verifying_key, &bytes, &signature)
                }
                DsaHash::Sha384 => {
                    verify_message::<sha2::Sha384>(&verifying_key, &bytes, &signature)
                }
                DsaHash::Sha512 => {
                    verify_message::<sha2::Sha512>(&verifying_key, &bytes, &signature)
                }
            }
        }
        DsaPreimage::Digest(hex) => {
            // PrehashVerifier is not digest-generic: the raw digest bytes are
            // verified as-is regardless of which hash produced them.
            let bytes = decode_hex("digest", hex)?;
            verify_prehashed(&verifying_key, &bytes, &signature)
        }
    }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Variable-length integer parameter: hex (optional 0x prefix) → BigUint.
/// An odd nibble count is normalized with a leading zero — big-integer hex
/// transports (unlike fixed-width keys) routinely drop leading zeros.
fn parse_component(parameter: &str, value: &str) -> PkiResult<BigUint> {
    let trimmed = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    let normalized = if trimmed.len() % 2 == 1 {
        // Re-prefix with 0x so an original prefix is not doubled.
        format!("0x0{trimmed}")
    } else if trimmed.len() != value.trim().len() {
        format!("0x{trimmed}")
    } else {
        value.trim().to_string()
    };
    let bytes = decode_hex(parameter, &normalized)?;
    if bytes.is_empty() {
        return Err(
            PkiError::decode(format!("empty DSA component `{parameter}`"))
                .with_parameter(parameter)
                .with_expected("a non-empty hex integer"),
        );
    }
    Ok(BigUint::from_bytes_be(&bytes))
}

fn big_to_hex(value: &BigUint) -> String {
    to_hex(&value.to_bytes_be())
}

fn internal(message: &str) -> PkiError {
    PkiError::internal(message)
}

fn signing_key_from_components(
    p: BigUint,
    q: BigUint,
    g: BigUint,
    x: BigUint,
) -> PkiResult<dsa::SigningKey> {
    let components = DsaComponents::from_components(p, q, g).map_err(|_| {
        PkiError::key("invalid DSA domain parameters (need p, q ≥ 2 and 0 < g ≤ p)")
            .with_parameter("p/q/g")
    })?;
    if x.is_zero() || x >= *components.q() {
        return Err(
            PkiError::key("invalid DSA private component x (need 0 < x < q)")
                .with_parameter("private_key"),
        );
    }
    let y = components.g().modpow(&x, components.p());
    let verifying_key = dsa::VerifyingKey::from_components(components, y).map_err(|_| {
        PkiError::key("invalid DSA key: the derived public component violates y^q ≡ 1 (mod p)")
    })?;
    dsa::SigningKey::from_components(verifying_key, x)
        .map_err(|_| internal("DSA private component rejected after local validation"))
}

fn keypair_from_signing_key(signing_key: dsa::SigningKey, size: String) -> PkiResult<DsaKeyPair> {
    let verifying_key = signing_key.verifying_key();
    let components = verifying_key.components();
    let private_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map(|pem| pem.to_string())
        .map_err(|e| internal("PKCS#8 PEM encoding failed").with_details(e.to_string()))?;
    let public_pem = verifying_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| internal("SPKI PEM encoding failed").with_details(e.to_string()))?;
    Ok(DsaKeyPair {
        size,
        p: big_to_hex(components.p()),
        q: big_to_hex(components.q()),
        g: big_to_hex(components.g()),
        private_key: big_to_hex(signing_key.x()),
        public_key: big_to_hex(verifying_key.y()),
        private_key_pem: private_pem,
        public_key_pem: public_pem,
    })
}

/// Best-effort FIPS size label for a parameter set built from components.
fn classify_size(p: &BigUint, q: &BigUint) -> String {
    match (p.bits(), q.bits()) {
        (1024, 160) => DsaKeySize::Dsa1024_160.label().to_string(),
        (2048, 224) => DsaKeySize::Dsa2048_224.label().to_string(),
        (2048, 256) => DsaKeySize::Dsa2048_256.label().to_string(),
        (3072, 256) => DsaKeySize::Dsa3072_256.label().to_string(),
        (l, n) => format!("{l}/{n}"),
    }
}

fn signature_from(sig: &dsa::Signature) -> DsaSignature {
    DsaSignature {
        r: big_to_hex(sig.r()),
        s: big_to_hex(sig.s()),
    }
}

fn sign_message<D>(key: &dsa::SigningKey, message: &[u8]) -> PkiResult<DsaSignature>
where
    D: Digest + BlockSizeUser + FixedOutputReset,
{
    let digest = D::new_with_prefix(message);
    let sig = key
        .try_sign_digest(digest)
        .map_err(|e| PkiError::internal("DSA signing failed").with_details(e.to_string()))?;
    Ok(signature_from(&sig))
}

fn sign_prehashed<D>(key: &dsa::SigningKey, prehash: &[u8]) -> PkiResult<DsaSignature>
where
    D: Digest + BlockSizeUser + FixedOutputReset,
{
    let sig = key
        .sign_prehashed_rfc6979::<D>(prehash)
        .map_err(|e| PkiError::internal("DSA signing failed").with_details(e.to_string()))?;
    Ok(signature_from(&sig))
}

fn verify_message<D>(
    key: &dsa::VerifyingKey,
    message: &[u8],
    signature: &dsa::Signature,
) -> PkiResult<DsaVerifyResult>
where
    D: Digest,
{
    let digest = D::new_with_prefix(message);
    verify_outcome(key.verify_digest(digest, signature))
}

fn verify_prehashed(
    key: &dsa::VerifyingKey,
    prehash: &[u8],
    signature: &dsa::Signature,
) -> PkiResult<DsaVerifyResult> {
    verify_outcome(key.verify_prehash(prehash, signature))
}

fn verify_outcome(outcome: Result<(), signature::Error>) -> PkiResult<DsaVerifyResult> {
    Ok(match outcome {
        Ok(()) => DsaVerifyResult {
            valid: true,
            reason: None,
        },
        Err(_) => DsaVerifyResult {
            valid: false,
            reason: Some(
                "signature does not verify (v ≠ r, or r/s out of range for q)".to_string(),
            ),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic toy key: p = 2027 = 2·1013 + 1 (prime), q = 1013
    /// (prime), g = 4 = 2²  (order 1013 mod 2027), x = 7, y = 4⁷ mod 2027 =
    /// 168. Valid DSA math at toy scale; everything downstream (RFC 6979
    /// nonces, truncation) exercises the same code paths as real sizes.
    /// Values are hex: p = 0x7eb, q = 0x3f5, g = 4, x = 7, y = 0xa8.
    fn toy_key() -> (String, String, String, String, String) {
        (
            "7eb".to_string(),
            "3f5".to_string(),
            "04".to_string(),
            "07".to_string(),
            "a8".to_string(), // 168
        )
    }

    const MSG: &str = "deadbeefcafebabe";

    #[test]
    fn toy_key_is_valid_and_deterministic() {
        let (p, q, g, x, y) = toy_key();
        let kp = dsa_keypair_from_components(&p, &q, &g, &x).expect("toy key is valid");
        assert_eq!(kp.public_key, y);
        assert_eq!(kp.size, "11/10"); // classify_size falls back to bit sizes
                                      // Deterministic signing: same message ⇒ same signature.
        let sig1 = dsa_sign(
            &p,
            &q,
            &g,
            &x,
            &DsaPreimage::Message(MSG.into()),
            DsaHash::Sha256,
        )
        .expect("signing must succeed");
        let sig2 = dsa_sign(
            &p,
            &q,
            &g,
            &x,
            &DsaPreimage::Message(MSG.into()),
            DsaHash::Sha256,
        )
        .expect("signing must succeed");
        assert_eq!(sig1, sig2, "RFC 6979 signatures are deterministic");
    }

    #[test]
    fn sign_verify_roundtrip_message() {
        let (p, q, g, x, y) = toy_key();
        for hash in [
            DsaHash::Sha1,
            DsaHash::Sha224,
            DsaHash::Sha256,
            DsaHash::Sha384,
            DsaHash::Sha512,
        ] {
            let sig = dsa_sign(&p, &q, &g, &x, &DsaPreimage::Message(MSG.into()), hash)
                .unwrap_or_else(|e| panic!("{hash:?} signing failed: {e}"));
            let result = dsa_verify(
                &p,
                &q,
                &g,
                &y,
                &DsaPreimage::Message(MSG.into()),
                hash,
                &sig.r,
                &sig.s,
            )
            .expect("verification runs");
            assert!(result.valid, "{hash:?}: {:?}", result.reason);
        }
    }

    #[test]
    fn sign_verify_roundtrip_prehashed() {
        let (p, q, g, x, y) = toy_key();
        // digest = SHA-256(MSG)
        let digest_hex = to_hex(&sha2::Sha256::digest(decode_hex("message", MSG).unwrap()));
        let sig = dsa_sign(
            &p,
            &q,
            &g,
            &x,
            &DsaPreimage::Digest(digest_hex.clone()),
            DsaHash::Sha256,
        )
        .expect("prehashed signing must succeed");
        let result = dsa_verify(
            &p,
            &q,
            &g,
            &y,
            &DsaPreimage::Digest(digest_hex.clone()),
            DsaHash::Sha256,
            &sig.r,
            &sig.s,
        )
        .expect("verification runs");
        assert!(result.valid);
        // The message path and the digest path agree (same hash, same bytes).
        let via_message = dsa_sign(
            &p,
            &q,
            &g,
            &x,
            &DsaPreimage::Message(MSG.into()),
            DsaHash::Sha256,
        )
        .expect("message signing must succeed");
        assert_eq!(sig, via_message);
    }

    #[test]
    fn verify_rejects_tampered_message_and_wrong_hash() {
        let (p, q, g, x, y) = toy_key();
        let sig = dsa_sign(
            &p,
            &q,
            &g,
            &x,
            &DsaPreimage::Message(MSG.into()),
            DsaHash::Sha256,
        )
        .expect("signing must succeed");
        // Tampered message.
        let tampered = "deadbeefcafebabf";
        let result = dsa_verify(
            &p,
            &q,
            &g,
            &y,
            &DsaPreimage::Message(tampered.into()),
            DsaHash::Sha256,
            &sig.r,
            &sig.s,
        )
        .expect("verification runs");
        assert!(!result.valid);
        assert!(result.reason.is_some());
        // Same signature checked under a different hash.
        let result = dsa_verify(
            &p,
            &q,
            &g,
            &y,
            &DsaPreimage::Message(MSG.into()),
            DsaHash::Sha512,
            &sig.r,
            &sig.s,
        )
        .expect("verification runs");
        assert!(!result.valid);
    }

    #[test]
    fn verify_with_wrong_public_key_fails() {
        let (p, q, g, x, _y) = toy_key();
        let sig = dsa_sign(
            &p,
            &q,
            &g,
            &x,
            &DsaPreimage::Message(MSG.into()),
            DsaHash::Sha256,
        )
        .expect("signing must succeed");
        // A second key under the same domain parameters: x = 8.
        let kp = dsa_keypair_from_components(&p, &q, &g, "8").expect("second key");
        assert_ne!(kp.public_key, _y);
        let result = dsa_verify(
            &p,
            &q,
            &g,
            &kp.public_key,
            &DsaPreimage::Message(MSG.into()),
            DsaHash::Sha256,
            &sig.r,
            &sig.s,
        )
        .expect("verification runs");
        assert!(!result.valid);
    }

    #[test]
    fn malformed_inputs_are_typed_errors() {
        let (p, q, g, x, y) = toy_key();
        // Bad hex.
        assert!(dsa_keypair_from_components(&p, &q, &g, "zz").is_err());
        // x out of range (x ≥ q).
        assert!(dsa_keypair_from_components(&p, &q, &g, "401").is_err());
        // g = 0 rejected by the crate's constructor.
        assert!(dsa_keypair_from_components(&p, &q, "0", &x).is_err());
        // Unknown hash label.
        assert!(DsaHash::parse("md5").is_err());
        // Unknown size label.
        assert!(DsaKeySize::parse("512/128").is_err());
        // Zero r/s signature rejected as a typed error, not a result.
        let err = dsa_verify(
            &p,
            &q,
            &g,
            &y,
            &DsaPreimage::Message(MSG.into()),
            DsaHash::Sha256,
            "0",
            "1",
        )
        .expect_err("zero r must be a typed error");
        assert!(format!("{err}").contains("non-zero"));
        // Non-hex message.
        assert!(dsa_sign(
            &p,
            &q,
            &g,
            &x,
            &DsaPreimage::Message("nothex".into()),
            DsaHash::Sha256
        )
        .is_err());
    }

    #[test]
    fn generated_keypair_1024_is_usable() {
        // FIPS parameter generation at the smallest standard size; keeps the
        // test fast while exercising the real keygen path end-to-end.
        let kp = dsa_generate_keypair(DsaKeySize::Dsa1024_160).expect("keygen must succeed");
        assert_eq!(kp.size, "1024/160");
        assert!(kp
            .private_key_pem
            .starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(kp.public_key_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        // The generated pair round-trips through the component constructor.
        let rebuilt = dsa_keypair_from_components(&kp.p, &kp.q, &kp.g, &kp.private_key)
            .expect("generated components must re-validate");
        assert_eq!(rebuilt.public_key, kp.public_key);
        // And signs verifiably.
        let sig = dsa_sign(
            &kp.p,
            &kp.q,
            &kp.g,
            &kp.private_key,
            &DsaPreimage::Message(MSG.into()),
            DsaHash::Sha256,
        )
        .expect("signing must succeed");
        let result = dsa_verify(
            &kp.p,
            &kp.q,
            &kp.g,
            &kp.public_key,
            &DsaPreimage::Message(MSG.into()),
            DsaHash::Sha256,
            &sig.r,
            &sig.s,
        )
        .expect("verification runs");
        assert!(result.valid);
    }
}
