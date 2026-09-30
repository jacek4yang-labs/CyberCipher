//! JWT / JWS (RFC 7519 + RFC 7515): decode, sign, and verify compact
//! JWS serializations with the registered asymmetric/MAC algorithms:
//!
//! | JWS alg | Family | Key material                                    |
//! |---------|--------|-------------------------------------------------|
//! | HS256/384/512 | HMAC-SHA | shared secret (`utf8` or `hex`)        |
//! | RS256/384/512 | RSASSA-PKCS1-v1_5 | RSA key PEM (SPKI/PKCS#1/PKCS#8) |
//! | ES256/384 | ECDSA P-256/P-384 | EC key PEM (SPKI/PKCS#8) or hex   |
//! | EdDSA   | Ed25519 | Ed25519 key PEM (SPKI/PKCS#8) or raw hex       |
//!
//! Security posture (deliberate policy, not options):
//! - Decode is *never* verification: [`JwtDecoded`] always carries
//!   `verified == false`, and every consumer must run [`jwt_verify`] before
//!   trusting anything about a token.
//! - `alg: none`, missing `alg`, and empty-signature tokens are always
//!   rejected with a policy error naming RFC 8725 (JOSE Best Current
//!   Practices, section 2.1 "Perform Algorithm Verification").
//! - The JOSE header `alg` must exactly equal the caller-selected algorithm
//!   (algorithm-substitution hardening; case-sensitive per RFC 7515).
//! - MAC (HS*) comparisons are constant-time via `subtle`.
//! - HS* secrets that look like PEM armor are rejected (key-confusion
//!   hardening).
//! - Signature length is checked per algorithm before any verification work.
//!
//! Error semantics follow the rest of the crate ([`crate::ops::sign`]):
//! malformed tokens, keys, and parameters are typed [`PkiError`]s, while a
//! well-formed token whose signature or claims fail is a normal
//! [`JwtVerified`] result with `valid: false` and a `reason`.

use serde::{Deserialize, Serialize};

pub mod decode;
pub mod registry;
pub mod sign;
pub mod verify;

pub use decode::{jwt_decode, JwtDecoded};
pub use registry::register;
pub use sign::{jwt_sign, JwtSignParams};
pub use verify::{jwt_verify, jwt_verify_at, JwtVerifyParams, JwtVerified};

use crate::error::{PkiError, PkiResult};

/// Size bound for compact serializations (1 MiB). Hostile "tokens" larger
/// than this are rejected before any base64/JSON work so memory use stays
/// bounded; genuine JWTs are orders of magnitude smaller.
pub const MAX_TOKEN_BYTES: usize = 1024 * 1024;

/// JWS signature algorithms supported by the JWT module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JwtAlg {
    /// HMAC-SHA-256 (RFC 7518 section 3.2).
    #[serde(rename = "HS256")]
    Hs256,
    /// HMAC-SHA-384.
    #[serde(rename = "HS384")]
    Hs384,
    /// HMAC-SHA-512.
    #[serde(rename = "HS512")]
    Hs512,
    /// RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7518 section 3.3).
    #[serde(rename = "RS256")]
    Rs256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    #[serde(rename = "RS384")]
    Rs384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    #[serde(rename = "RS512")]
    Rs512,
    /// ECDSA P-256 with SHA-256, fixed-width r||s signature (RFC 7518
    /// section 3.4).
    #[serde(rename = "ES256")]
    Es256,
    /// ECDSA P-384 with SHA-384, fixed-width r||s signature.
    #[serde(rename = "ES384")]
    Es384,
    /// EdDSA / Ed25519 (RFC 7518 section 3.1, RFC 8032).
    #[serde(rename = "EdDSA")]
    EdDsa,
}

impl JwtAlg {
    /// Canonical (case-sensitive) JOSE `alg` header value.
    pub fn label(&self) -> &'static str {
        match self {
            JwtAlg::Hs256 => "HS256",
            JwtAlg::Hs384 => "HS384",
            JwtAlg::Hs512 => "HS512",
            JwtAlg::Rs256 => "RS256",
            JwtAlg::Rs384 => "RS384",
            JwtAlg::Rs512 => "RS512",
            JwtAlg::Es256 => "ES256",
            JwtAlg::Es384 => "ES384",
            JwtAlg::EdDsa => "EdDSA",
        }
    }

    /// Parse an algorithm label (case-insensitive); the registry/CLI accept
    /// user input this way. Unknown labels are typed errors.
    pub fn parse(label: &str) -> PkiResult<JwtAlg> {
        match label.trim().to_ascii_uppercase().as_str() {
            "HS256" => Ok(JwtAlg::Hs256),
            "HS384" => Ok(JwtAlg::Hs384),
            "HS512" => Ok(JwtAlg::Hs512),
            "RS256" => Ok(JwtAlg::Rs256),
            "RS384" => Ok(JwtAlg::Rs384),
            "RS512" => Ok(JwtAlg::Rs512),
            "ES256" => Ok(JwtAlg::Es256),
            "ES384" => Ok(JwtAlg::Es384),
            "EDDSA" => Ok(JwtAlg::EdDsa),
            "NONE" => Err(reject_none_alg("none")),
            other => Err(PkiError::invalid_param(
                "alg",
                format!("unknown JWS algorithm '{other}'"),
            )
            .with_expected("one of HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, EdDSA")
            .with_actual(label)),
        }
    }

    /// True for the HMAC family (shared-secret keys, constant-time compare).
    pub fn is_hmac(&self) -> bool {
        matches!(self, JwtAlg::Hs256 | JwtAlg::Hs384 | JwtAlg::Hs512)
    }

    /// HMAC digest output size in bytes (also the exact JWS signature size
    /// for the HS* family).
    pub fn mac_size(&self) -> usize {
        match self {
            JwtAlg::Hs256 => 32,
            JwtAlg::Hs384 => 48,
            JwtAlg::Hs512 => 64,
            _ => 0,
        }
    }

    /// ECDSA curve for the ES* family; `None` for every other algorithm.
    pub fn ecdsa_curve(&self) -> Option<crate::ecc::EccCurve> {
        match self {
            JwtAlg::Es256 => Some(crate::ecc::EccCurve::P256),
            JwtAlg::Es384 => Some(crate::ecc::EccCurve::P384),
            _ => None,
        }
    }

    /// Exact JWS signature size in bytes for the fixed-width families
    /// (ES*, EdDSA); `None` for families whose signature size depends on the
    /// key (RS*) or which are checked via the digest length (HS*).
    pub fn fixed_signature_size(&self) -> Option<usize> {
        match self {
            JwtAlg::Es256 => Some(64),
            JwtAlg::Es384 => Some(96),
            JwtAlg::EdDsa => Some(64),
            _ => None,
        }
    }
}

impl std::fmt::Display for JwtAlg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Canonical JOSE labels in registry/CLI order.
pub const JWT_ALG_LABELS: &[&str] = &[
    "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "EdDSA",
];

/// How the HS* shared-secret parameter is interpreted. HMAC secrets are raw
/// byte strings; PEM detection is a confusion-hardening check, not an
/// encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretEncoding {
    /// The secret text is its UTF-8 bytes (default).
    #[default]
    Utf8,
    /// The secret text is a (0x-optional) hex string.
    Hex,
}

impl SecretEncoding {
    /// Parse the parameter label (`"utf8"` / `"hex"`).
    pub fn parse(label: &str) -> PkiResult<SecretEncoding> {
        match label.trim().to_ascii_lowercase().as_str() {
            "utf8" | "utf-8" | "text" => Ok(SecretEncoding::Utf8),
            "hex" => Ok(SecretEncoding::Hex),
            other => Err(PkiError::invalid_param(
                "secret_encoding",
                format!("unknown secret encoding '{other}'"),
            )
            .with_expected("utf8 or hex")
            .with_actual(label)),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            SecretEncoding::Utf8 => "utf8",
            SecretEncoding::Hex => "hex",
        }
    }
}

/// How the ES*/EdDSA key parameter is interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyEncoding {
    /// PEM armor: SPKI `PUBLIC KEY` (verify) or PKCS#8 `PRIVATE KEY` (sign).
    #[default]
    Pem,
    /// Hex transport: SEC1 public key / fixed-width private scalar for ES*;
    /// raw 32-byte public key / seed for EdDSA.
    Hex,
}

impl KeyEncoding {
    /// Parse the parameter label (`"pem"` / `"hex"`).
    pub fn parse(label: &str) -> PkiResult<KeyEncoding> {
        match label.trim().to_ascii_lowercase().as_str() {
            "pem" => Ok(KeyEncoding::Pem),
            "hex" => Ok(KeyEncoding::Hex),
            other => Err(PkiError::invalid_param(
                "key_encoding",
                format!("unknown key encoding '{other}'"),
            )
            .with_expected("pem or hex")
            .with_actual(label)),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            KeyEncoding::Pem => "pem",
            KeyEncoding::Hex => "hex",
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers (pub(crate))
// ---------------------------------------------------------------------------

/// Strict base64url decode for JWS segments: no padding, standard URL-safe
/// alphabet, no non-canonical trailing bits tolerated by the codec. Every
/// failure is a typed `Decode` error naming the segment.
pub(crate) fn b64url_decode_strict(segment: &str, parameter: &str) -> PkiResult<Vec<u8>> {
    use base64ct::Encoding as _;
    if segment.contains('=') {
        return Err(PkiError::decode(format!(
            "JWS {parameter} segment contains base64 padding ('='), which compact JWS never uses"
        ))
        .with_parameter(parameter)
        .with_expected("unpadded base64url")
        .with_actual(crate::keys::preview(segment, 32)));
    }
    base64ct::Base64UrlUnpadded::decode_vec(segment).map_err(|e| {
        PkiError::decode(format!("JWS {parameter} segment is not valid unpadded base64url"))
            .with_parameter(parameter)
            .with_expected("base64url characters [A-Za-z0-9_-]")
            .with_details(e.to_string())
    })
}

/// Unpadded base64url encode (RFC 7515 section 2).
pub(crate) fn b64url_encode(bytes: &[u8]) -> String {
    use base64ct::Encoding as _;
    base64ct::Base64UrlUnpadded::encode_string(bytes)
}

/// Shared-secret material for the HS* family with confusion hardening: text
/// that looks like PEM armor is rejected instead of silently hashed.
pub(crate) fn hmac_secret_bytes(key: &str, encoding: SecretEncoding) -> PkiResult<Vec<u8>> {
    if key.contains("-----BEGIN") {
        return Err(PkiError::key(
            "HS* secret looks like PEM armor ('-----BEGIN'): refusing to treat a key file as an HMAC shared secret",
        )
        .with_parameter("key")
        .with_details(
            "key-confusion hardening: HMAC secrets and PEM keys are not interchangeable; \
             supply the raw shared secret (secret_encoding = utf8 or hex)",
        ));
    }
    if key.trim().is_empty() {
        return Err(PkiError::key("HS* secret is empty")
            .with_parameter("key")
            .with_expected("a non-empty shared secret"));
    }
    match encoding {
        SecretEncoding::Utf8 => Ok(key.as_bytes().to_vec()),
        SecretEncoding::Hex => crate::ecc::decode_hex("key", key),
    }
}

/// Policy error for the `alg: none` / unsigned-token family. Always an error,
/// never a `valid: false` result: unsigned JWTs are rejected before any
/// verification work (RFC 8725, BCP 201, section 2.1).
pub(crate) fn reject_none_alg(actual: &str) -> PkiError {
    PkiError::unsupported(format!(
        "unsigned JWT rejected: header 'alg' is '{actual}' and the none algorithm is never accepted"
    ))
    .with_parameter("alg")
    .with_expected("a signed JWS algorithm (HS256/384/512, RS256/384/512, ES256/384, EdDSA)")
    .with_actual(actual)
    .with_details(
        "unauthenticated JWTs are the classic JWT forgery vector; \
         RFC 8725 (JOSE Best Current Practices, section 2.1) requires algorithm verification",
    )
}

/// Policy error for empty-signature tokens (e.g. `...payload.`).
pub(crate) fn reject_unsigned_token() -> PkiError {
    PkiError::unsupported(
        "unsigned JWT rejected: the JWS signature segment is empty, so nothing is protected",
    )
    .with_parameter("signature")
    .with_expected("a non-empty base64url signature segment")
    .with_actual("empty")
    .with_details(
        "RFC 8725 (JOSE Best Current Practices, section 2.1): tokens without a \
         verifiable signature are never accepted",
    )
}

/// Typed mismatch error when the JOSE header `alg` differs from the
/// caller-selected algorithm.
pub(crate) fn alg_mismatch(expected: &JwtAlg, actual: &str) -> PkiError {
    PkiError::invalid_input(
        "JOSE header 'alg' does not match the requested verification algorithm",
    )
    .with_parameter("alg")
    .with_expected(expected.label())
    .with_actual(actual)
    .with_details(
        "RFC 8725 (JOSE Best Current Practices, section 2.1): verify that the \
         algorithm in the token is the algorithm you expect",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alg_labels_roundtrip_case_insensitive() {
        for label in JWT_ALG_LABELS {
            let alg = JwtAlg::parse(label).unwrap();
            assert_eq!(alg.label(), *label);
        }
        // Case-insensitive parse for user input...
        assert_eq!(JwtAlg::parse("hs256").unwrap(), JwtAlg::Hs256);
        assert_eq!(JwtAlg::parse(" eddsa ").unwrap(), JwtAlg::EdDsa);
        // ...while the canonical label is case-sensitive.
        assert!(matches!(JwtAlg::parse("eddsa"), Ok(JwtAlg::EdDsa)));
        assert!(JwtAlg::parse("PS256").is_err());
        assert!(JwtAlg::parse("bogus").is_err());
    }

    #[test]
    fn alg_parse_none_is_policy_error() {
        let err = JwtAlg::parse("none").unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Unsupported);
        assert!(err.details.as_deref().unwrap_or_default().contains("8725"));
    }

    #[test]
    fn alg_families() {
        assert!(JwtAlg::Hs256.is_hmac());
        assert_eq!(JwtAlg::Hs512.mac_size(), 64);
        assert_eq!(JwtAlg::Es256.fixed_signature_size(), Some(64));
        assert_eq!(JwtAlg::Es384.fixed_signature_size(), Some(96));
        assert_eq!(JwtAlg::EdDsa.fixed_signature_size(), Some(64));
        assert_eq!(JwtAlg::Rs256.fixed_signature_size(), None);
        assert_eq!(JwtAlg::Es384.ecdsa_curve(), Some(crate::ecc::EccCurve::P384));
        assert_eq!(JwtAlg::EdDsa.ecdsa_curve(), None);
    }

    #[test]
    fn b64url_roundtrip_and_strictness() {
        let bytes = b"\xff\xfe\x01";
        let encoded = b64url_encode(bytes);
        assert!(!encoded.contains('='));
        assert_eq!(b64url_decode_strict(&encoded, "sig").unwrap(), bytes);
        // Padding rejected explicitly.
        assert!(b64url_decode_strict("c3RyaW5n=", "sig").is_err());
        // Non-alphabet characters rejected.
        assert!(b64url_decode_strict("ab!c", "sig").is_err());
        assert!(b64url_decode_strict("ab+c", "sig").is_err());
    }

    #[test]
    fn hmac_secret_confusion_hardening() {
        let pem = "-----BEGIN PUBLIC KEY-----\nMFww\n-----END PUBLIC KEY-----";
        let err = hmac_secret_bytes(pem, SecretEncoding::Utf8).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::KeyError);
        assert!(hmac_secret_bytes("plain secret", SecretEncoding::Utf8).unwrap() == b"plain secret");
        assert_eq!(
            hmac_secret_bytes("4142", SecretEncoding::Hex).unwrap(),
            vec![0x41, 0x42]
        );
        assert!(hmac_secret_bytes("414", SecretEncoding::Hex).is_err());
        assert!(hmac_secret_bytes("  ", SecretEncoding::Utf8).is_err());
    }

    #[test]
    fn encoding_params_parse() {
        assert_eq!(SecretEncoding::parse("utf8").unwrap(), SecretEncoding::Utf8);
        assert_eq!(SecretEncoding::parse("HEX").unwrap(), SecretEncoding::Hex);
        assert!(SecretEncoding::parse("base64").is_err());
        assert_eq!(KeyEncoding::parse("pem").unwrap(), KeyEncoding::Pem);
        assert_eq!(KeyEncoding::parse("HEX").unwrap(), KeyEncoding::Hex);
        assert!(KeyEncoding::parse("der").is_err());
    }
}
