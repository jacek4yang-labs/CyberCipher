//! Digest and salt-length choices shared by the RSA encryption and signature
//! operations. These are the serde-serializable enums the CLI/GUI send across
//! the IPC boundary; string parsing (`RsaDigest::parse`) is where unknown
//! digest names become typed errors.

use serde::{Deserialize, Serialize};

use crate::error::{PkiError, PkiResult};
use crate::keys::preview;

/// Hash/digest choice for RSA operations (RFC 8017). SHA-1 is kept for
/// interoperability with legacy systems and is labeled as legacy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RsaDigest {
    /// SHA-1 (legacy). Accepted for compatibility; prefer SHA-256+.
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl RsaDigest {
    /// Canonical lowercase label (`"sha256"`), used in results and errors.
    pub fn label(&self) -> &'static str {
        match self {
            RsaDigest::Sha1 => "sha1",
            RsaDigest::Sha256 => "sha256",
            RsaDigest::Sha384 => "sha384",
            RsaDigest::Sha512 => "sha512",
        }
    }

    /// Digest output length in bytes.
    pub fn output_len(&self) -> usize {
        match self {
            RsaDigest::Sha1 => 20,
            RsaDigest::Sha256 => 32,
            RsaDigest::Sha384 => 48,
            RsaDigest::Sha512 => 64,
        }
    }

    /// Parse a digest name (case-insensitive). Accepted spellings:
    /// `sha1` / `sha-1` / `sha_1` / `legacy`; `sha256` / `sha-256` /
    /// `sha_256`; likewise for 384 and 512. Anything else is a typed
    /// `unsupported` error with the accepted choices in `expected`.
    pub fn parse(label: &str) -> PkiResult<Self> {
        let normalized: String = label
            .trim()
            .to_ascii_lowercase()
            .replace(['-', '_', ' '], "");
        match normalized.as_str() {
            "sha1" | "legacy" => Ok(RsaDigest::Sha1),
            "sha256" => Ok(RsaDigest::Sha256),
            "sha384" => Ok(RsaDigest::Sha384),
            "sha512" => Ok(RsaDigest::Sha512),
            other => Err(
                PkiError::unsupported(format!("unsupported digest '{other}'"))
                    .with_expected("sha1 (legacy), sha256, sha384, or sha512")
                    .with_actual(preview(label.trim(), 32)),
            ),
        }
    }
}

/// PSS salt length (RFC 8017 section 9.1.1, `sLen`). The classic choice is
/// `Digest` (salt as long as the hash output); `Zero` produces a deterministic
/// salt-less signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode", content = "bytes")]
pub enum PssSaltLength {
    /// Salt length equals the digest output length (the default in most tooling).
    Digest,
    /// Empty salt (deterministic signatures).
    Zero,
    /// An explicit salt length in bytes.
    Fixed(usize),
}

impl PssSaltLength {
    /// Human-readable label for results and errors.
    pub fn label(&self) -> String {
        match self {
            PssSaltLength::Digest => "digest-length".to_string(),
            PssSaltLength::Zero => "0".to_string(),
            PssSaltLength::Fixed(n) => n.to_string(),
        }
    }

    /// Resolve to a concrete byte length for the given digest.
    pub fn resolve(&self, digest: RsaDigest) -> usize {
        match self {
            PssSaltLength::Digest => digest.output_len(),
            PssSaltLength::Zero => 0,
            PssSaltLength::Fixed(n) => *n,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_common_spellings() {
        assert!(matches!(RsaDigest::parse("sha256"), Ok(RsaDigest::Sha256)));
        assert!(matches!(RsaDigest::parse("SHA-256"), Ok(RsaDigest::Sha256)));
        assert!(matches!(
            RsaDigest::parse(" sha_512 "),
            Ok(RsaDigest::Sha512)
        ));
        assert!(matches!(RsaDigest::parse("legacy"), Ok(RsaDigest::Sha1)));
        assert!(matches!(RsaDigest::parse("SHA1"), Ok(RsaDigest::Sha1)));
    }

    #[test]
    fn parse_rejects_unknown_with_typed_error() {
        let err = RsaDigest::parse("md5").unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Unsupported);
        assert!(err.expected.as_deref().unwrap().contains("sha512"));
        assert_eq!(err.actual.as_deref(), Some("md5"));
    }

    #[test]
    fn salt_length_resolution() {
        assert_eq!(PssSaltLength::Digest.resolve(RsaDigest::Sha256), 32);
        assert_eq!(PssSaltLength::Zero.resolve(RsaDigest::Sha512), 0);
        assert_eq!(PssSaltLength::Fixed(7).resolve(RsaDigest::Sha1), 7);
    }
}
