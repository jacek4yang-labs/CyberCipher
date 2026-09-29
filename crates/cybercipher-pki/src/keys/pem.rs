//! PEM armor handling and DER parse/serialize for RSA key objects.
//!
//! Recognized PEM labels:
//! - `PUBLIC KEY`      — SPKI `SubjectPublicKeyInfo` (RFC 5280)
//! - `PRIVATE KEY`     — PKCS#8 `PrivateKeyInfo` (RFC 5958)
//! - `RSA PRIVATE KEY` — PKCS#1 `RSAPrivateKey` (RFC 8017)
//! - `RSA PUBLIC KEY`  — PKCS#1 `RSAPublicKey` (RFC 8017)
//!
//! `ENCRYPTED PRIVATE KEY` and RFC 1421-style `Proc-Type: 4,ENCRYPTED`
//! headers are detected and rejected with an explicit
//! "encrypted keys are not supported yet" error. Every malformed input is a
//! typed error — no panics.

use base64ct::Encoding as _;
use der::Decode as _;
use num_bigint_dig::BigUint;

use crate::error::{invalid_armor, invalid_der, unsupported_key_type, wrong_object_type, PkiError, PkiResult};
use crate::keys::{
    biguint_from_hex, to_hex, InspectKey, KeyFormat, KeyInspection, RsaKeypair,
    RsaPublicKeyMaterial,
};

/// rsaEncryption (PKCS#1) algorithm OID: 1.2.840.113549.1.1.1
const RSA_ENCRYPTION_OID: spki::ObjectIdentifier =
    spki::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// A parsed key: private (full CRT set) or public (n, e), together with the
/// container format it was parsed from.
#[derive(Debug, Clone)]
pub enum ParsedKey {
    Private {
        keypair: RsaKeypair,
        format: KeyFormat,
    },
    Public {
        material: RsaPublicKeyMaterial,
        format: KeyFormat,
    },
}

impl ParsedKey {
    /// Inspect whichever key variant this is (format preserved).
    pub fn inspect(&self) -> PkiResult<KeyInspection> {
        let (mut inspection, format) = match self {
            ParsedKey::Private { keypair, format } => (keypair.inspect()?, *format),
            ParsedKey::Public { material, format } => (material.inspect()?, *format),
        };
        inspection.format = format;
        Ok(inspection)
    }
}

// ---------------------------------------------------------------------------
// PEM armor
// ---------------------------------------------------------------------------

struct PemBlock {
    label: String,
    der: Vec<u8>,
}

/// Split PEM armor, detect encryption headers, and base64-decode the payload.
fn split_armor(input: &str) -> PkiResult<PemBlock> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(invalid_armor("empty PEM input").with_expected("PEM with BEGIN/END armor lines"));
    }
    let mut lines = trimmed.lines();
    let begin = lines.next().unwrap_or_default();
    let rest = begin.trim_start().strip_prefix("-----BEGIN ").ok_or_else(|| {
        invalid_armor("missing '-----BEGIN ...-----' armor header")
            .with_actual(crate::keys::preview(begin, 48))
    })?;
    let Some(label) = rest.strip_suffix("-----") else {
        return Err(invalid_armor("BEGIN header is not terminated by '-----'")
            .with_actual(crate::keys::preview(begin, 48)));
    };
    if label.is_empty()
        || !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b' ' || b == b'-')
    {
        return Err(invalid_armor("malformed PEM object label").with_actual(crate::keys::preview(label, 48)));
    }

    let end_marker = format!("-----END {label}-----");
    let mut base64 = String::new();
    let mut headers: Vec<String> = Vec::new();
    let mut saw_end = false;
    for line in lines {
        let line = line.trim();
        if line == end_marker {
            saw_end = true;
            break;
        }
        if line.contains(':') {
            // RFC 7468 header lines (e.g. Proc-Type / DEK-Info).
            headers.push(line.to_ascii_uppercase());
            continue;
        }
        base64.push_str(line);
    }
    if !saw_end {
        return Err(invalid_armor(format!("missing '-----END {label}-----' terminator")));
    }

    // RFC 1421-style encrypted PEM (legacy "RSA PRIVATE KEY" + Proc-Type).
    if headers
        .iter()
        .any(|h| h.starts_with("PROC-TYPE:") && h.contains("ENCRYPTED"))
        || headers.iter().any(|h| h.starts_with("DEK-INFO:"))
    {
        return Err(encrypted_pem_error(label));
    }

    let der = base64ct::Base64::decode_vec(&base64)
        .map_err(|e| invalid_armor("invalid base64 payload in PEM body").with_details(e.to_string()))?;
    Ok(PemBlock {
        label: label.to_string(),
        der,
    })
}

fn encrypted_pem_error(label: &str) -> PkiError {
    PkiError::unsupported(format!(
        "encrypted keys are not supported yet: '{label}' PEM contains an encrypted key"
    ))
    .with_expected("an unencrypted key PEM")
    .with_details("decrypt the key with an external tool (e.g. `openssl pkey`) and retry")
}

/// Parse a PEM string into an RSA key. Recognizes the four standard key
/// labels, rejects certificates/CSRs with a "wrong object type" error, and
/// rejects encrypted keys with a clear not-supported-yet error.
pub fn parse_pem(pem: &str) -> PkiResult<ParsedKey> {
    parse_pem_tagged(pem).map(|(key, _)| key)
}

fn parse_pem_tagged(pem: &str) -> PkiResult<(ParsedKey, KeyFormat)> {
    let block = split_armor(pem)?;
    match block.label.as_str() {
        "ENCRYPTED PRIVATE KEY" => Err(encrypted_pem_error(&block.label)),
        "PUBLIC KEY" => parse_spki_public_der(&block.der)
            .map(|m| (ParsedKey::Public { material: m, format: KeyFormat::Spki }, KeyFormat::Spki)),
        "PRIVATE KEY" => parse_pkcs8_private_der(&block.der)
            .map(|k| (ParsedKey::Private { keypair: k, format: KeyFormat::Pkcs8 }, KeyFormat::Pkcs8)),
        "RSA PRIVATE KEY" => parse_pkcs1_private_der(&block.der)
            .map(|k| (ParsedKey::Private { keypair: k, format: KeyFormat::Pkcs1 }, KeyFormat::Pkcs1)),
        "RSA PUBLIC KEY" => parse_pkcs1_public_der(&block.der)
            .map(|m| (ParsedKey::Public { material: m, format: KeyFormat::Pkcs1 }, KeyFormat::Pkcs1)),
        "CERTIFICATE" | "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" | "X509 CRL"
        | "ATTRIBUTE CERTIFICATE" => Err(wrong_object_type(&block.label)),
        other => Err(PkiError::unsupported(format!(
            "unsupported PEM object type: '{other}'"
        ))
        .with_expected("PUBLIC KEY, PRIVATE KEY, RSA PUBLIC KEY, or RSA PRIVATE KEY")
        .with_actual(other)),
    }
}

/// Parse + inspect in one step. `format` reflects the PEM container type.
pub fn inspect_pem(pem: &str) -> PkiResult<KeyInspection> {
    let (key, _) = parse_pem_tagged(pem)?;
    key.inspect()
}

// ---------------------------------------------------------------------------
// DER decode (raw objects)
// ---------------------------------------------------------------------------

/// Decode a raw PKCS#1 `RSAPrivateKey` DER blob.
pub fn parse_pkcs1_private_der(der: &[u8]) -> PkiResult<RsaKeypair> {
    let parsed =
        pkcs1::RsaPrivateKey::from_der(der).map_err(|e| invalid_der("PKCS#1 RSAPrivateKey", e))?;
    if parsed.version() != pkcs1::Version::TwoPrime {
        return Err(PkiError::unsupported(
            "multi-prime RSA private keys (version 1) are not supported yet",
        )
        .with_expected("two-prime RSA private key (version 0)")
        .with_actual("multi-prime key"));
    }
    let n = BigUint::from_bytes_be(parsed.modulus.as_bytes());
    let e = BigUint::from_bytes_be(parsed.public_exponent.as_bytes());
    let d = BigUint::from_bytes_be(parsed.private_exponent.as_bytes());
    let p = BigUint::from_bytes_be(parsed.prime1.as_bytes());
    let q = BigUint::from_bytes_be(parsed.prime2.as_bytes());
    RsaKeypair::from_biguints(n, e, d, p, q)
}

/// Decode a raw PKCS#8 `PrivateKeyInfo` DER blob. Only `rsaEncryption`
/// (1.2.840.113549.1.1.1) is accepted; other algorithms produce a typed
/// "unsupported key type" error.
pub fn parse_pkcs8_private_der(der: &[u8]) -> PkiResult<RsaKeypair> {
    let pki =
        pkcs8::PrivateKeyInfo::from_der(der).map_err(|e| invalid_der("PKCS#8 PrivateKeyInfo", e))?;
    if pki.algorithm.oid != RSA_ENCRYPTION_OID {
        return Err(unsupported_key_type(
            "PKCS#8 private key is not rsaEncryption",
            &pki.algorithm.oid.to_string(),
        ));
    }
    // The PKCS#8 private_key OCTET STRING carries the PKCS#1 RSAPrivateKey.
    parse_pkcs1_private_der(pki.private_key)
}

/// Decode a raw PKCS#1 `RSAPublicKey` DER blob.
pub fn parse_pkcs1_public_der(der: &[u8]) -> PkiResult<RsaPublicKeyMaterial> {
    let parsed =
        pkcs1::RsaPublicKey::from_der(der).map_err(|e| invalid_der("PKCS#1 RSAPublicKey", e))?;
    let n = BigUint::from_bytes_be(parsed.modulus.as_bytes());
    let e = BigUint::from_bytes_be(parsed.public_exponent.as_bytes());
    public_material_from_parts(n, e)
}

/// Decode a raw SPKI `SubjectPublicKeyInfo` DER blob (RSA only).
pub fn parse_spki_public_der(der: &[u8]) -> PkiResult<RsaPublicKeyMaterial> {
    let spki = spki::SubjectPublicKeyInfoRef::from_der(der)
        .map_err(|e| invalid_der("SPKI SubjectPublicKeyInfo", e))?;
    if spki.algorithm.oid != RSA_ENCRYPTION_OID {
        return Err(unsupported_key_type(
            "SPKI public key is not rsaEncryption",
            &spki.algorithm.oid.to_string(),
        ));
    }
    let key_der = spki.subject_public_key.as_bytes().ok_or_else(|| {
        invalid_der(
            "SPKI SubjectPublicKeyInfo",
            "subjectPublicKey BIT STRING has unused bits",
        )
    })?;
    parse_pkcs1_public_der(key_der)
}

/// Validate (n, e) via the `rsa` crate and produce public material.
pub(crate) fn public_material_from_parts(
    n: BigUint,
    e: BigUint,
) -> PkiResult<RsaPublicKeyMaterial> {
    rsa::RsaPublicKey::new(n.clone(), e.clone()).map_err(|err| {
        crate::error::inconsistent_key("invalid RSA public key")
            .with_parameter("n")
            .with_details(err.to_string())
    })?;
    Ok(RsaPublicKeyMaterial {
        n: to_hex(&n.to_bytes_be()),
        e: to_hex(&e.to_bytes_be()),
    })
}

// ---------------------------------------------------------------------------
// Public-key serialization from material
// ---------------------------------------------------------------------------

impl RsaPublicKeyMaterial {
    /// Modulus bit length (computed from the hex string).
    pub fn bits(&self) -> usize {
        crate::keys::hex_bit_length(&self.n)
    }

    /// Build a validated `rsa` crate public key.
    pub fn to_rsa_public_key(&self) -> PkiResult<rsa::RsaPublicKey> {
        let n = biguint_from_hex(&self.n).map_err(|e| e.with_parameter("n"))?;
        let e = biguint_from_hex(&self.e).map_err(|e| e.with_parameter("e"))?;
        rsa::RsaPublicKey::new(n, e).map_err(|err| {
            crate::error::inconsistent_key("invalid RSA public key").with_details(err.to_string())
        })
    }

    /// RSAPublicKey DER (PKCS#1).
    pub fn to_pkcs1_der(&self) -> PkiResult<Vec<u8>> {
        use rsa::pkcs1::EncodeRsaPublicKey;
        self.to_rsa_public_key()?
            .to_pkcs1_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|e| {
                PkiError::internal("PKCS#1 RSAPublicKey DER encoding failed").with_details(e.to_string())
            })
    }

    /// SubjectPublicKeyInfo DER (SPKI).
    pub fn to_spki_der(&self) -> PkiResult<Vec<u8>> {
        use rsa::pkcs8::EncodePublicKey;
        self.to_rsa_public_key()?
            .to_public_key_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|e| PkiError::internal("SPKI DER encoding failed").with_details(e.to_string()))
    }

    /// `-----BEGIN RSA PUBLIC KEY-----` PEM (PKCS#1).
    pub fn to_pkcs1_pem(&self) -> PkiResult<String> {
        use rsa::pkcs1::EncodeRsaPublicKey;
        self.to_rsa_public_key()?
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .map(|s| s.to_string())
            .map_err(|e| {
                PkiError::internal("PKCS#1 RSAPublicKey PEM encoding failed").with_details(e.to_string())
            })
    }

    /// `-----BEGIN PUBLIC KEY-----` PEM (SPKI).
    pub fn to_spki_pem(&self) -> PkiResult<String> {
        use rsa::pkcs8::EncodePublicKey;
        self.to_rsa_public_key()?
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map(|s| s.to_string())
            .map_err(|e| PkiError::internal("SPKI PEM encoding failed").with_details(e.to_string()))
    }
}

/// Inspect a raw DER blob by trying the four standard RSA structures
/// (PKCS#8 private, PKCS#1 private, SPKI public, PKCS#1 public).
pub fn inspect_der(der: &[u8]) -> PkiResult<KeyInspection> {
    if let Ok(k) = parse_pkcs8_private_der(der) {
        let mut insp = k.inspect()?;
        insp.format = KeyFormat::Pkcs8;
        return Ok(insp);
    }
    if let Ok(k) = parse_pkcs1_private_der(der) {
        let mut insp = k.inspect()?;
        insp.format = KeyFormat::Pkcs1;
        return Ok(insp);
    }
    if let Ok(m) = parse_spki_public_der(der) {
        let mut insp = m.inspect()?;
        insp.format = KeyFormat::Spki;
        return Ok(insp);
    }
    if let Ok(m) = parse_pkcs1_public_der(der) {
        let mut insp = m.inspect()?;
        insp.format = KeyFormat::Pkcs1;
        return Ok(insp);
    }
    Err(invalid_der(
        "key DER",
        "not a recognizable RSA private or public key structure",
    ))
}
