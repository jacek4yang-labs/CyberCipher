//! X.509 certificate, certification-request (CSR), and CRL inspection.
//!
//! The structural walk (version, serial, names, validity, SPKI) uses the
//! `x509-cert` crate — version-aligned with the `der` 0.7 / `spki` 0.7 stack
//! the rest of this crate uses. Extension *decoding* (SAN, key usage, EKU,
//! basic constraints, SKI/AKI) is delegated to `x509-parser`, which ships the
//! richer per-extension parsers; if that secondary parse fails, the extension
//! list (OID + criticality) from `x509-cert` is still reported and only the
//! decoded convenience fields stay empty.
//!
//! Inputs are either PEM armor (detected by the `-----BEGIN ` prefix) or raw
//! DER bytes. The PEM object type is identified generically first, so feeding
//! a CRL to [`inspect_certificate`] is a precise "wrong object type" error,
//! and encrypted PEMs are rejected with an explicit unsupported error.
//!
//! Everything is read-only and serde-serializable; no signature is trusted
//! and no validity check is performed beyond parsing. The CSR inspector
//! verifies the self-signature when the algorithm/key pair is one this crate
//! supports natively (RSA PKCS#1 v1.5, ECDSA P-256/P-384, Ed25519) and marks
//! the result "not verified" otherwise.

use base64ct::Encoding as _;
use der::Decode as _;
use der::Encode as _;
use num_bigint_dig::BigUint;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Digest as _;
use sha2::Sha256;
use spki::ObjectIdentifier;
use x509_cert::certificate::{Certificate, Version};
use x509_cert::request::CertReq;
use x509_cert::request::Version as ReqVersion;
use x509_cert::time::Time;

use crate::error::{invalid_der, PkiError, PkiResult};
use crate::keys::{bytes_bit_length, to_hex};

// ---------------------------------------------------------------------------
// Object identifiers used for key-type detection
// ---------------------------------------------------------------------------

/// rsaEncryption (PKCS#1): 1.2.840.113549.1.1.1
const RSA_ENCRYPTION_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// id-ecPublicKey (RFC 5480): 1.2.840.10045.2.1
const EC_PUBLIC_KEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// prime256v1 / secp256r1 (P-256): 1.2.840.10045.3.1.7
const P256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// secp384r1 (P-384): 1.3.132.0.34
const P384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
/// id-Ed25519 (RFC 8410): 1.3.101.112
const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
/// id-X25519 (RFC 8410): 1.3.101.110
const X25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

// ---------------------------------------------------------------------------
// Generic PEM object identification
// ---------------------------------------------------------------------------

/// The X.509-family object a PEM block claims to contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PemObjectType {
    /// `-----BEGIN CERTIFICATE-----` (X.509 certificate).
    Certificate,
    /// `-----BEGIN CERTIFICATE REQUEST-----` (PKCS#10 CSR).
    CertificateRequest,
    /// `-----BEGIN X509 CRL-----` (certificate revocation list).
    Crl,
    /// `-----BEGIN PUBLIC KEY-----` (SPKI).
    PublicKey,
    /// `-----BEGIN PRIVATE KEY-----` (PKCS#8).
    PrivateKey,
    /// `-----BEGIN RSA PRIVATE KEY-----` (PKCS#1).
    RsaPrivateKey,
    /// `-----BEGIN RSA PUBLIC KEY-----` (PKCS#1).
    RsaPublicKey,
    /// `-----BEGIN EC PRIVATE KEY-----` (SEC1, legacy).
    EcPrivateKey,
    /// `-----BEGIN ENCRYPTED PRIVATE KEY-----` or RFC 1421 encryption
    /// headers. Not supported — rejected with a typed error.
    EncryptedPrivateKey,
    /// Any other label.
    Other,
}

impl PemObjectType {
    /// Human label used in errors (`"certificate"`, `"X509 CRL"`, ...).
    pub fn label(&self) -> &'static str {
        match self {
            PemObjectType::Certificate => "certificate (CERTIFICATE)",
            PemObjectType::CertificateRequest => "CSR (CERTIFICATE REQUEST)",
            PemObjectType::Crl => "CRL (X509 CRL)",
            PemObjectType::PublicKey => "public key (PUBLIC KEY)",
            PemObjectType::PrivateKey => "private key (PRIVATE KEY)",
            PemObjectType::RsaPrivateKey => "RSA private key (RSA PRIVATE KEY)",
            PemObjectType::RsaPublicKey => "RSA public key (RSA PUBLIC KEY)",
            PemObjectType::EcPrivateKey => "EC private key (EC PRIVATE KEY)",
            PemObjectType::EncryptedPrivateKey => "encrypted private key (ENCRYPTED PRIVATE KEY)",
            PemObjectType::Other => "other",
        }
    }

    /// Map a PEM `-----BEGIN <label>-----` label to its object type.
    pub fn from_label(label: &str) -> Self {
        match label {
            "CERTIFICATE" => PemObjectType::Certificate,
            "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => PemObjectType::CertificateRequest,
            "X509 CRL" | "CRL" => PemObjectType::Crl,
            "PUBLIC KEY" => PemObjectType::PublicKey,
            "PRIVATE KEY" => PemObjectType::PrivateKey,
            "RSA PRIVATE KEY" => PemObjectType::RsaPrivateKey,
            "RSA PUBLIC KEY" => PemObjectType::RsaPublicKey,
            "EC PRIVATE KEY" => PemObjectType::EcPrivateKey,
            "ENCRYPTED PRIVATE KEY" => PemObjectType::EncryptedPrivateKey,
            _ => PemObjectType::Other,
        }
    }
}

/// Result of classifying a PEM block: the armor label, the object type it
/// denotes, and the size of the contained DER payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PemIdentification {
    /// The armor label exactly as written (`"CERTIFICATE REQUEST"`).
    pub label: String,
    /// The classified object type.
    pub object_type: PemObjectType,
    /// Size of the DER payload inside the armor.
    pub der_len: usize,
}

/// True when the input starts like PEM armor (only meaningful for text
/// inputs; raw DER never starts with `-----BEGIN `).
fn looks_like_pem(input: &[u8]) -> bool {
    core::str::from_utf8(input)
        .ok()
        .and_then(|text| text.trim_start().strip_prefix("-----BEGIN "))
        .is_some()
}

struct PemBlock {
    label: String,
    der: Vec<u8>,
}

/// Split PEM armor into label + DER, rejecting RFC 1421-style encrypted
/// bodies (Proc-Type / DEK-Info headers) the same way `keys::pem` does.
fn split_pem(input: &[u8]) -> PkiResult<PemBlock> {
    let text = core::str::from_utf8(input).map_err(|_| {
        PkiError::decode("PEM input is not valid text")
            .with_expected("ASCII PEM armor or raw DER bytes")
    })?;
    let trimmed = text.trim();
    let begin = trimmed.lines().next().unwrap_or_default().trim_start();
    let Some(rest) = begin.strip_prefix("-----BEGIN ") else {
        return Err(
            PkiError::decode("missing '-----BEGIN ...-----' armor header")
                .with_expected("PEM armor or raw DER bytes"),
        );
    };
    let Some(label) = rest.strip_suffix("-----") else {
        return Err(PkiError::decode(
            "BEGIN header is not terminated by '-----'",
        ));
    };
    if label.is_empty() {
        return Err(PkiError::decode("malformed PEM object label"));
    }

    let end_marker = format!("-----END {label}-----");
    let mut base64 = String::new();
    let mut headers: Vec<String> = Vec::new();
    let mut saw_end = false;
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
        return Err(PkiError::decode(format!(
            "missing '-----END {label}-----' terminator"
        )));
    }
    if headers
        .iter()
        .any(|h| h.starts_with("PROC-TYPE:") && h.contains("ENCRYPTED"))
        || headers.iter().any(|h| h.starts_with("DEK-INFO:"))
    {
        return Err(encrypted_pem_error(label));
    }

    let der = base64ct::Base64::decode_vec(&base64).map_err(|e| {
        PkiError::decode("invalid base64 payload in PEM body").with_details(e.to_string())
    })?;
    Ok(PemBlock {
        label: label.to_string(),
        der,
    })
}

fn encrypted_pem_error(label: &str) -> PkiError {
    PkiError::unsupported(format!(
        "encrypted PEM objects are not supported yet: '{label}' contains an encrypted object"
    ))
    .with_expected("an unencrypted PEM object")
    .with_details("decrypt the object with an external tool (e.g. `openssl pkey`) and retry")
}

/// Classify a PEM input. Non-PEM input is a typed decode error — use the
/// `inspect_*` functions directly for raw DER.
pub fn identify_pem(input: &[u8]) -> PkiResult<PemIdentification> {
    let block = split_pem(input)?;
    let object_type = PemObjectType::from_label(&block.label);
    Ok(PemIdentification {
        label: block.label,
        object_type,
        der_len: block.der.len(),
    })
}

/// Resolve the DER payload of a `pem_or_der` input, enforcing that a PEM
/// input carries the expected object type (and is not encrypted).
fn pem_or_der(input: &[u8], expected: PemObjectType, context: &str) -> PkiResult<Vec<u8>> {
    if !looks_like_pem(input) {
        return Ok(input.to_vec());
    }
    let block = split_pem(input)?;
    let object_type = PemObjectType::from_label(&block.label);
    if object_type == PemObjectType::EncryptedPrivateKey {
        return Err(encrypted_pem_error(&block.label));
    }
    if object_type != expected {
        return Err(PkiError::invalid_input(format!(
            "wrong PEM object type for the {context} inspector: expected {} but found {}",
            expected.label(),
            object_type.label()
        ))
        .with_expected(expected.label())
        .with_actual(block.label)
        .with_details(
            "use identify_pem to classify the object, or the matching inspect_* function",
        ));
    }
    Ok(block.der)
}

// ---------------------------------------------------------------------------
// Shared inspection shapes
// ---------------------------------------------------------------------------

/// One attribute of a distinguished name (flattened RDN list; multi-valued
/// RDNs appear as consecutive entries).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RdnEntry {
    /// Attribute OID, dotted.
    pub oid: String,
    /// Well-known attribute name when known (`"commonName"`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Attribute value rendered as text (hex with `0x` prefix when the
    /// value is not valid UTF-8).
    pub value: String,
}

/// SubjectPublicKeyInfo summary: algorithm identity, key family, and size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyInfoInspection {
    /// Algorithm name (`"rsaEncryption"`, `"ecPublicKey (prime256v1 (P-256))"`,
    /// `"Ed25519"`, ...). Unknown OIDs render as dotted numbers.
    pub algorithm: String,
    /// Algorithm OID, dotted.
    pub algorithm_oid: String,
    /// Key family: `"rsa"`, `"ec"`, `"ed25519"`, `"x25519"`, or `"unknown"`.
    pub key_type: String,
    /// Key size in bits (RSA modulus, EC field size, 256 for Ed25519/X25519);
    /// `None` when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bit_length: Option<usize>,
    /// Named curve for EC keys (`"prime256v1 (P-256)"`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
    /// Raw `subjectPublicKey` BIT STRING bytes as hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_hex: Option<String>,
}

/// Extension summary: identity and criticality only (decoded values live in
/// the dedicated fields of the surrounding inspection).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionSummary {
    /// Extension OID, dotted.
    pub oid: String,
    /// Well-known extension name when known (`"subjectAltName"`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether the extension is marked critical.
    pub critical: bool,
}

/// Decoded basicConstraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicConstraintsInspection {
    /// Whether the subject may act as a CA.
    pub ca: bool,
    /// Maximum number of intermediate CA certificates below this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_len: Option<u32>,
}

fn oid_label(oid: &str) -> String {
    crate::asn1::oid_name(oid)
        .map(str::to_string)
        .unwrap_or_else(|| oid.to_string())
}

/// Render an X.501 `Name` (RDN sequence) into a flattened entry list.
fn render_name(name: &x509_cert::name::Name) -> Vec<RdnEntry> {
    let mut entries = Vec::new();
    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            let oid = atv.oid.to_string();
            entries.push(RdnEntry {
                name: crate::asn1::oid_name(&oid).map(str::to_string),
                value: attribute_value_string(atv.value.value()),
                oid,
            });
        }
    }
    entries
}

/// First value with the given OID in an RDN list (used for summaries).
fn rdn_value_of<'a>(entries: &'a [RdnEntry], oid: &str) -> Option<&'a str> {
    entries
        .iter()
        .find(|entry| entry.oid == oid)
        .map(|entry| entry.value.as_str())
}

fn attribute_value_string(bytes: &[u8]) -> String {
    match core::str::from_utf8(bytes) {
        Ok(text) => text.to_string(),
        Err(_) => format!("0x{}", to_hex(bytes)),
    }
}

/// Summarize a SPKI structure: algorithm identity, key family, size.
fn inspect_spki(
    spki: &spki::SubjectPublicKeyInfo<der::asn1::Any, der::asn1::BitString>,
) -> PublicKeyInfoInspection {
    let oid = spki.algorithm.oid;
    let oid_dotted = oid.to_string();
    let raw = spki.subject_public_key.as_bytes();
    let mut info = PublicKeyInfoInspection {
        algorithm: oid_label(&oid_dotted),
        algorithm_oid: oid_dotted,
        key_type: "unknown".to_string(),
        bit_length: None,
        curve: None,
        public_key_hex: raw.map(to_hex),
    };
    match oid {
        RSA_ENCRYPTION_OID => {
            info.key_type = "rsa".to_string();
            // The BIT STRING carries a PKCS#1 RSAPublicKey; parse it for the
            // modulus bit length (failure keeps the inspection browsable).
            info.bit_length = raw
                .and_then(|bytes| pkcs1::RsaPublicKey::from_der(bytes).ok())
                .map(|key| bytes_bit_length(key.modulus.as_bytes()));
        }
        EC_PUBLIC_KEY_OID => {
            info.key_type = "ec".to_string();
            let curve_oid: Option<ObjectIdentifier> = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|params| params.clone().decode_as().ok());
            if let Some(curve_oid) = curve_oid {
                let dotted = curve_oid.to_string();
                info.curve = Some(oid_label(&dotted));
                info.bit_length = match curve_oid {
                    P256_OID => Some(256),
                    P384_OID => Some(384),
                    _ => None,
                };
                info.algorithm = format!("ecPublicKey ({})", info.curve.as_deref().unwrap_or("?"));
            }
        }
        ED25519_OID => {
            info.key_type = "ed25519".to_string();
            info.bit_length = Some(256);
        }
        X25519_OID => {
            info.key_type = "x25519".to_string();
            info.bit_length = Some(256);
        }
        _ => {}
    }
    info
}

/// RFC 3339 rendering of an X.501 `Time` (`2026-09-30T05:51:07Z`).
fn rfc3339(time: &Time) -> String {
    rfc3339_from_unix((*time).to_unix_duration().as_secs() as i64)
}

/// RFC 3339 from Unix seconds (UTC). Civil-date conversion is the classic
/// days-from-era algorithm (Howard Hinnant's `civil_from_days`), which keeps
/// this crate free of a calendar dependency.
fn rfc3339_from_unix(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn version_number(version: Version) -> u32 {
    match version {
        Version::V1 => 0,
        Version::V2 => 1,
        Version::V3 => 2,
    }
}

// ---------------------------------------------------------------------------
// Certificate inspection
// ---------------------------------------------------------------------------

/// Structured X.509 certificate inspection (serde-serializable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateInspection {
    /// Version field as encoded (0 = v1, 1 = v2, 2 = v3).
    pub version: u32,
    /// Version label (`"v1"` / `"v2"` / `"v3"`).
    pub version_label: String,
    /// Serial number, big-endian hex (no `0x` prefix, per the crate
    /// big-integer transport convention).
    pub serial_hex: String,
    /// Signature algorithm name (`"sha256WithRSAEncryption"`, ...).
    pub signature_algorithm: String,
    /// Signature algorithm OID, dotted.
    pub signature_algorithm_oid: String,
    pub issuer: Vec<RdnEntry>,
    pub subject: Vec<RdnEntry>,
    /// `notBefore` as an RFC 3339 UTC string.
    pub not_before: String,
    /// `notAfter` as an RFC 3339 UTC string.
    pub not_after: String,
    pub public_key: PublicKeyInfoInspection,
    /// SHA-256 fingerprint of the DER certificate (lowercase hex).
    pub fingerprint_sha256: String,
    /// SHA-1 fingerprint of the DER certificate (lowercase hex).
    pub fingerprint_sha1: String,
    /// All extensions, in order, with criticality.
    pub extensions: Vec<ExtensionSummary>,
    /// Decoded `subjectAltName` entries (`"DNS:example.com"`,
    /// `"IP:127.0.0.1"`, `"email:..."`, `"URI:..."`, ...).
    pub subject_alt_names: Vec<String>,
    /// Decoded `keyUsage` flag names (RFC 5280 spellings).
    pub key_usage: Vec<String>,
    /// Decoded `extKeyUsage` purposes (well-known names when known).
    pub extended_key_usage: Vec<String>,
    /// Decoded `basicConstraints`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basic_constraints: Option<BasicConstraintsInspection>,
    /// Decoded `subjectKeyIdentifier` (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_key_identifier: Option<String>,
    /// Decoded `authorityKeyIdentifier` keyIdentifier field (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_key_identifier: Option<String>,
    /// Human-readable one-line summary.
    pub summary: String,
}

/// Inspect an X.509 certificate given as PEM (`CERTIFICATE`) or raw DER.
pub fn inspect_certificate(input: &[u8]) -> PkiResult<CertificateInspection> {
    let der = pem_or_der(input, PemObjectType::Certificate, "certificate")?;
    let cert = Certificate::from_der(&der).map_err(|e| invalid_der("X.509 Certificate", e))?;
    let tbs = &cert.tbs_certificate;

    let version = version_number(tbs.version);
    let issuer = render_name(&tbs.issuer);
    let subject = render_name(&tbs.subject);
    let public_key = inspect_spki(&tbs.subject_public_key_info);

    let mut inspection = CertificateInspection {
        version,
        version_label: format!("v{}", version + 1),
        serial_hex: to_hex(tbs.serial_number.as_bytes()),
        signature_algorithm: oid_label(&cert.signature_algorithm.oid.to_string()),
        signature_algorithm_oid: cert.signature_algorithm.oid.to_string(),
        issuer,
        subject,
        not_before: rfc3339(&tbs.validity.not_before),
        not_after: rfc3339(&tbs.validity.not_after),
        public_key,
        fingerprint_sha256: to_hex(&Sha256::digest(&der)),
        fingerprint_sha1: to_hex(&Sha1::digest(&der)),
        extensions: Vec::new(),
        subject_alt_names: Vec::new(),
        key_usage: Vec::new(),
        extended_key_usage: Vec::new(),
        basic_constraints: None,
        subject_key_identifier: None,
        authority_key_identifier: None,
        summary: String::new(),
    };

    if let Some(exts) = &tbs.extensions {
        for ext in exts.iter() {
            let oid = ext.extn_id.to_string();
            inspection.extensions.push(ExtensionSummary {
                name: crate::asn1::oid_name(&oid).map(str::to_string),
                oid,
                critical: ext.critical,
            });
        }
    }

    // Richer decoding via x509-parser; on any parse hiccup the extension
    // list above still stands and only the decoded fields stay empty.
    if let Ok((_, parsed)) = x509_parser::parse_x509_certificate(&der) {
        for ext in parsed.extensions() {
            match ext.parsed_extension() {
                x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => {
                    for gn in &san.general_names {
                        inspection
                            .subject_alt_names
                            .push(general_name_to_string(gn));
                    }
                }
                x509_parser::extensions::ParsedExtension::KeyUsage(ku) => {
                    inspection.key_usage = key_usage_names(ku);
                }
                x509_parser::extensions::ParsedExtension::ExtendedKeyUsage(eku) => {
                    inspection.extended_key_usage = extended_key_usage_names(eku);
                }
                x509_parser::extensions::ParsedExtension::BasicConstraints(bc) => {
                    inspection.basic_constraints = Some(BasicConstraintsInspection {
                        ca: bc.ca,
                        path_len: bc.path_len_constraint,
                    });
                }
                x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(ski) => {
                    inspection.subject_key_identifier = Some(to_hex(ski.0));
                }
                x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    if let Some(kid) = &aki.key_identifier {
                        inspection.authority_key_identifier = Some(to_hex(kid.0));
                    }
                }
                _ => {}
            }
        }
    }

    let cn = rdn_value_of(&inspection.subject, "2.5.4.3").unwrap_or("(no CN)");
    let key_desc = match (
        inspection.public_key.key_type.as_str(),
        inspection.public_key.bit_length,
    ) {
        ("rsa", Some(bits)) => format!("RSA {bits}-bit"),
        (key_type, Some(bits)) => format!("{key_type} {bits}-bit"),
        (key_type, None) => key_type.to_string(),
    };
    inspection.summary = format!(
        "X.509 {} certificate, serial 0x{}, subject CN={cn}, {key_desc}, \
         signed with {}, valid {} .. {}",
        inspection.version_label,
        inspection.serial_hex,
        inspection.signature_algorithm,
        inspection.not_before,
        inspection.not_after,
    );
    Ok(inspection)
}

/// Render a `GeneralName` the way OpenSSL prints it (`DNS:...`, `IP:...`).
fn general_name_to_string(gn: &x509_parser::extensions::GeneralName<'_>) -> String {
    use x509_parser::extensions::GeneralName;
    match gn {
        GeneralName::OtherName(oid, data) => format!("otherName[{oid}]={}", to_hex(data)),
        GeneralName::RFC822Name(s) => format!("email:{s}"),
        GeneralName::DNSName(s) => format!("DNS:{s}"),
        GeneralName::X400Address(_) => "X400Address".to_string(),
        GeneralName::DirectoryName(name) => format!("dirName:{name}"),
        GeneralName::EDIPartyName(_) => "EDIPartyName".to_string(),
        GeneralName::URI(s) => format!("URI:{s}"),
        GeneralName::IPAddress(bytes) => format!("IP:{}", format_ip(bytes)),
        GeneralName::RegisteredID(oid) => format!("RID:{oid}"),
    }
}

fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join("."),
        16 => bytes
            .chunks(2)
            .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
            .collect::<Vec<_>>()
            .join(":"),
        _ => to_hex(bytes),
    }
}

/// RFC 5280 keyUsage flag names, in bit order.
fn key_usage_names(ku: &x509_parser::extensions::KeyUsage) -> Vec<String> {
    type KeyUsageFlag = (&'static str, fn(&x509_parser::extensions::KeyUsage) -> bool);
    const FLAGS: [KeyUsageFlag; 9] = [
        (
            "digitalSignature",
            x509_parser::extensions::KeyUsage::digital_signature,
        ),
        (
            "nonRepudiation",
            x509_parser::extensions::KeyUsage::non_repudiation,
        ),
        (
            "keyEncipherment",
            x509_parser::extensions::KeyUsage::key_encipherment,
        ),
        (
            "dataEncipherment",
            x509_parser::extensions::KeyUsage::data_encipherment,
        ),
        (
            "keyAgreement",
            x509_parser::extensions::KeyUsage::key_agreement,
        ),
        (
            "keyCertSign",
            x509_parser::extensions::KeyUsage::key_cert_sign,
        ),
        ("cRLSign", x509_parser::extensions::KeyUsage::crl_sign),
        (
            "encipherOnly",
            x509_parser::extensions::KeyUsage::encipher_only,
        ),
        (
            "decipherOnly",
            x509_parser::extensions::KeyUsage::decipher_only,
        ),
    ];
    FLAGS
        .iter()
        .filter(|(_, check)| check(ku))
        .map(|(name, _)| (*name).to_string())
        .collect()
}

fn extended_key_usage_names(eku: &x509_parser::extensions::ExtendedKeyUsage<'_>) -> Vec<String> {
    let mut names = Vec::new();
    if eku.any {
        names.push("anyExtendedKeyUsage".to_string());
    }
    if eku.server_auth {
        names.push("serverAuth".to_string());
    }
    if eku.client_auth {
        names.push("clientAuth".to_string());
    }
    if eku.code_signing {
        names.push("codeSigning".to_string());
    }
    if eku.email_protection {
        names.push("emailProtection".to_string());
    }
    if eku.time_stamping {
        names.push("timeStamping".to_string());
    }
    if eku.ocsp_signing {
        names.push("OCSPSigning".to_string());
    }
    for oid in &eku.other {
        names.push(oid_label(&oid.to_string()));
    }
    names
}

// ---------------------------------------------------------------------------
// CSR inspection
// ---------------------------------------------------------------------------

/// One PKCS#10 attribute (identity + how many values it carries).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributeSummary {
    /// Attribute OID, dotted (`1.2.840.113549.1.9.8` = extensionRequest).
    pub oid: String,
    /// Well-known attribute name when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Number of values in the attribute's SET.
    pub value_count: usize,
}

/// Structured PKCS#10 certification request inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CsrInspection {
    /// Version field as encoded (usually 0).
    pub version: u32,
    pub subject: Vec<RdnEntry>,
    pub public_key: PublicKeyInfoInspection,
    /// Signature algorithm name (`"sha256WithRSAEncryption"`, ...).
    pub signature_algorithm: String,
    /// Signature algorithm OID, dotted.
    pub signature_algorithm_oid: String,
    /// PKCS#10 attributes (extensionRequest and friends).
    pub attributes: Vec<AttributeSummary>,
    /// `Some(true/false)` when the self-signature was verified with the
    /// embedded public key; `None` when the algorithm/key combination is not
    /// verifiable here (see `verification_note`).
    pub signature_verified: Option<bool>,
    /// Human-readable note about the verification outcome.
    pub verification_note: String,
    /// Human-readable one-line summary.
    pub summary: String,
}

/// Inspect a PKCS#10 certification request given as PEM
/// (`CERTIFICATE REQUEST`) or raw DER. The self-signature is verified when
/// the algorithm/key pair is supported natively (RSA PKCS#1 v1.5 with
/// SHA-1/256/384/512, ECDSA P-256/P-384, Ed25519) and otherwise marked
/// "not verified".
pub fn inspect_csr(input: &[u8]) -> PkiResult<CsrInspection> {
    let der = pem_or_der(input, PemObjectType::CertificateRequest, "CSR")?;
    let req =
        CertReq::from_der(&der).map_err(|e| invalid_der("PKCS#10 CertificationRequest", e))?;
    let info = &req.info;

    let subject = render_name(&info.subject);
    let public_key = inspect_spki(&info.public_key);

    let mut attributes = Vec::new();
    for attr in info.attributes.iter() {
        let oid = attr.oid.to_string();
        attributes.push(AttributeSummary {
            name: crate::asn1::oid_name(&oid).map(str::to_string),
            value_count: attr.values.iter().count(),
            oid,
        });
    }

    let signature_bytes = req.signature.as_bytes().ok_or_else(|| {
        invalid_der(
            "PKCS#10 CertificationRequest",
            "signature BIT STRING has unused bits",
        )
    })?;
    let info_der = info.to_der().map_err(|e| {
        PkiError::internal("failed to re-encode certificationRequestInfo")
            .with_details(e.to_string())
    })?;
    let (signature_verified, verification_note) = verify_csr_signature(
        &info.public_key,
        &req.algorithm.oid.to_string(),
        &info_der,
        signature_bytes,
    );

    let cn = rdn_value_of(&subject, "2.5.4.3").unwrap_or("(no CN)");
    let key_desc = match (public_key.key_type.as_str(), public_key.bit_length) {
        ("rsa", Some(bits)) => format!("RSA {bits}-bit"),
        (key_type, Some(bits)) => format!("{key_type} {bits}-bit"),
        (key_type, None) => key_type.to_string(),
    };
    let summary = format!(
        "PKCS#10 CSR, subject CN={cn}, {key_desc}, signed with {} ({})",
        oid_label(&req.algorithm.oid.to_string()),
        match signature_verified {
            Some(true) => "self-signature verified",
            Some(false) => "self-signature INVALID",
            None => "self-signature not verified",
        },
    );

    Ok(CsrInspection {
        // PKCS#10 defines only v1 (encoded value 0).
        version: match info.version {
            ReqVersion::V1 => 0,
        },
        subject,
        public_key,
        signature_algorithm: oid_label(&req.algorithm.oid.to_string()),
        signature_algorithm_oid: req.algorithm.oid.to_string(),
        attributes,
        signature_verified,
        verification_note,
        summary,
    })
}

/// Best-effort CSR self-signature verification. Never fails: anything the
/// crate cannot verify becomes `(None, note)`.
fn verify_csr_signature(
    spki: &spki::SubjectPublicKeyInfo<der::asn1::Any, der::asn1::BitString>,
    algorithm_oid: &str,
    info_der: &[u8],
    signature: &[u8],
) -> (Option<bool>, String) {
    let Some(raw) = spki.subject_public_key.as_bytes() else {
        return (
            None,
            "subjectPublicKey BIT STRING has unused bits; signature not verified".to_string(),
        );
    };
    match algorithm_oid {
        "1.2.840.113549.1.1.5" => {
            verify_csr_rsa(raw, crate::ops::RsaDigest::Sha1, info_der, signature)
        }
        "1.2.840.113549.1.1.11" => {
            verify_csr_rsa(raw, crate::ops::RsaDigest::Sha256, info_der, signature)
        }
        "1.2.840.113549.1.1.12" => {
            verify_csr_rsa(raw, crate::ops::RsaDigest::Sha384, info_der, signature)
        }
        "1.2.840.113549.1.1.13" => {
            verify_csr_rsa(raw, crate::ops::RsaDigest::Sha512, info_der, signature)
        }
        "1.2.840.10045.4.3.2" => verify_csr_ecdsa(
            raw,
            crate::ecc::EccCurve::P256,
            crate::ecc::EcdsaDigest::Sha256,
            info_der,
            signature,
        ),
        "1.2.840.10045.4.3.3" => verify_csr_ecdsa(
            raw,
            crate::ecc::EccCurve::P384,
            crate::ecc::EcdsaDigest::Sha384,
            info_der,
            signature,
        ),
        "1.3.101.112" => verify_csr_ed25519(raw, info_der, signature),
        other => (
            None,
            format!("signature algorithm {other} is not verifiable here; marked as not verified"),
        ),
    }
}

fn verify_csr_rsa(
    spki_key: &[u8],
    digest: crate::ops::RsaDigest,
    info_der: &[u8],
    signature: &[u8],
) -> (Option<bool>, String) {
    let parsed = match pkcs1::RsaPublicKey::from_der(spki_key) {
        Ok(key) => key,
        Err(e) => {
            return (
                None,
                format!(
                    "could not parse the embedded RSA public key ({e}); signature not verified"
                ),
            )
        }
    };
    let n = BigUint::from_bytes_be(parsed.modulus.as_bytes());
    let e = BigUint::from_bytes_be(parsed.public_exponent.as_bytes());
    let key = match rsa::RsaPublicKey::new(n, e) {
        Ok(key) => key,
        Err(err) => {
            return (
                None,
                format!("embedded RSA public key is invalid ({err}); signature not verified"),
            )
        }
    };
    match crate::ops::sign::pkcs1v15_verify_with_key(&key, digest, info_der, signature) {
        Ok(result) => {
            let what = format!(
                "PKCS#1 v1.5 signature over certificationRequestInfo ({})",
                digest.label()
            );
            match result.valid {
                true => (Some(true), what),
                false => (Some(false), result.reason.unwrap_or(what)),
            }
        }
        Err(e) => (None, format!("signature verification could not run ({e})")),
    }
}

fn verify_csr_ecdsa(
    spki_key: &[u8],
    curve: crate::ecc::EccCurve,
    digest: crate::ecc::EcdsaDigest,
    info_der: &[u8],
    signature: &[u8],
) -> (Option<bool>, String) {
    match crate::ecc::ecdsa_verify(
        curve,
        &to_hex(spki_key),
        info_der,
        digest,
        crate::ecc::EcdsaSignatureFormat::Der,
        &to_hex(signature),
    ) {
        Ok(result) => {
            let what = format!("ECDSA signature over certificationRequestInfo ({curve})");
            match result.valid {
                true => (Some(true), what),
                false => (Some(false), result.reason.unwrap_or(what)),
            }
        }
        Err(e) => (None, format!("signature verification could not run ({e})")),
    }
}

fn verify_csr_ed25519(
    spki_key: &[u8],
    info_der: &[u8],
    signature: &[u8],
) -> (Option<bool>, String) {
    match crate::ecc::ed25519_verify(&to_hex(spki_key), info_der, &to_hex(signature)) {
        Ok(result) => {
            let what = "Ed25519 signature over certificationRequestInfo".to_string();
            match result.valid {
                true => (Some(true), what),
                false => (Some(false), result.reason.unwrap_or(what)),
            }
        }
        Err(e) => (None, format!("signature verification could not run ({e})")),
    }
}

// ---------------------------------------------------------------------------
// CRL inspection
// ---------------------------------------------------------------------------

/// One revoked certificate: serial and revocation date.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedEntry {
    /// Serial number, big-endian hex.
    pub serial_hex: String,
    /// Revocation date as an RFC 3339 UTC string.
    pub revocation_date: String,
}

/// Structured X.509 CRL inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrlInspection {
    pub issuer: Vec<RdnEntry>,
    /// `thisUpdate` as an RFC 3339 UTC string.
    pub this_update: String,
    /// `nextUpdate` as an RFC 3339 UTC string, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_update: Option<String>,
    /// Signature algorithm name (`"sha256WithRSAEncryption"`, ...).
    pub signature_algorithm: String,
    /// Signature algorithm OID, dotted.
    pub signature_algorithm_oid: String,
    /// Revoked serials with their revocation dates, in CRL order.
    pub revoked: Vec<RevokedEntry>,
    /// Convenience count of `revoked`.
    pub revoked_count: usize,
    /// cRLNumber extension value (big-endian hex) when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crl_number_hex: Option<String>,
    /// Human-readable one-line summary.
    pub summary: String,
}

/// Inspect an X.509 CRL given as PEM (`X509 CRL`) or raw DER.
///
/// This is decoded with `x509-parser` rather than `x509-cert`: the latter
/// (0.2.5) requires the OPTIONAL `version` field to be present, so CRLs
/// encoded with the default v1 — the common case — would fail to parse.
pub fn inspect_crl(input: &[u8]) -> PkiResult<CrlInspection> {
    let der = pem_or_der(input, PemObjectType::Crl, "CRL")?;
    let (_, crl) =
        x509_parser::parse_x509_crl(&der).map_err(|e| invalid_der("X.509 CertificateList", e))?;

    let mut issuer = Vec::new();
    for atv in crl.issuer().iter_attributes() {
        let oid = atv.attr_type().to_string();
        issuer.push(RdnEntry {
            name: crate::asn1::oid_name(&oid).map(str::to_string),
            value: attribute_value_string(atv.attr_value().as_bytes()),
            oid,
        });
    }

    let mut revoked = Vec::new();
    for entry in crl.iter_revoked_certificates() {
        revoked.push(RevokedEntry {
            serial_hex: entry.serial().to_str_radix(16),
            revocation_date: rfc3339_from_unix(entry.revocation_date.timestamp()),
        });
    }

    let mut crl_number_hex = None;
    for ext in crl.tbs_cert_list.extensions() {
        if let x509_parser::extensions::ParsedExtension::CRLNumber(number) = ext.parsed_extension()
        {
            crl_number_hex = Some(number.to_str_radix(16));
        }
    }

    let signature_algorithm_oid = crl.signature_algorithm.algorithm.to_string();
    let cn = rdn_value_of(&issuer, "2.5.4.3").unwrap_or("(no CN)");
    let summary = format!(
        "X.509 CRL issued by CN={cn}, {} revoked serial(s), valid {} .. {}",
        revoked.len(),
        rfc3339_from_unix(crl.last_update().timestamp()),
        crl.next_update()
            .map(|t| rfc3339_from_unix(t.timestamp()))
            .unwrap_or_else(|| "(none)".to_string()),
    );

    Ok(CrlInspection {
        issuer,
        this_update: rfc3339_from_unix(crl.last_update().timestamp()),
        next_update: crl.next_update().map(|t| rfc3339_from_unix(t.timestamp())),
        signature_algorithm: oid_label(&signature_algorithm_oid.clone()),
        signature_algorithm_oid,
        revoked_count: revoked.len(),
        revoked,
        crl_number_hex,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_rendering() {
        assert_eq!(rfc3339_from_unix(0), "1970-01-01T00:00:00Z");
        // 2026-09-30 05:51:07 UTC
        assert_eq!(rfc3339_from_unix(1_790_747_467), "2026-09-30T05:51:07Z");
        // Leap-year day: 2024-02-29 12:00:00 UTC
        assert_eq!(rfc3339_from_unix(1_709_208_000), "2024-02-29T12:00:00Z");
        // Epoch-minus-one stays representable.
        assert_eq!(rfc3339_from_unix(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn pem_object_type_labels() {
        assert_eq!(
            PemObjectType::from_label("CERTIFICATE REQUEST"),
            PemObjectType::CertificateRequest
        );
        assert_eq!(
            PemObjectType::from_label("NEW CERTIFICATE REQUEST"),
            PemObjectType::CertificateRequest
        );
        assert_eq!(PemObjectType::from_label("X509 CRL"), PemObjectType::Crl);
        assert_eq!(
            PemObjectType::from_label("WEIRD THING"),
            PemObjectType::Other
        );
    }
}
