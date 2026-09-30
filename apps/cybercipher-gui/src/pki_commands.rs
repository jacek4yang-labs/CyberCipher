//! Tauri IPC commands for the PKI Lab page (`PkiLabPage.tsx`).
//!
//! The command layer is a thin adapter over `cybercipher-pki`: all real work
//! happens in the engine so the same API can back the CLI and MCP later.
//! Errors cross the IPC boundary as the engine's full structured
//! `OperationError` (kind, message, parameter, expected, actual, details) so
//! the frontend can render the typed diagnostics verbatim.
//!
//! Every command runs its engine call on the blocking thread pool
//! (`tauri::async_runtime::spawn_blocking`) so long operations (RSA-4096
//! keygen) never freeze the UI.
//!
//! Input size is bounded here at [`MAX_TEXT_INPUT`] (the ASN.1 engine's own
//! cap); the engine re-checks and applies its own finer bounds (DER depth,
//! hex lengths, plaintext-size rules) with typed errors.

use cybercipher_codec::decode_input;
use cybercipher_core::OperationError;
use cybercipher_pki as pki;
use serde::{Deserialize, Serialize};

/// Upper bound for any text input crossing the PKI IPC boundary. Matches the
/// ASN.1 engine's own input cap, so a rejected input would fail there anyway.
const MAX_TEXT_INPUT: usize = pki::asn1::MAX_INPUT_SIZE;

// ---------------------------------------------------------------------------
// Error + byte transport
// ---------------------------------------------------------------------------

/// Structured error crossing the IPC boundary. Mirrors the engine's
/// `OperationError` field-for-field (kind as the snake_case label) so the
/// frontend can render kind/parameter/expected/actual/details directly.
#[derive(Debug, Serialize)]
pub struct PkiCmdError {
    pub kind: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl From<OperationError> for PkiCmdError {
    fn from(e: OperationError) -> Self {
        PkiCmdError {
            kind: serde_json::to_value(e.kind)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "internal".to_string()),
            message: e.message,
            parameter: e.parameter,
            expected: e.expected,
            actual: e.actual,
            details: e.details,
        }
    }
}

impl PkiCmdError {
    /// Attach the accepted-choices hint to a parameter error.
    fn and_expected(mut self, expected: impl Into<String>) -> Self {
        self.expected = Some(expected.into());
        self
    }

    /// Attach the offending value to an input error.
    fn and_actual(mut self, actual: impl Into<String>) -> Self {
        self.actual = Some(actual.into());
        self
    }
}

fn invalid_param(parameter: &str, message: impl Into<String>) -> PkiCmdError {
    OperationError::invalid_param(parameter, message).into()
}

fn invalid_input(message: impl Into<String>) -> PkiCmdError {
    OperationError::invalid_input(message).into()
}

fn check_text_size(name: &str, text: &str) -> Result<(), PkiCmdError> {
    if text.len() > MAX_TEXT_INPUT {
        Err(invalid_param(
            name,
            format!(
                "input is too large: {} bytes (max {MAX_TEXT_INPUT})",
                text.len()
            ),
        ))
    } else {
        Ok(())
    }
}

/// Decode a data input with the Workbench's encoding vocabulary
/// (`utf8` | `hex` | `base64` | `decimal`).
fn decode_data(param: &str, encoding: &str, text: &str) -> Result<Vec<u8>, PkiCmdError> {
    check_text_size(param, text)?;
    decode_input(encoding, text).map_err(PkiCmdError::from)
}

/// Binary result crossing the IPC boundary: lowercase hex is the canonical
/// transport, with a UTF-8 rendering when the bytes are valid text.
#[derive(Debug, Clone, Serialize)]
pub struct PkiBytes {
    pub hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utf8: Option<String>,
    pub size: usize,
}

impl PkiBytes {
    fn new(bytes: &[u8]) -> Self {
        PkiBytes {
            hex: to_hex(bytes),
            utf8: std::str::from_utf8(bytes).ok().map(str::to_string),
            size: bytes.len(),
        }
    }
}

/// Lowercase big-endian hex (the CyberCipher transport convention).
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
    }
    out
}

// ---------------------------------------------------------------------------
// Unified key-inspection report
// ---------------------------------------------------------------------------

/// One label/value row of a key report (`n`, `e`, a PEM encoding, ...).
#[derive(Debug, Clone, Serialize)]
pub struct PkiField {
    pub label: String,
    pub value: String,
    /// True for PEM blocks (rendered as a multi-line block).
    pub multiline: bool,
}

fn field(label: &str, value: impl Into<String>) -> PkiField {
    let value = value.into();
    PkiField {
        label: label.to_string(),
        multiline: value.contains('\n'),
        value,
    }
}

/// Unified key-inspection report: what the engine decided the material is,
/// its component fields, and every encoding the engine can produce for it.
#[derive(Debug, Clone, Serialize)]
pub struct PkiKeyReport {
    /// `"rsa"` | `"ec"` | `"ed25519"` | `"x25519"` | `"sm2"`.
    pub kind: String,
    /// Named curve for `ec` (`p256`/`p384`) and `sm2` (`sm2p256v1`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
    pub is_private: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_length: Option<usize>,
    /// How the input was classified (`pem_pkcs8`, `der_spki`, `jwk`,
    /// `hex_sec1`, `hex_scalar`, `generated`, ...).
    pub source_format: String,
    pub summary: String,
    /// Public component rows (n/e for RSA, SEC1 points, ...).
    pub public_fields: Vec<PkiField>,
    /// Private component rows; empty for public keys.
    pub private_fields: Vec<PkiField>,
    /// Every encoding the engine can produce for this key (PEM blocks,
    /// DER as hex, JWK JSON), ready to copy.
    pub encodings: Vec<PkiField>,
    /// For raw-hex inputs: other plausible interpretations besides the
    /// primary one (a 32-byte scalar can be a valid key on several curves).
    pub alternatives: Vec<String>,
}

/// Best-effort re-encoding row. The input already parsed and validated, so a
/// failed re-encode is skipped rather than failing the whole inspection.
fn encoding_row(label: &str, value: pki::PkiResult<String>) -> Option<PkiField> {
    value.ok().map(|text| field(label, text))
}

fn rsa_report_from_keypair(keypair: &pki::RsaKeypair, source_format: &str) -> PkiKeyReport {
    let m = keypair.material();
    let bits = keypair.bits();
    PkiKeyReport {
        kind: "rsa".to_string(),
        curve: None,
        is_private: true,
        bit_length: Some(bits),
        source_format: source_format.to_string(),
        summary: format!(
            "RSA private key ({source_format}, {bits} bits, e = {})",
            m.e
        ),
        public_fields: vec![field("n", m.n), field("e", m.e)],
        private_fields: vec![
            field("d", m.d),
            field("p", m.p),
            field("q", m.q),
            field("dp", m.dp),
            field("dq", m.dq),
            field("qinv", m.qinv),
        ],
        encodings: vec![
            encoding_row("PKCS#8 private PEM", keypair.to_pkcs8_pem()),
            encoding_row("PKCS#1 private PEM", keypair.to_pkcs1_pem()),
            encoding_row("SPKI public PEM", keypair.to_public_spki_pem()),
            encoding_row("PKCS#1 public PEM", keypair.to_public_pkcs1_pem()),
            encoding_row(
                "PKCS#8 private DER (hex)",
                keypair.to_pkcs8_der().map(|d| to_hex(&d)),
            ),
            encoding_row(
                "SPKI public DER (hex)",
                keypair.to_public_spki_der().map(|d| to_hex(&d)),
            ),
            encoding_row(
                "JWK (private)",
                pki::jwk_to_json(&pki::keypair_to_jwk(keypair)),
            ),
        ]
        .into_iter()
        .flatten()
        .collect(),
        alternatives: Vec::new(),
    }
}

fn rsa_report_from_public(
    material: &pki::RsaPublicKeyMaterial,
    source_format: &str,
) -> PkiKeyReport {
    let bits = material.bits();
    PkiKeyReport {
        kind: "rsa".to_string(),
        curve: None,
        is_private: false,
        bit_length: Some(bits),
        source_format: source_format.to_string(),
        summary: format!(
            "RSA public key ({source_format}, {bits} bits, e = {})",
            material.e
        ),
        public_fields: vec![
            field("n", material.n.clone()),
            field("e", material.e.clone()),
        ],
        private_fields: Vec::new(),
        encodings: vec![
            encoding_row("SPKI public PEM", material.to_spki_pem()),
            encoding_row("PKCS#1 public PEM", material.to_pkcs1_pem()),
            encoding_row(
                "SPKI public DER (hex)",
                material.to_spki_der().map(|d| to_hex(&d)),
            ),
            encoding_row(
                "PKCS#1 public DER (hex)",
                material.to_pkcs1_der().map(|d| to_hex(&d)),
            ),
            encoding_row(
                "JWK (public)",
                pki::jwk_to_json(&pki::public_material_to_jwk(material)),
            ),
        ]
        .into_iter()
        .flatten()
        .collect(),
        alternatives: Vec::new(),
    }
}

/// ECC curves whose public keys have two distinct SEC1 encodings.
fn has_dual_sec1(curve: pki::EccCurve) -> bool {
    matches!(curve, pki::EccCurve::P256 | pki::EccCurve::P384)
}

fn ecc_public_rows(curve: pki::EccCurve, material: &pki::EccPublicKeyMaterial) -> Vec<PkiField> {
    if has_dual_sec1(curve) {
        vec![
            field(
                "public_compressed (SEC1)",
                material.public_compressed_hex.clone(),
            ),
            field(
                "public_uncompressed (SEC1)",
                material.public_uncompressed_hex.clone(),
            ),
        ]
    } else {
        // Ed25519/X25519 have a single canonical 32-byte public encoding.
        vec![field(
            "public_key (raw)",
            material.public_compressed_hex.clone(),
        )]
    }
}

/// Key-kind classification: the NIST curves report as `ec` + curve name;
/// Ed25519/X25519 are their own kind (no separate curve name).
fn ecc_kind_and_curve(curve: pki::EccCurve) -> (String, Option<String>) {
    match curve {
        pki::EccCurve::P256 | pki::EccCurve::P384 => {
            ("ec".to_string(), Some(curve.label().to_string()))
        }
        other => (other.label().to_string(), None),
    }
}

fn ecc_report_from_keypair(keypair: &pki::EccKeyPair, source_format: &str) -> PkiKeyReport {
    let curve = keypair.curve;
    let (kind, curve_name) = ecc_kind_and_curve(curve);
    let bits = curve.private_key_size() * 8;
    let public_material = pki::EccPublicKeyMaterial {
        curve,
        public_compressed_hex: keypair.public_compressed_hex.clone(),
        public_uncompressed_hex: keypair.public_uncompressed_hex.clone(),
    };
    PkiKeyReport {
        kind,
        curve: curve_name,
        is_private: true,
        bit_length: Some(bits),
        source_format: source_format.to_string(),
        summary: format!("{} keypair ({source_format}, {bits} bits)", curve.label()),
        public_fields: ecc_public_rows(curve, &public_material),
        private_fields: vec![field("private_key", keypair.private_hex.clone())],
        encodings: vec![
            encoding_row(
                "PKCS#8 private PEM",
                pki::ecc_private_key_to_pkcs8_pem(curve, &keypair.private_hex),
            ),
            encoding_row(
                "SPKI public PEM",
                pki::ecc_public_key_to_spki_pem(curve, &keypair.public_uncompressed_hex),
            ),
            encoding_row(
                "PKCS#8 private DER (hex)",
                pki::ecc_private_key_to_pkcs8_der(curve, &keypair.private_hex).map(|d| to_hex(&d)),
            ),
            encoding_row(
                "SPKI public DER (hex)",
                pki::ecc_public_key_to_spki_der(curve, &keypair.public_uncompressed_hex)
                    .map(|d| to_hex(&d)),
            ),
        ]
        .into_iter()
        .flatten()
        .collect(),
        alternatives: Vec::new(),
    }
}

fn ecc_report_from_public(
    material: &pki::EccPublicKeyMaterial,
    source_format: &str,
) -> PkiKeyReport {
    let curve = material.curve;
    let (kind, curve_name) = ecc_kind_and_curve(curve);
    let bits = curve.private_key_size() * 8;
    PkiKeyReport {
        kind,
        curve: curve_name,
        is_private: false,
        bit_length: Some(bits),
        source_format: source_format.to_string(),
        summary: format!(
            "{} public key ({source_format}, {bits} bits)",
            curve.label()
        ),
        public_fields: ecc_public_rows(curve, material),
        private_fields: Vec::new(),
        encodings: vec![
            encoding_row(
                "SPKI public PEM",
                pki::ecc_public_key_to_spki_pem(curve, &material.public_uncompressed_hex),
            ),
            encoding_row(
                "SPKI public DER (hex)",
                pki::ecc_public_key_to_spki_der(curve, &material.public_uncompressed_hex)
                    .map(|d| to_hex(&d)),
            ),
        ]
        .into_iter()
        .flatten()
        .collect(),
        alternatives: Vec::new(),
    }
}

fn sm2_report_from_keypair(keypair: &pki::Sm2KeyPair, source_format: &str) -> PkiKeyReport {
    PkiKeyReport {
        kind: "sm2".to_string(),
        curve: Some("sm2p256v1".to_string()),
        is_private: true,
        bit_length: Some(256),
        source_format: source_format.to_string(),
        summary: format!(
            "SM2 keypair ({source_format}, 256 bits) — raw hex only; \
             PKCS#8/SPKI containers for SM2 are not supported yet"
        ),
        public_fields: vec![
            field(
                "public_compressed (SEC1)",
                keypair.public_compressed_hex.clone(),
            ),
            field(
                "public_uncompressed (SEC1)",
                keypair.public_uncompressed_hex.clone(),
            ),
        ],
        private_fields: vec![field("private_key", keypair.private_hex.clone())],
        // SM2 PKCS#8/SPKI containers are a later phase in the engine (see
        // the sm2::key module docs); the raw hex material is the encoding.
        encodings: Vec::new(),
        alternatives: Vec::new(),
    }
}

fn sm2_report_from_public(
    material: &pki::Sm2PublicKeyMaterial,
    source_format: &str,
) -> PkiKeyReport {
    PkiKeyReport {
        kind: "sm2".to_string(),
        curve: Some("sm2p256v1".to_string()),
        is_private: false,
        bit_length: Some(256),
        source_format: source_format.to_string(),
        summary: format!(
            "SM2 public key ({source_format}, 256 bits) — raw hex only; \
             PKCS#8/SPKI containers for SM2 are not supported yet"
        ),
        public_fields: vec![
            field(
                "public_compressed (SEC1)",
                material.public_compressed_hex.clone(),
            ),
            field(
                "public_uncompressed (SEC1)",
                material.public_uncompressed_hex.clone(),
            ),
        ],
        private_fields: Vec::new(),
        encodings: Vec::new(),
        alternatives: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// pki_inspect_key
// ---------------------------------------------------------------------------

/// Restriction applied to raw-hex interpretation when a `hint` is supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hint {
    Rsa,
    Sm2,
    Curve(pki::EccCurve),
}

fn parse_hint(hint: Option<&str>) -> Result<Option<Hint>, PkiCmdError> {
    let Some(h) = hint.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    match h.to_ascii_lowercase().as_str() {
        "rsa" => Ok(Some(Hint::Rsa)),
        "sm2" => Ok(Some(Hint::Sm2)),
        other => pki::parse_ecc_curve(other)
            .map(|c| Some(Hint::Curve(c)))
            .map_err(PkiCmdError::from),
    }
}

fn hint_wants_der(hint: &Option<Hint>) -> bool {
    matches!(hint, None | Some(Hint::Rsa))
}

fn hint_wants_curve(hint: &Option<Hint>, curve: pki::EccCurve) -> bool {
    match hint {
        None => true,
        Some(Hint::Curve(c)) => *c == curve,
        _ => false,
    }
}

fn hint_wants_sm2(hint: &Option<Hint>) -> bool {
    matches!(hint, None | Some(Hint::Sm2))
}

/// Classify and inspect key material: PEM (any supported key label), a JWK
/// object, or raw hex (RSA/ECC DER structures, SEC1 public points, or raw
/// private scalars). `hint` restricts the raw-hex interpretations
/// (`"rsa"`, `"sm2"`, or a curve label such as `"p256"`); it is ignored for
/// PEM/JWK inputs, which are self-describing.
pub fn inspect_key(material: &str, hint: Option<&str>) -> Result<PkiKeyReport, PkiCmdError> {
    check_text_size("material", material)?;
    let trimmed = material.trim();
    if trimmed.is_empty() {
        return Err(invalid_input(
            "empty key material: paste a PEM, DER hex, JWK, or hex key",
        ));
    }
    if trimmed.starts_with("-----BEGIN ") {
        inspect_pem_input(trimmed)
    } else if trimmed.starts_with('{') {
        inspect_jwk_input(trimmed)
    } else {
        inspect_hex_input(trimmed, parse_hint(hint)?)
    }
}

/// The PEM label of the first armor line, if the input is shaped like PEM.
fn pem_label(pem: &str) -> Option<String> {
    let first = pem.lines().next()?.trim();
    let rest = first.strip_prefix("-----BEGIN ")?;
    let label = rest.strip_suffix("-----")?;
    Some(label.to_string())
}

fn pem_source_format(format: pki::KeyFormat) -> String {
    format!("pem_{}", format.label())
}

fn rsa_report_from_parsed(key: pki::ParsedKey) -> PkiKeyReport {
    match key {
        pki::ParsedKey::Private { keypair, format } => {
            rsa_report_from_keypair(&keypair, &pem_source_format(format))
        }
        pki::ParsedKey::Public { material, format } => {
            rsa_report_from_public(&material, &pem_source_format(format))
        }
    }
}

fn inspect_pem_input(pem: &str) -> Result<PkiKeyReport, PkiCmdError> {
    let label = pem_label(pem);
    match label.as_deref() {
        // Generic containers may hold RSA *or* an ECC curve: try the RSA
        // parser first, then the ECC one with curve auto-detection. When both
        // fail, the RSA error wins (it is the more specific diagnostic).
        Some("PUBLIC KEY") | Some("PRIVATE KEY") => match pki::parse_pem(pem) {
            Ok(key) => Ok(rsa_report_from_parsed(key)),
            Err(rsa_err) => {
                let ecc_result = match label.as_deref() {
                    Some("PUBLIC KEY") => pki::ecc_public_key_from_spki_pem(pem)
                        .map(|m| ecc_report_from_public(&m, "pem_spki"))
                        .map_err(PkiCmdError::from),
                    _ => pki::ecc_private_key_from_pkcs8_pem(pem)
                        .map(|kp| ecc_report_from_keypair(&kp, "pem_pkcs8"))
                        .map_err(PkiCmdError::from),
                };
                ecc_result.map_err(|_| PkiCmdError::from(rsa_err))
            }
        },
        // Everything else (RSA-specific labels, EC PRIVATE KEY, certificates,
        // encrypted keys, ...) goes to the engine for its typed error.
        _ => pki::parse_pem(pem)
            .map_err(PkiCmdError::from)
            .map(rsa_report_from_parsed),
    }
}

fn inspect_jwk_input(json: &str) -> Result<PkiKeyReport, PkiCmdError> {
    let jwk = pki::parse_jwk(json).map_err(PkiCmdError::from)?;
    if jwk.d.is_some() {
        let keypair = pki::jwk_to_keypair(&jwk).map_err(PkiCmdError::from)?;
        Ok(rsa_report_from_keypair(&keypair, "jwk"))
    } else {
        let material = pki::jwk_to_public_material(&jwk).map_err(PkiCmdError::from)?;
        Ok(rsa_report_from_public(&material, "jwk"))
    }
}

const ECC_CURVES: [pki::EccCurve; 4] = [
    pki::EccCurve::P256,
    pki::EccCurve::P384,
    pki::EccCurve::Ed25519,
    pki::EccCurve::X25519,
];

/// Strict hex decode for the raw-hex key path (whitespace already stripped).
fn hex_decode_strict(s: &str) -> Result<Vec<u8>, PkiCmdError> {
    if s.is_empty() || !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid_input(
            "unrecognized key material: expected a PEM, a JWK object, or hex",
        ));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| invalid_input("non-hex character in key material"))
        })
        .collect()
}

/// Accumulator for raw-hex interpretations: the first successful one becomes
/// the primary report, the rest are listed as alternative kinds.
#[derive(Default)]
struct Interpretations {
    primary: Option<PkiKeyReport>,
    names: Vec<String>,
}

impl Interpretations {
    fn record(&mut self, name: &str, report: PkiKeyReport) {
        if self.primary.is_none() {
            self.primary = Some(report);
        }
        self.names.push(name.to_string());
    }
}

fn inspect_hex_input(hex_text: &str, hint: Option<Hint>) -> Result<PkiKeyReport, PkiCmdError> {
    let mut normalized: String = hex_text
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if normalized.starts_with("0x") || normalized.starts_with("0X") {
        normalized = normalized[2..].to_string();
    }
    if normalized.is_empty() {
        return Err(invalid_input("empty key material"));
    }
    let bytes = hex_decode_strict(&normalized)?;

    // Structured interpretations first (DER containers).
    if hint_wants_der(&hint) {
        if let Ok(report) = inspect_der_input(&bytes) {
            return Ok(report);
        }
    }

    // Raw material interpretations: private scalars first (the most common
    // intent for pasted hex), then SEC1 public points. The order makes the
    // primary choice deterministic for ambiguous inputs: Ed25519/X25519
    // seeds/scalars exist *only* as raw 32-byte material, so for exactly
    // 32-byte inputs they are tried before the NIST scalars (which are
    // usually transported in structured containers instead). Every further
    // successful interpretation is reported under `alternatives`.
    let byte_len = bytes.len();
    let private_order: [pki::EccCurve; 4] = if byte_len == 32 {
        [
            pki::EccCurve::Ed25519,
            pki::EccCurve::X25519,
            pki::EccCurve::P256,
            pki::EccCurve::P384,
        ]
    } else {
        ECC_CURVES
    };
    let mut found = Interpretations::default();
    for curve in private_order {
        if hint_wants_curve(&hint, curve) {
            if let Ok(kp) = pki::parse_ecc_private_key(curve, &normalized) {
                let report = ecc_report_from_keypair(&kp, "hex_scalar");
                found.record(&format!("{} private key", curve.label()), report);
            }
        }
    }
    if hint_wants_sm2(&hint) {
        if let Ok(kp) = pki::parse_sm2_private_key(&normalized) {
            found.record(
                "sm2 private key",
                sm2_report_from_keypair(&kp, "hex_scalar"),
            );
        }
    }
    for curve in ECC_CURVES {
        if hint_wants_curve(&hint, curve) {
            if let Ok(m) = pki::parse_ecc_public_key(curve, &normalized) {
                let report = ecc_report_from_public(&m, "hex_sec1");
                found.record(&format!("{} public key", curve.label()), report);
            }
        }
    }
    if hint_wants_sm2(&hint) {
        if let Ok(m) = pki::parse_sm2_public_key(&normalized) {
            found.record("sm2 public key", sm2_report_from_public(&m, "hex_sec1"));
        }
    }

    match found.primary {
        Some(mut report) => {
            report.alternatives = found.names.into_iter().skip(1).collect();
            Ok(report)
        }
        None => Err(invalid_input(
            "could not interpret the hex input as any supported key structure",
        )
        .and_expected(
            "an RSA PKCS#1/PKCS#8/SPKI DER blob, an ECC PKCS#8/SPKI DER blob, \
             a SEC1 public point, a raw private scalar, a PEM, or a JWK",
        )),
    }
}

/// Try the DER container interpretations (RSA PKCS#1/PKCS#8/SPKI and the ECC
/// PKCS#8/SPKI with curve auto-detection).
fn inspect_der_input(bytes: &[u8]) -> Result<PkiKeyReport, PkiCmdError> {
    if let Ok(keypair) = pki::parse_pkcs8_private_der(bytes) {
        return Ok(rsa_report_from_keypair(&keypair, "der_pkcs8"));
    }
    if let Ok(keypair) = pki::parse_pkcs1_private_der(bytes) {
        return Ok(rsa_report_from_keypair(&keypair, "der_pkcs1"));
    }
    if let Ok(material) = pki::parse_spki_public_der(bytes) {
        return Ok(rsa_report_from_public(&material, "der_spki"));
    }
    if let Ok(material) = pki::parse_pkcs1_public_der(bytes) {
        return Ok(rsa_report_from_public(&material, "der_pkcs1"));
    }
    if let Ok(keypair) = pki::ecc_private_key_from_pkcs8_der(bytes) {
        return Ok(ecc_report_from_keypair(&keypair, "der_pkcs8"));
    }
    if let Ok(material) = pki::ecc_public_key_from_spki_der(bytes) {
        return Ok(ecc_report_from_public(&material, "der_spki"));
    }
    Err(invalid_input("not a recognizable key DER structure"))
}

// ---------------------------------------------------------------------------
// RSA operations
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PkiRsaKeygenRequest {
    pub bits: u32,
}

#[derive(Debug, Serialize)]
pub struct PkiRsaKeygenResult {
    /// `-----BEGIN PRIVATE KEY-----` (PKCS#8).
    pub private_pem: String,
    /// `-----BEGIN PUBLIC KEY-----` (SPKI).
    pub public_pem: String,
    /// `-----BEGIN RSA PRIVATE KEY-----` (PKCS#1).
    pub private_pkcs1_pem: String,
    /// `-----BEGIN RSA PUBLIC KEY-----` (PKCS#1).
    pub public_pkcs1_pem: String,
    pub report: PkiKeyReport,
}

/// Generate an RSA keypair (engine-enforced sizes: 1024/2048/3072/4096).
pub fn rsa_keygen(request: PkiRsaKeygenRequest) -> Result<PkiRsaKeygenResult, PkiCmdError> {
    let keypair = pki::generate_rsa_keypair(request.bits as usize, pki::DEFAULT_EXPONENT_HEX)
        .map_err(PkiCmdError::from)?;
    Ok(PkiRsaKeygenResult {
        private_pem: keypair.to_pkcs8_pem().map_err(PkiCmdError::from)?,
        public_pem: keypair.to_public_spki_pem().map_err(PkiCmdError::from)?,
        private_pkcs1_pem: keypair.to_pkcs1_pem().map_err(PkiCmdError::from)?,
        public_pkcs1_pem: keypair.to_public_pkcs1_pem().map_err(PkiCmdError::from)?,
        report: rsa_report_from_keypair(&keypair, "generated"),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RsaScheme {
    Oaep,
    Pkcs1v15,
    Pss,
}

fn parse_scheme(s: &str, allowed: &[RsaScheme], param: &str) -> Result<RsaScheme, PkiCmdError> {
    let scheme = match s.trim().to_ascii_lowercase().as_str() {
        "oaep" => RsaScheme::Oaep,
        "pkcs1v15" | "pkcs1" => RsaScheme::Pkcs1v15,
        "pss" => RsaScheme::Pss,
        other => {
            return Err(
                invalid_param(param, format!("unknown RSA scheme '{other}'"))
                    .and_expected("oaep, pkcs1v15, or pss"),
            );
        }
    };
    if allowed.contains(&scheme) {
        Ok(scheme)
    } else {
        let names: Vec<&str> = allowed
            .iter()
            .map(|s| match s {
                RsaScheme::Oaep => "oaep",
                RsaScheme::Pkcs1v15 => "pkcs1v15",
                RsaScheme::Pss => "pss",
            })
            .collect();
        Err(invalid_param(
            param,
            format!("scheme '{}' is not valid for this operation", s.trim()),
        )
        .and_expected(names.join(", ")))
    }
}

fn parse_digest(label: Option<&str>) -> Result<pki::RsaDigest, PkiCmdError> {
    // OAEP without an explicit hash defaults to SHA-256 (the modern choice).
    let label = label
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("sha256");
    pki::RsaDigest::parse(label).map_err(PkiCmdError::from)
}

fn parse_salt_len(salt: Option<&str>) -> Result<pki::PssSaltLength, PkiCmdError> {
    let Some(text) = salt.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(pki::PssSaltLength::Digest);
    };
    match text.to_ascii_lowercase().as_str() {
        "digest" | "digest-length" => Ok(pki::PssSaltLength::Digest),
        "zero" | "0" => Ok(pki::PssSaltLength::Zero),
        other => other
            .parse::<usize>()
            .map(pki::PssSaltLength::Fixed)
            .map_err(|_| {
                invalid_param("salt_len", format!("invalid PSS salt length '{other}'"))
                    .and_expected("digest, zero, or a byte count")
            }),
    }
}

#[derive(Debug, Deserialize)]
pub struct PkiRsaEncryptRequest {
    pub key_pem: String,
    /// `oaep` | `pkcs1v15`.
    pub scheme: String,
    /// OAEP digest (`sha1`/`sha256`/`sha384`/`sha512`); default `sha256`.
    #[serde(default)]
    pub hash: Option<String>,
    /// Optional OAEP label (UTF-8, per the engine's label handling).
    #[serde(default)]
    pub label: Option<String>,
    pub plaintext_text: String,
    /// `utf8` | `hex` | `base64` | `decimal`.
    pub plaintext_encoding: String,
}

#[derive(Debug, Serialize)]
pub struct PkiRsaEncryptResult {
    pub ciphertext: PkiBytes,
    pub scheme: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

pub fn rsa_encrypt(request: PkiRsaEncryptRequest) -> Result<PkiRsaEncryptResult, PkiCmdError> {
    check_text_size("key_pem", &request.key_pem)?;
    let scheme = parse_scheme(
        &request.scheme,
        &[RsaScheme::Oaep, RsaScheme::Pkcs1v15],
        "scheme",
    )?;
    let plaintext = decode_data(
        "plaintext_text",
        &request.plaintext_encoding,
        &request.plaintext_text,
    )?;
    let (ciphertext, hash_label) = match scheme {
        RsaScheme::Oaep => {
            let hash = parse_digest(request.hash.as_deref())?;
            let ct = pki::ops::rsa_encrypt_oaep_pem(
                &request.key_pem,
                &plaintext,
                hash,
                request.label.as_deref().map(str::as_bytes),
            )
            .map_err(PkiCmdError::from)?;
            (ct, Some(hash.label().to_string()))
        }
        RsaScheme::Pkcs1v15 => (
            pki::ops::rsa_encrypt_pkcs1v15_pem(&request.key_pem, &plaintext)
                .map_err(PkiCmdError::from)?,
            None,
        ),
        RsaScheme::Pss => {
            return Err(invalid_param(
                "scheme",
                "pss is a signature scheme, not an encryption scheme",
            )
            .and_expected("oaep or pkcs1v15"));
        }
    };
    Ok(PkiRsaEncryptResult {
        ciphertext: PkiBytes::new(&ciphertext),
        scheme: scheme_name(scheme).to_string(),
        hash: hash_label,
    })
}

#[derive(Debug, Deserialize)]
pub struct PkiRsaDecryptRequest {
    pub key_pem: String,
    /// `oaep` | `pkcs1v15`.
    pub scheme: String,
    #[serde(default)]
    pub hash: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    pub ciphertext_text: String,
    pub ciphertext_encoding: String,
}

#[derive(Debug, Serialize)]
pub struct PkiRsaDecryptResult {
    pub plaintext: PkiBytes,
}

pub fn rsa_decrypt(request: PkiRsaDecryptRequest) -> Result<PkiRsaDecryptResult, PkiCmdError> {
    check_text_size("key_pem", &request.key_pem)?;
    let scheme = parse_scheme(
        &request.scheme,
        &[RsaScheme::Oaep, RsaScheme::Pkcs1v15],
        "scheme",
    )?;
    let ciphertext = decode_data(
        "ciphertext_text",
        &request.ciphertext_encoding,
        &request.ciphertext_text,
    )?;
    let plaintext = match scheme {
        RsaScheme::Oaep => {
            let hash = parse_digest(request.hash.as_deref())?;
            pki::ops::rsa_decrypt_oaep_pem(
                &request.key_pem,
                &ciphertext,
                hash,
                request.label.as_deref().map(str::as_bytes),
            )
        }
        RsaScheme::Pkcs1v15 => pki::ops::rsa_decrypt_pkcs1v15_pem(&request.key_pem, &ciphertext),
        RsaScheme::Pss => {
            return Err(invalid_param(
                "scheme",
                "pss is a signature scheme, not an encryption scheme",
            )
            .and_expected("oaep or pkcs1v15"));
        }
    }
    .map_err(PkiCmdError::from)?;
    Ok(PkiRsaDecryptResult {
        plaintext: PkiBytes::new(&plaintext),
    })
}

#[derive(Debug, Deserialize)]
pub struct PkiRsaSignRequest {
    pub key_pem: String,
    /// `pkcs1v15` | `pss`.
    pub scheme: String,
    pub hash: String,
    /// PSS salt length (`digest` | `zero` | byte count); default `digest`.
    #[serde(default)]
    pub salt_len: Option<String>,
    pub data_text: String,
    pub data_encoding: String,
}

#[derive(Debug, Serialize)]
pub struct PkiRsaSignResult {
    pub signature: PkiBytes,
    pub scheme: String,
    pub digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt_len: Option<String>,
}

pub fn rsa_sign(request: PkiRsaSignRequest) -> Result<PkiRsaSignResult, PkiCmdError> {
    check_text_size("key_pem", &request.key_pem)?;
    let scheme = parse_scheme(
        &request.scheme,
        &[RsaScheme::Pkcs1v15, RsaScheme::Pss],
        "scheme",
    )?;
    let digest = pki::RsaDigest::parse(request.hash.trim()).map_err(PkiCmdError::from)?;
    let data = decode_data("data_text", &request.data_encoding, &request.data_text)?;
    let (signature, salt_len) = match scheme {
        RsaScheme::Pkcs1v15 => {
            let sig = pki::ops::rsa_sign_pkcs1v15_pem(&request.key_pem, digest.label(), &data)
                .map_err(PkiCmdError::from)?;
            (sig, None)
        }
        RsaScheme::Pss => {
            let salt = parse_salt_len(request.salt_len.as_deref())?;
            let sig = pki::ops::rsa_sign_pss_pem(&request.key_pem, digest.label(), &data, salt)
                .map_err(PkiCmdError::from)?;
            (sig, Some(salt.label()))
        }
        RsaScheme::Oaep => {
            return Err(invalid_param(
                "scheme",
                "oaep is an encryption scheme, not a signature scheme",
            )
            .and_expected("pkcs1v15 or pss"));
        }
    };
    Ok(PkiRsaSignResult {
        signature: PkiBytes::new(&signature),
        scheme: scheme_name(scheme).to_string(),
        digest: digest.label().to_string(),
        salt_len,
    })
}

fn scheme_name(scheme: RsaScheme) -> &'static str {
    match scheme {
        RsaScheme::Oaep => "oaep",
        RsaScheme::Pkcs1v15 => "pkcs1v15",
        RsaScheme::Pss => "pss",
    }
}

#[derive(Debug, Deserialize)]
pub struct PkiRsaVerifyRequest {
    pub key_pem: String,
    /// `pkcs1v15` | `pss`.
    pub scheme: String,
    pub hash: String,
    #[serde(default)]
    pub salt_len: Option<String>,
    pub data_text: String,
    pub data_encoding: String,
    /// Signature as hex or base64 (the engine's `decode_signature_text`).
    pub signature_text: String,
}

pub fn rsa_verify(request: PkiRsaVerifyRequest) -> Result<pki::SignatureVerifyResult, PkiCmdError> {
    check_text_size("key_pem", &request.key_pem)?;
    let scheme = parse_scheme(
        &request.scheme,
        &[RsaScheme::Pkcs1v15, RsaScheme::Pss],
        "scheme",
    )?;
    let digest = pki::RsaDigest::parse(request.hash.trim()).map_err(PkiCmdError::from)?;
    let data = decode_data("data_text", &request.data_encoding, &request.data_text)?;
    check_text_size("signature_text", &request.signature_text)?;
    let verdict = match scheme {
        RsaScheme::Pkcs1v15 => pki::ops::rsa_verify_pkcs1v15_pem(
            &request.key_pem,
            digest.label(),
            &data,
            &request.signature_text,
        ),
        RsaScheme::Pss => {
            let salt = parse_salt_len(request.salt_len.as_deref())?;
            pki::ops::rsa_verify_pss_pem(
                &request.key_pem,
                digest.label(),
                &data,
                &request.signature_text,
                salt,
            )
        }
        RsaScheme::Oaep => {
            return Err(invalid_param(
                "scheme",
                "oaep is an encryption scheme, not a signature scheme",
            )
            .and_expected("pkcs1v15 or pss"));
        }
    };
    verdict.map_err(PkiCmdError::from)
}

// ---------------------------------------------------------------------------
// ECC operations
// ---------------------------------------------------------------------------

fn parse_curve(label: &str) -> Result<pki::EccCurve, PkiCmdError> {
    pki::parse_ecc_curve(label).map_err(PkiCmdError::from)
}

#[derive(Debug, Deserialize)]
pub struct PkiEccKeygenRequest {
    pub curve: String,
}

#[derive(Debug, Serialize)]
pub struct PkiEccKeygenResult {
    pub curve: String,
    pub private_hex: String,
    pub public_compressed_hex: String,
    pub public_uncompressed_hex: String,
    pub private_pkcs8_pem: String,
    pub public_spki_pem: String,
    pub report: PkiKeyReport,
}

pub fn ecc_keygen(request: PkiEccKeygenRequest) -> Result<PkiEccKeygenResult, PkiCmdError> {
    let curve = parse_curve(&request.curve)?;
    let keypair = pki::generate_ecc_keypair(curve).map_err(PkiCmdError::from)?;
    let private_pkcs8_pem = pki::ecc_private_key_to_pkcs8_pem(curve, &keypair.private_hex)
        .map_err(PkiCmdError::from)?;
    let public_spki_pem = pki::ecc_public_key_to_spki_pem(curve, &keypair.public_uncompressed_hex)
        .map_err(PkiCmdError::from)?;
    Ok(PkiEccKeygenResult {
        curve: curve.label().to_string(),
        private_hex: keypair.private_hex.clone(),
        public_compressed_hex: keypair.public_compressed_hex.clone(),
        public_uncompressed_hex: keypair.public_uncompressed_hex.clone(),
        private_pkcs8_pem,
        public_spki_pem,
        report: ecc_report_from_keypair(&keypair, "generated"),
    })
}

fn parse_ecdsa_digest(label: &str) -> Result<pki::EcdsaDigest, PkiCmdError> {
    match label.trim().to_ascii_lowercase().as_str() {
        "sha256" => Ok(pki::EcdsaDigest::Sha256),
        "sha384" => Ok(pki::EcdsaDigest::Sha384),
        other => Err(
            invalid_param("digest", format!("unsupported ECDSA digest '{other}'"))
                .and_expected("sha256 (P-256) or sha384 (P-384)"),
        ),
    }
}

fn parse_signature_format(label: Option<&str>) -> Result<pki::EcdsaSignatureFormat, PkiCmdError> {
    match label
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("der")
    {
        "der" => Ok(pki::EcdsaSignatureFormat::Der),
        "fixed" => Ok(pki::EcdsaSignatureFormat::Fixed),
        other => Err(invalid_param(
            "format",
            format!("unknown ECDSA signature format '{other}'"),
        )
        .and_expected("der or fixed")),
    }
}

fn parse_nonce_mode(label: Option<&str>) -> Result<pki::EcdsaNonceMode, PkiCmdError> {
    match label
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("deterministic")
    {
        "deterministic" => Ok(pki::EcdsaNonceMode::Deterministic),
        "random" => Ok(pki::EcdsaNonceMode::Random),
        other => Err(
            invalid_param("nonce", format!("unknown ECDSA nonce mode '{other}'"))
                .and_expected("deterministic (RFC 6979) or random"),
        ),
    }
}

#[derive(Debug, Deserialize)]
pub struct PkiEcdsaSignRequest {
    pub curve: String,
    pub private_hex: String,
    /// `sha256` (P-256) or `sha384` (P-384); the engine enforces the pairing.
    pub digest: String,
    /// `der` (default) or `fixed` (r||s).
    #[serde(default)]
    pub format: Option<String>,
    /// `deterministic` (RFC 6979, default) or `random`.
    #[serde(default)]
    pub nonce: Option<String>,
    pub data_text: String,
    pub data_encoding: String,
}

#[derive(Debug, Serialize)]
pub struct PkiEcdsaSignResult {
    pub signature_hex: String,
    pub curve: String,
    pub digest: String,
    pub format: String,
    pub nonce: String,
}

pub fn ecdsa_sign(request: PkiEcdsaSignRequest) -> Result<PkiEcdsaSignResult, PkiCmdError> {
    let curve = parse_curve(&request.curve)?;
    let digest = parse_ecdsa_digest(&request.digest)?;
    let format = parse_signature_format(request.format.as_deref())?;
    let nonce = parse_nonce_mode(request.nonce.as_deref())?;
    let data = decode_data("data_text", &request.data_encoding, &request.data_text)?;
    let signature_hex = pki::ecdsa_sign(curve, &request.private_hex, &data, digest, nonce, format)
        .map_err(PkiCmdError::from)?;
    Ok(PkiEcdsaSignResult {
        signature_hex,
        curve: curve.label().to_string(),
        digest: digest.label().to_string(),
        format: format.label().to_string(),
        nonce: match nonce {
            pki::EcdsaNonceMode::Deterministic => "deterministic".to_string(),
            pki::EcdsaNonceMode::Random => "random".to_string(),
        },
    })
}

#[derive(Debug, Deserialize)]
pub struct PkiEcdsaVerifyRequest {
    pub curve: String,
    pub public_hex: String,
    pub digest: String,
    #[serde(default)]
    pub format: Option<String>,
    pub data_text: String,
    pub data_encoding: String,
    pub signature_hex: String,
}

pub fn ecdsa_verify(request: PkiEcdsaVerifyRequest) -> Result<pki::EcdsaVerifyResult, PkiCmdError> {
    let curve = parse_curve(&request.curve)?;
    let digest = parse_ecdsa_digest(&request.digest)?;
    let format = parse_signature_format(request.format.as_deref())?;
    let data = decode_data("data_text", &request.data_encoding, &request.data_text)?;
    pki::ecdsa_verify(
        curve,
        &request.public_hex,
        &data,
        digest,
        format,
        &request.signature_hex,
    )
    .map_err(PkiCmdError::from)
}

#[derive(Debug, Deserialize)]
pub struct PkiEcdhRequest {
    pub curve: String,
    pub private_hex: String,
    pub peer_public_hex: String,
}

#[derive(Debug, Serialize)]
pub struct PkiSharedSecretResult {
    pub shared_secret_hex: String,
}

pub fn ecdh(request: PkiEcdhRequest) -> Result<PkiSharedSecretResult, PkiCmdError> {
    let curve = parse_curve(&request.curve)?;
    let secret = pki::ecdh_shared_secret(curve, &request.private_hex, &request.peer_public_hex)
        .map_err(PkiCmdError::from)?;
    Ok(PkiSharedSecretResult {
        shared_secret_hex: secret,
    })
}

#[derive(Debug, Deserialize)]
pub struct PkiEd25519SignRequest {
    pub private_hex: String,
    pub data_text: String,
    pub data_encoding: String,
}

#[derive(Debug, Serialize)]
pub struct PkiSignatureHexResult {
    pub signature_hex: String,
}

pub fn ed25519_sign(request: PkiEd25519SignRequest) -> Result<PkiSignatureHexResult, PkiCmdError> {
    let data = decode_data("data_text", &request.data_encoding, &request.data_text)?;
    let signature_hex =
        pki::ed25519_sign(&request.private_hex, &data).map_err(PkiCmdError::from)?;
    Ok(PkiSignatureHexResult { signature_hex })
}

#[derive(Debug, Deserialize)]
pub struct PkiEd25519VerifyRequest {
    pub public_hex: String,
    pub data_text: String,
    pub data_encoding: String,
    pub signature_hex: String,
}

pub fn ed25519_verify(
    request: PkiEd25519VerifyRequest,
) -> Result<pki::Ed25519VerifyResult, PkiCmdError> {
    let data = decode_data("data_text", &request.data_encoding, &request.data_text)?;
    pki::ed25519_verify(&request.public_hex, &data, &request.signature_hex)
        .map_err(PkiCmdError::from)
}

#[derive(Debug, Deserialize)]
pub struct PkiX25519Request {
    pub private_hex: String,
    pub peer_public_hex: String,
}

pub fn x25519(request: PkiX25519Request) -> Result<PkiSharedSecretResult, PkiCmdError> {
    let secret = pki::x25519_shared_secret(&request.private_hex, &request.peer_public_hex)
        .map_err(PkiCmdError::from)?;
    Ok(PkiSharedSecretResult {
        shared_secret_hex: secret,
    })
}

// ---------------------------------------------------------------------------
// SM2 operations
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct PkiSm2KeygenResult {
    pub private_hex: String,
    pub public_compressed_hex: String,
    pub public_uncompressed_hex: String,
    pub report: PkiKeyReport,
}

pub fn sm2_keygen() -> Result<PkiSm2KeygenResult, PkiCmdError> {
    let keypair = pki::generate_sm2_keypair().map_err(PkiCmdError::from)?;
    Ok(PkiSm2KeygenResult {
        private_hex: keypair.private_hex.clone(),
        public_compressed_hex: keypair.public_compressed_hex.clone(),
        public_uncompressed_hex: keypair.public_uncompressed_hex.clone(),
        report: sm2_report_from_keypair(&keypair, "generated"),
    })
}

#[derive(Debug, Deserialize)]
pub struct PkiSm2SignRequest {
    pub private_hex: String,
    pub data_text: String,
    pub data_encoding: String,
    /// SM2 user ID (the ZA hash context); empty selects the engine default
    /// `"1234567812345678"`.
    #[serde(default)]
    pub user_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PkiSm2SignResult {
    pub signature_hex: String,
    pub user_id: String,
}

pub fn sm2_sign(request: PkiSm2SignRequest) -> Result<PkiSm2SignResult, PkiCmdError> {
    let data = decode_data("data_text", &request.data_encoding, &request.data_text)?;
    let signature_hex = pki::sm2_sign(&request.private_hex, &data, request.user_id.as_deref())
        .map_err(PkiCmdError::from)?;
    Ok(PkiSm2SignResult {
        signature_hex,
        user_id: request
            .user_id
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| pki::SM2_DEFAULT_USER_ID.to_string()),
    })
}

#[derive(Debug, Deserialize)]
pub struct PkiSm2VerifyRequest {
    pub public_hex: String,
    pub data_text: String,
    pub data_encoding: String,
    pub signature_hex: String,
    #[serde(default)]
    pub user_id: Option<String>,
}

pub fn sm2_verify(request: PkiSm2VerifyRequest) -> Result<pki::Sm2VerifyResult, PkiCmdError> {
    let data = decode_data("data_text", &request.data_encoding, &request.data_text)?;
    pki::sm2_verify(
        &request.public_hex,
        &data,
        &request.signature_hex,
        request.user_id.as_deref(),
    )
    .map_err(PkiCmdError::from)
}

#[derive(Debug, Deserialize)]
pub struct PkiSm2EncryptRequest {
    pub public_hex: String,
    pub plaintext_text: String,
    pub plaintext_encoding: String,
}

#[derive(Debug, Serialize)]
pub struct PkiSm2EncryptResult {
    /// `C1 || C3 || C2` transport (uncompressed C1 point, SM3 tag, masked M).
    pub ciphertext: PkiBytes,
}

pub fn sm2_encrypt(request: PkiSm2EncryptRequest) -> Result<PkiSm2EncryptResult, PkiCmdError> {
    let plaintext = decode_data(
        "plaintext_text",
        &request.plaintext_encoding,
        &request.plaintext_text,
    )?;
    let ciphertext =
        pki::sm2_encrypt(&request.public_hex, &plaintext).map_err(PkiCmdError::from)?;
    Ok(PkiSm2EncryptResult {
        ciphertext: PkiBytes::new(&ciphertext),
    })
}

#[derive(Debug, Deserialize)]
pub struct PkiSm2DecryptRequest {
    pub private_hex: String,
    pub ciphertext_text: String,
    pub ciphertext_encoding: String,
}

#[derive(Debug, Serialize)]
pub struct PkiSm2DecryptResult {
    pub plaintext: PkiBytes,
}

pub fn sm2_decrypt(request: PkiSm2DecryptRequest) -> Result<PkiSm2DecryptResult, PkiCmdError> {
    let ciphertext = decode_data(
        "ciphertext_text",
        &request.ciphertext_encoding,
        &request.ciphertext_text,
    )?;
    let plaintext =
        pki::sm2_decrypt(&request.private_hex, &ciphertext).map_err(PkiCmdError::from)?;
    Ok(PkiSm2DecryptResult {
        plaintext: PkiBytes::new(&plaintext),
    })
}

// ---------------------------------------------------------------------------
// Certificate / CSR / CRL inspection
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PkiCertInspectRequest {
    pub material: String,
}

#[derive(Debug, Serialize)]
pub struct PkiCertReport {
    /// `"certificate"` | `"csr"` | `"crl"`.
    pub object_type: String,
    /// PEM armor label when the input was PEM.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pem_label: Option<String>,
    /// The DER payload actually inspected, as lowercase hex.
    pub der_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<pki::CertificateInspection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csr: Option<pki::CsrInspection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crl: Option<pki::CrlInspection>,
    /// Bounded ASN.1 tree of the DER payload (engine-capped depth and size).
    pub asn1_tree: Vec<pki::Asn1Node>,
}

/// Inspect an X.509 certificate, PKCS#10 CSR, or CRL given as PEM armor, raw
/// DER hex, or base64 DER (auto-detected for non-PEM input).
pub fn cert_inspect(request: PkiCertInspectRequest) -> Result<PkiCertReport, PkiCmdError> {
    check_text_size("material", &request.material)?;
    let trimmed = request.material.trim();
    if trimmed.is_empty() {
        return Err(invalid_input(
            "empty input: paste a certificate, CSR, or CRL as PEM or DER hex",
        ));
    }
    if trimmed.starts_with("-----BEGIN ") {
        let identification = pki::identify_pem(trimmed.as_bytes()).map_err(PkiCmdError::from)?;
        use pki::PemObjectType as T;
        if !matches!(
            identification.object_type,
            T::Certificate | T::CertificateRequest | T::Crl
        ) {
            // Key PEMs and other objects get the precise wrong-object-type
            // error instead of a bare DER parse failure.
            return Err(invalid_input(format!(
                "wrong PEM object type for the certificate inspector: {}",
                identification.object_type.label()
            ))
            .and_expected("a CERTIFICATE, CERTIFICATE REQUEST, or X509 CRL PEM")
            .and_actual(identification.label));
        }
        let der = pem_der_payload(trimmed)?;
        let mut report = classify_der(&der, &identification.object_type)?;
        report.pem_label = Some(identification.label);
        Ok(report)
    } else {
        let der = decode_der_blob(trimmed)?;
        classify_der(&der, &pki::PemObjectType::Other)
    }
}

fn empty_cert_report(object_type: &str, der: &[u8]) -> PkiCertReport {
    PkiCertReport {
        object_type: object_type.to_string(),
        pem_label: None,
        der_hex: to_hex(der),
        certificate: None,
        csr: None,
        crl: None,
        asn1_tree: Vec::new(),
    }
}

/// Route a DER payload to the right inspector. `declared` is the PEM object
/// type when the input was PEM (`Other` for raw DER, where try-all-in-order
/// semantics apply).
fn classify_der(der: &[u8], declared: &pki::PemObjectType) -> Result<PkiCertReport, PkiCmdError> {
    use pki::PemObjectType as T;
    let mut report = match declared {
        T::Certificate => {
            let mut r = empty_cert_report("certificate", der);
            r.certificate = Some(pki::inspect_certificate(der).map_err(PkiCmdError::from)?);
            r
        }
        T::CertificateRequest => {
            let mut r = empty_cert_report("csr", der);
            r.csr = Some(pki::inspect_csr(der).map_err(PkiCmdError::from)?);
            r
        }
        T::Crl => {
            let mut r = empty_cert_report("crl", der);
            r.crl = Some(pki::inspect_crl(der).map_err(PkiCmdError::from)?);
            r
        }
        // Raw DER: no header to trust, try each inspector in turn.
        _ => {
            if let Ok(certificate) = pki::inspect_certificate(der) {
                let mut r = empty_cert_report("certificate", der);
                r.certificate = Some(certificate);
                r
            } else if let Ok(csr) = pki::inspect_csr(der) {
                let mut r = empty_cert_report("csr", der);
                r.csr = Some(csr);
                r
            } else if let Ok(crl) = pki::inspect_crl(der) {
                let mut r = empty_cert_report("crl", der);
                r.crl = Some(crl);
                r
            } else {
                // Surface the certificate parse failure as the primary error
                // (the most likely intent); it carries the DER diagnostics.
                return Err(pki::inspect_certificate(der)
                    .err()
                    .map(PkiCmdError::from)
                    .unwrap_or_else(|| invalid_input("not a certificate, CSR, or CRL")));
            }
        }
    };
    report.asn1_tree =
        pki::parse_der_tree(der, pki::asn1::DEFAULT_MAX_DEPTH).map_err(PkiCmdError::from)?;
    Ok(report)
}

/// Extract and decode the base64 payload of a PEM block (the engine's
/// inspectors accept the full armor; the ASN.1 tree needs the raw DER).
fn pem_der_payload(pem: &str) -> Result<Vec<u8>, PkiCmdError> {
    let label = pem_label(pem).ok_or_else(|| invalid_input("malformed PEM armor header"))?;
    let end_marker = format!("-----END {label}-----");
    let mut body = String::new();
    for line in pem.lines().skip(1) {
        let line = line.trim();
        if line == end_marker {
            return decode_input("base64", &body).map_err(PkiCmdError::from);
        }
        if !line.contains(':') {
            body.push_str(line);
        }
    }
    Err(invalid_input(format!(
        "missing '-----END {label}-----' terminator"
    )))
}

/// Decode a non-PEM certificate blob: hex when the text is all hex digits,
/// base64 otherwise (both relaxed, via the codec).
fn decode_der_blob(text: &str) -> Result<Vec<u8>, PkiCmdError> {
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let looks_hex = !compact.is_empty()
        && compact.len().is_multiple_of(2)
        && compact.bytes().all(|b| b.is_ascii_hexdigit());
    if looks_hex {
        decode_input("hex", text).map_err(PkiCmdError::from)
    } else {
        decode_input("base64", text).map_err(PkiCmdError::from)
    }
}

// ---------------------------------------------------------------------------
// Async wrappers (registered in main.rs)
// ---------------------------------------------------------------------------

/// Run an engine call on the blocking thread pool so long operations (RSA
/// keygen) never freeze the UI thread.
async fn run_blocking<T, F>(work: F) -> Result<T, PkiCmdError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, PkiCmdError> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|e| PkiCmdError::from(OperationError::internal(format!("pki task failed: {e}"))))?
}

#[tauri::command]
pub async fn pki_inspect_key(
    material: String,
    hint: Option<String>,
) -> Result<PkiKeyReport, PkiCmdError> {
    run_blocking(move || inspect_key(&material, hint.as_deref())).await
}

#[tauri::command]
pub async fn pki_rsa_keygen(
    request: PkiRsaKeygenRequest,
) -> Result<PkiRsaKeygenResult, PkiCmdError> {
    run_blocking(move || rsa_keygen(request)).await
}

#[tauri::command]
pub async fn pki_rsa_encrypt(
    request: PkiRsaEncryptRequest,
) -> Result<PkiRsaEncryptResult, PkiCmdError> {
    run_blocking(move || rsa_encrypt(request)).await
}

#[tauri::command]
pub async fn pki_rsa_decrypt(
    request: PkiRsaDecryptRequest,
) -> Result<PkiRsaDecryptResult, PkiCmdError> {
    run_blocking(move || rsa_decrypt(request)).await
}

#[tauri::command]
pub async fn pki_rsa_sign(request: PkiRsaSignRequest) -> Result<PkiRsaSignResult, PkiCmdError> {
    run_blocking(move || rsa_sign(request)).await
}

#[tauri::command]
pub async fn pki_rsa_verify(
    request: PkiRsaVerifyRequest,
) -> Result<pki::SignatureVerifyResult, PkiCmdError> {
    run_blocking(move || rsa_verify(request)).await
}

#[tauri::command]
pub async fn pki_ecc_keygen(
    request: PkiEccKeygenRequest,
) -> Result<PkiEccKeygenResult, PkiCmdError> {
    run_blocking(move || ecc_keygen(request)).await
}

#[tauri::command]
pub async fn pki_ecdsa_sign(
    request: PkiEcdsaSignRequest,
) -> Result<PkiEcdsaSignResult, PkiCmdError> {
    run_blocking(move || ecdsa_sign(request)).await
}

#[tauri::command]
pub async fn pki_ecdsa_verify(
    request: PkiEcdsaVerifyRequest,
) -> Result<pki::EcdsaVerifyResult, PkiCmdError> {
    run_blocking(move || ecdsa_verify(request)).await
}

#[tauri::command]
pub async fn pki_ecdh(request: PkiEcdhRequest) -> Result<PkiSharedSecretResult, PkiCmdError> {
    run_blocking(move || ecdh(request)).await
}

#[tauri::command]
pub async fn pki_ed25519_sign(
    request: PkiEd25519SignRequest,
) -> Result<PkiSignatureHexResult, PkiCmdError> {
    run_blocking(move || ed25519_sign(request)).await
}

#[tauri::command]
pub async fn pki_ed25519_verify(
    request: PkiEd25519VerifyRequest,
) -> Result<pki::Ed25519VerifyResult, PkiCmdError> {
    run_blocking(move || ed25519_verify(request)).await
}

#[tauri::command]
pub async fn pki_x25519(request: PkiX25519Request) -> Result<PkiSharedSecretResult, PkiCmdError> {
    run_blocking(move || x25519(request)).await
}

#[tauri::command]
pub async fn pki_sm2_keygen() -> Result<PkiSm2KeygenResult, PkiCmdError> {
    run_blocking(sm2_keygen).await
}

#[tauri::command]
pub async fn pki_sm2_sign(request: PkiSm2SignRequest) -> Result<PkiSm2SignResult, PkiCmdError> {
    run_blocking(move || sm2_sign(request)).await
}

#[tauri::command]
pub async fn pki_sm2_verify(
    request: PkiSm2VerifyRequest,
) -> Result<pki::Sm2VerifyResult, PkiCmdError> {
    run_blocking(move || sm2_verify(request)).await
}

#[tauri::command]
pub async fn pki_sm2_encrypt(
    request: PkiSm2EncryptRequest,
) -> Result<PkiSm2EncryptResult, PkiCmdError> {
    run_blocking(move || sm2_encrypt(request)).await
}

#[tauri::command]
pub async fn pki_sm2_decrypt(
    request: PkiSm2DecryptRequest,
) -> Result<PkiSm2DecryptResult, PkiCmdError> {
    run_blocking(move || sm2_decrypt(request)).await
}

#[tauri::command]
pub async fn pki_cert_inspect(
    request: PkiCertInspectRequest,
) -> Result<PkiCertReport, PkiCmdError> {
    run_blocking(move || cert_inspect(request)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixture from the engine's own x509 test suite (OpenSSL-generated
    // self-signed RSA-2048 root CA).
    const CA_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDiTCCAnGgAwIBAgIUYxEzsk2jl4+VmmrSRgUXoqbhPX8wDQYJKoZIhvcNAQEL
BQAwTDELMAkGA1UEBhMCVVMxGjAYBgNVBAoMEUN5YmVyQ2lwaGVyIFRlc3RzMSEw
HwYDVQQDDBhDeWJlckNpcGhlciBUZXN0IFJvb3QgQ0EwHhcNMjYwOTMwMDU1MTA2
WhcNMzYwOTI3MDU1MTA2WjBMMQswCQYDVQQGEwJVUzEaMBgGA1UECgwRQ3liZXJD
aXBoZXIgVGVzdHMxITAfBgNVBAMMGEN5YmVyQ2lwaGVyIFRlc3QgUm9vdCBDQTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALvElSr43goHNJcdGHAb3Dn6
xl4zpZ3XdBsNlLRUt7JOykmPL23FnjlvmzgnoH/VliFqdOnMDkPAcoPrfVEnA1u8
62CFQHr63aIS77yWacf9BDZRbTlzWcZGsXWtjEH684D0y7M42IuBEPZKsbbw1bux
kUEyuOzwYAY/kp41YIq+CSQTdZObA5EQSnn36iEo0iQ+mw0FW1VhU5DnOHK1OQOf
beDx8vucI3M9qIC/NAoCTmaA2LZZhz4xjkNwRix4Vbl1Ys9SKcKPJIoRK0vUjfwB
y70OwgCEPsluacb85w+brJG3Nwbmuz2azv7wjhx33kviI37+MoM3+XOJ2RBen1sC
AwEAAaNjMGEwHwYDVR0jBBgwFoAULUfONRDgYx1a+b6onAIvybVPVC4wDwYDVR0T
AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFC1HzjUQ4GMdWvm+
qJwCL8m1T1QuMA0GCSqGSIb3DQEBCwUAA4IBAQBJR+2Dhug5HxKgsNnFpxCsJonw
eBGgfhp5Grfzuuee+dKrlH8aAd/SUunC8tqQX2lxyziXyoLshTkcVOEEJ5q1nncG
S8L/q96Ydkf8k7IW9QG6j5NHfzscyZ6AnKtlm9nTWMNTnowflhvxx78oRF1/ALNI
jeOoLUUYPTR8DqcslBQIjTZX/Ft7vafZZ/ZDTvge5KXoYAEEC0XddqVf1qEUdlNu
qj236vBnRMmwSkVuPGxR+KCPOAKZ60ZF3PQ4ABo0NXNu5VCWVSbigdSs88aww6+x
AsTTNsv9HUkT9hSOWUsUuJVe3V5tsNfjUeGmfn6lY+vyjChB6DW9B+abyeFN
-----END CERTIFICATE-----
";

    fn sample_rsa_keypair() -> pki::RsaKeypair {
        pki::generate_rsa_keypair(1024, pki::DEFAULT_EXPONENT_HEX).unwrap()
    }

    fn sample_ecc_keypair(curve: pki::EccCurve) -> pki::EccKeyPair {
        pki::generate_ecc_keypair(curve).unwrap()
    }

    // ------------------------------------------------------ parameters ----

    #[test]
    fn salt_len_parsing() {
        assert!(matches!(
            parse_salt_len(None).unwrap(),
            pki::PssSaltLength::Digest
        ));
        assert!(matches!(
            parse_salt_len(Some("digest")).unwrap(),
            pki::PssSaltLength::Digest
        ));
        assert!(matches!(
            parse_salt_len(Some("zero")).unwrap(),
            pki::PssSaltLength::Zero
        ));
        assert!(matches!(
            parse_salt_len(Some("16")).unwrap(),
            pki::PssSaltLength::Fixed(16)
        ));
        let err = parse_salt_len(Some("nonsense")).unwrap_err();
        assert_eq!(err.parameter.as_deref(), Some("salt_len"));
        assert!(err.expected.as_deref().unwrap().contains("digest"));
    }

    #[test]
    fn scheme_parsing() {
        assert_eq!(
            parse_scheme("oaep", &[RsaScheme::Oaep, RsaScheme::Pkcs1v15], "scheme").unwrap(),
            RsaScheme::Oaep
        );
        assert_eq!(
            parse_scheme("PKCS1", &[RsaScheme::Oaep, RsaScheme::Pkcs1v15], "scheme").unwrap(),
            RsaScheme::Pkcs1v15
        );
        // pss is known but not allowed for encryption.
        let err =
            parse_scheme("pss", &[RsaScheme::Oaep, RsaScheme::Pkcs1v15], "scheme").unwrap_err();
        assert!(err.expected.as_deref().unwrap().contains("pkcs1v15"));
        let err = parse_scheme("md5", &[RsaScheme::Oaep], "scheme").unwrap_err();
        assert!(err.message.contains("unknown RSA scheme"));
    }

    #[test]
    fn digest_parsing_defaults_and_rejects() {
        assert_eq!(
            parse_digest(None).unwrap().label(),
            "sha256",
            "OAEP defaults to SHA-256"
        );
        assert_eq!(parse_digest(Some("SHA-1")).unwrap().label(), "sha1");
        let err = parse_digest(Some("md5")).unwrap_err();
        assert_eq!(err.kind, "unsupported");
    }

    #[test]
    fn ecdsa_param_parsing() {
        assert!(matches!(
            parse_ecdsa_digest("sha256").unwrap(),
            pki::EcdsaDigest::Sha256
        ));
        assert!(matches!(
            parse_signature_format(None).unwrap(),
            pki::EcdsaSignatureFormat::Der
        ));
        assert!(matches!(
            parse_nonce_mode(Some("random")).unwrap(),
            pki::EcdsaNonceMode::Random
        ));
        assert!(parse_ecdsa_digest("sha512").is_err());
        assert!(parse_signature_format(Some("raw")).is_err());
        assert!(parse_nonce_mode(Some("fixed")).is_err());
    }

    #[test]
    fn hint_parsing() {
        assert!(parse_hint(None).unwrap().is_none());
        assert_eq!(parse_hint(Some("rsa")).unwrap(), Some(Hint::Rsa));
        assert_eq!(parse_hint(Some("sm2")).unwrap(), Some(Hint::Sm2));
        assert_eq!(
            parse_hint(Some("secp256r1")).unwrap(),
            Some(Hint::Curve(pki::EccCurve::P256))
        );
        assert!(parse_hint(Some("curve9999")).is_err());
    }

    #[test]
    fn oversize_input_rejected() {
        let big = "a".repeat(MAX_TEXT_INPUT + 1);
        let err = inspect_key(&big, None).unwrap_err();
        assert_eq!(err.kind, "invalid_param");
        assert_eq!(err.parameter.as_deref(), Some("material"));
    }

    // -------------------------------------------------- key inspection ----

    #[test]
    fn inspect_rsa_private_pem() {
        let keypair = sample_rsa_keypair();
        let pem = keypair.to_pkcs8_pem().unwrap();
        let report = inspect_key(&pem, None).unwrap();
        assert_eq!(report.kind, "rsa");
        assert!(report.is_private);
        assert_eq!(report.bit_length, Some(1024));
        assert_eq!(report.source_format, "pem_pkcs8");
        assert!(report.private_fields.iter().any(|f| f.label == "d"));
        assert!(report
            .encodings
            .iter()
            .any(|f| f.label == "SPKI public PEM" && f.value.contains("BEGIN PUBLIC KEY")));
    }

    #[test]
    fn inspect_rsa_public_pkcs1_pem() {
        let keypair = sample_rsa_keypair();
        let pem = keypair.to_public_pkcs1_pem().unwrap();
        let report = inspect_key(&pem, None).unwrap();
        assert_eq!(report.kind, "rsa");
        assert!(!report.is_private);
        assert_eq!(report.source_format, "pem_pkcs1");
        assert!(report.private_fields.is_empty());
    }

    #[test]
    fn inspect_ecc_pkcs8_pem_autodetects_curve() {
        let keypair = sample_ecc_keypair(pki::EccCurve::P384);
        let pem =
            pki::ecc_private_key_to_pkcs8_pem(pki::EccCurve::P384, &keypair.private_hex).unwrap();
        let report = inspect_key(&pem, None).unwrap();
        assert_eq!(report.kind, "ec");
        assert_eq!(report.curve.as_deref(), Some("p384"));
        assert_eq!(report.bit_length, Some(384));
    }

    #[test]
    fn inspect_ec_spki_pem_falls_back_from_rsa_parse() {
        let keypair = sample_ecc_keypair(pki::EccCurve::P256);
        let pem =
            pki::ecc_public_key_to_spki_pem(pki::EccCurve::P256, &keypair.public_uncompressed_hex)
                .unwrap();
        let report = inspect_key(&pem, None).unwrap();
        assert_eq!(report.kind, "ec");
        assert_eq!(report.curve.as_deref(), Some("p256"));
        assert!(!report.is_private);
    }

    #[test]
    fn inspect_jwk_roundtrip() {
        let keypair = sample_rsa_keypair();
        let json = pki::jwk_to_json(&pki::keypair_to_jwk(&keypair)).unwrap();
        let report = inspect_key(&json, None).unwrap();
        assert_eq!(report.kind, "rsa");
        assert!(report.is_private);
        assert_eq!(report.source_format, "jwk");
    }

    #[test]
    fn inspect_raw_scalar_reports_alternatives() {
        let keypair = sample_ecc_keypair(pki::EccCurve::Ed25519);
        let report = inspect_key(&keypair.private_hex, None).unwrap();
        // The seed is a valid Ed25519 private key; other interpretations may
        // or may not also validate, so only the primary kind is asserted.
        assert_eq!(report.kind, "ed25519");
        for name in &report.alternatives {
            assert!(!name.contains("ed25519 private"), "primary leaked: {name}");
        }
    }

    #[test]
    fn inspect_raw_sec1_public_with_curve_hint() {
        let keypair = sample_ecc_keypair(pki::EccCurve::P256);
        let report = inspect_key(&keypair.public_uncompressed_hex, Some("p256")).unwrap();
        assert_eq!(report.kind, "ec");
        assert_eq!(report.curve.as_deref(), Some("p256"));
        assert_eq!(report.source_format, "hex_sec1");
        assert!(
            report.alternatives.is_empty(),
            "hint restricts to one curve"
        );
    }

    #[test]
    fn inspect_hex_der_spki() {
        let keypair = sample_rsa_keypair();
        let der_hex = to_hex(&keypair.to_public_spki_der().unwrap());
        let report = inspect_key(&der_hex, None).unwrap();
        assert_eq!(report.kind, "rsa");
        assert!(!report.is_private);
        assert_eq!(report.source_format, "der_spki");
    }

    #[test]
    fn inspect_rejects_certificate_pem_with_engine_error() {
        let err = inspect_key(CA_CERT_PEM, None).unwrap_err();
        assert_eq!(err.kind, "invalid_input");
        assert!(err.message.contains("wrong PEM object type"));
        assert!(err
            .details
            .as_deref()
            .unwrap_or_default()
            .contains("certificate"));
    }

    #[test]
    fn inspect_empty_and_garbage() {
        assert!(inspect_key("   ", None).is_err());
        let err = inspect_key("zzzz-not-any-format", None).unwrap_err();
        assert!(err.message.contains("unrecognized key material"));
        // A valid hex blob that is no known structure gets the "could not
        // interpret" error with the accepted-shapes hint attached.
        let err = inspect_key("00", None).unwrap_err();
        assert!(err.message.contains("could not interpret"));
        assert!(err.expected.is_some());
    }

    // ---------------------------------------------------- RSA operations --

    #[test]
    fn rsa_keygen_enforces_engine_sizes() {
        assert!(rsa_keygen(PkiRsaKeygenRequest { bits: 512 }).is_err());
        let result = rsa_keygen(PkiRsaKeygenRequest { bits: 1024 }).unwrap();
        assert!(result.private_pem.contains("BEGIN PRIVATE KEY"));
        assert!(result.public_pem.contains("BEGIN PUBLIC KEY"));
        assert!(result.private_pkcs1_pem.contains("BEGIN RSA PRIVATE KEY"));
        assert!(result.public_pkcs1_pem.contains("BEGIN RSA PUBLIC KEY"));
        assert_eq!(result.report.kind, "rsa");
    }

    #[test]
    fn rsa_encrypt_decrypt_roundtrip_both_schemes() {
        let keypair = sample_rsa_keypair();
        let private_pem = keypair.to_pkcs8_pem().unwrap();
        let public_pem = keypair.to_public_spki_pem().unwrap();

        for (scheme, hash) in [("oaep", Some("sha256")), ("pkcs1v15", None)] {
            let ct = rsa_encrypt(PkiRsaEncryptRequest {
                key_pem: public_pem.clone(),
                scheme: scheme.to_string(),
                hash: hash.map(str::to_string),
                label: None,
                plaintext_text: "attack at dawn".to_string(),
                plaintext_encoding: "utf8".to_string(),
            })
            .unwrap();
            assert_eq!(ct.scheme, scheme);
            let pt = rsa_decrypt(PkiRsaDecryptRequest {
                key_pem: private_pem.clone(),
                scheme: scheme.to_string(),
                hash: hash.map(str::to_string),
                label: None,
                ciphertext_text: ct.ciphertext.hex,
                ciphertext_encoding: "hex".to_string(),
            })
            .unwrap();
            assert_eq!(pt.plaintext.utf8.as_deref(), Some("attack at dawn"));
        }
    }

    #[test]
    fn rsa_encrypt_rejects_pss_scheme() {
        let keypair = sample_rsa_keypair();
        let err = rsa_encrypt(PkiRsaEncryptRequest {
            key_pem: keypair.to_public_spki_pem().unwrap(),
            scheme: "pss".to_string(),
            hash: None,
            label: None,
            plaintext_text: "x".to_string(),
            plaintext_encoding: "utf8".to_string(),
        })
        .unwrap_err();
        assert_eq!(err.kind, "invalid_param");
        assert!(err.message.contains("not valid for this operation"));
        assert!(err.expected.as_deref().unwrap().contains("pkcs1v15"));
    }

    #[test]
    fn rsa_sign_verify_roundtrip_pss_salt() {
        let keypair = sample_rsa_keypair();
        let sig = rsa_sign(PkiRsaSignRequest {
            key_pem: keypair.to_pkcs8_pem().unwrap(),
            scheme: "pss".to_string(),
            hash: "sha256".to_string(),
            salt_len: Some("zero".to_string()),
            data_text: "616263".to_string(),
            data_encoding: "hex".to_string(),
        })
        .unwrap();
        assert_eq!(sig.digest, "sha256");
        assert_eq!(sig.salt_len.as_deref(), Some("0"));
        let verdict = rsa_verify(PkiRsaVerifyRequest {
            key_pem: keypair.to_public_spki_pem().unwrap(),
            scheme: "pss".to_string(),
            hash: "sha256".to_string(),
            salt_len: Some("zero".to_string()),
            data_text: "616263".to_string(),
            data_encoding: "hex".to_string(),
            signature_text: sig.signature.hex,
        })
        .unwrap();
        assert!(verdict.valid, "reason: {:?}", verdict.reason);
    }

    // ---------------------------------------------------- ECC operations --

    #[test]
    fn ecc_keygen_all_curves_produce_pem_and_hex() {
        for curve in ECC_CURVES {
            let result = ecc_keygen(PkiEccKeygenRequest {
                curve: curve.label().to_string(),
            })
            .unwrap();
            assert_eq!(result.curve, curve.label());
            assert!(!result.private_hex.is_empty());
            assert!(result.private_pkcs8_pem.contains("BEGIN PRIVATE KEY"));
            assert!(result.public_spki_pem.contains("BEGIN PUBLIC KEY"));
            assert_eq!(
                result.report.kind,
                if matches!(curve, pki::EccCurve::P256 | pki::EccCurve::P384) {
                    "ec"
                } else {
                    curve.label()
                }
            );
        }
        assert!(ecc_keygen(PkiEccKeygenRequest {
            curve: "p521".to_string(),
        })
        .is_err());
    }

    #[test]
    fn ecdsa_sign_verify_roundtrip_and_wrong_data() {
        let keypair = sample_ecc_keypair(pki::EccCurve::P256);
        let sig = ecdsa_sign(PkiEcdsaSignRequest {
            curve: "p256".to_string(),
            private_hex: keypair.private_hex.clone(),
            digest: "sha256".to_string(),
            format: Some("fixed".to_string()),
            nonce: None,
            data_text: "hello".to_string(),
            data_encoding: "utf8".to_string(),
        })
        .unwrap();
        assert_eq!(sig.signature_hex.len(), 128, "fixed r||s is 64 bytes");
        let verdict = ecdsa_verify(PkiEcdsaVerifyRequest {
            curve: "p256".to_string(),
            public_hex: keypair.public_uncompressed_hex.clone(),
            digest: "sha256".to_string(),
            format: Some("fixed".to_string()),
            data_text: "hello".to_string(),
            data_encoding: "utf8".to_string(),
            signature_hex: sig.signature_hex.clone(),
        })
        .unwrap();
        assert!(verdict.valid);
        // Tampered data with a well-formed signature is a valid:false
        // verdict, not an error.
        let verdict = ecdsa_verify(PkiEcdsaVerifyRequest {
            curve: "p256".to_string(),
            public_hex: keypair.public_uncompressed_hex.clone(),
            digest: "sha256".to_string(),
            format: Some("fixed".to_string()),
            data_text: "hellO".to_string(),
            data_encoding: "utf8".to_string(),
            signature_hex: sig.signature_hex.clone(),
        })
        .unwrap();
        assert!(!verdict.valid);
        // A malformed (all-zero r/s) signature is a typed error instead.
        let err = ecdsa_verify(PkiEcdsaVerifyRequest {
            curve: "p256".to_string(),
            public_hex: keypair.public_uncompressed_hex,
            digest: "sha256".to_string(),
            format: Some("fixed".to_string()),
            data_text: "hello".to_string(),
            data_encoding: "utf8".to_string(),
            signature_hex: "00".repeat(64),
        })
        .unwrap_err();
        assert_eq!(err.kind, "decode");
    }

    #[test]
    fn ecdsa_rejects_mismatched_digest_pairing() {
        let keypair = sample_ecc_keypair(pki::EccCurve::P384);
        let err = ecdsa_sign(PkiEcdsaSignRequest {
            curve: "p384".to_string(),
            private_hex: keypair.private_hex,
            digest: "sha256".to_string(),
            format: None,
            nonce: None,
            data_text: "hello".to_string(),
            data_encoding: "utf8".to_string(),
        })
        .unwrap_err();
        // The engine's typed pairing error passes through verbatim.
        assert_eq!(err.kind, "invalid_param");
        assert_eq!(err.parameter.as_deref(), Some("digest"));
    }

    #[test]
    fn ecdh_and_x25519_shared_secrets_agree() {
        let a = sample_ecc_keypair(pki::EccCurve::P256);
        let b = sample_ecc_keypair(pki::EccCurve::P256);
        let ab = ecdh(PkiEcdhRequest {
            curve: "p256".to_string(),
            private_hex: a.private_hex.clone(),
            peer_public_hex: b.public_uncompressed_hex.clone(),
        })
        .unwrap();
        let ba = ecdh(PkiEcdhRequest {
            curve: "p256".to_string(),
            private_hex: b.private_hex,
            peer_public_hex: a.public_uncompressed_hex,
        })
        .unwrap();
        assert_eq!(ab.shared_secret_hex, ba.shared_secret_hex);
        assert_eq!(ab.shared_secret_hex.len(), 64);

        let a = sample_ecc_keypair(pki::EccCurve::X25519);
        let b = sample_ecc_keypair(pki::EccCurve::X25519);
        let ab = x25519(PkiX25519Request {
            private_hex: a.private_hex.clone(),
            peer_public_hex: b.public_compressed_hex.clone(),
        })
        .unwrap();
        let ba = x25519(PkiX25519Request {
            private_hex: b.private_hex,
            peer_public_hex: a.public_compressed_hex,
        })
        .unwrap();
        assert_eq!(ab.shared_secret_hex, ba.shared_secret_hex);
    }

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let keypair = sample_ecc_keypair(pki::EccCurve::Ed25519);
        let sig = ed25519_sign(PkiEd25519SignRequest {
            private_hex: keypair.private_hex.clone(),
            data_text: "msg".to_string(),
            data_encoding: "utf8".to_string(),
        })
        .unwrap();
        assert_eq!(sig.signature_hex.len(), 128);
        let verdict = ed25519_verify(PkiEd25519VerifyRequest {
            public_hex: keypair.public_compressed_hex,
            data_text: "msg".to_string(),
            data_encoding: "utf8".to_string(),
            signature_hex: sig.signature_hex,
        })
        .unwrap();
        assert!(verdict.valid);
    }

    // ---------------------------------------------------- SM2 operations --

    #[test]
    fn sm2_keygen_report_and_sign_verify() {
        let keygen = sm2_keygen().unwrap();
        assert_eq!(keygen.report.kind, "sm2");
        assert_eq!(keygen.private_hex.len(), 64);

        let sig = sm2_sign(PkiSm2SignRequest {
            private_hex: keygen.private_hex.clone(),
            data_text: "68656c6c6f".to_string(),
            data_encoding: "hex".to_string(),
            user_id: None,
        })
        .unwrap();
        assert_eq!(sig.user_id, pki::SM2_DEFAULT_USER_ID);
        let verdict = sm2_verify(PkiSm2VerifyRequest {
            public_hex: keygen.public_uncompressed_hex.clone(),
            data_text: "68656c6c6f".to_string(),
            data_encoding: "hex".to_string(),
            signature_hex: sig.signature_hex.clone(),
            user_id: None,
        })
        .unwrap();
        assert!(verdict.valid);
        // A different user ID must invalidate the signature (ZA context).
        let verdict = sm2_verify(PkiSm2VerifyRequest {
            public_hex: keygen.public_uncompressed_hex,
            data_text: "68656c6c6f".to_string(),
            data_encoding: "hex".to_string(),
            signature_hex: sig.signature_hex,
            user_id: Some("other-id@example".to_string()),
        })
        .unwrap();
        assert!(!verdict.valid);
    }

    #[test]
    fn sm2_encrypt_decrypt_roundtrip() {
        let keygen = sm2_keygen().unwrap();
        let ct = sm2_encrypt(PkiSm2EncryptRequest {
            public_hex: keygen.public_uncompressed_hex,
            plaintext_text: "sm2 secret".to_string(),
            plaintext_encoding: "utf8".to_string(),
        })
        .unwrap();
        // 65 (C1) + 32 (C3) + plaintext length.
        assert_eq!(ct.ciphertext.size, 65 + 32 + "sm2 secret".len());
        let pt = sm2_decrypt(PkiSm2DecryptRequest {
            private_hex: keygen.private_hex,
            ciphertext_text: ct.ciphertext.hex,
            ciphertext_encoding: "hex".to_string(),
        })
        .unwrap();
        assert_eq!(pt.plaintext.utf8.as_deref(), Some("sm2 secret"));
    }

    // -------------------------------------------------- cert inspection ----

    #[test]
    fn cert_inspect_pem_certificate_with_asn1_tree() {
        let report = cert_inspect(PkiCertInspectRequest {
            material: CA_CERT_PEM.to_string(),
        })
        .unwrap();
        assert_eq!(report.object_type, "certificate");
        assert_eq!(report.pem_label.as_deref(), Some("CERTIFICATE"));
        let cert = report.certificate.as_ref().unwrap();
        assert_eq!(cert.version, 2);
        assert!(!cert.fingerprint_sha256.is_empty());
        assert!(report.csr.is_none() && report.crl.is_none());
        assert_eq!(report.asn1_tree.len(), 1, "one root DER node");
        assert!(!report.asn1_tree[0].children.is_empty());
    }

    #[test]
    fn cert_inspect_der_hex_and_routing() {
        let report = cert_inspect(PkiCertInspectRequest {
            material: CA_CERT_PEM.to_string(),
        })
        .unwrap();
        // The same DER pasted as hex must route to the certificate inspector.
        let der_report = cert_inspect(PkiCertInspectRequest {
            material: report.der_hex.clone(),
        })
        .unwrap();
        assert_eq!(der_report.object_type, "certificate");
        assert_eq!(der_report.pem_label, None);
        assert_eq!(der_report.der_hex, report.der_hex);
    }

    #[test]
    fn cert_inspect_rejects_a_key_pem() {
        let keypair = sample_rsa_keypair();
        let err = cert_inspect(PkiCertInspectRequest {
            material: keypair.to_public_spki_pem().unwrap(),
        })
        .unwrap_err();
        assert_eq!(err.kind, "invalid_input");
        assert!(err.message.contains("wrong PEM object type"));
    }

    #[test]
    fn cert_inspect_empty_and_oversize() {
        let err = cert_inspect(PkiCertInspectRequest {
            material: "  ".to_string(),
        })
        .unwrap_err();
        assert_eq!(err.kind, "invalid_input");
        let big = "a".repeat(MAX_TEXT_INPUT + 1);
        let err = cert_inspect(PkiCertInspectRequest { material: big }).unwrap_err();
        assert_eq!(err.kind, "invalid_param");
    }

    // -------------------------------------------------------- transport ----

    #[test]
    fn pki_bytes_utf8_and_size() {
        let b = PkiBytes::new(b"hello");
        assert_eq!(b.hex, "68656c6c6f");
        assert_eq!(b.utf8.as_deref(), Some("hello"));
        assert_eq!(b.size, 5);
        let b = PkiBytes::new(&[0xff, 0x00]);
        assert!(b.utf8.is_none());
    }

    #[test]
    fn hex_decode_strict_rejects_odd_and_nonhex() {
        assert!(hex_decode_strict("abc").is_err());
        assert!(hex_decode_strict("zz").is_err());
        assert!(hex_decode_strict("").is_err());
        assert_eq!(hex_decode_strict("00ff").unwrap(), vec![0x00, 0xff]);
    }
}
