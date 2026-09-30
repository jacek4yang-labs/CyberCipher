//! Generic DER/ASN.1 tree inspector — the "show me the structure" tool that
//! backs the GUI's DER viewer and the odd-blob triage workflows.
//!
//! This is a *pure decoder*, not a validator: it walks tag-length-value
//! triples and renders what it finds (OIDs as dotted strings with names from
//! a small well-known-OID table, INTEGERs as decimal where they fit, common
//! string/time types as text, everything else as a bounded hex preview).
//! Anything that cannot be decoded stays visible as raw hex instead of failing
//! the whole tree — the caller asked "what is this", not "is this valid".
//!
//! Hard bounds (the input is always treated as untrusted):
//! - input size capped at [`MAX_INPUT_SIZE`] bytes;
//! - recursion capped at an explicit `max_depth` (default [`DEFAULT_MAX_DEPTH`]);
//! - multi-byte lengths capped at 4 length bytes (DER lengths beyond 4 GiB are
//!   meaningless here) and checked against the remaining input;
//! - indefinite (BER) lengths are rejected — DER only.
//!
//! [`parse_der_tree`] expects exactly one top-level TLV: trailing bytes after
//! the root object are a typed error. [`parse_der_nodes`] accepts a stream of
//! concatenated DER objects instead.

use serde::{Deserialize, Serialize};

use crate::error::{PkiError, PkiResult};
use crate::keys::to_hex;

/// Default recursion cap for [`parse_der_tree`].
pub const DEFAULT_MAX_DEPTH: usize = 32;

/// Upper bound on accepted input size (1 MiB). DER blobs beyond this are
/// almost certainly mislabeled binaries, and capping keeps the recursive
/// walk and the JSON render bounded.
pub const MAX_INPUT_SIZE: usize = 1 << 20;

/// Hex preview width for undecoded primitive values.
const HEX_PREVIEW_BYTES: usize = 64;

// ---------------------------------------------------------------------------
// Transport structs (serde boundary)
// ---------------------------------------------------------------------------

/// ASN.1 tag class (X.690 section 8.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Asn1Class {
    Universal,
    Application,
    Context,
    Private,
}

impl Asn1Class {
    /// Canonical lowercase label (`"universal"`, ...).
    pub fn label(&self) -> &'static str {
        match self {
            Asn1Class::Universal => "universal",
            Asn1Class::Application => "application",
            Asn1Class::Context => "context",
            Asn1Class::Private => "private",
        }
    }

    fn from_bits(bits: u8) -> Self {
        match bits {
            0b00 => Asn1Class::Universal,
            0b01 => Asn1Class::Application,
            0b10 => Asn1Class::Context,
            _ => Asn1Class::Private,
        }
    }
}

/// Decoded content of a node for the common universal types. Everything the
/// inspector cannot confidently decode stays out of this enum — those nodes
/// carry a `hex_preview` on [`Asn1Node`] instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Asn1Value {
    /// INTEGER / ENUMERATED. `value` is the decimal rendering when the
    /// magnitude fits in 8 bytes (two's complement for negatives), otherwise
    /// a signed hex rendering; `hex` is always the raw two's-complement bytes.
    Integer {
        value: String,
        hex: String,
    },
    /// BOOLEAN (DER: 0x00 = false, 0xff = true).
    Boolean {
        value: bool,
    },
    /// NULL (empty value).
    Null,
    /// OBJECT IDENTIFIER, rendered dotted with a well-known name when known.
    ObjectIdentifier {
        dotted: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    Utf8String {
        text: String,
    },
    PrintableString {
        text: String,
    },
    Ia5String {
        text: String,
    },
    NumericString {
        text: String,
    },
    VisibleString {
        text: String,
    },
    /// UTCTime (RFC 5280: `YYMMDDHHMMSSZ`), raw content string.
    UtcTime {
        text: String,
    },
    /// GeneralizedTime, raw content string.
    GeneralizedTime {
        text: String,
    },
    /// BIT STRING minus the leading unused-bits octet.
    BitString {
        hex: String,
        unused_bits: u8,
    },
    /// OCTET STRING as raw hex.
    OctetString {
        hex: String,
    },
    /// Content that exists but could not be decoded as its tag promised
    /// (malformed OID, invalid UTF-8, non-empty NULL, ...). The tree stays
    /// browsable; see the node's `hex_preview`.
    Raw {
        hex: String,
    },
}

/// One node of the DER tree. Serde-serializable (snake_case) for the GUI;
/// `children`/`value`/`hex_preview` are omitted when empty so the JSON stays
/// compact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asn1Node {
    /// Tag class (universal / application / context / private).
    pub tag_class: Asn1Class,
    /// Tag number within the class (the low 5 bits, or the decoded
    /// base-128 value for high tag numbers).
    pub tag_number: u32,
    /// Standard name for universal tags ("SEQUENCE", "INTEGER", ...);
    /// `None` for the other classes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag_name: Option<String>,
    /// True when the TLV is constructed (has children).
    pub constructed: bool,
    /// Absolute offset of this TLV's identifier octet in the input.
    pub offset: usize,
    /// Bytes of the identifier + length headers.
    pub header_len: usize,
    /// Absolute offset of the value bytes.
    pub value_offset: usize,
    /// Length of the value bytes (the DER length field).
    pub value_len: usize,
    /// Total TLV size (`header_len + value_len`).
    pub total_len: usize,
    /// Decoded content for common universal types.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Asn1Value>,
    /// Child nodes (constructed TLVs only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<Asn1Node>,
    /// Bounded hex preview for primitive values with no decoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hex_preview: Option<String>,
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Parse a single top-level DER object into a tree of [`Asn1Node`]s. The
/// returned vec always has exactly one root; trailing bytes after the root
/// TLV are a typed error (see [`parse_der_nodes`] for concatenated objects).
///
/// `max_depth` caps recursion (use [`DEFAULT_MAX_DEPTH`] unless you know
/// better); `0` is rejected as a parameter error and exceeding the cap is a
/// typed `InvalidInput` error.
pub fn parse_der_tree(data: &[u8], max_depth: usize) -> PkiResult<Vec<Asn1Node>> {
    check_depth_param(max_depth)?;
    check_input_size(data)?;
    let root = parse_node(data, 0, data.len(), 1, max_depth)?;
    if root.total_len < data.len() {
        return Err(trailing_bytes(data.len() - root.total_len));
    }
    Ok(vec![root])
}

/// Parse the input as a *stream* of consecutive top-level DER TLVs (e.g. a
/// file concatenating several objects) and render each as a tree. Bounds are
/// the same as [`parse_der_tree`]; trailing data is impossible by
/// construction here.
pub fn parse_der_nodes(data: &[u8], max_depth: usize) -> PkiResult<Vec<Asn1Node>> {
    check_depth_param(max_depth)?;
    check_input_size(data)?;
    let mut nodes = Vec::new();
    let mut cursor = 0;
    while cursor < data.len() {
        let node = parse_node(data, cursor, data.len(), 1, max_depth)?;
        cursor += node.total_len;
        nodes.push(node);
    }
    Ok(nodes)
}

fn check_depth_param(max_depth: usize) -> PkiResult<()> {
    if max_depth == 0 {
        return Err(
            PkiError::invalid_param("max_depth", "maximum DER depth must be at least 1")
                .with_expected(format!(">= 1 (default {DEFAULT_MAX_DEPTH})"))
                .with_actual(max_depth.to_string()),
        );
    }
    Ok(())
}

fn check_input_size(data: &[u8]) -> PkiResult<()> {
    if data.len() > MAX_INPUT_SIZE {
        return Err(PkiError::invalid_input("DER input exceeds the size cap")
            .with_parameter("der")
            .with_expected(format!("at most {MAX_INPUT_SIZE} bytes"))
            .with_actual(format!("{} bytes", data.len())));
    }
    Ok(())
}

fn trailing_bytes(extra: usize) -> PkiError {
    PkiError::decode(format!("{extra} trailing bytes after the DER object"))
        .with_expected("the input to end after the final TLV")
        .with_actual(format!("{extra} trailing bytes"))
        .with_details("use parse_der_nodes to inspect a stream of concatenated DER objects")
}

// ---------------------------------------------------------------------------
// Recursive TLV walk
// ---------------------------------------------------------------------------

/// Parse one TLV at `offset`, bounded by `end` (the parent's value end, or
/// the input end for top-level nodes). `depth` is 1 for a root node;
/// `max_depth` is the inclusive cap. Every failure is a typed error.
///
/// Node offsets are always absolute (relative to `data`), which is what the
/// GUI hex view needs.
fn parse_node(
    data: &[u8],
    offset: usize,
    end: usize,
    depth: usize,
    max_depth: usize,
) -> PkiResult<Asn1Node> {
    if depth > max_depth {
        return Err(depth_exceeded(max_depth, depth));
    }
    // Invariant: end <= data.len() holds for every recursion level (children
    // are bounded by the parent's value end, the root by data.len()).
    let Some(rest) = data.get(offset..end) else {
        return Err(truncated(offset, "identifier"));
    };
    if rest.len() < 2 {
        return Err(truncated(offset, "identifier + length headers"));
    }

    // -- identifier octet(s)
    let tag_byte = rest[0];
    let tag_class = Asn1Class::from_bits(tag_byte >> 6);
    let constructed = tag_byte & 0x20 != 0;
    let mut tag_number = (tag_byte & 0x1f) as u32;
    let mut header_len = 2usize; // identifier + (at least) one length octet
    if tag_number == 0x1f {
        // High tag number form: base-128 continuation octets.
        tag_number = 0;
        let mut i = 1;
        loop {
            let Some(&b) = rest.get(i) else {
                return Err(truncated(offset + i, "high tag number continuation"));
            };
            tag_number = tag_number
                .checked_mul(128)
                .and_then(|v| v.checked_add((b & 0x7f) as u32))
                .ok_or_else(|| decode_error(offset + i, "high tag number overflows 32 bits"))?;
            if b & 0x80 == 0 {
                header_len += i; // identifier: initial octet + i continuations
                break;
            }
            i += 1;
            if i > 5 {
                return Err(decode_error(
                    offset + i,
                    "high tag number longer than 5 continuation octets",
                )
                .with_expected("<= 5 continuation octets"));
            }
        }
    }

    // -- length octets (DER: definite only)
    let first_len = rest[header_len - 1];
    let value_len: usize = match first_len {
        0x80 => {
            return Err(decode_error(
                offset + header_len - 1,
                "indefinite length (0x80) is BER, not DER",
            )
            .with_expected("definite length encoding"));
        }
        0..=0x7f => first_len as usize,
        n => {
            let len_octets = (n & 0x7f) as usize;
            if len_octets > 4 {
                return Err(decode_error(
                    offset + header_len - 1,
                    format!("long-form length uses {len_octets} octets (cap is 4)"),
                )
                .with_expected("<= 4 length octets"));
            }
            if rest.len() < header_len + len_octets {
                return Err(truncated(offset + rest.len(), "long-form length octets"));
            }
            let mut len: usize = 0;
            for &b in &rest[header_len..header_len + len_octets] {
                len = len
                    .checked_mul(256)
                    .and_then(|v| v.checked_add(b as usize))
                    .ok_or_else(|| {
                        decode_error(offset + header_len, "declared length overflows usize")
                    })?;
            }
            header_len += len_octets;
            len
        }
    };

    let value_offset = offset + header_len;
    let value_end = value_offset
        .checked_add(value_len)
        .ok_or_else(|| decode_error(offset, "declared length overflows usize"))?;
    if value_end > end {
        return Err(PkiError::decode(format!(
            "DER value extends past the enclosing boundary: declared {value_len} bytes \
             at offset {value_offset} but only {} remain",
            end - value_offset
        ))
        .with_expected("length field within the enclosing object")
        .with_actual(format!("{value_len} bytes declared")));
    }
    let value = &data[value_offset..value_end];

    // -- children (constructed) or decoded value (primitive)
    let mut children = Vec::new();
    if constructed {
        let child_depth = depth + 1;
        let mut cursor = value_offset;
        while cursor < value_end {
            let child = parse_node(data, cursor, value_end, child_depth, max_depth)?;
            cursor += child.total_len;
            children.push(child);
        }
    }

    let mut node = Asn1Node {
        tag_class,
        tag_number,
        tag_name: universal_tag_name(tag_class, tag_number),
        constructed,
        offset,
        header_len,
        value_offset,
        value_len,
        total_len: header_len + value_len,
        value: None,
        children,
        hex_preview: None,
    };

    if !constructed {
        decode_primitive(&mut node, value);
    }
    Ok(node)
}

/// Decode the value bytes of a primitive TLV into `node.value`, falling back
/// to `hex_preview` for anything undecodable.
fn decode_primitive(node: &mut Asn1Node, value: &[u8]) {
    if node.tag_class != Asn1Class::Universal {
        node.hex_preview = Some(hex_preview(value));
        return;
    }
    let decoded = match node.tag_number {
        // BOOLEAN: exactly one octet (0x00 or 0xff in DER).
        1 => match value {
            [b] => Decoded::Value(Asn1Value::Boolean { value: *b != 0 }),
            _ => Decoded::Raw,
        },
        // INTEGER / ENUMERATED share the encoding; DER forbids empty values.
        2 | 10 => {
            if value.is_empty() {
                Decoded::Raw
            } else {
                Decoded::Value(Asn1Value::Integer {
                    value: integer_value(value),
                    hex: to_hex(value),
                })
            }
        }
        // BIT STRING: first octet counts unused bits in the last octet.
        3 => match value.split_first() {
            Some((unused, bits)) if *unused <= 7 => Decoded::Value(Asn1Value::BitString {
                hex: to_hex(bits),
                unused_bits: *unused,
            }),
            _ => Decoded::Raw,
        },
        4 => Decoded::Value(Asn1Value::OctetString { hex: to_hex(value) }),
        5 => {
            if value.is_empty() {
                Decoded::Value(Asn1Value::Null)
            } else {
                Decoded::Raw
            }
        }
        6 => match decode_oid(value) {
            Some(dotted) => Decoded::Value(Asn1Value::ObjectIdentifier {
                name: oid_name(&dotted).map(str::to_string),
                dotted,
            }),
            None => Decoded::Raw,
        },
        12 => string_value(value, utf8_string),
        18 => string_value(value, numeric_string),
        19 => string_value(value, printable_string),
        // T61String (teletex) is technically latin-1; valid UTF-8 still
        // renders as text, anything else stays raw hex.
        20 | 22 => string_value(value, ia5_string),
        23 => string_value(value, utc_time),
        24 => string_value(value, generalized_time),
        26 => string_value(value, visible_string),
        // No decode path for this tag: bounded hex preview.
        _ => Decoded::NoDecoder,
    };
    match decoded {
        Decoded::Value(v) => node.value = Some(v),
        Decoded::Raw => node.value = Some(Asn1Value::Raw { hex: to_hex(value) }),
        Decoded::NoDecoder => node.hex_preview = Some(hex_preview(value)),
    }
}

/// Outcome of attempting to decode a primitive value.
enum Decoded {
    /// Decoded into the given shape.
    Value(Asn1Value),
    /// The tag has a decode path but the content violates it — keep the node
    /// browsable as a [`Asn1Value::Raw`] hex blob.
    Raw,
    /// No decode path exists for this tag — bounded hex preview instead.
    NoDecoder,
}

// Struct-variant constructors usable as `fn(String) -> Asn1Value`.
fn utf8_string(text: String) -> Asn1Value {
    Asn1Value::Utf8String { text }
}
fn numeric_string(text: String) -> Asn1Value {
    Asn1Value::NumericString { text }
}
fn printable_string(text: String) -> Asn1Value {
    Asn1Value::PrintableString { text }
}
fn ia5_string(text: String) -> Asn1Value {
    Asn1Value::Ia5String { text }
}
fn visible_string(text: String) -> Asn1Value {
    Asn1Value::VisibleString { text }
}
fn utc_time(text: String) -> Asn1Value {
    Asn1Value::UtcTime { text }
}
fn generalized_time(text: String) -> Asn1Value {
    Asn1Value::GeneralizedTime { text }
}

/// ASCII-family string decode (PrintableString, IA5String, VisibleString,
/// NumericString, T61String, UTCTime, GeneralizedTime): valid UTF-8 becomes
/// text of the requested shape, anything else stays browsable as a Raw hex
/// blob.
fn string_value(value: &[u8], make: fn(String) -> Asn1Value) -> Decoded {
    match core::str::from_utf8(value) {
        Ok(text) => Decoded::Value(make(text.to_string())),
        Err(_) => Decoded::Raw,
    }
}

/// Decimal rendering of a DER INTEGER (two's complement). Fits i64 ->
/// decimal; otherwise a signed hex rendering so arbitrarily large moduli
/// stay visible.
fn integer_value(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "0".to_string();
    }
    if bytes.len() <= 8 {
        let mut v: u128 = 0;
        for &b in bytes {
            v = (v << 8) | b as u128;
        }
        let shift = 128 - bytes.len() * 8;
        let signed = ((v << shift) as i128) >> shift;
        return signed.to_string();
    }
    if bytes[0] & 0x80 == 0 {
        return format!("0x{}", trim_hex(&to_hex(bytes)));
    }
    // Negative: magnitude is the two's complement negation.
    let mut neg: Vec<u8> = bytes.iter().map(|b| !b).collect();
    for b in neg.iter_mut().rev() {
        match *b {
            0xff => *b = 0,
            _ => {
                *b += 1;
                break;
            }
        }
    }
    format!("-0x{}", trim_hex(&to_hex(&neg)))
}

fn trim_hex(hex: &str) -> String {
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Decode an OBJECT IDENTIFIER value into its dotted string (X.690 section
/// 8.19). Returns `None` for empty or truncated encodings.
fn decode_oid(bytes: &[u8]) -> Option<String> {
    let (&first, rest) = bytes.split_first()?;
    let mut arcs: Vec<String> = Vec::with_capacity(rest.len() + 2);
    match first {
        0..=39 => arcs.extend(["0".to_string(), first.to_string()]),
        40..=79 => arcs.extend(["1".to_string(), (first - 40).to_string()]),
        _ => arcs.extend(["2".to_string(), (first - 80).to_string()]),
    }
    let mut acc: u128 = 0;
    let mut in_progress = false;
    for &b in rest {
        in_progress = true;
        if acc > (u128::MAX >> 7) {
            return None;
        }
        acc = (acc << 7) | (b & 0x7f) as u128;
        if b & 0x80 == 0 {
            arcs.push(acc.to_string());
            acc = 0;
            in_progress = false;
        }
    }
    if in_progress {
        return None;
    }
    Some(arcs.join("."))
}

/// Bounded hex preview: the first [`HEX_PREVIEW_BYTES`] bytes plus an
/// ellipsis marker when truncated.
fn hex_preview(bytes: &[u8]) -> String {
    if bytes.len() <= HEX_PREVIEW_BYTES {
        to_hex(bytes)
    } else {
        format!(
            "{}...(+{} bytes)",
            to_hex(&bytes[..HEX_PREVIEW_BYTES]),
            bytes.len() - HEX_PREVIEW_BYTES
        )
    }
}

fn universal_tag_name(class: Asn1Class, tag: u32) -> Option<String> {
    if class != Asn1Class::Universal {
        return None;
    }
    let name = match tag {
        0 => "EOC",
        1 => "BOOLEAN",
        2 => "INTEGER",
        3 => "BIT STRING",
        4 => "OCTET STRING",
        5 => "NULL",
        6 => "OBJECT IDENTIFIER",
        7 => "ObjectDescriptor",
        8 => "EXTERNAL",
        9 => "REAL",
        10 => "ENUMERATED",
        11 => "EMBEDDED PDV",
        12 => "UTF8String",
        13 => "RELATIVE-OID",
        16 => "SEQUENCE",
        17 => "SET",
        18 => "NumericString",
        19 => "PrintableString",
        20 => "T61String",
        21 => "VideotexString",
        22 => "IA5String",
        23 => "UTCTime",
        24 => "GeneralizedTime",
        25 => "GraphicString",
        26 => "VisibleString",
        27 => "GeneralString",
        28 => "UniversalString",
        29 => "CHARACTER STRING",
        30 => "BMPString",
        _ => return None,
    };
    Some(name.to_string())
}

// ---------------------------------------------------------------------------
// Typed error helpers
// ---------------------------------------------------------------------------

fn depth_exceeded(max_depth: usize, depth: usize) -> PkiError {
    PkiError::invalid_input("DER nesting exceeds the maximum depth")
        .with_parameter("max_depth")
        .with_expected(format!("nesting depth <= {max_depth}"))
        .with_actual(format!("depth {depth}"))
        .with_details(format!(
            "raise max_depth (default {DEFAULT_MAX_DEPTH}) to inspect deeper structures"
        ))
}

fn truncated(offset: usize, what: &str) -> PkiError {
    PkiError::decode(format!(
        "truncated DER: input ends inside {what} at offset {offset}"
    ))
    .with_expected("a complete TLV")
    .with_actual(format!("input ends at offset {offset}"))
}

fn decode_error(offset: usize, message: impl Into<String>) -> PkiError {
    PkiError::decode(message).with_details(format!("at offset {offset}"))
}

// ---------------------------------------------------------------------------
// Well-known OID table
// ---------------------------------------------------------------------------

/// Small well-known-OID table covering the identifiers that appear in the
/// X.509 material this crate inspects (names as commonly spelled in RFC 5280
/// and the RustCrypto crates). Unknown OIDs render as dotted numbers.
const WELL_KNOWN_OIDS: &[(&str, &str)] = &[
    // -- distinguished-name attribute types (X.520)
    ("2.5.4.3", "commonName"),
    ("2.5.4.4", "surname"),
    ("2.5.4.5", "serialNumber"),
    ("2.5.4.6", "countryName"),
    ("2.5.4.7", "localityName"),
    ("2.5.4.8", "stateOrProvinceName"),
    ("2.5.4.9", "streetAddress"),
    ("2.5.4.10", "organizationName"),
    ("2.5.4.11", "organizationalUnitName"),
    ("2.5.4.12", "title"),
    ("2.5.4.17", "postalCode"),
    ("2.5.4.42", "givenName"),
    ("2.5.4.43", "initials"),
    ("2.5.4.44", "generationQualifier"),
    ("2.5.4.45", "uniqueIdentifier"),
    ("2.5.4.46", "dnQualifier"),
    ("2.5.4.65", "pseudonym"),
    ("0.9.2342.19200300.100.1.1", "userID"),
    ("0.9.2342.19200300.100.1.25", "domainComponent"),
    ("1.2.840.113549.1.9.1", "emailAddress"),
    ("1.2.840.113549.1.9.2", "unstructuredName"),
    ("1.2.840.113549.1.9.3", "unstructuredAddress"),
    ("1.2.840.113549.1.9.7", "challengePassword"),
    ("1.2.840.113549.1.9.14", "extensionRequest"),
    // -- RSA / PKCS#1 algorithms
    ("1.2.840.113549.1.1.1", "rsaEncryption"),
    ("1.2.840.113549.1.1.4", "md5WithRSAEncryption"),
    ("1.2.840.113549.1.1.5", "sha1WithRSAEncryption"),
    ("1.2.840.113549.1.1.10", "rsassaPss"),
    ("1.2.840.113549.1.1.11", "sha256WithRSAEncryption"),
    ("1.2.840.113549.1.1.12", "sha384WithRSAEncryption"),
    ("1.2.840.113549.1.1.13", "sha512WithRSAEncryption"),
    ("1.2.840.113549.1.1.14", "sha224WithRSAEncryption"),
    // -- ECC algorithms and curves
    ("1.2.840.10045.2.1", "ecPublicKey"),
    ("1.2.840.10045.4.1", "ecdsa-with-SHA1"),
    ("1.2.840.10045.4.3.2", "ecdsa-with-SHA256"),
    ("1.2.840.10045.4.3.3", "ecdsa-with-SHA384"),
    ("1.2.840.10045.4.3.4", "ecdsa-with-SHA512"),
    ("1.2.840.10045.3.1.7", "prime256v1 (P-256)"),
    ("1.3.132.0.34", "secp384r1 (P-384)"),
    ("1.3.132.0.35", "secp521r1 (P-521)"),
    ("1.3.101.110", "X25519"),
    ("1.3.101.111", "X448"),
    ("1.3.101.112", "Ed25519"),
    ("1.3.101.113", "Ed448"),
    // -- X.509 extensions
    ("2.5.29.9", "subjectDirectoryAttributes"),
    ("2.5.29.14", "subjectKeyIdentifier"),
    ("2.5.29.15", "keyUsage"),
    ("2.5.29.16", "privateKeyUsagePeriod"),
    ("2.5.29.17", "subjectAltName"),
    ("2.5.29.18", "issuerAltName"),
    ("2.5.29.19", "basicConstraints"),
    ("2.5.29.20", "cRLNumber"),
    ("2.5.29.21", "cRLReason"),
    ("2.5.29.24", "invalidityDate"),
    ("2.5.29.27", "privateKeyUsagePeriod"),
    ("2.5.29.28", "issuingDistributionPoint"),
    ("2.5.29.30", "nameConstraints"),
    ("2.5.29.31", "cRLDistributionPoints"),
    ("2.5.29.32", "certificatePolicies"),
    ("2.5.29.33", "policyMappings"),
    ("2.5.29.35", "authorityKeyIdentifier"),
    ("2.5.29.36", "policyConstraints"),
    ("2.5.29.37", "extKeyUsage"),
    ("2.5.29.46", "freshestCRL"),
    ("1.3.6.1.5.5.7.1.1", "authorityInfoAccess"),
    ("1.3.6.1.5.5.7.1.11", "subjectInfoAccess"),
    // -- extended key usages
    ("1.3.6.1.5.5.7.3.1", "serverAuth"),
    ("1.3.6.1.5.5.7.3.2", "clientAuth"),
    ("1.3.6.1.5.5.7.3.3", "codeSigning"),
    ("1.3.6.1.5.5.7.3.4", "emailProtection"),
    ("1.3.6.1.5.5.7.3.5", "ipsecEndSystem"),
    ("1.3.6.1.5.5.7.3.6", "ipsecTunnel"),
    ("1.3.6.1.5.5.7.3.7", "ipsecUser"),
    ("1.3.6.1.5.5.7.3.8", "timeStamping"),
    ("1.3.6.1.5.5.7.3.9", "OCSPSigning"),
    ("2.5.29.37.0", "anyExtendedKeyUsage"),
];

/// Look up a dotted OID string in the well-known table.
pub fn oid_name(dotted: &str) -> Option<&'static str> {
    WELL_KNOWN_OIDS
        .iter()
        .find(|(oid, _)| *oid == dotted)
        .map(|(_, name)| *name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_decode_and_names() {
        // 2.5.4.3 = commonName (55 04 03)
        assert_eq!(decode_oid(&[0x55, 0x04, 0x03]), Some("2.5.4.3".to_string()));
        assert_eq!(oid_name("2.5.4.3"), Some("commonName"));
        // 1.2.840.113549.1.1.1 — multi-octet subidentifiers
        assert_eq!(
            decode_oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]),
            Some("1.2.840.113549.1.1.1".to_string())
        );
        assert_eq!(
            oid_name("1.2.840.113549.1.1.11"),
            Some("sha256WithRSAEncryption")
        );
        assert_eq!(oid_name("1.99.99.99.99"), None);
        // Truncated subidentifier (continuation bit never cleared)
        assert_eq!(decode_oid(&[0x2a, 0x86]), None);
    }

    #[test]
    fn integer_renderings() {
        assert_eq!(integer_value(&[0x00]), "0");
        assert_eq!(integer_value(&[0x01, 0xe2, 0x40]), "123456");
        assert_eq!(integer_value(&[0xff]), "-1");
        assert_eq!(integer_value(&[0x80]), "-128");
        // 9-byte values fall back to signed hex (magnitude = two's
        // complement negation).
        assert_eq!(
            integer_value(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0]),
            "0x10000000000000000"
        );
        assert_eq!(
            integer_value(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            "-0x1"
        );
    }

    #[test]
    fn hex_preview_is_bounded() {
        let bytes = vec![0xa5u8; 100];
        let preview = hex_preview(&bytes);
        assert!(preview.starts_with(&"a5".repeat(HEX_PREVIEW_BYTES)));
        assert!(preview.ends_with("...(+36 bytes)"));
        assert_eq!(hex_preview(&[0x01, 0x02]), "0102");
    }
}
