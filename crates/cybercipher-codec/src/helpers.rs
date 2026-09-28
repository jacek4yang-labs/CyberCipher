//! Shared helpers for codec operations: spec construction, input extraction,
//! and key/parameter decoding.

use crate::decode_input;
use cybercipher_core::prelude::*;

/// Build a leaked `&'static OperationSpec`. The registry is constructed once
/// per process; leaking the (small) metadata is intentional and bounded.
#[allow(clippy::too_many_arguments)]
pub fn spec(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    category: Category,
    inputs: &[ValueKind],
    output: ValueKind,
    cost: CostClass,
    reversible: bool,
    params: Vec<ParamSpec>,
    tags: &[&'static str],
    aliases: &[&'static str],
    standard: &'static str,
    vectors: &'static str,
) -> &'static OperationSpec {
    Box::leak(Box::new(OperationSpec {
        id,
        name,
        description,
        category,
        input_kinds: Box::leak(inputs.to_vec().into_boxed_slice()),
        output_kind: output,
        params: Box::leak(params.into_boxed_slice()),
        cost,
        security: Security::Neutral,
        deterministic: true,
        reversible,
        aliases: Box::leak(aliases.to_vec().into_boxed_slice()),
        tags: Box::leak(tags.to_vec().into_boxed_slice()),
        provenance: Provenance {
            standard,
            implementation: "CyberCipher native Rust",
            test_vectors: vectors,
        },
    }))
}

pub fn p_text(
    key: &'static str,
    label: &'static str,
    default: &'static str,
    hint: &'static str,
) -> ParamSpec {
    ParamSpec {
        key,
        label,
        kind: ParamKind::Text,
        default: ParamDefault::Str(default),
        optional: false,
        hint,
        options: &[],
    }
}

pub fn p_bool(
    key: &'static str,
    label: &'static str,
    default: bool,
    hint: &'static str,
) -> ParamSpec {
    ParamSpec {
        key,
        label,
        kind: ParamKind::Boolean,
        default: ParamDefault::Bool(default),
        optional: false,
        hint,
        options: &[],
    }
}

pub fn p_int(
    key: &'static str,
    label: &'static str,
    default: i64,
    hint: &'static str,
) -> ParamSpec {
    ParamSpec {
        key,
        label,
        kind: ParamKind::Integer,
        default: ParamDefault::Int(default),
        optional: false,
        hint,
        options: &[],
    }
}

pub fn p_opts(
    key: &'static str,
    label: &'static str,
    default: &'static str,
    options: &'static [ParamOption],
    hint: &'static str,
) -> ParamSpec {
    ParamSpec {
        key,
        label,
        kind: ParamKind::Options,
        default: ParamDefault::Str(default),
        optional: false,
        hint,
        options,
    }
}

pub fn p_enc(
    key: &'static str,
    label: &'static str,
    default: &'static str,
    hint: &'static str,
) -> ParamSpec {
    ParamSpec {
        key,
        label,
        kind: ParamKind::Encoding,
        default: ParamDefault::Str(default),
        optional: false,
        hint,
        options: key_encodings(),
    }
}

/// Interpretation encodings accepted for key-like parameters.
pub fn key_encodings() -> &'static [ParamOption] {
    static OPTS: &[ParamOption] = &[
        ParamOption {
            value: "utf8",
            label: "UTF-8 text",
        },
        ParamOption {
            value: "hex",
            label: "Hex",
        },
        ParamOption {
            value: "base64",
            label: "Base64",
        },
        ParamOption {
            value: "decimal",
            label: "Decimal byte list",
        },
    ];
    OPTS
}

/// Extract the input as bytes, with a useful typed error on mismatch.
pub fn input_bytes<'a>(v: &'a Value, op_name: &str) -> OpResult<std::borrow::Cow<'a, [u8]>> {
    v.as_bytes().ok_or_else(|| {
        OperationError::invalid_input(format!(
            "`{op_name}` operates on bytes or text, but received {}",
            v.kind().name()
        ))
        .with_expected("bytes or text")
        .with_actual(v.kind().name())
    })
}

/// Extract the input as text, with a useful typed error on mismatch.
pub fn input_text<'a>(v: &'a Value, op_name: &str) -> OpResult<&'a str> {
    v.as_text().ok_or_else(|| {
        OperationError::invalid_input(format!(
            "`{op_name}` operates on text, but received {} (input is not valid UTF-8)",
            v.kind().name()
        ))
        .with_expected("text")
        .with_actual(v.kind().name())
    })
}

/// Decode a key-like parameter into bytes according to its encoding selector.
/// The resulting byte length is embedded in error messages to prevent the
/// classic "key interpreted with the wrong encoding" failure mode.
pub fn decode_key(map: &ParamMap, key_param: &str, enc_param: &str) -> OpResult<Vec<u8>> {
    let raw = map.require_str(key_param)?;
    let enc = map.str_or(enc_param, "utf8");
    let bytes = decode_input(enc, raw).map_err(|e| e.with_parameter(key_param))?;
    if bytes.is_empty() {
        return Err(
            OperationError::key(format!("`{key_param}` decodes to zero bytes"))
                .with_parameter(key_param)
                .with_actual(enc),
        );
    }
    Ok(bytes)
}

/// Decode a delimiter parameter, honoring common escape sequences.
pub fn decode_delimiter(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('0') => out.push('\0'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}
