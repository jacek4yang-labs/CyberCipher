//! Shared helpers for crypto operations: spec construction and key material
//! decoding with explicit length diagnostics.

use cybercipher_core::prelude::*;

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

/// Decode key-like material, reporting the resulting byte length in errors.
pub fn decode_material(
    map: &ParamMap,
    key_param: &str,
    enc_param: &str,
    _name: &str,
) -> OpResult<Vec<u8>> {
    let raw = map.require_str(key_param)?;
    let enc = map.str_or(enc_param, "hex");
    cybercipher_codec::decode_input(enc, raw).map_err(|e| e.with_parameter(key_param))
}

pub fn hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Parameter set shared by every block cipher operation: key + encoding,
/// mode selector, IV (+ encoding) and padding policy.
fn block_mode_params() -> Vec<ParamSpec> {
    vec![
        p_text("key", "Key", "", "Key material; see the encoding selector."),
        p_enc("key_encoding", "Key encoding", "hex", ""),
        p_opts(
            "mode",
            "Mode",
            "cbc",
            &[
                ParamOption {
                    value: "ecb",
                    label: "ECB",
                },
                ParamOption {
                    value: "cbc",
                    label: "CBC",
                },
                ParamOption {
                    value: "ctr",
                    label: "CTR",
                },
                ParamOption {
                    value: "cfb",
                    label: "CFB",
                },
                ParamOption {
                    value: "ofb",
                    label: "OFB",
                },
            ],
            "Every block cipher supports all five modes.",
        ),
        p_text(
            "iv",
            "IV / counter",
            "",
            "IV for CBC/CTR/CFB/OFB. Empty for ECB. Carries the mandatory 16-byte tweak for Threefish.",
        ),
        p_enc("iv_encoding", "IV encoding", "hex", ""),
        p_opts(
            "padding",
            "Padding",
            "pkcs7",
            &[
                ParamOption {
                    value: "pkcs7",
                    label: "PKCS#7",
                },
                ParamOption {
                    value: "none",
                    label: "None",
                },
                ParamOption {
                    value: "zero",
                    label: "Zero",
                },
                ParamOption {
                    value: "iso7816",
                    label: "ISO 7816-4",
                },
            ],
            "ECB/CBC only; stream modes ignore padding.",
        ),
    ]
}

/// Leak a spec built from the shared block-mode parameter set.
#[allow(clippy::too_many_arguments)]
fn leak_cipher_spec(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    standard: &'static str,
    implementation: &'static str,
    test_vectors: &'static str,
    security: Security,
    tags: &'static [&'static str],
) -> &'static OperationSpec {
    let params = block_mode_params();
    Box::leak(Box::new(OperationSpec {
        id,
        name,
        description,
        category: Category::Crypto,
        input_kinds: Box::leak(vec![ValueKind::Bytes, ValueKind::Text].into_boxed_slice()),
        output_kind: ValueKind::Bytes,
        params: Box::leak(params.into_boxed_slice()),
        cost: CostClass::Instant,
        security,
        deterministic: true,
        reversible: true,
        aliases: Box::leak(
            vec![
                &*Box::leak(
                    id.split('-')
                        .next()
                        .unwrap_or(id)
                        .to_string()
                        .into_boxed_str(),
                ),
                &*Box::leak(format!("{name} crypt").into_boxed_str()),
            ]
            .into_boxed_slice(),
        ),
        tags,
        provenance: Provenance {
            standard,
            implementation,
            test_vectors,
        },
    }))
}

/// Build a leaked spec for the legacy AES/DES/SM4 cipher operations.
pub fn cipher_spec(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    standard: &'static str,
    tags: &'static [&'static str],
) -> &'static OperationSpec {
    leak_cipher_spec(
        id,
        name,
        description,
        standard,
        "RustCrypto block cipher crates + CyberCipher native mode wiring",
        "NIST SP 800-38A / GB/T 0002 / known-answer tests",
        if id.starts_with("des") {
            Security::Broken
        } else {
            Security::Modern
        },
        tags,
    )
}

/// Build a leaked spec for a table-registered block cipher operation with
/// explicit security classification (implementation/vectors provenance is
/// completed by the caller from the registry row).
pub fn block_cipher_spec(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    standard: &'static str,
    security: Security,
    tags: &'static [&'static str],
) -> &'static OperationSpec {
    leak_cipher_spec(
        id,
        name,
        description,
        standard,
        "RustCrypto block cipher crates + CyberCipher native mode wiring",
        "NIST SP 800-38A / RFC / NESSIE known-answer tests",
        security,
        tags,
    )
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

/// Like [`p_text`], but the parameter is optional (e.g. AEAD associated data).
pub fn p_text_opt(
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
        optional: true,
        hint,
        options: &[],
    }
}

pub fn p_enc(
    key: &'static str,
    label: &'static str,
    default: &'static str,
    hint: &'static str,
) -> ParamSpec {
    static KEY_ENCODINGS: &[ParamOption] = &[
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
    ParamSpec {
        key,
        label,
        kind: ParamKind::Encoding,
        default: ParamDefault::Str(default),
        optional: false,
        hint,
        options: KEY_ENCODINGS,
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

/// Spec for the RC4 stream cipher (single op: encryption == decryption).
pub fn rc4_spec(tags: &'static [&'static str]) -> &'static OperationSpec {
    let params = vec![
        p_text("key", "Key", "", "1-256 bytes after decoding."),
        p_enc("key_encoding", "Key encoding", "hex", ""),
        p_int(
            "drop",
            "Drop bytes (RC4-drop[n])",
            0,
            "Discard the first N keystream bytes (recommended: 768).",
        ),
    ];
    Box::leak(Box::new(OperationSpec {
        id: "rc4",
        name: "RC4",
        description: "Applies the RC4 keystream (encryption and decryption are identical). Legacy/broken — for CTF and interop.",
        category: Category::Crypto,
        input_kinds: Box::leak(vec![ValueKind::Bytes, ValueKind::Text].into_boxed_slice()),
        output_kind: ValueKind::Bytes,
        params: Box::leak(params.into_boxed_slice()),
        cost: CostClass::Instant,
        security: Security::Broken,
        deterministic: true,
        reversible: true,
        aliases: &["rc4-drop", "arc4"],
        tags,
        provenance: Provenance {
            standard: "Original RC4 (Rivest); RFC 6229 vectors",
            implementation: "RustCrypto `rc4` crate",
            test_vectors: "RFC 6229 / classic test vectors",
        },
    }))
}
