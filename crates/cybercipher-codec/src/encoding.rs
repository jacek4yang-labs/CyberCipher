//! Encoding operations: hex, base64, base32, URL, radix conversions,
//! hexdump, and UTF-8 text handling.

use crate::helpers::{input_bytes, input_text, p_bool, p_opts, p_text, spec};
use cybercipher_core::prelude::*;
use num_traits::ToPrimitive;
use percent_encoding::{percent_decode_str, percent_encode, AsciiSet, NON_ALPHANUMERIC};
use std::borrow::Cow;

use base64::Engine as _;

// ---------------------------------------------------------------- hex ----

fn hex_encode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Hex")?;
    let uppercase = map.bool_or("uppercase", false);
    let sep = map.str_or("separator", "");
    let mut out = String::with_capacity(bytes.len() * 2);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && !sep.is_empty() {
            out.push_str(sep);
        }
        if uppercase {
            out.push_str(&format!("{b:02X}"));
        } else {
            out.push_str(&format!("{b:02x}"));
        }
    }
    Ok(Value::Text(out))
}

/// Decode hex with explicit diagnostics. `strict` forbids any character
/// outside hex digits and whitespace; relaxed drops all non-hex characters.
pub fn decode_hex_strict(text: &str) -> OpResult<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 2 + 1);
    let mut nibbles = 0u8;
    let mut pending = 0u8;
    for (idx, c) in text.chars().enumerate() {
        if c.is_whitespace() {
            continue;
        }
        let d = match c.to_digit(16) {
            Some(d) => d as u8,
            None => {
                return Err(OperationError::decode(format!(
                    "invalid hex character `{c}`"
                ))
                .with_expected("0-9, a-f, A-F or whitespace")
                .with_actual(format!("character at offset {idx}"))
                .with_details("Use relaxed mode to ignore non-hex characters, or remove them from the input."));
            }
        };
        if nibbles == 0 {
            pending = d;
            nibbles = 1;
        } else {
            out.push((pending << 4) | d);
            nibbles = 0;
        }
    }
    if nibbles != 0 {
        return Err(
            OperationError::decode("hex input has an odd number of digits")
                .with_expected("an even number of hex digits")
                .with_actual("odd count")
                .with_details(
                    "The final digit has no pair. Append a leading zero if a nibble is intended.",
                ),
        );
    }
    Ok(out)
}

/// Relaxed hex decode: whitespace and non-hex characters are ignored.
pub fn decode_hex_relaxed(text: &str) -> OpResult<Vec<u8>> {
    let filtered: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    decode_hex_strict(&filtered)
}

fn hex_decode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From Hex")?;
    let strict = map.bool_or("strict", true);
    let bytes = if strict {
        decode_hex_strict(text)?
    } else {
        decode_hex_relaxed(text)?
    };
    Ok(Value::Bytes(bytes))
}

// ------------------------------------------------------------- base64 ----

fn b64_engine(
    alphabet: &base64::alphabet::Alphabet,
    canonical: bool,
) -> base64::engine::GeneralPurpose {
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    let mode = if canonical {
        DecodePaddingMode::RequireCanonical
    } else {
        DecodePaddingMode::Indifferent
    };
    let cfg = GeneralPurposeConfig::new().with_decode_padding_mode(mode);
    GeneralPurpose::new(alphabet, cfg)
}

fn b64_alphabet(name: &str) -> OpResult<&'static base64::alphabet::Alphabet> {
    match name {
        "standard" => Ok(&base64::alphabet::STANDARD),
        "urlsafe" => Ok(&base64::alphabet::URL_SAFE),
        other => Err(OperationError::invalid_param(
            "alphabet",
            format!("unknown Base64 alphabet `{other}`"),
        )),
    }
}

fn base64_encode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Base64")?;
    let alpha = b64_alphabet(map.str_or("alphabet", "standard"))?;
    let engine = b64_engine(alpha, true);
    Ok(Value::Text(engine.encode(bytes.as_ref())))
}

/// Relaxed Base64 decode: whitespace and non-alphabet characters are ignored,
/// missing padding is repaired when possible.
pub fn base64_decode_relaxed(text: &str, alphabet: &str) -> OpResult<Vec<u8>> {
    let alpha = b64_alphabet(alphabet)?;
    let engine = b64_engine(alpha, false);
    let allowed: &[char] = match alphabet {
        "urlsafe" => &[
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
            'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
            'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
            'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_',
        ],
        _ => &[
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
            'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
            'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
            'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
        ],
    };
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .filter(|c| allowed.contains(c))
        .collect();
    match cleaned.len() % 4 {
        0 => {}
        2 => return engine.decode(format!("{cleaned}==")).map_err(decode_err),
        3 => return engine.decode(format!("{cleaned}=")).map_err(decode_err),
        _ => {
            return Err(OperationError::decode(
                "Base64 payload length (after removing invalid characters) is invalid",
            )
            .with_expected("length mod 4 of 0, 2 or 3")
            .with_actual(format!("length {}", cleaned.len())))
        }
    }
    engine.decode(cleaned.as_bytes()).map_err(decode_err)
}

fn decode_err(e: base64::DecodeError) -> OperationError {
    match e {
        base64::DecodeError::InvalidByte(pos, b) => OperationError::decode(format!(
            "invalid Base64 character `{}` at offset {pos}",
            b as char
        ))
        .with_actual(format!("byte 0x{b:02x}")),
        base64::DecodeError::InvalidLength(len) => {
            OperationError::decode(format!("invalid Base64 length {len}"))
        }
        base64::DecodeError::InvalidLastSymbol(pos, b) => OperationError::decode(format!(
            "invalid trailing Base64 symbol `{}` at offset {pos}",
            b as char
        )),
        base64::DecodeError::InvalidPadding => OperationError::decode("invalid Base64 padding"),
    }
}

fn base64_decode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    use base64::Engine as _;
    let text = input_text(v, "From Base64")?;
    let alphabet = map.str_or("alphabet", "standard");
    let strict = map.bool_or("strict", true);
    if strict {
        let text_clean = text.trim();
        if text_clean.contains(char::is_whitespace) {
            return Err(
                OperationError::decode("strict Base64 input contains whitespace").with_details(
                    "Disable strict mode to ignore whitespace and invalid characters.",
                ),
            );
        }
        let engine = b64_engine(b64_alphabet(alphabet)?, true);
        let bytes = engine.decode(text_clean).map_err(decode_err)?;
        Ok(Value::Bytes(bytes))
    } else {
        let bytes = base64_decode_relaxed(text, alphabet)?;
        Ok(Value::Bytes(bytes))
    }
}

// ------------------------------------------------------------- base32 ----

const B32_STANDARD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const B32_HEX: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

fn b32_alphabet(name: &str) -> OpResult<&'static [u8]> {
    match name {
        "standard" => Ok(B32_STANDARD),
        "hex" => Ok(B32_HEX),
        other => Err(OperationError::invalid_param(
            "alphabet",
            format!("unknown Base32 alphabet `{other}`"),
        )),
    }
}

fn base32_encode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Base32")?;
    let alpha = b32_alphabet(map.str_or("alphabet", "standard"))?;
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &b in bytes.iter() {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(alpha[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(alpha[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    while !out.len().is_multiple_of(8) {
        out.push('=');
    }
    Ok(Value::Text(out))
}

fn base32_decode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From Base32")?;
    let alpha = b32_alphabet(map.str_or("alphabet", "standard"))?;
    let strict = map.bool_or("strict", true);
    let cleaned: String = if strict {
        let filtered: String = text.trim().chars().filter(|c| !c.is_whitespace()).collect();
        for (idx, c) in filtered.chars().enumerate() {
            if c != '=' && !alpha.contains(&(c as u8)) {
                return Err(OperationError::decode(format!(
                    "invalid Base32 character `{c}` at offset {idx}"
                ))
                .with_details("Disable strict mode to ignore invalid characters."));
            }
        }
        filtered
    } else {
        text.chars()
            .filter(|c| alpha.contains(&(*c as u8)) || *c == '=')
            .filter(|c| *c != '=')
            .collect()
    };
    let body: String = cleaned.chars().filter(|c| *c != '=').collect();
    if body.len() % 8 == 1 || body.len() % 8 == 3 || body.len() % 8 == 6 {
        return Err(OperationError::decode("Base32 payload length is invalid")
            .with_expected("length mod 8 of 0, 2, 4, 5 or 7")
            .with_actual(format!("length {}", body.len())));
    }
    let mut out = Vec::with_capacity(body.len() * 5 / 8);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for c in body.chars() {
        let d = alpha
            .iter()
            .position(|&a| a as char == c)
            .ok_or_else(|| OperationError::decode(format!("invalid Base32 character `{c}`")))?
            as u32;
        buffer = (buffer << 5) | d;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(Value::Bytes(out))
}

// ---------------------------------------------------------------- url ----

const URL_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

fn url_encode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To URL")?;
    let encoded = percent_encode(bytes.as_ref(), URL_SET).to_string();
    let _ = map; // reserved for future "encode space as +" option
    Ok(Value::Text(encoded))
}

fn url_decode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From URL")?;
    let plus_as_space = map.bool_or("plus_as_space", false);
    let normalized: Cow<str> = if plus_as_space {
        Cow::Owned(text.replace('+', " "))
    } else {
        Cow::Borrowed(text)
    };
    let decoded = percent_decode_str(&normalized).decode_utf8_lossy();
    Ok(Value::Text(decoded.into_owned()))
}

// -------------------------------------------------------------- radix ----

const RADIX_DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

fn to_radix(radix: u32) -> impl Fn(&Value, &ParamMap, &ExecutionContext) -> OpResult<Value> {
    move |v, map, _| {
        let bytes = input_bytes(v, "To Radix")?;
        let delim = crate::helpers::decode_delimiter(map.str_or("delimiter", " "));
        let mut out = String::with_capacity(bytes.len() * 8);
        for (i, b) in bytes.iter().enumerate() {
            if i > 0 && !delim.is_empty() {
                out.push_str(&delim);
            }
            let mut stack = Vec::new();
            let mut n = *b as u32;
            if n == 0 {
                stack.push(0u8);
            }
            while n > 0 {
                stack.push((n % radix) as u8);
                n /= radix;
            }
            for d in stack.iter().rev() {
                out.push(RADIX_DIGITS[*d as usize] as char);
            }
        }
        Ok(Value::Text(out))
    }
}

/// Parse a byte list in a given radix; tokens are separated by any
/// non-digit characters (whitespace, commas, semicolons, ...).
pub fn from_radix_text(text: &str, radix: u32) -> OpResult<Vec<u8>> {
    fn parse_byte_token(token: &str, radix: u32, index: usize) -> OpResult<u8> {
        let value = u32::from_str_radix(token, radix).map_err(|_| {
            OperationError::decode(format!(
                "token `{token}` is not a valid base-{radix} number"
            ))
            .with_actual(format!("token #{index}"))
        })?;
        if value > 255 {
            return Err(
                OperationError::decode(format!("value {value} does not fit in a byte"))
                    .with_expected("0-255")
                    .with_actual(format!("token `{token}` (#{index})")),
            );
        }
        Ok(value as u8)
    }

    let mut out = Vec::new();
    let mut token = String::new();
    for c in text.chars() {
        if c.is_digit(radix) {
            token.push(c);
        } else if !token.is_empty() {
            out.push(parse_byte_token(&token, radix, out.len() + 1)?);
            token.clear();
        }
    }
    if !token.is_empty() {
        out.push(parse_byte_token(&token, radix, out.len() + 1)?);
    }
    Ok(out)
}

/// Decode GUI input text according to the input-box encoding selector.
/// Hex and Base64 are decoded in relaxed mode with diagnostics; failures are
/// surfaced to the user rather than silently reinterpreted.
pub fn decode_input(encoding: &str, text: &str) -> OpResult<Vec<u8>> {
    match encoding {
        "utf8" => Ok(text.as_bytes().to_vec()),
        "hex" => decode_hex_relaxed(text),
        "base64" => base64_decode_relaxed(text, "standard"),
        "decimal" => from_radix_text(text, 10),
        other => Err(OperationError::invalid_param(
            "encoding",
            format!("unknown input encoding `{other}`"),
        )
        .with_expected("utf8, hex, base64 or decimal")
        .with_actual(other)),
    }
}

fn from_radix(radix: u32) -> impl Fn(&Value, &ParamMap, &ExecutionContext) -> OpResult<Value> {
    move |v, map, _| {
        let _ = map;
        if let Value::IntegerList(list) = v {
            let mut out = Vec::with_capacity(list.len());
            for (i, n) in list.iter().enumerate() {
                let val = n.to_u64().filter(|x| *x <= 255).ok_or_else(|| {
                    OperationError::decode(format!("value at index {i} does not fit in a byte"))
                        .with_expected("0-255")
                        .with_actual(n.to_string())
                })?;
                out.push(val as u8);
            }
            return Ok(Value::Bytes(out));
        }
        let text = input_text(v, "From Radix")?;
        let bytes = from_radix_text(text, radix)?;
        Ok(Value::Bytes(bytes))
    }
}

// ------------------------------------------------------------ hexdump ----

fn hexdump(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Hexdump")?;
    let uppercase = map.bool_or("uppercase", false);
    let mut out = String::with_capacity(bytes.len().div_ceil(16) * 80);
    for (row, chunk) in bytes.chunks(16).enumerate() {
        out.push_str(&format!("{row:08x}  "));
        for group in 0..4 {
            for i in 0..4 {
                let idx = group * 4 + i;
                match chunk.get(idx) {
                    Some(b) => {
                        if uppercase {
                            out.push_str(&format!("{b:02X} "));
                        } else {
                            out.push_str(&format!("{b:02x} "));
                        }
                    }
                    None => out.push_str("   "),
                }
            }
            out.push(' ');
        }
        out.push('|');
        for &b in chunk {
            out.push(if (0x20..=0x7E).contains(&b) {
                b as char
            } else {
                '.'
            });
        }
        out.push('|');
        out.push('\n');
    }
    Ok(Value::Text(out))
}

// ---------------------------------------------------------------- utf8 ----

fn utf8_encode(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    match v {
        Value::Text(t) => Ok(Value::Bytes(t.as_bytes().to_vec())),
        Value::Bytes(_) => Ok(v.clone()),
        other => Err(OperationError::invalid_input(format!(
            "Encode Text expects text or bytes, got {}",
            other.kind().name()
        ))),
    }
}

fn utf8_decode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "Decode Text")?;
    let lossy = map.bool_or("lossy", false);
    if lossy {
        Ok(Value::Text(
            String::from_utf8_lossy(bytes.as_ref()).into_owned(),
        ))
    } else {
        match std::str::from_utf8(bytes.as_ref()) {
            Ok(text) => Ok(Value::Text(text.to_string())),
            Err(e) => {
                let valid = e.valid_up_to();
                let bad =
                    &bytes.as_ref()[valid..(valid + e.error_len().unwrap_or(1)).min(bytes.len())];
                Err(OperationError::decode("input is not valid UTF-8")
                    .with_expected("valid UTF-8")
                    .with_actual(format!("invalid sequence at byte offset {valid}"))
                    .with_details(format!(
                        "First invalid bytes: {} — enable lossy mode to replace them with U+FFFD.",
                        bad.iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(" ")
                    )))
            }
        }
    }
}

// ------------------------------------------------------------ registry ----

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    use cybercipher_core::Category::{self as C, Encoding as E};
    use cybercipher_core::ValueKind::{Bytes as B, Text as T};

    let enc_tag: &'static [&'static str] = &["encoding", "ctf"];

    reg.add_simple(
        spec(
            "to-hex",
            "To Hex",
            "Encodes bytes as hexadecimal text.",
            C::Encoding,
            &[B, T],
            T,
            CostClass::Instant,
            true,
            vec![
                p_bool("uppercase", "Uppercase", false, "Use A-F instead of a-f."),
                p_text(
                    "separator",
                    "Separator",
                    "",
                    "Inserted between bytes, e.g. a space.",
                ),
            ],
            enc_tag,
            &["hex encode", "hexadecimal"],
            "Common convention; equivalent to CyberChef To Hex",
            "Round-trip and known-answer tests",
        ),
        hex_encode,
    );

    reg.add_simple(
        spec(
            "from-hex",
            "From Hex",
            "Decodes hexadecimal text into bytes.",
            E,
            &[T],
            B,
            CostClass::Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Reject non-hex characters instead of ignoring them.",
            )],
            enc_tag,
            &["hex decode", "hexadecimal", "unhex"],
            "Common convention; equivalent to CyberChef From Hex",
            "Known-answer tests",
        ),
        hex_decode,
    );

    reg.add_simple(
        spec(
            "to-base64",
            "To Base64",
            "Encodes bytes as Base64 text (RFC 4648).",
            E,
            &[B, T],
            T,
            CostClass::Instant,
            true,
            vec![p_opts(
                "alphabet",
                "Alphabet",
                "standard",
                &[
                    ParamOption {
                        value: "standard",
                        label: "Standard (A-Za-z0-9+/)",
                    },
                    ParamOption {
                        value: "urlsafe",
                        label: "URL safe (A-Za-z0-9-_)",
                    },
                ],
                "Standard vs URL-safe alphabet.",
            )],
            enc_tag,
            &["b64", "base64 encode"],
            "RFC 4648 (Base 64 Encoding)",
            "RFC 4648 §10 test vectors",
        ),
        base64_encode,
    );

    reg.add_simple(
        spec(
            "from-base64",
            "From Base64",
            "Decodes Base64 text into bytes (RFC 4648).",
            E,
            &[T],
            B,
            CostClass::Instant,
            true,
            vec![
                p_opts(
                    "alphabet",
                    "Alphabet",
                    "standard",
                    &[
                        ParamOption {
                            value: "standard",
                            label: "Standard (A-Za-z0-9+/)",
                        },
                        ParamOption {
                            value: "urlsafe",
                            label: "URL safe (A-Za-z0-9-_)",
                        },
                    ],
                    "Standard vs URL-safe alphabet.",
                ),
                p_bool(
                    "strict",
                    "Strict",
                    true,
                    "Reject invalid characters and whitespace; relaxed mode repairs padding.",
                ),
            ],
            enc_tag,
            &["b64", "base64 decode"],
            "RFC 4648 (Base 64 Encoding)",
            "RFC 4648 §10 test vectors",
        ),
        base64_decode,
    );

    reg.add_simple(
        spec(
            "to-base32",
            "To Base32",
            "Encodes bytes as Base32 text (RFC 4648).",
            E,
            &[B, T],
            T,
            CostClass::Instant,
            true,
            vec![p_opts(
                "alphabet",
                "Alphabet",
                "standard",
                &[
                    ParamOption {
                        value: "standard",
                        label: "Standard (A-Z2-7)",
                    },
                    ParamOption {
                        value: "hex",
                        label: "Extended hex (0-9A-V)",
                    },
                ],
                "RFC 4648 base32 vs base32hex.",
            )],
            enc_tag,
            &["b32", "base32 encode"],
            "RFC 4648 (Base 32 Encoding)",
            "RFC 4648 §7 test vectors",
        ),
        base32_encode,
    );

    reg.add_simple(
        spec(
            "from-base32",
            "From Base32",
            "Decodes Base32 text into bytes (RFC 4648).",
            E,
            &[T],
            B,
            CostClass::Instant,
            true,
            vec![
                p_opts(
                    "alphabet",
                    "Alphabet",
                    "standard",
                    &[
                        ParamOption {
                            value: "standard",
                            label: "Standard (A-Z2-7)",
                        },
                        ParamOption {
                            value: "hex",
                            label: "Extended hex (0-9A-V)",
                        },
                    ],
                    "RFC 4648 base32 vs base32hex.",
                ),
                p_bool(
                    "strict",
                    "Strict",
                    true,
                    "Reject invalid characters; relaxed mode ignores them.",
                ),
            ],
            enc_tag,
            &["b32", "base32 decode"],
            "RFC 4648 (Base 32 Encoding)",
            "RFC 4648 §7 test vectors",
        ),
        base32_decode,
    );

    reg.add_simple(
        spec(
            "to-url",
            "To URL",
            "Percent-encodes all bytes outside the URL unreserved set (ALPHA / DIGIT / - . _ ~).",
            E,
            &[B, T],
            T,
            CostClass::Instant,
            true,
            vec![],
            enc_tag,
            &["url encode", "percent encode", "uri"],
            "RFC 3986 (Percent-Encoding)",
            "Round-trip tests",
        ),
        url_encode,
    );

    reg.add_simple(
        spec(
            "from-url",
            "From URL",
            "Decodes percent-encoded text.",
            E,
            &[T],
            B,
            CostClass::Instant,
            true,
            vec![p_bool(
                "plus_as_space",
                "Treat '+' as space",
                false,
                "Common in form-encoded data.",
            )],
            enc_tag,
            &["url decode", "percent decode", "uri"],
            "RFC 3986 (Percent-Encoding)",
            "Round-trip tests",
        ),
        url_decode,
    );

    for (id, name, radix, alias) in [
        ("to-binary", "To Binary", 2u32, "bin"),
        ("to-octal", "To Octal", 8, "oct"),
        ("to-decimal", "To Decimal", 10, "dec"),
    ] {
        reg.add_simple(
            spec(
                id,
                name,
                match radix {
                    2 => "Encodes bytes as a list of binary byte values.",
                    8 => "Encodes bytes as a list of octal byte values.",
                    _ => "Encodes bytes as a list of decimal byte values.",
                },
                E,
                &[B, T],
                T,
                CostClass::Instant,
                true,
                vec![p_text(
                    "delimiter",
                    "Delimiter",
                    " ",
                    "Between values. Escape sequences \\n, \\t, \\r, \\0 supported.",
                )],
                enc_tag,
                &[alias, "byte values"],
                "Common convention; equivalent to CyberChef radix operations",
                "Round-trip tests",
            ),
            to_radix(radix),
        );
    }

    for (id, name, radix, alias) in [
        ("from-binary", "From Binary", 2u32, "bin"),
        ("from-octal", "From Octal", 8, "oct"),
        ("from-decimal", "From Decimal", 10, "dec"),
    ] {
        reg.add_simple(
            spec(
                id,
                name,
                match radix {
                    2 => "Parses binary byte values into bytes.",
                    8 => "Parses octal byte values into bytes.",
                    _ => "Parses decimal byte values into bytes.",
                },
                E,
                &[T],
                B,
                CostClass::Instant,
                true,
                vec![],
                enc_tag,
                &[alias, "byte values"],
                "Common convention; equivalent to CyberChef radix operations",
                "Round-trip tests",
            ),
            from_radix(radix),
        );
    }

    reg.add_simple(
        spec(
            "to-hexdump",
            "To Hexdump",
            "Formats bytes as an offset/hex/ASCII hexdump, 16 bytes per row.",
            C::Utility,
            &[B, T],
            T,
            CostClass::Instant,
            false,
            vec![p_bool(
                "uppercase",
                "Uppercase",
                false,
                "Use uppercase hex digits.",
            )],
            &["utility", "ctf"],
            &["hex dump", "xxd"],
            "Common hexdump layout (BSD-style)",
            "Layout snapshot tests",
        ),
        hexdump,
    );

    reg.add_simple(
        spec(
            "encode-text",
            "Encode Text (UTF-8)",
            "Converts text to its UTF-8 byte representation.",
            E,
            &[T, B],
            B,
            CostClass::Instant,
            true,
            vec![],
            enc_tag,
            &["utf8 encode", "text to bytes"],
            "The Unicode Standard / RFC 3629",
            "Round-trip tests",
        ),
        utf8_encode,
    );

    reg.add_simple(
        spec(
            "decode-text",
            "Decode Text (UTF-8)",
            "Interprets bytes as UTF-8 text, validating or replacing invalid sequences.",
            E,
            &[B, T],
            T,
            CostClass::Instant,
            true,
            vec![p_bool(
                "lossy",
                "Lossy",
                false,
                "Replace invalid sequences with U+FFFD instead of failing.",
            )],
            enc_tag,
            &["utf8 decode", "text from bytes", "unicode"],
            "The Unicode Standard / RFC 3629",
            "Malformed-input tests",
        ),
        utf8_decode,
    );
}
