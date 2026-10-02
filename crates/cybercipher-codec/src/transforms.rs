//! Encoding transforms: C escapes, JSON string escaping, BCD, ModHex, COBS,
//! NetBIOS first-level encoding, and Base100 (emoji).
//!
//! Conventions (matching the rest of the crate):
//!
//! * Decoders have strict (default) and relaxed modes. Strict mode fails with
//!   typed errors; relaxed mode keeps or drops malformed constructs instead of
//!   guessing what they meant.
//! * Every reversible op round-trips against its inverse; every algorithm
//!   carries a provenance citation and, where a de-facto reference exists,
//!   its published test vectors.

use crate::helpers::{input_bytes, input_text, p_bool, p_opts, spec};
use cybercipher_core::prelude::*;

const ENC_TAG: &[&str] = &["encoding", "ctf"];

// ----------------------------------------------------------- C escapes ----

/// Encode text as a C string body (no surrounding quotes): the two-char
/// escapes cover the named control characters and the backslash/quote pair,
/// other control bytes use 3-digit octal (self-delimiting, unlike `\x`),
/// and non-ASCII scalars pass through as UTF-8 (valid in C string literals).
fn encode_c_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 2);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\'' => out.push_str("\\'"),
            '\0' => out.push_str("\\0"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{b}' => out.push_str("\\v"),
            '\u{c}' => out.push_str("\\f"),
            c if (0x20..=0x7E).contains(&(c as u32)) => out.push(c),
            c if c as u32 <= 0xFF => out.push_str(&format!("\\{:03o}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Decode C escape sequences: the standard two-char escapes, `\0`, octal
/// `\NNN` (1-3 digits, max 0377) and `\xHH` (up to two hex digits, the
/// deterministic spelling Python/JS use). Strict mode rejects unknown
/// escapes and out-of-range values; relaxed mode keeps them verbatim.
pub fn decode_c_escapes(text: &str, strict: bool) -> OpResult<Vec<u8>> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            i += 1;
            continue;
        }
        let Some(next) = chars.get(i + 1).copied() else {
            if strict {
                return Err(
                    OperationError::decode("input ends with a dangling backslash")
                        .with_expected("an escape sequence")
                        .with_actual("backslash at end of input"),
                );
            }
            out.push(b'\\');
            i += 1;
            continue;
        };
        let simple = match next {
            'a' => Some(0x07),
            'b' => Some(0x08),
            'f' => Some(0x0C),
            'n' => Some(b'\n'),
            'r' => Some(b'\r'),
            't' => Some(b'\t'),
            'v' => Some(0x0B),
            '\\' => Some(b'\\'),
            '\'' => Some(b'\''),
            '"' => Some(b'"'),
            '?' => Some(b'?'),
            _ => None,
        };
        if let Some(byte) = simple {
            out.push(byte);
            i += 2;
            continue;
        }
        match next {
            '0'..='7' => {
                let mut value = 0u32;
                let mut digits = 0usize;
                let mut j = i + 1;
                while j < chars.len() && digits < 3 {
                    match chars[j].to_digit(8) {
                        Some(d) => value = value * 8 + d,
                        None => break,
                    }
                    digits += 1;
                    j += 1;
                }
                if value > 0xFF {
                    if strict {
                        return Err(OperationError::decode(format!(
                            "octal escape value {value:03o} exceeds one byte (max \\377)"
                        ))
                        .with_expected("an octal value of at most 0377")
                        .with_actual(format!("{value:03o}")));
                    }
                    out.push(b'\\');
                    i += 1;
                    continue;
                }
                out.push(value as u8);
                i = j;
            }
            'x' => {
                let mut value = 0u32;
                let mut digits = 0usize;
                let mut j = i + 2;
                while j < chars.len() && digits < 2 {
                    match chars[j].to_digit(16) {
                        Some(d) => value = value * 16 + d,
                        None => break,
                    }
                    digits += 1;
                    j += 1;
                }
                if digits == 0 {
                    if strict {
                        return Err(OperationError::decode(
                            "malformed \\x escape: expected one or two hex digits",
                        )
                        .with_expected("\\xHH")
                        .with_actual("`\\x` with no hex digits"));
                    }
                    out.extend_from_slice(b"\\x");
                    i += 2;
                    continue;
                }
                out.push(value as u8);
                i = j;
            }
            other => {
                if strict {
                    return Err(
                        OperationError::decode(format!("unknown C escape `\\{other}`"))
                            .with_expected(
                                "a, b, f, n, r, t, v, \\, ', \", ?, 0-7 (octal) or x (hex)",
                            )
                            .with_actual(format!("`\\{other}`")),
                    );
                }
                out.push(b'\\');
                let mut buf = [0u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
                i += 2;
            }
        }
    }
    Ok(out)
}

fn to_c_escapes_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "To C Escapes")?;
    Ok(Value::Text(encode_c_escapes(text)))
}

fn from_c_escapes_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From C Escapes")?;
    let strict = map.bool_or("strict", true);
    Ok(Value::from_bytes(decode_c_escapes(text, strict)?))
}

// ------------------------------------------------------------ JSON string ----

/// Escape text as the body of a JSON string (RFC 8259): quote and backslash
/// become two-char escapes, control characters use the short forms where
/// they exist and `\u00XX` otherwise; non-ASCII stays as UTF-8 (valid JSON).
fn encode_json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn to_json_escape_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "To JSON Escape")?;
    Ok(Value::Text(encode_json_string(text)))
}

// ----------------------------------------------------------------- BCD ----

/// Pack one decimal digit per nibble. `high_first` puts the first digit in
/// the high nibble (`"1234"` -> 0x12 0x34); `low_first` mirrors telephony
/// layouts (`"1234"` -> 0x21 0x43).
fn bcd_nibbles_to_bytes(nibbles: &[u8], high_first: bool) -> Vec<u8> {
    nibbles
        .chunks(2)
        .map(|pair| match pair {
            [a, b] if high_first => (*a << 4) | *b,
            [a, b] => (*b << 4) | *a,
            [a] if high_first => *a << 4,
            [a] => *a,
            _ => unreachable!("chunks(2) yields slices of length 1 or 2"),
        })
        .collect()
}

fn to_bcd_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "To BCD")?;
    let strict = map.bool_or("strict", true);
    let mut digits: Vec<u8> = Vec::with_capacity(text.len());
    for c in text.chars() {
        match c.to_digit(10) {
            Some(d) => digits.push(d as u8),
            None if !strict => continue,
            None => {
                return Err(OperationError::decode(format!(
                    "BCD input contains the non-digit character `{c}`"
                ))
                .with_expected("decimal digits 0-9")
                .with_actual(format!("`{c}`")))
            }
        }
    }
    if digits.len() % 2 == 1 {
        match map.str_or("padding", "zero") {
            "f" => digits.push(0xF),
            "reject" => {
                return Err(OperationError::decode(format!(
                    "BCD input has an odd digit count ({})",
                    digits.len()
                ))
                .with_expected("an even number of digits or a padding policy")
                .with_actual("padding=reject"));
            }
            _ => digits.insert(0, 0),
        }
    }
    let high_first = map.str_or("nibble_order", "high_first") == "high_first";
    Ok(Value::Bytes(bcd_nibbles_to_bytes(&digits, high_first)))
}

fn from_bcd_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "From BCD")?;
    let strict = map.bool_or("strict", true);
    let strip_padding = map.bool_or("strip_padding", false);
    let high_first = map.str_or("nibble_order", "high_first") == "high_first";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes.as_ref() {
        let nibbles = if high_first {
            [byte >> 4, byte & 0xF]
        } else {
            [byte & 0xF, byte >> 4]
        };
        for nibble in nibbles {
            match nibble {
                0..=9 => out.push((b'0' + nibble) as char),
                0xF if strip_padding || !strict => continue,
                other => {
                    return Err(OperationError::decode(format!(
                        "BCD byte 0x{byte:02x} holds the non-decimal nibble {other:X}"
                    ))
                    .with_expected("nibbles 0-9 (0xF only as padding)")
                    .with_actual(format!("nibble {other:X}")));
                }
            }
        }
    }
    Ok(Value::Text(out))
}

// --------------------------------------------------------------- ModHex ----

/// The ModHex table (YubiKey): hex digits mapped to keyboard-adjacent keys.
const MODHEX_ALPHABET: &[u8; 16] = b"cbdefghijklnrtuv";

fn to_modhex_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To ModHex")?;
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes.as_ref() {
        out.push(MODHEX_ALPHABET[(b >> 4) as usize] as char);
        out.push(MODHEX_ALPHABET[(b & 0xF) as usize] as char);
    }
    Ok(Value::Text(out))
}

fn from_modhex_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From ModHex")?;
    let strict = map.bool_or("strict", true);
    let mut nibbles: Vec<u8> = Vec::with_capacity(text.len());
    for c in text.chars() {
        match MODHEX_ALPHABET
            .iter()
            .position(|&a| a == c.to_ascii_lowercase() as u8)
        {
            Some(pos) => nibbles.push(pos as u8),
            None if !strict => continue,
            None => {
                return Err(OperationError::decode(format!(
                    "ModHex input contains the invalid character `{c}`"
                ))
                .with_expected("characters from `cbdefghijklnrtuv`")
                .with_actual(format!("`{c}`")));
            }
        }
    }
    if nibbles.len() % 2 != 0 {
        return Err(
            OperationError::decode("ModHex input has an odd number of characters")
                .with_expected("an even number of characters")
                .with_actual(format!("{} characters", nibbles.len())),
        );
    }
    let out = nibbles
        .chunks(2)
        .map(|pair| (pair[0] << 4) | pair[1])
        .collect();
    Ok(Value::Bytes(out))
}

// ----------------------------------------------------------------- COBS ----

/// Encode one COBS frame (Consistent Overhead Byte Stuffing): the overhead
/// byte counts up to the next zero, and a trailing 0x00 delimiter closes the
/// frame. A 0xFF overhead byte marks a full 254-byte run without a zero.
fn cobs_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 254 + 3);
    let mut block_start = 0usize;
    let mut code = 1usize;
    for (i, &b) in data.iter().enumerate() {
        if b == 0 {
            out.push(code as u8);
            out.extend_from_slice(&data[block_start..i]);
            block_start = i + 1;
            code = 1;
        } else {
            code += 1;
            if code == 0xFF {
                out.push(0xFF);
                out.extend_from_slice(&data[block_start..i + 1]);
                block_start = i + 1;
                code = 1;
            }
        }
    }
    out.push(code as u8);
    out.extend_from_slice(&data[block_start..]);
    out.push(0x00);
    out
}

/// Decode a COBS frame. The trailing 0x00 delimiter is optional; interior
/// zeros and truncated blocks are typed errors. Relaxed mode returns the
/// decodable prefix of a truncated stream instead of failing.
fn cobs_decode(data: &[u8], strict: bool) -> OpResult<Vec<u8>> {
    let data = if data.last() == Some(&0) {
        &data[..data.len() - 1]
    } else {
        data
    };
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0usize;
    while i < data.len() {
        let code = data[i] as usize;
        i += 1;
        if code == 0 {
            return Err(OperationError::decode(
                "COBS input contains a zero overhead byte (interior frame delimiter)",
            )
            .with_expected("non-zero overhead bytes between delimiters")
            .with_actual(format!("zero at offset {}", i - 1)));
        }
        let block_len = code - 1;
        if i + block_len > data.len() {
            if strict {
                return Err(OperationError::decode(
                    "truncated COBS block: the overhead byte promises more data than follows",
                )
                .with_expected(format!("at least {block_len} bytes after offset {i}"))
                .with_actual(format!("{} bytes remain", data.len() - i)));
            }
            out.extend_from_slice(&data[i..]);
            return Ok(out);
        }
        out.extend_from_slice(&data[i..i + block_len]);
        i += block_len;
        if code < 0xFF && i < data.len() {
            out.push(0);
        }
    }
    Ok(out)
}

fn to_cobs_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To COBS")?;
    Ok(Value::Bytes(cobs_encode(bytes.as_ref())))
}

fn from_cobs_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "From COBS")?;
    let strict = map.bool_or("strict", true);
    Ok(Value::Bytes(cobs_decode(bytes.as_ref(), strict)?))
}

// --------------------------------------------------------------- NetBIOS ----

/// RFC 1002 first-level (NetBIOS) name encoding: every byte becomes two
/// ASCII characters, one per nibble, offset by 'A'. With `pad_to_16` the
/// input is space-padded to the 16-byte NetBIOS name slot first.
fn to_netbios_name_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To NetBIOS Name")?;
    let mut data = bytes.as_ref().to_vec();
    if map.bool_or("pad_to_16", true) {
        if data.len() > 16 {
            return Err(OperationError::length(
                "at most 16 bytes for a padded RFC 1002 name",
                format!("{} bytes", data.len()),
                "NetBIOS name input is longer than the 16-byte name slot",
            ));
        }
        data.resize(16, b' ');
    }
    let mut out = String::with_capacity(data.len() * 2);
    for &b in &data {
        out.push((b'A' + (b >> 4)) as char);
        out.push((b'A' + (b & 0xF)) as char);
    }
    Ok(Value::Text(out))
}

fn from_netbios_name_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From NetBIOS Name")?;
    let strict = map.bool_or("strict", true);
    let mut nibbles: Vec<u8> = Vec::with_capacity(text.len());
    for c in text.chars() {
        let upper = c.to_ascii_uppercase();
        if ('A'..='P').contains(&upper) {
            nibbles.push(upper as u32 - 'A' as u32);
        } else if strict {
            return Err(OperationError::decode(format!(
                "NetBIOS encoded name contains the invalid character `{c}`"
            ))
            .with_expected("characters A-P (RFC 1002 first-level encoding)")
            .with_actual(format!("`{c}`")));
        }
    }
    if nibbles.len() % 2 != 0 {
        return Err(
            OperationError::decode("NetBIOS encoded name has an odd number of characters")
                .with_expected("an even number of characters")
                .with_actual(format!("{} characters", nibbles.len())),
        );
    }
    let out = nibbles
        .chunks(2)
        .map(|pair| ((pair[0] << 4) | pair[1]) as u8)
        .collect();
    Ok(Value::Bytes(out))
}

// --------------------------------------------------------------- Base100 ----

/// Base100 maps each byte to the emoji at code point `0x1F3F7 + b`
/// (U+1F3F7..U+1F4F6), the algorithm of the reference `base100` crate that
/// ToolsFx and the CTF ecosystem match.
const BASE100_OFFSET: u32 = 0x1F3F7;

fn to_base100_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Base100")?;
    let mut out = String::with_capacity(bytes.len() * 4);
    for &b in bytes.as_ref() {
        let cp = BASE100_OFFSET + b as u32;
        out.push(char::from_u32(cp).expect("base100 range is inside the scalar space"));
    }
    Ok(Value::Text(out))
}

fn from_base100_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From Base100")?;
    let strict = map.bool_or("strict", true);
    let mut out = Vec::with_capacity(text.chars().count());
    for c in text.chars() {
        let cp = c as u32;
        if (BASE100_OFFSET..=BASE100_OFFSET + 0xFF).contains(&cp) {
            out.push((cp - BASE100_OFFSET) as u8);
        } else if strict {
            return Err(OperationError::decode(format!(
                "Base100 input contains `{c}` (U+{cp:04X}) outside the emoji range"
            ))
            .with_expected("U+1F3F7..U+1F4F6, one emoji per byte")
            .with_actual(format!("U+{cp:04X}")));
        }
    }
    Ok(Value::Bytes(out))
}

// ------------------------------------------------------------- registry ----

pub(crate) fn register(reg: &mut OperationRegistry) {
    use cybercipher_core::Category::Encoding as E;
    use cybercipher_core::CostClass::Instant;

    reg.add_simple(
        spec(
            "to-c-escapes",
            "To C Escapes",
            "Encodes text as a C string body: named two-char escapes, 3-digit octal \
             for other control bytes, backslash/quote escaping; non-ASCII stays \
             as UTF-8.",
            E,
            &[B, T],
            T,
            Instant,
            true,
            vec![],
            ENC_TAG,
            &["c escape", "c string escape", "escape c"],
            "C standard escape sequences (ISO/IEC 9899)",
            "Round-trip tests (all ASCII) + escape-form vectors",
        ),
        to_c_escapes_op,
    );

    reg.add_simple(
        spec(
            "from-c-escapes",
            "From C Escapes",
            "Decodes C escape sequences: two-char escapes, octal \\NNN (max 0377) \
             and \\xHH. Strict mode rejects unknown escapes and out-of-range \
             values; relaxed mode keeps them verbatim.",
            E,
            &[T],
            B,
            Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Fail on unknown escapes and out-of-range values instead of keeping them.",
            )],
            ENC_TAG,
            &["c unescape", "c string decode"],
            "C standard escape sequences (ISO/IEC 9899)",
            "Round-trip tests + malformed-input tests",
        ),
        from_c_escapes_op,
    );

    reg.add_simple(
        spec(
            "to-json-escape",
            "To JSON Escape",
            "Escapes text as a JSON string body (RFC 8259): quote/backslash and \
             control characters are escaped, non-ASCII stays as UTF-8.",
            E,
            &[B, T],
            T,
            Instant,
            true,
            vec![],
            ENC_TAG,
            &["json escape", "json stringify escape"],
            "RFC 8259 (JSON) string grammar",
            "serde_json parse-back validation + round-trip tests",
        ),
        to_json_escape_op,
    );

    reg.add_simple(
        spec(
            "to-bcd",
            "To BCD",
            "Packs decimal digits one per nibble (\"1234\" -> 0x12 0x34). Nibble \
             order and odd-digit padding are configurable.",
            E,
            &[B, T],
            B,
            Instant,
            true,
            vec![
                p_opts(
                    "nibble_order",
                    "Nibble order",
                    "high_first",
                    &[
                        ParamOption {
                            value: "high_first",
                            label: "High nibble first (0x12 0x34)",
                        },
                        ParamOption {
                            value: "low_first",
                            label: "Low nibble first (0x21 0x43)",
                        },
                    ],
                    "Which nibble of each byte holds the earlier digit.",
                ),
                p_opts(
                    "padding",
                    "Odd-digit padding",
                    "zero",
                    &[
                        ParamOption {
                            value: "zero",
                            label: "Prepend a zero nibble",
                        },
                        ParamOption {
                            value: "f",
                            label: "Append an 0xF nibble (telephony)",
                        },
                        ParamOption {
                            value: "reject",
                            label: "Reject odd digit counts",
                        },
                    ],
                    "How to handle an odd number of digits.",
                ),
            ],
            ENC_TAG,
            &["bcd encode", "binary coded decimal"],
            "Binary-coded decimal convention (ISO/ITU telephony usage)",
            "Round-trip tests + padding vectors",
        ),
        to_bcd_op,
    );

    reg.add_simple(
        spec(
            "from-bcd",
            "From BCD",
            "Expands one decimal digit per nibble into text. Non-decimal nibbles \
             are errors in strict mode; 0xF padding can be stripped.",
            E,
            &[B, T],
            T,
            Instant,
            true,
            vec![
                p_opts(
                    "nibble_order",
                    "Nibble order",
                    "high_first",
                    &[
                        ParamOption {
                            value: "high_first",
                            label: "High nibble first (0x12 0x34)",
                        },
                        ParamOption {
                            value: "low_first",
                            label: "Low nibble first (0x21 0x43)",
                        },
                    ],
                    "Which nibble of each byte holds the earlier digit.",
                ),
                p_bool(
                    "strip_padding",
                    "Strip 0xF padding",
                    false,
                    "Drop 0xF nibbles (telephony padding) instead of failing.",
                ),
            ],
            ENC_TAG,
            &["bcd decode", "binary coded decimal"],
            "Binary-coded decimal convention (ISO/ITU telephony usage)",
            "Round-trip tests + malformed-nibble tests",
        ),
        from_bcd_op,
    );

    reg.add_simple(
        spec(
            "to-modhex",
            "To ModHex",
            "Encodes bytes with the YubiKey ModHex alphabet \
             (hex digits mapped to `cbdefghijklnrtuv`).",
            E,
            &[B, T],
            T,
            Instant,
            true,
            vec![],
            ENC_TAG,
            &["modhex encode", "yubikey"],
            "ModHex (Yubico YubiKey OTP encoding)",
            "Alphabet vectors + round-trip tests",
        ),
        to_modhex_op,
    );

    reg.add_simple(
        spec(
            "from-modhex",
            "From ModHex",
            "Decodes ModHex text (YubiKey alphabet). Strict mode rejects characters \
             outside `cbdefghijklnrtuv`; relaxed mode ignores them.",
            E,
            &[T],
            B,
            Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Fail on characters outside the ModHex alphabet.",
            )],
            ENC_TAG,
            &["modhex decode", "yubikey"],
            "ModHex (Yubico YubiKey OTP encoding)",
            "Alphabet vectors + round-trip + malformed tests",
        ),
        from_modhex_op,
    );

    reg.add_simple(
        spec(
            "to-cobs",
            "To COBS",
            "Encodes one Consistent Overhead Byte Stuffing frame: zero bytes are \
             removed with overhead-byte pointers and the frame is closed with a \
             0x00 delimiter.",
            E,
            &[B, T],
            B,
            Instant,
            true,
            vec![],
            ENC_TAG,
            &["cobs encode", "byte stuffing"],
            "Consistent Overhead Byte Stuffing (Chesire, SIGCOMM '97; PPP-style framing)",
            "Reference vectors + round-trip tests (all lengths 0-600)",
        ),
        to_cobs_op,
    );

    reg.add_simple(
        spec(
            "from-cobs",
            "From COBS",
            "Decodes a COBS frame (trailing 0x00 delimiter optional). Interior \
             zeros and truncated blocks are typed errors; relaxed mode returns \
             the decodable prefix of a truncated stream.",
            E,
            &[B, T],
            B,
            Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Fail on truncated blocks and interior zeros instead of recovering a prefix.",
            )],
            ENC_TAG,
            &["cobs decode", "unstuff bytes"],
            "Consistent Overhead Byte Stuffing (Chesire, SIGCOMM '97; PPP-style framing)",
            "Reference vectors + round-trip + malformed tests",
        ),
        from_cobs_op,
    );

    reg.add_simple(
        spec(
            "to-netbios-name",
            "To NetBIOS Name",
            "Encodes bytes with RFC 1002 first-level encoding (each byte becomes \
             two letters A-P). Input is space-padded to the 16-byte name slot by \
             default.",
            E,
            &[B, T],
            T,
            Instant,
            true,
            vec![p_bool(
                "pad_to_16",
                "Pad to 16 bytes",
                true,
                "Pad with spaces to the RFC 1002 name slot length (fails if longer).",
            )],
            ENC_TAG,
            &["netbios encode", "nbname", "rfc 1002"],
            "RFC 1002 section 4.1 (first-level encoding)",
            "RFC 1002 mapping vectors + round-trip tests",
        ),
        to_netbios_name_op,
    );

    reg.add_simple(
        spec(
            "from-netbios-name",
            "From NetBIOS Name",
            "Decodes RFC 1002 first-level encoding (pairs of letters A-P back into \
             bytes). Strict mode rejects other characters; relaxed mode ignores \
             them.",
            E,
            &[T],
            B,
            Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Fail on characters outside A-P instead of ignoring them.",
            )],
            ENC_TAG,
            &["netbios decode", "nbname", "rfc 1002"],
            "RFC 1002 section 4.1 (first-level encoding)",
            "RFC 1002 mapping vectors + round-trip + malformed tests",
        ),
        from_netbios_name_op,
    );

    reg.add_simple(
        spec(
            "to-base100",
            "To Base100",
            "Encodes bytes as Base100 emoji: each byte becomes the emoji at code \
             point 0x1F3F7 + byte (U+1F3F7..U+1F4F6).",
            E,
            &[B, T],
            T,
            Instant,
            true,
            vec![],
            ENC_TAG,
            &["base100 encode", "emoji encode", "emoji base"],
            "Base100 (AdamNiederer/base100 reference algorithm)",
            "Reference README vectors + full byte-range round-trip",
        ),
        to_base100_op,
    );

    reg.add_simple(
        spec(
            "from-base100",
            "From Base100",
            "Decodes Base100 emoji back into bytes. Strict mode rejects any \
             character outside U+1F3F7..U+1F4F6; relaxed mode ignores them.",
            E,
            &[T],
            B,
            Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Fail on characters outside the Base100 emoji range.",
            )],
            ENC_TAG,
            &["base100 decode", "emoji decode"],
            "Base100 (AdamNiederer/base100 reference algorithm)",
            "Reference README vectors + full byte-range round-trip",
        ),
        from_base100_op,
    );
}

// -------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ExecutionContext {
        ExecutionContext::new()
    }

    fn strict_off() -> ParamMap {
        let mut map = ParamMap::new();
        map.insert("strict", false);
        map
    }

    // -------------------------------------------------------- C escapes ----

    #[test]
    fn c_escapes_known_forms() {
        assert_eq!(encode_c_escapes("a\nb\\\"c"), "a\\nb\\\\\\\"c");
        assert_eq!(
            encode_c_escapes("\u{7}\u{8}\u{b}\u{c}\0"),
            "\\a\\b\\v\\f\\0"
        );
        assert_eq!(encode_c_escapes("\u{1}\u{7f}"), "\\001\\177");
        assert_eq!(encode_c_escapes("é中"), "é中");
        assert_eq!(decode_c_escapes("\\101\\x42\\n", true).unwrap(), b"AB\n");
        assert_eq!(decode_c_escapes("\\377", true).unwrap(), vec![0xFF]);
    }

    #[test]
    fn c_escapes_roundtrip_all_ascii() {
        let text: String = (0u8..=0x7F).map(|b| b as char).collect();
        let enc = encode_c_escapes(&text);
        assert_eq!(decode_c_escapes(&enc, true).unwrap(), text.as_bytes());
    }

    #[test]
    fn c_escapes_strict_rejects_and_relaxed_keeps() {
        for bad in ["\\q", "\\x", "trailing\\", "\\400"] {
            assert!(
                decode_c_escapes(bad, true).is_err(),
                "strict must reject {bad}"
            );
        }
        assert_eq!(decode_c_escapes("a\\qb", false).unwrap(), b"a\\qb".to_vec());
        assert_eq!(decode_c_escapes("\\400", false).unwrap(), b"\\400".to_vec());
    }

    // -------------------------------------------------------- JSON escape ----

    #[test]
    fn json_escape_form_and_roundtrip() {
        let text = "a\"b\\c\nd\u{7}é";
        let enc = encode_json_string(text);
        assert_eq!(enc, "a\\\"b\\\\c\\nd\\u0007é");
        // The escaped body must be a valid JSON string with the original text.
        let parsed: String =
            serde_json::from_str(&format!("\"{enc}\"")).expect("valid JSON string");
        assert_eq!(parsed, text);
    }

    // ---------------------------------------------------------------- BCD ----

    #[test]
    fn bcd_packing_vectors() {
        let mut map = ParamMap::new();
        map.insert("nibble_order", "high_first");
        assert_eq!(
            to_bcd_op(&Value::Text("1234".into()), &map, &ctx()).unwrap(),
            Value::Bytes(vec![0x12, 0x34])
        );
        map.insert("nibble_order", "low_first");
        assert_eq!(
            to_bcd_op(&Value::Text("1234".into()), &map, &ctx()).unwrap(),
            Value::Bytes(vec![0x21, 0x43])
        );
        map.insert("nibble_order", "high_first");
        // Odd digit count: default zero-prefix preserves the value.
        assert_eq!(
            to_bcd_op(&Value::Text("123".into()), &map, &ctx()).unwrap(),
            Value::Bytes(vec![0x01, 0x23])
        );
        map.insert("padding", "f");
        assert_eq!(
            to_bcd_op(&Value::Text("123".into()), &map, &ctx()).unwrap(),
            Value::Bytes(vec![0x12, 0x3F])
        );
        map.insert("padding", "reject");
        assert!(
            to_bcd_op(&Value::Text("123".into()), &map, &ctx()).is_err(),
            "padding=reject must fail on odd digit counts"
        );
    }

    #[test]
    fn bcd_decode_strict_and_relaxed() {
        let mut map = ParamMap::new();
        assert_eq!(
            from_bcd_op(&Value::Bytes(vec![0x12, 0x34]), &map, &ctx()).unwrap(),
            Value::Text("1234".into())
        );
        map.insert("strip_padding", true);
        assert_eq!(
            from_bcd_op(&Value::Bytes(vec![0x12, 0x3F]), &map, &ctx()).unwrap(),
            Value::Text("123".into())
        );
        // Non-decimal nibble A: strict error, relaxed drops it.
        assert!(from_bcd_op(&Value::Bytes(vec![0x1A]), &map, &ctx()).is_err());
        assert_eq!(
            from_bcd_op(&Value::Bytes(vec![0x1A]), &strict_off(), &ctx()).unwrap(),
            Value::Text("1".into())
        );
    }

    #[test]
    fn bcd_roundtrip_digits() {
        for text in ["0", "7", "42", "0123456789", "9999999999999999"] {
            let enc = to_bcd_op(&Value::Text(text.into()), &ParamMap::new(), &ctx()).unwrap();
            assert_eq!(
                from_bcd_op(&enc, &ParamMap::new(), &ctx()).unwrap(),
                Value::Text(text.into())
            );
        }
    }

    // -------------------------------------------------------------- ModHex ----

    #[test]
    fn modhex_alphabet_vector() {
        let data = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let enc = to_modhex_op(&Value::Bytes(data.to_vec()), &ParamMap::new(), &ctx()).unwrap();
        assert_eq!(enc, Value::Text("cbdefghijklnrtuv".into()));
        assert_eq!(
            from_modhex_op(&enc, &ParamMap::new(), &ctx()).unwrap(),
            Value::Bytes(data.to_vec())
        );
    }

    #[test]
    fn modhex_roundtrip_binary() {
        let data: Vec<u8> = (0..=255u8).cycle().take(512).collect();
        let enc = to_modhex_op(&Value::Bytes(data.clone()), &ParamMap::new(), &ctx()).unwrap();
        assert_eq!(
            from_modhex_op(&enc, &ParamMap::new(), &ctx()).unwrap(),
            Value::Bytes(data)
        );
        assert!(from_modhex_op(&Value::Text("zz".into()), &ParamMap::new(), &ctx()).is_err());
        // Relaxed drops the invalid `z`, leaving the nibble pair "cz" -> 0x0C.
        assert_eq!(
            from_modhex_op(&Value::Text("cz".into()), &strict_off(), &ctx()).unwrap(),
            Value::Bytes(vec![0x0C])
        );
    }

    // ---------------------------------------------------------------- COBS ----

    #[test]
    fn cobs_reference_vectors() {
        assert_eq!(cobs_encode(&[]), vec![0x01, 0x00]);
        assert_eq!(cobs_encode(&[0x00]), vec![0x01, 0x01, 0x00]);
        assert_eq!(
            cobs_encode(&[0x11, 0x22, 0x00, 0x33]),
            vec![0x03, 0x11, 0x22, 0x02, 0x33, 0x00]
        );
        assert_eq!(
            cobs_decode(&[0x03, 0x11, 0x22, 0x02, 0x33], true).unwrap(),
            vec![0x11, 0x22, 0x00, 0x33]
        );
        assert_eq!(cobs_decode(&[0x01, 0x01, 0x00], true).unwrap(), vec![0x00]);
        assert_eq!(cobs_decode(&[0x01], true).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn cobs_roundtrip_all_lengths() {
        for len in 0..=600usize {
            let data: Vec<u8> = (0..len as u8).cycle().take(len).collect();
            let enc = cobs_encode(&data);
            assert_eq!(cobs_decode(&enc, true).unwrap(), data, "len {len}");
        }
        // Worst case: 254-byte blocks with the 0xFF overhead byte.
        let data = vec![0xAAu8; 255];
        let enc = cobs_encode(&data);
        assert_eq!(&enc[..2], &[0xFF, 0xAA]);
        assert_eq!(cobs_decode(&enc, true).unwrap(), data);
    }

    #[test]
    fn cobs_strict_rejects_malformed_and_relaxed_recovers() {
        // Zero overhead byte inside the frame.
        assert!(cobs_decode(&[0x03, 0x11, 0x00, 0x02, 0x33], true).is_err());
        // Truncated block: overhead promises 2 data bytes, only 1 follows.
        assert!(cobs_decode(&[0x03, 0x11], true).is_err());
        assert_eq!(cobs_decode(&[0x03, 0x11], false).unwrap(), vec![0x11]);
    }

    // -------------------------------------------------------------- NetBIOS ----

    #[test]
    fn netbios_encoding_vectors() {
        let mut map = ParamMap::new();
        map.insert("pad_to_16", false);
        let data = vec![0x00u8, 0xFF, 0x41];
        let enc = to_netbios_name_op(&Value::Bytes(data.clone()), &map, &ctx()).unwrap();
        assert_eq!(enc, Value::Text("AAPBEB".into()));
        assert_eq!(
            from_netbios_name_op(&enc, &ParamMap::new(), &ctx()).unwrap(),
            Value::Bytes(data)
        );
    }

    #[test]
    fn netbios_pads_to_16_bytes() {
        let enc =
            to_netbios_name_op(&Value::Text("FRED".into()), &ParamMap::new(), &ctx()).unwrap();
        let Value::Text(text) = enc else {
            panic!("text output")
        };
        assert_eq!(text.chars().count(), 32);
        // 'F'=0x46 -> "EG", 'R'=0x52 -> "FC", 'E'=0x45 -> "EF", 'D'=0x44 -> "EE".
        assert!(text.starts_with("EGFCEFEE"));
        assert!(text.ends_with("CACA"));
        assert_eq!(
            from_netbios_name_op(&Value::Text(text), &ParamMap::new(), &ctx()).unwrap(),
            Value::Bytes(b"FRED".iter().copied().chain([b' '; 12]).collect())
        );
        // Longer than the name slot: typed error.
        assert!(to_netbios_name_op(&Value::Bytes(vec![0; 17]), &ParamMap::new(), &ctx()).is_err());
    }

    #[test]
    fn netbios_strict_rejects_invalid_characters() {
        assert!(from_netbios_name_op(&Value::Text("Q!".into()), &ParamMap::new(), &ctx()).is_err());
        // Relaxed ignores them; an all-invalid input decodes to empty bytes.
        assert_eq!(
            from_netbios_name_op(&Value::Text("Q!".into()), &strict_off(), &ctx()).unwrap(),
            Value::Bytes(Vec::new())
        );
        // An odd surviving nibble count still errors even in relaxed mode.
        let err =
            from_netbios_name_op(&Value::Text("A!".into()), &strict_off(), &ctx()).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Decode);
    }

    // -------------------------------------------------------------- Base100 ----

    #[test]
    fn base100_reference_vectors() {
        // From the reference crate README: "the quick brown fox ..." begins
        // with the emoji for 't' (U+1F46B), 'h' (U+1F45F), 'e' (U+1F45C).
        let enc = to_base100_op(&Value::Text("the".into()), &ParamMap::new(), &ctx()).unwrap();
        assert_eq!(enc, Value::Text("\u{1F46B}\u{1F45F}\u{1F45C}".into()));
    }

    #[test]
    fn base100_roundtrip_all_bytes() {
        let data: Vec<u8> = (0..=255u8).collect();
        let enc = to_base100_op(&Value::Bytes(data.clone()), &ParamMap::new(), &ctx()).unwrap();
        assert_eq!(enc.kind(), ValueKind::Text);
        assert_eq!(
            from_base100_op(&enc, &ParamMap::new(), &ctx()).unwrap(),
            Value::Bytes(data)
        );
        assert!(from_base100_op(&Value::Text("hi".into()), &ParamMap::new(), &ctx()).is_err());
        assert_eq!(
            from_base100_op(&Value::Text("hi".into()), &strict_off(), &ctx()).unwrap(),
            Value::Bytes(Vec::new())
        );
    }

    // ------------------------------------------------------------- registry ----

    #[test]
    fn transform_ops_are_registered_and_reversible() {
        let mut reg = cybercipher_core::OperationRegistry::new();
        register(&mut reg);
        for id in [
            "to-c-escapes",
            "from-c-escapes",
            "to-json-escape",
            "to-bcd",
            "from-bcd",
            "to-modhex",
            "from-modhex",
            "to-cobs",
            "from-cobs",
            "to-netbios-name",
            "from-netbios-name",
            "to-base100",
            "from-base100",
        ] {
            assert!(reg.get(id).is_some(), "missing op {id}");
        }
        // Registry-level round trip through COBS.
        let cobs = reg.get("to-cobs").unwrap();
        let enc = cobs
            .execute(&Value::Bytes(vec![0, 1, 2, 0]), &ParamMap::new(), &ctx())
            .unwrap();
        let uncobs = reg.get("from-cobs").unwrap();
        assert_eq!(
            uncobs.execute(&enc, &ParamMap::new(), &ctx()).unwrap(),
            Value::Bytes(vec![0, 1, 2, 0])
        );
    }
}
