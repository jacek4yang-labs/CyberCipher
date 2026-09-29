//! Base families beyond RFC 4648: Base36, Base45 (RFC 9285), Base58 /
//! Base58Check (Bitcoin), Base62, Ascii85 (btoa/Adobe), Z85 (ZeroMQ), and
//! basE91 (Joachim Henke).
//!
//! Conventions (documented per operation, pinned by tests):
//!
//! * **Big-number bases** (Base36, Base58, Base62) treat the input as an
//!   unsigned big-endian big-integer. There is no length prefix, so leading
//!   zero bytes are *not* representable and decode returns the minimal
//!   big-endian byte string. The all-zero input encodes to a single `0`
//!   digit (Base58: a single `1`), and Base58 additionally maps every
//!   leading zero byte to a leading `1` (Bitcoin convention).
//! * **Chunked bases** (Base45, Ascii85, Z85, basE91) preserve every input
//!   byte and are exactly reversible.
//! * **Strict decode** (the default) rejects any character outside the
//!   alphabet (and, unless documented otherwise, any internal whitespace);
//!   **relaxed decode** silently drops non-alphabet characters before
//!   decoding. Error offsets refer to the character stream the decoder
//!   actually walks (the trimmed input in strict mode, the filtered input in
//!   relaxed mode).
//! * Big-number conversions are capped at 1 MiB of input with a typed
//!   budget error; chunked bases are linear and uncapped.

use crate::helpers::{input_bytes, input_text, p_bool, p_int, p_opts, spec};
use cybercipher_core::prelude::*;
use num_bigint::BigUint;
use num_traits::Zero;
use sha2::{Digest, Sha256};

/// Input cap for big-number conversions (Base36/58/58Check/62).
const BIGNUM_MAX_INPUT: usize = 1 << 20; // 1 MiB

fn check_bignum_budget(len: usize, direction: &str, base: &str) -> OpResult<()> {
    if len > BIGNUM_MAX_INPUT {
        return Err(OperationError::new(
            ErrorKind::BudgetExceeded,
            format!("{base} {direction} input of {len} bytes exceeds the 1 MiB big-number limit"),
        )
        .with_expected("at most 1048576 bytes")
        .with_actual(format!("{len} bytes"))
        .with_details(
            "Big-number conversions are superlinear; split the input or use a chunked base such as Base45 or Ascii85.",
        ));
    }
    Ok(())
}

/// Map a character to its digit value in `alphabet`, or `None`.
/// Alphabets are ASCII byte strings.
fn digit_of(c: char, alphabet: &[u8]) -> Option<u8> {
    if !c.is_ascii() {
        return None;
    }
    alphabet.iter().position(|&a| a == c as u8).map(|p| p as u8)
}

fn invalid_char(base: &str, c: char, idx: usize) -> OperationError {
    OperationError::decode(format!("invalid {base} character `{c}` at offset {idx}"))
        .with_expected(format!("a character from the {base} alphabet"))
        .with_actual(format!("character at offset {idx}"))
        .with_details("Disable strict mode to drop invalid characters before decoding.")
}

/// Map a character to its digit value, optionally accepting lowercase
/// spellings for uppercase-only alphabets (Base36).
fn digit_of_folded(c: char, alphabet: &[u8], case_fold: bool) -> Option<u8> {
    if let Some(d) = digit_of(c, alphabet) {
        return Some(d);
    }
    if case_fold && c.is_ascii_lowercase() {
        return digit_of(c.to_ascii_uppercase(), alphabet);
    }
    None
}

// ------------------------------------------------------------- Base36 ----

const B36_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

fn base36_encode(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Base36")?;
    check_bignum_budget(bytes.len(), "encode", "Base36")?;
    Ok(Value::Text(bignum_encode_text(
        bytes.as_ref(),
        B36_ALPHABET,
    )))
}

/// Encode bytes as a big-endian big-integer in `alphabet`. Leading zero
/// bytes are trimmed (no length prefix exists); an all-zero input encodes
/// to a single `alphabet[0]` digit.
fn bignum_encode_text(bytes: &[u8], alphabet: &[u8]) -> String {
    let radix = alphabet.len() as u32;
    if bytes.is_empty() {
        return String::new();
    }
    let num = BigUint::from_bytes_be(bytes);
    num.to_radix_le(radix)
        .into_iter()
        .rev()
        .map(|d| alphabet[d as usize] as char)
        .collect()
}

fn base36_decode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From Base36")?;
    let strict = map.bool_or("strict", true);
    check_bignum_budget(text.len(), "decode", "Base36")?;
    let digits = collect_digits(text, strict, "Base36", B36_ALPHABET, true)?;
    Ok(Value::Bytes(bignum_decode_bytes(&digits, 36)))
}

/// Walk the input character stream applying the strict/relaxed whitespace
/// policy and collect digit values. `case_fold` accepts lowercase spellings
/// of uppercase-only alphabets (Base36). Offsets refer to the stream the
/// decoder walks (trimmed input in strict mode, filtered in relaxed mode).
fn collect_digits(
    text: &str,
    strict: bool,
    base: &str,
    alphabet: &[u8],
    case_fold: bool,
) -> OpResult<Vec<u8>> {
    if strict {
        let trimmed = text.trim();
        let mut digits = Vec::with_capacity(trimmed.len());
        for (idx, c) in trimmed.chars().enumerate() {
            match digit_of_folded(c, alphabet, case_fold) {
                Some(d) => digits.push(d),
                None if c.is_whitespace() => {
                    return Err(OperationError::decode(format!(
                        "strict {base} input contains whitespace at offset {idx}"
                    ))
                    .with_details(
                        "Disable strict mode to ignore whitespace and invalid characters.",
                    ));
                }
                None => return Err(invalid_char(base, c, idx)),
            }
        }
        Ok(digits)
    } else {
        let mut digits = Vec::with_capacity(text.len());
        for c in text.chars() {
            if let Some(d) = digit_of_folded(c, alphabet, case_fold) {
                digits.push(d);
            }
        }
        Ok(digits)
    }
}

/// Convert collected digits (big-endian, radix `radix`) back to bytes.
/// An empty digit list yields empty output; a single zero digit yields
/// `[0]`; leading zeros beyond that are not representable.
fn bignum_decode_bytes(digits: &[u8], radix: u32) -> Vec<u8> {
    if digits.is_empty() {
        return Vec::new();
    }
    let mut num = BigUint::zero();
    for &d in digits {
        num = num * radix + d;
    }
    let mut out = num.to_bytes_be();
    if out.is_empty() {
        out.push(0);
    }
    out
}

// ------------------------------------------------------------- Base45 ----

/// RFC 9285 Table 1. Value 36 is a literal space.
const B45_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

fn base45_encode(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Base45")?;
    let mut out = String::with_capacity(bytes.len().div_ceil(2) * 3);
    for chunk in bytes.chunks(2) {
        let n: u32 = if chunk.len() == 2 {
            chunk[0] as u32 * 256 + chunk[1] as u32
        } else {
            chunk[0] as u32
        };
        let digits = if chunk.len() == 2 { 3 } else { 2 };
        for i in 0..digits {
            out.push(B45_ALPHABET[((n / 45u32.pow(i)) % 45) as usize] as char);
        }
    }
    Ok(Value::Text(out))
}

fn base45_decode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From Base45")?;
    let strict = map.bool_or("strict", true);
    let digits = collect_digits(text, strict, "Base45", B45_ALPHABET, false)?;
    if digits.len() % 3 == 1 {
        return Err(OperationError::decode(
            "Base45 input length is invalid (a lone trailing character has no group)",
        )
        .with_expected("length mod 3 of 0 or 2")
        .with_actual(format!("length {}", digits.len()))
        .with_details("RFC 9285 groups bytes in pairs: two bytes become three characters, a trailing single byte becomes two characters."));
    }
    let mut out = Vec::with_capacity(digits.len() / 3 * 2 + 1);
    let (groups, remainder) = digits.as_chunks::<3>();
    for g in groups {
        let n = g[0] as u32 + 45 * g[1] as u32 + 2025 * g[2] as u32;
        if n > 0xFFFF {
            return Err(OperationError::decode(format!(
                "Base45 group `{}` decodes to {n}, which exceeds the 16-bit pair range",
                group_text(&[
                    B45_ALPHABET[g[0] as usize],
                    B45_ALPHABET[g[1] as usize],
                    B45_ALPHABET[g[2] as usize]
                ])
            ))
            .with_expected("a group value of at most 65535 (RFC 9285)"));
        }
        out.push((n / 256) as u8);
        out.push((n % 256) as u8);
    }
    if let [c0, c1] = remainder {
        let n = *c0 as u32 + 45 * *c1 as u32;
        if n > 0xFF {
            return Err(OperationError::decode(format!(
                "final Base45 group `{}` decodes to {n}, which exceeds the single-byte range",
                group_text(&[B45_ALPHABET[*c0 as usize], B45_ALPHABET[*c1 as usize]])
            ))
            .with_expected("a final group value of at most 255 (RFC 9285)"));
        }
        out.push(n as u8);
    }
    Ok(Value::Bytes(out))
}

fn group_text(chars: &[u8]) -> String {
    chars.iter().map(|&b| b as char).collect()
}

// ------------------------------------------------------------- Base58 ----

/// Bitcoin alphabet (excludes 0, O, I, l).
const B58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_encode(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Base58")?;
    check_bignum_budget(bytes.len(), "encode", "Base58")?;
    Ok(Value::Text(base58_encode_bytes(bytes.as_ref())))
}

/// Base58 with the Bitcoin leading-zero convention: every leading zero byte
/// becomes a leading `1`.
fn base58_encode_bytes(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let mut out = String::with_capacity(bytes.len() * 138 / 100 + 1);
    for _ in 0..zeros {
        out.push('1');
    }
    if zeros < bytes.len() {
        let num = BigUint::from_bytes_be(&bytes[zeros..]);
        out.extend(
            num.to_radix_le(58)
                .into_iter()
                .rev()
                .map(|d| B58_ALPHABET[d as usize] as char),
        );
    }
    out
}

/// Strict Base58 decode honoring the leading-`1` zero-byte convention.
fn base58_decode_strict(trimmed: &str) -> OpResult<Vec<u8>> {
    let mut zeros = 0usize;
    let mut past_leading = false;
    let mut num = BigUint::zero();
    for (idx, c) in trimmed.chars().enumerate() {
        let d = digit_of(c, B58_ALPHABET).ok_or_else(|| invalid_char("Base58", c, idx))?;
        if !past_leading {
            if c == '1' {
                zeros += 1;
                continue;
            }
            past_leading = true;
        }
        num = num * 58u32 + d;
    }
    let mut out = vec![0u8; zeros];
    if past_leading {
        out.extend(num.to_bytes_be());
    }
    Ok(out)
}

fn base58_decode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From Base58")?;
    let strict = map.bool_or("strict", true);
    check_bignum_budget(text.len(), "decode", "Base58")?;
    if strict {
        Ok(Value::Bytes(base58_decode_strict(text.trim())?))
    } else {
        let filtered: String = text
            .chars()
            .filter(|c| digit_of(*c, B58_ALPHABET).is_some())
            .collect();
        Ok(Value::Bytes(base58_decode_strict(&filtered)?))
    }
}

// -------------------------------------------------------- Base58Check ----

fn base58check_encode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Base58Check")?;
    check_bignum_budget(bytes.len().saturating_add(5), "encode", "Base58Check")?;
    let version = map.int_or("version", 0);
    if !(0..=255).contains(&version) {
        return Err(OperationError::invalid_param(
            "version",
            format!("version byte must be 0-255, got {version}"),
        )
        .with_expected("0-255")
        .with_actual(version.to_string()));
    }
    let mut data = Vec::with_capacity(bytes.len() + 5);
    data.push(version as u8);
    data.extend_from_slice(bytes.as_ref());
    let checksum = double_sha256(&data);
    data.extend_from_slice(&checksum);
    Ok(Value::Text(base58_encode_bytes(&data)))
}

fn double_sha256(data: &[u8]) -> [u8; 4] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    [second[0], second[1], second[2], second[3]]
}

fn base58check_decode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From Base58Check")?;
    // Checksum validation is the point of Base58Check; there is no relaxed
    // mode that skips it.
    let expect_version = map.int_or("version", -1);
    if !(-1..=255).contains(&expect_version) {
        return Err(OperationError::invalid_param(
            "version",
            format!("version parameter must be -1 (any) or 0-255, got {expect_version}"),
        ));
    }
    let output = map.str_or("output", "payload");

    let data = base58_decode_strict(text.trim())?;
    check_bignum_budget(data.len(), "decode", "Base58Check")?;
    if data.len() < 5 {
        return Err(OperationError::decode(format!(
            "Base58Check payload is too short: {} byte(s) cannot hold version + payload + 4-byte checksum",
            data.len()
        ))
        .with_expected("at least 5 bytes after Base58 decoding")
        .with_actual(format!("{} bytes", data.len())));
    }
    let (versioned, checksum) = data.split_at(data.len() - 4);
    let version = versioned[0];
    let expected = double_sha256(versioned);
    if checksum != expected {
        return Err(OperationError::decode("Base58Check checksum mismatch")
            .with_expected(format!(
                "checksum {:02x}{:02x}{:02x}{:02x} (derived from the payload)",
                expected[0], expected[1], expected[2], expected[3]
            ))
            .with_actual(format!(
                "checksum {:02x}{:02x}{:02x}{:02x}",
                checksum[0], checksum[1], checksum[2], checksum[3]
            ))
            .with_details(format!(
                "The data is corrupted or truncated. Version byte found: 0x{version:02x}."
            )));
    }
    if expect_version >= 0 && version != expect_version as u8 {
        return Err(OperationError::decode(format!(
            "Base58Check version byte mismatch: found 0x{version:02x}, expected 0x{expect_version:02x}"
        ))
        .with_expected(format!("version byte 0x{expect_version:02x}"))
        .with_actual(format!("version byte 0x{version:02x}")));
    }
    match output {
        "versioned" => Ok(Value::Bytes(versioned.to_vec())),
        _ => Ok(Value::Bytes(versioned[1..].to_vec())),
    }
}

// ------------------------------------------------------------- Base62 ----

const B62_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn base62_encode(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Base62")?;
    check_bignum_budget(bytes.len(), "encode", "Base62")?;
    Ok(Value::Text(bignum_encode_text(
        bytes.as_ref(),
        B62_ALPHABET,
    )))
}

fn base62_decode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From Base62")?;
    let strict = map.bool_or("strict", true);
    check_bignum_budget(text.len(), "decode", "Base62")?;
    let digits = collect_digits(text, strict, "Base62", B62_ALPHABET, false)?;
    Ok(Value::Bytes(bignum_decode_bytes(&digits, 62)))
}

// ------------------------------------------------------------ Ascii85 ----

/// btoa/Adobe Ascii85: digits 0-84 map to characters '!'..'u'. `z` replaces
/// an all-zero group and `y` (when enabled) a group of four spaces; both
/// shorthands are only valid for complete groups and only at group
/// boundaries on decode.
fn ascii85_encode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Ascii85")?;
    let delimiters = map.bool_or("delimiters", false);
    let zero = map.bool_or("zero_shorthand", true);
    let y = map.bool_or("y_shorthand", false);

    let mut out = String::with_capacity(bytes.len().div_ceil(4) * 5 + 4);
    if delimiters {
        out.push_str("<~");
    }
    let (chunks, rem) = bytes.as_chunks::<4>();
    for chunk in chunks {
        let n = u32::from_be_bytes(*chunk);
        if n == 0 && zero {
            out.push('z');
            continue;
        }
        if n == 0x2020_2020 && y {
            out.push('y');
            continue;
        }
        push_ascii85_group(&mut out, n, 5);
    }
    if !rem.is_empty() {
        let mut padded = [0u8; 4];
        padded[..rem.len()].copy_from_slice(rem);
        let n = u32::from_be_bytes(padded);
        // A partial group emits (len + 1) characters. The `z`/`y`
        // shorthands are never used for partial groups.
        push_ascii85_group(&mut out, n, rem.len() + 1);
    }
    if delimiters {
        out.push_str("~>");
    }
    Ok(Value::Text(out))
}

/// Emit the `count` most significant base-85 digits of `n`.
fn push_ascii85_group(out: &mut String, n: u32, count: usize) {
    for i in (5 - count..5).rev() {
        let divisor = 85u64.pow(i as u32);
        out.push(((n as u64 / divisor % 85) as u8 + b'!') as char);
    }
}

fn ascii85_group_value(digits: &[u8; 5]) -> OpResult<u32> {
    let mut n: u64 = 0;
    for &d in digits {
        n = n * 85 + d as u64;
    }
    if n > u32::MAX as u64 {
        return Err(
            OperationError::decode("Ascii85 group exceeds the 32-bit range")
                .with_expected("a group value of at most 4294967295")
                .with_actual(n.to_string()),
        );
    }
    Ok(n as u32)
}

fn ascii85_decode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From Ascii85")?;
    let strict = map.bool_or("strict", true);
    let y = map.bool_or("y_shorthand", false);

    let mut body = text.trim();
    if let Some(rest) = body.strip_prefix("<~") {
        if !rest.ends_with("~>") {
            return Err(OperationError::decode(
                "unbalanced Ascii85 delimiters: `<~` without closing `~>`",
            ));
        }
        body = &rest[..rest.len() - 2];
    } else if body.ends_with("~>") {
        return Err(OperationError::decode(
            "unbalanced Ascii85 delimiters: closing `~>` without opening `<~`",
        ));
    }

    let mut out: Vec<u8> = Vec::with_capacity(body.len() * 4 / 5);
    let mut group: Vec<u8> = Vec::with_capacity(5);
    for (idx, c) in body.char_indices() {
        if c == 'z' || c == 'y' {
            let is_zero = c == 'z';
            let enabled = is_zero || y;
            if !enabled {
                if strict {
                    return Err(invalid_char("Ascii85", c, idx));
                }
                continue;
            }
            if !group.is_empty() {
                return Err(OperationError::decode(format!(
                    "Ascii85 shorthand `{c}` appears inside a group at offset {idx}"
                ))
                .with_expected("`z`/`y` at a group boundary")
                .with_details(
                    "Shorthands replace a complete 4-byte group and cannot occur mid-group.",
                ));
            }
            out.extend_from_slice(if is_zero { &[0, 0, 0, 0] } else { b"    " });
            continue;
        }
        if c.is_whitespace() {
            if strict {
                return Err(OperationError::decode(format!(
                    "strict Ascii85 input contains whitespace at offset {idx}"
                ))
                .with_details("Disable strict mode to ignore whitespace and invalid characters."));
            }
            continue;
        }
        if !c.is_ascii() || !(b'!'..=b'u').contains(&(c as u8)) {
            if strict {
                return Err(invalid_char("Ascii85", c, idx));
            }
            continue;
        }
        group.push(c as u8 - b'!');
        if group.len() == 5 {
            let digits = [group[0], group[1], group[2], group[3], group[4]];
            out.extend_from_slice(&ascii85_group_value(&digits)?.to_be_bytes());
            group.clear();
        }
    }
    match group.len() {
        0 => {}
        1 => {
            return Err(OperationError::decode(
                "a lone trailing Ascii85 character encodes zero bytes and is invalid",
            )
            .with_expected("2-5 characters in the final group"))
        }
        k => {
            let mut digits = [84u8; 5]; // pad with 'u' (the maximum digit)
            digits[..k].copy_from_slice(&group);
            let n = ascii85_group_value(&digits)?;
            out.extend_from_slice(&n.to_be_bytes()[..k - 1]);
        }
    }
    Ok(Value::Bytes(out))
}

// ---------------------------------------------------------------- Z85 ----

/// ZeroMQ Z85 alphabet (0MQ spec 32/ZMTP).
const Z85_ALPHABET: &[u8] =
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";

fn z85_encode(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Z85")?;
    if bytes.len() % 4 != 0 {
        return Err(OperationError::length(
            "a multiple of 4 bytes (each 4-byte group becomes 5 characters)",
            format!("{} bytes", bytes.len()),
            "Z85 input length is not a multiple of 4",
        )
        .with_details("Pad the input to a multiple of 4 bytes, or use a base without block alignment such as Base58."));
    }
    let mut out = String::with_capacity(bytes.len() * 5 / 4);
    let (chunks, _) = bytes.as_chunks::<4>();
    for chunk in chunks {
        let n = u32::from_be_bytes(*chunk);
        for i in (0..5).rev() {
            let divisor = 85u64.pow(i);
            out.push(Z85_ALPHABET[(n as u64 / divisor % 85) as usize] as char);
        }
    }
    Ok(Value::Text(out))
}

fn z85_decode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From Z85")?;
    let strict = map.bool_or("strict", true);
    let filtered: String = if strict {
        let trimmed = text.trim();
        for (idx, c) in trimmed.char_indices() {
            if digit_of(c, Z85_ALPHABET).is_none() {
                if c.is_whitespace() {
                    return Err(OperationError::decode(format!(
                        "strict Z85 input contains whitespace at offset {idx}"
                    ))
                    .with_details(
                        "Disable strict mode to ignore whitespace and invalid characters.",
                    ));
                }
                return Err(invalid_char("Z85", c, idx));
            }
        }
        trimmed.to_string()
    } else {
        text.chars()
            .filter(|c| digit_of(*c, Z85_ALPHABET).is_some())
            .collect()
    };
    let chars: Vec<char> = filtered.chars().collect();
    if !chars.len().is_multiple_of(5) {
        return Err(OperationError::length(
            "a multiple of 5 characters (each group of 5 encodes 4 bytes)",
            format!("{} characters", chars.len()),
            "Z85 input length is not a multiple of 5",
        ));
    }
    let mut out = Vec::with_capacity(chars.len() * 4 / 5);
    let (groups, remainder) = chars.as_chunks::<5>();
    debug_assert!(remainder.is_empty());
    for group in groups {
        let mut n: u64 = 0;
        for &c in group {
            n = n * 85 + digit_of(c, Z85_ALPHABET).unwrap_or(0) as u64;
        }
        if n > u32::MAX as u64 {
            return Err(OperationError::decode("Z85 group exceeds the 32-bit range")
                .with_expected("a group value of at most 4294967295")
                .with_actual(n.to_string()));
        }
        out.extend_from_slice(&(n as u32).to_be_bytes());
    }
    Ok(Value::Bytes(out))
}

// ------------------------------------------------------------- Base91 ----

/// basE91 alphabet by Joachim Henke (91 printable ASCII characters;
/// space, `\`, `'` and `-` are excluded).
const B91_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";

fn base91_encode(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Base91")?;
    let mut out = String::with_capacity(bytes.len() * 23 / 19 + 2);
    let mut ebq: u32 = 0;
    let mut en: u32 = 0;
    for &byte in bytes.as_ref() {
        ebq |= (byte as u32) << en;
        en += 8;
        if en > 13 {
            let v13 = ebq & 8191;
            let ev = if v13 > 88 {
                ebq >>= 13;
                en -= 13;
                v13
            } else {
                let v14 = ebq & 16383;
                ebq >>= 14;
                en -= 14;
                v14
            };
            out.push(B91_ALPHABET[(ev % 91) as usize] as char);
            out.push(B91_ALPHABET[(ev / 91) as usize] as char);
        }
    }
    if en > 0 {
        out.push(B91_ALPHABET[(ebq % 91) as usize] as char);
        if en > 7 || ebq > 90 {
            out.push(B91_ALPHABET[(ebq / 91) as usize] as char);
        }
    }
    Ok(Value::Text(out))
}

fn base91_decode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From Base91")?;
    let strict = map.bool_or("strict", true);
    let mut out: Vec<u8> = Vec::with_capacity(text.len() * 19 / 23);
    let mut pending: Option<u8> = None;
    let mut dbq: u32 = 0;
    let mut dn: u32 = 0;
    for (idx, c) in text.char_indices() {
        let d = match digit_of(c, B91_ALPHABET) {
            Some(d) => d,
            None if strict => return Err(invalid_char("Base91", c, idx)),
            // Relaxed mode skips non-alphabet characters, matching the
            // basE91 reference decoder.
            None => continue,
        };
        match pending {
            None => pending = Some(d),
            Some(first) => {
                let dv = first as u32 + d as u32 * 91;
                dbq |= dv << dn;
                dn += if dv & 8191 > 88 { 13 } else { 14 };
                while dn > 7 {
                    out.push((dbq & 0xff) as u8);
                    dbq >>= 8;
                    dn -= 8;
                }
                pending = None;
            }
        }
    }
    if let Some(first) = pending {
        out.push((dbq | (first as u32) << dn) as u8);
    }
    Ok(Value::Bytes(out))
}

// ------------------------------------------------------------ registry ----

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    use cybercipher_core::Category::Encoding as E;
    use cybercipher_core::ValueKind::{Bytes as B, Text as T};

    let enc_tag: &'static [&'static str] = &["encoding", "ctf"];

    reg.add_simple(
        spec(
            "to-base36",
            "To Base36",
            "Encodes bytes as Base36 text (0-9A-Z). The byte string is treated as an unsigned \
             big-endian big-integer: leading zero bytes are trimmed (there is no length prefix) \
             and an all-zero input encodes to `0`.",
            E,
            &[B, T],
            T,
            CostClass::Instant,
            true,
            vec![],
            enc_tag,
            &["base36 encode", "b36"],
            "Common convention (0-9A-Z big-integer encoding); no formal RFC",
            "Round-trip and cross-implementation tests",
        ),
        base36_encode,
    );

    reg.add_simple(
        spec(
            "from-base36",
            "From Base36",
            "Decodes Base36 text into bytes. Case-insensitive (both 0-9A-Z and 0-9a-z are \
             accepted). Decode returns the minimal big-endian byte string, so leading zero \
             bytes cannot be recovered.",
            E,
            &[T],
            B,
            CostClass::Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Reject non-alphabet characters and whitespace; relaxed mode drops them.",
            )],
            enc_tag,
            &["base36 decode", "b36 decode"],
            "Common convention (0-9A-Z big-integer encoding); no formal RFC",
            "Round-trip and cross-implementation tests",
        ),
        base36_decode,
    );

    reg.add_simple(
        spec(
            "to-base45",
            "To Base45",
            "Encodes bytes as Base45 text (RFC 9285). Two bytes become three characters and a \
             trailing single byte becomes two characters; the least significant digit is \
             emitted first within each group. The RFC defines no checksum.",
            E,
            &[B, T],
            T,
            CostClass::Instant,
            true,
            vec![],
            enc_tag,
            &["base45 encode", "b45", "rfc9285"],
            "RFC 9285 (The Base45 Data Encoding)",
            "RFC 9285 §4 test vectors",
        ),
        base45_encode,
    );

    reg.add_simple(
        spec(
            "from-base45",
            "From Base45",
            "Decodes Base45 text into bytes (RFC 9285). Groups of three characters must not \
             exceed 65535 and a final group of two must not exceed 255; both are rejected as \
             the RFC requires. Note: RFC 9285 defines no checksum, so corruption is only \
             caught by range or alphabet violations.",
            E,
            &[T],
            B,
            CostClass::Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Reject non-alphabet characters and whitespace; relaxed mode drops them.",
            )],
            enc_tag,
            &["base45 decode", "b45 decode"],
            "RFC 9285 (The Base45 Data Encoding)",
            "RFC 9285 §4 test vectors",
        ),
        base45_decode,
    );

    reg.add_simple(
        spec(
            "to-base58",
            "To Base58",
            "Encodes bytes as Base58 text with the Bitcoin alphabet. Treated as an unsigned \
             big-endian big-integer; every leading zero byte becomes a leading `1`.",
            E,
            &[B, T],
            T,
            CostClass::Instant,
            true,
            vec![],
            enc_tag,
            &["base58 encode", "b58", "bitcoin base58"],
            "Bitcoin Base58 (Bitcoin Core base58.h convention)",
            "Round-trip and cross-implementation tests (Cn8eVZg for \"hello\")",
        ),
        base58_encode,
    );

    reg.add_simple(
        spec(
            "from-base58",
            "From Base58",
            "Decodes Base58 text (Bitcoin alphabet) into bytes. Leading `1` characters become \
             leading zero bytes.",
            E,
            &[T],
            B,
            CostClass::Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Reject non-alphabet characters and whitespace; relaxed mode drops them.",
            )],
            enc_tag,
            &["base58 decode", "b58 decode"],
            "Bitcoin Base58 (Bitcoin Core base58.h convention)",
            "Round-trip and cross-implementation tests",
        ),
        base58_decode,
    );

    reg.add_simple(
        spec(
            "to-base58check",
            "To Base58Check",
            "Encodes bytes as Base58Check: version byte || payload || first 4 bytes of \
             SHA-256(SHA-256(version || payload)), all Base58-encoded. This is the Bitcoin \
             address container.",
            E,
            &[B, T],
            T,
            CostClass::Instant,
            true,
            vec![p_int(
                "version",
                "Version byte",
                0,
                "Prepended to the payload before checksumming (0-255; Bitcoin uses 0 for P2PKH addresses).",
            )],
            enc_tag,
            &["base58check encode", "b58check", "bitcoin address"],
            "Bitcoin Base58Check (Bitcoin Wiki / Bitcoin Core)",
            "Bitcoin Wiki Base58Check example (16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM)",
        ),
        base58check_encode,
    );

    reg.add_simple(
        spec(
            "from-base58check",
            "From Base58Check",
            "Decodes Base58Check text, validating the 4-byte double-SHA256 checksum and \
             reporting the version byte. Returns the payload by default, or version||payload \
             with `output = versioned`.",
            E,
            &[T],
            B,
            CostClass::Instant,
            true,
            vec![
                p_int(
                    "version",
                    "Expected version",
                    -1,
                    "Enforce a specific version byte (0-255); -1 accepts any version.",
                ),
                p_opts(
                    "output",
                    "Output",
                    "payload",
                    &[
                        ParamOption {
                            value: "payload",
                            label: "Payload only (version stripped)",
                        },
                        ParamOption {
                            value: "versioned",
                            label: "Version byte + payload",
                        },
                    ],
                    "Whether the decoded output keeps the version byte.",
                ),
            ],
            enc_tag,
            &["base58check decode", "b58check decode"],
            "Bitcoin Base58Check (Bitcoin Wiki / Bitcoin Core)",
            "Bitcoin Wiki Base58Check example (16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM)",
        ),
        base58check_decode,
    );

    reg.add_simple(
        spec(
            "to-base62",
            "To Base62",
            "Encodes bytes as Base62 text (0-9A-Za-z). Treated as an unsigned big-endian \
             big-integer; Base62 has no universally adopted leading-zero convention, so \
             leading zero bytes are trimmed and an all-zero input encodes to `0`.",
            E,
            &[B, T],
            T,
            CostClass::Instant,
            true,
            vec![],
            enc_tag,
            &["base62 encode", "b62"],
            "Common convention (0-9A-Za-z big-integer encoding); no formal standard",
            "Round-trip and cross-implementation tests",
        ),
        base62_encode,
    );

    reg.add_simple(
        spec(
            "from-base62",
            "From Base62",
            "Decodes Base62 text (0-9A-Za-z, case-sensitive) into bytes. Decode returns the \
             minimal big-endian byte string; leading zero bytes cannot be recovered.",
            E,
            &[T],
            B,
            CostClass::Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Reject non-alphabet characters and whitespace; relaxed mode drops them.",
            )],
            enc_tag,
            &["base62 decode", "b62 decode"],
            "Common convention (0-9A-Za-z big-integer encoding); no formal standard",
            "Round-trip and cross-implementation tests",
        ),
        base62_decode,
    );

    reg.add_simple(
        spec(
            "to-ascii85",
            "To Ascii85",
            "Encodes bytes as Ascii85 (Base85, btoa/Adobe variant). Groups of four bytes \
             become five characters '!'..'u'; `z` replaces an all-zero group and `y` (when \
             enabled) a group of four spaces. Partial trailing groups emit length+1 \
             characters.",
            E,
            &[B, T],
            T,
            CostClass::Instant,
            true,
            vec![
                p_bool(
                    "delimiters",
                    "Adobe delimiters",
                    false,
                    "Wrap the output in <~ and ~>.",
                ),
                p_bool(
                    "zero_shorthand",
                    "Use 'z' shorthand",
                    true,
                    "Replace all-zero groups with a single 'z' (Adobe convention).",
                ),
                p_bool(
                    "y_shorthand",
                    "Use 'y' shorthand",
                    false,
                    "Replace groups of four spaces with a single 'y' (btoa -y).",
                ),
            ],
            enc_tag,
            &["ascii85 encode", "a85", "base85", "btoa", "adobe ascii85"],
            "Adobe Ascii85 (PostScript Language Reference) / btoa variant",
            "Cross-implementation tests (Python base64.a85encode)",
        ),
        ascii85_encode,
    );

    reg.add_simple(
        spec(
            "from-ascii85",
            "From Ascii85",
            "Decodes Ascii85 (Base85, btoa/Adobe variant). Optional <~ ~> delimiters are \
             detected automatically. `z` (all-zero group) and `y` (four spaces, when \
             enabled) are only valid at group boundaries; the final partial group is padded \
             with 'u'. A lone trailing character is invalid.",
            E,
            &[T],
            B,
            CostClass::Instant,
            true,
            vec![
                p_bool(
                    "strict",
                    "Strict",
                    true,
                    "Reject whitespace and invalid characters; relaxed mode drops them.",
                ),
                p_bool(
                    "y_shorthand",
                    "Accept 'y' shorthand",
                    false,
                    "Decode 'y' at a group boundary as four spaces.",
                ),
            ],
            enc_tag,
            &["ascii85 decode", "a85 decode", "base85 decode", "atob"],
            "Adobe Ascii85 (PostScript Language Reference) / btoa variant",
            "Cross-implementation tests (Python base64.a85encode)",
        ),
        ascii85_decode,
    );

    reg.add_simple(
        spec(
            "to-z85",
            "To Z85",
            "Encodes bytes as Z85 (ZeroMQ). Every 4-byte group becomes 5 characters; the \
             input length must be a multiple of 4.",
            E,
            &[B, T],
            T,
            CostClass::Instant,
            true,
            vec![],
            enc_tag,
            &["z85 encode", "zeromq base85", "zmq base85"],
            "ZeroMQ Z85 (0MQ spec 32/ZMTP)",
            "Z85 spec test vector (864FD26FB559F75B -> HelloWorld)",
        ),
        z85_encode,
    );

    reg.add_simple(
        spec(
            "from-z85",
            "From Z85",
            "Decodes Z85 (ZeroMQ) text into bytes. The character length must be a multiple \
             of 5 and each group must not exceed the 32-bit range.",
            E,
            &[T],
            B,
            CostClass::Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Reject non-alphabet characters and whitespace; relaxed mode drops them.",
            )],
            enc_tag,
            &["z85 decode", "zeromq base85 decode"],
            "ZeroMQ Z85 (0MQ spec 32/ZMTP)",
            "Z85 spec test vector (864FD26FB559F75B -> HelloWorld)",
        ),
        z85_decode,
    );

    reg.add_simple(
        spec(
            "to-base91",
            "To Base91",
            "Encodes bytes as basE91 (Joachim Henke): 13-14 bit chunks become pairs from a \
             91-character alphabet, roughly 23% overhead vs Base64's 33%.",
            E,
            &[B, T],
            T,
            CostClass::Instant,
            true,
            vec![],
            enc_tag,
            &["base91 encode", "b91", "base e91"],
            "basE91 by Joachim Henke (base91.sourceforge.net)",
            "basE91 reference implementation cross-checks",
        ),
        base91_encode,
    );

    reg.add_simple(
        spec(
            "from-base91",
            "From Base91",
            "Decodes basE91 text into bytes. Strict mode rejects non-alphabet characters; \
             relaxed mode skips them, matching the reference decoder's behavior.",
            E,
            &[T],
            B,
            CostClass::Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Reject non-alphabet characters; relaxed mode skips them (reference behavior).",
            )],
            enc_tag,
            &["base91 decode", "b91 decode"],
            "basE91 by Joachim Henke (base91.sourceforge.net)",
            "basE91 reference implementation cross-checks",
        ),
        base91_decode,
    );
}
