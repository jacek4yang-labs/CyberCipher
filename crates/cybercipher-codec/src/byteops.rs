//! Byte and bit operations: XOR family, bitwise logic, rotation, reversal,
//! endianness, split/join. These are the workhorses of CTF data analysis.

use crate::helpers::{
    decode_delimiter, decode_key, input_bytes, input_text, p_bool, p_enc, p_int, p_opts, p_text,
    spec,
};
use cybercipher_core::prelude::*;

const BYTE_TAGS: &[&str] = &["byteops", "ctf"];
const BYTE_PROV: &str = "CyberCipher native Rust implementation";

// ---------------------------------------------------------------- xor ----

fn xor_scheme(map: &ParamMap) -> &str {
    map.str_or("scheme", "standard")
}

fn xor_apply(data: &[u8], key: &[u8], scheme: &str, null_preserving: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let klen = key.len();
    for (i, &b) in data.iter().enumerate() {
        if null_preserving && b == 0 {
            out.push(0);
            continue;
        }
        let k = match scheme {
            // The key repeats over the data.
            "standard" => key[i % klen],
            // The key byte is incremented once per full pass over the key.
            "rolling" => key[i % klen].wrapping_add((i / klen) as u8),
            // Key is a single start byte; the counter increments every byte.
            "incrementing" => key[0].wrapping_add(i as u8),
            _ => key[i % klen],
        };
        out.push(b ^ k);
    }
    out
}

fn xor_op(v: &Value, map: &ParamMap, ctx: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "XOR")?;
    let key = decode_key(map, "key", "key_encoding")?;
    let scheme = xor_scheme(map);
    if scheme == "incrementing" && key.len() != 1 {
        return Err(OperationError::invalid_param(
            "key",
            format!(
                "incrementing scheme expects a 1-byte key, got {} bytes",
                key.len()
            ),
        )
        .with_expected("1 byte")
        .with_actual(format!("{} bytes", key.len())));
    }
    ctx.check()?;
    let null_preserving = map.bool_or("null_preserving", false);
    Ok(Value::Bytes(xor_apply(
        bytes.as_ref(),
        &key,
        scheme,
        null_preserving,
    )))
}

// ------------------------------------------------------------ bitwise ----

fn bitwise_op(
    name: &'static str,
    f: fn(u8, u8) -> u8,
) -> impl Fn(&Value, &ParamMap, &ExecutionContext) -> OpResult<Value> {
    move |v, map, _| {
        let bytes = input_bytes(v, name)?;
        let key = decode_key(map, "key", "key_encoding")?;
        let klen = key.len();
        let out: Vec<u8> = bytes
            .iter()
            .enumerate()
            .map(|(i, &b)| f(b, key[i % klen]))
            .collect();
        Ok(Value::Bytes(out))
    }
}

fn not_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "NOT")?;
    Ok(Value::Bytes(bytes.iter().map(|b| !b).collect()))
}

// ------------------------------------------------------------ rotation ----

fn rotate_op(
    name: &'static str,
    left: bool,
) -> impl Fn(&Value, &ParamMap, &ExecutionContext) -> OpResult<Value> {
    move |v, map, _| {
        let bytes = input_bytes(v, name)?;
        let amount = map.require_int("amount", 0, 255)? as u32 % 8;
        let out: Vec<u8> = bytes
            .iter()
            .map(|&b| {
                if left {
                    b.rotate_left(amount)
                } else {
                    b.rotate_right(amount)
                }
            })
            .collect();
        Ok(Value::Bytes(out))
    }
}

fn reverse_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let by = map.str_or("by", "bytes");
    match by {
        "chars" => {
            let text = input_text(v, "Reverse")?;
            Ok(Value::Text(text.chars().rev().collect()))
        }
        _ => {
            let bytes = input_bytes(v, "Reverse")?;
            Ok(Value::Bytes(bytes.iter().rev().copied().collect()))
        }
    }
}

fn swap_endianness_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "Swap Endianness")?;
    let word: usize = map.require_int("word_size", 2, 64)? as usize;
    let mut out = Vec::with_capacity(bytes.len());
    for chunk in bytes.chunks(word) {
        out.extend(chunk.iter().rev());
    }
    Ok(Value::Bytes(out))
}

// -------------------------------------------------------- split / join ----

fn split_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let delim_raw = map.str_or("delimiter", " ");
    let delim = decode_delimiter(delim_raw);
    match v {
        Value::Text(text) => {
            let parts: Vec<Value> = if delim.is_empty() {
                text.chars().map(|c| Value::Text(c.to_string())).collect()
            } else {
                text.split(&delim)
                    .map(|p| Value::Text(p.to_string()))
                    .collect()
            };
            Ok(Value::List(parts))
        }
        Value::Bytes(bytes) => {
            if delim.is_empty() {
                return Ok(Value::List(
                    bytes.iter().map(|b| Value::Bytes(vec![*b])).collect(),
                ));
            }
            let d = delim.as_bytes();
            let mut parts: Vec<Value> = Vec::new();
            let mut start = 0usize;
            let mut i = 0usize;
            while i + d.len() <= bytes.len() {
                if &bytes[i..i + d.len()] == d {
                    parts.push(Value::Bytes(bytes[start..i].to_vec()));
                    i += d.len();
                    start = i;
                } else {
                    i += 1;
                }
            }
            parts.push(Value::Bytes(bytes[start..].to_vec()));
            Ok(Value::List(parts))
        }
        other => Err(OperationError::invalid_input(format!(
            "Split expects text or bytes, got {}",
            other.kind().name()
        ))
        .with_expected("text or bytes")
        .with_actual(other.kind().name())),
    }
}

fn join_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let delim = decode_delimiter(map.str_or("delimiter", ""));
    let items: &[Value] = match v {
        Value::List(items) => items,
        other => {
            return Err(OperationError::invalid_input(format!(
                "Join expects a list (usually produced by Split), got {}",
                other.kind().name()
            ))
            .with_expected("list")
            .with_actual(other.kind().name()))
        }
    };
    let all_text = items.iter().all(|i| matches!(i, Value::Text(_)));
    if all_text {
        let parts: Vec<&str> = items.iter().filter_map(|i| i.as_text()).collect();
        return Ok(Value::Text(parts.join(&delim)));
    }
    let mut out: Vec<u8> = Vec::new();
    for (i, item) in items.iter().enumerate() {
        if i > 0 && !delim.is_empty() {
            out.extend_from_slice(delim.as_bytes());
        }
        match item {
            Value::Text(t) => out.extend_from_slice(t.as_bytes()),
            Value::Bytes(b) => out.extend_from_slice(b),
            Value::Null => {}
            other => {
                return Err(OperationError::invalid_input(format!(
                    "Join cannot combine item #{i} of kind {}",
                    other.kind().name()
                ))
                .with_expected("text or bytes items")
                .with_actual(other.kind().name()))
            }
        }
    }
    Ok(Value::Bytes(out))
}

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    use cybercipher_core::{
        Category::ByteOperation as C,
        ValueKind::{Bytes as B, Text as T},
    };

    reg.add_simple(spec(
        "xor", "XOR",
        "XORs the input with a key. Schemes: standard (repeating key), rolling (key increments per pass), incrementing (key is a start byte + counter).",
        C, &[B, T], B, CostClass::Instant, true,
        vec![
            p_text("key", "Key", "", "XOR key."),
            p_enc("key_encoding", "Key encoding", "utf8", "How to interpret the key."),
            p_opts("scheme", "Scheme", "standard",
                &[ParamOption { value: "standard", label: "Standard (repeating key)" },
                  ParamOption { value: "rolling", label: "Rolling (increment per pass)" },
                  ParamOption { value: "incrementing", label: "Incrementing (start byte + i)" }],
                ""),
            p_bool("null_preserving", "Null preserving", false, "Leave zero bytes unchanged."),
        ],
        BYTE_TAGS, &["xor crack", "single byte xor"],
        "CyberCipher convention, documented in description", "Known-answer tests",
    ), xor_op);

    reg.add_simple(
        spec(
            "bitwise-and",
            "AND",
            "Bitwise AND with a repeating key.",
            C,
            &[B, T],
            B,
            CostClass::Instant,
            true,
            vec![
                p_text("key", "Key", "", ""),
                p_enc("key_encoding", "Key encoding", "utf8", ""),
            ],
            BYTE_TAGS,
            &["and"],
            BYTE_PROV,
            "Known-answer tests",
        ),
        bitwise_op("AND", |a, b| a & b),
    );

    reg.add_simple(
        spec(
            "bitwise-or",
            "OR",
            "Bitwise OR with a repeating key.",
            C,
            &[B, T],
            B,
            CostClass::Instant,
            true,
            vec![
                p_text("key", "Key", "", ""),
                p_enc("key_encoding", "Key encoding", "utf8", ""),
            ],
            BYTE_TAGS,
            &["or"],
            BYTE_PROV,
            "Known-answer tests",
        ),
        bitwise_op("OR", |a, b| a | b),
    );

    reg.add_simple(
        spec(
            "bitwise-not",
            "NOT",
            "Bitwise NOT (one's complement) of every byte.",
            C,
            &[B, T],
            B,
            CostClass::Instant,
            true,
            vec![],
            BYTE_TAGS,
            &["not", "invert"],
            BYTE_PROV,
            "Known-answer tests",
        ),
        not_op,
    );

    reg.add_simple(
        spec(
            "rotate-left",
            "Rotate Left",
            "Rotates every byte left by the given number of bits (0-7).",
            C,
            &[B, T],
            B,
            CostClass::Instant,
            true,
            vec![p_int(
                "amount",
                "Amount (bits)",
                1,
                "0-7; values above 7 wrap around.",
            )],
            BYTE_TAGS,
            &["rol", "rotate"],
            BYTE_PROV,
            "Known-answer tests",
        ),
        rotate_op("Rotate Left", true),
    );

    reg.add_simple(
        spec(
            "rotate-right",
            "Rotate Right",
            "Rotates every byte right by the given number of bits (0-7).",
            C,
            &[B, T],
            B,
            CostClass::Instant,
            true,
            vec![p_int(
                "amount",
                "Amount (bits)",
                1,
                "0-7; values above 7 wrap around.",
            )],
            BYTE_TAGS,
            &["ror", "rotate"],
            BYTE_PROV,
            "Known-answer tests",
        ),
        rotate_op("Rotate Right", false),
    );

    reg.add_simple(
        spec(
            "reverse",
            "Reverse",
            "Reverses the input by bytes or characters.",
            C,
            &[B, T],
            B,
            CostClass::Instant,
            true,
            vec![p_opts(
                "by",
                "By",
                "bytes",
                &[
                    ParamOption {
                        value: "bytes",
                        label: "Bytes",
                    },
                    ParamOption {
                        value: "chars",
                        label: "Characters",
                    },
                ],
                "",
            )],
            BYTE_TAGS,
            &["flip"],
            BYTE_PROV,
            "Round-trip tests",
        ),
        reverse_op,
    );

    reg.add_simple(
        spec(
            "swap-endianness",
            "Swap Endianness",
            "Reverses the byte order of fixed-size words within the data.",
            C,
            &[B, T],
            B,
            CostClass::Instant,
            true,
            vec![p_int(
                "word_size",
                "Word size (bytes)",
                4,
                "2, 4 or 8 bytes.",
            )],
            BYTE_TAGS,
            &["endianness", "byte swap", "little endian", "big endian"],
            BYTE_PROV,
            "Known-answer tests",
        ),
        swap_endianness_op,
    );

    reg.add_simple(spec(
        "split", "Split",
        "Splits text or bytes on a delimiter into a list. Empty delimiter splits per character/byte.",
        C, &[T, B], cybercipher_core::ValueKind::List, CostClass::Instant, true,
        vec![p_text("delimiter", "Delimiter", " ", "Escape sequences \\n, \\t, \\r, \\0, \\\\ supported.")],
        BYTE_TAGS, &["separate"],
        BYTE_PROV, "Round-trip tests with Join",
    ), split_op);

    reg.add_simple(
        spec(
            "join",
            "Join",
            "Joins a list of text/byte items with a delimiter.",
            C,
            &[cybercipher_core::ValueKind::List],
            B,
            CostClass::Instant,
            true,
            vec![p_text(
                "delimiter",
                "Delimiter",
                "",
                "Escape sequences \\n, \\t, \\r, \\0, \\\\ supported.",
            )],
            BYTE_TAGS,
            &["merge", "concatenate"],
            BYTE_PROV,
            "Round-trip tests with Split",
        ),
        join_op,
    );
}
