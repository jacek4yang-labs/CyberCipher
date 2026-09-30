//! Structured-data serialization: CBOR, MessagePack, LEB128 varints, and
//! generic tag-length-value records. Parse ops surface JSON; encode ops
//! accept JSON text (or the matching native value kind) and emit bytes.

use crate::helpers::{input_bytes, spec};
use cybercipher_core::prelude::*;

/// Pull the input as JSON text: native `Json` values pass through, text and
/// bytes are parsed from their UTF-8 representation.
fn input_json(v: &Value, op_name: &str) -> OpResult<serde_json::Value> {
    match v {
        Value::Json(j) => Ok(j.clone()),
        Value::Text(_) | Value::Bytes(_) | Value::Null => {
            let bytes = input_bytes(v, op_name)?;
            serde_json::from_slice(bytes.as_ref()).map_err(|e| {
                OperationError::decode(format!("{op_name} input is not valid JSON: {e}"))
            })
        }
        other => Err(OperationError::invalid_input(format!(
            "`{op_name}` operates on JSON or text, but received {}",
            other.kind().name()
        ))
        .with_expected("json or text")
        .with_actual(other.kind().name())),
    }
}

// ---------------------------------------------------------------------------
// CBOR (RFC 8949)
// ---------------------------------------------------------------------------

fn cbor_to_json(data: &[u8]) -> OpResult<serde_json::Value> {
    ciborium::de::from_reader(data)
        .map_err(|e| OperationError::decode(format!("CBOR parse failed: {e}")))
}

fn json_to_cbor(json: &serde_json::Value) -> OpResult<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(json, &mut out)
        .map_err(|e| OperationError::decode(format!("CBOR encode failed: {e}")))?;
    Ok(out)
}

fn from_cbor_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "From Cbor")?;
    Ok(Value::Json(cbor_to_json(bytes.as_ref())?))
}

fn to_cbor_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let json = input_json(v, "To Cbor")?;
    Ok(Value::Bytes(json_to_cbor(&json)?))
}

// ---------------------------------------------------------------------------
// MessagePack
// ---------------------------------------------------------------------------

fn msgpack_to_json(data: &[u8]) -> OpResult<serde_json::Value> {
    rmp_serde::from_slice(data)
        .map_err(|e| OperationError::decode(format!("MessagePack parse failed: {e}")))
}

fn json_to_msgpack(json: &serde_json::Value) -> OpResult<Vec<u8>> {
    let mut out = Vec::new();
    rmp_serde::encode::write(&mut out, json)
        .map_err(|e| OperationError::decode(format!("MessagePack encode failed: {e}")))?;
    Ok(out)
}

fn from_msgpack_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "From Msgpack")?;
    Ok(Value::Json(msgpack_to_json(bytes.as_ref())?))
}

fn to_msgpack_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let json = input_json(v, "To Msgpack")?;
    Ok(Value::Bytes(json_to_msgpack(&json)?))
}

// ---------------------------------------------------------------------------
// LEB128 unsigned varints
// ---------------------------------------------------------------------------

/// Split free-form text into alphanumeric tokens (hex or decimal byte values,
/// integer lists, ...). Splits on anything that is not ASCII alphanumeric.
fn tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
}

/// Parse one token as a byte/integer value. `0x`-prefixed tokens are hex;
/// bare tokens are decimal when all-digit, hex when they contain hex letters
/// (so `ac 02`, `0xAC,0x02`, and `172 2` all work).
fn parse_number(token: &str, max: u64, what: &str) -> OpResult<u64> {
    let (digits, radix) = if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        (hex, 16u32)
    } else if token.chars().all(|c| c.is_ascii_digit()) {
        (token, 10)
    } else if token.chars().all(|c| c.is_ascii_hexdigit()) {
        (token, 16)
    } else {
        return Err(OperationError::decode(format!(
            "invalid {what} token {token:?} (expected 0x-hex or decimal)"
        ))
        .with_expected("hex or decimal integer")
        .with_actual(token.to_string()));
    };
    let value = u64::from_str_radix(digits, radix).map_err(|_| {
        OperationError::decode(format!("invalid {what} token {token:?}"))
            .with_expected("hex or decimal integer")
            .with_actual(token.to_string())
    })?;
    if value > max {
        return Err(OperationError::decode(format!(
            "{what} token {token:?} exceeds the maximum of {max}"
        ))
        .with_expected(format!("at most {max}"))
        .with_actual(token.to_string()));
    }
    Ok(value)
}

fn varint_encode(mut value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn varint_decode(data: &[u8]) -> OpResult<Vec<u64>> {
    let mut values = Vec::new();
    let mut acc: u64 = 0;
    let mut shift: u32 = 0;
    let mut pending = false;
    for &byte in data {
        let bits = (byte & 0x7F) as u64;
        if shift >= 64 || (shift == 63 && bits > 1) {
            return Err(OperationError::decode(
                "varint does not fit in 64 bits (more than 10 bytes)",
            )
            .with_expected("at most 10 continuation bytes")
            .with_actual(format!("value overflow at byte {shift}")));
        }
        acc |= bits << shift;
        if byte & 0x80 == 0 {
            values.push(acc);
            acc = 0;
            shift = 0;
            pending = false;
        } else {
            shift += 7;
            pending = true;
        }
    }
    if pending {
        return Err(
            OperationError::decode("input ends mid-varint (trailing continuation byte)")
                .with_expected("terminating byte without the high bit set")
                .with_actual("input truncated"),
        );
    }
    Ok(values)
}

fn from_varint_op(v: &Value, _: &ParamMap, ctx: &ExecutionContext) -> OpResult<Value> {
    let data: Vec<u8> = match v {
        // Raw bytes are the varint stream directly.
        Value::Bytes(b) => b.clone(),
        // Text is a decimal / 0x-hex byte list.
        Value::Text(_) | Value::Null => {
            let bytes = input_bytes(v, "From Varint")?;
            let mut out = Vec::with_capacity(bytes.len());
            for token in tokens(std::str::from_utf8(bytes.as_ref()).map_err(|_| {
                OperationError::invalid_input(
                    "`From Varint` text input must be UTF-8 (decimal or 0x hex byte list)",
                )
            })?) {
                out.push(parse_number(token, 255, "varint byte")? as u8);
                ctx.check()?;
            }
            out
        }
        other => {
            return Err(OperationError::invalid_input(format!(
                "`From Varint` operates on bytes or text, but received {}",
                other.kind().name()
            ))
            .with_expected("bytes or text")
            .with_actual(other.kind().name()))
        }
    };
    if data.is_empty() {
        return Err(OperationError::invalid_input("no varint bytes to decode"));
    }
    let values = varint_decode(&data)?;
    Ok(Value::IntegerList(
        values.into_iter().map(num_bigint::BigInt::from).collect(),
    ))
}

fn to_varint_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let values: Vec<u64> = match v {
        Value::IntegerList(list) => {
            let mut out = Vec::with_capacity(list.len());
            for item in list {
                let text = item.to_string();
                let negative = item.sign() == num_bigint::Sign::Minus;
                if negative {
                    return Err(OperationError::decode(
                        "unsigned varints cannot encode negative integers",
                    )
                    .with_expected("non-negative integer")
                    .with_actual(text));
                }
                out.push(parse_number(&text, u64::MAX, "varint integer")?);
            }
            out
        }
        Value::Text(_) | Value::Null => {
            let text = v.as_text().unwrap_or_default();
            let trimmed = text.trim();
            if trimmed.contains('-') {
                return Err(OperationError::decode(
                    "unsigned varints cannot encode negative integers",
                )
                .with_expected("non-negative integer")
                .with_actual(trimmed.to_string()));
            }
            if trimmed.starts_with('[') {
                serde_json::from_str::<Vec<u64>>(trimmed).map_err(|e| {
                    OperationError::decode(format!("input is not a JSON array of integers: {e}"))
                })?
            } else {
                let mut out = Vec::new();
                for token in tokens(trimmed) {
                    out.push(parse_number(token, u64::MAX, "varint integer")?);
                }
                out
            }
        }
        Value::Json(j) => serde_json::from_value::<Vec<u64>>(j.clone())
            .map_err(|e| OperationError::decode(format!("input is not an integer array: {e}")))?,
        other => {
            return Err(OperationError::invalid_input(format!(
                "`To Varint` operates on integers or text, but received {}",
                other.kind().name()
            ))
            .with_expected("integer list or text")
            .with_actual(other.kind().name()))
        }
    };
    if values.is_empty() {
        return Err(OperationError::invalid_input("no integers to encode"));
    }
    let mut out = Vec::new();
    for value in values {
        out.extend_from_slice(&varint_encode(value));
    }
    Ok(Value::Bytes(out))
}

// ---------------------------------------------------------------------------
// Generic TLV (tag u8, DER-style length, value bytes)
// ---------------------------------------------------------------------------

/// Read a DER-style definite length starting at `data[pos]`. Returns the
/// length and the offset of the first value byte.
fn read_tlv_length(data: &[u8], header_start: usize) -> OpResult<(usize, usize)> {
    let len_byte = data[header_start];
    if len_byte < 0x80 {
        return Ok((len_byte as usize, header_start + 1));
    }
    if len_byte == 0x80 {
        return Err(OperationError::decode(
            "TLV uses indefinite length (0x80); only definite lengths are supported",
        )
        .with_expected("definite DER length")
        .with_actual("0x80 indefinite marker"));
    }
    let n = (len_byte & 0x7F) as usize;
    if n > 4 {
        return Err(OperationError::decode(format!(
            "TLV length field uses {n} bytes; at most 4 are supported"
        ))
        .with_expected("1-4 length bytes")
        .with_actual(format!("{n} length bytes")));
    }
    let start = header_start + 1;
    let end = start + n;
    if end > data.len() {
        return Err(OperationError::decode("TLV length field is truncated")
            .with_expected(format!("{n} length bytes"))
            .with_actual(format!("only {} available", data.len() - start)));
    }
    let mut length = 0usize;
    for &b in &data[start..end] {
        length = (length << 8) | b as usize;
    }
    Ok((length, end))
}

fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let be = len.to_be_bytes();
        let skip = be.iter().take_while(|&&b| b == 0).count();
        let significant = &be[skip..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(value);
    out
}

fn hex_string(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex_value(text: &str) -> OpResult<Vec<u8>> {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    let cleaned = cleaned.strip_prefix("0x").unwrap_or(&cleaned);
    if !cleaned.len().is_multiple_of(2) {
        return Err(
            OperationError::decode("hex value has an odd number of digits")
                .with_expected("even-length hex string")
                .with_actual(text.to_string()),
        );
    }
    (0..cleaned.len() / 2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16)
                .map_err(|_| OperationError::decode(format!("invalid hex digit in value {text:?}")))
        })
        .collect()
}

fn parse_tlv(data: &[u8]) -> OpResult<serde_json::Value> {
    let mut elements = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        if data.len() - pos < 2 {
            return Err(OperationError::decode("TLV header is truncated")
                .with_expected("tag byte plus length byte")
                .with_actual(format!(
                    "{} trailing byte(s) at offset {pos}",
                    data.len() - pos
                )));
        }
        let tag = data[pos];
        let (length, value_start) = read_tlv_length(data, pos + 1)?;
        let value_end = value_start
            .checked_add(length)
            .filter(|&end| end <= data.len())
            .ok_or_else(|| {
                OperationError::decode("TLV value is truncated")
                    .with_expected(format!("{length} value bytes"))
                    .with_actual(format!("only {} available", data.len() - value_start))
            })?;
        let value = &data[value_start..value_end];
        let printable = !value.is_empty() && value.iter().all(|&b| (0x20..=0x7E).contains(&b));
        elements.push(serde_json::json!({
            "index": elements.len(),
            "offset": pos,
            "tag": tag,
            "tag_hex": format!("{tag:02x}"),
            "length": length,
            "value_hex": hex_string(value),
            "value_ascii": if printable {
                serde_json::Value::String(String::from_utf8_lossy(value).into_owned())
            } else {
                serde_json::Value::Null
            },
        }));
        pos = value_end;
    }
    Ok(serde_json::json!({ "element_count": elements.len(), "elements": elements }))
}

fn from_tlv_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "From Tlv")?;
    let data = bytes.as_ref();
    if data.is_empty() {
        return Err(OperationError::invalid_input("no TLV bytes to parse"));
    }
    Ok(Value::Json(parse_tlv(data)?))
}

/// Extract one element's value from a JSON TLV element object.
fn tlv_element_value(element: &serde_json::Value, index: usize) -> OpResult<Vec<u8>> {
    let obj = element.as_object().ok_or_else(|| {
        OperationError::decode(format!("TLV element {index} is not an object"))
            .with_expected(r#"{"tag": number, "value": hex}"#)
            .with_actual(element.to_string())
    })?;
    let tag = match obj.get("tag") {
        Some(serde_json::Value::Number(n)) => n.as_u64().ok_or_else(|| {
            OperationError::decode(format!("TLV element {index} tag must be 0-255"))
                .with_actual(n.to_string())
        })?,
        Some(serde_json::Value::String(s)) => parse_number(s.trim(), 255, "TLV tag")?,
        _ => {
            return Err(OperationError::decode(format!(
                "TLV element {index} is missing an integer `tag`"
            ))
            .with_expected("integer tag 0-255"))
        }
    };
    if tag > 255 {
        return Err(
            OperationError::decode(format!("TLV element {index} tag must be 0-255"))
                .with_actual(tag.to_string()),
        );
    }
    let value = if let Some(text) = obj.get("value_text").and_then(|v| v.as_str()) {
        text.as_bytes().to_vec()
    } else if let Some(hex) = obj.get("value").and_then(|v| v.as_str()) {
        parse_hex_value(hex)?
    } else if let Some(arr) = obj.get("value").and_then(|v| v.as_array()) {
        let mut out = Vec::with_capacity(arr.len());
        for item in arr {
            let n = item.as_u64().ok_or_else(|| {
                OperationError::decode(format!("TLV element {index} value byte out of range"))
                    .with_actual(item.to_string())
            })?;
            if n > 255 {
                return Err(OperationError::decode(format!(
                    "TLV element {index} value byte out of range"
                ))
                .with_expected("0-255")
                .with_actual(n.to_string()));
            }
            out.push(n as u8);
        }
        out
    } else {
        Vec::new()
    };
    Ok(encode_tlv(tag as u8, &value))
}

fn to_tlv_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let json = input_json(v, "To Tlv")?;
    let elements = json.as_array().ok_or_else(|| {
        OperationError::decode("TLV input must be a JSON array of {tag, value} objects")
            .with_expected("json array")
            .with_actual(if json.is_object() {
                "json object"
            } else {
                "other"
            })
    })?;
    let mut out = Vec::new();
    for (i, element) in elements.iter().enumerate() {
        out.extend_from_slice(&tlv_element_value(element, i)?);
    }
    Ok(Value::Bytes(out))
}

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    use cybercipher_core::{
        Category::Serialization as S,
        ValueKind::{Bytes as B, IntegerList as IL, Json as J, Text as T},
    };

    let tags: &'static [&'static str] = &["serialization", "ctf", "structured"];

    reg.add_simple(
        spec(
            "from-cbor",
            "From Cbor",
            "Parses CBOR data into JSON.",
            S,
            &[B, T],
            J,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["cbor decode", "cbor parse"],
            "RFC 8949 (Concise Binary Object Representation)",
            "RFC 8949 appendix vectors (A1616101) + round-trip tests",
        ),
        from_cbor_op,
    );

    reg.add_simple(
        spec(
            "to-cbor",
            "To Cbor",
            "Encodes JSON (text or native JSON input) as CBOR bytes.",
            S,
            &[J, T, B],
            B,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["cbor encode"],
            "RFC 8949 (Concise Binary Object Representation)",
            "RFC 8949 vectors + round-trip tests",
        ),
        to_cbor_op,
    );

    reg.add_simple(
        spec(
            "from-msgpack",
            "From Msgpack",
            "Parses MessagePack data into JSON.",
            S,
            &[B, T],
            J,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["msgpack decode", "messagepack parse"],
            "MessagePack specification (msgpack.org)",
            "Reference vectors (81a1616101) + round-trip tests",
        ),
        from_msgpack_op,
    );

    reg.add_simple(
        spec(
            "to-msgpack",
            "To Msgpack",
            "Encodes JSON (text or native JSON input) as MessagePack bytes.",
            S,
            &[J, T, B],
            B,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["msgpack encode", "messagepack encode"],
            "MessagePack specification (msgpack.org)",
            "Reference vectors + round-trip tests",
        ),
        to_msgpack_op,
    );

    reg.add_simple(
        spec(
            "from-varint",
            "From Varint",
            "Decodes unsigned LEB128 varints from a byte list (decimal or 0x hex tokens) or raw bytes. Output is an integer list.",
            S,
            &[B, T],
            IL,
            CostClass::Instant,
            true,
            vec![],
            tags,
            &["varint decode", "leb128 decode"],
            "LEB128 base-128 varints (DWARF / Protocol Buffers convention)",
            "Hand-checked vectors (300 = ac 02) + boundary tests",
        ),
        from_varint_op,
    );

    reg.add_simple(
        spec(
            "to-varint",
            "To Varint",
            "Encodes integers as unsigned LEB128 varints. Accepts an integer list or text (JSON array, or decimal/0x-hex tokens).",
            S,
            &[IL, T],
            B,
            CostClass::Instant,
            true,
            vec![],
            tags,
            &["varint encode", "leb128 encode"],
            "LEB128 base-128 varints (DWARF / Protocol Buffers convention)",
            "Hand-checked vectors (300 = ac 02) + boundary tests",
        ),
        to_varint_op,
    );

    reg.add_simple(
        spec(
            "from-tlv",
            "From Tlv",
            "Parses generic tag-length-value records (u8 tag, DER-style definite length) into JSON elements with tag/length/value per record.",
            S,
            &[B, T],
            J,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["tlv decode", "tlv parse", "ber tlv"],
            "BER/DER TLV convention (ITU-T X.690)",
            "Hand-built vectors + round-trip tests",
        ),
        from_tlv_op,
    );

    reg.add_simple(
        spec(
            "to-tlv",
            "To Tlv",
            "Encodes a JSON array of {tag, value} elements (value as hex string, byte array, or value_text) into TLV bytes with DER-style lengths.",
            S,
            &[J, T],
            B,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["tlv encode"],
            "BER/DER TLV convention (ITU-T X.690)",
            "Round-trip tests",
        ),
        to_tlv_op,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_boundaries() {
        for (value, expected) in [
            (0u64, vec![0x00]),
            (1, vec![0x01]),
            (127, vec![0x7F]),
            (128, vec![0x80, 0x01]),
            (300, vec![0xAC, 0x02]),
            (16384, vec![0x80, 0x80, 0x01]),
            (u64::MAX, vec![0xFF; 9].into_iter().chain([0x01]).collect()),
        ] {
            assert_eq!(varint_encode(value), expected, "encode {value}");
            assert_eq!(
                varint_decode(&expected).unwrap(),
                vec![value],
                "decode {value}"
            );
        }
    }

    #[test]
    fn varint_rejects_truncated_and_overflow() {
        assert!(varint_decode(&[0x80]).is_err());
        assert!(
            varint_decode(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02]).is_err()
        );
        assert_eq!(
            varint_decode(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]).unwrap(),
            vec![u64::MAX]
        );
    }

    #[test]
    fn tlv_long_form_lengths() {
        assert_eq!(
            encode_tlv(1, &[0xAA; 5]),
            vec![1, 5, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]
        );
        assert_eq!(
            encode_tlv(2, &[0xBB; 200])[..3].to_vec(),
            vec![2, 0x81, 200]
        );
        let parsed = parse_tlv(&encode_tlv(3, &[0xCC; 70_000])).unwrap();
        assert_eq!(parsed["elements"][0]["length"], 70_000);
        // Indefinite length is rejected.
        assert!(parse_tlv(&[1, 0x80]).is_err());
        // Truncated value is rejected.
        assert!(parse_tlv(&[1, 5, 0xAA]).is_err());
    }
}
