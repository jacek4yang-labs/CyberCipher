//! Big-integer operations: bytes/text ⇄ arbitrary-precision integers.
//!
//! Big cryptographic integers are transported as strings everywhere (JSON
//! params, IPC); they are never represented as floating-point numbers.

use crate::helpers::{input_bytes, p_int, p_opts, spec};
use cybercipher_core::prelude::*;
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed};

fn parse_integer_text(text: &str, radix_mode: &str) -> OpResult<BigInt> {
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return Err(OperationError::decode("empty integer input")
            .with_expected("a decimal or 0x-prefixed hexadecimal integer"));
    }
    let (radix, digits) = match radix_mode {
        "hex" => (
            16,
            cleaned.trim_start_matches("0x").trim_start_matches("0X"),
        ),
        "decimal" => (10, cleaned.as_str()),
        _ => match cleaned
            .strip_prefix("0x")
            .or_else(|| cleaned.strip_prefix("0X"))
        {
            Some(hex) => (16, hex),
            None => (10, cleaned.as_str()),
        },
    };
    BigInt::parse_bytes(digits.as_bytes(), radix).ok_or_else(|| {
        OperationError::decode(format!("`{text}` is not a valid base-{radix} integer"))
            .with_expected(match radix {
                16 => "hexadecimal digits (0x optional)",
                _ => "decimal digits",
            })
            .with_actual(text.to_string())
    })
}

fn to_integer(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    match v {
        Value::Integer(_) | Value::Null => Ok(v.clone()),
        Value::Text(text) => {
            let radix = map.str_or("radix", "auto");
            Ok(Value::Integer(parse_integer_text(text, radix)?))
        }
        input => {
            let bytes = input_bytes(input, "To Integer")?;
            let little = map.str_or("byteorder", "big") == "little";
            let signed = map.bool_or("signed", false);
            let ordered: Vec<u8> = if little {
                bytes.iter().rev().copied().collect()
            } else {
                bytes.as_ref().to_vec()
            };
            if signed {
                Ok(Value::Integer(BigInt::from_signed_bytes_be(&ordered)))
            } else {
                Ok(Value::Integer(BigInt::from(BigUint::from_bytes_be(
                    &ordered,
                ))))
            }
        }
    }
}

fn from_integer(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let int = match v {
        Value::Integer(i) => i,
        other => {
            return Err(OperationError::invalid_input(format!(
                "From Integer expects an integer (produce one with To Integer), got {}",
                other.kind().name()
            ))
            .with_expected("integer")
            .with_actual(other.kind().name()))
        }
    };
    let output = map.str_or("output", "hex");
    let little = map.str_or("byteorder", "big") == "little";
    let min_len = map.int_or("min_length", 0).max(0) as usize;
    match output {
        "decimal" => Ok(Value::Text(int.to_string())),
        "hex" => {
            let (sign, digits) = int.to_bytes_be();
            let mut hex = if digits.is_empty() {
                "0".to_string()
            } else {
                digits
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            };
            if sign == Sign::Minus {
                hex.insert(0, '-');
            }
            Ok(Value::Text(hex))
        }
        "bytes" => {
            let signed = map.bool_or("signed", false);
            let mut bytes = if signed && int.is_negative() {
                let magnitude = (-int).to_biguint().unwrap();
                // Two's complement: 2^bits - |m|, byte-aligned.
                let len = (magnitude.bits() as usize) / 8 + 1;
                let modulus: BigUint = BigUint::one() << (len as u32 * 8);
                let wrapped: BigUint = modulus - magnitude;
                wrapped.to_bytes_be()
            } else {
                int.to_biguint().unwrap().to_bytes_be()
            };
            if bytes.is_empty() {
                bytes = vec![0];
            }
            while bytes.len() < min_len {
                bytes.insert(0, 0);
            }
            if little {
                bytes.reverse();
            }
            Ok(Value::Bytes(bytes))
        }
        other => Err(OperationError::invalid_param(
            "output",
            format!("unknown output format `{other}`"),
        )
        .with_expected("bytes, hex or decimal")),
    }
}

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    use cybercipher_core::{
        Category::Encoding as E,
        ValueKind::{Integer as I, Text as T},
    };

    let tags: &'static [&'static str] = &["encoding", "math", "ctf"];
    let prov = "CyberCipher native Rust on num-bigint";

    reg.add_simple(spec(
        "to-integer", "To Integer",
        "Parses text (decimal or 0x hex, radix mode configurable) or bytes (big/little endian, signed optional) into an arbitrary-precision integer.",
        E, &[T, cybercipher_core::ValueKind::Bytes], I, CostClass::Instant, true,
        vec![
            p_opts("radix", "Radix (text input)", "auto",
                &[ParamOption { value: "auto", label: "Auto (0x prefix → hex)" },
                  ParamOption { value: "decimal", label: "Decimal" },
                  ParamOption { value: "hex", label: "Hex" }], ""),
            p_opts("byteorder", "Byte order (bytes input)", "big",
                &[ParamOption { value: "big", label: "Big endian" },
                  ParamOption { value: "little", label: "Little endian" }], ""),
            p_bool_param(),
            p_int("min_length", "Min bytes (bytes input)", 0, "Zero-pad to this length when converting back later."),
        ],
        tags, &["bigint", "big integer", "bignum"],
        prov, "Round-trip + known-answer tests",
    ), to_integer);

    reg.add_simple(spec(
        "from-integer", "From Integer",
        "Renders an integer as hex, decimal, or byte content (big/little endian, two's complement for negatives).",
        E, &[I], cybercipher_core::ValueKind::Bytes, CostClass::Instant, true,
        vec![
            p_opts("output", "Output", "hex",
                &[ParamOption { value: "hex", label: "Hex text" },
                  ParamOption { value: "decimal", label: "Decimal text" },
                  ParamOption { value: "bytes", label: "Bytes" }], ""),
            p_opts("byteorder", "Byte order (bytes)", "big",
                &[ParamOption { value: "big", label: "Big endian" },
                  ParamOption { value: "little", label: "Little endian" }], ""),
            p_bool_param(),
            p_int("min_length", "Min length (bytes)", 0, "Zero-pad to at least this many bytes."),
        ],
        tags, &["bigint", "big integer", "bignum"],
        prov, "Round-trip + known-answer tests",
    ), from_integer);
}

fn p_bool_param() -> ParamSpec {
    ParamSpec {
        key: "signed",
        label: "Signed (bytes)",
        kind: ParamKind::Boolean,
        default: ParamDefault::Bool(false),
        optional: false,
        hint: "Two's complement for negatives.",
        options: &[],
    }
}
