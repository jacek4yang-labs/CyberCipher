//! Known-answer and round-trip tests for codec operations.
//! Vectors: RFC 4648 (Base64 §10, Base32 §7), hand-computed byte-op cases.

// See cybercipher-core/src/lib.rs for the rationale.
#![allow(clippy::result_large_err)]

use cybercipher_core::prelude::*;
use cybercipher_core::OperationRegistry;

fn run_op(
    reg: &OperationRegistry,
    id: &str,
    input: Value,
    params: &[(&str, ParamValue)],
) -> OpResult<Value> {
    let op = reg.get(id).unwrap_or_else(|| panic!("missing op {id}"));
    let mut map = ParamMap::new();
    for (k, v) in params {
        map.insert(*k, v.clone());
    }
    op.execute(&input, &map, &ExecutionContext::new())
}

fn run_text(
    reg: &OperationRegistry,
    id: &str,
    input: &str,
    params: &[(&str, ParamValue)],
) -> OpResult<Value> {
    run_op(reg, id, Value::Text(input.to_string()), params)
}

fn pv(params: &[(&'static str, &str)]) -> Vec<(&'static str, ParamValue)> {
    params
        .iter()
        .map(|(k, v)| (*k, ParamValue::Str(v.to_string())))
        .collect()
}

fn pvb(params: &[(&'static str, bool)]) -> Vec<(&'static str, ParamValue)> {
    params
        .iter()
        .map(|(k, v)| (*k, ParamValue::Bool(*v)))
        .collect()
}

fn pvi(params: &[(&'static str, i64)]) -> Vec<(&'static str, ParamValue)> {
    params
        .iter()
        .map(|(k, v)| (*k, ParamValue::Int(*v)))
        .collect()
}

#[test]
fn rfc4648_base64_vectors() {
    let mut reg = OperationRegistry::new();
    cybercipher_codec::register_all(&mut reg);

    for (input, expected) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        let out = run_text(&reg, "to-base64", input, &[]).unwrap();
        assert_eq!(out, Value::Text(expected.to_string()), "input {input:?}");
        let back = run_text(&reg, "from-base64", expected, &[]).unwrap();
        assert_eq!(
            back,
            Value::Bytes(input.as_bytes().to_vec()),
            "b64 {expected:?}"
        );
    }
}

#[test]
fn rfc4648_base32_vectors() {
    let mut reg = OperationRegistry::new();
    cybercipher_codec::register_all(&mut reg);
    for (input, expected) in [
        ("", ""),
        ("f", "MY======"),
        ("fo", "MZXQ===="),
        ("foo", "MZXW6==="),
        ("foob", "MZXW6YQ="),
        ("fooba", "MZXW6YTB"),
        ("foobar", "MZXW6YTBOI======"),
    ] {
        let out = run_text(&reg, "to-base32", input, &[]).unwrap();
        assert_eq!(out, Value::Text(expected.to_string()), "input {input:?}");
        let back = run_text(&reg, "from-base32", expected, &[]).unwrap();
        assert_eq!(back, Value::Bytes(input.as_bytes().to_vec()));
    }
}

#[test]
fn hex_roundtrip_and_strict_diagnostics() {
    let mut reg = OperationRegistry::new();
    cybercipher_codec::register_all(&mut reg);

    let out = run_text(&reg, "to-hex", "Hello", &[]).unwrap();
    assert_eq!(out, Value::Text("48656c6c6f".to_string()));

    let out = run_text(&reg, "to-hex", "Hello", &pvb(&[("uppercase", true)])).unwrap();
    assert_eq!(out, Value::Text("48656C6C6F".to_string()));

    let back = run_text(&reg, "from-hex", "48 65 6C 6C 6F", &[]).unwrap();
    assert_eq!(back, Value::Bytes(b"Hello".to_vec()));

    // Odd digit count -> actionable error.
    let err = run_text(&reg, "from-hex", "48656c6c6", &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode);

    // Non-hex char in strict mode names the offending character.
    let err = run_text(&reg, "from-hex", "48 65 zz", &[]).unwrap_err();
    assert!(err.message.contains('z'), "message: {}", err.message);

    // Relaxed mode drops non-hex characters.
    let back = run_text(
        &reg,
        "from-hex",
        "48-65-6c-6c-6f",
        &pvb(&[("strict", false)]),
    )
    .unwrap();
    assert_eq!(back, Value::Bytes(b"Hello".to_vec()));
}

#[test]
fn base64_urlsafe_and_relaxed() {
    let mut reg = OperationRegistry::new();
    cybercipher_codec::register_all(&mut reg);
    let bytes = vec![0xfb, 0xff, 0xfe];
    let out = run_op(
        &reg,
        "to-base64",
        Value::Bytes(bytes.clone()),
        &pv(&[("alphabet", "urlsafe")]),
    )
    .unwrap();
    assert_eq!(out, Value::Text("-__-".to_string()));
    let back = run_text(&reg, "from-base64", "-__-", &pv(&[("alphabet", "urlsafe")])).unwrap();
    assert_eq!(back, Value::Bytes(bytes));

    // Relaxed: whitespace + missing padding repaired.
    let back = run_text(&reg, "from-base64", "Z g", &pvb(&[("strict", false)])).unwrap();
    assert_eq!(back, Value::Bytes(b"f".to_vec()));

    // Strict rejects whitespace with actionable details.
    let err = run_text(&reg, "from-base64", "Z g==", &[]).unwrap_err();
    assert!(err.details.is_some());
}

#[test]
fn url_roundtrip() {
    let mut reg = OperationRegistry::new();
    cybercipher_codec::register_all(&mut reg);
    let out = run_text(&reg, "to-url", "a b/c?d=e&f+g", &[]).unwrap();
    assert_eq!(out, Value::Text("a%20b%2Fc%3Fd%3De%26f%2Bg".to_string()));
    let back = run_text(&reg, "from-url", "a%20b%2Fc%3Fd%3De%26f%2Bg", &[]).unwrap();
    assert_eq!(back, Value::Text("a b/c?d=e&f+g".to_string()));
    let plus = run_text(&reg, "from-url", "a+b", &pvb(&[("plus_as_space", true)])).unwrap();
    assert_eq!(plus, Value::Text("a b".to_string()));
}

#[test]
fn radix_roundtrips() {
    let mut reg = OperationRegistry::new();
    cybercipher_codec::register_all(&mut reg);
    let text = "Hi!";
    for (to, from) in [
        ("to-binary", "from-binary"),
        ("to-octal", "from-octal"),
        ("to-decimal", "from-decimal"),
    ] {
        let out = run_text(&reg, to, text, &[]).unwrap();
        let back = run_text(&reg, from, out.as_text().unwrap(), &[]).unwrap();
        assert_eq!(back, Value::Bytes(b"Hi!".to_vec()), "{to}");
    }
    let dec = run_text(&reg, "to-decimal", "Hi!", &[]).unwrap();
    assert_eq!(dec, Value::Text("72 105 33".to_string()));
    // From-decimal accepts commas and newlines.
    let back = run_text(&reg, "from-decimal", "72,105,\n33", &[]).unwrap();
    assert_eq!(back, Value::Bytes(b"Hi!".to_vec()));
    // Out-of-range values are rejected with context.
    let err = run_text(&reg, "from-decimal", "72 999", &[]).unwrap_err();
    assert!(err.message.contains("does not fit"), "{}", err.message);
}

#[test]
fn xor_known_answers() {
    let mut reg = OperationRegistry::new();
    cybercipher_codec::register_all(&mut reg);

    // Single-byte key, known answer.
    let out = run_op(
        &reg,
        "xor",
        Value::Bytes(vec![0x00, 0x01, 0x02]),
        &pv(&[("key", "ff"), ("key_encoding", "hex")]),
    )
    .unwrap();
    assert_eq!(out, Value::Bytes(vec![0xff, 0xfe, 0xfd]));

    // Repeating key.
    let out = run_op(
        &reg,
        "xor",
        Value::Bytes(vec![0x00, 0x00, 0x00, 0x00]),
        &pv(&[("key", "aabb"), ("key_encoding", "hex")]),
    )
    .unwrap();
    assert_eq!(out, Value::Bytes(vec![0xaa, 0xbb, 0xaa, 0xbb]));

    // XOR is its own inverse.
    let out2 = run_op(
        &reg,
        "xor",
        out,
        &pv(&[("key", "aabb"), ("key_encoding", "hex")]),
    )
    .unwrap();
    assert_eq!(out2, Value::Bytes(vec![0, 0, 0, 0]));

    // Incrementing: key byte 0x10 -> out[i] = in[i] ^ (0x10 + i).
    let out = run_op(
        &reg,
        "xor",
        Value::Bytes(vec![0x00, 0x00, 0x00]),
        &pv(&[
            ("key", "10"),
            ("key_encoding", "hex"),
            ("scheme", "incrementing"),
        ]),
    )
    .unwrap();
    assert_eq!(out, Value::Bytes(vec![0x10, 0x11, 0x12]));

    // Empty key -> typed error.
    let err = run_op(&reg, "xor", Value::Bytes(vec![1]), &pv(&[("key", "")])).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyError);
    assert_eq!(err.parameter.as_deref(), Some("key"));
}

#[test]
fn bitwise_rotate_endianness() {
    let mut reg = OperationRegistry::new();
    cybercipher_codec::register_all(&mut reg);

    let out = run_op(
        &reg,
        "bitwise-and",
        Value::Bytes(vec![0xab]),
        &pv(&[("key", "0f"), ("key_encoding", "hex")]),
    )
    .unwrap();
    assert_eq!(out, Value::Bytes(vec![0x0b]));

    let out = run_op(&reg, "bitwise-not", Value::Bytes(vec![0x0f, 0xf0]), &[]).unwrap();
    assert_eq!(out, Value::Bytes(vec![0xf0, 0x0f]));

    let out = run_op(
        &reg,
        "rotate-left",
        Value::Bytes(vec![0b1000_0001]),
        &pvi(&[("amount", 1)]),
    )
    .unwrap();
    assert_eq!(out, Value::Bytes(vec![0b0000_0011]));

    let out = run_op(
        &reg,
        "rotate-right",
        Value::Bytes(vec![0b0000_0011]),
        &pvi(&[("amount", 1)]),
    )
    .unwrap();
    assert_eq!(out, Value::Bytes(vec![0b1000_0001]));

    let out = run_op(
        &reg,
        "swap-endianness",
        Value::Bytes(vec![1, 2, 3, 4]),
        &pvi(&[("word_size", 4)]),
    )
    .unwrap();
    assert_eq!(out, Value::Bytes(vec![4, 3, 2, 1]));

    // Trailing partial word is preserved as-is.
    let out = run_op(
        &reg,
        "swap-endianness",
        Value::Bytes(vec![1, 2, 3]),
        &pvi(&[("word_size", 2)]),
    )
    .unwrap();
    assert_eq!(out, Value::Bytes(vec![2, 1, 3]));
}

#[test]
fn reverse_split_join_roundtrip() {
    let mut reg = OperationRegistry::new();
    cybercipher_codec::register_all(&mut reg);

    let out = run_text(&reg, "reverse", "abc", &[]).unwrap();
    assert_eq!(out, Value::Bytes(b"cba".to_vec()));

    let out = run_text(&reg, "reverse", "abc", &pv(&[("by", "chars")])).unwrap();
    assert_eq!(out, Value::Text("cba".to_string()));

    let split = run_text(&reg, "split", "a,b,,c", &pv(&[("delimiter", ",")])).unwrap();
    match &split {
        Value::List(items) => assert_eq!(items.len(), 4),
        other => panic!("expected list, got {other:?}"),
    }
    let joined = run_op(&reg, "join", split, &pv(&[("delimiter", "-")])).unwrap();
    assert_eq!(joined, Value::Text("a-b--c".to_string()));

    let split = run_text(&reg, "split", "a,b", &pv(&[("delimiter", ",")])).unwrap();
    let joined = run_op(&reg, "join", split, &pv(&[("delimiter", ",")])).unwrap();
    assert_eq!(joined, Value::Text("a,b".to_string()));
}

#[test]
fn entropy_and_strings() {
    let mut reg = OperationRegistry::new();
    cybercipher_codec::register_all(&mut reg);

    let out = run_op(&reg, "entropy", Value::Bytes(b"aaaa".to_vec()), &[]).unwrap();
    match out {
        Value::Json(j) => {
            assert_eq!(j["entropy_bits_per_byte"], 0.0);
            assert_eq!(j["unique_bytes"], 1);
        }
        other => panic!("expected json, got {other:?}"),
    }

    let out = run_text(
        &reg,
        "strings",
        "ab\x00\x01hello world\x02cd",
        &pvi(&[("min_length", 4)]),
    )
    .unwrap();
    assert_eq!(out, Value::Text("hello world".to_string()));
}

#[test]
fn utf8_decode_reports_offset() {
    let mut reg = OperationRegistry::new();
    cybercipher_codec::register_all(&mut reg);
    let err = run_op(
        &reg,
        "decode-text",
        Value::Bytes(vec![0x61, 0xff, 0x62]),
        &[],
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode);
    assert!(err.message.contains("UTF-8"));
    assert!(err
        .actual
        .as_deref()
        .unwrap_or("")
        .contains("byte offset 1"));

    let out = run_op(
        &reg,
        "decode-text",
        Value::Bytes(vec![0x61, 0xff, 0x62]),
        &pvb(&[("lossy", true)]),
    )
    .unwrap();
    assert_eq!(out, Value::Text("a\u{FFFD}b".to_string()));
}

#[test]
fn input_encoding_decode_helpers() {
    assert_eq!(
        cybercipher_codec::decode_input("hex", "48 65").unwrap(),
        b"He"
    );
    assert_eq!(
        cybercipher_codec::decode_input("base64", "SGk=").unwrap(),
        b"Hi"
    );
    assert_eq!(
        cybercipher_codec::decode_input("utf8", "Hi").unwrap(),
        b"Hi"
    );
    assert_eq!(
        cybercipher_codec::decode_input("decimal", "72 105").unwrap(),
        b"Hi"
    );
    assert!(cybercipher_codec::decode_input("nope", "x").is_err());
}
