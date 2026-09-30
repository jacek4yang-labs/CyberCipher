//! Known-answer and round-trip tests for structured-data operations.
//! Vectors: RFC 8949 (CBOR), MessagePack reference encoding, hand-computed
//! LEB128 varints and TLV records.

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

fn run_bytes(
    reg: &OperationRegistry,
    id: &str,
    input: &[u8],
    params: &[(&str, ParamValue)],
) -> OpResult<Value> {
    run_op(reg, id, Value::Bytes(input.to_vec()), params)
}

fn bytes_of(v: Value) -> Vec<u8> {
    match v {
        Value::Bytes(b) => b,
        Value::Text(t) => t.into_bytes(),
        other => panic!("expected bytes/text, got {other:?}"),
    }
}

fn ints_of(v: Value) -> Vec<String> {
    match v {
        Value::IntegerList(list) => list.iter().map(|i| i.to_string()).collect(),
        other => panic!("expected integer list, got {other:?}"),
    }
}

fn reg() -> OperationRegistry {
    let mut r = OperationRegistry::new();
    cybercipher_codec::register_all(&mut r);
    r
}

#[test]
fn cbor_known_vector_and_symmetry() {
    let r = reg();

    // RFC 8949-style known answer: {"a":1} encodes to A1 61 61 01.
    let out = run_op(&r, "to-cbor", Value::Text(r#"{"a":1}"#.into()), &[]).unwrap();
    assert_eq!(bytes_of(out), vec![0xA1, 0x61, 0x61, 0x01]);

    let back = run_bytes(&r, "from-cbor", &[0xA1, 0x61, 0x61, 0x01], &[]).unwrap();
    match back {
        Value::Json(j) => {
            assert_eq!(j["a"], 1);
        }
        other => panic!("expected JSON, got {other:?}"),
    }

    // Nested document round-trips (text input, then native JSON input).
    let doc = r#"{"s":"value","n":42,"neg":-7,"f":2.5,"b":true,"z":null,"arr":[1,"two",3],"map":{"k":"v"}}"#;
    let encoded = bytes_of(run_op(&r, "to-cbor", Value::Text(doc.into()), &[]).unwrap());
    let decoded = run_bytes(&r, "from-cbor", &encoded, &[]).unwrap();
    let json = match &decoded {
        Value::Json(j) => j.clone(),
        other => panic!("expected JSON, got {other:?}"),
    };
    assert_eq!(json["s"], "value");
    assert_eq!(json["n"], 42);
    assert_eq!(json["neg"], -7);
    assert_eq!(json["f"], 2.5);
    assert_eq!(json["b"], true);
    assert!(json["z"].is_null());
    assert_eq!(json["arr"][1], "two");
    assert_eq!(json["map"]["k"], "v");

    // Recipe chaining: from-cbor's native JSON output feeds to-cbor directly.
    let re_encoded = run_op(&r, "to-cbor", decoded, &[]).unwrap();
    assert_eq!(bytes_of(re_encoded), encoded);

    // Malformed input is a typed Decode error.
    let err = run_bytes(&r, "from-cbor", &[0xFF, 0x00, 0x01], &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode, "{err}");
}

#[test]
fn msgpack_known_vector_and_symmetry() {
    let r = reg();

    // Reference encoding: {"a":1} -> 81 a1 61 01 (fixmap, fixstr "a", int 1).
    let out = run_op(&r, "to-msgpack", Value::Text(r#"{"a":1}"#.into()), &[]).unwrap();
    assert_eq!(bytes_of(out), vec![0x81, 0xA1, 0x61, 0x01]);

    let back = run_bytes(&r, "from-msgpack", &[0x81, 0xA1, 0x61, 0x01], &[]).unwrap();
    match back {
        Value::Json(j) => assert_eq!(j["a"], 1),
        other => panic!("expected JSON, got {other:?}"),
    }

    let doc = r#"{"list":[1,2,3],"text":"hello","flag":false}"#;
    let encoded = bytes_of(run_op(&r, "to-msgpack", Value::Text(doc.into()), &[]).unwrap());
    let decoded = run_bytes(&r, "from-msgpack", &encoded, &[]).unwrap();
    match decoded {
        Value::Json(j) => {
            assert_eq!(j["list"][2], 3);
            assert_eq!(j["text"], "hello");
            assert_eq!(j["flag"], false);
        }
        other => panic!("expected JSON, got {other:?}"),
    }

    let err = run_bytes(&r, "from-msgpack", &[0xC1, 0x42], &[]).unwrap_err(); // 0xC1 is "never used"
    assert_eq!(err.kind, ErrorKind::Decode, "{err}");
}

#[test]
fn varint_known_vectors_and_symmetry() {
    let r = reg();

    // encode(300) = ac 02.
    let out = run_op(&r, "to-varint", Value::Text("300".into()), &[]).unwrap();
    assert_eq!(bytes_of(out), vec![0xAC, 0x02]);

    // Decode from decimal and 0x-hex tokens.
    for text in ["ac 02", "0xAC,0x02", "172 2"] {
        let out = run_op(&r, "from-varint", Value::Text(text.into()), &[]).unwrap();
        assert_eq!(ints_of(out), vec!["300"], "text {text:?}");
    }

    // Multi-byte boundaries.
    for (value, expected) in [
        ("0", vec![0x00]),
        ("127", vec![0x7F]),
        ("128", vec![0x80, 0x01]),
        ("16384", vec![0x80, 0x80, 0x01]),
    ] {
        let out = run_op(&r, "to-varint", Value::Text(value.into()), &[]).unwrap();
        assert_eq!(bytes_of(out), expected, "value {value}");
    }

    // Multiple concatenated varints round-trip.
    let values = "0 1 127 128 300 16384 4294967296";
    let encoded = bytes_of(run_op(&r, "to-varint", Value::Text(values.into()), &[]).unwrap());
    let decoded = ints_of(run_bytes(&r, "from-varint", &encoded, &[]).unwrap());
    assert_eq!(
        decoded,
        vec!["0", "1", "127", "128", "300", "16384", "4294967296"]
    );

    // JSON-array text and native JSON input.
    let encoded = bytes_of(run_op(&r, "to-varint", Value::Text("[1, 300]".into()), &[]).unwrap());
    assert_eq!(encoded, vec![0x01, 0xAC, 0x02]);
    let encoded = bytes_of(
        run_op(
            &r,
            "to-varint",
            Value::Json(serde_json::json!([1, 300])),
            &[],
        )
        .unwrap(),
    );
    assert_eq!(encoded, vec![0x01, 0xAC, 0x02]);
    // Native integer-list input.
    let encoded = run_op(
        &r,
        "to-varint",
        Value::IntegerList(vec![300u32.into()]),
        &[],
    )
    .unwrap();
    assert_eq!(bytes_of(encoded), vec![0xAC, 0x02]);

    // Raw bytes input decodes directly.
    let out = run_bytes(&r, "from-varint", &[0xAC, 0x02], &[]).unwrap();
    assert_eq!(ints_of(out), vec!["300"]);

    // Negatives: truncated varint, 64-bit overflow, bad byte token.
    let err = run_bytes(&r, "from-varint", &[0x80], &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode, "{err}");
    let err = run_bytes(
        &r,
        "from-varint",
        &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F],
        &[],
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode, "{err}");
    let err = run_op(&r, "from-varint", Value::Text("ac 999".into()), &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode, "{err}");
    let err = run_op(&r, "to-varint", Value::Text("-5".into()), &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode, "{err}");
    let err = run_op(&r, "from-varint", Value::Text(String::new()), &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidInput, "{err}");
}

#[test]
fn tlv_known_vectors_and_symmetry() {
    let r = reg();

    // Known answer: tag 01, length 02, "hi".
    let out = run_op(
        &r,
        "to-tlv",
        Value::Text(r#"[{"tag":1,"value":"68 69"}]"#.into()),
        &[],
    )
    .unwrap();
    assert_eq!(bytes_of(out), vec![0x01, 0x02, 0x68, 0x69]);

    let parsed = run_bytes(&r, "from-tlv", &[0x01, 0x02, 0x68, 0x69], &[]).unwrap();
    match parsed {
        Value::Json(j) => {
            assert_eq!(j["element_count"], 1);
            assert_eq!(j["elements"][0]["tag"], 1);
            assert_eq!(j["elements"][0]["length"], 2);
            assert_eq!(j["elements"][0]["value_hex"], "6869");
            assert_eq!(j["elements"][0]["value_ascii"], "hi");
        }
        other => panic!("expected JSON, got {other:?}"),
    }

    // Long-form length: a 200-byte value encodes the length as 81 C8.
    let long_value = vec![0xEE; 200];
    let hex: String = long_value.iter().map(|b| format!("{b:02x}")).collect();
    let out = run_op(
        &r,
        "to-tlv",
        Value::Text(format!(r#"[{{"tag": "0x7f", "value": "{hex}"}}]"#)),
        &[],
    )
    .unwrap();
    let encoded = bytes_of(out);
    assert_eq!(&encoded[..3], &[0x7F, 0x81, 0xC8]);
    let parsed = run_bytes(&r, "from-tlv", &encoded, &[]).unwrap();
    match parsed {
        Value::Json(j) => assert_eq!(j["elements"][0]["length"], 200),
        other => panic!("expected JSON, got {other:?}"),
    }

    // value_text and byte-array value forms.
    let out = run_op(
        &r,
        "to-tlv",
        Value::Text(r#"[{"tag":2,"value_text":"abc"},{"tag":3,"value":[1,2,3]}]"#.into()),
        &[],
    )
    .unwrap();
    assert_eq!(bytes_of(out), vec![2, 3, b'a', b'b', b'c', 3, 3, 1, 2, 3]);

    // Multi-element round-trip through native JSON.
    let doc = serde_json::json!([
        {"tag": 1, "value": "dead"},
        {"tag": 255, "value_text": "ok"}
    ]);
    let encoded = bytes_of(run_op(&r, "to-tlv", Value::Json(doc), &[]).unwrap());
    let parsed = run_bytes(&r, "from-tlv", &encoded, &[]).unwrap();
    match parsed {
        Value::Json(j) => {
            assert_eq!(j["element_count"], 2);
            assert_eq!(j["elements"][1]["tag"], 255);
            assert_eq!(j["elements"][1]["value_ascii"], "ok");
            assert!(j["elements"][0]["value_ascii"].is_null());
        }
        other => panic!("expected JSON, got {other:?}"),
    }

    // Negatives: indefinite length, truncated value, truncated header.
    for bad in [
        vec![0x01, 0x80],
        vec![0x01, 0x05, 0xAA],
        vec![0x01],
        vec![0x01, 0x82, 0x00],
    ] {
        let err = run_bytes(&r, "from-tlv", &bad, &[]).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Decode, "{err} for {bad:?}");
    }
}
