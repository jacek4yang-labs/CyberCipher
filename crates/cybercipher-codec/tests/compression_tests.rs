//! Known-answer and round-trip tests for compression operations.
//! Vectors: RFC 1950/1951/1952 cross-checked against Python `zlib`/`gzip`
//! reference output; format magics per IANA registrations.

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

fn reg() -> OperationRegistry {
    let mut r = OperationRegistry::new();
    cybercipher_codec::register_all(&mut r);
    r
}

#[test]
fn zlib_symmetry_and_known_vector() {
    let r = reg();

    // Known-answer decode: zlib level 6 of "hello" (python zlib.compress).
    let known = [
        0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x06, 0x2c, 0x02, 0x15,
    ];
    let out = run_bytes(&r, "from-zlib", &known, &[]).unwrap();
    assert_eq!(bytes_of(out), b"hello".to_vec());

    // Round-trip.
    let encoded = run_bytes(&r, "to-zlib", b"hello", &[]).unwrap();
    let encoded = bytes_of(encoded);
    assert_eq!(encoded[0], 0x78, "zlib header byte");
    let back = run_bytes(&r, "from-zlib", &encoded, &[]).unwrap();
    assert_eq!(bytes_of(back), b"hello".to_vec());

    // Larger payload round-trips too.
    let payload: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
    let encoded = bytes_of(run_bytes(&r, "to-zlib", &payload, &[]).unwrap());
    let back = bytes_of(run_bytes(&r, "from-zlib", &encoded, &[]).unwrap());
    assert_eq!(back, payload);
}

#[test]
fn deflate_symmetry() {
    let r = reg();
    let payload = b"raw deflate round trip payload".to_vec();
    let encoded = bytes_of(run_bytes(&r, "to-deflate", &payload, &[]).unwrap());
    // Raw deflate has no wrapper: first byte is a deflate block header.
    assert!(!encoded.is_empty());
    assert_ne!(encoded[0], 0x78, "raw deflate must not have a zlib header");
    let back = bytes_of(run_bytes(&r, "from-raw-deflate", &encoded, &[]).unwrap());
    assert_eq!(back, payload);
}

#[test]
fn gzip_known_vector_and_symmetry() {
    let r = reg();

    // Known-answer decode: gzip of "hello" with mtime=0 (python gzip.compress).
    let known: Vec<u8> = vec![
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
        0x07, 0x00, 0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00,
    ];
    let out = run_bytes(&r, "from-gzip", &known, &[]).unwrap();
    assert_eq!(bytes_of(out), b"hello".to_vec());

    let payload = b"gzip symmetry check".to_vec();
    let encoded = bytes_of(run_bytes(&r, "to-gzip", &payload, &[]).unwrap());
    assert_eq!(&encoded[..2], &[0x1f, 0x8b]);
    let back = bytes_of(run_bytes(&r, "from-gzip", &encoded, &[]).unwrap());
    assert_eq!(back, payload);
}

#[test]
fn zlib_malformed_input_is_typed_error() {
    let r = reg();
    let err = run_bytes(&r, "from-zlib", b"\x00\x01\x02\x03", &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode, "{err}");

    let err = run_bytes(&r, "from-gzip", b"PK\x03\x04garbage", &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode, "{err}");
}
