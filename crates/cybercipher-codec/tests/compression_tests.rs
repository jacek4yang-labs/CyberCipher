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

#[test]
fn bzip2_known_vector_and_symmetry() {
    let r = reg();

    // Known-answer decode: bzip2 level 9 of "hello" (python bz2.compress).
    let known: Vec<u8> = vec![
        0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x19, 0x31, 0x65, 0x3d, 0x00,
        0x00, 0x00, 0x81, 0x00, 0x02, 0x44, 0xa0, 0x00, 0x21, 0x9a, 0x68, 0x33, 0x4d, 0x07, 0x33,
        0x8b, 0xb9, 0x22, 0x9c, 0x28, 0x48, 0x0c, 0x98, 0xb2, 0x9e, 0x80,
    ];
    let out = run_bytes(&r, "from-bzip2", &known, &[]).unwrap();
    assert_eq!(bytes_of(out), b"hello".to_vec());

    let payload: Vec<u8> = (0..60_000u32).map(|i| (i % 7) as u8).collect();
    let encoded = bytes_of(run_bytes(&r, "to-bzip2", &payload, &[]).unwrap());
    assert_eq!(&encoded[..3], b"BZh", "bzip2 magic prefix");
    let back = bytes_of(run_bytes(&r, "from-bzip2", &encoded, &[]).unwrap());
    assert_eq!(back, payload);

    let err = run_bytes(&r, "from-bzip2", b"BZh9garbage!", &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode, "{err}");
    let err = run_bytes(&r, "from-bzip2", b"not bzip2 at all", &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode, "{err}");
}

#[test]
fn xz_known_vector_and_symmetry() {
    let r = reg();

    // Known-answer decode: xz preset 6 of "hello" (python lzma, FORMAT_XZ).
    let known: Vec<u8> = vec![
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x02, 0x00, 0x21,
        0x01, 0x16, 0x00, 0x00, 0x00, 0x74, 0x2f, 0xe5, 0xa3, 0x01, 0x00, 0x04, 0x68, 0x65, 0x6c,
        0x6c, 0x6f, 0x00, 0x00, 0x00, 0x00, 0xb1, 0x37, 0xb9, 0xdb, 0xe5, 0xda, 0x1e, 0x9b, 0x00,
        0x01, 0x1d, 0x05, 0xb8, 0x2d, 0x80, 0xaf, 0x1f, 0xb6, 0xf3, 0x7d, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x59, 0x5a,
    ];
    let out = run_bytes(&r, "from-xz", &known, &[]).unwrap();
    assert_eq!(bytes_of(out), b"hello".to_vec());

    let payload = b"xz round trip payload".to_vec();
    let encoded = bytes_of(run_bytes(&r, "to-xz", &payload, &[]).unwrap());
    assert_eq!(
        &encoded[..6],
        &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],
        "xz magic"
    );
    let back = bytes_of(run_bytes(&r, "from-xz", &encoded, &[]).unwrap());
    assert_eq!(back, payload);

    let mut truncated = known.clone();
    truncated.truncate(30);
    let err = run_bytes(&r, "from-xz", &truncated, &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode, "{err}");
    let err = run_bytes(&r, "from-xz", b"garbage not xz", &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode, "{err}");
}

#[test]
fn zstd_magic_and_symmetry() {
    let r = reg();
    let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 13) as u8).collect();
    let encoded = bytes_of(run_bytes(&r, "to-zstd", &payload, &[]).unwrap());
    assert_eq!(&encoded[..4], &[0x28, 0xB5, 0x2F, 0xFD], "zstd magic");
    let back = bytes_of(run_bytes(&r, "from-zstd", &encoded, &[]).unwrap());
    assert_eq!(back, payload);

    // Truncated stream: valid magic, garbage payload.
    let mut bad = encoded.clone();
    bad.truncate(12);
    let err = run_bytes(&r, "from-zstd", &bad, &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode, "{err}");
    let err = run_bytes(&r, "from-zstd", b"junkjunkjunk", &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode, "{err}");
}

#[test]
fn lz4_magic_and_symmetry() {
    let r = reg();
    let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 9) as u8).collect();
    let encoded = bytes_of(run_bytes(&r, "to-lz4", &payload, &[]).unwrap());
    assert_eq!(&encoded[..4], &[0x04, 0x22, 0x4D, 0x18], "lz4 frame magic");
    let back = bytes_of(run_bytes(&r, "from-lz4", &encoded, &[]).unwrap());
    assert_eq!(back, payload);

    // Truncate in the middle of the compressed block data (EOF at a block
    // boundary is a clean end for the LZ4 frame format).
    let mut bad = encoded.clone();
    bad.truncate(encoded.len() / 2);
    let err = run_bytes(&r, "from-lz4", &bad, &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode, "{err}");
    let err = run_bytes(&r, "from-lz4", b"junkjunkjunk", &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode, "{err}");
}

#[test]
fn brotli_symmetry_no_magic() {
    let r = reg();
    let payload = b"brotli has no magic number, so round-trip only".to_vec();
    let encoded = bytes_of(run_bytes(&r, "to-brotli", &payload, &[]).unwrap());
    assert!(!encoded.is_empty());
    let back = bytes_of(run_bytes(&r, "from-brotli", &encoded, &[]).unwrap());
    assert_eq!(back, payload);

    let err = run_bytes(&r, "from-brotli", &[0xff; 16], &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode, "{err}");
}

#[test]
fn decompression_cap_rejects_huge_output() {
    let r = reg();
    // ~70 MiB of zeros compresses to a few KB but exceeds the 64 MiB cap.
    let payload = vec![0u8; 70 * 1024 * 1024];
    let encoded = bytes_of(run_bytes(&r, "to-gzip", &payload, &[]).unwrap());
    assert!(encoded.len() < 1024 * 1024, "sanity: zeros compress well");
    let err = run_bytes(&r, "from-gzip", &encoded, &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::BudgetExceeded, "{err}");
}

#[test]
fn bomb_ratio_rejects_100x_expansion() {
    let r = reg();
    // 16 MiB of zeros -> ~7 KB gzip (>= 1 KiB floor) -> ratio ~2300x > 100x.
    let payload = vec![0u8; 16 * 1024 * 1024];
    let encoded = bytes_of(run_bytes(&r, "to-gzip", &payload, &[]).unwrap());
    assert!(encoded.len() >= 1024, "sanity: compressed size hits floor");
    let err = run_bytes(&r, "from-gzip", &encoded, &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::BudgetExceeded, "{err}");

    // Small highly-compressible payloads stay below the ratio floor and
    // must keep working (a few bytes legitimately expand 1000x).
    let small_encoded = bytes_of(run_bytes(&r, "to-gzip", &[0u8; 4096], &[]).unwrap());
    let back = bytes_of(run_bytes(&r, "from-gzip", &small_encoded, &[]).unwrap());
    assert_eq!(back, vec![0u8; 4096]);
}
