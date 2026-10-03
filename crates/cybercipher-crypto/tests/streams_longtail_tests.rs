//! Known-answer and round-trip tests for the keystream ops that XOR the
//! input with a stream cipher output (HC-256, Rabbit, ZUC-128).
//!
//! Vector sources: HC-256 paper test vectors (Wu, FSE 2004; as pinned by the
//! RustCrypto `hc-256` crate tests), RFC 4503 Appendix A.2 (Rabbit IV setup)
//! and the 3GPP TS 35.221 Document 3 "Implementor's Test Data" ZUC test sets
//! 1-3 (which match GB/T 33133.1-2016 annex C with the standard work-mode
//! discard of the transition-cycle output).

// See cybercipher-core/src/lib.rs for the rationale.
#![allow(clippy::result_large_err)]

use cybercipher_core::prelude::*;
use cybercipher_core::OperationRegistry;

fn reg() -> OperationRegistry {
    let mut r = OperationRegistry::new();
    cybercipher_crypto::register_all(&mut r);
    r
}

fn run(
    reg: &OperationRegistry,
    id: &str,
    input: &[u8],
    params: &[(&'static str, ParamValue)],
) -> OpResult<Value> {
    let op = reg.get(id).unwrap_or_else(|| panic!("missing op {id}"));
    let mut map = ParamMap::new();
    for (k, v) in params {
        map.insert(*k, v.clone());
    }
    op.execute(
        &Value::Bytes(input.to_vec()),
        &map,
        &ExecutionContext::new(),
    )
}

fn s(v: &Value) -> String {
    match v {
        Value::Text(t) => t.clone(),
        Value::Bytes(b) => b.iter().map(|x| format!("{x:02x}")).collect(),
        other => panic!("unexpected value {other:?}"),
    }
}

fn pv(params: &[(&'static str, &str)]) -> Vec<(&'static str, ParamValue)> {
    params
        .iter()
        .map(|(k, v)| (*k, ParamValue::Str(v.to_string())))
        .collect()
}

fn hex_bytes(input: &str) -> Vec<u8> {
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
        .collect()
}

/// Encrypting `zero_len` zero bytes under (key, nonce) yields the raw
/// keystream; assert it against `expected`. Then a full round-trip on a
/// payload and the symmetric-decrypt direction.
fn keystream_known_answer(op: &str, key: &str, nonce: &str, zero_len: usize, expected: &str) {
    let r = reg();
    let params = pv(&[
        ("key", key),
        ("key_encoding", "hex"),
        ("nonce", nonce),
        ("nonce_encoding", "hex"),
    ]);
    let zeros = vec![0u8; zero_len];
    let out = run(&r, op, &zeros, &params).unwrap();
    assert_eq!(s(&out), expected, "{op} keystream known answer");

    // Round-trip: keystream ops are symmetric, so applying the same op to
    // the ciphertext recovers the payload.
    let payload: Vec<u8> = (0..zero_len).map(|i| (i * 7 + 3) as u8).collect();
    let ct = run(&r, op, &payload, &params).unwrap();
    let back = run(&r, op, &hex_bytes(&s(&ct)), &params).unwrap();
    assert_eq!(back, Value::Bytes(payload), "{op} round-trip");
}

fn rejects_bad_material(op: &str, key: &str, nonce: &str, bad_param: &str) {
    let r = reg();
    let err = run(
        &r,
        op,
        b"data",
        &pv(&[
            ("key", key),
            ("key_encoding", "hex"),
            ("nonce", nonce),
            ("nonce_encoding", "hex"),
        ]),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyError, "{op}");
    assert_eq!(err.parameter.as_deref(), Some(bad_param), "{op}");
}

// -------------------------------------------------------- HC-256 ----
// 32-byte key, 32-byte IV. Paper vectors (Wu, FSE 2004): encrypting all
// zeros gives the keystream directly.

#[test]
fn hc256_paper_vectors() {
    keystream_known_answer(
        "hc256-encrypt",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        64,
        "5b078985d8f6f30d42c5c02fa6b67951\
         53f06534801f89f24e74248b720b4818\
         cd9227ecebcf4dbf8dbf6977e4ae14fa\
         e8504c7bc8a9f3ea6c0106f5327e6981",
    );
    keystream_known_answer(
        "hc256-encrypt",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        64,
        "afe2a2bf4f17cee9fec2058bd1b18bb1\
         5fc042ee712b3101dd501fc60b082a50\
         06c7feed41923d6348c4daa6ff6185af\
         5a13045e34c44894f3e9e72ddf0b5237",
    );
    keystream_known_answer(
        "hc256-encrypt",
        "5500000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        64,
        "1c404afe4fe25fed958f9ad1ae36c06f\
         88a65a3cc0abe223aeb3902f420ed3a8\
         6c3af05944eb396efb79758f5e7a1370\
         d8b7106dcdf7d0adda233472e6dd75f5",
    );
}

#[test]
fn hc256_rejects_bad_lengths() {
    rejects_bad_material(
        "hc256-encrypt",
        "000102030405060708090a0b0c0d0e0f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "key",
    );
    rejects_bad_material(
        "hc256-encrypt",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00",
        "nonce",
    );
}

// -------------------------------------------------------- Rabbit ----
// RFC 4503 Appendix A.2: key 00..00, three IVs, 48 keystream bytes each.
// The RFC prints S[0..3] as big-endian integers (OS2IP/I2OSP), so the
// byte-level keystream of the reference implementation is the reversed
// byte order of the printed octet strings; the values below (and the IV
// byte orders) are the reference-implementation form pinned by the
// RustCrypto `rabbit` crate tests.

#[test]
fn rabbit_rfc4503_iv_vectors() {
    keystream_known_answer(
        "rabbit-encrypt",
        "00000000000000000000000000000000",
        "0000000000000000",
        48,
        "edb70567375dcd7cd89554f85e27a7c6\
         8d4adc7032298f7bd4eff504aca6295f\
         668fbf478adb2be51e6cde292b82de2a",
    );
    keystream_known_answer(
        "rabbit-encrypt",
        "00000000000000000000000000000000",
        "597e26c175f573c3",
        48,
        "6d7d012292ccdce0e2120058b94ecd1f\
         2e6f93edff99247b012521d1104e5fa7\
         a79b0212d0bd56233938e793c312c1eb",
    );
    keystream_known_answer(
        "rabbit-encrypt",
        "00000000000000000000000000000000",
        "2717f4d21a56eba6",
        48,
        "4d1051a123afb670bf8d8505c8d85a44\
         035bc3acc667aeae5b2cf44779f2c896\
         cb5115f034f03d31171ca75f89fccb9f",
    );
}

#[test]
fn rabbit_rejects_bad_lengths() {
    rejects_bad_material(
        "rabbit-encrypt",
        "000102030405060708090a0b0c0d0e0f10",
        "0000000000000000",
        "key",
    );
    rejects_bad_material(
        "rabbit-encrypt",
        "00000000000000000000000000000000",
        "000102030405",
        "nonce",
    );
}

// ------------------------------------------------------- ZUC-128 ----
// 3GPP TS 35.221 Document 3 (Implementor's Test Data) ZUC test sets 1-3:
// z1/z2 are the first two keystream words after the standard work-mode
// transition (the discarded cycle is internal to the implementation).

#[test]
fn zuc_3gpp_test_sets() {
    keystream_known_answer(
        "zuc-encrypt",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        8,
        "27bede74018082da",
    );
    keystream_known_answer(
        "zuc-encrypt",
        "ffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffff",
        8,
        "0657cfa07096398b",
    );
    keystream_known_answer(
        "zuc-encrypt",
        "3d4c4be96a82fdaeb58f641db17b455b",
        "84319aa8de6915ca1f6bda6bfbd8c766",
        8,
        "14f1c2723279c419",
    );
}

#[test]
fn zuc_rejects_bad_lengths() {
    rejects_bad_material(
        "zuc-encrypt",
        "000102030405060708090a0b0c0d0e0f00",
        "00000000000000000000000000000000",
        "key",
    );
    rejects_bad_material(
        "zuc-encrypt",
        "00000000000000000000000000000000",
        "0000000000000000000000000000000000",
        "nonce",
    );
}

/// Regression for the batch B refactor of `stream_spec`/`stream_run`: the
/// pre-existing Salsa20/XSalsa20 ops must still round-trip through the
/// registry with their original key/nonce widths.
#[test]
fn salsa20_xsalsa20_regression_roundtrip() {
    let r = reg();
    let payload = b"regression payload 0123456789".to_vec();
    let cases = [
        (
            "salsa20",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "0001020304050607",
        ),
        (
            "xsalsa20",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f1011121314151617",
        ),
    ];
    for (op, key, nonce) in cases {
        let params = pv(&[
            ("key", key),
            ("key_encoding", "hex"),
            ("nonce", nonce),
            ("nonce_encoding", "hex"),
        ]);
        let ct = run(&r, op, &payload, &params).unwrap();
        let back = run(&r, op, &hex_bytes(&s(&ct)), &params).unwrap();
        assert_eq!(back, Value::Bytes(payload.clone()), "{op} round-trip");
    }
}

/// Text inputs coerce to UTF-8 bytes for the keystream ops, and the ops stay
/// reachable under their short aliases.
#[test]
fn stream_ops_accept_text_input_and_aliases() {
    let r = reg();
    let zuc_params = pv(&[
        ("key", "3d4c4be96a82fdaeb58f641db17b455b"),
        ("key_encoding", "hex"),
        ("nonce", "84319aa8de6915ca1f6bda6bfbd8c766"),
        ("nonce_encoding", "hex"),
    ]);
    let as_bytes = run(&r, "zuc-encrypt", b"hello", &zuc_params).unwrap();
    let op = r.get("zuc-encrypt").unwrap();
    let mut map = ParamMap::new();
    for (k, v) in zuc_params.clone() {
        map.insert(k, v);
    }
    let as_text = op
        .execute(
            &Value::Text("hello".to_string()),
            &map,
            &ExecutionContext::new(),
        )
        .unwrap();
    assert_eq!(as_bytes, as_text, "Text input == Bytes input");

    // The short aliases are advertised on the specs (search resolves them).
    let aliases: Vec<&str> = ["rabbit", "hc256", "zuc"]
        .iter()
        .map(|alias| {
            r.all()
                .find(|op| op.spec().aliases.iter().any(|a| a == alias))
                .map(|op| op.spec().id)
                .unwrap_or_else(|| panic!("missing alias {alias}"))
        })
        .collect();
    assert_eq!(aliases, ["rabbit-encrypt", "hc256-encrypt", "zuc-encrypt"]);
}

/// Non-hex key material surfaces a structured decode error naming the
/// parameter, not a panic.
#[test]
fn stream_ops_reject_undecodable_key_material() {
    let r = reg();
    let err = run(
        &r,
        "rabbit-encrypt",
        b"data",
        &pv(&[
            ("key", "zzzz-not-hex"),
            ("key_encoding", "hex"),
            ("nonce", "0000000000000000"),
            ("nonce_encoding", "hex"),
        ]),
    )
    .unwrap_err();
    assert_eq!(err.parameter.as_deref(), Some("key"));
}
