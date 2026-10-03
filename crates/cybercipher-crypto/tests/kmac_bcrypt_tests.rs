//! Known-answer and behavior tests for KMAC (NIST SP 800-185, in-tree
//! Keccak sponge) and bcrypt (hash/verify).
//!
//! KMAC vectors: NIST SP 800-185 "KMAC samples" #1-#6 (extracted from
//! csrc.nist.gov). bcrypt vectors: the Openwall bcrypt test set
//! (https://www.openwall.com/crypt/), verified through bcrypt-verify so no
//! salt-encoding assumptions are needed.

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

fn pi(key: &'static str, value: i64) -> (&'static str, ParamValue) {
    (key, ParamValue::Int(value))
}

fn hex_bytes(input: &str) -> Vec<u8> {
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
        .collect()
}

// --------------------------------------------------------- KMAC ----

const SAMPLE_KEY: &str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
const DATA4: &str = "00010203";
const CUST: &str = "My Tagged Application";

/// The 1600-bit (200-byte) sample data: bytes 00..C7.
fn data200() -> Vec<u8> {
    (0u16..200).map(|i| i as u8).collect()
}

#[test]
fn kmac128_nist_samples() {
    let r = reg();
    // Sample #1: L = 32 bytes, empty customization.
    let out = run(
        &r,
        "kmac128",
        &hex_bytes(DATA4),
        &pv(&[("key", SAMPLE_KEY), ("key_encoding", "hex")]),
    )
    .unwrap();
    assert_eq!(
        s(&out),
        "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e"
    );

    // Sample #2: with the sample customization string.
    let out = run(
        &r,
        "kmac128",
        &hex_bytes(DATA4),
        &pv(&[
            ("key", SAMPLE_KEY),
            ("key_encoding", "hex"),
            ("customization", CUST),
        ]),
    )
    .unwrap();
    assert_eq!(
        s(&out),
        "3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5"
    );

    // Sample #3: 200-byte message with the customization string.
    let out = run(
        &r,
        "kmac128",
        &data200(),
        &pv(&[
            ("key", SAMPLE_KEY),
            ("key_encoding", "hex"),
            ("customization", CUST),
        ]),
    )
    .unwrap();
    assert_eq!(
        s(&out),
        "1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230"
    );
}

#[test]
fn kmac256_nist_samples() {
    let r = reg();
    // Sample #4: 64-byte tag over the 4-byte message.
    let out = run(
        &r,
        "kmac256",
        &hex_bytes(DATA4),
        &pv(&[
            ("key", SAMPLE_KEY),
            ("key_encoding", "hex"),
            ("customization", CUST),
        ]),
    )
    .unwrap();
    assert_eq!(
        s(&out),
        "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7\
         f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd"
    );

    // Sample #5: 200-byte message, empty customization.
    let out = run(
        &r,
        "kmac256",
        &data200(),
        &pv(&[("key", SAMPLE_KEY), ("key_encoding", "hex")]),
    )
    .unwrap();
    assert_eq!(
        s(&out),
        "75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691\
         589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69"
    );

    // Sample #6: 200-byte message with the customization string.
    let out = run(
        &r,
        "kmac256",
        &data200(),
        &pv(&[
            ("key", SAMPLE_KEY),
            ("key_encoding", "hex"),
            ("customization", CUST),
        ]),
    )
    .unwrap();
    assert_eq!(
        s(&out),
        "b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d9\
         70fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965"
    );
}

#[test]
fn kmac_keys_and_lengths() {
    let r = reg();
    // A different key must produce a different tag; the output_length
    // parameter controls L for fixed-length KMAC.
    let tag = run(
        &r,
        "kmac128",
        b"attack at dawn",
        &pv(&[("key", SAMPLE_KEY), ("key_encoding", "hex")]),
    )
    .unwrap();
    let other_key = run(
        &r,
        "kmac128",
        b"attack at dawn",
        &pv(&[("key", "00"), ("key_encoding", "hex")]),
    )
    .unwrap();
    assert_ne!(s(&tag), s(&other_key));

    let short = run(
        &r,
        "kmac128",
        b"attack at dawn",
        &[
            ("key", ParamValue::Str(SAMPLE_KEY.to_string())),
            ("key_encoding", ParamValue::Str("hex".to_string())),
            pi("output_length", 16),
        ],
    )
    .unwrap();
    assert_eq!(s(&short).len(), 32); // 16 bytes as hex
                                     // The suffix encodes the output length L (SP 800-185 §4.3), so tags of
                                     // different lengths are independent outputs, not prefix extensions.
    assert_ne!(s(&short), s(&tag)[..32]);

    // Missing key and out-of-range lengths produce typed errors.
    let err = run(&r, "kmac128", b"data", &[]).unwrap_err();
    assert_eq!(err.parameter.as_deref(), Some("key"));
    let err = run(
        &r,
        "kmac128",
        b"data",
        &[
            ("key", ParamValue::Str("00".to_string())),
            ("key_encoding", ParamValue::Str("hex".to_string())),
            pi("output_length", 0),
        ],
    )
    .unwrap_err();
    assert_eq!(err.parameter.as_deref(), Some("output_length"));
}

// -------------------------------------------------------- bcrypt ----

const OPENWALL_VECTORS: &[(&str, &str)] = &[
    (
        "U*U",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
    ),
    (
        "U*U*",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK",
    ),
    (
        "U*U*U",
        "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a",
    ),
    // Passwords longer than 72 bytes: bcrypt-2a silently truncates, so the
    // digest only depends on the first 72 bytes (the vector's point).
    (
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789chars after 72 are ignored",
        "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui",
    ),
];

#[test]
fn bcrypt_verify_openwall_vectors() {
    let r = reg();
    for (password, hash) in OPENWALL_VECTORS {
        let out = run(
            &r,
            "bcrypt-verify",
            password.as_bytes(),
            &pv(&[("hash", hash)]),
        )
        .unwrap();
        assert_eq!(s(&out), "true", "verify {hash}");
    }

    // Wrong password: valid hash, negative verdict.
    let out = run(
        &r,
        "bcrypt-verify",
        b"U*U*U*",
        &pv(&[("hash", OPENWALL_VECTORS[0].1)]),
    )
    .unwrap();
    assert_eq!(s(&out), "false");
}

#[test]
fn bcrypt_verify_rejects_malformed_hashes() {
    let r = reg();
    for bad in [
        "not-a-hash",
        "$2a$05$short",
        "$2c$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
    ] {
        let err = run(&r, "bcrypt-verify", b"U*U", &pv(&[("hash", bad)])).unwrap_err();
        assert_eq!(err.parameter.as_deref(), Some("hash"), "{bad}");
    }
}

#[test]
fn bcrypt_hash_deterministic_with_salt_and_roundtrips() {
    let r = reg();
    let salt = "000102030405060708090a0b0c0d0e0f";
    let params = vec![
        pi("cost", 5),
        ("salt", ParamValue::Str(salt.to_string())),
        ("salt_encoding", ParamValue::Str("hex".to_string())),
    ];
    let h1 = run(&r, "bcrypt-hash", b"correct horse", &params).unwrap();
    let h2 = run(&r, "bcrypt-hash", b"correct horse", &params).unwrap();
    assert_eq!(s(&h1), s(&h2), "explicit salt must be deterministic");
    assert!(s(&h1).starts_with("$2b$05$"), "got {}", s(&h1));

    // Version selector is honored with an explicit salt.
    let v2a = run(
        &r,
        "bcrypt-hash",
        b"correct horse",
        &[
            pi("cost", 5),
            ("salt", ParamValue::Str(salt.to_string())),
            ("salt_encoding", ParamValue::Str("hex".to_string())),
            ("version", ParamValue::Str("2a".to_string())),
        ],
    )
    .unwrap();
    assert!(s(&v2a).starts_with("$2a$05$"), "got {}", s(&v2a));

    // The produced hash verifies under bcrypt-verify.
    let ok = run(
        &r,
        "bcrypt-verify",
        b"correct horse",
        &pv(&[("hash", &s(&h1))]),
    )
    .unwrap();
    assert_eq!(s(&ok), "true");
    let no = run(
        &r,
        "bcrypt-verify",
        b"wrong horse",
        &pv(&[("hash", &s(&h1))]),
    )
    .unwrap();
    assert_eq!(s(&no), "false");
}

#[test]
fn bcrypt_hash_rejects_bad_params() {
    let r = reg();
    // Cost out of range.
    for cost in [3, 32] {
        let err = run(&r, "bcrypt-hash", b"pw", &[pi("cost", cost)]).unwrap_err();
        assert_eq!(err.parameter.as_deref(), Some("cost"), "cost {cost}");
    }
    // Salt length must be exactly 16 bytes.
    let err = run(
        &r,
        "bcrypt-hash",
        b"pw",
        &[
            (
                "salt",
                ParamValue::Str("000102030405060708090a0b0c0d0e".to_string()),
            ),
            ("salt_encoding", ParamValue::Str("hex".to_string())),
        ],
    )
    .unwrap_err();
    assert_eq!(err.parameter.as_deref(), Some("salt"));
}
