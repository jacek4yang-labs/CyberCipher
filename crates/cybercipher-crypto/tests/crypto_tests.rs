//! Known-answer and round-trip tests. Vector sources: NIST SP 800-38A /
//! FIPS 197 (AES), GB/T 0002 (SM4), classic DES example, RC4 classic vector,
//! FIPS 180-4 / RFC 1321 (hashes), RFC 4231 (HMAC), TEA reference vector.

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

const FIPS_KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const FIPS_PT: &str = "6bc1bee22e409f96e93d7e117393172a";

#[test]
fn aes128_ecb_nist_vector() {
    let r = reg();
    // FIPS 197 Appendix C.1 / SP 800-38A F.1.1 (first block).
    let out = run(
        &r,
        "aes-encrypt",
        &hex_bytes(FIPS_PT),
        &pv(&[
            ("key", FIPS_KEY),
            ("key_encoding", "hex"),
            ("mode", "ecb"),
            ("padding", "none"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&out), "3ad77bb40d7a3660a89ecaf32466ef97");

    let back = run(
        &r,
        "aes-decrypt",
        &hex_bytes(&s(&out)),
        &pv(&[
            ("key", FIPS_KEY),
            ("key_encoding", "hex"),
            ("mode", "ecb"),
            ("padding", "none"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&back), FIPS_PT);
}

#[test]
fn aes128_cbc_nist_vector() {
    let r = reg();
    // SP 800-38A F.2.1 (first block) with the F.2.1 IV.
    let out = run(
        &r,
        "aes-encrypt",
        &hex_bytes(FIPS_PT),
        &pv(&[
            ("key", FIPS_KEY),
            ("key_encoding", "hex"),
            ("mode", "cbc"),
            ("iv", "000102030405060708090a0b0c0d0e0f"),
            ("iv_encoding", "hex"),
            ("padding", "none"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&out), "7649abac8119b246cee98e9b12e9197d");

    let back = run(
        &r,
        "aes-decrypt",
        &hex_bytes(&s(&out)),
        &pv(&[
            ("key", FIPS_KEY),
            ("key_encoding", "hex"),
            ("mode", "cbc"),
            ("iv", "000102030405060708090a0b0c0d0e0f"),
            ("iv_encoding", "hex"),
            ("padding", "none"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&back), FIPS_PT);
}

#[test]
fn aes256_ecb_nist_vector() {
    let r = reg();
    // SP 800-38A C.1 (first block).
    let out = run(
        &r,
        "aes-encrypt",
        &hex_bytes(FIPS_PT),
        &pv(&[
            (
                "key",
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            ),
            ("key_encoding", "hex"),
            ("mode", "ecb"),
            ("padding", "none"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&out), "f3eed1bdb5d2a03c064b5a7e3db181f8");
}

#[test]
fn aes_stream_modes_roundtrip() {
    let r = reg();
    let data = b"stream mode roundtrip with a non-aligned tail!!".to_vec();
    for mode in ["ctr", "cfb", "ofb"] {
        let params: Vec<(&'static str, ParamValue)> = pv(&[
            ("key", FIPS_KEY),
            ("key_encoding", "hex"),
            ("mode", mode),
            ("iv", "000102030405060708090a0b0c0d0e0f"),
        ]);
        let ct = run(&r, "aes-encrypt", &data, &params.clone()).unwrap();
        let back = run(&r, "aes-decrypt", &hex_bytes(&s(&ct)), &params).unwrap();
        assert_eq!(s(&back), hex(&data), "mode {mode}");
    }
}

#[test]
fn aes_pkcs7_roundtrip_and_invalid_padding_diagnostics() {
    let r = reg();
    let data = b"pad me please".to_vec();
    let params: Vec<(&'static str, ParamValue)> = pv(&[
        ("key", FIPS_KEY),
        ("key_encoding", "hex"),
        ("mode", "cbc"),
        ("iv", "00112233445566778899aabbccddeeff"),
    ]);
    let ct = run(&r, "aes-encrypt", &data, &params.clone()).unwrap();
    let back = run(&r, "aes-decrypt", &hex_bytes(&s(&ct)), &params).unwrap();
    assert_eq!(back, Value::Bytes(data));

    // Corrupt the ciphertext: CBC decrypt then PKCS7 unpad must produce a
    // structured error, not silent garbage.
    let mut bad = s(&ct).as_bytes().to_vec();
    let n = bad.len();
    bad[0] ^= 0xff;
    let err = run(
        &r,
        "aes-decrypt",
        &bad,
        &pv(&[
            ("key", FIPS_KEY),
            ("key_encoding", "hex"),
            ("mode", "cbc"),
            ("iv", "00112233445566778899aabbccddeeff"),
        ]),
    )
    .unwrap_err();
    assert!(
        err.kind == ErrorKind::Decode || err.kind == ErrorKind::LengthMismatch,
        "unexpected kind {:?}",
        err.kind
    );
    let _ = n;
}

#[test]
fn aes_key_length_validation() {
    let r = reg();
    let err = run(
        &r,
        "aes-encrypt",
        b"x",
        &pv(&[
            ("key", "2b7e151628aed2a6"),
            ("key_encoding", "hex"),
            ("mode", "ecb"),
            ("padding", "pkcs7"),
        ]),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyError);
    assert!(err.message.contains("16 / 24 / 32"), "{}", err.message);
    assert_eq!(err.parameter.as_deref(), Some("key"));
}

#[test]
fn cbc_requires_iv() {
    let r = reg();
    let err = run(
        &r,
        "aes-encrypt",
        b"0123456789abcdef",
        &pv(&[("key", FIPS_KEY), ("key_encoding", "hex"), ("mode", "cbc")]),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyError);
    assert!(err.message.contains("IV"), "{}", err.message);
}

#[test]
fn sm4_gb_standard_vector() {
    let r = reg();
    // GB/T 32907 standard example: key = plaintext = 0123456789abcdeffedcba9876543210.
    let out = run(
        &r,
        "sm4-encrypt",
        &hex_bytes("0123456789abcdeffedcba9876543210"),
        &pv(&[
            ("key", "0123456789abcdeffedcba9876543210"),
            ("key_encoding", "hex"),
            ("mode", "ecb"),
            ("padding", "none"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&out), "681edf34d206965e86b3e94f536e4246");

    let back = run(
        &r,
        "sm4-decrypt",
        &hex_bytes(&s(&out)),
        &pv(&[
            ("key", "0123456789abcdeffedcba9876543210"),
            ("key_encoding", "hex"),
            ("mode", "ecb"),
            ("padding", "none"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&back), "0123456789abcdeffedcba9876543210");
}

#[test]
fn des_classic_vector_and_3des() {
    let r = reg();
    // Widely-cited DES example: key 0E329232EA6D0D73 encrypts 8787878787878787 to zero.
    let out = run(
        &r,
        "des-encrypt",
        &hex_bytes("8787878787878787"),
        &pv(&[
            ("key", "0E329232EA6D0D73"),
            ("key_encoding", "hex"),
            ("mode", "ecb"),
            ("padding", "none"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&out), "0000000000000000");

    // 3DES round-trip with 2-key and 3-key material.
    for key in [
        "0123456789abcdef0123456789abcdef",
        "0123456789abcdef0123456789abcdef0123456789abcdef",
    ] {
        let params: Vec<(&'static str, ParamValue)> = pv(&[
            ("key", key),
            ("key_encoding", "hex"),
            ("mode", "cbc"),
            ("iv", "fedcba9876543210"),
        ]);
        let ct = run(&r, "des-encrypt", b"3DES!!", &params.clone()).unwrap();
        let back = run(&r, "des-decrypt", &hex_bytes(&s(&ct)), &params).unwrap();
        assert_eq!(back, Value::Bytes(b"3DES!!".to_vec()), "key {key}");
    }
}

#[test]
fn rc4_classic_vector() {
    let r = reg();
    // Classic RC4 vector: key "Key", plaintext "Plaintext" -> BBF316E8D940AF0AD3.
    let out = run(&r, "rc4", b"Plaintext", &pv(&[("key", "4b6579")])).unwrap();
    assert_eq!(s(&out), "bbf316e8d940af0ad3");

    // RC4 is an involution.
    let back = run(&r, "rc4", &hex_bytes(&s(&out)), &pv(&[("key", "4b6579")])).unwrap();
    assert_eq!(back, Value::Bytes(b"Plaintext".to_vec()));
}

#[test]
fn tea_reference_vector_and_family_roundtrips() {
    let r = reg();
    // Zero key/plaintext TEA vector, cross-verified against an independent
    // implementation of the original Wheeler definition (32 cycles).
    let out = run(
        &r,
        "tea-encrypt",
        &[0u8; 8],
        &pv(&[("key", &"0".repeat(32))]),
    )
    .unwrap();
    assert_eq!(s(&out), "41ea3a0a94baa940");

    // Round-trips for the whole family.
    let data = b"round-trip-16by!".to_vec();
    let cases: Vec<(&str, &str)> = vec![
        ("tea", "00000000000000000000000000000000"),
        ("tea", "0123456789abcdeffedcba9876543210"),
        ("xtea", "0123456789abcdeffedcba9876543210"),
        ("xxtea", "0123456789abcdeffedcba9876543210"),
    ];
    for (family, key) in cases {
        let params: Vec<(&'static str, ParamValue)> = pv(&[("key", key)]);
        let enc_op = format!("{family}-encrypt");
        let dec_op = format!("{family}-decrypt");
        let ct = run(&r, &enc_op, &data, &params.clone()).unwrap();
        let back = run(&r, &dec_op, &hex_bytes(&s(&ct)), &params).unwrap();
        assert_eq!(back, Value::Bytes(data.clone()), "{family}");
    }
}

#[test]
fn tea_input_validation() {
    let r = reg();
    // Not a multiple of 8.
    let err = run(
        &r,
        "tea-encrypt",
        b"1234567",
        &pv(&[("key", &"0".repeat(32))]),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::LengthMismatch);

    // XXTEA needs at least two words.
    let err = run(
        &r,
        "xxtea-encrypt",
        b"abcd",
        &pv(&[("key", &"0".repeat(32))]),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::LengthMismatch);
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn hash_known_answers() {
    let r = reg();
    let abc = b"abc".to_vec();
    let cases: Vec<(&str, &str)> = vec![
        ("md5", "900150983cd24fb0d6963f7d28e17f72"),
        ("sha1", "a9993e364706816aba3e25717850c26c9cd0d89d"),
        ("sha256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            "sha512",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
        ("sha3", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        ("sm3", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
    ];
    for (op, expected) in cases {
        let params: Vec<(&'static str, ParamValue)> = if op == "sha3" {
            pv(&[("variant", "sha3-256")])
        } else {
            vec![]
        };
        let out = run(&r, op, &abc, &params).unwrap();
        assert_eq!(s(&out), expected, "{op}");
    }
}

#[test]
fn hmac_rfc4231_vector() {
    let r = reg();
    // RFC 4231 test case 1: key = 0x0b * 20, data "Hi There".
    let out = run(
        &r,
        "hmac",
        b"Hi There",
        &pv(&[
            ("key", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            ("key_encoding", "hex"),
            ("algorithm", "sha256"),
        ]),
    )
    .unwrap();
    assert_eq!(
        s(&out),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

#[test]
fn engine_integrates_crypto_ops() {
    let engine =
        cybercipher_engine::RecipeEngine::new(Arc::new(cybercipher_engine::default_registry()));
    let recipe = cybercipher_engine::RecipeV1::new(vec![cybercipher_engine::RecipeNodeV1 {
        id: "h".into(),
        op: "sha256".into(),
        enabled: true,
        params: ParamMap::new(),
    }]);
    let report = engine
        .execute(
            &recipe,
            Value::Text("abc".into()),
            cybercipher_engine::RunMode::Manual,
            &ExecutionContext::new(),
        )
        .unwrap();
    assert!(report.error.is_none());
    match &report.output {
        Some(Value::Text(t)) => assert_eq!(
            t,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        ),
        other => panic!("unexpected output {other:?}"),
    }
}

// Engine integration requires the engine crate as a dev-dependency.
use std::sync::Arc;
