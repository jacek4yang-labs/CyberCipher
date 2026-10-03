//! Known-answer and round-trip tests for the breadth block ciphers
//! (Serpent, Twofish, Blowfish, Camellia, ARIA, CAST5, IDEA, RC2, RC5, RC6,
//! Threefish, Magma, Kuznyechik) and their shared mode wiring.
//!
//! Vector sources: RFC 3713 (Camellia), RFC 5794 (ARIA), RFC 2144 (CAST5),
//! RFC 2268 (RC2), draft-krovetz-rc6-rc5-vectors (RC5/RC6), GOST R 34.12-2015
//! (Magma/Kuznyechik), Crypto++ Threefish vectors, Twofish submission vectors,
//! NESSIE (Serpent/IDEA), Eric Young's Blowfish vectors, NIST SP 800-38A
//! (AES-192/256 and mode wiring).

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

/// ECB single-block known answer, encrypt then decrypt back. `iv` is only
/// needed for ciphers with a mandatory tweak (Threefish).
fn ecb_known_answer(algo: &str, key: &str, pt: &str, ct: &str, tweak: Option<&str>) {
    let r = reg();
    let mut raw = vec![
        ("key", key),
        ("key_encoding", "hex"),
        ("mode", "ecb"),
        ("padding", "none"),
    ];
    if let Some(tweak) = tweak {
        raw.push(("iv", tweak));
        raw.push(("iv_encoding", "hex"));
    }
    let params = pv(&raw);
    let out = run(&r, &format!("{algo}-encrypt"), &hex_bytes(pt), &params).unwrap();
    assert_eq!(s(&out), ct, "{algo} ECB known answer");

    let back = run(&r, &format!("{algo}-decrypt"), &hex_bytes(ct), &params).unwrap();
    assert_eq!(s(&back), pt, "{algo} ECB decrypt");
}

/// Every mode round-trips a mixed-length payload for one cipher.
/// `iv_len` is the width of the IV (or the mandatory tweak).
fn all_modes_roundtrip(algo: &str, key: &str, iv_len: usize) {
    let r = reg();
    let data: Vec<u8> = b"breadth mode round-trip payload with tail!".to_vec();
    let tweak = "000102030405060708090a0b0c0d0e0f";
    let iv = &tweak[..iv_len * 2];
    for mode in ["ecb", "cbc", "ctr", "cfb", "ofb"] {
        let mut params = vec![("key", key), ("key_encoding", "hex"), ("mode", mode)];
        // Threefish needs its tweak in every mode, including ECB.
        if mode != "ecb" || algo == "threefish" {
            params.push(("iv", iv));
            params.push(("iv_encoding", "hex"));
        }
        let params: Vec<(&'static str, ParamValue)> = pv(&params);
        let ct = run(&r, &format!("{algo}-encrypt"), &data, &params.clone()).unwrap();
        let back = run(&r, &format!("{algo}-decrypt"), &hex_bytes(&s(&ct)), &params).unwrap();
        assert_eq!(back, Value::Bytes(data.clone()), "{algo} mode {mode}");
    }
}

/// Wrong-length keys produce structured key errors.
fn rejects_bad_key_length(algo: &str, bad_key: &str) {
    let r = reg();
    let err = run(
        &r,
        &format!("{algo}-encrypt"),
        b"data",
        &pv(&[
            ("key", bad_key),
            ("key_encoding", "hex"),
            ("mode", "ecb"),
            ("padding", "pkcs7"),
        ]),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyError, "{algo}");
    assert_eq!(err.parameter.as_deref(), Some("key"), "{algo}");
}

// ----------------------------------------------------- Serpent ----

#[test]
fn serpent_ecb_nessie_vector_and_modes() {
    // NESSIE Serpent-128-128 verified test vectors, Set 1 vector #0
    // (cross-checked against the NESSIE file hosted at Technion).
    ecb_known_answer(
        "serpent",
        "80000000000000000000000000000000",
        "00000000000000000000000000000000",
        "264e5481eff42a4606abda06c0bfda3d",
        None,
    );
    all_modes_roundtrip("serpent", "000102030405060708090a0b0c0d0e0f", 16);
    rejects_bad_key_length("serpent", "000102030405060708090a0b0c0d0e");
}

// ----------------------------------------------------- Twofish ----

#[test]
fn twofish_ecb_submission_vector_and_modes() {
    // Twofish submission vectors: zero 128-bit key, zero plaintext, first
    // iteration output (same values used by the RustCrypto crate tests).
    ecb_known_answer(
        "twofish",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "9f589f5cf6122c32b6bfec2f2ae8c35a",
        None,
    );
    all_modes_roundtrip("twofish", "000102030405060708090a0b0c0d0e0f", 16);
    rejects_bad_key_length("twofish", "00");
}

// ---------------------------------------------------- Blowfish ----

#[test]
fn blowfish_ecb_eric_young_vector_and_modes() {
    // Eric Young's Blowfish test vectors: entry #0 and the 8-byte-key entry.
    ecb_known_answer(
        "blowfish",
        "0000000000000000",
        "0000000000000000",
        "4ef997456198dd78",
        None,
    );
    ecb_known_answer(
        "blowfish",
        "fedcba9876543210",
        "0123456789abcdef",
        "0aceab0fc6a0a28d",
        None,
    );
    all_modes_roundtrip("blowfish", "0123456789abcdeff0e1d2c3b4a59687", 8);
    // Blowfish keys are variable length: 3 bytes is rejected.
    rejects_bad_key_length("blowfish", "000102");
}

// ---------------------------------------------------- Camellia ----

#[test]
fn camellia_ecb_rfc3713_vector_and_modes() {
    // RFC 3713 test vector (128-bit key).
    ecb_known_answer(
        "camellia",
        "0123456789abcdeffedcba9876543210",
        "0123456789abcdeffedcba9876543210",
        "67673138549669730857065648eabe43",
        None,
    );
    // RFC 3713 192-bit key vector.
    ecb_known_answer(
        "camellia",
        "0123456789abcdeffedcba98765432100011223344556677",
        "0123456789abcdeffedcba9876543210",
        "b4993401b3e996f84ee5cee7d79b09b9",
        None,
    );
    // RFC 3713 256-bit key vector.
    ecb_known_answer(
        "camellia",
        "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
        "0123456789abcdeffedcba9876543210",
        "9acc237dff16d76c20ef7c919e3a7509",
        None,
    );
    all_modes_roundtrip("camellia", "0123456789abcdeffedcba9876543210", 16);
    rejects_bad_key_length("camellia", "0123456789abcdef");
}

// -------------------------------------------------------- ARIA ----

#[test]
fn aria_ecb_rfc5794_vector_and_modes() {
    // RFC 5794 Appendix A.1 (128-bit key).
    ecb_known_answer(
        "aria",
        "000102030405060708090a0b0c0d0e0f",
        "00112233445566778899aabbccddeeff",
        "d718fbd6ab644c739da95f3be6451778",
        None,
    );
    // RFC 5794 Appendix A.3 (256-bit key).
    ecb_known_answer(
        "aria",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00112233445566778899aabbccddeeff",
        "f92bd7c79fb72e2f2b8f80c1972d24fc",
        None,
    );
    all_modes_roundtrip("aria", "000102030405060708090a0b0c0d0e0f", 16);
    rejects_bad_key_length("aria", "0001");
}

// ------------------------------------------------------- CAST5 ----

#[test]
fn cast5_ecb_rfc2144_vector_and_modes() {
    // RFC 2144 Appendix B.1 (128-bit key).
    ecb_known_answer(
        "cast5",
        "0123456712345678234567893456789a",
        "0123456789abcdef",
        "238b4fe5847e44b2",
        None,
    );
    all_modes_roundtrip("cast5", "0123456712345678234567893456789a", 8);
    rejects_bad_key_length("cast5", "0001");
}

// ------------------------------------------------------- CAST6 ----

#[test]
fn cast6_ecb_rfc2612_vector_and_modes() {
    // RFC 2612 Appendix A: zero block under 128- and 256-bit keys.
    ecb_known_answer(
        "cast6",
        "2342bb9efa38542c0af75647f29f615d",
        "00000000000000000000000000000000",
        "c842a08972b43d20836c91d1b7530f6b",
        None,
    );
    ecb_known_answer(
        "cast6",
        "2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604",
        "00000000000000000000000000000000",
        "4f6a2038286897b9c9870136553317fa",
        None,
    );
    // 192-bit key exercises the middle of the key-length table.
    all_modes_roundtrip(
        "cast6",
        "2342bb9efa38542cbed0ac83940ac298bac77a7717942863",
        16,
    );
    rejects_bad_key_length("cast6", "000102030405060708090a0b0c0d0e");
}

// -------------------------------------------------------- IDEA ----

#[test]
fn idea_ecb_classic_vector_and_modes() {
    // Classic IDEA vector (NESSIE/PGP era): key 0001..0008, pt 0000..0003.
    ecb_known_answer(
        "idea",
        "00010002000300040005000600070008",
        "0000000100020003",
        "11fbed2b01986de5",
        None,
    );
    all_modes_roundtrip("idea", "00010002000300040005000600070008", 8);
    rejects_bad_key_length("idea", "0001000200030004");
}

// --------------------------------------------------------- RC2 ----

#[test]
fn rc2_ecb_rfc2268_vector_and_modes() {
    // RFC 2268 section 5, vector 2 (64-bit effective key length).
    ecb_known_answer(
        "rc2",
        "ffffffffffffffff",
        "ffffffffffffffff",
        "278b27e42e2f0d49",
        None,
    );
    all_modes_roundtrip("rc2", "88bca2efdaad32be8f19ec43", 8);
    rejects_bad_key_length("rc2", "");
}

// --------------------------------------------------------- RC5 ----

#[test]
fn rc5_ecb_ietf_vector_and_modes() {
    // draft-krovetz-rc6-rc5-vectors RC5-32/12/16.
    ecb_known_answer(
        "rc5",
        "000102030405060708090a0b0c0d0e0f",
        "0001020304050607",
        "c8d3b3c486700cfa",
        None,
    );
    all_modes_roundtrip("rc5", "000102030405060708090a0b0c0d0e0f", 8);
    rejects_bad_key_length("rc5", "0001020304050607");
}

// --------------------------------------------------------- RC6 ----

#[test]
fn rc6_ecb_ietf_vector_and_modes() {
    // draft-krovetz-rc6-rc5-vectors RC6-32/20/16.
    ecb_known_answer(
        "rc6",
        "000102030405060708090a0b0c0d0e0f",
        "000102030405060708090a0b0c0d0e0f",
        "3a96f9c7f6755cfe46f00e3dcd5d2a3c",
        None,
    );
    all_modes_roundtrip("rc6", "000102030405060708090a0b0c0d0e0f", 16);
    rejects_bad_key_length("rc6", "00");
}

// ---------------------------------------------------- Threefish ----

#[test]
fn threefish_ecb_cryptopp_vector_and_modes() {
    // Crypto++ threefish.txt: zero key, zero tweak, zero plaintext.
    ecb_known_answer(
        "threefish",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "84da2a1f8beaee947066ae3e3103f1ad536db1f4a1192495116b9f3ce6133fd8",
        Some("00000000000000000000000000000000"),
    );
    // Threefish-512 zero key/tweak/plaintext.
    ecb_known_answer(
        "threefish",
        &"00".repeat(64),
        &"00".repeat(64),
        "b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe",
        Some("00000000000000000000000000000000"),
    );
    // Threefish requires a 16-byte tweak even in ECB mode.
    let r = reg();
    let err = run(
        &r,
        "threefish-encrypt",
        &[0u8; 32],
        &pv(&[
            ("key", &"00".repeat(32)),
            ("key_encoding", "hex"),
            ("mode", "ecb"),
            ("padding", "none"),
        ]),
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyError);
    assert!(err.message.contains("tweak"), "{}", err.message);

    // 512-bit key round-trips across all modes: a 16-byte tweak in ECB,
    // a 64-byte IV (whose first 16 bytes are the tweak) in IV modes.
    let r = reg();
    let data: Vec<u8> = b"threefish wide-block round-trip!!".to_vec();
    let tweak = "000102030405060708090a0b0c0d0e0f";
    for mode in ["ecb", "cbc", "ctr", "cfb", "ofb"] {
        let iv: String = if mode == "ecb" {
            tweak.to_string()
        } else {
            // 64-byte IV: tweak (16 bytes) followed by 48 more bytes.
            format!("{tweak}{tweak}{tweak}{tweak}")
        };
        let params: Vec<(&'static str, ParamValue)> = pv(&[
            ("key", &"00".repeat(64)),
            ("key_encoding", "hex"),
            ("mode", mode),
            ("iv", &iv),
            ("iv_encoding", "hex"),
        ]);
        let ct = run(&r, "threefish-encrypt", &data, &params.clone()).unwrap();
        let back = run(&r, "threefish-decrypt", &hex_bytes(&s(&ct)), &params).unwrap();
        assert_eq!(back, Value::Bytes(data.clone()), "threefish mode {mode}");
    }
    rejects_bad_key_length("threefish", &"00".repeat(16));
}

// ------------------------------------------------------- Magma ----

#[test]
fn magma_ecb_gost_vector_and_modes() {
    // GOST R 34.12-2015 test vector (TC26 sbox).
    ecb_known_answer(
        "magma",
        "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "fedcba9876543210",
        "4ee901e5c2d8ca3d",
        None,
    );
    all_modes_roundtrip(
        "magma",
        "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        8,
    );
    rejects_bad_key_length("magma", "ffeeddcc");
}

// -------------------------------------------------- Kuznyechik ----

#[test]
fn kuznyechik_ecb_gost_vector_and_modes() {
    // GOST R 34.12-2015 test vector.
    ecb_known_answer(
        "kuznyechik",
        "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
        "1122334455667700ffeeddccbbaa9988",
        "7f679d90bebc24305a468d42b9d4edcd",
        None,
    );
    all_modes_roundtrip(
        "kuznyechik",
        "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
        16,
    );
    rejects_bad_key_length("kuznyechik", "8899aabb");
}

// --------------------------------- shared wiring regression (AES) ----

#[test]
fn aes192_ecb_nist_vector_through_table() {
    // NIST SP 800-38A F.1.5 (AES-192, first block) — proves the AES key
    // variants still route correctly through the shared table path.
    ecb_known_answer(
        "aes",
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "6bc1bee22e409f96e93d7e117393172a",
        "bd334f1d6e45f25ff712a214571fa5cc",
        None,
    );
}

#[test]
fn aes_ctr_cbc_ofb_nist_mode_vectors() {
    // NIST SP 800-38A F.5.1 (CTR), F.2.1 (CBC) and F.4.1 (OFB) first blocks
    // validate the native mode wiring against the standard.
    let r = reg();
    let key = "2b7e151628aed2a6abf7158809cf4f3c";
    let pt = "6bc1bee22e409f96e93d7e117393172a";

    let ctr_out = run(
        &r,
        "aes-encrypt",
        &hex_bytes(pt),
        &pv(&[
            ("key", key),
            ("key_encoding", "hex"),
            ("mode", "ctr"),
            ("iv", "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
            ("iv_encoding", "hex"),
            ("padding", "none"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&ctr_out), "874d6191b620e3261bef6864990db6ce", "CTR F.5.1");

    let ofb_out = run(
        &r,
        "aes-encrypt",
        &hex_bytes(pt),
        &pv(&[
            ("key", key),
            ("key_encoding", "hex"),
            ("mode", "ofb"),
            ("iv", "000102030405060708090a0b0c0d0e0f"),
            ("iv_encoding", "hex"),
            ("padding", "none"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&ofb_out), "3b3fd92eb72dad20333449f8e83cfb4a", "OFB F.4.1");

    // CFB-128 F.3.1 first block.
    let cfb_out = run(
        &r,
        "aes-encrypt",
        &hex_bytes(pt),
        &pv(&[
            ("key", key),
            ("key_encoding", "hex"),
            ("mode", "cfb"),
            ("iv", "000102030405060708090a0b0c0d0e0f"),
            ("iv_encoding", "hex"),
            ("padding", "none"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&cfb_out), "3b3fd92eb72dad20333449f8e83cfb4a", "CFB F.3.1");
}

// -------------------------------------------- streaming compatibility ----

#[test]
fn ctr_keystream_matches_ctr128_for_large_payloads() {
    // CTR counter carry must behave like Ctr128BE across many blocks.
    let r = reg();
    let data: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
    let params: Vec<(&'static str, ParamValue)> = pv(&[
        ("key", "2b7e151628aed2a6abf7158809cf4f3c"),
        ("key_encoding", "hex"),
        ("mode", "ctr"),
        ("iv", "ffffffffffffffffffffffffffffffff"),
        ("iv_encoding", "hex"),
    ]);
    let ct = run(&r, "aes-encrypt", &data, &params.clone()).unwrap();
    let back = run(&r, "aes-decrypt", &hex_bytes(&s(&ct)), &params).unwrap();
    assert_eq!(back, Value::Bytes(data));
}

#[test]
fn des_now_supports_stream_modes() {
    // 3DES CTR/CFB/OFB round-trip through the shared wiring.
    let r = reg();
    let data = b"3des stream!".to_vec();
    for mode in ["ctr", "cfb", "ofb"] {
        let params: Vec<(&'static str, ParamValue)> = pv(&[
            ("key", "0123456789abcdef0123456789abcdef"),
            ("key_encoding", "hex"),
            ("mode", mode),
            ("iv", "fedcba9876543210"),
            ("iv_encoding", "hex"),
        ]);
        let ct = run(&r, "des-encrypt", &data, &params.clone()).unwrap();
        let back = run(&r, "des-decrypt", &hex_bytes(&s(&ct)), &params).unwrap();
        assert_eq!(back, Value::Bytes(data.clone()), "3DES mode {mode}");
    }
}

// ------------------------------- CBC ciphertext stealing (CTS) ----
// Vector sources: NIST SP 800-38A addendum (CS1 == CBC for whole blocks;
// the addendum's normative equivalences), RFC 3962 appendix B (Kerberos
// CBC-CS3), and the NIST SP 800-38A F.2.1 CBC-AES128 example.

const SP800_38A_KEY128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const SP800_38A_IV: &str = "000102030405060708090a0b0c0d0e0f";

#[test]
fn cbc_cs1_equals_cbc_on_whole_blocks() {
    let r = reg();
    // NIST SP 800-38A F.2.1 CBC-AES128.Encrypt vector #1.
    let params = pv(&[
        ("key", SP800_38A_KEY128),
        ("key_encoding", "hex"),
        ("iv", SP800_38A_IV),
        ("iv_encoding", "hex"),
        ("mode", "cbc-cs1"),
        ("padding", "none"),
    ]);
    let out = run(
        &r,
        "aes-encrypt",
        &hex_bytes("6bc1bee22e409f96e93d7e117393172a"),
        &params,
    )
    .unwrap();
    assert_eq!(s(&out), "7649abac8119b246cee98e9b12e9197d");
}

#[test]
fn cbc_cs3_rfc3962_kerberos_vectors() {
    let r = reg();
    let params = |mode: &'static str| {
        pv(&[
            ("key", "636869636b656e207465726979616b69"), // "chicken teriyaki"
            ("key_encoding", "hex"),
            ("iv", "00000000000000000000000000000000"),
            ("iv_encoding", "hex"),
            ("mode", mode),
            ("padding", "none"),
        ])
    };
    // RFC 3962 appendix B: 17-byte input ("I would like the ").
    let out = run(
        &r,
        "aes-encrypt",
        &hex_bytes("4920776f756c64206c696b652074686520"),
        &params("cbc-cs3"),
    )
    .unwrap();
    assert_eq!(
        s(&out),
        "c6353568f2bf8cb4d8a580362da7ff7f97",
        "RFC 3962 17-byte CTS vector"
    );
    // RFC 3962 appendix B: 31-byte input ("I would like the General Gau's ").
    let out = run(
        &r,
        "aes-encrypt",
        &hex_bytes("4920776f756c64206c696b65207468652047656e6572616c20476175277320"),
        &params("cbc-cs3"),
    )
    .unwrap();
    assert_eq!(
        s(&out),
        "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5"
    );
    // Round trip both lengths back to the plaintext.
    for (pt, mode) in [
        ("4920776f756c64206c696b652074686520", "cbc-cs3"),
        (
            "4920776f756c64206c696b65207468652047656e6572616c20476175277320",
            "cbc-cs3",
        ),
        ("4920776f756c64206c696b652074686520", "cbc-cs1"),
        (
            "4920776f756c64206c696b65207468652047656e6572616c20476175277320",
            "cbc-cs1",
        ),
        ("4920776f756c64206c696b652074686520", "cbc-cs2"),
    ] {
        let enc = run(&r, "aes-encrypt", &hex_bytes(pt), &params(mode)).unwrap();
        let dec = run(&r, "aes-decrypt", &hex_bytes(&s(&enc)), &params(mode)).unwrap();
        assert_eq!(s(&dec), pt, "CTS {mode} round trip");
    }
}

#[test]
fn cts_variants_follow_addendum_ordering_rules() {
    let r = reg();
    let params = |mode: &'static str| {
        pv(&[
            ("key", SP800_38A_KEY128),
            ("key_encoding", "hex"),
            ("iv", SP800_38A_IV),
            ("iv_encoding", "hex"),
            ("mode", mode),
            ("padding", "none"),
        ])
    };
    // 21-byte plaintext: 1 complete block + 5-byte partial.
    let pt = "6bc1bee22e409f96e93d7e117393172aaabbccdddd";
    let cs1 = run(&r, "aes-encrypt", &hex_bytes(pt), &params("cbc-cs1")).unwrap();
    let cs2 = run(&r, "aes-encrypt", &hex_bytes(pt), &params("cbc-cs2")).unwrap();
    let cs3 = run(&r, "aes-encrypt", &hex_bytes(pt), &params("cbc-cs3")).unwrap();
    // Same length as the plaintext (no padding expansion).
    assert_eq!(s(&cs1).len(), pt.len());
    // CS2 == CS1 with the two final pieces swapped; CS3 == CS2 for a
    // partial final block (NIST addendum sections 3 and 4). The hex string
    // holds 21 bytes = 42 chars: head 32, partial 10, fin 32.
    let swap_tail = |v: &str| {
        let (head, rest) = v.split_at(v.len() - 42);
        let (partial, fin) = rest.split_at(10);
        format!("{head}{fin}{partial}")
    };
    assert_eq!(s(&cs2), swap_tail(&s(&cs1)));
    assert_eq!(s(&cs3), s(&cs2));
    // CS2 == CS1 when the plaintext fills whole blocks.
    let whole = "6bc1bee22e409f96e93d7e117393172a";
    let cs1w = run(&r, "aes-encrypt", &hex_bytes(whole), &params("cbc-cs1")).unwrap();
    let cs2w = run(&r, "aes-encrypt", &hex_bytes(whole), &params("cbc-cs2")).unwrap();
    assert_eq!(s(&cs1w), s(&cs2w));
    // CS3 on two whole blocks swaps the last two ciphertext blocks.
    let two = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";
    let cs3w = run(&r, "aes-encrypt", &hex_bytes(two), &params("cbc-cs3")).unwrap();
    let cbcw = run(&r, "aes-encrypt", &hex_bytes(two), &params("cbc")).unwrap();
    let v = s(&cbcw);
    let (head, rest) = v.split_at(v.len() - 64);
    let (a, b) = rest.split_at(32);
    assert_eq!(s(&cs3w), format!("{head}{b}{a}"));
    // Too-short inputs are rejected.
    let err = run(&r, "aes-encrypt", b"short", &params("cbc-cs1")).unwrap_err();
    assert!(err.message.contains("at least"));
}

#[test]
fn cts_works_for_non_aes_block_ciphers() {
    let r = reg();
    // SM4 (a 128-bit block cipher) exercises the CTS wiring at the same
    // block width but through a different primitive; a 19-byte input has one
    // full block plus a 3-byte partial.
    let params = pv(&[
        ("key", "0123456789abcdeffedcba9876543210"),
        ("key_encoding", "hex"),
        ("iv", "00000000000000000000000000000000"),
        ("iv_encoding", "hex"),
        ("mode", "cbc-cs3"),
        ("padding", "none"),
    ]);
    let enc = run(&r, "sm4-encrypt", b"1234567890123456789", &params).unwrap();
    assert_eq!(s(&enc).len(), 38);
    let dec = run(&r, "sm4-decrypt", &hex_bytes(&s(&enc)), &params).unwrap();
    assert_eq!(s(&dec), s(&Value::Bytes(b"1234567890123456789".to_vec())));
}

// ---------------------------------------------------------- XTS ----
// IEEE P1619/D16 sample vectors (as distributed in the Mbed TLS
// test_suite_aes.xts.data file).

#[test]
fn xts_ieee_p1619_d16_vectors() {
    let r = reg();
    let params = |key: &'static str, tweak: &'static str| {
        pv(&[
            ("key", key),
            ("key_encoding", "hex"),
            ("iv", tweak),
            ("iv_encoding", "hex"),
        ])
    };
    // Vector 1: all-zero 128-bit key, zero tweak, 32-byte data unit.
    let out = run(
        &r,
        "aes-xts-encrypt",
        &hex_bytes("0000000000000000000000000000000000000000000000000000000000000000"),
        &params(
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
        ),
    )
    .unwrap();
    assert_eq!(
        s(&out),
        "917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e"
    );

    // Vector 2.
    let out = run(
        &r,
        "aes-xts-encrypt",
        &hex_bytes(&"44".repeat(32)),
        &params(
            "1111111111111111111111111111111122222222222222222222222222222222",
            "33333333330000000000000000000000",
        ),
    )
    .unwrap();
    assert_eq!(
        s(&out),
        "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0"
    );

    // Vector 3.
    let out = run(
        &r,
        "aes-xts-encrypt",
        &hex_bytes(&"44".repeat(32)),
        &params(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f022222222222222222222222222222222",
            "33333333330000000000000000000000",
        ),
    )
    .unwrap();
    assert_eq!(
        s(&out),
        "af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89"
    );

    // Vectors 15/16: 17- and 18-byte data units (ciphertext stealing);
    // the tweak is the little-endian data-unit number 0x123456789a.
    let key = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0";
    let tweak = "9a785634120000000000000000000000";
    let out = run(
        &r,
        "aes-xts-encrypt",
        &hex_bytes("000102030405060708090a0b0c0d0e0f10"),
        &params(key, tweak),
    )
    .unwrap();
    assert_eq!(s(&out), "6c1625db4671522d3d7599601de7ca09ed");
    let out = run(
        &r,
        "aes-xts-encrypt",
        &hex_bytes("000102030405060708090a0b0c0d0e0f1011"),
        &params(key, tweak),
    )
    .unwrap();
    assert_eq!(s(&out), "d069444b7a7e0cab09e24447d24deb1fedbf");

    // Steal cases decrypt back to the plaintext.
    for pt in [
        "000102030405060708090a0b0c0d0e0f10",
        "000102030405060708090a0b0c0d0e0f1011",
    ] {
        let enc = run(&r, "aes-xts-encrypt", &hex_bytes(pt), &params(key, tweak)).unwrap();
        let dec = run(
            &r,
            "aes-xts-decrypt",
            &hex_bytes(&s(&enc)),
            &params(key, tweak),
        )
        .unwrap();
        assert_eq!(s(&dec), pt);
    }
}

#[test]
fn xts_aes256_round_trip_and_validation() {
    let r = reg();
    let params = pv(&[
        (
            "key",
            "2718281828459045235360287471352662497757247093699959574966967627\
             3141592653589793238462643383279502884197169399375105820974944592",
        ),
        ("key_encoding", "hex"),
        ("iv", "ffffffff000000000000000000000000"),
        ("iv_encoding", "hex"),
    ]);
    // Round trip an odd 33-byte data unit (stealing path) with AES-256-XTS.
    let enc = run(
        &r,
        "aes-xts-encrypt",
        b"XTS-AES data unit payload 33 bytes!!",
        &params,
    )
    .unwrap();
    let dec = run(&r, "aes-xts-decrypt", &hex_bytes(&s(&enc)), &params).unwrap();
    assert_eq!(
        s(&dec),
        s(&Value::Bytes(
            b"XTS-AES data unit payload 33 bytes!!".to_vec()
        ))
    );

    // Doubled-key length is validated.
    let err = run(
        &r,
        "aes-xts-encrypt",
        b"x",
        &pv(&[
            ("key", "000102030405060708090a0b0c0d0e0f"),
            ("key_encoding", "hex"),
            ("iv", "00000000000000000000000000000000"),
            ("iv_encoding", "hex"),
        ]),
    )
    .unwrap_err();
    assert!(err.message.contains("32 / 48 / 64"));

    // The 16-byte tweak is mandatory.
    let err = run(
        &r,
        "aes-xts-encrypt",
        b"x",
        &pv(&[
            (
                "key",
                "2718281828459045235360287471352662497757247093699959574966967627\
                 3141592653589793238462643383279502884197169399375105820974944592",
            ),
            ("key_encoding", "hex"),
            ("iv", "0000"),
            ("iv_encoding", "hex"),
        ]),
    )
    .unwrap_err();
    assert!(err.message.contains("tweak"));

    // Data units shorter than one block are rejected (SP 800-38E).
    let err = run(&r, "aes-xts-encrypt", b"tiny", &params).unwrap_err();
    assert!(err.message.contains("at least"));
}
