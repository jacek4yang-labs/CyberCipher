//! Official test vectors and negative tests for the AEAD operations.
//!
//! Vector sources: RFC 8439 section 2.8.2 (ChaCha20-Poly1305); NIST GCM test
//! cases 3 and 4 from the McGrew/Viega spec; RFC 3610 packet vectors #1/#2
//! (AES-CCM, 13-byte nonce, 8-byte tag); draft-irtf-cfrg-xchacha section A.1
//! (XChaCha20-Poly1305); RFC 8452 sections 8 and C (AES-GCM-SIV).
//!
//! Negative tests cover corrupted tags, AAD and ciphertext, plus nonce and
//! key length validation.

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

/// Integer parameter (tag lengths, iteration counts, ...).
fn pi(key: &'static str, value: i64) -> (&'static str, ParamValue) {
    (key, ParamValue::Int(value))
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd-length hex in test data");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

const SUNSCREEN: &[u8] =
    b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

const RFC8439_KEY: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
const RFC8439_NONCE: &str = "070000004041424344454647";
const RFC8439_AAD: &str = "50515253c0c1c2c3c4c5c6c7";

#[test]
fn chacha20poly1305_rfc8439_2_8_2() {
    let r = reg();
    let out = run(
        &r,
        "aead-chacha20poly1305-encrypt",
        SUNSCREEN,
        &pv(&[
            ("key", RFC8439_KEY),
            ("key_encoding", "hex"),
            ("nonce", RFC8439_NONCE),
            ("nonce_encoding", "hex"),
            ("aad", RFC8439_AAD),
            ("aad_encoding", "hex"),
        ]),
    )
    .unwrap();
    // RFC 8439 section 2.8.2: ciphertext followed by the tag.
    assert_eq!(
        s(&out),
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
         3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
         92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
         3ff4def08e4b7a9de576d26586cec64b6116\
         1ae10b594f09e26a7e902ecbd0600691"
            .replace(['\n', ' '], "")
    );

    let back = run(
        &r,
        "aead-chacha20poly1305-decrypt",
        &hex_bytes(&s(&out)),
        &pv(&[
            ("key", RFC8439_KEY),
            ("key_encoding", "hex"),
            ("nonce", RFC8439_NONCE),
            ("nonce_encoding", "hex"),
            ("aad", RFC8439_AAD),
            ("aad_encoding", "hex"),
        ]),
    )
    .unwrap();
    assert_eq!(
        s(&back),
        SUNSCREEN
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
}

#[test]
fn aes_gcm_nist_test_case_3() {
    // McGrew/Viega GCM spec test case 3: same key/IV/plaintext as case 4,
    // but no associated data.
    let r = reg();
    let pt = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
              1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
        .replace(['\n', ' '], "");
    let params = pv(&[
        ("key", "feffe9928665731c6d6a8f9467308308"),
        ("key_encoding", "hex"),
        ("nonce", "cafebabefacedbaddecaf888"),
        ("nonce_encoding", "hex"),
    ]);
    let out = run(&r, "aead-aes-gcm-encrypt", &hex_bytes(&pt), &params).unwrap();
    assert_eq!(
        s(&out),
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
         21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985\
         4d5c2af327cd64a62cf35abd2ba6fab4"
            .replace(['\n', ' '], "")
    );

    let back = run(&r, "aead-aes-gcm-decrypt", &hex_bytes(&s(&out)), &params).unwrap();
    assert_eq!(s(&back), pt);
}

#[test]
fn aes_gcm_nist_test_case_4() {
    // McGrew/Viega GCM spec test case 4: the same ciphertext as case 3,
    // but with the 20-byte AAD (which changes the tag).
    let r = reg();
    let pt = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
              1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
        .replace(['\n', ' '], "");
    let out = run(
        &r,
        "aead-aes-gcm-encrypt",
        &hex_bytes(&pt),
        &pv(&[
            ("key", "feffe9928665731c6d6a8f9467308308"),
            ("key_encoding", "hex"),
            ("nonce", "cafebabefacedbaddecaf888"),
            ("nonce_encoding", "hex"),
            ("aad", "feedfacedeadbeeffeedfacedeadbeefabaddad2"),
            ("aad_encoding", "hex"),
        ]),
    )
    .unwrap();
    // NIST GCM test case 4: ciphertext + tag (cross-checked against
    // OpenSSL's AES-128-GCM and the RustCrypto aes-gcm crate).
    assert_eq!(
        s(&out),
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
         21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985\
         da80ce830cfda02da2a218a1744f4c76"
            .replace(['\n', ' '], "")
    );

    let back = run(
        &r,
        "aead-aes-gcm-decrypt",
        &hex_bytes(&s(&out)),
        &pv(&[
            ("key", "feffe9928665731c6d6a8f9467308308"),
            ("key_encoding", "hex"),
            ("nonce", "cafebabefacedbaddecaf888"),
            ("nonce_encoding", "hex"),
            ("aad", "feedfacedeadbeeffeedfacedeadbeefabaddad2"),
            ("aad_encoding", "hex"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&back), pt);
}

#[test]
fn aes_gcm_key_sizes_round_trip() {
    let r = reg();
    for key in [
        "feffe9928665731c6d6a8f9467308308feffe9928665731c",
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
    ] {
        let params = pv(&[
            ("key", key),
            ("key_encoding", "hex"),
            ("nonce", "cafebabefacedbaddecaf888"),
            ("nonce_encoding", "hex"),
        ]);
        let out = run(&r, "aead-aes-gcm-encrypt", SUNSCREEN, &params).unwrap();
        assert_eq!(s(&out).len(), SUNSCREEN.len() * 2 + 32);
        let back = run(&r, "aead-aes-gcm-decrypt", &hex_bytes(&s(&out)), &params).unwrap();
        assert_eq!(
            s(&back),
            SUNSCREEN
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    }
}

#[test]
fn gcm_siv_rfc8452_section_8_worked_example() {
    let r = reg();
    let out = run(
        &r,
        "aead-aes-gcm-siv-encrypt",
        b"Hello world",
        &pv(&[
            ("key", "ee8e1ed9ff2540ae8f2ba9f50bc2f27c"),
            ("key_encoding", "hex"),
            ("nonce", "752abad3e0afb5f434dc4310"),
            ("nonce_encoding", "hex"),
            ("aad", "6578616d706c65"), // "example"
            ("aad_encoding", "hex"),
        ]),
    )
    .unwrap();
    assert_eq!(
        s(&out),
        "5d349ead175ef6b1def6fd4fbcdeb7e4793f4a1d7e4faa70100af1"
    );

    let back = run(
        &r,
        "aead-aes-gcm-siv-decrypt",
        &hex_bytes(&s(&out)),
        &pv(&[
            ("key", "ee8e1ed9ff2540ae8f2ba9f50bc2f27c"),
            ("key_encoding", "hex"),
            ("nonce", "752abad3e0afb5f434dc4310"),
            ("nonce_encoding", "hex"),
            ("aad", "6578616d706c65"),
            ("aad_encoding", "hex"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&back), "48656c6c6f20776f726c64"); // "Hello world"
}

#[test]
fn gcm_siv_rfc8452_appendix_c() {
    let r = reg();
    // C.1, AEAD_AES_128_GCM_SIV, empty plaintext.
    let out = run(
        &r,
        "aead-aes-gcm-siv-encrypt",
        &[],
        &pv(&[
            ("key", "01000000000000000000000000000000"),
            ("key_encoding", "hex"),
            ("nonce", "030000000000000000000000"),
            ("nonce_encoding", "hex"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&out), "dc20e2d83f25705bb49e439eca56de25");

    // C.1, AEAD_AES_128_GCM_SIV, 8-byte plaintext of zeros with the 01 header.
    let out = run(
        &r,
        "aead-aes-gcm-siv-encrypt",
        &hex_bytes("0100000000000000"),
        &pv(&[
            ("key", "01000000000000000000000000000000"),
            ("key_encoding", "hex"),
            ("nonce", "030000000000000000000000"),
            ("nonce_encoding", "hex"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&out), "b5d839330ac7b786578782fff6013b815b287c22493a364c");

    // C.1, AEAD_AES_128_GCM_SIV, 8-byte plaintext plus one AAD byte.
    let out = run(
        &r,
        "aead-aes-gcm-siv-encrypt",
        &hex_bytes("0200000000000000"),
        &pv(&[
            ("key", "01000000000000000000000000000000"),
            ("key_encoding", "hex"),
            ("nonce", "030000000000000000000000"),
            ("nonce_encoding", "hex"),
            ("aad", "01"),
            ("aad_encoding", "hex"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&out), "1e6daba35669f4273b0a1a2560969cdf790d99759abd1508");

    // C.2, AEAD_AES_256_GCM_SIV, empty plaintext.
    let out = run(
        &r,
        "aead-aes-gcm-siv-encrypt",
        &[],
        &pv(&[
            (
                "key",
                "0100000000000000000000000000000000000000000000000000000000000000",
            ),
            ("key_encoding", "hex"),
            ("nonce", "030000000000000000000000"),
            ("nonce_encoding", "hex"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&out), "07f5f4169bbf55a8400cd47ea6fd400f");

    // C.2, AEAD_AES_256_GCM_SIV, 8-byte plaintext of zeros with the 01 header.
    let out = run(
        &r,
        "aead-aes-gcm-siv-encrypt",
        &hex_bytes("0100000000000000"),
        &pv(&[
            (
                "key",
                "0100000000000000000000000000000000000000000000000000000000000000",
            ),
            ("key_encoding", "hex"),
            ("nonce", "030000000000000000000000"),
            ("nonce_encoding", "hex"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&out), "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28");
}

#[test]
fn xchacha20poly1305_draft_a1() {
    let r = reg();
    let out = run(
        &r,
        "aead-xchacha20poly1305-encrypt",
        SUNSCREEN,
        &pv(&[
            ("key", RFC8439_KEY),
            ("key_encoding", "hex"),
            ("nonce", "404142434445464748494a4b4c4d4e4f5051525354555657"),
            ("nonce_encoding", "hex"),
            ("aad", RFC8439_AAD),
            ("aad_encoding", "hex"),
        ]),
    )
    .unwrap();
    assert_eq!(
        s(&out),
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cb\
         b731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b45\
         22f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff\
         921f9664c97637da9768812f615c68b13b52e\
         c0875924c1c7987947deafd8780acf49"
            .replace(['\n', ' '], "")
    );

    let back = run(
        &r,
        "aead-xchacha20poly1305-decrypt",
        &hex_bytes(&s(&out)),
        &pv(&[
            ("key", RFC8439_KEY),
            ("key_encoding", "hex"),
            ("nonce", "404142434445464748494a4b4c4d4e4f5051525354555657"),
            ("nonce_encoding", "hex"),
            ("aad", RFC8439_AAD),
            ("aad_encoding", "hex"),
        ]),
    )
    .unwrap();
    assert_eq!(
        s(&back),
        SUNSCREEN
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
}

#[test]
fn aes_ccm_rfc3610_vector_1() {
    let r = reg();
    let msg = hex_bytes("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
    let params = pv(&[
        ("key", "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"),
        ("key_encoding", "hex"),
        ("nonce", "00000003020100a0a1a2a3a4a5"),
        ("nonce_encoding", "hex"),
        ("aad", "0001020304050607"),
        ("aad_encoding", "hex"),
    ]);
    let mut params = params;
    params.push(pi("tag_length", 8));
    let out = run(&r, "aead-aes-ccm-encrypt", &msg, &params).unwrap();
    // RFC 3610 packet vector #1: ciphertext (22) followed by the 8-byte MIC.
    assert_eq!(
        s(&out),
        "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0"
    );

    let back = run(&r, "aead-aes-ccm-decrypt", &hex_bytes(&s(&out)), &params).unwrap();
    assert_eq!(s(&back), "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
}

#[test]
fn aes_ccm_rfc3610_vector_2() {
    let r = reg();
    let msg = hex_bytes("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let params = pv(&[
        ("key", "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"),
        ("key_encoding", "hex"),
        ("nonce", "00000004030201a0a1a2a3a4a5"),
        ("nonce_encoding", "hex"),
        ("aad", "0001020304050607"),
        ("aad_encoding", "hex"),
    ]);
    let mut params = params;
    params.push(pi("tag_length", 8));
    let out = run(&r, "aead-aes-ccm-encrypt", &msg, &params).unwrap();
    // RFC 3610 packet vector #2.
    assert_eq!(
        s(&out),
        "72c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3ba091d56e10400916"
    );

    let back = run(&r, "aead-aes-ccm-decrypt", &hex_bytes(&s(&out)), &params).unwrap();
    assert_eq!(s(&back), "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
}

#[test]
fn aes_ccm_nist_vector_tag4_nonce7() {
    // NIST CCM validation vector (AES-128, 7-byte nonce, 4-byte tag).
    let r = reg();
    let params = pv(&[
        ("key", "404142434445464748494a4b4c4d4e4f"),
        ("key_encoding", "hex"),
        ("nonce", "10111213141516"),
        ("nonce_encoding", "hex"),
        ("aad", "0001020304050607"),
        ("aad_encoding", "hex"),
    ]);
    let mut params = params;
    params.push(pi("tag_length", 4));
    let out = run(&r, "aead-aes-ccm-encrypt", &hex_bytes("20212223"), &params).unwrap();
    assert_eq!(s(&out), "7162015b4dac255d");

    let back = run(
        &r,
        "aead-aes-ccm-decrypt",
        &hex_bytes("7162015b4dac255d"),
        &params,
    )
    .unwrap();
    assert_eq!(s(&back), "20212223");
}

#[test]
fn aes_ccm_tag16_round_trip() {
    let r = reg();
    let params = pv(&[
        ("key", "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"),
        ("key_encoding", "hex"),
        ("nonce", "00000003020100a0a1a2a3a4a5"),
        ("nonce_encoding", "hex"),
        ("aad", "0001020304050607"),
        ("aad_encoding", "hex"),
    ]);
    let mut params = params;
    params.push(pi("tag_length", 16));
    let out = run(&r, "aead-aes-ccm-encrypt", SUNSCREEN, &params).unwrap();
    assert_eq!(s(&out).len(), SUNSCREEN.len() * 2 + 32);
    let back = run(&r, "aead-aes-ccm-decrypt", &hex_bytes(&s(&out)), &params).unwrap();
    assert_eq!(
        s(&back),
        SUNSCREEN
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
}

#[test]
fn aead_round_trips_every_construction() {
    let r = reg();
    let cases: &[(&str, &[(&'static str, &str)])] = &[
        (
            "aead-aes-gcm-encrypt",
            &[
                ("key", "000102030405060708090a0b0c0d0e0f"),
                ("key_encoding", "hex"),
                ("nonce", "266d3d4fc0dc4e92a59bb7ea"),
                ("nonce_encoding", "hex"),
            ],
        ),
        (
            "aead-aes-ccm-encrypt",
            &[
                ("key", "000102030405060708090a0b0c0d0e0f"),
                ("key_encoding", "hex"),
                ("nonce", "00000003020100a0a1a2a3a4a5"),
                ("nonce_encoding", "hex"),
            ],
        ),
        (
            "aead-chacha20poly1305-encrypt",
            &[
                ("key", RFC8439_KEY),
                ("key_encoding", "hex"),
                ("nonce", RFC8439_NONCE),
                ("nonce_encoding", "hex"),
            ],
        ),
        (
            "aead-xchacha20poly1305-encrypt",
            &[
                ("key", RFC8439_KEY),
                ("key_encoding", "hex"),
                ("nonce", "404142434445464748494a4b4c4d4e4f5051525354555657"),
                ("nonce_encoding", "hex"),
            ],
        ),
        (
            "aead-aes-gcm-siv-encrypt",
            &[
                ("key", "01000000000000000000000000000000"),
                ("key_encoding", "hex"),
                ("nonce", "030000000000000000000000"),
                ("nonce_encoding", "hex"),
            ],
        ),
    ];
    let msg = b"round trip message \x00\x01\xff bytes included";
    for (enc_id, params) in cases {
        let mut params = pv(params);
        if enc_id.ends_with("ccm-encrypt") {
            params.push(pi("tag_length", 16));
        }
        let dec_id = enc_id.replace("-encrypt", "-decrypt");
        let out = run(&r, enc_id, msg, &params).unwrap();
        let back = run(&r, &dec_id, &hex_bytes(&s(&out)), &params).unwrap();
        assert_eq!(
            s(&back),
            msg.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "round trip failed for {enc_id}"
        );
    }
}

#[test]
fn corrupted_tag_is_rejected() {
    let r = reg();
    for (enc_id, params) in [
        (
            "aead-aes-gcm-encrypt",
            vec![
                ("key", "000102030405060708090a0b0c0d0e0f"),
                ("key_encoding", "hex"),
                ("nonce", "266d3d4fc0dc4e92a59bb7ea"),
                ("nonce_encoding", "hex"),
            ],
        ),
        (
            "aead-chacha20poly1305-encrypt",
            vec![
                ("key", RFC8439_KEY),
                ("key_encoding", "hex"),
                ("nonce", RFC8439_NONCE),
                ("nonce_encoding", "hex"),
            ],
        ),
        (
            "aead-xchacha20poly1305-encrypt",
            vec![
                ("key", RFC8439_KEY),
                ("key_encoding", "hex"),
                ("nonce", "404142434445464748494a4b4c4d4e4f5051525354555657"),
                ("nonce_encoding", "hex"),
            ],
        ),
        (
            "aead-aes-ccm-encrypt",
            vec![
                ("key", "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"),
                ("key_encoding", "hex"),
                ("nonce", "00000003020100a0a1a2a3a4a5"),
                ("nonce_encoding", "hex"),
            ],
        ),
        (
            "aead-aes-gcm-siv-encrypt",
            vec![
                ("key", "01000000000000000000000000000000"),
                ("key_encoding", "hex"),
                ("nonce", "030000000000000000000000"),
                ("nonce_encoding", "hex"),
            ],
        ),
    ] {
        let mut params = pv(&params);
        if enc_id.ends_with("ccm-encrypt") {
            params.push(pi("tag_length", 8));
        }
        let out = run(&r, enc_id, SUNSCREEN, &params).unwrap();
        let mut sealed = hex_bytes(&s(&out));
        let n = sealed.len();
        sealed[n - 1] ^= 0x01; // flip a tag bit
        let dec_id = enc_id.replace("-encrypt", "-decrypt");
        let err = run(&r, &dec_id, &sealed, &params).unwrap_err();
        assert!(
            err.message.contains("authentication"),
            "{enc_id}: expected an authentication error, got: {err:?}"
        );
    }
}

#[test]
fn corrupted_ciphertext_is_rejected() {
    let r = reg();
    let params = pv(&[
        ("key", "000102030405060708090a0b0c0d0e0f"),
        ("key_encoding", "hex"),
        ("nonce", "266d3d4fc0dc4e92a59bb7ea"),
        ("nonce_encoding", "hex"),
    ]);
    let out = run(&r, "aead-aes-gcm-encrypt", SUNSCREEN, &params).unwrap();
    let mut sealed = hex_bytes(&s(&out));
    sealed[0] ^= 0x80;
    let err = run(&r, "aead-aes-gcm-decrypt", &sealed, &params).unwrap_err();
    assert!(err.message.contains("authentication"));
}

#[test]
fn wrong_aad_is_rejected() {
    let r = reg();
    let params = pv(&[
        ("key", "000102030405060708090a0b0c0d0e0f"),
        ("key_encoding", "hex"),
        ("nonce", "266d3d4fc0dc4e92a59bb7ea"),
        ("nonce_encoding", "hex"),
        ("aad", "deadbeef"),
        ("aad_encoding", "hex"),
    ]);
    let out = run(&r, "aead-aes-gcm-encrypt", SUNSCREEN, &params).unwrap();
    let wrong = pv(&[
        ("key", "000102030405060708090a0b0c0d0e0f"),
        ("key_encoding", "hex"),
        ("nonce", "266d3d4fc0dc4e92a59bb7ea"),
        ("nonce_encoding", "hex"),
        ("aad", "deadbeee"), // different AAD
        ("aad_encoding", "hex"),
    ]);
    let err = run(&r, "aead-aes-gcm-decrypt", &hex_bytes(&s(&out)), &wrong).unwrap_err();
    assert!(err.message.contains("authentication"));
}

#[test]
fn wrong_key_is_rejected() {
    let r = reg();
    let params = pv(&[
        ("key", RFC8439_KEY),
        ("key_encoding", "hex"),
        ("nonce", RFC8439_NONCE),
        ("nonce_encoding", "hex"),
    ]);
    let out = run(&r, "aead-chacha20poly1305-encrypt", SUNSCREEN, &params).unwrap();
    let wrong = pv(&[
        (
            "key",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ),
        ("key_encoding", "hex"),
        ("nonce", RFC8439_NONCE),
        ("nonce_encoding", "hex"),
    ]);
    let err = run(
        &r,
        "aead-chacha20poly1305-decrypt",
        &hex_bytes(&s(&out)),
        &wrong,
    )
    .unwrap_err();
    assert!(err.message.contains("authentication"));
}

#[test]
fn nonce_length_validation() {
    let r = reg();
    // GCM: exactly 12 bytes.
    for nonce in ["cafebabefacedbaddecaf8", "cafebabefacedbaddecaf888aa"] {
        let err = run(
            &r,
            "aead-aes-gcm-encrypt",
            SUNSCREEN,
            &pv(&[
                ("key", "000102030405060708090a0b0c0d0e0f"),
                ("key_encoding", "hex"),
                ("nonce", nonce),
                ("nonce_encoding", "hex"),
            ]),
        )
        .unwrap_err();
        assert!(err.message.contains("nonce"));
    }
    // Empty nonce.
    let err = run(
        &r,
        "aead-aes-gcm-encrypt",
        SUNSCREEN,
        &pv(&[
            ("key", "000102030405060708090a0b0c0d0e0f"),
            ("key_encoding", "hex"),
            ("nonce", ""),
            ("nonce_encoding", "hex"),
        ]),
    )
    .unwrap_err();
    assert!(err.message.contains("nonce"));

    // XChaCha20-Poly1305: exactly 24 bytes (a 12-byte nonce is rejected).
    let err = run(
        &r,
        "aead-xchacha20poly1305-encrypt",
        SUNSCREEN,
        &pv(&[
            ("key", RFC8439_KEY),
            ("key_encoding", "hex"),
            ("nonce", "00000003020100a0a1a2a3a4a5"),
            ("nonce_encoding", "hex"),
        ]),
    )
    .unwrap_err();
    assert!(err.message.contains("nonce"));

    // CCM: 7-13 bytes; 6 and 14 are outside.
    for nonce in ["000000030201", "00000003020100a0a1a2a3a4a5a6"] {
        let err = run(
            &r,
            "aead-aes-ccm-encrypt",
            SUNSCREEN,
            &pv(&[
                ("key", "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"),
                ("key_encoding", "hex"),
                ("nonce", nonce),
                ("nonce_encoding", "hex"),
            ]),
        )
        .unwrap_err();
        assert!(err.message.contains("nonce"));
    }
}

#[test]
fn key_length_validation() {
    let r = reg();
    // GCM: 15 bytes is not a valid AES key length.
    let err = run(
        &r,
        "aead-aes-gcm-encrypt",
        SUNSCREEN,
        &pv(&[
            ("key", "000102030405060708090a0b0c0d0e"),
            ("key_encoding", "hex"),
            ("nonce", "266d3d4fc0dc4e92a59bb7ea"),
            ("nonce_encoding", "hex"),
        ]),
    )
    .unwrap_err();
    assert!(err.message.contains("key"));

    // ChaCha20-Poly1305: 32 bytes only.
    let err = run(
        &r,
        "aead-chacha20poly1305-encrypt",
        SUNSCREEN,
        &pv(&[
            ("key", "000102030405060708090a0b0c0d0e0f"),
            ("key_encoding", "hex"),
            ("nonce", RFC8439_NONCE),
            ("nonce_encoding", "hex"),
        ]),
    )
    .unwrap_err();
    assert!(err.message.contains("key"));

    // GCM-SIV: 16 or 32 bytes, not 24.
    let err = run(
        &r,
        "aead-aes-gcm-siv-encrypt",
        SUNSCREEN,
        &pv(&[
            ("key", "000102030405060708090a0b0c0d0e0f1011121314151617"),
            ("key_encoding", "hex"),
            ("nonce", "030000000000000000000000"),
            ("nonce_encoding", "hex"),
        ]),
    )
    .unwrap_err();
    assert!(err.message.contains("key"));

    // CCM tag length is restricted to 4/8/16.
    let mut params = pv(&[
        ("key", "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"),
        ("key_encoding", "hex"),
        ("nonce", "00000003020100a0a1a2a3a4a5"),
        ("nonce_encoding", "hex"),
    ]);
    params.push(pi("tag_length", 6));
    let err = run(&r, "aead-aes-ccm-encrypt", SUNSCREEN, &params).unwrap_err();
    assert!(err.message.contains("tag length"));
}

#[test]
fn decrypt_input_shorter_than_tag() {
    let r = reg();
    let err = run(
        &r,
        "aead-aes-gcm-decrypt",
        &hex_bytes("00112233"),
        &pv(&[
            ("key", "000102030405060708090a0b0c0d0e0f"),
            ("key_encoding", "hex"),
            ("nonce", "266d3d4fc0dc4e92a59bb7ea"),
            ("nonce_encoding", "hex"),
        ]),
    )
    .unwrap_err();
    assert!(err.message.contains("too short"));
}

#[test]
fn key_as_utf8_encoding_round_trip() {
    let r = reg();
    let params = pv(&[
        ("key", "sixteen byte key"),
        ("key_encoding", "utf8"),
        ("nonce", "266d3d4fc0dc4e92a59bb7ea"),
        ("nonce_encoding", "hex"),
    ]);
    let out = run(&r, "aead-aes-gcm-encrypt", SUNSCREEN, &params).unwrap();
    let back = run(&r, "aead-aes-gcm-decrypt", &hex_bytes(&s(&out)), &params).unwrap();
    assert_eq!(
        s(&back),
        SUNSCREEN
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
}

// ------------------------------------------------------- AES-EAX ----
// Vectors from Appendix G of "The EAX Mode of Operation" (Bellare, Rogaway,
// Wagner; eprint 2003/069), as distributed in Project Wycheproof's
// aes_eax_test.json (C2SP).

#[test]
fn eax_brw_appendix_g_vectors() {
    let r = reg();
    // Vector 1: 16-byte key, 16-byte nonce, 8-byte AAD, 2-byte message.
    let out = run(
        &r,
        "aead-aes-eax-encrypt",
        &hex_bytes("f7fb"),
        &pv(&[
            ("key", "91945d3f4dcbee0bf45ef52255f095a4"),
            ("key_encoding", "hex"),
            ("nonce", "becaf043b0a23d843194ba972c66debd"),
            ("nonce_encoding", "hex"),
            ("aad", "fa3bfd4806eb53fa"),
            ("aad_encoding", "hex"),
        ]),
    )
    .unwrap();
    assert_eq!(
        s(&out),
        "19dd5c4c9331049d0bdab0277408f67967e5",
        "EAX appendix G vector 1 (ciphertext || tag)"
    );
    let back = run(
        &r,
        "aead-aes-eax-decrypt",
        &hex_bytes(&s(&out)),
        &pv(&[
            ("key", "91945d3f4dcbee0bf45ef52255f095a4"),
            ("key_encoding", "hex"),
            ("nonce", "becaf043b0a23d843194ba972c66debd"),
            ("nonce_encoding", "hex"),
            ("aad", "fa3bfd4806eb53fa"),
            ("aad_encoding", "hex"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&back), "f7fb");

    // Vector 6: 16-byte key, 17-byte message.
    let out = run(
        &r,
        "aead-aes-eax-encrypt",
        &hex_bytes("8b0a79306c9ce7ed99dae4f87f8dd61636"),
        &pv(&[
            ("key", "7c77d6e813bed5ac98baa417477a2e7d"),
            ("key_encoding", "hex"),
            ("nonce", "1a8c98dcd73d38393b2bf1569deefc19"),
            ("nonce_encoding", "hex"),
            ("aad", "65d2017990d62528"),
            ("aad_encoding", "hex"),
        ]),
    )
    .unwrap();
    assert_eq!(
        s(&out),
        "02083e3979da014812f59f11d52630da30137327d10649b0aa6e1c181db617d7f2"
    );
}

fn hex_str(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn eax_256_round_trip_and_nonce_validation() {
    let r = reg();
    let params = pv(&[
        (
            "key",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ),
        ("key_encoding", "hex"),
        ("nonce", "bbaa9988776655443322110011223344"),
        ("nonce_encoding", "hex"),
        ("aad", "deadbeef"),
        ("aad_encoding", "hex"),
    ]);
    let out = run(&r, "aead-aes-eax-encrypt", SUNSCREEN, &params).unwrap();
    let back = run(&r, "aead-aes-eax-decrypt", &hex_bytes(&s(&out)), &params).unwrap();
    assert_eq!(s(&back), s(&Value::Bytes(SUNSCREEN.to_vec())));

    // EAX requires the 128-bit nonce.
    let err = run(
        &r,
        "aead-aes-eax-encrypt",
        SUNSCREEN,
        &pv(&[
            ("key", "000102030405060708090a0b0c0d0e0f"),
            ("key_encoding", "hex"),
            ("nonce", "bbaa99887766554433221100"),
            ("nonce_encoding", "hex"),
        ]),
    )
    .unwrap_err();
    assert!(err.message.contains("nonce"));

    // EAX supports 192-bit keys too.
    let params192 = pv(&[
        ("key", "000102030405060708090a0b0c0d0e0f1011121314151617"),
        ("key_encoding", "hex"),
        ("nonce", "bbaa9988776655443322110011223344"),
        ("nonce_encoding", "hex"),
    ]);
    let out = run(&r, "aead-aes-eax-encrypt", b"192-bit EAX", &params192).unwrap();
    let back = run(&r, "aead-aes-eax-decrypt", &hex_bytes(&s(&out)), &params192).unwrap();
    assert_eq!(s(&back), hex_str(b"192-bit EAX"));
}

// ---------------------------------------------------------- OCB3 ----
// RFC 7253 appendix A test vectors (AES-128, 128-bit tag, incrementing
// 96-bit nonces).

#[test]
fn ocb3_rfc7253_appendix_a_vectors() {
    let r = reg();
    let key = "000102030405060708090a0b0c0d0e0f";

    // Vector 1: empty AD, empty plaintext (tag only).
    let out = run(
        &r,
        "aead-ocb3-encrypt",
        b"",
        &pv(&[
            ("key", key),
            ("key_encoding", "hex"),
            ("nonce", "bbaa99887766554433221100"),
            ("nonce_encoding", "hex"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&out), "785407bfffc8ad9edcc5520ac9111ee6");

    // Vector 2: 8-byte AD, 8-byte plaintext.
    let out = run(
        &r,
        "aead-ocb3-encrypt",
        &hex_bytes("0001020304050607"),
        &pv(&[
            ("key", key),
            ("key_encoding", "hex"),
            ("nonce", "bbaa99887766554433221101"),
            ("nonce_encoding", "hex"),
            ("aad", "0001020304050607"),
            ("aad_encoding", "hex"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&out), "6820b3657b6f615a5725bda0d3b4eb3a257c9af1f8f03009");

    // Vector 3: 8-byte AD, empty plaintext.
    let out = run(
        &r,
        "aead-ocb3-encrypt",
        b"",
        &pv(&[
            ("key", key),
            ("key_encoding", "hex"),
            ("nonce", "bbaa99887766554433221102"),
            ("nonce_encoding", "hex"),
            ("aad", "0001020304050607"),
            ("aad_encoding", "hex"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&out), "81017f8203f081277152fade694a0a00");

    // Vector 4: empty AD, 8-byte plaintext.
    let out = run(
        &r,
        "aead-ocb3-encrypt",
        &hex_bytes("0001020304050607"),
        &pv(&[
            ("key", key),
            ("key_encoding", "hex"),
            ("nonce", "bbaa99887766554433221103"),
            ("nonce_encoding", "hex"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&out), "45dd69f8f5aae72414054cd1f35d82760b2cd00d2f99bfa9");

    // Vector 6: 16-byte AD, empty plaintext.
    let out = run(
        &r,
        "aead-ocb3-encrypt",
        b"",
        &pv(&[
            ("key", key),
            ("key_encoding", "hex"),
            ("nonce", "bbaa99887766554433221105"),
            ("nonce_encoding", "hex"),
            ("aad", "000102030405060708090a0b0c0d0e0f"),
            ("aad_encoding", "hex"),
        ]),
    )
    .unwrap();
    assert_eq!(s(&out), "8cf761b6902ef764462ad86498ca6b97");

    // Decrypt vector 2 back and reject a corrupted tag.
    let ct = "6820b3657b6f615a5725bda0d3b4eb3a257c9af1f8f03009";
    let params = pv(&[
        ("key", key),
        ("key_encoding", "hex"),
        ("nonce", "bbaa99887766554433221101"),
        ("nonce_encoding", "hex"),
        ("aad", "0001020304050607"),
        ("aad_encoding", "hex"),
    ]);
    let back = run(&r, "aead-ocb3-decrypt", &hex_bytes(ct), &params).unwrap();
    assert_eq!(s(&back), "0001020304050607");

    let mut corrupted = hex_bytes(ct);
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0x01;
    let err = run(&r, "aead-ocb3-decrypt", &corrupted, &params).unwrap_err();
    assert!(err.message.contains("authentication failed"));

    // OCB3 requires the 96-bit nonce.
    let err = run(
        &r,
        "aead-ocb3-encrypt",
        b"",
        &pv(&[
            ("key", key),
            ("key_encoding", "hex"),
            ("nonce", "bbaa998877665544332211001122"),
            ("nonce_encoding", "hex"),
        ]),
    )
    .unwrap_err();
    assert!(err.message.contains("nonce"));
}

// ------------------------------------------------------- AES-SIV ----
// RFC 5297 appendix A.1 (deterministic) and A.2 (nonce-based) test vectors.
// Wire layout: SIV || ciphertext.

#[test]
fn aes_siv_rfc5297_a1_deterministic() {
    let r = reg();
    let params = pv(&[
        (
            "key",
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        ),
        ("key_encoding", "hex"),
        ("aad", "101112131415161718191a1b1c1d1e1f2021222324252627"),
        ("aad_encoding", "hex"),
    ]);
    let out = run(
        &r,
        "aead-aes-siv-encrypt",
        &hex_bytes("112233445566778899aabbccddee"),
        &params,
    )
    .unwrap();
    assert_eq!(
        s(&out),
        "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c",
        "RFC 5297 A.1: SIV || ciphertext"
    );
    let back = run(&r, "aead-aes-siv-decrypt", &hex_bytes(&s(&out)), &params).unwrap();
    assert_eq!(s(&back), "112233445566778899aabbccddee");
}

#[test]
fn aes_siv_rfc5297_a2_nonce_based() {
    let r = reg();
    let params = pv(&[
        (
            "key",
            "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
        ),
        ("key_encoding", "hex"),
        (
            "aad",
            "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
        ),
        ("aad_encoding", "hex"),
        ("aad2", "102030405060708090a0"),
        ("aad2_encoding", "hex"),
        ("nonce", "09f911029d74e35bd84156c5635688c0"),
        ("nonce_encoding", "hex"),
    ]);
    let out = run(
        &r,
        "aead-aes-siv-encrypt",
        &hex_bytes(
            "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553",
        ),
        &params,
    )
    .unwrap();
    assert_eq!(
        s(&out),
        "7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17\
         dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d"
    );
    let back = run(&r, "aead-aes-siv-decrypt", &hex_bytes(&s(&out)), &params).unwrap();
    assert_eq!(
        s(&back),
        "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553"
    );
}

#[test]
fn aes_siv_round_trip_and_negative_cases() {
    let r = reg();
    // AES-256-SIV (64-byte key) round trip with the nonce omitted.
    let params = pv(&[
        (
            "key",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        ),
        ("key_encoding", "hex"),
    ]);
    let out = run(&r, "aead-aes-siv-encrypt", SUNSCREEN, &params).unwrap();
    let back = run(&r, "aead-aes-siv-decrypt", &hex_bytes(&s(&out)), &params).unwrap();
    assert_eq!(s(&back), s(&Value::Bytes(SUNSCREEN.to_vec())));

    // Corrupting the leading SIV fails authentication.
    let mut sealed = hex_bytes(&s(&out));
    sealed[0] ^= 0x01;
    let err = run(&r, "aead-aes-siv-decrypt", &sealed, &params).unwrap_err();
    assert!(err.message.contains("authentication failed"));

    // Key must be 32 or 64 bytes.
    let err = run(
        &r,
        "aead-aes-siv-encrypt",
        b"x",
        &pv(&[
            ("key", "000102030405060708090a0b0c0d0e0f"),
            ("key_encoding", "hex"),
        ]),
    )
    .unwrap_err();
    assert!(err.message.contains("key"));

    // Decrypt input shorter than the SIV prefix is rejected.
    let err = run(
        &r,
        "aead-aes-siv-decrypt",
        &hex_bytes("00112233"),
        &pv(&[
            (
                "key",
                "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            ),
            ("key_encoding", "hex"),
        ]),
    )
    .unwrap_err();
    assert!(err.message.contains("too short"));
}
