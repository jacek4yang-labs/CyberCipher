//! Crypto Assist profile tests for SM4/DES/3DES/Serpent/Twofish/Camellia/RC4:
//! per-algorithm roundtrips (the true configuration must rank first with a
//! confident score), structural pruning negatives (wrong key/IV lengths are
//! pruned, never attempted), bounded candidate counts, official test-vector
//! fixtures, and exact recipe replay. Ciphertext instances are generated
//! deterministically through the registry itself.

#![allow(clippy::result_large_err)]

use cybercipher_attack::assist::{
    camellia_assist, des_assist, generate_profile_candidates, rc4_assist, recipe_ops_for_profile,
    serpent_assist, sm4_assist, tdes_assist, twofish_assist, AssistInput, AssistProfile,
    CamelliaProfile, DesProfile, IvSource, KeyInterpretation, Mode, Rc4Profile, SerpentProfile,
    Sm4Profile, TdesProfile, TwofishProfile,
};
use cybercipher_core::{ExecutionContext, OperationRegistry, ParamMap, ParamValue, Value};

fn registry() -> OperationRegistry {
    cybercipher_engine::default_registry()
}

/// Encrypt with a registry block-cipher op (empty mode/iv/padding omitted).
fn block_encrypt(
    reg: &OperationRegistry,
    op_id: &str,
    plaintext: &[u8],
    key_hex: &str,
    mode: &str,
    iv_hex: &str,
    padding: &str,
) -> Vec<u8> {
    let op = reg.get(op_id).unwrap();
    let mut map = ParamMap::new();
    map.insert("key", ParamValue::Str(key_hex.to_string()));
    map.insert("key_encoding", ParamValue::Str("hex".to_string()));
    if !mode.is_empty() {
        map.insert("mode", ParamValue::Str(mode.to_string()));
    }
    if !iv_hex.is_empty() {
        map.insert("iv", ParamValue::Str(iv_hex.to_string()));
        map.insert("iv_encoding", ParamValue::Str("hex".to_string()));
    }
    if !padding.is_empty() {
        map.insert("padding", ParamValue::Str(padding.to_string()));
    }
    match op
        .execute(
            &Value::Bytes(plaintext.to_vec()),
            &map,
            &ExecutionContext::new(),
        )
        .unwrap()
    {
        Value::Bytes(b) => b,
        other => panic!("unexpected encrypt output {other:?}"),
    }
}

/// RC4 (encryption == decryption, no mode/IV/padding parameters).
fn rc4_encrypt(reg: &OperationRegistry, key_hex: &str, plaintext: &[u8]) -> Vec<u8> {
    let op = reg.get("rc4").unwrap();
    let mut map = ParamMap::new();
    map.insert("key", ParamValue::Str(key_hex.to_string()));
    map.insert("key_encoding", ParamValue::Str("hex".to_string()));
    match op
        .execute(
            &Value::Bytes(plaintext.to_vec()),
            &map,
            &ExecutionContext::new(),
        )
        .unwrap()
    {
        Value::Bytes(b) => b,
        other => panic!("unexpected rc4 output {other:?}"),
    }
}

const SM4_KEY: &str = "0123456789abcdeffedcba9876543210";
const DES_KEY: &str = "0123456789abcdef";
const IV16: &str = "0f0e0d0c0b0a09080706050403020100";
const IV8: &str = "0f0e0d0c0b0a0908";
const ENGLISH: &[u8] =
    b"there is a steady market for the ordinary words of the language and the matter of the fact remains the same";

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ------------------------------------------------ official test vectors ----

/// GB/T 32907-2016 Appendix A example: SM4 encrypts the key under itself to
/// 681edf34d206965e86b3e94f536e4246 (single ECB block).
#[test]
fn sm4_gbt32907_standard_vector() {
    let reg = registry();
    let ct = block_encrypt(
        &reg,
        "sm4-encrypt",
        &hex_bytes(SM4_KEY),
        SM4_KEY,
        "ecb",
        "",
        "none",
    );
    assert_eq!(hex_str(&ct), "681edf34d206965e86b3e94f536e4246");
}

/// FIPS 81 Appendix C ECB example: DES(key 0123456789ABCDEF) of "Now is t"
/// is 3FA40E8A984D4815.
#[test]
fn des_fips81_standard_vector() {
    let reg = registry();
    let ct = block_encrypt(&reg, "des-encrypt", b"Now is t", DES_KEY, "ecb", "", "none");
    assert_eq!(hex_str(&ct), "3fa40e8a984d4815");
}

// ----------------------------------------------------- roundtrip ranks ----

#[test]
fn sm4_cbc_iv_prefix_ranked_first_with_evidence() {
    let reg = registry();
    let plaintext =
        b"Congratulations, the secret flag is flag{sm4_assist_rocks} and the rest is padding.";
    let ct = block_encrypt(
        &reg,
        "sm4-encrypt",
        plaintext,
        SM4_KEY,
        "cbc",
        IV16,
        "pkcs7",
    );
    // Classic transport layout: IV || body.
    let mut payload = hex_bytes(IV16);
    payload.extend_from_slice(&ct);

    let input = AssistInput {
        ciphertext: payload,
        key_candidate: SM4_KEY.to_string(),
        iv_hex: None,
        hint: Some("flag{".to_string()),
    };
    let result = sm4_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    assert!(!result.hits.is_empty());
    let top = &result.hits[0];
    assert_eq!(top.cipher, "SM4");
    assert_eq!(top.mode, Mode::Cbc);
    assert_eq!(top.iv_source, IvSource::FirstBlock);
    assert_eq!(top.key_interpretation, KeyInterpretation::Hex);
    assert_eq!(top.key_length, 16);
    assert!(top.confident, "score {}", top.score);
    assert!(
        top.preview.contains("flag{sm4_assist_rocks}"),
        "{}",
        top.preview
    );
    assert!(top
        .evidence
        .iter()
        .any(|e| e.to_lowercase().contains("pkcs7")));
}

#[test]
fn sm4_ctr_explicit_iv_ranked_first() {
    let reg = registry();
    let plaintext = b"stream mode leaves lengths untouched and the ordinary words of the language remain the same throughout";
    let ct = block_encrypt(&reg, "sm4-encrypt", plaintext, SM4_KEY, "ctr", IV16, "none");
    assert_eq!(ct.len(), plaintext.len());

    let input = AssistInput {
        ciphertext: ct,
        key_candidate: SM4_KEY.to_string(),
        iv_hex: Some(IV16.to_string()),
        hint: None,
    };
    let result = sm4_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    let top = &result.hits[0];
    assert_eq!(top.mode, Mode::Ctr, "top mode {:?}", top.mode);
    assert_eq!(top.iv_source, IvSource::Explicit);
    assert_eq!(top.padding, None);
    assert!(top.confident, "score {}", top.score);
    assert!(top.preview.contains("stream mode leaves lengths"));
}

#[test]
fn des_cbc_ascii_key_ranked_first() {
    let reg = registry();
    // An 8-character raw-ASCII key: the DES classic interpretation.
    let key = "goblue!!";
    assert_eq!(key.len(), 8);
    let plaintext =
        b"the ordinary words of the language remain the same and the flag is flag{des_assist}";
    let ct = block_encrypt(
        &reg,
        "des-encrypt",
        plaintext,
        &hex_str(key.as_bytes()),
        "cbc",
        IV8,
        "pkcs7",
    );

    let input = AssistInput {
        ciphertext: ct,
        key_candidate: key.to_string(),
        iv_hex: Some(IV8.to_string()),
        hint: None,
    };
    let result = des_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    let top = &result.hits[0];
    assert_eq!(top.cipher, "DES");
    assert_eq!(top.key_interpretation, KeyInterpretation::Utf8);
    assert_eq!(top.key_length, 8);
    assert_eq!(top.mode, Mode::Cbc);
    assert_eq!(top.iv_source, IvSource::Explicit);
    assert_eq!(top.iv_hex, IV8);
    assert!(top.confident, "score {}", top.score);
    assert!(top.preview.contains("flag{des_assist}"));
}

#[test]
fn tdes_cbc_24byte_key_ranked_first() {
    let reg = registry();
    let key24 = "000102030405060708090a0b0c0d0e0f1011121314151617";
    let plaintext = ENGLISH;
    let ct = block_encrypt(&reg, "des-encrypt", plaintext, key24, "cbc", IV8, "pkcs7");

    let input = AssistInput {
        ciphertext: ct,
        key_candidate: key24.to_string(),
        iv_hex: Some(IV8.to_string()),
        hint: None,
    };
    let result = tdes_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    let top = &result.hits[0];
    assert_eq!(top.cipher, "3DES");
    assert_eq!(top.key_length, 24);
    assert_eq!(top.mode, Mode::Cbc);
    assert!(top.confident, "score {}", top.score);
    assert!(top.preview.contains("steady market"));
}

#[test]
fn tdes_16byte_key_ecb_ranked_first() {
    let reg = registry();
    let key16 = "2b7e151628aed2a6abf7158809cf4f3c";
    let ct = block_encrypt(
        &reg,
        "des-encrypt",
        b"three des ecb mode round trip check with ordinary words!!",
        key16,
        "ecb",
        "",
        "pkcs7",
    );

    let input = AssistInput {
        ciphertext: ct,
        key_candidate: key16.to_string(),
        iv_hex: None,
        hint: None,
    };
    let result = tdes_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    let top = &result.hits[0];
    assert_eq!(top.cipher, "3DES");
    assert_eq!(top.key_length, 16);
    assert_eq!(top.mode, Mode::Ecb);
    assert_eq!(top.iv_hex, "");
    assert!(top.confident, "score {}", top.score);
    assert!(top.preview.contains("three des ecb mode"));
}

#[test]
fn serpent_cbc_iv_prefix_ranked_first() {
    let reg = registry();
    let key = "00112233445566778899aabbccddeeff";
    let plaintext =
        b"Congratulations, the secret flag is flag{serpent_rocks} and the rest is padding.";
    let ct = block_encrypt(
        &reg,
        "serpent-encrypt",
        plaintext,
        key,
        "cbc",
        IV16,
        "pkcs7",
    );
    let mut payload = hex_bytes(IV16);
    payload.extend_from_slice(&ct);

    let input = AssistInput {
        ciphertext: payload,
        key_candidate: key.to_string(),
        iv_hex: None,
        hint: Some("flag{".to_string()),
    };
    let result = serpent_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    let top = &result.hits[0];
    assert_eq!(top.cipher, "Serpent");
    assert_eq!(top.mode, Mode::Cbc);
    assert_eq!(top.iv_source, IvSource::FirstBlock);
    // The hex decoding (16 bytes) wins; the 32-char ASCII decoding of the
    // same string is also a legal Serpent key but decrypts to garbage.
    assert_eq!(top.key_interpretation, KeyInterpretation::Hex);
    assert_eq!(top.key_length, 16);
    assert!(top.confident, "score {}", top.score);
    assert!(top.preview.contains("flag{serpent_rocks}"));
}

#[test]
fn twofish_ctr_explicit_iv_ranked_first() {
    let reg = registry();
    let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let plaintext = ENGLISH;
    let ct = block_encrypt(&reg, "twofish-encrypt", plaintext, key, "ctr", IV16, "none");

    let input = AssistInput {
        ciphertext: ct,
        key_candidate: key.to_string(),
        iv_hex: Some(IV16.to_string()),
        hint: None,
    };
    let result = twofish_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    let top = &result.hits[0];
    assert_eq!(top.cipher, "Twofish");
    assert_eq!(top.key_length, 32);
    assert_eq!(top.mode, Mode::Ctr);
    assert!(top.confident, "score {}", top.score);
    assert!(top.preview.contains("steady market"));
}

#[test]
fn camellia_cbc_24byte_key_ranked_first() {
    let reg = registry();
    let key = "2b7e151628aed2a6abf7158809cf4f3cef0123456789abcd";
    let plaintext = ENGLISH;
    let ct = block_encrypt(
        &reg,
        "camellia-encrypt",
        plaintext,
        key,
        "cbc",
        IV16,
        "pkcs7",
    );

    let input = AssistInput {
        ciphertext: ct,
        key_candidate: key.to_string(),
        iv_hex: Some(IV16.to_string()),
        hint: None,
    };
    let result = camellia_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    let top = &result.hits[0];
    assert_eq!(top.cipher, "Camellia");
    assert_eq!(top.key_length, 24);
    assert_eq!(top.mode, Mode::Cbc);
    assert_eq!(top.iv_source, IvSource::Explicit);
    assert!(top.confident, "score {}", top.score);
    assert!(top.preview.contains("steady market"));
}

#[test]
fn rc4_ascii_key_stream_roundtrip() {
    let reg = registry();
    let key = "SuperSecretKey!";
    let ct = rc4_encrypt(&reg, &hex_str(key.as_bytes()), ENGLISH);

    let input = AssistInput {
        ciphertext: ct,
        key_candidate: key.to_string(),
        iv_hex: None,
        hint: None,
    };
    let result = rc4_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    // Only the raw-ASCII interpretation decodes to an in-range RC4 key.
    assert_eq!(result.hits.len(), 1);
    let hit = &result.hits[0];
    assert_eq!(hit.cipher, "RC4");
    assert_eq!(hit.mode, Mode::Stream);
    assert_eq!(hit.padding, None);
    assert_eq!(hit.iv_hex, "");
    assert_eq!(hit.key_interpretation, KeyInterpretation::Utf8);
    assert_eq!(hit.key_length, 15);
    assert!(hit.confident, "score {}", hit.score);
    assert!(hit.preview.contains("steady market"));
    assert!(hit
        .evidence
        .iter()
        .any(|e| e.contains("stream cipher: no mode, IV, or padding")));
}

#[test]
fn rc4_hex_key_ranked_first() {
    let reg = registry();
    let key_hex = "7365637265746b657931"; // "secretkey1", 10 bytes
    let plaintext = b"rc4 keystream xor is symmetric and the flag is flag{rc4_assist} here";
    let ct = rc4_encrypt(&reg, key_hex, plaintext);

    let input = AssistInput {
        ciphertext: ct,
        key_candidate: key_hex.to_string(),
        iv_hex: None,
        hint: None,
    };
    let result = rc4_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    // Both interpretations are in range: hex (10 bytes) and the 20 ASCII bytes.
    assert_eq!(result.hits.len(), 2);
    let top = &result.hits[0];
    assert_eq!(top.key_interpretation, KeyInterpretation::Hex);
    assert_eq!(top.key_length, 10);
    assert!(top.confident, "score {}", top.score);
    assert!(top.preview.contains("flag{rc4_assist}"));
}

// ------------------------------------------------------ pruning rules ----

#[test]
fn wrong_key_length_pruned_sm4() {
    let reg = registry();
    let key24 = "000102030405060708090a0b0c0d0e0f1011121314151617";
    let input = AssistInput {
        ciphertext: vec![0x11u8; 32],
        key_candidate: key24.to_string(),
        iv_hex: None,
        hint: None,
    };
    let result = sm4_assist(&reg, &input, &ExecutionContext::new());
    assert!(
        result.is_err(),
        "a 24-byte decoding is not an accepted SM4 key length: nothing may be attempted"
    );
}

#[test]
fn wrong_iv_length_pruned_not_attempted_sm4() {
    let reg = registry();
    let plaintext = b"wrong length ivs must be pruned before any decryption is attempted!!";
    let ct = block_encrypt(
        &reg,
        "sm4-encrypt",
        plaintext,
        SM4_KEY,
        "cbc",
        IV16,
        "pkcs7",
    );

    // A 4-byte explicit IV is structurally impossible for SM4 CBC (needs 16).
    let cands = generate_profile_candidates(&Sm4Profile, SM4_KEY, Some(vec![0xab; 4]), &ct);
    assert!(
        cands.iter().all(|c| c.iv.len() != 4),
        "the wrong-length explicit IV must never reach a candidate"
    );
    assert!(cands.iter().all(|c| !c.mode.uses_iv() || c.iv.len() == 16));

    let input = AssistInput {
        ciphertext: ct,
        key_candidate: SM4_KEY.to_string(),
        iv_hex: Some("0f0e0d0c".to_string()),
        hint: None,
    };
    let result = sm4_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    assert!(
        result
            .hits
            .iter()
            .all(|h| h.iv_hex.is_empty() || h.iv_hex.len() == 32),
        "no candidate may run with the 4-byte IV"
    );
}

#[test]
fn des_wrong_iv_length_pruned() {
    let ct = vec![0x33u8; 24]; // aligned for the 8-byte DES block
    let cands = generate_profile_candidates(&DesProfile, DES_KEY, Some(vec![0u8; 16]), &ct);
    assert!(
        cands.iter().all(|c| !c.mode.uses_iv() || c.iv.len() == 8),
        "every DES IV-mode candidate must carry exactly one 8-byte block, not the 16-byte input"
    );
    assert!(cands.iter().all(|c| c.iv.len() != 16));
}

#[test]
fn unaligned_ciphertext_prunes_block_modes_serpent() {
    let cands = generate_profile_candidates(
        &SerpentProfile,
        "00112233445566778899aabbccddeeff",
        None,
        &[0x42u8; 30],
    );
    assert!(!cands.is_empty());
    assert!(
        cands
            .iter()
            .all(|c| c.mode == Mode::Ctr || c.mode == Mode::Cfb || c.mode == Mode::Ofb),
        "unaligned input must leave only streaming modes, got {:?}",
        cands.iter().map(|c| c.mode).collect::<Vec<_>>()
    );
}

#[test]
fn twofish_wrong_key_length_zero_candidates() {
    let reg = registry();
    let input = AssistInput {
        ciphertext: vec![0x11u8; 32],
        key_candidate: "deadbeef".to_string(),
        iv_hex: None,
        hint: None,
    };
    let result = twofish_assist(&reg, &input, &ExecutionContext::new());
    assert!(
        result.is_err(),
        "8 bytes is not an accepted Twofish key length"
    );
}

#[test]
fn rc4_key_length_bounds() {
    // Below the 5-byte floor: no interpretation decodes into range.
    assert!(generate_profile_candidates(&Rc4Profile, "abc", None, &[0u8; 8]).is_empty());
    // Above the 32-byte ceiling: same.
    let long_key = "a".repeat(33);
    assert!(generate_profile_candidates(&Rc4Profile, &long_key, None, &[0u8; 8]).is_empty());
    // At the floor (5 bytes): hex decoding is accepted.
    let floor = generate_profile_candidates(&Rc4Profile, "a1b2c3d4e5", None, &[0u8; 8]);
    assert!(floor.iter().any(|c| c.key.len() == 5));
    // At the ceiling (32 bytes): hex decoding is accepted.
    let ceiling = generate_profile_candidates(&Rc4Profile, &hex_str(&[0x5a; 32]), None, &[0u8; 8]);
    assert_eq!(ceiling.len(), 1);
    assert_eq!(ceiling[0].key.len(), 32);

    // The engine surfaces the bound honestly.
    let reg = registry();
    let input = AssistInput {
        ciphertext: vec![0x11u8; 8],
        key_candidate: "abc".to_string(),
        iv_hex: None,
        hint: None,
    };
    assert!(rc4_assist(&reg, &input, &ExecutionContext::new()).is_err());
}

#[test]
fn wrong_key_scores_low_sm4() {
    let reg = registry();
    let plaintext = b"the flag is flag{sm4_secret} but the assist gets the wrong key here";
    let ct = block_encrypt(
        &reg,
        "sm4-encrypt",
        plaintext,
        SM4_KEY,
        "cbc",
        IV16,
        "pkcs7",
    );
    let input = AssistInput {
        ciphertext: ct,
        key_candidate: "00112233445566778899aabbccddeeff".to_string(),
        iv_hex: Some(IV16.to_string()),
        hint: None,
    };
    let result = sm4_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    assert!(result.candidates_tried > 0);
    assert!(
        result.hits.iter().all(|h| !h.confident),
        "a wrong key must never produce a confident candidate: {:?}",
        result
            .hits
            .iter()
            .map(|h| (h.rank, h.score))
            .collect::<Vec<_>>()
    );
}

// ------------------------------------------------ bounded candidate counts ----

#[test]
fn sm4_candidate_count_bounded() {
    let reg = registry();
    let plaintext = b"a fixed plaintext used for the bounded candidate count check";
    let ct = block_encrypt(
        &reg,
        "sm4-encrypt",
        plaintext,
        SM4_KEY,
        "cbc",
        IV16,
        "pkcs7",
    );
    assert_eq!(ct.len() % 16, 0);

    // One key (hex; the 32-char ASCII decoding is not 16 bytes) crossed with
    // ECB(2 paddings) + CBC(2 paddings x 4 IV sources) + CTR/CFB/OFB(2 sources
    // each) = 16 — structurally bounded, no Cartesian explosion.
    let cands = generate_profile_candidates(&Sm4Profile, SM4_KEY, Some(hex_bytes(IV16)), &ct);
    assert_eq!(cands.len(), 16);

    let input = AssistInput {
        ciphertext: ct,
        key_candidate: SM4_KEY.to_string(),
        iv_hex: Some(IV16.to_string()),
        hint: None,
    };
    let result = sm4_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    assert_eq!(result.candidates_tried, 16);
    assert_eq!(result.candidates_pruned, 0);
}

#[test]
fn rc4_candidate_count_small() {
    let reg = registry();
    // "deadbeef1234" decodes both as hex (6 bytes) and as 12 ASCII bytes —
    // and RC4 has exactly one (stream) configuration per key.
    let cands = generate_profile_candidates(&Rc4Profile, "deadbeef1234", None, &[0u8; 8]);
    assert_eq!(cands.len(), 2);

    let input = AssistInput {
        ciphertext: {
            // Deterministic pseudo-random bytes: both decodings are wrong keys
            // for this data, so neither may look plausible.
            let mut lcg = 0xC0FFEEu64;
            (0..16)
                .map(|_| {
                    lcg = lcg
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    (lcg >> 33) as u8
                })
                .collect()
        },
        key_candidate: "deadbeef1234".to_string(),
        iv_hex: None,
        hint: None,
    };
    let result = rc4_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    assert_eq!(result.candidates_tried, 2);
    assert_eq!(result.hits.len(), 2);
}

// ------------------------------------------------------ recipe replays ----

#[test]
fn recipe_replay_sm4_cbc() {
    let reg = registry();
    let plaintext = b"deterministic sm4 recipe reproduction check.";
    let ct = block_encrypt(
        &reg,
        "sm4-encrypt",
        plaintext,
        SM4_KEY,
        "cbc",
        IV16,
        "pkcs7",
    );

    let cands = generate_profile_candidates(&Sm4Profile, SM4_KEY, Some(hex_bytes(IV16)), &ct);
    let cand = cands
        .iter()
        .find(|c| {
            c.mode == Mode::Cbc && c.iv_source == IvSource::Explicit && c.key == hex_bytes(SM4_KEY)
        })
        .unwrap()
        .clone();
    let ops = recipe_ops_for_profile(&Sm4Profile, &cand, &hex_bytes(IV16));
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].0, "sm4-decrypt");

    let op = reg.get("sm4-decrypt").unwrap();
    match op
        .execute(&Value::Bytes(ct), &ops[0].1, &ExecutionContext::new())
        .unwrap()
    {
        Value::Bytes(b) => assert_eq!(b, plaintext.to_vec()),
        other => panic!("unexpected replay output {other:?}"),
    }
}

#[test]
fn recipe_replay_rc4() {
    let reg = registry();
    let key_hex = "7365637265746b657931";
    let plaintext = b"the rc4 recipe must replay byte for byte";
    let ct = rc4_encrypt(&reg, key_hex, plaintext);

    let cands = generate_profile_candidates(&Rc4Profile, key_hex, None, &ct);
    let cand = cands
        .iter()
        .find(|c| c.key_interpretation == KeyInterpretation::Hex)
        .unwrap()
        .clone();
    let ops = recipe_ops_for_profile(&Rc4Profile, &cand, &[]);
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].0, "rc4");

    let op = reg.get("rc4").unwrap();
    match op
        .execute(&Value::Bytes(ct), &ops[0].1, &ExecutionContext::new())
        .unwrap()
    {
        Value::Bytes(b) => assert_eq!(b, plaintext.to_vec()),
        other => panic!("unexpected replay output {other:?}"),
    }
}

#[test]
fn recipe_replay_des_ecb() {
    let reg = registry();
    let plaintext = b"eight byte blocks all the way down and then some!!";
    let ct = block_encrypt(&reg, "des-encrypt", plaintext, DES_KEY, "ecb", "", "pkcs7");

    let cands = generate_profile_candidates(&DesProfile, DES_KEY, None, &ct);
    let cand = cands.iter().find(|c| c.mode == Mode::Ecb).unwrap().clone();
    let ops = recipe_ops_for_profile(&DesProfile, &cand, &[]);
    assert_eq!(ops[0].0, "des-decrypt");

    let op = reg.get("des-decrypt").unwrap();
    match op
        .execute(&Value::Bytes(ct), &ops[0].1, &ExecutionContext::new())
        .unwrap()
    {
        Value::Bytes(b) => assert_eq!(b, plaintext.to_vec()),
        other => panic!("unexpected replay output {other:?}"),
    }
}

// ---------------------------------------------------------- fallbacks ----

#[test]
fn sm4_zero_iv_fallback_still_found() {
    let reg = registry();
    let plaintext = b"the remainder of this sentence stays readable even when the leading block is scrambled flag{zero_iv_sm4}";
    let zero_iv = "00000000000000000000000000000000";
    let ct = block_encrypt(
        &reg,
        "sm4-encrypt",
        plaintext,
        SM4_KEY,
        "cbc",
        zero_iv,
        "pkcs7",
    );

    let input = AssistInput {
        ciphertext: ct,
        key_candidate: SM4_KEY.to_string(),
        iv_hex: None,
        hint: None,
    };
    let result = sm4_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    let zero_hit = result
        .hits
        .iter()
        .find(|h| h.iv_source == IvSource::Zero)
        .expect("zero-IV fallback must be generated");
    assert!(zero_hit.preview.contains("flag{zero_iv_sm4}"));
    assert!(zero_hit.iv_hex == "0".repeat(32));
}

#[test]
fn twofish_cbc_last_block_carve() {
    let reg = registry();
    let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let plaintext = b"twofish cbc with the iv appended after the ciphertext body still yields flag{twofish_last} here";
    let ct = block_encrypt(
        &reg,
        "twofish-encrypt",
        plaintext,
        key,
        "cbc",
        IV16,
        "pkcs7",
    );
    // Layout: body || IV (the IV trails the ciphertext).
    let mut payload = ct.clone();
    payload.extend_from_slice(&hex_bytes(IV16));

    let input = AssistInput {
        ciphertext: payload,
        key_candidate: key.to_string(),
        iv_hex: None,
        hint: None,
    };
    let result = twofish_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    let last = result
        .hits
        .iter()
        .find(|h| h.iv_source == IvSource::LastBlock)
        .expect("last-block carve must be generated");
    assert!(last.confident, "score {}", last.score);
    assert!(last.preview.contains("flag{twofish_last}"));
}

// --------------------------------------------------- profile metadata ----

#[test]
fn profiles_declare_structural_rules() {
    assert_eq!(Sm4Profile.key_lengths(), &[16]);
    assert_eq!(Sm4Profile.block_size(), 16);
    assert_eq!(Sm4Profile.op_id(), "sm4-decrypt");
    assert_eq!(Sm4Profile.key_len_desc(), "16 bytes");
    assert!(!Sm4Profile.key_len_ok(24));

    assert_eq!(DesProfile.key_lengths(), &[8]);
    assert_eq!(DesProfile.block_size(), 8);
    assert_eq!(DesProfile.key_len_desc(), "8 bytes");

    assert_eq!(TdesProfile.key_lengths(), &[16, 24]);
    assert_eq!(TdesProfile.block_size(), 8);
    assert_eq!(TdesProfile.op_id(), "des-decrypt");
    assert_eq!(TdesProfile.key_len_desc(), "16/24 bytes");

    for profile in [
        &SerpentProfile as &dyn AssistProfile,
        &TwofishProfile as &dyn AssistProfile,
        &CamelliaProfile as &dyn AssistProfile,
    ] {
        assert_eq!(profile.key_lengths(), &[16, 24, 32]);
        assert_eq!(profile.block_size(), 16);
        assert!(profile.key_len_ok(16) && profile.key_len_ok(24) && profile.key_len_ok(32));
        assert!(!profile.key_len_ok(8));
    }

    assert_eq!(Rc4Profile.op_id(), "rc4");
    assert_eq!(Rc4Profile.key_len_desc(), "5-32 bytes");
    assert!(Rc4Profile.key_len_ok(5) && Rc4Profile.key_len_ok(32));
    assert!(!Rc4Profile.key_len_ok(4) && !Rc4Profile.key_len_ok(33));
    assert_eq!(Rc4Profile.modes(), &[Mode::Stream]);

    // Block profiles expose exactly the five block modes; the stream variant
    // is reserved for RC4.
    for mode in Sm4Profile.modes() {
        assert!(*mode != Mode::Stream);
    }
    assert_eq!(Sm4Profile.modes().len(), 5);
}

/// The non-AES profiles accept hex and raw ASCII only — a Base64 key string
/// is never silently guessed (explicit interpretations, per the profile).
#[test]
fn base64_interpretation_not_guessed_for_new_profiles() {
    let reg = registry();
    // Base64 of the 16 ASCII bytes "SixteenByteKey!!" — a valid AES key
    // under the Base64 reading, but neither the hex nor the raw-ASCII
    // reading of the string is a valid SM4 key.
    let key_b64 = "U2l4dGVlbkJ5dGVLZXkhIQ";
    let input = AssistInput {
        ciphertext: vec![0x11u8; 32],
        key_candidate: key_b64.to_string(),
        iv_hex: None,
        hint: None,
    };
    let result = sm4_assist(&reg, &input, &ExecutionContext::new());
    assert!(result.is_err(), "base64 must not be guessed for SM4 keys");
    // ...while AES (which declares every interpretation) still finds it.
    let aes_input = AssistInput {
        ciphertext: vec![0x11u8; 32],
        key_candidate: key_b64.to_string(),
        iv_hex: None,
        hint: None,
    };
    let aes =
        cybercipher_attack::assist::aes_assist(&reg, &aes_input, &ExecutionContext::new()).unwrap();
    assert!(aes
        .hits
        .iter()
        .any(|h| h.key_interpretation == KeyInterpretation::Base64 && h.key_length == 16));
}
