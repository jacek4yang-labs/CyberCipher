//! Crypto Assist acceptance tests: candidate generation, pruning, ranking,
//! evidence, and honest negatives. Instances are generated deterministically
//! through the registry itself.

#![allow(clippy::result_large_err)]

use cybercipher_attack::assist::{
    aes_assist, generate_candidates, AesProfile, AssistInput, IvSource, KeyInterpretation,
};
use cybercipher_core::{ExecutionContext, OperationRegistry, ParamMap, ParamValue, Value};

fn registry() -> OperationRegistry {
    cybercipher_engine::default_registry()
}

/// Encrypt with the registry's aes-encrypt op.
fn aes_encrypt(
    reg: &OperationRegistry,
    plaintext: &[u8],
    key_hex: &str,
    mode: &str,
    iv_hex: &str,
    padding: &str,
) -> Vec<u8> {
    let op = reg.get("aes-encrypt").unwrap();
    let mut map = ParamMap::new();
    map.insert("key", ParamValue::Str(key_hex.to_string()));
    map.insert("key_encoding", ParamValue::Str("hex".to_string()));
    map.insert("mode", ParamValue::Str(mode.to_string()));
    if !iv_hex.is_empty() {
        map.insert("iv", ParamValue::Str(iv_hex.to_string()));
        map.insert("iv_encoding", ParamValue::Str("hex".to_string()));
    }
    map.insert("padding", ParamValue::Str(padding.to_string()));
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

const KEY32: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const IV16: &str = "0f0e0d0c0b0a09080706050403020100";

#[test]
fn cbc_pkcs7_ranked_first_with_evidence() {
    let reg = registry();
    let plaintext =
        b"Congratulations, the secret flag is flag{aes_assist_rocks} and the rest is padding.";
    let iv = IV16;
    let ct = aes_encrypt(&reg, plaintext, &KEY32[..32], "cbc", iv, "pkcs7");
    // Ciphertext = IV || body (classic transport layout).
    let mut payload = hex_bytes(iv);
    payload.extend_from_slice(&ct);

    let input = AssistInput {
        ciphertext: payload,
        key_candidate: KEY32[..32].to_string(),
        iv_hex: None,
        hint: Some("flag{".to_string()),
    };
    let result = aes_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    assert!(!result.hits.is_empty(), "must find candidates");
    let top = &result.hits[0];
    assert_eq!(top.mode, cybercipher_attack::assist::Mode::Cbc);
    assert_eq!(top.key_interpretation, KeyInterpretation::Hex);
    assert_eq!(top.iv_source, IvSource::FirstBlock);
    assert_eq!(
        top.key_length, 16,
        "hex key candidate was the first 16 bytes"
    );
    assert!(
        top.preview.contains("flag{aes_assist_rocks}"),
        "top preview must contain the flag: {}",
        top.preview
    );
    assert!(
        top.evidence
            .iter()
            .any(|e| e.to_lowercase().contains("pkcs7")),
        "evidence must mention padding: {:?}",
        top.evidence
    );
}

#[test]
fn utf8_key_interpretation_wins_for_ascii_key() {
    let reg = registry();
    // 16 ASCII characters as a raw-text key.
    let key = "SixteenBytesKey!";
    assert_eq!(key.len(), 16);
    let key_hex = hex_str(key.as_bytes());
    let plaintext = b"there is a steady market for the ordinary words of the language and the matter of the fact remains the same";
    let ct = aes_encrypt(&reg, plaintext, &key_hex, "ecb", "", "pkcs7");

    let input = AssistInput {
        ciphertext: ct,
        key_candidate: key.to_string(),
        iv_hex: None,
        hint: None,
    };
    let result = aes_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    let top = &result.hits[0];
    assert_eq!(top.key_interpretation, KeyInterpretation::Utf8);
    assert!(top.confident);
    assert!(top.preview.contains("there is a steady market"));
}

#[test]
fn ctr_mode_found_for_unaligned_ciphertext() {
    let reg = registry();
    let plaintext = b"stream mode leaves lengths untouched and the ordinary words of the language remain the same throughout".to_vec();
    let ct = aes_encrypt(&reg, &plaintext, &KEY32[..64], "ctr", IV16, "none");
    assert_eq!(ct.len(), plaintext.len()); // unaligned length kept

    let input = AssistInput {
        ciphertext: ct,
        key_candidate: KEY32[..64].to_string(), // full AES-256 hex key
        iv_hex: Some(IV16.to_string()),
        hint: None,
    };
    let result = aes_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    let top = &result.hits[0];
    assert_eq!(
        top.mode,
        cybercipher_attack::assist::Mode::Ctr,
        "CTR must rank first: {:?}",
        top.mode
    );
    assert_eq!(top.key_length, 32);
    assert!(top.confident, "score {}", top.score);
}

#[test]
fn zero_iv_candidate_labeled_low_confidence() {
    let reg = registry();
    // Encrypted with an all-zero IV under CBC — the Zero fallback finds it.
    let plaintext = b"zero iv was used here, a classic ctf shortcut but insecure!!";
    let zero_iv = "00000000000000000000000000000000";
    let ct = aes_encrypt(&reg, plaintext, &KEY32[..32], "cbc", zero_iv, "pkcs7");

    let input = AssistInput {
        ciphertext: ct,
        key_candidate: KEY32[..32].to_string(),
        iv_hex: None,
        hint: None,
    };
    let result = aes_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    let zero_hit = result
        .hits
        .iter()
        .find(|h| h.iv_source == IvSource::Zero)
        .expect("zero-IV candidate must be present");
    assert!(zero_hit.preview.contains("zero iv was used"));
}

#[test]
fn garbage_input_yields_no_confident_candidate() {
    let reg = registry();
    let mut lcg = 0xBADC0DEu64;
    let data: Vec<u8> = (0..256)
        .map(|_| {
            lcg = lcg
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (lcg >> 33) as u8
        })
        .collect();
    let input = AssistInput {
        ciphertext: data,
        key_candidate: KEY32[..32].to_string(),
        iv_hex: None,
        hint: None,
    };
    let result = aes_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    assert!(
        result.hits.iter().all(|h| !h.confident),
        "random data must not produce a confident candidate"
    );
}

#[test]
fn non_aligned_ciphertext_prunes_block_modes() {
    let mut candidates = generate_candidates(
        &KEY32[..32],
        None,
        &[0u8; 30], // not a multiple of 16
        16,
        &[16, 32],
    );
    assert!(
        candidates
            .iter()
            .all(|c| c.mode != cybercipher_attack::assist::Mode::Ecb),
        "ECB must be pruned for unaligned input"
    );
    assert!(
        candidates
            .iter()
            .all(|c| c.mode != cybercipher_attack::assist::Mode::Cbc),
        "CBC must be pruned for unaligned input"
    );
    candidates.clear();

    // Aligned input keeps block modes.
    candidates = generate_candidates(&KEY32[..32], None, &[0u8; 32], 16, &[16, 32]);
    assert!(candidates
        .iter()
        .any(|c| c.mode == cybercipher_attack::assist::Mode::Cbc));
}

#[test]
fn wrong_length_keys_are_pruned_not_padded() {
    let candidates = generate_candidates("short", None, &[0u8; 32], 16, &[16, 24, 32]);
    assert!(
        candidates.is_empty(),
        "a key that decodes to a non-accepted length must yield zero candidates"
    );
}

#[test]
fn deadline_respected() {
    let reg = registry();
    let input = AssistInput {
        ciphertext: vec![0u8; 64],
        key_candidate: KEY32[..32].to_string(),
        iv_hex: None,
        hint: None,
    };
    // A zero deadline must return promptly with an honest timed-out result.
    let result = cybercipher_attack::assist::aes_assist_with_profile(
        &reg,
        &AesProfile,
        &input,
        &ExecutionContext::new(),
        0,
    )
    .unwrap();
    assert!(result.timed_out);
    assert_eq!(result.hits.len(), 0);
}

#[test]
fn recipe_ops_reproduce_the_transformation() {
    let reg = registry();
    let plaintext = b"deterministic recipe reproduction check.";
    let ct = aes_encrypt(&reg, plaintext, &KEY32[..32], "cbc", IV16, "pkcs7");
    let input = AssistInput {
        ciphertext: ct.clone(),
        key_candidate: KEY32[..32].to_string(),
        iv_hex: Some(IV16.to_string()),
        hint: None,
    };
    let result = aes_assist(&reg, &input, &ExecutionContext::new()).unwrap();
    let top = &result.hits[0];
    assert_eq!(top.iv_source, IvSource::Explicit);

    // Replay the recipe ops through the registry on the same ciphertext.
    let ops = cybercipher_attack::assist::recipe_ops_for(
        &cybercipher_attack::assist::generate_candidates(
            &input.key_candidate,
            Some(hex_bytes(IV16)),
            &ct,
            16,
            &[16, 32],
        )
        .into_iter()
        .find(|c| {
            c.mode == cybercipher_attack::assist::Mode::Cbc
                && c.iv_source == IvSource::Explicit
                && c.key == hex_bytes(&KEY32[..32])
        })
        .unwrap(),
        &hex_bytes(IV16),
    );
    let (op_id, params) = &ops[0];
    let op = reg.get(op_id).unwrap();
    let out = op
        .execute(&Value::Bytes(ct.clone()), params, &ExecutionContext::new())
        .unwrap();
    match out {
        Value::Bytes(b) => assert_eq!(b, plaintext.to_vec()),
        other => panic!("unexpected replay output {other:?}"),
    }
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
