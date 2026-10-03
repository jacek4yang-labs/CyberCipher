//! Keyed Auto Decode tests: user-supplied key/IV/hint hints fold symmetric
//! decryption into the beam. Fixtures are built through the real registry
//! cipher ops, so every test exercises exactly the ops the beam must drive.

#![allow(clippy::result_large_err)]

use cybercipher_core::{ExecutionContext, OperationRegistry, ParamMap, Value};
use cybercipher_engine::{
    auto_decode, default_registry, AutoHints, RecipeEngine, RecipeNodeV1, RecipeV1, RunMode,
};

const KEYED_OPS: &[&str] = &["aes-decrypt", "des-decrypt", "sm4-decrypt"];

fn registry() -> OperationRegistry {
    default_registry()
}

fn ctx() -> ExecutionContext {
    ExecutionContext::new()
}

fn key_hints(key: &[u8], iv: Option<&[u8]>) -> AutoHints {
    AutoHints {
        key: Some(key.to_vec()),
        iv: iv.map(|v| v.to_vec()),
        hint: None,
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn b64_encode(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Encrypt `plain` through a registered cipher op with fixed hex params.
fn encrypt_with(
    reg: &OperationRegistry,
    op_id: &str,
    params: &[(&str, &str)],
    plain: &[u8],
) -> Vec<u8> {
    let op = reg
        .get(op_id)
        .unwrap_or_else(|| panic!("{op_id} must be registered"));
    let mut map = ParamMap::new();
    for (k, v) in params {
        map.insert(*k, *v);
    }
    match op
        .execute(&Value::Bytes(plain.to_vec()), &map, &ctx())
        .expect("fixture encryption must succeed")
    {
        Value::Bytes(b) => b,
        other => panic!("encryption must produce bytes, got {}", other.kind().name()),
    }
}

fn is_keyed_path(path: &[String]) -> bool {
    path.iter().any(|p| KEYED_OPS.contains(&p.as_str()))
}

// ----------------------------------------------------- end-to-end chains ----

#[test]
fn keyed_aes128_cbc_multilayer_chain() {
    let reg = registry();
    let key = [0x42u8; 16];
    let iv = [0x11u8; 16];
    let key_hex = hex_encode(&key);
    let iv_hex = hex_encode(&iv);
    // flag -> AES-128-CBC -> hex -> base64; auto input is the outer layer.
    let ct = encrypt_with(
        &reg,
        "aes-encrypt",
        &[
            ("key", key_hex.as_str()),
            ("key_encoding", "hex"),
            ("mode", "cbc"),
            ("iv", iv_hex.as_str()),
            ("iv_encoding", "hex"),
            ("padding", "pkcs7"),
        ],
        b"flag{keyed_auto_decode}",
    );
    let input = b64_encode(hex_encode(&ct).as_bytes());

    let hints = key_hints(&key, Some(&iv));
    let candidates = auto_decode(&reg, input.as_bytes(), &ctx(), &hints);
    let keyed = candidates
        .iter()
        .find(|c| is_keyed_path(&c.path) && c.preview.contains("flag{keyed_auto_decode}"))
        .expect("keyed chain must be recovered with hints");
    assert_eq!(
        keyed.path,
        vec![
            "from-base64".to_string(),
            "from-hex".to_string(),
            "aes-decrypt".to_string()
        ],
        "{:?}",
        keyed.path
    );
    assert!(keyed.confident, "score {}", keyed.score);
    assert!(keyed
        .evidence
        .iter()
        .any(|e| e.contains("keyed decrypt: AES-128-CBC with user key")));
}

#[test]
fn keyed_aes128_cbc_raw_ciphertext_bounded() {
    let reg = registry();
    let key = [0x24u8; 16];
    let iv = [0xcdu8; 16];
    let ct = encrypt_with(
        &reg,
        "aes-encrypt",
        &[
            ("key", hex_encode(&key).as_str()),
            ("key_encoding", "hex"),
            ("mode", "cbc"),
            ("iv", hex_encode(&iv).as_str()),
            ("iv_encoding", "hex"),
            ("padding", "pkcs7"),
        ],
        b"flag{raw_ciphertext_keyed}",
    );
    assert_eq!(ct.len(), 48, "fixture is 3 aligned blocks");

    let hints = key_hints(&key, Some(&iv));
    let candidates = auto_decode(&reg, &ct, &ctx(), &hints);
    let keyed: Vec<_> = candidates
        .iter()
        .filter(|c| is_keyed_path(&c.path))
        .collect();
    // The plan allows at most 4 candidates for a 16-byte key (cap 8); only
    // AES-128-CBC survives PKCS7 validation on this fixture.
    assert!(keyed.len() <= 8, "keyed candidates must stay bounded");
    assert_eq!(keyed.len(), 1, "{keyed:#?}");
    assert!(keyed[0].path.last().unwrap() == "aes-decrypt");
    assert!(keyed[0]
        .evidence
        .iter()
        .any(|e| e.contains("keyed decrypt: AES-128-CBC with user key")));
    assert!(keyed[0]
        .evidence
        .iter()
        .any(|e| e.contains("PKCS7 padding validated")));
    assert!(keyed[0].preview.contains("flag{raw_ciphertext_keyed}"));
    assert!(keyed[0].confident);
}

#[test]
fn keyed_aes128_ecb_with_key_only() {
    let reg = registry();
    let key = [0x77u8; 16];
    let ct = encrypt_with(
        &reg,
        "aes-encrypt",
        &[
            ("key", hex_encode(&key).as_str()),
            ("key_encoding", "hex"),
            ("mode", "ecb"),
            ("padding", "pkcs7"),
        ],
        b"flag{ecb_mode_keyed}",
    );
    let input = hex_encode(&ct);

    // No IV supplied: ECB still runs, CBC is structurally impossible.
    let hints = key_hints(&key, None);
    let candidates = auto_decode(&reg, input.as_bytes(), &ctx(), &hints);
    let keyed = candidates
        .iter()
        .filter(|c| is_keyed_path(&c.path))
        .collect::<Vec<_>>();
    assert_eq!(keyed.len(), 1, "{keyed:#?}");
    assert_eq!(keyed[0].path, vec!["from-hex", "aes-decrypt"]);
    assert!(keyed[0]
        .evidence
        .iter()
        .any(|e| e.contains("keyed decrypt: AES-128-ECB with user key")));
    assert!(keyed[0].preview.contains("flag{ecb_mode_keyed}"));
    assert!(keyed[0].confident);
}

#[test]
fn keyed_sm4_candidate() {
    let reg = registry();
    let key = [0x5au8; 16];
    let ct = encrypt_with(
        &reg,
        "sm4-encrypt",
        &[
            ("key", hex_encode(&key).as_str()),
            ("key_encoding", "hex"),
            ("mode", "ecb"),
            ("padding", "pkcs7"),
        ],
        b"flag{sm4_keyed_decode}",
    );
    let input = hex_encode(&ct);

    let hints = key_hints(&key, None);
    let candidates = auto_decode(&reg, input.as_bytes(), &ctx(), &hints);
    let keyed: Vec<_> = candidates
        .iter()
        .filter(|c| is_keyed_path(&c.path))
        .collect();
    assert_eq!(keyed.len(), 1, "{keyed:#?}");
    assert!(keyed[0].path.last().unwrap() == "sm4-decrypt");
    assert!(keyed[0]
        .evidence
        .iter()
        .any(|e| e.contains("keyed decrypt: SM4-ECB with user key")));
    assert!(keyed[0].preview.contains("flag{sm4_keyed_decode}"));
    assert!(keyed[0].confident);
}

#[test]
fn keyed_3des_candidate() {
    let reg = registry();
    let key = [0x3du8; 24];
    let ct = encrypt_with(
        &reg,
        "des-encrypt",
        &[
            ("key", hex_encode(&key).as_str()),
            ("key_encoding", "hex"),
            ("mode", "ecb"),
            ("padding", "pkcs7"),
        ],
        b"flag{triple_des_keyed_decode}",
    );
    let input = hex_encode(&ct);

    let hints = key_hints(&key, None);
    let candidates = auto_decode(&reg, input.as_bytes(), &ctx(), &hints);
    let keyed = candidates
        .iter()
        .find(|c| c.path.last().map(|p| p == "des-decrypt").unwrap_or(false))
        .expect("3DES keyed candidate must be recovered");
    assert!(keyed
        .evidence
        .iter()
        .any(|e| e.contains("keyed decrypt: 3DES-ECB with user key")));
    assert!(keyed.preview.contains("flag{triple_des_keyed_decode}"));
    assert!(keyed.confident);
    // AES-192 was structurally attempted (32-byte ct is block-aligned) but
    // must not have produced a candidate on 3DES ciphertext.
    assert!(!candidates
        .iter()
        .any(|c| c.path.last().unwrap() == "aes-decrypt"));
}

#[test]
fn keyed_3des_cbc_with_block_size_iv() {
    let reg = registry();
    let key = [0x9eu8; 24];
    let iv = [0x22u8; 8];
    let ct = encrypt_with(
        &reg,
        "des-encrypt",
        &[
            ("key", hex_encode(&key).as_str()),
            ("key_encoding", "hex"),
            ("mode", "cbc"),
            ("iv", hex_encode(&iv).as_str()),
            ("iv_encoding", "hex"),
            ("padding", "pkcs7"),
        ],
        b"flag{3des_cbc_with_iv}",
    );
    let input = hex_encode(&ct);

    let hints = key_hints(&key, Some(&iv));
    let candidates = auto_decode(&reg, input.as_bytes(), &ctx(), &hints);
    let keyed = candidates
        .iter()
        .find(|c| c.path.last().map(|p| p == "des-decrypt").unwrap_or(false))
        .expect("3DES-CBC keyed candidate must be recovered");
    assert!(keyed
        .evidence
        .iter()
        .any(|e| e.contains("keyed decrypt: 3DES-CBC with user key")));
    assert!(keyed.preview.contains("flag{3des_cbc_with_iv}"));
}

// ---------------------------------------------------- negative / pruning ----

#[test]
fn wrong_key_yields_no_keyed_candidate() {
    let reg = registry();
    let key = [0x42u8; 16];
    let iv = [0x11u8; 16];
    let ct = encrypt_with(
        &reg,
        "aes-encrypt",
        &[
            ("key", hex_encode(&key).as_str()),
            ("key_encoding", "hex"),
            ("mode", "cbc"),
            ("iv", hex_encode(&iv).as_str()),
            ("iv_encoding", "hex"),
            ("padding", "pkcs7"),
        ],
        b"flag{wrong_key_is_pruned}",
    );
    let input = b64_encode(hex_encode(&ct).as_bytes());

    let wrong = [0x99u8; 16];
    let hints = key_hints(&wrong, Some(&iv));
    let candidates = auto_decode(&reg, input.as_bytes(), &ctx(), &hints);
    assert!(
        !candidates.iter().any(|c| is_keyed_path(&c.path)),
        "wrong key must not survive PKCS7 pruning: {candidates:#?}"
    );
    assert!(
        !candidates
            .iter()
            .any(|c| c.preview.contains("flag{wrong_key_is_pruned}")),
        "the flag must not appear without the right key"
    );
}

#[test]
fn wrong_iv_yields_no_keyed_candidate() {
    let reg = registry();
    let key = [0x11u8; 16];
    let iv = [0xa1u8; 16];
    let ct = encrypt_with(
        &reg,
        "aes-encrypt",
        &[
            ("key", hex_encode(&key).as_str()),
            ("key_encoding", "hex"),
            ("mode", "cbc"),
            ("iv", hex_encode(&iv).as_str()),
            ("iv_encoding", "hex"),
            ("padding", "pkcs7"),
        ],
        b"flag{wrong_iv_is_pruned}",
    );
    let input = hex_encode(&ct);

    let wrong_iv = [0xffu8; 16];
    let hints = key_hints(&key, Some(&wrong_iv));
    let candidates = auto_decode(&reg, input.as_bytes(), &ctx(), &hints);
    assert!(
        !candidates.iter().any(|c| is_keyed_path(&c.path)),
        "wrong IV must not survive PKCS7 pruning: {candidates:#?}"
    );
}

#[test]
fn no_hints_keyed_steps_never_fire() {
    let reg = registry();
    let key = [0x42u8; 16];
    let iv = [0x11u8; 16];
    let ct = encrypt_with(
        &reg,
        "aes-encrypt",
        &[
            ("key", hex_encode(&key).as_str()),
            ("key_encoding", "hex"),
            ("mode", "cbc"),
            ("iv", hex_encode(&iv).as_str()),
            ("iv_encoding", "hex"),
            ("padding", "pkcs7"),
        ],
        b"flag{no_hints_no_keyed}",
    );
    let input = b64_encode(hex_encode(&ct).as_bytes());

    let candidates = auto_decode(&reg, input.as_bytes(), &ctx(), &AutoHints::default());
    assert!(
        !candidates.iter().any(|c| is_keyed_path(&c.path)),
        "without hints the beam must stay hintless: {candidates:#?}"
    );
}

#[test]
fn malformed_key_length_skips_keyed_candidates() {
    let reg = registry();
    let key = [0x42u8; 16];
    let iv = [0x11u8; 16];
    let ct = encrypt_with(
        &reg,
        "aes-encrypt",
        &[
            ("key", hex_encode(&key).as_str()),
            ("key_encoding", "hex"),
            ("mode", "cbc"),
            ("iv", hex_encode(&iv).as_str()),
            ("iv_encoding", "hex"),
            ("padding", "pkcs7"),
        ],
        b"flag{malformed_key_length}",
    );
    let input = b64_encode(hex_encode(&ct).as_bytes());

    // 10 bytes admits no planned algorithm: no panic, no keyed candidates.
    let hints = key_hints(&[7u8; 10], Some(&iv));
    let candidates = auto_decode(&reg, input.as_bytes(), &ctx(), &hints);
    assert!(!candidates.iter().any(|c| is_keyed_path(&c.path)));
}

#[test]
fn unaligned_data_skips_all_keyed_candidates() {
    let reg = registry();
    let key = [0x42u8; 16];
    let iv = [0x11u8; 16];
    let ct = encrypt_with(
        &reg,
        "aes-encrypt",
        &[
            ("key", hex_encode(&key).as_str()),
            ("key_encoding", "hex"),
            ("mode", "cbc"),
            ("iv", hex_encode(&iv).as_str()),
            ("iv_encoding", "hex"),
            ("padding", "pkcs7"),
        ],
        b"flag{unaligned_ciphertext_skips}",
    );
    // Drop the tail: 44 bytes is not a multiple of the 16-byte block.
    let unaligned = &ct[..44];
    assert_ne!(unaligned.len() % 16, 0);

    let hints = key_hints(&key, Some(&iv));
    let candidates = auto_decode(&reg, unaligned, &ctx(), &hints);
    assert!(
        !candidates.iter().any(|c| is_keyed_path(&c.path)),
        "unaligned ECB/CBC data must be gated out: {candidates:#?}"
    );
}

#[test]
fn block_size_gate_is_per_cipher() {
    let reg = registry();
    let key = [0x3du8; 24];
    // 50 bytes of plaintext -> 56 bytes of ciphertext: aligned for the 8-byte
    // 3DES block, unaligned for the 16-byte AES block.
    let plain = b"flag{triple_des_block_gate_is_per_cipher_row}";
    let ct = encrypt_with(
        &reg,
        "des-encrypt",
        &[
            ("key", hex_encode(&key).as_str()),
            ("key_encoding", "hex"),
            ("mode", "ecb"),
            ("padding", "pkcs7"),
        ],
        plain,
    );
    assert_eq!(ct.len() % 8, 0);
    assert_ne!(ct.len() % 16, 0);
    let input = hex_encode(&ct);

    let hints = key_hints(&key, None);
    let candidates = auto_decode(&reg, input.as_bytes(), &ctx(), &hints);
    let keyed = candidates
        .iter()
        .find(|c| c.path.last().map(|p| p == "des-decrypt").unwrap_or(false))
        .expect("3DES must fire on its own block alignment");
    assert!(keyed.preview.contains("flag{triple_des_block_gate_is_per_cipher_row}"));
    assert!(
        !candidates.iter().any(|c| c.path.last().unwrap() == "aes-decrypt"),
        "AES rows must be skipped for 16-unaligned data"
    );
}

#[test]
fn cbc_skipped_when_iv_size_does_not_match_block() {
    let reg = registry();
    let key = [0x77u8; 16];
    let ct = encrypt_with(
        &reg,
        "aes-encrypt",
        &[
            ("key", hex_encode(&key).as_str()),
            ("key_encoding", "hex"),
            ("mode", "ecb"),
            ("padding", "pkcs7"),
        ],
        b"flag{iv_size_gate_test}",
    );
    let input = hex_encode(&ct);

    // An 8-byte IV cannot drive a 16-byte-block CBC candidate.
    let hints = key_hints(&key, Some(&[0xaau8; 8]));
    let candidates = auto_decode(&reg, input.as_bytes(), &ctx(), &hints);
    let keyed: Vec<_> = candidates
        .iter()
        .filter(|c| is_keyed_path(&c.path))
        .collect();
    assert_eq!(keyed.len(), 1, "{keyed:#?}");
    assert!(keyed[0]
        .evidence
        .iter()
        .any(|e| e.contains("AES-128-ECB with user key")));
    assert!(
        !keyed[0].evidence.iter().any(|e| e.contains("CBC")),
        "CBC must be structurally skipped with a mismatched IV"
    );
}

// ---------------------------------------------------------- hint boost ----

#[test]
fn hint_boost_raises_score_and_adds_evidence() {
    let reg = registry();
    let inner = b"the quick brown fox jumps over the lazy dog";
    let input = b64_encode(inner);

    let base = auto_decode(&reg, input.as_bytes(), &ctx(), &AutoHints::default());
    let base = base
        .iter()
        .find(|c| c.path == vec!["from-base64"] && c.preview.contains("lazy dog"))
        .expect("plain base64 candidate must exist");

    // Case-insensitive containment: the hint differs in case from the output.
    let hints = AutoHints {
        hint: Some("Lazy Dog".to_string()),
        ..Default::default()
    };
    let hinted = auto_decode(&reg, input.as_bytes(), &ctx(), &hints);
    let hinted = hinted
        .iter()
        .find(|c| c.path == vec!["from-base64"])
        .expect("hinted run keeps the candidate");
    assert!(
        hinted.score > base.score,
        "{} vs {}",
        hinted.score,
        base.score
    );
    assert!(hinted
        .evidence
        .iter()
        .any(|e| e.contains("hint \"Lazy Dog\" matched")));
    assert!(hinted.confident);
}

#[test]
fn hint_boost_does_not_penalize_non_match() {
    let reg = registry();
    let inner = b"the quick brown fox jumps over the lazy dog";
    let input = b64_encode(inner);

    let base = auto_decode(&reg, input.as_bytes(), &ctx(), &AutoHints::default());
    let hints = AutoHints {
        hint: Some("zebra unicorn".to_string()),
        ..Default::default()
    };
    let hinted = auto_decode(&reg, input.as_bytes(), &ctx(), &hints);
    let base = base
        .iter()
        .find(|c| c.path == vec!["from-base64"])
        .expect("base candidate");
    let hinted = hinted
        .iter()
        .find(|c| c.path == vec!["from-base64"])
        .expect("hinted candidate");
    assert_eq!(
        hinted.score, base.score,
        "non-matching hint must not touch the score"
    );
    assert!(!hinted.evidence.iter().any(|e| e.contains("hint \"")));
}

#[test]
fn hint_lifts_weak_xor_candidate_to_confident() {
    let reg = registry();
    // Mass-search territory: single-byte XOR output has no syntax evidence
    // and stays below confidence on its own.
    let plain = b"needle in the haystack text";
    let xored: Vec<u8> = plain.iter().map(|b| b ^ 0x5a).collect();

    let base = auto_decode(&reg, &xored, &ctx(), &AutoHints::default());
    let base = base
        .iter()
        .find(|c| {
            c.path
                .last()
                .map(|p| p == "xor-single-byte")
                .unwrap_or(false)
        })
        .expect("xor candidate must be collected");
    assert!(
        !base.confident,
        "xor noise must not be confident on its own: {}",
        base.score
    );

    let hints = AutoHints {
        hint: Some("needle".to_string()),
        ..Default::default()
    };
    let hinted = auto_decode(&reg, &xored, &ctx(), &hints);
    let hinted = hinted
        .iter()
        .find(|c| {
            c.path
                .last()
                .map(|p| p == "xor-single-byte")
                .unwrap_or(false)
                && c.preview.contains("needle")
        })
        .expect("hinted xor candidate");
    assert!(
        hinted.confident,
        "hint must lift the match: {}",
        hinted.score
    );
    assert!(hinted
        .evidence
        .iter()
        .any(|e| e.contains("hint \"needle\" matched")));
}

// ------------------------------------------------------- recipe replay ----

#[test]
fn keyed_candidate_replays_as_recipe() {
    let reg = registry();
    let key = [0x42u8; 16];
    let iv = [0x11u8; 16];
    let key_hex = hex_encode(&key);
    let iv_hex = hex_encode(&iv);
    let ct = encrypt_with(
        &reg,
        "aes-encrypt",
        &[
            ("key", key_hex.as_str()),
            ("key_encoding", "hex"),
            ("mode", "cbc"),
            ("iv", iv_hex.as_str()),
            ("iv_encoding", "hex"),
            ("padding", "pkcs7"),
        ],
        b"flag{keyed_recipe_replay}",
    );
    let input = b64_encode(hex_encode(&ct).as_bytes());

    let hints = key_hints(&key, Some(&iv));
    let candidates = auto_decode(&reg, input.as_bytes(), &ctx(), &hints);
    let keyed = candidates
        .iter()
        .find(|c| is_keyed_path(&c.path) && c.preview.contains("flag{keyed_recipe_replay}"))
        .expect("keyed candidate");

    // "Apply as recipe": path ops + per-step parameter overrides must replay
    // the decode exactly through the public recipe engine.
    let nodes: Vec<RecipeNodeV1> = keyed
        .path
        .iter()
        .enumerate()
        .map(|(i, op)| RecipeNodeV1 {
            id: format!("n{i}"),
            op: op.clone(),
            enabled: true,
            params: keyed
                .step_params
                .get(i)
                .map(params_from_step_json)
                .unwrap_or_default(),
        })
        .collect();
    let recipe = RecipeV1::new(nodes);
    recipe.validate(&reg).expect("keyed recipe must validate");
    let engine = RecipeEngine::new(std::sync::Arc::new(reg));
    let report = engine
        .execute(
            &recipe,
            Value::Bytes(input.as_bytes().to_vec()),
            RunMode::Manual,
            &ctx(),
        )
        .expect("recipe executes");
    assert!(report.error.is_none(), "{:?}", report.error);
    assert_eq!(
        report.output.unwrap(),
        Value::Bytes(b"flag{keyed_recipe_replay}".to_vec()),
        "recipe reconstruction must replay the keyed decode"
    );
}

/// Convert a step_params JSON object (strings/bools/ints) into a ParamMap.
fn params_from_step_json(value: &serde_json::Value) -> ParamMap {
    let mut map = ParamMap::new();
    if let serde_json::Value::Object(obj) = value {
        for (k, v) in obj {
            match v {
                serde_json::Value::String(s) => map.insert(k.clone(), s.clone()),
                serde_json::Value::Bool(b) => map.insert(k.clone(), *b),
                serde_json::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        map.insert(k.clone(), i);
                    }
                }
                _ => {}
            }
        }
    }
    map
}
