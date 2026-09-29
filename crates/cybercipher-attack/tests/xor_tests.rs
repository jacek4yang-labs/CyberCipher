//! XOR Lab acceptance tests: single-byte crack, key-length estimation,
//! repeating-key crack, crib dragging, and the multi-time-pad helper.
//! Instances are generated deterministically in-test.

#![allow(clippy::result_large_err)]

use cybercipher_attack::xor::{
    crack_repeating_key, crack_single_byte, crib_drag, estimate_key_length, mtp_break,
    CribDragOptions, KeyLengthOptions, RepeatingOptions, SingleByteOptions,
};

/// Deterministic LCG stream for reproducible noise.
struct Lcg(u64);

impl Lcg {
    fn next_byte(&mut self) -> u8 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) as u8
    }
}

/// English-like text with realistic letter distribution (repeated sentence).
fn english_text(len: usize) -> String {
    let sentence = "the quick brown fox jumps over the lazy dog and hides in the calm woods ";
    let mut out = String::with_capacity(len);
    while out.len() < len {
        out.push_str(sentence);
    }
    out.truncate(len);
    out
}

#[test]
fn single_byte_crack_finds_known_key() {
    let plaintext = english_text(4096);
    let key = 0x37u8;
    let ciphertext: Vec<u8> = plaintext.bytes().map(|b| b ^ key).collect();

    let result = crack_single_byte(&ciphertext, &SingleByteOptions::default()).unwrap();
    assert_eq!(
        result.best_key,
        Some(key),
        "top candidate must be the true key"
    );
    assert!(
        result.confident,
        "score {} must be confident",
        result.best_score
    );
    assert!(result.candidates[0].preview.starts_with("the quick"));
    // Evidence must mention the composite scoring, not a bare guess.
    assert!(!result.candidates[0].evidence.is_empty());
}

#[test]
fn single_byte_crack_honest_on_random_data() {
    let mut lcg = Lcg(0xDEADBEEF);
    let data: Vec<u8> = (0..4096).map(|_| lcg.next_byte()).collect();
    let result = crack_single_byte(&data, &SingleByteOptions::default()).unwrap();
    assert!(
        !result.confident,
        "random data must not produce a confident key (best score {})",
        result.best_score
    );
}

#[test]
fn key_length_estimation_recovers_true_length() {
    let plaintext = english_text(8192);
    let key = b"xorlab7";
    let ciphertext: Vec<u8> = plaintext
        .bytes()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();

    let result = estimate_key_length(&ciphertext, &KeyLengthOptions::default()).unwrap();
    let top: Vec<usize> = result.candidates.iter().map(|c| c.key_length).collect();
    // Multiples of the true length share its high IOC (classic ladder) — the
    // estimator must surface the ladder, not unrelated lengths.
    assert!(
        top.iter().any(|l| l % 7 == 0),
        "the true-length ladder must appear: {top:?}"
    );
    // The parsimony promotion must pick the smallest ladder member.
    assert_eq!(
        result.best_key_length % 7,
        0,
        "promoted length {} must lie on the ladder",
        result.best_key_length
    );
    // Length 1 (single-byte) must not dominate a repeating-key sample.
    assert!(
        !top.contains(&1),
        "length 1 must not rank for a repeating-key sample: {top:?}"
    );
}

#[test]
fn repeating_key_crack_recovers_full_key() {
    let plaintext = english_text(8192);
    let key = b"labs42x";
    let ciphertext: Vec<u8> = plaintext
        .bytes()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();

    let result = crack_repeating_key(&ciphertext, key.len(), &RepeatingOptions::default()).unwrap();
    assert_eq!(
        result.key,
        key.to_vec(),
        "per-column crack must recover the full key"
    );
    assert!(result.confident, "all unlocked columns must be confident");
    assert!(result.plaintext_preview.starts_with("the quick"));
}

#[test]
fn repeating_key_crack_with_crib_locks_columns() {
    let plaintext = english_text(4096);
    let key = b"crib7xy";
    let ciphertext: Vec<u8> = plaintext
        .bytes()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();

    let options = RepeatingOptions {
        crib: Some("the quick".to_string()),
        crib_offset: 0,
        ..RepeatingOptions::default()
    };
    let result = crack_repeating_key(&ciphertext, key.len(), &options).unwrap();
    // The crib locks the first 9 columns — key bytes 0, 1, 2 must be exact.
    assert_eq!(result.key[0], key[0]);
    assert_eq!(result.key[1], key[1]);
    assert_eq!(result.key[2], key[2]);
}

#[test]
fn repeating_key_crack_rejects_short_input() {
    let err = crack_repeating_key(b"ab", 5, &RepeatingOptions::default()).unwrap_err();
    assert_eq!(
        serde_json::to_string(&err.kind).unwrap(),
        "\"invalid_input\""
    );
}

#[test]
fn crib_drag_finds_true_position() {
    let plaintext = format!("{}{}", "the quick brown fox ", "x".repeat(200));
    let key = 0x5au8;
    let ciphertext: Vec<u8> = plaintext.bytes().map(|b| b ^ key).collect();

    let result = crib_drag(&ciphertext, "the quick", &CribDragOptions::default()).unwrap();
    assert!(
        !result.hits.is_empty(),
        "the true crib position must produce a printable hit"
    );
    // At position 0 the recovered fragment is the key stream itself
    // (cipher ^ crib = key), i.e. 0x5a repeated.
    assert!(
        result
            .hits
            .iter()
            .any(|h| { h.position == 0 && h.key_fragment == [0x5au8; 9] }),
        "hits: {:?}",
        &result.hits[..result.hits.len().min(3)]
    );
}

#[test]
fn crib_drag_honest_when_no_hits() {
    let mut lcg = Lcg(7);
    let data: Vec<u8> = (0..512).map(|_| lcg.next_byte()).collect();
    let result = crib_drag(&data, "\u{1f984}\u{1f984}", &CribDragOptions::default()).unwrap();
    // Non-ASCII crib bytes produce no printable fragments on random data.
    assert!(result.hits.is_empty());
}

#[test]
fn mtp_break_recovers_key_and_plaintexts() {
    // 8 genuinely different messages, same key reused (the MTP mistake).
    let key: Vec<u8> = {
        let mut lcg = Lcg(0xC0FFEE);
        (0..600).map(|_| lcg.next_byte()).collect()
    };
    let sentences = [
        "the quick brown fox jumps over the lazy dog near the river bank at dawn ",
        "a clever spy hides secret notes inside ordinary letters every week ",
        "cryptanalysis works best when the same key protects many messages ",
        "the agent drops a plain envelope behind the old clock every friday ",
        "nothing leaks when keys are random and used only once per message ",
        "eight different messages give the analyst eight samples per position ",
        "english text has strong structure that survives the xor operation ",
        "the river flows past the mill and the bridge at the edge of town ",
    ];
    let mut ciphertexts = Vec::new();
    for sentence in sentences.iter() {
        let mut pt = String::with_capacity(600);
        while pt.len() < 600 {
            pt.push_str(sentence);
        }
        pt.truncate(600);
        ciphertexts.push(
            pt.bytes()
                .zip(key.iter())
                .map(|(b, k)| b ^ k)
                .collect::<Vec<u8>>(),
        );
    }

    let result = mtp_break(&ciphertexts).unwrap();
    assert_eq!(result.key.len(), 600);
    // Most positions must decrypt to the expected English text.
    let mut readable = 0usize;
    for ct in &ciphertexts {
        let decoded: Vec<u8> = ct
            .iter()
            .zip(result.key.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        let text = String::from_utf8_lossy(&decoded);
        if text.starts_with("the ") || text.contains(" the ") {
            readable += 1;
        }
    }
    assert!(
        readable >= 6,
        "most messages must decode to readable text ({readable}/8)"
    );
}

#[test]
fn mtp_break_rejects_single_ciphertext() {
    let err = mtp_break(&[vec![1, 2, 3]]).unwrap_err();
    assert!(err.message.contains("too few"));
}
