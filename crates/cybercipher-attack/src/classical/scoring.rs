//! English-language scoring for the classical cracking layer.
//!
//! This is the text-oriented sibling of the XOR lab's `scoring` module: the
//! XOR scorer must grade arbitrary bytes, so it mixes in printable/UTF-8
//! signals. Classical cipher candidates are always pure text, so this scorer
//! works on `&str` and combines exactly two honest signals:
//!
//! 1. **English letter fit** — chi-square goodness of fit of the observed
//!    letter distribution against a compact hardcoded English letter-frequency
//!    table ([`ENGLISH_LETTER_FREQ_PCT`]), computed over letters only, mapped
//!    through `exp(-chi²/letters)` so 1.0 is a perfect fit.
//! 2. **Common-bigram coverage** — the fraction of adjacent letter pairs that
//!    appear in [`COMMON_BIGRAMS`], the twenty most frequent English bigrams.
//!    Cheap bigram-ish heuristic (per M6 design: no quadgram tables — too
//!    large for a std-only crate), but it separates real words from
//!    frequency-plausible gibberish far better than the unigram fit alone.
//!
//! The composite [`text_score`] is `0.72 * letter_fit + 0.28 * bigram_fit`
//! plus a CTF flag-token bonus when one is present. Every component stays
//! individually reportable so a UI can show *why* a candidate ranked where it
//! did.
//!
//! The frequency table is the widely reproduced table from Robert Edward
//! Lewand, *Cryptological Mathematics* (2000) — the same values tabulated on
//! Wikipedia's "Letter frequency" page. A unit test pins the copy to the XOR
//! lab's table so the two cannot silently diverge.

use crate::xor::scoring::{find_flag_pattern, FLAG_BONUS};
use serde::{Deserialize, Serialize};

/// Standard English letter frequencies in percent, `a`..=`z` (Lewand,
/// *Cryptological Mathematics*, 2000; sums to ~99.99%). Copied from the XOR
/// lab's `scoring` module (same table, text-oriented scorer); a test asserts
/// the two stay in sync.
pub const ENGLISH_LETTER_FREQ_PCT: [f64; 26] = [
    8.167,  // a
    1.492,  // b
    2.782,  // c
    4.253,  // d
    12.702, // e
    2.228,  // f
    2.015,  // g
    6.094,  // h
    6.966,  // i
    0.153,  // j
    0.772,  // k
    4.025,  // l
    2.406,  // m
    6.749,  // n
    7.507,  // o
    1.929,  // p
    0.095,  // q
    5.987,  // r
    6.327,  // s
    9.056,  // t
    2.758,  // u
    0.978,  // v
    2.360,  // w
    0.150,  // x
    1.974,  // y
    0.074,  // z
];

/// English letters ordered by descending frequency — the target order for the
/// substitution frequency-mapping hint.
pub const ENGLISH_LETTER_ORDER: &str = "ETAOINSHRDLCUMWFGYPBVKJXQZ";

/// The twenty most frequent English bigrams (lowercase). Used by
/// [`bigram_fit`] as the cheap bigram-ish heuristic — deliberately *not* a
/// full quadgram table (too large for a std-only crate; documented M6 scope).
pub const COMMON_BIGRAMS: [&str; 20] = [
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es", "or", "te", "of", "ed",
    "is", "it", "al", "ar",
];

/// Qualitative confidence label for a composite text score. Mirrors the XOR
/// lab's thresholds: `score >= 0.80` → High, `>= 0.60` → Medium, else Low.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextConfidence {
    High,
    Medium,
    Low,
}

impl TextConfidence {
    /// Map a composite [`text_score`] to its qualitative label.
    pub fn from_score(score: f64) -> Self {
        if score >= 0.80 {
            TextConfidence::High
        } else if score >= 0.60 {
            TextConfidence::Medium
        } else {
            TextConfidence::Low
        }
    }
}

/// Counts of each letter `a`..=`z` (case-folded, ASCII only) in `text`, plus
/// the total letter count.
pub fn letter_counts(text: &str) -> ([u64; 26], usize) {
    let mut counts = [0u64; 26];
    let mut total = 0usize;
    for ch in text.chars() {
        if ch.is_ascii_lowercase() {
            counts[(ch as u8 - b'a') as usize] += 1;
            total += 1;
        } else if ch.is_ascii_uppercase() {
            counts[(ch as u8 - b'A') as usize] += 1;
            total += 1;
        }
    }
    (counts, total)
}

/// Chi-square goodness of fit of the observed letter distribution against the
/// English table, over letters only. Returns `None` when the text contains no
/// ASCII letters (there is nothing to fit).
pub fn chi_square_english(text: &str) -> Option<f64> {
    let (counts, total) = letter_counts(text);
    if total == 0 {
        return None;
    }
    let n = total as f64;
    let mut chi = 0.0;
    for (i, &observed) in counts.iter().enumerate() {
        let expected = n * ENGLISH_LETTER_FREQ_PCT[i] / 100.0;
        let diff = observed as f64 - expected;
        chi += diff * diff / expected;
    }
    Some(chi)
}

/// English letter fit in `0.0..=1.0`: `exp(-chi²/letters)` over letters only.
/// Returns 0.0 when the text contains fewer than 3 letters (the statistic is
/// meaningless on such samples).
pub fn english_fit(text: &str) -> f64 {
    match chi_square_english(text) {
        None => 0.0,
        Some(chi) => {
            let (_, total) = letter_counts(text);
            if total < 3 {
                return 0.0;
            }
            (-chi / total as f64).exp()
        }
    }
}

/// Common-bigram coverage in `0.0..=1.0`: the fraction of adjacent letter
/// pairs (computed over letters only, case-folded) that appear in
/// [`COMMON_BIGRAMS`]. Returns 0.0 for texts with fewer than 2 letters.
pub fn bigram_fit(text: &str) -> f64 {
    let letters: Vec<u8> = text
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_lowercase() as u8)
        .collect();
    if letters.len() < 2 {
        return 0.0;
    }
    let mut hits = 0usize;
    for pair in letters.windows(2) {
        if COMMON_BIGRAMS
            .iter()
            .any(|b| b.as_bytes() == [pair[0], pair[1]])
        {
            hits += 1;
        }
    }
    hits as f64 / (letters.len() - 1) as f64
}

/// Composite text score in `0.0..=1.45`:
/// `0.72 * english_fit + 0.28 * bigram_fit + flag_bonus`. The flag bonus
/// (reused from the XOR lab) adds a decisive, human-verifiable signal when a
/// known flag-like token (`flag{`, `ctf{`, ...) appears in the candidate.
pub fn text_score(text: &str) -> f64 {
    let fit = english_fit(text);
    let bigram = bigram_fit(text);
    let flag = if find_flag_pattern(text.as_bytes()).is_some() {
        FLAG_BONUS
    } else {
        0.0
    };
    0.72 * fit + 0.28 * bigram + flag
}

/// Index of coincidence over the letters of `text`:
/// `sum(n_i * (n_i - 1)) / (n * (n - 1))`. For English monoalphabetic text
/// this is ~0.0667; for uniformly random letters ~0.0385. Returns `None` when
/// the text has fewer than 2 letters.
pub fn index_of_coincidence(text: &str) -> Option<f64> {
    let (counts, total) = letter_counts(text);
    if total < 2 {
        return None;
    }
    let coincidences: u64 = counts.iter().map(|&c| c * (c.saturating_sub(1))).sum();
    let n = total as f64;
    Some(coincidences as f64 / (n * (n - 1.0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xor::scoring::ENGLISH_LETTER_FREQ_PCT as XOR_TABLE;

    #[test]
    fn frequency_table_matches_xor_lab_copy() {
        // The classical table is a deliberate copy of the XOR lab's table;
        // this pins them together so they cannot silently diverge.
        assert_eq!(ENGLISH_LETTER_FREQ_PCT, XOR_TABLE);
        let sum: f64 = ENGLISH_LETTER_FREQ_PCT.iter().sum();
        assert!((sum - 100.0).abs() < 0.1, "sum = {sum}");
    }

    #[test]
    fn english_text_outranks_garbage() {
        let prose = "there is a steady market for the ordinary words of the \
                     language and the matter of the fact remains that the same \
                     people read the same papers in the same places";
        let good = text_score(prose);
        let garbage: String = (0..300usize)
            .map(|i| (b'a' + ((i * 7) % 26) as u8) as char)
            .collect();
        let bad = text_score(&garbage);
        assert!(good > 0.5, "prose score = {good}");
        assert!(bad < good / 3.0, "garbage score = {bad} vs prose {good}");
    }

    #[test]
    fn no_letters_scores_zero() {
        assert_eq!(chi_square_english("123 456!"), None);
        assert_eq!(english_fit("ab"), 0.0, "fewer than 3 letters scores 0");
        assert_eq!(bigram_fit("a"), 0.0);
        assert_eq!(text_score(""), 0.0);
    }

    #[test]
    fn ioc_separates_english_from_uniform() {
        let english = index_of_coincidence("this is the other letter that the reader there had")
            .expect("enough letters");
        assert!(english > 0.06, "english ioc = {english}");
        // Uniform 26-letter text: two of each letter.
        let mut uniform = String::new();
        for _ in 0..4 {
            for c in b'a'..=b'z' {
                uniform.push(c as char);
            }
        }
        let flat = index_of_coincidence(&uniform).expect("enough letters");
        assert!(flat < 0.045, "uniform ioc = {flat}");
        assert!(english > flat);
    }

    #[test]
    fn ioc_needs_two_letters() {
        assert_eq!(index_of_coincidence(""), None);
        assert_eq!(index_of_coincidence("x"), None);
    }

    #[test]
    fn flag_bonus_lifts_score() {
        let base = text_score("some perfectly ordinary sentence about things");
        let flagged = text_score("flag{test} some perfectly ordinary sentence");
        assert!(flagged > base + 0.3, "{flagged} vs {base}");
    }

    #[test]
    fn confidence_labels_follow_thresholds() {
        assert_eq!(TextConfidence::from_score(0.95), TextConfidence::High);
        assert_eq!(TextConfidence::from_score(0.70), TextConfidence::Medium);
        assert_eq!(TextConfidence::from_score(0.10), TextConfidence::Low);
    }
}
