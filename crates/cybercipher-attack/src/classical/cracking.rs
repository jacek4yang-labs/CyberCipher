//! Ranked statistical attacks against the classical Vigenere family.
//!
//! Entry points:
//!
//! * [`ioc`] — index of coincidence over the letters of a text (the
//!   monoalphabetic-vs-polyalphabetic discriminator: ~0.066 for English, ~0.038
//!   for uniform letters).
//! * [`kasiski`] — Kasiski examination: repeated N-grams, pairwise distances,
//!   divisor tally, and a ranked list of candidate key lengths with example
//!   evidence.
//! * [`crack_caesar`] — all 26 shifts scored against the English model,
//!   ranked candidates with evidence and an honest "no confident key" flag.
//! * [`crack_vigenere`] — for every candidate key length, a per-column
//!   chi-square Caesar solve assembles a key; full decryptions are scored with
//!   the shared [`super::scoring`] model and returned ranked with per-column
//!   evidence.
//! * [`crack_substitution_lite`] — a frequency-mapping *hint* for
//!   monoalphabetic substitution: maps observed letter frequencies onto the
//!   English order and reports the mapping. Clearly labeled heuristic — not a
//!   solve.
//!
//! Scoring uses [`super::scoring`]'s English model (chi-square letter fit plus
//! common-bigram coverage; deliberately no quadgram tables — documented M6
//! scope). Every crack is honest about failure: when no candidate reaches the
//! confidence threshold the result carries `confident = false` and no claimed
//! key, instead of a plausible-looking wrong answer.

use super::check_text;
use super::polyalphabetic::vigenere_decode;
use super::scoring::{
    english_fit, text_score, TextConfidence, ENGLISH_LETTER_FREQ_PCT, ENGLISH_LETTER_ORDER,
};
use super::simple::CaseOptions;
use crate::xor::scoring::{preview_text, PREVIEW_MAX};
use cybercipher_core::error::OperationError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Smallest letter count accepted by [`crack_caesar`] — below this the
/// chi-square is meaningless.
pub const MIN_CAESAR_LETTERS: usize = 3;

/// Smallest letter count accepted by [`crack_vigenere`] — each column of the
/// shortest key still needs a usable sample.
pub const MIN_VIGENERE_LETTERS: usize = 24;

/// Default largest key length considered by [`crack_vigenere`] and
/// [`kasiski`].
pub const DEFAULT_MAX_KEY_LENGTH: usize = 20;

/// Hard cap on key lengths considered by [`crack_vigenere`] /
/// [`kasiski`].
pub const MAX_KEY_LENGTH_CAP: usize = 32;

/// Default composite-score threshold above which [`crack_vigenere`] claims
/// its best key (`confident = true`), on the [`text_score`] scale: genuine
/// English decryptions land at ~0.45..0.65, partially-corrupted ones below
/// ~0.35, random letters below ~0.10.
pub const DEFAULT_CONFIDENCE_THRESHOLD: f64 = 0.40;

/// Default composite-score threshold for [`crack_caesar`]. Deliberately lower
/// than the Vigenère default: Caesar cracks routinely run on very short texts
/// where even genuine English ("hello world", 10 letters) scores only ~0.14
/// because the chi-square statistic needs volume. Random-letter input still
/// scores below ~0.05, so the honest-failure boundary holds.
pub const CAESAR_DEFAULT_CONFIDENCE_THRESHOLD: f64 = 0.12;

/// Smallest letter count accepted by [`crack_substitution_lite`] — a
/// frequency-mapping hint needs roughly one occurrence per letter.
pub const MIN_SUBSTITUTION_LETTERS: usize = 26;

/// Deterministic cap on repeat pairs examined by [`kasiski`] (protects against
/// degenerate inputs like a single repeated letter).
pub const REPEAT_PAIR_BUDGET: usize = 262_144;

/// Deterministic cap on distinct repeated N-grams tracked by [`kasiski`].
pub const MAX_TRACKED_REPEATS: usize = 262_144;

/// Kasiski ranking weight: candidate score is
/// `length * divisor_count / total_distances` (see [`kasiski`]).
pub const KASISKI_LENGTH_WEIGHT: f64 = 1.0;

/// Options for [`kasiski`].
#[derive(Debug, Clone, PartialEq)]
pub struct KasiskiOptions {
    /// Minimum length of the repeated substrings examined. Default: 3.
    pub min_repeat_length: usize,
    /// Largest key length considered. Default:
    /// [`DEFAULT_MAX_KEY_LENGTH`].
    pub max_key_length: usize,
    /// How many ranked candidates to return. Default: 10.
    pub top_n: usize,
}

impl Default for KasiskiOptions {
    fn default() -> Self {
        Self {
            min_repeat_length: 3,
            max_key_length: DEFAULT_MAX_KEY_LENGTH,
            top_n: 10,
        }
    }
}

/// One ranked key-length candidate from [`kasiski`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KasiskiCandidate {
    /// Candidate key length (a divisor of repeat distances).
    pub key_length: usize,
    /// How many examined repeat distances this length divides.
    pub divisor_count: u64,
    /// Fraction of all examined distances this length divides (0..=1).
    pub distance_fraction: f64,
    /// Length-weighted ranking score (`distance_fraction * length`): guards
    /// against trivially high divisor counts for tiny lengths, since every
    /// distance divides by 1 and half of them by 2.
    pub score: f64,
    /// One repeated substring that supports this candidate (uppercase).
    pub example_repeat: Option<String>,
    /// Distance between two occurrences of `example_repeat`.
    pub example_distance: Option<usize>,
}

/// Outcome of [`kasiski`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KasiskiResult {
    /// Ranked key-length candidates (best first).
    pub candidates: Vec<KasiskiCandidate>,
    /// Number of distinct repeated N-grams found.
    pub repeats_found: usize,
    /// Number of repeat pairs (distances) examined.
    pub pairs_examined: u64,
    /// Letter count of the analyzed text.
    pub letters: usize,
    /// Honest diagnostics (degenerate input, truncated examination, ...).
    pub note: Option<String>,
}

/// Index of coincidence over the letters of `text`.
///
/// Returns the probability that two uniformly drawn letters are equal:
/// ~0.0667 for English (monoalphabetic), ~0.0385 for uniform random letters.
/// Errors when the text has fewer than 2 letters.
pub fn ioc(text: &str) -> Result<f64, OperationError> {
    check_text(text)?;
    super::scoring::index_of_coincidence(text).ok_or_else(|| {
        OperationError::invalid_input("input too short for an index of coincidence")
            .with_parameter("text")
            .with_expected("at least 2 letters")
            .with_actual(format!("{} letters", super::scoring::letter_counts(text).1))
    })
}

/// Kasiski examination: find repeated N-grams, tally the divisors of their
/// pairwise distances, and rank candidate key lengths.
///
/// Each candidate's ranking score is `distance_fraction * key_length` (see
/// [`KasiskiCandidate::score`]). On degenerate input the examination reports
/// what it could compute in `note` instead of failing: a text with *no*
/// repeated N-grams simply yields an empty candidate list with an honest note.
pub fn kasiski(text: &str, options: &KasiskiOptions) -> Result<KasiskiResult, OperationError> {
    check_text(text)?;
    if options.min_repeat_length == 0 || options.min_repeat_length > 10 {
        return Err(OperationError::invalid_param(
            "min_repeat_length",
            "min_repeat_length must be in 1..=10",
        )
        .with_expected("1..=10")
        .with_actual(options.min_repeat_length.to_string()));
    }
    if options.max_key_length == 0 || options.max_key_length > MAX_KEY_LENGTH_CAP {
        return Err(OperationError::invalid_param(
            "max_key_length",
            format!("max_key_length must be in 1..={MAX_KEY_LENGTH_CAP}"),
        )
        .with_expected(format!("1..={MAX_KEY_LENGTH_CAP}"))
        .with_actual(options.max_key_length.to_string()));
    }
    if options.top_n == 0 || options.top_n > 1024 {
        return Err(
            OperationError::invalid_param("top_n", "top_n must be in 1..=1024")
                .with_expected("1..=1024")
                .with_actual(options.top_n.to_string()),
        );
    }

    let l = options.min_repeat_length;
    let letters = super::scoring::letter_counts(text).1;
    if letters < l + 1 {
        return Err(
            OperationError::invalid_input("input too short for Kasiski examination")
                .with_parameter("text")
                .with_expected(format!("at least {} letters", l + 1))
                .with_actual(format!("{letters} letters")),
        );
    }

    // Collect positions of each N-gram (uppercase letters only).
    let upper: Vec<u8> = text
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase() as u8)
        .collect();
    let mut positions: HashMap<Vec<u8>, Vec<u32>> = HashMap::new();
    let mut note: Option<String> = None;
    for (i, w) in upper.windows(l).enumerate() {
        if positions.len() >= MAX_TRACKED_REPEATS && !positions.contains_key(w) {
            note = Some(format!(
                "repeat-tracking cap of {MAX_TRACKED_REPEATS} distinct N-grams reached; \
                 examination is based on the prefix of the text"
            ));
            break;
        }
        positions.entry(w.to_vec()).or_default().push(i as u32);
    }

    // Deterministic order: by first occurrence.
    let mut repeats: Vec<(Vec<u8>, Vec<u32>)> = positions
        .into_iter()
        .filter(|(_, ps)| ps.len() > 1)
        .collect();
    repeats.sort_by(|a, b| (a.1[0], &a.0).cmp(&(b.1[0], &b.0)));
    let repeats_found = repeats.len();

    let mut divisor_count = vec![0u64; options.max_key_length + 1];
    let mut example: Vec<Option<(String, usize)>> = vec![None; options.max_key_length + 1];
    let mut pairs_examined: u64 = 0;
    let mut budget_hit = false;
    'outer: for (ngram, ps) in &repeats {
        for (a, &pa) in ps.iter().enumerate() {
            for &pb in &ps[a + 1..] {
                let distance = (pb - pa) as usize;
                for len in 1..=options.max_key_length {
                    if distance.is_multiple_of(len) {
                        divisor_count[len] += 1;
                        if example[len].is_none() {
                            example[len] =
                                Some((String::from_utf8_lossy(ngram).into_owned(), distance));
                        }
                    }
                }
                pairs_examined += 1;
                if pairs_examined >= REPEAT_PAIR_BUDGET as u64 {
                    budget_hit = true;
                    break 'outer;
                }
            }
        }
    }
    if budget_hit {
        let msg = format!(
            "repeat-pair budget of {REPEAT_PAIR_BUDGET} reached; examination is based on \
             the first {pairs_examined} pairs"
        );
        note = Some(match note {
            Some(existing) => format!("{existing}; {msg}"),
            None => msg,
        });
    }

    let total = pairs_examined as f64;
    let mut candidates: Vec<KasiskiCandidate> = divisor_count
        .iter()
        .enumerate()
        .skip(1) // length 0 does not exist; length 1 is reported but never wins
        .filter(|(_, &count)| count > 0)
        .map(|(len, &count)| {
            let fraction = if total > 0.0 {
                count as f64 / total
            } else {
                0.0
            };
            KasiskiCandidate {
                key_length: len,
                divisor_count: count,
                distance_fraction: fraction,
                score: fraction * (len as f64) * KASISKI_LENGTH_WEIGHT,
                example_repeat: example[len].as_ref().map(|(s, _)| s.clone()),
                example_distance: example[len].as_ref().map(|(_, d)| *d),
            }
        })
        .collect();
    candidates.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.key_length.cmp(&b.key_length))
    });
    candidates.truncate(options.top_n);

    if repeats_found == 0 && note.is_none() {
        note = Some(format!(
            "no repeated {l}-grams found: the text may be too short for Kasiski \
             examination, or the cipher is not periodic over letters"
        ));
    }

    Ok(KasiskiResult {
        candidates,
        repeats_found,
        pairs_examined,
        letters,
        note,
    })
}

// -------------------------------------------------------- crack_caesar ----

/// Options for [`crack_caesar`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CaesarCrackOptions {
    /// Minimum composite score for the best candidate to be claimed.
    /// Default: [`CAESAR_DEFAULT_CONFIDENCE_THRESHOLD`].
    pub confidence_threshold: f64,
}

impl Default for CaesarCrackOptions {
    fn default() -> Self {
        Self {
            confidence_threshold: CAESAR_DEFAULT_CONFIDENCE_THRESHOLD,
        }
    }
}

/// One ranked Caesar candidate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaesarCandidate {
    /// Decryption shift: applying `caesar_decode(shift)` yields this
    /// candidate's plaintext, so `shift` equals the original encryption key.
    pub shift: i32,
    /// The shift as a key letter (`'A' + shift`).
    pub key_letter: char,
    /// Composite score in `0.0..=1.45` (see `scoring`).
    pub score: f64,
    /// Qualitative label for `score`.
    pub confidence: TextConfidence,
    /// Bounded (≤ 96 chars), lossy preview of the decryption.
    pub preview: String,
    /// English letter fit of the decryption.
    pub english_fit: f64,
    /// Common-bigram coverage of the decryption.
    pub bigram_fit: f64,
    /// Human-readable evidence lines.
    pub evidence: Vec<String>,
}

/// Outcome of [`crack_caesar`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaesarCrackResult {
    /// `true` when the best score reaches the confidence threshold.
    pub confident: bool,
    /// The claimed original key (0..=25), or `None` when not confident.
    pub best_shift: Option<i32>,
    /// The claimed key as a letter, or `None` when not confident.
    pub best_key: Option<String>,
    /// All 26 shifts, ranked best first.
    pub candidates: Vec<CaesarCandidate>,
    /// Letter count of the analyzed text.
    pub letters: usize,
}

/// Crack a Caesar cipher: try all 26 shifts, score every decryption against
/// the English model, and rank. Honest failure: when the best score is below
/// the threshold the result reports `confident = false` and no key.
pub fn crack_caesar(
    text: &str,
    options: &CaesarCrackOptions,
) -> Result<CaesarCrackResult, OperationError> {
    check_text(text)?;
    let (counts, letters) = super::scoring::letter_counts(text);
    if letters < MIN_CAESAR_LETTERS {
        return Err(
            OperationError::invalid_input("input too short for a Caesar crack")
                .with_parameter("text")
                .with_expected(format!("at least {MIN_CAESAR_LETTERS} letters"))
                .with_actual(format!("{letters} letters")),
        );
    }
    let expected: [f64; 26] = {
        let n = letters as f64;
        let mut e = [0.0; 26];
        for (i, item) in e.iter_mut().enumerate() {
            *item = n * ENGLISH_LETTER_FREQ_PCT[i] / 100.0;
        }
        e
    };

    let mut candidates: Vec<CaesarCandidate> = Vec::with_capacity(26);
    for shift in 0i32..26 {
        // Decode in the counts domain (fast), score the decoded text once.
        let mut decoded = String::with_capacity(text.len());
        for ch in text.chars() {
            if ch.is_ascii_alphabetic() {
                let c = ch.to_ascii_uppercase() as u8;
                let p = (c + 26 - b'A' - shift as u8) % 26;
                let mapped = (p + b'A') as char;
                decoded.push(if ch.is_ascii_lowercase() {
                    mapped.to_ascii_lowercase()
                } else {
                    mapped
                });
            } else {
                decoded.push(ch);
            }
        }
        // Chi-square of the decoded distribution: plaintext letter i comes
        // from ciphertext letter (i + shift), so rotate the observed counts
        // forward.
        let mut chi = 0.0;
        for i in 0..26usize {
            let obs = counts[(i + shift as usize) % 26] as f64;
            let diff = obs - expected[i];
            chi += diff * diff / expected[i];
        }
        let fit = (-chi / letters as f64).exp();
        let bigram = super::scoring::bigram_fit(&decoded);
        let score = text_score(&decoded);
        candidates.push(CaesarCandidate {
            shift,
            key_letter: (b'A' + shift as u8) as char,
            score,
            confidence: TextConfidence::from_score(score),
            preview: preview_text(decoded.as_bytes(), PREVIEW_MAX),
            english_fit: fit,
            bigram_fit: bigram,
            evidence: vec![
                format!(
                    "english letter fit {fit:.3} (chi²/letter {:.2} over {letters} letters)",
                    chi / letters as f64
                ),
                format!("common-bigram coverage {bigram:.3}"),
            ],
        });
    }
    candidates.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.shift.cmp(&b.shift))
    });

    let best = &candidates[0];
    let confident = best.score >= options.confidence_threshold;
    Ok(CaesarCrackResult {
        confident,
        best_shift: confident.then_some(best.shift),
        best_key: confident.then(|| best.key_letter.to_string()),
        candidates,
        letters,
    })
}

// ------------------------------------------------------ crack_vigenere ----

/// Options for [`crack_vigenere`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VigenereCrackOptions {
    /// Smallest key length to try. Default: 1.
    pub min_key_length: usize,
    /// Largest key length to try. Default: [`DEFAULT_MAX_KEY_LENGTH`].
    pub max_key_length: usize,
    /// How many ranked candidates to return. Default: 5.
    pub top_n: usize,
    /// Minimum composite score for the best candidate to be claimed.
    /// Default: [`DEFAULT_CONFIDENCE_THRESHOLD`].
    pub confidence_threshold: f64,
}

impl Default for VigenereCrackOptions {
    fn default() -> Self {
        Self {
            min_key_length: 1,
            max_key_length: DEFAULT_MAX_KEY_LENGTH,
            top_n: 5,
            confidence_threshold: DEFAULT_CONFIDENCE_THRESHOLD,
        }
    }
}

/// Per-column evidence of a [`crack_vigenere`] candidate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VigenereColumnEvidence {
    /// Column index (positions `p ≡ column (mod key_length)`).
    pub column: usize,
    /// The chi-square-winning key letter for this column.
    pub key_letter: char,
    /// The winning shift (0..=25) applied to this column.
    pub shift: i32,
    /// English letter fit of this column under the winning letter.
    pub best_fit: f64,
    /// Runner-up letter's fit — a large gap means a confident column.
    pub runner_up_letter: char,
    pub runner_up_fit: f64,
    /// Letters observed in this column.
    pub column_letters: usize,
}

/// One ranked Vigenère candidate from [`crack_vigenere`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VigenereCandidate {
    /// The assembled key (uppercase).
    pub key: String,
    /// Key length in letters.
    pub key_length: usize,
    /// Composite score of the full decryption in `0.0..=1.45`.
    pub score: f64,
    /// Qualitative label for `score`.
    pub confidence: TextConfidence,
    /// Bounded (≤ 96 chars), lossy preview of the decryption.
    pub preview: String,
    /// English letter fit of the full decryption.
    pub english_fit: f64,
    /// Common-bigram coverage of the full decryption.
    pub bigram_fit: f64,
    /// Mean English fit across the per-column solves.
    pub avg_column_fit: f64,
    /// Index of coincidence averaged across columns (key-length evidence).
    pub avg_column_ioc: f64,
    /// Per-column chi-square evidence.
    pub columns: Vec<VigenereColumnEvidence>,
}

/// Outcome of [`crack_vigenere`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VigenereCrackResult {
    /// `true` when the best score reaches the confidence threshold.
    pub confident: bool,
    /// The claimed key, or `None` when not confident.
    pub best_key: Option<String>,
    /// The claimed key length, or `None` when not confident.
    pub best_key_length: Option<usize>,
    /// Ranked candidates (best first).
    pub candidates: Vec<VigenereCandidate>,
    /// Letter count of the analyzed text.
    pub letters: usize,
    /// How many key lengths were actually solved.
    pub key_lengths_considered: usize,
    /// Honest diagnostics (clamped key-length range, low-confidence outcome).
    pub note: Option<String>,
}

/// Crack a Vigenère-family cipher (Vigenère, Gronsfeld, and any plain
/// periodic shift cipher).
///
/// For every key length `L` in the requested range the ciphertext is split
/// into `L` columns; each column is solved independently by trying all 26
/// shifts and picking the one whose decoded letter distribution fits English
/// (chi-square); the winning letters are assembled into a key, the full text
/// is decrypted, and the decryption is scored with the shared English model.
/// Candidates are ranked by score; on score ties the shorter key wins
/// (parsimony — a length-12 solve of a length-6 key decrypts identically).
///
/// Honest failure: when no candidate reaches the confidence threshold the
/// result reports `confident = false` and no key.
pub fn crack_vigenere(
    text: &str,
    options: &VigenereCrackOptions,
) -> Result<VigenereCrackResult, OperationError> {
    check_text(text)?;
    if options.min_key_length == 0 {
        return Err(OperationError::invalid_param(
            "min_key_length",
            "min_key_length must be at least 1",
        )
        .with_expected(">= 1")
        .with_actual("0"));
    }
    if options.max_key_length > MAX_KEY_LENGTH_CAP {
        return Err(OperationError::invalid_param(
            "max_key_length",
            format!("max_key_length must be at most {MAX_KEY_LENGTH_CAP}"),
        )
        .with_expected(format!("1..={MAX_KEY_LENGTH_CAP}"))
        .with_actual(options.max_key_length.to_string()));
    }
    if options.min_key_length > options.max_key_length {
        return Err(OperationError::invalid_param(
            "min_key_length",
            "min_key_length must not exceed max_key_length",
        )
        .with_expected(format!("<= {}", options.max_key_length))
        .with_actual(options.min_key_length.to_string()));
    }
    if options.top_n == 0 || options.top_n > 1024 {
        return Err(
            OperationError::invalid_param("top_n", "top_n must be in 1..=1024")
                .with_expected("1..=1024")
                .with_actual(options.top_n.to_string()),
        );
    }

    let upper: Vec<u8> = text
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase() as u8)
        .collect();
    let letters = upper.len();
    if letters < MIN_VIGENERE_LETTERS {
        return Err(
            OperationError::invalid_input("input too short for a Vigenere crack")
                .with_parameter("text")
                .with_expected(format!("at least {MIN_VIGENERE_LETTERS} letters"))
                .with_actual(format!("{letters} letters")),
        );
    }

    // Every length needs at least 2 letters per column to be meaningful.
    let effective_max = options.max_key_length.min(letters / 2);
    if effective_max < options.min_key_length {
        return Err(OperationError::invalid_input(
            "not enough letters for the requested key lengths",
        )
        .with_parameter("text")
        .with_expected(format!(
            "at least {} letters for key lengths {}..={}",
            2 * options.min_key_length,
            options.min_key_length,
            options.max_key_length
        ))
        .with_actual(format!("{letters} letters")));
    }
    let mut note: Option<String> = (effective_max < options.max_key_length).then(|| {
        format!(
            "max_key_length clamped to {effective_max}: {} letters only admit 2 letters \
             per column beyond that",
            letters
        )
    });

    let mut candidates: Vec<VigenereCandidate> = Vec::new();
    for len in options.min_key_length..=effective_max {
        // Per-column letter counts of the ciphertext.
        let mut column_counts: Vec<[u64; 26]> = vec![[0; 26]; len];
        let mut column_len = vec![0usize; len];
        for (i, &c) in upper.iter().enumerate() {
            let col = i % len;
            column_counts[col][(c - b'A') as usize] += 1;
            column_len[col] += 1;
        }

        // Column-wise IOC (key-length evidence for the UI).
        let mut ioc_sum = 0.0;
        for (col, counts) in column_counts.iter().enumerate() {
            let n = column_len[col] as f64;
            if n >= 2.0 {
                let coincidences: u64 = counts.iter().map(|&c| c * (c.saturating_sub(1))).sum();
                ioc_sum += coincidences as f64 / (n * (n - 1.0));
            }
        }
        let avg_ioc = ioc_sum / len as f64;

        // Chi-square solve per column.
        let mut key = String::with_capacity(len);
        let mut columns: Vec<VigenereColumnEvidence> = Vec::with_capacity(len);
        let mut fit_sum = 0.0;
        for (col, counts) in column_counts.iter().enumerate() {
            let n = column_len[col] as f64;
            let mut ranked: Vec<(f64, usize)> = Vec::with_capacity(26);
            for shift in 0usize..26 {
                let mut chi = 0.0;
                for i in 0..26usize {
                    // Decoding letter i comes from ciphertext letter (i+shift).
                    let obs = counts[(i + shift) % 26] as f64;
                    let expected = n * ENGLISH_LETTER_FREQ_PCT[i] / 100.0;
                    let diff = obs - expected;
                    chi += diff * diff / expected;
                }
                ranked.push(((-chi / n).exp(), shift));
            }
            ranked.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
            let (best_fit, best_shift) = ranked[0];
            let (runner_fit, runner_shift) = ranked[1];
            key.push((b'A' + best_shift as u8) as char);
            fit_sum += best_fit;
            columns.push(VigenereColumnEvidence {
                column: col,
                key_letter: (b'A' + best_shift as u8) as char,
                shift: best_shift as i32,
                best_fit,
                runner_up_letter: (b'A' + runner_shift as u8) as char,
                runner_up_fit: runner_fit,
                column_letters: column_len[col],
            });
        }

        let decrypted = vigenere_decode(text, &key, &CaseOptions::default())?;
        let fit = english_fit(&decrypted.output);
        let bigram = super::scoring::bigram_fit(&decrypted.output);
        let score = text_score(&decrypted.output);
        candidates.push(VigenereCandidate {
            key,
            key_length: len,
            score,
            confidence: TextConfidence::from_score(score),
            preview: preview_text(decrypted.output.as_bytes(), PREVIEW_MAX),
            english_fit: fit,
            bigram_fit: bigram,
            avg_column_fit: fit_sum / len as f64,
            avg_column_ioc: avg_ioc,
            columns,
        });
    }

    let key_lengths_considered = candidates.len();
    candidates.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.key_length.cmp(&b.key_length))
            .then_with(|| a.key.cmp(&b.key))
    });
    candidates.truncate(options.top_n);

    let best = &candidates[0];
    let confident = best.score >= options.confidence_threshold;
    if !confident {
        let msg = format!(
            "no candidate reached the confidence threshold ({:.2}): best score {:.3} — \
             the text may be too short, non-English, or not a periodic shift cipher",
            options.confidence_threshold, best.score
        );
        note = Some(match note {
            Some(existing) => format!("{existing}; {msg}"),
            None => msg,
        });
    }

    Ok(VigenereCrackResult {
        confident,
        best_key: confident.then(|| best.key.clone()),
        best_key_length: confident.then_some(best.key_length),
        candidates,
        letters,
        key_lengths_considered,
        note,
    })
}

// --------------------------------------------- crack_substitution_lite ----

/// Options for [`crack_substitution_lite`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SubstitutionOptions {
    /// How many frequent observed bigrams to report as extra evidence.
    /// Default: 8.
    pub top_bigrams: usize,
}

impl Default for SubstitutionOptions {
    fn default() -> Self {
        Self { top_bigrams: 8 }
    }
}

/// One suggested letter mapping from [`crack_substitution_lite`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubstitutionMapping {
    /// The ciphertext letter (uppercase).
    pub cipher_letter: char,
    /// The suggested plaintext letter by frequency rank (uppercase).
    pub suggested_letter: char,
    /// How often the ciphertext letter occurs.
    pub count: u64,
    /// Frequency rank of the ciphertext letter (0 = most frequent).
    pub rank: usize,
}

/// One observed frequent bigram from [`crack_substitution_lite`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedBigram {
    /// The bigram as it appears in the ciphertext (uppercase).
    pub bigram: String,
    /// How often it occurs.
    pub count: u64,
}

/// Outcome of [`crack_substitution_lite`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubstitutionHintResult {
    /// Frequency-rank mapping hint (every observed letter).
    pub mapping: Vec<SubstitutionMapping>,
    /// Most frequent observed letter bigrams (evidence, not a solve).
    pub observed_bigrams: Vec<ObservedBigram>,
    /// Index of coincidence of the text — the monoalphabetic discriminator.
    pub ioc: f64,
    /// Letter count of the analyzed text.
    pub letters: usize,
    /// Always present: what this result is and how to use it.
    pub note: String,
}

/// A frequency-mapping *hint* for monoalphabetic substitution ciphers.
///
/// Maps the observed ciphertext letters (most frequent first, ties broken
/// alphabetically for determinism) onto the standard English frequency order
/// and reports the mapping plus the most frequent bigrams and the text's
/// index of coincidence. This is a heuristic starting point for manual
/// cryptanalysis — the note field says so explicitly; it is not a solve, and
/// rare letters (j, q, x, z) are notoriously unreliable in it.
pub fn crack_substitution_lite(
    text: &str,
    options: &SubstitutionOptions,
) -> Result<SubstitutionHintResult, OperationError> {
    check_text(text)?;
    if options.top_bigrams > 64 {
        return Err(
            OperationError::invalid_param("top_bigrams", "top_bigrams must be at most 64")
                .with_expected("0..=64")
                .with_actual(options.top_bigrams.to_string()),
        );
    }
    let (counts, letters) = super::scoring::letter_counts(text);
    if letters < MIN_SUBSTITUTION_LETTERS {
        return Err(
            OperationError::invalid_input("input too short for a frequency-mapping hint")
                .with_parameter("text")
                .with_expected(format!("at least {MIN_SUBSTITUTION_LETTERS} letters"))
                .with_actual(format!("{letters} letters")),
        );
    }

    let mut ranked: Vec<(u64, usize)> = counts
        .iter()
        .enumerate()
        .filter(|(_, &count)| count > 0)
        .map(|(i, &count)| (count, i))
        .collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

    let mapping: Vec<SubstitutionMapping> = ranked
        .iter()
        .enumerate()
        .map(|(rank, &(count, letter))| SubstitutionMapping {
            cipher_letter: (b'A' + letter as u8) as char,
            suggested_letter: ENGLISH_LETTER_ORDER
                .as_bytes()
                .get(rank)
                .copied()
                .map(char::from)
                .unwrap_or('?'),
            count,
            rank,
        })
        .collect();

    // Frequent observed bigrams.
    let upper: Vec<u8> = text
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase() as u8)
        .collect();
    let mut bigrams: HashMap<[u8; 2], u64> = HashMap::new();
    for pair in upper.windows(2) {
        *bigrams.entry([pair[0], pair[1]]).or_default() += 1;
    }
    let mut observed: Vec<ObservedBigram> = bigrams
        .into_iter()
        .map(|(b, count)| ObservedBigram {
            bigram: String::from_utf8_lossy(&b).into_owned(),
            count,
        })
        .collect();
    observed.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.bigram.cmp(&b.bigram)));
    observed.truncate(options.top_bigrams);

    let index = super::scoring::index_of_coincidence(text).unwrap_or(0.0);
    let note = if index >= 0.06 {
        format!(
            "heuristic frequency-mapping hint only, not a solve — IOC {index:.3} suggests a \
             monoalphabetic cipher, so the mapping is meaningful; validate rare letters \
             (j, q, x, z) manually"
        )
    } else {
        format!(
            "heuristic frequency-mapping hint only, not a solve — IOC {index:.3} is low, \
             which suggests a polyalphabetic cipher (e.g. Vigenere); try crack_vigenere \
             instead of trusting this mapping"
        )
    };

    Ok(SubstitutionHintResult {
        mapping,
        observed_bigrams: observed,
        ioc: index,
        letters,
        note,
    })
}

// ------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classical::polyalphabetic::vigenere_encode;

    /// Representative English prose (~340 letters) used by the crack tests.
    const PROSE: &str = "the quick brown fox jumps over the lazy dog while the \
         quiet farmer watches the river flow past the old mill every morning \
         the same birds sing the same songs and the world keeps turning the \
         way it always has there is a steady market for the ordinary words \
         of the english language and the matter of the fact remains that the \
         same people read the same papers in the same places at the same \
         time every single day of the week without fail";

    #[test]
    fn ioc_reports_statistic_and_validates() {
        let english_ioc = ioc(PROSE).unwrap();
        assert!(
            english_ioc > 0.06 && english_ioc < 0.08,
            "got {english_ioc}"
        );
        let err = ioc("a").unwrap_err();
        assert_eq!(err.expected.as_deref(), Some("at least 2 letters"));
        assert_eq!(err.actual.as_deref(), Some("1 letters"));
    }

    #[test]
    fn kasiski_ranks_true_key_length() {
        let cipher = vigenere_encode(PROSE, "QUARTZ", &CaseOptions::default())
            .unwrap()
            .output;
        let result = kasiski(&cipher, &KasiskiOptions::default()).unwrap();
        assert!(result.repeats_found > 0);
        let top3: Vec<usize> = result
            .candidates
            .iter()
            .take(3)
            .map(|c| c.key_length)
            .collect();
        assert!(
            top3.contains(&6),
            "key length 6 should rank in the top 3, got {top3:?} (scores: {:?})",
            result
                .candidates
                .iter()
                .take(5)
                .map(|c| (c.key_length, c.score))
                .collect::<Vec<_>>()
        );
        assert!(result.candidates[0].example_repeat.is_some());
        assert!(result.candidates.iter().all(|c| c.key_length >= 1));
    }

    #[test]
    fn kasiski_ranks_single_repeat_distance() {
        // Exactly one repeated trigram, at distance 26: divisors 1, 2, 13, 26
        // all score, and the length-weighted ranking must prefer 26.
        let text = "ABCDEFGHIJKLMNOPQRSTUVWXYZABC";
        let result = kasiski(
            text,
            &KasiskiOptions {
                max_key_length: 26,
                ..KasiskiOptions::default()
            },
        )
        .unwrap();
        assert_eq!(result.repeats_found, 1);
        assert_eq!(result.candidates[0].key_length, 26);
        assert_eq!(result.candidates[0].divisor_count, 1);
        assert_eq!(result.candidates[0].example_repeat.as_deref(), Some("ABC"));
        assert_eq!(result.candidates[0].example_distance, Some(26));
    }

    #[test]
    fn kasiski_honest_on_repeat_free_text() {
        // 26 distinct letters: every trigram occurs exactly once.
        let text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let result = kasiski(text, &KasiskiOptions::default()).unwrap();
        assert_eq!(result.repeats_found, 0);
        assert_eq!(result.candidates.len(), 0);
        assert!(result.note.is_some());
    }

    #[test]
    fn kasiski_validates_options() {
        assert!(kasiski(
            "abcdef",
            &KasiskiOptions {
                min_repeat_length: 0,
                ..KasiskiOptions::default()
            }
        )
        .is_err());
        assert!(kasiski(
            "abcdef",
            &KasiskiOptions {
                max_key_length: MAX_KEY_LENGTH_CAP + 1,
                ..KasiskiOptions::default()
            }
        )
        .is_err());
        assert!(
            kasiski("abc", &KasiskiOptions::default()).is_err(),
            "too short"
        );
    }

    #[test]
    fn caesar_crack_finds_rot13() {
        let cipher = "Uryyb jbeyq";
        let result = crack_caesar(cipher, &CaesarCrackOptions::default()).unwrap();
        assert_eq!(result.candidates.len(), 26);
        assert_eq!(result.candidates[0].shift, 13);
        assert!(result.confident);
        assert_eq!(result.best_shift, Some(13));
        assert_eq!(result.best_key.as_deref(), Some("N"));
        assert!(result.candidates[0]
            .preview
            .to_lowercase()
            .starts_with("hello"));
        assert!(result.candidates[0].evidence.iter().all(|l| !l.is_empty()));
    }

    #[test]
    fn caesar_crack_ranks_english_above_shifted() {
        // Shift-3 of "the same people read the same papers in the same
        // places" (deliberately not a pangram: pangrams over-represent rare
        // letters and score low on any unigram chi-square, see scoring docs).
        let result = crack_caesar(
            "WKH VDPH SHRSOH UHDG WKH VDPH SDSHUV LQ WKH VDPH SODFHV",
            &CaesarCrackOptions::default(),
        )
        .unwrap();
        assert_eq!(result.candidates[0].shift, 3);
        assert!(result.confident);
        assert_eq!(result.best_shift, Some(3));
        // Runner-up is clearly separated.
        assert!(result.candidates[0].score > result.candidates[1].score);
    }

    #[test]
    fn caesar_crack_honest_on_garbage() {
        let garbage: String = (0..200)
            .map(|i| (b'A' + ((i * 17) % 26) as u8) as char)
            .collect();
        let result = crack_caesar(&garbage, &CaesarCrackOptions::default()).unwrap();
        assert!(!result.confident);
        assert_eq!(result.best_shift, None);
        assert_eq!(result.best_key, None);
        assert_eq!(result.candidates.len(), 26);
    }

    #[test]
    fn caesar_crack_validates_input() {
        let err = crack_caesar("ab", &CaesarCrackOptions::default()).unwrap_err();
        assert_eq!(err.expected.as_deref(), Some("at least 3 letters"));
        assert_eq!(err.actual.as_deref(), Some("2 letters"));
        assert_eq!(err.kind, cybercipher_core::error::ErrorKind::InvalidInput);
    }

    #[test]
    fn vigenere_crack_recovers_six_letter_key_top1() {
        let cipher = vigenere_encode(PROSE, "QUARTZ", &CaseOptions::default())
            .unwrap()
            .output;
        let result = crack_vigenere(&cipher, &VigenereCrackOptions::default()).unwrap();
        assert!(
            result.confident,
            "note: {:?}, best: {:?}",
            result.note,
            result.candidates.first().map(|c| (c.key.clone(), c.score))
        );
        assert_eq!(result.best_key.as_deref(), Some("QUARTZ"));
        assert_eq!(result.best_key_length, Some(6));
        assert_eq!(result.candidates[0].key, "QUARTZ");
        // Parsimony: the true length outranks its multiples on ties.
        for c in &result.candidates {
            assert_eq!(c.columns.len(), c.key_length);
            assert!((c.avg_column_ioc) >= 0.0);
        }
        let preview = result.candidates[0].preview.to_lowercase();
        assert!(preview.starts_with("the quick"), "preview: {preview}");
    }

    #[test]
    fn vigenere_crack_honest_on_garbage() {
        let garbage: String = (0..400)
            .map(|i| (b'A' + ((i * 17) % 26) as u8) as char)
            .collect();
        let result = crack_vigenere(&garbage, &VigenereCrackOptions::default()).unwrap();
        assert!(!result.confident);
        assert_eq!(result.best_key, None);
        assert!(result.note.is_some());
        assert!(
            !result.candidates.is_empty(),
            "candidates still returned, ranked"
        );
    }

    #[test]
    fn vigenere_crack_validates_input_and_options() {
        assert!(crack_vigenere("too short", &VigenereCrackOptions::default()).is_err());
        assert!(crack_vigenere(
            &"a".repeat(100),
            &VigenereCrackOptions {
                min_key_length: 0,
                ..VigenereCrackOptions::default()
            }
        )
        .is_err());
        assert!(crack_vigenere(
            &"a".repeat(100),
            &VigenereCrackOptions {
                min_key_length: 5,
                max_key_length: 4,
                ..VigenereCrackOptions::default()
            }
        )
        .is_err());
        assert!(crack_vigenere(
            &"a".repeat(100),
            &VigenereCrackOptions {
                max_key_length: MAX_KEY_LENGTH_CAP + 1,
                ..VigenereCrackOptions::default()
            }
        )
        .is_err());
    }

    #[test]
    fn substitution_hint_maps_by_frequency() {
        // Encode prose with Atbash and check the hint against ground truth:
        // the most frequent ciphertext letter is the Atbash mirror of the
        // most frequent plaintext letter, and the hint suggests 'E' for it
        // (rank 0 of the English order).
        let cipher = super::super::simple::atbash_encode(PROSE, &CaseOptions::default())
            .unwrap()
            .output;
        let (prose_counts, _) = super::super::scoring::letter_counts(PROSE);
        let top_plain = (0..26usize)
            .max_by_key(|&i| (prose_counts[i], 25u8.wrapping_sub(i as u8)))
            .expect("26 letters");
        let top_plain_letter = (b'A' + top_plain as u8) as char;
        let mirror = |c: char| (b'Z' - (c as u8 - b'A')) as char;

        let result = crack_substitution_lite(&cipher, &SubstitutionOptions::default()).unwrap();
        let top = result.mapping[0];
        assert_eq!(
            top.cipher_letter,
            mirror(top_plain_letter),
            "most frequent cipher letter mirrors most frequent plain letter"
        );
        assert_eq!(top.suggested_letter, 'E');
        assert_eq!(top.rank, 0);
        assert!(
            result.ioc >= 0.06,
            "Atbash is monoalphabetic: {}",
            result.ioc
        );
        assert!(result.note.contains("monoalphabetic"));
        assert!(!result.observed_bigrams.is_empty());
        // Mapping covers every observed letter; counts are non-increasing.
        let unique: std::collections::HashSet<char> =
            result.mapping.iter().map(|m| m.cipher_letter).collect();
        assert_eq!(unique.len(), result.mapping.len());
        for pair in result.mapping.windows(2) {
            assert!(pair[0].count >= pair[1].count);
        }
    }

    #[test]
    fn substitution_hint_warns_when_polyalphabetic() {
        let cipher = vigenere_encode(PROSE, "QUARTZ", &CaseOptions::default())
            .unwrap()
            .output;
        let result = crack_substitution_lite(&cipher, &SubstitutionOptions::default()).unwrap();
        assert!(result.ioc < 0.055);
        assert!(result.note.contains("polyalphabetic"));
    }

    #[test]
    fn substitution_hint_validates_input() {
        let err = crack_substitution_lite("short", &SubstitutionOptions::default()).unwrap_err();
        assert_eq!(err.expected.as_deref(), Some("at least 26 letters"));
    }
}
