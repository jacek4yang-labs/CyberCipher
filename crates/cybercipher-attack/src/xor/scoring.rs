//! English-language scoring for the XOR analysis layer.
//!
//! Every candidate decryption produced by the XOR lab is ranked with a
//! composite score built from five honest, individually reportable signals:
//!
//! 1. **Printable ratio** — fraction of bytes that are printable ASCII or
//!    common whitespace (reused from [`cybercipher_core::util`]).
//! 2. **English letter fit** — chi-square goodness of fit of the observed
//!    letter distribution against a compact hardcoded English letter-frequency
//!    table ([`ENGLISH_LETTER_FREQ_PCT`]), computed **over letters only**:
//!    non-letter bytes are ignored and each letter's expected count is scaled
//!    to the number of letters actually observed. The chi-square statistic per
//!    letter is mapped through `exp(-chi²/letter)` so 1.0 is a perfect English
//!    fit and values decay smoothly to 0.
//! 3. **ASCII letter ratio** — fraction of bytes that are ASCII letters or
//!    spaces ([`cybercipher_core::util::ascii_letter_ratio`]).
//! 4. **UTF-8 validity** — sampled on the first [`UTF8_SAMPLE_MAX`] bytes for
//!    large inputs (exact for smaller ones).
//! 5. **CTF flag-pattern bonus** — a small additive bonus when a known
//!    flag-like token (`flag{`, `ctf{`, ...) appears in the candidate; a
//!    decisive, human-verifiable signal when present.
//!
//! The frequency table is the widely reproduced table from Robert Edward
//! Lewand, *Cryptological Mathematics* (2000) — the same values tabulated on
//! Wikipedia's "Letter frequency" page and used across classical-crypto
//! literature.
//!
//! **Scope note**: scoring is tuned for ASCII English text. Scoring for
//! Chinese and other non-Latin scripts (e.g. fitting a bigram model over
//! UTF-8) is future work; such inputs will score honestly low and surface as
//! "no confident key" rather than a false positive.

use cybercipher_core::util::{ascii_letter_ratio, printable_ratio};
use serde::{Deserialize, Serialize};

/// Standard English letter frequencies in percent, `a`..=`z` (Lewand,
/// *Cryptological Mathematics*, 2000; sums to ~99.99%).
pub const ENGLISH_LETTER_FREQ_PCT: [f64; 26] = [
    8.167, // a
    1.492, // b
    2.782, // c
    4.253, // d
    12.702, // e
    2.228, // f
    2.015, // g
    6.094, // h
    6.966, // i
    0.153, // j
    0.772, // k
    4.025, // l
    2.406, // m
    6.749, // n
    7.507, // o
    1.929, // p
    0.095, // q
    5.987, // r
    6.327, // s
    9.056, // t
    2.758, // u
    0.978, // v
    2.360, // w
    0.150, // x
    1.974, // y
    0.074, // z
];

/// Known CTF flag token prefixes, matched case-insensitively. `htb` = Hack
/// The Box, `thm` = TryHackMe, `picoctf` = picoCTF.
pub const FLAG_PREFIXES: [&str; 5] = ["flag{", "ctf{", "picoctf{", "htb{", "thm{"];

/// Additive score bonus when a flag-like token is present.
pub const FLAG_BONUS: f64 = 0.25;

/// Maximum preview length (characters) in result payloads.
pub const PREVIEW_MAX: usize = 96;

/// Byte count over which UTF-8 validity is sampled for large inputs.
pub const UTF8_SAMPLE_MAX: usize = 8192;

/// Byte count over which flag tokens are searched.
pub const FLAG_SAMPLE_MAX: usize = 4096;

/// Qualitative confidence label derived from a composite score.
///
/// `score >= 0.80` → `High`, `score >= 0.60` → `Medium`, else `Low`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    /// Map a composite score to its qualitative label.
    pub fn from_score(score: f64) -> Self {
        if score >= 0.80 {
            Confidence::High
        } else if score >= 0.60 {
            Confidence::Medium
        } else {
            Confidence::Low
        }
    }
}

/// A byte is "printable" under the same definition as
/// [`cybercipher_core::util::printable_ratio`]: printable ASCII or `\n`, `\r`,
/// `\t`.
pub fn is_printable_byte(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || matches!(b, b'\n' | b'\r' | b'\t')
}

/// Counts of each ASCII letter (`a`..=`z`, case-folded) in `data`, plus the
/// total letter count.
fn letter_counts(data: &[u8]) -> ([u64; 26], usize) {
    let mut counts = [0u64; 26];
    let mut total = 0usize;
    for &b in data {
        if b.is_ascii_lowercase() {
            counts[(b - b'a') as usize] += 1;
            total += 1;
        } else if b.is_ascii_uppercase() {
            counts[(b - b'A') as usize] += 1;
            total += 1;
        }
    }
    (counts, total)
}

/// Chi-square goodness of fit of the observed letter distribution against the
/// English table, over letters only. Returns `None` when the data contains no
/// ASCII letters (there is nothing to fit).
pub fn chi_square_english(data: &[u8]) -> Option<f64> {
    let (counts, total) = letter_counts(data);
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

/// English letter fit in `0.0..=1.0`: `exp(-chi²/letter)` over letters only.
/// Returns 0.0 when the data contains fewer than 3 letters (the statistic is
/// meaningless on such samples).
pub fn english_fit(data: &[u8]) -> f64 {
    match chi_square_english(data) {
        None => 0.0,
        Some(chi) => {
            let (_, total) = letter_counts(data);
            if total < 3 {
                return 0.0;
            }
            (-chi / total as f64).exp()
        }
    }
}

/// Search the sampled prefix of `data` for a known CTF flag token
/// (case-insensitive). Returns the matched token as it appears in the data,
/// truncated to 16 characters.
pub fn find_flag_pattern(data: &[u8]) -> Option<String> {
    let sample = &data[..data.len().min(FLAG_SAMPLE_MAX)];
    let lower: Vec<u8> = sample.iter().map(|b| b.to_ascii_lowercase()).collect();
    for prefix in FLAG_PREFIXES {
        if lower.windows(prefix.len()).any(|w| w == prefix.as_bytes()) {
            let start = lower
                .windows(prefix.len())
                .position(|w| w == prefix.as_bytes())
                .unwrap_or(0);
            let end = (start + 16).min(sample.len());
            return Some(String::from_utf8_lossy(&sample[start..end]).into_owned());
        }
    }
    None
}

/// Bounded, lossy text preview: printable ASCII and whitespace pass through,
/// everything else becomes `.`, truncated to `max` characters with `...` when
/// anything was cut.
pub fn preview_text(data: &[u8], max: usize) -> String {
    let take = data.len().min(max);
    let mut out = String::with_capacity(take + 4);
    for &b in &data[..take] {
        if is_printable_byte(b) {
            out.push(b as char);
        } else {
            out.push('.');
        }
    }
    if data.len() > take {
        out.push_str("...");
    }
    out
}

/// All five scoring signals for one candidate decryption, plus the composite.
///
/// The composite is `0.40*printable + 0.35*english_fit + 0.15*letter_ratio +
/// 0.10*utf8 + flag_bonus`, in `0.0..=1.25`. Every component is reported so a
/// UI can show *why* a candidate ranked where it did.
#[derive(Debug, Clone, PartialEq)]
pub struct CompositeScore {
    /// Final composite score (higher is better).
    pub score: f64,
    /// Printable-ASCII ratio of the full candidate.
    pub printable: f64,
    /// ASCII letter+space ratio of the full candidate.
    pub letter_ratio: f64,
    /// English letter fit (`exp(-chi²/letter)`, letters only).
    pub english_fit: f64,
    /// Chi-square per observed letter (`None` when there are no letters).
    pub chi_per_letter: Option<f64>,
    /// Number of ASCII letters observed.
    pub letters: usize,
    /// UTF-8 validity (sampled on the first [`UTF8_SAMPLE_MAX`] bytes).
    pub valid_utf8: bool,
    /// Flag-like token found, if any.
    pub flag_pattern: Option<String>,
}

impl CompositeScore {
    /// Score the candidate plaintext `data`.
    pub fn of(data: &[u8]) -> Self {
        let printable = printable_ratio(data);
        let letter_ratio = ascii_letter_ratio(data);
        let chi_per_letter = chi_square_english(data).map(|chi| {
            let (_, total) = letter_counts(data);
            chi / total as f64
        });
        let fit = english_fit(data);
        let sample = &data[..data.len().min(UTF8_SAMPLE_MAX)];
        let valid_utf8 = std::str::from_utf8(sample).is_ok();
        let flag_pattern = find_flag_pattern(data);
        let flag = if flag_pattern.is_some() {
            FLAG_BONUS
        } else {
            0.0
        };
        let score = 0.40 * printable
            + 0.35 * fit
            + 0.15 * letter_ratio
            + 0.10 * u8::from(valid_utf8) as f64
            + flag;
        Self {
            score,
            printable,
            letter_ratio,
            english_fit: fit,
            chi_per_letter,
            letters: letter_counts(data).1,
            valid_utf8,
            flag_pattern,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frequency_table_sums_to_roughly_100_percent() {
        let sum: f64 = ENGLISH_LETTER_FREQ_PCT.sum();
        assert!((sum - 100.0).abs() < 0.1, "sum = {sum}");
    }

    #[test]
    fn english_text_fits_well_and_garbage_does_not() {
        let text = b"the quick brown fox jumps over the lazy dog and keeps on running";
        let fit = english_fit(text);
        assert!(fit > 0.7, "english fit = {fit}");
        let garbage: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let fit_garbage = english_fit(&garbage);
        assert!(fit_garbage < 0.2, "garbage fit = {fit_garbage}");
    }

    #[test]
    fn no_letters_yields_none_and_zero_fit() {
        assert_eq!(chi_square_english(b"123 456!"), None);
        assert_eq!(english_fit(b"123 456!"), 0.0);
        assert_eq!(english_fit(b"ab"), 0.0, "fewer than 3 letters scores 0");
    }

    #[test]
    fn flag_detection_is_case_insensitive() {
        assert!(find_flag_pattern(b"xxxx FLAG{abc} yyyy").is_some());
        assert_eq!(
            find_flag_pattern(b"xxxx ctf{ok} yyyy").as_deref(),
            Some("ctf{ok}")
        );
        assert!(find_flag_pattern(b"no tokens here").is_none());
    }

    #[test]
    fn preview_is_bounded_and_lossy() {
        let p = preview_text(&[b'a', 0x00, b'b', 0xFF], 96);
        assert_eq!(p, "a.b.");
        let long = vec![b'x'; 200];
        let p = preview_text(&long, 96);
        assert!(p.starts_with('x'));
        assert!(p.ends_with("..."));
        assert_eq!(p.len(), 96 + 3);
    }

    #[test]
    fn composite_ranks_english_above_random() {
        let text = b"Congratulations, you have recovered the plaintext of the message.";
        let good = CompositeScore::of(text);
        let bad: Vec<u8> = [0x9Cu8, 0xE7, 0x03, 0xF1, 0x44, 0x88].repeat(4);
        let bad = CompositeScore::of(&bad);
        assert!(good.score > bad.score + 0.3);
        assert_eq!(good.flag_pattern, None);
        let flagged = CompositeScore::of(b"flag{test}");
        assert!(flagged.score > 1.0, "flag bonus pushes above 1.0");
    }
}
