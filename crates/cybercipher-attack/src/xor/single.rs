//! Single-byte XOR cracking: score all 256 candidate keys against an
//! English-language model and return a ranked list with per-candidate
//! evidence — or an honest "no confident key" outcome.
//!
//! The caller chooses how many candidates to keep ([`SingleByteOptions::
//! top_n`]); every candidate carries its composite score, the key, a bounded
//! decoded preview and human-readable evidence strings. Ties are broken by
//! ascending key byte so results are fully deterministic; the gap to the
//! runner-up and an exact-tie flag are reported so a UI can show when the
//! ranking is ambiguous.
//!
//! When the best score is below [`SingleByteOptions::confidence_threshold`]
//! the result is `confident = false` and `best_key = None` — the candidates
//! are still returned, but no key is claimed. This is the honest outcome for
//! random or non-English data.

use super::scoring::{preview_text, CompositeScore, Confidence, PREVIEW_MAX};
use super::{DEFAULT_CONFIDENT_THRESHOLD, MAX_INPUT_BYTES, MAX_TOP_N};
use cybercipher_core::error::OperationError;
use serde::{Deserialize, Serialize};

/// Options for [`crack_single_byte`].
#[derive(Debug, Clone, PartialEq)]
pub struct SingleByteOptions {
    /// How many ranked candidates to return (1..=[`MAX_TOP_N`]; a key space
    /// of 256 makes anything larger pointless). Default: 8.
    pub top_n: usize,
    /// Minimum composite score for the best candidate to be claimed as the
    /// key. Below it the crack honestly reports "no confident key". Default:
    /// [`DEFAULT_CONFIDENT_THRESHOLD`].
    pub confidence_threshold: f64,
}

impl Default for SingleByteOptions {
    fn default() -> Self {
        Self {
            top_n: 8,
            confidence_threshold: DEFAULT_CONFIDENT_THRESHOLD,
        }
    }
}

/// One ranked single-byte XOR key candidate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SingleByteCandidate {
    /// The candidate key byte (0..=255).
    pub key: u8,
    /// The key as `0xNN` hex.
    pub key_hex: String,
    /// Composite score in `0.0..=1.25` (see `scoring`).
    pub score: f64,
    /// Qualitative label for `score`.
    pub confidence: Confidence,
    /// Bounded (≤ [`PREVIEW_MAX`] chars), lossy preview of the decryption.
    pub preview: String,
    /// Printable-ASCII ratio of the decryption.
    pub printable_ratio: f64,
    /// ASCII letter+space ratio of the decryption.
    pub letter_ratio: f64,
    /// Chi-square per observed letter against English (`None` when the
    /// candidate has no ASCII letters).
    pub chi_square_per_letter: Option<f64>,
    /// UTF-8 validity of the decryption (sampled prefix for large inputs).
    pub valid_utf8: bool,
    /// Flag-like token found in the decryption, if any.
    pub flag_pattern: Option<String>,
    /// Human-readable evidence lines explaining the score.
    pub evidence: Vec<String>,
}

/// Outcome of [`crack_single_byte`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SingleByteCrackResult {
    /// `true` when the best score reaches the confidence threshold.
    pub confident: bool,
    /// The claimed key, or `None` when not confident.
    pub best_key: Option<u8>,
    /// The claimed key as `0xNN` hex, or `None` when not confident.
    pub best_key_hex: Option<String>,
    /// Composite score of the best candidate (reported even when not
    /// confident, so the UI can show *how far* from confident it was).
    pub best_score: f64,
    /// Qualitative label for `best_score`.
    pub best_confidence: Confidence,
    /// Gap between the best and second-best scores (`None` when only one key
    /// could be scored, which cannot happen for the full 256-key sweep but
    /// keeps the shape stable).
    pub runner_up_gap: Option<f64>,
    /// `true` when the top two scores are exactly equal — the tie-breaker
    /// (ascending key) picked the winner, not the evidence.
    pub tie: bool,
    /// Ciphertext length in bytes.
    pub input_len: usize,
    /// The threshold that was applied.
    pub confidence_threshold: f64,
    /// Ranked candidates (best first), at most `top_n`.
    pub candidates: Vec<SingleByteCandidate>,
}

/// Crack a single-byte XOR ciphertext: try all 256 keys, score each
/// decryption with the English model, and return the ranked candidates.
///
/// Errors are typed: empty input, input over [`MAX_INPUT_BYTES`], or an
/// invalid `options` (zero/oversized `top_n`, threshold outside `0.0..=1.0`).
pub fn crack_single_byte(
    data: &[u8],
    options: &SingleByteOptions,
) -> Result<SingleByteCrackResult, OperationError> {
    validate_input(data)?;
    validate_options(options)?;

    // Score all 256 keys. One reusable buffer keeps this allocation-free per
    // key; cost is 256 * len byte operations (≤ 256 MiB at the 1 MiB cap).
    let mut buf: Vec<u8> = Vec::with_capacity(data.len());
    let mut scored: Vec<(u8, CompositeScore, String)> = Vec::with_capacity(256);
    for key in 0..=255u8 {
        buf.clear();
        buf.extend(data.iter().map(|b| b ^ key));
        let score = CompositeScore::of(&buf);
        let preview = preview_text(&buf, PREVIEW_MAX);
        scored.push((key, score, preview));
    }

    // Deterministic order: score descending, then ascending key byte as the
    // tie-breaker.
    scored.sort_by(|a, b| {
        b.1.score
            .total_cmp(&a.1.score)
            .then_with(|| a.0.cmp(&b.0))
    });

    let runner_up_gap = scored
        .get(1)
        .map(|(_, s, _)| scored[0].1.score - s.score);
    let tie = runner_up_gap.is_some_and(|gap| gap == 0.0);

    let best_score = scored[0].1.score;
    let confident = best_score >= options.confidence_threshold;
    let best_key = confident.then_some(scored[0].0);

    let candidates = scored
        .iter()
        .take(options.top_n)
        .map(|(key, s, preview)| SingleByteCandidate {
            key: *key,
            key_hex: format!("0x{key:02x}"),
            score: s.score,
            confidence: Confidence::from_score(s.score),
            preview: preview.clone(),
            printable_ratio: s.printable,
            letter_ratio: s.letter_ratio,
            chi_square_per_letter: s.chi_per_letter,
            valid_utf8: s.valid_utf8,
            flag_pattern: s.flag_pattern.clone(),
            evidence: evidence_lines(s),
        })
        .collect();

    Ok(SingleByteCrackResult {
        confident,
        best_key,
        best_key_hex: best_key.map(|k| format!("0x{k:02x}")),
        best_score,
        best_confidence: Confidence::from_score(best_score),
        runner_up_gap,
        tie,
        input_len: data.len(),
        confidence_threshold: options.confidence_threshold,
        candidates,
    })
}

/// Build the per-candidate evidence strings from a composite score.
pub(crate) fn evidence_lines(s: &CompositeScore) -> Vec<String> {
    let mut evidence = Vec::with_capacity(5);
    evidence.push(format!("printable {:.1}%", s.printable * 100.0));
    evidence.push(format!("ASCII letters {:.1}% of bytes", s.letter_ratio * 100.0));
    match s.chi_per_letter {
        Some(chi) => evidence.push(format!("English chi2/letter {chi:.3}")),
        None => evidence.push("no ASCII letters to score".to_string()),
    }
    evidence.push(
        if s.valid_utf8 {
            "valid UTF-8 (sampled prefix)"
        } else {
            "not valid UTF-8"
        }
        .to_string(),
    );
    if let Some(token) = &s.flag_pattern {
        evidence.push(format!("flag-like token \"{token}\""));
    }
    evidence
}

fn validate_input(data: &[u8]) -> Result<(), OperationError> {
    if data.is_empty() {
        return Err(
            OperationError::invalid_input("cannot crack an empty ciphertext")
                .with_parameter("ciphertext")
                .with_expected(format!("1..={MAX_INPUT_BYTES} bytes"))
                .with_actual("0 bytes"),
        );
    }
    if data.len() > MAX_INPUT_BYTES {
        return Err(OperationError::invalid_input(
            "ciphertext exceeds the analysis bound",
        )
        .with_parameter("ciphertext")
        .with_expected(format!("at most {MAX_INPUT_BYTES} bytes (1 MiB)"))
        .with_actual(format!("{} bytes", data.len())));
    }
    Ok(())
}

fn validate_options(options: &SingleByteOptions) -> Result<(), OperationError> {
    if options.top_n == 0 || options.top_n > MAX_TOP_N {
        return Err(OperationError::invalid_param(
            "top_n",
            format!("top_n must be in 1..={MAX_TOP_N}"),
        )
        .with_expected(format!("1..={MAX_TOP_N}"))
        .with_actual(options.top_n.to_string()));
    }
    if !(0.0..=1.0).contains(&options.confidence_threshold) {
        return Err(OperationError::invalid_param(
            "confidence_threshold",
            "confidence_threshold must be within 0.0..=1.0",
        )
        .with_expected("0.0..=1.0")
        .with_actual(options.confidence_threshold.to_string()));
    }
    Ok(())
}
