//! Key-length estimation for repeating-key XOR.
//!
//! For each candidate length `L` in `1..=max_length` two independent
//! statistics are computed and combined into one ranking score:
//!
//! * **Index of coincidence (IOC)** — the ciphertext is split into `L`
//!   columns (positions `i ≡ j (mod L)`); each column was XORed with a single
//!   key byte, so a correct `L` gives every column the peaked byte
//!   distribution of English text (IOC ≈ 0.066) while a wrong `L` mixes
//!   several key bytes and flattens it (IOC → ~0.004). Reported as the mean
//!   over columns.
//! * **Normalized Hamming distance (Friedman-style)** — mean popcount of the
//!   XOR between consecutive `L`-byte blocks, divided by `L`. English text
//!   XORed at the correct period differs by fewer flipped bits (~2.5-3.5)
//!   than random-looking bytes (~4+).
//!
//! The ranking score is `avg_ioc / avg_hamming_distance` (high IOC and low
//! Hamming distance are both good). **Parsimony promotion**: every multiple
//! of the true key length inherits its high IOC, so the smallest candidate
//! whose score is within [`PARSIMONY_RATIO`] of the best score is promoted to
//! the top rank; the remaining candidates follow by score. This selects the
//! true length over its multiples without hiding them — all candidates with
//! their raw statistics are still returned.
//!
//! A degenerate input (e.g. a *single*-byte XOR ciphertext) scores similarly
//! at every length; this is reported in [`KeyLengthResult::note`] rather than
//! hidden.

use super::{MAX_INPUT_BYTES, MAX_KEY_LENGTH, MAX_TOP_N, MIN_KEYLEN_SAMPLE};
use cybercipher_core::error::OperationError;
use serde::{Deserialize, Serialize};

/// Consecutive block pairs sampled for the Hamming statistic (the mean is
/// over the first `N` pairs, keeping cost bounded at the 1 MiB input cap).
pub const HAMMING_PAIR_SAMPLE: usize = 256;

/// Fraction of the best score a candidate must reach to be promoted by
/// parsimony (smallest such length wins over its multiples).
pub const PARSIMONY_RATIO: f64 = 0.85;

/// Relative spread below which all lengths are considered to score
/// "similarly" (single-byte-key degenerate case).
const SIMILARITY_SPREAD: f64 = 0.15;

/// One ranked candidate key length with its raw statistics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyLengthCandidate {
    /// Candidate key length in bytes.
    pub key_length: usize,
    /// Mean index of coincidence over the `L` columns.
    pub avg_ioc: f64,
    /// Mean normalized Hamming distance between consecutive `L`-byte blocks
    /// (bits per byte).
    pub avg_hamming_distance: f64,
    /// Combined ranking score: `avg_ioc / avg_hamming_distance`.
    pub score: f64,
}

/// Outcome of [`estimate_key_length`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyLengthResult {
    /// The promoted best guess: the smallest length within
    /// [`PARSIMONY_RATIO`] of the best raw score.
    pub best_key_length: usize,
    /// Raw score of the promoted candidate.
    pub best_score: f64,
    /// Ranked candidates (promoted candidate first, then by score
    /// descending, length ascending), at most `top_n`.
    pub candidates: Vec<KeyLengthCandidate>,
    /// Largest candidate length that was evaluated.
    pub max_key_length_tried: usize,
    /// Input length in bytes.
    pub input_len: usize,
    /// Set when the statistics are degenerate — e.g. all lengths scoring
    /// similarly, which points at a single-byte (or very short) key.
    pub note: Option<String>,
}

/// Options for [`estimate_key_length`].
#[derive(Debug, Clone, PartialEq)]
pub struct KeyLengthOptions {
    /// Largest candidate length to evaluate (1..=[`MAX_KEY_LENGTH`]).
    /// Default: [`MAX_KEY_LENGTH`].
    pub max_length: usize,
    /// How many ranked candidates to return (1..=[`MAX_TOP_N`]). Default: 5.
    pub top_n: usize,
}

impl Default for KeyLengthOptions {
    fn default() -> Self {
        Self {
            max_length: MAX_KEY_LENGTH,
            top_n: 5,
        }
    }
}

/// Estimate the repeating-key XOR key length of `data` by index of
/// coincidence plus normalized Hamming distance, for candidate lengths
/// `1..=options.max_length`.
///
/// Errors are typed: input below [`MIN_KEYLEN_SAMPLE`] bytes or above
/// [`MAX_INPUT_BYTES`], or an invalid `options` (`max_length` outside
/// `1..=[`MAX_KEY_LENGTH`]`, zero/oversized `top_n`).
pub fn estimate_key_length(
    data: &[u8],
    options: &KeyLengthOptions,
) -> Result<KeyLengthResult, OperationError> {
    if data.len() < MIN_KEYLEN_SAMPLE {
        return Err(OperationError::invalid_input(
            "input too short for key-length estimation",
        )
        .with_parameter("ciphertext")
        .with_expected(format!("at least {MIN_KEYLEN_SAMPLE} bytes"))
        .with_actual(format!("{} bytes", data.len())));
    }
    if data.len() > MAX_INPUT_BYTES {
        return Err(OperationError::invalid_input(
            "input exceeds the analysis bound",
        )
        .with_parameter("ciphertext")
        .with_expected(format!("at most {MAX_INPUT_BYTES} bytes (1 MiB)"))
        .with_actual(format!("{} bytes", data.len())));
    }
    if options.max_length == 0 || options.max_length > MAX_KEY_LENGTH {
        return Err(OperationError::invalid_param(
            "max_length",
            format!("max_length must be in 1..={MAX_KEY_LENGTH}"),
        )
        .with_expected(format!("1..={MAX_KEY_LENGTH}"))
        .with_actual(options.max_length.to_string()));
    }
    if options.top_n == 0 || options.top_n > MAX_TOP_N {
        return Err(OperationError::invalid_param(
            "top_n",
            format!("top_n must be in 1..={MAX_TOP_N}"),
        )
        .with_expected(format!("1..={MAX_TOP_N}"))
        .with_actual(options.top_n.to_string()));
    }

    let mut candidates: Vec<KeyLengthCandidate> = Vec::new();
    for l in 1..=options.max_length {
        // Each column needs at least 2 bytes for a meaningful IOC.
        if data.len() < 2 * l {
            break;
        }
        let avg_ioc = mean_column_ioc(data, l);
        let avg_hamming = mean_hamming(data, l);
        let score = avg_ioc / avg_hamming.max(1e-9);
        candidates.push(KeyLengthCandidate {
            key_length: l,
            avg_ioc,
            avg_hamming_distance: avg_hamming,
            score,
        });
    }
    debug_assert!(!candidates.is_empty(), "len >= 32 admits length 1");

    // Parsimony: multiples of the true length inherit its high IOC. Promote
    // the smallest candidate within PARSIMONY_RATIO of the best raw score.
    let max_score = candidates
        .iter()
        .map(|c| c.score)
        .fold(f64::NEG_INFINITY, f64::max);
    let promote_at = max_score * PARSIMONY_RATIO;
    let winner_idx = candidates
        .iter()
        .position(|c| c.score >= promote_at)
        .unwrap_or(0);
    let winner = candidates.remove(winner_idx);

    // Remaining candidates follow by score descending, length ascending.
    candidates.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.key_length.cmp(&b.key_length))
    });

    let min_score = candidates
        .iter()
        .map(|c| c.score)
        .fold(f64::INFINITY, f64::min)
        .min(winner.score);
    let spread = if max_score > 0.0 {
        (max_score - min_score) / max_score
    } else {
        0.0
    };
    let note = (spread < SIMILARITY_SPREAD).then(|| {
        "all key lengths score similarly: the data is consistent with a single-byte \
         key (or a key no longer than the text structure reveals)"
            .to_string()
    });

    let best_key_length = winner.key_length;
    let best_score = winner.score;
    let mut ranked = Vec::with_capacity(candidates.len() + 1);
    ranked.push(winner);
    ranked.extend(candidates);
    ranked.truncate(options.top_n);

    Ok(KeyLengthResult {
        best_key_length,
        best_score,
        candidates: ranked,
        max_key_length_tried: options.max_length,
        input_len: data.len(),
        note,
    })
}

/// Mean index of coincidence over the `L` columns of `data`.
fn mean_column_ioc(data: &[u8], l: usize) -> f64 {
    let mut total_ioc = 0.0;
    for col in 0..l {
        let mut freq = [0u64; 256];
        let mut n = 0usize;
        for i in (col..data.len()).step_by(l) {
            freq[data[i] as usize] += 1;
            n += 1;
        }
        if n < 2 {
            continue;
        }
        let coincidences: u64 = freq.iter().map(|&c| c * (c.saturating_sub(1))).sum();
        total_ioc += coincidences as f64 / (n as f64 * (n as f64 - 1.0));
    }
    total_ioc / l as f64
}

/// Mean normalized Hamming distance (popcount of XOR per byte) between
/// consecutive `L`-byte blocks, sampled over the first [`HAMMING_PAIR_SAMPLE`]
/// pairs. Callers guarantee `data.len() >= 2 * l`, so at least one pair exists.
fn mean_hamming(data: &[u8], l: usize) -> f64 {
    let total_pairs = data.len() / l;
    debug_assert!(total_pairs >= 2, "candidate admitted only with 2*l bytes");
    let pairs = (total_pairs - 1).min(HAMMING_PAIR_SAMPLE);
    let mut sum = 0u64;
    for t in 0..pairs {
        let a = &data[t * l..(t + 1) * l];
        let b = &data[(t + 1) * l..(t + 2) * l];
        let bits: u32 = a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum();
        sum += bits as u64;
    }
    sum as f64 / (pairs as f64 * l as f64)
}
