//! Repeating-key XOR cracking: given (or estimated) key length `L`, split the
//! ciphertext into `L` columns, run a position-wise single-byte crack on each
//! column, and assemble the full key with per-column evidence.
//!
//! Each column of a repeating-key XOR ciphertext is a single-byte XOR of a
//! slice of the plaintext — so every column is scored across all 256 key
//! bytes with the same English model used by [`super::single`], and the top-3
//! keys per column plus the margin to the runner-up are reported as evidence.
//!
//! A known **crib** locks columns: every crib byte at absolute plaintext
//! position `p` implies key byte `cipher[p] ^ crib[p - offset]` for column
//! `p mod L`. If two crib positions in the same column imply different key
//! bytes, the crib is inconsistent with the key length at that offset and a
//! typed error names both conflicting keys. Locked columns are marked in the
//! evidence; when a locked key disagrees with the best-scoring key the
//! disagreement is reported rather than hidden.

use super::scoring::{preview_text, CompositeScore, Confidence, PREVIEW_MAX};
use super::{MAX_CRIB_BYTES, MAX_INPUT_BYTES, MAX_KEY_LENGTH};
use cybercipher_core::error::OperationError;
use serde::{Deserialize, Serialize};

/// Score threshold a column's chosen key must reach for the overall crack to
/// count as confident. Columns are shorter than whole messages, so this is
/// deliberately lower than the single-byte default.
pub const REPEAT_COLUMN_THRESHOLD: f64 = 0.50;

/// Evidence kept per column: the top keys by score.
pub const COLUMN_TOP_KEYS: usize = 3;

/// Options for [`crack_repeating_key`].
#[derive(Debug, Clone, PartialEq)]
pub struct RepeatingOptions {
    /// Known plaintext assumed to sit at `crib_offset` in the plaintext.
    /// Crib bytes lock their columns to the implied key byte. Default: none.
    pub crib: Option<String>,
    /// Absolute plaintext offset the crib starts at. Default: 0.
    pub crib_offset: usize,
    /// Minimum column score for an unlocked column to count as confident.
    /// Default: [`REPEAT_COLUMN_THRESHOLD`].
    pub confidence_threshold: f64,
}

impl Default for RepeatingOptions {
    fn default() -> Self {
        Self {
            crib: None,
            crib_offset: 0,
            confidence_threshold: REPEAT_COLUMN_THRESHOLD,
        }
    }
}

/// One alternative key byte for a column, kept as evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ColumnKeyCandidate {
    /// Candidate key byte.
    pub key: u8,
    /// The key as `0xNN` hex.
    pub key_hex: String,
    /// Composite score of the column decrypted with this key.
    pub score: f64,
}

/// Per-column evidence for [`crack_repeating_key`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ColumnEvidence {
    /// Column index (0-based; column `c` holds positions `p ≡ c (mod L)`).
    pub column: usize,
    /// The chosen key byte for this column (crib-locked or best-scoring).
    pub key_byte: u8,
    /// The chosen key as `0xNN` hex.
    pub key_hex: String,
    /// Composite score of the chosen key.
    pub score: f64,
    /// Qualitative label for `score`.
    pub confidence: Confidence,
    /// Gap between the chosen key's score and the best alternative score.
    pub margin: f64,
    /// Bytes scored in this column.
    pub sample_len: usize,
    /// `true` when the key byte was derived from the crib, not from scoring.
    pub locked_by_crib: bool,
    /// Top keys by score (up to [`COLUMN_TOP_KEYS`]), regardless of locking.
    pub top_keys: Vec<ColumnKeyCandidate>,
    /// Human-readable evidence lines.
    pub evidence: Vec<String>,
}

/// Outcome of [`crack_repeating_key`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepeatingKeyCrackResult {
    /// Recovered key bytes (one per column).
    pub key: Vec<u8>,
    /// The key as lowercase hex.
    pub key_hex: String,
    /// The key as ASCII, when every byte is printable (else `None`).
    pub key_ascii: Option<String>,
    /// Key length (number of columns).
    pub key_length: usize,
    /// Bounded (≤ [`PREVIEW_MAX`] chars), lossy preview of the decryption.
    pub plaintext_preview: String,
    /// Decrypted length in bytes.
    pub plaintext_len: usize,
    /// Per-column evidence, in column order.
    pub columns: Vec<ColumnEvidence>,
    /// Mean composite score across columns.
    pub avg_column_score: f64,
    /// `true` when every unlocked column reaches `confidence_threshold`
    /// (crib-locked columns are ground truth and do not gate this flag).
    pub confident: bool,
    /// The crib that was applied, if any.
    pub crib: Option<String>,
    /// The crib offset that was applied.
    pub crib_offset: usize,
}

/// Crack a repeating-key XOR ciphertext of known key length `L`.
///
/// Splits the ciphertext into `L` columns, scores each across all 256 key
/// bytes with position-wise English scoring, optionally locks columns with a
/// known crib, and assembles the key. Errors are typed: input bounds,
/// key length outside `1..=[`MAX_KEY_LENGTH`]`, ciphertext shorter than the
/// key length, or a crib that is empty, oversized ([`MAX_CRIB_BYTES`]), out
/// of range, or inconsistent with `L` at the given offset.
pub fn crack_repeating_key(
    data: &[u8],
    key_length: usize,
    options: &RepeatingOptions,
) -> Result<RepeatingKeyCrackResult, OperationError> {
    if data.is_empty() {
        return Err(OperationError::invalid_input(
            "cannot crack an empty ciphertext",
        )
        .with_parameter("ciphertext")
        .with_expected(format!("1..={MAX_INPUT_BYTES} bytes"))
        .with_actual("0 bytes"));
    }
    if data.len() > MAX_INPUT_BYTES {
        return Err(OperationError::invalid_input(
            "ciphertext exceeds the analysis bound",
        )
        .with_parameter("ciphertext")
        .with_expected(format!("at most {MAX_INPUT_BYTES} bytes (1 MiB)"))
        .with_actual(format!("{} bytes", data.len())));
    }
    if key_length == 0 || key_length > MAX_KEY_LENGTH {
        return Err(OperationError::invalid_param(
            "key_length",
            format!("key_length must be in 1..={MAX_KEY_LENGTH}"),
        )
        .with_expected(format!("1..={MAX_KEY_LENGTH}"))
        .with_actual(key_length.to_string()));
    }
    if data.len() < key_length {
        return Err(OperationError::invalid_input(
            "ciphertext is shorter than the key length: every column needs at least one byte",
        )
        .with_parameter("key_length")
        .with_expected(format!("ciphertext of at least {key_length} bytes"))
        .with_actual(format!("{} bytes", data.len())));
    }
    if options.crib_offset > data.len() {
        return Err(OperationError::invalid_input(
            "crib_offset is beyond the ciphertext",
        )
        .with_parameter("crib_offset")
        .with_expected(format!("<= {}", data.len()))
        .with_actual(options.crib_offset.to_string()));
    }
    let locked = match &options.crib {
        None => vec![None; key_length],
        Some(crib) => {
            let crib_bytes = crib.as_bytes();
            if crib_bytes.is_empty() {
                return Err(OperationError::invalid_param(
                    "crib",
                    "crib must not be empty",
                ));
            }
            if crib_bytes.len() > MAX_CRIB_BYTES {
                return Err(OperationError::invalid_param(
                    "crib",
                    format!("crib exceeds {MAX_CRIB_BYTES} bytes"),
                )
                .with_expected(format!("at most {MAX_CRIB_BYTES} bytes"))
                .with_actual(format!("{} bytes", crib_bytes.len())));
            }
            if options.crib_offset + crib_bytes.len() > data.len() {
                return Err(OperationError::invalid_input(
                    "crib extends past the end of the ciphertext",
                )
                .with_parameter("crib_offset")
                .with_expected(format!(
                    "crib_offset + crib_len <= {}",
                    data.len()
                ))
                .with_actual(format!(
                    "{} + {}",
                    options.crib_offset,
                    crib_bytes.len()
                )));
            }
            lock_columns(data, crib_bytes, key_length, options.crib_offset)?
        }
    };
    let mut key = vec![0u8; key_length];
    let mut columns = Vec::with_capacity(key_length);
    let mut all_confident = true;

    for col in 0..key_length {
        let column: Vec<u8> = data[col..].iter().step_by(key_length).copied().collect();
        let mut buf: Vec<u8> = Vec::with_capacity(column.len());
        let mut scored: Vec<(u8, f64)> = Vec::with_capacity(256);
        for k in 0..=255u8 {
            buf.clear();
            buf.extend(column.iter().map(|b| b ^ k));
            scored.push((k, CompositeScore::of(&buf).score));
        }
        scored.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        let best_key = scored[0].0;
        let best_score = scored[0].1;
        let (chosen_key, chosen_score, locked_by_crib) = match locked[col] {
            Some(k) => {
                let s = scored
                    .iter()
                    .find(|(cand, _)| *cand == k)
                    .map(|(_, s)| *s)
                    .unwrap_or(0.0);
                (k, s, true)
            }
            None => (best_key, best_score, false),
        };
        // Margin: gap between the chosen key's score and the best score among
        // keys that were *not* chosen (scored is sorted descending, so the
        // first non-chosen entry is the best alternative).
        let best_alternative = scored
            .iter()
            .find(|(cand, _)| *cand != chosen_key)
            .map(|(_, s)| *s)
            .unwrap_or(chosen_score);
        let margin = (chosen_score - best_alternative).max(0.0);

        key[col] = chosen_key;
        let chosen_confidence = Confidence::from_score(chosen_score);
        let mut evidence = Vec::with_capacity(4);
        if locked_by_crib {
            evidence.push("key byte locked by crib".to_string());
            if chosen_key != best_key {
                evidence.push(format!(
                    "note: best-scoring key {} (score {best_score:.4}) differs from the \
                     crib-locked key",
                    format!("0x{best_key:02x}")
                ));
            }
        } else {
            evidence.push(format!("best of 256 keys by score ({best_score:.4})"));
        }
        evidence.push(format!("margin over next alternative: {margin:.4}"));
        evidence.push(format!("{} bytes scored in column", column.len()));
        columns.push(ColumnEvidence {
            column: col,
            key_byte: chosen_key,
            key_hex: format!("0x{chosen_key:02x}"),
            score: chosen_score,
            confidence: chosen_confidence,
            margin,
            sample_len: column.len(),
            locked_by_crib,
            top_keys: scored
                .iter()
                .take(COLUMN_TOP_KEYS)
                .map(|(k, s)| ColumnKeyCandidate {
                    key: *k,
                    key_hex: format!("0x{k:02x}"),
                    score: *s,
                })
                .collect(),
            evidence,
        });
        if !locked_by_crib && chosen_score < options.confidence_threshold {
            all_confident = false;
        }
    }

    let plaintext: Vec<u8> = data
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key_length])
        .collect();
    let avg_column_score =
        columns.iter().map(|c| c.score).sum::<f64>() / columns.len().max(1) as f64;
    let key_ascii = if key.iter().all(|b| super::scoring::is_printable_byte(*b)) {
        Some(key.iter().map(|b| *b as char).collect())
    } else {
        None
    };

    Ok(RepeatingKeyCrackResult {
        key_length,
        key_hex: key.iter().map(|b| format!("{b:02x}")).collect(),
        key,
        key_ascii,
        plaintext_preview: preview_text(&plaintext, PREVIEW_MAX),
        plaintext_len: plaintext.len(),
        columns,
        avg_column_score,
        confident: all_confident,
        crib: options.crib.clone(),
        crib_offset: options.crib_offset,
    })
}

/// Derive the per-column key bytes implied by the crib, erroring on conflict.
fn lock_columns(
    data: &[u8],
    crib: &[u8],
    key_length: usize,
    crib_offset: usize,
) -> Result<Vec<Option<u8>>, OperationError> {
    let mut locked: Vec<Option<u8>> = vec![None; key_length];
    for (i, &c) in crib.iter().enumerate() {
        let p = crib_offset + i;
        let col = p % key_length;
        let k = data[p] ^ c;
        match locked[col] {
            Some(prev) if prev != k => {
                return Err(OperationError::invalid_input(format!(
                    "crib is inconsistent with key length {key_length} at offset \
                     {crib_offset}: column {col} implies both {prev:#04x} and {k:#04x}"
                ))
                .with_parameter("crib")
                .with_details(
                    "the crib bytes disagree on a key byte; try a different offset or \
                     key length, or check the crib text",
                ));
            }
            _ => locked[col] = Some(k),
        }
    }
    Ok(locked)
}
