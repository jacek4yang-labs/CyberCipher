//! Multi-time-pad (MTP) breaking: several ciphertexts XORed with the *same*
//! unknown key (the classic one-time-pad reuse).
//!
//! The key length equals the message length, so each **position** `i` is a
//! column of its own: `c_j[i] ^ k = p_j[i]` for every ciphertext `j`. The
//! per-position attack scores each of the 256 key bytes by summing a compact
//! byte-level English likelihood over *all* ciphertexts at that position —
//! much stronger than any single-ciphertext signal, and stronger the more
//! ciphertexts are available (2 is the floor, 6+ is recommended).
//!
//! **Iterative refinement**: positions with low confidence are revisited with
//! crib seeding — the word `"the "` is slid over the first ciphertext and any
//! derived key byte that scores strictly better than the current choice (and
//! only at low-confidence positions) is adopted. This can only improve the
//! model score, and the adopted-vs-initial source is reported per position.
//!
//! Every position carries its own confidence (printable fraction of the
//! decrypted column times a margin term), so the result never pretends to be
//! more certain than the evidence; positions that stay weak are visible in
//! the per-position map.

use super::scoring::is_printable_byte;
use super::{
    MAX_INPUT_BYTES, MTP_KEY_PREVIEW_BYTES, MTP_MAX_CIPHERTEXTS, MTP_MAX_MESSAGE_BYTES,
    MTP_MIN_CIPHERTEXTS, MTP_RECOMMENDED_CIPHERTEXTS,
};
use cybercipher_core::error::OperationError;
use serde::{Deserialize, Serialize};

/// Confidence below which a position becomes eligible for crib-seed refinement.
pub const REFINE_CONFIDENCE: f64 = 0.6;

/// The crib used for iterative refinement ("the " is the most common English
/// trigram-plus-space anchor).
pub const REFINE_CRIB: &[u8; 4] = b"the ";

/// How a position's key byte was determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MtpKeySource {
    /// Plain per-position likelihood over all ciphertexts.
    Likelihood,
    /// Adopted during `"the "` crib-seed refinement.
    CribSeed,
}

/// Per-position recovery state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MtpPosition {
    /// Position within the messages (0-based).
    pub position: usize,
    /// Recovered key byte at this position.
    pub key: u8,
    /// The key byte as `0xNN` hex.
    pub key_hex: String,
    /// Confidence in `0.0..=1.0`: printable fraction of the decrypted column
    /// times `margin / (margin + 1)`.
    pub confidence: f64,
    /// Fraction of ciphertexts whose byte decrypts to printable ASCII at
    /// this position with the recovered key.
    pub printable_fraction: f64,
    /// How the key byte was determined.
    pub source: MtpKeySource,
}

/// Outcome of [`mtp_break`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MtpBreakResult {
    /// Recovered key (one byte per message position).
    pub key: Vec<u8>,
    /// The full key as lowercase hex (can be long — it is the payload, not a
    /// preview; see `key_hex_preview` for a bounded rendering).
    pub key_hex: String,
    /// Bounded preview of the key hex (first [`MTP_KEY_PREVIEW_BYTES`] bytes,
    /// `...`-terminated when truncated).
    pub key_hex_preview: String,
    /// Key length (== message length).
    pub key_len: usize,
    /// All decrypted messages, in input order (lossy UTF-8).
    pub texts: Vec<String>,
    /// Per-position confidence map, in position order.
    pub positions: Vec<MtpPosition>,
    /// Mean per-position confidence.
    pub avg_confidence: f64,
    /// Number of positions with confidence >= 0.6.
    pub confident_positions: usize,
    /// Number of ciphertexts analyzed.
    pub ciphertext_count: usize,
    /// Message length in bytes.
    pub message_len: usize,
    /// Advisory note — set when fewer than
    /// [`MTP_RECOMMENDED_CIPHERTEXTS`] ciphertexts were provided.
    pub note: Option<String>,
}

/// Break a multi-time pad: `ciphertexts[j] = plaintexts[j] ^ key` for one
/// shared, unknown `key`. All ciphertexts must have the same length.
///
/// Honest failure modes are typed errors: fewer than
/// [`MTP_MIN_CIPHERTEXTS`] ciphertexts (6+ recommended), more than
/// [`MTP_MAX_CIPHERTEXTS`], zero-length or over-length messages
/// ([`MTP_MAX_MESSAGE_BYTES`]), or mismatched message lengths.
pub fn mtp_break(ciphertexts: &[Vec<u8>]) -> Result<MtpBreakResult, OperationError> {
    if ciphertexts.len() < MTP_MIN_CIPHERTEXTS {
        return Err(OperationError::invalid_input(
            "too few ciphertexts for multi-time-pad analysis: reusing the same key across \
             messages is only breakable with several samples",
        )
        .with_parameter("ciphertexts")
        .with_expected(format!(
            "at least {MTP_MIN_CIPHERTEXTS} same-length ciphertexts ({MTP_RECOMMENDED_CIPHERTEXTS}+ recommended)"
        ))
        .with_actual(format!("{} ciphertext(s)", ciphertexts.len())));
    }
    if ciphertexts.len() > MTP_MAX_CIPHERTEXTS {
        return Err(OperationError::invalid_param(
            "ciphertexts",
            format!("more than {MTP_MAX_CIPHERTEXTS} ciphertexts is not supported"),
        )
        .with_expected(format!("at most {MTP_MAX_CIPHERTEXTS} ciphertexts"))
        .with_actual(ciphertexts.len().to_string()));
    }
    let message_len = ciphertexts[0].len();
    if message_len == 0 {
        return Err(OperationError::invalid_input(
            "ciphertexts must not be empty",
        )
        .with_parameter("ciphertexts")
        .with_expected("at least 1 byte per ciphertext")
        .with_actual("0 bytes"));
    }
    if message_len > MTP_MAX_MESSAGE_BYTES {
        return Err(OperationError::invalid_param(
            "ciphertexts",
            format!("messages exceed the {MTP_MAX_MESSAGE_BYTES}-byte analysis bound"),
        )
        .with_expected(format!("at most {MTP_MAX_MESSAGE_BYTES} bytes per message"))
        .with_actual(format!("{message_len} bytes")));
    }
    for (j, c) in ciphertexts.iter().enumerate().skip(1) {
        if c.len() != message_len {
            return Err(OperationError::length(
                format!("len(ciphertexts[0]) = {message_len} bytes"),
                format!("ciphertexts[{j}] has {} bytes", c.len()),
                "multi-time-pad ciphertexts must all have the same length",
            )
            .with_parameter("ciphertexts"));
        }
    }

    let n = ciphertexts.len();
    let mut key = vec![0u8; message_len];
    let mut states: Vec<PositionState> = (0..message_len)
        .map(|pos| {
            let column: Vec<u8> = ciphertexts.iter().map(|c| c[pos]).collect();
            PositionState::from_column(&column)
        })
        .collect();

    refine_with_crib_seeding(ciphertexts, &mut states);

    let mut positions = Vec::with_capacity(message_len);
    for (pos, state) in states.iter().enumerate() {
        key[pos] = state.key;
        positions.push(MtpPosition {
            position: pos,
            key: state.key,
            key_hex: format!("0x{:02x}", state.key),
            confidence: state.confidence(),
            printable_fraction: state.printable_fraction,
            source: state.source,
        });
    }

    let texts: Vec<String> = ciphertexts
        .iter()
        .map(|c| {
            let plain: Vec<u8> = c.iter().zip(&key).map(|(b, k)| b ^ k).collect();
            String::from_utf8_lossy(&plain).into_owned()
        })
        .collect();

    let avg_confidence =
        positions.iter().map(|p| p.confidence).sum::<f64>() / positions.len().max(1) as f64;
    let confident_positions = positions
        .iter()
        .filter(|p| p.confidence >= REFINE_CONFIDENCE)
        .count();
    let note = (n < MTP_RECOMMENDED_CIPHERTEXTS).then(|| {
        format!(
            "only {n} ciphertexts provided; {MTP_RECOMMENDED_CIPHERTEXTS} or more give \
             much stronger per-position recovery"
        )
    });

    let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    let preview_len = key.len().min(MTP_KEY_PREVIEW_BYTES);
    let key_hex_preview = if key.len() > preview_len {
        format!("{}...", &key_hex[..preview_len * 2])
    } else {
        key_hex.clone()
    };

    Ok(MtpBreakResult {
        key_len: message_len,
        key,
        key_hex,
        key_hex_preview,
        texts,
        positions,
        avg_confidence,
        confident_positions,
        ciphertext_count: n,
        message_len,
        note,
    })
}

/// Working state for one position: best and second-best key by total
/// likelihood, with the printable fraction of the best decryption.
struct PositionState {
    key: u8,
    best_total: f64,
    second_total: f64,
    printable_fraction: f64,
    source: MtpKeySource,
}

impl PositionState {
    /// Score all 256 candidate keys over the column (one byte per
    /// ciphertext) and keep the top two. Ties break toward the smaller key.
    fn from_column(column: &[u8]) -> Self {
        let mut best_key = 0u8;
        let mut best_total = f64::NEG_INFINITY;
        let mut second_total = f64::NEG_INFINITY;
        for k in 0..=255u8 {
            let total: f64 = column.iter().map(|&c| byte_likelihood(c ^ k)).sum();
            if total > best_total {
                second_total = best_total;
                best_total = total;
                best_key = k;
            } else if total > second_total {
                second_total = total;
            }
        }
        let printable_fraction = printable_fraction_for(column, best_key);
        Self {
            key: best_key,
            best_total,
            second_total,
            printable_fraction,
            source: MtpKeySource::Likelihood,
        }
    }

    /// Confidence of the current choice: printable fraction times a saturating
    /// margin term.
    fn confidence(&self) -> f64 {
        let margin = (self.best_total - self.second_total).max(0.0);
        self.printable_fraction * (margin / (margin + 1.0))
    }

    /// Re-evaluate a candidate key against the column; adopt it when it beats
    /// the current best (refinement may only improve the model score).
    fn try_adopt(&mut self, column: &[u8], candidate: u8) {
        if candidate == self.key {
            return;
        }
        let total: f64 = column.iter().map(|&c| byte_likelihood(c ^ candidate)).sum();
        if total <= self.best_total {
            return;
        }
        // The old best becomes the runner-up.
        self.second_total = self.best_total;
        self.best_total = total;
        self.key = candidate;
        self.printable_fraction = printable_fraction_for(column, candidate);
        self.source = MtpKeySource::CribSeed;
    }
}

/// Fraction of the column that decrypts to printable bytes under `k`.
fn printable_fraction_for(column: &[u8], k: u8) -> f64 {
    let printable = column
        .iter()
        .filter(|&&c| is_printable_byte(c ^ k))
        .count();
    printable as f64 / column.len() as f64
}

/// Compact English byte likelihood for one decrypted byte (ad-hoc units):
/// spaces score highest (they dominate English text), then lowercase letters,
/// uppercase, digits, punctuation; non-printable bytes are penalized.
fn byte_likelihood(b: u8) -> f64 {
    match b {
        b' ' => 2.0,
        b'a'..=b'z' => 1.0,
        b'A'..=b'Z' => 0.8,
        b'0'..=b'9' => 0.4,
        b'\n' | b'\r' | b'\t' => 0.3,
        b'.' | b',' | b'\'' | b'"' | b'!' | b'?' | b';' | b':' | b'-' | b'(' | b')' => 0.3,
        _ if (0x20..=0x7E).contains(&b) => 0.0,
        _ => -1.5,
    }
}

/// Slide [`REFINE_CRIB`] over the first ciphertext; wherever the derived key
/// bytes beat the current choice at low-confidence positions, adopt them.
fn refine_with_crib_seeding(ciphertexts: &[Vec<u8>], states: &mut [PositionState]) {
    let message_len = ciphertexts[0].len();
    if message_len < REFINE_CRIB.len() {
        return;
    }
    let anchor = &ciphertexts[0];
    for offset in 0..=(message_len - REFINE_CRIB.len()) {
        for (i, &crib_byte) in REFINE_CRIB.iter().enumerate() {
            let pos = offset + i;
            if states[pos].confidence() >= REFINE_CONFIDENCE {
                continue;
            }
            let candidate = anchor[pos] ^ crib_byte;
            if candidate == states[pos].key {
                continue;
            }
            let column: Vec<u8> = ciphertexts.iter().map(|c| c[pos]).collect();
            states[pos].try_adopt(&column, candidate);
        }
    }
}

// Keep the input bound referenced from the shared module constants so bounds
// stay documented in one place; MTP messages are additionally capped by
// MTP_MAX_MESSAGE_BYTES (which is stricter than MAX_INPUT_BYTES).
const _: () = assert!(MTP_MAX_MESSAGE_BYTES <= MAX_INPUT_BYTES);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn space_beats_everything_and_garbage_is_penalized() {
        assert!(byte_likelihood(b' ') > byte_likelihood(b'e'));
        assert!(byte_likelihood(b'e') > byte_likelihood(b'E'));
        assert!(byte_likelihood(b'E') > byte_likelihood(b'!'));
        assert!(byte_likelihood(b'!') > byte_likelihood(0xFF));
        assert!(byte_likelihood(0xFF) < 0.0);
    }

    #[test]
    fn column_scoring_prefers_the_key_that_yields_english() {
        let key = 0x2Eu8;
        // Plain English words XORed with one byte: the correct key must win.
        let column: Vec<u8> = b"the quick".iter().map(|b| b ^ key).collect();
        let state = PositionState::from_column(&column);
        assert_eq!(state.key, key);
        assert_eq!(state.printable_fraction, 1.0);
    }
}
