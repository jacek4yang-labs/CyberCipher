//! Crib dragging: slide a guessed plaintext fragment through every offset of
//! an XOR ciphertext and surface the offsets where the recovered fragment is
//! printable.
//!
//! With `c = p1 ^ p2` (a two-time pad), dragging a guess for `p1` over the
//! ciphertext recovers candidate fragments of `p2`; with a single-message
//! known-plaintext view, the same bytes are the key fragment
//! `c ^ crib`. Both interpretations produce byte-identical values, so the
//! result carries the fragment (the printable candidate) and the key fragment
//! side by side; which one is "the key" depends on the attack scenario.
//!
//! Ranking is by the English composite score of the fragment, then by offset
//! — deterministic, with the true alignment typically scoring well above
//! accidental printable hits.

use super::scoring::{is_printable_byte, CompositeScore, Confidence};
use super::{MAX_CRIB_BYTES, MAX_INPUT_BYTES, MAX_TOP_N};
use cybercipher_core::error::OperationError;
use serde::{Deserialize, Serialize};

/// Options for [`crib_drag`].
#[derive(Debug, Clone, PartialEq)]
pub struct CribDragOptions {
    /// How many ranked hits to return (1..=[`MAX_TOP_N`]). Default: 50.
    pub top_n: usize,
}

impl Default for CribDragOptions {
    fn default() -> Self {
        Self { top_n: 50 }
    }
}

/// One printable alignment found by [`crib_drag`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CribDragHit {
    /// Ciphertext offset where the crib was placed.
    pub position: usize,
    /// The recovered fragment (printable by construction), bounded to the
    /// crib length (≤ [`MAX_CRIB_BYTES`] bytes).
    pub fragment: String,
    /// Key fragment `cipher[position..position + crib_len] ^ crib` — the
    /// bytes that map the ciphertext slice onto the crib (identical to the
    /// recovered fragment; kept explicitly for the known-plaintext view).
    pub key_fragment: Vec<u8>,
    /// The key fragment as lowercase hex.
    pub key_fragment_hex: String,
    /// English composite score of the fragment.
    pub score: f64,
    /// Qualitative label for `score`.
    pub confidence: Confidence,
}

/// Outcome of [`crib_drag`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CribDragResult {
    /// The crib that was dragged (as given).
    pub crib: String,
    /// Crib length in bytes.
    pub crib_len: usize,
    /// Printable hits, ranked by fragment score then position.
    pub hits: Vec<CribDragHit>,
    /// Number of offsets tried (`input_len - crib_len + 1`).
    pub positions_tried: usize,
    /// Ciphertext length in bytes.
    pub input_len: usize,
}

/// Drag `crib` through every offset of `data` and return the alignments whose
/// recovered fragment is fully printable, ranked by English plausibility.
///
/// A garbage crib honestly yields an empty hit list — no alignment is forced.
/// Errors are typed: empty input or input over [`MAX_INPUT_BYTES`], an empty
/// crib, a crib longer than [`MAX_CRIB_BYTES`] or than the ciphertext, or an
/// out-of-range `top_n`.
pub fn crib_drag(
    data: &[u8],
    crib: &str,
    options: &CribDragOptions,
) -> Result<CribDragResult, OperationError> {
    if data.is_empty() {
        return Err(
            OperationError::invalid_input("cannot drag a crib over an empty ciphertext")
                .with_parameter("ciphertext")
                .with_expected(format!("1..={MAX_INPUT_BYTES} bytes"))
                .with_actual("0 bytes"),
        );
    }
    if data.len() > MAX_INPUT_BYTES {
        return Err(
            OperationError::invalid_input("ciphertext exceeds the analysis bound")
                .with_parameter("ciphertext")
                .with_expected(format!("at most {MAX_INPUT_BYTES} bytes (1 MiB)"))
                .with_actual(format!("{} bytes", data.len())),
        );
    }
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
    if crib_bytes.len() > data.len() {
        return Err(
            OperationError::invalid_input("crib is longer than the ciphertext")
                .with_parameter("crib")
                .with_expected(format!("crib of at most {} bytes", data.len()))
                .with_actual(format!("{} bytes", crib_bytes.len())),
        );
    }
    if options.top_n == 0 || options.top_n > MAX_TOP_N {
        return Err(OperationError::invalid_param(
            "top_n",
            format!("top_n must be in 1..={MAX_TOP_N}"),
        )
        .with_expected(format!("1..={MAX_TOP_N}"))
        .with_actual(options.top_n.to_string()));
    }

    let positions_tried = data.len() - crib_bytes.len() + 1;
    let mut hits: Vec<CribDragHit> = Vec::new();
    for position in 0..positions_tried {
        let slice = &data[position..position + crib_bytes.len()];
        let fragment: Vec<u8> = slice.iter().zip(crib_bytes).map(|(c, p)| c ^ p).collect();
        if !fragment.iter().all(|&b| is_printable_byte(b)) {
            continue;
        }
        let score = CompositeScore::of(&fragment).score;
        hits.push(CribDragHit {
            position,
            fragment: String::from_utf8_lossy(&fragment).into_owned(),
            key_fragment: fragment.clone(),
            key_fragment_hex: fragment.iter().map(|b| format!("{b:02x}")).collect(),
            score,
            confidence: Confidence::from_score(score),
        });
    }

    hits.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.position.cmp(&b.position))
    });
    hits.truncate(options.top_n);

    Ok(CribDragResult {
        crib: crib.to_string(),
        crib_len: crib_bytes.len(),
        hits,
        positions_tried,
        input_len: data.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drag_finds_known_alignment() {
        let plaintext = b"attack at dawn, the fleet moves at noon";
        let key = 0x37u8;
        let cipher: Vec<u8> = plaintext.iter().map(|b| b ^ key).collect();
        let result = crib_drag(&cipher, "the ", &CribDragOptions::default()).unwrap();
        assert!(result
            .hits
            .iter()
            .any(|h| h.fragment == "the " && h.key_fragment.iter().all(|&b| b == key)));
    }

    #[test]
    fn garbage_crib_yields_empty_hits() {
        let cipher: Vec<u8> = b"ordinary english text".iter().map(|b| b ^ 0x37).collect();
        // High-bit crib bytes against ASCII ciphertext can never be printable.
        let result = crib_drag(&cipher, "\u{41f}\u{41f}", &CribDragOptions::default()).unwrap();
        assert!(result.hits.is_empty());
        assert!(result.positions_tried > 0);
    }
}
