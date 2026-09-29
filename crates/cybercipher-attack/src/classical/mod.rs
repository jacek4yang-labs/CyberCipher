//! Classical cipher workbench: encode/decode for the standard pencil-and-paper
//! ciphers plus ranked, evidence-carrying statistical attacks against the
//! Vigenere family.
//!
//! Modules:
//!
//! * [`simple`] — Caesar, ROT13/5/18/47, Atbash, Affine.
//! * [`polyalphabetic`] — Vigenere, Autokey, Beaufort, Gronsfeld, Porta.
//! * [`transposition`] — Rail Fence, Columnar, Route (spiral).
//! * [`square`] — Polybius, Playfair, Bifid, Trifid, Four-square, ADFGX,
//!   ADFGVX, Hill.
//! * [`misc`] — Morse, A1Z26, Tap code, Bacon, Braille.
//! * [`cracking`] — index of coincidence, Kasiski examination, ranked Caesar /
//!   Vigenere cracks, substitution frequency hints.
//! * [`scoring`] — English letter/bigram scoring shared by the crackers.
//!
//! House rules (matching the rest of the attack crate): every routine
//! validates preconditions and fails with a typed [`cybercipher_core::error::
//! OperationError`] carrying expected/actual instead of panicking; text inputs
//! are bounded (1 MiB); result structs are serde-serializable with snake_case
//! fields. Letters are normalized to `A`..=`Z` internally — substitution
//! ciphers pass non-letters through untouched and honor
//! [`CaseOptions::preserve_case`]; position-based ciphers (transposition,
//! fractionation squares) operate on letters only and drop non-letters, which
//! is the standard convention for those ciphers and keeps every round-trip
//! deterministic.
//!
//! **Scope note**: cracking scores are tuned for ASCII English text (see
//! [`scoring`]). Non-English plaintext scores honestly low and surfaces as a
//! "no confident candidate" outcome rather than a false positive.

// Documented project decision (.agent/decisions.md): OperationError crosses
// failure paths only; boxing it at every call site was judged not worth the
// churn, so the oversized-Err lint is silenced per module.
#![allow(clippy::result_large_err)]

pub mod cracking;
pub mod polyalphabetic;
pub mod scoring;
pub mod simple;
pub mod square;
pub mod transposition;

pub use cracking::{
    crack_caesar, crack_substitution_lite, crack_vigenere, ioc, kasiski, CaesarCandidate,
    CaesarCrackOptions, CaesarCrackResult, KasiskiCandidate, KasiskiOptions, KasiskiResult,
    ObservedBigram, SubstitutionHintResult, SubstitutionMapping, SubstitutionOptions,
    VigenereCandidate, VigenereColumnEvidence, VigenereCrackOptions, VigenereCrackResult,
};
pub use polyalphabetic::{
    autokey_decode, autokey_encode, beaufort_decode, beaufort_encode, gronsfeld_decode,
    gronsfeld_encode, porta_decode, porta_encode, vigenere_decode, vigenere_encode,
};
pub use scoring::{
    bigram_fit, chi_square_english, english_fit, index_of_coincidence, letter_counts, text_score,
    TextConfidence, COMMON_BIGRAMS, ENGLISH_LETTER_FREQ_PCT, ENGLISH_LETTER_ORDER,
};
pub use simple::{
    affine_check, affine_decode, affine_encode, atbash_decode, atbash_encode, caesar_decode,
    caesar_encode, rot13_decode, rot13_encode, rot18_decode, rot18_encode, rot47_decode,
    rot47_encode, rot5_decode, rot5_encode, AffineCheck, CaseOptions,
};
pub use square::{
    adfgvx_decode, adfgvx_encode, adfgx_decode, adfgx_encode, bifid_decode, bifid_encode,
    foursquare_decode, foursquare_encode, hill_decode, hill_encode, playfair_decode,
    playfair_encode, polybius_decode, polybius_encode, trifid_decode, trifid_encode, AdfgvxOptions,
    AlphabetMode, BifidOptions, FoursquareOptions, HillOptions, PlayfairOptions, PolybiusOptions,
    SquareResult, TrifidOptions,
};
pub use transposition::{
    columnar_decode, columnar_encode, rail_fence_decode, rail_fence_encode, route_decode,
    route_encode, ColumnarOptions, RailFenceOptions, RouteOptions,
};

// ------------------------------------------------------------ bounds ----

/// Hard cap on text input size for all classical routines: 1 MiB.
pub const MAX_TEXT_BYTES: usize = 1_048_576;

/// Hard cap on key input size: 1 KiB. Classical keys are short by nature;
/// anything longer is a mistake and would only slow the crackers down.
pub const MAX_KEY_BYTES: usize = 1024;

/// Upper bound for rail counts / column counts / Hill block sizes.
pub const MAX_TRANSPOSITION_SHAPE: usize = 4096;

/// Upper bound for Bifid/Trifid periods.
pub const MAX_PERIOD: usize = 4096;

/// Bounded text validation applied by every entry point.
pub(crate) fn check_text(text: &str) -> Result<(), cybercipher_core::error::OperationError> {
    use cybercipher_core::error::OperationError;
    if text.len() > MAX_TEXT_BYTES {
        return Err(
            OperationError::invalid_input("input exceeds the analysis bound")
                .with_parameter("text")
                .with_expected(format!("at most {MAX_TEXT_BYTES} bytes (1 MiB)"))
                .with_actual(format!("{} bytes", text.len())),
        );
    }
    Ok(())
}

/// Bounded key validation applied by keyed entry points.
pub(crate) fn check_key(key: &str) -> Result<(), cybercipher_core::error::OperationError> {
    use cybercipher_core::error::OperationError;
    if key.len() > MAX_KEY_BYTES {
        return Err(OperationError::key("key exceeds the accepted length")
            .with_parameter("key")
            .with_expected(format!("at most {MAX_KEY_BYTES} bytes"))
            .with_actual(format!("{} bytes", key.len())));
    }
    Ok(())
}

/// A shared result payload for text transforms: the transformed output plus
/// honest counters of what was consumed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TextResult {
    /// The transformed text.
    pub output: String,
    /// Number of letters transformed.
    pub letters: usize,
    /// Number of characters passed through untouched.
    pub passthrough: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_are_sane() {
        assert_eq!(MAX_TEXT_BYTES, 1_048_576);
        assert_eq!(MAX_KEY_BYTES, 1024);
        assert_eq!(MAX_PERIOD, 4096);
        assert_eq!(MAX_TRANSPOSITION_SHAPE, 4096);
    }

    #[test]
    fn check_text_rejects_oversized_input() {
        let big = "a".repeat(MAX_TEXT_BYTES + 1);
        let err = check_text(&big).unwrap_err();
        assert_eq!(
            err.expected.as_deref(),
            Some("at most 1048576 bytes (1 MiB)")
        );
        assert!(check_text("fine").is_ok());
    }
}
