//! XOR analysis engine: interactive cracking with explanations. This is the
//! ANALYSIS layer on top of the codec's transform-only `xor` recipe op and
//! the engine's Auto Decode single-byte exploration — those apply/inspect
//! XOR; this module *cracks* it and shows its work.
//!
//! Entry points:
//!
//! * [`crack_single_byte`] — all 256 keys scored against the English model,
//!   ranked candidates with per-candidate evidence, honest "no confident
//!   key" outcome below the confidence threshold.
//! * [`estimate_key_length`] — index of coincidence plus normalized Hamming
//!   distance for candidate lengths 1..=64, with parsimony promotion so the
//!   true length outranks its multiples.
//! * [`crack_repeating_key`] — column-wise single-byte crack with per-column
//!   evidence (top-3 keys, margins) and optional crib locking.
//! * [`crib_drag`] — slide a crib through the ciphertext, keep the printable
//!   alignments with position and key fragment.
//! * [`mtp_break`] — multi-time-pad breaking: per-position likelihood over
//!   all ciphertexts, `"the "` crib-seed refinement, per-position confidence.
//!
//! House rules (matching the rest of the attack crate): every routine
//! validates preconditions and fails with a typed [`OperationError`] carrying
//! expected/actual instead of panicking; inputs are bounded (1 MiB for
//! ciphertexts, 64 for key lengths); result structs are serde-serializable
//! with snake_case fields and bounded preview strings. Scoring is tuned for
//! ASCII English (see [`scoring`] for the frequency-table source); scoring
//! for Chinese and other non-Latin scripts is future work.

// Documented project decision (.agent/decisions.md): OperationError crosses
// failure paths only; boxing it at every call site was judged not worth the
// churn, so the oversized-Err lint is silenced per module.
#![allow(clippy::result_large_err)]

pub mod crib;
pub mod keylen;
pub mod mtp;
pub mod repeating;
pub mod scoring;
pub mod single;

pub use crib::{crib_drag, CribDragHit, CribDragOptions, CribDragResult};
pub use keylen::{
    estimate_key_length, KeyLengthCandidate, KeyLengthOptions, KeyLengthResult,
    HAMMING_PAIR_SAMPLE, PARSIMONY_RATIO,
};
pub use mtp::{
    mtp_break, MtpBreakResult, MtpKeySource, MtpPosition, REFINE_CONFIDENCE, REFINE_CRIB,
};
pub use repeating::{
    crack_repeating_key, ColumnEvidence, ColumnKeyCandidate, RepeatingKeyCrackResult,
    RepeatingOptions, COLUMN_TOP_KEYS, REPEAT_COLUMN_THRESHOLD,
};
pub use scoring::{
    chi_square_english, english_fit, find_flag_pattern, is_printable_byte, preview_text,
    Confidence, CompositeScore, ENGLISH_LETTER_FREQ_PCT, FLAG_BONUS, FLAG_PREFIXES, PREVIEW_MAX,
    UTF8_SAMPLE_MAX,
};
pub use single::{
    crack_single_byte, SingleByteCandidate, SingleByteCrackResult, SingleByteOptions,
};

// ------------------------------------------------------------ bounds ----

/// Hard cap on ciphertext input size for all XOR analysis routines: 1 MiB.
pub const MAX_INPUT_BYTES: usize = 1_048_576;

/// Largest repeating-key length considered: 64 bytes.
pub const MAX_KEY_LENGTH: usize = 64;

/// Hard cap on `top_n`-style options.
pub const MAX_TOP_N: usize = 1024;

/// Smallest sample accepted by [`estimate_key_length`] — below this the IOC
/// per column is noise for any realistic key length.
pub const MIN_KEYLEN_SAMPLE: usize = 32;

/// Largest crib accepted by [`crib_drag`] / [`crack_repeating_key`]: 256 bytes.
pub const MAX_CRIB_BYTES: usize = 256;

/// Default composite-score threshold above which a best candidate is claimed
/// as the key (`confident = true`).
pub const DEFAULT_CONFIDENT_THRESHOLD: f64 = 0.60;

// --------------------------------------------------------- MTP bounds ----

/// Minimum number of ciphertexts for [`mtp_break`] (6+ recommended).
pub const MTP_MIN_CIPHERTEXTS: usize = 2;

/// Recommended number of ciphertexts for reliable per-position recovery.
pub const MTP_RECOMMENDED_CIPHERTEXTS: usize = 6;

/// Maximum number of ciphertexts accepted by [`mtp_break`].
pub const MTP_MAX_CIPHERTEXTS: usize = 64;

/// Per-message byte cap for [`mtp_break`] (the key is as long as the message,
/// so unbounded messages would make unbounded keys).
pub const MTP_MAX_MESSAGE_BYTES: usize = 65_536;

/// Key-hex preview width for [`mtp_break`] results, in bytes.
pub const MTP_KEY_PREVIEW_BYTES: usize = 48;
