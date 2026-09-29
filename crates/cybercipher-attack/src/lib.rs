//! CyberCipher attack: number-theory primitives, RSA attack engine, PRNG
//! recovery, and XOR analysis (single-byte, repeating-key, crib dragging,
//! multi-time-pad).
//!
//! Attacks are first-class analyzable units: every one declares its
//! preconditions, validates them, runs under explicit resource bounds, and
//! returns a typed outcome with diagnostics — positive and negative tests
//! exist for each.

pub mod lattice;
pub mod math;
pub mod prng;
pub mod rsa;
pub mod xor;

pub use lattice::{
    small_roots, CoppersmithBeta, CoppersmithParams, Lattice, LllConfig, LllResult, Poly,
    SmallRootsResult,
};
pub use rsa::{
    analyze, AnalyzerReport, AttackCost, AttackOutcome, AttackStatus, PlaintextResult, RsaParams,
    RsaSet,
};
pub use xor::{
    crack_repeating_key, crack_single_byte, crib_drag, estimate_key_length, mtp_break,
    MtpBreakResult, RepeatingKeyCrackResult, SingleByteCrackResult,
};
