//! CyberCipher attack: number-theory primitives, RSA attack engine, and
//! (upcoming) PRNG recovery + lattice reduction.
//!
//! Attacks are first-class analyzable units: every one declares its
//! preconditions, validates them, runs under explicit resource bounds, and
//! returns a typed outcome with diagnostics — positive and negative tests
//! exist for each.

pub mod math;
pub mod prng;
pub mod rsa;

pub use rsa::{
    analyze, AnalyzerReport, AttackCost, AttackOutcome, AttackStatus, PlaintextResult, RsaParams,
    RsaSet,
};
