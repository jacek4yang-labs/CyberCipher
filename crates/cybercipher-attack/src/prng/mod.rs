//! PRNG recovery attacks: linear congruential generators ([`lcg`]) and the
//! MT19937 Mersenne Twister ([`mt19937`]).
//!
//! Every routine validates its preconditions, works under explicit resource
//! bounds, and fails with a typed [`OperationError`] instead of panicking on
//! user input. JSON-facing result types serialize big integers as decimal
//! strings (project convention); the working types are [`LcgParams`] and
//! [`Mt19937`].
//!
//! Future work (not in this pass): truncated-output LCG recovery (lattice
//! based, see the `lattice` module lane) and MT19937 recovery from windows
//! that start mid-block.

// Documented project decision (.agent/decisions.md): OperationError crosses
// failure paths only; boxing it at every call site was judged not worth the
// churn, so the oversized-Err lint is silenced per module.
#![allow(clippy::result_large_err)]

pub mod lcg;
pub mod mt19937;

pub use lcg::{
    recover_params_known_m, recover_params_unknown, LcgParams, LcgRecovery, MAX_OUTPUTS,
    MAX_PREDICT, MAX_STEPS_BACK,
};
pub use mt19937::{
    cpython_key, getrandbits_from, init_by_array, init_genrand, temper, twist, untemper, Mt19937,
    MT_M, MT_MAX_GETRANDBITS, MT_MAX_WORDS, MT_N,
};

use cybercipher_core::error::OperationError;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

// -------------------------------------------------- LCG result types ----

/// Direction of a sequence extrapolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredictionDirection {
    /// Following the stream.
    Forward,
    /// Against the stream (requires `a` invertible modulo `m`).
    Backward,
}

/// JSON-friendly outcome of an LCG stream extrapolation. All integers are
/// decimal strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LcgPredictionResult {
    pub params: LcgParams,
    /// State the extrapolation started from (decimal).
    pub start_state: String,
    pub direction: PredictionDirection,
    /// Predicted states in prediction order (decimal).
    pub outputs: Vec<String>,
}

impl LcgPredictionResult {
    /// Package a forward prediction.
    pub fn forward(params: &LcgParams, start: &BigUint, outputs: &[BigUint]) -> Self {
        Self {
            params: params.clone(),
            start_state: (start % params.m()).to_string(),
            direction: PredictionDirection::Forward,
            outputs: outputs.iter().map(|o| o.to_string()).collect(),
        }
    }

    /// Package a backward prediction.
    pub fn backward(params: &LcgParams, start: &BigUint, outputs: &[BigUint]) -> Self {
        Self {
            params: params.clone(),
            start_state: (start % params.m()).to_string(),
            direction: PredictionDirection::Backward,
            outputs: outputs.iter().map(|o| o.to_string()).collect(),
        }
    }
}

// ------------------------------------------------- MT19937 result types ----

/// MT19937 state recovered from 624 consecutive observed outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mt19937StateRecovery {
    /// The 624 untempered state words, lowercase hex.
    pub state: Vec<String>,
    /// Generator index for the recovered block (always 624: the block is
    /// exhausted and the next draw triggers a twist).
    pub index: u32,
    /// Number of observed outputs consumed (always 624).
    pub outputs_used: usize,
}

impl Mt19937StateRecovery {
    /// Clone the generator state from at least 624 consecutive raw outputs.
    pub fn from_outputs(outputs: &[u32]) -> Result<Self, OperationError> {
        let mt = Mt19937::from_outputs(outputs)?;
        Ok(Self {
            state: mt.state().iter().map(|w| format!("{w:08x}")).collect(),
            index: mt.index() as u32,
            outputs_used: MT_N,
        })
    }
}

/// JSON-friendly outcome of a `getrandbits` reconstruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MtRandBitsResult {
    pub bits: u32,
    /// The reconstructed value in decimal.
    pub value: String,
    /// The reconstructed value in lowercase hex.
    pub value_hex: String,
    /// Number of 32-bit outputs consumed (`ceil(bits / 32)`, or 0 for
    /// `bits = 0`, matching CPython).
    pub words_consumed: usize,
}

impl MtRandBitsResult {
    /// Package a reconstructed `getrandbits(bits)` value.
    pub fn new(bits: u32, value: BigUint) -> Self {
        let words_consumed = bits.div_ceil(32) as usize;
        Self {
            bits,
            value: value.to_string(),
            value_hex: format!("{value:x}"),
            words_consumed,
        }
    }
}
