//! Linear congruential generator (LCG) recovery attacks.
//!
//! State convention: `s_{i+1} = a * s_i + b (mod m)` with the raw output equal
//! to the state (`y_i = s_i`). The module recovers the parameters from
//! observed outputs (with known or unknown modulus), predicts the stream
//! forwards and backwards, and recovers the initial seed from a single
//! observed output.
//!
//! Truncated outputs (only some bits of each state observed) are **not**
//! supported in this pass; that requires lattice work and is tracked as
//! future work.

use crate::math::{gcd, modinv};
use cybercipher_core::error::OperationError;
use num_bigint::{BigInt, BigUint};
use num_traits::{Num, One, Signed, Zero};
use serde::de::{self, Deserializer};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};

/// Maximum number of observed outputs accepted by a recovery routine.
pub const MAX_OUTPUTS: usize = 8192;
/// Maximum number of predicted states per prediction call.
pub const MAX_PREDICT: usize = 65_536;
/// Maximum number of reverse steps per seed-recovery call.
pub const MAX_STEPS_BACK: u64 = 1 << 20;

/// Parameters of a full-output LCG: `s_{i+1} = a * s_i + b (mod m)`.
///
/// Serialized as decimal strings — big integers cross the IPC boundary as
/// strings, never as JS numbers (project convention).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LcgParams {
    a: BigUint,
    b: BigUint,
    m: BigUint,
}

impl LcgParams {
    /// Validates the modulus (`m >= 2`) and reduces `a` and `b` modulo `m`.
    pub fn new(a: BigUint, b: BigUint, m: BigUint) -> Result<Self, OperationError> {
        if m.is_zero() || m.is_one() {
            return Err(
                OperationError::invalid_param("modulus", "LCG modulus must be at least 2")
                    .with_expected(">= 2")
                    .with_actual(m.to_string()),
            );
        }
        Ok(Self {
            a: a % &m,
            b: b % &m,
            m,
        })
    }

    /// Multiplier `a` (always reduced modulo `m`).
    pub fn a(&self) -> &BigUint {
        &self.a
    }

    /// Increment `b` (always reduced modulo `m`).
    pub fn b(&self) -> &BigUint {
        &self.b
    }

    /// Modulus `m`.
    pub fn m(&self) -> &BigUint {
        &self.m
    }

    /// Next state: `(a * s + b) mod m`.
    pub fn next(&self, state: &BigUint) -> BigUint {
        (&self.a * state + &self.b) % &self.m
    }

    /// Previous state: `a^-1 * (s - b) mod m`.
    ///
    /// Fails with a typed error when `a` is not invertible modulo `m`
    /// (the LCG is then not a permutation and has no unique predecessor).
    pub fn prev(&self, state: &BigUint) -> Result<BigUint, OperationError> {
        let a_inv = modinv(&self.a, &self.m).ok_or_else(|| {
            OperationError::invalid_input(
                "cannot step backwards: multiplier a is not invertible modulo m",
            )
            .with_parameter("multiplier")
            .with_expected("gcd(a, m) = 1")
            .with_actual(format!("gcd(a, m) = {}", gcd(&self.a, &self.m)))
        })?;
        let s = state % &self.m;
        let diff = (&s + &self.m - &self.b) % &self.m;
        Ok((diff * a_inv) % &self.m)
    }

    /// Predict the `count` states following `state` (exclusive of `state`),
    /// in stream order.
    pub fn predict(&self, state: &BigUint, count: usize) -> Result<Vec<BigUint>, OperationError> {
        check_count(count, "prediction")?;
        let mut s = state % &self.m;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            s = self.next(&s);
            out.push(s.clone());
        }
        Ok(out)
    }

    /// Step backwards `count` states from `state` (exclusive of `state`),
    /// oldest first: `[prev(state), prev(prev(state)), ...]`.
    pub fn step_back(&self, state: &BigUint, count: usize) -> Result<Vec<BigUint>, OperationError> {
        check_count(count, "backward")?;
        let mut s = state % &self.m;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            s = self.prev(&s)?;
            out.push(s.clone());
        }
        Ok(out)
    }

    /// Recover the initial seed (the state producing output index 0) from one
    /// observed output and its 0-based index in the output stream.
    ///
    /// With `index = 0` the output itself is the seed (the raw output equals
    /// the state).
    pub fn recover_seed(&self, output: &BigUint, index: u64) -> Result<BigUint, OperationError> {
        if index > MAX_STEPS_BACK {
            return Err(OperationError::invalid_param(
                "index",
                format!("seed recovery index exceeds the bound of {MAX_STEPS_BACK}"),
            )
            .with_expected(MAX_STEPS_BACK.to_string())
            .with_actual(index.to_string()));
        }
        let mut s = output % &self.m;
        for _ in 0..index {
            s = self.prev(&s)?;
        }
        Ok(s)
    }
}

fn check_count(count: usize, direction: &str) -> Result<(), OperationError> {
    if count > MAX_PREDICT {
        return Err(OperationError::invalid_param(
            "count",
            format!("{direction} step count exceeds the bound of {MAX_PREDICT}"),
        )
        .with_expected(MAX_PREDICT.to_string())
        .with_actual(count.to_string()));
    }
    Ok(())
}

// ----------------------------------------------------- serialization ----

impl Serialize for LcgParams {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut s = serializer.serialize_struct("LcgParams", 3)?;
        s.serialize_field("multiplier", &self.a.to_string())?;
        s.serialize_field("increment", &self.b.to_string())?;
        s.serialize_field("modulus", &self.m.to_string())?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for LcgParams {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            multiplier: String,
            increment: String,
            modulus: String,
        }
        let raw = Raw::deserialize(deserializer)?;
        let parse = |field: &str, value: &str| -> Result<BigUint, D::Error> {
            BigUint::from_str_radix(value, 10).map_err(|_| {
                de::Error::custom(format!("invalid decimal integer for `{field}`: {value:?}"))
            })
        };
        let a = parse("multiplier", &raw.multiplier)?;
        let b = parse("increment", &raw.increment)?;
        let m = parse("modulus", &raw.modulus)?;
        LcgParams::new(a, b, m).map_err(|e| de::Error::custom(e.to_string()))
    }
}

// --------------------------------------------------------- recovery ----

/// Outcome of a parameter-recovery attack: the recovered parameters plus how
/// many consecutive outputs were consumed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LcgRecovery {
    pub params: LcgParams,
    pub outputs_used: usize,
}

/// Recover `(a, b)` for a **known** modulus from at least 3 consecutive
/// outputs: `a = (y2 - y1) * (y1 - y0)^-1 mod m`, `b = y1 - a * y0 mod m`.
///
/// Consecutive output triples are tried until one has an invertible
/// difference; if every difference shares a factor with `m` the multiplier is
/// not identifiable and a typed error is returned. The recovered parameters
/// are verified against the full output list.
pub fn recover_params_known_m(
    outputs: &[BigUint],
    m: &BigUint,
) -> Result<LcgRecovery, OperationError> {
    if outputs.len() < 3 {
        return Err(OperationError::invalid_input(
            "recovering (a, b) with a known modulus requires at least 3 consecutive outputs",
        )
        .with_parameter("outputs")
        .with_expected("at least 3 outputs")
        .with_actual(format!("{} outputs", outputs.len())));
    }
    if outputs.len() > MAX_OUTPUTS {
        return Err(output_bound_error(outputs.len()));
    }
    if m.is_zero() || m.is_one() {
        return Err(
            OperationError::invalid_param("modulus", "LCG modulus must be at least 2")
                .with_expected(">= 2")
                .with_actual(m.to_string()),
        );
    }
    for (i, y) in outputs.iter().enumerate() {
        if y >= m {
            return Err(OperationError::invalid_input(format!(
                "output {i} is not reduced modulo the given modulus; the inputs are inconsistent"
            )));
        }
    }

    let mut saw_nonzero_diff = false;
    let mut found: Option<(BigUint, usize)> = None;
    for i in 0..outputs.len() - 2 {
        let d1 = (&outputs[i + 1] + m - &outputs[i]) % m;
        if d1.is_zero() {
            continue;
        }
        saw_nonzero_diff = true;
        let Some(d1_inv) = modinv(&d1, m) else {
            continue; // non-coprime difference: try the next triple
        };
        let d2 = (&outputs[i + 2] + m - &outputs[i + 1]) % m;
        found = Some(((d2 * d1_inv) % m, i));
        break;
    }

    let (a, i) = found.ok_or_else(|| {
        if saw_nonzero_diff {
            OperationError::invalid_input(
                "could not recover multiplier a: every non-zero output difference shares a common factor with the modulus",
            )
            .with_parameter("outputs")
            .with_expected("a difference pair coprime with m")
            .with_actual("no invertible difference found")
        } else {
            OperationError::invalid_input(
                "outputs are constant; the LCG parameters are underdetermined",
            )
            .with_parameter("outputs")
        }
    })?;

    let b = (&outputs[i + 1] + m - ((&a * &outputs[i]) % m)) % m;
    let params = LcgParams::new(a, b, m.clone())?;
    verify_stream(&params, outputs)?;
    Ok(LcgRecovery {
        params,
        outputs_used: outputs.len(),
    })
}

/// Recover `(a, b, m)` from at least 6 consecutive outputs without knowing
/// the modulus (classic technique).
///
/// With `t_i = y_{i+1} - y_i`, every `g_i = t_{i+2} * t_i - t_{i+1}^2` is a
/// multiple of the modulus, so `m = gcd(|g_0|, |g_1|, ...)`. The multiplier is
/// then `a = t_{i+1} * t_i^-1 mod m` for the first invertible difference pair,
/// and `b = y_1 - a * y_0 mod m`. Everything is verified against the observed
/// stream; degenerate streams (constant, or purely linear with `a = 1`) and
/// non-coprime difference pairs fail with typed errors instead of panicking.
pub fn recover_params_unknown(outputs: &[BigUint]) -> Result<LcgRecovery, OperationError> {
    if outputs.len() < 6 {
        return Err(OperationError::invalid_input(
            "modulus-free LCG recovery requires at least 6 consecutive outputs",
        )
        .with_parameter("outputs")
        .with_expected("at least 6 outputs")
        .with_actual(format!("{} outputs", outputs.len())));
    }
    if outputs.len() > MAX_OUTPUTS {
        return Err(output_bound_error(outputs.len()));
    }

    // Signed differences over the integers: y_{i+1} - y_i need not be
    // non-negative because the generator reduces modulo m.
    let ys: Vec<BigInt> = outputs.iter().map(|y| BigInt::from(y.clone())).collect();
    let t: Vec<BigInt> = ys.windows(2).map(|w| &w[1] - &w[0]).collect();

    let mut m: Option<BigUint> = None;
    for i in 0..t.len() - 2 {
        let g = (&t[i + 2] * &t[i] - &t[i + 1] * &t[i + 1]).abs();
        if g.is_zero() {
            continue;
        }
        let g = g.to_biguint().expect("|g| is non-negative");
        m = Some(match m {
            None => g,
            Some(current) => gcd(&current, &g),
        });
    }
    let Some(m) = m else {
        return Err(OperationError::invalid_input(
            "could not determine the modulus: all difference products vanished (the stream is constant or purely linear, i.e. a = 1)",
        )
        .with_parameter("outputs"));
    };
    for (i, y) in outputs.iter().enumerate() {
        if y >= &m {
            return Err(OperationError::invalid_input(format!(
                "observed output {i} is not smaller than the recovered modulus; the inputs are probably not from a single LCG stream"
            ))
            .with_parameter("outputs")
            .with_details(format!("recovered modulus = {m}")));
        }
    }

    let mut saw_nonzero_diff = false;
    let mut found: Option<(BigUint, usize)> = None;
    for i in 0..t.len() - 1 {
        let ti = mod_big(&t[i], &m);
        if ti.is_zero() {
            continue;
        }
        saw_nonzero_diff = true;
        let Some(ti_inv) = modinv(&ti, &m) else {
            continue; // non-coprime difference: try the next pair
        };
        found = Some(((mod_big(&t[i + 1], &m) * ti_inv) % &m, i));
        break;
    }
    let (a, _) = found.ok_or_else(|| {
        if saw_nonzero_diff {
            OperationError::invalid_input(
                "could not recover multiplier a: every non-zero difference t_i shares a common factor with the recovered modulus m",
            )
            .with_parameter("outputs")
            .with_expected("a difference pair coprime with m")
            .with_actual("no invertible difference found")
        } else {
            OperationError::invalid_input(
                "outputs are constant; the LCG parameters are underdetermined",
            )
            .with_parameter("outputs")
        }
    })?;

    let b = (&outputs[1] + &m - ((&a * &outputs[0]) % &m)) % &m;
    let params = LcgParams::new(a, b, m)?;
    verify_stream(&params, outputs)?;
    Ok(LcgRecovery {
        params,
        outputs_used: outputs.len(),
    })
}

/// Least non-negative residue of a signed integer modulo `m > 0`.
fn mod_big(x: &BigInt, m: &BigUint) -> BigUint {
    let m_signed = BigInt::from(m.clone());
    let r = x % &m_signed;
    let residue = if r.is_negative() { r + m_signed } else { r };
    residue.to_biguint().expect("residue is non-negative")
}

/// Verify that `params` reproduces the whole observed stream from its first
/// element.
fn verify_stream(params: &LcgParams, outputs: &[BigUint]) -> Result<(), OperationError> {
    let mut s = outputs[0].clone();
    for (i, y) in outputs.iter().enumerate().skip(1) {
        s = params.next(&s);
        if s != *y {
            return Err(OperationError::invalid_input(format!(
                "recovered parameters do not reproduce the observed outputs (first mismatch at output {i}); the inputs may not come from a single LCG stream"
            ))
            .with_parameter("outputs"));
        }
    }
    Ok(())
}

fn output_bound_error(actual: usize) -> OperationError {
    OperationError::invalid_param(
        "outputs",
        format!("output count exceeds the bound of {MAX_OUTPUTS}"),
    )
    .with_expected(MAX_OUTPUTS.to_string())
    .with_actual(actual.to_string())
}
