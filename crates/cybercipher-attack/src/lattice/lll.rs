//! Exact integral LLL reduction (rational-free Gram–Schmidt).
//!
//! The implementation follows the classical integral LLL of de Weger
//! ("Algorithms for Diophantine Equations", ch. 3; same formulation as
//! Cohen's Algorithm 2.6.7). No floating point and no rational arithmetic is
//! used in the reduction loop: the Gram–Schmidt structure is carried by two
//! integer tables only,
//!
//! * `λ[i][j]` for `0 ≤ j < i` — the integer Gram–Schmidt coefficients with
//!   `μ_{i,j} = λ[i][j] / d[j]`, and
//! * `d[i]` — the Gram determinant of the first `i+1` basis vectors, i.e.
//!   `d[i] = ∏_{k≤i} ‖b*_k‖²` (with the sentinel `d[-1] = 1`).
//!
//! These satisfy the identities the loop relies on:
//!
//! * `‖b*_i‖² = d[i]/d[i-1]`,
//! * `⟨b_i, w_j⟩ = λ[i][j]` where `w_j = d[j-1]·b*_j` is an integral vector
//!   (integrality of `w_j` follows from Cramer's rule on the Gram system —
//!   the adjugate of an integer matrix is integral),
//! * Lovász condition in exact cross-multiplied form:
//!   `δ·d[k-1]² ≤ d[k-2]·d[k] + λ[k][k-1]²` (all integer products, no
//!   division),
//! * size reduction rounds `μ_{k,j} = λ[k][j]/d[j]` to the nearest integer
//!   via `q = ⌊(2λ + d) / 2d⌋` — still division-free in the loop.
//!
//! The swap step updates `λ`/`d` with the classical exact divisions
//! `d'[k-1] = (d[k-2]·d[k] + C²)/d[k-1]`, `λ'[l][k-1] = (d[k-2]·λ[l][k] +
//! C·λ[l][k-1])/d[k-1]`, `λ'[l][k] = (d[k]·λ[l][k-1] − C·λ[l][k])/d[k-1]`
//! (`C = λ[k][k-1]`). Each quotient is an inner product of integral vectors
//! (`⟨b_l, w'_{k-1}⟩`, `⟨b_l, w'_k⟩` with `w'_{k-1} = d[k-2]·b*'_{k-1}`,
//! `w'_k = d'[k-1]·b*_k'` integral by the same Cramer argument), so the
//! divisions are exact; a non-exact quotient is surfaced as an `Internal`
//! error rather than a panic or silent corruption.
//!
//! ## Termination invariant
//!
//! Let `Δ = ∏_{i=0}^{n-2} d[i]` (a positive integer for an independent
//! basis). Size reductions change no `d[i]`. A swap at position `k` replaces
//! `d[k-1]` by `(d[k-2]·d[k] + C²)/d[k-1]` and — because the Lovász
//! condition failed — that value is `< δ·d[k-1]`; all other factors of `Δ`
//! are unchanged. Hence every swap multiplies `Δ` by a factor `< δ ≤ 1`,
//! i.e. strictly decreases the positive integer `Δ`. Therefore the number of
//! swaps is finite (with δ = 99/100 it is at most `≈ 100·ln Δ₀`, itself
//! bounded by the entry bit budget), and the loop terminates. `MAX_LLL_STEPS`
//! is a belt-and-braces runaway guard on top of that proof.

use super::matrix::Lattice;
use super::{exact_div, floor_div, MAX_DIM, MAX_TOTAL_BITS};
use cybercipher_core::error::{ErrorKind, OperationError};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use serde::{Deserialize, Serialize};

/// Numerator of the default Lovász parameter δ = 99/100.
pub const DEFAULT_DELTA_NUM: u32 = 99;
/// Denominator of the default Lovász parameter δ = 99/100.
pub const DEFAULT_DELTA_DEN: u32 = 100;
/// Runaway guard on reduction iterations. The termination proof above bounds
/// legitimate runs far below this; hitting it indicates a bug and is reported
/// as [`ErrorKind::BudgetExceeded`] instead of hanging.
pub const MAX_LLL_STEPS: u64 = 10_000_000;

/// LLL configuration. δ = `delta_num/delta_den` must lie in `[1/2, 1]`
/// (the classical termination requirement is δ > 1/4; we insist on the
/// conventional, safely-convergent range).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LllConfig {
    pub delta_num: u32,
    pub delta_den: u32,
}

impl Default for LllConfig {
    fn default() -> Self {
        LllConfig {
            delta_num: DEFAULT_DELTA_NUM,
            delta_den: DEFAULT_DELTA_DEN,
        }
    }
}

impl LllConfig {
    pub fn new(delta_num: u32, delta_den: u32) -> Result<Self, OperationError> {
        let cfg = LllConfig {
            delta_num,
            delta_den,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), OperationError> {
        if self.delta_den == 0 {
            return Err(OperationError::invalid_param(
                "delta_den",
                "delta denominator must be non-zero",
            ));
        }
        // Require 1/2 ≤ num/den ≤ 1.
        if (self.delta_num as u64) * 2 < self.delta_den as u64 || self.delta_num > self.delta_den {
            return Err(OperationError::invalid_param(
                "delta",
                format!(
                    "Lovász parameter δ must lie in [1/2, 1], got {}/{}",
                    self.delta_num, self.delta_den
                ),
            )
            .with_expected("delta_num/delta_den in [1/2, 1]")
            .with_actual(format!("{}/{}", self.delta_num, self.delta_den)));
        }
        Ok(())
    }
}

/// Counters and final state of a reduction run. Norms are exact squared
/// Euclidean norms, serialized as decimal strings (project convention).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LllDiagnostics {
    pub swap_count: u64,
    pub size_reductions: u64,
    pub iterations: u64,
    pub final_norms_squared: Vec<String>,
}

/// Outcome of [`lll_reduce`]: the reduced basis, the unimodular transform
/// that produces it (`transform · original = reduced`, `det(transform) = ±1`)
/// and run diagnostics.
#[derive(Debug, Clone)]
pub struct LllResult {
    pub basis: Lattice,
    pub transform: Lattice,
    pub diagnostics: LllDiagnostics,
}

/// Exact rational used only during initialization (building the initial
/// `λ`/`d` tables); the reduction loop itself is pure integer arithmetic.
/// Always normalized: `den > 0` and `gcd(|num|, den) = 1`.
#[derive(Debug, Clone)]
struct Rat {
    num: BigInt,
    den: BigInt,
}

fn big_gcd(a: &BigInt, b: &BigInt) -> BigInt {
    let (mut a, mut b) = (a.abs(), b.abs());
    while !b.is_zero() {
        let r = &a % &b;
        a = b;
        b = r;
    }
    a
}

impl Rat {
    fn new(num: BigInt, den: BigInt) -> Self {
        let mut r = Rat { num, den };
        if r.den.is_negative() {
            r.num = -r.num;
            r.den = -r.den;
        }
        let g = big_gcd(&r.num, &r.den);
        if !g.is_zero() && g != BigInt::from(1) {
            r.num /= &g;
            r.den /= g;
        }
        r
    }

    fn int(v: BigInt) -> Self {
        Rat {
            den: BigInt::from(1),
            num: v,
        }
    }

    fn is_zero(&self) -> bool {
        self.num.is_zero()
    }

    fn sub(&self, other: &Rat) -> Rat {
        Rat::new(
            &self.num * &other.den - &other.num * &self.den,
            &self.den * &other.den,
        )
    }

    fn mul_int(&self, v: &BigInt) -> Rat {
        Rat::new(&self.num * v, self.den.clone())
    }

    fn to_integer(&self) -> Option<BigInt> {
        if self.den == BigInt::from(1) {
            Some(self.num.clone())
        } else {
            None
        }
    }
}

fn dot(a: &[BigInt], b: &[BigInt]) -> BigInt {
    a.iter()
        .zip(b.iter())
        .fold(BigInt::zero(), |acc, (x, y)| acc + x * y)
}

/// Nearest integer to `lam/den` (`den > 0`), ties rounded up.
fn round_ratio(lam: &BigInt, den: &BigInt) -> BigInt {
    floor_div(&((lam << 1u32) + den), &(den << 1u32))
}

/// `target -= q * src` elementwise (zip stops at the shorter row).
fn sub_scaled_row(target: &mut [BigInt], src: &[BigInt], q: &BigInt) {
    for (t, s) in target.iter_mut().zip(src.iter()) {
        *t -= q * s;
    }
}

/// Integral Gram–Schmidt tables: `λ` rows (`λ[i]` has `i` entries) and the
/// determinant sequence `d`.
pub type GramSchmidtTables = (Vec<Vec<BigInt>>, Vec<BigInt>);

/// Computed Gram–Schmidt data of a basis in integral form: `lam[i][j]`
/// (`0 ≤ j < i`) with `μ_{i,j} = lam[i][j]/d[j]`, and `d[i]` = Gram
/// determinant of the first `i+1` vectors (`d[-1] = 1` implicitly). Also used
/// by tests to verify that an output basis is size-reduced and satisfies the
/// Lovász condition exactly.
pub fn gram_schmidt_data(lattice: &Lattice) -> Result<GramSchmidtTables, OperationError> {
    let (lam, d, _w) = init_gram_schmidt(lattice)?;
    Ok((lam, d))
}

/// Build the initial `λ`/`d` tables (and the integral GS vectors `w_j =
/// d[j-1]·b*_j`, needed only to construct the tables).
type InitTables = (Vec<Vec<BigInt>>, Vec<BigInt>, Vec<Vec<BigInt>>);

fn init_gram_schmidt(lattice: &Lattice) -> Result<InitTables, OperationError> {
    let n = lattice.nrows();
    let one = BigInt::from(1);
    let mut lam: Vec<Vec<BigInt>> = Vec::with_capacity(n);
    // d_all[0] is the sentinel d[-1] = 1; d_all[k+1] = d[k].
    let mut d_all: Vec<BigInt> = vec![one.clone()];
    let mut w: Vec<Vec<BigInt>> = Vec::with_capacity(n);

    for i in 0..n {
        // λ[i][j] = ⟨b_i, w_j⟩ — plain integer inner products.
        let row_lam: Vec<BigInt> = w
            .iter()
            .take(i)
            .map(|wj| dot(lattice.row(i), wj))
            .collect();
        // w_i = d[i-1]·b_i − Σ_{j<i} (λ[i][j]·d[i-1]/(d[j]·d[j-1]))·w_j.
        // The coefficients are rational but the result is provably integral
        // (w_i = d[i-1]·b*_i by Cramer's rule); verify rather than assume.
        let d_prev = d_all[i].clone();
        let mut wi: Vec<Rat> = lattice
            .row(i)
            .iter()
            .map(|c| Rat::int(d_prev.clone() * c))
            .collect();
        for (j, lam_ij) in row_lam.iter().enumerate().take(i) {
            let coef = Rat::new(lam_ij.clone() * &d_prev, &d_all[j + 1] * &d_all[j]);
            if !coef.is_zero() {
                for (wt, wjt) in wi.iter_mut().zip(w[j].iter()) {
                    *wt = wt.sub(&coef.mul_int(wjt));
                }
            }
        }
        let wi_int: Vec<BigInt> = wi
            .into_iter()
            .map(|r| {
                r.to_integer().ok_or_else(|| {
                    OperationError::internal(
                        "Gram-Schmidt integrality invariant violated (d[i-1]·b*_i not integral)",
                    )
                })
            })
            .collect::<Result<_, _>>()?;
        // d[i] = ⟨w_i, w_i⟩ / d[i-1]  — a Gram determinant, positive integer.
        let sq = dot(&wi_int, &wi_int);
        let d_i = Rat::new(sq, d_prev).to_integer().ok_or_else(|| {
            OperationError::internal(
                "Gram determinant d[i] came out non-integral — internal invariant violated",
            )
        })?;
        if d_i.is_zero() {
            return Err(OperationError::invalid_input(format!(
                "basis is linearly dependent (Gram determinant vanishes at index {i}); \
                 LLL requires an independent basis"
            )));
        }
        if d_i.is_negative() {
            return Err(OperationError::internal(
                "Gram determinant d[i] negative — internal invariant violated",
            ));
        }
        lam.push(row_lam);
        d_all.push(d_i);
        w.push(wi_int);
    }
    d_all.remove(0); // drop the d[-1] sentinel; caller indexes d[i] directly
    Ok((lam, d_all, w))
}

/// LLL-reduce an integer basis with exact integer arithmetic.
///
/// Returns the reduced basis spanning the same lattice, the unimodular row
/// transform `U` with `U · original = reduced` (so `det U = ±1`), and
/// diagnostics. Fails with a typed [`OperationError`] on: dimension/bit
/// budget cap overflow, zero rows, a linearly dependent basis, a δ outside
/// `[1/2, 1]`, or a runaway run (budget guard).
pub fn lll_reduce(lattice: &Lattice, config: &LllConfig) -> Result<LllResult, OperationError> {
    config.validate()?;
    let n = lattice.nrows();
    if n > MAX_DIM {
        return Err(OperationError::invalid_param(
            "rows",
            format!("lattice dimension {n} exceeds LLL cap {MAX_DIM}"),
        )
        .with_expected(MAX_DIM.to_string())
        .with_actual(n.to_string()));
    }
    let total_bits: u64 = lattice
        .rows()
        .iter()
        .map(|r| r.iter().map(|c| c.bits()).sum::<u64>())
        .sum();
    if total_bits > MAX_TOTAL_BITS {
        return Err(OperationError::new(
            ErrorKind::BudgetExceeded,
            format!("lattice entries total {total_bits} bits, exceeding budget {MAX_TOTAL_BITS}"),
        )
        .with_expected(MAX_TOTAL_BITS.to_string())
        .with_actual(total_bits.to_string())
        .with_parameter("rows"));
    }
    for i in 0..n {
        if lattice.row(i).iter().all(|c| c.is_zero()) {
            return Err(OperationError::invalid_input(format!(
                "row {i} is the zero vector; LLL requires a non-degenerate basis"
            )));
        }
    }

    let (mut lam, mut d, _w) = init_gram_schmidt(lattice)?;
    let mut basis: Vec<Vec<BigInt>> = lattice.rows().to_vec();
    // Unimodular transform U: U · original = reduced.
    let mut u: Vec<Vec<BigInt>> = (0..n)
        .map(|i| {
            (0..n)
                .map(|j| {
                    if i == j {
                        BigInt::from(1)
                    } else {
                        BigInt::from(0)
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect();

    let delta_num = BigInt::from(config.delta_num);
    let delta_den = BigInt::from(config.delta_den);
    let one = BigInt::from(1);
    let zero = BigInt::from(0);

    let mut k = 1usize;
    let mut swaps = 0u64;
    let mut reductions = 0u64;
    let mut steps = 0u64;

    while k < n {
        steps += 1;
        if steps > MAX_LLL_STEPS {
            return Err(OperationError::new(
                ErrorKind::BudgetExceeded,
                format!("LLL exceeded {MAX_LLL_STEPS} iterations; aborting"),
            )
            .with_details("runaway-guard on a provably terminating loop"));
        }
        // --- Size-reduce row k against rows k-1 .. 0 ---------------------
        for j in (0..k).rev() {
            let q = round_ratio(&lam[k][j], &d[j]);
            if !q.is_zero() {
                for (bk, bj) in basis[k].iter_mut().zip(basis[j].iter()) {
                    *bk -= &q * bj;
                }
                for (uk, uj) in u[k].iter_mut().zip(u[j].iter()) {
                    *uk -= &q * uj;
                }
                // λ[k][t] ← λ[k][t] − q·λ[j][t] for t < j (λ[j][t] = 0 for
                // t > j because ⟨b_j, b*_t⟩ = 0), and λ[k][j] ← λ[k][j] − q·d[j].
                for (lk, lj) in lam[k].iter_mut().zip(lam[j].iter()) {
                    *lk -= &q * lj;
                }
                lam[k][j] -= &q * &d[j];
                reductions += 1;
            }
        }
        // --- Lovász condition (exact cross-multiplication) ---------------
        let dk2 = if k >= 2 {
            d[k - 2].clone()
        } else {
            one.clone()
        };
        let c = &lam[k][k - 1];
        let lovasz_lhs = &delta_den * (&dk2 * &d[k] + c * c);
        let lovasz_rhs = &delta_num * &d[k - 1] * &d[k - 1];
        if lovasz_lhs >= lovasz_rhs {
            k += 1;
        } else {
            // --- Swap k-1 ↔ k with the classical exact update ------------
            basis.swap(k - 1, k);
            u.swap(k - 1, k);
            let mut row_hi = std::mem::take(&mut lam[k]);
            let row_lo = std::mem::take(&mut lam[k - 1]);
            let c = row_hi.pop().unwrap_or_else(|| zero.clone());
            lam[k - 1] = row_hi; // λ'[k-1][j] = λ[k][j] for j ≤ k-2
            let mut new_row_k = row_lo; // λ'[k][j] = λ[k-1][j] for j ≤ k-2
            new_row_k.push(c.clone()); // λ'[k][k-1] = C
            lam[k] = new_row_k;
            let dk2 = if k >= 2 {
                d[k - 2].clone()
            } else {
                one.clone()
            };
            let dk1_old = d[k - 1].clone();
            let dk = d[k].clone();
            for row in lam.iter_mut().skip(k + 1) {
                let t = row[k].clone();
                let num_lo = &dk2 * &t + &c * &row[k - 1];
                let num_hi = &dk * &row[k - 1] - &c * &t;
                row[k - 1] = exact_div(&num_lo, &dk1_old)?;
                row[k] = exact_div(&num_hi, &dk1_old)?;
            }
            d[k - 1] = exact_div(&(&dk2 * &dk + &c * &c), &dk1_old)?;
            swaps += 1;
            k = k.saturating_sub(1).max(1);
        }
    }

    let final_norms = basis.iter().map(|r| dot(r, r).to_string()).collect();
    let basis_l = Lattice::from_rows(basis)?;
    let transform = Lattice::from_rows(u)?;
    Ok(LllResult {
        basis: basis_l,
        transform,
        diagnostics: LllDiagnostics {
            swap_count: swaps,
            size_reductions: reductions,
            iterations: steps,
            final_norms_squared: final_norms,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(v: &[i64]) -> Vec<BigInt> {
        v.iter().map(|&x| BigInt::from(x)).collect()
    }

    fn lat(rows: Vec<Vec<BigInt>>) -> Lattice {
        Lattice::from_rows(rows).unwrap()
    }

    #[test]
    fn round_ratio_nearest_with_tie_up() {
        let d = BigInt::from(10);
        assert_eq!(round_ratio(&BigInt::from(4), &d), BigInt::from(0));
        assert_eq!(round_ratio(&BigInt::from(5), &d), BigInt::from(1));
        assert_eq!(round_ratio(&BigInt::from(-5), &d), BigInt::from(0));
        assert_eq!(round_ratio(&BigInt::from(-6), &d), BigInt::from(-1));
        assert_eq!(round_ratio(&BigInt::from(15), &d), BigInt::from(2));
    }

    #[test]
    fn gram_schmidt_matches_hand_computation() {
        // Worked example: b0=(1,3,0), b1=(2,2,0), b2=(1,1,5).
        let l = lat(vec![b(&[1, 3, 0]), b(&[2, 2, 0]), b(&[1, 1, 5])]);
        let (lam, d) = gram_schmidt_data(&l).unwrap();
        assert_eq!(lam[1][0], BigInt::from(8)); // μ = 8/10
        assert_eq!(lam[2][0], BigInt::from(4));
        assert_eq!(lam[2][1], BigInt::from(8)); // μ = 8/16
        assert_eq!(d[0], BigInt::from(10));
        assert_eq!(d[1], BigInt::from(16));
        assert_eq!(d[2], BigInt::from(400)); // Gram determinant
    }

    #[test]
    fn gram_schmidt_rejects_dependent_basis() {
        let l = lat(vec![b(&[1, 2, 3]), b(&[2, 4, 6])]);
        let err = gram_schmidt_data(&l).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidInput);
        assert!(err.message.contains("linearly dependent"));
    }
}
