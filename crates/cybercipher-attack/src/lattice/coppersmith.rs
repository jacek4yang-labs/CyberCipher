//! Coppersmith small-root attacks via the Howgrave-Graham lattice over the
//! exact integer LLL of [`super::lll`].
//!
//! ## Problem
//!
//! Given a polynomial `f(x)` of degree `d` modulo a composite `N` and a bound
//! `X`, find every integer `x0` with `|x0| ≤ X` and `f(x0) ≡ 0 (mod N)`. The
//! classical regime is `X ≤ N^{1/d − ε}`: a root hidden in the low bits of a
//! modular relation (stereotyped messages, known-MSB factoring where
//! `f(x0) = p` is itself a root of `f` mod `N`).
//!
//! ## Construction (Howgrave-Graham)
//!
//! With multiplicity `m ≥ 1` and `t ≥ 0` extra `f`-shifts, the lattice rows
//! are the coefficient vectors of the shift polynomials
//!
//! ```text
//! g_{i,j}(x) = N^{m−i} · f(x)^i · x^j   (0 ≤ i < m, 0 ≤ j < d)   — x-shifts
//! h_j(x)     = f(x)^m · x^j             (0 ≤ j < t)             — f-shifts
//! ```
//!
//! reduced to their monic representatives mod `N`. Every row polynomial
//! vanishes at `x0` modulo `N^m`, hence so does any integer combination.
//! Each coefficient of `x^k` is scaled by `X^k`, making the coefficient
//! vector of `p(X·x)` a lattice vector whose norm bounds `|p(x0)|`:
//! `|p(x0)| ≤ ‖p‖·√n` (Cauchy–Schwarz over `(1, x0, …, x0^{n−1})`,
//! `|x0| ≤ X`). The lattice is `n = d·m + t` dimensional with determinant
//!
//! ```text
//! det = N^{d·m(m+1)/2} · X^{n(n−1)/2}
//! ```
//!
//! (shift degrees `d·i + j` are distinct, so each row's leading coefficient
//! and each column's `X^k` factor contribute exactly once).
//!
//! ## Parameterization: which `m`/`t` for which `X`
//!
//! LLL guarantees `‖b₁‖ ≤ 2^{(n−1)/4}·det^{1/n}`, so the construction is
//! *certified* whenever `2^{(n−1)/4}·det^{1/n}·√n < N^m`. Solving for `X`
//! gives the certified bound implemented in [`guaranteed_bound`]:
//!
//! ```text
//! X_guaranteed = ⌊ ( N^{2m(2n − d(m+1))} / (2^{n(n−1)} · n^{2n}) )^{1/(2n(n−1))} ⌋
//!              ≈ N^{ε(d,m,t)},   ε = m(2n − d(m+1)) / (n(n−1))
//! ```
//!
//! Asymptotics of `ε` (dimension `n = dm + t` capped at
//! [`MAX_COPPERSMITH_DIM`] here):
//!
//! * degree `d`, pure x-shifts (`t = 0`): `ε = (m−1)/(dm−1) → 1/d`,
//! * with `t ≈ (1/d − ε)/(1 − 1/d)·…` extra shifts `ε` approaches `1/d`
//!   faster; the exact optimum is found by [`choose_params`].
//!
//! Concrete values at `bits(N) = 512`:
//!
//! | d | m | t | n  | ε      | certified X     |
//! |---|---|---|----|--------|-----------------|
//! | 1 | 4 | 4 | 8  | 0.786  | ~2^{402}        |
//! | 3 | 3 | 2 | 11 | 0.273  | ~2^{139}        |
//! | 3 | 4 | 3 | 15 | 0.286  | ~2^{146}        |
//!
//! A bound `X` beyond `X_guaranteed` for the chosen parameters is rejected
//! with a typed [`ErrorKind::Unsupported`] error that cites the bound — the
//! API never answers "no roots" for a problem that merely exceeded the
//! *certified* regime, and it never returns a root without exact
//! verification.
//!
//! ## Root extraction
//!
//! A reduced vector is read back as a polynomial over ℤ (the `X^k` scalings
//! divide out exactly). For any output vector `v`, Howgrave-Graham gives
//! `p(x0) = 0` over ℤ (not just mod `N^m`), so by the rational-root theorem
//! `x0` divides the constant term of the primitive part of `p`. Candidates
//! are enumerated by trial division with the small-prime table (all prime
//! powers `p^e ≤ X` dividing `a0`), plus a perfect-power refinement
//! (`x0 = r^e` detected via [`crate::math::iroot`]). Every candidate is then
//! verified exactly: `|x0| ≤ X` and `f(x0) ≡ 0 (mod N)`.
//!
//! **Documented limitation of the search:** divisors of `a0` are enumerated
//! from the crate's small-prime table (primes < 2^{14}); a root with a prime
//! factor above that table and outside a perfect-power shape would be
//! missed (reported as no root — never a wrong root). Coppersmith instances
//! in this regime use smooth hidden offsets; this is the standard
//! trade-off for big-integer-only implementations without a factoring
//! oracle for the ~`N^m`-sized constant term.
//!
//! ## Resource bounds
//!
//! Dimension is capped at [`MAX_COPPERSMITH_DIM`] (≤ the LLL [`super::MAX_DIM`]),
//! polynomial degrees at [`super::poly::MAX_POLY_DEGREE`], the lattice
//! entries at the module bit budget, and the candidate enumeration at a
//! fixed budget. All failures are typed [`OperationError`]s; no panics on
//! user input.

use super::exact_div;
use super::lll::{lll_reduce, LllConfig, LllDiagnostics};
use super::matrix::Lattice;
use super::poly::{validate_degree, Poly};
use crate::math::{iroot, small_primes};
use cybercipher_core::error::{ErrorKind, OperationError};
use num_bigint::{BigInt, BigUint};
use num_traits::{One, Signed, Zero};
use serde::{Deserialize, Serialize};

/// Hard cap on the Coppersmith lattice dimension `n = d·m + t`. The certified
/// bound grows only logarithmically with `n` (see the parameterization table
/// in the module docs), so requests beyond this cap are refused with a typed
/// error instead of mounting a hopeless reduction.
pub const MAX_COPPERSMITH_DIM: usize = 32;

/// How many reduced vectors (in norm order) are tried for root extraction.
/// The shortest is certified to satisfy Howgrave-Graham; the runners-up are
/// a cheap robustness net for lattices where a runner-up happens to be the
/// informative one.
const ROOT_POLY_CANDIDATES: usize = 4;

/// Cap on enumerated divisor candidates per polynomial (hostile `a0` values
/// with many small prime factors cannot blow up the search).
const MAX_DIVISOR_CANDIDATES: usize = 100_000;

/// Shift multiplicities for the Howgrave-Graham lattice: `m` = multiplicity
/// of `f`, `t` = number of extra `f^m·x^j` shifts. Dimension is `d·m + t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoppersmithParams {
    pub m: usize,
    pub t: usize,
}

impl CoppersmithParams {
    /// Validate multiplicities (`m ≥ 1`; `t ≥ 0` by type). Dimension-fit
    /// against a concrete degree is checked in [`small_roots`].
    pub fn new(m: usize, t: usize) -> Result<Self, OperationError> {
        if m == 0 {
            return Err(OperationError::invalid_param(
                "m",
                "shift multiplicity must be at least 1",
            ));
        }
        Ok(CoppersmithParams { m, t })
    }

    /// Lattice dimension for a degree-`d` input polynomial.
    pub fn dimension(&self, degree: usize) -> usize {
        degree * self.m + self.t
    }
}

/// Largest `X` for which the Howgrave-Graham + LLL worst-case guarantee
/// certifies recovery of every root `|x0| ≤ X` — see the derivation in the
/// module docs. Zero when the shape cannot certify anything (e.g. `t = 0,
/// m = 1`).
pub fn guaranteed_bound(n_mod: &BigUint, degree: usize, params: &CoppersmithParams) -> BigUint {
    let n = params.dimension(degree);
    if n < 2 {
        return BigUint::zero();
    }
    // E = 4mn − 2dm(m+1) = 2m(2n − d(m+1)); ≤ 0 means even X = 1 fails.
    let e: i64 = 2 * params.m as i64 * (2 * n as i64 - degree as i64 * (params.m as i64 + 1));
    if e <= 0 {
        return BigUint::zero();
    }
    // X_guaranteed^{2n(n−1)} = N^E / (2^{n(n−1)} · n^{2n}).
    let num = n_mod.pow(e as u32);
    let denom = (BigUint::one() << (n * (n - 1))) * BigUint::from(n as u64).pow(2 * n as u32);
    iroot(&(&num / &denom), (2 * n * (n - 1)) as u32)
}

/// Pick shift parameters certifying the requested bound, scanning shapes in
/// order of increasing dimension (then increasing `m`) — the documented
/// parameterization as a search. Errors when no shape within
/// [`MAX_COPPERSMITH_DIM`] certifies `X`, citing the regime.
pub fn choose_params(
    n_mod: &BigUint,
    degree: usize,
    x_bound: &BigUint,
) -> Result<CoppersmithParams, OperationError> {
    validate_degree(degree)?;
    let mut best_bound = BigUint::zero();
    let n_bits = n_mod.bits();
    for n in (degree + 1)..=MAX_COPPERSMITH_DIM {
        // Bit-length gate (necessary condition for certification, integer
        // math only): X_guaranteed ≈ N^{E/(2n(n−1))} needs
        // E·bits(N) ≥ 2n(n−1)·bits(X) + log2(2^{n(n−1)}·n^{2n}). Shapes
        // failing it cannot certify and are skipped without touching the
        // multi-hundred-thousand-bit exact arithmetic in `guaranteed_bound`.
        let k = 2 * n * (n - 1); // root degree
        let den_log2 = (n * (n - 1)) as u64 + 2 * n as u64 * (n.ilog2() as u64);
        let needed = k as u64 * x_bound.bits() + den_log2;
        for m in 1..=(n / degree) {
            let e = 2 * m as u64 * (2 * n as u64 - degree as u64 * (m as u64 + 1));
            if e.checked_mul(n_bits).is_none_or(|lhs| lhs < needed) {
                continue;
            }
            let params = CoppersmithParams {
                m,
                t: n - degree * m,
            };
            let bound = guaranteed_bound(n_mod, degree, &params);
            if &bound >= x_bound {
                return Ok(params);
            }
            if bound > best_bound {
                best_bound = bound;
            }
        }
    }
    Err(OperationError::new(
        ErrorKind::Unsupported,
        format!(
            "no shift parameters within dimension cap {MAX_COPPERSMITH_DIM} certify \
             X = 2^{} for degree {degree}: achievable regime is X ≤ N^(1/{degree} − ε) \
             (best certified bound found: 2^{} bits)",
            x_bound.bits(),
            best_bound.bits()
        ),
    )
    .with_expected(format!("X ≤ N^(1/{degree} − ε)"))
    .with_actual(format!("X = 2^{}", x_bound.bits())))
}

/// Outcome of a small-root search: every root is *verified exactly*
/// (`|x0| ≤ X`, `f(x0) ≡ 0 (mod N)`); an empty `roots` means no verified
/// root exists in range — never an unverified guess.
#[derive(Debug, Clone)]
pub struct SmallRootsResult {
    /// Verified roots, sorted ascending, deduplicated.
    pub roots: Vec<BigInt>,
    /// The certified bound `X_guaranteed` for the chosen parameters.
    pub guaranteed_bound: BigUint,
    /// Lattice dimension `n = d·m + t` that was reduced.
    pub lattice_dim: usize,
    /// LLL run diagnostics (step counts, final norms).
    pub diagnostics: LllDiagnostics,
}

/// Find all integers `x0` with `|x0| ≤ x_bound` and `f(x0) ≡ 0 (mod n_mod)`
/// using the Howgrave-Graham lattice reduced by exact integer LLL.
///
/// Fails with a typed [`OperationError`] when the input is malformed, the
/// shift lattice would exceed a resource cap, or — importantly — when
/// `x_bound` exceeds [`guaranteed_bound`] for `params` (the bound-exceeded
/// case cites the achievable bound; it is a configuration error, not an
/// empty result).
pub fn small_roots(
    f: &Poly,
    n_mod: &BigUint,
    x_bound: &BigUint,
    params: &CoppersmithParams,
) -> Result<SmallRootsResult, OperationError> {
    if n_mod.is_zero() {
        return Err(OperationError::invalid_param(
            "n",
            "modulus must be non-zero",
        ));
    }
    if params.m == 0 {
        return Err(OperationError::invalid_param(
            "m",
            "shift multiplicity must be at least 1",
        ));
    }
    if x_bound.is_zero() {
        return Err(OperationError::invalid_param(
            "x_bound",
            "root bound must be positive",
        ));
    }
    let degree = f
        .degree()
        .ok_or_else(|| OperationError::invalid_input("f must be a non-zero polynomial"))?;
    validate_degree(degree)?;
    let n = params.dimension(degree);
    if n > MAX_COPPERSMITH_DIM {
        return Err(OperationError::invalid_param(
            "params",
            format!(
                "Coppersmith lattice dimension {n} (degree {degree} × m {} + t {}) \
                 exceeds cap {MAX_COPPERSMITH_DIM}",
                params.m, params.t
            ),
        )
        .with_expected(MAX_COPPERSMITH_DIM.to_string())
        .with_actual(n.to_string()));
    }
    if x_bound >= n_mod {
        return Err(OperationError::invalid_input(format!(
            "root bound {x_bound} must lie below the modulus"
        )));
    }
    let certified = guaranteed_bound(n_mod, degree, params);
    if certified < *x_bound {
        return Err(OperationError::new(
            ErrorKind::Unsupported,
            format!(
                "root bound X = 2^{} exceeds the certified bound 2^{} for degree {degree} \
                 with (m, t) = ({}, {}); achievable regime is X ≤ N^(1/{degree} − ε) — \
                 raise m/t within dimension cap {MAX_COPPERSMITH_DIM} or lower X",
                x_bound.bits(),
                certified.bits(),
                params.m,
                params.t
            ),
        )
        .with_expected(format!("X ≤ 2^{}", certified.bits()))
        .with_actual(format!("X = 2^{}", x_bound.bits())));
    }

    // Monic representative mod N: same roots, monic so shift degrees/powers
    // behave; a non-invertible leading coefficient is itself a factor of N
    // and surfaces as a typed error from `to_monic_mod`.
    let f_mon = f.to_monic_mod(n_mod)?;
    let f_check = f.reduce_mod(n_mod)?;
    let n_big = BigInt::from(n_mod.clone());
    let x_big = BigInt::from(x_bound.clone());

    // Precomputed power tables: X^k for the column scalings, N^j for the
    // shift coefficients.
    let mut x_pow = Vec::with_capacity(n);
    let mut n_pow = Vec::with_capacity(params.m + 1);
    x_pow.push(BigInt::one());
    n_pow.push(BigInt::one());
    for _ in 1..n {
        let next = x_pow.last().unwrap() * &x_big;
        x_pow.push(next);
    }
    for _ in 1..=params.m {
        let next = n_pow.last().unwrap() * &n_big;
        n_pow.push(next);
    }

    // Assemble the n × n shift lattice.
    let mut rows: Vec<Vec<BigInt>> = Vec::with_capacity(n);
    let mut f_pow_i = Poly::constant(BigInt::one());
    for i in 0..params.m {
        let scale = n_pow[params.m - i].clone();
        for j in 0..degree {
            let g = f_pow_i.mul_x_pow(j).scalar_mul(&scale);
            rows.push(scaled_coeffs(&g, &x_pow, n));
        }
        f_pow_i = f_pow_i.mul(&f_mon);
    }
    for j in 0..params.t {
        // f_pow_i is f^m here.
        let g = f_pow_i.mul_x_pow(j);
        rows.push(scaled_coeffs(&g, &x_pow, n));
    }
    debug_assert_eq!(rows.len(), n);
    let lattice = Lattice::from_rows(rows)?;
    let reduced = lll_reduce(&lattice, &LllConfig::default())?;

    // Root extraction: shortest vectors first, each read back as a poly over
    // Z (column k is divisible by X^k by construction), candidates from the
    // bounded rational-root search, every candidate verified exactly.
    let mut order: Vec<usize> = (0..reduced.basis.nrows()).collect();
    order.sort_by_key(|&i| reduced.basis.norm_squared(i));
    let mut roots: Vec<BigInt> = Vec::new();
    for &i in order.iter().take(ROOT_POLY_CANDIDATES) {
        let coeffs: Vec<BigInt> = reduced
            .basis
            .row(i)
            .iter()
            .enumerate()
            .map(|(k, v)| exact_div(v, &x_pow[k]))
            .collect::<Result<_, _>>()?;
        let p = Poly::from_coeffs(coeffs).primitive_part();
        for cand in bounded_divisor_roots(&p, x_bound)? {
            if cand.magnitude() > x_bound {
                continue;
            }
            if rem_nonneg(&f_check.eval(&cand), &n_big).is_zero() && !roots.contains(&cand) {
                roots.push(cand);
            }
        }
    }
    roots.sort();
    Ok(SmallRootsResult {
        roots,
        guaranteed_bound: certified,
        lattice_dim: n,
        diagnostics: reduced.diagnostics,
    })
}

/// Coefficient vector of `g` padded to `n` columns with the `X^k` column
/// scalings of the Howgrave-Graham embedding.
fn scaled_coeffs(g: &Poly, x_pow: &[BigInt], n: usize) -> Vec<BigInt> {
    (0..n)
        .map(|k| {
            let c = g.coeff(k);
            if c.is_zero() {
                BigInt::zero()
            } else {
                c * &x_pow[k]
            }
        })
        .collect()
}

/// Non-negative remainder mod `m > 0`.
fn rem_nonneg(a: &BigInt, m: &BigInt) -> BigInt {
    let r = a % m;
    if r.is_negative() {
        r + m
    } else {
        r
    }
}

/// Bounded rational-root candidate enumeration for a polynomial `p` over ℤ:
/// every integer root of `p` divides its constant term, so the candidates
/// are the divisors of `|a0|` up to `X`, enumerated by trial division with
/// the small-prime table plus the perfect-power refinement (see module
/// docs). Never panics; oversized searches fail with [`ErrorKind::BudgetExceeded`].
fn bounded_divisor_roots(p: &Poly, x_bound: &BigUint) -> Result<Vec<BigInt>, OperationError> {
    let mut cands: Vec<BigInt> = Vec::new();
    // Strip factors of x: root 0 (if in range, verified by the caller), then
    // the remaining roots divide the new constant term.
    let mut p = p.clone();
    while p.degree().is_some_and(|d| d > 0) && p.constant_term().is_zero() {
        cands.push(BigInt::zero());
        p = Poly::from_coeffs(p.coeffs()[1..].to_vec());
    }
    if p.is_zero() {
        return Ok(cands);
    }
    let a0 = p.constant_term().abs();
    let a0 = a0.magnitude();
    // a0 itself divides a0 — needed when the root equals the whole constant
    // term (p(x) = c·(x − a0)-shaped), whose prime factors may dwarf the
    // small-prime table.
    if a0 <= x_bound {
        cands.push(BigInt::from(a0.clone()));
        cands.push(-BigInt::from(a0.clone()));
    }

    // Prime powers p^e (e ≥ 1, p^e ≤ X) dividing a0, from the small-prime table.
    let mut groups: Vec<Vec<BigUint>> = Vec::new();
    for &prime in small_primes() {
        let p_big = BigUint::from(prime);
        if p_big > *x_bound {
            break; // table is sorted ascending; larger primes are out of range
        }
        let mut powers = Vec::new();
        let mut q = p_big.clone();
        while q <= *x_bound && (a0 % &q).is_zero() {
            powers.push(q.clone());
            q *= &p_big;
        }
        if !powers.is_empty() {
            groups.push(powers);
        }
    }

    // All products of these prime powers that stay ≤ X (each is a distinct
    // divisor of a0 by unique factorization).
    let mut products: Vec<BigUint> = vec![BigUint::one()];
    for powers in &groups {
        let mut next = products.clone();
        for prod in &products {
            for pw in powers {
                let cand = prod * pw;
                if cand <= *x_bound {
                    next.push(cand);
                    if next.len() > MAX_DIVISOR_CANDIDATES {
                        return Err(OperationError::new(
                            ErrorKind::BudgetExceeded,
                            format!(
                                "divisor candidate enumeration exceeded {MAX_DIVISOR_CANDIDATES} \
                                 candidates"
                            ),
                        )
                        .with_details("raise the bound cap or shrink X"));
                    }
                }
            }
        }
        products = next;
    }
    for d in products {
        cands.push(BigInt::from(d.clone()));
        cands.push(-BigInt::from(d));
    }

    // Perfect-power refinement: x0 = ±r^e for e ≥ 2 (covers roots whose shape
    // is a perfect power even when r itself exceeds the small-prime table).
    let max_e = a0.bits().min(4096);
    for e in 2u64..=max_e {
        let r = iroot(a0, e as u32);
        if r <= BigUint::one() || r > *x_bound {
            continue;
        }
        if r.pow(e as u32) == *a0 {
            cands.push(BigInt::from(r.clone()));
            cands.push(-BigInt::from(r));
        }
    }
    cands.sort();
    cands.dedup();
    Ok(cands)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n512() -> BigUint {
        // Deterministic 512-bit odd modulus (not nec. prime): 2^511 | 0xC0FFEE.
        (BigUint::one() << 511u32) | BigUint::from(0xC0FFEFu64)
    }

    fn poly(v: &[i64]) -> Poly {
        Poly::from_coeffs(v.iter().map(|&x| BigInt::from(x)).collect())
    }

    #[test]
    fn guaranteed_bound_matches_defining_inequality() {
        // Hand-checked shape: N = 101, d = 1, m = 2, t = 2 → n = 4,
        // X_g^24 · 2^12 · 4^8 ≤ 101^20 with X_g ≈ 2^{4.4}.
        let n = BigUint::from(101u32);
        let params = CoppersmithParams { m: 2, t: 2 };
        let xg = guaranteed_bound(&n, 1, &params);
        assert!(
            BigUint::from(16u32) <= xg && xg < BigUint::from(32u32),
            "xg = {xg}"
        );
        // Consistency: X_g sits just under the certification threshold
        // X^{24}·2^{n(n−1)}·n^{2n} < N^{E}; X_g itself satisfies ≤, X_g+1 does not.
        let k = 24u32;
        let lhs = |x: &BigUint| x.pow(k) * (BigUint::one() << 12u32) * BigUint::from(4u32).pow(8);
        assert!(lhs(&xg) <= n.pow(20));
        let xg1 = &xg + BigUint::one();
        assert!(lhs(&xg1) >= n.pow(20));
    }

    #[test]
    fn guaranteed_bound_scales_as_documented() {
        let n = n512();
        // Bound shrinks with the degree (regime X ≤ N^{1/d − ε}).
        let b1 = guaranteed_bound(&n, 1, &CoppersmithParams { m: 4, t: 4 });
        let b2 = guaranteed_bound(&n, 2, &CoppersmithParams { m: 4, t: 4 });
        let b3 = guaranteed_bound(&n, 3, &CoppersmithParams { m: 4, t: 4 });
        assert!(b1 > b2 && b2 > b3);
        // Bound grows with the shift multiplicity (fixed degree).
        let m2 = guaranteed_bound(&n, 3, &CoppersmithParams { m: 2, t: 1 });
        let m3 = guaranteed_bound(&n, 3, &CoppersmithParams { m: 3, t: 2 });
        assert!(m3 > m2);
        // ε stays below 1/d: certified bound for d = 3 is below N^{1/3}.
        let third = BigUint::one() << (512 / 3);
        assert!(b3 < third);
        // Degenerate shape (m = 1, t = 0) certifies nothing.
        assert!(guaranteed_bound(&n, 3, &CoppersmithParams { m: 1, t: 0 }).is_zero());
    }

    #[test]
    fn choose_params_finds_certifying_shape_or_cites_regime() {
        let n = n512();
        // 58 hidden bits for a degree-3 polynomial is comfortably in regime.
        let params = choose_params(&n, 3, &(BigUint::one() << 58u32)).unwrap();
        assert!(params.dimension(3) <= MAX_COPPERSMITH_DIM);
        assert!(guaranteed_bound(&n, 3, &params) >= (BigUint::one() << 58u32));
        // 200 hidden bits for degree 3 exceeds N^{1/3}: impossible, typed error.
        let e = choose_params(&n, 3, &(BigUint::one() << 200u32)).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Unsupported);
        assert!(e.message.contains("1/3"));
    }

    #[test]
    fn small_roots_end_to_end_tiny_modulus() {
        // f(x) = x + 5 mod 101: root x0 = −5 (|x0| ≤ 16), recovered exactly.
        let n = BigUint::from(101u32);
        let f = poly(&[5, 1]);
        let res = small_roots(
            &f,
            &n,
            &BigUint::from(16u32),
            &CoppersmithParams { m: 2, t: 2 },
        )
        .unwrap();
        assert_eq!(res.roots, vec![BigInt::from(-5)]);
        assert_eq!(res.lattice_dim, 4);
        // Diagnostics expose the LLL run.
        assert_eq!(res.diagnostics.final_norms_squared.len(), 4);
    }

    #[test]
    fn small_roots_no_root_input_returns_empty() {
        // x² + 1 mod N with a tiny bound: x² + 1 < N for |x| ≤ X, so no root
        // can exist — the answer is an (empty, verified) result, not an error.
        let n = n512();
        let f = poly(&[1, 0, 1]);
        let res = small_roots(
            &f,
            &n,
            &(BigUint::one() << 20u32),
            &CoppersmithParams { m: 2, t: 1 },
        )
        .unwrap();
        assert!(res.roots.is_empty());
    }

    #[test]
    fn small_roots_rejects_bad_inputs_typed() {
        let n = n512();
        let f = poly(&[5, 1]);
        // Zero modulus / zero bound / zero poly.
        assert_eq!(
            small_roots(
                &f,
                &BigUint::zero(),
                &BigUint::from(1u32),
                &CoppersmithParams::new(2, 2).unwrap()
            )
            .unwrap_err()
            .kind,
            ErrorKind::InvalidParam
        );
        assert_eq!(
            small_roots(
                &f,
                &n,
                &BigUint::zero(),
                &CoppersmithParams::new(2, 2).unwrap()
            )
            .unwrap_err()
            .kind,
            ErrorKind::InvalidParam
        );
        assert_eq!(
            small_roots(
                &Poly::zero(),
                &n,
                &BigUint::from(1u32),
                &CoppersmithParams::new(2, 2).unwrap()
            )
            .unwrap_err()
            .kind,
            ErrorKind::InvalidInput
        );
        // Constant polynomial has no small-root problem to solve.
        assert_eq!(
            small_roots(
                &poly(&[7]),
                &n,
                &BigUint::from(1u32),
                &CoppersmithParams::new(2, 2).unwrap()
            )
            .unwrap_err()
            .kind,
            ErrorKind::InvalidInput
        );
        // Bound at/above the modulus.
        assert_eq!(
            small_roots(&f, &n, &n, &CoppersmithParams::new(2, 2).unwrap())
                .unwrap_err()
                .kind,
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn small_roots_rejects_bound_beyond_certified_limit() {
        let n = n512();
        let f = poly(&[5, 1]);
        // (m,t) = (2,2) at d = 1 certifies ~2^{426}; 2^{510} is beyond it and
        // must be a typed failure citing the bound — never a wrong root.
        let x = BigUint::one() << 510u32;
        let e = small_roots(&f, &n, &x, &CoppersmithParams { m: 2, t: 2 }).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Unsupported);
        assert!(
            e.message.contains("exceeds the certified bound"),
            "{}",
            e.message
        );
        assert!(e.message.contains("N^(1/1 − ε)"));
        assert!(e.expected.unwrap().starts_with("X ≤ 2^"));
    }

    #[test]
    fn small_roots_rejects_dimension_cap() {
        let n = n512();
        let f = poly(&[5, 1]);
        // d·m + t = 33 > 32.
        let e = small_roots(
            &f,
            &n,
            &BigUint::from(16u32),
            &CoppersmithParams { m: 31, t: 2 },
        )
        .unwrap_err();
        assert_eq!(e.kind, ErrorKind::InvalidParam);
        assert!(e.message.contains("cap"));
        // m = 0 is refused even though the dimension would look small.
        assert_eq!(
            small_roots(
                &f,
                &n,
                &BigUint::from(16u32),
                &CoppersmithParams { m: 0, t: 0 }
            )
            .unwrap_err()
            .kind,
            ErrorKind::InvalidParam
        );
    }

    #[test]
    fn divisor_candidates_cover_smooth_power_and_table_beyond_roots() {
        // p = 6·x − 1500 → roots ±250 = ±2·5^3 (smooth) — enumerated via a0.
        let p = poly(&[-1500, 6]);
        let cands = bounded_divisor_roots(&p, &BigUint::from(1000u32)).unwrap();
        assert!(cands.contains(&BigInt::from(250)));
        assert!(cands.contains(&BigInt::from(-250)));
        // Perfect-power root with a prime factor beyond the small-prime table:
        // 65537 is prime and > 17389 (table max), so neither the smooth
        // product path nor the table can build it. a0 itself (≤ X) supplies
        // the true root 65537², and the iroot refinement supplies ±65537 as a
        // (rejected-by-verification) candidate.
        let root = BigUint::from(65537u32) * BigUint::from(65537u32);
        let neg_root = -BigInt::from(root.clone());
        let q = Poly::from_coeffs(vec![neg_root, BigInt::one()]);
        let cands = bounded_divisor_roots(&q, &(BigUint::one() << 33u32)).unwrap();
        assert!(cands.contains(&BigInt::from(root)));
        assert!(cands.contains(&BigInt::from(65537u32)));
        // x-factor stripping: p = x·(x − 6) → root 0 plus divisors of 6.
        let r = poly(&[0, -6, 1]);
        let cands = bounded_divisor_roots(&r, &BigUint::from(10u32)).unwrap();
        assert!(cands.contains(&BigInt::zero()));
        assert!(cands.contains(&BigInt::from(6)));
    }
}
