//! Coppersmith small-root attacks via the Howgrave-Graham lattice over the
//! exact integer LLL of [`super::lll`].
//!
//! ## Problem
//!
//! Given a polynomial `f(x)` of degree `d` modulo a composite `N`, a bound
//! `X`, and a divisor fraction β ∈ (0, 1] ([`CoppersmithBeta`]), find every
//! integer `x0` with `|x0| ≤ X` such that `f(x0)` vanishes modulo some
//! divisor `b ≥ N^β` of `N`. β = 1 is the plain small-root setting
//! (`f(x0) ≡ 0 (mod N)`): a root hidden in the low bits of a modular
//! relation — stereotyped messages, padding recovery. β < 1 is the
//! divisor-root setting — known-MSB factoring, where `f(x0) = p` vanishes
//! modulo the unknown factor `p ≈ N^{1/2}` of `N`. The classical regime is
//! `X ≤ N^{β²/d − ε}`.
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
//! reduced to their monic representatives mod `N`. If `f(x0) ≡ 0 (mod b)`
//! for a divisor `b ≥ N^β`, every row polynomial vanishes at `x0` modulo
//! `b^m` (each `N^{m−i}` carries a factor `b^{m−i}`), hence so does any
//! integer combination. Each coefficient of `x^k` is scaled by `X^k`, making
//! the coefficient vector of `p(X·x)` a lattice vector whose norm bounds
//! `|p(x0)|`: `|p(x0)| ≤ ‖p‖·√n` (Cauchy–Schwarz over
//! `(1, x0, …, x0^{n−1})`, `|x0| ≤ X`). The lattice is `n = d·m + t`
//! dimensional with determinant
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
//! *certified* whenever `2^{(n−1)/4}·det^{1/n}·√n < b^m ≥ N^{βm}`. Solving
//! for `X` gives the certified bound implemented in [`guaranteed_bound`]
//! (integer-exact form: `X^{2n(n−1)δ}·(2^{n(n−1)}·n^{2n})^δ < N^{E}` with
//! `E = 4νmn − 2δd·m(m+1)` for β = ν/δ), i.e.
//!
//! ```text
//! X_guaranteed ≈ N^{ε(d,m,t;β)},  ε = m(2νn/δ − d(m+1))·δ / (2n(n−1)δ)
//! ```
//!
//! Asymptotics (dimension `n = dm + t` capped at [`MAX_COPPERSMITH_DIM`]):
//!
//! * β = 1, pure x-shifts (`t = 0`): `ε = (m−1)/(dm−1) → 1/d`;
//! * β = 1/2, degree 1, `t = m`: `ε → 1/4 = β²` — the classical
//!   known-MSB bound (up to half the bits of the smaller factor);
//! * for every setting, [`choose_params`] searches the documented
//!   shapes by increasing dimension and returns the first that certifies.
//!
//! Concrete values at `bits(N) = 512`:
//!
//! | d | β   | m | t | n  | ε      | certified X     |
//! |---|-----|---|---|----|--------|-----------------|
//! | 1 | 1/2 | 4 | 4 | 8  | 0.214  | ~2^{109}        |
//! | 1 | 1/2 | 2 | 2 | 4  | 0.167  | ~2^{85}         |
//! | 1 | 1   | 4 | 4 | 8  | 0.786  | ~2^{402}        |
//! | 3 | 1   | 3 | 2 | 11 | 0.273  | ~2^{139}        |
//! | 3 | 1   | 4 | 3 | 15 | 0.286  | ~2^{146}        |
//!
//! A bound `X` beyond `X_guaranteed` for the chosen parameters is rejected
//! with a typed [`ErrorKind::Unsupported`] error that cites the bound — the
//! API never answers "no roots" for a problem that merely exceeded the
//! *certified* regime, and it never returns a root without exact
//! verification.
//!
//! ## Root extraction
//!
//! A reduced vector is read back as a polynomial `p` over ℤ (the `X^k`
//! scalings divide out exactly). For any output vector `v` satisfying
//! Howgrave-Graham (`‖v‖·√n < b^m`), `p(x0) = 0` over ℤ — not just mod
//! `b^m` — so by the rational-root theorem `x0` divides the constant term
//! `a0` of the primitive part of `p`. The same holds for *every*
//! HG-satisfying vector, so the candidate pool enumerates divisors of the
//! **gcd of the constant terms of the few shortest vectors**: the gcd
//! retains every prime factor of `x0` while shedding most of the incidental
//! smooth factors of an individual `a0`, which keeps the enumeration small.
//! Candidates are enumerated by trial division with the small-prime table
//! (all prime powers `p^e ≤ X` dividing the target), plus a perfect-power
//! refinement (`a0 = r^e` via [`crate::math::iroot`]) and the `a0` value
//! itself.
//!
//! Every candidate is then verified *exactly*: `|x0| ≤ X` and
//! `gcd(|f(x0)|, N) > 1` — i.e. `f(x0)` genuinely vanishes modulo a
//! non-trivial divisor of `N` (`gcd = N` recovers the β = 1 mod-`N` case).
//! A candidate that fails this is dropped, so the API never emits a wrong
//! root.
//!
//! **Documented limitation of the search:** divisor enumeration uses the
//! crate's small-prime table (primes < 2^{14}); a root with a prime factor
//! above that table and outside a perfect-power shape would be missed
//! (reported as no root — never a wrong root). Coppersmith instances in
//! this regime use smooth hidden offsets; this is the standard trade-off
//! for big-integer-only implementations without a factoring oracle for the
//! ~`N^m`-sized constant term.
//!
//! ## Resource bounds
//!
//! Dimension is capped at [`MAX_COPPERSMITH_DIM`] (≤ the LLL
//! [`super::MAX_DIM`]), polynomial degrees at
//! [`super::poly::MAX_POLY_DEGREE`], the lattice entries at the module bit
//! budget, and the candidate enumeration at a fixed budget. All failures
//! are typed [`OperationError`]s; no panics on user input.

use super::exact_div;
use super::lll::{lll_reduce, LllConfig, LllDiagnostics};
use super::matrix::Lattice;
use super::poly::{validate_degree, Poly};
use crate::math::{gcd, iroot, small_primes};
use cybercipher_core::error::{ErrorKind, OperationError};
use num_bigint::{BigInt, BigUint};
use num_traits::{One, Signed, Zero};
use serde::{Deserialize, Serialize};

/// Hard cap on the Coppersmith lattice dimension `n = d·m + t`. The certified
/// bound grows only logarithmically with `n` (see the parameterization table
/// in the module docs), so requests beyond this cap are refused with a typed
/// error instead of mounting a hopeless reduction.
pub const MAX_COPPERSMITH_DIM: usize = 32;

/// How many reduced vectors (in norm order) feed the root search. The
/// shortest is certified to satisfy Howgrave-Graham; the runners-up are a
/// cheap robustness net, and their constant terms are gcd-ed into the
/// divisor pool (see module docs).
const ROOT_POLY_CANDIDATES: usize = 4;

/// Cap on enumerated divisor candidates (hostile constant terms with many
/// small prime factors cannot blow up the search).
const MAX_DIVISOR_CANDIDATES: usize = 1_000_000;

/// Tighter cap for the big-`X` (≥ 2^63) enumeration path, where candidates
/// are full [`BigUint`]s.
const MAX_DIVISOR_CANDIDATES_WIDE: usize = 100_000;

/// Divisor fraction β = num/den ∈ (0, 1]: a root is searched modulo an
/// (unknown) divisor `b ≥ N^β` of `N`. [`CoppersmithBeta::MOD_N`] (β = 1)
/// is the plain small-root setting; [`CoppersmithBeta::HALF`] (β = 1/2) is
/// the known-MSB factoring setting for balanced moduli.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoppersmithBeta {
    pub num: u32,
    pub den: u32,
}

impl CoppersmithBeta {
    /// β = 1: roots modulo `N` itself.
    pub const MOD_N: CoppersmithBeta = CoppersmithBeta { num: 1, den: 1 };
    /// β = 1/2: roots modulo a balanced-size factor (known-MSB regime).
    pub const HALF: CoppersmithBeta = CoppersmithBeta { num: 1, den: 2 };

    /// Validate β ∈ (0, 1].
    pub fn new(num: u32, den: u32) -> Result<Self, OperationError> {
        let beta = CoppersmithBeta { num, den };
        if den == 0 || num == 0 || num > den {
            return Err(OperationError::invalid_param(
                "beta",
                format!("divisor fraction β must lie in (0, 1], got {num}/{den}"),
            )
            .with_expected("β = num/den in (0, 1]")
            .with_actual(format!("{num}/{den}")));
        }
        Ok(beta)
    }
}

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
/// certifies recovery of every root `|x0| ≤ X` modulo any divisor
/// `b ≥ N^β` — see the derivation in the module docs. Zero when the shape
/// cannot certify anything (e.g. `m = t = 1`, β = 1/2).
pub fn guaranteed_bound(
    n_mod: &BigUint,
    degree: usize,
    params: &CoppersmithParams,
    beta: &CoppersmithBeta,
) -> BigUint {
    let n = params.dimension(degree);
    if n < 2 {
        return BigUint::zero();
    }
    // Exact integer form (β = ν/δ):
    //   X^{2n(n−1)·δ} · (2^{n(n−1)}·n^{2n})^{δ} < N^{4νmn − 2δ·d·m(m+1)}
    let e = 4 * beta.num as u64 * params.m as u64 * n as u64;
    let e_sub = 2 * beta.den as u64 * degree as u64 * params.m as u64 * (params.m as u64 + 1);
    if e <= e_sub {
        return BigUint::zero();
    }
    let num = n_mod.pow((e - e_sub) as u32);
    let den_base = (BigUint::one() << (n * (n - 1))) * BigUint::from(n as u64).pow(2 * n as u32);
    let denom = den_base.pow(beta.den);
    let root_degree = (2 * n * (n - 1)) as u64 * beta.den as u64;
    iroot(&(&num / &denom), root_degree as u32)
}

/// Pick shift parameters certifying the requested bound, scanning shapes in
/// order of increasing dimension (then increasing `m`) — the documented
/// parameterization as a search. A bit-length gate skips shapes that cannot
/// certify before any big arithmetic; errors when no shape within
/// [`MAX_COPPERSMITH_DIM`] certifies `X`, citing the regime.
pub fn choose_params(
    n_mod: &BigUint,
    degree: usize,
    x_bound: &BigUint,
    beta: &CoppersmithBeta,
) -> Result<CoppersmithParams, OperationError> {
    validate_degree(degree)?;
    let mut best_bound = BigUint::zero();
    let n_bits = n_mod.bits().max(1);
    for n in (degree + 1)..=MAX_COPPERSMITH_DIM {
        // Necessary bit-length condition for certification, integer math
        // only: E·bits(N) ≥ 2n(n−1)·δ·bits(X) + δ·log2(2^{n(n−1)}·n^{2n}).
        let k = 2 * n * (n - 1);
        let den_log2 =
            (beta.den as u64) * ((n * (n - 1)) as u64 + 2 * n as u64 * (n.ilog2() as u64));
        let needed = k as u64 * beta.den as u64 * x_bound.bits() + den_log2;
        for m in 1..=(n / degree) {
            let e_gross = 4 * beta.num as u64 * m as u64 * n as u64;
            let e_sub = 2 * beta.den as u64 * degree as u64 * m as u64 * (m as u64 + 1);
            if e_gross <= e_sub {
                continue;
            }
            // Gate on the *net* exponent E = e_gross − e_sub: certification
            // needs E·bits(N) ≥ needed, and shapes failing that never reach
            // the multi-hundred-thousand-bit exact arithmetic.
            let e_net = e_gross - e_sub;
            if e_net.checked_mul(n_bits).is_none_or(|lhs| lhs < needed) {
                continue;
            }
            let params = CoppersmithParams {
                m,
                t: n - degree * m,
            };
            let bound = guaranteed_bound(n_mod, degree, &params, beta);
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
             X = 2^{} for degree {degree} at β = {}/{}: achievable regime is \
             X ≤ N^(β²/d − ε) with β = {}/{} and d = {degree} \
             (best certified bound found: 2^{} bits)",
            x_bound.bits(),
            beta.num,
            beta.den,
            beta.num,
            beta.den,
            best_bound.bits()
        ),
    )
    .with_expected(format!("X ≤ N^(β²/d − ε), β = {}/{}", beta.num, beta.den))
    .with_actual(format!("X = 2^{}", x_bound.bits())))
}

/// Outcome of a small-root search: every root is *verified exactly*
/// (`|x0| ≤ X` and `gcd(|f(x0)|, N) > 1`); an empty `roots` means no
/// verified root exists in range — never an unverified guess.
#[derive(Debug, Clone)]
pub struct SmallRootsResult {
    /// Verified roots, sorted ascending, deduplicated.
    pub roots: Vec<BigInt>,
    /// The certified bound `X_guaranteed` for the chosen parameters.
    pub guaranteed_bound: BigUint,
    /// The divisor fraction the search was certified for.
    pub beta: CoppersmithBeta,
    /// Lattice dimension `n = d·m + t` that was reduced.
    pub lattice_dim: usize,
    /// LLL run diagnostics (step counts, final norms).
    pub diagnostics: LllDiagnostics,
}

/// Find all integers `x0` with `|x0| ≤ x_bound` such that `f(x0)` vanishes
/// modulo some divisor `b ≥ N^β` of `n_mod`, using the Howgrave-Graham
/// lattice reduced by exact integer LLL.
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
    beta: &CoppersmithBeta,
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
    CoppersmithBeta::new(beta.num, beta.den)?;
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
    let certified = guaranteed_bound(n_mod, degree, params, beta);
    if certified < *x_bound {
        return Err(OperationError::new(
            ErrorKind::Unsupported,
            format!(
                "root bound X = 2^{} exceeds the certified bound 2^{} for degree {degree} \
                 at β = {}/{} with (m, t) = ({}, {}); achievable regime is \
                 X ≤ N^(β²/d − ε) — raise m/t within dimension cap \
                 {MAX_COPPERSMITH_DIM} or lower X",
                x_bound.bits(),
                certified.bits(),
                beta.num,
                beta.den,
                params.m,
                params.t
            ),
        )
        .with_expected(format!("X ≤ 2^{} (X ≤ N^(β²/d − ε))", certified.bits()))
        .with_actual(format!("X = 2^{}", x_bound.bits())));
    }

    // Monic representative mod N: same roots, and monic so shift degrees and
    // powers behave. A non-invertible leading coefficient is itself a factor
    // of N and surfaces as a typed error from `to_monic_mod`.
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

    // Root extraction. Read the shortest vectors back as polynomials over Z
    // (column k is divisible by X^k by construction), make them primitive
    // and strip factors of x; every HG-satisfying polynomial has the true
    // root x0 among its integer roots, so x0 divides each of their constant
    // terms — and therefore their gcd, which the divisor enumeration walks.
    let mut order: Vec<usize> = (0..reduced.basis.nrows()).collect();
    order.sort_by_key(|&i| reduced.basis.norm_squared(i));
    let mut primitive_polys: Vec<Poly> = Vec::new();
    let mut has_zero_root = false;
    for &i in order.iter().take(ROOT_POLY_CANDIDATES) {
        let coeffs: Vec<BigInt> = reduced
            .basis
            .row(i)
            .iter()
            .enumerate()
            .map(|(k, v)| exact_div(v, &x_pow[k]))
            .collect::<Result<_, _>>()?;
        let mut p = Poly::from_coeffs(coeffs).primitive_part();
        while p.degree().is_some_and(|d| d > 0) && p.constant_term().is_zero() {
            has_zero_root = true;
            p = Poly::from_coeffs(p.coeffs()[1..].to_vec());
        }
        if !p.is_zero() {
            primitive_polys.push(p);
        }
    }
    let constant_terms: Vec<BigUint> = primitive_polys
        .iter()
        .map(|p| p.constant_term().abs().magnitude().clone())
        .collect();

    // Candidate pools, tried in order until one yields a verified root:
    // 1. gcd of the constant terms of the two shortest vectors — every
    //    HG-satisfying vector has x0 as an integer root, so x0 divides the
    //    gcd, which also strips the incidental smooth factors that make a
    //    single constant term divisor-dense;
    // 2. the shortest vector's constant term alone — the fallback when the
    //    runner-up is short *without* satisfying Howgrave-Graham (only the
    //    first vector is certified), so the gcd would be coprime to x0.
    let mut pools: Vec<BigUint> = Vec::new();
    if constant_terms.len() >= 2 && !constant_terms[0].is_zero() && !constant_terms[1].is_zero() {
        let g = gcd(&constant_terms[0], &constant_terms[1]);
        if !g.is_zero() {
            pools.push(g);
        }
    }
    if let Some(a0) = constant_terms.first().filter(|a| !a.is_zero()) {
        if pools.last() != Some(a0) {
            pools.push(a0.clone());
        }
    }

    // Exact verification of every candidate: bounded in magnitude and
    // vanishing mod a non-trivial divisor of N.
    let mut roots: Vec<BigInt> = Vec::new();
    for pool in &pools {
        let mut cands = divisor_candidates_upto(pool, x_bound)?;
        if has_zero_root {
            cands.push(BigInt::zero());
        }
        for cand in cands {
            if cand.magnitude() > x_bound {
                continue;
            }
            let fv = f_check.eval(&cand);
            if gcd(fv.magnitude(), n_mod) > BigUint::one() && !roots.contains(&cand) {
                roots.push(cand);
            }
        }
        if !roots.is_empty() {
            break;
        }
    }
    roots.sort();
    Ok(SmallRootsResult {
        roots,
        guaranteed_bound: certified,
        beta: *beta,
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

/// Distinct divisors `d` of the non-zero integer `a0` with `1 ≤ d ≤ x_bound`,
/// returned as ±[`BigInt`] pairs, sorted and deduplicated.
///
/// Enumerated from the prime powers `p^e ≤ x_bound` dividing `a0` (small
/// prime table), with a u64 fast path for practical bounds; `a0` itself is
/// included when it fits the bound (the root may be the whole constant
/// term). Divisor-dense constant terms are bounded by the candidate budget —
/// callers should shrink the pool first (the gcd trick in [`small_roots`]).
fn divisor_candidates_upto(a0: &BigUint, x_bound: &BigUint) -> Result<Vec<BigInt>, OperationError> {
    debug_assert!(!a0.is_zero());
    // Fast path: every partial product fits a u64 with headroom.
    if let Ok(xu) = u64::try_from(x_bound.clone()) {
        if xu <= (1u64 << 62) {
            let mut vals: Vec<u64> = vec![1];
            for &prime in small_primes() {
                if prime > xu {
                    break; // table sorted ascending; larger primes are out of range
                }
                let mut powers: Vec<u64> = Vec::new();
                let mut q = prime;
                while q <= xu && (a0 % q).is_zero() {
                    powers.push(q);
                    match q.checked_mul(prime) {
                        Some(next) => q = next,
                        None => break,
                    }
                }
                if powers.is_empty() {
                    continue;
                }
                let base = vals.clone();
                for v in &base {
                    for pw in &powers {
                        match v.checked_mul(*pw) {
                            Some(c) if c <= xu => {
                                vals.push(c);
                                if vals.len() > MAX_DIVISOR_CANDIDATES {
                                    return Err(budget_error());
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            vals.sort_unstable();
            vals.dedup();
            let mut cands: Vec<BigInt> = Vec::with_capacity(vals.len() * 2);
            for v in vals {
                cands.push(BigInt::from(v));
                cands.push(-BigInt::from(v));
            }
            cands.extend(perfect_power_candidates(a0, x_bound));
            if *a0 <= *x_bound {
                cands.push(BigInt::from(a0.clone()));
                cands.push(-BigInt::from(a0.clone()));
            }
            cands.sort();
            cands.dedup();
            return Ok(cands);
        }
    }

    // Wide path (x_bound ≥ 2^63): same enumeration over BigUints, tighter
    // budget.
    let mut vals: Vec<BigUint> = vec![BigUint::one()];
    for &prime in small_primes() {
        let p_big = BigUint::from(prime);
        if p_big > *x_bound {
            break;
        }
        let mut powers = Vec::new();
        let mut q = p_big.clone();
        while q <= *x_bound && (a0 % &q).is_zero() {
            powers.push(q.clone());
            q *= &p_big;
        }
        if powers.is_empty() {
            continue;
        }
        let base = vals.clone();
        for v in &base {
            for pw in &powers {
                let cand = v * pw;
                if cand <= *x_bound {
                    vals.push(cand);
                    if vals.len() > MAX_DIVISOR_CANDIDATES_WIDE {
                        return Err(budget_error());
                    }
                }
            }
        }
    }
    vals.sort();
    vals.dedup();
    let mut cands: Vec<BigInt> = Vec::with_capacity(vals.len() * 2);
    for v in vals {
        cands.push(BigInt::from(v.clone()));
        cands.push(-BigInt::from(v));
    }
    cands.extend(perfect_power_candidates(a0, x_bound));
    if *a0 <= *x_bound {
        cands.push(BigInt::from(a0.clone()));
        cands.push(-BigInt::from(a0.clone()));
    }
    cands.sort();
    cands.dedup();
    Ok(cands)
}

/// Perfect-power refinement: if `a0` is an exact e-th power (e ≥ 2), its
/// root r is a divisor of `a0` the prime-table walk may be unable to build
/// (r's own prime factors can exceed the table). Adds ±r when `r ≤ x_bound`.
fn perfect_power_candidates(a0: &BigUint, x_bound: &BigUint) -> Vec<BigInt> {
    let mut out = Vec::new();
    let max_e = a0.bits().min(4096);
    for e in 2u64..=max_e {
        let r = iroot(a0, e as u32);
        if r <= BigUint::one() || r > *x_bound {
            continue;
        }
        if r.pow(e as u32) == *a0 {
            out.push(BigInt::from(r.clone()));
            out.push(-BigInt::from(r));
        }
    }
    out
}

fn budget_error() -> OperationError {
    OperationError::new(
        ErrorKind::BudgetExceeded,
        "divisor candidate enumeration exceeded its budget".to_string(),
    )
    .with_details("shrink X or narrow the candidate pool")
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
    fn beta_validation() {
        assert!(CoppersmithBeta::new(1, 2).is_ok());
        assert!(CoppersmithBeta::new(1, 1).is_ok());
        assert!(CoppersmithBeta::new(0, 2).is_err());
        assert!(CoppersmithBeta::new(1, 0).is_err());
        assert!(CoppersmithBeta::new(3, 2).is_err());
    }

    #[test]
    fn guaranteed_bound_matches_defining_inequality() {
        // Hand-checked shape: N = 101, d = 1, m = 2, t = 2, β = 1 → n = 4,
        // X_g^24 · 2^12 · 4^8 ≤ 101^20 with X_g ≈ 2^{4.4}.
        let n = BigUint::from(101u32);
        let params = CoppersmithParams { m: 2, t: 2 };
        let xg = guaranteed_bound(&n, 1, &params, &CoppersmithBeta::MOD_N);
        assert!(
            BigUint::from(16u32) <= xg && xg < BigUint::from(32u32),
            "xg = {xg}"
        );
        // Consistency: X_g sits just under the certification threshold; X_g
        // itself satisfies ≤, X_g+1 does not.
        let k = 24u32;
        let lhs = |x: &BigUint| x.pow(k) * (BigUint::one() << 12u32) * BigUint::from(4u32).pow(8);
        assert!(lhs(&xg) <= n.pow(20));
        let xg1 = &xg + BigUint::one();
        assert!(lhs(&xg1) >= n.pow(20));
    }

    #[test]
    fn guaranteed_bound_scales_as_documented() {
        let n = n512();
        // Bound shrinks with the degree (regime X ≤ N^{β²/d − ε}).
        let b1 = guaranteed_bound(
            &n,
            1,
            &CoppersmithParams { m: 4, t: 4 },
            &CoppersmithBeta::MOD_N,
        );
        let b2 = guaranteed_bound(
            &n,
            2,
            &CoppersmithParams { m: 4, t: 4 },
            &CoppersmithBeta::MOD_N,
        );
        let b3 = guaranteed_bound(
            &n,
            3,
            &CoppersmithParams { m: 4, t: 4 },
            &CoppersmithBeta::MOD_N,
        );
        assert!(b1 > b2 && b2 > b3);
        // Bound grows with the shift multiplicity (fixed degree and β).
        let m2 = guaranteed_bound(
            &n,
            3,
            &CoppersmithParams { m: 2, t: 1 },
            &CoppersmithBeta::MOD_N,
        );
        let m3 = guaranteed_bound(
            &n,
            3,
            &CoppersmithParams { m: 3, t: 2 },
            &CoppersmithBeta::MOD_N,
        );
        assert!(m3 > m2);
        // ε stays below 1/d: certified bound for d = 3 is below N^{1/3}.
        let third = BigUint::one() << (512 / 3);
        assert!(b3 < third);
        // Degenerate shape (m = 1, t = 0) certifies nothing.
        assert!(guaranteed_bound(
            &n,
            3,
            &CoppersmithParams { m: 1, t: 0 },
            &CoppersmithBeta::MOD_N
        )
        .is_zero());
        // β = 1/2 (divisor roots) is strictly harder than β = 1: d = 1 with
        // (m, t) = (4, 4) certifies ~N^{0.214} ≈ 2^{109}, not ~N^{0.786}.
        let half = guaranteed_bound(
            &n,
            1,
            &CoppersmithParams { m: 4, t: 4 },
            &CoppersmithBeta::HALF,
        );
        assert!(half < b1, "β=1/2 must certify less than β=1");
        assert!(
            half >= (BigUint::one() << 100u32),
            "half = 2^{}",
            half.bits()
        );
        assert!(
            half < (BigUint::one() << 120u32),
            "half = 2^{}",
            half.bits()
        );
    }

    #[test]
    fn choose_params_finds_certifying_shape_or_cites_regime() {
        let n = n512();
        // 58 hidden bits for a degree-3 polynomial is comfortably in regime.
        let params =
            choose_params(&n, 3, &(BigUint::one() << 58u32), &CoppersmithBeta::MOD_N).unwrap();
        assert!(params.dimension(3) <= MAX_COPPERSMITH_DIM);
        assert!(
            guaranteed_bound(&n, 3, &params, &CoppersmithBeta::MOD_N) >= (BigUint::one() << 58u32)
        );
        // Divisor setting too.
        let half =
            choose_params(&n, 1, &(BigUint::one() << 16u32), &CoppersmithBeta::HALF).unwrap();
        assert!(
            guaranteed_bound(&n, 1, &half, &CoppersmithBeta::HALF) >= (BigUint::one() << 16u32)
        );
        // 200 hidden bits for degree 3 exceeds N^{1/3}: impossible, typed error.
        let e =
            choose_params(&n, 3, &(BigUint::one() << 200u32), &CoppersmithBeta::MOD_N).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Unsupported);
        assert!(e.message.contains("β²/d"), "{}", e.message);
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
            &CoppersmithBeta::MOD_N,
        )
        .unwrap();
        assert_eq!(res.roots, vec![BigInt::from(-5)]);
        assert_eq!(res.lattice_dim, 4);
        assert_eq!(res.beta, CoppersmithBeta::MOD_N);
        // Diagnostics expose the LLL run.
        assert_eq!(res.diagnostics.final_norms_squared.len(), 4);
    }

    #[test]
    fn small_roots_recovers_factor_root_mod_divisor() {
        // Known-MSB in miniature: N = p·q (32-bit factors), f(x) = (p − 5) + x
        // has the root x0 = 5 modulo p — a divisor b ≥ N^{1/2}. β = 1/2 with
        // (m, t) = (2, 2) certifies it, and gcd(f(x0), N) = p verifies.
        let mut state = 0xABCDEFu64;
        let p = crate::math::weak_prime(32, &mut state);
        let q = crate::math::weak_prime(32, &mut state);
        let n = &p * &q;
        let big_k = &p - 5u32;
        let f = Poly::from_coeffs(vec![BigInt::from(big_k.clone()), BigInt::one()]);
        let res = small_roots(
            &f,
            &n,
            &BigUint::from(8u32),
            &CoppersmithParams { m: 2, t: 2 },
            &CoppersmithBeta::HALF,
        )
        .unwrap();
        assert_eq!(res.roots, vec![BigInt::from(5)]);
        // And the recovered offset indeed factors N.
        let factor = crate::math::gcd(&(&big_k + 5u32), &n);
        assert_eq!(factor, p);
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
            &CoppersmithBeta::MOD_N,
        )
        .unwrap();
        assert!(res.roots.is_empty());
    }

    #[test]
    fn small_roots_rejects_bad_inputs_typed() {
        let n = n512();
        let f = poly(&[5, 1]);
        // Zero modulus / zero bound / zero poly / bad β.
        assert_eq!(
            small_roots(
                &f,
                &BigUint::zero(),
                &BigUint::from(1u32),
                &CoppersmithParams::new(2, 2).unwrap(),
                &CoppersmithBeta::MOD_N
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
                &CoppersmithParams::new(2, 2).unwrap(),
                &CoppersmithBeta::MOD_N
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
                &CoppersmithParams::new(2, 2).unwrap(),
                &CoppersmithBeta::MOD_N
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
                &CoppersmithParams::new(2, 2).unwrap(),
                &CoppersmithBeta::MOD_N
            )
            .unwrap_err()
            .kind,
            ErrorKind::InvalidInput
        );
        // Bound at/above the modulus.
        assert_eq!(
            small_roots(
                &f,
                &n,
                &n,
                &CoppersmithParams::new(2, 2).unwrap(),
                &CoppersmithBeta::MOD_N
            )
            .unwrap_err()
            .kind,
            ErrorKind::InvalidInput
        );
        // β outside (0, 1] (struct literal bypasses the constructor check).
        assert_eq!(
            small_roots(
                &f,
                &n,
                &BigUint::from(1u32),
                &CoppersmithParams::new(2, 2).unwrap(),
                &CoppersmithBeta { num: 3, den: 2 }
            )
            .unwrap_err()
            .kind,
            ErrorKind::InvalidParam
        );
    }

    #[test]
    fn small_roots_rejects_bound_beyond_certified_limit() {
        let n = n512();
        let f = poly(&[5, 1]);
        // (m,t) = (2,2) at d = 1, β = 1 certifies ~2^{426}; 2^{510} is beyond
        // it and must be a typed failure citing the bound — never a wrong root.
        let x = BigUint::one() << 510u32;
        let e = small_roots(
            &f,
            &n,
            &x,
            &CoppersmithParams { m: 2, t: 2 },
            &CoppersmithBeta::MOD_N,
        )
        .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Unsupported);
        assert!(
            e.message.contains("exceeds the certified bound"),
            "{}",
            e.message
        );
        assert!(e.message.contains("β²/d"), "{}", e.message);
        assert!(e.expected.as_deref().unwrap().starts_with("X ≤ 2^"));
        // Same for the divisor setting: β = 1/2 certifies ~2^{85} here.
        let e = small_roots(
            &f,
            &n,
            &(BigUint::one() << 500u32),
            &CoppersmithParams { m: 2, t: 2 },
            &CoppersmithBeta::HALF,
        )
        .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Unsupported);
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
            &CoppersmithBeta::MOD_N,
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
                &CoppersmithParams { m: 0, t: 0 },
                &CoppersmithBeta::MOD_N
            )
            .unwrap_err()
            .kind,
            ErrorKind::InvalidParam
        );
    }

    #[test]
    fn divisor_candidates_cover_smooth_power_and_table_beyond_roots() {
        // p = 6·x − 1500 → roots ±250 = ±2·5^3 (smooth) — enumerated via a0.
        let cands =
            divisor_candidates_upto(&BigUint::from(1500u32), &BigUint::from(1000u32)).unwrap();
        assert!(cands.contains(&BigInt::from(250)));
        assert!(cands.contains(&BigInt::from(-250)));
        // Perfect-power constant term with a prime factor beyond the
        // small-prime table: 65537 is prime and > 17389 (table max). Both the
        // ±a0 rule and the iroot refinement supply candidates.
        let root = BigUint::from(65537u32) * BigUint::from(65537u32);
        let cands = divisor_candidates_upto(&root, &(BigUint::one() << 33u32)).unwrap();
        assert!(cands.contains(&BigInt::from(root)));
        assert!(cands.contains(&BigInt::from(65537u32)));
        // Powers of a single small prime: 13^6 ≤ 2^24 is enumerated directly.
        let cands =
            divisor_candidates_upto(&(BigUint::from(13u32)).pow(6), &(BigUint::one() << 24u32))
                .unwrap();
        assert!(cands.contains(&BigInt::from(4_826_809u32)));
    }

    #[test]
    fn zero_root_poly_yields_zero_candidate() {
        // p = x·(x − 6): stripped to x − 6; small_roots records the zero root
        // separately. The divisor path on the stripped constant term 6 finds
        // ±6 and ±1 etc.
        let cands = divisor_candidates_upto(&BigUint::from(6u32), &BigUint::from(10u32)).unwrap();
        assert!(cands.contains(&BigInt::from(6)));
        assert!(cands.contains(&BigInt::from(-6)));
        assert!(cands.contains(&BigInt::one()));
    }
}
