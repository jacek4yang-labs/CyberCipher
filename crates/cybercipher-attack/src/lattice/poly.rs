//! Dense univariate polynomials over ℤ — the arithmetic backbone of the
//! Coppersmith construction ([`super::coppersmith`]).
//!
//! Coefficients are stored little-endian: `coeffs[i]` multiplies `x^i`. The
//! representation is kept canonical — no trailing zero coefficients — so
//! [`Poly::degree`] is always exact and equality is structural. All
//! arithmetic is exact (arbitrary-precision integers); no modular reduction
//! happens implicitly, since Howgrave-Graham needs both the exact integer
//! view (root finding, evaluation) and the mod-`N` view (shift polynomials).
//!
//! Everything here is total: no panics on any input, and every fallible
//! constructor surfaces a typed [`OperationError`].

use super::{MAX_COLS, MAX_DIM};
use cybercipher_core::error::{ErrorKind, OperationError};
use num_bigint::{BigInt, BigUint};
use num_traits::{One, Signed, Zero};
use std::fmt;

/// gcd of the absolute values of two integers (delegates to the crate's
/// number-theory module; `gcd(0, 0) = 0`).
fn gcd_abs(a: &BigInt, b: &BigInt) -> BigInt {
    BigInt::from(crate::math::gcd(a.magnitude(), b.magnitude()))
}

/// Modular inverse of a non-negative residue `a` modulo `n`.
fn modinv_residue(a: &BigInt, n: &BigUint) -> Option<BigInt> {
    crate::math::modinv(a.magnitude(), n).map(BigInt::from)
}

/// Non-negative remainder of `a` modulo `m > 0` (Rust's `%` truncates toward
/// zero; the mod-`N` views here need representatives in `[0, m)`).
fn rem_nonneg(a: &BigInt, m: &BigInt) -> BigInt {
    let r = a % m;
    if r.is_negative() {
        r + m
    } else {
        r
    }
}

/// Cap on polynomial degree accepted from user input. The Coppersmith
/// exercises stay far below it; the cap exists so a hostile polynomial
/// cannot trigger unbounded work (`pow` squares degrees).
pub const MAX_POLY_DEGREE: usize = 1024;

/// A dense univariate polynomial over ℤ, canonical (trailing zeros trimmed).
/// The zero polynomial has empty coefficients and [`Poly::degree`] `None`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Poly {
    coeffs: Vec<BigInt>,
}

/// Trim trailing zeros so the representation stays canonical.
fn normalize(mut coeffs: Vec<BigInt>) -> Vec<BigInt> {
    while coeffs.last().is_some_and(|c| c.is_zero()) {
        coeffs.pop();
    }
    coeffs
}

impl Poly {
    /// The zero polynomial.
    pub fn zero() -> Self {
        Poly { coeffs: Vec::new() }
    }

    /// The constant polynomial `c` (zero gives the zero polynomial).
    pub fn constant(c: BigInt) -> Self {
        Poly {
            coeffs: normalize(vec![c]),
        }
    }

    /// Build from little-endian coefficients (index `i` multiplies `x^i`).
    /// Trailing zeros are trimmed, so the result is canonical.
    pub fn from_coeffs(coeffs: Vec<BigInt>) -> Self {
        Poly {
            coeffs: normalize(coeffs),
        }
    }

    /// Borrowed little-endian coefficient slice (canonical: no trailing 0s).
    pub fn coeffs(&self) -> &[BigInt] {
        &self.coeffs
    }

    /// Degree, or `None` for the zero polynomial.
    pub fn degree(&self) -> Option<usize> {
        self.coeffs.len().checked_sub(1)
    }

    /// True for the zero polynomial.
    pub fn is_zero(&self) -> bool {
        self.coeffs.is_empty()
    }

    /// Leading coefficient (the coefficient of `x^degree`), or zero.
    pub fn leading_coeff(&self) -> BigInt {
        self.coeffs.last().cloned().unwrap_or_else(BigInt::zero)
    }

    /// Constant term (coefficient of `x^0`), or zero.
    pub fn constant_term(&self) -> BigInt {
        self.coeffs.first().cloned().unwrap_or_else(BigInt::zero)
    }

    /// Coefficient of `x^k` (zero when `k` exceeds the degree).
    pub fn coeff(&self, k: usize) -> BigInt {
        self.coeffs.get(k).cloned().unwrap_or_else(BigInt::zero)
    }

    /// `self + other`.
    pub fn add(&self, other: &Poly) -> Poly {
        let n = self.coeffs.len().max(other.coeffs.len());
        let mut coeffs = Vec::with_capacity(n);
        for i in 0..n {
            coeffs.push(self.coeff(i) + other.coeff(i));
        }
        Poly::from_coeffs(coeffs)
    }

    /// `self − other`.
    pub fn sub(&self, other: &Poly) -> Poly {
        let n = self.coeffs.len().max(other.coeffs.len());
        let mut coeffs = Vec::with_capacity(n);
        for i in 0..n {
            coeffs.push(self.coeff(i) - other.coeff(i));
        }
        Poly::from_coeffs(coeffs)
    }

    /// `self · other` (schoolbook; degrees here are small by construction).
    pub fn mul(&self, other: &Poly) -> Poly {
        if self.is_zero() || other.is_zero() {
            return Poly::zero();
        }
        let n = self.coeffs.len() + other.coeffs.len() - 1;
        let mut coeffs = vec![BigInt::zero(); n];
        for (i, a) in self.coeffs.iter().enumerate() {
            if a.is_zero() {
                continue;
            }
            for (j, b) in other.coeffs.iter().enumerate() {
                coeffs[i + j] += a * b;
            }
        }
        Poly::from_coeffs(coeffs)
    }

    /// `k · self`.
    pub fn scalar_mul(&self, k: &BigInt) -> Poly {
        if k.is_zero() {
            return Poly::zero();
        }
        Poly::from_coeffs(self.coeffs.iter().map(|c| k * c).collect())
    }

    /// `self` raised to `e ≥ 0` by binary exponentiation. `0^0 = 1`.
    /// Errors if the result would exceed the degree cap (a hostile `e`
    /// cannot otherwise be distinguished from a legitimate one up front).
    pub fn pow(&self, e: u32) -> Result<Poly, OperationError> {
        if self.is_zero() && e == 0 {
            return Ok(Poly::constant(BigInt::one()));
        }
        let d = self.degree().unwrap_or(0);
        // Result degree is d·e; reject early if it would blow the cap. The
        // log-free check d·e ≤ MAX_POLY_DEGREE cannot overflow on 64-bit.
        let de = d as u64 * e as u64;
        if de > MAX_POLY_DEGREE as u64 {
            return Err(OperationError::new(
                ErrorKind::BudgetExceeded,
                format!("poly pow would reach degree {de}, exceeding cap {MAX_POLY_DEGREE}"),
            )
            .with_expected(MAX_POLY_DEGREE.to_string())
            .with_actual(de.to_string())
            .with_parameter("exponent"));
        }
        let mut base = self.clone();
        let mut acc = Poly::constant(BigInt::one());
        let mut exp = e;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = acc.mul(&base);
            }
            exp >>= 1;
            if exp > 0 {
                base = base.mul(&base);
            }
        }
        Ok(acc)
    }

    /// Shift: `self · x^k` (free — just a coefficient-vector offset).
    pub fn mul_x_pow(&self, k: usize) -> Poly {
        if self.is_zero() {
            return Poly::zero();
        }
        let mut coeffs = vec![BigInt::zero(); k];
        coeffs.extend(self.coeffs.iter().cloned());
        Poly { coeffs }
    }

    /// Exact evaluation at an integer point via Horner's rule.
    pub fn eval(&self, x: &BigInt) -> BigInt {
        let mut acc = BigInt::zero();
        for c in self.coeffs.iter().rev() {
            acc = acc * x + c;
        }
        acc
    }

    /// Reduce every coefficient modulo `n > 0` into `[0, n)`.
    pub fn reduce_mod(&self, n: &num_bigint::BigUint) -> Result<Poly, OperationError> {
        if n.is_zero() {
            return Err(OperationError::invalid_param(
                "n",
                "modulus must be non-zero",
            ));
        }
        let n = BigInt::from(n.clone());
        Ok(Poly {
            coeffs: self.coeffs.iter().map(|c| rem_nonneg(c, &n)).collect(),
        })
    }

    /// Make monic modulo `n`: scale by the inverse of the leading coefficient.
    /// The result has the same roots modulo `n` as `self`. Fails with a typed
    /// error when the leading coefficient is not invertible mod `n` — for
    /// composite `n` that gcd is a proper factor of `n`, which the message
    /// points out.
    pub fn to_monic_mod(&self, n: &num_bigint::BigUint) -> Result<Poly, OperationError> {
        let red = self.reduce_mod(n)?;
        let lc = red.leading_coeff();
        if lc.is_zero() {
            return Err(OperationError::invalid_input(
                "polynomial vanishes modulo n — no roots to find",
            ));
        }
        let n_big = BigInt::from(n.clone());
        let g = gcd_abs(&lc, &n_big);
        if !g.is_one() {
            return Err(OperationError::new(
                ErrorKind::Unsupported,
                format!(
                    "leading coefficient not invertible mod n (gcd = {g}); \
                     for composite n this gcd is a non-trivial factor of n"
                ),
            ));
        }
        let inv = modinv_residue(&lc, n).ok_or_else(|| {
            // The gcd check above already established invertibility; failure
            // here would be an internal invariant violation.
            OperationError::internal(
                "modular inverse of leading coefficient not found despite gcd = 1",
            )
        })?;
        red.scalar_mul(&inv).reduce_mod(n)
    }

    /// Content: gcd of all coefficients (0 for the zero polynomial).
    pub fn content(&self) -> BigInt {
        let mut g = BigInt::zero();
        for c in &self.coeffs {
            g = gcd_abs(&g, &c.abs());
            if g.is_one() {
                break;
            }
        }
        g
    }

    /// Primitive part: every coefficient divided by their common content.
    /// Exact by definition of the content, and root-preserving (the content
    /// is a non-zero constant).
    pub fn primitive_part(&self) -> Poly {
        let g = self.content();
        if g.is_zero() {
            return Poly::zero();
        }
        Poly::from_coeffs(self.coeffs.iter().map(|c| c / &g).collect())
    }
}

impl fmt::Display for Poly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            return write!(f, "0");
        }
        for (i, c) in self.coeffs.iter().enumerate().rev() {
            if c.is_zero() {
                continue;
            }
            if i != self.coeffs.len() - 1 && !c.is_negative() {
                write!(f, " + ")?;
            }
            match i {
                0 => write!(f, "{c}")?,
                1 => write!(f, "{c}·x")?,
                _ => write!(f, "{c}·x^{i}")?,
            }
        }
        Ok(())
    }
}

/// Validate a degree coming from user-controlled input against the caps
/// shared with the lattice module (rows ≤ MAX_DIM, columns ≤ MAX_COLS).
pub(crate) fn validate_degree(d: usize) -> Result<(), OperationError> {
    if d == 0 {
        return Err(OperationError::invalid_input(
            "polynomial degree must be at least 1",
        ));
    }
    if d > MAX_POLY_DEGREE {
        return Err(OperationError::invalid_param(
            "degree",
            format!("polynomial degree {d} exceeds cap {MAX_POLY_DEGREE}"),
        ));
    }
    if d > MAX_COLS || d > MAX_DIM {
        return Err(OperationError::invalid_param(
            "degree",
            format!("polynomial degree {d} exceeds lattice dimension cap {MAX_DIM}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: &[i64]) -> Poly {
        Poly::from_coeffs(v.iter().map(|&x| BigInt::from(x)).collect())
    }

    #[test]
    fn canonical_form_and_accessors() {
        let z = Poly::zero();
        assert!(z.is_zero());
        assert_eq!(z.degree(), None);
        assert_eq!(z.leading_coeff(), BigInt::zero());
        // Trailing zeros are trimmed on construction.
        let a = Poly::from_coeffs(vec![BigInt::from(2), BigInt::from(0), BigInt::from(0)]);
        assert_eq!(a, Poly::constant(BigInt::from(2)));
        assert_eq!(a.degree(), Some(0));
        let b = p(&[1, 2, 3]);
        assert_eq!(b.degree(), Some(2));
        assert_eq!(b.leading_coeff(), BigInt::from(3));
        assert_eq!(b.coeff(5), BigInt::zero());
        assert_eq!(b.constant_term(), BigInt::one());
    }

    #[test]
    fn ring_operations() {
        let a = p(&[1, 2]); // 1 + 2x
        let b = p(&[3, 0, 1]); // 3 + x²
        assert_eq!(a.add(&b), p(&[4, 2, 1]));
        assert_eq!(a.sub(&a), Poly::zero());
        // (1+2x)(3+x²) = 3 + 6x + x² + 2x³
        assert_eq!(a.mul(&b), p(&[3, 6, 1, 2]));
        assert_eq!(a.scalar_mul(&BigInt::from(3)), p(&[3, 6]));
        assert_eq!(a.scalar_mul(&BigInt::zero()), Poly::zero());
        // Multiplication by the zero and unit polynomials.
        assert_eq!(a.mul(&Poly::zero()), Poly::zero());
        assert_eq!(a.mul(&Poly::constant(BigInt::one())), a);
    }

    #[test]
    fn pow_by_squaring_matches_repeated_mul() {
        let a = p(&[-1, 1]); // x - 1
        let mut acc = Poly::constant(BigInt::one());
        for e in 1u32..=6 {
            acc = acc.mul(&a);
            assert_eq!(a.pow(e).unwrap(), acc, "x-1 to the {e}");
        }
        // (x−1)² = x² − 2x + 1.
        assert_eq!(a.pow(2).unwrap(), p(&[1, -2, 1]));
        assert_eq!(Poly::zero().pow(0).unwrap(), Poly::constant(BigInt::one()));
        let err = p(&[1, 1]).pow(2000).unwrap_err();
        assert_eq!(err.kind, ErrorKind::BudgetExceeded);
    }

    #[test]
    fn eval_matches_horner_hand_check() {
        // 3x³ − 2x² + x − 7 at x = 5: 375 − 50 + 5 − 7 = 323.
        let f = p(&[-7, 1, -2, 3]);
        assert_eq!(f.eval(&BigInt::from(5)), BigInt::from(323));
        assert_eq!(f.eval(&BigInt::zero()), BigInt::from(-7));
        assert_eq!(Poly::zero().eval(&BigInt::from(9)), BigInt::zero());
    }

    #[test]
    fn shift_and_modular_operations() {
        let a = p(&[1, 2, 3]);
        assert_eq!(a.mul_x_pow(2), p(&[0, 0, 1, 2, 3]));
        assert_eq!(Poly::zero().mul_x_pow(3), Poly::zero());
        // (x² + 1) mod 3 = 1·x² + 1 (2 → 2 stays, check wrap: 5 → 2).
        let f = p(&[1, 5, 1]).reduce_mod(&3u8.into()).unwrap();
        assert_eq!(f, p(&[1, 2, 1]));
        assert!(Poly::zero().reduce_mod(&0u8.into()).is_err());
        // 2x² + 3 mod 5: leading coeff 2·3 = 6 ≡ 1 → monic.
        let g = p(&[3, 0, 2]).to_monic_mod(&5u8.into()).unwrap();
        assert_eq!(g, p(&[4, 0, 1])); // 3·3=9≡4, 2·3=6≡1
                                      // Non-invertible leading coefficient mod composite n is a typed error.
        let h = p(&[1, 0, 5]); // lc = 5, n = 15
        let e = h.to_monic_mod(&15u8.into()).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Unsupported);
        assert!(e.message.contains("factor of n"));
    }

    #[test]
    fn content_and_primitive_part() {
        let f = p(&[4, 6, 10]);
        assert_eq!(f.content(), BigInt::from(2));
        assert_eq!(f.primitive_part(), p(&[2, 3, 5]));
        assert_eq!(Poly::zero().primitive_part(), Poly::zero());
        // Coprime content is 1 — primitive part is itself.
        let g = p(&[1, 2, 3]);
        assert_eq!(g.content(), BigInt::one());
        assert_eq!(g.primitive_part(), g);
        // Negative coefficients: content is taken over absolute values, and
        // signs are preserved by the exact division.
        let h = p(&[-4, 6]);
        assert_eq!(h.primitive_part(), p(&[-2, 3]));
    }

    #[test]
    fn degree_validation() {
        assert!(validate_degree(0).is_err());
        assert!(validate_degree(1).is_ok());
        // Up to the lattice dimension cap is fine (Coppersmith layers its own
        // stricter dimension cap on top).
        assert!(validate_degree(64).is_ok());
        assert!(validate_degree(65).is_err());
        assert!(validate_degree(10_000).is_err());
    }

    #[test]
    fn display_is_readable() {
        assert_eq!(Poly::zero().to_string(), "0");
        // Negative coefficients carry their own sign; positives get " + ".
        assert_eq!(p(&[-7, 1, -2, 3]).to_string(), "3·x^3-2·x^2 + 1·x-7");
        assert_eq!(p(&[5]).to_string(), "5");
        assert_eq!(p(&[1, 2]).to_string(), "2·x + 1");
    }
}
