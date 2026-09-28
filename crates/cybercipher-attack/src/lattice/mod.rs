//! Lattice reduction and Coppersmith small-root attacks.
//!
//! Two layers:
//!
//! * [`matrix`] / [`lll`] — an exact integer lattice type and an integral LLL
//!   reduction (de Weger's rational-free formulation). Every Gram–Schmidt
//!   quantity is kept as exact integers (`λ` coefficients and the `d`
//!   determinant sequence), so there are no floating-point round-off errors
//!   anywhere in the reduction itself. Termination is guaranteed by the
//!   classical invariant documented in [`lll`].
//! * [`coppersmith`] — Howgrave-Graham's construction over that LLL: given a
//!   monic `f(x) mod N` of degree `d`, find all integer roots `|x0| ≤ X` with
//!   `f(x0) ≡ 0 (mod N)` (or modulo an unknown divisor of `N`) whenever `X`
//!   is within the bound the chosen lattice parameters guarantee. Every
//!   candidate root is verified exactly before it is returned, so the API
//!   never emits a wrong root; infeasible bounds fail with a typed
//!   [`OperationError`] that cites the achievable bound.
//!
//! Resource bounds: hostile input cannot hang the engine — dimension and
//! bit-budget caps are enforced at construction, the reduction loop has a
//! step budget, and root enumeration is capped in candidates and steps.

// Documented project decision (.agent/decisions.md): OperationError crosses
// failure paths only; boxing it at every call site was judged not worth the
// churn, so the oversized-Err lint is silenced per module.
#![allow(clippy::result_large_err)]

pub mod coppersmith;
pub mod lll;
pub mod matrix;
pub mod poly;

pub use coppersmith::{
    choose_params, guaranteed_bound, small_roots, CoppersmithBeta, CoppersmithParams,
    SmallRootsResult, MAX_COPPERSMITH_DIM,
};
pub use lll::{
    gram_schmidt_data, lll_reduce, LllConfig, LllDiagnostics, LllResult, DEFAULT_DELTA_DEN,
    DEFAULT_DELTA_NUM, MAX_LLL_STEPS,
};
pub use matrix::Lattice;
pub use poly::Poly;

use cybercipher_core::error::OperationError;
use num_bigint::BigInt;
use num_traits::{Signed, Zero};

/// Maximum number of lattice rows accepted by LLL (and matrix rows by
/// [`Lattice`]). A hostile caller requesting more gets a typed error instead
/// of a runaway reduction; at this cap the exact-arithmetic worst case is
/// bounded by the bit budget below.
pub const MAX_DIM: usize = 64;

/// Maximum number of columns (ambient dimension) of a [`Lattice`].
pub const MAX_COLS: usize = 4096;

/// Total bit budget over all matrix entries. The cost of exact LLL grows
/// with the entry sizes; this cap bounds the worst case for a single call.
/// The Coppersmith exercises in this milestone stay an order of magnitude
/// below it.
pub const MAX_TOTAL_BITS: u64 = 262_144;

/// Floor division by a strictly positive integer (Rust's `/` truncates
/// toward zero; LLL needs Euclidean rounding).
pub(crate) fn floor_div(num: &BigInt, den: &BigInt) -> BigInt {
    debug_assert!(den.is_positive());
    let q = num / den;
    if num.is_negative() && (num % den) != BigInt::from(0) {
        q - 1
    } else {
        q
    }
}

/// Exact integer division. Division by zero or a non-zero remainder is an
/// internal invariant violation (the LLL/HG mathematics guarantees exactness
/// — a failure here is a bug, surfaced as [`cybercipher_core::error::ErrorKind::Internal`]
/// rather than a panic).
pub(crate) fn exact_div(a: &BigInt, b: &BigInt) -> Result<BigInt, OperationError> {
    if b.is_zero() {
        return Err(OperationError::internal("exact_div: division by zero"));
    }
    let (q, r) = (a / b, a % b);
    if !r.is_zero() {
        return Err(OperationError::internal(format!(
            "exact_div: {a} is not divisible by {b}"
        )));
    }
    Ok(q)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_div_rounds_toward_negative_infinity() {
        let d = BigInt::from(10);
        assert_eq!(floor_div(&BigInt::from(25), &d), BigInt::from(2));
        assert_eq!(floor_div(&BigInt::from(-25), &d), BigInt::from(-3));
        assert_eq!(floor_div(&BigInt::from(-20), &d), BigInt::from(-2));
        assert_eq!(floor_div(&BigInt::from(0), &d), BigInt::from(0));
    }

    #[test]
    fn exact_div_rejects_remainder() {
        assert_eq!(
            exact_div(&BigInt::from(12), &BigInt::from(3)).unwrap(),
            BigInt::from(4)
        );
        assert!(exact_div(&BigInt::from(7), &BigInt::from(3)).is_err());
        assert!(exact_div(&BigInt::from(1), &BigInt::from(0)).is_err());
    }
}
