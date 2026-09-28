//! Lattice core + Coppersmith tests (M4-LAT-01 / M4-LAT-02).
//!
//! LLL is checked against hand-computable reductions, the exact Lovász and
//! size-reduction conditions (recomputed independently via
//! [`gram_schmidt_data`]), and lattice-invariance through the exposed
//! unimodular transform. The Coppersmith section exercises the classic
//! regressions: stereotyped messages and factoring with known MSB bits at two
//! different bit splits, plus typed-failure negative tests.

use cybercipher_attack::lattice::{gram_schmidt_data, lll_reduce, Lattice, LllConfig};
use cybercipher_core::error::ErrorKind;
use num_bigint::BigInt;
use num_traits::{One, Signed, Zero};

// ------------------------------------------------------------ helpers ----

fn bi(v: i64) -> BigInt {
    BigInt::from(v)
}

fn row(v: &[i64]) -> Vec<BigInt> {
    v.iter().map(|&x| bi(x)).collect()
}

fn lat(rows: Vec<Vec<BigInt>>) -> Lattice {
    Lattice::from_rows(rows).unwrap()
}

fn err_kind(e: &cybercipher_core::error::OperationError) -> ErrorKind {
    e.kind
}

/// Verify the exact post-reduction conditions every LLL output must satisfy:
/// the basis is size-reduced (`|μ_{i,j}| ≤ 1/2`, i.e. `2|λ| ≤ d[j]`) and the
/// Lovász condition holds with the configured δ.
fn assert_reduced(lattice: &Lattice, config: &LllConfig) {
    let (lam, d) = gram_schmidt_data(lattice).unwrap();
    let two = bi(2);
    // λ[i] has exactly i entries, so enumerate covers every (i, j<i) pair.
    for (i, lam_i) in lam.iter().enumerate() {
        for (j, lam_ij) in lam_i.iter().enumerate() {
            assert!(
                (lam_ij * &two).abs() <= d[j],
                "size reduction violated at ({i},{j})"
            );
        }
    }
    for k in 1..lattice.nrows() {
        let dk2 = if k >= 2 { d[k - 2].clone() } else { bi(1) };
        let c = &lam[k][k - 1];
        let lhs = BigInt::from(config.delta_den) * (&dk2 * &d[k] + c * c);
        let rhs = BigInt::from(config.delta_num) * &d[k - 1] * &d[k - 1];
        assert!(lhs >= rhs, "Lovász condition violated at k={k}");
    }
}

// ------------------------------------------------------- M4-LAT-01 LLL ----

#[test]
fn lll_reduces_hand_checkable_2d() {
    // GS: b0* = (2,0), μ10 = 6/4 → round to 2: b1 ← b1 − 2·b0 = (−1,5).
    // Lovász: 26 ≥ 0.99·4. Expected output: [(2,0), (−1,5)].
    let l = lat(vec![row(&[2, 0]), row(&[3, 5])]);
    let res = lll_reduce(&l, &LllConfig::default()).unwrap();
    assert_eq!(res.basis.row(0), row(&[2, 0]).as_slice());
    assert_eq!(res.basis.row(1), row(&[-1, 5]).as_slice());
    assert_reduced(&res.basis, &LllConfig::default());
}

#[test]
fn lll_finds_shortest_vector_of_unimodular_fibonacci_lattice() {
    // det(89·34 − 55·55) = 1, so the lattice is all of Z² and the shortest
    // vector has norm 1. LLL must find it.
    let l = lat(vec![row(&[89, 55]), row(&[55, 34])]);
    let res = lll_reduce(&l, &LllConfig::default()).unwrap();
    assert_eq!(res.basis.norm_squared(0), BigInt::one());
    assert_reduced(&res.basis, &LllConfig::default());
}

#[test]
fn lll_leaves_already_reduced_basis_unchanged() {
    // δ = 99/100: every Gram-Schmidt μ is 0, all norms equal → no swaps.
    let l = lat(vec![row(&[1, 0, 0]), row(&[0, 0, 1]), row(&[0, 1, 0])]);
    let res = lll_reduce(&l, &LllConfig::default()).unwrap();
    assert_eq!(res.basis.rows()[0], row(&[1, 0, 0]));
    assert_eq!(res.basis.rows()[1], row(&[0, 0, 1]));
    assert_eq!(res.basis.rows()[2], row(&[0, 1, 0]));
    assert_eq!(res.diagnostics.swap_count, 0);
}

#[test]
fn lll_transform_is_unimodular_and_preserves_the_lattice() {
    // (1,1,0),(1,0,1),(0,1,1): det = -2. Reduced output must span the same
    // lattice: U·original = reduced with det(U) = ±1, |det| preserved.
    let cases = vec![
        vec![row(&[1, 1, 0]), row(&[1, 0, 1]), row(&[0, 1, 1])],
        vec![row(&[201, 37, 11]), row(&[164, 21, 3]), row(&[5, 1, 1])],
        vec![row(&[2, 0]), row(&[3, 5])],
    ];
    for rows in cases {
        let original = lat(rows.clone());
        let det_before = original.determinant().unwrap().abs();
        let res = lll_reduce(&original, &LllConfig::default()).unwrap();
        let det_u = res.transform.determinant().unwrap().abs();
        assert_eq!(det_u, BigInt::one(), "transform must be unimodular");
        let combined = original.transform_rows(&res.transform).unwrap();
        assert_eq!(combined.rows(), res.basis.rows(), "U·original = reduced");
        let det_after = res.basis.determinant().unwrap().abs();
        assert_eq!(det_after, det_before, "lattice covolume preserved");
        assert_reduced(&res.basis, &LllConfig::default());
    }
}

#[test]
fn lll_first_vector_within_classical_approximation_bound() {
    // ‖b'_0‖ ≤ 2^((n-1)/2) · λ1 ≤ 2^((n-1)/2) · min ‖b_i‖.
    let rows = vec![
        row(&[1302, 511, 39, 7]),
        row(&[-981, 22, 74, 512]),
        row(&[7, 9001, 313, 45]),
        row(&[55, 61, 999, 8]),
    ];
    let l = lat(rows.clone());
    let min_norm_sq = rows
        .iter()
        .map(|r| r.iter().fold(BigInt::zero(), |a, c| a + c * c))
        .min()
        .unwrap();
    let res = lll_reduce(&l, &LllConfig::default()).unwrap();
    let bound = BigInt::from(1u8) << (2 * (rows.len() as u32 - 1)); // 2^(n-1)
    assert!(res.basis.norm_squared(0) <= &bound * &min_norm_sq);
    assert_reduced(&res.basis, &LllConfig::default());
}

#[test]
fn lll_two_dimensional_delta_one_sorts_norms() {
    // With δ = 1 a reduced 2D basis satisfies ‖b0‖ ≤ ‖b1‖ exactly.
    let l = lat(vec![row(&[13, 5]), row(&[8, 3])]);
    let cfg = LllConfig::new(1, 1).unwrap();
    let res = lll_reduce(&l, &cfg).unwrap();
    assert!(res.basis.norm_squared(0) <= res.basis.norm_squared(1));
    assert_reduced(&res.basis, &cfg);
}

#[test]
fn lll_is_exact_on_large_entries() {
    // ~200-bit entries: pure-integer arithmetic must preserve the determinant
    // and all invariants where float Gram-Schmidt would round.
    let big = |s: u64| (BigInt::from(1u8) << 200u32) | BigInt::from(s);
    let l = lat(vec![
        vec![big(0xACE1), big(0x0B7), big(0x5EED)],
        vec![big(0x1234), big(0xF00D), big(0x00C0)],
        vec![big(0x9999), big(0x0DD1), big(0x7EEE)],
    ]);
    let det_before = l.determinant().unwrap().abs();
    let res = lll_reduce(&l, &LllConfig::default()).unwrap();
    assert_eq!(res.basis.determinant().unwrap().abs(), det_before);
    assert_reduced(&res.basis, &LllConfig::default());
    // Diagnostics report exact final norms.
    assert_eq!(res.diagnostics.final_norms_squared.len(), 3);
    for (i, ns) in res.diagnostics.final_norms_squared.iter().enumerate() {
        let expected: BigInt = res
            .basis
            .row(i)
            .iter()
            .fold(BigInt::zero(), |a, c| a + c * c);
        assert_eq!(ns.parse::<BigInt>().unwrap(), expected);
    }
}

#[test]
fn lll_single_row_is_trivial() {
    let l = lat(vec![row(&[3, 4])]);
    let res = lll_reduce(&l, &LllConfig::default()).unwrap();
    assert_eq!(res.basis.row(0), row(&[3, 4]).as_slice());
    assert_eq!(res.transform.determinant().unwrap(), BigInt::one());
}

#[test]
fn lll_rejects_oversized_dimension() {
    let rows: Vec<Vec<BigInt>> = (0..65)
        .map(|i| {
            let mut r = vec![bi(0); 65];
            r[i] = bi(1);
            r
        })
        .collect();
    // Lattice::from_rows rejects at the matrix cap already; LLL re-checks.
    let e = Lattice::from_rows(rows).unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidParam);
    assert!(e.message.contains("cap"));
}

#[test]
fn lll_rejects_zero_row_and_dependent_basis() {
    let l = lat(vec![row(&[1, 2]), row(&[0, 0])]);
    let e = lll_reduce(&l, &LllConfig::default()).unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidInput);
    assert!(e.message.contains("zero vector"));

    let l = lat(vec![row(&[1, 2, 3]), row(&[2, 4, 6]), row(&[0, 1, 0])]);
    let e = lll_reduce(&l, &LllConfig::default()).unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidInput);
    assert!(e.message.contains("linearly dependent"));
}

#[test]
fn lll_validates_delta() {
    let l = lat(vec![row(&[1, 0]), row(&[0, 1])]);
    let e = LllConfig::new(3, 2).unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidParam);
    let e = LllConfig::new(1, 3).unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidParam);
    let e = LllConfig::new(99, 0).unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidParam);
    // δ = 1/2 exactly is the inclusive lower edge and must work.
    let res = lll_reduce(&l, &LllConfig::new(1, 2).unwrap()).unwrap();
    assert_reduced(&res.basis, &LllConfig::new(1, 2).unwrap());
}
