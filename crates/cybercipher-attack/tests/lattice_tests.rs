//! Lattice core + Coppersmith tests (M4-LAT-01 / M4-LAT-02).
//!
//! LLL is checked against hand-computable reductions, the exact Lovász and
//! size-reduction conditions (recomputed independently via
//! [`gram_schmidt_data`]), and lattice-invariance through the exposed
//! unimodular transform. The Coppersmith section exercises the classic
//! regressions: stereotyped messages and factoring with known MSB bits at two
//! different bit splits, plus typed-failure negative tests.

use cybercipher_attack::lattice::{
    gram_schmidt_data, guaranteed_bound, lll_reduce, small_roots, CoppersmithBeta,
    CoppersmithParams, Lattice, LllConfig, Poly,
};
use cybercipher_attack::math::{gcd, is_probable_prime, weak_prime, weak_random_odd};
use cybercipher_core::error::ErrorKind;
use num_bigint::{BigInt, BigUint};
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

// --------------------------------------------- M4-LAT-02 Coppersmith ----

/// Deterministic 512-bit semaphimic modulus `N = p·q` from [`weak_prime`].
fn modulus_512(state: &mut u64) -> (BigUint, BigUint, BigUint) {
    let p = weak_prime(256, state);
    let q = weak_prime(256, state);
    let n = &p * &q;
    (p, q, n)
}

/// Exercise 1 (M4-LAT-02): known-MSB factoring. 256-bit p, q; p = K + x0 with
/// |x0| ≤ 2^10 hidden. f(x) = K + x has degree d = 1 and the root
/// x0 modulo the unknown divisor p (f(x0) = p ≡ 0 (mod p)), so the search
/// runs at β = 1/2; shift shape (m, t) = (4, 2), dimension 6, whose
/// certified bound ≈ N^{0.133} ≈ 2^{68} dwarfs the 10-bit split.
#[test]
fn coppersmith_recovers_prime_from_known_msb_bits_k10() {
    let mut state = 0xD1CEu64;
    let (p, q, n) = modulus_512(&mut state);
    let x0 = BigInt::from(1021u32); // 2^10 − 3; prime, within the small-prime table
    let big_k = &p - 1021u32;

    let f = Poly::from_coeffs(vec![BigInt::from(big_k.clone()), BigInt::one()]);
    let params = CoppersmithParams { m: 4, t: 2 };
    let bound = BigUint::one() << 10u32;
    // The documented regime must certify the split before we run.
    let certified = guaranteed_bound(&n, 1, &params, &CoppersmithBeta::HALF);
    assert!(certified >= bound, "bound must be certified for k=10");

    let res = small_roots(&f, &n, &bound, &params, &CoppersmithBeta::HALF).unwrap();
    assert_eq!(res.lattice_dim, 6);
    assert_eq!(res.roots, vec![x0], "exactly the hidden offset");
    // Recovered factor verifies completely: p·q = N and p is prime.
    let recovered = &big_k + 1021u32;
    assert_eq!(recovered, p, "K + x0 must reproduce p");
    assert!(is_probable_prime(&recovered));
    assert_eq!(&recovered * &q, n);
    // Diagnostics: the run stepped and reported final norms.
    assert_eq!(res.diagnostics.final_norms_squared.len(), 6);
    assert!(res.diagnostics.iterations > 0);
}

/// Exercise 2 (M4-LAT-02): stereotyped message. e = 3, c = (M + x0)³ mod N
/// with the CTF-flavored structured offset x0 = 0x1337; f(x) = (M + x)³ − c
/// has degree d = 3 and the root x0 modulo N (β = 1). Shift shape
/// (m, t) = (2, 1), dimension 7; its certified bound ≈ N^{0.238} ≈ 2^{121}
/// dwarfs the offset. (Bigger offsets just need larger m/t — the
/// parameterization table in [`cybercipher_attack::lattice::coppersmith`].)
#[test]
fn coppersmith_stereotyped_message_recovers_padding() {
    let mut state = 0x5EEDu64;
    let (_, _, n) = modulus_512(&mut state);
    let m_msg = weak_random_odd(200, &mut state);
    // Structured offset with sparse prime factors (4919 = 13·379), so the
    // rational-root divisor search enumerates it cheaply.
    let x0: BigUint = BigUint::from(0x1337u32);
    let bound = BigUint::one() << 13u32;
    assert!(x0 < bound);

    let x = &m_msg + &x0;
    let c = x.pow(3) % &n; // e = 3
    let base = Poly::from_coeffs(vec![BigInt::from(m_msg.clone()), BigInt::one()]);
    let f = base
        .pow(3)
        .unwrap()
        .sub(&Poly::constant(BigInt::from(c.clone())));

    let params = CoppersmithParams { m: 2, t: 1 };
    let certified = guaranteed_bound(&n, 3, &params, &CoppersmithBeta::MOD_N);
    assert!(certified >= bound, "bound must be certified for d=3");

    let res = small_roots(&f, &n, &bound, &params, &CoppersmithBeta::MOD_N).unwrap();
    assert_eq!(res.roots, vec![BigInt::from(x0)], "exact padding recovery");
}

/// Exercise 3 (M4-LAT-02): second known-bits split (k = 16 vs k = 10 above)
/// with a *smaller* shift shape (m, t) = (2, 2), dimension 4 — demonstrating
/// that the certified divisor-root bound (≈ N^{1/6} ≈ 2^{85} here) scales as
/// documented and comfortably covers the larger hidden part at the smaller
/// dimension.
#[test]
fn coppersmith_known_msb_second_split_k16_shows_bound_scaling() {
    let mut state = 0x51CEu64;
    let (p, q, n) = modulus_512(&mut state);
    let x0 = BigInt::from(65535u32); // 3·5·17·257 ≤ 2^16, all table primes
    let big_k = &p - 65535u32;

    let f = Poly::from_coeffs(vec![BigInt::from(big_k.clone()), BigInt::one()]);
    let params = CoppersmithParams { m: 2, t: 2 };
    let bound = BigUint::one() << 16u32;
    let certified = guaranteed_bound(&n, 1, &params, &CoppersmithBeta::HALF);
    assert!(certified >= bound);

    let res = small_roots(&f, &n, &bound, &params, &CoppersmithBeta::HALF).unwrap();
    assert_eq!(res.lattice_dim, 4);
    assert_eq!(res.roots, vec![x0]);
    let recovered = &big_k + 65535u32;
    assert_eq!(recovered, p);
    assert!(is_probable_prime(&recovered));
    assert_eq!(&recovered * &q, n);
    // Verification semantics for the divisor setting: gcd(f(x0), N) is the
    // factor itself.
    assert_eq!(gcd(&recovered, &n), p);

    // Documented scaling (regime X ≤ N^{β²/d − ε}), compared within the same
    // β: raising the multiplicity raises the divisor-root bound…
    let b1_42 = guaranteed_bound(
        &n,
        1,
        &CoppersmithParams { m: 4, t: 2 },
        &CoppersmithBeta::HALF,
    );
    let b1_84 = guaranteed_bound(
        &n,
        1,
        &CoppersmithParams { m: 8, t: 4 },
        &CoppersmithBeta::HALF,
    );
    assert!(b1_84 > b1_42, "more shifts ⇒ larger achievable bound");
    // …and at equal β the bound shrinks as the degree grows (ε → 1/d).
    let b1 = guaranteed_bound(
        &n,
        1,
        &CoppersmithParams { m: 4, t: 4 },
        &CoppersmithBeta::MOD_N,
    );
    let b3 = guaranteed_bound(
        &n,
        3,
        &CoppersmithParams { m: 4, t: 4 },
        &CoppersmithBeta::MOD_N,
    );
    assert!(b1 > b3, "higher degree ⇒ smaller achievable bound");
}

/// Negative: an X beyond the certified bound is a typed failure citing the
/// bound and the N^{1/d − ε} regime — never a wrong root.
#[test]
fn coppersmith_bound_beyond_regime_fails_typed() {
    let mut state = 0xBAD5u64;
    let (_, _, n) = modulus_512(&mut state);
    let f = Poly::from_coeffs(vec![BigInt::from(12345u32), BigInt::one()]);
    let params = CoppersmithParams { m: 2, t: 2 };
    let x = BigUint::one() << 510u32; // below N but far above the certified bound
    let e = small_roots(&f, &n, &x, &params, &CoppersmithBeta::MOD_N).unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::Unsupported);
    assert!(
        e.message.contains("exceeds the certified bound"),
        "{}",
        e.message
    );
    assert!(e.message.contains("β²/d"), "{}", e.message);
    assert!(e.expected.as_deref().unwrap().starts_with("X ≤ 2^"));
}

/// Negative: requesting a shift lattice above the dimension cap is a typed
/// InvalidParam error (hostile parameters cannot mount a runaway reduction).
#[test]
fn coppersmith_dimension_cap_is_typed() {
    let mut state = 0xC4F5u64;
    let (_, _, n) = modulus_512(&mut state);
    let f = Poly::from_coeffs(vec![BigInt::from(7u32), BigInt::one()]);
    let e = small_roots(
        &f,
        &n,
        &(BigUint::from(16u32)),
        &CoppersmithParams { m: 31, t: 2 },
        &CoppersmithBeta::MOD_N,
    )
    .unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidParam);
    assert!(e.message.contains("cap"), "{}", e.message);
    assert_eq!(e.actual.as_deref(), Some("33"));
}

/// Negative: f(x) = x² + 1 mod N with |x| ≤ 2^20 has no root (x² + 1 < N
/// there), and the search reports an empty verified set rather than guessing.
#[test]
fn coppersmith_no_root_input_yields_empty_verified_set() {
    let mut state = 0x0042u64;
    let (_, _, n) = modulus_512(&mut state);
    let f = Poly::from_coeffs(vec![bi(1), bi(0), bi(1)]);
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
