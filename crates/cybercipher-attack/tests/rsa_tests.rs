//! End-to-end tests for the RSA attack vertical: one positive and one
//! negative case per attack, plus analyzer/pipeline and robustness tests.
//!
//! Instances are generated with the crate's LCG-driven `weak_prime` so every
//! test is deterministic.

use cybercipher_attack::math;
use cybercipher_attack::rsa::{
    analyze, attack_common_modulus, attack_dp_leak, attack_fermat, attack_hastad, attack_known_d,
    attack_known_phi, attack_known_pq, attack_low_e, attack_pollard_pm1, attack_pollard_rho,
    attack_shared_prime, attack_wiener, AnalyzerReport, AttackOutcome, AttackStatus, RsaParams,
    RsaSet,
};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::time::{Duration, Instant};

const FLAG: &[u8] = b"flag{r54_4tt4ck5}";
/// Short flag for tests with small moduli (n < 2^128).
const SMALL_FLAG: &[u8] = b"ctf{sm}";

fn big(n: u64) -> BigUint {
    BigUint::from(n)
}

fn bytes_to_m(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

fn in_ms(ms: u64) -> Instant {
    Instant::now() + Duration::from_millis(ms)
}

fn next_probable_prime(mut x: BigUint) -> BigUint {
    if (&x % big(2)).is_zero() {
        x += big(1);
    }
    while !math::is_probable_prime(&x) {
        x += big(2);
    }
    x
}

/// A synthetic RSA key with all derived quantities.
#[derive(Clone)]
#[allow(dead_code)] // dq kept for completeness of the key model
struct TestKey {
    p: BigUint,
    q: BigUint,
    n: BigUint,
    phi: BigUint,
    e: BigUint,
    d: BigUint,
    dp: BigUint,
    dq: BigUint,
}

impl TestKey {
    fn encrypt(&self, m: &BigUint) -> BigUint {
        m.modpow(&self.e, &self.n)
    }

    fn params_with_c(&self, m: &BigUint) -> RsaParams {
        RsaParams {
            n: Some(self.n.clone()),
            e: Some(self.e.clone()),
            c: Some(self.encrypt(m)),
            ..Default::default()
        }
    }
}

/// Generate a random key with the requested prime size and exponent `e`.
/// Retries until e is invertible modulo φ(n) (always terminates fast).
fn keypair(bits: u64, state: &mut u64, e: u64) -> TestKey {
    loop {
        let p = math::weak_prime(bits, state);
        let q = math::weak_prime(bits, state);
        if p == q {
            continue;
        }
        let n = &p * &q;
        let phi = (&p - big(1)) * (&q - big(1));
        let e = big(e);
        let Some(d) = math::modinv(&e, &phi) else {
            continue;
        };
        if d <= big(1) {
            continue;
        }
        let dp = &d % (&p - big(1));
        let dq = &d % (&q - big(1));
        return TestKey {
            p,
            q,
            n,
            phi,
            e,
            d,
            dp,
            dq,
        };
    }
}

fn finding<'a>(report: &'a AnalyzerReport, id: &str) -> &'a AttackOutcome {
    report
        .findings
        .iter()
        .find(|f| f.id == id)
        .unwrap_or_else(|| panic!("report is missing a `{id}` finding"))
}

fn assert_plaintext(out: &AttackOutcome, m: &BigUint) {
    let pt = out
        .plaintext
        .as_ref()
        .unwrap_or_else(|| panic!("attack `{}` returned no plaintext", out.id));
    assert_eq!(pt.m_hex, format!("{m:x}"), "plaintext hex mismatch");
}

// ------------------------------------------------------------ known p,q --

#[test]
fn known_pq_recovers_plaintext() {
    let mut state = 0xA11CEu64;
    let key = keypair(64, &mut state, 65537);
    let m = bytes_to_m(SMALL_FLAG);
    let mut params = key.params_with_c(&m);
    params.p = Some(key.p.clone());
    params.q = Some(key.q.clone());
    let out = attack_known_pq(&mut params);
    assert_eq!(out.status, AttackStatus::Success, "{}", out.message);
    assert_plaintext(&out, &m);
    assert_eq!(params.d.unwrap(), key.d);
}

#[test]
fn known_pq_without_q_is_not_applicable() {
    let mut state = 0xA11CEu64;
    let key = keypair(64, &mut state, 65537);
    let m = bytes_to_m(SMALL_FLAG);
    let mut params = key.params_with_c(&m);
    params.q = None;
    let out = attack_known_pq(&mut params);
    assert_eq!(out.status, AttackStatus::NotApplicable);
    assert!(out.plaintext.is_none());
}

#[test]
fn known_pq_degenerate_factors_rejected() {
    let mut state = 0xA11CEu64;
    let key = keypair(64, &mut state, 65537);
    let mut params = key.params_with_c(&bytes_to_m(SMALL_FLAG));
    params.p = Some(big(1));
    params.q = Some(key.n.clone());
    let out = attack_known_pq(&mut params);
    assert_eq!(out.status, AttackStatus::NotApplicable);
}

// -------------------------------------------------------------- known d --

#[test]
fn known_d_recovers_plaintext_and_factors() {
    let mut state = 0xB0Bu64;
    let key = keypair(64, &mut state, 65537);
    let m = bytes_to_m(SMALL_FLAG);
    let mut params = key.params_with_c(&m);
    params.d = Some(key.d.clone());
    let out = attack_known_d(&mut params);
    assert_eq!(out.status, AttackStatus::Success, "{}", out.message);
    assert_plaintext(&out, &m);
    // Bonus: n must be factored from (e, d).
    let p = params.p.clone().expect("n must be factored from (e, d)");
    let q = params.q.clone().expect("q must be factored from (e, d)");
    assert!(p == key.p || p == key.q);
    assert_eq!(p * q, key.n);
}

#[test]
fn known_d_wrong_d_fails_without_false_success() {
    let mut state = 0xC0DEu64;
    let key = keypair(64, &mut state, 65537);
    let mut params = key.params_with_c(&bytes_to_m(FLAG));
    params.d = Some(&key.d + big(1)); // deliberately wrong
    let out = attack_known_d(&mut params);
    assert_eq!(out.status, AttackStatus::Failed, "{}", out.message);
    assert!(out.plaintext.is_none());
}

#[test]
fn known_d_degenerate_no_panic() {
    // e·d = 1 (degenerate): must not panic or hang in factor_from_ed.
    let mut params = RsaParams {
        n: Some(big(3233)),
        e: Some(big(1)),
        c: Some(big(7)),
        d: Some(big(1)),
        ..Default::default()
    };
    let _out = attack_known_d(&mut params);
    assert!(params.p.is_none(), "e·d = 1 must not yield a factorization");
}

// ------------------------------------------------------------- known phi --

#[test]
fn known_phi_recovers_plaintext() {
    let mut state = 0x0F11;
    let key = keypair(64, &mut state, 65537);
    let m = bytes_to_m(SMALL_FLAG);
    let mut params = key.params_with_c(&m);
    params.phi = Some(key.phi.clone());
    let out = attack_known_phi(&mut params);
    assert_eq!(out.status, AttackStatus::Success, "{}", out.message);
    assert_plaintext(&out, &m);
    assert_eq!(params.d.unwrap(), key.d);
}

#[test]
fn known_phi_wrong_phi_fails() {
    let mut state = 0x0F12;
    let key = keypair(64, &mut state, 65537);
    let mut params = key.params_with_c(&bytes_to_m(FLAG));
    params.phi = Some(&key.phi + big(2)); // wrong φ
    let out = attack_known_phi(&mut params);
    assert_eq!(out.status, AttackStatus::Failed, "{}", out.message);
    assert!(out.plaintext.is_none());
}

// --------------------------------------------------------------- dp leak --

#[test]
fn dp_leak_recovers_plaintext() {
    let mut state = 0xD0D1;
    let key = keypair(64, &mut state, 17); // moderate e → small k sweep
    assert!(key.dp > big(0), "dp must be non-zero for this instance");
    let m = bytes_to_m(SMALL_FLAG);
    let mut params = RsaParams {
        n: Some(key.n.clone()),
        e: Some(key.e.clone()),
        c: Some(key.encrypt(&m)),
        dp: Some(key.dp.clone()),
        ..Default::default()
    };
    let out = attack_dp_leak(&mut params, in_ms(5_000));
    assert_eq!(out.status, AttackStatus::Success, "{}", out.message);
    assert_plaintext(&out, &m);
    assert_eq!(params.p.unwrap() * params.q.unwrap(), key.n);
}

#[test]
fn dp_leak_recovers_factors_even_without_c() {
    let mut state = 0xD0D2u64;
    let key = keypair(64, &mut state, 17);
    assert!(key.dp > big(0));
    let mut params = RsaParams {
        n: Some(key.n.clone()),
        e: Some(key.e.clone()),
        dp: Some(key.dp.clone()),
        ..Default::default()
    };
    let out = attack_dp_leak(&mut params, in_ms(5_000));
    assert_eq!(out.status, AttackStatus::Applicable, "{}", out.message);
    assert!(out.plaintext.is_none());
    assert_eq!(params.p.unwrap() * params.q.unwrap(), key.n);
}

#[test]
fn dp_leak_wrong_leak_fails_without_false_success() {
    let mut state = 0xD0D3u64;
    // Ensure p ≢ 1 (mod 257) so no base can accidentally satisfy the
    // identity with the corrupted leak.
    let key = loop {
        let k = keypair(64, &mut state, 257);
        if (&k.p - big(1)) % big(257) != big(0) {
            break k;
        }
    };
    let wrong_dp = &key.dp + big(1); // e·(dp+1) − 1 ≢ 0 (mod p−1)
    let mut params = RsaParams {
        n: Some(key.n.clone()),
        e: Some(key.e.clone()),
        c: Some(big(12345)),
        dp: Some(wrong_dp),
        ..Default::default()
    };
    let out = attack_dp_leak(&mut params, in_ms(5_000));
    assert_eq!(out.status, AttackStatus::Failed, "{}", out.message);
    assert!(out.plaintext.is_none());
    assert!(params.p.is_none(), "no factor may be installed on failure");
}

// --------------------------------------------------------------- Wiener --

#[test]
fn wiener_recovers_small_d() {
    let mut state = 0x1134;
    // n = 256 bits, d = 60 bits < n^(1/4)/3 = 2^64/3 → Wiener applies.
    let p = math::weak_prime(128, &mut state);
    let q = math::weak_prime(128, &mut state);
    let n = &p * &q;
    let phi = (&p - big(1)) * (&q - big(1));
    let (e, d) = loop {
        let d = math::weak_random_odd(60, &mut state);
        if let Some(e) = math::modinv(&d, &phi) {
            break (e, d);
        }
    };
    let m = bytes_to_m(FLAG);
    let c = m.modpow(&e, &n);
    let mut params = RsaParams {
        n: Some(n.clone()),
        e: Some(e),
        c: Some(c),
        ..Default::default()
    };
    let out = attack_wiener(&mut params);
    assert_eq!(out.status, AttackStatus::Success, "{}", out.message);
    assert_plaintext(&out, &m);
    assert_eq!(params.d.as_ref().unwrap(), &d);
    assert_eq!(params.p.unwrap() * params.q.unwrap(), n);
}

#[test]
fn wiener_large_d_fails() {
    let mut state = 0x11F0;
    let key = keypair(96, &mut state, 65537); // d is full-size → not vulnerable
    let mut params = RsaParams {
        n: Some(key.n.clone()),
        e: Some(key.e.clone()),
        ..Default::default()
    };
    let out = attack_wiener(&mut params);
    assert_eq!(out.status, AttackStatus::Failed, "{}", out.message);
    assert!(params.p.is_none() && params.d.is_none());
}

// --------------------------------------------------------------- Fermat --

#[test]
fn fermat_recovers_close_primes() {
    let mut state = 0xF3A1;
    let base = math::weak_prime(60, &mut state);
    let p = next_probable_prime(base);
    let q = next_probable_prime(&p + (big(1) << 20usize)); // gap ≈ 2^20 → few steps
    let n = &p * &q;
    let phi = (&p - big(1)) * (&q - big(1));
    let e = big(65537);
    let d = math::modinv(&e, &phi).expect("e invertible mod φ");
    let m = bytes_to_m(SMALL_FLAG); // n is only ~128 bits
    let c = m.modpow(&e, &n);
    let mut params = RsaParams {
        n: Some(n.clone()),
        e: Some(e),
        c: Some(c),
        ..Default::default()
    };
    let out = attack_fermat(&mut params, in_ms(10_000));
    assert_eq!(out.status, AttackStatus::Success, "{}", out.message);
    assert_plaintext(&out, &m);
    assert_eq!(params.p.unwrap(), p.min(q.clone()));
    assert_eq!(params.q.unwrap(), q);
    assert_eq!(params.d.unwrap(), d);
}

#[test]
fn fermat_unbalanced_primes_fails_within_bounds() {
    let mut state = 0xF422;
    let p = math::weak_prime(64, &mut state);
    let q = math::weak_prime(128, &mut state); // far apart and unbalanced
    let key = TestKey {
        p: p.clone(),
        q: q.clone(),
        n: &p * &q,
        phi: (&p - big(1)) * (&q - big(1)),
        e: big(65537),
        d: big(0),
        dp: big(0),
        dq: big(0),
    };
    let mut params = key.params_with_c(&bytes_to_m(FLAG));
    let out = attack_fermat(&mut params, in_ms(300));
    assert_eq!(out.status, AttackStatus::Failed, "{}", out.message);
    assert!(out.plaintext.is_none());
    assert!(params.p.is_none());
}

// ---------------------------------------------------------------- low e --

#[test]
fn low_e_recovers_unpadded_small_message() {
    let mut state = 0x1011;
    let key = keypair(256, &mut state, 3);
    let m = bytes_to_m(FLAG); // 17 bytes = 136 bits → m³ = 408 bits < 512-bit n
    assert!((&m * &m * &m) < key.n);
    let mut params = key.params_with_c(&m);
    let out = attack_low_e(&mut params, in_ms(5_000));
    assert_eq!(out.status, AttackStatus::Success, "{}", out.message);
    assert_plaintext(&out, &m);
}

#[test]
fn low_e_large_message_fails() {
    let mut state = 0x1111;
    let key = keypair(256, &mut state, 3);
    let m = math::weak_random_odd(300, &mut state); // m³ ≫ n → no exact root
    let mut params = key.params_with_c(&m);
    let out = attack_low_e(&mut params, in_ms(5_000));
    assert_eq!(out.status, AttackStatus::Failed, "{}", out.message);
    assert!(out.plaintext.is_none());
}

#[test]
fn low_e_degenerate_exponent_not_applicable() {
    let mut state = 0x1211;
    let key = keypair(64, &mut state, 3);
    let mut params = key.params_with_c(&bytes_to_m(FLAG));
    params.e = Some(big(1)); // e = 1 is out of the supported range
    let out = attack_low_e(&mut params, in_ms(1_000));
    assert_eq!(out.status, AttackStatus::NotApplicable);
}

// -------------------------------------------------------- common modulus --

#[test]
fn common_modulus_recovers_plaintext() {
    let mut state = 0xC0A0;
    let (p, q, phi) = loop {
        let p = math::weak_prime(128, &mut state);
        let q = math::weak_prime(128, &mut state);
        let phi = (&p - big(1)) * (&q - big(1));
        if math::modinv(&big(5), &phi).is_some() && math::modinv(&big(17), &phi).is_some() {
            break (p, q, phi);
        }
    };
    let n = &p * &q;
    let (e1, e2) = (big(5), big(17));
    let (d1, d2) = (
        math::modinv(&e1, &phi).expect("5 invertible"),
        math::modinv(&e2, &phi).expect("17 invertible"),
    );
    assert!(d1 > big(1) && d2 > big(1));
    let m = bytes_to_m(FLAG);
    let c1 = m.modpow(&e1, &n);
    let c2 = m.modpow(&e2, &n);
    let mut params = RsaParams {
        n: Some(n.clone()),
        e: Some(e1),
        c: Some(c1),
        sets: vec![RsaSet {
            n: Some(n),
            e: Some(e2),
            c: Some(c2),
        }],
        ..Default::default()
    };
    let out = attack_common_modulus(&mut params);
    assert_eq!(out.status, AttackStatus::Success, "{}", out.message);
    assert_plaintext(&out, &m);
}

#[test]
fn common_modulus_same_exponent_not_applicable() {
    let mut state = 0xC0A1;
    let key = keypair(64, &mut state, 17);
    let m = bytes_to_m(FLAG);
    let c = key.encrypt(&m);
    let mut params = key.params_with_c(&m);
    params.c = Some(c.clone());
    params.sets = vec![RsaSet {
        n: Some(key.n.clone()),
        e: Some(key.e.clone()),
        c: Some(c),
    }];
    let out = attack_common_modulus(&mut params);
    assert_eq!(out.status, AttackStatus::NotApplicable);
    assert!(out.plaintext.is_none());
}

#[test]
fn common_modulus_non_coprime_exponents_fail() {
    let mut state = 0xC0A2;
    // e1 = 3, e2 = 9 share the factor 3; both are valid exponents when
    // gcd(9, φ) = 1.
    let (p, q, n, _phi) = loop {
        let p = math::weak_prime(64, &mut state);
        let q = math::weak_prime(64, &mut state);
        let phi = (&p - big(1)) * (&q - big(1));
        if math::modinv(&big(9), &phi).is_some() && math::modinv(&big(3), &phi).is_some() {
            let n = &p * &q;
            break (p, q, n, phi);
        }
    };
    let m = bytes_to_m(FLAG);
    let c1 = m.modpow(&big(3), &n);
    let c2 = m.modpow(&big(9), &n);
    let mut params = RsaParams {
        n: Some(n.clone()),
        e: Some(big(3)),
        c: Some(c1),
        sets: vec![RsaSet {
            n: Some(n),
            e: Some(big(9)),
            c: Some(c2),
        }],
        ..Default::default()
    };
    let out = attack_common_modulus(&mut params);
    assert_eq!(out.status, AttackStatus::Failed, "{}", out.message);
    assert!(out.plaintext.is_none());
    drop((p, q));
}

#[test]
fn common_modulus_different_moduli_not_applicable() {
    let mut state = 0xC0A3;
    let key1 = keypair(64, &mut state, 5);
    let key2 = keypair(64, &mut state, 17);
    let m = bytes_to_m(FLAG);
    let mut params = key1.params_with_c(&m);
    params.sets = vec![RsaSet {
        n: Some(key2.n.clone()),
        e: Some(key2.e.clone()),
        c: Some(key2.encrypt(&m)),
    }];
    let out = attack_common_modulus(&mut params);
    assert_eq!(out.status, AttackStatus::NotApplicable);
}

// ---------------------------------------------------------------- Håstad --

#[test]
fn hastad_recovers_broadcast() {
    let mut state = 0xCA57;
    let e = big(3);
    let mut moduli = Vec::new();
    let mut ciphertexts = Vec::new();
    let m = bytes_to_m(b"flag{h}");
    for _ in 0..3 {
        let p = math::weak_prime(64, &mut state);
        let q = math::weak_prime(64, &mut state);
        let n = &p * &q;
        moduli.push(n.clone());
        ciphertexts.push(m.modpow(&e, &n));
    }
    let mut params = RsaParams {
        n: Some(moduli[0].clone()),
        e: Some(e.clone()),
        c: Some(ciphertexts[0].clone()),
        sets: vec![
            RsaSet {
                n: Some(moduli[1].clone()),
                e: Some(e.clone()),
                c: Some(ciphertexts[1].clone()),
            },
            RsaSet {
                n: Some(moduli[2].clone()),
                e: Some(e.clone()),
                c: Some(ciphertexts[2].clone()),
            },
        ],
        ..Default::default()
    };
    let out = attack_hastad(&mut params);
    assert_eq!(out.status, AttackStatus::Success, "{}", out.message);
    assert_plaintext(&out, &m);
}

#[test]
fn hastad_insufficient_sets_not_applicable() {
    let mut state = 0xCA56;
    let key = keypair(64, &mut state, 3);
    let mut params = key.params_with_c(&bytes_to_m(FLAG));
    params.sets = vec![RsaSet {
        n: Some(key.n.clone()),
        e: Some(key.e.clone()),
        c: Some(key.encrypt(&bytes_to_m(FLAG))),
    }];
    let out = attack_hastad(&mut params);
    assert_eq!(out.status, AttackStatus::NotApplicable);
}

#[test]
fn hastad_different_messages_fail() {
    let mut state = 0xCA58;
    let e = big(3);
    let mut params = RsaParams {
        e: Some(e.clone()),
        ..Default::default()
    };
    let mut ns = Vec::new();
    for i in 0..3u64 {
        let p = math::weak_prime(64, &mut state);
        let q = math::weak_prime(64, &mut state);
        let n = &p * &q;
        let m = bytes_to_m(FLAG) + big(i * 7919); // different messages
        let c = m.modpow(&e, &n);
        if i == 0 {
            params.n = Some(n.clone());
            params.c = Some(c);
        } else {
            params.sets.push(RsaSet {
                n: Some(n.clone()),
                e: Some(e.clone()),
                c: Some(c),
            });
        }
        ns.push(n);
    }
    let _ = ns;
    let out = attack_hastad(&mut params);
    assert_eq!(out.status, AttackStatus::Failed, "{}", out.message);
    assert!(out.plaintext.is_none());
}

// ---------------------------------------------------------- shared prime --

#[test]
fn shared_prime_recovers_factors_and_plaintext() {
    let mut state = 0x5CA1;
    let shared = math::weak_prime(64, &mut state);
    let q1 = math::weak_prime(64, &mut state);
    let q2 = math::weak_prime(64, &mut state);
    let n1 = &shared * &q1;
    let n2 = &shared * &q2;
    let phi = (&shared - big(1)) * (&q1 - big(1));
    let e = big(65537);
    let d = math::modinv(&e, &phi).expect("e invertible");
    let m = bytes_to_m(SMALL_FLAG); // n1 is only 128 bits
    let c = m.modpow(&e, &n1);
    let mut params = RsaParams {
        n: Some(n1.clone()),
        e: Some(e),
        c: Some(c),
        ns: vec![n2],
        ..Default::default()
    };
    let out = attack_shared_prime(&mut params);
    assert_eq!(out.status, AttackStatus::Success, "{}", out.message);
    assert_plaintext(&out, &m);
    let _ = d;
    assert_eq!(params.p.unwrap(), shared.min(q1.clone()));
}

#[test]
fn shared_prime_coprime_moduli_fail() {
    let mut state = 0x5CA2;
    let key = keypair(64, &mut state, 65537);
    let other = keypair(64, &mut state, 65537);
    let mut params = key.params_with_c(&bytes_to_m(FLAG));
    params.ns = vec![other.n.clone()];
    let out = attack_shared_prime(&mut params);
    assert_eq!(out.status, AttackStatus::Failed, "{}", out.message);
    assert!(out.plaintext.is_none());
}

#[test]
fn shared_prime_needs_two_moduli() {
    let mut state = 0x5CA3;
    let key = keypair(64, &mut state, 65537);
    let mut params = key.params_with_c(&bytes_to_m(FLAG));
    let out = attack_shared_prime(&mut params);
    assert_eq!(out.status, AttackStatus::NotApplicable);
}

// ----------------------------------------------------------- Pollard rho --

#[test]
fn pollard_rho_factors_small_modulus() {
    let mut state = 0xA40;
    let key = keypair(32, &mut state, 65537); // 64-bit n
    let m = bytes_to_m(SMALL_FLAG);
    let mut params = key.params_with_c(&m);
    let out = attack_pollard_rho(&mut params, in_ms(10_000));
    assert_eq!(out.status, AttackStatus::Success, "{}", out.message);
    assert_plaintext(&out, &m);
    assert_eq!(params.p.unwrap() * params.q.unwrap(), key.n);
}

#[test]
fn pollard_rho_large_modulus_not_applicable() {
    let mut state = 0xA41;
    let key = keypair(128, &mut state, 65537); // 256-bit n ≫ 96-bit cap
    let mut params = key.params_with_c(&bytes_to_m(FLAG));
    let out = attack_pollard_rho(&mut params, in_ms(1_000));
    assert_eq!(out.status, AttackStatus::NotApplicable);
    assert!(out.plaintext.is_none());
}

#[test]
fn pollard_rho_prime_modulus_fails_cleanly() {
    let mut state = 0xA42;
    let prime = math::weak_prime(64, &mut state);
    let mut params = RsaParams {
        n: Some(prime),
        e: Some(big(65537)),
        c: Some(big(123)),
        ..Default::default()
    };
    let out = attack_pollard_rho(&mut params, in_ms(2_000));
    assert_eq!(out.status, AttackStatus::Failed, "{}", out.message);
    assert!(out.plaintext.is_none());
}

// --------------------------------------------------------- Pollard p − 1 --

#[test]
fn pollard_pm1_factors_smooth_prime() {
    let mut state = 0xFA1A;
    // M = product of primes ≤ 100; p = 2tM + 1 prime ⇒ p−1 = 2tM is
    // 200000-smooth for any t ≤ 500.
    let mut smooth = BigUint::one();
    for &pr in math::small_primes() {
        if pr > 100 {
            break;
        }
        smooth *= big(pr);
    }
    let p = (1..500u64)
        .map(|t| big(2) * big(t) * &smooth + big(1))
        .find(math::is_probable_prime)
        .expect("a prime of the form 2tM+1 must exist below t=500");
    let q = math::weak_prime(64, &mut state);
    let n = &p * &q;
    let phi = (&p - big(1)) * (&q - big(1));
    let e = big(65537);
    assert!(math::modinv(&e, &phi).is_some(), "e must be invertible");
    let m = bytes_to_m(FLAG);
    let mut params = RsaParams {
        n: Some(n.clone()),
        e: Some(e),
        c: Some(m.modpow(&big(65537), &n)),
        ..Default::default()
    };
    let out = attack_pollard_pm1(&mut params, in_ms(15_000));
    assert_eq!(out.status, AttackStatus::Success, "{}", out.message);
    assert_plaintext(&out, &m);
    assert_eq!(params.p.unwrap(), p.min(q.clone()));
}

#[test]
fn pollard_pm1_non_smooth_fails() {
    let mut state = 0xFA1B;
    let key = keypair(64, &mut state, 65537); // random 64-bit primes: p−1 not smooth
    let mut params = key.params_with_c(&bytes_to_m(FLAG));
    let out = attack_pollard_pm1(&mut params, in_ms(10_000));
    assert_eq!(out.status, AttackStatus::Failed, "{}", out.message);
    assert!(out.plaintext.is_none());
}

// -------------------------------------------------------------- analyzer --

#[test]
fn analyze_hard_instance_reports_expected_statuses() {
    let mut state = 0xA141;
    let key = keypair(96, &mut state, 65537); // well-formed, not vulnerable
    let report = analyze(&key.params_with_c(&bytes_to_m(FLAG)), false, 700);
    let expect = [
        ("known-pq", AttackStatus::NotApplicable),
        ("known-d", AttackStatus::NotApplicable),
        ("known-phi", AttackStatus::NotApplicable),
        ("dp-leak", AttackStatus::NotApplicable),
        ("common-modulus", AttackStatus::NotApplicable),
        ("hastad", AttackStatus::NotApplicable),
        ("shared-prime", AttackStatus::NotApplicable),
        ("low-e", AttackStatus::NotApplicable),
        ("wiener", AttackStatus::Failed),
        ("fermat", AttackStatus::Failed),
        ("pollard-rho", AttackStatus::NotApplicable),
        ("pollard-pm1", AttackStatus::Failed),
    ];
    for (id, status) in expect {
        assert_eq!(
            finding(&report, id).status,
            status,
            "finding {id}: {}",
            finding(&report, id).message
        );
    }
    assert!(
        report.plaintext.is_none(),
        "hard instance must not yield a plaintext"
    );
}

#[test]
fn analyze_from_json_params_file_with_only_n_e_c() {
    // Simulate a CTF "params file": only the public triple (n, e, c).
    let mut state = 0xA142;
    let key = keypair(96, &mut state, 65537);
    let doc = serde_json::json!({
        "n": format!("{}", key.n),
        "e": "65537",
        "c": format!("{}", key.encrypt(&bytes_to_m(FLAG))),
    });
    let params = RsaParams::from_json(&doc).expect("params file must parse");
    let report = analyze(&params, true, 700);
    // The structural attacks are inapplicable; the bounded searches run and
    // must fail without a false success.
    for (id, status) in [
        ("low-e", AttackStatus::NotApplicable),
        ("wiener", AttackStatus::Failed),
        ("fermat", AttackStatus::Failed),
    ] {
        assert_eq!(
            finding(&report, id).status,
            status,
            "finding {id}: {}",
            finding(&report, id).message
        );
    }
    assert!(report.plaintext.is_none());
    assert!(report.params["n"].as_str().is_some());
}

#[test]
fn analyze_from_json_with_factors_solves() {
    let mut state = 0xA143;
    let key = keypair(64, &mut state, 65537);
    let m = bytes_to_m(SMALL_FLAG);
    let doc = serde_json::json!({
        "n": format!("{}", key.n),
        "e": format!("{}", key.e),
        "c": format!("{}", key.encrypt(&m)),
        "p": format!("{}", key.p),
        "q": format!("{}", key.q),
    });
    let params = RsaParams::from_json(&doc).expect("params file must parse");
    let report = analyze(&params, true, 5_000);
    let pt = report.plaintext.expect("p,q in the file must solve it");
    assert_eq!(pt.m_hex, format!("{m:x}"));
    assert_eq!(
        pt.flag_like.as_deref(),
        Some(std::str::from_utf8(SMALL_FLAG).unwrap())
    );
}

#[test]
fn analyze_with_pq_solves_and_verifies_hex() {
    let mut state = 0xA151;
    let key = keypair(64, &mut state, 65537);
    let m = bytes_to_m(SMALL_FLAG);
    let mut params = key.params_with_c(&m);
    params.p = Some(key.p.clone());
    params.q = Some(key.q.clone());
    let report = analyze(&params, true, 5_000);
    assert_eq!(report.findings[0].id, "known-pq");
    assert_eq!(report.findings[0].status, AttackStatus::Success);
    let pt = report.plaintext.expect("solve must produce the plaintext");
    assert_eq!(pt.m_hex, format!("{m:x}"));
    assert_eq!(
        pt.utf8.as_deref(),
        Some(std::str::from_utf8(SMALL_FLAG).unwrap())
    );
    assert_eq!(
        report.params["p"],
        serde_json::Value::String(format!("0x{:x}", key.p))
    );
}

#[test]
fn analyze_solves_low_e_instance() {
    let mut state = 0xA152;
    let key = keypair(256, &mut state, 3);
    let m = bytes_to_m(FLAG);
    let report = analyze(&key.params_with_c(&m), true, 5_000);
    let low_e = finding(&report, "low-e");
    assert_eq!(low_e.status, AttackStatus::Success, "{}", low_e.message);
    let pt = report.plaintext.expect("solve must produce the plaintext");
    assert_eq!(pt.m_hex, format!("{m:x}"));
    // Solve must stop at the first success: no factorization escalations ran.
    assert!(report.findings.iter().all(|f| f.id != "wiener"));
}

#[test]
fn analyze_solves_wiener_instance() {
    let mut state = 0xA153;
    // n = 256 bits, d = 60 bits < n^(1/4)/3 → Wiener-vulnerable.
    let p = math::weak_prime(128, &mut state);
    let q = math::weak_prime(128, &mut state);
    let n = &p * &q;
    let phi = (&p - big(1)) * (&q - big(1));
    let (e, d) = loop {
        let d = math::weak_random_odd(60, &mut state);
        if let Some(e) = math::modinv(&d, &phi) {
            break (e, d);
        }
    };
    let m = bytes_to_m(FLAG);
    let c = m.modpow(&e, &n);
    let params = RsaParams {
        n: Some(n),
        e: Some(e),
        c: Some(c),
        ..Default::default()
    };
    let report = analyze(&params, true, 5_000);
    let wiener = finding(&report, "wiener");
    assert_eq!(wiener.status, AttackStatus::Success, "{}", wiener.message);
    assert_eq!(report.plaintext.expect("plaintext").m_hex, format!("{m:x}"));
    assert_eq!(
        report.params["d"],
        serde_json::Value::String(format!("0x{d:x}"))
    );
}

// ------------------------------------------------------------ robustness --

#[test]
fn analyzer_never_panics_on_degenerate_input() {
    let cases = vec![
        RsaParams::default(),
        RsaParams {
            n: Some(big(0)),
            e: Some(big(0)),
            c: Some(big(0)),
            d: Some(big(0)),
            p: Some(big(0)),
            q: Some(big(0)),
            phi: Some(big(0)),
            dp: Some(big(0)),
            dq: Some(big(0)),
            qinv: Some(big(0)),
            ..Default::default()
        },
        RsaParams {
            n: Some(big(1)),
            e: Some(big(1)),
            c: Some(big(1)),
            ..Default::default()
        },
        RsaParams {
            n: Some(big(4)),
            e: Some(big(3)),
            c: Some(big(3)),
            ..Default::default()
        },
        RsaParams {
            n: Some(big(9)),
            e: Some(big(1)),
            c: Some(big(1)),
            dp: Some(big(1)),
            ..Default::default()
        },
        RsaParams {
            n: Some(big(3233)),
            e: Some(big(17)),
            c: Some(big(855)),
            p: Some(big(2)),
            q: Some(big(2)),
            ..Default::default()
        },
        RsaParams {
            n: Some(big(3233)),
            e: Some(big(17)),
            c: Some(big(855)),
            sets: vec![
                RsaSet::default(),
                RsaSet {
                    n: Some(big(3233)),
                    ..Default::default()
                },
            ],
            ns: vec![big(3233), big(0), big(1)],
            ..Default::default()
        },
    ];
    for params in cases {
        let _ = analyze(&params, true, 150);
        let _ = analyze(&params, false, 150);
    }
}
