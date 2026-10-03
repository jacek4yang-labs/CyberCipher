//! End-to-end tests for the PKI-residual RSA attacks: the dp+dq joint leak
//! (`rsa-dpdq-recover`) and Rabin e=2 decryption with its four-root
//! ambiguity.
//!
//! Instances are generated with the crate's LCG-driven `weak_prime` (or
//! deterministic prime walks) so every test is reproducible.

use cybercipher_attack::math;
use cybercipher_attack::rsa::{
    analyze, attack_dpdq_recover, attack_rabin, rabin_decrypt, AttackStatus, RsaParams,
};
use num_bigint::BigUint;

const FLAG: &[u8] = b"flag{r54_4tt4ck5}";
const SMALL_FLAG: &[u8] = b"ctf{sm}";

fn big(n: u64) -> BigUint {
    BigUint::from(n)
}

fn bytes_to_m(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

fn finding<'a>(
    report: &'a cybercipher_attack::rsa::AnalyzerReport,
    id: &str,
) -> &'a cybercipher_attack::rsa::AttackOutcome {
    report
        .findings
        .iter()
        .find(|f| f.id == id)
        .unwrap_or_else(|| panic!("report is missing a `{id}` finding"))
}

/// Deterministic prime with residue 3 mod 4 (Rabin's shortcut path), walked
/// from a fixed constant so the value is stable across runs.
fn prime_3mod4(start: BigUint) -> BigUint {
    let mut x = start | big(1);
    loop {
        if (&x & big(3)) == big(3) && math::is_probable_prime(&x) {
            return x;
        }
        x += big(2);
    }
}

/// A synthetic two-prime RSA key with the CRT exponents.
struct TestKey {
    p: BigUint,
    q: BigUint,
    n: BigUint,
    e: BigUint,
    d: BigUint,
    dp: BigUint,
    dq: BigUint,
}

impl TestKey {
    fn encrypt(&self, m: &BigUint) -> BigUint {
        m.modpow(&self.e, &self.n)
    }
}

/// Generate a key with the requested prime size and exponent `e`. Retries
/// until e is invertible modulo φ(n) (always terminates fast).
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
            e,
            d,
            dp,
            dq,
        };
    }
}

// ----------------------------------------------------- dp+dq joint leak --

#[test]
fn dpdq_recover_recovers_plaintext_and_full_key() {
    let mut state = 0xD0D0u64;
    let key = keypair(64, &mut state, 65537);
    let m = bytes_to_m(SMALL_FLAG);
    let mut params = RsaParams {
        n: Some(key.n.clone()),
        e: Some(key.e.clone()),
        c: Some(key.encrypt(&m)),
        dp: Some(key.dp.clone()),
        dq: Some(key.dq.clone()),
        ..Default::default()
    };
    let out = attack_dpdq_recover(&mut params);
    assert_eq!(out.status, AttackStatus::Success, "outcome: {out:?}");
    let pt = out.plaintext.expect("success carries the plaintext");
    assert_eq!(pt.m_hex, format!("{m:x}"));
    assert_eq!(params.p.as_ref(), Some(&key.p));
    assert_eq!(params.q.as_ref(), Some(&key.q));
    assert_eq!(params.d.as_ref(), Some(&key.d));
    // The CRT material is recomputed consistently with the recovered key.
    assert_eq!(params.dp.as_ref(), Some(&key.dp));
    assert_eq!(params.dq.as_ref(), Some(&key.dq));
    assert_eq!(
        params.qinv.as_ref().map(|v| v * &key.q % &key.p),
        Some(big(1))
    );
    assert!(out
        .details
        .as_deref()
        .unwrap_or_default()
        .contains("jointly verified"));
}

#[test]
fn dpdq_recover_requires_all_four_parameters() {
    let mut state = 0xD0D1u64;
    let key = keypair(48, &mut state, 65537);
    let mut params = RsaParams {
        n: Some(key.n.clone()),
        e: Some(key.e.clone()),
        dp: Some(key.dp.clone()),
        ..Default::default()
    };
    let out = attack_dpdq_recover(&mut params);
    assert_eq!(out.status, AttackStatus::NotApplicable);
    assert!(out.message.contains("dq"));
}

#[test]
fn dpdq_recover_fails_on_inconsistent_leaks() {
    let mut state = 0xD0D2u64;
    let key = keypair(64, &mut state, 65537);
    // Both leaks scrambled: no identity holds, nothing factors n.
    let bogus_dp = (&key.dp ^ big(0xDEADBEEF)) | big(1);
    let bogus_dq = (&key.dq ^ big(0xABABABAB)) | big(1);
    let mut params = RsaParams {
        n: Some(key.n.clone()),
        e: Some(key.e.clone()),
        dp: Some(bogus_dp),
        dq: Some(bogus_dq),
        ..Default::default()
    };
    let out = attack_dpdq_recover(&mut params);
    assert_eq!(out.status, AttackStatus::Failed, "outcome: {out:?}");
    assert!(
        params.p.is_none(),
        "a failed attack must not enrich factors"
    );
}

#[test]
fn dpdq_recover_tolerates_a_corrupt_second_leak() {
    // Genuine dp plus garbage dq: the dp identity factors n on its own and
    // the inconsistent dq is reported as ignored rather than blocking.
    let mut state = 0xD0D2u64;
    let key = keypair(64, &mut state, 65537);
    let m = bytes_to_m(SMALL_FLAG);
    let bogus_dq = (&key.dq ^ big(0xABABABAB)) | big(1);
    let mut params = RsaParams {
        n: Some(key.n.clone()),
        e: Some(key.e.clone()),
        c: Some(key.encrypt(&m)),
        dp: Some(key.dp.clone()),
        dq: Some(bogus_dq),
        ..Default::default()
    };
    let out = attack_dpdq_recover(&mut params);
    assert_eq!(out.status, AttackStatus::Success, "outcome: {out:?}");
    let pt = out.plaintext.expect("success carries the plaintext");
    assert_eq!(pt.m_hex, format!("{m:x}"));
    let details = out.details.as_deref().unwrap_or_default();
    assert!(details.contains("was ignored"), "details: {details}");
}

#[test]
fn dpdq_recover_without_c_reports_key_material() {
    let mut state = 0xD0D3u64;
    let key = keypair(48, &mut state, 65537);
    let mut params = RsaParams {
        n: Some(key.n.clone()),
        e: Some(key.e.clone()),
        dp: Some(key.dp.clone()),
        dq: Some(key.dq.clone()),
        ..Default::default()
    };
    let out = attack_dpdq_recover(&mut params);
    assert_eq!(out.status, AttackStatus::Applicable);
    assert!(out.plaintext.is_none());
    assert_eq!(params.d.as_ref(), Some(&key.d));
    assert!(out.message.contains("provide c to decrypt"));
}

#[test]
fn dpdq_recover_dq_identity_rescues_mislabeled_dp() {
    // The dp value is garbage: the dp-side identity finds nothing, and the
    // escalation to the dq identity is what factors n.
    let mut state = 0xD0D4u64;
    let key = keypair(64, &mut state, 65537);
    let m = bytes_to_m(SMALL_FLAG);
    let bogus_dp = (&key.dp ^ big(0x5151515151515151)) | big(1);
    let mut params = RsaParams {
        n: Some(key.n.clone()),
        e: Some(key.e.clone()),
        c: Some(key.encrypt(&m)),
        dp: Some(bogus_dp),
        dq: Some(key.dq.clone()),
        ..Default::default()
    };
    let out = attack_dpdq_recover(&mut params);
    assert_eq!(out.status, AttackStatus::Success, "outcome: {out:?}");
    let pt = out.plaintext.expect("success carries the plaintext");
    assert_eq!(pt.m_hex, format!("{m:x}"));
    assert_eq!(params.d.as_ref(), Some(&key.d));
}

#[test]
fn dpdq_recover_pipeline_escalates_past_dp_leak() {
    // In the analyzer the garbage-dp instance makes dp-leak fail; the
    // dpdq-recover stage picks it up and solves it.
    let mut state = 0xD0D5u64;
    let key = keypair(64, &mut state, 65537);
    let m = bytes_to_m(SMALL_FLAG);
    let bogus_dp = (&key.dp ^ big(0x6262626262626262)) | big(1);
    let params = RsaParams {
        n: Some(key.n.clone()),
        e: Some(key.e.clone()),
        c: Some(key.encrypt(&m)),
        dp: Some(bogus_dp),
        dq: Some(key.dq.clone()),
        ..Default::default()
    };
    let report = analyze(&params, true, 10_000);
    assert_eq!(
        report.plaintext.as_ref().map(|p| p.m_hex.as_str()),
        Some(format!("{m:x}").as_str())
    );
    assert_eq!(
        finding(&report, "dpdq-recover").status,
        AttackStatus::Success
    );
    // dp-leak ran first and failed on the bogus dp.
    assert_eq!(finding(&report, "dp-leak").status, AttackStatus::Failed);
}

#[test]
fn dpdq_recover_works_with_large_e() {
    // e = 2^31 − 1 exceeds the k-sweep bound (2^24), so only the
    // Fermat-base gcd identities can succeed here.
    let mut state = 0xD0D6u64;
    let key = keypair(64, &mut state, (1u64 << 31) - 1);
    let m = bytes_to_m(SMALL_FLAG);
    let mut params = RsaParams {
        n: Some(key.n.clone()),
        e: Some(key.e.clone()),
        c: Some(key.encrypt(&m)),
        dp: Some(key.dp.clone()),
        dq: Some(key.dq.clone()),
        ..Default::default()
    };
    let out = attack_dpdq_recover(&mut params);
    assert_eq!(out.status, AttackStatus::Success, "outcome: {out:?}");
    let pt = out.plaintext.expect("success carries the plaintext");
    assert_eq!(pt.m_hex, format!("{m:x}"));
}

// ------------------------------------------------------------- Rabin ----

#[test]
fn rabin_decrypt_returns_four_verified_roots() {
    let p = prime_3mod4(big(1) << 100);
    let q = prime_3mod4(big(3) << 100);
    let n = &p * &q;
    let m = bytes_to_m(FLAG);
    let c = &m * &m % &n;
    let result = rabin_decrypt(&p, &q, &c, None).expect("c must be a QR for a Rabin ciphertext");
    assert_eq!(
        result.roots.len(),
        4,
        "standard Rabin ambiguity: four roots"
    );
    assert_eq!(result.matched_hint, None);
    // One of the roots is the original message; all roots verify by contract.
    assert!(
        result.roots.iter().any(|r| r.m_hex == format!("{m:x}")),
        "the original message must be among the roots"
    );
    for r in &result.roots {
        let root = BigUint::parse_bytes(r.m_hex.as_bytes(), 16).unwrap();
        assert_eq!((&root * &root) % &n, c);
    }
}

#[test]
fn rabin_decrypt_hint_selects_true_root() {
    let p = prime_3mod4(big(5) << 100);
    let q = prime_3mod4(big(7) << 100);
    let m = bytes_to_m(FLAG);
    let c = &m * &m % &(&p * &q);
    let result = rabin_decrypt(&p, &q, &c, Some("flag{")).expect("QR ciphertext");
    let idx = result.matched_hint.expect("hint must match the true root");
    assert_eq!(result.roots[idx].m_hex, format!("{m:x}"));
}

#[test]
fn rabin_attack_auto_selects_flag_root() {
    let mut state = 0xD0D7u64;
    let p = math::weak_prime(64, &mut state);
    let mut q = math::weak_prime(64, &mut state);
    while q == p {
        q = math::weak_prime(64, &mut state);
    }
    let m = bytes_to_m(SMALL_FLAG);
    let c = &m * &m % &(&p * &q);
    let mut params = RsaParams {
        p: Some(p),
        q: Some(q),
        c: Some(c),
        ..Default::default()
    };
    let out = attack_rabin(&mut params);
    assert_eq!(out.status, AttackStatus::Success, "outcome: {out:?}");
    let pt = out.plaintext.expect("success carries the plaintext");
    assert_eq!(pt.m_hex, format!("{m:x}"));
    let details = out.details.as_deref().unwrap_or_default();
    assert!(
        details.contains("#0:") && details.contains("#3:"),
        "all roots listed: {details}"
    );
    // n is derived and stored.
    assert!(params.n.is_some());
}

#[test]
fn rabin_attack_reports_ambiguity_without_hint() {
    // Non-UTF-8, non-flag message: the roots stay genuinely ambiguous or the
    // outcome auto-selects a unique interpretation — either way every root
    // must be listed in the details.
    let p = prime_3mod4(big(11) << 100);
    let q = prime_3mod4(big(13) << 100);
    let m = BigUint::from_bytes_be(&[0xFFu8; 24]);
    let c = &m * &m % &(&p * &q);
    let mut params = RsaParams {
        p: Some(p),
        q: Some(q),
        c: Some(c),
        ..Default::default()
    };
    let out = attack_rabin(&mut params);
    let details = out.details.as_deref().unwrap_or_default();
    match out.status {
        AttackStatus::Applicable => {
            assert!(out.message.contains("ambiguity"), "outcome: {out:?}");
            assert!(
                details.contains("#0:") && details.contains("#3:"),
                "details: {details}"
            );
        }
        AttackStatus::Success => {
            assert!(
                details.contains("#0:") && details.contains("#3:"),
                "details: {details}"
            );
        }
        other => panic!("unexpected status {other:?}: {out:?}"),
    }
}

#[test]
fn rabin_attack_not_applicable_for_e_not_2() {
    let mut state = 0xD0D8u64;
    let p = math::weak_prime(48, &mut state);
    let q = math::weak_prime(48, &mut state);
    let mut params = RsaParams {
        p: Some(p),
        q: Some(q),
        e: Some(big(3)),
        c: Some(big(25)),
        ..Default::default()
    };
    let out = attack_rabin(&mut params);
    assert_eq!(out.status, AttackStatus::NotApplicable);
    assert!(out.message.contains("e = 2"));
}

#[test]
fn rabin_decrypt_rejects_non_residue_and_bad_factors() {
    let p = prime_3mod4(big(17) << 40);
    let q = prime_3mod4(big(19) << 40);
    // A quadratic non-residue mod p, found by Euler's criterion.
    let half = (&p - big(1)) >> 1usize;
    let mut nr = big(5);
    while nr.modpow(&half, &p) != &p - big(1) {
        nr += big(1);
    }
    let err = rabin_decrypt(&p, &q, &nr, None).unwrap_err();
    assert!(err.contains("quadratic residue"), "error: {err}");
    // Equal factors.
    let err = rabin_decrypt(&p, &p, &big(4), None).unwrap_err();
    assert!(err.contains("distinct primes"), "error: {err}");
    // Composite factor.
    let err = rabin_decrypt(&(&p * &q), &q, &big(4), None).unwrap_err();
    assert!(err.contains("not prime"), "error: {err}");
}

#[test]
fn rabin_decrypt_degenerate_root_counts() {
    let p = prime_3mod4(big(23) << 40);
    let q = prime_3mod4(big(29) << 40);
    // c = 0: the single root 0.
    let result = rabin_decrypt(&p, &q, &big(0), None).unwrap();
    assert_eq!(result.roots.len(), 1);
    assert_eq!(result.roots[0].m_hex, "0");
    // c ≡ 0 mod p but not mod q: mp = 0 collapses two sign pairs → 2 roots.
    let m = &p * big(7); // divisible by p, coprime to q
    let c = &m * &m % &(&p * &q);
    let result = rabin_decrypt(&p, &q, &c, None).unwrap();
    assert_eq!(result.roots.len(), 2, "c ≡ 0 mod p yields two roots");
    assert!(result.roots.iter().any(|r| r.m_hex == format!("{m:x}")));
}

#[test]
fn rabin_pipeline_solves_when_known_pq_cannot() {
    // With e = 2 the known-pq stage cannot invert e mod φ; the rabin stage
    // produces the verified plaintext.
    let mut state = 0xD0D9u64;
    let p = math::weak_prime(64, &mut state);
    let q = math::weak_prime(64, &mut state);
    let m = bytes_to_m(SMALL_FLAG);
    let c = &m * &m % &(&p * &q);
    let params = RsaParams {
        p: Some(p),
        q: Some(q),
        e: Some(big(2)),
        c: Some(c),
        ..Default::default()
    };
    let report = analyze(&params, true, 10_000);
    assert_eq!(
        report.plaintext.as_ref().map(|pt| pt.m_hex.as_str()),
        Some(format!("{m:x}").as_str())
    );
    assert_eq!(finding(&report, "rabin").status, AttackStatus::Success);
}
