//! Rabin cryptosystem (e = 2): decryption and the four-square-root ambiguity.
//!
//! With n = p·q and c ≡ m² (mod n), the plaintext is recovered from the
//! square roots of c modulo each prime (Tonelli–Shanks, so primes ≡ 1 mod 4
//! work too) recombined by the CRT. Unlike RSA there is no unique answer:
//! four residues r satisfy r² ≡ c (mod n) for coprime p ≠ q (fewer in the
//! degenerate c ≡ 0 case), and every one decrypts. The result reports ALL of
//! them with byte/UTF-8 interpretations; a known-plaintext hint selects the
//! genuine message, and a flag-like or unique-UTF-8 root is auto-selected.
//!
//! Every reported root is verified: r² mod n == c, round trip.

use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde::Serialize;

use crate::math;
use crate::rsa::attacks::{AttackCost, AttackOutcome, AttackStatus, PlaintextResult};
use crate::rsa::params::RsaParams;

/// All square roots of the ciphertext modulo n, with interpretations.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RabinDecryptResult {
    /// The distinct roots (1, 2, or 4 entries; 4 for the standard case
    /// c ≢ 0 with p ≠ q), each verified to satisfy r² ≡ c (mod n).
    pub roots: Vec<PlaintextResult>,
    /// Index into `roots` of the root matching the known-plaintext hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_hint: Option<usize>,
}

/// Square roots of c modulo n = p·q for the Rabin cryptosystem.
///
/// `hint` is an optional known-plaintext substring used to mark the genuine
/// root. Errors carry a diagnostic string (invalid factors, c not a
/// quadratic residue — i.e. not a Rabin ciphertext for these factors).
pub fn rabin_decrypt(
    p: &BigUint,
    q: &BigUint,
    c: &BigUint,
    hint: Option<&str>,
) -> Result<RabinDecryptResult, String> {
    for (name, prime) in [("p", p), ("q", q)] {
        if prime < &BigUint::from(3u32) || (prime & BigUint::one()).is_zero() {
            return Err(format!(
                "{name} must be an odd prime ≥ 3 for Rabin decryption"
            ));
        }
        if !math::is_probable_prime(prime) {
            return Err(format!(
                "{name} is not prime — Rabin needs the prime factors"
            ));
        }
    }
    if p == q {
        return Err("p = q — the four-root CRT formula requires distinct primes".to_string());
    }
    let n = p * q;
    let c = c % &n;

    let cp = &c % p;
    let cq = &c % q;
    let mp = sqrt_mod_prime(&cp, p)
        .ok_or("c is not a quadratic residue mod p — no Rabin plaintext exists")?;
    let mq = sqrt_mod_prime(&cq, q)
        .ok_or("c is not a quadratic residue mod q — no Rabin plaintext exists")?;

    // Recombine ±mp (mod p) with ±mq (mod q); the four sign combinations are
    // the classic Rabin ambiguity. Duplicate residues (mp ≡ 0, small roots
    // colliding) are deduplicated.
    let pm = p - &mp;
    let qm = q - &mq;
    let mut roots: Vec<BigUint> = Vec::with_capacity(4);
    for (rp, rq) in [(&mp, &mq), (&mp, &qm), (&pm, &mq), (&pm, &qm)] {
        let Some((r, _)) = math::crt(&[rp.clone(), rq.clone()], &[p.clone(), q.clone()]) else {
            return Err("CRT recombination failed — p and q must be coprime".to_string());
        };
        if !roots.contains(&r) {
            roots.push(r);
        }
    }

    // Paranoia: each reported root must re-encrypt to the ciphertext.
    for r in &roots {
        if (r * r) % &n != c {
            return Err("internal error: CRT root failed the r² ≡ c check".to_string());
        }
    }

    let results: Vec<PlaintextResult> = roots.iter().map(PlaintextResult::from_m).collect();
    let matched_hint = hint.and_then(|h| {
        if h.is_empty() {
            return None;
        }
        results
            .iter()
            .position(|r| r.utf8.as_deref().is_some_and(|text| text.contains(h)))
    });

    Ok(RabinDecryptResult {
        roots: results,
        matched_hint,
    })
}

/// Analyze/decrypt a Rabin ciphertext inside the RSA parameter model:
/// applicable when p, q and c are present and e is absent or equal to 2.
/// Status semantics:
/// - `Success` — a root was selected (hint match, unique flag-like, or
///   unique UTF-8 candidate) and verified;
/// - `Applicable` — the roots are recovered (details list all of them) but
///   the Rabin ambiguity is unresolved — provide `hint`;
/// - `Failed` — no root exists (c is not a QR / factors are invalid).
pub fn attack_rabin(params: &mut RsaParams) -> AttackOutcome {
    const ID: &str = "rabin";
    const NAME: &str = "Rabin (e = 2 square roots)";

    let (Some(p), Some(q), Some(c)) = (params.p.clone(), params.q.clone(), params.c.clone()) else {
        return AttackOutcome::not_applicable(ID, NAME, "p, q and c");
    };
    if let Some(e) = &params.e {
        if *e != BigUint::from(2u32) {
            return AttackOutcome::not_applicable(ID, NAME, "e = 2 (Rabin) or no e at all");
        }
    }
    if p == q {
        // Degenerate n = p²: the CRT ambiguity formula does not apply.
        return AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Failed,
            AttackCost::Instant,
            "p = q (n is a prime square) — Rabin decryption needs distinct primes".to_string(),
        );
    }
    let pq = &p * &q;
    if let Some(n) = &params.n {
        if *n != pq {
            return AttackOutcome::new(
                ID,
                NAME,
                AttackStatus::Failed,
                AttackCost::Instant,
                "p·q ≠ n — the factors are inconsistent with the modulus".to_string(),
            );
        }
    }

    let hint = params.hint.clone();
    let result = match rabin_decrypt(&p, &q, &c, hint.as_deref()) {
        Ok(r) => r,
        Err(msg) => {
            return AttackOutcome::new(ID, NAME, AttackStatus::Failed, AttackCost::Instant, msg)
        }
    };
    if params.n.is_none() {
        params.n = Some(pq);
    }

    let listing = listing(&result.roots);
    let selected: Option<(usize, &PlaintextResult, &str)> = if let Some(idx) = result.matched_hint {
        Some((idx, &result.roots[idx], "hint match"))
    } else {
        let flagged: Vec<usize> = result
            .roots
            .iter()
            .enumerate()
            .filter(|(_, r)| r.flag_like.is_some())
            .map(|(i, _)| i)
            .collect();
        match flagged.len() {
            1 => {
                let i = flagged[0];
                Some((i, &result.roots[i], "unique flag-like root"))
            }
            0 => {
                let utf8: Vec<usize> = result
                    .roots
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| r.utf8.is_some())
                    .map(|(i, _)| i)
                    .collect();
                if utf8.len() == 1 {
                    let i = utf8[0];
                    Some((i, &result.roots[i], "unique UTF-8 root"))
                } else {
                    None
                }
            }
            _ => None,
        }
    };

    if let Some((idx, root, how)) = selected {
        let mut o = AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Success,
            AttackCost::Instant,
            format!(
                "plaintext recovered: {how} — root {idx} of {} (all roots verified: r² ≡ c mod n)",
                result.roots.len()
            ),
        );
        o.plaintext = Some(root.clone());
        o.details = Some(listing);
        return o;
    }

    AttackOutcome::new(
        ID,
        NAME,
        AttackStatus::Applicable,
        AttackCost::Instant,
        format!(
            "Rabin ambiguity: {} square roots recovered (all satisfy r² ≡ c mod n); \
             provide a known-plaintext hint to select the message",
            result.roots.len()
        ),
    )
    .with_details(listing)
}

/// Compact human-readable listing of the roots for outcome details.
fn listing(roots: &[PlaintextResult]) -> String {
    roots
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let note = match (&r.flag_like, &r.utf8) {
                (Some(flag), _) => format!("flag-like: {flag}"),
                (None, Some(text)) => format!("utf8: {}", preview(text)),
                (None, None) => "binary".to_string(),
            };
            format!("#{i}: 0x{} ({note})", r.m_hex)
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn preview(text: &str) -> String {
    if text.chars().count() <= 48 {
        text.to_string()
    } else {
        let head: String = text.chars().take(45).collect();
        format!("{head}…")
    }
}

// ------------------------------------------------------- square roots ----

/// Square root of `a` modulo an odd prime `p` (the smaller of ±r). None when
/// `a` is a quadratic non-residue. Tonelli–Shanks, so p ≡ 1 mod 4 works; the
/// p ≡ 3 mod 4 case uses the direct exponentiation shortcut.
fn sqrt_mod_prime(a: &BigUint, p: &BigUint) -> Option<BigUint> {
    debug_assert!(p > &BigUint::from(2u32));
    if a.is_zero() {
        return Some(BigUint::zero());
    }
    let one = BigUint::one();
    let a = a % p;
    if a.is_zero() {
        return Some(BigUint::zero());
    }
    // Euler's criterion: a^((p−1)/2) must be 1 for a residue, p−1 otherwise.
    let half = (p - &one) >> 1usize;
    let legendre = a.modpow(&half, p);
    if legendre != one {
        return None;
    }
    if (p & BigUint::from(3u32)) == BigUint::from(3u32) {
        // r = a^((p+1)/4) mod p.
        let r = a.modpow(&((p + &one) >> 2usize), p);
        let other = p - &r;
        return Some(r.min(other));
    }

    // Tonelli–Shanks: p − 1 = q_odd·2^s with q_odd odd.
    let mut s = 0u32;
    let mut q_odd = p - &one;
    while (&q_odd & &one).is_zero() {
        q_odd >>= 1usize;
        s += 1;
    }
    // Any quadratic non-residue z: z^((p−1)/2) ≡ −1 (mod p).
    let mut z = BigUint::from(2u32);
    while z.modpow(&half, p) != p - &one {
        z += &one;
    }
    let mut m = s;
    let mut c = z.modpow(&q_odd, p);
    let mut t = a.modpow(&q_odd, p);
    let mut r = a.modpow(&((&q_odd + &one) >> 1usize), p);
    while t != one {
        // Least i < m with t^(2^i) ≡ 1.
        let mut i = 0u32;
        let mut t2 = t.clone();
        while t2 != one {
            t2 = (&t2 * &t2) % p;
            i += 1;
            if i >= m {
                return None; // unreachable for a prime modulus
            }
        }
        let mut b = c.clone();
        for _ in 0..(m - i - 1) {
            b = (&b * &b) % p;
        }
        m = i;
        c = (&b * &b) % p;
        t = (&t * &c) % p;
        r = (&r * &b) % p;
    }
    let other = p - &r;
    Some(r.min(other))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn big(n: u64) -> BigUint {
        BigUint::from(n)
    }

    #[test]
    fn sqrt_mod_prime_matches_bruteforce() {
        // p = 13 (≡ 1 mod 4, exercises Tonelli–Shanks): every a in 0..p is
        // classified and rooted, cross-checked against a brute-force search.
        let p = big(13);
        for a in 0u64..13 {
            let a = big(a);
            let brute_root = (0u64..13).map(big).find(|r| (r * r) % &p == a);
            let root = sqrt_mod_prime(&a, &p);
            assert_eq!(root, brute_root, "sqrt of {a} mod 13");
            if let Some(r) = root {
                assert_eq!((&r * &r) % &p, a);
                // canonical: r ≤ p − r
                assert!(r <= &p - &r);
            }
        }
    }

    #[test]
    fn sqrt_mod_prime_shortcut_and_non_residue() {
        // p = 7 (≡ 3 mod 4, shortcut path): residues {1, 2, 4}, 3 is a
        // non-residue.
        let p = big(7);
        assert_eq!(sqrt_mod_prime(&big(4), &p), Some(big(2)));
        assert_eq!(sqrt_mod_prime(&big(2), &p), Some(big(3))); // min(3, 4)
        assert_eq!(sqrt_mod_prime(&big(3), &p), None);
        assert_eq!(sqrt_mod_prime(&big(0), &p), Some(big(0)));
    }

    #[test]
    fn sqrt_mod_prime_consistent_with_euler_criterion() {
        // 998244353 = 119·2^23 + 1 is a well-known prime ≡ 1 (mod 4), so the
        // Tonelli–Shanks path runs. Cross-check the root against Euler's
        // criterion computed independently: a is a residue iff
        // a^((p−1)/2) ≡ 1, and every reported root must square to a.
        let p = BigUint::parse_bytes(b"998244353", 10).unwrap();
        assert!(math::is_probable_prime(&p));
        assert_eq!((&p & big(3)), big(1));
        let half = (&p - big(1)) >> 1usize;
        for x in 1u64..64 {
            let a = (&big(x) * big(x)) % &p; // guaranteed residue
            assert_eq!(a.modpow(&half, &p), big(1), "Euler: {x}² must be a residue");
            let r = sqrt_mod_prime(&a, &p).expect("residue must have a root");
            assert_eq!((&r * &r) % &p, a);
            assert!(r <= &p - &r);
        }
        // Non-residues: verify sqrt_mod_prime agrees with the criterion.
        let mut non_residues = 0;
        for a in 2u64..256 {
            let a = big(a);
            let is_residue = a.modpow(&half, &p) == big(1);
            let root = sqrt_mod_prime(&a, &p);
            assert_eq!(root.is_some(), is_residue, "Euler disagreement at a={a}");
            if !is_residue {
                non_residues += 1;
            }
            if non_residues >= 20 {
                break;
            }
        }
        assert!(non_residues >= 10, "expected a healthy mix of non-residues");
    }
}
