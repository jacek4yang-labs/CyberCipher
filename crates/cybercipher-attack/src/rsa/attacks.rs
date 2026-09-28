//! RSA attack primitives and the analyzer/solver.
//!
//! Every attack: validates preconditions, runs under explicit bounds,
//! returns a typed [`AttackOutcome`] with diagnostics. Attacks enrich the
//! working parameter set as they succeed (factors → d → plaintext).

use crate::math;
use crate::rsa::params::RsaParams;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackStatus {
    /// Preconditions met; the attack ran.
    Applicable,
    /// Preconditions not met (reported with what is missing).
    NotApplicable,
    /// Preconditions met and the goal was achieved.
    Success,
    /// Preconditions met but the attack failed within its bounds.
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackCost {
    Instant,
    Fast,
    Slow,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttackOutcome {
    pub id: &'static str,
    pub name: &'static str,
    pub status: AttackStatus,
    pub cost: AttackCost,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Recovered plaintext when the attack achieves the goal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext: Option<PlaintextResult>,
}

impl AttackOutcome {
    fn not_applicable(id: &'static str, name: &'static str, missing: &str) -> Self {
        AttackOutcome {
            id,
            name,
            status: AttackStatus::NotApplicable,
            cost: AttackCost::Instant,
            message: format!("not applicable: requires {missing}"),
            details: None,
            plaintext: None,
        }
    }
}

/// Recovered plaintext with human-readable interpretations.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PlaintextResult {
    pub m_hex: String,
    pub m_decimal: String,
    pub bytes_be: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utf8: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flag_like: Option<String>,
}

impl PlaintextResult {
    pub fn from_m(m: &BigUint) -> Self {
        let bytes = m.to_bytes_be();
        let utf8 = std::str::from_utf8(&bytes)
            .ok()
            .filter(|s| s.chars().all(|c| !c.is_control()))
            .map(|s| s.to_string());
        let flag_like = utf8.as_deref().and_then(flag_pattern);
        PlaintextResult {
            m_hex: format!("{m:x}"),
            m_decimal: m.to_string(),
            bytes_be: bytes.iter().map(|b| format!("{b:02x}")).collect(),
            utf8,
            flag_like,
        }
    }
}

fn flag_pattern(text: &str) -> Option<String> {
    for pat in ["flag{", "FLAG{", "ctf{", "CTF{", "picoCTF{", "HTB{"] {
        if let Some(idx) = text.find(pat) {
            let rest = &text[idx..];
            if let Some(end) = rest.find('}') {
                if end <= 128 {
                    return Some(rest[..=end].to_string());
                }
            }
        }
    }
    None
}

fn decrypt_result(m: BigUint) -> AttackOutcome {
    let m = PlaintextResult::from_m(&m);
    AttackOutcome {
        id: "",
        name: "",
        status: AttackStatus::Success,
        cost: AttackCost::Instant,
        message: "plaintext recovered".to_string(),
        details: None,
        plaintext: Some(m),
    }
}

// ----------------------------------------------------------- attacks ----

fn attack_known_pq(params: &mut RsaParams) -> AttackOutcome {
    const ID: &str = "known-pq";
    const NAME: &str = "Known p and q";
    if params.p.is_none() || params.q.is_none() {
        return AttackOutcome::not_applicable(ID, NAME, "p and q");
    }
    params.enrich_from_factors();
    if let Some(m) = params.decrypt() {
        let mut out = decrypt_result(m);
        out.id = ID;
        out.name = NAME;
        out.message = "factored via known p, q; plaintext recovered".to_string();
        return out;
    }
    AttackOutcome {
        id: ID,
        name: NAME,
        status: AttackStatus::Applicable,
        cost: AttackCost::Instant,
        message: "key material completed from p, q (d = e⁻¹ mod φ(n))".to_string(),
        details: None,
        plaintext: None,
    }
}

fn attack_known_d(params: &mut RsaParams) -> AttackOutcome {
    const ID: &str = "known-d";
    const NAME: &str = "Known private exponent d";
    let (Some(n), Some(e), Some(d)) = (params.n.clone(), params.e.clone(), params.d.clone())
    else {
        return AttackOutcome::not_applicable(ID, NAME, "n, e and d");
    };
    let mut outcome = if let Some(m) = params.decrypt() {
        let mut o = decrypt_result(m);
        o.id = ID;
        o.name = NAME;
        o.message = "decrypted with known d".to_string();
        o
    } else {
        AttackOutcome {
            id: ID,
            name: NAME,
            status: AttackStatus::Applicable,
            cost: AttackCost::Instant,
            message: "d available; provide c to decrypt".to_string(),
            details: None,
            plaintext: None,
        }
    };
    // Try to factor n from (e, d) — useful when p/q are also wanted.
    if let Some((p, q)) = factor_from_ed(&n, &e, &d, 64) {
        params.p = Some(p);
        params.q = Some(q);
        params.enrich_from_factors();
        outcome.details = Some("n factored from (e, d) via the square-root-of-1 method".to_string());
    }
    outcome
}

/// Factor n from (e, d): e*d - 1 = k*φ(n). Find a non-trivial square root of
/// 1 modulo n. Bounded attempts.
fn factor_from_ed(n: &BigUint, e: &BigUint, d: &BigUint, attempts: usize) -> Option<(BigUint, BigUint)> {
    let kphi = (e * d) - BigUint::one();
    let two = BigUint::from(2u32);
    let mut s = 0u64;
    let mut t = kphi.clone();
    while (&t & BigUint::one()) == BigUint::zero() {
        t >>= 1;
        s += 1;
    }
    let mut state = 0x5EEDu64;
    for _ in 0..attempts {
        let a = math::weak_random_odd(n.bits().min(32).max(8), &mut state) % n;
        if a.is_zero() || math::gcd(&a, n) != BigUint::one() {
            continue;
        }
        let mut x = a.modpow(&t, n);
        if x.is_one() || x == n - BigUint::one() {
            continue;
        }
        for _ in 0..s {
            let y = x.modpow(&two, n);
            if y.is_one() {
                let p = math::gcd(&(x - BigUint::one()), n);
                if p != BigUint::one() && p != *n {
                    let q = n / &p;
                    return Some((p.clone().min(q.clone()), p.max(q)));
                }
                break;
            }
            if y == n - BigUint::one() {
                break;
            }
            x = y;
        }
    }
    None
}

fn attack_known_phi(params: &mut RsaParams) -> AttackOutcome {
    const ID: &str = "known-phi";
    const NAME: &str = "Known φ(n)";
    let (Some(e), Some(phi)) = (params.e.clone(), params.phi.clone()) else {
        return AttackOutcome::not_applicable(ID, NAME, "e and φ(n)");
    };
    let Some(d) = math::modinv(&e, &phi) else {
        return AttackOutcome {
            id: ID,
            name: NAME,
            status: AttackStatus::Failed,
            cost: AttackCost::Instant,
            message: "e is not invertible modulo φ(n) — parameters are inconsistent".to_string(),
            details: Some("gcd(e, φ(n)) != 1".to_string()),
            plaintext: None,
        };
    };
    params.d = Some(d);
    if let Some(m) = params.decrypt() {
        let mut o = decrypt_result(m);
        o.id = ID;
        o.name = NAME;
        o.message = "d = e⁻¹ mod φ(n); plaintext recovered".to_string();
        return o;
    }
    AttackOutcome {
        id: ID,
        name: NAME,
        status: AttackStatus::Applicable,
        cost: AttackCost::Instant,
        message: "d recovered from φ(n); provide c to decrypt".to_string(),
        details: None,
        plaintext: None,
    }
}

/// dp leak: p ≡ gcd(a^(k·e·dp − 1) − 1, n) for some small k.
fn attack_dp_leak(params: &mut RsaParams, deadline: Instant) -> AttackOutcome {
    const ID: &str = "dp-leak";
    const NAME: &str = "dp leak (CRT exponent of p)";
    let (Some(n), Some(e), Some(dp)) = (params.n.clone(), params.e.clone(), params.dp.clone())
    else {
        return AttackOutcome::not_applicable(ID, NAME, "n, e and dp");
    };
    if e > BigUint::from(1u64 << 24) {
        return AttackOutcome {
            id: ID,
            name: NAME,
            status: AttackStatus::Failed,
            cost: AttackCost::Fast,
            message: "e is too large for the k-enumeration attack".to_string(),
            details: Some("this attack needs a moderate public exponent (e < 2²⁴)".to_string()),
            plaintext: None,
        };
    }
    let e_u64 = e.iter_u64_digits().next().unwrap_or(0);
    let one = BigUint::one();
    let bases = [BigUint::from(2u32), BigUint::from(3u32), BigUint::from(5u32), BigUint::from(7u32)];
    for k in 1..=e_u64.saturating_sub(1).max(1) {
        if Instant::now() >= deadline {
            return AttackOutcome {
                id: ID,
                name: NAME,
                status: AttackStatus::Failed,
                cost: AttackCost::Fast,
                message: format!("time budget exhausted while enumerating k (reached k={k})"),
                details: None,
                plaintext: None,
            };
        }
        let target = &e * BigUint::from(k) * &dp - &one;
        if target.is_zero() {
            continue;
        }
        for a in &bases {
            let candidate = a.modpow(&target, &n);
            let minus_one = if candidate.is_zero() {
                n.clone() - &one
            } else {
                &candidate - &one
            };
            let g = math::gcd(&minus_one, &n);
            if g != one && g != n {
                let (p, q) = if &g * &g == n {
                    (g.clone(), g.clone())
                } else {
                    let q = &n / &g;
                    (g.clone(), q)
                };
                // Sanity: p (or q) should satisfy dp = d mod (p-1).
                params.p = Some(p);
                params.q = Some(q);
                if params.enrich_from_factors() {
                    if let Some(m) = params.decrypt() {
                        let mut o = decrypt_result(m);
                        o.id = ID;
                        o.name = NAME;
                        o.message = format!("factored n via dp leak at k={k}; plaintext recovered");
                        return o;
                    }
                }
                params.p = None;
                params.q = None;
                params.d = None;
            }
        }
    }
    AttackOutcome {
        id: ID,
        name: NAME,
        status: AttackStatus::Failed,
        cost: AttackCost::Fast,
        message: "no factor found from dp within the enumeration bound".to_string(),
        details: Some("the leak may correspond to a different exponent or the parameters may be inconsistent".to_string()),
        plaintext: None,
    }
}

/// Wiener's attack on small d via continued-fraction convergents of e/n.
fn attack_wiener(params: &mut RsaParams) -> AttackOutcome {
    const ID: &str = "wiener";
    const NAME: &str = "Wiener (small d)";
    let (Some(n), Some(e)) = (params.n.clone(), params.e.clone()) else {
        return AttackOutcome::not_applicable(ID, NAME, "n and e");
    };
    // Continued fraction of e/n.
    let mut num = e.clone();
    let mut den = n.clone();
    let mut convergents: Vec<(BigUint, BigUint)> = Vec::new(); // (k, d)
    let mut h0 = BigUint::zero();
    let mut h1 = BigUint::one();
    let mut k0 = BigUint::one();
    let mut k1 = BigUint::zero();
    while !den.is_zero() {
        let q = &num / &den;
        let r = &num % &den;
        num = den;
        den = r;
        let h = &q * &h1 + &h0;
        let k = &q * &k1 + &k0;
        h0 = h1;
        h1 = h.clone();
        k0 = k1;
        k1 = k.clone();
        convergents.push((k, h));
        if convergents.len() > 10_000 {
            break;
        }
    }
    for (k, d) in convergents {
        if k.is_zero() {
            continue;
        }
        // φ = (e*d - 1) / k must be an integer; then x² - (n - φ + 1)x + n = 0.
        let numerator = &e * &d - BigUint::one();
        if (&numerator % &k) != BigUint::zero() {
            continue;
        }
        let phi = &numerator / &k;
        let b = &n - &phi + BigUint::one();
        // x² - b x + n = 0 → discriminant b² - 4n must be a perfect square.
        let disc = &b * &b - BigUint::from(4u32) * &n;
        let Some(root) = math::isqrt_exact(&disc) else {
            continue;
        };
        let p = (&b + &root) / BigUint::from(2u32);
        let q = (&b - &root) / BigUint::from(2u32);
        if &p * &q == n && !p.is_zero() && !q.is_zero() {
            params.p = Some(p);
            params.q = Some(q);
            params.enrich_from_factors();
            if let Some(m) = params.decrypt() {
                let mut o = decrypt_result(m);
                o.id = ID;
                o.name = NAME;
                o.message = "Wiener convergent recovered d; n factored; plaintext recovered".to_string();
                return o;
            }
            return AttackOutcome {
                id: ID,
                name: NAME,
                status: AttackStatus::Applicable,
                cost: AttackCost::Instant,
                message: "Wiener recovered d and factored n; provide c to decrypt".to_string(),
                details: None,
                plaintext: None,
            };
        }
    }
    AttackOutcome {
        id: ID,
        name: NAME,
        status: AttackStatus::Failed,
        cost: AttackCost::Instant,
        message: "no convergent produced a valid factorization (d is probably not small)".to_string(),
        details: None,
        plaintext: None,
    }
}

/// Fermat factorization for close primes.
fn attack_fermat(params: &mut RsaParams, deadline: Instant) -> AttackOutcome {
    const ID: &str = "fermat";
    const NAME: &str = "Fermat (close primes)";
    let Some(n) = params.n.clone() else {
        return AttackOutcome::not_applicable(ID, NAME, "n");
    };
    let one = BigUint::one();
    let mut a = math::iroot(&n, 2) + &one;
    let max_iter = 1u64 << 20;
    for i in 0..max_iter {
        if i % 256 == 0 && Instant::now() >= deadline {
            return AttackOutcome {
                id: ID,
                name: NAME,
                status: AttackStatus::Failed,
                cost: AttackCost::Fast,
                message: format!("time budget exhausted after {i} steps"),
                details: None,
                plaintext: None,
            };
        }
        let b2 = &a * &a - &n;
        if let Some(b) = math::isqrt_exact(&b2) {
            let p = &a - &b;
            let q = &a + &b;
            if !p.is_one() && !p.is_zero() && &p * &q == n {
                params.p = Some(p);
                params.q = Some(q);
                params.enrich_from_factors();
                if let Some(m) = params.decrypt() {
                    let mut o = decrypt_result(m);
                    o.id = ID;
                    o.name = NAME;
                    o.message = format!("primes are close: factored after {i} steps; plaintext recovered");
                    return o;
                }
                return AttackOutcome {
                    id: ID,
                    name: NAME,
                    status: AttackStatus::Applicable,
                    cost: AttackCost::Instant,
                    message: format!("factored n after {i} Fermat steps; provide c to decrypt"),
                    details: None,
                    plaintext: None,
                };
            }
        }
        a += &one;
    }
    AttackOutcome {
        id: ID,
        name: NAME,
        status: AttackStatus::Failed,
        cost: AttackCost::Fast,
        message: "primes are not close enough within the step bound".to_string(),
        details: None,
        plaintext: None,
    }
}

/// Small-e / small-message: m = e-th root of c + k·n.
fn attack_low_e(params: &mut RsaParams, deadline: Instant) -> AttackOutcome {
    const ID: &str = "low-e";
    const NAME: &str = "Low public exponent (small message)";
    let (Some(n), Some(e), Some(c)) = (params.n.clone(), params.e.clone(), params.c.clone())
    else {
        return AttackOutcome::not_applicable(ID, NAME, "n, e and c");
    };
    let e_u64 = match e.iter_u64_digits().collect::<Vec<_>>()[..] {
        [v] if v <= 257 => v,
        _ => {
            return AttackOutcome::not_applicable(ID, NAME, "a small public exponent (e ≤ 257)")
        }
    };
    let max_k = 4096u64;
    for k in 0..=max_k {
        if k % 64 == 0 && Instant::now() >= deadline {
            return AttackOutcome {
                id: ID,
                name: NAME,
                status: AttackStatus::Failed,
                cost: AttackCost::Fast,
                message: format!("time budget exhausted while testing k (reached k={k})"),
                details: None,
                plaintext: None,
            };
        }
        let v = &c + BigUint::from(e_u64) * &n;
        let m = math::iroot(&v, e_u64 as u32);
        if pow_exact(&m, e_u64) == v {
            let mut o = decrypt_result(m);
            o.id = ID;
            o.name = NAME;
            o.message = format!("message recovered as exact {e_u64}-th root at k={k}");
            return o;
        }
    }
    AttackOutcome {
        id: ID,
        name: NAME,
        status: AttackStatus::Failed,
        cost: AttackCost::Fast,
        message: "no exact e-th root found in the k range (message is likely padded or larger)".to_string(),
        details: None,
        plaintext: None,
    }
}

fn pow_exact(m: &BigUint, e: u64) -> BigUint {
    m.pow(e as u32)
}

/// Common modulus: same n, coprime e1/e2, two ciphertexts.
fn attack_common_modulus(params: &mut RsaParams) -> AttackOutcome {
    const ID: &str = "common-modulus";
    const NAME: &str = "Common modulus";
    let set = params.sets.iter().find(|s| s.n.is_some() && s.e.is_some() && s.c.is_some());
    let (Some(n), Some(e1), Some(c1)) = (params.n.clone(), params.e.clone(), params.c.clone())
    else {
        return AttackOutcome::not_applicable(ID, NAME, "n, e, c (first set)");
    };
    let Some(set) = set else {
        return AttackOutcome::not_applicable(
            ID,
            NAME,
            "a second (n, e, c) set in the `sets` array",
        );
    };
    if set.n.as_ref() != Some(&n) {
        return AttackOutcome::not_applicable(ID, NAME, "both sets to share the same modulus n");
    }
    let e2 = set.e.clone().unwrap();
    let c2 = set.c.clone().unwrap();
    if e1 == e2 {
        return AttackOutcome::not_applicable(ID, NAME, "distinct exponents e1 ≠ e2");
    }
    let (g, s1, s2) = math::extended_gcd(
        &num_bigint::BigInt::from(e1.clone()),
        &num_bigint::BigInt::from(e2.clone()),
    );
    if g.abs() != num_bigint::BigInt::one() {
        return AttackOutcome {
            id: ID,
            name: NAME,
            status: AttackStatus::Failed,
            cost: AttackCost::Instant,
            message: "exponents are not coprime".to_string(),
            details: Some(format!("gcd(e1, e2) = {g}")),
            plaintext: None,
        };
    }
    use num_traits::Signed;
    let m1 = if s1.is_negative() {
        math::modinv(&c1, &n)
            .expect("ciphertext checked invertible above")
            .modpow(&s1.abs().to_biguint().unwrap(), &n)
    } else {
        c1.modpow(&s1.to_biguint().unwrap(), &n)
    };
    let m2 = if s2.is_negative() {
        math::modinv(&c2, &n)
            .expect("ciphertext checked invertible above")
            .modpow(&s2.abs().to_biguint().unwrap(), &n)
    } else {
        c2.modpow(&s2.to_biguint().unwrap(), &n)
    };
    let m = (m1 * m2) % &n;
    let mut o = decrypt_result(m);
    o.id = ID;
    o.name = NAME;
    o.message = "plaintext recovered via extended gcd on the two exponents".to_string();
    o
}

/// Håstad broadcast: ≥ e ciphertexts of the same message under distinct moduli.
fn attack_hastad(params: &mut RsaParams) -> AttackOutcome {
    const ID: &str = "hastad";
    const NAME: &str = "Håstad broadcast";
    let e = match &params.e {
        Some(e) => e.clone(),
        None => return AttackOutcome::not_applicable(ID, NAME, "e"),
    };
    let e_u64 = match e.iter_u64_digits().collect::<Vec<_>>()[..] {
        [v] => v,
        _ => return AttackOutcome::not_applicable(ID, NAME, "a small exponent e"),
    };
    let mut remainders = Vec::new();
    let mut moduli = Vec::new();
    if let (Some(n), Some(c)) = (&params.n, &params.c) {
        remainders.push(c.clone());
        moduli.push(n.clone());
    }
    for set in &params.sets {
        if let (Some(n), Some(c)) = (&set.n, &set.c) {
            remainders.push(c.clone());
            moduli.push(n.clone());
        }
    }
    if remainders.len() < e_u64 as usize {
        return AttackOutcome::not_applicable(
            ID,
            NAME,
            &format!("at least e={e_u64} (n, c) sets — have {}", remainders.len()),
        );
    }
    let Some((x, _)) = math::crt(&remainders, &moduli) else {
        return AttackOutcome {
            id: ID,
            name: NAME,
            status: AttackStatus::Failed,
            cost: AttackCost::Instant,
            message: "CRT failed — moduli must be pairwise coprime".to_string(),
            details: None,
            plaintext: None,
        };
    };
    let m = math::iroot(&x, e_u64 as u32);
    if pow_exact(&m, e_u64) == x {
        let mut o = decrypt_result(m);
        o.id = ID;
        o.name = NAME;
        o.message = "plaintext recovered via CRT + e-th root".to_string();
        return o;
    }
    AttackOutcome {
        id: ID,
        name: NAME,
        status: AttackStatus::Failed,
        cost: AttackCost::Instant,
        message: "CRT result is not a perfect e-th power (padded messages need Coppersmith)".to_string(),
        details: None,
        plaintext: None,
    }
}

/// Shared prime between two moduli.
fn attack_shared_prime(params: &mut RsaParams) -> AttackOutcome {
    const ID: &str = "shared-prime";
    const NAME: &str = "Shared prime (batch gcd)";
    let mut ns = Vec::new();
    if let Some(n) = &params.n {
        ns.push(("n".to_string(), n.clone()));
    }
    for (i, set) in params.sets.iter().enumerate() {
        if let Some(n) = &set.n {
            ns.push((format!("sets[{i}].n"), n.clone()));
        }
    }
    for (i, n) in params.ns.iter().enumerate() {
        ns.push((format!("ns[{i}]"), n.clone()));
    }
    if ns.len() < 2 {
        return AttackOutcome::not_applicable(ID, NAME, "at least two moduli (n plus sets/ns)");
    }
    for i in 0..ns.len() {
        for j in (i + 1)..ns.len() {
            let g = math::gcd(&ns[i].1, &ns[j].1);
            if g != BigUint::one() && g != ns[i].1 && g != ns[j].1 {
                if ns[i].0 == "n" {
                    params.p = Some(g.clone());
                    params.q = Some(&ns[i].1 / &g);
                    params.enrich_from_factors();
                }
                let mut o = AttackOutcome {
                    id: ID,
                    name: NAME,
                    status: AttackStatus::Success,
                    cost: AttackCost::Instant,
                    message: format!(
                        "{} and {} share the prime {}",
                        ns[i].0, ns[j].0, g
                    ),
                    details: None,
                    plaintext: None,
                };
                if let Some(m) = params.decrypt() {
                    o.plaintext = Some(PlaintextResult::from_m(&m));
                    o.message += "; plaintext recovered for the primary n";
                }
                return o;
            }
        }
    }
    AttackOutcome {
        id: ID,
        name: NAME,
        status: AttackStatus::Failed,
        cost: AttackCost::Instant,
        message: "no shared prime found among the provided moduli".to_string(),
        details: None,
        plaintext: None,
    }
}

/// Pollard rho escalation for small moduli.
fn attack_pollard_rho(params: &mut RsaParams, deadline: Instant) -> AttackOutcome {
    const ID: &str = "pollard-rho";
    const NAME: &str = "Pollard rho factorization";
    let Some(n) = params.n.clone() else {
        return AttackOutcome::not_applicable(ID, NAME, "n");
    };
    if n.bits() > 96 {
        return AttackOutcome::not_applicable(
            ID,
            NAME,
            "a small modulus (≤ 96 bits) — use an external factorer for larger n",
        );
    }
    let Some(f) = math::pollard_rho(&n, 20_000_000) else {
        return AttackOutcome {
            id: ID,
            name: NAME,
            status: AttackStatus::Failed,
            cost: AttackCost::Slow,
            message: "no factor found within the step bound".to_string(),
            details: None,
            plaintext: None,
        };
    };
    let _ = deadline;
    params.p = Some(f.clone());
    params.q = Some(&n / &f);
    params.enrich_from_factors();
    if let Some(m) = params.decrypt() {
        let mut o = decrypt_result(m);
        o.id = ID;
        o.name = NAME;
        o.message = format!("n factored ({} bits); plaintext recovered", f.bits());
        return o;
    }
    AttackOutcome {
        id: ID,
        name: NAME,
        status: AttackStatus::Applicable,
        cost: AttackCost::Slow,
        message: format!("n factored ({} bits); provide c to decrypt", f.bits()),
        details: None,
        plaintext: None,
    }
}

/// Pollard p-1 escalation for B-smooth p-1.
fn attack_pollard_pm1(params: &mut RsaParams, deadline: Instant) -> AttackOutcome {
    const ID: &str = "pollard-pm1";
    const NAME: &str = "Pollard p−1 factorization";
    let Some(n) = params.n.clone() else {
        return AttackOutcome::not_applicable(ID, NAME, "n");
    };
    if n.bits() > 256 {
        return AttackOutcome::not_applicable(ID, NAME, "a modulus ≤ 256 bits");
    }
    let _ = deadline;
    let Some(f) = math::pollard_pm1(&n, 200_000) else {
        return AttackOutcome {
            id: ID,
            name: NAME,
            status: AttackStatus::Failed,
            cost: AttackCost::Slow,
            message: "no B-smooth factor found (B = 200000)".to_string(),
            details: None,
            plaintext: None,
        };
    };
    params.p = Some(f.clone());
    params.q = Some(&n / &f);
    params.enrich_from_factors();
    if let Some(m) = params.decrypt() {
        let mut o = decrypt_result(m);
        o.id = ID;
        o.name = NAME;
        o.message = "n factored via p−1; plaintext recovered".to_string();
        return o;
    }
    AttackOutcome {
        id: ID,
        name: NAME,
        status: AttackStatus::Applicable,
        cost: AttackCost::Slow,
        message: "n factored via p−1; provide c to decrypt".to_string(),
        details: None,
        plaintext: None,
    }
}

// ---------------------------------------------------------- analyzer ----

#[derive(Debug, Clone, Serialize)]
pub struct AnalyzerReport {
    pub findings: Vec<AttackOutcome>,
    /// Parameter set after all enrichments (serialized for the UI).
    pub params: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext: Option<PlaintextResult>,
}

type AttackFn = fn(&mut RsaParams, Instant) -> AttackOutcome;

/// Attack pipeline in preference order: exact-algebra attacks first, then
/// bounded search attacks, then factorization escalation last.
const PIPELINE: &[(&str, AttackFn)] = &[
    ("known-pq", |p, _| attack_known_pq(p)),
    ("known-d", |p, _| attack_known_d(p)),
    ("known-phi", |p, _| attack_known_phi(p)),
    ("dp-leak", attack_dp_leak),
    ("common-modulus", |p, _| attack_common_modulus(p)),
    ("hastad", |p, _| attack_hastad(p)),
    ("shared-prime", |p, _| attack_shared_prime(p)),
    ("low-e", attack_low_e),
    ("wiener", |p, _| attack_wiener(p)),
    ("fermat", attack_fermat),
    ("pollard-rho", attack_pollard_rho),
    ("pollard-pm1", attack_pollard_pm1),
];

/// Analyze known parameters; when `solve` is true, run attacks in order until
/// the plaintext is recovered or the pipeline is exhausted.
pub fn analyze(params: &RsaParams, solve: bool, deadline_ms: u64) -> AnalyzerReport {
    let deadline = Instant::now() + Duration::from_millis(deadline_ms);
    let mut work = params.clone();
    let mut findings = Vec::new();
    let mut plaintext: Option<PlaintextResult> = None;

    // Quick win: the parameters may already be sufficient.
    if let Some(m) = work.decrypt() {
        plaintext = Some(PlaintextResult::from_m(&m));
    }

    for (id, attack) in PIPELINE {
        let started = Instant::now();
        let mut outcome = attack(&mut work, deadline);
        if outcome.id.is_empty() {
            // Outcome produced by a helper without an id (decrypt_result).
            outcome.id = id;
        }
        findings.push(outcome);
        if solve {
            if let Some(m) = work.decrypt() {
                plaintext = Some(PlaintextResult::from_m(&m));
                break;
            }
            if let Some(outcome) = findings.last() {
                if let Some(p) = &outcome.plaintext {
                    plaintext = Some(p.clone());
                    break;
                }
            }
        }
        let _ = started;
    }

    AnalyzerReport {
        findings,
        params: work.to_json(),
        plaintext,
    }
}
