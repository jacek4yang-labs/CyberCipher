//! RSA attack primitives and the analyzer/solver.
//!
//! Every attack: validates preconditions, runs under explicit bounds,
//! returns a typed [`AttackOutcome`] with diagnostics. Attacks enrich the
//! working parameter set as they succeed (factors → d → plaintext).
//!
//! Status semantics:
//! - [`AttackStatus::NotApplicable`] — structural preconditions unmet
//!   (missing/inconsistent inputs); nothing ran.
//! - [`AttackStatus::Applicable`] — the attack ran and made verifiable
//!   progress (e.g. factored n) but could not produce a verified plaintext.
//! - [`AttackStatus::Success`] — the attack produced a plaintext that
//!   re-encrypts to the given ciphertext (round-trip verified).
//! - [`AttackStatus::Failed`] — preconditions were met but the attack did
//!   not achieve its goal within its resource bounds.

use crate::math;
use crate::rsa::params::RsaParams;
use num_bigint::{BigInt, BigUint};
use num_traits::{CheckedSub, One, Signed, Zero};
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
    pub(crate) fn new(
        id: &'static str,
        name: &'static str,
        status: AttackStatus,
        cost: AttackCost,
        message: String,
    ) -> Self {
        AttackOutcome {
            id,
            name,
            status,
            cost,
            message,
            details: None,
            plaintext: None,
        }
    }

    pub(crate) fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }

    pub(crate) fn not_applicable(id: &'static str, name: &'static str, missing: &str) -> Self {
        AttackOutcome::new(
            id,
            name,
            AttackStatus::NotApplicable,
            AttackCost::Instant,
            format!("not applicable: requires {missing}"),
        )
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

fn success_plaintext(
    id: &'static str,
    name: &'static str,
    cost: AttackCost,
    message: String,
    m: BigUint,
) -> AttackOutcome {
    let mut o = AttackOutcome::new(id, name, AttackStatus::Success, cost, message);
    o.plaintext = Some(PlaintextResult::from_m(&m));
    o
}

// ----------------------------------------------------------- helpers ----

/// Non-trivial modulus guard: rejects the degenerate inputs 0, 1 and small
/// constants that no RSA analysis applies to.
fn modulus_usable(n: &BigUint) -> bool {
    *n > BigUint::from(3u32)
}

/// Extract one u64 word from e, or None when e is zero or multi-word.
fn small_exponent(e: &BigUint) -> Option<u64> {
    match e.iter_u64_digits().collect::<Vec<_>>()[..] {
        [v] if v > 0 => Some(v),
        _ => None,
    }
}

/// Install a candidate factorization (p, q) into `params`, enrich the key,
/// and return a Success outcome with the round-trip-verified plaintext when
/// c is available. Restores `params` and returns None when the
/// factorization is inconsistent with the ciphertext (e.g. multi-prime n).
fn finish_factorization(
    params: &mut RsaParams,
    p: BigUint,
    q: BigUint,
    id: &'static str,
    name: &'static str,
    cost: AttackCost,
    how: &str,
) -> Option<AttackOutcome> {
    if p <= BigUint::one() || q <= BigUint::one() || &p * &q != *params.n.as_ref()? {
        return None;
    }
    let snapshot = params.clone();
    params.p = Some(p);
    params.q = Some(q);
    params.enrich_from_factors();
    if let Some(m) = params.decrypt() {
        if params.verify_decryption(&m) {
            return Some(success_plaintext(
                id,
                name,
                cost,
                format!("n factored via {how}; plaintext recovered"),
                m,
            ));
        }
        // p·q = n but the derived key does not reproduce c — spurious split
        // (e.g. n has more than two prime factors).
        *params = snapshot;
        return None;
    }
    // No ciphertext (or no usable e): the factorization itself stands.
    let mut o = AttackOutcome::new(
        id,
        name,
        AttackStatus::Applicable,
        cost,
        format!("n factored via {how}; provide c to decrypt"),
    );
    if params.d.is_none() && params.e.is_some() {
        o.details = Some("gcd(e, φ(n)) ≠ 1 for this split; d not derivable".to_string());
    }
    Some(o)
}

// ----------------------------------------------------------- attacks ----

/// Known p and q: complete the key and decrypt.
pub fn attack_known_pq(params: &mut RsaParams) -> AttackOutcome {
    const ID: &str = "known-pq";
    const NAME: &str = "Known p and q";
    let (Some(p), Some(q)) = (params.p.clone(), params.q.clone()) else {
        return AttackOutcome::not_applicable(ID, NAME, "p and q");
    };
    if p <= BigUint::from(2u32) || q <= BigUint::from(2u32) {
        return AttackOutcome::not_applicable(ID, NAME, "non-trivial factors p, q ≥ 3");
    }
    params.enrich_from_factors();
    if let Some(m) = params.decrypt() {
        if params.verify_decryption(&m) {
            return success_plaintext(
                ID,
                NAME,
                AttackCost::Instant,
                "factored via known p, q; plaintext recovered".to_string(),
                m,
            );
        }
        return AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Failed,
            AttackCost::Instant,
            "decryption with the key derived from p, q failed round-trip verification".to_string(),
        )
        .with_details(
            "p·q = n but (c^d)^e ≠ c — n may have more than two prime factors".to_string(),
        );
    }
    AttackOutcome::new(
        ID,
        NAME,
        AttackStatus::Applicable,
        AttackCost::Instant,
        "key material completed from p, q (d = e⁻¹ mod φ(n))".to_string(),
    )
}

/// Known private exponent d: decrypt and (bonus) recover the factors of n
/// from (e, d) via non-trivial square roots of 1 mod n.
pub fn attack_known_d(params: &mut RsaParams) -> AttackOutcome {
    const ID: &str = "known-d";
    const NAME: &str = "Known private exponent d";
    let (Some(n), Some(e), Some(d)) = (params.n.clone(), params.e.clone(), params.d.clone()) else {
        return AttackOutcome::not_applicable(ID, NAME, "n, e and d");
    };
    if !modulus_usable(&n) || e.is_zero() || d.is_zero() {
        return AttackOutcome::not_applicable(ID, NAME, "non-zero n, e and d");
    }

    // 1) Try the plaintext with round-trip verification.
    let outcome = if let Some(m) = params.decrypt_with(&d) {
        if params.verify_decryption(&m) {
            success_plaintext(
                ID,
                NAME,
                AttackCost::Instant,
                "decrypted with known d (verified)".to_string(),
                m,
            )
        } else {
            AttackOutcome::new(
                ID,
                NAME,
                AttackStatus::Failed,
                AttackCost::Instant,
                "d is inconsistent: c·d does not re-encrypt to c".to_string(),
            )
            .with_details("the provided d does not satisfy (c^d)^e ≡ c (mod n)".to_string())
        }
    } else {
        AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Applicable,
            AttackCost::Instant,
            "d available; provide c to decrypt".to_string(),
        )
    };

    // 2) Bonus: recover p, q from (e, d). Valid regardless of whether c was
    //    present; a wrong d simply will not factor n.
    if let Some((p, q)) = factor_from_ed(&n, &e, &d, 64) {
        params.p = Some(p);
        params.q = Some(q);
        params.enrich_from_factors();
        let mut outcome = outcome;
        if outcome.status == AttackStatus::Failed {
            // Wrong d for decryption, but it still split n — report progress.
            outcome.status = AttackStatus::Applicable;
            outcome.message = "d inconsistent with c, but (e, d) factored n".to_string();
        } else {
            outcome.details =
                Some("n factored from (e, d) via non-trivial square roots of 1 mod n".to_string());
        }
        return outcome;
    }
    outcome
}

/// Factor n from (e, d): e·d − 1 = k·φ(n). Find a non-trivial square root
/// of 1 modulo n by taking random bases through the 2-adic chain of e·d−1.
/// Bounded attempts; never panics on degenerate input.
fn factor_from_ed(
    n: &BigUint,
    e: &BigUint,
    d: &BigUint,
    attempts: usize,
) -> Option<(BigUint, BigUint)> {
    if !modulus_usable(n) || e.is_zero() || d.is_zero() {
        return None;
    }
    let kphi = (e * d).checked_sub(&BigUint::one())?;
    if kphi.is_zero() {
        return None; // e·d = 1: degenerate, no φ-multiple to work with
    }
    // kphi = t·2^s with t odd.
    let one = BigUint::one();
    let two = BigUint::from(2u32);
    let mut s = 0u64;
    let mut t = kphi.clone();
    while (&t & &one).is_zero() {
        t >>= 1;
        s += 1;
    }
    let mut state = 0x5EEDu64;
    for _ in 0..attempts {
        let a = math::weak_random_odd(n.bits().clamp(8, 32), &mut state) % n;
        if a <= BigUint::one() || math::gcd(&a, n) != one {
            continue;
        }
        let mut x = a.modpow(&t, n);
        if x.is_one() || x == n - &one {
            continue;
        }
        for _ in 0..s {
            let y = x.modpow(&two, n);
            if y.is_one() {
                // x is a non-trivial square root of 1 mod n.
                let p = math::gcd(&(x - &one), n);
                if p > one && p < *n {
                    let q = n / &p;
                    return Some((p.min(q.clone()), q));
                }
                break;
            }
            if y == n - &one {
                break;
            }
            x = y;
        }
    }
    None
}

/// Known φ(n): d = e⁻¹ mod φ(n).
pub fn attack_known_phi(params: &mut RsaParams) -> AttackOutcome {
    const ID: &str = "known-phi";
    const NAME: &str = "Known φ(n)";
    let (Some(e), Some(phi)) = (params.e.clone(), params.phi.clone()) else {
        return AttackOutcome::not_applicable(ID, NAME, "e and φ(n)");
    };
    if e.is_zero() || phi <= BigUint::one() {
        return AttackOutcome::not_applicable(ID, NAME, "a non-trivial φ(n) and non-zero e");
    }
    let Some(d) = math::modinv(&e, &phi) else {
        return AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Failed,
            AttackCost::Instant,
            "e is not invertible modulo φ(n) — parameters are inconsistent".to_string(),
        )
        .with_details(format!("gcd(e, φ(n)) = {} ≠ 1", math::gcd(&e, &phi)));
    };
    params.d = Some(d);
    if let Some(m) = params.decrypt() {
        if params.verify_decryption(&m) {
            return success_plaintext(
                ID,
                NAME,
                AttackCost::Instant,
                "d = e⁻¹ mod φ(n); plaintext recovered".to_string(),
                m,
            );
        }
        return AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Failed,
            AttackCost::Instant,
            "d derived from φ(n) failed round-trip verification".to_string(),
        )
        .with_details("the provided φ(n) is inconsistent with (n, e, c)".to_string());
    }
    AttackOutcome::new(
        ID,
        NAME,
        AttackStatus::Applicable,
        AttackCost::Instant,
        "d recovered from φ(n); provide c to decrypt".to_string(),
    )
}

/// dp leak: dp ≡ d (mod p−1) ⇒ e·dp ≡ 1 (mod p−1) ⇒ p−1 divides e·dp − 1,
/// hence a^(e·dp−1) ≡ 1 (mod p) for every a coprime to p and
/// p = gcd(a^(e·dp−1) − 1, n). If the plain gcds all collapse to n, fall
/// back to the arithmetic form: e·dp − 1 = k·(p−1) with 0 < k < e, so each
/// divisor k < e yields the candidate p = (e·dp−1)/k + 1.
pub fn attack_dp_leak(params: &mut RsaParams, deadline: Instant) -> AttackOutcome {
    const ID: &str = "dp-leak";
    const NAME: &str = "dp leak (CRT exponent of p)";
    let (Some(n), Some(e), Some(dp)) = (params.n.clone(), params.e.clone(), params.dp.clone())
    else {
        return AttackOutcome::not_applicable(ID, NAME, "n, e and dp");
    };
    if !modulus_usable(&n) {
        return AttackOutcome::not_applicable(ID, NAME, "a non-trivial modulus n");
    }
    if e.is_zero() {
        return AttackOutcome::not_applicable(ID, NAME, "a non-zero public exponent e");
    }
    if dp.is_zero() {
        return AttackOutcome::not_applicable(
            ID,
            NAME,
            "a non-zero dp (dp ≡ 0 mod p−1 gives no usable identity)",
        );
    }
    let Some(target) = (&e * &dp).checked_sub(&BigUint::one()) else {
        return AttackOutcome::not_applicable(ID, NAME, "e·dp ≥ 1");
    };
    if target.is_zero() {
        return AttackOutcome::not_applicable(ID, NAME, "e·dp > 1");
    }

    let accepted = |params: &RsaParams, p: &BigUint| -> bool {
        // The recovered factor must be consistent with the leak:
        // d mod (p−1) must reproduce dp exactly.
        match (&params.d, params.e.as_ref()) {
            (Some(d), Some(_)) => d % &(p - BigUint::one()) == dp,
            _ => true,
        }
    };

    // Method 1: direct identity, a handful of bases. Each base costs one
    // modpow; for the true p the gcd is non-trivial with overwhelming
    // probability, so this is O(1) modpows, not an enumeration.
    let bases = [2u32, 3, 5, 7, 11, 13];
    for a in bases {
        let candidate = BigUint::from(a).modpow(&target, &n);
        let minus_one = if candidate.is_zero() {
            n.clone() - BigUint::one()
        } else {
            &candidate - BigUint::one()
        };
        let g = math::gcd(&minus_one, &n);
        if g > BigUint::one() && g < n {
            let snapshot = params.clone();
            params.p = Some(g.clone());
            params.q = Some(&n / &g);
            params.enrich_from_factors();
            if accepted(params, &g) {
                if let Some(mut o) = finish_factorization(
                    params,
                    g.clone(),
                    &n / &g,
                    ID,
                    NAME,
                    AttackCost::Fast,
                    "dp leak",
                ) {
                    o.details = Some(format!("p = gcd({a}^(e·dp−1) − 1, n)"));
                    return o;
                }
            }
            *params = snapshot;
        }
    }

    // Method 2: arithmetic divisor sweep, e·dp − 1 = k·(p−1) with k < e.
    let Some(e_u64) = small_exponent(&e) else {
        return AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Failed,
            AttackCost::Fast,
            "the k-divisor sweep needs a moderate e (< 2³²)".to_string(),
        )
        .with_details("the direct gcd identity above already ran and found nothing".to_string());
    };
    if e_u64 > 1 << 24 {
        return AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Failed,
            AttackCost::Fast,
            format!("e = {e_u64} is too large for the k-divisor sweep (needs e < 2²⁴)"),
        )
        .with_details("the direct gcd identity above already ran and found nothing".to_string());
    }
    let mut checked = 0u64;
    for k in 1..e_u64 {
        checked += 1;
        if checked.is_multiple_of(1024) && Instant::now() >= deadline {
            return AttackOutcome::new(
                ID,
                NAME,
                AttackStatus::Failed,
                AttackCost::Fast,
                format!("time budget exhausted in the k-sweep (reached k={k} of {e_u64})"),
            );
        }
        if &target % k != BigUint::zero() {
            continue;
        }
        let p = &target / k + BigUint::one();
        if p <= BigUint::one() || p >= n || &n % &p != BigUint::zero() {
            continue;
        }
        let q = &n / &p;
        let snapshot = params.clone();
        params.p = Some(p.clone());
        params.q = Some(q.clone());
        params.enrich_from_factors();
        if accepted(params, &p) {
            if let Some(mut o) =
                finish_factorization(params, p, q, ID, NAME, AttackCost::Fast, "dp leak")
            {
                o.details = Some(format!("p = (e·dp−1)/k + 1 at k={k}"));
                return o;
            }
        }
        *params = snapshot;
    }
    AttackOutcome::new(
        ID,
        NAME,
        AttackStatus::Failed,
        AttackCost::Fast,
        format!("no factor recovered from dp within k < {e_u64}"),
    )
    .with_details(
        "the leak may correspond to dq rather than dp, or the parameters are inconsistent"
            .to_string(),
    )
}

/// dp+dq joint leak (capability id `rsa-dpdq-recover`; pipeline id
/// `dpdq-recover`, the sibling of `dp-leak`): both CRT exponents are known.
/// e·dp ≡ 1 (mod p−1) and e·dq ≡ 1 (mod q−1), so X = e·dp − 1 is a multiple
/// of p−1 and Y = e·dq − 1 a multiple of q−1.
///
/// Method 1 (any e): for small bases a, a^X ≡ 1 (mod p) and a^Y ≡ 1 (mod q)
/// (Fermat), so gcd(a^X − 1, n) yields p and gcd(a^Y − 1, n) yields q with
/// overwhelming probability — the dq identity is tried when the dp one
/// collapses to n.
///
/// Method 2 (small e): X = k·(p−1) with 0 < k < e, so every divisor k of X
/// below e gives the candidate p = X/k + 1; the dq leak cross-checks the
/// split (Y must vanish mod q−1) before it is accepted.
///
/// Every candidate factorization must satisfy the joint identity — the
/// derived d must reduce to dp mod (p−1) AND to dq mod (q−1) — which is what
/// separates a genuine split from a spurious one.
pub fn attack_dpdq_recover(params: &mut RsaParams) -> AttackOutcome {
    const ID: &str = "dpdq-recover";
    const NAME: &str = "dp+dq joint leak (CRT)";

    let (Some(n), Some(e), Some(dp), Some(dq)) = (
        params.n.clone(),
        params.e.clone(),
        params.dp.clone(),
        params.dq.clone(),
    ) else {
        return AttackOutcome::not_applicable(ID, NAME, "n, e, dp and dq");
    };
    if !modulus_usable(&n) {
        return AttackOutcome::not_applicable(ID, NAME, "a non-trivial modulus n");
    }
    if e.is_zero() {
        return AttackOutcome::not_applicable(ID, NAME, "a non-zero public exponent e");
    }
    if dp.is_zero() || dq.is_zero() {
        return AttackOutcome::not_applicable(
            ID,
            NAME,
            "non-zero dp and dq (a zero CRT exponent gives no usable identity)",
        );
    }
    let Some(x) = (&e * &dp).checked_sub(&BigUint::one()) else {
        return AttackOutcome::not_applicable(ID, NAME, "e·dp ≥ 1");
    };
    let Some(y) = (&e * &dq).checked_sub(&BigUint::one()) else {
        return AttackOutcome::not_applicable(ID, NAME, "e·dq ≥ 1");
    };
    if x.is_zero() || y.is_zero() {
        return AttackOutcome::not_applicable(ID, NAME, "e·dp > 1 and e·dq > 1");
    }

    // Acceptance: the identity that PRODUCED the factor must verify
    // algebraically — e·d? ≡ 1 (mod g−1) is exactly "leak vanishes mod g−1".
    // The other leak is a cross-check: when it also vanishes mod (n/g − 1)
    // the split is *jointly* verified; when it does not (a mislabeled or
    // corrupt second leak) the split still stands on the driving identity,
    // with finish_factorization's round-trip check guarding false positives.
    let leak_consistent = |leak: &BigUint, prime: &BigUint| -> bool {
        let pm1 = prime - BigUint::one();
        !pm1.is_zero() && leak % &pm1 == BigUint::zero()
    };

    let try_split = |params: &mut RsaParams,
                     driving: &BigUint,
                     other: &BigUint,
                     which: &str,
                     g: BigUint,
                     how: &str|
     -> Option<AttackOutcome> {
        if g <= BigUint::one() || g >= n || &n % &g != BigUint::zero() {
            return None;
        }
        if !leak_consistent(driving, &g) {
            return None;
        }
        let q = &n / &g;
        let joint = leak_consistent(other, &q);
        let snapshot = params.clone();
        params.p = Some(g.clone());
        params.q = Some(q.clone());
        params.enrich_from_factors();
        if let Some(mut o) = finish_factorization(
            params,
            g,
            q,
            ID,
            NAME,
            AttackCost::Instant,
            &format!("dp+dq joint leak ({how})"),
        ) {
            let joint_note = if joint {
                "both CRT-exponent identities hold (jointly verified)"
            } else {
                "the second leak is inconsistent with this split and was ignored"
            };
            o.details = Some(format!(
                "verified via the {which} identity ({joint_note}) [{how}]"
            ));
            return Some(o);
        }
        *params = snapshot;
        None
    };

    // Method 1: Fermat-base gcds on both CRT exponents.
    let bases = [2u32, 3, 5, 7, 11, 13];
    for a in bases {
        for (leak, other, which) in [(&x, &y, "dp"), (&y, &x, "dq")] {
            let candidate = BigUint::from(a).modpow(leak, &n);
            let minus_one = if candidate.is_zero() {
                n.clone() - BigUint::one()
            } else {
                &candidate - BigUint::one()
            };
            let g = math::gcd(&minus_one, &n);
            if g > BigUint::one() && g < n {
                let how = format!("gcd({a}^(e·d{which}−1) − 1, n)");
                if let Some(o) = try_split(params, leak, other, which, g, &how) {
                    return o;
                }
            }
        }
    }

    // Method 2: k-divisor sweep on X (needs a moderate e). The dq leak
    // cross-checks every candidate split.
    let Some(e_u64) = small_exponent(&e) else {
        return AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Failed,
            AttackCost::Instant,
            "no factor recovered from the dp/dq identities (large e)".to_string(),
        )
        .with_details(
            "the Fermat-base gcds found nothing; without a moderate e the k-sweep is unavailable"
                .to_string(),
        );
    };
    if e_u64 > 1 << 24 {
        return AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Failed,
            AttackCost::Instant,
            format!("e = {e_u64} is too large for the k-divisor sweep (needs e < 2²⁴)"),
        )
        .with_details("the Fermat-base gcds above already ran and found nothing".to_string());
    }
    for k in 1..e_u64 {
        if &x % k != BigUint::zero() {
            continue;
        }
        let p = &x / k + BigUint::one();
        if p <= BigUint::one() || p >= n || &n % &p != BigUint::zero() {
            continue;
        }
        // Joint cross-check: q = n/p must also satisfy Y ≡ 0 (mod q−1).
        let q = &n / &p;
        let qm1 = if q > BigUint::one() {
            q.clone() - BigUint::one()
        } else {
            continue;
        };
        if &y % &qm1 != BigUint::zero() {
            continue;
        }
        let how = format!("p = (e·dp−1)/k + 1 at k={k}");
        if let Some(o) = try_split(params, &x, &y, "dp", p, &how) {
            return o;
        }
    }

    AttackOutcome::new(
        ID,
        NAME,
        AttackStatus::Failed,
        AttackCost::Instant,
        "no factorization satisfies both CRT-exponent identities".to_string(),
    )
    .with_details(
        "dp and dq may be inconsistent with (n, e), or the leaks are swapped between the primes"
            .to_string(),
    )
}

/// Wiener's attack on small d: continued-fraction convergents k/d of e/n;
/// for each candidate check φ = (e·d − 1)/k and solve
/// x² − (n − φ + 1)x + n = 0 (roots are the primes).
pub fn attack_wiener(params: &mut RsaParams) -> AttackOutcome {
    const ID: &str = "wiener";
    const NAME: &str = "Wiener (small d)";
    let (Some(n), Some(e)) = (params.n.clone(), params.e.clone()) else {
        return AttackOutcome::not_applicable(ID, NAME, "n and e");
    };
    if !modulus_usable(&n) || e.is_zero() {
        return AttackOutcome::not_applicable(ID, NAME, "a non-trivial n and non-zero e");
    }

    // Continued fraction expansion of e/n. Convergent i has numerator h_i
    // and denominator k_i; Wiener's theorem says k (the φ-multiplier)
    // appears as a NUMERATOR and d as the DENOMINATOR.
    let one = BigUint::one();
    let four = BigUint::from(4u32);
    let (mut num, mut den) = (e.clone(), n.clone());
    let (mut h0, mut h1) = (BigUint::zero(), BigUint::one()); // numerators
    let (mut k0, mut k1) = (BigUint::one(), BigUint::zero()); // denominators
    let mut steps = 0usize;
    while !den.is_zero() {
        let a = &num / &den;
        let r = &num % &den;
        num = std::mem::replace(&mut den, r);
        let h = &a * &h1 + &h0;
        let k = &a * &k1 + &k0;
        h0 = std::mem::replace(&mut h1, h);
        k0 = std::mem::replace(&mut k1, k);
        steps += 1;
        if steps > 10_000 {
            break; // bound: CF of e/n has O(bits) terms anyway
        }
        // Convergent = h1 / k1; candidate (k, d) = (h1, k1).
        if h1.is_zero() || k1.is_zero() {
            continue;
        }
        let Some(edm1) = (&e * &k1).checked_sub(&one) else {
            continue; // e·d = 1
        };
        if &edm1 % &h1 != BigUint::zero() {
            continue;
        }
        let phi = &edm1 / &h1;
        if phi.is_zero() {
            continue;
        }
        // x² − (n − φ + 1)x + n = 0; discriminant must be a perfect square.
        let Some(b) = (&n + &one).checked_sub(&phi) else {
            continue; // φ > n + 1: impossible for RSA
        };
        let Some(disc) = (&b * &b).checked_sub(&(&four * &n)) else {
            continue; // negative discriminant (b² < 4n)
        };
        let Some(root) = math::isqrt_exact(&disc) else {
            continue;
        };
        if root > b {
            continue;
        }
        let p = (&b + &root) >> 1usize;
        let q = (&b - &root) >> 1usize;
        if p > one && q > one && &p * &q == n {
            let (lo, hi) = if p <= q { (p, q) } else { (q, p) };
            if let Some(o) = finish_factorization(
                params,
                lo,
                hi,
                ID,
                NAME,
                AttackCost::Instant,
                "Wiener's attack (small d)",
            ) {
                return o;
            }
        }
    }
    AttackOutcome::new(
        ID,
        NAME,
        AttackStatus::Failed,
        AttackCost::Instant,
        "no convergent produced a valid factorization (d is probably not small)".to_string(),
    )
}

/// Fermat factorization: write n = a² − b² with a = ⌈√n⌉ + i for small i;
/// then p = a − b, q = a + b. Works when |p − q| is small.
pub fn attack_fermat(params: &mut RsaParams, deadline: Instant) -> AttackOutcome {
    const ID: &str = "fermat";
    const NAME: &str = "Fermat (close primes)";
    let Some(n) = params.n.clone() else {
        return AttackOutcome::not_applicable(ID, NAME, "n");
    };
    if !modulus_usable(&n) {
        return AttackOutcome::not_applicable(ID, NAME, "a non-trivial modulus n");
    }
    if (&n & BigUint::one()).is_zero() {
        // Even n factors trivially; Fermat's iteration would wander.
        if let Some(o) = finish_factorization(
            params,
            BigUint::from(2u32),
            &n >> 1usize,
            ID,
            NAME,
            AttackCost::Instant,
            "trial split (n even)",
        ) {
            return o;
        }
        return AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Failed,
            AttackCost::Instant,
            "n is even but the split did not verify".to_string(),
        );
    }
    let one = BigUint::one();
    // Perfect square: n = r² with r > 1 is a valid (p = q = r) factorization
    // that the a ≥ √n + 1 iteration would step over.
    if let Some(r) = math::isqrt_exact(&n) {
        if r > one {
            if let Some(o) = finish_factorization(
                params,
                r.clone(),
                r,
                ID,
                NAME,
                AttackCost::Instant,
                "perfect square (p = q)",
            ) {
                return o;
            }
            return AttackOutcome::new(
                ID,
                NAME,
                AttackStatus::Failed,
                AttackCost::Instant,
                "n is a perfect square but the split did not verify".to_string(),
            );
        }
    }
    let mut a = math::iroot(&n, 2) + &one;
    let max_iter = 1u64 << 20;
    for i in 0..max_iter {
        if i % 256 == 0 && Instant::now() >= deadline {
            return AttackOutcome::new(
                ID,
                NAME,
                AttackStatus::Failed,
                AttackCost::Fast,
                format!("time budget exhausted after {i} Fermat steps"),
            );
        }
        if let Some(b2) = (&a * &a).checked_sub(&n) {
            if let Some(b) = math::isqrt_exact(&b2) {
                let p = &a - &b;
                let q = &a + &b;
                if p > one && &p * &q == n {
                    if let Some(mut o) = finish_factorization(
                        params,
                        p,
                        q,
                        ID,
                        NAME,
                        AttackCost::Instant,
                        "Fermat factorization (close primes)",
                    ) {
                        o.message = format!(
                            "primes are close: factored after {i} steps; {}",
                            if o.plaintext.is_some() {
                                "plaintext recovered".to_string()
                            } else {
                                "provide c to decrypt".to_string()
                            }
                        );
                        return o;
                    }
                }
            }
        }
        a += &one;
    }
    AttackOutcome::new(
        ID,
        NAME,
        AttackStatus::Failed,
        AttackCost::Fast,
        "primes are not close enough within the step bound".to_string(),
    )
}

/// Small-e / small-message: m = e-th root of c + k·n for some small k ≥ 0.
pub fn attack_low_e(params: &mut RsaParams, deadline: Instant) -> AttackOutcome {
    const ID: &str = "low-e";
    const NAME: &str = "Low public exponent (small message)";
    let (Some(n), Some(e), Some(c)) = (params.n.clone(), params.e.clone(), params.c.clone()) else {
        return AttackOutcome::not_applicable(ID, NAME, "n, e and c");
    };
    if !modulus_usable(&n) {
        return AttackOutcome::not_applicable(ID, NAME, "a non-trivial modulus n");
    }
    let Some(e_u64) = small_exponent(&e).filter(|v| (2..=257).contains(v)) else {
        return AttackOutcome::not_applicable(ID, NAME, "a small public exponent (2 ≤ e ≤ 257)");
    };
    let exp = e_u64 as u32;
    let max_k = 4096u64;
    for k in 0..=max_k {
        if k % 64 == 0 && Instant::now() >= deadline {
            return AttackOutcome::new(
                ID,
                NAME,
                AttackStatus::Failed,
                AttackCost::Fast,
                format!("time budget exhausted while testing k (reached k={k})"),
            );
        }
        let v = &c + k * &n;
        let m = math::iroot(&v, exp);
        if pow_exact(&m, exp) == v {
            let mut o = success_plaintext(
                ID,
                NAME,
                AttackCost::Fast,
                format!("message recovered as exact {e_u64}-th root at k={k}"),
                m,
            );
            o.details = Some("round-trip verified: m^e = c + k·n exactly".to_string());
            return o;
        }
    }
    AttackOutcome::new(
        ID,
        NAME,
        AttackStatus::Failed,
        AttackCost::Fast,
        "no exact e-th root found in the k range (message is likely padded or larger)".to_string(),
    )
}

fn pow_exact(m: &BigUint, e: u32) -> BigUint {
    let mut result = BigUint::one();
    let mut base = m.clone();
    let mut exp = e;
    while exp > 0 {
        if exp & 1 == 1 {
            result *= &base;
        }
        base = &base * &base;
        exp >>= 1;
    }
    result
}

/// Common modulus: one n, two coprime exponents e1, e2 with ciphertexts
/// c1, c2 of the same m. With s1·e1 + s2·e2 = 1 (extended gcd),
/// m = c1^s1 · c2^s2 mod n; negative coefficients use modular inverses.
pub fn attack_common_modulus(params: &mut RsaParams) -> AttackOutcome {
    const ID: &str = "common-modulus";
    const NAME: &str = "Common modulus";
    let (Some(n), Some(e1), Some(c1)) = (params.n.clone(), params.e.clone(), params.c.clone())
    else {
        return AttackOutcome::not_applicable(ID, NAME, "n, e and c (first set)");
    };
    if !modulus_usable(&n) {
        return AttackOutcome::not_applicable(ID, NAME, "a non-trivial modulus n");
    }
    let second = params
        .sets
        .iter()
        .position(|s| s.n.as_ref() == Some(&n) && (s.e.is_some() || s.c.is_some()));
    let Some(idx) = second else {
        return AttackOutcome::not_applicable(
            ID,
            NAME,
            "a second (n, e, c) set sharing the SAME modulus n",
        );
    };
    let (Some(e2), Some(c2)) = (params.sets[idx].e.clone(), params.sets[idx].c.clone()) else {
        return AttackOutcome::not_applicable(ID, NAME, "e and c in the second set");
    };
    if e1.is_zero() || e2.is_zero() {
        return AttackOutcome::not_applicable(ID, NAME, "non-zero exponents");
    }
    if e1 == e2 {
        return AttackOutcome::not_applicable(ID, NAME, "distinct exponents e1 ≠ e2");
    }

    let (g, s1, s2) = math::extended_gcd(&BigInt::from(e1.clone()), &BigInt::from(e2.clone()));
    if g.abs() != BigInt::one() {
        return AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Failed,
            AttackCost::Instant,
            "exponents are not coprime".to_string(),
        )
        .with_details(format!("gcd(e1, e2) = {g}"));
    }

    // m = c1^s1 · c2^s2 (mod n). A missing inverse means the ciphertext
    // shares a factor with n — which factors n outright.
    let pair = (pow_signed(&c1, &s1, &n), pow_signed(&c2, &s2, &n));
    let m = match pair {
        (Some(m1), Some(m2)) => (m1 * m2) % &n,
        _ => {
            let leak = math::gcd(&c1, &n);
            let leak = if leak > BigUint::one() && leak < n {
                leak
            } else {
                math::gcd(&c2, &n)
            };
            if leak > BigUint::one() && leak < n {
                if let Some(o) = finish_factorization(
                    params,
                    leak.clone(),
                    &n / &leak,
                    ID,
                    NAME,
                    AttackCost::Instant,
                    "common-modulus ciphertext sharing a factor with n",
                ) {
                    return o;
                }
            }
            return AttackOutcome::new(
                ID,
                NAME,
                AttackStatus::Failed,
                AttackCost::Instant,
                "ciphertext is not invertible mod n and the leaked factor did not verify"
                    .to_string(),
            );
        }
    };

    // Round-trip verification: m^e1 must reproduce c1 (holds exactly when
    // s1·e1 + s2·e2 = 1 and the ciphertexts encrypt the same m).
    if m.modpow(&e1, &n) != c1 {
        return AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Failed,
            AttackCost::Instant,
            "recovered message failed verification (m^e1 ≠ c1)".to_string(),
        )
        .with_details("the two ciphertexts may encrypt different messages".to_string());
    }
    success_plaintext(
        ID,
        NAME,
        AttackCost::Instant,
        "plaintext recovered via extended gcd on the two exponents".to_string(),
        m,
    )
}

/// Signed-exponent modular power: base^s mod n with negative s via inverse.
/// None when the inverse does not exist (base shares a factor with n).
fn pow_signed(base: &BigUint, s: &BigInt, n: &BigUint) -> Option<BigUint> {
    if s.is_zero() {
        return Some(BigUint::one());
    }
    if s.is_negative() {
        let inv = math::modinv(base, n)?;
        let mag = s.abs().to_biguint()?;
        Some(inv.modpow(&mag, n))
    } else {
        let mag = s.to_biguint()?;
        Some(base.modpow(&mag, n))
    }
}

/// Håstad broadcast: the same m encrypted (no padding) under ≥ e distinct
/// coprime moduli with exponent e. CRT the ciphertexts, take the exact
/// e-th root.
pub fn attack_hastad(params: &mut RsaParams) -> AttackOutcome {
    const ID: &str = "hastad";
    const NAME: &str = "Håstad broadcast";
    let Some(e) = params.e.clone() else {
        return AttackOutcome::not_applicable(ID, NAME, "e");
    };
    let Some(e_u64) = small_exponent(&e) else {
        return AttackOutcome::not_applicable(ID, NAME, "a small non-zero exponent e");
    };
    let mut remainders: Vec<BigUint> = Vec::new();
    let mut moduli: Vec<BigUint> = Vec::new();
    let push =
        |r: &BigUint, m: &BigUint, remainders: &mut Vec<BigUint>, moduli: &mut Vec<BigUint>| {
            if moduli.len() >= 64 || moduli.contains(m) {
                return; // bound the CRT product; skip duplicate moduli
            }
            remainders.push(r.clone());
            moduli.push(m.clone());
        };
    if let (Some(n), Some(c)) = (&params.n, &params.c) {
        push(c, n, &mut remainders, &mut moduli);
    }
    for set in &params.sets {
        if let (Some(n), Some(c)) = (&set.n, &set.c) {
            push(c, n, &mut remainders, &mut moduli);
        }
    }
    if remainders.len() < e_u64 as usize {
        return AttackOutcome::not_applicable(
            ID,
            NAME,
            &format!(
                "at least e={e_u64} distinct (n, c) sets — have {}",
                remainders.len()
            ),
        );
    }
    let Some((x, _)) = math::crt(&remainders, &moduli) else {
        return AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Failed,
            AttackCost::Instant,
            "CRT failed — moduli must be pairwise coprime".to_string(),
        );
    };
    let m = math::iroot(&x, e_u64 as u32);
    if pow_exact(&m, e_u64 as u32) == x {
        return success_plaintext(
            ID,
            NAME,
            AttackCost::Instant,
            "plaintext recovered via CRT + exact e-th root".to_string(),
            m,
        );
    }
    AttackOutcome::new(
        ID,
        NAME,
        AttackStatus::Failed,
        AttackCost::Instant,
        "CRT result is not a perfect e-th power (padded messages need Coppersmith)".to_string(),
    )
}

/// Shared prime between any two provided moduli (n, sets[].n, ns[]):
/// pairwise gcd; enrich the primary key when n is involved.
pub fn attack_shared_prime(params: &mut RsaParams) -> AttackOutcome {
    const ID: &str = "shared-prime";
    const NAME: &str = "Shared prime (batch gcd)";
    const MAX_MODULI: usize = 512;
    let mut ns: Vec<(String, BigUint)> = Vec::new();
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
    ns.truncate(MAX_MODULI);
    if ns.len() < 2 {
        return AttackOutcome::not_applicable(ID, NAME, "at least two moduli (n plus sets/ns)");
    }
    let one = BigUint::one();
    for i in 0..ns.len() {
        for j in (i + 1)..ns.len() {
            let g = math::gcd(&ns[i].1, &ns[j].1);
            if g > one && g != ns[i].1 && g != ns[j].1 {
                let mut o = AttackOutcome::new(
                    ID,
                    NAME,
                    AttackStatus::Success,
                    AttackCost::Instant,
                    format!("{} and {} share the prime factor {}", ns[i].0, ns[j].0, g),
                );
                // If the primary n is one of the pair, complete the key.
                let primary = [i, j].into_iter().find(|&idx| ns[idx].0 == "n");
                if let Some(idx) = primary {
                    let base = &ns[idx].1;
                    let (p, q) = {
                        let gmin = std::cmp::min(&g, &(base / &g)).clone();
                        let gmax = std::cmp::max(&g, &(base / &g)).clone();
                        (gmin, gmax)
                    };
                    params.p = Some(p.clone());
                    params.q = Some(q.clone());
                    params.enrich_from_factors();
                    if let Some(m) = params.decrypt() {
                        if params.verify_decryption(&m) {
                            o.plaintext = Some(PlaintextResult::from_m(&m));
                            o.message
                                .push_str("; plaintext recovered for the primary n");
                        }
                    }
                }
                return o;
            }
        }
    }
    AttackOutcome::new(
        ID,
        NAME,
        AttackStatus::Failed,
        AttackCost::Instant,
        "no shared prime found among the provided moduli".to_string(),
    )
}

/// Pollard rho escalation for small moduli (≤ 96 bits).
pub fn attack_pollard_rho(params: &mut RsaParams, deadline: Instant) -> AttackOutcome {
    const ID: &str = "pollard-rho";
    const NAME: &str = "Pollard rho factorization";
    let Some(n) = params.n.clone() else {
        return AttackOutcome::not_applicable(ID, NAME, "n");
    };
    if !modulus_usable(&n) {
        return AttackOutcome::not_applicable(ID, NAME, "a non-trivial modulus n");
    }
    if n.bits() > 96 {
        return AttackOutcome::not_applicable(
            ID,
            NAME,
            "a small modulus (≤ 96 bits) — use an external factorer for larger n",
        );
    }
    if math::is_probable_prime(&n) {
        return AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Failed,
            AttackCost::Fast,
            "n appears to be prime — nothing to factor".to_string(),
        );
    }
    let Some(f) = math::pollard_rho_bounded(&n, 20_000_000, Some(deadline)) else {
        return AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Failed,
            AttackCost::Slow,
            "no factor found within the step/time bound".to_string(),
        );
    };
    let q = &n / &f;
    let fbits = f.bits();
    let (lo, hi) = if f <= q { (f, q) } else { (q, f) };
    finish_factorization(
        params,
        lo,
        hi,
        ID,
        NAME,
        AttackCost::Slow,
        &format!("Pollard rho (factor has {fbits} bits)"),
    )
    .unwrap_or_else(|| {
        AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Failed,
            AttackCost::Slow,
            "factor found but it did not reproduce the ciphertext".to_string(),
        )
    })
}

/// Pollard p−1 escalation for moduli with a B-smooth p−1 (B = 200 000).
pub fn attack_pollard_pm1(params: &mut RsaParams, deadline: Instant) -> AttackOutcome {
    const ID: &str = "pollard-pm1";
    const NAME: &str = "Pollard p−1 factorization";
    let Some(n) = params.n.clone() else {
        return AttackOutcome::not_applicable(ID, NAME, "n");
    };
    if !modulus_usable(&n) {
        return AttackOutcome::not_applicable(ID, NAME, "a non-trivial modulus n");
    }
    if n.bits() > 256 {
        return AttackOutcome::not_applicable(ID, NAME, "a modulus ≤ 256 bits");
    }
    if math::is_probable_prime(&n) {
        return AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Failed,
            AttackCost::Fast,
            "n appears to be prime — nothing to factor".to_string(),
        );
    }
    let Some(f) = math::pollard_pm1_bounded(&n, 200_000, Some(deadline)) else {
        return AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Failed,
            AttackCost::Slow,
            "no B-smooth factor found (B = 200000)".to_string(),
        );
    };
    let q = &n / &f;
    let (lo, hi) = if f <= q { (f, q) } else { (q, f) };
    finish_factorization(
        params,
        lo,
        hi,
        ID,
        NAME,
        AttackCost::Slow,
        "Pollard p−1 (smooth p−1)",
    )
    .unwrap_or_else(|| {
        AttackOutcome::new(
            ID,
            NAME,
            AttackStatus::Failed,
            AttackCost::Slow,
            "factor found but it did not reproduce the ciphertext".to_string(),
        )
    })
}

/// Coppersmith escalation for stereotyped messages: with a known plaintext
/// prefix (`hint`) and a small exponent, the unknown suffix is a small root
/// of f(x) = (prefix·256^L + x)^e − c (mod N) for each candidate suffix
/// length L. Verified candidates decrypt to the full message.
fn attack_coppersmith_hint(params: &mut RsaParams, deadline: Instant) -> AttackOutcome {
    const ID: &str = "coppersmith-hint";
    const NAME: &str = "Coppersmith (known plaintext prefix)";
    let (Some(n), Some(e), Some(c)) = (params.n.clone(), params.e.clone(), params.c.clone()) else {
        return AttackOutcome::not_applicable(ID, NAME, "n, e and c");
    };
    let Some(hint) = params.hint.clone().filter(|h| !h.is_empty()) else {
        return AttackOutcome::not_applicable(
            ID,
            NAME,
            "a known plaintext prefix in the `hint` field",
        );
    };
    if hint.len() > 32 {
        return AttackOutcome::not_applicable(ID, NAME, "a hint of at most 32 bytes");
    }
    let e_u64 = match e.iter_u64_digits().collect::<Vec<_>>()[..] {
        [v] if (2..=257).contains(&v) => v,
        _ => return AttackOutcome::not_applicable(ID, NAME, "a small public exponent (2..=257)"),
    };

    use crate::lattice::coppersmith::{small_roots, CoppersmithBeta, CoppersmithParams};
    use crate::lattice::poly::Poly;
    use num_bigint::BigInt;
    use num_traits::One;

    let beta = CoppersmithBeta::MOD_N;

    // Suffix length L: unknown bytes after the prefix. e grows the degree,
    // so keep L small enough for the dimension cap.
    for suffix_len in 1usize..=8 {
        if Instant::now() >= deadline {
            break;
        }
        let shift = BigUint::from(256u32).pow(suffix_len as u32);
        // f(x) = (prefix·256^L + x)^e - c
        let base_coeffs = {
            let mut v = vec![BigInt::zero(); e_u64 as usize + 1];
            let mut coef = BigInt::one();
            // binomial expansion of (A + x)^e: coefficient of x^k = C(e,k)·A^(e-k)
            for k in 0..=e_u64 {
                let comb = binomial(e_u64, k);
                v[k as usize] = coef.clone() * BigInt::from(comb);
                coef *= BigInt::from(shift.clone());
            }
            v[e_u64 as usize] -= BigInt::from(c.clone());
            v
        };
        let f = Poly::from_coeffs(base_coeffs);
        let x_bound = BigUint::one() << (8 * suffix_len as u32);

        for m in 1usize..=6 {
            if Instant::now() >= deadline {
                break;
            }
            let Ok(cparams) = CoppersmithParams::new(m, 0) else {
                continue;
            };
            let Ok(result) = small_roots(&f, &n, &x_bound, &cparams, &beta) else {
                continue;
            };
            for root in &result.roots {
                // Reconstruct the full message: prefix || suffix (root bytes).
                let root_uint = if root.is_negative() {
                    continue; // suffix bytes are non-negative
                } else {
                    match root.to_biguint() {
                        Some(v) if v < x_bound => v,
                        _ => continue,
                    }
                };
                let suffix = root_uint.to_bytes_be();
                let mut msg_bytes = hint.as_bytes().to_vec();
                if suffix.len() < suffix_len {
                    msg_bytes.extend(std::iter::repeat_n(0u8, suffix_len - suffix.len()));
                }
                msg_bytes.extend_from_slice(&suffix);
                let m_full = BigUint::from_bytes_be(&msg_bytes);
                if m_full.modpow(&e, &n) == c {
                    params.d = None;
                    let mut o = AttackOutcome {
                        id: ID,
                        name: NAME,
                        status: AttackStatus::Success,
                        cost: AttackCost::Fast,
                        message: String::new(),
                        details: None,
                        plaintext: Some(PlaintextResult::from_m(&m_full)),
                    };
                    o.id = ID;
                    o.name = NAME;
                    o.message = format!(
                        "stereotyped message recovered: suffix length {suffix_len}, lattice dim {}",
                        result.lattice_dim
                    );
                    return o;
                }
            }
        }
    }
    AttackOutcome {
        id: ID,
        name: NAME,
        status: AttackStatus::Failed,
        cost: AttackCost::Fast,
        message: "no suffix length produced a verified message within the lattice caps".to_string(),
        details: Some(
            "the unknown tail must be short relative to N^(1/e); padded randomness beyond that needs larger parameters".to_string(),
        ),
        plaintext: None,
    }
}

fn binomial(n: u64, k: u64) -> BigUint {
    let mut result = BigUint::one();
    for i in 0..k {
        result = result * BigUint::from(n - i) / BigUint::from(i + 1);
    }
    result
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
    ("rabin", |p, _| crate::rsa::rabin::attack_rabin(p)),
    ("dp-leak", attack_dp_leak),
    ("dpdq-recover", |p, _| attack_dpdq_recover(p)),
    ("common-modulus", |p, _| attack_common_modulus(p)),
    ("hastad", |p, _| attack_hastad(p)),
    ("shared-prime", |p, _| attack_shared_prime(p)),
    ("low-e", attack_low_e),
    ("coppersmith-hint", attack_coppersmith_hint),
    ("wiener", |p, _| attack_wiener(p)),
    ("fermat", attack_fermat),
    ("pollard-rho", attack_pollard_rho),
    ("pollard-pm1", attack_pollard_pm1),
];

/// Factorization escalations that are redundant once p and q are known.
const FACTORIZATION_ATTACKS: &[&str] = &[
    "dp-leak",
    "dpdq-recover",
    "wiener",
    "fermat",
    "pollard-rho",
    "pollard-pm1",
];

/// Verified plaintext from the current parameter set: decrypt with d and
/// confirm re-encryption reproduces c (when e, n, c are all known).
fn verified_plaintext(params: &RsaParams) -> Option<PlaintextResult> {
    let m = params.decrypt()?;
    if !params.verify_decryption(&m) {
        return None;
    }
    Some(PlaintextResult::from_m(&m))
}

/// Analyze known parameters; when `solve` is true, run attacks in order
/// until the plaintext is recovered or the pipeline is exhausted. The
/// deadline is shared by all bounded attacks.
pub fn analyze(params: &RsaParams, solve: bool, deadline_ms: u64) -> AnalyzerReport {
    let deadline = Instant::now() + Duration::from_millis(deadline_ms);
    let mut work = params.clone();
    let mut findings = Vec::new();
    let mut plaintext = verified_plaintext(&work);

    for (id, attack) in PIPELINE {
        // Skip factorization escalations once the modulus is already factored.
        if FACTORIZATION_ATTACKS.contains(id) && work.p.is_some() && work.q.is_some() {
            continue;
        }
        let outcome = attack(&mut work, deadline);
        if outcome.plaintext.is_some() {
            plaintext = outcome.plaintext.clone();
        } else if let Some(pt) = verified_plaintext(&work) {
            // The attack enriched d/φ without embedding the plaintext in its
            // outcome (e.g. known-phi); pick it up here.
            plaintext = Some(pt);
        }
        findings.push(outcome);
        if solve && plaintext.is_some() {
            break;
        }
    }

    AnalyzerReport {
        findings,
        params: work.to_json(),
        plaintext,
    }
}
