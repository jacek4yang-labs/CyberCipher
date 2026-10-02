//! ECDSA attack helpers: duplicate-`r` detection, nonce-reuse private-key
//! recovery, known-`k` recovery, and bounded small-`k` recovery for the NIST
//! curves (P-256 / P-384).
//!
//! # Crate placement
//!
//! This module lives in `cybercipher-pki` (not `cybercipher-attack`) by
//! dependency design: everything it needs is already here — the
//! `p256`/`p384`/`elliptic-curve` point/scalar code, SEC1 key parsing, the
//! digest/curve pairing rules, and the typed `PkiError` model. The
//! `cybercipher-attack` crate has big-integer math but no elliptic curves, so
//! placing the attacks there would duplicate the whole EC stack or force a
//! `pki -> attack`-cycle-risk dependency in the wrong direction. The modular
//! scalar algebra (the attack math itself) runs on `num-bigint-dig`, already
//! a dependency of this crate for the RSA half; the curve group order is
//! derived from the `p256`/`p384` crates themselves (see [`group_order`]) —
//! no curve constants are hard-coded here.
//!
//! # Input contract (hex transport, shared with the rest of the `ecc` module)
//!
//! - messages are raw bytes as hex and are hashed internally with the
//!   configured digest (`sha256` | `sha384`); a pre-computed digest may be
//!   supplied instead via [`EcdsaPreimage::Digest`] (exact digest length is
//!   enforced: 32 bytes for SHA-256, 48 for SHA-384);
//! - `r`, `s`, and `k` are big-endian integer hex (optional `0x` prefix,
//!   leading zeros allowed); every component must lie in `1..n`, where `n` is
//!   the curve group order;
//! - public keys are SEC1 hex (compressed or uncompressed), validated by
//!   [`parse_ecc_public_key`];
//! - the digest/curve pairing is enforced exactly like [`super::ecdsa`]:
//!   P-256 with SHA-256, P-384 with SHA-384.
//!
//! # Verification policy (mandatory on every recovery path)
//!
//! A recovered candidate private scalar `d` is only accepted when the public
//! key derived from it — with the same RustCrypto curve code the sign/verify
//! ops use — equals the provided public key (compressed SEC1 comparison).
//! Any mismatch is a typed error ("recovered key does not match the public
//! key"); an unverified key is never reported.
//!
//! # Bounds
//!
//! The small-`k` search is bounded by construction: candidates run over
//! `1..=max_k` (default [`SMALL_K_DEFAULT`], hard cap [`SMALL_K_HARD_CAP`])
//! and are checked against the [`ExecutionContext`] deadline and cancellation
//! flag. This module contains no unbounded loops.

use cybercipher_core::{ErrorKind, ExecutionContext};
use elliptic_curve::sec1::ToEncodedPoint as _;
use num_bigint_dig::BigUint;
use num_traits::Zero;
use serde::Serialize;
use sha2::{Digest as _, Sha256, Sha384};

use super::curve::{parse_ecc_private_key, parse_ecc_public_key, EccCurve, EccPublicKeyMaterial};
use super::ecdsa::{check_digest_pairing, EcdsaDigest};
use super::{decode_fixed_hex, decode_hex, internal, wrong_curve, wrong_length};
use crate::error::{PkiError, PkiResult};
use crate::keys::{preview, to_hex};

/// Default upper bound for the small-`k` brute force.
pub const SMALL_K_DEFAULT: u64 = 100_000;
/// Hard cap for the small-`k` brute force (rejects larger bounds instead of
/// silently clamping).
pub const SMALL_K_HARD_CAP: u64 = 10_000_000;

// ---------------------------------------------------------------------------
// Input model
// ---------------------------------------------------------------------------

/// What the signature was computed over: raw message bytes (hashed internally
/// with the paired digest) or an already-computed digest (used as-is).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcdsaPreimage {
    /// Hex-encoded raw message bytes; hashed internally.
    Message(String),
    /// Hex-encoded digest (sha256: exactly 32 bytes, sha384: exactly 48).
    Digest(String),
}

/// One ECDSA signature together with its message preimage, as consumed by the
/// attack entry points. Curve and digest are passed per call so a whole batch
/// ([`ecdsa_duplicate_r_detect`]) shares one configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaAttackSignature {
    /// What the signature was computed over.
    pub preimage: EcdsaPreimage,
    /// Signature component `r` as hex (1..n).
    pub r_hex: String,
    /// Signature component `s` as hex (1..n).
    pub s_hex: String,
}

impl EcdsaAttackSignature {
    /// Signature over raw message bytes (hex); hashed internally.
    pub fn from_message(message_hex: &str, r_hex: &str, s_hex: &str) -> Self {
        EcdsaAttackSignature {
            preimage: EcdsaPreimage::Message(message_hex.to_string()),
            r_hex: r_hex.to_string(),
            s_hex: s_hex.to_string(),
        }
    }

    /// Signature over an already-computed digest (hex).
    pub fn from_digest(digest_hex: &str, r_hex: &str, s_hex: &str) -> Self {
        EcdsaAttackSignature {
            preimage: EcdsaPreimage::Digest(digest_hex.to_string()),
            r_hex: r_hex.to_string(),
            s_hex: s_hex.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Report model
// ---------------------------------------------------------------------------

/// A recovered private key. `recovered` and `verified` are always `true` on a
/// success report — every failure path (wrong key, exhausted bounds, bad
/// input) is a typed [`PkiError`], never an unverified report.
#[derive(Debug, Clone, Serialize)]
pub struct EcdsaKeyRecoveryReport {
    /// Recovery path that produced the key: `"nonce-reuse"`, `"known-k"`, or
    /// `"small-k"`.
    pub method: &'static str,
    pub curve: EccCurve,
    pub digest: EcdsaDigest,
    /// Always `true`; failures are typed errors.
    pub recovered: bool,
    /// Always `true`: the public key derived from `private_key_hex` equals
    /// the provided public key (mandatory verification policy).
    pub verified: bool,
    /// Recovered private scalar, fixed-width big-endian hex.
    pub private_key_hex: String,
    /// Public key derived from the recovered scalar (SEC1 compressed).
    pub public_key_compressed_hex: String,
    /// Public key derived from the recovered scalar (SEC1 uncompressed).
    pub public_key_uncompressed_hex: String,
    /// The nonce, when it is known or was recovered (fixed-width hex).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_k_hex: Option<String>,
    /// Whether `x(k*G) == r` holds for the recovered nonce (evidence).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_r_matches: Option<bool>,
    /// Candidate nonces tried before the verified match (small-`k` evidence).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidates_tried: Option<u64>,
    /// Human-readable recovery evidence (formulas, digest, verification).
    pub evidence: Vec<String>,
}

/// One group of signatures sharing an exact `r` value.
#[derive(Debug, Clone, Serialize)]
pub struct EcdsaDuplicateRGroup {
    /// The shared `r`, fixed-width hex.
    pub r_hex: String,
    /// Indices (into the input list) of the signatures sharing it.
    pub indices: Vec<usize>,
}

/// One pair of signatures sharing an exact `r` value.
#[derive(Debug, Clone, Serialize)]
pub struct EcdsaDuplicateRPair {
    /// Index of the first signature (0-based).
    pub first_index: usize,
    /// Index of the second signature (0-based).
    pub second_index: usize,
    /// The shared `r`, fixed-width hex.
    pub r_hex: String,
}

/// Result of duplicate-`r` detection over a list of signatures.
#[derive(Debug, Clone, Serialize)]
pub struct EcdsaDuplicateRReport {
    pub curve: EccCurve,
    pub digest: EcdsaDigest,
    pub total_signatures: usize,
    /// True when at least two signatures share an exact `r` value.
    pub duplicates_found: bool,
    /// Groups of signatures sharing an `r` (only groups of size >= 2).
    pub groups: Vec<EcdsaDuplicateRGroup>,
    /// All pairs (i < j) of signatures sharing an `r`.
    pub pairs: Vec<EcdsaDuplicateRPair>,
    /// Per-signature digest (hex), as used by the recovery formulas.
    pub digests_hex: Vec<String>,
}

// ---------------------------------------------------------------------------
// Public attack entry points
// ---------------------------------------------------------------------------

/// Detect duplicate `r` values across a list of ECDSA signatures — the
/// fingerprint of nonce reuse. The match is exact on the parsed `r` values
/// (hex encoding differences such as case or leading zeros are normalized).
/// Every signature is fully validated (hex, range, digest/curve pairing), so
/// the same list is recovery-ready for [`ecdsa_nonce_reuse_recover`].
pub fn ecdsa_duplicate_r_detect(
    curve: EccCurve,
    digest: EcdsaDigest,
    signatures: &[EcdsaAttackSignature],
) -> PkiResult<EcdsaDuplicateRReport> {
    check_ecdsa_curve(curve)?;
    check_digest_pairing(curve, digest)?;
    if signatures.is_empty() {
        return Err(
            PkiError::invalid_input("no signatures provided for duplicate-r detection")
                .with_expected("at least one signature")
                .with_actual("an empty list"),
        );
    }
    let field_len = curve.private_key_size();
    let mut rs = Vec::with_capacity(signatures.len());
    let mut digests_hex = Vec::with_capacity(signatures.len());
    for signature in signatures {
        let resolved = resolve_signature(curve, digest, signature)?;
        digests_hex.push(resolved.digest_hex);
        rs.push(resolved.r);
    }
    // Group signatures by exact r value (linear scan; lists are small).
    let mut groups: Vec<(BigUint, Vec<usize>)> = Vec::new();
    for (index, r) in rs.iter().enumerate() {
        let existing = groups.iter_mut().find(|(value, _)| *value == *r);
        match existing {
            Some((_, indices)) => indices.push(index),
            None => groups.push((r.clone(), vec![index])),
        }
    }
    let mut duplicate_groups = Vec::new();
    let mut pairs = Vec::new();
    for (r, indices) in &groups {
        if indices.len() < 2 {
            continue;
        }
        let r_hex = scalar_to_fixed_hex(r, field_len);
        for (position, first) in indices.iter().enumerate() {
            for second in &indices[position + 1..] {
                pairs.push(EcdsaDuplicateRPair {
                    first_index: *first,
                    second_index: *second,
                    r_hex: r_hex.clone(),
                });
            }
        }
        duplicate_groups.push(EcdsaDuplicateRGroup {
            r_hex,
            indices: indices.clone(),
        });
    }
    Ok(EcdsaDuplicateRReport {
        curve,
        digest,
        total_signatures: signatures.len(),
        duplicates_found: !duplicate_groups.is_empty(),
        groups: duplicate_groups,
        pairs,
        digests_hex,
    })
}

/// Recover the ECDSA private key from two signatures that share a nonce (the
/// same `r`): `k = (h1 - h2) * (s1 - s2)^-1 mod n`, then
/// `d = (s1 * k - h1) * r^-1 mod n`.
///
/// The recovered key is verified against `public_key_hex` (mandatory);
/// identical signatures (`s1 == s2 mod n`), identical digests (`h1 == h2`),
/// and non-invertible differences are typed errors.
pub fn ecdsa_nonce_reuse_recover(
    curve: EccCurve,
    digest: EcdsaDigest,
    sig1: &EcdsaAttackSignature,
    sig2: &EcdsaAttackSignature,
    public_key_hex: &str,
) -> PkiResult<EcdsaKeyRecoveryReport> {
    let first = resolve_signature(curve, digest, sig1)?;
    let second = resolve_signature(curve, digest, sig2)?;
    let public = parse_ecc_public_key(curve, public_key_hex)?;
    if first.r != second.r {
        return Err(PkiError::invalid_input(
            "the two signatures have different r values — nonce reuse requires the same r",
        )
        .with_parameter("r")
        .with_expected("two signatures with the same r")
        .with_actual("two different r values (run ecdsa-duplicate-r-detect first)"));
    }
    let denominator = mod_sub(&first.s, &second.s, &first.n);
    if denominator.is_zero() {
        return Err(PkiError::invalid_input(
            "the two signatures have the same s (mod n): identical signatures leak no nonce information",
        )
        .with_parameter("s")
        .with_expected("two signatures with the same r but different s (mod n)"));
    }
    let numerator = mod_sub(&first.h, &second.h, &first.n);
    if numerator.is_zero() {
        return Err(PkiError::invalid_input(
            "the two message digests are identical (h1 == h2): the recovery formula would produce the invalid nonce k = 0",
        )
        .with_parameter("message")
        .with_expected("two messages with different digests"));
    }
    let inverse = mod_inverse(&denominator, &first.n).ok_or_else(|| not_invertible("s1 - s2"))?;
    let k = (&numerator * &inverse) % &first.n;
    let r_inverse = mod_inverse(&first.r, &first.n).ok_or_else(|| not_invertible("r"))?;
    let d = (mod_sub(&((&first.s * &k) % &first.n), &first.h, &first.n) * &r_inverse) % &first.n;
    let nonce_r_matches = nonce_reproduces_r(curve, &k, &first.r);
    finish_recovery(&first, d, "nonce-reuse", Some(&k), None, &public, Some(nonce_r_matches))
}

/// Recover the ECDSA private key from one signature whose nonce `k` is known:
/// `d = (s * k - h) * r^-1 mod n`. The recovered key is verified against the
/// provided public key (mandatory); a wrong `k` therefore fails with a typed
/// error instead of reporting a bogus key.
pub fn ecdsa_known_k_recover(
    curve: EccCurve,
    digest: EcdsaDigest,
    signature: &EcdsaAttackSignature,
    k_hex: &str,
    public_key_hex: &str,
) -> PkiResult<EcdsaKeyRecoveryReport> {
    let resolved = resolve_signature(curve, digest, signature)?;
    let public = parse_ecc_public_key(curve, public_key_hex)?;
    let k = parse_scalar_component("k", k_hex, &resolved.n, resolved.field_len)?;
    let r_inverse = mod_inverse(&resolved.r, &resolved.n).ok_or_else(|| not_invertible("r"))?;
    let d = (mod_sub(
        &((&resolved.s * &k) % &resolved.n),
        &resolved.h,
        &resolved.n,
    ) * &r_inverse)
        % &resolved.n;
    let nonce_r_matches = nonce_reproduces_r(curve, &k, &resolved.r);
    finish_recovery(&resolved, d, "known-k", Some(&k), None, &public, Some(nonce_r_matches))
}

/// Recover the ECDSA private key under the assumption of a small nonce:
/// brute-forces `k` over `1..=max_k` (default [`SMALL_K_DEFAULT`], hard cap
/// [`SMALL_K_HARD_CAP`]), deriving `d = (s * k - h) * r^-1 mod n` for each
/// candidate and accepting the first whose derived public key equals the
/// provided public key. Bounded by construction and deadline-aware: the
/// [`ExecutionContext`] deadline/cancellation flag is checked every 64
/// candidates. Exhausting the bound is a typed error, never a bogus report.
pub fn ecdsa_small_k_recover(
    curve: EccCurve,
    digest: EcdsaDigest,
    signature: &EcdsaAttackSignature,
    public_key_hex: &str,
    max_k: u64,
    ctx: &ExecutionContext,
) -> PkiResult<EcdsaKeyRecoveryReport> {
    if max_k == 0 || max_k > SMALL_K_HARD_CAP {
        return Err(PkiError::invalid_param(
            "max_k",
            format!("the small-k search bound must be in 1..={SMALL_K_HARD_CAP}"),
        )
        .with_expected(format!("1..={SMALL_K_HARD_CAP}"))
        .with_actual(max_k.to_string()));
    }
    // Fail fast on cancellation/past deadlines before doing any work.
    ctx.check()?;
    let resolved = resolve_signature(curve, digest, signature)?;
    let public = parse_ecc_public_key(curve, public_key_hex)?;
    let r_inverse = mod_inverse(&resolved.r, &resolved.n).ok_or_else(|| not_invertible("r"))?;
    // d_k = (s*k - h) * r^-1 mod n = a*k - b (mod n): each candidate costs one
    // modular addition plus one public-key derivation.
    let a = (&resolved.s * &r_inverse) % &resolved.n;
    let b = (&resolved.h * &r_inverse) % &resolved.n;
    let mut d = mod_sub(&a, &b, &resolved.n);
    for k in 1u64..=max_k {
        if k % 64 == 0 {
            ctx.check()?;
        }
        if derive_compressed_hex(curve, &d).as_deref()
            == Some(public.public_compressed_hex.as_str())
        {
            let k_big = BigUint::from(k);
            let nonce_r_matches = nonce_reproduces_r(curve, &k_big, &resolved.r);
            return finish_recovery(
                &resolved,
                d,
                "small-k",
                Some(&k_big),
                Some(k),
                &public,
                Some(nonce_r_matches),
            );
        }
        d = &d + &a;
        if d >= resolved.n {
            d = &d - &resolved.n;
        }
    }
    Err(PkiError::new(
        ErrorKind::BudgetExceeded,
        format!(
            "small-k candidate budget exhausted: no nonce in 1..={max_k} recovered a key matching the provided public key"
        ),
    )
    .with_expected(format!(
        "a candidate k in 1..={max_k} whose derived public key equals the provided key"
    ))
    .with_actual(format!("{max_k} candidates tried, none matched")))
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// ECDSA attacks are only defined for the NIST curves (P-256/P-384).
fn check_ecdsa_curve(curve: EccCurve) -> PkiResult<()> {
    match curve {
        EccCurve::P256 | EccCurve::P384 => Ok(()),
        other => Err(wrong_curve("p256 or p384", other.label())
            .with_details("ECDSA attacks are only defined for the NIST curves P-256 and P-384")),
    }
}

/// Curve group order `n`, derived from the curve crates themselves:
/// `SecretKey::from_bytes` accepts exactly the scalars in `[1, n-1]`, so `n`
/// is the smallest rejected value in the scalar range. Both NIST group orders
/// have their top bit set, so `[2^(bits-1), 2^bits]` brackets `n` and a
/// binary search converges in `bits` steps. No curve constants are hard-coded
/// in this module; the derivation is pinned against the FIPS 186-4 constants
/// in the unit tests.
fn group_order(curve: EccCurve) -> PkiResult<BigUint> {
    let bits = 8 * curve.private_key_size();
    let one = BigUint::from(1u32);
    let two = BigUint::from(2u32);
    let mut lo = BigUint::from(1u32) << (bits - 1);
    let mut hi = BigUint::from(1u32) << bits;
    // Invariant: lo is accepted (lo <= n-1), hi is rejected (hi >= n).
    while &lo + &one < hi {
        let mid = (&lo + &hi) / &two;
        if scalar_in_range(curve, &mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    let odd = (&hi & &one) == one;
    if !scalar_in_range(curve, &lo) || scalar_in_range(curve, &hi) || !odd {
        return Err(internal("curve group order derivation failed"));
    }
    Ok(hi)
}

/// Whether `value` is a valid scalar for `curve` per the crates' own range
/// validation (`1 <= value <= n-1`).
fn scalar_in_range(curve: EccCurve, value: &BigUint) -> bool {
    let bytes = scalar_field_bytes(value, curve.private_key_size());
    match curve {
        EccCurve::P256 => scalar_in_range_curve::<p256::NistP256>(&bytes),
        EccCurve::P384 => scalar_in_range_curve::<p384::NistP384>(&bytes),
        _ => false,
    }
}

fn scalar_in_range_curve<C>(bytes: &[u8]) -> bool
where
    C: elliptic_curve::PrimeCurve + elliptic_curve::CurveArithmetic,
{
    let field = elliptic_curve::FieldBytes::<C>::clone_from_slice(bytes);
    elliptic_curve::SecretKey::<C>::from_bytes(&field).is_ok()
}

/// A fully validated signature: parsed components plus the digest-derived
/// scalar, all reduced into `1..n` where required.
struct ResolvedSignature {
    curve: EccCurve,
    digest: EcdsaDigest,
    field_len: usize,
    n: BigUint,
    /// Digest (or supplied prehash) as raw hex, for the evidence trail.
    digest_hex: String,
    /// Digest as a scalar mod n.
    h: BigUint,
    r: BigUint,
    s: BigUint,
}

fn resolve_signature(
    curve: EccCurve,
    digest: EcdsaDigest,
    signature: &EcdsaAttackSignature,
) -> PkiResult<ResolvedSignature> {
    check_ecdsa_curve(curve)?;
    check_digest_pairing(curve, digest)?;
    let field_len = curve.private_key_size();
    let n = group_order(curve)?;
    let digest_bytes = match &signature.preimage {
        EcdsaPreimage::Message(hex) => {
            let message = decode_hex("message", hex)?;
            digest_message(digest, &message)
        }
        EcdsaPreimage::Digest(hex) => decode_fixed_hex("digest", hex, digest_len(digest))?,
    };
    let digest_hex = to_hex(&digest_bytes);
    let h = BigUint::from_bytes_be(&digest_bytes) % &n;
    let r = parse_scalar_component("r", &signature.r_hex, &n, field_len)?;
    let s = parse_scalar_component("s", &signature.s_hex, &n, field_len)?;
    Ok(ResolvedSignature {
        curve,
        digest,
        field_len,
        n,
        digest_hex,
        h,
        r,
        s,
    })
}

fn digest_len(digest: EcdsaDigest) -> usize {
    match digest {
        EcdsaDigest::Sha256 => 32,
        EcdsaDigest::Sha384 => 48,
    }
}

fn digest_message(digest: EcdsaDigest, message: &[u8]) -> Vec<u8> {
    match digest {
        EcdsaDigest::Sha256 => Sha256::digest(message).to_vec(),
        EcdsaDigest::Sha384 => Sha384::digest(message).to_vec(),
    }
}

/// Parse a hex scalar (r, s, or k): non-empty hex, at most field-size bytes,
/// and canonically in `1..n`.
fn parse_scalar_component(
    name: &str,
    hex: &str,
    n: &BigUint,
    field_len: usize,
) -> PkiResult<BigUint> {
    let bytes = decode_hex(name, hex)?;
    if bytes.len() > field_len {
        return Err(wrong_length(
            name,
            format!("at most {field_len} bytes"),
            format!("{} bytes", bytes.len()),
        ));
    }
    let value = BigUint::from_bytes_be(&bytes);
    if value.is_zero() {
        return Err(PkiError::invalid_input(format!(
            "scalar `{name}` is zero: valid ECDSA components and nonces lie in 1..n"
        ))
        .with_parameter(name)
        .with_expected("1 <= value < n")
        .with_actual("0"));
    }
    if value >= *n {
        return Err(PkiError::invalid_input(format!(
            "scalar `{name}` is not canonical: it is not below the curve group order n"
        ))
        .with_parameter(name)
        .with_expected("1 <= value < n")
        .with_actual(preview(hex, 32)));
    }
    Ok(value)
}

/// `(a - b) mod n` for `a, b` in `[0, n)` — always non-negative, so plain
/// big-integer arithmetic suffices.
fn mod_sub(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint {
    if a >= b {
        a - b
    } else {
        (a + n) - b
    }
}

/// Modular inverse via Fermat's little theorem: both NIST group orders are
/// prime, so `v^(n-2) mod n` is `v^-1` for every `v != 0`. Returns `None`
/// when `v` is zero mod n (the explicit existence check for divisions by
/// zero).
fn mod_inverse(v: &BigUint, n: &BigUint) -> Option<BigUint> {
    if v.is_zero() {
        return None;
    }
    Some(v.modpow(&(n - 2u32), n))
}

fn not_invertible(what: &str) -> PkiError {
    PkiError::invalid_input(format!("{what} is not invertible mod n (division by zero)"))
        .with_expected("a non-zero residue mod n")
}

/// Fixed-width big-endian byte encoding of a scalar (left-padded).
fn scalar_field_bytes(value: &BigUint, field_len: usize) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    let mut padded = vec![0u8; field_len.saturating_sub(bytes.len())];
    padded.extend_from_slice(&bytes);
    padded
}

fn scalar_to_fixed_hex(value: &BigUint, field_len: usize) -> String {
    to_hex(&scalar_field_bytes(value, field_len))
}

/// Derive the SEC1 compressed public key of a scalar with the same RustCrypto
/// curve code the sign/verify ops use. `None` when the scalar is not a valid
/// private key (zero or >= n).
fn derive_compressed_hex(curve: EccCurve, scalar: &BigUint) -> Option<String> {
    let bytes = scalar_field_bytes(scalar, curve.private_key_size());
    match curve {
        EccCurve::P256 => derive_compressed_hex_curve::<p256::NistP256>(&bytes),
        EccCurve::P384 => derive_compressed_hex_curve::<p384::NistP384>(&bytes),
        _ => None,
    }
}

fn derive_compressed_hex_curve<C>(bytes: &[u8]) -> Option<String>
where
    C: elliptic_curve::PrimeCurve + elliptic_curve::CurveArithmetic,
    elliptic_curve::AffinePoint<C>:
        elliptic_curve::sec1::FromEncodedPoint<C> + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    let field = elliptic_curve::FieldBytes::<C>::clone_from_slice(bytes);
    let secret = elliptic_curve::SecretKey::<C>::from_bytes(&field).ok()?;
    Some(to_hex(
        secret.public_key().to_encoded_point(true).as_bytes(),
    ))
}

/// Evidence check: does the recovered nonce reproduce the signature's `r`
/// (`x(k*G) == r`)?
fn nonce_reproduces_r(curve: EccCurve, k: &BigUint, r: &BigUint) -> bool {
    match derive_compressed_hex(curve, k) {
        Some(hex) if hex.len() > 2 => scalar_to_fixed_hex(r, curve.private_key_size()) == hex[2..],
        _ => false,
    }
}

fn formula_evidence(method: &str) -> &'static str {
    match method {
        "nonce-reuse" => "k = (h1 - h2) * (s1 - s2)^-1 mod n; d = (s1 * k - h1) * r^-1 mod n",
        _ => "d = (s * k - h) * r^-1 mod n",
    }
}

/// Shared tail of every recovery path: derive the public key from `d` and
/// accept only on an exact match with the provided public key (mandatory
/// verification), then package the key with its evidence.
fn finish_recovery(
    resolved: &ResolvedSignature,
    d: BigUint,
    method: &'static str,
    k: Option<&BigUint>,
    candidates_tried: Option<u64>,
    public: &EccPublicKeyMaterial,
    nonce_r_matches: Option<bool>,
) -> PkiResult<EcdsaKeyRecoveryReport> {
    let derived_hex = derive_compressed_hex(resolved.curve, &d);
    if derived_hex.as_deref() != Some(public.public_compressed_hex.as_str()) {
        return Err(PkiError::key("recovered key does not match the public key")
            .with_parameter("public_key")
            .with_expected("the public key derived from the recovered private key")
            .with_actual(
                "a different public point: the signature was not created with the private key matching the provided public key",
            ));
    }
    let private_hex = scalar_to_fixed_hex(&d, resolved.field_len);
    // Re-parses the (already verified) scalar into a full keypair; cannot
    // fail for a verified non-zero scalar, but stays typed regardless.
    let keypair = parse_ecc_private_key(resolved.curve, &private_hex)?;
    let mut evidence = vec![
        format!(
            "digest ({}) hex: {}",
            resolved.digest.label(),
            resolved.digest_hex
        ),
        formula_evidence(method).to_string(),
    ];
    if let Some(k) = k {
        evidence.push(format!(
            "nonce k (hex): {}",
            scalar_to_fixed_hex(k, resolved.field_len)
        ));
    }
    if let Some(tried) = candidates_tried {
        evidence.push(format!(
            "candidate nonces tried before the verified match: {tried}"
        ));
    }
    if nonce_r_matches == Some(true) {
        evidence.push("x(k*G) == r: the recovered nonce reproduces the signature's r".to_string());
    }
    evidence.push(format!(
        "verification: the public key derived from d equals the provided key ({})",
        public.public_compressed_hex
    ));
    Ok(EcdsaKeyRecoveryReport {
        method,
        curve: resolved.curve,
        digest: resolved.digest,
        recovered: true,
        verified: true,
        private_key_hex: keypair.private_hex,
        public_key_compressed_hex: keypair.public_compressed_hex,
        public_key_uncompressed_hex: keypair.public_uncompressed_hex,
        nonce_k_hex: k.map(|k| scalar_to_fixed_hex(k, resolved.field_len)),
        nonce_r_matches,
        candidates_tried,
        evidence,
    })
}

// ---------------------------------------------------------------------------
// Test support (crate-visible fixtures; no sign-with-k API exists in
// `ecdsa.rs`, which only offers RFC 6979 / random nonces)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::ecc::decode_scalar_hex;

    /// Construct a real ECDSA signature from a fixed nonce `k` using the
    /// curve arithmetic: `r = x(k*G)` (through the crate's own key
    /// derivation) and `s = k^-1 * (h + r*d) mod n`.
    pub(crate) fn sign_with_k(
        curve: EccCurve,
        digest: EcdsaDigest,
        private_hex: &str,
        message: &[u8],
        k: u64,
    ) -> (String, String) {
        let field_len = curve.private_key_size();
        let n = group_order(curve).unwrap();
        let d_bytes = decode_scalar_hex("private_key", private_hex, field_len).unwrap();
        let d = BigUint::from_bytes_be(&d_bytes);
        let k_big = BigUint::from(k);
        let compressed = derive_compressed_hex(curve, &k_big).expect("k in 1..n");
        let r = BigUint::from_bytes_be(&decode_hex("r", &compressed[2..]).unwrap());
        let h = BigUint::from_bytes_be(&digest_message(digest, message)) % &n;
        let k_inverse = mod_inverse(&k_big, &n).expect("k in 1..n");
        let inner = (&h + &(&r * &d)) % &n;
        let s = (&k_inverse * &inner) % &n;
        (
            scalar_to_fixed_hex(&r, field_len),
            scalar_to_fixed_hex(&s, field_len),
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::test_support::sign_with_k;
    use super::*;
    use crate::ecc::{ecdsa_verify, generate_ecc_keypair, EcdsaSignatureFormat};
    use std::time::{Duration, Instant};

    const MSG1: &[u8] = b"attack at dawn";
    const MSG2: &[u8] = b"meet at the harbor";

    #[test]
    fn group_order_matches_fips_186_4_constants() {
        let p256_n = group_order(EccCurve::P256).unwrap();
        assert_eq!(
            p256_n,
            BigUint::parse_bytes(
                b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                16,
            )
            .unwrap()
        );
        let p384_n = group_order(EccCurve::P384).unwrap();
        assert_eq!(
            p384_n,
            BigUint::parse_bytes(
                b"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
                16,
            )
            .unwrap()
        );
    }

    #[test]
    fn group_order_boundary_matches_scalar_validation() {
        // n itself must be rejected as a private key, n-1 accepted.
        let n_hex = scalar_to_fixed_hex(&group_order(EccCurve::P256).unwrap(), 32);
        assert!(parse_ecc_private_key(EccCurve::P256, &n_hex).is_err());
        let n_minus_1 = group_order(EccCurve::P256).unwrap() - 1u32;
        let n_minus_1_hex = scalar_to_fixed_hex(&n_minus_1, 32);
        assert!(parse_ecc_private_key(EccCurve::P256, &n_minus_1_hex).is_ok());
    }

    #[test]
    fn fixed_nonce_signature_verifies_with_real_verifier_p256() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let (r_hex, s_hex) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG1,
            42,
        );
        let signature = format!("{r_hex}{s_hex}");
        let verdict = ecdsa_verify(
            EccCurve::P256,
            &keypair.public_uncompressed_hex,
            MSG1,
            EcdsaDigest::Sha256,
            EcdsaSignatureFormat::Fixed,
            &signature,
        )
        .unwrap();
        assert!(
            verdict.valid,
            "fixed-nonce signature must verify: {:?}",
            verdict.reason
        );
    }

    #[test]
    fn fixed_nonce_signature_verifies_with_real_verifier_p384() {
        let keypair = generate_ecc_keypair(EccCurve::P384).unwrap();
        let (r_hex, s_hex) = sign_with_k(
            EccCurve::P384,
            EcdsaDigest::Sha384,
            &keypair.private_hex,
            MSG1,
            7,
        );
        let signature = format!("{r_hex}{s_hex}");
        let verdict = ecdsa_verify(
            EccCurve::P384,
            &keypair.public_compressed_hex,
            MSG1,
            EcdsaDigest::Sha384,
            EcdsaSignatureFormat::Fixed,
            &signature,
        )
        .unwrap();
        assert!(
            verdict.valid,
            "fixed-nonce signature must verify: {:?}",
            verdict.reason
        );
    }

    #[test]
    fn nonce_reuse_recovers_p256_key() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let (r1, s1) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG1,
            42,
        );
        let (r2, s2) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG2,
            42,
        );
        assert_eq!(r1, r2, "same nonce must produce the same r");
        let report = ecdsa_nonce_reuse_recover(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &EcdsaAttackSignature::from_message(&to_hex(MSG1), &r1, &s1),
            &EcdsaAttackSignature::from_message(&to_hex(MSG2), &r2, &s2),
            &keypair.public_uncompressed_hex,
        )
        .unwrap();
        assert!(report.recovered && report.verified);
        assert_eq!(report.method, "nonce-reuse");
        assert_eq!(report.private_key_hex, keypair.private_hex);
        assert_eq!(
            report.public_key_compressed_hex,
            keypair.public_compressed_hex
        );
        assert_eq!(report.nonce_r_matches, Some(true));
    }

    #[test]
    fn nonce_reuse_recovers_p384_key_with_compressed_public_key() {
        let keypair = generate_ecc_keypair(EccCurve::P384).unwrap();
        let (r1, s1) = sign_with_k(
            EccCurve::P384,
            EcdsaDigest::Sha384,
            &keypair.private_hex,
            MSG1,
            999,
        );
        let (r2, s2) = sign_with_k(
            EccCurve::P384,
            EcdsaDigest::Sha384,
            &keypair.private_hex,
            MSG2,
            999,
        );
        let report = ecdsa_nonce_reuse_recover(
            EccCurve::P384,
            EcdsaDigest::Sha384,
            &EcdsaAttackSignature::from_message(&to_hex(MSG1), &r1, &s1),
            &EcdsaAttackSignature::from_message(&to_hex(MSG2), &r2, &s2),
            &keypair.public_compressed_hex,
        )
        .unwrap();
        assert_eq!(report.private_key_hex, keypair.private_hex);
        assert_eq!(
            report.nonce_k_hex,
            Some(scalar_to_fixed_hex(&999u32.into(), 48))
        );
    }

    #[test]
    fn nonce_reuse_wrong_public_key_is_typed_error() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let other = generate_ecc_keypair(EccCurve::P256).unwrap();
        let (r1, s1) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG1,
            42,
        );
        let (r2, s2) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG2,
            42,
        );
        let error = ecdsa_nonce_reuse_recover(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &EcdsaAttackSignature::from_message(&to_hex(MSG1), &r1, &s1),
            &EcdsaAttackSignature::from_message(&to_hex(MSG2), &r2, &s2),
            &other.public_uncompressed_hex,
        )
        .unwrap_err();
        assert_eq!(error.kind, cybercipher_core::ErrorKind::KeyError);
        assert!(error.message.contains("does not match the public key"));
    }

    #[test]
    fn nonce_reuse_identical_signatures_is_typed_error() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let (r, s) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG1,
            42,
        );
        let error = ecdsa_nonce_reuse_recover(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &EcdsaAttackSignature::from_message(&to_hex(MSG1), &r, &s.clone()),
            &EcdsaAttackSignature::from_message(&to_hex(MSG1), &r, &s),
            &keypair.public_uncompressed_hex,
        )
        .unwrap_err();
        assert_eq!(error.kind, cybercipher_core::ErrorKind::InvalidInput);
        assert!(error.message.contains("same s"));
    }

    #[test]
    fn nonce_reuse_identical_digests_is_typed_error() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let (r, s1) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG1,
            42,
        );
        // Same r and same digest, different s: the numerator (h1 - h2) is zero.
        let s2 = scalar_to_fixed_hex(
            &(&BigUint::from_bytes_be(&decode_hex("s", &s1).unwrap()) + 1u32),
            32,
        );
        let error = ecdsa_nonce_reuse_recover(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &EcdsaAttackSignature::from_digest(&"11".repeat(32), &r, &s1),
            &EcdsaAttackSignature::from_digest(&"11".repeat(32), &r, &s2),
            &keypair.public_uncompressed_hex,
        )
        .unwrap_err();
        assert_eq!(error.kind, cybercipher_core::ErrorKind::InvalidInput);
        assert!(error.message.contains("identical"));
    }

    #[test]
    fn nonce_reuse_different_r_is_typed_error() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let (r1, s1) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG1,
            42,
        );
        let (r2, s2) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG2,
            43,
        );
        assert_ne!(r1, r2);
        let error = ecdsa_nonce_reuse_recover(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &EcdsaAttackSignature::from_message(&to_hex(MSG1), &r1, &s1),
            &EcdsaAttackSignature::from_message(&to_hex(MSG2), &r2, &s2),
            &keypair.public_uncompressed_hex,
        )
        .unwrap_err();
        assert!(error.message.contains("different r"));
    }

    #[test]
    fn nonce_reuse_zero_components_are_typed_errors() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let (r, s) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG1,
            42,
        );
        let sig = EcdsaAttackSignature::from_message(&to_hex(MSG1), &r, &s);
        let zero_s = EcdsaAttackSignature::from_message(&to_hex(MSG1), &r, "00");
        let zero_r = EcdsaAttackSignature::from_message(&to_hex(MSG1), "00", &s);
        let error = ecdsa_nonce_reuse_recover(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &sig,
            &zero_s,
            &keypair.public_uncompressed_hex,
        )
        .unwrap_err();
        assert!(error.message.contains("zero"));
        let error = ecdsa_nonce_reuse_recover(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &zero_r,
            &sig,
            &keypair.public_uncompressed_hex,
        )
        .unwrap_err();
        assert!(error.message.contains("zero"));
    }

    #[test]
    fn nonce_reuse_malformed_hex_is_decode_error() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let odd = EcdsaAttackSignature::from_message(&to_hex(MSG1), "abc", "42");
        let error = ecdsa_nonce_reuse_recover(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &odd,
            &EcdsaAttackSignature::from_message(&to_hex(MSG2), "ab", "42"),
            &keypair.public_uncompressed_hex,
        )
        .unwrap_err();
        assert_eq!(error.kind, cybercipher_core::ErrorKind::Decode);
        let non_hex = EcdsaAttackSignature::from_message(&to_hex(MSG1), "zz", "42");
        let error = ecdsa_nonce_reuse_recover(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &non_hex,
            &EcdsaAttackSignature::from_message(&to_hex(MSG2), "ab", "42"),
            &keypair.public_uncompressed_hex,
        )
        .unwrap_err();
        assert_eq!(error.kind, cybercipher_core::ErrorKind::Decode);
    }

    #[test]
    fn nonce_reuse_enforces_digest_curve_pairing_and_curve() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let (r, s) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG1,
            42,
        );
        let sig = EcdsaAttackSignature::from_message(&to_hex(MSG1), &r, &s);
        let error = ecdsa_nonce_reuse_recover(
            EccCurve::P256,
            EcdsaDigest::Sha384,
            &sig,
            &sig,
            &keypair.public_uncompressed_hex,
        )
        .unwrap_err();
        assert_eq!(error.kind, cybercipher_core::ErrorKind::InvalidParam);
        let error =
            ecdsa_nonce_reuse_recover(EccCurve::Ed25519, EcdsaDigest::Sha256, &sig, &sig, "00")
                .unwrap_err();
        assert_eq!(error.kind, cybercipher_core::ErrorKind::InvalidInput);
        assert!(error.message.contains("wrong curve"));
    }

    #[test]
    fn nonce_reuse_digest_length_is_enforced() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let (r, s) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG1,
            42,
        );
        let short = EcdsaAttackSignature::from_digest(&"11".repeat(16), &r, &s);
        let error = ecdsa_nonce_reuse_recover(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &short,
            &EcdsaAttackSignature::from_digest(&"22".repeat(32), &r, &s),
            &keypair.public_uncompressed_hex,
        )
        .unwrap_err();
        assert_eq!(error.kind, cybercipher_core::ErrorKind::LengthMismatch);
    }

    #[test]
    fn known_k_recovers_p256_key() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let (r, s) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG1,
            12345,
        );
        let report = ecdsa_known_k_recover(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &EcdsaAttackSignature::from_message(&to_hex(MSG1), &r, &s),
            "3039",
            &keypair.public_uncompressed_hex,
        )
        .unwrap();
        assert_eq!(report.method, "known-k");
        assert_eq!(report.private_key_hex, keypair.private_hex);
        assert_eq!(
            report.nonce_k_hex,
            Some(scalar_to_fixed_hex(&12345u32.into(), 32))
        );
        assert_eq!(report.nonce_r_matches, Some(true));
    }

    #[test]
    fn known_k_wrong_k_fails_verification() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let (r, s) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG1,
            12345,
        );
        let error = ecdsa_known_k_recover(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &EcdsaAttackSignature::from_message(&to_hex(MSG1), &r, &s),
            "303a",
            &keypair.public_uncompressed_hex,
        )
        .unwrap_err();
        assert_eq!(error.kind, cybercipher_core::ErrorKind::KeyError);
        assert!(error.message.contains("does not match the public key"));
    }

    #[test]
    fn known_k_zero_and_out_of_range_k_are_typed_errors() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let (r, s) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG1,
            42,
        );
        let sig = EcdsaAttackSignature::from_message(&to_hex(MSG1), &r, &s);
        let error = ecdsa_known_k_recover(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &sig,
            "00",
            &keypair.public_uncompressed_hex,
        )
        .unwrap_err();
        assert!(error.message.contains("zero"));
        let n = group_order(EccCurve::P256).unwrap();
        let error = ecdsa_known_k_recover(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &sig,
            &format!("{n:x}"),
            &keypair.public_uncompressed_hex,
        )
        .unwrap_err();
        assert!(error.message.contains("canonical"));
    }

    #[test]
    fn small_k_recovers_k_12345_with_candidate_evidence() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let (r, s) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG1,
            12345,
        );
        let report = ecdsa_small_k_recover(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &EcdsaAttackSignature::from_message(&to_hex(MSG1), &r, &s),
            &keypair.public_uncompressed_hex,
            SMALL_K_DEFAULT,
            &ExecutionContext::new(),
        )
        .unwrap();
        assert_eq!(report.method, "small-k");
        assert_eq!(report.private_key_hex, keypair.private_hex);
        assert_eq!(report.candidates_tried, Some(12345));
        assert_eq!(
            report.nonce_k_hex,
            Some(scalar_to_fixed_hex(&12345u32.into(), 32))
        );
    }

    #[test]
    fn small_k_exhausted_bound_is_typed_error() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let (r, s) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG1,
            12345,
        );
        let error = ecdsa_small_k_recover(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &EcdsaAttackSignature::from_message(&to_hex(MSG1), &r, &s),
            &keypair.public_uncompressed_hex,
            12344,
            &ExecutionContext::new(),
        )
        .unwrap_err();
        assert_eq!(error.kind, cybercipher_core::ErrorKind::BudgetExceeded);
        assert!(error.message.contains("budget exhausted"));
    }

    #[test]
    fn small_k_rejects_bounds_outside_the_cap() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let (r, s) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG1,
            42,
        );
        let sig = EcdsaAttackSignature::from_message(&to_hex(MSG1), &r, &s);
        for bad in [0u64, SMALL_K_HARD_CAP + 1] {
            let error = ecdsa_small_k_recover(
                EccCurve::P256,
                EcdsaDigest::Sha256,
                &sig,
                &keypair.public_uncompressed_hex,
                bad,
                &ExecutionContext::new(),
            )
            .unwrap_err();
            assert_eq!(error.kind, cybercipher_core::ErrorKind::InvalidParam);
        }
    }

    #[test]
    fn small_k_respects_deadline_and_cancellation() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let (r, s) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG1,
            12345,
        );
        let sig = EcdsaAttackSignature::from_message(&to_hex(MSG1), &r, &s);
        let past = ExecutionContext::new().with_deadline(Instant::now() - Duration::from_secs(1));
        let error = ecdsa_small_k_recover(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &sig,
            &keypair.public_uncompressed_hex,
            SMALL_K_DEFAULT,
            &past,
        )
        .unwrap_err();
        assert_eq!(error.kind, cybercipher_core::ErrorKind::BudgetExceeded);
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let cancelled = ExecutionContext::new().with_cancel(flag);
        let error = ecdsa_small_k_recover(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &sig,
            &keypair.public_uncompressed_hex,
            SMALL_K_DEFAULT,
            &cancelled,
        )
        .unwrap_err();
        assert_eq!(error.kind, cybercipher_core::ErrorKind::Cancelled);
    }

    #[test]
    fn duplicate_r_detects_the_sharing_pair() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let (r, s1) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG1,
            42,
        );
        let (_r2, s2) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG2,
            42,
        );
        let (_r3, s3) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG2,
            43,
        );
        let report = ecdsa_duplicate_r_detect(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &[
                EcdsaAttackSignature::from_message(&to_hex(MSG1), &r, &s1),
                EcdsaAttackSignature::from_message(&to_hex(MSG2), &r, &s2),
                EcdsaAttackSignature::from_message(&to_hex(MSG2), &_r3, &s3),
            ],
        )
        .unwrap();
        assert!(report.duplicates_found);
        assert_eq!(report.total_signatures, 3);
        assert_eq!(report.groups.len(), 1);
        assert_eq!(report.groups[0].indices, vec![0, 1]);
        assert_eq!(report.pairs.len(), 1);
        assert_eq!(report.pairs[0].first_index, 0);
        assert_eq!(report.pairs[0].second_index, 1);
    }

    #[test]
    fn duplicate_r_without_reuse_reports_no_duplicates() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let signatures: Vec<EcdsaAttackSignature> = [1u64, 2, 3]
            .iter()
            .map(|k| {
                let (r, s) = sign_with_k(
                    EccCurve::P256,
                    EcdsaDigest::Sha256,
                    &keypair.private_hex,
                    MSG1,
                    *k,
                );
                EcdsaAttackSignature::from_message(&to_hex(MSG1), &r, &s)
            })
            .collect();
        let report =
            ecdsa_duplicate_r_detect(EccCurve::P256, EcdsaDigest::Sha256, &signatures).unwrap();
        assert!(!report.duplicates_found);
        assert!(report.groups.is_empty() && report.pairs.is_empty());
        assert_eq!(report.digests_hex.len(), 3);
    }

    #[test]
    fn duplicate_r_accepts_prehashed_digest_form() {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let (r, s1) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG1,
            42,
        );
        let (_r2, s2) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG2,
            42,
        );
        let h1 = {
            let resolved = resolve_signature(
                EccCurve::P256,
                EcdsaDigest::Sha256,
                &EcdsaAttackSignature::from_message(&to_hex(MSG1), &r, &s1),
            )
            .unwrap();
            resolved.digest_hex
        };
        let report = ecdsa_duplicate_r_detect(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &[
                EcdsaAttackSignature::from_digest(&h1, &r, &s1),
                EcdsaAttackSignature::from_digest(&"22".repeat(32), &r, &s2),
            ],
        )
        .unwrap();
        assert!(report.duplicates_found);
    }

    #[test]
    fn duplicate_r_rejects_empty_lists_and_bad_components() {
        let error = ecdsa_duplicate_r_detect(EccCurve::P256, EcdsaDigest::Sha256, &[]).unwrap_err();
        assert_eq!(error.kind, cybercipher_core::ErrorKind::InvalidInput);
        let bad = [EcdsaAttackSignature::from_message(
            &to_hex(MSG1),
            "42",
            "00",
        )];
        let error =
            ecdsa_duplicate_r_detect(EccCurve::P256, EcdsaDigest::Sha256, &bad).unwrap_err();
        assert!(error.message.contains("zero"));
    }

    #[test]
    fn real_rfc6979_signatures_produce_distinct_r_values() {
        // End-to-end anchor against the real signing path: two RFC 6979
        // signatures over different messages never share r, and parsing their
        // fixed-size encoding feeds the detector unchanged.
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let sig1 = crate::ecc::ecdsa_sign(
            EccCurve::P256,
            &keypair.private_hex,
            MSG1,
            EcdsaDigest::Sha256,
            crate::ecc::EcdsaNonceMode::Deterministic,
            EcdsaSignatureFormat::Fixed,
        )
        .unwrap();
        let sig2 = crate::ecc::ecdsa_sign(
            EccCurve::P256,
            &keypair.private_hex,
            MSG2,
            EcdsaDigest::Sha256,
            crate::ecc::EcdsaNonceMode::Deterministic,
            EcdsaSignatureFormat::Fixed,
        )
        .unwrap();
        let parse = |hex: &str| {
            let bytes = decode_hex("signature", hex).unwrap();
            (to_hex(&bytes[..32]), to_hex(&bytes[32..]))
        };
        let (r1, s1) = parse(&sig1);
        let (r2, s2) = parse(&sig2);
        assert_ne!(r1, r2);
        let report = ecdsa_duplicate_r_detect(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &[
                EcdsaAttackSignature::from_message(&to_hex(MSG1), &r1, &s1),
                EcdsaAttackSignature::from_message(&to_hex(MSG2), &r2, &s2),
            ],
        )
        .unwrap();
        assert!(!report.duplicates_found);
    }
}
