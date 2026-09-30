//! SM2 public-key encryption (GB/T 32918.4 / GM/T 0003.4) for CyberCipher.
//!
//! The `sm2` 0.13 crate provides the sm2p256v1 group arithmetic but no PKE
//! layer, so this module implements the standard-prescribed composition on
//! top of it (the scalar multiplications, point validation, and SM3 hash all
//! come from the audited RustCrypto `sm2`/`sm3` crates):
//!
//! ## Ciphertext layout: `C1 || C3 || C2` (the standard "new" mode)
//!
//! ```text
//! 0x04 || x1(32) || y1(32) || C3(32) || C2(klen)
//! \------ C1: ephemeral point ------/
//! ```
//!
//! - `C1` = SEC1-uncompressed ephemeral point `[k]G` (65 bytes, `0x04`
//!   prefix) — decrypt recovers the shared point as `[dB]C1 = [k]PB`;
//! - `C3` = `SM3(x2 || M || y2)` — 32-byte integrity hash, verified on
//!   decrypt;
//! - `C2` = `M xor KDF(x2 || y2, klen)` — the masked message.
//!
//! This is the layout used by GM/T 0003.4-2012 as amended and by modern
//! tooling (GmSSL `sm2_encrypt`, BouncyCastle `C1C3C2` mode). The legacy
//! `C1 || C2 || C3` ordering is *not* produced here; a `C1C2C3` blob decrypts
//! to a C3-mismatch error rather than silently wrong plaintext.
//!
//! ## KDF (GB/T 32918.4 section 5.4.3)
//!
//! ```text
//! t = SM3(x2||y2||ct=1) || SM3(x2||y2||ct=2) || ... truncated to klen bytes
//! ```
//! with `ct` a 32-bit big-endian counter starting at 1. An all-zero `t` is a
//! hard error on decrypt and forces a new random `k` on encrypt (the
//! standard's retry rule; probability ~2^-256 per attempt).
//!
//! No length limit is imposed on the plaintext (SM2-PKE has no RSA-style
//! modulus cap; long messages are KDF-extended).

use elliptic_curve::ops::MulByGenerator as _;
use rand::rngs::OsRng;
use sm2::elliptic_curve::sec1::{Coordinates, ToEncodedPoint as _};
use sm3::digest::Digest as _;

use super::key::{public_from_hex, secret_from_hex};
use crate::ecc::{internal, invalid_key, wrong_encoding, wrong_length};
use crate::error::{PkiError, PkiResult};

/// Ciphertext C1 size: SEC1-uncompressed ephemeral point (`04 || x || y`).
pub const SM2_C1_LEN: usize = 65;

/// Ciphertext C3 size: SM3 integrity hash `SM3(x2 || M || y2)`.
pub const SM2_C3_LEN: usize = 32;

/// The C1 point tag byte. SM2 ciphertexts here are always uncompressed SEC1.
pub const SM2_CIPHERTEXT_PREFIX: u8 = 0x04;

/// Encryption retries with a fresh `k` if the KDF mask comes out all-zero.
/// The mask is a hash output, so two attempts never happen in practice; the
/// cap just makes the loop provably finite.
const MAX_KDF_RETRIES: usize = 8;

/// SM2 encrypt a message to a hex-encoded SEC1 public key.
///
/// Returns the standard ciphertext `0x04 || x1 || y1 || C3 || C2` (see the
/// module docs): `C1` = fresh random `[k]G` uncompressed (65 bytes), `C3` =
/// `SM3(x2 || M || y2)` (32 bytes), `C2` = message masked with the SM3-based
/// KDF of the shared point.
pub fn sm2_encrypt(public_hex: &str, plaintext: &[u8]) -> PkiResult<Vec<u8>> {
    let public = public_from_hex(public_hex)?;
    for _ in 0..MAX_KDF_RETRIES {
        if let Some(ct) = try_encrypt_once(&public, plaintext)? {
            return Ok(ct);
        }
    }
    Err(internal(
        "SM2 encryption failed: KDF returned all-zero masks repeatedly (cryptographically impossible; RNG suspect)",
    ))
}

/// One encryption attempt. `Ok(None)` = the standard's "t is all-zero, pick a
/// new k" case.
fn try_encrypt_once(public: &sm2::PublicKey, plaintext: &[u8]) -> PkiResult<Option<Vec<u8>>> {
    // k in [1, n-1] via the same validated path as keygen.
    let k = sm2::SecretKey::random(&mut OsRng).to_nonzero_scalar();

    // C1 = [k]G, encoded SEC1-uncompressed (0x04 prefix).
    let c1 = sm2::ProjectivePoint::mul_by_generator(&k).to_affine();
    let c1_encoded = c1.to_encoded_point(false);

    // Shared point [k]PB = (x2, y2).
    let shared = (sm2::ProjectivePoint::from(*public.as_affine()) * *k).to_affine();
    let (x2, y2) = affine_coordinates(&shared)?;

    // t = KDF(x2 || y2, klen); all-zero t retries with a fresh k.
    let t = kdf(&[x2.as_slice(), y2.as_slice()].concat(), plaintext.len());
    if !plaintext.is_empty() && t.iter().all(|&b| b == 0) {
        return Ok(None);
    }

    // C2 = M xor t.
    let c2: Vec<u8> = plaintext.iter().zip(&t).map(|(m, ti)| m ^ ti).collect();

    // C3 = SM3(x2 || M || y2).
    let c3 = sm3::Sm3::new()
        .chain_update(x2)
        .chain_update(plaintext)
        .chain_update(y2)
        .finalize();

    let mut out = Vec::with_capacity(SM2_C1_LEN + SM2_C3_LEN + c2.len());
    out.extend_from_slice(c1_encoded.as_bytes());
    out.extend_from_slice(&c3);
    out.extend_from_slice(&c2);
    Ok(Some(out))
}

/// SM2 decrypt a standard `C1 || C3 || C2` ciphertext (0x04-prefixed; see the
/// module docs) with a hex-encoded private scalar.
///
/// Every structural problem is a typed error: wrong total length
/// (`LengthMismatch`), wrong C1 tag (`Decode`), C1 not on the curve
/// (`KeyError`), or a C3 hash mismatch — the last proves wrong key, tampered
/// ciphertext, or a non-standard C1/C2/C3 ordering.
pub fn sm2_decrypt(private_hex: &str, ciphertext: &[u8]) -> PkiResult<Vec<u8>> {
    let secret = secret_from_hex(private_hex)?;

    if ciphertext.len() < SM2_C1_LEN + SM2_C3_LEN {
        return Err(wrong_length(
            "ciphertext",
            format!(
                "at least {} bytes (C1 {SM2_C1_LEN} || C3 {SM2_C3_LEN}) plus the C2 message bytes",
                SM2_C1_LEN + SM2_C3_LEN
            ),
            format!("{} bytes", ciphertext.len()),
        ));
    }
    let tag = ciphertext[0];
    if tag != SM2_CIPHERTEXT_PREFIX {
        return Err(wrong_encoding(format!(
            "invalid SM2 ciphertext: C1 must be an uncompressed SEC1 point with tag 0x04, found tag 0x{tag:02x}"
        ))
        .with_parameter("ciphertext")
        .with_expected(format!("tag 0x04 (uncompressed C1, {SM2_C1_LEN} bytes)"))
        .with_actual(format!("tag 0x{tag:02x}")));
    }

    // C1: on-curve, non-identity point. from_sec1_bytes enforces all of it.
    let c1 = sm2::PublicKey::from_sec1_bytes(&ciphertext[..SM2_C1_LEN]).map_err(|e| {
        invalid_key(format!(
            "invalid SM2 ciphertext: C1 point rejected ({e}); coordinates may be non-canonical \
             or the point may not satisfy the curve equation"
        ))
        .with_parameter("ciphertext")
    })?;

    // Shared point [dB]C1 = (x2, y2).
    let shared =
        (sm2::ProjectivePoint::from(*c1.as_affine()) * *secret.to_nonzero_scalar()).to_affine();
    let (x2, y2) = affine_coordinates(&shared)?;

    // C3 || C2 split.
    let c3 = &ciphertext[SM2_C1_LEN..SM2_C1_LEN + SM2_C3_LEN];
    let c2 = &ciphertext[SM2_C1_LEN + SM2_C3_LEN..];

    // t = KDF(x2 || y2, len(C2)); all-zero t is a hard error on decrypt.
    let t = kdf(&[x2.as_slice(), y2.as_slice()].concat(), c2.len());
    if !c2.is_empty() && t.iter().all(|&b| b == 0) {
        return Err(wrong_encoding(
            "invalid SM2 ciphertext: KDF output is all zero (corrupt C1 or wrong curve point)",
        )
        .with_parameter("ciphertext"));
    }

    // M = C2 xor t, then verify C3 = SM3(x2 || M || y2).
    let plaintext: Vec<u8> = c2.iter().zip(&t).map(|(c, ti)| c ^ ti).collect();
    let computed_c3 = sm3::Sm3::new()
        .chain_update(x2)
        .chain_update(&plaintext)
        .chain_update(y2)
        .finalize();
    if computed_c3.as_slice() != c3 {
        return Err(PkiError::key(
            "SM2 decryption failed: C3 integrity hash mismatch (wrong private key, tampered \
             ciphertext, or C1||C2||C3 legacy ordering)",
        )
        .with_parameter("ciphertext")
        .with_expected(format!("SM3(x2 || M || y2) = {}", crate::keys::to_hex(c3)))
        .with_actual(format!(
            "SM3(x2 || M' || y2) = {}",
            crate::keys::to_hex(computed_c3.as_slice())
        )));
    }
    Ok(plaintext)
}

/// SM3-based KDF per GB/T 32918.4 section 5.4.3: concatenation of
/// `SM3(Z || ct)` for a 32-bit big-endian counter `ct` starting at 1,
/// truncated to `out_len` bytes.
fn kdf(z: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len + SM2_C3_LEN);
    let mut ct: u32 = 1;
    while out.len() < out_len {
        let block = sm3::Sm3::new()
            .chain_update(z)
            .chain_update(ct.to_be_bytes());
        out.extend_from_slice(&block.finalize());
        ct = ct.wrapping_add(1);
    }
    out.truncate(out_len);
    out
}

/// Extract `(x, y)` field bytes from an affine point. A fresh
/// SEC1-uncompressed encode is always `Uncompressed`; the other arm is an
/// internal invariant, reported as an error rather than a panic.
fn affine_coordinates(point: &sm2::AffinePoint) -> PkiResult<(sm2::FieldBytes, sm2::FieldBytes)> {
    match point.to_encoded_point(false).coordinates() {
        Coordinates::Uncompressed { x, y } => Ok((*x, *y)),
        _ => Err(internal(
            "uncompressed SEC1 encode of a validated SM2 point was not uncompressed",
        )),
    }
}
