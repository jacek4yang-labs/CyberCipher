//! RSASSA signature operations (RFC 8017 sections 8-9): PKCS#1 v1.5 and
//! PSS. Signing and verification delegate to the `rsa` crate's scheme
//! implementations (`rsa::Pkcs1v15Sign` and
//! `rsa::pss::BlindedSigningKey`/`VerifyingKey`) — no hand-written padding,
//! no hand-rolled DigestInfo prefixes.
//!
//! Error semantics (deliberately split):
//! - malformed *operation input* is a typed error: bad key material,
//!   a signature whose length differs from the modulus size, an impossible
//!   PSS salt length;
//! - a signature that fails *cryptographic* verification is a normal
//!   [`SignatureVerifyResult`] with `valid: false` and a `reason` — an
//!   invalid signature is a verification result, not an error.

use rand::rngs::OsRng;
use rsa::pkcs8::AssociatedOid;
use rsa::pss::{BlindedSigningKey, VerifyingKey as PssVerifyingKey};
use rsa::sha2::digest::{DynDigest, FixedOutputReset};
use rsa::sha2::Digest;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use super::digest::{PssSaltLength, RsaDigest};
use super::encrypt::{modulus_len, private_key_from_material};
use crate::error::{PkiError, PkiResult};
use crate::keys::RsaKeyMaterial;

/// Result of a signature verification. `valid == false` (with a `reason`)
/// is a normal outcome; only malformed inputs produce [`PkiResult`] errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureVerifyResult {
    /// Whether the signature verifies over the data with the given key.
    pub valid: bool,
    /// Why verification failed; `None` when `valid` is `true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Signature scheme: `"pkcs1v15"` or `"pss"`.
    pub scheme: &'static str,
    /// Digest used, in canonical label form (`"sha256"` ...).
    pub digest: String,
    /// PSS salt length in bytes; `None` for PKCS#1 v1.5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt_len: Option<usize>,
}

impl SignatureVerifyResult {
    fn valid(scheme: &'static str, digest: RsaDigest, salt_len: Option<usize>) -> Self {
        SignatureVerifyResult {
            valid: true,
            reason: None,
            scheme,
            digest: digest.label().to_string(),
            salt_len,
        }
    }

    fn invalid(
        scheme: &'static str,
        digest: RsaDigest,
        salt_len: Option<usize>,
        why: String,
    ) -> Self {
        SignatureVerifyResult {
            valid: false,
            reason: Some(why),
            scheme,
            digest: digest.label().to_string(),
            salt_len,
        }
    }
}

/// Verify-side input guard: signature length must equal the modulus size.
fn check_signature_len(signature: &[u8], k: usize) -> PkiResult<()> {
    if signature.len() != k {
        return Err(PkiError::length(
            format!("{k} bytes (modulus size)"),
            format!("{} bytes", signature.len()),
            "signature length must equal the RSA modulus size",
        )
        .with_parameter("signature"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RSASSA-PKCS1-v1_5 (RFC 8017 section 8.2)
// ---------------------------------------------------------------------------

/// RSASSA-PKCS1-v1_5 sign: `rsa_signPkcs1v15(priv, digest, data)`. The data
/// is hashed here with the chosen digest; the `rsa` crate builds the
/// DigestInfo prefix and the v1.5 padding deterministically.
pub fn rsa_sign_pkcs1v15(
    private_key: &RsaKeyMaterial,
    digest: RsaDigest,
    data: &[u8],
) -> PkiResult<Vec<u8>> {
    let keypair = private_key_from_material(private_key)?;
    pkcs1v15_sign_with_key(&keypair.rsa_private_key(), digest, data)
}

/// Sign with an already-built `rsa` private key (PEM wrapper path).
pub(crate) fn pkcs1v15_sign_with_key(
    private_key: &RsaPrivateKey,
    digest: RsaDigest,
    data: &[u8],
) -> PkiResult<Vec<u8>> {
    match digest {
        RsaDigest::Sha1 => pkcs1v15_sign_hashed::<Sha1>(private_key, data, digest),
        RsaDigest::Sha256 => pkcs1v15_sign_hashed::<Sha256>(private_key, data, digest),
        RsaDigest::Sha384 => pkcs1v15_sign_hashed::<Sha384>(private_key, data, digest),
        RsaDigest::Sha512 => pkcs1v15_sign_hashed::<Sha512>(private_key, data, digest),
    }
}

fn pkcs1v15_sign_hashed<D: Digest + AssociatedOid>(
    private_key: &RsaPrivateKey,
    data: &[u8],
    digest: RsaDigest,
) -> PkiResult<Vec<u8>> {
    let hashed = D::digest(data);
    private_key
        .sign(Pkcs1v15Sign::new::<D>(), &hashed)
        .map_err(|e| {
            PkiError::internal(format!("PKCS#1 v1.5 signing failed ({})", digest.label()))
                .with_parameter("digest")
                .with_details(e.to_string())
        })
}

/// RSASSA-PKCS1-v1_5 verify: `rsa_verifyPkcs1v15(pub, digest, data, sig)`.
pub fn rsa_verify_pkcs1v15(
    public_key: &crate::keys::RsaPublicKeyMaterial,
    digest: RsaDigest,
    data: &[u8],
    signature: &[u8],
) -> PkiResult<SignatureVerifyResult> {
    let key = public_key.to_rsa_public_key()?;
    pkcs1v15_verify_with_key(&key, digest, data, signature)
}

/// Verify with an already-built `rsa` public key (PEM wrapper path).
pub(crate) fn pkcs1v15_verify_with_key(
    public_key: &RsaPublicKey,
    digest: RsaDigest,
    data: &[u8],
    signature: &[u8],
) -> PkiResult<SignatureVerifyResult> {
    check_signature_len(signature, modulus_len(public_key))?;
    let outcome = match digest {
        RsaDigest::Sha1 => pkcs1v15_verify_hashed::<Sha1>(public_key, data, signature),
        RsaDigest::Sha256 => pkcs1v15_verify_hashed::<Sha256>(public_key, data, signature),
        RsaDigest::Sha384 => pkcs1v15_verify_hashed::<Sha384>(public_key, data, signature),
        RsaDigest::Sha512 => pkcs1v15_verify_hashed::<Sha512>(public_key, data, signature),
    };
    Ok(match outcome {
        Ok(()) => SignatureVerifyResult::valid("pkcs1v15", digest, None),
        Err(e) => SignatureVerifyResult::invalid(
            "pkcs1v15",
            digest,
            None,
            format!("PKCS#1 v1.5 verification failed (wrong key, tampered data/signature, or mismatched digest): {e}"),
        ),
    })
}

fn pkcs1v15_verify_hashed<D: Digest + AssociatedOid>(
    public_key: &RsaPublicKey,
    data: &[u8],
    signature: &[u8],
) -> Result<(), rsa::errors::Error> {
    let hashed = D::digest(data);
    public_key.verify(Pkcs1v15Sign::new::<D>(), &hashed, signature)
}

// ---------------------------------------------------------------------------
// RSASSA-PSS (RFC 8017 section 8.1)
// ---------------------------------------------------------------------------

/// RSASSA-PSS sign with blinding:
/// `rsa_signPss(priv, digest, data, salt_len)`. The signature bytes are
/// randomized (fresh salt per call) unless the salt length is `Zero`.
pub fn rsa_sign_pss(
    private_key: &RsaKeyMaterial,
    digest: RsaDigest,
    data: &[u8],
    salt_len: PssSaltLength,
) -> PkiResult<Vec<u8>> {
    let keypair = private_key_from_material(private_key)?;
    pss_sign_with_key(&keypair.rsa_private_key(), digest, data, salt_len)
}

/// PSS sign with an already-built `rsa` private key (PEM wrapper path).
pub(crate) fn pss_sign_with_key(
    private_key: &RsaPrivateKey,
    digest: RsaDigest,
    data: &[u8],
    salt_len: PssSaltLength,
) -> PkiResult<Vec<u8>> {
    let k = private_key.size();
    let resolved = salt_len.resolve(digest);
    // RFC 8017 requires emLen >= hLen + sLen + 2.
    let max_salt = k.saturating_sub(digest.output_len() + 2);
    if resolved > max_salt {
        return Err(PkiError::invalid_param(
            "salt_len",
            format!(
                "PSS salt length {} is too large for a {k}-byte modulus with {}",
                salt_len.label(),
                digest.label()
            ),
        )
        .with_expected(format!("at most {max_salt} bytes"))
        .with_actual(salt_len.label()));
    }
    match digest {
        RsaDigest::Sha1 => pss_sign_hashed::<Sha1>(private_key, data, resolved, digest),
        RsaDigest::Sha256 => pss_sign_hashed::<Sha256>(private_key, data, resolved, digest),
        RsaDigest::Sha384 => pss_sign_hashed::<Sha384>(private_key, data, resolved, digest),
        RsaDigest::Sha512 => pss_sign_hashed::<Sha512>(private_key, data, resolved, digest),
    }
}

fn pss_sign_hashed<D: Digest + DynDigest + FixedOutputReset + Send + Sync>(
    private_key: &RsaPrivateKey,
    data: &[u8],
    salt_len: usize,
    digest: RsaDigest,
) -> PkiResult<Vec<u8>> {
    let signing = BlindedSigningKey::<D>::new_with_salt_len(private_key.clone(), salt_len);
    let signature = signing
        .try_sign_with_rng(&mut OsRng, data)
        .map_err(|e| {
            PkiError::internal(format!("PSS signing failed ({})", digest.label()))
                .with_parameter("digest")
                .with_details(e.to_string())
        })?
        .to_vec();
    if signature.len() != private_key.size() {
        // Defensive: the crate should always emit exactly k bytes.
        return Err(PkiError::internal(format!(
            "PSS signing produced {} bytes, expected {}",
            signature.len(),
            private_key.size()
        ))
        .with_parameter("digest")
        .with_actual(digest.label()));
    }
    Ok(signature)
}

/// RSASSA-PSS verify: `rsa_verifyPss(pub, digest, data, sig, salt_len)`.
/// The salt length must match the one used at signing time.
pub fn rsa_verify_pss(
    public_key: &crate::keys::RsaPublicKeyMaterial,
    digest: RsaDigest,
    data: &[u8],
    signature: &[u8],
    salt_len: PssSaltLength,
) -> PkiResult<SignatureVerifyResult> {
    let key = public_key.to_rsa_public_key()?;
    pss_verify_with_key(&key, digest, data, signature, salt_len)
}

/// PSS verify with an already-built `rsa` public key (PEM wrapper path).
pub(crate) fn pss_verify_with_key(
    public_key: &RsaPublicKey,
    digest: RsaDigest,
    data: &[u8],
    signature: &[u8],
    salt_len: PssSaltLength,
) -> PkiResult<SignatureVerifyResult> {
    check_signature_len(signature, modulus_len(public_key))?;
    let resolved = salt_len.resolve(digest);
    let outcome = match digest {
        RsaDigest::Sha1 => pss_verify_hashed::<Sha1>(public_key, data, signature, resolved),
        RsaDigest::Sha256 => pss_verify_hashed::<Sha256>(public_key, data, signature, resolved),
        RsaDigest::Sha384 => pss_verify_hashed::<Sha384>(public_key, data, signature, resolved),
        RsaDigest::Sha512 => pss_verify_hashed::<Sha512>(public_key, data, signature, resolved),
    };
    Ok(match outcome {
        Ok(()) => SignatureVerifyResult::valid("pss", digest, Some(resolved)),
        Err(e) => SignatureVerifyResult::invalid(
            "pss",
            digest,
            Some(resolved),
            format!("PSS verification failed (wrong key, tampered data/signature, wrong salt length, or mismatched digest): {e}"),
        ),
    })
}

fn pss_verify_hashed<D: Digest + DynDigest + FixedOutputReset + Send + Sync>(
    public_key: &RsaPublicKey,
    data: &[u8],
    signature: &[u8],
    salt_len: usize,
) -> Result<(), rsa::signature::Error> {
    let verifying = PssVerifyingKey::<D>::new_with_salt_len(public_key.clone(), salt_len);
    let sig = rsa::pss::Signature::try_from(signature)?;
    verifying.verify(data, &sig)
}
