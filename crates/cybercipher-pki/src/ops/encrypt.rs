//! RSAES encryption/decryption operations (RFC 8017 section 7): OAEP and
//! PKCS#1 v1.5. All padding is delegated to the `rsa` crate's own scheme
//! implementations (`rsa::Oaep`, `rsa::Pkcs1v15Encrypt`) — nothing here
//! hand-assembles encoded messages.
//!
//! Size rules are enforced up front, as typed `LengthMismatch` errors with
//! `expected`/`actual` filled in:
//! - ciphertext length must equal the modulus size `k` for every decrypt;
//! - plaintext length must satisfy `k - 2*hLen - 2` (OAEP) or `k - 11`
//!   (PKCS#1 v1.5).
//!
//! A decrypt that fails padding/label validation (wrong key, tampered
//! ciphertext, wrong hash or label) is reported as a `KeyError`-kind error,
//! deliberately distinct from the `LengthMismatch` kind so callers can tell
//! "input is malformed" apart from "this is not the right key".

use rand::rngs::OsRng;
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use sha2::digest::DynDigest;
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::digest::RsaDigest;
use crate::error::{PkiError, PkiResult};
use crate::keys::{biguint_from_hex, RsaKeyMaterial, RsaKeypair, RsaPublicKeyMaterial};

/// Reconstruct and re-validate an `rsa` crate private key from hex-string
/// material (the transport shape produced by keygen and by every parse path).
/// The `dp`/`dq`/`qinv` fields of the material are ignored — CRT components
/// are re-derived canonically from `(d, p, q)`, never trusted from input.
pub(crate) fn private_key_from_material(material: &RsaKeyMaterial) -> PkiResult<RsaKeypair> {
    let n = biguint_from_hex(&material.n).map_err(|e| e.with_parameter("n"))?;
    let e = biguint_from_hex(&material.e).map_err(|e| e.with_parameter("e"))?;
    let d = biguint_from_hex(&material.d).map_err(|e| e.with_parameter("d"))?;
    let p = biguint_from_hex(&material.p).map_err(|e| e.with_parameter("p"))?;
    let q = biguint_from_hex(&material.q).map_err(|e| e.with_parameter("q"))?;
    RsaKeypair::from_biguints(n, e, d, p, q)
}

/// Boxed hasher instance for a digest choice (used by the dynamically typed
/// `rsa::Oaep` padding struct).
pub(crate) fn box_digest(hash: RsaDigest) -> Box<dyn DynDigest + Send + Sync> {
    match hash {
        RsaDigest::Sha1 => Box::new(sha1::Sha1::new()),
        RsaDigest::Sha256 => Box::new(Sha256::new()),
        RsaDigest::Sha384 => Box::new(Sha384::new()),
        RsaDigest::Sha512 => Box::new(Sha512::new()),
    }
}

/// Build the `rsa::Oaep` padding scheme for a digest choice and optional
/// label. MGF1 always uses the same hash as the label digest (the standard
/// configuration; the `rsa` crate also supports split digest/MGF hashes but
/// CyberCipher does not expose that here).
///
/// The `rsa` crate models OAEP labels as UTF-8 strings, so a non-UTF-8 label
/// is rejected with a typed `invalid_param` error rather than being silently
/// mangled.
fn oaep_padding(hash: RsaDigest, label: Option<&[u8]>) -> PkiResult<Oaep> {
    let label = match label {
        None => None,
        Some(bytes) => match std::str::from_utf8(bytes) {
            Ok(s) => Some(s.to_string()),
            Err(e) => {
                return Err(
                    PkiError::invalid_param("label", "OAEP label must be valid UTF-8")
                        .with_expected("UTF-8 label bytes")
                        .with_actual(format!("invalid UTF-8 after byte {}", e.valid_up_to()))
                        .with_details(
                            "the underlying RSA implementation hashes labels as UTF-8 strings; \
                     encode non-text labels yourself (e.g. as hex) before passing them",
                        ),
                );
            }
        },
    };
    Ok(Oaep {
        digest: box_digest(hash),
        mgf_digest: box_digest(hash),
        label,
    })
}

/// RSAES-OAEP encrypt: `rsa_encryptOAEP(pub, plaintext, hash, label)`.
pub fn rsa_encrypt_oaep(
    public_key: &RsaPublicKeyMaterial,
    plaintext: &[u8],
    hash: RsaDigest,
    label: Option<&[u8]>,
) -> PkiResult<Vec<u8>> {
    let key = public_key.to_rsa_public_key()?;
    let k = key.size();
    let max = k.saturating_sub(2 * hash.output_len() + 2);
    if plaintext.len() > max {
        return Err(PkiError::length(
            format!("at most {max} bytes (k - 2*{} - 2)", hash.output_len()),
            format!("{} bytes", plaintext.len()),
            format!(
                "OAEP-{} plaintext too long for a {k}-byte RSA modulus",
                hash.label()
            ),
        )
        .with_parameter("plaintext"));
    }
    let padding = oaep_padding(hash, label)?;
    key.encrypt(&mut OsRng, padding, plaintext)
        .map_err(|e| PkiError::internal("OAEP encryption failed").with_details(e.to_string()))
}

/// RSAES-OAEP decrypt on hex-string private material:
/// `rsa_decryptOAEP(priv, ct, hash, label)`.
pub fn rsa_decrypt_oaep(
    private_key: &RsaKeyMaterial,
    ciphertext: &[u8],
    hash: RsaDigest,
    label: Option<&[u8]>,
) -> PkiResult<Vec<u8>> {
    let keypair = private_key_from_material(private_key)?;
    oaep_decrypt_with_key(&keypair.rsa_private_key(), ciphertext, hash, label)
}

/// RSAES-OAEP decrypt on an already-built `rsa` private key (used by the
/// PEM-level wrappers, which already hold a validated keypair).
pub(crate) fn oaep_decrypt_with_key(
    private_key: &RsaPrivateKey,
    ciphertext: &[u8],
    hash: RsaDigest,
    label: Option<&[u8]>,
) -> PkiResult<Vec<u8>> {
    let k = private_key.size();
    if ciphertext.len() != k {
        return Err(PkiError::length(
            format!("{k} bytes (modulus size)"),
            format!("{} bytes", ciphertext.len()),
            "OAEP ciphertext length must equal the RSA modulus size",
        )
        .with_parameter("ciphertext"));
    }
    let padding = oaep_padding(hash, label)?;
    private_key
        .decrypt_blinded(&mut OsRng, padding, ciphertext)
        .map_err(|e| {
            PkiError::key(
                "OAEP decryption failed: wrong private key, wrong hash/label, or tampered ciphertext",
            )
            .with_parameter("ciphertext")
            .with_details(e.to_string())
        })
}

/// RSAES-PKCS1-v1_5 encrypt: `rsa_encryptPkcs1v15(pub, plaintext)`.
pub fn rsa_encrypt_pkcs1v15(
    public_key: &RsaPublicKeyMaterial,
    plaintext: &[u8],
) -> PkiResult<Vec<u8>> {
    let key = public_key.to_rsa_public_key()?;
    let k = key.size();
    let max = k.saturating_sub(11);
    if plaintext.len() > max {
        return Err(PkiError::length(
            format!("at most {max} bytes (k - 11)"),
            format!("{} bytes", plaintext.len()),
            format!("PKCS#1 v1.5 plaintext too long for a {k}-byte RSA modulus"),
        )
        .with_parameter("plaintext"));
    }
    key.encrypt(&mut OsRng, Pkcs1v15Encrypt, plaintext)
        .map_err(|e| {
            PkiError::internal("PKCS#1 v1.5 encryption failed").with_details(e.to_string())
        })
}

/// RSAES-PKCS1-v1_5 decrypt on hex-string private material.
pub fn rsa_decrypt_pkcs1v15(private_key: &RsaKeyMaterial, ciphertext: &[u8]) -> PkiResult<Vec<u8>> {
    let keypair = private_key_from_material(private_key)?;
    pkcs1v15_decrypt_with_key(&keypair.rsa_private_key(), ciphertext)
}

/// RSAES-PKCS1-v1_5 decrypt on an already-built `rsa` private key.
pub(crate) fn pkcs1v15_decrypt_with_key(
    private_key: &RsaPrivateKey,
    ciphertext: &[u8],
) -> PkiResult<Vec<u8>> {
    let k = private_key.size();
    if ciphertext.len() != k {
        return Err(PkiError::length(
            format!("{k} bytes (modulus size)"),
            format!("{} bytes", ciphertext.len()),
            "PKCS#1 v1.5 ciphertext length must equal the RSA modulus size",
        )
        .with_parameter("ciphertext"));
    }
    private_key
        .decrypt_blinded(&mut OsRng, Pkcs1v15Encrypt, ciphertext)
        .map_err(|e| {
            PkiError::key("PKCS#1 v1.5 decryption failed: wrong private key or tampered ciphertext")
                .with_parameter("ciphertext")
                .with_details(e.to_string())
        })
}

/// Public-key byte length helper shared with the signature module.
pub(crate) fn modulus_len(key: &RsaPublicKey) -> usize {
    PublicKeyParts::size(key)
}
