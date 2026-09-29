//! PEM-level convenience wrappers around the raw RSA operations. These are
//! the functions the CLI/GUI call: keys go in as PEM strings (any of the
//! four supported key labels, parsed by [`crate::keys::pem`]) and signature
//! blobs as hex or base64 text. Binary data (plaintext, ciphertext, signed
//! data) still crosses as bytes.
//!
//! - Encrypt/verify accept either a public or a private key PEM (a private
//!   key carries its own public half).
//! - Decrypt/sign require a private key PEM; passing a public key is a typed
//!   error, not a silent failure.

use base64ct::Encoding as _;

use super::digest::{PssSaltLength, RsaDigest};
use super::encrypt::{
    oaep_decrypt_with_key, pkcs1v15_decrypt_with_key, rsa_encrypt_oaep as raw_encrypt_oaep,
    rsa_encrypt_pkcs1v15 as raw_encrypt_pkcs1v15,
};
use super::sign::{
    rsa_sign_pkcs1v15 as raw_sign_pkcs1v15, rsa_sign_pss as raw_sign_pss,
    rsa_verify_pkcs1v15 as raw_verify_pkcs1v15, rsa_verify_pss as raw_verify_pss,
    SignatureVerifyResult,
};
use crate::error::{PkiError, PkiResult};
use crate::keys::{parse_pem, ParsedKey, RsaKeypair, RsaPublicKeyMaterial};

/// Extract public-key material from a PEM string; a private key PEM is
/// accepted and reduced to its public half.
fn public_from_pem(pem: &str) -> PkiResult<RsaPublicKeyMaterial> {
    match parse_pem(pem)? {
        ParsedKey::Public { material, .. } => Ok(material),
        ParsedKey::Private { keypair, .. } => Ok(keypair.public_material()),
    }
}

/// Extract a validated keypair from a private-key PEM string.
fn private_from_pem(pem: &str, operation: &str) -> PkiResult<RsaKeypair> {
    match parse_pem(pem)? {
        ParsedKey::Private { keypair, .. } => Ok(*keypair),
        ParsedKey::Public { .. } => Err(PkiError::invalid_input(format!(
            "{operation} requires a private key"
        ))
        .with_expected("a private key PEM (PRIVATE KEY or RSA PRIVATE KEY)")
        .with_actual("a public key")
        .with_details(
            "decryption/signing is mathematically impossible with a public key; \
             supply the matching private key",
        )),
    }
}

/// Decode a signature supplied as text: hex (preferred; optional `0x`/`0X`
/// prefix) or base64 (standard or URL alphabet, padded or not). Whitespace
/// is ignored. Ambiguity resolves to hex: an all-hex-digit, even-length,
/// non-empty string is always treated as hex.
pub fn decode_signature_text(signature: &str) -> PkiResult<Vec<u8>> {
    let stripped: String = signature
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if stripped.is_empty() {
        return Err(PkiError::decode("empty signature input")
            .with_expected("hex or base64 signature text")
            .with_actual("empty"));
    }
    let Some(hex_body) = stripped
        .strip_prefix("0x")
        .or_else(|| stripped.strip_prefix("0X"))
        .or({
            // No explicit prefix: only claim hex when unambiguous.
            let is_hex = !stripped.is_empty()
                && stripped.len().is_multiple_of(2)
                && stripped.bytes().all(|b| b.is_ascii_hexdigit());
            is_hex.then_some(stripped.as_str())
        })
    else {
        return decode_as_base64(signature, &stripped);
    };
    if hex_body.is_empty() {
        return Err(
            PkiError::decode("signature has no data after the 0x prefix")
                .with_expected("hex digits")
                .with_actual(stripped.as_str()),
        );
    }
    if !hex_body.len().is_multiple_of(2) {
        return Err(PkiError::decode("odd-length hex signature")
            .with_expected("even-length hex string")
            .with_actual(crate::keys::preview(&stripped, 32)));
    }
    hex_decode(hex_body).ok_or_else(|| {
        PkiError::decode("non-hex character in hex signature")
            .with_expected("hex characters [0-9a-fA-F]")
            .with_actual(crate::keys::preview(&stripped, 32))
    })
}

/// Try the four base64 alphabets; produce a typed decode error if none fit.
fn decode_as_base64(original: &str, stripped: &str) -> PkiResult<Vec<u8>> {
    let attempts = [
        base64ct::Base64::decode_vec(stripped),
        base64ct::Base64Unpadded::decode_vec(stripped),
        base64ct::Base64Url::decode_vec(stripped),
        base64ct::Base64UrlUnpadded::decode_vec(stripped),
    ];
    for decoded in attempts.into_iter().flatten() {
        if !decoded.is_empty() {
            return Ok(decoded);
        }
    }
    Err(
        PkiError::decode("signature is neither valid hex nor valid base64")
            .with_expected("hex string (optionally 0x-prefixed) or base64 signature")
            .with_actual(crate::keys::preview(original.trim(), 32)),
    )
}

/// Decode an even-length hex string. The characters were validated by the
/// caller, so this only fails on internal inconsistency.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().as_chunks::<2>().0 {
        let hi = (pair[0] as char).to_digit(16)? as u8;
        let lo = (pair[1] as char).to_digit(16)? as u8;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// RSAES wrappers (encryption)
// ---------------------------------------------------------------------------

/// RSAES-OAEP encrypt against a key PEM.
pub fn rsa_encrypt_oaep_pem(
    public_pem: &str,
    plaintext: &[u8],
    hash: RsaDigest,
    label: Option<&[u8]>,
) -> PkiResult<Vec<u8>> {
    let public = public_from_pem(public_pem)?;
    raw_encrypt_oaep(&public, plaintext, hash, label)
}

/// RSAES-OAEP decrypt against a private key PEM.
pub fn rsa_decrypt_oaep_pem(
    private_pem: &str,
    ciphertext: &[u8],
    hash: RsaDigest,
    label: Option<&[u8]>,
) -> PkiResult<Vec<u8>> {
    let keypair = private_from_pem(private_pem, "RSA-OAEP decryption")?;
    oaep_decrypt_with_key(&keypair.rsa_private_key(), ciphertext, hash, label)
}

/// RSAES-PKCS1-v1_5 encrypt against a key PEM.
pub fn rsa_encrypt_pkcs1v15_pem(public_pem: &str, plaintext: &[u8]) -> PkiResult<Vec<u8>> {
    let public = public_from_pem(public_pem)?;
    raw_encrypt_pkcs1v15(&public, plaintext)
}

/// RSAES-PKCS1-v1_5 decrypt against a private key PEM.
pub fn rsa_decrypt_pkcs1v15_pem(private_pem: &str, ciphertext: &[u8]) -> PkiResult<Vec<u8>> {
    let keypair = private_from_pem(private_pem, "RSA PKCS#1 v1.5 decryption")?;
    pkcs1v15_decrypt_with_key(&keypair.rsa_private_key(), ciphertext)
}

// ---------------------------------------------------------------------------
// RSASSA wrappers (signatures)
// ---------------------------------------------------------------------------

/// RSASSA-PKCS1-v1_5 sign against a private key PEM. `digest_label` is parsed
/// by [`RsaDigest::parse`] (unknown names produce a typed `unsupported`
/// error). Returns the signature as exactly `k` raw bytes.
pub fn rsa_sign_pkcs1v15_pem(
    private_pem: &str,
    digest_label: &str,
    data: &[u8],
) -> PkiResult<Vec<u8>> {
    let digest = RsaDigest::parse(digest_label)?;
    let keypair = private_from_pem(private_pem, "RSA PKCS#1 v1.5 signing")?;
    raw_sign_pkcs1v15(&keypair.material(), digest, data)
}

/// RSASSA-PKCS1-v1_5 verify against a key PEM. `signature_text` is decoded
/// by [`decode_signature_text`]; a malformed blob is a typed `decode` error,
/// while a well-formed but wrong signature is a `valid: false` result.
pub fn rsa_verify_pkcs1v15_pem(
    public_pem: &str,
    digest_label: &str,
    data: &[u8],
    signature_text: &str,
) -> PkiResult<SignatureVerifyResult> {
    let digest = RsaDigest::parse(digest_label)?;
    let public = public_from_pem(public_pem)?;
    let signature = decode_signature_text(signature_text)?;
    raw_verify_pkcs1v15(&public, digest, data, &signature)
}

/// RSASSA-PSS sign against a private key PEM.
pub fn rsa_sign_pss_pem(
    private_pem: &str,
    digest_label: &str,
    data: &[u8],
    salt_len: PssSaltLength,
) -> PkiResult<Vec<u8>> {
    let digest = RsaDigest::parse(digest_label)?;
    let keypair = private_from_pem(private_pem, "RSA-PSS signing")?;
    raw_sign_pss(&keypair.material(), digest, data, salt_len)
}

/// RSASSA-PSS verify against a key PEM. `salt_len` must match the salt
/// length used at signing time.
pub fn rsa_verify_pss_pem(
    public_pem: &str,
    digest_label: &str,
    data: &[u8],
    signature_text: &str,
    salt_len: PssSaltLength,
) -> PkiResult<SignatureVerifyResult> {
    let digest = RsaDigest::parse(digest_label)?;
    let public = public_from_pem(public_pem)?;
    let signature = decode_signature_text(signature_text)?;
    raw_verify_pss(&public, digest, data, &signature, salt_len)
}
