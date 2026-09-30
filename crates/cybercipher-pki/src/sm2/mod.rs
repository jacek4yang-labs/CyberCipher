//! SM2 (GB/T 32918, a.k.a. GM/T 0003) and SM3 (GB/T 32905-2016) for
//! CyberCipher: first-class Chinese national-standard public-key crypto.
//!
//! All curve and scalar arithmetic comes from the RustCrypto `sm2` crate
//! (sm2p256v1 via `primeorder`); the SM3 hash comes from RustCrypto `sm3`.
//! Nothing is implemented by hand except the standard-prescribed compositions:
//! the SM3-based KDF and the C1/C3/C2 ciphertext framing of SM2 public-key
//! encryption (GB/T 32918.4), which the `sm2` crate does not provide.
//!
//! Conventions (shared with the rest of CyberCipher):
//! - Keys, points, and signatures cross the boundary as lowercase big-endian
//!   hex strings (the big-int transport); messages, plaintexts, and
//!   ciphertexts are raw bytes.
//! - Results are serde-serializable structs (snake_case).
//! - No panics on user input: every malformed key, point, signature, or
//!   ciphertext input is a typed [`crate::error::PkiError`].
//!
//! Typed error distinctions (by `ErrorKind` + message shape), mirroring
//! [`crate::ecc`]:
//! - invalid key material             -> `KeyError`
//! - point not on the curve           -> `KeyError` ("point is not on the ... curve")
//! - wrong container encoding         -> `Decode`
//! - wrong length                     -> `LengthMismatch`
//! - wrong curve                      -> `InvalidInput` (expected / actual)
//!
//! Signature-verification failures are *results* (`valid: false` + a
//! `reason`), not errors — mirroring [`crate::ecc::ecdsa_verify`].

pub mod encrypt;
pub mod hash;
pub mod key;
pub mod sign;

pub use encrypt::{sm2_decrypt, sm2_encrypt, SM2_C1_LEN, SM2_C3_LEN, SM2_CIPHERTEXT_PREFIX};
pub use hash::{sm3_digest, sm3_hex};
pub use key::{
    generate_sm2_keypair, parse_sm2_private_key, parse_sm2_public_key, Sm2KeyPair,
    Sm2PublicKeyMaterial,
};
pub use sign::{
    sm2_sign, sm2_signature_from_bytes, sm2_signature_to_bytes, sm2_verify, Sm2VerifyResult,
};

/// The default SM2 user ID (`ID_A`) per GB/T 32918.2 / GM/T 0003.2 appendix A:
/// the ASCII string `"1234567812345678"`. Signatures are computed over
/// `ZA || M` with `ZA = SM3(ENTLa || IDa || a || b || xG || yG || xA || yA)`,
/// so the ID is part of every signature; tooling that omits it means this
/// default value.
pub const SM2_DEFAULT_USER_ID: &str = "1234567812345678";

/// Maximum SM2 user ID length in bytes. The ID is hashed with a 16-bit
/// `ENTLa` *bit* length prefix, so at most 65535 bits (8191 bytes) fit.
pub const SM2_MAX_USER_ID_BYTES: usize = 8191;

/// Fixed SM2 private-key/scalar/signature-component size in bytes (256-bit
/// curve, like P-256).
pub const SM2_SCALAR_LEN: usize = 32;

/// SM2 signature size in bytes: the raw fixed-size `r || s` encoding
/// (r = bytes 0..32, s = bytes 32..64, both zero-padded big-endian).
pub const SM2_SIGNATURE_LEN: usize = 64;

/// SEC1 compressed SM2 public key size in bytes (`02/03 || x`).
pub const SM2_PUBLIC_COMPRESSED_LEN: usize = 33;

/// SEC1 uncompressed SM2 public key size in bytes (`04 || x || y`).
pub const SM2_PUBLIC_UNCOMPRESSED_LEN: usize = 65;

/// Resolve the SM2 user ID parameter: `None` or an empty string selects
/// [`SM2_DEFAULT_USER_ID`]. Rejects IDs that would overflow the 16-bit
/// `ENTLa` bit-length field.
pub(crate) fn effective_user_id(user_id: Option<&str>) -> crate::error::PkiResult<&str> {
    let id = match user_id {
        Some(id) if !id.is_empty() => id,
        _ => SM2_DEFAULT_USER_ID,
    };
    if id.len() > SM2_MAX_USER_ID_BYTES {
        return Err(crate::error::PkiError::invalid_param(
            "user_id",
            format!(
                "SM2 user ID must fit the 16-bit ENTLa bit-length field (at most {SM2_MAX_USER_ID_BYTES} bytes)"
            ),
        )
        .with_expected(format!("at most {SM2_MAX_USER_ID_BYTES} bytes"))
        .with_actual(format!("{} bytes", id.len())));
    }
    Ok(id)
}
