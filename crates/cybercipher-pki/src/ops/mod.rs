//! Standard RSA cryptographic operations (RFC 8017): RSAES encryption
//! ([`encrypt`]) and RSASSA signatures ([`sign`]), plus the digest/salt
//! parameter enums they share ([`digest`]) and PEM-string convenience
//! wrappers ([`pem`]).
//!
//! Everything is built on the `rsa` crate's own scheme implementations
//! (`rsa::Oaep`, `rsa::Pkcs1v15Encrypt`, `rsa::Pkcs1v15Sign`,
//! `rsa::pss::BlindedSigningKey`/`VerifyingKey`) — no hand-written padding.
//! The raw-byte level functions operate on the hex-string key material
//! structs from [`crate::keys`]; the [`pem`] module adds PEM-string
//! wrappers for the CLI/GUI.

pub mod digest;
pub mod encrypt;
pub mod pem;
pub mod sign;

pub use digest::{PssSaltLength, RsaDigest};
pub use encrypt::{rsa_decrypt_oaep, rsa_decrypt_pkcs1v15, rsa_encrypt_oaep, rsa_encrypt_pkcs1v15};
pub use pem::{
    decode_signature_text, rsa_decrypt_oaep_pem, rsa_decrypt_pkcs1v15_pem, rsa_encrypt_oaep_pem,
    rsa_encrypt_pkcs1v15_pem, rsa_sign_pkcs1v15_pem, rsa_sign_pss_pem, rsa_verify_pkcs1v15_pem,
    rsa_verify_pss_pem,
};
pub use sign::{
    rsa_sign_pkcs1v15, rsa_sign_pss, rsa_verify_pkcs1v15, rsa_verify_pss, SignatureVerifyResult,
};
