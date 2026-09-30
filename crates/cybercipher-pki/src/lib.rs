//! CyberCipher PKI: public-key infrastructure foundations — key generation,
//! key-format handling (PEM/DER, PKCS#1, PKCS#8, SPKI), key inspection,
//! JWK/JWKS (RFC 7517) conversion, and standard RSA encryption/signature
//! operations (RFC 8017).
//!
//! This crate intentionally depends only on `cybercipher-core` and the
//! RustCrypto ASN.1 stack. GUI/CLI/registry wiring is a later phase; the
//! module surface here is a library API with serde-serializable results.

// OperationError is ~128 bytes (five string fields). Failure paths are cold,
// so boxing the error at every call site is not worth the churn; silence the
// size lint until profiling says otherwise. (Same rationale as
// cybercipher-core/src/lib.rs.)
#![allow(clippy::result_large_err)]

pub mod error;
pub mod keys;
pub mod ops;
pub mod ecc;

pub use error::{PkiError, PkiResult};
pub use keys::*;
pub use ops::{PssSaltLength, RsaDigest, SignatureVerifyResult};
pub use ecc::*;
