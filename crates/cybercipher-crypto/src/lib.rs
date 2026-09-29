//! CyberCipher crypto: symmetric ciphers, hashes, and MACs.

// See cybercipher-core/src/lib.rs for the rationale.
#![allow(clippy::result_large_err)]
//!
//! Standardized algorithms use RustCrypto implementations; block-mode wiring,
//! padding policy, key/IV validation, and diagnostics are CyberCipher's.
//! Every operation carries provenance metadata and validates key material
//! with explicit expected/actual lengths.

mod aead;
mod ciphers;
mod hashes;
mod helpers;
mod kdf;
mod mac;
mod streams;
mod tea;

use cybercipher_core::OperationRegistry;

/// Register every crypto operation into the registry.
pub fn register_all(reg: &mut OperationRegistry) {
    aead::register(reg);
    ciphers::register(reg);
    hashes::register(reg);
    kdf::register(reg);
    mac::register(reg);
    streams::register(reg);
    tea::register(reg);
}
