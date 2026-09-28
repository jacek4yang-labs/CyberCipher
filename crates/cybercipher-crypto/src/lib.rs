//! CyberCipher crypto: symmetric ciphers, hashes, and MACs.
//!
//! Standardized algorithms use RustCrypto implementations; block-mode wiring,
//! padding policy, key/IV validation, and diagnostics are CyberCipher's.
//! Every operation carries provenance metadata and validates key material
//! with explicit expected/actual lengths.

mod ciphers;
mod helpers;
mod hashes;
mod tea;

use cybercipher_core::OperationRegistry;

/// Register every crypto operation into the registry.
pub fn register_all(reg: &mut OperationRegistry) {
    ciphers::register(reg);
    hashes::register(reg);
    tea::register(reg);
}
