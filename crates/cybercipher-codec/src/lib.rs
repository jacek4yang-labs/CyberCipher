// OperationError is ~128 bytes (five string fields). Failure paths are cold,
// so boxing the error at every call site is not worth the churn; silence the
// size lint until profiling says otherwise.
#![allow(clippy::result_large_err)]
//! CyberCipher codec: encoding, radix, and byte-level operations.
//!
//! All operations are stateless functions wrapped into the common operation
//! model via [`SimpleOp`]. Decoders implement strict **and** relaxed modes;
//! relaxed modes are explicit, documented, and produce diagnostics rather
//! than silently guessing.

mod byteops;
mod compression;
mod encoding;
mod integer;
mod helpers;
mod inspect;

pub use encoding::decode_input;

use cybercipher_core::OperationRegistry;

/// Register every codec operation into the registry.
pub fn register_all(reg: &mut OperationRegistry) {
    compression::register(reg);
    integer::register(reg);
    encoding::register(reg);
    byteops::register(reg);
    inspect::register(reg);
}
