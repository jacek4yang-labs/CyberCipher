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

mod archives;
mod basefamilies;
mod byteops;
mod classical_misc;
mod compression;
mod encoding;
mod fileinfo;
mod helpers;
mod inspect;
mod integer;
mod specialty;
mod structured;
mod wrappers;

pub use encoding::decode_input;
pub use fileinfo::{sniff_magic, MagicMatch};

use cybercipher_core::OperationRegistry;

/// Register every codec operation into the registry.
pub fn register_all(reg: &mut OperationRegistry) {
    compression::register(reg);
    archives::register(reg);
    integer::register(reg);
    encoding::register(reg);
    fileinfo::register(reg);
    basefamilies::register(reg);
    classical_misc::register(reg);
    specialty::register(reg);
    byteops::register(reg);
    inspect::register(reg);
    structured::register(reg);
    wrappers::register(reg);
}
