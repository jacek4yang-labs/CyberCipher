//! CyberCipher steg: image steganography engine.
//!
//! The transform catalog and the bit-extraction semantics are a faithful
//! port of the StegSolver engine (reference commit `c14bfa9`, MIT, which
//! itself rebuilds the original StegSolve by Caesum). Compatibility quirks
//! that are part of the established behavior — the legacy full-channel
//! `>>> 8` shift, the Java `Random`-driven random colour maps, the opaque
//! output of every computed transform, alpha-first extraction with
//! MSB-first bit packing — are reproduced exactly and covered by golden
//! parity tests. See `compatibility/stegsolver.toml` and
//! `docs/design-steg-sstv.md`.

#![allow(clippy::result_large_err)]

pub mod extract;
pub mod java_random;
pub mod ops;
pub mod transforms;

use cybercipher_core::OperationRegistry;

/// Register every steg operation into the registry.
pub fn register_all(reg: &mut OperationRegistry) {
    ops::register(reg);
}
