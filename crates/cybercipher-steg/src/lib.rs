//! CyberCipher steg: image steganography engine.
//!
//! The transform catalog and the bit-extraction semantics are a faithful
//! port of the StegSolver engine (reference commit `c14bfa9`, MIT, which
//! itself rebuilds the original StegSolve by Caesum). Compatibility quirks
//! that are part of the established behavior — the legacy full-channel
//! `>>> 8` shift, the Java `Random`-driven random colour maps, the opaque
//! output of every computed transform, alpha-first extraction with
//! MSB-first bit packing — are reproduced exactly and covered by golden
//! parity tests. The `structure`/`carving` modules port the StegSolver
//! container analyzers (PNG chunk / JPEG marker / GIF block / BMP header
//! walks over raw file bytes) with appended-data carving; `stereo` and
//! `combine` port the stereogram solver and the 13-mode combiner bit for
//! bit; `frames` adds lazy GIF frame indexing and disposal-aware frame
//! decoding. See `compatibility/stegsolver.toml` and
//! `docs/design-steg-sstv.md`.

#![allow(clippy::result_large_err)]

pub mod auto_lsb;
pub mod carving;
pub mod combine;
pub mod extract;
pub mod frames;
pub mod java_random;
pub mod ops;
pub mod payload;
pub mod stereo;
pub mod structure;
pub mod transforms;

use cybercipher_core::OperationRegistry;

/// Register every steg operation into the registry.
pub fn register_all(reg: &mut OperationRegistry) {
    ops::register(reg);
    structure::register(reg);
}
