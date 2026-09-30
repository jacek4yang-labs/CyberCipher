//! `cybercipher-sstv` — automatic SSTV detection and decoding.
//!
//! Migrated from sstv-auto f626d50 (MIT,
//! <https://github.com/jacek4yang/sstv-auto>) with minimal boundary
//! adaptation; original MIT license preserved — see [NOTICE].
//!
//! [NOTICE]: https://github.com/jacek4yang-labs/CyberCipher/blob/main/crates/cybercipher-sstv/NOTICE
//!
//! The crate is split into layers that can each be tested on their own:
//!
//! * [`audio`] — container/codec ingestion, channel selection, level safety.
//! * [`dsp`] — FFT analysis producing a compact time-frequency [`dsp::Track`]
//!   and the [`dsp::Trajectory`] model every later stage reads.
//! * [`modes`] — data-driven SSTV mode geometry and the level/frequency map.
//! * [`vis`] — VIS header detection and synthesis.
//! * [`sync`] — line-sync pulse detection, period fitting, clock recovery.
//! * [`raster`] — recovering a pixel grid from a measured signal.
//! * [`synth`] — rendering a grid back to audio (the inverse of [`raster`]).
//! * [`autodetect`] — mode/offset/clock inference and candidate ranking.
//! * [`backend`] — driving the full-resolution raster decoder.
//! * [`score`] — image plausibility metrics used to reject false positives.
//! * [`error`] — the crate's typed error transport (stands in for the
//!   `anyhow` dependency the upstream crate used; see the module docs).
//! * [`ops`] — the CyberCipher registry operation (`sstv_decode`,
//!   CostClass::Heavy) with the resource bounds shared by the registry op,
//!   the Tauri commands and the CLI.
//!
//! Boundary adaptations relative to upstream (the algorithm code is
//! unchanged):
//!
//! * `audio::load_bytes(&[u8], ChannelChoice)` decodes from an in-memory
//!   blob via symphonia's content probing; the path-based `audio::load`
//!   delegates to it.
//! * `pipeline::decode_bytes(&[u8], &Options)` is the bytes-in/bytes-out
//!   core: it returns the report and every decoded image **in memory**
//!   (`Outcome::images`), and PNG serialization is an explicit step
//!   (`backend::encode_png`). The path-based `pipeline::run` composes over
//!   the same core and additionally writes PNGs and `report.json`.
//! * the upstream `main.rs` CLI (clap) is intentionally not migrated.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod audio;
pub mod autodetect;
pub mod backend;
pub mod dsp;
pub mod error;
pub mod modes;
pub mod ops;
pub mod pipeline;
pub mod raster;
pub mod report;
pub mod score;
pub mod sync;
pub mod synth;
pub mod vis;

use cybercipher_core::OperationRegistry;

/// Register every sstv operation into the registry.
pub fn register_all(reg: &mut OperationRegistry) {
    ops::register(reg);
}
