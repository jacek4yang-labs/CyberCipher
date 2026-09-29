//! Crypto Assist: constrained parameter-space search over known cipher
//! families. Given a ciphertext and an ambiguous key candidate, the engine
//! generates only structurally possible candidates, executes them through
//! the operation registry, scores the plaintexts, and ranks results with
//! per-candidate evidence plus a reproducible recipe.

pub mod engine;
pub mod params;
pub mod scoring;

pub use engine::{
    aes_assist, aes_assist_with_profile, recipe_ops_for, AssistHit, AssistInput, AssistResult,
    DEFAULT_DEADLINE_MS,
};
pub use params::{
    generate_candidates, AesCandidate, AesProfile, AssistProfile, IvSource, KeyInterpretation,
    Mode, Padding,
};
pub use scoring::AssistScore;
