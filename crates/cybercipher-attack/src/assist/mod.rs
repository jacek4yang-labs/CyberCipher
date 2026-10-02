//! Crypto Assist: constrained parameter-space search over known cipher
//! families. Given a ciphertext and an ambiguous key candidate, the engine
//! generates only structurally possible candidates, executes them through
//! the operation registry, scores the plaintexts, and ranks results with
//! per-candidate evidence plus a reproducible recipe.

pub mod engine;
pub mod params;
pub mod scoring;

pub use engine::{
    aes_assist, aes_assist_with_profile, assist_with_profile, camellia_assist, des_assist,
    rc4_assist, recipe_ops_for, recipe_ops_for_profile, serpent_assist, sm4_assist, tdes_assist,
    twofish_assist, AssistHit, AssistInput, AssistResult, DEFAULT_DEADLINE_MS,
};
pub use params::{
    generate_candidates, generate_profile_candidates, AesCandidate, AesProfile, AssistCandidate,
    AssistProfile, CamelliaProfile, DesProfile, IvSource, KeyInterpretation, Mode, Padding,
    Rc4Profile, SerpentProfile, Sm4Profile, TdesProfile, TwofishProfile,
};
pub use scoring::AssistScore;
