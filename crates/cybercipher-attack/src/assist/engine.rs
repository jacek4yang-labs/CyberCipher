//! The Crypto Assist engine: generate → prune → execute via the operation
//! registry → score → rank. AES is the first profile; the trait generalizes
//! the search to SM4/DES/3DES/Serpent/Twofish/Camellia/RC4 without
//! duplicating it.

// See cybercipher-core/src/lib.rs for the rationale.
#![allow(clippy::result_large_err)]

use super::params::{
    generate_profile_candidates, AesCandidate, AesProfile, AssistCandidate, AssistProfile,
    CamelliaProfile, DesProfile, IvSource, KeyInterpretation, Mode, Padding, Rc4Profile,
    SerpentProfile, Sm4Profile, TdesProfile, TwofishProfile,
};
use super::scoring::AssistScore;
use cybercipher_core::error::{OpResult, OperationError};
use cybercipher_core::{ExecutionContext, OperationRegistry, ParamMap, ParamValue, Value};
use serde::Serialize;
use std::time::{Duration, Instant};

/// Default wall-clock budget for a full assist search.
pub const DEFAULT_DEADLINE_MS: u64 = 10_000;

/// Input to the assist search.
#[derive(Debug, Clone, Default)]
pub struct AssistInput {
    /// Raw ciphertext bytes (the caller decodes the outer encoding first).
    pub ciphertext: Vec<u8>,
    /// The key candidate exactly as the user typed it.
    pub key_candidate: String,
    /// Optional explicit IV as a hex string (empty/None = not supplied).
    pub iv_hex: Option<String>,
    /// Optional known-plaintext hint (boosts matches).
    pub hint: Option<String>,
}

/// One ranked assist candidate with full evidence.
#[derive(Debug, Clone, Serialize)]
pub struct AssistHit {
    pub rank: usize,
    pub score: f64,
    pub confident: bool,
    pub cipher: String,
    pub key_length: usize,
    pub key_interpretation: KeyInterpretation,
    pub key_hex: String,
    pub mode: Mode,
    pub padding: Option<Padding>,
    pub iv_source: IvSource,
    pub iv_hex: String,
    /// Bounded lossy plaintext preview.
    pub preview: String,
    pub evidence: Vec<String>,
}

/// Full assist result.
#[derive(Debug, Clone, Serialize)]
pub struct AssistResult {
    pub hits: Vec<AssistHit>,
    pub candidates_tried: usize,
    pub candidates_pruned: usize,
    pub deadline_ms: u64,
    pub timed_out: bool,
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Run the AES assist search over the input.
pub fn aes_assist(
    registry: &OperationRegistry,
    input: &AssistInput,
    ctx: &ExecutionContext,
) -> OpResult<AssistResult> {
    assist_with_profile(registry, &AesProfile, input, ctx, DEFAULT_DEADLINE_MS)
}

/// Run the SM4 assist search over the input.
pub fn sm4_assist(
    registry: &OperationRegistry,
    input: &AssistInput,
    ctx: &ExecutionContext,
) -> OpResult<AssistResult> {
    assist_with_profile(registry, &Sm4Profile, input, ctx, DEFAULT_DEADLINE_MS)
}

/// Run the single-DES assist search over the input.
pub fn des_assist(
    registry: &OperationRegistry,
    input: &AssistInput,
    ctx: &ExecutionContext,
) -> OpResult<AssistResult> {
    assist_with_profile(registry, &DesProfile, input, ctx, DEFAULT_DEADLINE_MS)
}

/// Run the triple-DES assist search over the input.
pub fn tdes_assist(
    registry: &OperationRegistry,
    input: &AssistInput,
    ctx: &ExecutionContext,
) -> OpResult<AssistResult> {
    assist_with_profile(registry, &TdesProfile, input, ctx, DEFAULT_DEADLINE_MS)
}

/// Run the Serpent assist search over the input.
pub fn serpent_assist(
    registry: &OperationRegistry,
    input: &AssistInput,
    ctx: &ExecutionContext,
) -> OpResult<AssistResult> {
    assist_with_profile(registry, &SerpentProfile, input, ctx, DEFAULT_DEADLINE_MS)
}

/// Run the Twofish assist search over the input.
pub fn twofish_assist(
    registry: &OperationRegistry,
    input: &AssistInput,
    ctx: &ExecutionContext,
) -> OpResult<AssistResult> {
    assist_with_profile(registry, &TwofishProfile, input, ctx, DEFAULT_DEADLINE_MS)
}

/// Run the Camellia assist search over the input.
pub fn camellia_assist(
    registry: &OperationRegistry,
    input: &AssistInput,
    ctx: &ExecutionContext,
) -> OpResult<AssistResult> {
    assist_with_profile(registry, &CamelliaProfile, input, ctx, DEFAULT_DEADLINE_MS)
}

/// Run the RC4 assist search over the input.
pub fn rc4_assist(
    registry: &OperationRegistry,
    input: &AssistInput,
    ctx: &ExecutionContext,
) -> OpResult<AssistResult> {
    assist_with_profile(registry, &Rc4Profile, input, ctx, DEFAULT_DEADLINE_MS)
}

/// Generalized assist search driven by a profile.
pub fn assist_with_profile(
    registry: &OperationRegistry,
    profile: &dyn AssistProfile,
    input: &AssistInput,
    ctx: &ExecutionContext,
    deadline_ms: u64,
) -> OpResult<AssistResult> {
    if input.ciphertext.is_empty() {
        return Err(
            OperationError::invalid_input("assist needs non-empty ciphertext")
                .with_parameter("ciphertext"),
        );
    }
    let deadline = Instant::now() + Duration::from_millis(deadline_ms);

    // The explicit IV may be given as raw bytes (already decoded) or hex.
    let explicit_iv: Option<Vec<u8>> = match input.iv_hex.as_deref() {
        Some(iv_str) if !iv_str.trim().is_empty() => {
            let cleaned: String = iv_str.chars().filter(|c| !c.is_whitespace()).collect();
            let bytes = (0..cleaned.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).ok())
                .collect::<Option<Vec<u8>>>();
            match bytes {
                Some(b) => Some(b),
                None => {
                    return Err(OperationError::decode("explicit IV is not valid hex")
                        .with_parameter("iv")
                        .with_actual(iv_str))
                }
            }
        }
        _ => None,
    };

    let block_size = profile.block_size();
    let candidates = generate_profile_candidates(
        profile,
        &input.key_candidate,
        explicit_iv,
        &input.ciphertext,
    );
    let candidates_total = candidates.len();
    if candidates_total == 0 {
        return Err(OperationError::decode(
            "no structurally possible candidate: the key candidate does not decode to \
             an accepted key length for this cipher",
        )
        .with_expected(format!("a key decoding to {}", profile.key_len_desc()))
        .with_actual(format!("\"{}\"", input.key_candidate))
        .with_details(format!(
            "Accepted interpretations are {}; keys are never truncated or padded.",
            profile
                .key_interpretations()
                .iter()
                .map(|i| i.name())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    let op = registry
        .get(profile.op_id())
        .ok_or_else(|| OperationError::internal("assist: decryption op missing from registry"))?;

    let mut hits: Vec<AssistHit> = Vec::new();
    let mut tried = 0usize;
    let mut timed_out = false;

    for cand in &candidates {
        if ctx.is_cancelled() || Instant::now() >= deadline {
            timed_out = true;
            break;
        }

        // CBC with First/LastBlock: carve the IV out of the ciphertext body.
        let (body, iv): (&[u8], Vec<u8>) = match (cand.mode, cand.iv_source) {
            (Mode::Cbc, IvSource::FirstBlock) => (&input.ciphertext[block_size..], cand.iv.clone()),
            (Mode::Cbc, IvSource::LastBlock) => (
                &input.ciphertext[..input.ciphertext.len() - block_size],
                cand.iv.clone(),
            ),
            _ => (input.ciphertext.as_slice(), cand.iv.clone()),
        };
        if body.is_empty() {
            continue;
        }

        let mut map = ParamMap::new();
        map.insert("key", ParamValue::Str(hex_str(&cand.key)));
        map.insert("key_encoding", ParamValue::Str("hex".to_string()));
        // A pure stream cipher (RC4) takes no mode/IV/padding parameters.
        if cand.mode != Mode::Stream {
            map.insert("mode", ParamValue::Str(cand.mode.name().to_string()));
        }
        if cand.mode.uses_iv() {
            map.insert("iv", ParamValue::Str(hex_str(&iv)));
            map.insert("iv_encoding", ParamValue::Str("hex".to_string()));
        }
        if let Some(pad) = cand.padding {
            map.insert("padding", ParamValue::Str(pad.name().to_string()));
        }

        tried += 1;
        let decrypted = match op.execute(&Value::Bytes(body.to_vec()), &map, ctx) {
            Ok(v) => match v {
                Value::Bytes(b) => b,
                Value::Text(t) => t.into_bytes(),
                _ => continue,
            },
            // Padding/length rejections are recorded as implicit negatives:
            // the candidate executed but produced nothing to score.
            Err(_) => continue,
        };

        let score = AssistScore::of(&decrypted);
        let mut evidence = score.evidence();
        evidence.push(format!(
            "key decoded to {} bytes from {}",
            cand.key.len(),
            cand.key_interpretation.name()
        ));
        if cand.mode.uses_iv() {
            evidence.push(format!("IV from {}", cand.iv_source.name()));
        }
        if cand.mode == Mode::Stream {
            // A pure stream cipher has no padding parameter at all — the
            // evidence line must fire here, not inside the padding match
            // (stream candidates carry Padding::None and never entered it).
            evidence.push("stream cipher: no mode, IV, or padding".to_string());
        } else if let Some(pad) = cand.padding {
            match pad {
                Padding::Pkcs7 | Padding::Iso7816 => {
                    // Reaching here means the op's decrypt-side validation
                    // accepted the padding. Valid structured padding is real
                    // evidence, not just decoration: lift it (the old code
                    // recorded the line but left borderline candidates at
                    // 0.69, below confidence).
                    evidence.push(format!("{} padding valid", pad.name()));
                    total = (total + 0.05).min(1.0);
                }
                Padding::None => {
                    if cand.mode.is_stream() {
                        evidence.push("stream mode: no padding applied".to_string());
                    } else {
                        evidence.push("no padding (raw blocks)".to_string());
                    }
                }
                Padding::Zero => evidence.push("zero padding (ambiguous tail)".to_string()),
            }
        }
        if let Some(hint) = &input.hint {
            if !hint.is_empty()
                && decrypted
                    .windows(hint.len())
                    .any(|w| w.eq_ignore_ascii_case(hint.as_bytes()))
            {
                evidence.push(format!("hint \"{}\" matched in output", hint));
            }
        }

        let mut total = score.total;
        // Zero padding is ambiguous (any zero tail "matches") and a zero IV is
        // a low-confidence CTF fallback — apply small honesty penalties so
        // structurally stronger candidates rank above them at equal scores.
        if cand.padding == Some(Padding::Zero) {
            total *= 0.9;
        }
        if cand.iv_source == IvSource::Zero {
            total *= 0.9;
        }
        if let Some(hint) = &input.hint {
            if !hint.is_empty()
                && decrypted
                    .windows(hint.len())
                    .any(|w| w.eq_ignore_ascii_case(hint.as_bytes()))
            {
                total = (total + 0.30).min(1.0);
            }
        }
        let total = total.min(1.0);

        hits.push(AssistHit {
            rank: 0,
            score: (total * 1000.0).round() / 1000.0,
            confident: total >= 0.70,
            cipher: profile.name().to_string(),
            key_length: cand.key.len(),
            key_interpretation: cand.key_interpretation,
            key_hex: hex_str(&cand.key),
            mode: cand.mode,
            padding: cand.padding,
            iv_source: cand.iv_source,
            iv_hex: hex_str(&iv),
            preview: String::from_utf8_lossy(&decrypted[..decrypted.len().min(2048)]).into_owned(),
            evidence,
        });
    }

    hits.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.rank_key().cmp(&b.rank_key()))
    });
    for (i, h) in hits.iter_mut().enumerate() {
        h.rank = i + 1;
    }
    hits.truncate(24);

    Ok(AssistResult {
        hits,
        candidates_tried: tried,
        candidates_pruned: candidates_total - tried,
        deadline_ms,
        timed_out,
    })
}

/// Pre-generalization name of [`assist_with_profile`]; kept for compatibility.
pub fn aes_assist_with_profile(
    registry: &OperationRegistry,
    profile: &dyn AssistProfile,
    input: &AssistInput,
    ctx: &ExecutionContext,
    deadline_ms: u64,
) -> OpResult<AssistResult> {
    assist_with_profile(registry, profile, input, ctx, deadline_ms)
}

impl AssistHit {
    /// Deterministic secondary sort: prefer explicit IV, hex interpretation,
    /// and declared padding over fallbacks at equal score.
    fn rank_key(&self) -> (u8, u8, u8) {
        let iv_rank = match self.iv_source {
            IvSource::Explicit => 0u8,
            IvSource::FirstBlock => 1,
            IvSource::LastBlock => 2,
            IvSource::Zero => 3,
        };
        let interp_rank = match self.key_interpretation {
            KeyInterpretation::Hex => 0,
            KeyInterpretation::Base64 => 1,
            KeyInterpretation::Utf8 => 2,
        };
        (iv_rank, interp_rank, self.padding.map_or(3, |_| 0))
    }
}

/// Build the recipe steps reproducing this candidate in the Workbench for a
/// profile. The GUI serializes these into recipe nodes ("Apply as Recipe").
pub fn recipe_ops_for_profile(
    profile: &dyn AssistProfile,
    cand: &AssistCandidate,
    iv: &[u8],
) -> Vec<(String, ParamMap)> {
    let mut params = ParamMap::new();
    params.insert("key", ParamValue::Str(hex_str(&cand.key)));
    params.insert("key_encoding", ParamValue::Str("hex".to_string()));
    // A pure stream cipher (RC4) takes no mode/IV/padding parameters.
    if cand.mode != Mode::Stream {
        params.insert("mode", ParamValue::Str(cand.mode.name().to_string()));
    }
    if cand.mode.uses_iv() {
        params.insert("iv", ParamValue::Str(hex_str(iv)));
        params.insert("iv_encoding", ParamValue::Str("hex".to_string()));
    }
    if let Some(pad) = cand.padding {
        params.insert("padding", ParamValue::Str(pad.name().to_string()));
    }
    vec![(profile.op_id().to_string(), params)]
}

/// AES recipe steps reproducing this candidate (pre-generalization form).
pub fn recipe_ops_for(cand: &AesCandidate, iv: &[u8]) -> Vec<(String, ParamMap)> {
    recipe_ops_for_profile(&AesProfile, cand, iv)
}
