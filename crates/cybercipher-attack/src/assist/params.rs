//! Crypto Assist candidate parameter space: key interpretations, modes, IV
//! sources, and padding — with structural pruning helpers.
//!
//! The search space is profile-driven: every [`AssistProfile`] declares the
//! key lengths, key interpretations, modes, paddings, and IV sources that are
//! structurally possible for its cipher family, and
//! [`generate_profile_candidates`] enumerates only those combinations.
//! Combinations that the crypto registry would reject on key/IV/mode shape
//! (wrong key length, wrong IV length, unaligned block-mode input) are pruned
//! here — never attempted — and the total candidate count is hard-capped per
//! profile so no interpretation can explode the search.

use serde::{Deserialize, Serialize};

/// How the user-supplied key candidate string is decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyInterpretation {
    Utf8,
    Hex,
    Base64,
}

impl KeyInterpretation {
    pub fn all() -> &'static [KeyInterpretation] {
        &[
            KeyInterpretation::Utf8,
            KeyInterpretation::Hex,
            KeyInterpretation::Base64,
        ]
    }

    pub fn name(self) -> &'static str {
        match self {
            KeyInterpretation::Utf8 => "utf8",
            KeyInterpretation::Hex => "hex",
            KeyInterpretation::Base64 => "base64",
        }
    }
}

/// Modes considered by the assist framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Ecb,
    Cbc,
    Ctr,
    Cfb,
    Ofb,
    /// Pure stream cipher (RC4): no mode parameter, no IV, no padding.
    Stream,
}

/// The five block-cipher modes (everything except [`Mode::Stream`]).
pub const BLOCK_MODES: &[Mode] = &[Mode::Ecb, Mode::Cbc, Mode::Ctr, Mode::Cfb, Mode::Ofb];

impl Mode {
    /// Every mode known to the assist framework.
    pub fn all() -> &'static [Mode] {
        &[
            Mode::Ecb,
            Mode::Cbc,
            Mode::Ctr,
            Mode::Cfb,
            Mode::Ofb,
            Mode::Stream,
        ]
    }

    pub fn name(self) -> &'static str {
        match self {
            Mode::Ecb => "ecb",
            Mode::Cbc => "cbc",
            Mode::Ctr => "ctr",
            Mode::Cfb => "cfb",
            Mode::Ofb => "ofb",
            Mode::Stream => "stream",
        }
    }

    /// Modes that consume an IV/counter block.
    pub fn uses_iv(self) -> bool {
        !matches!(self, Mode::Ecb | Mode::Stream)
    }

    /// Modes whose output length equals input length (no padding applies).
    pub fn is_stream(self) -> bool {
        matches!(self, Mode::Ctr | Mode::Cfb | Mode::Ofb | Mode::Stream)
    }
}

/// Padding schemes considered (only meaningful for ECB/CBC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Padding {
    Pkcs7,
    None,
    Zero,
    Iso7816,
}

/// The AES padding set: PKCS7 plus the compatibility paddings.
const AES_BLOCK_PADDINGS: &[Padding] = &[
    Padding::Pkcs7,
    Padding::None,
    Padding::Zero,
    Padding::Iso7816,
];

/// Padding set for the newer block-cipher profiles: PKCS7 (validated on
/// decrypt — invalid padding is pruning evidence) plus raw unpadded blocks.
const PKCS7_OR_NONE: &[Padding] = &[Padding::Pkcs7, Padding::None];

/// Hex first, raw ASCII second — the interpretations used by the non-AES
/// profiles. Never silent guessing: each interpretation must decode to an
/// accepted key length on its own or it is dropped.
const HEX_THEN_ASCII: &[KeyInterpretation] =
    &[KeyInterpretation::Hex, KeyInterpretation::Utf8];

/// Every IV source (explicit, CBC carve, zero fallback).
const ALL_IV_SOURCES: &[IvSource] = &[
    IvSource::Explicit,
    IvSource::FirstBlock,
    IvSource::LastBlock,
    IvSource::Zero,
];

impl Padding {
    pub fn for_block_modes() -> &'static [Padding] {
        &[
            Padding::Pkcs7,
            Padding::None,
            Padding::Zero,
            Padding::Iso7816,
        ]
    }

    pub fn name(self) -> &'static str {
        match self {
            Padding::Pkcs7 => "pkcs7",
            Padding::None => "none",
            Padding::Zero => "zero",
            Padding::Iso7816 => "iso7816",
        }
    }
}

/// Where the IV/counter block comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IvSource {
    /// The user supplied an IV explicitly.
    Explicit,
    /// CBC: the first `block_size` bytes of the ciphertext are the IV.
    FirstBlock,
    /// CBC: the last `block_size` bytes of the ciphertext are the IV.
    LastBlock,
    /// All-zero IV — documented low-confidence CTF compatibility fallback.
    Zero,
}

impl IvSource {
    pub fn name(self) -> &'static str {
        match self {
            IvSource::Explicit => "explicit",
            IvSource::FirstBlock => "first block",
            IvSource::LastBlock => "last block",
            IvSource::Zero => "zero iv",
        }
    }

    pub fn applies(
        self,
        mode: Mode,
        has_explicit_iv: bool,
        ct_len: usize,
        block_size: usize,
    ) -> bool {
        match self {
            IvSource::Explicit => has_explicit_iv,
            IvSource::FirstBlock => mode == Mode::Cbc && ct_len >= 2 * block_size,
            IvSource::LastBlock => mode == Mode::Cbc && ct_len >= 2 * block_size,
            IvSource::Zero => mode.uses_iv(),
        }
    }
}

/// One fully-resolved candidate ready for execution. (The type predates the
/// generalization from AES to arbitrary profiles, hence the historical name.)
#[derive(Debug, Clone, PartialEq)]
pub struct AesCandidate {
    pub key_interpretation: KeyInterpretation,
    pub key: Vec<u8>,
    pub mode: Mode,
    pub padding: Option<Padding>,
    pub iv_source: IvSource,
    pub iv: Vec<u8>,
}

/// Alias used by the generalized (non-AES) entry points.
pub type AssistCandidate = AesCandidate;

/// Minimal standard-alphabet Base64 decoder (accepting missing padding) so
/// the assist module needs no external crate.
fn decode_base64_std(text: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut vals = Vec::with_capacity(text.len());
    for &b in text.as_bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        if b == b'=' {
            break;
        }
        vals.push(TABLE.iter().position(|&t| t == b)? as u32);
    }
    let mut out = Vec::with_capacity(vals.len() * 3 / 4);
    for chunk in vals.chunks(4) {
        let mut acc = 0u32;
        for (i, &v) in chunk.iter().enumerate() {
            acc |= v << (18 - 6 * i);
        }
        match chunk.len() {
            4 => out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]),
            3 => out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8]),
            2 => out.push((acc >> 16) as u8),
            _ => return None, // 1 leftover char is invalid
        }
    }
    Some(out)
}

/// Cipher-family search parameters — implement to add a cipher family to the
/// assist framework without duplicating the search. Every method is a
/// structural pruning rule: combinations outside the declared space are
/// dropped before execution, never attempted.
pub trait AssistProfile {
    /// The registry op id used for decryption (e.g. "aes-decrypt").
    fn op_id(&self) -> &'static str;
    /// Exact accepted decoded key lengths (pruning rule).
    fn key_lengths(&self) -> &'static [usize];
    /// Cipher name for evidence lines (e.g. "AES", "3DES").
    fn name(&self) -> &'static str;

    /// Inclusive variable key-length range for ciphers accepting a span of
    /// key sizes (RC4: 5-32 bytes). `None` for fixed-length families.
    fn key_range(&self) -> Option<(usize, usize)> {
        None
    }

    /// Whether a decoded key length is structurally possible for this family.
    fn key_len_ok(&self, len: usize) -> bool {
        self.key_lengths().contains(&len)
            || self
                .key_range()
                .is_some_and(|(lo, hi)| (lo..=hi).contains(&len))
    }

    /// Human-readable accepted key lengths for diagnostics.
    fn key_len_desc(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        let lengths = self.key_lengths();
        if !lengths.is_empty() {
            parts.push(
                lengths
                    .iter()
                    .map(|l| l.to_string())
                    .collect::<Vec<_>>()
                    .join("/"),
            );
        }
        if let Some((lo, hi)) = self.key_range() {
            parts.push(format!("{lo}-{hi}"));
        }
        if parts.is_empty() {
            return "no accepted key length".to_string();
        }
        format!("{} bytes", parts.join(" or "))
    }

    /// Key interpretations accepted for the candidate string, primary first.
    /// Defaults to every interpretation (AES behavior); the newer profiles
    /// accept hex plus raw ASCII so a wrong decoding is never guessed.
    fn key_interpretations(&self) -> &'static [KeyInterpretation] {
        KeyInterpretation::all()
    }

    /// Modes structurally possible for this cipher. Pure stream ciphers
    /// declare [`Mode::Stream`] only; block ciphers never include it.
    fn modes(&self) -> &'static [Mode] {
        BLOCK_MODES
    }

    /// Block size in bytes (prunes unaligned ECB/CBC input and fixes the IV
    /// width). Pure stream profiles keep the default; it is never consulted.
    fn block_size(&self) -> usize {
        16
    }

    /// Paddings considered for block modes (ECB/CBC). Stream modes are never
    /// padded.
    fn block_paddings(&self) -> &'static [Padding] {
        AES_BLOCK_PADDINGS
    }

    /// IV/counter sources considered for IV-consuming modes.
    fn iv_sources(&self) -> &'static [IvSource] {
        ALL_IV_SOURCES
    }

    /// Hard cap on generated candidates — the profile-level anti-explosion
    /// bound. The structural rules already keep real spaces tiny; the cap
    /// guarantees it stays that way.
    fn candidate_cap(&self) -> usize {
        128
    }
}

/// AES profile: 128/192/256-bit keys, 16-byte block, all five block modes,
/// every key interpretation, padding, and IV source.
pub struct AesProfile;

impl AssistProfile for AesProfile {
    fn op_id(&self) -> &'static str {
        "aes-decrypt"
    }
    fn key_lengths(&self) -> &'static [usize] {
        &[16, 24, 32]
    }
    fn name(&self) -> &'static str {
        "AES"
    }
}

/// SM4 profile (GB/T 32907): fixed 16-byte key, 16-byte block.
///
/// Modes: ECB/CBC/CTR/CFB/OFB. Every IV mode consumes exactly one 16-byte
/// block (CTR uses the whole block as a big-endian counter, matching the
/// crypto registry's convention). Padding: PKCS7 on ECB/CBC (validated on
/// decrypt — invalid padding is pruning evidence), none on the streaming
/// modes. Keys: hex or raw ASCII decoding to exactly 16 bytes.
pub struct Sm4Profile;

impl AssistProfile for Sm4Profile {
    fn op_id(&self) -> &'static str {
        "sm4-decrypt"
    }
    fn key_lengths(&self) -> &'static [usize] {
        &[16]
    }
    fn name(&self) -> &'static str {
        "SM4"
    }
    fn key_interpretations(&self) -> &'static [KeyInterpretation] {
        HEX_THEN_ASCII
    }
    fn block_paddings(&self) -> &'static [Padding] {
        PKCS7_OR_NONE
    }
}

/// DES profile (FIPS 46-3, single DES): fixed 8-byte key, 8-byte block.
///
/// Modes/IV/padding rules as for SM4 but every IV is 8 bytes (one DES block).
pub struct DesProfile;

impl AssistProfile for DesProfile {
    fn op_id(&self) -> &'static str {
        "des-decrypt"
    }
    fn key_lengths(&self) -> &'static [usize] {
        &[8]
    }
    fn name(&self) -> &'static str {
        "DES"
    }
    fn key_interpretations(&self) -> &'static [KeyInterpretation] {
        HEX_THEN_ASCII
    }
    fn block_paddings(&self) -> &'static [Padding] {
        PKCS7_OR_NONE
    }
    fn block_size(&self) -> usize {
        8
    }
}

/// Triple DES profile (EDE): 16-byte (two-key) or 24-byte (three-key) keys,
/// 8-byte block. Shares the registry op with DES — the op dispatches on the
/// decoded key length, and this profile accepts only the 3DES lengths.
pub struct TdesProfile;

impl AssistProfile for TdesProfile {
    fn op_id(&self) -> &'static str {
        "des-decrypt"
    }
    fn key_lengths(&self) -> &'static [usize] {
        &[16, 24]
    }
    fn name(&self) -> &'static str {
        "3DES"
    }
    fn key_interpretations(&self) -> &'static [KeyInterpretation] {
        HEX_THEN_ASCII
    }
    fn block_paddings(&self) -> &'static [Padding] {
        PKCS7_OR_NONE
    }
    fn block_size(&self) -> usize {
        8
    }
}

/// Serpent profile: 16/24/32-byte keys, 16-byte block, ECB/CBC/CTR/CFB/OFB.
pub struct SerpentProfile;

impl AssistProfile for SerpentProfile {
    fn op_id(&self) -> &'static str {
        "serpent-decrypt"
    }
    fn key_lengths(&self) -> &'static [usize] {
        &[16, 24, 32]
    }
    fn name(&self) -> &'static str {
        "Serpent"
    }
    fn key_interpretations(&self) -> &'static [KeyInterpretation] {
        HEX_THEN_ASCII
    }
    fn block_paddings(&self) -> &'static [Padding] {
        PKCS7_OR_NONE
    }
}

/// Twofish profile: 16/24/32-byte keys, 16-byte block, ECB/CBC/CTR/CFB/OFB.
pub struct TwofishProfile;

impl AssistProfile for TwofishProfile {
    fn op_id(&self) -> &'static str {
        "twofish-decrypt"
    }
    fn key_lengths(&self) -> &'static [usize] {
        &[16, 24, 32]
    }
    fn name(&self) -> &'static str {
        "Twofish"
    }
    fn key_interpretations(&self) -> &'static [KeyInterpretation] {
        HEX_THEN_ASCII
    }
    fn block_paddings(&self) -> &'static [Padding] {
        PKCS7_OR_NONE
    }
}

/// Camellia profile (RFC 3713): 16/24/32-byte keys, 16-byte block,
/// ECB/CBC/CTR/CFB/OFB.
pub struct CamelliaProfile;

impl AssistProfile for CamelliaProfile {
    fn op_id(&self) -> &'static str {
        "camellia-decrypt"
    }
    fn key_lengths(&self) -> &'static [usize] {
        &[16, 24, 32]
    }
    fn name(&self) -> &'static str {
        "Camellia"
    }
    fn key_interpretations(&self) -> &'static [KeyInterpretation] {
        HEX_THEN_ASCII
    }
    fn block_paddings(&self) -> &'static [Padding] {
        PKCS7_OR_NONE
    }
}

/// RC4 profile: pure stream cipher — no mode, no IV, no padding. Keys are
/// bounded to 5-32 bytes (the registry op itself accepts 1-256; the assist
/// deliberately narrows to the meaningful CTF range). Keys: hex or raw ASCII.
pub struct Rc4Profile;

impl AssistProfile for Rc4Profile {
    fn op_id(&self) -> &'static str {
        "rc4"
    }
    fn key_lengths(&self) -> &'static [usize] {
        &[]
    }
    fn key_range(&self) -> Option<(usize, usize)> {
        Some((5, 32))
    }
    fn name(&self) -> &'static str {
        "RC4"
    }
    fn key_interpretations(&self) -> &'static [KeyInterpretation] {
        HEX_THEN_ASCII
    }
    fn modes(&self) -> &'static [Mode] {
        &[Mode::Stream]
    }
}

/// The full description of one profile's candidate space, materialized so
/// generation can run without dynamic dispatch per combination.
#[derive(Debug, Clone, Copy)]
struct CandidateSpace<'a> {
    interpretations: &'a [KeyInterpretation],
    key_lengths: &'a [usize],
    key_range: Option<(usize, usize)>,
    modes: &'a [Mode],
    block_size: usize,
    block_paddings: &'a [Padding],
    iv_sources: &'a [IvSource],
    cap: usize,
}

impl<'a> CandidateSpace<'a> {
    fn from_profile(profile: &'a dyn AssistProfile) -> Self {
        CandidateSpace {
            interpretations: profile.key_interpretations(),
            key_lengths: profile.key_lengths(),
            key_range: profile.key_range(),
            modes: profile.modes(),
            block_size: profile.block_size(),
            block_paddings: profile.block_paddings(),
            iv_sources: profile.iv_sources(),
            cap: profile.candidate_cap(),
        }
    }

    fn key_len_ok(&self, len: usize) -> bool {
        self.key_lengths.contains(&len)
            || self
                .key_range
                .is_some_and(|(lo, hi)| (lo..=hi).contains(&len))
    }
}

/// Generate the pruned candidate list for a profile. Structurally impossible
/// combinations are dropped here so execution and scoring never waste
/// compute: wrong key lengths, wrong IV lengths, unaligned block-mode input,
/// and modes/paddings the family does not support are all pruned, and the
/// total is capped by [`AssistProfile::candidate_cap`].
pub fn generate_profile_candidates(
    profile: &dyn AssistProfile,
    key_candidate: &str,
    explicit_iv: Option<Vec<u8>>,
    ciphertext: &[u8],
) -> Vec<AssistCandidate> {
    let space = CandidateSpace::from_profile(profile);
    generate_with_space(&space, key_candidate, explicit_iv.as_deref(), ciphertext)
}

/// Legacy AES-shaped entry point kept for compatibility: every interpretation,
/// all five block modes, all paddings, and all IV sources at the given block
/// size and key lengths.
pub fn generate_candidates(
    key_candidate: &str,
    explicit_iv: Option<Vec<u8>>,
    ciphertext: &[u8],
    block_size: usize,
    key_lengths: &[usize],
) -> Vec<AesCandidate> {
    let space = CandidateSpace {
        interpretations: KeyInterpretation::all(),
        key_lengths,
        key_range: None,
        modes: BLOCK_MODES,
        block_size,
        block_paddings: AES_BLOCK_PADDINGS,
        iv_sources: ALL_IV_SOURCES,
        cap: 256,
    };
    generate_with_space(&space, key_candidate, explicit_iv.as_deref(), ciphertext)
}

/// The single generation algorithm shared by every profile: decode keys →
/// filter by length → cross with declared modes → apply alignment/padding/
/// IV-source structural rules → cap.
fn generate_with_space(
    space: &CandidateSpace,
    key_candidate: &str,
    explicit_iv: Option<&[u8]>,
    ciphertext: &[u8],
) -> Vec<AesCandidate> {
    let mut out = Vec::new();

    // Key interpretations, filtered by decoded length.
    let mut keys: Vec<(KeyInterpretation, Vec<u8>)> = Vec::new();
    for interp in space.interpretations {
        let decoded = match interp {
            KeyInterpretation::Utf8 => Some(key_candidate.as_bytes().to_vec()),
            KeyInterpretation::Hex => {
                let cleaned: String = key_candidate
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect();
                if !cleaned.len().is_multiple_of(2) {
                    None
                } else {
                    (0..cleaned.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).ok())
                        .collect::<Option<Vec<u8>>>()
                }
            }
            KeyInterpretation::Base64 => decode_base64_std(key_candidate.trim()),
        };
        if let Some(bytes) = decoded {
            if space.key_len_ok(bytes.len()) {
                keys.push((*interp, bytes));
            }
        }
    }

    'keys: for (interp, key) in keys {
        for &mode in space.modes {
            if out.len() >= space.cap {
                break 'keys;
            }
            // Structural pruning: block modes need block-aligned ciphertext.
            if !mode.is_stream() && !ciphertext.len().is_multiple_of(space.block_size) {
                continue;
            }
            if mode.is_stream() {
                emit_iv_variants(
                    space,
                    &mut out,
                    interp,
                    &key,
                    mode,
                    None,
                    explicit_iv,
                    ciphertext,
                );
            } else {
                for &padding in space.block_paddings {
                    emit_iv_variants(
                        space,
                        &mut out,
                        interp,
                        &key,
                        mode,
                        Some(padding),
                        explicit_iv,
                        ciphertext,
                    );
                }
            }
        }
    }
    out.truncate(space.cap);
    out
}

/// Push one (key, mode, padding) combination across the profile's IV sources,
/// applying the per-source structural rules and the IV-width rule: every
/// IV-consuming mode of a family takes exactly one block (CBC/CFB/OFB
/// feedback IV, CTR full-block counter). A wrong-length explicit IV is
/// pruned here, never attempted.
#[allow(clippy::too_many_arguments)]
fn emit_iv_variants(
    space: &CandidateSpace,
    out: &mut Vec<AesCandidate>,
    interp: KeyInterpretation,
    key: &[u8],
    mode: Mode,
    padding: Option<Padding>,
    explicit_iv: Option<&[u8]>,
    ciphertext: &[u8],
) {
    if !mode.uses_iv() {
        out.push(AesCandidate {
            key_interpretation: interp,
            key: key.to_vec(),
            mode,
            padding,
            iv_source: IvSource::Explicit,
            iv: Vec::new(),
        });
        return;
    }
    for &source in space.iv_sources {
        if out.len() >= space.cap {
            return;
        }
        if !source.applies(mode, explicit_iv.is_some(), ciphertext.len(), space.block_size) {
            continue;
        }
        let iv = match source {
            IvSource::Explicit => explicit_iv.unwrap_or_default().to_vec(),
            IvSource::FirstBlock => ciphertext[..space.block_size].to_vec(),
            IvSource::LastBlock => ciphertext[ciphertext.len() - space.block_size..].to_vec(),
            IvSource::Zero => vec![0u8; space.block_size],
        };
        if iv.len() != space.block_size {
            continue;
        }
        out.push(AesCandidate {
            key_interpretation: interp,
            key: key.to_vec(),
            mode,
            padding,
            iv_source: source,
            iv,
        });
    }
}
