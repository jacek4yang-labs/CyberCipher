//! AES Assist candidate parameter space: key interpretations, modes, IV
//! sources, and padding — with structural pruning helpers.

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

/// Block cipher modes considered by AES Assist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Ecb,
    Cbc,
    Ctr,
    Cfb,
    Ofb,
}

impl Mode {
    pub fn all() -> &'static [Mode] {
        &[Mode::Ecb, Mode::Cbc, Mode::Ctr, Mode::Cfb, Mode::Ofb]
    }

    pub fn name(self) -> &'static str {
        match self {
            Mode::Ecb => "ecb",
            Mode::Cbc => "cbc",
            Mode::Ctr => "ctr",
            Mode::Cfb => "cfb",
            Mode::Ofb => "ofb",
        }
    }

    /// Modes that consume an IV/counter block.
    pub fn uses_iv(self) -> bool {
        !matches!(self, Mode::Ecb)
    }

    /// Modes whose output length equals input length (no padding applies).
    pub fn is_stream(self) -> bool {
        matches!(self, Mode::Ctr | Mode::Cfb | Mode::Ofb)
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
    /// CBC: the first 16 bytes of the ciphertext are the IV.
    FirstBlock,
    /// CBC: the last 16 bytes of the ciphertext are the IV.
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

/// One fully-resolved AES candidate ready for execution.
#[derive(Debug, Clone, PartialEq)]
pub struct AesCandidate {
    pub key_interpretation: KeyInterpretation,
    pub key: Vec<u8>,
    pub mode: Mode,
    pub padding: Option<Padding>,
    pub iv_source: IvSource,
    pub iv: Vec<u8>,
}

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

/// Cipher-family search parameters — implement to add a new family
/// (SM4/DES/Serpent/RC4) to the assist framework without duplicating search.
pub trait AssistProfile {
    /// The registry op id used for decryption (e.g. "aes-decrypt").
    fn op_id(&self) -> &'static str;
    /// Accepted decoded key lengths (pruning rule).
    fn key_lengths(&self) -> &'static [usize];
    /// Cipher name for evidence lines.
    fn name(&self) -> &'static str;
}

/// AES profile: 128/192/256.
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

/// Generate the pruned candidate list. Structurally impossible combinations
/// are dropped here so execution and scoring never waste compute.
pub fn generate_candidates(
    key_candidate: &str,
    explicit_iv: Option<Vec<u8>>,
    ciphertext: &[u8],
    block_size: usize,
    key_lengths: &[usize],
) -> Vec<AesCandidate> {
    let mut out = Vec::new();

    // Key interpretations, filtered by decoded length.
    let mut keys: Vec<(KeyInterpretation, Vec<u8>)> = Vec::new();
    for interp in KeyInterpretation::all() {
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
            if key_lengths.contains(&bytes.len()) {
                keys.push((*interp, bytes));
            }
        }
    }

    for (interp, key) in keys {
        for &mode in Mode::all() {
            // Structural pruning: block modes need block-aligned ciphertext.
            if !mode.is_stream() && !ciphertext.len().is_multiple_of(block_size) {
                continue;
            }
            let paddings: &[Option<Padding>] = if mode.is_stream() {
                &[None]
            } else {
                &[
                    Some(Padding::Pkcs7),
                    Some(Padding::None),
                    Some(Padding::Zero),
                    Some(Padding::Iso7816),
                ]
            };
            for &padding in paddings {
                if !mode.uses_iv() {
                    out.push(AesCandidate {
                        key_interpretation: interp,
                        key: key.clone(),
                        mode,
                        padding,
                        iv_source: IvSource::Explicit,
                        iv: Vec::new(),
                    });
                    continue;
                }
                for source in [
                    IvSource::Explicit,
                    IvSource::FirstBlock,
                    IvSource::LastBlock,
                    IvSource::Zero,
                ] {
                    if !source.applies(mode, explicit_iv.is_some(), ciphertext.len(), block_size) {
                        continue;
                    }
                    let iv = match source {
                        IvSource::Explicit => explicit_iv.clone().unwrap_or_default(),
                        IvSource::FirstBlock => ciphertext[..block_size].to_vec(),
                        IvSource::LastBlock => ciphertext[ciphertext.len() - block_size..].to_vec(),
                        IvSource::Zero => vec![0u8; block_size],
                    };
                    if iv.len() != 16 {
                        continue;
                    }
                    // CBC with First/LastBlock: the IV is carved from the
                    // ciphertext, so the decryption body must exclude it.
                    if iv.len() != block_size {
                        continue;
                    }
                    out.push(AesCandidate {
                        key_interpretation: interp,
                        key: key.clone(),
                        mode,
                        padding,
                        iv_source: source,
                        iv,
                    });
                }
            }
        }
    }
    out
}
