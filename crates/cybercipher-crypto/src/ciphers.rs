//! Symmetric block cipher operations: AES, DES/3DES, SM4, Serpent, Twofish,
//! Blowfish, Camellia, ARIA, CAST5, IDEA, RC2, RC5, RC6, Threefish, Magma and
//! Kuznyechik (block modes with orthogonal padding policy), plus native RC4.
//!
//! Design rules:
//! - Key/IV decoding is explicit (encoding selector + strict length checks
//!   with expected/actual diagnostics). No silent re-interpretation.
//! - Padding is a separate policy parameter; decryption validates padding
//!   and reports structured errors instead of returning garbage silently.
//! - Every block cipher plugs into ONE shared engine abstraction
//!   ([`BlockEngine`]); the mode wiring (ECB/CBC/CTR/CFB-128/OFB) is written
//!   once against that trait, so adding a cipher is a table row — not a new
//!   set of mode bindings (charter §21: orthogonal Cipher x Mode x Padding).
//! - RustCrypto crates provide the primitives; this module owns mode wiring
//!   and validation.

use cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit};
use cybercipher_codec::decode_input;
use cybercipher_core::prelude::*;
use cybercipher_core::Security;
use rc5::RC5;
use rc6::RC6;

type Rc5 = RC5<u32, cipher::consts::U12, cipher::consts::U16>;
type Rc6 = RC6<u32, cipher::consts::U20, cipher::consts::U16>;

use crate::helpers::{decode_material, p_enc, p_text};

// ------------------------------------------------------ engine layer ----

/// A keyed block-cipher instance exposing raw block operations.
///
/// This is CyberCipher's own vtable: it deliberately does not depend on a
/// specific `cipher` crate trait version, so cipher crates from any
/// RustCrypto generation can sit behind it and share the mode plumbing.
trait BlockEngine: Send + Sync {
    fn block_size(&self) -> usize;
    fn encrypt_block(&self, block: &mut [u8]);
    fn decrypt_block(&self, block: &mut [u8]);
}

/// Adapter that lifts any RustCrypto block cipher (encrypt + decrypt +
/// compile-time block size) into a [`BlockEngine`].
struct Engine<C> {
    cipher: C,
}

impl<C> BlockEngine for Engine<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + BlockSizeUser + Send + Sync + 'static,
{
    fn block_size(&self) -> usize {
        C::block_size()
    }

    fn encrypt_block(&self, block: &mut [u8]) {
        let arr: &mut Block<C> = block
            .try_into()
            .expect("chunk length equals the cipher block size");
        self.cipher.encrypt_block(arr);
    }

    fn decrypt_block(&self, block: &mut [u8]) {
        let arr: &mut Block<C> = block
            .try_into()
            .expect("chunk length equals the cipher block size");
        self.cipher.decrypt_block(arr);
    }
}

/// Build an engine from a cipher type via `KeyInit`.
fn keyed<C>(key: &[u8]) -> OpResult<Box<dyn BlockEngine>>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + BlockSizeUser + KeyInit + Send + Sync + 'static,
{
    let cipher = C::new_from_slice(key)
        .map_err(|_| OperationError::internal("cipher key rejected by the primitive"))?;
    Ok(Box::new(Engine { cipher }))
}

// -------------------------------------------------- cipher registry ----

/// How wide a cipher's blocks are.
#[derive(Debug, Clone, Copy)]
enum BlockWidth {
    /// Fixed block size in bytes (all ciphers here except Threefish).
    Fixed(usize),
    /// Threefish-256/512/1024: the block width equals the key length.
    SameAsKey,
}

/// Static description of one block cipher. Adding a cipher to CyberCipher
/// means adding one of these rows plus a factory; nothing else changes.
struct BlockCipherEntry {
    /// Op-id prefix (`<id>-encrypt` / `<id>-decrypt`).
    id: &'static str,
    /// Human name used in specs, errors, and aliases.
    display: &'static str,
    /// Exact key lengths in bytes; empty means the `key_range` applies.
    key_lengths: &'static [usize],
    /// Inclusive (min, max) key length in bytes for variable-key ciphers.
    key_range: (usize, usize),
    /// Block width of the primitive.
    width: BlockWidth,
    /// Security classification shown in the spec.
    security: Security,
    /// Ciphers such as Threefish require a 16-byte tweak even in ECB mode.
    tweak_required: bool,
    /// Provenance: (standard, implementation, test vectors).
    provenance: (&'static str, &'static str, &'static str),
    /// Key/block summary sentence used in op descriptions.
    shape: &'static str,
    /// Build a keyed engine from (key, tweak). `tweak` is empty unless
    /// `tweak_required` is set.
    #[allow(clippy::type_complexity)]
    factory: fn(&[u8], &[u8]) -> OpResult<Box<dyn BlockEngine>>,
}

impl BlockCipherEntry {
    fn key_len_ok(&self, len: usize) -> bool {
        if self.key_lengths.is_empty() {
            (self.key_range.0..=self.key_range.1).contains(&len)
        } else {
            self.key_lengths.contains(&len)
        }
    }

    fn key_len_desc(&self) -> String {
        if self.key_lengths.is_empty() {
            format!("{}-{}", self.key_range.0, self.key_range.1)
        } else {
            self.key_lengths
                .iter()
                .map(|l| l.to_string())
                .collect::<Vec<_>>()
                .join(" / ")
        }
    }

    /// Runtime block size for a validated key length.
    fn block_size(&self, key_len: usize) -> usize {
        match self.width {
            BlockWidth::Fixed(size) => size,
            BlockWidth::SameAsKey => key_len,
        }
    }

    /// Bytes required from the `iv` parameter (the Threefish tweak is
    /// always 16 bytes wide, regardless of the block size).
    fn iv_len(&self) -> usize {
        if self.tweak_required {
            16
        } else {
            match self.width {
                BlockWidth::Fixed(size) => size,
                BlockWidth::SameAsKey => 16,
            }
        }
    }

    /// Resolve the concrete engine for (key, tweak), validating lengths.
    fn engine(&self, key: &[u8], tweak: &[u8]) -> OpResult<Box<dyn BlockEngine>> {
        if !self.key_len_ok(key.len()) {
            return Err(key_error(self, key.len()));
        }
        (self.factory)(key, tweak)
    }
}

fn key_error(entry: &BlockCipherEntry, actual: usize) -> OperationError {
    OperationError::key(format!(
        "{} key must be {} bytes after decoding, got {} bytes",
        entry.display,
        entry.key_len_desc(),
        actual
    ))
    .with_parameter("key")
    .with_expected(entry.key_len_desc())
    .with_actual(format!("{actual} bytes"))
}

fn iv_error(entry: &BlockCipherEntry, actual: usize, expected: usize) -> OperationError {
    let what = if entry.tweak_required {
        if expected == 16 {
            "tweak"
        } else {
            "IV (first 16 bytes are the tweak)"
        }
    } else {
        "IV"
    };
    OperationError::key(format!(
        "{} {} must be {expected} bytes after decoding, got {actual} bytes",
        entry.display, what
    ))
    .with_parameter("iv")
    .with_expected(format!("{expected} bytes"))
    .with_actual(format!("{actual} bytes"))
}

// Cipher factories. Each is a few lines: pick the concrete RustCrypto type
// from the (validated) key length and hand it to the shared engine adapter.

fn make_aes(key: &[u8], _tweak: &[u8]) -> OpResult<Box<dyn BlockEngine>> {
    match key.len() {
        16 => keyed::<aes::Aes128>(key),
        24 => keyed::<aes::Aes192>(key),
        _ => keyed::<aes::Aes256>(key),
    }
}

fn make_des(key: &[u8], _tweak: &[u8]) -> OpResult<Box<dyn BlockEngine>> {
    match key.len() {
        8 => keyed::<des::Des>(key),
        16 => keyed::<des::TdesEde2>(key),
        _ => keyed::<des::TdesEde3>(key),
    }
}

fn make_camellia(key: &[u8], _tweak: &[u8]) -> OpResult<Box<dyn BlockEngine>> {
    match key.len() {
        16 => keyed::<camellia::Camellia128>(key),
        24 => keyed::<camellia::Camellia192>(key),
        _ => keyed::<camellia::Camellia256>(key),
    }
}

fn make_aria(key: &[u8], _tweak: &[u8]) -> OpResult<Box<dyn BlockEngine>> {
    match key.len() {
        16 => keyed::<aria::Aria128>(key),
        24 => keyed::<aria::Aria192>(key),
        _ => keyed::<aria::Aria256>(key),
    }
}

fn make_threefish(key: &[u8], tweak: &[u8]) -> OpResult<Box<dyn BlockEngine>> {
    if tweak.len() != 16 {
        return Err(iv_error(
            &BLOCK_THREEFISH,
            tweak.len(),
            BLOCK_THREEFISH.iv_len(),
        ));
    }
    let tweak: [u8; 16] = tweak.try_into().expect("checked 16 bytes");
    match key.len() {
        32 => {
            let key: [u8; 32] = key.try_into().expect("checked 32 bytes");
            Ok(Box::new(Engine {
                cipher: threefish::Threefish256::new_with_tweak(&key, &tweak),
            }))
        }
        64 => {
            let key: [u8; 64] = key.try_into().expect("checked 64 bytes");
            Ok(Box::new(Engine {
                cipher: threefish::Threefish512::new_with_tweak(&key, &tweak),
            }))
        }
        _ => {
            let key: [u8; 128] = key.try_into().expect("checked 128 bytes");
            Ok(Box::new(Engine {
                cipher: threefish::Threefish1024::new_with_tweak(&key, &tweak),
            }))
        }
    }
}

const BLOCK_THREEFISH: BlockCipherEntry = BlockCipherEntry {
    id: "threefish",
    display: "Threefish",
    key_lengths: &[32, 64, 128],
    key_range: (32, 128),
    width: BlockWidth::SameAsKey,
    security: Security::Modern,
    tweak_required: true,
    provenance: (
        "Threefish (Skein hash core; Schneier et al.)",
        "RustCrypto `threefish` crate",
        "Crypto++ Threefish test vectors",
    ),
    shape: "32/64/128-byte keys; the iv parameter carries the mandatory 16-byte tweak.",
    factory: make_threefish,
};

/// The registry: every block cipher exposed by CyberCipher's
/// `<algo>-encrypt` / `<algo>-decrypt` operations.
const BLOCK_CIPHERS: &[BlockCipherEntry] = &[
    BlockCipherEntry {
        id: "aes",
        display: "AES",
        key_lengths: &[16, 24, 32],
        key_range: (16, 32),
        width: BlockWidth::Fixed(16),
        security: Security::Modern,
        tweak_required: false,
        provenance: (
            "NIST FIPS 197 + SP 800-38 family",
            "RustCrypto `aes` crate",
            "NIST SP 800-38A / FIPS 197 known-answer tests",
        ),
        shape: "16/24/32-byte keys, 16-byte block.",
        factory: make_aes,
    },
    BlockCipherEntry {
        id: "des",
        display: "DES / 3DES",
        key_lengths: &[8, 16, 24],
        key_range: (8, 24),
        width: BlockWidth::Fixed(8),
        security: Security::Broken,
        tweak_required: false,
        provenance: (
            "FIPS 46-3 (withdrawn); NIST SP 800-67 for 3DES",
            "RustCrypto `des` crate",
            "Classic DES known-answer tests",
        ),
        shape: "8-byte key for DES or 16/24-byte key for 3DES, 8-byte block.",
        factory: make_des,
    },
    BlockCipherEntry {
        id: "sm4",
        display: "SM4",
        key_lengths: &[16],
        key_range: (16, 16),
        width: BlockWidth::Fixed(16),
        security: Security::Modern,
        tweak_required: false,
        provenance: (
            "GB/T 32907-2016",
            "RustCrypto `sm4` crate",
            "GB/T 32907 standard example",
        ),
        shape: "16-byte key, 16-byte block.",
        factory: |key, _| keyed::<sm4::Sm4>(key),
    },
    BlockCipherEntry {
        id: "serpent",
        display: "Serpent",
        key_lengths: &[16, 24, 32],
        key_range: (16, 32),
        width: BlockWidth::Fixed(16),
        security: Security::Modern,
        tweak_required: false,
        provenance: (
            "Serpent AES submission; ISO/IEC 18033-3; NESSIE",
            "RustCrypto `serpent` crate",
            "NESSIE Serpent verified test vectors",
        ),
        shape: "16/24/32-byte keys, 16-byte block.",
        factory: |key, _| keyed::<serpent::Serpent>(key),
    },
    BlockCipherEntry {
        id: "twofish",
        display: "Twofish",
        key_lengths: &[16, 24, 32],
        key_range: (16, 32),
        width: BlockWidth::Fixed(16),
        security: Security::Modern,
        tweak_required: false,
        provenance: (
            "Twofish AES submission (Schneier et al.)",
            "RustCrypto `twofish` crate",
            "Twofish submission test vectors",
        ),
        shape: "16/24/32-byte keys, 16-byte block.",
        factory: |key, _| keyed::<twofish::Twofish>(key),
    },
    BlockCipherEntry {
        id: "blowfish",
        display: "Blowfish",
        key_lengths: &[],
        key_range: (4, 56),
        width: BlockWidth::Fixed(8),
        security: Security::Legacy,
        tweak_required: false,
        provenance: (
            "Original Blowfish (Schneier, 1993)",
            "RustCrypto `blowfish` crate",
            "Eric Young's Blowfish test vectors",
        ),
        shape: "variable 4-56 byte keys, 8-byte block.",
        factory: |key, _| keyed::<blowfish::Blowfish>(key),
    },
    BlockCipherEntry {
        id: "camellia",
        display: "Camellia",
        key_lengths: &[16, 24, 32],
        key_range: (16, 32),
        width: BlockWidth::Fixed(16),
        security: Security::Modern,
        tweak_required: false,
        provenance: (
            "RFC 3713; ISO/IEC 18033-3; CRYPTREC",
            "RustCrypto `camellia` crate",
            "RFC 3713 test vectors / NESSIE",
        ),
        shape: "16/24/32-byte keys, 16-byte block.",
        factory: make_camellia,
    },
    BlockCipherEntry {
        id: "aria",
        display: "ARIA",
        key_lengths: &[16, 24, 32],
        key_range: (16, 32),
        width: BlockWidth::Fixed(16),
        security: Security::Modern,
        tweak_required: false,
        provenance: (
            "KS X 1213; RFC 5794 (Korean standard)",
            "RustCrypto `aria` crate",
            "RFC 5794 Appendix A test vectors",
        ),
        shape: "16/24/32-byte keys, 16-byte block.",
        factory: make_aria,
    },
    BlockCipherEntry {
        id: "cast5",
        display: "CAST5",
        key_lengths: &[],
        key_range: (5, 16),
        width: BlockWidth::Fixed(8),
        security: Security::Modern,
        tweak_required: false,
        provenance: (
            "RFC 2144",
            "RustCrypto `cast5` crate",
            "RFC 2144 Appendix B test vectors",
        ),
        shape: "5-16 byte keys, 8-byte block.",
        factory: |key, _| keyed::<cast5::Cast5>(key),
    },
    BlockCipherEntry {
        id: "cast6",
        display: "CAST6",
        key_lengths: &[16, 20, 24, 28, 32],
        key_range: (16, 32),
        width: BlockWidth::Fixed(16),
        security: Security::Modern,
        tweak_required: false,
        provenance: (
            "RFC 2612 (CAST-256, AES candidate)",
            "RustCrypto `cast6` crate",
            "RFC 2612 Appendix A test vectors",
        ),
        shape: "16/20/24/28/32-byte keys, 16-byte block.",
        factory: |key, _| keyed::<cast6::Cast6>(key),
    },
    BlockCipherEntry {
        id: "idea",
        display: "IDEA",
        key_lengths: &[16],
        key_range: (16, 16),
        width: BlockWidth::Fixed(8),
        security: Security::Legacy,
        tweak_required: false,
        provenance: (
            "Original IDEA (Lai & Massey, 1991); PGP legacy",
            "RustCrypto `idea` crate",
            "NESSIE IDEA verified test vectors",
        ),
        shape: "16-byte key, 8-byte block.",
        factory: |key, _| keyed::<idea::Idea>(key),
    },
    BlockCipherEntry {
        id: "rc2",
        display: "RC2",
        key_lengths: &[],
        key_range: (1, 16),
        width: BlockWidth::Fixed(8),
        security: Security::Legacy,
        tweak_required: false,
        provenance: (
            "RFC 2268",
            "RustCrypto `rc2` crate",
            "RFC 2268 section 5 test vectors",
        ),
        shape: "1-16 byte keys (effective key length equals the key bits), 8-byte block.",
        factory: |key, _| keyed::<rc2::Rc2>(key),
    },
    BlockCipherEntry {
        id: "rc5",
        display: "RC5",
        key_lengths: &[16],
        key_range: (16, 16),
        width: BlockWidth::Fixed(8),
        security: Security::Modern,
        tweak_required: false,
        provenance: (
            "Original RC5-32/12/16 (Rivest)",
            "RustCrypto `rc5` crate",
            "draft-krovetz-rc6-rc5-vectors (IETF)",
        ),
        shape: "16-byte key, 8-byte block.",
        factory: |key, _| keyed::<Rc5>(key),
    },
    BlockCipherEntry {
        id: "rc6",
        display: "RC6",
        key_lengths: &[16],
        key_range: (16, 16),
        width: BlockWidth::Fixed(16),
        security: Security::Modern,
        tweak_required: false,
        provenance: (
            "Original RC6-32/20/16 (Rivest et al., AES finalist)",
            "RustCrypto `rc6` crate",
            "draft-krovetz-rc6-rc5-vectors (IETF)",
        ),
        shape: "16-byte key, 16-byte block.",
        factory: |key, _| keyed::<Rc6>(key),
    },
    BLOCK_THREEFISH,
    BlockCipherEntry {
        id: "magma",
        display: "Magma",
        key_lengths: &[32],
        key_range: (32, 32),
        width: BlockWidth::Fixed(8),
        security: Security::Legacy,
        tweak_required: false,
        provenance: (
            "GOST R 34.12-2015 (Magma, 64-bit block)",
            "RustCrypto `magma` crate",
            "GOST R 34.12-2015 test vectors",
        ),
        shape: "32-byte key, 8-byte block.",
        factory: |key, _| keyed::<magma::Magma>(key),
    },
    BlockCipherEntry {
        id: "kuznyechik",
        display: "Kuznyechik",
        key_lengths: &[32],
        key_range: (32, 32),
        width: BlockWidth::Fixed(16),
        security: Security::Legacy,
        tweak_required: false,
        provenance: (
            "GOST R 34.12-2015 (Kuznyechik, 128-bit block)",
            "RustCrypto `kuznyechik` crate",
            "GOST R 34.12-2015 test vectors",
        ),
        shape: "32-byte key, 16-byte block.",
        factory: |key, _| keyed::<kuznyechik::Kuznyechik>(key),
    },
];

fn resolve_entry(op_id: &str) -> OpResult<&'static BlockCipherEntry> {
    BLOCK_CIPHERS
        .iter()
        .find(|e| op_id.starts_with(e.id))
        .ok_or_else(|| OperationError::internal("unknown cipher op"))
}

// ------------------------------------------------------- modes ----

#[derive(Debug, Clone, Copy, PartialEq)]
enum Mode {
    Ecb,
    Cbc,
    Ctr,
    Cfb,
    Ofb,
    CbcCs1,
    CbcCs2,
    CbcCs3,
}

impl Mode {
    fn parse(s: &str) -> OpResult<Mode> {
        match s {
            "ecb" => Ok(Mode::Ecb),
            "cbc" => Ok(Mode::Cbc),
            "ctr" => Ok(Mode::Ctr),
            "cfb" => Ok(Mode::Cfb),
            "ofb" => Ok(Mode::Ofb),
            "cbc-cs1" => Ok(Mode::CbcCs1),
            "cbc-cs2" => Ok(Mode::CbcCs2),
            "cbc-cs3" => Ok(Mode::CbcCs3),
            other => Err(OperationError::invalid_param(
                "mode",
                format!("unknown block cipher mode `{other}`"),
            )),
        }
    }

    fn uses_iv(self) -> bool {
        !matches!(self, Mode::Ecb)
    }

    /// Modes whose output length equals the input length for any alignment:
    /// the stream modes and the ciphertext-stealing CBC variants (NIST
    /// SP 800-38A addendum), which have no padding concept.
    fn length_preserving(self) -> bool {
        matches!(
            self,
            Mode::Ctr | Mode::Cfb | Mode::Ofb | Mode::CbcCs1 | Mode::CbcCs2 | Mode::CbcCs3
        )
    }

    fn as_str(self) -> &'static str {
        match self {
            Mode::Ecb => "ecb",
            Mode::Cbc => "cbc",
            Mode::Ctr => "ctr",
            Mode::Cfb => "cfb",
            Mode::Ofb => "ofb",
            Mode::CbcCs1 => "cbc-cs1",
            Mode::CbcCs2 => "cbc-cs2",
            Mode::CbcCs3 => "cbc-cs3",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Padding {
    Pkcs7,
    None,
    Zero,
    Iso7816,
}

impl Padding {
    fn parse(s: &str) -> OpResult<Padding> {
        match s {
            "pkcs7" => Ok(Padding::Pkcs7),
            "none" => Ok(Padding::None),
            "zero" => Ok(Padding::Zero),
            "iso7816" => Ok(Padding::Iso7816),
            other => Err(OperationError::invalid_param(
                "padding",
                format!("unknown padding scheme `{other}`"),
            )),
        }
    }
}

/// Apply padding so the data fills whole blocks.
fn pad(data: &[u8], block: usize, padding: Padding) -> OpResult<Vec<u8>> {
    let rem = data.len() % block;
    match padding {
        Padding::None => {
            if rem != 0 {
                return Err(OperationError::length(
                    format!("multiple of {block} bytes (no padding)"),
                    format!("{} bytes", data.len()),
                    "input length is not a multiple of the block size",
                )
                .with_details(
                    "Choose a padding scheme (PKCS7 is standard) or use a stream mode like CTR/CFB/OFB.",
                ));
            }
            Ok(data.to_vec())
        }
        Padding::Pkcs7 => {
            let n = (block - rem) as u8;
            let mut out = data.to_vec();
            out.extend(std::iter::repeat_n(n, n as usize));
            Ok(out)
        }
        Padding::Zero => {
            let mut out = data.to_vec();
            if rem != 0 {
                out.extend(std::iter::repeat_n(0u8, block - rem));
            }
            Ok(out)
        }
        Padding::Iso7816 => {
            let mut out = data.to_vec();
            out.push(0x80);
            let rem = out.len() % block;
            if rem != 0 {
                out.extend(std::iter::repeat_n(0u8, block - rem));
            }
            Ok(out)
        }
    }
}

/// Remove padding after decryption, with structured validation errors.
fn unpad(data: &[u8], block: usize, padding: Padding) -> OpResult<Vec<u8>> {
    match padding {
        Padding::None => Ok(data.to_vec()),
        Padding::Zero => {
            let end = data
                .iter()
                .rposition(|&b| b != 0)
                .map(|p| p + 1)
                .unwrap_or(0);
            Ok(data[..end].to_vec())
        }
        Padding::Pkcs7 => {
            let last = data
                .last()
                .copied()
                .ok_or_else(|| OperationError::new(ErrorKind::Decode, "PKCS7: empty plaintext"))?;
            if last == 0 || last as usize > block {
                return Err(padding_error(block, last, "padding length out of range"));
            }
            if !data.ends_with(&vec![last; last as usize]) {
                return Err(padding_error(
                    block,
                    last,
                    "padding bytes are not all equal to the padding length",
                ));
            }
            Ok(data[..data.len() - last as usize].to_vec())
        }
        Padding::Iso7816 => {
            let end = data
                .iter()
                .rposition(|&b| b != 0)
                .ok_or_else(|| padding_error(block, 0, "no 0x80 marker found"))?;
            if data[end] != 0x80 {
                return Err(padding_error(
                    block,
                    data[end],
                    "expected 0x80 marker before zero padding",
                ));
            }
            Ok(data[..end].to_vec())
        }
    }
}

fn padding_error(block: usize, last: u8, why: &str) -> OperationError {
    OperationError::decode(format!("PKCS7 padding is invalid: {why}"))
        .with_expected(format!("valid padding within {block}-byte blocks"))
        .with_actual(format!("last block ends with 0x{last:02x}"))
        .with_details(
            "Wrong key, wrong mode, or wrong IV usually produce invalid padding — check those first.",
        )
}

// The five mode wirings, implemented ONCE over `dyn BlockEngine` and shared
// by every cipher in the registry.

fn ecb_apply(engine: &dyn BlockEngine, data: &mut [u8], encrypt: bool) {
    let bs = engine.block_size();
    for chunk in data.chunks_mut(bs) {
        if encrypt {
            engine.encrypt_block(chunk);
        } else {
            engine.decrypt_block(chunk);
        }
    }
}

fn cbc_encrypt(engine: &dyn BlockEngine, iv: &[u8], data: &mut [u8]) {
    let bs = engine.block_size();
    let mut prev = iv[..bs].to_vec();
    for chunk in data.chunks_mut(bs) {
        for (b, p) in chunk.iter_mut().zip(&prev) {
            *b ^= p;
        }
        engine.encrypt_block(chunk);
        prev.copy_from_slice(chunk);
    }
}

fn cbc_decrypt(engine: &dyn BlockEngine, iv: &[u8], data: &mut [u8]) {
    let bs = engine.block_size();
    let mut prev = iv[..bs].to_vec();
    for chunk in data.chunks_mut(bs) {
        let cur = chunk.to_vec();
        engine.decrypt_block(chunk);
        for (b, p) in chunk.iter_mut().zip(&prev) {
            *b ^= p;
        }
        prev = cur;
    }
}

/// CTR with a block-size big-endian counter (identical to Ctr128BE for
/// 16-byte blocks; the whole block is the counter).
fn ctr_apply(engine: &dyn BlockEngine, iv: &[u8], data: &mut [u8]) {
    let bs = engine.block_size();
    let mut counter = iv[..bs].to_vec();
    for chunk in data.chunks_mut(bs) {
        let mut ks = counter.clone();
        engine.encrypt_block(&mut ks);
        for (b, k) in chunk.iter_mut().zip(&ks) {
            *b ^= k;
        }
        for byte in counter.iter_mut().rev() {
            let (next, overflow) = byte.overflowing_add(1);
            *byte = next;
            if !overflow {
                break;
            }
        }
    }
}

/// OFB with block-size feedback: keystream block 0 = E(IV).
fn ofb_apply(engine: &dyn BlockEngine, iv: &[u8], data: &mut [u8]) {
    let bs = engine.block_size();
    let mut ks = iv[..bs].to_vec();
    for chunk in data.chunks_mut(bs) {
        engine.encrypt_block(&mut ks);
        for (b, k) in chunk.iter_mut().zip(&ks) {
            *b ^= k;
        }
    }
}

/// CFB-128 with partial final block, matching the classic construction:
/// C_i = P_i XOR E(C_{i-1}); the IV advances with full ciphertext blocks.
/// Implemented directly because RustCrypto exposes CFB only through the
/// padded block-mode API, which cannot express a partial final block.
fn cfb_encrypt(engine: &dyn BlockEngine, iv: &[u8], data: &[u8]) -> Vec<u8> {
    let bs = engine.block_size();
    let mut prev = iv[..bs].to_vec();
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(bs) {
        engine.encrypt_block(&mut prev);
        let ciphered: Vec<u8> = chunk.iter().zip(prev.iter()).map(|(a, b)| a ^ b).collect();
        if chunk.len() == bs {
            prev.copy_from_slice(&ciphered);
        }
        out.extend_from_slice(&ciphered);
    }
    out
}

fn cfb_decrypt(engine: &dyn BlockEngine, iv: &[u8], data: &[u8]) -> Vec<u8> {
    let bs = engine.block_size();
    let mut prev = iv[..bs].to_vec();
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(bs) {
        engine.encrypt_block(&mut prev);
        let plain: Vec<u8> = chunk.iter().zip(prev.iter()).map(|(a, b)| a ^ b).collect();
        if chunk.len() == bs {
            prev.copy_from_slice(chunk);
        }
        out.extend_from_slice(&plain);
    }
    out
}

// ------------------------------------ CBC ciphertext stealing (CTS) ----
// The three NIST SP 800-38A addendum variants. CBC-CS1/CS2/CS3 share the
// CS1 core and differ only in how the two final output blocks are ordered:
// CS1 keeps the (truncated) penultimate block before the last full block,
// CS2 swaps them when the final plaintext block is partial, and CS3 swaps
// unconditionally (the Kerberos 5 variant, RFC 3962).

#[derive(Debug, Clone, Copy, PartialEq)]
enum CtsVariant {
    Cs1,
    Cs2,
    Cs3,
}

fn cts_length_error(actual: usize, bs: usize) -> OperationError {
    OperationError::length(
        format!("at least {bs} bytes (one full block)"),
        format!("{actual} bytes"),
        "ciphertext-stealing CBC requires at least one full block",
    )
    .with_parameter("input")
}

/// CBC-CS1-Encrypt: plain CBC over the complete blocks, then the final
/// partial plaintext block is zero-padded, chained on the last ciphertext
/// block and encrypted; the tail of that block is stolen into the position
/// of the truncated penultimate block.
fn cbc_cs1_encrypt(engine: &dyn BlockEngine, iv: &[u8], data: &[u8]) -> OpResult<Vec<u8>> {
    let bs = engine.block_size();
    let n = data.len();
    if n < bs {
        return Err(cts_length_error(n, bs));
    }
    let d = n % bs;
    if d == 0 {
        let mut buf = data.to_vec();
        cbc_encrypt(engine, iv, &mut buf);
        return Ok(buf);
    }
    let complete = n - d;
    let mut buf = data[..complete].to_vec();
    cbc_encrypt(engine, iv, &mut buf);
    let last_ct = buf[complete - bs..].to_vec();
    // Final block: zero-pad the partial plaintext, XOR the chained block.
    let mut fin = data[complete..].to_vec();
    fin.resize(bs, 0);
    for (b, p) in fin.iter_mut().zip(&last_ct) {
        *b ^= p;
    }
    engine.encrypt_block(&mut fin);
    let mut out = buf[..complete - bs].to_vec();
    out.extend_from_slice(&last_ct[..d]);
    out.extend_from_slice(&fin);
    Ok(out)
}

/// CBC-CS1-Decrypt: recover the stolen tail from D(C_n), rebuild the
/// penultimate ciphertext block, decrypt the chain, XOR out the partial
/// plaintext.
fn cbc_cs1_decrypt(engine: &dyn BlockEngine, iv: &[u8], data: &[u8]) -> OpResult<Vec<u8>> {
    let bs = engine.block_size();
    let n = data.len();
    if n < bs {
        return Err(cts_length_error(n, bs));
    }
    let d = n % bs;
    if d == 0 {
        let mut buf = data.to_vec();
        cbc_decrypt(engine, iv, &mut buf);
        return Ok(buf);
    }
    let head_len = n - bs - d;
    let fin = &data[head_len + d..];
    let partial = &data[head_len..head_len + d];
    let mut z = fin.to_vec();
    engine.decrypt_block(&mut z);
    let mut chain = data[..head_len].to_vec();
    chain.extend_from_slice(partial);
    chain.extend_from_slice(&z[d..]);
    cbc_decrypt(engine, iv, &mut chain);
    let mut out = chain;
    out.extend(partial.iter().zip(&z[..d]).map(|(a, b)| a ^ b));
    Ok(out)
}

/// Reorders the CS1 tail layout `[head][partial d][fin bs]` into the swapped
/// CS2/CS3 layout `[head][fin bs][partial d]`; with whole blocks it swaps the
/// last two.
fn cts_tail_to_swapped(cs1: &[u8], bs: usize) -> Vec<u8> {
    let n = cs1.len();
    let d = n % bs;
    let head = if d == 0 { n - 2 * bs } else { n - bs - d };
    let mut out = cs1[..head].to_vec();
    if d == 0 {
        out.extend_from_slice(&cs1[n - bs..]);
        out.extend_from_slice(&cs1[n - 2 * bs..n - bs]);
    } else {
        out.extend_from_slice(&cs1[n - bs..]);
        out.extend_from_slice(&cs1[n - bs - d..n - bs]);
    }
    out
}

/// Inverse of [`cts_tail_to_swapped`]: `[head][fin bs][partial d]` back to
/// the CS1 layout `[head][partial d][fin bs]`.
fn cts_tail_to_cs1(swapped: &[u8], bs: usize) -> Vec<u8> {
    let n = swapped.len();
    let d = n % bs;
    let head = if d == 0 { n - 2 * bs } else { n - bs - d };
    let mut out = swapped[..head].to_vec();
    if d == 0 {
        out.extend_from_slice(&swapped[n - bs..]);
        out.extend_from_slice(&swapped[n - 2 * bs..n - bs]);
    } else {
        out.extend_from_slice(&swapped[n - d..]);
        out.extend_from_slice(&swapped[n - bs - d..n - d]);
    }
    out
}

fn cts_encrypt(
    engine: &dyn BlockEngine,
    iv: &[u8],
    data: &[u8],
    variant: CtsVariant,
) -> OpResult<Vec<u8>> {
    let bs = engine.block_size();
    let d = data.len() % bs;
    let swap = match variant {
        CtsVariant::Cs1 => false,
        // CS2 is CS1 with the tail swapped only for a partial final block;
        // CS3 swaps whenever there is more than one block (a lone full block
        // has no partner to swap, matching RFC 3962's one-block rule).
        CtsVariant::Cs2 => d != 0,
        CtsVariant::Cs3 => data.len() > bs,
    };
    if swap {
        Ok(cts_tail_to_swapped(&cbc_cs1_encrypt(engine, iv, data)?, bs))
    } else {
        cbc_cs1_encrypt(engine, iv, data)
    }
}

fn cts_decrypt(
    engine: &dyn BlockEngine,
    iv: &[u8],
    data: &[u8],
    variant: CtsVariant,
) -> OpResult<Vec<u8>> {
    let bs = engine.block_size();
    let n = data.len();
    if n < bs {
        return Err(cts_length_error(n, bs));
    }
    let d = n % bs;
    let swap = match variant {
        CtsVariant::Cs1 => false,
        CtsVariant::Cs2 => d != 0,
        CtsVariant::Cs3 => n > bs,
    };
    let cs1_order = if swap {
        cts_tail_to_cs1(data, bs)
    } else {
        data.to_vec()
    };
    cbc_cs1_decrypt(engine, iv, &cs1_order)
}

fn mode_apply(
    entry: &'static BlockCipherEntry,
    mode: Mode,
    key: &[u8],
    iv: &[u8],
    mut data: Vec<u8>,
    encrypt: bool,
) -> OpResult<Vec<u8>> {
    // For tweak ciphers (Threefish) the iv parameter carries the mandatory
    // 16-byte tweak: as-is in ECB mode, or as the leading 16 bytes of the
    // block-size mode IV in IV modes.
    let tweak: &[u8] = if entry.tweak_required { &iv[..16] } else { &[] };
    let engine = entry.engine(key, tweak)?;
    // Only ECB/CBC require block alignment; the stream modes and the CTS
    // variants handle arbitrary lengths natively.
    if matches!(mode, Mode::Ecb | Mode::Cbc) && !data.len().is_multiple_of(engine.block_size()) {
        return Err(OperationError::internal("pre-padded data misaligned"));
    }
    match mode {
        Mode::Ecb => ecb_apply(engine.as_ref(), &mut data, encrypt),
        Mode::Cbc => {
            if encrypt {
                cbc_encrypt(engine.as_ref(), iv, &mut data);
            } else {
                cbc_decrypt(engine.as_ref(), iv, &mut data);
            }
        }
        Mode::Ctr => ctr_apply(engine.as_ref(), iv, &mut data),
        Mode::Ofb => ofb_apply(engine.as_ref(), iv, &mut data),
        Mode::Cfb => {
            return Ok(if encrypt {
                cfb_encrypt(engine.as_ref(), iv, &data)
            } else {
                cfb_decrypt(engine.as_ref(), iv, &data)
            });
        }
        Mode::CbcCs1 | Mode::CbcCs2 | Mode::CbcCs3 => {
            let variant = match mode {
                Mode::CbcCs1 => CtsVariant::Cs1,
                Mode::CbcCs2 => CtsVariant::Cs2,
                _ => CtsVariant::Cs3,
            };
            return if encrypt {
                cts_encrypt(engine.as_ref(), iv, &data, variant)
            } else {
                cts_decrypt(engine.as_ref(), iv, &data, variant)
            };
        }
    }
    Ok(data)
}

// ------------------------------------------------------- op plumbing ----

fn cipher_run(
    op_id: &'static str,
    name: &'static str,
    encrypt: bool,
) -> impl Fn(&Value, &ParamMap, &ExecutionContext) -> OpResult<Value> + Send + Sync + 'static {
    move |v: &Value, map: &ParamMap, _: &ExecutionContext| -> OpResult<Value> {
        let bytes = crate::helpers::input_bytes(v, name)?;
        let key = decode_material(map, "key", "key_encoding", "key")?;
        let entry = resolve_entry(op_id)?;
        if !entry.key_len_ok(key.len()) {
            return Err(key_error(entry, key.len()));
        }
        let mode = Mode::parse(map.str_or("mode", "cbc"))?;
        let block = entry.block_size(key.len());
        // Tweak ciphers: exactly the 16-byte tweak in ECB mode; a full
        // block-size IV (whose leading 16 bytes are the tweak) otherwise.
        let iv_len = if entry.tweak_required && mode.uses_iv() {
            block
        } else {
            entry.iv_len()
        };
        let iv_needed = mode.uses_iv() || entry.tweak_required;
        let iv: Option<Vec<u8>> = if iv_needed {
            let raw = map.str_or("iv", "");
            if raw.is_empty() {
                return Err(OperationError::key(format!(
                    "{} requires a {iv_len}-byte {} for {} mode",
                    entry.display,
                    if entry.tweak_required { "tweak" } else { "IV" },
                    mode.as_str()
                ))
                .with_parameter("iv")
                .with_expected(format!("{iv_len} bytes"))
                .with_actual("empty"));
            }
            let decoded = decode_input(map.str_or("iv_encoding", "hex"), raw)
                .map_err(|e| e.with_parameter("iv"))?;
            if decoded.len() != iv_len {
                return Err(iv_error(entry, decoded.len(), iv_len));
            }
            Some(decoded)
        } else {
            None
        };
        let padding = Padding::parse(map.str_or("padding", "pkcs7"))?;

        // Stream modes (CTR/CFB/OFB) and the CTS variants have no padding
        // concept — their output length equals input length regardless of
        // alignment.
        let stream_mode = mode.length_preserving();
        let out = if encrypt {
            let padded: Vec<u8> = if stream_mode {
                bytes.as_ref().to_vec()
            } else {
                pad(bytes.as_ref(), block, padding)?
            };
            mode_apply(
                entry,
                mode,
                &key,
                iv.as_deref().unwrap_or(&[]),
                padded,
                true,
            )?
        } else {
            let decrypted = mode_apply(
                entry,
                mode,
                &key,
                iv.as_deref().unwrap_or(&[]),
                bytes.as_ref().to_vec(),
                false,
            )?;
            if stream_mode {
                decrypted
            } else {
                unpad(&decrypted, block, padding)?
            }
        };
        Ok(Value::Bytes(out))
    }
}

/// Native RC4 (KSA + PRGA per Rivest's spec) with optional keystream drop.
/// Implemented directly because variable-length keys do not fit the
/// RustCrypto `rc4` crate's compile-time key-size generics.
fn rc4_apply(key: &[u8], data: &[u8], drop: usize) -> Vec<u8> {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xff;
        s.swap(i, j);
    }
    let mut i = 0usize;
    let mut j = 0usize;
    let mut out = Vec::with_capacity(data.len());
    for n in 0..(drop + data.len()) {
        i = (i + 1) & 0xff;
        j = (j + s[i] as usize) & 0xff;
        s.swap(i, j);
        if n >= drop {
            let k = s[(s[i] as usize + s[j] as usize) & 0xff];
            out.push(k);
        }
    }
    out.iter().zip(data.iter()).map(|(k, p)| k ^ p).collect()
}

// ------------------------------------------------------- XTS-AES ----

/// Multiplies the 16-byte tweak by alpha in GF(2^128) using the
/// little-endian byte order of IEEE 1619 (byte 0 is the least significant,
/// matching the little-endian data-unit encoding): shift toward byte 15 and
/// XOR 0x87 into byte 0 when the top bit carries out.
fn xts_multiply(t: &mut [u8; 16]) {
    let mut carry = 0u8;
    for byte in t.iter_mut() {
        let next = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = next;
    }
    if carry == 1 {
        t[0] ^= 0x87;
    }
}

/// XTS-AES (IEEE 1619-2007; NIST SP 800-38E) with ciphertext stealing.
/// `key` is the doubled key K1 || K2 (two AES-128/192/256 keys); `tweak`
/// is the 16-byte tweak block (IEEE 1619 data-unit numbers are little-
/// endian). Data units shorter than one block are rejected per SP 800-38E.
fn xts_apply(encrypt: bool, key: &[u8], tweak: &[u8; 16], data: &mut [u8]) -> OpResult<()> {
    let bs = 16;
    let n = data.len();
    if n < bs {
        return Err(OperationError::length(
            format!("at least {bs} bytes (one full block)"),
            format!("{n} bytes"),
            "XTS data units must be at least one full block (NIST SP 800-38E)",
        )
        .with_parameter("input"));
    }
    let (k1, k2) = key.split_at(key.len() / 2);
    let data_engine: Box<dyn BlockEngine> = match k1.len() {
        16 => keyed::<aes::Aes128>(k1)?,
        24 => keyed::<aes::Aes192>(k1)?,
        _ => keyed::<aes::Aes256>(k1)?,
    };
    let tweak_engine: Box<dyn BlockEngine> = match k2.len() {
        16 => keyed::<aes::Aes128>(k2)?,
        24 => keyed::<aes::Aes192>(k2)?,
        _ => keyed::<aes::Aes256>(k2)?,
    };
    // PP = E_K2(tweak); T_j = alpha^j * PP.
    let mut t = *tweak;
    tweak_engine.encrypt_block(&mut t);
    let mut prev_t = t;

    let d = n % bs;
    let full_blocks = n / bs;
    // In decrypt-with-steal the loop decrypts the last full block IN PLACE,
    // so capture the raw ciphertext block for the steal step first.
    let raw_last_ct: Option<Vec<u8>> = if !encrypt && d != 0 {
        Some(data[(full_blocks - 1) * bs..full_blocks * bs].to_vec())
    } else {
        None
    };
    for (j, chunk) in data[..full_blocks * bs].chunks_mut(bs).enumerate() {
        // IEEE 1619 decrypt with a partial final block decrypts the LAST
        // full block under T_m (the next tweak) so that the steal step can
        // rebuild it; every other block uses its own T_j.
        let last_full_decrypt = !encrypt && d != 0 && j == full_blocks - 1;
        prev_t = t;
        if last_full_decrypt {
            xts_multiply(&mut t);
        }
        for (b, k) in chunk.iter_mut().zip(&t) {
            *b ^= k;
        }
        if encrypt {
            data_engine.encrypt_block(chunk);
        } else {
            data_engine.decrypt_block(chunk);
        }
        for (b, k) in chunk.iter_mut().zip(&t) {
            *b ^= k;
        }
        if !last_full_decrypt {
            xts_multiply(&mut t);
        }
    }
    if d == 0 {
        return Ok(());
    }

    // IEEE 1619-2007 ciphertext-stealing step over the final (full block,
    // partial block) pair, using the NEXT tweak T_m:
    //   encrypt: C_m = C_{m-1}[..d];
    //            C_{m-1} = E((P_m || C_{m-1}[d..]) XOR T_m) XOR T_m
    //   decrypt: P~   = D(C_{m-1} XOR T_m) XOR T_m;  P_m = P~[..d];
    //            P_{m-1} = D((C_m || P~[d..]) XOR T_{m-1}) XOR T_{m-1}
    let last_full = (full_blocks - 1) * bs;
    if encrypt {
        let c_prev: Vec<u8> = data[last_full..last_full + bs].to_vec();
        let mut cc = data[last_full + bs..n].to_vec(); // P_m (d bytes)
        cc.extend_from_slice(&c_prev[d..]);
        for (b, k) in cc.iter_mut().zip(&t) {
            *b ^= k;
        }
        data_engine.encrypt_block(&mut cc);
        for (b, k) in cc.iter_mut().zip(&t) {
            *b ^= k;
        }
        data[last_full..last_full + bs].copy_from_slice(&cc);
        data[last_full + bs..n].copy_from_slice(&c_prev[..d]);
    } else {
        let c_prev: Vec<u8> = raw_last_ct.expect("captured before the in-place loop");
        let c_m: Vec<u8> = data[last_full + bs..n].to_vec();
        // P~ = D(C_{m-1} XOR T_m) XOR T_m — its head is the partial plaintext.
        let mut pt = c_prev.clone();
        for (b, k) in pt.iter_mut().zip(&t) {
            *b ^= k;
        }
        data_engine.decrypt_block(&mut pt);
        for (b, k) in pt.iter_mut().zip(&t) {
            *b ^= k;
        }
        data[last_full + bs..n].copy_from_slice(&pt[..d]);
        // P_{m-1} = D((C_m || P~[d..]) XOR T_{m-1}) XOR T_{m-1}
        let mut cc = c_m;
        cc.extend_from_slice(&pt[d..]);
        for (b, k) in cc.iter_mut().zip(&prev_t) {
            *b ^= k;
        }
        data_engine.decrypt_block(&mut cc);
        for (b, k) in cc.iter_mut().zip(&prev_t) {
            *b ^= k;
        }
        data[last_full..last_full + bs].copy_from_slice(&cc);
    }
    Ok(())
}

fn xts_run(
    name: &'static str,
    encrypt: bool,
) -> impl Fn(&Value, &ParamMap, &ExecutionContext) -> OpResult<Value> + Send + Sync + 'static {
    move |v: &Value, map: &ParamMap, _: &ExecutionContext| -> OpResult<Value> {
        let bytes = crate::helpers::input_bytes(v, name)?;
        let key = decode_material(map, "key", "key_encoding", name)?;
        if ![32, 48, 64].contains(&key.len()) {
            return Err(OperationError::key(format!(
                "AES-XTS key must be 32 / 48 / 64 bytes after decoding (K1 || K2 for AES-128/192/256), got {} bytes",
                key.len()
            ))
            .with_parameter("key")
            .with_expected("32 / 48 / 64 bytes")
            .with_actual(format!("{} bytes", key.len())));
        }
        let raw = map.require_str("iv")?;
        let tweak = decode_input(map.str_or("iv_encoding", "hex"), raw)
            .map_err(|e| e.with_parameter("iv"))?;
        if tweak.len() != 16 {
            return Err(OperationError::key(format!(
                "AES-XTS tweak must be 16 bytes after decoding, got {} bytes",
                tweak.len()
            ))
            .with_parameter("iv")
            .with_expected("16 bytes")
            .with_actual(format!("{} bytes", tweak.len())));
        }
        let mut buf = bytes.as_ref().to_vec();
        xts_apply(
            encrypt,
            &key,
            tweak.as_slice().try_into().expect("checked 16 bytes"),
            &mut buf,
        )?;
        Ok(Value::Bytes(buf))
    }
}

fn xts_spec(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    tags: &'static [&'static str],
) -> &'static OperationSpec {
    let params = vec![
        p_text(
            "key",
            "Key",
            "",
            "Doubled key: K1 || K2, 32/48/64 bytes for AES-128/192/256 XTS.",
        ),
        p_enc("key_encoding", "Key encoding", "hex", ""),
        p_text(
            "iv",
            "Tweak (data-unit number)",
            "",
            "16-byte tweak; IEEE 1619 data-unit numbers are encoded little-endian.",
        ),
        p_enc("iv_encoding", "IV encoding", "hex", ""),
    ];
    Box::leak(Box::new(OperationSpec {
        id,
        name,
        description,
        category: Category::Crypto,
        input_kinds: Box::leak(vec![ValueKind::Bytes, ValueKind::Text].into_boxed_slice()),
        output_kind: ValueKind::Bytes,
        params: Box::leak(params.into_boxed_slice()),
        cost: CostClass::Instant,
        security: Security::Modern,
        deterministic: true,
        reversible: true,
        aliases: Box::leak(vec![id.strip_suffix("-encrypt").unwrap_or(id)].into_boxed_slice()),
        tags,
        provenance: Provenance {
            standard: "XTS-AES (IEEE 1619-2007; NIST SP 800-38E)",
            implementation: "CyberCipher native XTS over the RustCrypto `aes` crate",
            test_vectors: "IEEE 1619 sample vectors (IEEE P1619/D16 annex)",
        },
    }))
}

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    let tags: &'static [&'static str] = &["crypto", "ctf"];

    // The three legacy ops keep their hand-written specs (names, aliases and
    // provenance are part of the public surface), but run through the same
    // table + shared mode plumbing as every other cipher.
    reg.add_simple(
        crate::helpers::cipher_spec(
            "aes-encrypt", "AES Encrypt",
            "Encrypts with AES. Cipher, mode, and padding are validated explicitly; keys must decode to 16/24/32 bytes.",
            "NIST FIPS 197 + SP 800-38 family", tags,
        ),
        cipher_run("aes-encrypt", "AES Encrypt", true),
    );
    reg.add_simple(
        crate::helpers::cipher_spec(
            "aes-decrypt",
            "AES Decrypt",
            "Decrypts with AES and validates the selected padding scheme.",
            "NIST FIPS 197 + SP 800-38 family",
            tags,
        ),
        cipher_run("aes-decrypt", "AES Decrypt", false),
    );
    reg.add_simple(
        crate::helpers::cipher_spec(
            "des-encrypt", "DES / 3DES Encrypt",
            "Encrypts with DES (8-byte key) or 3DES (16/24-byte key). ECB/CBC modes. Legacy — labeled Broken.",
            "FIPS 46-3 (withdrawn); NIST SP 800-67 for 3DES", tags,
        ),
        cipher_run("des-encrypt", "DES / 3DES Encrypt", true),
    );
    reg.add_simple(
        crate::helpers::cipher_spec(
            "des-decrypt", "DES / 3DES Decrypt",
            "Decrypts with DES (8-byte key) or 3DES (16/24-byte key). ECB/CBC modes. Legacy — labeled Broken.",
            "FIPS 46-3 (withdrawn); NIST SP 800-67 for 3DES", tags,
        ),
        cipher_run("des-decrypt", "DES / 3DES Decrypt", false),
    );
    reg.add_simple(
        crate::helpers::cipher_spec(
            "sm4-encrypt",
            "SM4 Encrypt",
            "Encrypts with SM4 (GB/T 32907). 16-byte key, 16-byte block.",
            "GB/T 32907-2016",
            tags,
        ),
        cipher_run("sm4-encrypt", "SM4 Encrypt", true),
    );
    reg.add_simple(
        crate::helpers::cipher_spec(
            "sm4-decrypt",
            "SM4 Decrypt",
            "Decrypts with SM4 (GB/T 32907). 16-byte key, 16-byte block.",
            "GB/T 32907-2016",
            tags,
        ),
        cipher_run("sm4-decrypt", "SM4 Decrypt", false),
    );

    // Table-driven registration for the breadth ciphers.
    for entry in BLOCK_CIPHERS {
        if matches!(entry.id, "aes" | "des" | "sm4") {
            continue; // registered above with bespoke specs
        }
        for encrypt in [true, false] {
            let (verb, suffix) = if encrypt {
                ("Encrypts", "encrypt")
            } else {
                ("Decrypts", "decrypt")
            };
            let id: &'static str = Box::leak(format!("{}-{suffix}", entry.id).into_boxed_str());
            let name: &'static str = Box::leak(
                format!(
                    "{} {}",
                    entry.display,
                    verb.strip_suffix('s').unwrap_or(verb)
                )
                .into_boxed_str(),
            );
            let description: &'static str = Box::leak(
                format!(
                    "{verb} with {display}: {shape} Mode and padding are validated explicitly; the iv parameter carries the IV (or the mandatory 16-byte tweak for Threefish).",
                    display = entry.display,
                    shape = entry.shape,
                )
                .into_boxed_str(),
            );
            let spec = crate::helpers::block_cipher_spec(
                id,
                name,
                description,
                entry.provenance.0,
                entry.security,
                tags,
            );
            reg.add_simple(spec, cipher_run(id, name, encrypt));
        }
    }

    // RC4 stream cipher (single op: encryption == decryption).
    let rc4_spec = crate::helpers::rc4_spec(tags);
    reg.add_simple(rc4_spec, |v, map, _| {
        let bytes = crate::helpers::input_bytes(v, "RC4")?;
        let key = decode_material(map, "key", "key_encoding", "key")?;
        if !(1..=256).contains(&key.len()) {
            return Err(OperationError::key(format!(
                "RC4 key must be 1-256 bytes after decoding, got {} bytes",
                key.len()
            ))
            .with_parameter("key")
            .with_expected("1-256 bytes")
            .with_actual(format!("{} bytes", key.len())));
        }
        let drop: i64 = map.int_or("drop", 0);
        if !(0..=8192).contains(&drop) {
            return Err(OperationError::invalid_param(
                "drop",
                "drop must be between 0 and 8192 (RC4-drop[n])",
            ));
        }
        Ok(Value::Bytes(rc4_apply(&key, bytes.as_ref(), drop as usize)))
    });

    // XTS-AES (IEEE 1619-2007 / SP 800-38E): doubled key, 16-byte tweak.
    reg.add_simple(
        xts_spec(
            "aes-xts-encrypt",
            "AES-XTS Encrypt",
            "Encrypts one data unit with XTS-AES (IEEE 1619-2007; NIST SP 800-38E), the tweakable wide-block mode used for disk encryption. The key is the doubled key K1 || K2 (32/48/64 bytes for AES-128/192/256); the iv parameter carries the 16-byte tweak (data-unit number, little-endian per IEEE 1619). Data units must be at least one full block; a partial final block is handled with ciphertext stealing.",
            tags,
        ),
        xts_run("AES-XTS Encrypt", true),
    );
    reg.add_simple(
        xts_spec(
            "aes-xts-decrypt",
            "AES-XTS Decrypt",
            "Decrypts one data unit with XTS-AES (IEEE 1619-2007; NIST SP 800-38E) and reverses the ciphertext-stealing of a partial final block. The key is the doubled key K1 || K2; the iv parameter carries the 16-byte tweak (data-unit number, little-endian per IEEE 1619).",
            tags,
        ),
        xts_run("AES-XTS Decrypt", false),
    );
}
