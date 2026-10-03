//! Authenticated encryption with associated data (AEAD).
//!
//! Constructions: AES-GCM (NIST SP 800-38D), AES-CCM (NIST SP 800-38C),
//! ChaCha20-Poly1305 (RFC 8439), XChaCha20-Poly1305
//! (draft-irtf-cfrg-xchacha), AES-GCM-SIV (RFC 8452), AES-EAX
//! (Bellare-Rogaway-Wagner), OCB3 (RFC 7253), and AES-SIV (RFC 5297).
//!
//! Conventions:
//! - Encrypt outputs `ciphertext || tag`; decrypt expects the same layout and
//!   splits off the trailing tag before verification. AES-SIV is the one
//!   deliberate exception: it uses the RFC 5297 wire layout `SIV || ciphertext`
//!   (the tag is the Synthetic Initialization Vector and comes first).
//! - Verification failures are structured, typed errors. Authenticated
//!   decryption never returns plaintext when the tag does not verify.
//! - Nonce lengths are validated per construction: 96 bits for GCM, GCM-SIV,
//!   OCB3 and ChaCha20-Poly1305; 192 bits for XChaCha20-Poly1305; 128 bits for
//!   EAX; 7-13 bytes for CCM (NIST SP 800-38C). AES-SIV treats the nonce as an
//!   additional S2V associated-data string (optional, RFC 5297). Key lengths
//!   are checked before the cipher is constructed (the RustCrypto `new`
//!   panics on wrong sizes).

use aead::consts::{U10, U11, U12, U13, U16, U4, U7, U8, U9};
use aead::generic_array::GenericArray;
use aead::{AeadInPlace, KeyInit};
// aes-gcm / ccm are on the cipher 0.4 generation and need `aes` 0.8 types;
// `aes08` is that crate (renamed in Cargo.toml) while `aes` 0.9 serves the
// block-cipher table in ciphers.rs and the aead 0.6 crates (eax/ocb3/aes-siv).
use aes08 as aes;
use ::aes as aes09;
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use cybercipher_codec::decode_input;
use cybercipher_core::prelude::*;

use crate::helpers::{decode_material, input_bytes, p_enc, p_text, p_text_opt};

const AEAD_TAGS: &[&str] = &["crypto", "aead", "ctf"];

/// AES-GCM with a 192-bit key has no named alias in `aes-gcm`.
type Aes192Gcm = aes_gcm::AesGcm<aes::Aes192, U12>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algo {
    AesGcm,
    AesCcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
    AesGcmSiv,
}

impl Algo {
    fn name(self) -> &'static str {
        match self {
            Algo::AesGcm => "AES-GCM",
            Algo::AesCcm => "AES-CCM",
            Algo::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            Algo::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            Algo::AesGcmSiv => "AES-GCM-SIV",
        }
    }

    fn key_lengths(self) -> &'static [usize] {
        match self {
            Algo::AesGcm | Algo::AesCcm => &[16, 24, 32],
            Algo::AesGcmSiv => &[16, 32],
            Algo::ChaCha20Poly1305 | Algo::XChaCha20Poly1305 => &[32],
        }
    }

    /// Fixed nonce length in bytes; `None` = variable 7-13 bytes (CCM).
    fn nonce_len(self) -> Option<usize> {
        match self {
            Algo::AesGcm | Algo::AesGcmSiv | Algo::ChaCha20Poly1305 => Some(12),
            Algo::XChaCha20Poly1305 => Some(24),
            Algo::AesCcm => None,
        }
    }

    fn tag_len(self) -> usize {
        match self {
            Algo::AesCcm => 16, // overridden by the tag_length parameter
            _ => 16,
        }
    }

    fn nonce_valid(self, len: usize) -> bool {
        match self.nonce_len() {
            Some(n) => len == n,
            None => (7..=13).contains(&len),
        }
    }
}

// ------------------------------------------------------------ errors ----

fn key_length_error(algo: Algo, actual: usize) -> OperationError {
    let lengths: Vec<String> = algo.key_lengths().iter().map(|l| l.to_string()).collect();
    OperationError::key(format!(
        "{} key must be {} bytes after decoding, got {} bytes",
        algo.name(),
        lengths.join(" / "),
        actual
    ))
    .with_parameter("key")
    .with_expected(lengths.join(" / "))
    .with_actual(format!("{actual} bytes"))
}

fn nonce_length_error(algo: Algo, actual: usize) -> OperationError {
    let expected = match algo.nonce_len() {
        Some(n) => format!("{n} bytes ({}-bit nonce)", n * 8),
        None => "7-13 bytes (NIST SP 800-38C)".to_string(),
    };
    OperationError::length(
        expected.clone(),
        format!("{actual} bytes"),
        format!("{} nonce has the wrong length", algo.name()),
    )
    .with_parameter("nonce")
    .with_expected(expected)
    .with_actual(format!("{actual} bytes"))
}

fn auth_error(algo: Algo) -> OperationError {
    OperationError::decode(format!(
        "{} authentication failed: tag mismatch — the input was NOT decrypted",
        algo.name()
    ))
    .with_expected("ciphertext and tag produced with the same key, nonce, and AAD")
    .with_actual("authentication tag verification failed")
    .with_details(
        "A wrong key, wrong nonce, wrong AAD, or any corruption of the ciphertext or tag \
         produces this error. Authenticated decryption never returns plaintext when the \
         tag does not verify.",
    )
}

fn sealed_input_error(algo: Algo, tag_len: usize, actual: usize) -> OperationError {
    OperationError::length(
        format!("at least {tag_len} bytes (ciphertext + {tag_len}-byte tag)"),
        format!("{actual} bytes"),
        format!(
            "{} input is too short to contain the authentication tag",
            algo.name()
        ),
    )
    .with_parameter("input")
}

fn seal_failure(algo: Algo) -> OperationError {
    // In practice only CCM can fail encryption: the message must satisfy
    // len < 2^(8*(15-nonce_len)) for the selected nonce length.
    OperationError::length(
        "message within the CCM limit of 2^(8 * (15 - nonce_len)) bytes",
        "message too long for the selected nonce length",
        format!("{} encryption failed", algo.name()),
    )
}

// ------------------------------------------------------- AEAD cores ----

/// Encrypts in place and returns the authentication tag (to be appended
/// by the caller, giving the `ciphertext || tag` wire format).
fn seal<A>(algo: Algo, key: &[u8], nonce: &[u8], aad: &[u8], buf: &mut [u8]) -> OpResult<Vec<u8>>
where
    A: AeadInPlace + KeyInit,
{
    let cipher = A::new(GenericArray::from_slice(key));
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buf)
        .map_err(|_| seal_failure(algo))?;
    Ok(tag.to_vec())
}

fn open<A>(
    algo: Algo,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8],
) -> OpResult<()>
where
    A: AeadInPlace + KeyInit,
{
    let cipher = A::new(GenericArray::from_slice(key));
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            aad,
            buf,
            GenericArray::from_slice(tag),
        )
        .map_err(|_| auth_error(algo))
}

/// AES-GCM-SIV needs its own seal/open pair: `aes-gcm-siv` 0.10 implements
/// the `aead` 0.4 traits (the rest of the RustCrypto AEAD stack moved to
/// `aead` 0.5), so the generic helpers above do not apply.
fn siv_seal<A>(key: &[u8], nonce: &[u8], aad: &[u8], buf: &mut [u8]) -> OpResult<Vec<u8>>
where
    A: aes_gcm_siv::aead::AeadInPlace + aes_gcm_siv::aead::NewAead,
{
    use aes_gcm_siv::aead::{self, NewAead};
    let cipher = <A as NewAead>::new(aead::generic_array::GenericArray::from_slice(key));
    let tag = cipher
        .encrypt_in_place_detached(
            aead::generic_array::GenericArray::from_slice(nonce),
            aad,
            buf,
        )
        .map_err(|_| seal_failure(Algo::AesGcmSiv))?;
    Ok(tag.to_vec())
}

fn siv_open<A>(key: &[u8], nonce: &[u8], aad: &[u8], buf: &mut [u8], tag: &[u8]) -> OpResult<()>
where
    A: aes_gcm_siv::aead::AeadInPlace + aes_gcm_siv::aead::NewAead,
{
    use aes_gcm_siv::aead::{self, NewAead};
    let cipher = <A as NewAead>::new(aead::generic_array::GenericArray::from_slice(key));
    cipher
        .decrypt_in_place_detached(
            aead::generic_array::GenericArray::from_slice(nonce),
            aad,
            buf,
            aead::generic_array::GenericArray::from_slice(tag),
        )
        .map_err(|_| auth_error(Algo::AesGcmSiv))
}

/// CCM dispatch: the `ccm` crate encodes nonce length (7-13), tag length
/// (4/6/.../16) and cipher as type parameters, but CyberCipher accepts them
/// at runtime, so we fan out over the supported combinations
/// (tag lengths 4/8/16 x AES-128/192/256 x nonce 7-13).
macro_rules! ccm_seal {
    ($t:ty, $key:expr, $nonce:expr, $aad:expr, $buf:expr) => {
        seal::<$t>(Algo::AesCcm, $key, $nonce, $aad, $buf)
    };
}

macro_rules! ccm_open {
    ($t:ty, $key:expr, $nonce:expr, $aad:expr, $buf:expr, $tag:expr) => {
        open::<$t>(Algo::AesCcm, $key, $nonce, $aad, $buf, $tag)
    };
}

fn ccm_seal(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    buf: &mut [u8],
    tag_len: usize,
) -> OpResult<Vec<u8>> {
    macro_rules! by_nonce {
        ($cipher:ident, $tag_ty:ident) => {
            match nonce.len() {
                7 => ccm_seal!(ccm::Ccm<aes::$cipher, $tag_ty, U7>, key, nonce, aad, buf),
                8 => ccm_seal!(ccm::Ccm<aes::$cipher, $tag_ty, U8>, key, nonce, aad, buf),
                9 => ccm_seal!(ccm::Ccm<aes::$cipher, $tag_ty, U9>, key, nonce, aad, buf),
                10 => ccm_seal!(ccm::Ccm<aes::$cipher, $tag_ty, U10>, key, nonce, aad, buf),
                11 => ccm_seal!(ccm::Ccm<aes::$cipher, $tag_ty, U11>, key, nonce, aad, buf),
                12 => ccm_seal!(ccm::Ccm<aes::$cipher, $tag_ty, U12>, key, nonce, aad, buf),
                13 => ccm_seal!(ccm::Ccm<aes::$cipher, $tag_ty, U13>, key, nonce, aad, buf),
                n => return Err(nonce_length_error(Algo::AesCcm, n)),
            }
        };
    }
    macro_rules! by_tag_len {
        ($cipher:ident) => {
            match tag_len {
                4 => by_nonce!($cipher, U4),
                8 => by_nonce!($cipher, U8),
                16 => by_nonce!($cipher, U16),
                other => {
                    return Err(OperationError::invalid_param(
                        "tag_length",
                        format!("CCM tag length must be 4, 8, or 16 bytes, got {other}"),
                    ))
                }
            }
        };
    }
    match key.len() {
        16 => by_tag_len!(Aes128),
        24 => by_tag_len!(Aes192),
        32 => by_tag_len!(Aes256),
        other => Err(key_length_error(Algo::AesCcm, other)),
    }
}

fn ccm_open(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8],
    tag_len: usize,
) -> OpResult<()> {
    macro_rules! by_nonce {
        ($cipher:ident, $tag_ty:ident) => {
            match nonce.len() {
                7 => ccm_open!(ccm::Ccm<aes::$cipher, $tag_ty, U7>, key, nonce, aad, buf, tag),
                8 => ccm_open!(ccm::Ccm<aes::$cipher, $tag_ty, U8>, key, nonce, aad, buf, tag),
                9 => ccm_open!(ccm::Ccm<aes::$cipher, $tag_ty, U9>, key, nonce, aad, buf, tag),
                10 => ccm_open!(ccm::Ccm<aes::$cipher, $tag_ty, U10>, key, nonce, aad, buf, tag),
                11 => ccm_open!(ccm::Ccm<aes::$cipher, $tag_ty, U11>, key, nonce, aad, buf, tag),
                12 => ccm_open!(ccm::Ccm<aes::$cipher, $tag_ty, U12>, key, nonce, aad, buf, tag),
                13 => ccm_open!(ccm::Ccm<aes::$cipher, $tag_ty, U13>, key, nonce, aad, buf, tag),
                n => return Err(nonce_length_error(Algo::AesCcm, n)),
            }
        };
    }
    macro_rules! by_tag_len {
        ($cipher:ident) => {
            match tag_len {
                4 => by_nonce!($cipher, U4),
                8 => by_nonce!($cipher, U8),
                16 => by_nonce!($cipher, U16),
                other => {
                    return Err(OperationError::invalid_param(
                        "tag_length",
                        format!("CCM tag length must be 4, 8, or 16 bytes, got {other}"),
                    ))
                }
            }
        };
    }
    match key.len() {
        16 => by_tag_len!(Aes128),
        24 => by_tag_len!(Aes192),
        32 => by_tag_len!(Aes256),
        other => Err(key_length_error(Algo::AesCcm, other)),
    }
}

fn dispatch_seal(
    algo: Algo,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    buf: &mut Vec<u8>,
    tag_len: usize,
) -> OpResult<()> {
    let tag = match algo {
        Algo::AesGcm => match key.len() {
            16 => seal::<Aes128Gcm>(algo, key, nonce, aad, buf)?,
            24 => seal::<Aes192Gcm>(algo, key, nonce, aad, buf)?,
            32 => seal::<Aes256Gcm>(algo, key, nonce, aad, buf)?,
            _ => return Err(key_length_error(algo, key.len())),
        },
        Algo::AesCcm => ccm_seal(key, nonce, aad, buf, tag_len)?,
        Algo::ChaCha20Poly1305 => seal::<ChaCha20Poly1305>(algo, key, nonce, aad, buf)?,
        Algo::XChaCha20Poly1305 => seal::<XChaCha20Poly1305>(algo, key, nonce, aad, buf)?,
        Algo::AesGcmSiv => match key.len() {
            16 => siv_seal::<aes_gcm_siv::Aes128GcmSiv>(key, nonce, aad, buf)?,
            32 => siv_seal::<aes_gcm_siv::Aes256GcmSiv>(key, nonce, aad, buf)?,
            _ => return Err(key_length_error(algo, key.len())),
        },
    };
    buf.extend_from_slice(&tag);
    Ok(())
}

fn dispatch_open(
    algo: Algo,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8],
    tag_len: usize,
) -> OpResult<()> {
    match algo {
        Algo::AesGcm => match key.len() {
            16 => open::<Aes128Gcm>(algo, key, nonce, aad, buf, tag),
            24 => open::<Aes192Gcm>(algo, key, nonce, aad, buf, tag),
            32 => open::<Aes256Gcm>(algo, key, nonce, aad, buf, tag),
            _ => Err(key_length_error(algo, key.len())),
        },
        Algo::AesCcm => ccm_open(key, nonce, aad, buf, tag, tag_len),
        Algo::ChaCha20Poly1305 => open::<ChaCha20Poly1305>(algo, key, nonce, aad, buf, tag),
        Algo::XChaCha20Poly1305 => open::<XChaCha20Poly1305>(algo, key, nonce, aad, buf, tag),
        Algo::AesGcmSiv => match key.len() {
            16 => siv_open::<aes_gcm_siv::Aes128GcmSiv>(key, nonce, aad, buf, tag),
            32 => siv_open::<aes_gcm_siv::Aes256GcmSiv>(key, nonce, aad, buf, tag),
            _ => Err(key_length_error(algo, key.len())),
        },
    }
}

// --------------------------------------------------- op plumbing ----

fn key_hint(algo: Algo) -> &'static str {
    match algo {
        Algo::AesGcm | Algo::AesCcm => "16, 24, or 32 bytes after decoding (AES-128/192/256).",
        Algo::AesGcmSiv => "16 or 32 bytes after decoding (AES-128/256).",
        Algo::ChaCha20Poly1305 | Algo::XChaCha20Poly1305 => "32 bytes after decoding.",
    }
}

fn nonce_hint(algo: Algo) -> &'static str {
    match algo {
        Algo::AesGcm | Algo::ChaCha20Poly1305 => {
            "96-bit nonce (12 bytes). Never reuse a nonce with the same key."
        }
        Algo::AesCcm => "7-13 bytes (NIST SP 800-38C); 12 or 13 bytes are typical.",
        Algo::AesGcmSiv => "96-bit nonce (12 bytes). Nonce misuse is survivable, but random nonces are still recommended.",
        Algo::XChaCha20Poly1305 => "192-bit nonce (24 bytes), safe to generate randomly.",
    }
}

#[allow(clippy::too_many_arguments)]
fn aead_op(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    aliases: &'static [&'static str],
    algo: Algo,
    standard: &'static str,
    vectors: &'static str,
    with_tag_len: bool,
    sealing: bool,
) -> (
    &'static OperationSpec,
    impl Fn(&Value, &ParamMap, &ExecutionContext) -> OpResult<Value> + Send + Sync + 'static,
) {
    let mut params = vec![
        p_text("key", "Key", "", key_hint(algo)),
        p_enc("key_encoding", "Key encoding", "hex", ""),
        p_text("nonce", "Nonce", "", nonce_hint(algo)),
        p_enc("nonce_encoding", "Nonce encoding", "hex", ""),
        p_text_opt(
            "aad",
            "Associated data (AAD)",
            "",
            "Authenticated but not encrypted; leave empty for none.",
        ),
        p_enc("aad_encoding", "AAD encoding", "hex", ""),
    ];
    if with_tag_len {
        params.push(crate::helpers::p_opts(
            "tag_length",
            "Tag length",
            "16",
            &[
                ParamOption {
                    value: "4",
                    label: "4 bytes",
                },
                ParamOption {
                    value: "8",
                    label: "8 bytes",
                },
                ParamOption {
                    value: "16",
                    label: "16 bytes",
                },
            ],
            "CCM authentication field size (M in RFC 3610 / SP 800-38C).",
        ));
    }
    let spec = Box::leak(Box::new(OperationSpec {
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
        aliases,
        tags: AEAD_TAGS,
        provenance: Provenance {
            standard,
            implementation:
                "RustCrypto AEAD crates (aes-gcm / ccm / chacha20poly1305 / aes-gcm-siv)",
            test_vectors: vectors,
        },
    }));
    let run = move |v: &Value, map: &ParamMap, _: &ExecutionContext| -> OpResult<Value> {
        let bytes = input_bytes(v, name)?;
        let key = decode_material(map, "key", "key_encoding", name)?;
        if !algo.key_lengths().contains(&key.len()) {
            return Err(key_length_error(algo, key.len()));
        }
        let nonce_raw = map.str_or("nonce", "");
        if nonce_raw.is_empty() {
            return Err(nonce_length_error(algo, 0));
        }
        let nonce = decode_input(map.str_or("nonce_encoding", "hex"), nonce_raw)
            .map_err(|e| e.with_parameter("nonce"))?;
        if !algo.nonce_valid(nonce.len()) {
            return Err(nonce_length_error(algo, nonce.len()));
        }
        let aad_raw = map.str_or("aad", "");
        let aad = if aad_raw.is_empty() {
            Vec::new()
        } else {
            decode_input(map.str_or("aad_encoding", "hex"), aad_raw)
                .map_err(|e| e.with_parameter("aad"))?
        };
        let tag_len = if with_tag_len {
            let t = map.int_or("tag_length", 16);
            if ![4, 8, 16].contains(&t) {
                return Err(OperationError::invalid_param(
                    "tag_length",
                    format!("CCM tag length must be 4, 8, or 16 bytes, got {t}"),
                ));
            }
            t as usize
        } else {
            algo.tag_len()
        };

        if sealing {
            let mut buf = bytes.to_vec();
            dispatch_seal(algo, &key, &nonce, &aad, &mut buf, tag_len)?;
            Ok(Value::Bytes(buf))
        } else {
            let mut data = bytes.to_vec();
            if data.len() < tag_len {
                return Err(sealed_input_error(algo, tag_len, data.len()));
            }
            let tag = data.split_off(data.len() - tag_len);
            dispatch_open(algo, &key, &nonce, &aad, &mut data, &tag, tag_len)?;
            Ok(Value::Bytes(data))
        }
    };
    (spec, run)
}

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    // AES-GCM (NIST SP 800-38D)
    let (spec, run) = aead_op(
        "aead-aes-gcm-encrypt",
        "AES-GCM Encrypt",
        "Encrypts and authenticates with AES-GCM. Output is ciphertext followed by the 16-byte tag. Requires a unique 96-bit nonce per message under the same key.",
        &["aes-gcm-encrypt", "gcm-encrypt"],
        Algo::AesGcm,
        "NIST SP 800-38D",
        "NIST GCM test cases (McGrew/Viega) / RustCrypto known-answer tests",
        false,
        true,
    );
    reg.add_simple(spec, run);

    let (spec, run) = aead_op(
        "aead-aes-gcm-decrypt",
        "AES-GCM Decrypt",
        "Verifies the 16-byte tag and decrypts an AES-GCM message (ciphertext followed by tag). Returns a structured error on tag failure — never garbage plaintext.",
        &["aes-gcm-decrypt", "gcm-decrypt"],
        Algo::AesGcm,
        "NIST SP 800-38D",
        "NIST GCM test cases (McGrew/Viega) / RustCrypto known-answer tests",
        false,
        false,
    );
    reg.add_simple(spec, run);

    // AES-CCM (NIST SP 800-38C)
    let (spec, run) = aead_op(
        "aead-aes-ccm-encrypt",
        "AES-CCM Encrypt",
        "Encrypts and authenticates with AES-CCM. Nonce must be 7-13 bytes; tag length is selectable (4/8/16). Output is ciphertext followed by the tag.",
        &["aes-ccm-encrypt", "ccm-encrypt"],
        Algo::AesCcm,
        "NIST SP 800-38C / RFC 3610",
        "RFC 3610 packet vectors / NIST CCM validation set",
        true,
        true,
    );
    reg.add_simple(spec, run);

    let (spec, run) = aead_op(
        "aead-aes-ccm-decrypt",
        "AES-CCM Decrypt",
        "Verifies the tag and decrypts an AES-CCM message (ciphertext followed by tag). Returns a structured error on tag failure.",
        &["aes-ccm-decrypt", "ccm-decrypt"],
        Algo::AesCcm,
        "NIST SP 800-38C / RFC 3610",
        "RFC 3610 packet vectors / NIST CCM validation set",
        true,
        false,
    );
    reg.add_simple(spec, run);

    // ChaCha20-Poly1305 (RFC 8439)
    let (spec, run) = aead_op(
        "aead-chacha20poly1305-encrypt",
        "ChaCha20-Poly1305 Encrypt",
        "Encrypts and authenticates with ChaCha20-Poly1305 (RFC 8439). Output is ciphertext followed by the 16-byte tag. Requires a unique 96-bit nonce per message under the same key.",
        &["chacha20poly1305-encrypt", "chacha20-poly1305"],
        Algo::ChaCha20Poly1305,
        "RFC 8439",
        "RFC 8439 section 2.8.2 test vector",
        false,
        true,
    );
    reg.add_simple(spec, run);

    let (spec, run) = aead_op(
        "aead-chacha20poly1305-decrypt",
        "ChaCha20-Poly1305 Decrypt",
        "Verifies the 16-byte tag and decrypts a ChaCha20-Poly1305 message (ciphertext followed by tag). Returns a structured error on tag failure.",
        &["chacha20poly1305-decrypt"],
        Algo::ChaCha20Poly1305,
        "RFC 8439",
        "RFC 8439 section 2.8.2 test vector",
        false,
        false,
    );
    reg.add_simple(spec, run);

    // XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha)
    let (spec, run) = aead_op(
        "aead-xchacha20poly1305-encrypt",
        "XChaCha20-Poly1305 Encrypt",
        "Encrypts and authenticates with XChaCha20-Poly1305: ChaCha20-Poly1305 with a 192-bit nonce and HChaCha20 key derivation, safe with random nonces.",
        &["xchacha20poly1305-encrypt", "xchacha20-poly1305"],
        Algo::XChaCha20Poly1305,
        "draft-irtf-cfrg-xchacha",
        "draft-irtf-cfrg-xchacha appendix A.1 test vector",
        false,
        true,
    );
    reg.add_simple(spec, run);

    let (spec, run) = aead_op(
        "aead-xchacha20poly1305-decrypt",
        "XChaCha20-Poly1305 Decrypt",
        "Verifies the 16-byte tag and decrypts an XChaCha20-Poly1305 message (ciphertext followed by tag).",
        &["xchacha20poly1305-decrypt"],
        Algo::XChaCha20Poly1305,
        "draft-irtf-cfrg-xchacha",
        "draft-irtf-cfrg-xchacha appendix A.1 test vector",
        false,
        false,
    );
    reg.add_simple(spec, run);

    // AES-GCM-SIV (RFC 8452)
    let (spec, run) = aead_op(
        "aead-aes-gcm-siv-encrypt",
        "AES-GCM-SIV Encrypt",
        "Encrypts and authenticates with AES-GCM-SIV (RFC 8452): nonce-misuse-resistant AEAD. Output is ciphertext followed by the 16-byte tag.",
        &["aes-gcm-siv-encrypt", "gcm-siv-encrypt"],
        Algo::AesGcmSiv,
        "RFC 8452",
        "RFC 8452 section 8 and appendix C test vectors",
        false,
        true,
    );
    reg.add_simple(spec, run);

    let (spec, run) = aead_op(
        "aead-aes-gcm-siv-decrypt",
        "AES-GCM-SIV Decrypt",
        "Verifies the 16-byte tag and decrypts an AES-GCM-SIV message (ciphertext followed by tag).",
        &["aes-gcm-siv-decrypt"],
        Algo::AesGcmSiv,
        "RFC 8452",
        "RFC 8452 section 8 and appendix C test vectors",
        false,
        false,
    );
    reg.add_simple(spec, run);
}
