//! Symmetric cipher operations: AES, DES/3DES, SM4 (block modes with
//! orthogonal padding policy), and RC4.
//!
//! Design rules:
//! - Key/IV decoding is explicit (encoding selector + strict length checks
//!   with expected/actual diagnostics). No silent re-interpretation.
//! - Padding is a separate policy parameter; decryption validates padding
//!   and reports structured errors instead of returning garbage silently.
//! - RustCrypto crates provide the primitives; this module owns mode wiring
//!   and validation.

use cybercipher_core::prelude::*;
use cybercipher_codec::decode_input;
use cipher::{
    generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockDecryptMut, BlockEncrypt,
    BlockEncryptMut, KeyInit, KeyIvInit, StreamCipher,
};

use crate::helpers::decode_material;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Algo {
    Aes,
    Des,
    Tdes,
    Sm4,
}

impl Algo {
    fn name(self) -> &'static str {
        match self {
            Algo::Aes => "AES",
            Algo::Des => "DES",
            Algo::Tdes => "3DES",
            Algo::Sm4 => "SM4",
        }
    }

    fn valid_key_lengths(self) -> &'static [usize] {
        match self {
            Algo::Aes => &[16, 24, 32],
            Algo::Des => &[8],
            Algo::Tdes => &[16, 24],
            Algo::Sm4 => &[16],
        }
    }

    fn block_size(self) -> usize {
        match self {
            Algo::Aes | Algo::Sm4 => 16,
            Algo::Des | Algo::Tdes => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Mode {
    Ecb,
    Cbc,
    Ctr,
    Cfb,
    Ofb,
}

impl Mode {
    fn parse(s: &str) -> OpResult<Mode> {
        match s {
            "ecb" => Ok(Mode::Ecb),
            "cbc" => Ok(Mode::Cbc),
            "ctr" => Ok(Mode::Ctr),
            "cfb" => Ok(Mode::Cfb),
            "ofb" => Ok(Mode::Ofb),
            other => Err(OperationError::invalid_param(
                "mode",
                format!("unknown block cipher mode `{other}`"),
            )),
        }
    }

    fn uses_iv(self) -> bool {
        !matches!(self, Mode::Ecb)
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
                .with_details(format!(
                    "Choose a padding scheme (PKCS7 is standard) or use a stream mode like CTR/CFB/OFB."
                )));
            }
            Ok(data.to_vec())
        }
        Padding::Pkcs7 => {
            let n = (block - rem) as u8;
            let mut out = data.to_vec();
            out.extend(std::iter::repeat(n).take(n as usize));
            Ok(out)
        }
        Padding::Zero => {
            let mut out = data.to_vec();
            if rem != 0 {
                out.extend(std::iter::repeat(0u8).take(block - rem));
            }
            Ok(out)
        }
        Padding::Iso7816 => {
            let mut out = data.to_vec();
            out.push(0x80);
            let rem = out.len() % block;
            if rem != 0 {
                out.extend(std::iter::repeat(0u8).take(block - rem));
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
            let last = data.last().copied().ok_or_else(|| {
                OperationError::new(ErrorKind::Decode, "PKCS7: empty plaintext")
            })?;
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

fn key_error(algo: Algo, actual: usize) -> OperationError {
    let lengths: Vec<String> = algo
        .valid_key_lengths()
        .iter()
        .map(|l| l.to_string())
        .collect();
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

fn iv_error(algo: Algo, actual: usize, expected: usize) -> OperationError {
    OperationError::key(format!(
        "{} IV must be {expected} bytes after decoding, got {actual} bytes",
        algo.name()
    ))
    .with_parameter("iv")
    .with_expected(format!("{expected} bytes"))
    .with_actual(format!("{actual} bytes"))
}

// ------------------------------------------------------------- modes ----

use aes::Aes128;
use aes::Aes192;
use aes::Aes256;
use des::Des;
use des::TdesEde2;
use des::TdesEde3;
use sm4::Sm4;

fn encrypt_padded<C>(key: &[u8], data: &[u8]) -> OpResult<Vec<u8>>
where
    C: BlockCipher + BlockEncrypt + KeyInit,
{
    if data.len() % C::block_size() != 0 {
        return Err(OperationError::internal("pre-padded data misaligned"));
    }
    let enc = ecb::Encryptor::<C>::new(key.into());
    Ok(enc.encrypt_padded_vec_mut::<block_padding::NoPadding>(data))
}

fn decrypt_padded<C>(key: &[u8], data: &[u8]) -> OpResult<Vec<u8>>
where
    C: BlockCipher + BlockDecrypt + KeyInit,
{
    let dec = ecb::Decryptor::<C>::new(key.into());
    dec.decrypt_padded_vec_mut::<block_padding::NoPadding>(data)
        .map_err(|e| OperationError::internal(format!("block decrypt failed: {e}")))
}

fn cbc_encrypt<C>(key: &[u8], iv: &[u8], data: &[u8]) -> OpResult<Vec<u8>>
where
    C: BlockCipher + BlockEncrypt + KeyInit,
{
    if data.len() % C::block_size() != 0 {
        return Err(OperationError::internal("pre-padded data misaligned"));
    }
    let enc = cbc::Encryptor::<C>::new(key.into(), iv.into());
    Ok(enc.encrypt_padded_vec_mut::<block_padding::NoPadding>(data))
}

fn cbc_decrypt<C>(key: &[u8], iv: &[u8], data: &[u8]) -> OpResult<Vec<u8>>
where
    C: BlockCipher + BlockDecrypt + KeyInit,
{
    let dec = cbc::Decryptor::<C>::new(key.into(), iv.into());
    dec.decrypt_padded_vec_mut::<block_padding::NoPadding>(data)
        .map_err(|e| OperationError::internal(format!("block decrypt failed: {e}")))
}

fn stream<C>(key: &[u8], iv: &[u8], data: &[u8]) -> OpResult<Vec<u8>>
where
    C: StreamCipher + KeyIvInit,
{
    let mut buf = data.to_vec();
    let mut cipher = C::new(key.into(), iv.into());
    cipher.apply_keystream(&mut buf);
    Ok(buf)
}

/// CFB-128 with partial final block, matching the classic construction:
/// C_i = P_i XOR E(C_{i-1}); the IV advances with full ciphertext blocks.
/// Implemented directly because RustCrypto exposes CFB only through the
/// padded block-mode API, which cannot express a partial final block.
fn cfb_encrypt<C>(key: &[u8], iv: &[u8], data: &[u8]) -> OpResult<Vec<u8>>
where
    C: BlockCipher + BlockEncrypt + KeyInit,
{
    let bs = C::block_size();
    let cipher = C::new(GenericArray::from_slice(key));
    let mut prev = GenericArray::<u8, C::BlockSize>::clone_from_slice(&iv[..bs]);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(bs) {
        cipher.encrypt_block(&mut prev);
        let ciphered: Vec<u8> = chunk.iter().zip(prev.iter()).map(|(a, b)| a ^ b).collect();
        if chunk.len() == bs {
            prev = GenericArray::clone_from_slice(&ciphered);
        }
        out.extend_from_slice(&ciphered);
    }
    Ok(out)
}

fn cfb_decrypt<C>(key: &[u8], iv: &[u8], data: &[u8]) -> OpResult<Vec<u8>>
where
    C: BlockCipher + BlockEncrypt + KeyInit,
{
    let bs = C::block_size();
    let cipher = C::new(GenericArray::from_slice(key));
    let mut prev = GenericArray::<u8, C::BlockSize>::clone_from_slice(&iv[..bs]);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(bs) {
        cipher.encrypt_block(&mut prev);
        let plain: Vec<u8> = chunk.iter().zip(prev.iter()).map(|(a, b)| a ^ b).collect();
        if chunk.len() == bs {
            prev = GenericArray::clone_from_slice(chunk);
        }
        out.extend_from_slice(&plain);
    }
    Ok(out)
}

fn block_encrypt(algo: Algo, mode: Mode, key: &[u8], iv: &[u8], data: &[u8]) -> OpResult<Vec<u8>> {
    match (algo, mode) {
        (Algo::Aes, Mode::Ecb) => match key.len() {
            16 => encrypt_padded::<Aes128>(key, data),
            24 => encrypt_padded::<Aes192>(key, data),
            32 => encrypt_padded::<Aes256>(key, data),
            n => Err(key_error(Algo::Aes, n)),
        },
        (Algo::Aes, Mode::Cbc) => match key.len() {
            16 => cbc_encrypt::<Aes128>(key, iv, data),
            24 => cbc_encrypt::<Aes192>(key, iv, data),
            32 => cbc_encrypt::<Aes256>(key, iv, data),
            n => Err(key_error(Algo::Aes, n)),
        },
        (Algo::Aes, Mode::Ctr) => match key.len() {
            16 => stream::<ctr::Ctr128BE<Aes128>>(key, iv, data),
            24 => stream::<ctr::Ctr128BE<Aes192>>(key, iv, data),
            32 => stream::<ctr::Ctr128BE<Aes256>>(key, iv, data),
            n => Err(key_error(Algo::Aes, n)),
        },
        (Algo::Aes, Mode::Cfb) => match key.len() {
            16 => cfb_encrypt::<Aes128>(key, iv, data),
            24 => cfb_encrypt::<Aes192>(key, iv, data),
            32 => cfb_encrypt::<Aes256>(key, iv, data),
            n => Err(key_error(Algo::Aes, n)),
        },
        (Algo::Aes, Mode::Ofb) => match key.len() {
            16 => stream::<ofb::Ofb<Aes128>>(key, iv, data),
            24 => stream::<ofb::Ofb<Aes192>>(key, iv, data),
            32 => stream::<ofb::Ofb<Aes256>>(key, iv, data),
            n => Err(key_error(Algo::Aes, n)),
        },
        (Algo::Sm4, Mode::Ecb) => encrypt_padded::<Sm4>(key, data),
        (Algo::Sm4, Mode::Cbc) => cbc_encrypt::<Sm4>(key, iv, data),
        (Algo::Sm4, Mode::Ctr) => stream::<ctr::Ctr128BE<Sm4>>(key, iv, data),
        (Algo::Sm4, Mode::Cfb) => cfb_encrypt::<Sm4>(key, iv, data),
        (Algo::Sm4, Mode::Ofb) => stream::<ofb::Ofb<Sm4>>(key, iv, data),
        (Algo::Des, Mode::Ecb) => encrypt_padded::<Des>(key, data),
        (Algo::Des, Mode::Cbc) => cbc_encrypt::<Des>(key, iv, data),
        (Algo::Tdes, Mode::Ecb) => match key.len() {
            16 => encrypt_padded::<TdesEde2>(key, data),
            24 => encrypt_padded::<TdesEde3>(key, data),
            n => Err(key_error(Algo::Tdes, n)),
        },
        (Algo::Tdes, Mode::Cbc) => match key.len() {
            16 => cbc_encrypt::<TdesEde2>(key, iv, data),
            24 => cbc_encrypt::<TdesEde3>(key, iv, data),
            n => Err(key_error(Algo::Tdes, n)),
        },
        _ => Err(OperationError::unsupported(format!(
            "{} does not support {:?} mode",
            algo.name(),
            mode
        ))),
    }
}

fn block_decrypt(algo: Algo, mode: Mode, key: &[u8], iv: &[u8], data: &[u8]) -> OpResult<Vec<u8>> {
    match (algo, mode) {
        (Algo::Aes, Mode::Ecb) => match key.len() {
            16 => decrypt_padded::<Aes128>(key, data),
            24 => decrypt_padded::<Aes192>(key, data),
            32 => decrypt_padded::<Aes256>(key, data),
            n => Err(key_error(Algo::Aes, n)),
        },
        (Algo::Aes, Mode::Cbc) => match key.len() {
            16 => cbc_decrypt::<Aes128>(key, iv, data),
            24 => cbc_decrypt::<Aes192>(key, iv, data),
            32 => cbc_decrypt::<Aes256>(key, iv, data),
            n => Err(key_error(Algo::Aes, n)),
        },
        (Algo::Aes, Mode::Ctr) => match key.len() {
            16 => stream::<ctr::Ctr128BE<Aes128>>(key, iv, data),
            24 => stream::<ctr::Ctr128BE<Aes192>>(key, iv, data),
            32 => stream::<ctr::Ctr128BE<Aes256>>(key, iv, data),
            n => Err(key_error(Algo::Aes, n)),
        },
        (Algo::Aes, Mode::Cfb) => match key.len() {
            16 => cfb_decrypt::<Aes128>(key, iv, data),
            24 => cfb_decrypt::<Aes192>(key, iv, data),
            32 => cfb_decrypt::<Aes256>(key, iv, data),
            n => Err(key_error(Algo::Aes, n)),
        },
        (Algo::Aes, Mode::Ofb) => match key.len() {
            16 => stream::<ofb::Ofb<Aes128>>(key, iv, data),
            24 => stream::<ofb::Ofb<Aes192>>(key, iv, data),
            32 => stream::<ofb::Ofb<Aes256>>(key, iv, data),
            n => Err(key_error(Algo::Aes, n)),
        },
        (Algo::Sm4, Mode::Ecb) => decrypt_padded::<Sm4>(key, data),
        (Algo::Sm4, Mode::Cbc) => cbc_decrypt::<Sm4>(key, iv, data),
        (Algo::Sm4, Mode::Ctr) => stream::<ctr::Ctr128BE<Sm4>>(key, iv, data),
        (Algo::Sm4, Mode::Cfb) => cfb_decrypt::<Sm4>(key, iv, data),
        (Algo::Sm4, Mode::Ofb) => stream::<ofb::Ofb<Sm4>>(key, iv, data),
        (Algo::Des, Mode::Ecb) => decrypt_padded::<Des>(key, data),
        (Algo::Des, Mode::Cbc) => cbc_decrypt::<Des>(key, iv, data),
        (Algo::Tdes, Mode::Ecb) => match key.len() {
            16 => decrypt_padded::<TdesEde2>(key, data),
            24 => decrypt_padded::<TdesEde3>(key, data),
            n => Err(key_error(Algo::Tdes, n)),
        },
        (Algo::Tdes, Mode::Cbc) => match key.len() {
            16 => cbc_decrypt::<TdesEde2>(key, iv, data),
            24 => cbc_decrypt::<TdesEde3>(key, iv, data),
            n => Err(key_error(Algo::Tdes, n)),
        },
        _ => Err(OperationError::unsupported(format!(
            "{} does not support {:?} mode",
            algo.name(),
            mode
        ))),
    }
}

// ------------------------------------------------------- op plumbing ----

fn resolved_algo(op_id: &str, key: &[u8]) -> OpResult<Algo> {
    let algo = if op_id.starts_with("aes") {
        Algo::Aes
    } else if op_id.starts_with("sm4") {
        Algo::Sm4
    } else if op_id.starts_with("des") {
        match key.len() {
            8 => Algo::Des,
            16 | 24 => Algo::Tdes,
            n => return Err(key_error(Algo::Tdes, n)),
        }
    } else {
        return Err(OperationError::internal("unknown cipher op"));
    };
    Ok(algo)
}

fn cipher_op(
    op_id: &'static str,
    name: &'static str,
    description: &'static str,
    encrypt: bool,
    cost_note: &'static str,
    tags: &'static [&'static str],
) -> (&'static OperationSpec, impl Fn(&Value, &ParamMap, &ExecutionContext) -> OpResult<Value> + Send + Sync + 'static) {
    let spec = crate::helpers::cipher_spec(op_id, name, description, cost_note, tags);
    let run = move |v: &Value, map: &ParamMap, _: &ExecutionContext| -> OpResult<Value> {
        let bytes = crate::helpers::input_bytes(v, name)?;
        let key = decode_material(map, "key", "key_encoding", "key")?;
        let algo = resolved_algo(op_id, &key)?;
        if !algo.valid_key_lengths().contains(&key.len()) {
            return Err(key_error(algo, key.len()));
        }
        let mode = Mode::parse(map.str_or("mode", "cbc"))?;
        let iv: Option<Vec<u8>> = if mode.uses_iv() {
            let raw = map.str_or("iv", "");
            if raw.is_empty() {
                return Err(OperationError::key(format!(
                    "{}-{mode:?} requires a {}-byte IV",
                    algo.name(),
                    algo.block_size()
                ))
                .with_parameter("iv")
                .with_expected(format!("{} bytes", algo.block_size()))
                .with_actual("empty"));
            }
            let decoded = decode_input(map.str_or("iv_encoding", "hex"), raw)
                .map_err(|e| e.with_parameter("iv"))?;
            if decoded.len() != algo.block_size() {
                return Err(iv_error(algo, decoded.len(), algo.block_size()));
            }
            Some(decoded)
        } else {
            None
        };
        let padding = Padding::parse(map.str_or("padding", "pkcs7"))?;

        let out = if encrypt {
            let padded = pad(bytes.as_ref(), algo.block_size(), padding)?;
            block_encrypt(algo, mode, &key, iv.as_deref().unwrap_or(&[]), &padded)?
        } else {
            let decrypted = block_decrypt(algo, mode, &key, iv.as_deref().unwrap_or(&[]), bytes.as_ref())?;
            unpad(&decrypted, algo.block_size(), padding)?
        };
        Ok(Value::Bytes(out))
    };
    (spec, run)
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

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {

    let tags: &'static [&'static str] = &["crypto", "ctf"];

    let (spec, run) = cipher_op(
        "aes-encrypt", "AES Encrypt",
        "Encrypts with AES. Cipher, mode, and padding are validated explicitly; keys must decode to 16/24/32 bytes.",
        true,
        "NIST FIPS 197 + SP 800-38 family", tags,
    );
    reg.add_simple(spec, run);

    let (spec, run) = cipher_op(
        "aes-decrypt", "AES Decrypt",
        "Decrypts with AES and validates the selected padding scheme.",
        false,
        "NIST FIPS 197 + SP 800-38 family", tags,
    );
    reg.add_simple(spec, run);

    let (spec, run) = cipher_op(
        "des-encrypt", "DES / 3DES Encrypt",
        "Encrypts with DES (8-byte key) or 3DES (16/24-byte key). ECB/CBC modes. Legacy — labeled Broken.",
        true,
        "FIPS 46-3 (withdrawn); NIST SP 800-67 for 3DES", tags,
    );
    reg.add_simple(spec, run);

    let (spec, run) = cipher_op(
        "des-decrypt", "DES / 3DES Decrypt",
        "Decrypts with DES (8-byte key) or 3DES (16/24-byte key). ECB/CBC modes. Legacy — labeled Broken.",
        false,
        "FIPS 46-3 (withdrawn); NIST SP 800-67 for 3DES", tags,
    );
    reg.add_simple(spec, run);

    let (spec, run) = cipher_op(
        "sm4-encrypt", "SM4 Encrypt",
        "Encrypts with SM4 (GB/T 32907). 16-byte key, 16-byte block.",
        true,
        "GB/T 32907-2016", tags,
    );
    reg.add_simple(spec, run);

    let (spec, run) = cipher_op(
        "sm4-decrypt", "SM4 Decrypt",
        "Decrypts with SM4 (GB/T 32907). 16-byte key, 16-byte block.",
        false,
        "GB/T 32907-2016", tags,
    );
    reg.add_simple(spec, run);

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

}
