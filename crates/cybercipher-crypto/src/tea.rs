//! TEA family: TEA, XTEA, XXTEA. Not standardized — implemented from the
//! original Wheeler et al. definitions; XXTEA words are little-endian,
//! matching the canonical reference implementation as used in CTF material.

use crate::helpers::{decode_material, input_bytes, p_enc, p_int, p_text};
use cybercipher_core::prelude::*;

const DELTA: u32 = 0x9E37_79B9;

/// TEA: 64-bit block, 16-byte key, fixed 32 cycles.
fn tea_encrypt_block(v: &mut [u32; 2], k: &[u32; 4]) {
    let mut sum: u32 = 0;
    for _ in 0..32 {
        sum = sum.wrapping_add(DELTA);
        v[0] = v[0].wrapping_add(
            ((v[1] << 4).wrapping_add(k[0]))
                ^ (v[1].wrapping_add(sum))
                ^ ((v[1] >> 5).wrapping_add(k[1])),
        );
        v[1] = v[1].wrapping_add(
            ((v[0] << 4).wrapping_add(k[2]))
                ^ (v[0].wrapping_add(sum))
                ^ ((v[0] >> 5).wrapping_add(k[3])),
        );
    }
}

fn tea_decrypt_block(v: &mut [u32; 2], k: &[u32; 4]) {
    let mut sum: u32 = DELTA.wrapping_mul(32);
    for _ in 0..32 {
        v[1] = v[1].wrapping_sub(
            ((v[0] << 4).wrapping_add(k[2]))
                ^ (v[0].wrapping_add(sum))
                ^ ((v[0] >> 5).wrapping_add(k[3])),
        );
        v[0] = v[0].wrapping_sub(
            ((v[1] << 4).wrapping_add(k[0]))
                ^ (v[1].wrapping_add(sum))
                ^ ((v[1] >> 5).wrapping_add(k[1])),
        );
        sum = sum.wrapping_sub(DELTA);
    }
}

/// XTEA: 64-bit block, 16-byte key, configurable rounds (default 32).
fn xtea_encrypt_block(v: &mut [u32; 2], k: &[u32; 4], rounds: u32) {
    let mut sum: u32 = 0;
    for _ in 0..rounds {
        v[0] = v[0].wrapping_add(
            (((v[1] << 4) ^ (v[1] >> 5)).wrapping_add(v[1]))
                ^ (sum.wrapping_add(k[(sum & 3) as usize])),
        );
        sum = sum.wrapping_add(DELTA);
        v[1] = v[1].wrapping_add(
            (((v[0] << 4) ^ (v[0] >> 5)).wrapping_add(v[0]))
                ^ (sum.wrapping_add(k[((sum >> 11) & 3) as usize])),
        );
    }
}

fn xtea_decrypt_block(v: &mut [u32; 2], k: &[u32; 4], rounds: u32) {
    let mut sum: u32 = DELTA.wrapping_mul(rounds);
    for _ in 0..rounds {
        v[1] = v[1].wrapping_sub(
            (((v[0] << 4) ^ (v[0] >> 5)).wrapping_add(v[0]))
                ^ (sum.wrapping_add(k[((sum >> 11) & 3) as usize])),
        );
        sum = sum.wrapping_sub(DELTA);
        v[0] = v[0].wrapping_sub(
            (((v[1] << 4) ^ (v[1] >> 5)).wrapping_add(v[1]))
                ^ (sum.wrapping_add(k[(sum & 3) as usize])),
        );
    }
}

/// XXTEA: variable block length (>= 2 words), little-endian words.
fn xxtea_mx(sum: u32, y: u32, z: u32, p: usize, e: usize, k: &[u32; 4]) -> u32 {
    (((z >> 5) ^ (y << 2)).wrapping_add((y >> 3) ^ (z << 4)))
        ^ ((sum ^ y).wrapping_add(k[(p & 3 ^ e) as usize] ^ z))
}

fn xxtea_encrypt(words: &mut [u32], k: &[u32; 4]) {
    if words.len() < 2 {
        return;
    }
    let n = words.len();
    let rounds = 6 + 52 / n;
    let mut sum: u32 = 0;
    let mut z = words[n - 1];
    for _ in 0..rounds {
        sum = sum.wrapping_add(DELTA);
        let e = (sum >> 2) & 3;
        for p in 0..n - 1 {
            let y = words[p + 1];
            z = words[p]
                .wrapping_add(xxtea_mx(sum, y, z, p, e as usize, k));
            words[p] = z;
        }
        let y = words[0];
        z = words[n - 1]
            .wrapping_add(xxtea_mx(sum, y, z, n - 1, e as usize, k));
        words[n - 1] = z;
    }
}

fn xxtea_decrypt(words: &mut [u32], k: &[u32; 4]) {
    if words.len() < 2 {
        return;
    }
    let n = words.len();
    let rounds = 6 + 52 / n;
    let mut sum: u32 = DELTA.wrapping_mul(rounds as u32);
    let mut y = words[0];
    while sum != 0 {
        let e = (sum >> 2) & 3;
        for p in (1..n).rev() {
            let z = words[p - 1];
            y = words[p].wrapping_sub(xxtea_mx(sum, y, z, p, e as usize, k));
            words[p] = y;
        }
        let z = words[n - 1];
        y = words[0].wrapping_sub(xxtea_mx(sum, y, z, 0, e as usize, k));
        words[0] = y;
        sum = sum.wrapping_sub(DELTA);
    }
}

fn key_words(map: &ParamMap) -> OpResult<[u32; 4]> {
    let key = decode_material(map, "key", "key_encoding", "key")?;
    if key.len() != 16 {
        return Err(OperationError::key(format!(
            "TEA-family key must be 16 bytes after decoding, got {} bytes",
            key.len()
        ))
        .with_parameter("key")
        .with_expected("16 bytes")
        .with_actual(format!("{} bytes", key.len())));
    }
    Ok([
        u32::from_le_bytes(key[0..4].try_into().unwrap()),
        u32::from_le_bytes(key[4..8].try_into().unwrap()),
        u32::from_le_bytes(key[8..12].try_into().unwrap()),
        u32::from_le_bytes(key[12..16].try_into().unwrap()),
    ])
}

fn block_input<'a>(
    v: &'a Value,
    name: &str,
    word_size: usize,
) -> OpResult<std::borrow::Cow<'a, [u8]>> {
    let bytes = input_bytes(v, name)?;
    if bytes.len() % word_size != 0 {
        return Err(OperationError::length(
            format!("multiple of {word_size} bytes"),
            format!("{} bytes", bytes.len()),
            format!("{name} operates on fixed-size blocks"),
        ));
    }
    if name.starts_with("XXTEA") && bytes.len() < 8 {
        return Err(OperationError::length(
            "at least 8 bytes (2 words)",
            format!("{} bytes", bytes.len()),
            "XXTEA requires at least two words",
        ));
    }
    Ok(bytes)
}

fn tea_family_op(
    id: &'static str,
    name: &'static str,
    encrypt: bool,
) -> impl Fn(&Value, &ParamMap, &ExecutionContext) -> OpResult<Value> + Send + Sync + 'static {
    move |v, map, _| {
        let is_xxtea = id.starts_with("xxtea");
        let word_size = if is_xxtea { 4 } else { 8 };
        let bytes = block_input(v, name, word_size)?;
        let k = key_words(map)?;

        if is_xxtea {
            let mut words: Vec<u32> = bytes
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect();
            if encrypt {
                xxtea_encrypt(&mut words, &k);
            } else {
                xxtea_decrypt(&mut words, &k);
            }
            let mut out = Vec::with_capacity(words.len() * 4);
            for w in &words {
                out.extend_from_slice(&w.to_le_bytes());
            }
            return Ok(Value::Bytes(out));
        }

        let rounds = if id.starts_with("xtea") {
            map.int_or("rounds", 32).clamp(1, 1024) as u32
        } else {
            32
        };
        let mut out = Vec::with_capacity(bytes.len());
        for chunk in bytes.chunks_exact(8) {
            let mut block = [
                u32::from_be_bytes(chunk[0..4].try_into().unwrap()),
                u32::from_be_bytes(chunk[4..8].try_into().unwrap()),
            ];
            match (id, encrypt) {
                ("tea", true) => tea_encrypt_block(&mut block, &k),
                ("tea", false) => tea_decrypt_block(&mut block, &k),
                ("xtea", true) => xtea_encrypt_block(&mut block, &k, rounds),
                ("xtea", false) => xtea_decrypt_block(&mut block, &k, rounds),
                _ => return Err(OperationError::internal("bad tea op")),
            }
            out.extend_from_slice(&block[0].to_be_bytes());
            out.extend_from_slice(&block[1].to_be_bytes());
        }
        Ok(Value::Bytes(out))
    }
}

fn tea_spec(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    security: Security,
    with_rounds: bool,
) -> &'static OperationSpec {
    let mut params = vec![
        p_text("key", "Key", "", "16 bytes after decoding."),
        p_enc("key_encoding", "Key encoding", "hex", ""),
    ];
    if with_rounds {
        params.push(p_int("rounds", "Rounds", 32, "XTEA cycles; 32 is standard (64 Feistel rounds)."));
    }
    Box::leak(Box::new(OperationSpec {
        id,
        name,
        description,
        category: Category::Crypto,
        input_kinds: Box::leak(vec![ValueKind::Bytes, ValueKind::Text].into_boxed_slice()),
        output_kind: ValueKind::Bytes,
        params: Box::leak(params.into_boxed_slice()),
        cost: CostClass::Instant,
        security,
        deterministic: true,
        reversible: true,
        aliases: Box::leak(vec![id.split('-').next().unwrap_or(id)].into_boxed_slice()),
        tags: &["crypto", "ctf"],
        provenance: Provenance {
            standard: "Wheeler, Needham, Jones: TEA/XTEA/XXTEA (unstandardized)",
            implementation: "CyberCipher native Rust",
            test_vectors: "Known-answer + round-trip tests",
        },
    }))
}

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    let legacy = Security::Legacy;
    reg.add_simple(tea_spec("tea-encrypt", "TEA Encrypt",
        "Encrypts 64-bit big-endian blocks with TEA (32 cycles). Input must be a multiple of 8 bytes.", legacy, false),
        tea_family_op("tea", "TEA Encrypt", true));
    reg.add_simple(tea_spec("tea-decrypt", "TEA Decrypt",
        "Decrypts TEA blocks (32 cycles).", legacy, false),
        tea_family_op("tea", "TEA Decrypt", false));
    reg.add_simple(tea_spec("xtea-encrypt", "XTEA Encrypt",
        "Encrypts 64-bit big-endian blocks with XTEA. Input must be a multiple of 8 bytes.", legacy, true),
        tea_family_op("xtea", "XTEA Encrypt", true));
    reg.add_simple(tea_spec("xtea-decrypt", "XTEA Decrypt",
        "Decrypts XTEA blocks.", legacy, true),
        tea_family_op("xtea", "XTEA Decrypt", false));
    reg.add_simple(tea_spec("xxtea-encrypt", "XXTEA Encrypt",
        "Encrypts variable-length blocks (little-endian words, >= 2 words) with XXTEA.", legacy, false),
        tea_family_op("xxtea", "XXTEA Encrypt", true));
    reg.add_simple(tea_spec("xxtea-decrypt", "XXTEA Decrypt",
        "Decrypts XXTEA blocks (little-endian words).", legacy, false),
        tea_family_op("xxtea", "XXTEA Decrypt", false));
}
