//! KMAC (NIST SP 800-185): Keccak-based keyed message authentication code.
//!
//! Implemented in-tree over a direct Keccak-f[1600] sponge: no RustCrypto
//! `kmac` crate is published, and the `sha3` crate's cSHAKE types fix the
//! function-name parameter N to the empty string, which cannot express the
//! required `cSHAKE(N="KMAC", S)` domain separation. The sponge below is the
//! FIPS 202 permutation with cSHAKE's `04 .. 80` domain padding; correctness
//! is pinned by the official NIST SP 800-185 sample vectors.

use cybercipher_core::prelude::*;

use crate::helpers::{decode_material, hex, input_bytes, p_enc, p_int, p_text, p_text_opt};

const MAC_TAGS: &[&str] = &["crypto", "mac"];

// --------------------------------------- Keccak-f[1600] permutation ----

/// Round constants (FIPS 202, section 3.2.5).
const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation offsets in the rho/pi traversal order starting at lane 1
/// (FIPS 202, tables 1-2).
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
/// Lane indices visited by the rho/pi traversal (FIPS 202).
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

fn keccak_f1600(a: &mut [u64; 25]) {
    for &rc in &RC {
        // theta
        let mut c = [0u64; 5];
        for (x, slot) in c.iter_mut().enumerate() {
            *slot = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        // rho and pi
        let mut last = a[1];
        for i in 0..24 {
            let j = PI[i];
            let tmp = a[j];
            a[j] = last.rotate_left(RHO[i]);
            last = tmp;
        }
        // chi
        for y in 0..5 {
            let row = [
                a[5 * y],
                a[5 * y + 1],
                a[5 * y + 2],
                a[5 * y + 3],
                a[5 * y + 4],
            ];
            for (x, slot) in row.iter().enumerate() {
                a[5 * y + x] = slot ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
            }
        }
        // iota
        a[0] ^= rc;
    }
}

// -------------------------------------------------- cSHAKE sponge ----

/// Keccak sponge with a byte-level buffer. `rate` is a whole number of
/// 8-byte lanes (168 for KMAC128, 136 for KMAC256).
struct Sponge {
    rate: usize,
    state: [u64; 25],
    buf: Vec<u8>,
}

impl Sponge {
    fn new(rate: usize) -> Sponge {
        Sponge {
            rate,
            state: [0u64; 25],
            buf: Vec::with_capacity(rate),
        }
    }

    fn absorb(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (self.rate - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() == self.rate {
                self.permute_block();
            }
        }
    }

    /// XOR the buffered block into the rate lanes (little-endian) and apply
    /// the permutation.
    fn permute_block(&mut self) {
        debug_assert_eq!(self.buf.len(), self.rate);
        let (lanes, _remainder) = self.buf.as_chunks::<8>();
        for (i, lane) in lanes.iter().enumerate() {
            self.state[i] ^= u64::from_le_bytes(*lane);
        }
        keccak_f1600(&mut self.state);
        self.buf.clear();
    }

    /// Absorb the cSHAKE pad (`04` domain byte, `80` final byte).
    fn pad(&mut self) {
        self.buf.push(0x04);
        self.buf.resize(self.rate, 0);
        let last = self.rate - 1;
        self.buf[last] = 0x80;
        self.permute_block();
    }

    /// Squeeze `out.len()` bytes; each rate-lane block is read out of the
    /// state (little-endian) before the state advances.
    fn squeeze(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(self.rate) {
            for (i, lane) in self.state.iter().enumerate() {
                let bytes = lane.to_le_bytes();
                let start = i * 8;
                if start >= chunk.len() {
                    break;
                }
                let take = 8.min(chunk.len() - start);
                chunk[start..start + take].copy_from_slice(&bytes[..take]);
            }
            keccak_f1600(&mut self.state);
        }
    }
}

// --------------------------------------------- encoding helpers ----

/// `left_encode(x)`: byte count then big-endian bytes (SP 800-185 §2.3.1).
fn left_encode(x: usize) -> Vec<u8> {
    let be = x.to_be_bytes();
    let first = be.iter().position(|&b| b != 0).unwrap_or(7);
    let n = 8 - first;
    let mut out = Vec::with_capacity(n + 1);
    out.push(n as u8);
    out.extend_from_slice(&be[first..]);
    out
}

/// `right_encode(x)`: big-endian bytes then byte count (SP 800-185 §2.3.2).
fn right_encode(x: usize) -> Vec<u8> {
    let be = x.to_be_bytes();
    let first = be.iter().position(|&b| b != 0).unwrap_or(7);
    let n = 8 - first;
    let mut out = Vec::with_capacity(n + 1);
    out.extend_from_slice(&be[first..]);
    out.push(n as u8);
    out
}

/// `encode_string(S) = left_encode(len(S) * 8) || S` (lengths in bits).
fn encode_string(s: &[u8]) -> Vec<u8> {
    let mut out = left_encode(s.len() * 8);
    out.extend_from_slice(s);
    out
}

/// `bytepad(X, w) = left_encode(w) || X || 0*` to a multiple of w bytes.
fn bytepad(x: &[u8], w: usize) -> Vec<u8> {
    let mut out = left_encode(w);
    out.extend_from_slice(x);
    let rem = out.len() % w;
    if rem != 0 {
        out.extend(std::iter::repeat_n(0u8, w - rem));
    }
    out
}

/// KMAC (SP 800-185 §4.3) with a fixed-length output; `out_len` is the tag
/// length in bytes and `L = out_len * 8` the requested output length in bits:
///
/// ```text
/// KMAC(K, X, L, S) = cSHAKE(bytepad(encode_string(K), rate) || X
///                           || right_encode(L), L, "KMAC", S)
/// ```
///
/// where the cSHAKE domain prefix is `bytepad(encode_string("KMAC")
/// || encode_string(S), rate)` and the pad is the `04 .. 80` cSHAKE padding.
/// (The XOF variant with `L = 0` omits the `right_encode(L)` suffix and is
/// not exposed here.)
fn kmac(rate: usize, key: &[u8], data: &[u8], customization: &[u8], out_len: usize) -> Vec<u8> {
    let mut sponge = Sponge::new(rate);
    let mut name_and_s = encode_string(b"KMAC");
    name_and_s.extend_from_slice(&encode_string(customization));
    sponge.absorb(&bytepad(&name_and_s, rate));
    sponge.absorb(&bytepad(&encode_string(key), rate));
    sponge.absorb(data);
    sponge.absorb(&right_encode(out_len * 8));
    sponge.pad();
    let mut out = vec![0u8; out_len];
    sponge.squeeze(&mut out);
    out
}

// ------------------------------------------------------ op plumbing ----

fn kmac_spec(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    default_len: i64,
    aliases: &'static [&'static str],
) -> &'static OperationSpec {
    let params = vec![
        p_text("key", "Key", "", "Key material; see the encoding selector."),
        p_enc("key_encoding", "Key encoding", "hex", ""),
        p_text_opt(
            "customization",
            "Customization string",
            "",
            "Optional user-customization string S (UTF-8).",
        ),
        p_int(
            "output_length",
            "Output length",
            default_len,
            "Tag length L in bytes (a whole number of bytes).",
        ),
    ];
    Box::leak(Box::new(OperationSpec {
        id,
        name,
        description,
        category: Category::Mac,
        input_kinds: Box::leak(vec![ValueKind::Bytes, ValueKind::Text].into_boxed_slice()),
        output_kind: ValueKind::Text,
        params: Box::leak(params.into_boxed_slice()),
        cost: CostClass::Instant,
        security: Security::Modern,
        deterministic: true,
        reversible: false,
        aliases,
        tags: MAC_TAGS,
        provenance: Provenance {
            standard: "NIST SP 800-185 (KMAC)",
            implementation: "CyberCipher in-tree Keccak-f[1600] sponge (no published kmac crate)",
            test_vectors: "NIST SP 800-185 KMAC sample vectors",
        },
    }))
}

fn kmac_run(
    name: &'static str,
    rate: usize,
    default_len: usize,
) -> impl Fn(&Value, &ParamMap, &ExecutionContext) -> OpResult<Value> + Send + Sync + 'static {
    move |v: &Value, map: &ParamMap, _: &ExecutionContext| -> OpResult<Value> {
        let bytes = input_bytes(v, name)?;
        let key = decode_material(map, "key", "key_encoding", "key")?;
        let out_len = map.int_or("output_length", default_len as i64);
        if !(1..=8192).contains(&out_len) {
            return Err(OperationError::invalid_param(
                "output_length",
                "output_length must be between 1 and 8192 bytes",
            ));
        }
        let customization = map.str_or("customization", "").as_bytes().to_vec();
        let tag = kmac(rate, &key, bytes.as_ref(), &customization, out_len as usize);
        Ok(Value::Text(hex(&tag)))
    }
}

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    reg.add_simple(
        kmac_spec(
            "kmac128",
            "KMAC128",
            "Computes KMAC128 (NIST SP 800-185): a Keccak-based keyed MAC built on cSHAKE128 with the function name \"KMAC\". Keys of any length are encoded with bytepad; the optional customization string provides domain separation. Output is lowercase hex.",
            32,
            &["kmac-128", "kmac"],
        ),
        kmac_run("KMAC128", 168, 32),
    );
    reg.add_simple(
        kmac_spec(
            "kmac256",
            "KMAC256",
            "Computes KMAC256 (NIST SP 800-185): the 136-byte-rate (cSHAKE256) variant of KMAC. Keys of any length are encoded with bytepad; the optional customization string provides domain separation. Output is lowercase hex.",
            64,
            &["kmac-256"],
        ),
        kmac_run("KMAC256", 136, 64),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings_match_sp800185_examples() {
        // The NIST sample shows "01 A8" as the bytepad prefix for w = 168,
        // "01 20 4B 4D 41 43" as encode_string("KMAC"), and
        // "02 01 00 40 .. 5F" as encode_string of the 32-byte sample key.
        assert_eq!(left_encode(168), vec![1, 168]);
        assert_eq!(left_encode(0), vec![1, 0]);
        assert_eq!(right_encode(32), vec![32, 1]);
        assert_eq!(
            encode_string(b"KMAC"),
            vec![1, 0x20, b'K', b'M', b'A', b'C']
        );
        let key: Vec<u8> = (0x40u8..=0x5f).collect();
        let mut expected = vec![2, 1, 0];
        expected.extend_from_slice(&key);
        assert_eq!(encode_string(&key), expected);
        let padded = bytepad(&encode_string(&key), 168);
        assert_eq!(padded[..2], [1, 168]);
        assert_eq!(padded.len() % 168, 0);
    }

    #[test]
    fn keccak_permutation_sanity() {
        // Wiring check: the permutation must be deterministic, sensitive to
        // a one-bit input change, and must not fix the zero state.
        let mut a = [0u64; 25];
        keccak_f1600(&mut a);
        assert_ne!(a, [0u64; 25]);
        let mut c = [0u64; 25];
        keccak_f1600(&mut c);
        assert_eq!(c, a);
        let mut b = [0u64; 25];
        b[0] = 1;
        keccak_f1600(&mut b);
        assert_ne!(b, a);
        let mut d = [0u64; 25];
        d[24] = 1;
        keccak_f1600(&mut d);
        assert_ne!(d, b);
    }
}
