//! Checksums and non-cryptographic hashes: CRC-32 / CRC-32C, Adler-32,
//! Fletcher-8/16/32, FNV-1/FNV-1a, djb2, sdbm, Java `hashCode`, and xxHash.
//!
//! These are integrity/identification primitives, not message digests: output
//! is lowercase hex like the digest operations, but the security class is
//! `Neutral` and every provenance cites the defining specification. All
//! parameters follow the de-facto standards (CRC catalog check values, the
//! official FNV vectors, CyberChef's Fletcher definitions, xxHash sanity
//! vectors) so cross-tool values match.

use crate::helpers::input_bytes;
use cybercipher_core::prelude::*;

const TAGS: &[&str] = &["hash", "checksum", "ctf"];

// ---------------------------------------------------------------- crc ----

/// Build a reflected CRC table (bit-reversed polynomial, right shifts) in a
/// `const` context so both CRC variants share one compile-time generator.
const fn crc_reflected_table(poly: u32) -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                poly ^ (crc >> 1)
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// CRC-32/ISO-HDLC — the classic IEEE 802.3 / zlib / gzip CRC.
const CRC32_TABLE: [u32; 256] = crc_reflected_table(0xEDB8_8320);
/// CRC-32/ISCSI (Castagnoli) — iSCSI, ext4, zstd, and SSE4.2 hardware CRC.
const CRC32C_TABLE: [u32; 256] = crc_reflected_table(0x82F6_3B78);

fn crc32_with(table: &[u32; 256], data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc = table[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

// ------------------------------------------------------------ adler-32 ----

const ADLER_MOD: u32 = 65_521;
/// zlib's block size: 5552 additions of a byte cannot overflow 32 bits.
const ADLER_NMAX: usize = 5552;

fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for chunk in data.chunks(ADLER_NMAX) {
        for &byte in chunk {
            a += byte as u32;
            b += a;
        }
        a %= ADLER_MOD;
        b %= ADLER_MOD;
    }
    (b << 16) | a
}

// ------------------------------------------------------------ fletcher ----

/// Fletcher-8: 4-bit running sums mod 15 (CyberChef's definition).
fn fletcher8(data: &[u8]) -> u8 {
    let mut a: u16 = 0;
    let mut b: u16 = 0;
    for &byte in data {
        a = (a + byte as u16) % 15;
        b = (b + a) % 15;
    }
    ((b << 4) | a) as u8
}

/// Fletcher-16: 8-bit running sums mod 255 (the classic RFC 1005 layout).
fn fletcher16(data: &[u8]) -> u16 {
    let mut a: u16 = 0;
    let mut b: u16 = 0;
    for &byte in data {
        a = (a + byte as u16) % 255;
        b = (b + a) % 255;
    }
    (b << 8) | a
}

/// Fletcher-32: 16-bit little-endian words, sums mod 65535; a trailing odd
/// byte is added raw. Result is `(sum2 << 16) | sum1`.
fn fletcher32(data: &[u8]) -> u32 {
    let mut a: u32 = 0;
    let mut b: u32 = 0;
    let words = data.len() / 2;
    for i in 0..words {
        let word = data[2 * i] as u32 | ((data[2 * i + 1] as u32) << 8);
        a = (a + word) % 0xFFFF;
        b = (b + a) % 0xFFFF;
    }
    if data.len() % 2 != 0 {
        a = (a + data[2 * words] as u32) % 0xFFFF;
        b = (b + a) % 0xFFFF;
    }
    (b << 16) | a
}

// ---------------------------------------------------------------- fnv ----

const FNV32_BASIS: u32 = 2_166_136_261;
const FNV32_PRIME: u32 = 16_777_619;
const FNV64_BASIS: u64 = 14_695_981_039_346_656_037;
const FNV64_PRIME: u64 = 1_099_511_628_211;

fn fnv1_32(data: &[u8]) -> u32 {
    let mut hash = FNV32_BASIS;
    for &byte in data {
        hash = hash.wrapping_mul(FNV32_PRIME) ^ byte as u32;
    }
    hash
}

fn fnv1a_32(data: &[u8]) -> u32 {
    let mut hash = FNV32_BASIS;
    for &byte in data {
        hash = (hash ^ byte as u32).wrapping_mul(FNV32_PRIME);
    }
    hash
}

fn fnv1_64(data: &[u8]) -> u64 {
    let mut hash = FNV64_BASIS;
    for &byte in data {
        hash = hash.wrapping_mul(FNV64_PRIME) ^ byte as u64;
    }
    hash
}

fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash = FNV64_BASIS;
    for &byte in data {
        hash = (hash ^ byte as u64).wrapping_mul(FNV64_PRIME);
    }
    hash
}

// ------------------------------------------------- classical text hashes ----

/// Daniel Bernstein's djb2 over 32-bit wrapping arithmetic.
fn djb2(data: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &byte in data {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u32);
    }
    hash
}

/// The sdbm hash (Ozan Yigit) over 32-bit wrapping arithmetic.
fn sdbm(data: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    for &byte in data {
        hash = byte
            .wrapping_add(hash << 6)
            .wrapping_add(hash << 16)
            .wrapping_sub(hash);
    }
    hash
}

/// Java `String.hashCode()`: `h = 31*h + utf16_unit` with 32-bit signed
/// overflow, over the UTF-16 code units of the input.
fn java_hash_code(text: &str) -> i32 {
    let mut hash: i32 = 0;
    for unit in text.encode_utf16() {
        hash = hash.wrapping_mul(31).wrapping_add(unit as i32);
    }
    hash
}

// ------------------------------------------------------------- plumbing ----

#[allow(clippy::too_many_arguments)]
fn checksum_spec(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    aliases: &'static [&'static str],
    standard: &'static str,
    vectors: &'static str,
    params: Vec<ParamSpec>,
) -> &'static OperationSpec {
    Box::leak(Box::new(OperationSpec {
        id,
        name,
        description,
        category: Category::Hash,
        input_kinds: Box::leak(vec![ValueKind::Bytes, ValueKind::Text].into_boxed_slice()),
        output_kind: ValueKind::Text,
        params: Box::leak(params.into_boxed_slice()),
        cost: CostClass::Instant,
        security: Security::Neutral,
        deterministic: true,
        reversible: false,
        aliases,
        tags: TAGS,
        provenance: Provenance {
            standard,
            implementation: "CyberCipher native Rust (table-driven where applicable)",
            test_vectors: vectors,
        },
    }))
}

fn u32_text(value: u32, width: usize) -> String {
    format!("{value:0width$x}")
}

pub(crate) fn register(reg: &mut OperationRegistry) {
    reg.add_simple(
        checksum_spec(
            "crc-32",
            "CRC-32",
            "Computes the CRC-32/ISO-HDLC checksum (IEEE 802.3, zlib, gzip, PNG).",
            &["crc32", "crc", "ieee crc"],
            "ISO 3309 / ITU-T V.42 (CRC-32/ISO-HDLC)",
            "Standard check value: CRC-32(\"123456789\") = 0xCBF43926",
            vec![],
        ),
        |v, _, _| {
            let bytes = input_bytes(v, "CRC-32")?;
            Ok(Value::Text(u32_text(crc32_with(&CRC32_TABLE, &bytes), 8)))
        },
    );

    reg.add_simple(
        checksum_spec(
            "crc-32c",
            "CRC-32C",
            "Computes the CRC-32C (Castagnoli) checksum used by iSCSI, ext4 and zstd.",
            &["crc32c", "castagnoli"],
            "RFC 3720 / Castagnoli (CRC-32/ISCSI)",
            "Standard check value: CRC-32C(\"123456789\") = 0xE3069283",
            vec![],
        ),
        |v, _, _| {
            let bytes = input_bytes(v, "CRC-32C")?;
            Ok(Value::Text(u32_text(crc32_with(&CRC32C_TABLE, &bytes), 8)))
        },
    );

    reg.add_simple(
        checksum_spec(
            "adler-32",
            "Adler-32",
            "Computes the Adler-32 rolling checksum used by zlib and RFC 1950/1952.",
            &["adler32"],
            "RFC 1950 (zlib)",
            "Published example: Adler-32(\"Wikipedia\") = 0x11E60398",
            vec![],
        ),
        |v, _, _| {
            let bytes = input_bytes(v, "Adler-32")?;
            Ok(Value::Text(u32_text(adler32(&bytes), 8)))
        },
    );

    reg.add_simple(
        checksum_spec(
            "fletcher-8",
            "Fletcher-8",
            "Computes the Fletcher-8 checksum: 4-bit running sums mod 15, result \
             (sum2 << 4) | sum1.",
            &["fletcher8"],
            "Fletcher (1982); CyberChef-compatible 4-bit-sum definition",
            "Computed reference: Fletcher-8(\"abcdef\") = 0x2C",
            vec![],
        ),
        |v, _, _| {
            let bytes = input_bytes(v, "Fletcher-8")?;
            Ok(Value::Text(u32_text(fletcher8(&bytes) as u32, 2)))
        },
    );

    reg.add_simple(
        checksum_spec(
            "fletcher-16",
            "Fletcher-16",
            "Computes the Fletcher-16 checksum: 8-bit running sums mod 255, result \
             (sum2 << 8) | sum1.",
            &["fletcher16"],
            "Fletcher (1982) / RFC 1005",
            "Computed reference: Fletcher-16(\"123456789\") = 0x1EDE",
            vec![],
        ),
        |v, _, _| {
            let bytes = input_bytes(v, "Fletcher-16")?;
            Ok(Value::Text(u32_text(fletcher16(&bytes) as u32, 4)))
        },
    );

    reg.add_simple(
        checksum_spec(
            "fletcher-32",
            "Fletcher-32",
            "Computes the Fletcher-32 checksum over 16-bit little-endian words with \
             sums mod 65535; a trailing odd byte is added raw.",
            &["fletcher32"],
            "Fletcher (1982) / RFC 1005",
            "Computed reference: Fletcher-32(\"abcdef\") = 0x56502D2A",
            vec![],
        ),
        |v, _, _| {
            let bytes = input_bytes(v, "Fletcher-32")?;
            Ok(Value::Text(u32_text(fletcher32(&bytes), 8)))
        },
    );

    let fnv_params = vec![crate::helpers::p_opts(
        "variant",
        "Variant",
        "fnv-1a-32",
        &[
            ParamOption {
                value: "fnv-1a-32",
                label: "FNV-1a 32-bit",
            },
            ParamOption {
                value: "fnv-1-32",
                label: "FNV-1 32-bit",
            },
            ParamOption {
                value: "fnv-1a-64",
                label: "FNV-1a 64-bit",
            },
            ParamOption {
                value: "fnv-1-64",
                label: "FNV-1 64-bit",
            },
        ],
        "Which FNV round and width.",
    )];
    reg.add_simple(
        checksum_spec(
            "fnv",
            "FNV-1 / FNV-1a",
            "Computes the Fowler-Noll-Vo hash (FNV-1 or FNV-1a, 32 or 64 bit).",
            &["fnv1", "fnv1a", "fnv-1", "fnv-1a", "fowler-noll-vo"],
            "FNV-1/FNV-1a (L. Noll; IETF draft-eastlake-fnv)",
            "Official vectors (lcn2/fnv): FNV-1a-32(\"foobar\") = 0xBF9CF968, \
             FNV-1-64(\"foobar\") = 0x340D8765A4DDA9C2",
            fnv_params,
        ),
        |v, map, _| {
            let bytes = input_bytes(v, "FNV")?;
            let text = match map.str_or("variant", "fnv-1a-32") {
                "fnv-1-32" => format!("{:08x}", fnv1_32(&bytes)),
                "fnv-1a-64" => format!("{:016x}", fnv1a_64(&bytes)),
                "fnv-1-64" => format!("{:016x}", fnv1_64(&bytes)),
                _ => format!("{:08x}", fnv1a_32(&bytes)),
            };
            Ok(Value::Text(text))
        },
    );

    reg.add_simple(
        checksum_spec(
            "djb2",
            "DJB2",
            "Computes Daniel Bernstein's djb2 hash (h = 33*h + c, 32-bit wrapping).",
            &["djb2 hash", "bernstein hash", "times33"],
            "Daniel Bernstein's hash function (common convention)",
            "Published reference: djb2(\"hello\") = 0x0F923099",
            vec![],
        ),
        |v, _, _| {
            let bytes = input_bytes(v, "DJB2")?;
            Ok(Value::Text(u32_text(djb2(&bytes), 8)))
        },
    );

    reg.add_simple(
        checksum_spec(
            "sdbm",
            "SDBM",
            "Computes the sdbm hash (c + h<<6 + h<<16 - h, 32-bit wrapping) used by \
             Berkeley DB and awk.",
            &["sdbm hash"],
            "sdbm (Ozan Yigit) / Berkeley DB convention",
            "Computed reference: sdbm(\"ab\") = 0x00611841",
            vec![],
        ),
        |v, _, _| {
            let bytes = input_bytes(v, "SDBM")?;
            Ok(Value::Text(u32_text(sdbm(&bytes), 8)))
        },
    );

    let java_params = vec![crate::helpers::p_opts(
        "format",
        "Output format",
        "decimal",
        &[
            ParamOption {
                value: "decimal",
                label: "Signed decimal (Java's natural display)",
            },
            ParamOption {
                value: "hex",
                label: "Hex (32-bit pattern)",
            },
        ],
        "Java prints hashCode() as a signed 32-bit integer.",
    )];
    reg.add_simple(
        checksum_spec(
            "java-hash-code",
            "Java hashCode",
            "Computes Java's String.hashCode(): h = 31*h + UTF-16 unit with 32-bit \
             signed overflow.",
            &["java string hash", "string hashcode"],
            "Java String.hashCode() (JDK specification)",
            "Reference: \"hello\".hashCode() = 99162322",
            java_params,
        ),
        |v, map, _| {
            let text = input_text(v, "Java hashCode")?;
            let hash = java_hash_code(text);
            if map.str_or("format", "decimal") == "hex" {
                Ok(Value::Text(u32_text(hash as u32, 8)))
            } else {
                Ok(Value::Text(hash.to_string()))
            }
        },
    );

    let xxh_params = vec![
        crate::helpers::p_opts(
            "variant",
            "Variant",
            "xxh3-64",
            &[
                ParamOption {
                    value: "xxh3-64",
                    label: "XXH3-64",
                },
                ParamOption {
                    value: "xxh3-128",
                    label: "XXH3-128",
                },
                ParamOption {
                    value: "xxh64",
                    label: "XXH64",
                },
                ParamOption {
                    value: "xxh32",
                    label: "XXH32",
                },
            ],
            "Which xxHash variant to run.",
        ),
        crate::helpers::p_int(
            "seed",
            "Seed",
            0,
            "Seeds are 32-bit for XXH32 and 64-bit for the other variants.",
        ),
    ];
    reg.add_simple(
        checksum_spec(
            "xxhash",
            "xxHash",
            "Computes the xxHash (XXH32/XXH64/XXH3-64/XXH3-128) extremely fast \
             non-cryptographic hash with an optional seed.",
            &["xxh32", "xxh64", "xxh3", "xxhash64"],
            "xxHash (Y. Collet, Cyan4973)",
            "Official sanity vectors: XXH32(\"\") = 0x02CC5D05, \
             XXH64(\"\") = 0xEF46DB3751D8E999, XXH3-64(\"\") = 0x2D06800538D394C2",
            xxh_params,
        ),
        |v, map, _| {
            let bytes = input_bytes(v, "xxHash")?;
            let seed = map.int_or("seed", 0);
            let data = bytes.as_ref();
            let text = match map.str_or("variant", "xxh3-64") {
                "xxh32" => {
                    format!("{:08x}", xxhash_rust::xxh32::xxh32(data, seed as u32))
                }
                "xxh64" => format!("{:016x}", xxhash_rust::xxh64::xxh64(data, seed as u64)),
                "xxh3-128" => format!("{:032x}", xxhash_rust::xxh3::xxh3_128(data)),
                _ => {
                    let h = xxhash_rust::xxh3::xxh3_64_with_seed(data, seed as u64);
                    format!("{h:016x}")
                }
            };
            Ok(Value::Text(text))
        },
    );
}

// -------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> OperationRegistry {
        let mut reg = OperationRegistry::new();
        register(&mut reg);
        reg
    }

    fn run(reg: &OperationRegistry, id: &str, input: &str, params: &[(&str, &str)]) -> String {
        let op = reg.get(id).expect("operation registered");
        let mut map = ParamMap::new();
        for (key, value) in params {
            map.insert(*key, *value);
        }
        match op
            .execute(
                &Value::Text(input.to_string()),
                &map,
                &ExecutionContext::new(),
            )
            .expect("op runs")
        {
            Value::Text(t) => t,
            other => panic!("unexpected output kind: {}", other.kind().name()),
        }
    }

    #[test]
    fn crc32_known_vectors() {
        assert_eq!(crc32_with(&CRC32_TABLE, b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32_with(&CRC32_TABLE, b""), 0);
        assert_eq!(
            crc32_with(&CRC32_TABLE, b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    #[test]
    fn crc32c_known_vectors() {
        assert_eq!(crc32_with(&CRC32C_TABLE, b"123456789"), 0xE306_9283);
        assert_eq!(crc32_with(&CRC32C_TABLE, b""), 0);
    }

    #[test]
    fn adler32_known_vectors() {
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"a"), 0x0062_0062);
    }

    #[test]
    fn adler32_matches_zlib_blocking() {
        // The NMAX blocking must not change the result vs. per-byte reduction.
        let data: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let mut a: u64 = 1;
        let mut b: u64 = 0;
        for &byte in &data {
            a = (a + byte as u64) % 65_521;
            b = (b + a) % 65_521;
        }
        assert_eq!(adler32(&data), ((b as u32) << 16) | a as u32);
    }

    #[test]
    fn fletcher_known_vectors() {
        assert_eq!(fletcher8(b"abcdef"), 0x2C);
        assert_eq!(fletcher16(b"123456789"), 0x1EDE);
        assert_eq!(fletcher32(b"abcdef"), 0x5650_2D2A);
        assert_eq!(fletcher8(b""), 0);
        assert_eq!(fletcher16(b""), 0);
        assert_eq!(fletcher32(b""), 0);
        // A trailing odd byte is folded into the running sums (CyberChef).
        assert_eq!(fletcher32(b"a"), (0u32 << 16) | 0x61);
    }

    #[test]
    fn fnv_official_vectors() {
        assert_eq!(fnv1_32(b""), 0x811C_9DC5);
        assert_eq!(fnv1a_32(b""), 0x811C_9DC5);
        assert_eq!(fnv1_32(b"a"), 0x050C_5D7E);
        assert_eq!(fnv1a_32(b"a"), 0xE40C_292C);
        assert_eq!(fnv1_32(b"foobar"), 0x31F0_B262);
        assert_eq!(fnv1a_32(b"foobar"), 0xBF9C_F968);
        assert_eq!(fnv1_64(b""), 0xCBF2_9CE4_8422_2325);
        assert_eq!(fnv1a_64(b""), 0xCBF2_9CE4_8422_2325);
        assert_eq!(fnv1_64(b"a"), 0xAF63_BD4C_8601_B7BE);
        assert_eq!(fnv1_64(b"foobar"), 0x340D_8765_A4DD_A9C2);
        assert_eq!(fnv1a_64(b"foobar"), 0x8594_4171_F739_67E8);
    }

    #[test]
    fn classical_text_hash_vectors() {
        assert_eq!(djb2(b"hello"), 0x0F92_3099);
        assert_eq!(djb2(b""), 5381);
        assert_eq!(sdbm(b""), 0);
        assert_eq!(sdbm(b"ab"), 0x0061_1841);
        assert_eq!(java_hash_code(""), 0);
        assert_eq!(java_hash_code("hello"), 99_162_322);
    }

    #[test]
    fn xxhash_official_sanity_vectors() {
        assert_eq!(xxhash_rust::xxh32::xxh32(b"", 0), 0x02CC_5D05);
        assert_eq!(xxhash_rust::xxh32::xxh32(b"", 0x9E37_79B1), 0x36B7_8AE7);
        assert_eq!(xxhash_rust::xxh64::xxh64(b"", 0), 0xEF46_DB37_51D8_E999);
        assert_eq!(
            xxhash_rust::xxh64::xxh64(b"", 0x9E37_79B1),
            0xAC75_FDA2_929B_17EF
        );
        assert_eq!(xxhash_rust::xxh3::xxh3_64(b""), 0x2D06_8005_38D3_94C2);
        assert_eq!(
            xxhash_rust::xxh3::xxh3_64_with_seed(b"", 0x9E37_79B1_85EB_CA8D),
            0xA8A6_B918_B2F0_364A
        );
        assert_eq!(
            format!("{:032x}", xxhash_rust::xxh3::xxh3_128(b"")),
            "99aa06d3014798d86001c324468d497f"
        );
    }

    #[test]
    fn checksum_ops_render_hex() {
        let reg = registry();
        assert_eq!(run(&reg, "crc-32", "123456789", &[]), "cbf43926");
        assert_eq!(run(&reg, "crc-32c", "123456789", &[]), "e3069283");
        assert_eq!(run(&reg, "adler-32", "Wikipedia", &[]), "11e60398");
        assert_eq!(run(&reg, "fletcher-16", "123456789", &[]), "1ede");
        assert_eq!(run(&reg, "fletcher-32", "abcdef", &[]), "56502d2a");
        assert_eq!(run(&reg, "djb2", "hello", &[]), "0f923099");
    }

    #[test]
    fn fnv_java_xxhash_op_variants() {
        let reg = registry();
        assert_eq!(
            run(&reg, "fnv", "foobar", &[("variant", "fnv-1a-32")]),
            "bf9cf968"
        );
        assert_eq!(
            run(&reg, "fnv", "foobar", &[("variant", "fnv-1-64")]),
            "340d8765a4dda9c2"
        );
        assert_eq!(
            run(&reg, "fnv", "foobar", &[("variant", "fnv-1-32")]),
            "31f0b262"
        );
        assert_eq!(run(&reg, "java-hash-code", "hello", &[]), "99162322");
        assert_eq!(
            run(&reg, "java-hash-code", "hello", &[("format", "hex")]),
            "05e918d2"
        );
        assert_eq!(
            run(&reg, "xxhash", "", &[("variant", "xxh32")]),
            "02cc5d05"
        );
        assert_eq!(
            run(&reg, "xxhash", "", &[("variant", "xxh64")]),
            "ef46db3751d8e999"
        );
        assert_eq!(
            run(&reg, "xxhash", "", &[("variant", "xxh3-128")]),
            "99aa06d3014798d86001c324468d497f"
        );
    }

    #[test]
    fn java_hash_code_uses_utf16_units() {
        // "𝕏" is U+1D54F: two UTF-16 units, so 31*0xD835 + 0xDD4F (mod 2^32).
        let hash = java_hash_code("\u{1D54F}");
        let expected = 31i32.wrapping_mul(0xD835u32 as i32).wrapping_add(0xDD4Fu32 as i32);
        assert_eq!(hash, expected);
    }
}
