//! Hash and MAC operations, backed by RustCrypto digest implementations.
//! Output is lowercase hex text.

use crate::helpers::{hex, input_bytes};
use cybercipher_core::prelude::*;
use digest::{Digest, ExtendableOutput, Update, XofReader};

const HASH_TAGS: &[&str] = &["hash", "ctf"];

fn digest_bytes(algo: &str, data: &[u8], shake_len: usize) -> OpResult<Vec<u8>> {
    let out = match algo {
        "md5" => md5::Md5::digest(data).to_vec(),
        "sha1" => sha1::Sha1::digest(data).to_vec(),
        "sha224" => sha2::Sha224::digest(data).to_vec(),
        "sha256" => sha2::Sha256::digest(data).to_vec(),
        "sha384" => sha2::Sha384::digest(data).to_vec(),
        "sha512" => sha2::Sha512::digest(data).to_vec(),
        "sha3-224" => sha3::Sha3_224::digest(data).to_vec(),
        "sha3-256" => sha3::Sha3_256::digest(data).to_vec(),
        "sha3-384" => sha3::Sha3_384::digest(data).to_vec(),
        "sha3-512" => sha3::Sha3_512::digest(data).to_vec(),
        "keccak256" => sha3::Keccak256::digest(data).to_vec(),
        "keccak512" => sha3::Keccak512::digest(data).to_vec(),
        "keccak224" => sha3::Keccak224::digest(data).to_vec(),
        "keccak384" => sha3::Keccak384::digest(data).to_vec(),
        "md4" => md4::Md4::digest(data).to_vec(),
        "ripemd160" => ripemd::Ripemd160::digest(data).to_vec(),
        "blake2b" => blake2::Blake2b512::digest(data).to_vec(),
        "blake2s" => blake2::Blake2s256::digest(data).to_vec(),
        "whirlpool" => whirlpool::Whirlpool::digest(data).to_vec(),
        "sm3" => sm3::Sm3::digest(data).to_vec(),
        "md2" => md2::Md2::digest(data).to_vec(),
        "tiger" => tiger::Tiger::digest(data).to_vec(),
        "streebog-256" => streebog::Streebog256::digest(data).to_vec(),
        "streebog-512" => streebog::Streebog512::digest(data).to_vec(),
        "gost94" => gost94::Gost94Test::digest(data).to_vec(),
        "shabal" => shabal::Shabal512::digest(data).to_vec(),
        "groestl-256" => groestl::Groestl256::digest(data).to_vec(),
        "groestl-512" => groestl::Groestl512::digest(data).to_vec(),
        "shake128" => {
            let mut hasher = sha3::Shake128::default();
            hasher.update(data);
            let mut reader = hasher.finalize_xof();
            let mut out = vec![0u8; shake_len];
            reader.read(&mut out);
            out
        }
        "shake256" => {
            let mut hasher = sha3::Shake256::default();
            hasher.update(data);
            let mut reader = hasher.finalize_xof();
            let mut out = vec![0u8; shake_len];
            reader.read(&mut out);
            out
        }
        other => {
            return Err(OperationError::invalid_param(
                "algorithm",
                format!("unknown hash algorithm `{other}`"),
            ))
        }
    };
    Ok(out)
}

fn hash_op(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    aliases: &'static [&'static str],
    security: Security,
    standard: &'static str,
    vectors: &'static str,
) -> (
    &'static OperationSpec,
    impl Fn(&Value, &ParamMap, &ExecutionContext) -> OpResult<Value> + Send + Sync + 'static,
) {
    let spec = Box::leak(Box::new(OperationSpec {
        id,
        name,
        description,
        category: Category::Hash,
        input_kinds: Box::leak(vec![ValueKind::Bytes, ValueKind::Text].into_boxed_slice()),
        output_kind: ValueKind::Text,
        params: Box::leak(vec![].into_boxed_slice()),
        cost: CostClass::Instant,
        security,
        deterministic: true,
        reversible: false,
        aliases,
        tags: HASH_TAGS,
        provenance: Provenance {
            standard,
            implementation: "RustCrypto digest crates",
            test_vectors: vectors,
        },
    }));
    let run = move |v: &Value, _: &ParamMap, _: &ExecutionContext| -> OpResult<Value> {
        let bytes = input_bytes(v, name)?;
        Ok(Value::Text(hex(&digest_bytes(id, bytes.as_ref(), 32)?)))
    };
    (spec, run)
}

fn sha3_spec(
    id: &'static str,
    name: &'static str,
    aliases: &'static [&'static str],
    standard: &'static str,
) -> &'static OperationSpec {
    Box::leak(Box::new(OperationSpec {
        id,
        name,
        description: "Hashes the input; XOF variants take an output length in bytes.",
        category: Category::Hash,
        input_kinds: Box::leak(vec![ValueKind::Bytes, ValueKind::Text].into_boxed_slice()),
        output_kind: ValueKind::Text,
        params: Box::leak(
            vec![ParamSpec {
                key: "variant",
                label: "Variant",
                kind: ParamKind::Options,
                default: ParamDefault::Str("sha3-256"),
                optional: false,
                hint: "SHAKE variants use the output length parameter.",
                options: Box::leak(
                    vec![
                        ParamOption {
                            value: "sha3-224",
                            label: "SHA3-224",
                        },
                        ParamOption {
                            value: "sha3-256",
                            label: "SHA3-256",
                        },
                        ParamOption {
                            value: "sha3-384",
                            label: "SHA3-384",
                        },
                        ParamOption {
                            value: "sha3-512",
                            label: "SHA3-512",
                        },
                        ParamOption {
                            value: "shake128",
                            label: "SHAKE128",
                        },
                        ParamOption {
                            value: "shake256",
                            label: "SHAKE256",
                        },
                        ParamOption {
                            value: "keccak224",
                            label: "Keccak-224 (pre-standard padding)",
                        },
                        ParamOption {
                            value: "keccak256",
                            label: "Keccak-256 (pre-standard padding)",
                        },
                        ParamOption {
                            value: "keccak384",
                            label: "Keccak-384 (pre-standard padding)",
                        },
                        ParamOption {
                            value: "keccak512",
                            label: "Keccak-512 (pre-standard padding)",
                        },
                    ]
                    .into_boxed_slice(),
                ),
            }]
            .into_boxed_slice(),
        ),
        cost: CostClass::Instant,
        security: Security::Modern,
        deterministic: true,
        reversible: false,
        aliases,
        tags: HASH_TAGS,
        provenance: Provenance {
            standard,
            implementation: "RustCrypto `sha3` crate",
            test_vectors: "NIST KAT / published SHA3 vectors",
        },
    }))
}

fn hmac_run(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "HMAC")?;
    let raw = map.require_str("key")?;
    let enc = map.str_or("key_encoding", "hex");
    let key = cybercipher_codec::decode_input(enc, raw).map_err(|e| e.with_parameter("key"))?;
    let algo = map.str_or("algorithm", "sha256");
    let mac_bytes: Vec<u8> = match algo {
        "md5" => hmac_of::<hmac::Hmac<md5::Md5>>(key, bytes.as_ref())?,
        "sha1" => hmac_of::<hmac::Hmac<sha1::Sha1>>(key, bytes.as_ref())?,
        "sha224" => hmac_of::<hmac::Hmac<sha2::Sha224>>(key, bytes.as_ref())?,
        "sha256" => hmac_of::<hmac::Hmac<sha2::Sha256>>(key, bytes.as_ref())?,
        "sha384" => hmac_of::<hmac::Hmac<sha2::Sha384>>(key, bytes.as_ref())?,
        "sha512" => hmac_of::<hmac::Hmac<sha2::Sha512>>(key, bytes.as_ref())?,
        "sha3-256" => hmac_of::<hmac::Hmac<sha3::Sha3_256>>(key, bytes.as_ref())?,
        "sm3" => hmac_of::<hmac::Hmac<sm3::Sm3>>(key, bytes.as_ref())?,
        other => {
            return Err(OperationError::invalid_param(
                "algorithm",
                format!("unknown HMAC algorithm `{other}`"),
            ))
        }
    };
    Ok(Value::Text(hex(&mac_bytes)))
}

fn hmac_of<M: hmac::Mac + digest::KeyInit>(key: Vec<u8>, data: &[u8]) -> OpResult<Vec<u8>> {
    let mut mac = <M as digest::KeyInit>::new_from_slice(&key)
        .map_err(|e| OperationError::key(format!("HMAC key rejected: {e}")))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    use cybercipher_core::Security::{Broken, Legacy, Modern};

    let (spec, run) = hash_op(
        "md5",
        "MD5",
        "Computes the MD5 digest. Broken for collision resistance; still ubiquitous in CTF.",
        &["md5 hash"],
        Broken,
        "RFC 1321",
        "RFC 1321 test suite",
    );
    reg.add_simple(spec, run);

    let (spec, run) = hash_op(
        "sha1",
        "SHA-1",
        "Computes the SHA-1 digest. Legacy; collision attacks are practical.",
        &["sha1 hash"],
        Legacy,
        "FIPS 180-4",
        "NIST / RFC 3174 vectors",
    );
    reg.add_simple(spec, run);

    for (id, name, desc, aliases, security, standard) in [
        (
            "sha224",
            "SHA-224",
            "Computes the SHA-224 digest.",
            &["sha224"][..],
            Modern,
            "FIPS 180-4",
        ),
        (
            "sha256",
            "SHA-256",
            "Computes the SHA-256 digest.",
            &["sha256"][..],
            Modern,
            "FIPS 180-4",
        ),
        (
            "sha384",
            "SHA-384",
            "Computes the SHA-384 digest.",
            &["sha384"][..],
            Modern,
            "FIPS 180-4",
        ),
        (
            "sha512",
            "SHA-512",
            "Computes the SHA-512 digest.",
            &["sha512"][..],
            Modern,
            "FIPS 180-4",
        ),
    ] {
        let (spec, run) = hash_op(
            id,
            name,
            desc,
            aliases,
            security,
            standard,
            "NIST FIPS 180-4 example vectors",
        );
        reg.add_simple(spec, run);
    }

    let (spec, run) = hash_op(
        "sm3",
        "SM3",
        "Computes the SM3 digest (Chinese national standard).",
        &["sm3 hash"],
        Modern,
        "GB/T 32905-2016",
        "GB/T 32905 standard examples",
    );
    reg.add_simple(spec, run);

    for (id, name, desc, aliases, security, standard, vectors) in [
        (
            "md4",
            "MD4",
            "Computes the MD4 digest. Broken; predecessor of MD5, still requested for legacy NTLM work.",
            &["md4 hash"][..],
            Broken,
            "RFC 1320",
            "RFC 1320 test suite",
        ),
        (
            "ripemd160",
            "RIPEMD-160",
            "Computes the RIPEMD-160 digest (Bitcoin address hashing, older PKI).",
            &["ripemd160 hash", "ripemd"],
            Legacy,
            "ISO/IEC 10118-3 (RIPEMD-160)",
            "RIPEMD-160 reference vectors (Dobbertin, Bosselaers, Preneel)",
        ),
        (
            "blake2b",
            "BLAKE2b-512",
            "Computes the unkeyed BLAKE2b-512 digest.",
            &["blake2b hash", "blake2"],
            Modern,
            "RFC 7693",
            "RFC 7693 test vectors",
        ),
        (
            "blake2s",
            "BLAKE2s-256",
            "Computes the unkeyed BLAKE2s-256 digest.",
            &["blake2s hash", "blake2"],
            Modern,
            "RFC 7693",
            "RFC 7693 test vectors",
        ),
        (
            "whirlpool",
            "Whirlpool",
            "Computes the Whirlpool-1.0 digest (NESSIE-selected 512-bit hash).",
            &["whirlpool hash"],
            Legacy,
            "ISO/IEC 10118-3 (Whirlpool)",
            "NESSIE / ISO reference vectors",
        ),
    ] {
        let (spec, run) = hash_op(id, name, desc, aliases, security, standard, vectors);
        reg.add_simple(spec, run);
    }

    // Batch D: residual legacy/national digest families.
    for (id, name, desc, aliases, security, standard, vectors) in [
        (
            "md2",
            "MD2",
            "Computes the MD2 digest. Broken; RFC 1319 legacy, still seen in old PKI and CTF material.",
            &["md2 hash"][..],
            Broken,
            "RFC 1319",
            "RFC 1319 test suite / reference implementation vectors",
        ),
        (
            "tiger",
            "Tiger",
            "Computes the Tiger-192 digest (Anderson & Biham, FSE 1996); used by DC++ and Gajim message digests.",
            &["tiger hash", "tiger192"][..],
            Legacy,
            "Tiger (Anderson & Biham, FSE 1996)",
            "Tiger reference implementation test vectors",
        ),
        (
            "streebog-256",
            "Streebog-256",
            "Computes the Streebog-256 digest (GOST R 34.11-2012, 256-bit output).",
            &["streebog256", "gost3411-256"][..],
            Modern,
            "GOST R 34.11-2012 / RFC 6986",
            "GOST R 34.11-2012 test vectors (RFC 6986 appendix)",
        ),
        (
            "streebog-512",
            "Streebog-512",
            "Computes the Streebog-512 digest (GOST R 34.11-2012, 512-bit output).",
            &["streebog512", "gost3411-512"][..],
            Modern,
            "GOST R 34.11-2012 / RFC 6986",
            "GOST R 34.11-2012 test vectors (RFC 6986 appendix)",
        ),
        (
            "gost94",
            "GOST R 34.11-94",
            "Computes the GOST R 34.11-94 digest with the standard's test parameter set (S-box id-GostR3411-94-Test). Broken; superseded by Streebog.",
            &["gost94 hash", "gost3411-94"][..],
            Broken,
            "GOST R 34.11-94",
            "GOST R 34.11-94 test-suite vectors",
        ),
        (
            "shabal",
            "Shabal-512",
            "Computes the Shabal-512 digest (SHA-3 candidate family); the 512-bit variant of the five output sizes defined by the submission.",
            &["shabal hash", "shabal-512"][..],
            Legacy,
            "Shabal SHA-3 submission (Peneaud et al.)",
            "Shabal submission test values",
        ),
        (
            "groestl-256",
            "Grøstl-256",
            "Computes the Grøstl-256 digest (SHA-3 finalist, round 3).",
            &["groestl hash", "groestl256", "groestl-256"][..],
            Modern,
            "Grøstl SHA-3 submission (Gauravaram et al.)",
            "Grøstl reference ShortMsgKAT vectors",
        ),
        (
            "groestl-512",
            "Grøstl-512",
            "Computes the Grøstl-512 digest (SHA-3 finalist, round 3).",
            &["groestl hash", "groestl512", "groestl-512"][..],
            Modern,
            "Grøstl SHA-3 submission (Gauravaram et al.)",
            "Grøstl reference ShortMsgKAT vectors",
        ),
    ] {
        let (spec, run) = hash_op(id, name, desc, aliases, security, standard, vectors);
        reg.add_simple(spec, run);
    }

    // SHA-3 family with variant selection.
    let sha3_spec = sha3_spec(
        "sha3",
        "SHA-3 / SHAKE",
        &["sha3", "keccak", "shake"],
        "FIPS 202",
    );
    reg.add_simple(sha3_spec, |v, map, _| {
        let bytes = input_bytes(v, "SHA-3 / SHAKE")?;
        let variant = map.str_or("variant", "sha3-256");
        let shake_len = map.int_or("output_length", 32).clamp(1, 8192) as usize;
        Ok(Value::Text(hex(&digest_bytes(
            variant,
            bytes.as_ref(),
            shake_len,
        )?)))
    });

    let hmac_spec = Box::leak(Box::new(OperationSpec {
        id: "hmac",
        name: "HMAC",
        description: "Computes Hash-based Message Authentication Code over the input.",
        category: Category::Mac,
        input_kinds: Box::leak(vec![ValueKind::Bytes, ValueKind::Text].into_boxed_slice()),
        output_kind: ValueKind::Text,
        params: Box::leak(
            vec![
                crate::helpers::p_text("key", "Key", "", ""),
                crate::helpers::p_enc("key_encoding", "Key encoding", "hex", ""),
                crate::helpers::p_opts(
                    "algorithm",
                    "Algorithm",
                    "sha256",
                    &[
                        ParamOption {
                            value: "md5",
                            label: "HMAC-MD5",
                        },
                        ParamOption {
                            value: "sha1",
                            label: "HMAC-SHA1",
                        },
                        ParamOption {
                            value: "sha256",
                            label: "HMAC-SHA256",
                        },
                        ParamOption {
                            value: "sha512",
                            label: "HMAC-SHA512",
                        },
                        ParamOption {
                            value: "sha3-256",
                            label: "HMAC-SHA3-256",
                        },
                        ParamOption {
                            value: "sm3",
                            label: "HMAC-SM3",
                        },
                    ],
                    "",
                ),
            ]
            .into_boxed_slice(),
        ),
        cost: CostClass::Instant,
        security: Security::Modern,
        deterministic: true,
        reversible: false,
        aliases: &["hmac-sha256", "hmac-md5"],
        tags: HASH_TAGS,
        provenance: Provenance {
            standard: "RFC 2104 / FIPS 198-1",
            implementation: "RustCrypto `hmac` crate",
            test_vectors: "RFC 4231 test vectors",
        },
    }));
    reg.add_simple(hmac_spec, hmac_run);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md4_rfc1320_vectors() {
        assert_eq!(
            hex(&digest_bytes("md4", b"", 32).unwrap()),
            "31d6cfe0d16ae931b73c59d7e0c089c0"
        );
        assert_eq!(
            hex(&digest_bytes("md4", b"a", 32).unwrap()),
            "bde52cb31de33e46245e05fbdbd6fb24"
        );
        assert_eq!(
            hex(&digest_bytes("md4", b"abc", 32).unwrap()),
            "a448017aaf21d8525fc10ae87aa6729d"
        );
        assert_eq!(
            hex(&digest_bytes("md4", b"message digest", 32).unwrap()),
            // RFC 1320 section A.5 test suite (verbatim).
            "d9130a8164549fe818874806e1c7014b"
        );
    }

    #[test]
    fn ripemd160_reference_vectors() {
        assert_eq!(
            hex(&digest_bytes("ripemd160", b"", 32).unwrap()),
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        );
        assert_eq!(
            hex(&digest_bytes("ripemd160", b"abc", 32).unwrap()),
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        );
        assert_eq!(
            hex(&digest_bytes("ripemd160", b"message digest", 32).unwrap()),
            "5d0689ef49d2fae572b881b123a85ffa21595f36"
        );
    }

    #[test]
    fn blake2_rfc7693_vectors() {
        assert_eq!(
            hex(&digest_bytes("blake2b", b"abc", 32).unwrap()),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
        assert_eq!(
            hex(&digest_bytes("blake2s", b"abc", 32).unwrap()),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        );
    }

    #[test]
    fn whirlpool_reference_vector() {
        assert_eq!(
            hex(&digest_bytes(
                "whirlpool",
                b"The quick brown fox jumps over the lazy dog",
                32
            )
            .unwrap()),
            "b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725f\
             d2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35"
        );
    }

    #[test]
    fn keccak_variants_are_reachable() {
        // The Keccak padding (pre-SHA-3) variants: Keccak-256's empty digest
        // is the canonical Ethereum empty-trie root.
        assert_eq!(
            hex(&digest_bytes("keccak256", b"", 32).unwrap()),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex(&digest_bytes("keccak224", b"", 32).unwrap()),
            "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd"
        );
        assert_eq!(digest_bytes("keccak384", b"", 32).unwrap().len(), 48);
        assert_eq!(digest_bytes("keccak512", b"", 32).unwrap().len(), 64);
    }

    #[test]
    fn md2_rfc1319_vectors() {
        // RFC 1319 test suite (empty input) and the reference-implementation
        // vector pinned by the RustCrypto crate's KAT blob.
        assert_eq!(
            hex(&digest_bytes("md2", b"", 32).unwrap()),
            "8350e5a3e24c153df2275c9f80692773"
        );
        assert_eq!(
            hex(&digest_bytes("md2", b"The quick brown fox jumps over the lazy dog", 32).unwrap()),
            "03d85a0d629d2c442e987525319fc471"
        );
    }

    #[test]
    fn tiger_reference_vectors() {
        // Anderson & Biham's Tiger reference test vectors (as pinned by the
        // RustCrypto crate KAT).
        assert_eq!(
            hex(&digest_bytes("tiger", b"", 32).unwrap()),
            "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3"
        );
        assert_eq!(
            hex(&digest_bytes("tiger", b"abc", 32).unwrap()),
            "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93"
        );
        assert_eq!(
            hex(
                &digest_bytes("tiger", b"The quick brown fox jumps over the lazy dog", 32).unwrap()
            ),
            "6d12a41e72e644f017b6f0e2f7b44c6285f06dd5d2c5b075"
        );
        assert_eq!(
            hex(&digest_bytes(
                "tiger",
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                32
            )
            .unwrap()),
            "0f7bf9a19b9c58f2b7610df7e84f0ac3a71c631e7b53f78e"
        );
    }

    #[test]
    fn streebog_rfc6986_vectors() {
        // GOST R 34.11-2012 / RFC 6986 appendix: the 63-byte M1 and the
        // zero-length message.
        let m1 = b"012345678901234567890123456789012345678901234567890123456789012";
        assert_eq!(
            hex(&digest_bytes("streebog-256", m1, 32).unwrap()),
            "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500"
        );
        assert_eq!(
            hex(&digest_bytes("streebog-512", m1, 32).unwrap()),
            "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa\
             00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48"
        );
        assert_eq!(
            hex(&digest_bytes("streebog-256", b"", 32).unwrap()),
            "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb"
        );
        assert_eq!(
            hex(&digest_bytes("streebog-512", b"", 32).unwrap()),
            "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7\
             362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a"
        );
    }

    #[test]
    fn gost94_test_vectors() {
        // GOST R 34.11-94 with the standard's test parameter set: the
        // zero-length and "message digest" vectors.
        assert_eq!(
            hex(&digest_bytes("gost94", b"", 32).unwrap()),
            "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d"
        );
        assert_eq!(
            hex(&digest_bytes("gost94", b"message digest", 32).unwrap()),
            "ad4434ecb18f2c99b60cbe59ec3d2469582b65273f48de72db2fde16a4889a4d"
        );
    }

    #[test]
    fn shabal_submission_vectors() {
        // Shabal submission test values (512-bit output).
        assert_eq!(
            hex(&digest_bytes("shabal", b"abc", 32).unwrap()),
            "4a7f0f707c1b0c1d12ddcfa8aa0f9d2410dd9bab57c2d56705fc1acb02066f9\
             9678738cedb20a2aba94842a441e77bc02656fe5690f98b421d029bfc4df09f91"
        );
        assert_eq!(
            hex(&digest_bytes("shabal", b"a", 32).unwrap()),
            "a894803c71f526c3df7a8ac755c28f869828f3de509113043acfef7ce659b0f9\
             d476ec500910975c6d10740f7fd5fb643c1286426dac107a1562f6c1d6578a2a"
        );
    }

    #[test]
    fn groestl_reference_vectors() {
        // Grøstl reference ShortMsgKAT: zero-length message.
        assert_eq!(
            hex(&digest_bytes("groestl-256", b"", 32).unwrap()),
            "1a52d11d550039be16107f9c58db9ebcc417f16f736adb2502567119f0083467"
        );
        assert_eq!(
            hex(&digest_bytes("groestl-512", b"", 32).unwrap()),
            "6d3ad29d279110eef3adbd66de2a0345a77baede1557f5d099fce0c03d6dc2ba\
             8e6d4a6633dfbd66053c20faa87d1a11f39a7fbe4a6c2f009801370308fc4ad8"
        );
    }
}
