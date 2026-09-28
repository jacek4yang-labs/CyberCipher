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
        "sm3" => sm3::Sm3::digest(data).to_vec(),
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
