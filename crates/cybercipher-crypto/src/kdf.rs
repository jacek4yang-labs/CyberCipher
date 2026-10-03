//! Key derivation functions: PBKDF2 (RFC 8018), HKDF (RFC 5869), scrypt
//! (RFC 7914), and OpenSSL's legacy EVP_BytesToKey (MD5-based).
//!
//! All operations derive from explicit parameters (password, salt, cost
//! knobs) and return lowercase hex text. Cost parameters are bounded so a
//! GUI misconfiguration cannot exhaust memory or CPU.

use crate::helpers::{hex, p_enc, p_int, p_opts, p_text, p_text_opt};
use cybercipher_codec::decode_input;
use cybercipher_core::prelude::*;
use digest::Digest;

const KDF_TAGS: &[&str] = &["crypto", "kdf"];

/// Upper bound on PBKDF2 iterations accepted by CyberCipher operations.
const MAX_PBKDF2_ROUNDS: i64 = 10_000_000;
/// Upper bound on derived key length for all KDF operations (bytes).
const MAX_DK_LEN: i64 = 8192;
/// scrypt cost cap: log2(N) <= 22 (N <= 4194304).
const MAX_SCRYPT_LOG2_N: u32 = 22;
/// scrypt memory cap: 128 * r * N <= 1 GiB.
const MAX_SCRYPT_MEM_BYTES: u64 = 1 << 30;

fn decode_param(
    map: &ParamMap,
    param: &str,
    enc_param: &str,
    default_enc: &str,
) -> OpResult<Vec<u8>> {
    let raw = map.str_or(param, "");
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    decode_input(map.str_or(enc_param, default_enc), raw).map_err(|e| e.with_parameter(param))
}

fn dk_len_param(map: &ParamMap, what: &str) -> OpResult<usize> {
    let dk_len = map.int_or("dk_len", 32);
    if !(1..=MAX_DK_LEN).contains(&dk_len) {
        return Err(OperationError::invalid_param(
            "dk_len",
            format!("{what} derived key length must be 1-{MAX_DK_LEN} bytes, got {dk_len}"),
        )
        .with_parameter("dk_len")
        .with_expected(format!("1-{MAX_DK_LEN} bytes"))
        .with_actual(format!("{dk_len} bytes")));
    }
    Ok(dk_len as usize)
}

// -------------------------------------------------------- PBKDF2 ----

fn pbkdf2_derive(
    hash: &str,
    password: &[u8],
    salt: &[u8],
    rounds: u32,
    dk: &mut [u8],
) -> OpResult<()> {
    match hash {
        "sha1" => pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, salt, rounds, dk),
        "sha224" => pbkdf2::pbkdf2_hmac::<sha2::Sha224>(password, salt, rounds, dk),
        "sha256" => pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, rounds, dk),
        "sha384" => pbkdf2::pbkdf2_hmac::<sha2::Sha384>(password, salt, rounds, dk),
        "sha512" => pbkdf2::pbkdf2_hmac::<sha2::Sha512>(password, salt, rounds, dk),
        other => {
            return Err(OperationError::invalid_param(
                "hash",
                format!("unknown PBKDF2 hash `{other}`"),
            ))
        }
    }
    Ok(())
}

fn pbkdf2_run(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let _ = v;
    let password = decode_param(map, "password", "password_encoding", "utf8")?;
    let salt = decode_param(map, "salt", "salt_encoding", "utf8")?;
    let rounds = map.int_or("iterations", 100_000);
    if !(1..=MAX_PBKDF2_ROUNDS).contains(&rounds) {
        return Err(OperationError::invalid_param(
            "iterations",
            format!("PBKDF2 iteration count must be 1-{MAX_PBKDF2_ROUNDS}, got {rounds}"),
        )
        .with_parameter("iterations")
        .with_expected(format!("1-{MAX_PBKDF2_ROUNDS}"))
        .with_actual(format!("{rounds}")));
    }
    let hash = map.str_or("hash", "sha256");
    let dk_len = dk_len_param(map, "PBKDF2")?;
    let mut dk = vec![0u8; dk_len];
    pbkdf2_derive(hash, &password, &salt, rounds as u32, &mut dk)?;
    Ok(Value::Text(hex(&dk)))
}

// ---------------------------------------------------------- HKDF ----

fn hkdf_hash_len(hash: &str) -> OpResult<usize> {
    match hash {
        "sha256" => Ok(32),
        "sha512" => Ok(64),
        other => Err(OperationError::invalid_param(
            "hash",
            format!("unknown HKDF hash `{other}` (supported: sha256, sha512)"),
        )),
    }
}

fn hkdf_run(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let _ = v;
    let ikm = decode_param(map, "ikm", "ikm_encoding", "hex")?;
    let salt = decode_param(map, "salt", "salt_encoding", "hex")?;
    let info = decode_param(map, "info", "info_encoding", "hex")?;
    let hash = map.str_or("hash", "sha256");
    let hash_len = hkdf_hash_len(hash)?;
    let dk_len = dk_len_param(map, "HKDF")?;
    // RFC 5869: OKM is at most 255 * HashLen bytes.
    let max_len = 255 * hash_len;
    if dk_len > max_len {
        return Err(OperationError::length(
            format!("1-{max_len} bytes for {hash} (255 x {hash_len}-byte hash output)"),
            format!("{dk_len} bytes"),
            "HKDF output length exceeds the RFC 5869 maximum",
        )
        .with_parameter("dk_len")
        .with_expected(format!("1-{max_len} bytes"))
        .with_actual(format!("{dk_len} bytes")));
    }

    let salt = if salt.is_empty() {
        // RFC 5869: absent salt defaults to HashLen zero bytes.
        None
    } else {
        Some(salt)
    };
    let mut okm = vec![0u8; dk_len];
    match hash {
        "sha256" => hkdf::Hkdf::<sha2::Sha256>::new(salt.as_deref(), &ikm)
            .expand(&info, &mut okm)
            .map_err(|_| {
                OperationError::internal("HKDF expansion failed despite length pre-check")
            })?,
        "sha512" => hkdf::Hkdf::<sha2::Sha512>::new(salt.as_deref(), &ikm)
            .expand(&info, &mut okm)
            .map_err(|_| {
                OperationError::internal("HKDF expansion failed despite length pre-check")
            })?,
        _ => unreachable!("validated by hkdf_hash_len"),
    }
    Ok(Value::Text(hex(&okm)))
}

// -------------------------------------------------------- scrypt ----
fn scrypt_run(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let _ = v;
    let password = decode_param(map, "password", "password_encoding", "utf8")?;
    let salt = decode_param(map, "salt", "salt_encoding", "utf8")?;
    let n = map.int_or("n", 16_384);
    let r = map.int_or("r", 8);
    let p = map.int_or("p", 1);
    let dk_len = dk_len_param(map, "scrypt")?;

    if n < 2 || !(n as u64).is_power_of_two() {
        return Err(OperationError::invalid_param(
            "n",
            format!("scrypt cost N must be a power of two >= 2, got {n}"),
        )
        .with_parameter("n")
        .with_expected("a power of two >= 2")
        .with_actual(format!("{n}")));
    }
    let log2_n = n.trailing_zeros();
    if log2_n > MAX_SCRYPT_LOG2_N {
        return Err(OperationError::invalid_param(
            "n",
            format!(
                "scrypt cost N is capped at 2^{MAX_SCRYPT_LOG2_N} = {} (log2 N <= {MAX_SCRYPT_LOG2_N}) to bound memory, got N = {n}",
                1i64 << MAX_SCRYPT_LOG2_N
            ),
        )
        .with_parameter("n")
        .with_expected(format!("N <= 2^{MAX_SCRYPT_LOG2_N}"))
        .with_actual(format!("N = {n} (log2 N = {log2_n})")));
    }
    if !(1..=64).contains(&r) {
        return Err(OperationError::invalid_param(
            "r",
            format!("scrypt block size r must be 1-64, got {r}"),
        )
        .with_parameter("r"));
    }
    if !(1..=64).contains(&p) {
        return Err(OperationError::invalid_param(
            "p",
            format!("scrypt parallelization p must be 1-64, got {p}"),
        )
        .with_parameter("p"));
    }
    // scrypt V memory is 128 * r * N bytes; p multiplies work, not memory.
    let mem_bytes = 128u64 * r as u64 * n as u64;
    if mem_bytes > MAX_SCRYPT_MEM_BYTES {
        return Err(OperationError::invalid_param(
            "n",
            format!(
                "scrypt with r = {r}, N = {n} would need ~{} MiB (128 * r * N); CyberCipher caps this at 1024 MiB — lower N or r",
                mem_bytes >> 20
            ),
        )
        .with_parameter("n")
        .with_expected("memory 128 * r * N <= 1 GiB")
        .with_actual(format!("~{} MiB", mem_bytes >> 20)));
    }

    let params = scrypt::Params::new(log2_n as u8, r as u32, p as u32, dk_len).map_err(|e| {
        OperationError::invalid_param("n", format!("scrypt rejected the cost parameters: {e}"))
    })?;
    let mut dk = vec![0u8; dk_len];
    scrypt::scrypt(&password, &salt, &params, &mut dk)
        .map_err(|e| OperationError::internal(format!("scrypt derivation failed: {e}")))?;
    Ok(Value::Text(hex(&dk)))
}

// ------------------------------------------------------ Argon2id ----

/// Argon2id memory cost cap: m_cost is expressed in KiB, so 1 GiB = 2^20 KiB.
const MAX_ARGON2_M_COST_KIB: i64 = 1 << 20;
const MAX_ARGON2_T_COST: i64 = 10_000;
const MAX_ARGON2_P_COST: i64 = 255;

fn argon2id_run(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let _ = v;
    let password = decode_param(map, "password", "password_encoding", "utf8")?;
    let salt = decode_param(map, "salt", "salt_encoding", "utf8")?;
    let m_cost = map.int_or("m_cost", 19_456);
    if !(8..=MAX_ARGON2_M_COST_KIB).contains(&m_cost) {
        return Err(OperationError::invalid_param(
            "m_cost",
            format!(
                "Argon2 memory cost must be 8-{MAX_ARGON2_M_COST_KIB} KiB (<= 1 GiB), got {m_cost}"
            ),
        )
        .with_parameter("m_cost")
        .with_expected(format!("8-{MAX_ARGON2_M_COST_KIB} KiB"))
        .with_actual(format!("{m_cost} KiB")));
    }
    let t_cost = map.int_or("t_cost", 2);
    if !(1..=MAX_ARGON2_T_COST).contains(&t_cost) {
        return Err(OperationError::invalid_param(
            "t_cost",
            format!("Argon2 time cost must be 1-{MAX_ARGON2_T_COST}, got {t_cost}"),
        )
        .with_parameter("t_cost"));
    }
    let p_cost = map.int_or("p_cost", 1);
    if !(1..=MAX_ARGON2_P_COST).contains(&p_cost) {
        return Err(OperationError::invalid_param(
            "p_cost",
            format!("Argon2 parallelism must be 1-{MAX_ARGON2_P_COST}, got {p_cost}"),
        )
        .with_parameter("p_cost"));
    }
    let dk_len = map.int_or("dk_len", 32);
    if !(4..=MAX_DK_LEN).contains(&dk_len) {
        return Err(OperationError::invalid_param(
            "dk_len",
            format!("Argon2 output length must be 4-{MAX_DK_LEN} bytes, got {dk_len}"),
        )
        .with_parameter("dk_len")
        .with_expected(format!("4-{MAX_DK_LEN} bytes"))
        .with_actual(format!("{dk_len} bytes")));
    }
    if salt.len() < 8 {
        return Err(OperationError::length(
            "at least 8 bytes (Argon2 requires a >= 64-bit salt)",
            format!("{} bytes", salt.len()),
            "salt is too short for Argon2",
        )
        .with_parameter("salt")
        .with_expected(">= 8 bytes")
        .with_actual(format!("{} bytes", salt.len())));
    }
    if m_cost < 8 * p_cost {
        return Err(OperationError::invalid_param(
            "m_cost",
            format!(
                "Argon2 requires m_cost >= 8 * p_cost = {}, got {m_cost}",
                8 * p_cost
            ),
        )
        .with_parameter("m_cost")
        .with_expected(format!(">= {} KiB", 8 * p_cost))
        .with_actual(format!("{m_cost} KiB")));
    }

    let params = argon2::Params::new(
        m_cost as u32,
        t_cost as u32,
        p_cost as u32,
        Some(dk_len as usize),
    )
    .map_err(|e| {
        OperationError::invalid_param("m_cost", format!("Argon2 rejected the parameters: {e}"))
    })?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut dk = vec![0u8; dk_len as usize];
    argon
        .hash_password_into(&password, &salt, &mut dk)
        .map_err(|e| OperationError::internal(format!("Argon2id derivation failed: {e}")))?;
    Ok(Value::Text(hex(&dk)))
}

// -------------------------------------------------- EVP_BytesToKey ----

/// OpenSSL EVP_BytesToKey with MD5 (the classic `openssl enc` KDF):
/// D_1 = MD5^(count)(D_0 || password || salt), D_i = MD5^(count)(D_{i-1} || password || salt),
/// key = first key_len bytes of D_1 || D_2 || ..., iv = the next iv_len bytes.
fn evp_bytestokey(password: &[u8], salt: &[u8], count: u32, needed: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(needed + 16);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < needed {
        let mut hasher = md5::Md5::new();
        hasher.update(&prev);
        hasher.update(password);
        hasher.update(salt);
        let mut block = hasher.finalize().to_vec();
        for _ in 1..count {
            let mut hasher = md5::Md5::new();
            hasher.update(&block);
            block = hasher.finalize().to_vec();
        }
        out.extend_from_slice(&block);
        prev = block;
    }
    out.truncate(needed);
    out
}

fn evp_run(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let _ = v;
    let password = decode_param(map, "password", "password_encoding", "utf8")?;
    let salt = decode_param(map, "salt", "salt_encoding", "utf8")?;
    let count = map.int_or("count", 1);
    if !(1..=100_000).contains(&count) {
        return Err(OperationError::invalid_param(
            "count",
            format!("EVP_BytesToKey hash count must be 1-100000, got {count}"),
        )
        .with_parameter("count"));
    }
    let key_len = map.int_or("key_len", 32);
    if !(1..=1024).contains(&key_len) {
        return Err(OperationError::invalid_param(
            "key_len",
            format!("EVP_BytesToKey key length must be 1-1024 bytes, got {key_len}"),
        )
        .with_parameter("key_len"));
    }
    let iv_len = map.int_or("iv_len", 16);
    if !(0..=1024).contains(&iv_len) {
        return Err(OperationError::invalid_param(
            "iv_len",
            format!("EVP_BytesToKey IV length must be 0-1024 bytes, got {iv_len}"),
        )
        .with_parameter("iv_len"));
    }

    let stream = evp_bytestokey(&password, &salt, count as u32, (key_len + iv_len) as usize);
    let key_hex = hex(&stream[..key_len as usize]);
    if iv_len == 0 {
        return Ok(Value::Text(key_hex));
    }
    let iv_hex = hex(&stream[key_len as usize..]);
    Ok(Value::Text(format!("{key_hex}:{iv_hex}")))
}

// ---------------------------------------------------- op specs ----

fn text_params(password_hint: &'static str) -> Vec<ParamSpec> {
    vec![
        p_text("password", "Password", "", password_hint),
        p_enc("password_encoding", "Password encoding", "utf8", ""),
        p_text_opt("salt", "Salt", "", "Salt bytes; empty means no salt."),
        p_enc("salt_encoding", "Salt encoding", "utf8", ""),
    ]
}

#[allow(clippy::too_many_arguments)]
fn kdf_spec(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    aliases: &'static [&'static str],
    params: Vec<ParamSpec>,
    cost: CostClass,
    security: Security,
    standard: &'static str,
    implementation: &'static str,
    vectors: &'static str,
) -> &'static OperationSpec {
    Box::leak(Box::new(OperationSpec {
        id,
        name,
        description,
        category: Category::Kdf,
        input_kinds: Box::leak(vec![ValueKind::Bytes, ValueKind::Text].into_boxed_slice()),
        output_kind: ValueKind::Text,
        params: Box::leak(params.into_boxed_slice()),
        cost,
        security,
        deterministic: true,
        reversible: false,
        aliases,
        tags: KDF_TAGS,
        provenance: Provenance {
            standard,
            implementation,
            test_vectors: vectors,
        },
    }))
}

fn hash_opts(options: &'static [ParamOption], hint: &'static str) -> ParamSpec {
    p_opts("hash", "Hash", "sha256", options, hint)
}

fn dk_len_param_spec() -> ParamSpec {
    p_int(
        "dk_len",
        "Derived key length",
        32,
        "Output length in bytes.",
    )
}

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    // PBKDF2 (RFC 8018 / RFC 2898)
    let pbkdf2_hashes: &'static [ParamOption] = &[
        ParamOption {
            value: "sha1",
            label: "HMAC-SHA1",
        },
        ParamOption {
            value: "sha224",
            label: "HMAC-SHA224",
        },
        ParamOption {
            value: "sha256",
            label: "HMAC-SHA256",
        },
        ParamOption {
            value: "sha384",
            label: "HMAC-SHA384",
        },
        ParamOption {
            value: "sha512",
            label: "HMAC-SHA512",
        },
    ];
    let mut pbkdf2_params = text_params("Password bytes after decoding; UTF-8 text is typical.");
    pbkdf2_params.push(p_int(
        "iterations",
        "Iterations",
        100_000,
        "HMAC iterations c (1-10000000). Use what the protocol specifies.",
    ));
    pbkdf2_params.push(hash_opts(pbkdf2_hashes, "PBKDF2-HMAC hash function."));
    pbkdf2_params.push(dk_len_param_spec());
    let spec = kdf_spec(
        "kdf-pbkdf2",
        "PBKDF2",
        "Derives a key from a password with PBKDF2-HMAC (RFC 8018). Slow by design; the iteration count must match the protocol or original derivation.",
        &["pbkdf2", "pbkdf2-hmac-sha256"],
        pbkdf2_params,
        CostClass::Heavy,
        Security::Modern,
        "RFC 8018 (PKCS #5 v2.1)",
        "RustCrypto `pbkdf2` crate",
        "RFC 7914 section 11.1 / RFC 6070 (SHA-1) vectors",
    );
    reg.add_simple(spec, pbkdf2_run);

    // HKDF (RFC 5869)
    let hkdf_hashes: &'static [ParamOption] = &[
        ParamOption {
            value: "sha256",
            label: "HMAC-SHA256",
        },
        ParamOption {
            value: "sha512",
            label: "HMAC-SHA512",
        },
    ];
    let mut hkdf_params = vec![
        p_text(
            "ikm",
            "Input keying material",
            "",
            "IKM bytes after decoding.",
        ),
        p_enc("ikm_encoding", "IKM encoding", "hex", ""),
        p_text_opt(
            "salt",
            "Salt",
            "",
            "Optional; empty means the RFC 5869 default of hash-length zero bytes.",
        ),
        p_enc("salt_encoding", "Salt encoding", "hex", ""),
        p_text_opt("info", "Info", "", "Optional context/application string."),
        p_enc("info_encoding", "Info encoding", "hex", ""),
    ];
    hkdf_params.push(hash_opts(hkdf_hashes, "HKDF hash function (RFC 5869)."));
    hkdf_params.push(dk_len_param_spec());
    let spec = kdf_spec(
        "kdf-hkdf",
        "HKDF",
        "Derives key material with HKDF extract-and-expand (RFC 5869). For high-entropy input keying material, not passwords.",
        &["hkdf", "hkdf-sha256"],
        hkdf_params,
        CostClass::Instant,
        Security::Modern,
        "RFC 5869",
        "RustCrypto `hkdf` crate",
        "RFC 5869 section 10 test vectors",
    );
    reg.add_simple(spec, hkdf_run);

    // scrypt (RFC 7914)
    let mut scrypt_params = text_params("Password bytes after decoding; UTF-8 text is typical.");
    scrypt_params.push(p_int(
        "n",
        "Cost N",
        16_384,
        "CPU/memory cost, a power of two (log2 N <= 22 here).",
    ));
    scrypt_params.push(p_int(
        "r",
        "Block size r",
        8,
        "Mixing block size in 1024-byte units (1-64).",
    ));
    scrypt_params.push(p_int(
        "p",
        "Parallelization p",
        1,
        "Independent mixing passes (1-64).",
    ));
    scrypt_params.push(dk_len_param_spec());
    let spec = kdf_spec(
        "kdf-scrypt",
        "scrypt",
        "Derives a key from a password with scrypt (RFC 7914), a memory-hard KDF. Cost knobs must match the original derivation exactly.",
        &["scrypt", "kdf-scrypt"],
        scrypt_params,
        CostClass::Heavy,
        Security::Modern,
        "RFC 7914",
        "RustCrypto `scrypt` crate",
        "RFC 7914 section 12 test vectors",
    );
    reg.add_simple(spec, scrypt_run);

    // EVP_BytesToKey (legacy OpenSSL `enc` KDF)
    let mut evp_params = text_params("Password bytes after decoding; UTF-8 text is typical.");
    evp_params.push(p_int(
        "count",
        "Hash count",
        1,
        "Digest iteration count in EVP_BytesToKey; 1 for classic `openssl enc`.",
    ));
    evp_params.push(p_int(
        "key_len",
        "Key length",
        32,
        "Cipher key length in bytes (16 for AES-128, 32 for AES-256).",
    ));
    evp_params.push(p_int(
        "iv_len",
        "IV length",
        16,
        "IV length in bytes (16 for AES, 8 for DES/3DES, 0 to derive only the key).",
    ));
    let spec = kdf_spec(
        "kdf-evp-bytestokey",
        "EVP_BytesToKey",
        "Derives a key (and optional IV) like classic OpenSSL `enc`: MD5-stretched password and salt, no work factor. Output is `key_hex:iv_hex`, or just `key_hex` when iv_len is 0. Legacy - for decrypting old OpenSSL-encrypted material.",
        &["evp", "openssl-kdf", "evp-bytestokey"],
        evp_params,
        CostClass::Instant,
        Security::Legacy,
        "OpenSSL EVP_BytesToKey (legacy; undocumented de facto standard)",
        "CyberCipher native Rust (MD5 via RustCrypto)",
        "Generated and cross-checked against OpenSSL 3.x `enc -md md5`",
    );
    reg.add_simple(spec, evp_run);

    // Argon2id (RFC 9106)
    let mut argon2_params = text_params("Password bytes after decoding; UTF-8 text is typical.");
    argon2_params.push(p_int(
        "m_cost",
        "Memory cost (KiB)",
        19_456,
        "Memory in KiB (8-1048576; 1 GiB cap). Must match the original derivation.",
    ));
    argon2_params.push(p_int(
        "t_cost",
        "Time cost",
        2,
        "Number of passes (1-10000). Must match the original derivation.",
    ));
    argon2_params.push(p_int(
        "p_cost",
        "Parallelism",
        1,
        "Degree of parallelism lanes (1-255). Must match the original derivation.",
    ));
    argon2_params.push(p_int(
        "dk_len",
        "Derived key length",
        32,
        "Output length in bytes (4-8192).",
    ));
    let spec = kdf_spec(
        "kdf-argon2id",
        "Argon2id",
        "Derives a key from a password with Argon2id (RFC 9106), the memory-hard PHC winner. All cost parameters must match the original derivation exactly.",
        &["argon2", "argon2id"],
        argon2_params,
        CostClass::Heavy,
        Security::Modern,
        "RFC 9106",
        "RustCrypto `argon2` crate",
        "RFC 9106 section 5.3 test vector",
    );
    reg.add_simple(spec, argon2id_run);

    register_bcrypt(reg);
}

// -------------------------------------------------------- bcrypt ----

/// bcrypt (Provos & Mazieres, 1999; the OpenBSD `$2*` password scheme) via
/// the `bcrypt` crate. Unlike the KDFs above, the output is the canonical
/// Modular Crypt Format string, not raw bytes.
///
/// `bcrypt-hash` takes the password as the pipeline input and returns the
/// `$2*` hash string. With an explicit 16-byte salt the result is
/// deterministic; without one the crate draws a fresh random salt, so the
/// spec is marked non-deterministic. `bcrypt-verify` checks a password
/// against an existing hash string.
fn register_bcrypt(reg: &mut cybercipher_core::OperationRegistry) {
    const MIN_COST: i64 = 4;
    const MAX_COST: i64 = 31;

    fn cost_of(map: &ParamMap) -> OpResult<u32> {
        let cost = map.int_or("cost", 12);
        if !(MIN_COST..=MAX_COST).contains(&cost) {
            return Err(OperationError::invalid_param(
                "cost",
                format!("bcrypt cost must be {MIN_COST}-{MAX_COST}, got {cost}"),
            )
            .with_expected(format!("{MIN_COST}-{MAX_COST}"))
            .with_actual(format!("{cost}")));
        }
        Ok(cost as u32)
    }

    let hash_params = vec![
        p_int(
            "cost",
            "Cost",
            12,
            "Base-2 log of the key-setup rounds (4-31). Higher is slower.",
        ),
        p_text_opt(
            "salt",
            "Salt (optional)",
            "",
            "Explicit 16-byte salt; omit to generate a random one. Providing a salt makes the output deterministic.",
        ),
        p_enc("salt_encoding", "Salt encoding", "hex", ""),
        p_opts(
            "version",
            "Version",
            "2b",
            &[
                ParamOption {
                    value: "2b",
                    label: "$2b$ (OpenBSD 2014, current)",
                },
                ParamOption {
                    value: "2a",
                    label: "$2a$ (original)",
                },
                ParamOption {
                    value: "2y",
                    label: "$2y$ (PHP fix marker)",
                },
                ParamOption {
                    value: "2x",
                    label: "$2x$ (Broken 8-bit compat)",
                },
            ],
            "Only relevant with an explicit salt; all versions share the core algorithm.",
        ),
    ];
    let hash_spec = kdf_spec(
        "bcrypt-hash",
        "bcrypt Hash",
        "Hashes a password with bcrypt, returning the canonical $2b$/$2a$/... Modular-Crypt string. The password is the pipeline input; an optional explicit 16-byte salt makes the output deterministic (otherwise a random salt is generated). Verify with bcrypt-verify.",
        &["bcrypt", "bcrypt-hashing"],
        hash_params,
        CostClass::Heavy,
        Security::Modern,
        "bcrypt (Provos & Mazieres; OpenBSD)",
        "`bcrypt` crate (RustCrypto `blowfish` core)",
        "Openwall bcrypt test vectors",
    );
    // kdf_spec marks everything deterministic; bcrypt with a random salt is
    // not, so patch the flag on the leaked spec (OperationSpec is Copy).
    let hash_spec = Box::leak(Box::new(OperationSpec {
        deterministic: false,
        ..*hash_spec
    }));
    reg.add_simple(hash_spec, move |v, map, ctx| -> OpResult<Value> {
        let _ = ctx;
        let password = crate::helpers::input_bytes(v, "bcrypt Hash")?;
        let cost = cost_of(map)?;
        let salt_raw = map.str_or("salt", "");
        let result = if salt_raw.is_empty() {
            bcrypt::hash(password.as_ref(), cost)
        } else {
            let salt = decode_param(map, "salt", "salt_encoding", "hex")?;
            if salt.len() != 16 {
                return Err(OperationError::key(format!(
                    "bcrypt salt must be 16 bytes after decoding, got {} bytes",
                    salt.len()
                ))
                .with_parameter("salt")
                .with_expected("16 bytes")
                .with_actual(format!("{} bytes", salt.len())));
            }
            let salt: [u8; 16] = salt.try_into().expect("checked 16 bytes");
            bcrypt::hash_with_salt(password.as_ref(), cost, salt)
                .map(|parts| parts.format_for_version(bcrypt_version(map)))
        };
        let hash = result.map_err(|e| OperationError::internal(format!("bcrypt failed: {e}")))?;
        Ok(Value::Text(hash))
    });

    let verify_params = vec![p_text(
        "hash",
        "bcrypt hash",
        "",
        "The $2a$/$2b$/$2x$/$2y$ Modular-Crypt string to check against.",
    )];
    let verify_spec = kdf_spec(
        "bcrypt-verify",
        "bcrypt Verify",
        "Checks a password against a bcrypt hash string. The password is the pipeline input; output is the text value `true` or `false`. Malformed hash strings are reported as structured decode errors instead of a silent mismatch.",
        &["bcrypt-check", "bcrypt-validate"],
        verify_params,
        CostClass::Heavy,
        Security::Modern,
        "bcrypt (Provos & Mazieres; OpenBSD)",
        "`bcrypt` crate (RustCrypto `blowfish` core)",
        "Openwall bcrypt test vectors",
    );
    reg.add_simple(verify_spec, move |v, map, ctx| -> OpResult<Value> {
        let _ = ctx;
        let password = crate::helpers::input_bytes(v, "bcrypt Verify")?;
        let hash = map.require_str("hash")?;
        match bcrypt::verify(password.as_ref(), hash) {
            Ok(valid) => Ok(Value::Text(
                if valid { "true" } else { "false" }.to_string(),
            )),
            Err(e) => Err(
                OperationError::decode(format!("input is not a valid bcrypt hash: {e}"))
                    .with_parameter("hash")
                    .with_expected("a $2a$/$2b$/$2x$/$2y$ Modular-Crypt string (60 characters)")
                    .with_details(
                        "A malformed hash cannot be checked; verify the string was copied in full.",
                    ),
            ),
        }
    });
}

/// Map the `version` parameter to the crate's [`bcrypt::Version`].
fn bcrypt_version(map: &ParamMap) -> bcrypt::Version {
    match map.str_or("version", "2b") {
        "2a" => bcrypt::Version::TwoA,
        "2x" => bcrypt::Version::TwoX,
        "2y" => bcrypt::Version::TwoY,
        _ => bcrypt::Version::TwoB,
    }
}
