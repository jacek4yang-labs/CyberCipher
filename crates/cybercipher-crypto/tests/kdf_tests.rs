//! Official test vectors and validation tests for the KDF operations.
//!
//! Vector sources: RFC 7914 sections 11 and 12 (PBKDF2-HMAC-SHA256 and
//! scrypt); RFC 6070 (PBKDF2-HMAC-SHA1); RFC 5869 section 10 (HKDF-SHA256
//! test cases 1 and 3); EVP_BytesToKey vectors generated with OpenSSL 3.x
//! (`openssl enc -md md5 -nosalt/-S <salt> -P`).
//!
//! Negative tests cover cost and length bounds: PBKDF2 iterations, HKDF
//! output length, scrypt N power-of-two with log2 N <= 22, and the memory cap.

// See cybercipher-core/src/lib.rs for the rationale.
#![allow(clippy::result_large_err)]

use cybercipher_core::prelude::*;
use cybercipher_core::OperationRegistry;

fn reg() -> OperationRegistry {
    let mut r = OperationRegistry::new();
    cybercipher_crypto::register_all(&mut r);
    r
}

fn run(reg: &OperationRegistry, id: &str, params: &[(&'static str, ParamValue)]) -> String {
    let op = reg.get(id).unwrap_or_else(|| panic!("missing op {id}"));
    let mut map = ParamMap::new();
    for (k, v) in params {
        map.insert(*k, v.clone());
    }
    match op.execute(&Value::Bytes(Vec::new()), &map, &ExecutionContext::new()) {
        Ok(Value::Text(t)) => t,
        Ok(other) => panic!("{id}: unexpected output {other:?}"),
        Err(e) => panic!("{id}: unexpected error {e:?}"),
    }
}

fn try_run(
    reg: &OperationRegistry,
    id: &str,
    params: &[(&'static str, ParamValue)],
) -> OpResult<Value> {
    let op = reg.get(id).unwrap_or_else(|| panic!("missing op {id}"));
    let mut map = ParamMap::new();
    for (k, v) in params {
        map.insert(*k, v.clone());
    }
    op.execute(&Value::Bytes(Vec::new()), &map, &ExecutionContext::new())
}

fn pv(params: &[(&'static str, &str)]) -> Vec<(&'static str, ParamValue)> {
    params
        .iter()
        .map(|(k, v)| (*k, ParamValue::Str(v.to_string())))
        .collect()
}

fn pi(key: &'static str, value: i64) -> (&'static str, ParamValue) {
    (key, ParamValue::Int(value))
}

#[test]
fn pbkdf2_hmac_sha256_rfc7914_11() {
    let r = reg();
    // RFC 7914 section 11: (P="passwd", S="salt", c=1, dkLen=64).
    let out = run(
        &r,
        "kdf-pbkdf2",
        &pv(&[
            ("password", "passwd"),
            ("password_encoding", "utf8"),
            ("salt", "salt"),
            ("salt_encoding", "utf8"),
        ])
        .tap(|v| v.push(pi("iterations", 1)))
        .tap(|v| v.push(pi("dk_len", 64))),
    );
    assert_eq!(
        out,
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
         49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
            .replace(['\n', ' '], "")
    );

    // RFC 7914 section 11: (P="Password", S="NaCl", c=80000, dkLen=64).
    let out = run(
        &r,
        "kdf-pbkdf2",
        &pv(&[
            ("password", "Password"),
            ("password_encoding", "utf8"),
            ("salt", "NaCl"),
            ("salt_encoding", "utf8"),
        ])
        .tap(|v| v.push(pi("iterations", 80_000)))
        .tap(|v| v.push(pi("dk_len", 64))),
    );
    assert_eq!(
        out,
        "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56\
         a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
            .replace(['\n', ' '], "")
    );

    // Widely published PBKDF2-HMAC-SHA256 vector (draft-josefsson-scrypt
    // appendix / PBKDF2 literature): (P="password", S="salt", c=1, dkLen=32).
    let out = run(
        &r,
        "kdf-pbkdf2",
        &pv(&[
            ("password", "password"),
            ("password_encoding", "utf8"),
            ("salt", "salt"),
            ("salt_encoding", "utf8"),
        ])
        .tap(|v| v.push(pi("iterations", 1)))
        .tap(|v| v.push(pi("dk_len", 32))),
    );
    assert_eq!(
        out,
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    );

    // Same source with c=4096, dkLen=40 (cross-checked against OpenSSL).
    let out = run(
        &r,
        "kdf-pbkdf2",
        &pv(&[
            ("password", "password"),
            ("password_encoding", "utf8"),
            ("salt", "salt"),
            ("salt_encoding", "utf8"),
        ])
        .tap(|v| v.push(pi("iterations", 4096)))
        .tap(|v| v.push(pi("dk_len", 40))),
    );
    assert!(out.starts_with("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"));
    assert_eq!(out.len(), 80); // 40 bytes
}

#[test]
fn pbkdf2_hmac_sha1_rfc6070() {
    let r = reg();
    let base = vec![
        ("password", ParamValue::Str("password".to_string())),
        ("password_encoding", ParamValue::Str("utf8".to_string())),
        ("salt", ParamValue::Str("salt".to_string())),
        ("salt_encoding", ParamValue::Str("utf8".to_string())),
        ("hash", ParamValue::Str("sha1".to_string())),
    ];
    let mut params = base.clone();
    params.push(pi("iterations", 1));
    params.push(pi("dk_len", 20));
    assert_eq!(
        run(&r, "kdf-pbkdf2", &params),
        "0c60c80f961f0e71f3a9b524af6012062fe037a6"
    );

    let mut params = base;
    params.push(pi("iterations", 4096));
    params.push(pi("dk_len", 20));
    assert_eq!(
        run(&r, "kdf-pbkdf2", &params),
        "4b007901b765489abead49d926f721d065a429c1"
    );
}

#[test]
fn hkdf_sha256_rfc5869_case_1() {
    let r = reg();
    let ikm = "0b".repeat(22);
    let out = run(
        &r,
        "kdf-hkdf",
        &[
            ("ikm", ParamValue::Str(ikm)),
            ("ikm_encoding", ParamValue::Str("hex".to_string())),
            (
                "salt",
                ParamValue::Str("000102030405060708090a0b0c".to_string()),
            ),
            ("salt_encoding", ParamValue::Str("hex".to_string())),
            ("info", ParamValue::Str("f0f1f2f3f4f5f6f7f8f9".to_string())),
            ("info_encoding", ParamValue::Str("hex".to_string())),
            ("hash", ParamValue::Str("sha256".to_string())),
            pi("dk_len", 42),
        ],
    );
    assert_eq!(
        out,
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
         34007208d5b887185865"
            .replace(['\n', ' '], "")
    );
}

#[test]
fn hkdf_sha256_rfc5869_case_3() {
    // No salt, no info.
    let r = reg();
    let ikm = "0b".repeat(22);
    let out = run(
        &r,
        "kdf-hkdf",
        &[
            ("ikm", ParamValue::Str(ikm)),
            ("ikm_encoding", ParamValue::Str("hex".to_string())),
            ("hash", ParamValue::Str("sha256".to_string())),
            pi("dk_len", 42),
        ],
    );
    assert_eq!(
        out,
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
         9d201395faa4b61a96c8"
            .replace(['\n', ' '], "")
    );
}

#[test]
fn hkdf_sha512_round_trip_lengths() {
    let r = reg();
    let out = run(
        &r,
        "kdf-hkdf",
        &[
            (
                "ikm",
                ParamValue::Str("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".to_string()),
            ),
            ("ikm_encoding", ParamValue::Str("hex".to_string())),
            ("hash", ParamValue::Str("sha512".to_string())),
            pi("dk_len", 64),
        ],
    );
    assert_eq!(out.len(), 128);

    // OKM above 255 * HashLen must be rejected (RFC 5869 cap).
    let err = try_run(
        &r,
        "kdf-hkdf",
        &[
            ("ikm", ParamValue::Str("0b".repeat(22))),
            ("ikm_encoding", ParamValue::Str("hex".to_string())),
            ("hash", ParamValue::Str("sha256".to_string())),
            pi("dk_len", 8161),
        ],
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::LengthMismatch);
    assert!(
        err.message.contains("RFC 5869") && err.actual.as_deref() == Some("8161 bytes"),
        "{err:?}"
    );
}

#[test]
fn scrypt_rfc7914_12_vector_1() {
    let r = reg();
    let out = run(
        &r,
        "kdf-scrypt",
        &pv(&[
            ("password", "password"),
            ("password_encoding", "utf8"),
            ("salt", "NaCl"),
            ("salt_encoding", "utf8"),
        ])
        .tap(|v| v.push(pi("n", 1024)))
        .tap(|v| v.push(pi("r", 8)))
        .tap(|v| v.push(pi("p", 16)))
        .tap(|v| v.push(pi("dk_len", 64))),
    );
    assert_eq!(
        out,
        "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162\
         2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"
            .replace(['\n', ' '], "")
    );
}

#[test]
fn scrypt_rfc7914_12_vector_2() {
    let r = reg();
    let out = run(
        &r,
        "kdf-scrypt",
        &pv(&[
            ("password", "pleaseletmein"),
            ("password_encoding", "utf8"),
            ("salt", "SodiumChloride"),
            ("salt_encoding", "utf8"),
        ])
        .tap(|v| v.push(pi("n", 16384)))
        .tap(|v| v.push(pi("r", 8)))
        .tap(|v| v.push(pi("p", 1)))
        .tap(|v| v.push(pi("dk_len", 64))),
    );
    assert_eq!(
        out,
        "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2\
         d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"
            .replace(['\n', ' '], "")
    );
}

#[test]
fn scrypt_param_validation() {
    let r = reg();
    let base = || {
        pv(&[
            ("password", "password"),
            ("password_encoding", "utf8"),
            ("salt", "NaCl"),
            ("salt_encoding", "utf8"),
        ])
    };

    // N must be a power of two >= 2.
    let mut params = base();
    params.push(pi("n", 1023));
    let err = try_run(&r, "kdf-scrypt", &params).unwrap_err();
    assert!(err.message.contains("power of two"), "{err:?}");

    // log2 N <= 22 (N <= 4194304).
    let mut params = base();
    params.push(pi("n", 1 << 23));
    let err = try_run(&r, "kdf-scrypt", &params).unwrap_err();
    assert!(err.message.contains("22"), "{err:?}");

    // Memory cap: 128 * r * N <= 1 GiB (4 GiB requested here).
    let mut params = base();
    params.push(pi("n", 1 << 22));
    params.push(pi("r", 8));
    let err = try_run(&r, "kdf-scrypt", &params).unwrap_err();
    assert!(err.message.contains("MiB"), "{err:?}");

    // r and p lower bounds.
    let mut params = base();
    params.push(pi("r", 0));
    assert!(try_run(&r, "kdf-scrypt", &params).is_err());
    let mut params = base();
    params.push(pi("p", 0));
    assert!(try_run(&r, "kdf-scrypt", &params).is_err());
}

#[test]
fn pbkdf2_param_validation() {
    let r = reg();
    let base = || {
        pv(&[
            ("password", "password"),
            ("password_encoding", "utf8"),
            ("salt", "salt"),
            ("salt_encoding", "utf8"),
        ])
    };
    // iterations < 1 rejected.
    let mut params = base();
    params.push(pi("iterations", 0));
    assert!(try_run(&r, "kdf-pbkdf2", &params).is_err());

    // dk_len out of range rejected.
    let mut params = base();
    params.push(pi("iterations", 1));
    params.push(pi("dk_len", 0));
    assert!(try_run(&r, "kdf-pbkdf2", &params).is_err());

    // Unknown hash rejected.
    let mut params = base();
    params.push(pi("iterations", 1));
    params.push(("hash", ParamValue::Str("md5".to_string())));
    let err = try_run(&r, "kdf-pbkdf2", &params).unwrap_err();
    assert!(err.message.contains("hash"), "{err:?}");
}

#[test]
fn evp_bytestokey_openssl_vectors() {
    let r = reg();
    // OpenSSL 3.x: `openssl enc -aes-256-cbc -nosalt -k password -md md5 -P`
    //   key=5F4DCC3B5AA765D61D8327DEB882CF992B95990A9151374ABD8FF8C5A7A0FE08
    //   iv =B7B4372CDFBCB3D16A2631B59B509E94
    let out = run(
        &r,
        "kdf-evp-bytestokey",
        &pv(&[("password", "password"), ("password_encoding", "utf8")])
            .tap(|v| v.push(pi("key_len", 32)))
            .tap(|v| v.push(pi("iv_len", 16))),
    );
    assert_eq!(
        out,
        "5f4dcc3b5aa765d61d8327deb882cf992b95990a9151374abd8ff8c5a7a0fe08\
         :b7b4372cdfbcb3d16a2631b59b509e94"
            .replace(['\n', ' '], "")
    );

    // OpenSSL 3.x: `openssl enc -aes-256-cbc -k password -md md5 -P -S 0102030405060708`
    //   key=E7B0971E52CA5CC8D0539FB3412F6316F7BA2E6EE293D9F3457B99436B51CE02
    //   iv =8D450E2ED75A84A923D4EAC9FE49226B
    let out = run(
        &r,
        "kdf-evp-bytestokey",
        &pv(&[
            ("password", "password"),
            ("password_encoding", "utf8"),
            ("salt", "0102030405060708"),
            ("salt_encoding", "hex"),
        ])
        .tap(|v| v.push(pi("key_len", 32)))
        .tap(|v| v.push(pi("iv_len", 16))),
    );
    assert_eq!(
        out,
        "e7b0971e52ca5cc8d0539fb3412f6316f7ba2e6ee293d9f3457b99436b51ce02\
         :8d450e2ed75a84a923d4eac9fe49226b"
            .replace(['\n', ' '], "")
    );

    // OpenSSL 3.x: `openssl enc -des-ede3-cbc -k password -md md5 -P -S 0102030405060708`
    //   key=E7B0971E52CA5CC8D0539FB3412F6316F7BA2E6EE293D9F3
    //   iv =457B99436B51CE02
    let out = run(
        &r,
        "kdf-evp-bytestokey",
        &pv(&[
            ("password", "password"),
            ("password_encoding", "utf8"),
            ("salt", "0102030405060708"),
            ("salt_encoding", "hex"),
        ])
        .tap(|v| v.push(pi("key_len", 24)))
        .tap(|v| v.push(pi("iv_len", 8))),
    );
    assert_eq!(
        out,
        "e7b0971e52ca5cc8d0539fb3412f6316f7ba2e6ee293d9f3:457b99436b51ce02"
    );

    // iv_len = 0 returns only the key; with no salt the first block is the
    // famous MD5("password") (RFC 1321 test suite).
    let out = run(
        &r,
        "kdf-evp-bytestokey",
        &pv(&[("password", "password"), ("password_encoding", "utf8")])
            .tap(|v| v.push(pi("key_len", 16)))
            .tap(|v| v.push(pi("iv_len", 0))),
    );
    assert_eq!(out, "5f4dcc3b5aa765d61d8327deb882cf99");
}

#[test]
fn evp_bytestokey_stream_consistency() {
    // The derived key+iv stream must be a prefix of a longer derivation
    // with the same password/salt (D_1 || D_2 || ... concatenation rule).
    let r = reg();
    let short = run(
        &r,
        "kdf-evp-bytestokey",
        &pv(&[
            ("password", "password"),
            ("password_encoding", "utf8"),
            ("salt", "NaCl"),
            ("salt_encoding", "utf8"),
        ])
        .tap(|v| v.push(pi("key_len", 16)))
        .tap(|v| v.push(pi("iv_len", 16))),
    );
    let long = run(
        &r,
        "kdf-evp-bytestokey",
        &pv(&[
            ("password", "password"),
            ("password_encoding", "utf8"),
            ("salt", "NaCl"),
            ("salt_encoding", "utf8"),
        ])
        .tap(|v| v.push(pi("key_len", 48)))
        .tap(|v| v.push(pi("iv_len", 0))),
    );
    let short_stream: String = short.chars().filter(|c| *c != ':').collect();
    assert!(long.starts_with(&short_stream));
}

trait Tap: Sized {
    fn tap(self, f: impl FnOnce(&mut Self)) -> Self {
        let mut this = self;
        f(&mut this);
        this
    }
}
impl<T> Tap for T {}
