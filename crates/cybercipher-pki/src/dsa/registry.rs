//! Registry wiring for the DSA operations, following the crate-wide
//! [`SimpleOp`] pattern (see [`crate::ecc::registry`]): static
//! [`OperationSpec`]s plus closures that adapt the typed [`crate::dsa`] API
//! to [`Value`] in/out.
//!
//! Ops (ids are kebab-case like every other registry entry; snake_case
//! aliases mirror the task-named ids for search discovery):
//! - `dsa-keygen` — FIPS 186-4 parameter + key generation;
//! - `dsa-sign`   — RFC 6979 deterministic signature;
//! - `dsa-verify` — signature verification (`valid: false` is a result).
//!
//! Input contract (JSON value; Text is parsed as JSON):
//! - keygen: input is ignored (params only);
//! - sign:   `{"p", "q", "g", "x", "message" | "digest"}` — all hex, exactly
//!   one of message/digest;
//! - verify: `{"p", "q", "g", "y", "message" | "digest", "r", "s"}`.
//!
//! Params:
//! - `size` (keygen: 1024/160 | 2048/224 | 2048/256 | 3072/256, default
//!   2048/256);
//! - `hash` (sign/verify: sha1..sha512, default sha256).

use cybercipher_core::prelude::*;
use cybercipher_core::Value as CoreValue;
use serde_json::Value;

use crate::dsa::{dsa_generate_keypair, dsa_sign, dsa_verify, DsaHash, DsaKeySize, DsaPreimage};

const DSA_TAGS: &[&str] = &["dsa", "signature", "fips186", "public-key"];

const DSA_PROVENANCE: Provenance = Provenance {
    standard: "FIPS 186-4/5 Digital Signature Standard; RFC 6979 deterministic nonces",
    implementation: "CyberCipher native Rust (RustCrypto `dsa` crate: FIPS parameter generation, RFC 6979 signing; pkcs8/spki key containers)",
    test_vectors: "CyberCipher unit tests: deterministic toy key (p=2027, q=1013, g=4) RFC 6979 roundtrip for sha1..sha512 + FIPS 1024/160 keygen self-consistency",
};

static SIZE_OPTIONS: &[ParamOption] = &[
    ParamOption {
        value: "1024/160",
        label: "1024/160 — legacy (fast keygen)",
    },
    ParamOption {
        value: "2048/224",
        label: "2048/224",
    },
    ParamOption {
        value: "2048/256",
        label: "2048/256 — FIPS 186-4 baseline",
    },
    ParamOption {
        value: "3072/256",
        label: "3072/256 — highest strength (slow keygen)",
    },
];

static HASH_OPTIONS: &[ParamOption] = &[
    ParamOption {
        value: "sha1",
        label: "SHA-1 (1024/160 pairing)",
    },
    ParamOption {
        value: "sha224",
        label: "SHA-224 (2048/224 pairing)",
    },
    ParamOption {
        value: "sha256",
        label: "SHA-256",
    },
    ParamOption {
        value: "sha384",
        label: "SHA-384",
    },
    ParamOption {
        value: "sha512",
        label: "SHA-512",
    },
];

fn p_size() -> ParamSpec {
    ParamSpec {
        key: "size",
        label: "Parameter size (L/N)",
        kind: ParamKind::Encoding,
        default: ParamDefault::Str("2048/256"),
        optional: false,
        hint: "FIPS 186-4 sizes; 2048/3072-bit parameter generation can take seconds.",
        options: SIZE_OPTIONS,
    }
}

fn p_hash() -> ParamSpec {
    ParamSpec {
        key: "hash",
        label: "Hash",
        kind: ParamKind::Encoding,
        default: ParamDefault::Str("sha256"),
        optional: false,
        hint: "Digest for the message path and the RFC 6979 nonce; `digest` inputs are used as-is.",
        options: HASH_OPTIONS,
    }
}

fn dsa_spec(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    params: Vec<ParamSpec>,
    input_kinds: &'static [ValueKind],
    aliases: &'static [&'static str],
    deterministic: bool,
) -> &'static OperationSpec {
    Box::leak(Box::new(OperationSpec {
        id,
        name,
        description,
        category: Category::PublicKey,
        input_kinds,
        output_kind: ValueKind::Json,
        params: Box::leak(params.into_boxed_slice()),
        cost: CostClass::Interactive,
        security: Security::Neutral,
        deterministic,
        reversible: false,
        aliases,
        tags: DSA_TAGS,
        provenance: DSA_PROVENANCE,
    }))
}

/// Register the three DSA operations.
pub fn register(reg: &mut OperationRegistry) {
    reg.add_simple(
        dsa_spec(
            "dsa-keygen",
            "DSA Keygen",
            "Generates a DSA key pair with FIPS 186-4 parameter generation (probable primes): domain parameters p, q, g plus private x and public y = g^x mod p. Params: size (1024/160 | 2048/224 | 2048/256 | 3072/256, default 2048/256). Input is ignored. Output (JSON): all components as hex, the FIPS size label, and the PKCS#8/SPKI PEM containers. Note: 2048/3072-bit parameter generation can take seconds — inherent to DSA keygen.",
            vec![p_size()],
            &[ValueKind::Null, ValueKind::Text, ValueKind::Json],
            &["dsa_keygen", "dsa-keypair", "dsa_generate", "generate-dsa"],
            false,
        ),
        keygen_run,
    );
    reg.add_simple(
        dsa_spec(
            "dsa-sign",
            "DSA Sign",
            "Signs a message with DSA using deterministic RFC 6979 nonces (same key + message + hash ⇒ same signature). Input (JSON): {\"p\", \"q\", \"g\", \"x\", \"message\" | \"digest\"} — components and payload as hex, exactly one of message (raw bytes, hashed with the `hash` param) or digest (prehashed, used as-is). Param: hash (sha1|sha224|sha256|sha384|sha512, default sha256). Output (JSON): {\"r\", \"s\"} in hex.",
            vec![p_hash()],
            &[ValueKind::Text, ValueKind::Json],
            &["dsa_sign", "sign-dsa", "dsa-signature"],
            true,
        ),
        sign_run,
    );
    reg.add_simple(
        dsa_spec(
            "dsa-verify",
            "DSA Verify",
            "Verifies a DSA signature against the domain parameters (p, q, g), the public component y, and the message or precomputed digest. Input (JSON): {\"p\", \"q\", \"g\", \"y\", \"message\" | \"digest\", \"r\", \"s\"} — hex; param hash as in dsa-sign. Output (JSON): {\"valid\": bool, \"reason\": str?} — a well-formed signature that does not verify is a result, not an error; malformed components (bad hex, invalid y, zero r/s) are typed errors.",
            vec![p_hash()],
            &[ValueKind::Text, ValueKind::Json],
            &["dsa_verify", "verify-dsa"],
            true,
        ),
        verify_run,
    );
}

// ---------------------------------------------------------------------------
// Run adapters
// ---------------------------------------------------------------------------

fn keygen_run(
    _input: &CoreValue,
    params: &ParamMap,
    _ctx: &ExecutionContext,
) -> OpResult<CoreValue> {
    let size = match params.get_str("size") {
        Some(label) => DsaKeySize::parse(label)?,
        None => DsaKeySize::Dsa2048_256,
    };
    let keypair = dsa_generate_keypair(size)?;
    to_json_value(&keypair)
}

fn sign_run(input: &CoreValue, params: &ParamMap, _ctx: &ExecutionContext) -> OpResult<CoreValue> {
    let json = input_json(input)?;
    let hash = hash_from_params(params)?;
    let object = json
        .as_object()
        .ok_or_else(|| missing_contract("DSA signing"))?;
    let p = required_field(object, "p")?;
    let q = required_field(object, "q")?;
    let g = required_field(object, "g")?;
    let x = required_field(object, "x")?;
    let preimage = preimage_field(object)?;
    let signature = dsa_sign(p, q, g, x, &preimage, hash)?;
    to_json_value(&signature)
}

fn verify_run(
    input: &CoreValue,
    params: &ParamMap,
    _ctx: &ExecutionContext,
) -> OpResult<CoreValue> {
    let json = input_json(input)?;
    let hash = hash_from_params(params)?;
    let object = json
        .as_object()
        .ok_or_else(|| missing_contract("DSA verification"))?;
    let p = required_field(object, "p")?;
    let q = required_field(object, "q")?;
    let g = required_field(object, "g")?;
    let y = required_field(object, "y")?;
    let r = required_field(object, "r")?;
    let s = required_field(object, "s")?;
    let preimage = preimage_field(object)?;
    let result = dsa_verify(p, q, g, y, &preimage, hash, r, s)?;
    to_json_value(&result)
}

// ---------------------------------------------------------------------------
// Input coercion helpers
// ---------------------------------------------------------------------------

fn to_json_value<T: serde::Serialize>(value: &T) -> OpResult<CoreValue> {
    Ok(CoreValue::Json(serde_json::to_value(value).map_err(
        |e| OperationError::internal("DSA report serialization failed").with_details(e.to_string()),
    )?))
}

fn missing_contract(op: &str) -> OperationError {
    OperationError::invalid_input(format!(
        "{op} expects a JSON object with DSA component fields (see the operation description)"
    ))
    .with_expected("a JSON object")
}

fn input_json(input: &CoreValue) -> OpResult<Value> {
    match input {
        CoreValue::Json(json) => Ok(json.clone()),
        CoreValue::Text(text) => {
            serde_json::from_str(text).map_err(|e| parse_error("DSA input is not valid JSON", e))
        }
        CoreValue::Bytes(bytes) => {
            serde_json::from_slice(bytes).map_err(|e| parse_error("DSA input is not valid JSON", e))
        }
        other => Err(OperationError::invalid_input(format!(
            "DSA operations expect JSON input, got {}",
            other.kind().name()
        ))
        .with_expected("json or text containing JSON")),
    }
}

fn parse_error(message: &str, source: serde_json::Error) -> OperationError {
    OperationError::invalid_input(message).with_details(source.to_string())
}

fn required_field<'a>(object: &'a serde_json::Map<String, Value>, key: &str) -> OpResult<&'a str> {
    object.get(key).and_then(Value::as_str).ok_or_else(|| {
        OperationError::invalid_input(format!(
            "missing or non-string field `{key}` (hex expected)"
        ))
        .with_parameter(key)
        .with_expected("a hex string field")
    })
}

/// Exactly one of `message` (raw bytes) / `digest` (prehashed), hex.
fn preimage_field(object: &serde_json::Map<String, Value>) -> OpResult<DsaPreimage> {
    let message = object.get("message").and_then(Value::as_str);
    let digest = object.get("digest").and_then(Value::as_str);
    match (message, digest) {
        (Some(m), None) => Ok(DsaPreimage::Message(m.to_string())),
        (None, Some(d)) => Ok(DsaPreimage::Digest(d.to_string())),
        (Some(_), Some(_)) => Err(OperationError::invalid_input(
            "provide either `message` or `digest`, not both",
        )
        .with_parameter("message/digest")),
        (None, None) => Err(OperationError::invalid_input(
            "missing payload: provide `message` (raw hex) or `digest` (prehashed hex)",
        )
        .with_parameter("message/digest")
        .with_expected("exactly one of message / digest")),
    }
}

fn hash_from_params(params: &ParamMap) -> OpResult<DsaHash> {
    match params.get_str("hash") {
        // PkiError is a type alias for OperationError, so `?` converts 1:1.
        Some(label) => Ok(DsaHash::parse(label)?),
        None => Ok(DsaHash::Sha256),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsa::dsa_keypair_from_components;
    use cybercipher_core::OperationRegistry;
    use serde_json::json;

    fn registry() -> OperationRegistry {
        let mut reg = OperationRegistry::new();
        register(&mut reg);
        reg
    }

    /// The toy key from the unit tests (deterministic, valid DSA math).
    const P: &str = "7eb";
    const Q: &str = "3f5";
    const G: &str = "04";
    const X: &str = "07";
    const Y: &str = "a8";
    const MSG: &str = "deadbeefcafebabe";

    #[test]
    fn three_dsa_ops_registered_with_metadata_and_aliases() {
        let reg = registry();
        assert_eq!(reg.len(), 3);
        for id in ["dsa-keygen", "dsa-sign", "dsa-verify"] {
            let op = reg.get(id).unwrap_or_else(|| panic!("{id} not registered"));
            let info = cybercipher_core::registry::operation_info(op);
            assert_eq!(info.category, Category::PublicKey);
            assert_eq!(info.cost, CostClass::Interactive);
            assert!(info.tags.iter().any(|t| t == "dsa"));
        }
        // Snake-case aliases are searchable.
        let hits = reg.search("dsa_keygen", None);
        assert!(hits.iter().any(|(op, _)| op.spec().id == "dsa-keygen"));
    }

    #[test]
    fn registry_keygen_sign_verify_roundtrip() {
        let reg = registry();
        // Keygen at the fast legacy size (real FIPS generation path).
        let mut params = ParamMap::new();
        params.insert("size", "1024/160");
        let out = reg
            .get("dsa-keygen")
            .unwrap()
            .execute(&CoreValue::Null, &params, &ExecutionContext::new())
            .unwrap();
        let CoreValue::Json(kp) = out else {
            panic!("expected JSON keypair");
        };
        assert_eq!(kp["size"], json!("1024/160"));
        assert!(kp["private_key_pem"]
            .as_str()
            .unwrap()
            .starts_with("-----BEGIN PRIVATE KEY-----"));

        // Sign with the GENERATED key through the registry.
        let mut params = ParamMap::new();
        params.insert("hash", "sha256");
        let input = CoreValue::Json(json!({
            "p": kp["p"], "q": kp["q"], "g": kp["g"], "x": kp["private_key"],
            "message": crate::keys::to_hex(b"registry roundtrip"),
        }));
        let out = reg
            .get("dsa-sign")
            .unwrap()
            .execute(&input, &params, &ExecutionContext::new())
            .unwrap();
        let CoreValue::Json(sig) = out else {
            panic!("expected JSON signature");
        };
        assert!(sig["r"].as_str().is_some() && sig["s"].as_str().is_some());

        // Verify through the registry.
        let input = CoreValue::Json(json!({
            "p": kp["p"], "q": kp["q"], "g": kp["g"], "y": kp["public_key"],
            "message": crate::keys::to_hex(b"registry roundtrip"),
            "r": sig["r"], "s": sig["s"],
        }));
        let out = reg
            .get("dsa-verify")
            .unwrap()
            .execute(&input, &params, &ExecutionContext::new())
            .unwrap();
        let CoreValue::Json(report) = out else {
            panic!("expected JSON verify report");
        };
        assert_eq!(report["valid"], json!(true));
    }

    #[test]
    fn registry_verify_reports_invalid_signature_as_result() {
        let reg = registry();
        let params = ParamMap::new();
        let input = CoreValue::Json(json!({
            "p": P, "q": Q, "g": G, "y": Y,
            "message": "deadbeefcafebabf", // tampered last byte
            "r": "01", "s": "01",
        }));
        let out = reg
            .get("dsa-verify")
            .unwrap()
            .execute(&input, &params, &ExecutionContext::new())
            .unwrap();
        let CoreValue::Json(report) = out else {
            panic!("expected JSON verify report");
        };
        assert_eq!(report["valid"], json!(false));
        assert!(report["reason"].is_string());
    }

    #[test]
    fn registry_rejects_wrong_input_kinds_and_bad_contracts() {
        let reg = registry();
        let mut params = ParamMap::new();
        // Non-JSON text input → typed parse error.
        let err = reg
            .get("dsa-sign")
            .unwrap()
            .execute(
                &CoreValue::Text("not json".to_string()),
                &params,
                &ExecutionContext::new(),
            )
            .expect_err("non-JSON text must fail");
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidInput);
        // Missing payload (no message/digest) → typed contract error.
        let input = CoreValue::Json(json!({ "p": P, "q": Q, "g": G, "x": X }));
        let err = reg
            .get("dsa-sign")
            .unwrap()
            .execute(&input, &params, &ExecutionContext::new())
            .expect_err("missing payload must fail");
        assert!(err.message.contains("message") || err.message.contains("payload"));
        // Both payload fields → typed contract error.
        let input = CoreValue::Json(json!({
            "p": P, "q": Q, "g": G, "x": X, "message": MSG, "digest": MSG,
        }));
        let err = reg
            .get("dsa-sign")
            .unwrap()
            .execute(&input, &params, &ExecutionContext::new())
            .expect_err("both payloads must fail");
        assert!(err.message.contains("either"));
        // Unknown hash → typed unsupported error.
        params.insert("hash", "md5");
        let input = CoreValue::Json(json!({
            "p": P, "q": Q, "g": G, "x": X, "message": MSG,
        }));
        let err = reg
            .get("dsa-sign")
            .unwrap()
            .execute(&input, &params, &ExecutionContext::new())
            .expect_err("unknown hash must fail");
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Unsupported);
    }

    #[test]
    fn registry_keygen_rejects_unknown_size() {
        let reg = registry();
        let mut params = ParamMap::new();
        params.insert("size", "512/64");
        let err = reg
            .get("dsa-keygen")
            .unwrap()
            .execute(&CoreValue::Null, &params, &ExecutionContext::new())
            .expect_err("unknown size must fail");
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidInput);
        assert!(err.message.contains("key size"));
    }

    #[test]
    fn registry_sign_with_toy_key_is_deterministic() {
        let reg = registry();
        let params = ParamMap::new();
        let input = CoreValue::Json(json!({
            "p": P, "q": Q, "g": G, "x": X, "message": MSG,
        }));
        let out1 = reg
            .get("dsa-sign")
            .unwrap()
            .execute(&input.clone(), &params, &ExecutionContext::new())
            .unwrap();
        let out2 = reg
            .get("dsa-sign")
            .unwrap()
            .execute(&input, &params, &ExecutionContext::new())
            .unwrap();
        assert_eq!(out1, out2, "RFC 6979 signatures are deterministic");
        let CoreValue::Json(sig) = out1 else {
            panic!("expected JSON signature");
        };
        // Cross-check against the library API directly.
        let expected = dsa_sign(
            P,
            Q,
            G,
            X,
            &DsaPreimage::Message(MSG.to_string()),
            DsaHash::Sha256,
        )
        .unwrap();
        assert_eq!(sig["r"], json!(expected.r));
        assert_eq!(sig["s"], json!(expected.s));
    }

    #[test]
    fn registry_component_constructor_roundtrip() {
        // dsa_keypair_from_components is exposed for key-import flows.
        let kp = dsa_keypair_from_components(P, Q, G, X).expect("toy key is valid");
        assert_eq!(kp.public_key, Y);
        assert!(kp.private_key_pem.contains("PRIVATE KEY"));
    }
}
