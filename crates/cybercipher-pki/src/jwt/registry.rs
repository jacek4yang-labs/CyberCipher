//! Registry wiring for the JWT operations, following the crate-wide
//! [`SimpleOp`] pattern (`cybercipher-codec`/`cybercipher-crypto` style):
//! static [`OperationSpec`]s plus closures that adapt the typed
//! [`crate::jwt`] API to [`Value`] in/out.
//!
//! Ops (ids are kebab-case like every other registry entry):
//! - `jwt-decode` — structural decode; output is explicitly `verified: false`;
//! - `jwt-verify` — signature + claims verification with an explicit alg;
//! - `jwt-sign`   — claims JSON in, compact JWS out.
//!
//! Cost class is `Interactive` for all three: no network, but RSA/EC
//! verification and key parsing are too heavy for the `Instant` auto-bake
//! tier.

use cybercipher_core::prelude::*;
use cybercipher_core::Value as CoreValue;
use serde_json::Value;

use crate::jwt::{
    jwt_decode, jwt_sign, jwt_verify, jwt_verify_at, JwtAlg, JwtSignParams, JwtVerifyParams,
    KeyEncoding, SecretEncoding,
};

const JWT_TAGS: &[&str] = &["jwt", "jws", "token"];

const JWT_PROVENANCE: Provenance = Provenance {
    standard: "RFC 7519 / RFC 7515 (JOSE JWT/JWS); policy per RFC 8725",
    implementation: "CyberCipher native Rust (hmac, rsa, p256/p384, ed25519-dalek)",
    test_vectors: "RFC 7515 A.1/A.2, jwt.io sample, CyberCipher unit tests",
};

static ALG_OPTIONS: &[ParamOption] = &[
    ParamOption {
        value: "HS256",
        label: "HS256 — HMAC-SHA-256 (shared secret)",
    },
    ParamOption {
        value: "HS384",
        label: "HS384 — HMAC-SHA-384 (shared secret)",
    },
    ParamOption {
        value: "HS512",
        label: "HS512 — HMAC-SHA-512 (shared secret)",
    },
    ParamOption {
        value: "RS256",
        label: "RS256 — RSASSA-PKCS1-v1_5 + SHA-256",
    },
    ParamOption {
        value: "RS384",
        label: "RS384 — RSASSA-PKCS1-v1_5 + SHA-384",
    },
    ParamOption {
        value: "RS512",
        label: "RS512 — RSASSA-PKCS1-v1_5 + SHA-512",
    },
    ParamOption {
        value: "ES256",
        label: "ES256 — ECDSA P-256 (r||s)",
    },
    ParamOption {
        value: "ES384",
        label: "ES384 — ECDSA P-384 (r||s)",
    },
    ParamOption {
        value: "EdDSA",
        label: "EdDSA — Ed25519",
    },
];

static SECRET_ENCODINGS: &[ParamOption] = &[
    ParamOption {
        value: "utf8",
        label: "UTF-8 text",
    },
    ParamOption {
        value: "hex",
        label: "Hex",
    },
];

static KEY_ENCODINGS: &[ParamOption] = &[
    ParamOption {
        value: "pem",
        label: "PEM (SPKI / PKCS#8)",
    },
    ParamOption {
        value: "hex",
        label: "Hex (SEC1 / raw bytes)",
    },
];

fn p_text(key: &'static str, label: &'static str, hint: &'static str) -> ParamSpec {
    ParamSpec {
        key,
        label,
        kind: ParamKind::TextArea,
        default: ParamDefault::Str(""),
        optional: false,
        hint,
        options: &[],
    }
}

fn p_text_opt(key: &'static str, label: &'static str, hint: &'static str) -> ParamSpec {
    ParamSpec {
        key,
        label,
        kind: ParamKind::TextArea,
        default: ParamDefault::Str(""),
        optional: true,
        hint,
        options: &[],
    }
}

fn p_enc(
    key: &'static str,
    label: &'static str,
    default: &'static str,
    options: &'static [ParamOption],
    hint: &'static str,
) -> ParamSpec {
    ParamSpec {
        key,
        label,
        kind: ParamKind::Encoding,
        default: ParamDefault::Str(default),
        optional: false,
        hint,
        options,
    }
}

#[allow(clippy::too_many_arguments)] // same shape as crypto::mac::mac_spec
fn jwt_spec(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    params: Vec<ParamSpec>,
    output_kind: ValueKind,
    security: Security,
    aliases: &'static [&'static str],
    deterministic: bool,
) -> &'static OperationSpec {
    Box::leak(Box::new(OperationSpec {
        id,
        name,
        description,
        category: Category::PublicKey,
        input_kinds: Box::leak(vec![ValueKind::Text, ValueKind::Json].into_boxed_slice()),
        output_kind,
        params: Box::leak(params.into_boxed_slice()),
        cost: CostClass::Interactive,
        security,
        deterministic,
        reversible: false,
        aliases,
        tags: JWT_TAGS,
        provenance: JWT_PROVENANCE,
    }))
}

/// Register the three JWT operations.
pub fn register(reg: &mut OperationRegistry) {
    reg.add_simple(
        jwt_spec(
            "jwt-decode",
            "JWT Decode",
            "Decodes a JWT/JWS compact serialization into its JOSE header, payload, and signature (hex, plus the exact signing input). Purely structural: the report is marked \"verified\": false — decoding never checks the signature, so treat every claim as untrusted until jwt-verify passes. Rejects malformed segment counts, non-base64url characters, padding, non-JSON parts, and headers without a string alg.",
            vec![],
            ValueKind::Json,
            Security::Neutral,
            &["jwt", "jws-decode", "token-decode"],
            true,
        ),
        decode_run,
    );

    reg.add_simple(
        jwt_spec(
            "jwt-verify",
            "JWT Verify",
            "Verifies a JWT/JWS signature with an explicit algorithm (HS256/384/512, RS256/384/512, ES256/384, EdDSA). The header alg must equal the selected alg; alg=none and unsigned tokens are always rejected (RFC 8725). HS* keys are shared secrets (PEM-looking secrets are refused); RS* takes a public/private PEM; ES*/EdDSA take PEM or hex. Validates exp/nbf/iat/iss/aud with leeway when validate_claims is on.",
            vec![
                p_enc(
                    "alg",
                    "Algorithm",
                    "HS256",
                    ALG_OPTIONS,
                    "Must match the token's header alg exactly — mismatches are rejected.",
                ),
                p_text(
                    "key",
                    "Key",
                    "HS*: shared secret (see secret_encoding). RS*: PUBLIC KEY / RSA PUBLIC KEY / PRIVATE KEY PEM (private keys are reduced to their public half). ES*/EdDSA: PEM or hex per key_encoding.",
                ),
                p_enc(
                    "secret_encoding",
                    "Secret encoding (HS*)",
                    "utf8",
                    SECRET_ENCODINGS,
                    "How to read the HS* shared secret. Secrets that look like PEM armor are rejected.",
                ),
                p_enc(
                    "key_encoding",
                    "Key encoding (ES*/EdDSA)",
                    "pem",
                    KEY_ENCODINGS,
                    "How to read ES*/EdDSA keys: PEM armor or hex (SEC1 point / raw 32-byte key).",
                ),
                ParamSpec {
                    key: "validate_claims",
                    label: "Validate claims",
                    kind: ParamKind::Boolean,
                    default: ParamDefault::Bool(true),
                    optional: false,
                    hint: "Check exp/nbf/iat (NumericDate) and iss/aud exact matches after the signature.",
                    options: &[],
                },
                ParamSpec {
                    key: "leeway",
                    label: "Leeway (seconds)",
                    kind: ParamKind::Integer,
                    default: ParamDefault::Int(60),
                    optional: false,
                    hint: "Clock-skew tolerance for exp/nbf.",
                    options: &[],
                },
                p_text_opt(
                    "expected_iss",
                    "Expected issuer",
                    "Exact-match iss check; empty = do not check.",
                ),
                p_text_opt(
                    "expected_aud",
                    "Expected audience",
                    "Exact-match aud check (string or array member); empty = do not check.",
                ),
                ParamSpec {
                    key: "now_unix",
                    label: "Override now (unix seconds)",
                    kind: ParamKind::Integer,
                    default: ParamDefault::Int(0),
                    optional: true,
                    hint: "Freeze the verification clock for reproducible checks; empty = system time.",
                    options: &[],
                },
            ],
            ValueKind::Json,
            Security::Modern,
            &["verify-jwt", "jws-verify", "jwt-check"],
            true,
        ),
        verify_run,
    );

    reg.add_simple(
        jwt_spec(
            "jwt-sign",
            "JWT Sign",
            "Signs a JSON claims object into a compact JWS (header.payload.signature). The JOSE header is canonical {\"alg\":..., \"typ\":\"JWT\"} plus the given extras (extras may override typ but never alg; CyberCipher invents no fields). ECDSA (ES256/384) uses deterministic RFC 6979 nonces. HS* signs with the shared secret, RS* with a private-key PEM, ES*/EdDSA with a PEM or hex key.",
            vec![
                p_enc(
                    "alg",
                    "Algorithm",
                    "HS256",
                    ALG_OPTIONS,
                    "The algorithm written into the header and used to sign.",
                ),
                p_text(
                    "key",
                    "Key",
                    "HS*: shared secret. RS*: PRIVATE KEY / RSA PRIVATE KEY PEM. ES*/EdDSA: PRIVATE KEY PEM or hex (scalar / 32-byte seed).",
                ),
                p_enc(
                    "secret_encoding",
                    "Secret encoding (HS*)",
                    "utf8",
                    SECRET_ENCODINGS,
                    "How to read the HS* shared secret.",
                ),
                p_enc(
                    "key_encoding",
                    "Key encoding (ES*/EdDSA)",
                    "pem",
                    KEY_ENCODINGS,
                    "How to read ES*/EdDSA keys: PEM armor or hex.",
                ),
                p_text_opt(
                    "header_extra",
                    "Header extras (JSON)",
                    "Optional JSON object merged into the JOSE header (kid, jku, crit, ...).",
                ),
            ],
            ValueKind::Text,
            Security::Modern,
            &["sign-jwt", "jws-sign", "jwt-create"],
            true,
        ),
        sign_run,
    );
}

// ---------------------------------------------------------------------------
// Run adapters
// ---------------------------------------------------------------------------

fn decode_run(
    input: &CoreValue,
    _params: &ParamMap,
    _ctx: &ExecutionContext,
) -> OpResult<CoreValue> {
    let token = input_text(input)?;
    let decoded = jwt_decode(&token)?;
    let json = serde_json::to_value(&decoded).map_err(|e| {
        OperationError::internal("JWT decode report serialization failed")
            .with_details(e.to_string())
    })?;
    Ok(CoreValue::Json(json))
}

fn verify_run(
    input: &CoreValue,
    params: &ParamMap,
    _ctx: &ExecutionContext,
) -> OpResult<CoreValue> {
    let token = input_text(input)?;
    let alg = JwtAlg::parse(params.str_or("alg", "HS256"))?;
    let key = params.require_str("key")?;

    let vp = JwtVerifyParams {
        secret_encoding: SecretEncoding::parse(params.str_or("secret_encoding", "utf8"))?,
        key_encoding: KeyEncoding::parse(params.str_or("key_encoding", "pem"))?,
        validate_claims: params.bool_or("validate_claims", true),
        leeway_secs: params.int_or("leeway", 60),
        expected_iss: optional_str(params, "expected_iss"),
        expected_aud: optional_str(params, "expected_aud"),
    };

    let verified = match params.get_int("now_unix") {
        Some(now) if now > 0 => jwt_verify_at(&token, alg, key, &vp, now)?,
        _ => jwt_verify(&token, alg, key, &vp)?,
    };
    let json = serde_json::to_value(&verified).map_err(|e| {
        OperationError::internal("JWT verify report serialization failed")
            .with_details(e.to_string())
    })?;
    Ok(CoreValue::Json(json))
}

fn sign_run(input: &CoreValue, params: &ParamMap, _ctx: &ExecutionContext) -> OpResult<CoreValue> {
    let claims = input_json(input)?;
    let alg = JwtAlg::parse(params.str_or("alg", "HS256"))?;
    let key = params.require_str("key")?;

    let sp = JwtSignParams {
        secret_encoding: SecretEncoding::parse(params.str_or("secret_encoding", "utf8"))?,
        key_encoding: KeyEncoding::parse(params.str_or("key_encoding", "pem"))?,
    };

    let header_extra = match params.get_str("header_extra") {
        None | Some("") => Value::Null,
        Some(text) => serde_json::from_str(text).map_err(|e| {
            OperationError::invalid_param("header_extra", "header_extra is not valid JSON")
                .with_details(e.to_string())
        })?,
    };

    let token = jwt_sign(claims, header_extra, alg, key, &sp)?;
    Ok(CoreValue::Text(token))
}

// ---------------------------------------------------------------------------
// Input coercion helpers
// ---------------------------------------------------------------------------

fn input_text(input: &CoreValue) -> OpResult<String> {
    match input {
        CoreValue::Text(t) => Ok(t.clone()),
        CoreValue::Bytes(b) => String::from_utf8(b.clone()).map_err(|_| {
            OperationError::invalid_input("JWT token input is not valid UTF-8")
                .with_expected("a UTF-8 token string")
        }),
        other => Err(OperationError::invalid_input(format!(
            "JWT operations expect a token string, got {}",
            other.kind().name()
        ))
        .with_expected("text")),
    }
}

fn input_json(input: &CoreValue) -> OpResult<Value> {
    match input {
        CoreValue::Json(j) => Ok(j.clone()),
        CoreValue::Text(t) => serde_json::from_str(t).map_err(|e| {
            OperationError::invalid_input("JWT claims input is not valid JSON")
                .with_details(e.to_string())
        }),
        CoreValue::Bytes(b) => serde_json::from_slice(b).map_err(|e| {
            OperationError::invalid_input("JWT claims input is not valid JSON")
                .with_details(e.to_string())
        }),
        other => Err(OperationError::invalid_input(format!(
            "JWT signing expects a JSON claims object, got {}",
            other.kind().name()
        ))
        .with_expected("json")),
    }
}

fn optional_str(params: &ParamMap, key: &str) -> Option<String> {
    params
        .get_str(key)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const JWT_IO_SAMPLE: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    fn registry() -> OperationRegistry {
        let mut reg = OperationRegistry::new();
        register(&mut reg);
        reg
    }

    #[test]
    fn three_jwt_ops_registered_with_expected_metadata() {
        let reg = registry();
        for id in ["jwt-decode", "jwt-verify", "jwt-sign"] {
            let op = reg.get(id).unwrap_or_else(|| panic!("{id} not registered"));
            let info = cybercipher_core::registry::operation_info(op);
            assert_eq!(info.id, id);
            assert_eq!(info.category, Category::PublicKey);
            assert_eq!(info.cost, CostClass::Interactive);
            assert_eq!(info.provenance.standard, JWT_PROVENANCE.standard);
            assert!(!info.tags.is_empty());
        }
        assert_eq!(reg.len(), 3);
    }

    #[test]
    fn decode_op_marks_output_unverified() {
        let reg = registry();
        let op = reg.get("jwt-decode").unwrap();
        let out = op
            .execute(
                &CoreValue::Text(JWT_IO_SAMPLE.to_string()),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap();
        let CoreValue::Json(report) = out else {
            panic!("decode must produce JSON");
        };
        assert_eq!(report["verified"], json!(false));
        assert_eq!(report["header"]["alg"], json!("HS256"));
        assert_eq!(report["payload"]["name"], json!("John Doe"));
        assert!(report["signing_input"].as_str().unwrap().contains('.'));
    }

    #[test]
    fn sign_and_verify_roundtrip_through_ops() {
        let reg = registry();
        let ctx = ExecutionContext::new();

        let mut sign_params = ParamMap::new();
        sign_params.insert("alg", "HS256");
        sign_params.insert("key", "roundtrip-secret");
        let token = reg
            .get("jwt-sign")
            .unwrap()
            .execute(
                &CoreValue::Json(json!({"sub": "u1", "role": "admin"})),
                &sign_params,
                &ctx,
            )
            .unwrap();
        let CoreValue::Text(token) = token else {
            panic!("sign must produce text");
        };

        let mut verify_params = ParamMap::new();
        verify_params.insert("alg", "HS256");
        verify_params.insert("key", "roundtrip-secret");
        let out = reg
            .get("jwt-verify")
            .unwrap()
            .execute(&CoreValue::Text(token), &verify_params, &ctx)
            .unwrap();
        let CoreValue::Json(report) = out else {
            panic!("verify must produce JSON");
        };
        assert_eq!(report["valid"], json!(true));
        assert_eq!(report["payload"]["role"], json!("admin"));
        assert_eq!(report["alg"], json!("HS256"));
    }

    #[test]
    fn verify_op_reports_invalid_signature_as_valid_false() {
        let reg = registry();
        let mut verify_params = ParamMap::new();
        verify_params.insert("alg", "HS256");
        verify_params.insert("key", "wrong-secret");
        let out = reg
            .get("jwt-verify")
            .unwrap()
            .execute(
                &CoreValue::Text(JWT_IO_SAMPLE.to_string()),
                &verify_params,
                &ExecutionContext::new(),
            )
            .unwrap();
        let CoreValue::Json(report) = out else {
            panic!("verify must produce JSON");
        };
        assert_eq!(report["valid"], json!(false));
        assert!(report["reason"].is_string());
    }

    #[test]
    fn verify_op_none_alg_is_typed_error() {
        let reg = registry();
        let mut verify_params = ParamMap::new();
        verify_params.insert("alg", "HS256");
        verify_params.insert("key", "k");
        let err = reg
            .get("jwt-verify")
            .unwrap()
            .execute(
                &CoreValue::Text("eyJhbGciOiJub25lIn0.eyJhIjoxfQ.c2ln".to_string()),
                &verify_params,
                &ExecutionContext::new(),
            )
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Unsupported);
        assert!(err.details.as_deref().unwrap_or_default().contains("8725"));
    }

    #[test]
    fn ops_reject_wrong_input_kinds() {
        let reg = registry();
        let err = reg
            .get("jwt-decode")
            .unwrap()
            .execute(&CoreValue::Null, &ParamMap::new(), &ExecutionContext::new())
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidInput);
    }
}
