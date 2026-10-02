//! Registry wiring for the four ECDSA attack operations, following the
//! crate-wide [`SimpleOp`] pattern (see `crate::jwt::registry`): static
//! [`OperationSpec`]s plus closures that adapt the typed
//! [`crate::ecc::attacks`] API to [`Value`] in/out.
//!
//! Ops (ids are kebab-case like every other registry entry; snake_case
//! aliases mirror the task-named ids for search discovery):
//! - `ecdsa-duplicate-r-detect` — nonce-reuse fingerprint scan over a list;
//! - `ecdsa-nonce-reuse-recover` — private key from two same-r signatures;
//! - `ecdsa-known-k-recover` — private key from one signature + known nonce;
//! - `ecdsa-small-k-recover` — bounded brute force over small nonces.
//!
//! Input contract (JSON value; Text/Bytes are parsed as JSON, and the detect
//! op additionally accepts a `Value::List` of signature objects):
//! - detect: an array of `{message | digest, r, s}` objects, or an object
//!   with a `signatures` array;
//! - reuse: `{msg1 | digest1, msg2 | digest2, r (or r1 + r2), s1, s2}`;
//! - known-k: `{message | digest, r, s, k}`;
//! - small-k: `{message | digest, r, s}`.
//!
//! `message` is the hex of the raw message bytes (hashed internally with the
//! `hash` param); `digest` is the hex of the prehash (used as-is, exact
//! length enforced). Params: `curve` (p256|p384, default p256), `hash`
//! (auto|sha256|sha384, default auto = curve-paired), `public_key` (SEC1
//! hex, mandatory for the three recovery ops — verification policy), and
//! `max_k` (small-k bound, default 100000, hard cap 10000000).

use cybercipher_core::prelude::*;
use cybercipher_core::Value as CoreValue;
use serde_json::Value;

use super::attacks::{
    ecdsa_duplicate_r_detect, ecdsa_known_k_recover, ecdsa_nonce_reuse_recover,
    ecdsa_small_k_recover, EcdsaAttackSignature, EcdsaPreimage, SMALL_K_DEFAULT,
};
use super::curve::{parse_ecc_curve, EccCurve};
use super::ecdsa::EcdsaDigest;

const ECDSA_ATTACK_TAGS: &[&str] = &["ecdsa", "ecc", "attack", "nonce", "signature"];

const ECDSA_ATTACK_PROVENANCE: Provenance = Provenance {
    standard: "ECDSA key recovery from nonce reuse / known-k / small-k (signatures per FIPS 186-5)",
    implementation: "CyberCipher native Rust (num-bigint-dig scalar algebra over the p256/p384 crate group orders; key derivation via elliptic-curve)",
    test_vectors: "CyberCipher unit tests anchored on the existing ECDSA sign/verify roundtrip and the FIPS 186-4 group orders",
};

static CURVE_OPTIONS: &[ParamOption] = &[
    ParamOption {
        value: "p256",
        label: "P-256 (secp256r1)",
    },
    ParamOption {
        value: "p384",
        label: "P-384 (secp384r1)",
    },
];

static HASH_OPTIONS: &[ParamOption] = &[
    ParamOption {
        value: "auto",
        label: "Auto (curve default: P-256+SHA-256, P-384+SHA-384)",
    },
    ParamOption {
        value: "sha256",
        label: "SHA-256",
    },
    ParamOption {
        value: "sha384",
        label: "SHA-384",
    },
];

fn p_curve() -> ParamSpec {
    ParamSpec {
        key: "curve",
        label: "Curve",
        kind: ParamKind::Encoding,
        default: ParamDefault::Str("p256"),
        optional: false,
        hint: "ECDSA attacks are defined for the NIST curves only.",
        options: CURVE_OPTIONS,
    }
}

fn p_hash() -> ParamSpec {
    ParamSpec {
        key: "hash",
        label: "Hash",
        kind: ParamKind::Encoding,
        default: ParamDefault::Str("auto"),
        optional: false,
        hint: "Digest used by the signatures; auto = curve default. The pairing (P-256+SHA-256, P-384+SHA-384) is enforced.",
        options: HASH_OPTIONS,
    }
}

fn p_public_key() -> ParamSpec {
    ParamSpec {
        key: "public_key",
        label: "Public key (SEC1 hex)",
        kind: ParamKind::TextArea,
        default: ParamDefault::Str(""),
        optional: false,
        hint: "SEC1 hex (02/03||x or 04||x||y) of the signing key. Mandatory: every recovery is verified against it before it is reported.",
        options: &[],
    }
}

fn p_max_k() -> ParamSpec {
    ParamSpec {
        key: "max_k",
        label: "Max k",
        kind: ParamKind::Integer,
        default: ParamDefault::Int(100_000),
        optional: false,
        hint: "Search nonces 1..=max_k (default 100000, hard cap 10000000). Deadline-aware via the execution context.",
        options: &[],
    }
}

fn attack_spec(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    params: Vec<ParamSpec>,
    aliases: &'static [&'static str],
) -> &'static OperationSpec {
    Box::leak(Box::new(OperationSpec {
        id,
        name,
        description,
        category: Category::Analysis,
        input_kinds: Box::leak(
            vec![ValueKind::Text, ValueKind::Json, ValueKind::List].into_boxed_slice(),
        ),
        output_kind: ValueKind::Json,
        params: Box::leak(params.into_boxed_slice()),
        cost: CostClass::Interactive,
        security: Security::Neutral,
        deterministic: true,
        reversible: false,
        aliases,
        tags: ECDSA_ATTACK_TAGS,
        provenance: ECDSA_ATTACK_PROVENANCE,
    }))
}

/// Register the four ECDSA attack operations.
pub fn register(reg: &mut OperationRegistry) {
    reg.add_simple(
        attack_spec(
            "ecdsa-duplicate-r-detect",
            "ECDSA Duplicate-r Detect",
            "Scans a list of ECDSA signatures for repeated r values — the fingerprint of nonce reuse. Input: a JSON array of signature objects, an object with a `signatures` array, or a list value; each entry is {\"message\": <hex raw message bytes>} or {\"digest\": <hex prehash>} plus \"r\" and \"s\" (hex scalars in 1..n). Params: curve (p256|p384), hash (auto|sha256|sha384). The r comparison is exact on the parsed values; every signature is fully validated, so the list is recovery-ready for ecdsa-nonce-reuse-recover. Reports every group and pair sharing an r value.",
            vec![p_curve(), p_hash()],
            &["ecdsa_duplicate_r_detect", "duplicate-r", "nonce-detect"],
        ),
        detect_run,
    );
    reg.add_simple(
        attack_spec(
            "ecdsa-nonce-reuse-recover",
            "ECDSA Nonce-Reuse Recover",
            "Recovers the ECDSA private key from two signatures that share a nonce (same r): k = (h1-h2)/(s1-s2) mod n, then d = (s1*k-h1)/r mod n. Input (JSON): {\"msg1\"|\"digest1\", \"msg2\"|\"digest2\", \"r\" (or \"r1\"+\"r2\"), \"s1\", \"s2\"} (hex); param public_key (SEC1 hex) is mandatory. The recovered key is verified by deriving its public key — a mismatch is a typed error, never an unverified report. Identical signatures (s1 == s2 mod n), identical digests (h1 == h2), different r values, and zero/out-of-range components are typed errors.",
            vec![p_curve(), p_hash(), p_public_key()],
            &["ecdsa_nonce_reuse_recover", "nonce-reuse", "same-nonce"],
        ),
        reuse_run,
    );
    reg.add_simple(
        attack_spec(
            "ecdsa-known-k-recover",
            "ECDSA Known-k Recover",
            "Recovers the ECDSA private key from one signature whose nonce k is known: d = (s*k-h)/r mod n. Input (JSON): {\"message\"|\"digest\", \"r\", \"s\", \"k\"} (hex); param public_key (SEC1 hex) is mandatory. The recovered key is verified against the public key before it is reported — a wrong k fails with a typed error instead of producing a bogus key.",
            vec![p_curve(), p_hash(), p_public_key()],
            &["ecdsa_known_k_recover", "known-k", "known-nonce"],
        ),
        known_k_run,
    );
    reg.add_simple(
        attack_spec(
            "ecdsa-small-k-recover",
            "ECDSA Small-k Recover",
            "Brute-forces small ECDSA nonces: for each candidate k in 1..=max_k (param, default 100000, hard cap 10000000, deadline-aware via the execution context) it derives d = (s*k-h)/r mod n and accepts the first candidate whose derived public key equals the provided public key. Input (JSON): {\"message\"|\"digest\", \"r\", \"s\"} (hex); params public_key (SEC1 hex) and max_k. The verified match reports the recovered key, the nonce, and the number of candidates tried; exhausting the bound is a typed budget error.",
            vec![p_curve(), p_hash(), p_public_key(), p_max_k()],
            &["ecdsa_small_k_recover", "small-k", "small-nonce"],
        ),
        small_k_run,
    );
}

// ---------------------------------------------------------------------------
// Run adapters
// ---------------------------------------------------------------------------

fn detect_run(
    input: &CoreValue,
    params: &ParamMap,
    _ctx: &ExecutionContext,
) -> OpResult<CoreValue> {
    let curve = curve_from_params(params)?;
    let digest = digest_from_params(params, curve)?;
    let entries = detect_entries(input)?;
    let signatures = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| signature_from_entry(entry, index + 1))
        .collect::<OpResult<Vec<_>>>()?;
    let report = ecdsa_duplicate_r_detect(curve, digest, &signatures)?;
    to_json_value(&report)
}

fn reuse_run(input: &CoreValue, params: &ParamMap, _ctx: &ExecutionContext) -> OpResult<CoreValue> {
    let curve = curve_from_params(params)?;
    let digest = digest_from_params(params, curve)?;
    let public_key = params.require_str("public_key")?;
    let json = input_json(input)?;
    let object = json
        .as_object()
        .ok_or_else(|| missing_contract("nonce-reuse recovery"))?;
    let sig1 = EcdsaAttackSignature {
        preimage: preimage_field(object, "1")?,
        r_hex: shared_r_field(object, "1")?,
        s_hex: required_field(object, "s1")?,
    };
    let sig2 = EcdsaAttackSignature {
        preimage: preimage_field(object, "2")?,
        r_hex: shared_r_field(object, "2")?,
        s_hex: required_field(object, "s2")?,
    };
    let report = ecdsa_nonce_reuse_recover(curve, digest, &sig1, &sig2, public_key)?;
    to_json_value(&report)
}

fn known_k_run(
    input: &CoreValue,
    params: &ParamMap,
    _ctx: &ExecutionContext,
) -> OpResult<CoreValue> {
    let curve = curve_from_params(params)?;
    let digest = digest_from_params(params, curve)?;
    let public_key = params.require_str("public_key")?;
    let json = input_json(input)?;
    let object = json
        .as_object()
        .ok_or_else(|| missing_contract("known-k recovery"))?;
    let signature = EcdsaAttackSignature {
        preimage: preimage_field(object, "")?,
        r_hex: required_field(object, "r")?,
        s_hex: required_field(object, "s")?,
    };
    let k_hex = required_field(object, "k")?;
    let report = ecdsa_known_k_recover(curve, digest, &signature, &k_hex, public_key)?;
    to_json_value(&report)
}

fn small_k_run(
    input: &CoreValue,
    params: &ParamMap,
    ctx: &ExecutionContext,
) -> OpResult<CoreValue> {
    let curve = curve_from_params(params)?;
    let digest = digest_from_params(params, curve)?;
    let public_key = params.require_str("public_key")?;
    let max_k = max_k_from_params(params)?;
    let json = input_json(input)?;
    let object = json
        .as_object()
        .ok_or_else(|| missing_contract("small-k recovery"))?;
    let signature = EcdsaAttackSignature {
        preimage: preimage_field(object, "")?,
        r_hex: required_field(object, "r")?,
        s_hex: required_field(object, "s")?,
    };
    let report = ecdsa_small_k_recover(curve, digest, &signature, public_key, max_k, ctx)?;
    to_json_value(&report)
}

// ---------------------------------------------------------------------------
// Input coercion helpers
// ---------------------------------------------------------------------------

fn to_json_value<T: serde::Serialize>(value: &T) -> OpResult<CoreValue> {
    Ok(CoreValue::Json(serde_json::to_value(value).map_err(
        |e| {
            OperationError::internal("ECDSA attack report serialization failed")
                .with_details(e.to_string())
        },
    )?))
}

fn missing_contract(op: &str) -> OperationError {
    OperationError::invalid_input(format!(
        "{op} expects a JSON object with the signature fields (see the operation description)"
    ))
    .with_expected("a JSON object")
}

fn input_json(input: &CoreValue) -> OpResult<Value> {
    match input {
        CoreValue::Json(json) => Ok(json.clone()),
        CoreValue::Text(text) => serde_json::from_str(text)
            .map_err(|e| parse_error("ECDSA attack input is not valid JSON", e)),
        CoreValue::Bytes(bytes) => serde_json::from_slice(bytes)
            .map_err(|e| parse_error("ECDSA attack input is not valid JSON", e)),
        other => Err(OperationError::invalid_input(format!(
            "ECDSA attack operations expect JSON input, got {}",
            other.kind().name()
        ))
        .with_expected("json or text containing JSON")),
    }
}

fn parse_error(message: &str, source: serde_json::Error) -> OperationError {
    OperationError::invalid_input(message).with_details(source.to_string())
}

/// The detect op accepts a `Value::List` of signature objects, a JSON array,
/// or an object with a `signatures` array.
fn detect_entries(input: &CoreValue) -> OpResult<Vec<Value>> {
    match input {
        CoreValue::List(items) => items.iter().map(value_to_json).collect(),
        CoreValue::Text(_) | CoreValue::Bytes(_) => {
            let json = input_json(input)?;
            detect_entries(&CoreValue::Json(json))
        }
        CoreValue::Json(json) => match json {
            Value::Array(items) => Ok(items.clone()),
            Value::Object(map) => match map.get("signatures") {
                Some(Value::Array(items)) => Ok(items.clone()),
                _ => Err(OperationError::invalid_input(
                    "duplicate-r detection expects an array of signature objects or an object with a `signatures` array",
                )
                .with_expected("[{message | digest, r, s}, ...] or {\"signatures\": [...]}")),
            },
            _ => Err(missing_contract("duplicate-r detection")),
        },
        other => Err(OperationError::invalid_input(format!(
            "duplicate-r detection expects JSON input or a list value, got {}",
            other.kind().name()
        ))),
    }
}

fn value_to_json(value: &CoreValue) -> OpResult<Value> {
    match value {
        CoreValue::Json(json) => Ok(json.clone()),
        CoreValue::Text(text) => serde_json::from_str(text)
            .map_err(|e| parse_error("signature entry is not valid JSON", e)),
        other => Err(OperationError::invalid_input(format!(
            "signature entries must be JSON objects, got {}",
            other.kind().name()
        ))),
    }
}

fn field_str(value: &Value, key: &str) -> OpResult<String> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| OperationError::invalid_param(key, "expected a hex string value"))
}

fn required_field(object: &serde_json::Map<String, Value>, key: &str) -> OpResult<String> {
    object
        .get(key)
        .ok_or_else(|| {
            OperationError::invalid_input(format!("missing `{key}` field")).with_parameter(key)
        })
        .and_then(|value| field_str(value, key))
}

/// Message preimage for one signature: `msg<suffix>` (raw bytes, hex) or
/// `digest<suffix>` (prehash, hex) — exactly one of the two. An empty suffix
/// selects the singular `message`/`digest` keys.
fn preimage_field(
    object: &serde_json::Map<String, Value>,
    suffix: &str,
) -> OpResult<EcdsaPreimage> {
    let message_key = if suffix.is_empty() {
        "message".to_string()
    } else {
        format!("msg{suffix}")
    };
    let digest_key = if suffix.is_empty() {
        "digest".to_string()
    } else {
        format!("digest{suffix}")
    };
    match (object.get(&message_key), object.get(&digest_key)) {
        (Some(_), Some(_)) => Err(OperationError::invalid_input(format!(
            "provide either `{message_key}` (raw message bytes, hex) or `{digest_key}` (prehashed digest, hex), not both"
        ))),
        (Some(value), None) => Ok(EcdsaPreimage::Message(field_str(value, &message_key)?)),
        (None, Some(value)) => Ok(EcdsaPreimage::Digest(field_str(value, &digest_key)?)),
        (None, None) => Err(OperationError::invalid_input(format!(
            "missing `{message_key}` (raw message bytes, hex) or `{digest_key}` (prehashed digest, hex)"
        ))
        .with_expected("message or digest (hex)")),
    }
}

/// The shared-r convenience: one `r` field applies to both signatures;
/// otherwise `r1`/`r2` are required (and the library re-checks their equality).
fn shared_r_field(object: &serde_json::Map<String, Value>, suffix: &str) -> OpResult<String> {
    if let Some(value) = object.get("r") {
        return field_str(value, "r");
    }
    required_field(object, &format!("r{suffix}"))
}

fn signature_from_entry(entry: &Value, index: usize) -> OpResult<EcdsaAttackSignature> {
    let object = entry.as_object().ok_or_else(|| {
        OperationError::invalid_input(format!(
            "signature #{index} must be a JSON object with message|digest, r, s"
        ))
    })?;
    Ok(EcdsaAttackSignature {
        preimage: preimage_field(object, "")?,
        r_hex: required_field(object, "r")?,
        s_hex: required_field(object, "s")?,
    })
}

fn curve_from_params(params: &ParamMap) -> OpResult<EccCurve> {
    let curve = parse_ecc_curve(params.str_or("curve", "p256"))?;
    match curve {
        EccCurve::P256 | EccCurve::P384 => Ok(curve),
        other => Err(super::wrong_curve("p256 or p384", other.label())
            .with_details("ECDSA attacks are only defined for the NIST curves P-256 and P-384")),
    }
}

fn digest_from_params(params: &ParamMap, curve: EccCurve) -> OpResult<EcdsaDigest> {
    let label = params.str_or("hash", "auto").trim().to_ascii_lowercase();
    match label.as_str() {
        "auto" | "" => match curve {
            EccCurve::P256 => Ok(EcdsaDigest::Sha256),
            EccCurve::P384 => Ok(EcdsaDigest::Sha384),
            _ => Err(super::wrong_curve("p256 or p384", curve.label())
                .with_details("no auto digest exists for this curve")),
        },
        "sha256" => Ok(EcdsaDigest::Sha256),
        "sha384" => Ok(EcdsaDigest::Sha384),
        other => Err(
            OperationError::invalid_param("hash", format!("unknown hash '{other}'"))
                .with_expected("auto, sha256, or sha384")
                .with_actual(other),
        ),
    }
}

fn max_k_from_params(params: &ParamMap) -> OpResult<u64> {
    let raw = params.int_or("max_k", SMALL_K_DEFAULT as i64);
    u64::try_from(raw).map_err(|_| {
        OperationError::invalid_param("max_k", "must be a non-negative integer")
            .with_actual(raw.to_string())
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::attacks::test_support::sign_with_k;
    use super::*;
    use crate::ecc::{generate_ecc_keypair, EccCurve};
    use serde_json::json;

    fn registry() -> OperationRegistry {
        let mut reg = OperationRegistry::new();
        register(&mut reg);
        reg
    }

    const MSG1: &[u8] = b"attack at dawn";
    const MSG2: &[u8] = b"meet at the harbor";

    fn fixture(k: u64) -> (crate::ecc::EccKeyPair, String, String, String, String) {
        let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
        let (r1, s1) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG1,
            k,
        );
        let (_r2, s2) = sign_with_k(
            EccCurve::P256,
            EcdsaDigest::Sha256,
            &keypair.private_hex,
            MSG2,
            k,
        );
        (keypair, r1, s1, s2, crate::keys::to_hex(MSG2))
    }

    #[test]
    fn four_ecdsa_attack_ops_registered_with_metadata_and_aliases() {
        let reg = registry();
        assert_eq!(reg.len(), 4);
        for id in [
            "ecdsa-duplicate-r-detect",
            "ecdsa-nonce-reuse-recover",
            "ecdsa-known-k-recover",
            "ecdsa-small-k-recover",
        ] {
            let op = reg.get(id).unwrap_or_else(|| panic!("{id} not registered"));
            let info = cybercipher_core::registry::operation_info(op);
            assert_eq!(info.category, Category::Analysis);
            assert_eq!(info.cost, CostClass::Interactive);
            assert!(info.tags.contains(&"ecdsa"));
        }
        // Snake-case aliases are searchable.
        let hits = reg.search("ecdsa_nonce_reuse_recover", None);
        assert!(hits
            .iter()
            .any(|(op, _)| op.spec().id == "ecdsa-nonce-reuse-recover"));
    }

    #[test]
    fn registry_nonce_reuse_roundtrip() {
        let reg = registry();
        let (keypair, r, s1, s2, msg2_hex) = fixture(42);
        let mut params = ParamMap::new();
        params.insert("curve", "p256");
        params.insert("hash", "auto");
        params.insert("public_key", keypair.public_uncompressed_hex.as_str());
        let input = CoreValue::Json(json!({
            "msg1": crate::keys::to_hex(MSG1),
            "msg2": msg2_hex,
            "r": r,
            "s1": s1,
            "s2": s2,
        }));
        let out = reg
            .get("ecdsa-nonce-reuse-recover")
            .unwrap()
            .execute(&input, &params, &ExecutionContext::new())
            .unwrap();
        let CoreValue::Json(report) = out else {
            panic!("expected JSON report");
        };
        assert_eq!(report["verified"], json!(true));
        assert_eq!(report["recovered"], json!(true));
        assert_eq!(report["method"], json!("nonce-reuse"));
        assert_eq!(report["private_key_hex"], json!(keypair.private_hex));
    }

    #[test]
    fn registry_detect_accepts_list_value_and_json_text() {
        let reg = registry();
        let (keypair, r, s1, s2, msg2_hex) = fixture(42);
        let mut params = ParamMap::new();
        params.insert("curve", "p256");
        let entry1 = json!({"message": crate::keys::to_hex(MSG1), "r": r, "s": s1});
        let entry2 = json!({"message": msg2_hex, "r": r, "s": s2});
        let out = reg
            .get("ecdsa-duplicate-r-detect")
            .unwrap()
            .execute(
                &CoreValue::List(vec![
                    CoreValue::Json(entry1.clone()),
                    CoreValue::Json(entry2.clone()),
                ]),
                &params,
                &ExecutionContext::new(),
            )
            .unwrap();
        let CoreValue::Json(report) = out else {
            panic!("expected JSON report");
        };
        assert_eq!(report["duplicates_found"], json!(true));
        assert_eq!(report["pairs"].as_array().unwrap().len(), 1);
        // Same result through JSON text input.
        let text = serde_json::to_string(&json!({"signatures": [entry1, entry2]})).unwrap();
        let out = reg
            .get("ecdsa-duplicate-r-detect")
            .unwrap()
            .execute(&CoreValue::Text(text), &params, &ExecutionContext::new())
            .unwrap();
        let CoreValue::Json(report) = out else {
            panic!("expected JSON report");
        };
        assert_eq!(report["duplicates_found"], json!(true));
        assert_eq!(report["total_signatures"], json!(2));
    }

    #[test]
    fn registry_known_k_roundtrip() {
        let reg = registry();
        let (keypair, r, s, _s2, _msg2) = fixture(12345);
        let mut params = ParamMap::new();
        params.insert("curve", "p256");
        params.insert("public_key", keypair.public_compressed_hex.as_str());
        let input = CoreValue::Json(json!({
            "message": crate::keys::to_hex(MSG1),
            "r": r,
            "s": s,
            "k": "3039",
        }));
        let out = reg
            .get("ecdsa-known-k-recover")
            .unwrap()
            .execute(&input, &params, &ExecutionContext::new())
            .unwrap();
        let CoreValue::Json(report) = out else {
            panic!("expected JSON report");
        };
        assert_eq!(report["method"], json!("known-k"));
        assert_eq!(report["private_key_hex"], json!(keypair.private_hex));
        assert_eq!(report["nonce_r_matches"], json!(true));
    }

    #[test]
    fn registry_small_k_reports_candidates_and_honors_max_k() {
        let reg = registry();
        let (keypair, r, s, _s2, _msg2) = fixture(1234);
        let mut params = ParamMap::new();
        params.insert("curve", "p256");
        params.insert("public_key", keypair.public_uncompressed_hex.as_str());
        params.insert("max_k", ParamValue::Int(1234));
        let input = CoreValue::Json(json!({
            "message": crate::keys::to_hex(MSG1),
            "r": r,
            "s": s,
        }));
        let out = reg
            .get("ecdsa-small-k-recover")
            .unwrap()
            .execute(&input, &params, &ExecutionContext::new())
            .unwrap();
        let CoreValue::Json(report) = out else {
            panic!("expected JSON report");
        };
        assert_eq!(report["method"], json!("small-k"));
        assert_eq!(report["candidates_tried"], json!(1234));
        // A tighter bound misses the nonce and must be a typed error.
        params.insert("max_k", ParamValue::Int(1233));
        let error = reg
            .get("ecdsa-small-k-recover")
            .unwrap()
            .execute(&input, &params, &ExecutionContext::new())
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::BudgetExceeded);
    }

    #[test]
    fn registry_recovery_ops_require_the_public_key_param() {
        let reg = registry();
        let (_keypair, r, s1, s2, msg2_hex) = fixture(42);
        let mut params = ParamMap::new();
        params.insert("curve", "p256");
        let input = CoreValue::Json(json!({
            "msg1": crate::keys::to_hex(MSG1),
            "msg2": msg2_hex,
            "r": r,
            "s1": s1,
            "s2": s2,
        }));
        let error = reg
            .get("ecdsa-nonce-reuse-recover")
            .unwrap()
            .execute(&input, &params, &ExecutionContext::new())
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidParam);
    }

    #[test]
    fn registry_rejects_wrong_input_kinds() {
        let reg = registry();
        let error = reg
            .get("ecdsa-nonce-reuse-recover")
            .unwrap()
            .execute(&CoreValue::Null, &ParamMap::new(), &ExecutionContext::new())
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidInput);
        let error = reg
            .get("ecdsa-duplicate-r-detect")
            .unwrap()
            .execute(
                &CoreValue::Integer(1.into()),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidInput);
    }
}
