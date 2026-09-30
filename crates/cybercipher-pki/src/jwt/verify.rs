//! JWT verification (RFC 7515 section 5.2 + RFC 8725): recompute or check
//! the signature over the signing input with an explicitly selected
//! algorithm, then (optionally) validate the standard claims.
//!
//! Policy enforced here, always:
//! - the JOSE header `alg` must equal the caller-selected algorithm;
//! - `alg: none`, missing `alg`, and empty signatures are policy errors
//!   naming RFC 8725 (never a `valid: false` result — unsigned input is
//!   rejected, not "verified as invalid");
//! - HS* secrets that look like PEM armor are rejected (key confusion);
//! - signature lengths are checked per algorithm before verification;
//! - HS* MAC comparison is constant-time.
//!
//! Error semantics mirror [`crate::ops::sign`]: malformed tokens/keys/params
//! are typed [`PkiError`]s; a well-formed token whose signature or claims do
//! not hold is a normal [`JwtVerified`] with `valid: false` and a `reason`.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

use super::decode::jwt_decode;
use super::{
    alg_mismatch, hmac_secret_bytes, reject_none_alg, JwtAlg, KeyEncoding, SecretEncoding,
};
use crate::ecc::{EccCurve, EcdsaDigest, EcdsaSignatureFormat};
use crate::error::{PkiError, PkiResult};
use crate::keys::{parse_pem, ParsedKey, RsaKeypair, RsaPublicKeyMaterial};
use crate::ops::digest::RsaDigest;

/// Default clock-skew tolerance for temporal claims (seconds).
pub const DEFAULT_LEEWAY_SECS: i64 = 60;

/// Parameters for [`jwt_verify`]. Defaults: UTF-8 secrets, PEM keys, claim
/// validation on, 60 s leeway, no issuer/audience pinning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtVerifyParams {
    /// Shared-secret interpretation for HS* (`utf8` | `hex`).
    pub secret_encoding: SecretEncoding,
    /// Key interpretation for ES*/EdDSA (`pem` | `hex`).
    pub key_encoding: KeyEncoding,
    /// Validate exp/nbf/iat/iss/aud after the signature check (default on).
    pub validate_claims: bool,
    /// Clock-skew tolerance for temporal claims (seconds).
    pub leeway_secs: i64,
    /// Exact-match `iss` check; the claim must be present and equal.
    pub expected_iss: Option<String>,
    /// Exact-match `aud` check (string or array containing the value).
    pub expected_aud: Option<String>,
}

impl Default for JwtVerifyParams {
    fn default() -> Self {
        JwtVerifyParams {
            secret_encoding: SecretEncoding::Utf8,
            key_encoding: KeyEncoding::Pem,
            validate_claims: true,
            leeway_secs: DEFAULT_LEEWAY_SECS,
            expected_iss: None,
            expected_aud: None,
        }
    }
}

impl JwtVerifyParams {
    /// Same as [`Default::default`] (explicit constructor for readability).
    pub fn new() -> Self {
        JwtVerifyParams::default()
    }
}

/// Result of a JWT verification. Only returned for tokens that were
/// structurally decodable and policy-checked (`alg` verified, never `none`).
/// `valid == false` (with a `reason`) covers failed signatures and failed
/// claim validation; malformed input is a typed [`PkiError`] instead.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwtVerified {
    /// Signature **and** (when enabled) claim validation outcome.
    pub valid: bool,
    /// Why verification failed; `None` when `valid` is `true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Algorithm the verification ran with (equals the header `alg`).
    pub alg: JwtAlg,
    /// The decoded JOSE header.
    pub header: Value,
    /// The decoded payload.
    pub payload: Value,
    /// Standard claims actually evaluated (exp/nbf/iat/iss/aud when present
    /// and `validate_claims` is on).
    pub claims_checked: Vec<String>,
    /// Signature bytes, hex-encoded.
    pub signature_hex: String,
    /// The exact signed text (`header.payload`).
    pub signing_input: String,
}

/// Verify a JWT with the given algorithm and key, using the system clock for
/// temporal claims. See [`jwt_verify_at`] for an injectable clock.
pub fn jwt_verify(
    token: &str,
    alg: JwtAlg,
    key: &str,
    params: &JwtVerifyParams,
) -> PkiResult<JwtVerified> {
    jwt_verify_at(token, alg, key, params, system_now_unix()?)
}

/// Verify a JWT with an explicit "now" (Unix seconds) — the injectable-clock
/// entry point used by tests and reproducible tooling.
pub fn jwt_verify_at(
    token: &str,
    alg: JwtAlg,
    key: &str,
    params: &JwtVerifyParams,
    now_unix: i64,
) -> PkiResult<JwtVerified> {
    // Structural decode (also rejects unsigned/empty-signature shapes and
    // guarantees a JSON-object header with a string `alg`).
    let decoded = jwt_decode(token)?;

    // RFC 8725 section 2.1: algorithm verification, in this order —
    // (1) the header alg must not be the none algorithm;
    // (2) the header alg must exactly equal the caller-selected algorithm.
    // (The JOSE alg value is case-sensitive per RFC 7515, so "HS256" and
    // "hs256" are different values; only the exact canonical label matches.)
    let header_alg = decoded
        .header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            PkiError::internal("decoded header invariant violated: string alg guaranteed")
        })?;
    if header_alg.eq_ignore_ascii_case("none") {
        return Err(reject_none_alg(header_alg));
    }
    if header_alg != alg.label() {
        return Err(alg_mismatch(&alg, header_alg));
    }

    let signature = crate::ecc::decode_hex("signature", &decoded.signature_hex)?;
    if signature.is_empty() {
        return Err(super::reject_unsigned_token());
    }

    let base = JwtVerified {
        valid: false,
        reason: None,
        alg,
        header: decoded.header.clone(),
        payload: decoded.payload.clone(),
        claims_checked: Vec::new(),
        signature_hex: decoded.signature_hex.clone(),
        signing_input: decoded.signing_input.clone(),
    };

    // Signature check per family. A failed cryptographic check short-circuits
    // to `valid: false` (claims of an unauthenticated token are not trusted
    // material and are not evaluated).
    let signature_ok = match alg {
        JwtAlg::Hs256 | JwtAlg::Hs384 | JwtAlg::Hs512 => {
            verify_hmac(alg, key, params, &decoded.signing_input, &signature)?
        }
        JwtAlg::Rs256 | JwtAlg::Rs384 | JwtAlg::Rs512 => {
            verify_rsa(alg, key, &decoded.signing_input, &signature)?
        }
        JwtAlg::Es256 | JwtAlg::Es384 => {
            verify_ecdsa(alg, key, params, &decoded.signing_input, &signature)?
        }
        JwtAlg::EdDsa => verify_eddsa(key, params, &decoded.signing_input, &signature)?,
    };
    if !signature_ok {
        return Ok(JwtVerified {
            valid: false,
            reason: Some(format!(
                "signature verification failed for alg {alg} (wrong key or tampered token)"
            )),
            claims_checked: Vec::new(),
            ..base
        });
    }

    let mut verified = JwtVerified {
        valid: true,
        ..base
    };
    if params.validate_claims {
        let outcome = validate_claims(
            &decoded.payload,
            now_unix,
            params.leeway_secs,
            params.expected_iss.as_deref(),
            params.expected_aud.as_deref(),
            &mut verified.claims_checked,
        )?;
        if let Some(reason) = outcome {
            verified.valid = false;
            verified.reason = Some(reason);
        }
    }
    Ok(verified)
}

// ---------------------------------------------------------------------------
// Per-family signature checks (Ok(true) = valid, Ok(false) = invalid, Err =
// malformed input)
// ---------------------------------------------------------------------------

fn verify_hmac(
    alg: JwtAlg,
    key: &str,
    params: &JwtVerifyParams,
    signing_input: &str,
    signature: &[u8],
) -> PkiResult<bool> {
    let secret = hmac_secret_bytes(key, params.secret_encoding)?;
    // Length sanity before the constant-time compare: an HS* JWS signature is
    // exactly the digest output size.
    let expected = alg.mac_size();
    if signature.len() != expected {
        return Err(PkiError::length(
            format!("{expected} bytes ({alg} MAC size)"),
            format!("{} bytes", signature.len()),
            "JWS signature length does not match the HS* algorithm",
        )
        .with_parameter("signature"));
    }
    let computed = hmac_signature(alg, &secret, signing_input.as_bytes())?;
    Ok(constant_time_eq(signature, &computed))
}

fn verify_rsa(alg: JwtAlg, key: &str, signing_input: &str, signature: &[u8]) -> PkiResult<bool> {
    let digest = rsa_digest_for(alg)?;
    let public = rsa_public_from_key_text(key)?;
    let result =
        crate::ops::rsa_verify_pkcs1v15(&public, digest, signing_input.as_bytes(), signature)?;
    // A signature whose length differs from the modulus size already surfaced
    // as a typed error inside rsa_verify_pkcs1v15.
    Ok(result.valid)
}

fn verify_ecdsa(
    alg: JwtAlg,
    key: &str,
    params: &JwtVerifyParams,
    signing_input: &str,
    signature: &[u8],
) -> PkiResult<bool> {
    let curve = alg
        .ecdsa_curve()
        .ok_or_else(|| PkiError::internal("ecdsa dispatch on non-ES alg"))?;
    let digest = match alg {
        JwtAlg::Es256 => EcdsaDigest::Sha256,
        JwtAlg::Es384 => EcdsaDigest::Sha384,
        _ => return Err(PkiError::internal("ecdsa digest dispatch")),
    };
    let material = match params.key_encoding {
        KeyEncoding::Pem => crate::ecc::ecc_public_key_from_spki_pem(key)?,
        KeyEncoding::Hex => crate::ecc::parse_ecc_public_key(curve, key)?,
    };
    if material.curve != curve {
        return Err(wrong_key_curve(curve, material.curve));
    }
    // JWS ES* signatures are raw fixed-width r||s (64 bytes on P-256, 96 on
    // P-384). Check before verification with an algorithm-naming error.
    let expected = alg.fixed_signature_size().unwrap_or(0);
    if signature.len() != expected {
        return Err(PkiError::length(
            format!("{expected} bytes (r||s for {alg})"),
            format!("{} bytes", signature.len()),
            "JWS ES* signature must be the fixed-width r||s encoding",
        )
        .with_parameter("signature"));
    }
    let result = crate::ecc::ecdsa_verify(
        curve,
        &material.public_uncompressed_hex,
        signing_input.as_bytes(),
        digest,
        EcdsaSignatureFormat::Fixed,
        &crate::keys::to_hex(signature),
    )?;
    Ok(result.valid)
}

fn verify_eddsa(
    key: &str,
    params: &JwtVerifyParams,
    signing_input: &str,
    signature: &[u8],
) -> PkiResult<bool> {
    let public_hex = match params.key_encoding {
        KeyEncoding::Pem => {
            let material = crate::ecc::ecc_public_key_from_spki_pem(key)?;
            if material.curve != EccCurve::Ed25519 {
                return Err(wrong_key_curve(EccCurve::Ed25519, material.curve));
            }
            material.public_compressed_hex
        }
        KeyEncoding::Hex => key.trim().to_string(),
    };
    let expected = 64;
    if signature.len() != expected {
        return Err(PkiError::length(
            format!("{expected} bytes (R||S for EdDSA)"),
            format!("{} bytes", signature.len()),
            "JWS EdDSA signature must be 64 bytes",
        )
        .with_parameter("signature"));
    }
    let result = crate::ecc::ed25519_verify(
        &public_hex,
        signing_input.as_bytes(),
        &crate::keys::to_hex(signature),
    )?;
    Ok(result.valid)
}

// ---------------------------------------------------------------------------
// Claims validation (RFC 7519 section 4.1)
// ---------------------------------------------------------------------------

/// Validate exp/nbf/iat/iss/aud. Returns `Ok(Some(reason))` when a claim
/// check fails (a `valid: false` result) and `Err` only for malformed input
/// (non-NumericDate values). Evaluated claim names are appended to
/// `claims_checked`.
fn validate_claims(
    payload: &Value,
    now_unix: i64,
    leeway_secs: i64,
    expected_iss: Option<&str>,
    expected_aud: Option<&str>,
    claims_checked: &mut Vec<String>,
) -> PkiResult<Option<String>> {
    let now = now_unix as f64;
    let leeway = leeway_secs as f64;

    if let Some(exp) = numeric_date(payload, "exp")? {
        claims_checked.push("exp".to_string());
        if now > exp + leeway {
            return Ok(Some(format!(
                "token expired: exp={exp} is older than now={now_unix} (leeway {leeway_secs}s)"
            )));
        }
    }
    if let Some(nbf) = numeric_date(payload, "nbf")? {
        claims_checked.push("nbf".to_string());
        if now < nbf - leeway {
            return Ok(Some(format!(
                "token not yet valid: nbf={nbf} is later than now={now_unix} (leeway {leeway_secs}s)"
            )));
        }
    }
    if let Some(iat) = numeric_date(payload, "iat")? {
        // iat is type-checked as a NumericDate only; issuers clock-skew iat
        // and no RFC 7519 requirement pins it to the verifier's clock.
        claims_checked.push("iat".to_string());
        let _ = iat;
    }
    if let Some(expected) = expected_iss {
        claims_checked.push("iss".to_string());
        match payload.get("iss") {
            Some(Value::String(iss)) if iss == expected => {}
            Some(Value::String(iss)) => {
                return Ok(Some(format!(
                    "issuer mismatch: expected '{expected}', got '{iss}'"
                )))
            }
            other => {
                return Ok(Some(format!(
                    "issuer claim missing or not a string (expected '{expected}', found {})",
                    json_kind(other)
                )))
            }
        }
    }
    if let Some(expected) = expected_aud {
        claims_checked.push("aud".to_string());
        let matches = match payload.get("aud") {
            Some(Value::String(aud)) => aud == expected,
            Some(Value::Array(auds)) => auds.iter().any(|a| a.as_str() == Some(expected)),
            _ => false,
        };
        if !matches {
            return Ok(Some(format!(
                "audience mismatch: expected '{expected}', found {}",
                preview_value(payload.get("aud"))
            )));
        }
    }
    Ok(None)
}

/// Read a NumericDate claim (RFC 7519 section 2: "A JSON numeric value
/// representing the number of seconds ..."). Integers, floats, and huge
/// integral values are accepted; strings/booleans/containers are malformed.
fn numeric_date(payload: &Value, claim: &str) -> PkiResult<Option<f64>> {
    match payload.get(claim) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                Ok(Some(i as f64))
            } else if let Some(f) = n.as_f64() {
                if f.is_finite() {
                    Ok(Some(f))
                } else {
                    Err(malformed_date(claim, "non-finite number"))
                }
            } else {
                Err(malformed_date(
                    claim,
                    "number outside the NumericDate range",
                ))
            }
        }
        Some(other) => Err(malformed_date(claim, &preview_value(Some(other)))),
    }
}

fn malformed_date(claim: &str, actual: &str) -> PkiError {
    PkiError::decode(format!("JWT claim '{claim}' is not a NumericDate"))
        .with_parameter(claim)
        .with_expected("a JSON number (RFC 7519 NumericDate, seconds since epoch)")
        .with_actual(actual)
}

fn json_kind(value: Option<&Value>) -> &'static str {
    match value {
        None => "nothing",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "a boolean",
        Some(Value::Number(_)) => "a number",
        Some(Value::String(_)) => "a string",
        Some(Value::Array(_)) => "an array",
        Some(Value::Object(_)) => "an object",
    }
}

fn preview_value(value: Option<&Value>) -> String {
    match value {
        None => "missing".to_string(),
        Some(v) => crate::keys::preview(&v.to_string(), 48),
    }
}

// ---------------------------------------------------------------------------
// Shared key/time plumbing
// ---------------------------------------------------------------------------

/// System clock as Unix seconds; a pre-epoch clock is an internal error
/// rather than a silently negative "now".
fn system_now_unix() -> PkiResult<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| {
            PkiError::internal("system clock is before the Unix epoch").with_details(e.to_string())
        })
}

/// Constant-time byte-slice equality for MAC comparisons. Length differences
/// short-circuit: JWS signature lengths are public (base64 segment length).
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

macro_rules! hmac_sha {
    ($name:ident, $digest:ty) => {
        fn $name(secret: &[u8], input: &[u8]) -> PkiResult<Vec<u8>> {
            let mut mac = Hmac::<$digest>::new_from_slice(secret).map_err(|e| {
                PkiError::internal("HMAC rejected the secret").with_details(e.to_string())
            })?;
            Mac::update(&mut mac, input);
            Ok(Mac::finalize(mac).into_bytes().as_slice().to_vec())
        }
    };
}

hmac_sha!(hmac_sha256, Sha256);
hmac_sha!(hmac_sha384, Sha384);
hmac_sha!(hmac_sha512, Sha512);

/// HMAC over the signing input for the HS* family; non-HS algorithms are an
/// internal dispatch error. Shared with the signing path.
pub(crate) fn hmac_signature(alg: JwtAlg, secret: &[u8], input: &[u8]) -> PkiResult<Vec<u8>> {
    match alg {
        JwtAlg::Hs256 => hmac_sha256(secret, input),
        JwtAlg::Hs384 => hmac_sha384(secret, input),
        JwtAlg::Hs512 => hmac_sha512(secret, input),
        other => Err(PkiError::internal(format!(
            "hmac dispatch on non-HS alg {other}"
        ))),
    }
}

fn rsa_digest_for(alg: JwtAlg) -> PkiResult<RsaDigest> {
    match alg {
        JwtAlg::Rs256 => Ok(RsaDigest::Sha256),
        JwtAlg::Rs384 => Ok(RsaDigest::Sha384),
        JwtAlg::Rs512 => Ok(RsaDigest::Sha512),
        other => Err(PkiError::internal(format!(
            "rsa digest dispatch on non-RS alg {other}"
        ))),
    }
}

/// RSA key from PEM text for verification: public PEMs are used directly and
/// private PEMs are reduced to their public half.
pub(crate) fn rsa_public_from_key_text(key: &str) -> PkiResult<RsaPublicKeyMaterial> {
    match parse_pem(key)? {
        ParsedKey::Public { material, .. } => Ok(material),
        ParsedKey::Private { keypair, .. } => Ok(keypair.public_material()),
    }
}

/// RSA keypair from a private-key PEM for signing; a public key is a typed
/// error, not a silent failure.
pub(crate) fn rsa_private_from_key_text(key: &str, operation: &str) -> PkiResult<RsaKeypair> {
    match parse_pem(key)? {
        ParsedKey::Private { keypair, .. } => Ok(*keypair),
        ParsedKey::Public { .. } => Err(PkiError::invalid_input(format!(
            "{operation} requires a private key"
        ))
        .with_expected("a private key PEM (PRIVATE KEY or RSA PRIVATE KEY)")
        .with_actual("a public key")),
    }
}

fn wrong_key_curve(expected: EccCurve, actual: EccCurve) -> PkiError {
    PkiError::invalid_input(
        "key curve does not match the JWS algorithm: use the curve the alg is defined for",
    )
    .with_parameter("key")
    .with_expected(expected.label())
    .with_actual(actual.label())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The classic jwt.io sample token: HS256, secret `your-256-bit-secret`.
    const JWT_IO_SAMPLE: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    /// RFC 7515 A.1 HS256 example: key is the oct JWK as raw bytes.
    const RFC7515_A1_TOKEN: &str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const RFC7515_A1_KEY_HEX: &str = "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";

    fn params() -> JwtVerifyParams {
        JwtVerifyParams::new()
    }

    #[test]
    fn verify_jwt_io_sample_with_utf8_secret() {
        let result = jwt_verify(
            JWT_IO_SAMPLE,
            JwtAlg::Hs256,
            "your-256-bit-secret",
            &params(),
        )
        .unwrap();
        assert!(result.valid, "{:?}", result.reason);
        assert_eq!(result.alg, JwtAlg::Hs256);
        assert_eq!(result.payload["name"], json!("John Doe"));
        assert!(result.claims_checked.contains(&"iat".to_string()));
    }

    #[test]
    fn verify_rfc7515_a1_with_hex_secret() {
        let mut p = params();
        p.secret_encoding = SecretEncoding::Hex;
        p.validate_claims = false; // the vector payload is from 2011
        let result = jwt_verify(RFC7515_A1_TOKEN, JwtAlg::Hs256, RFC7515_A1_KEY_HEX, &p).unwrap();
        assert!(result.valid, "{:?}", result.reason);
        // Header JSON contains CRLF + spaces: exact decode still works.
        assert_eq!(result.header["alg"], json!("HS256"));
    }

    #[test]
    fn tampered_payload_rejected() {
        // Same claims except the name is changed: valid JSON, valid base64url,
        // but the signature no longer covers these bytes.
        use base64ct::Encoding as _;
        let tampered_payload = json!({"sub": "1234567890", "name": "John Dore", "iat": 1516239022});
        let payload_b64 = base64ct::Base64UrlUnpadded::encode_string(
            serde_json::to_string(&tampered_payload).unwrap().as_bytes(),
        );
        let tampered = format!(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{payload_b64}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        );
        let result =
            jwt_verify(&tampered, JwtAlg::Hs256, "your-256-bit-secret", &params()).unwrap();
        assert!(!result.valid);
        assert!(
            result
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("signature"),
            "{:?}",
            result.reason
        );
        assert!(
            result.claims_checked.is_empty(),
            "claims of a tampered token are not evaluated"
        );
    }

    #[test]
    fn tampered_signature_rejected() {
        let mut sig = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c".to_string();
        sig.replace_range(0..1, if sig.starts_with('S') { "T" } else { "S" });
        let forged = format!(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.{sig}"
        );
        let result = jwt_verify(&forged, JwtAlg::Hs256, "your-256-bit-secret", &params()).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn literal_none_alg_is_policy_error() {
        // alg:none with a bogus signature segment — still decoded structurally
        // by jwt_decode, but verification must reject it outright.
        let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.c2ln";
        let err = jwt_verify(token, JwtAlg::Hs256, "secret", &params()).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Unsupported);
        assert!(err.message.contains("none"), "{}", err.message);
        assert!(err.details.as_deref().unwrap_or_default().contains("8725"));
    }

    #[test]
    fn none_alg_rejected_for_every_requested_alg() {
        let token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.c2ln";
        for alg in [JwtAlg::Hs256, JwtAlg::Rs256, JwtAlg::Es256, JwtAlg::EdDsa] {
            let err = jwt_verify(token, alg, "k", &params()).unwrap_err();
            assert_eq!(err.kind, cybercipher_core::ErrorKind::Unsupported, "{alg}");
        }
    }

    #[test]
    fn header_alg_param_mismatch_is_typed_error() {
        // Signed as HS256, verified claiming HS384: algorithm verification
        // failure (RFC 8725 2.1), not a failed MAC.
        let err = jwt_verify(
            JWT_IO_SAMPLE,
            JwtAlg::Hs384,
            "your-256-bit-secret",
            &params(),
        )
        .unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidInput);
        assert_eq!(err.expected.as_deref(), Some("HS384"));
        assert_eq!(err.actual.as_deref(), Some("HS256"));
    }

    #[test]
    fn hs_sig_length_mismatch_is_typed_error() {
        // Truncate the 32-byte signature to 16 bytes (still valid base64url).
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpA";
        let err = jwt_verify(token, JwtAlg::Hs256, "your-256-bit-secret", &params()).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::LengthMismatch);
        assert!(err
            .expected
            .as_deref()
            .unwrap_or_default()
            .contains("32 bytes"));
    }

    #[test]
    fn constant_time_eq_functional() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(&[0u8; 32], &[0u8; 31]));
        // All-equal vs one-flipped at every position: length-aware, value-aware.
        let a = [7u8; 32];
        for i in 0..32 {
            let mut b = a;
            b[i] ^= 1;
            assert!(!constant_time_eq(&a, &b), "position {i}");
        }
    }

    #[test]
    fn claim_temporal_validation() {
        let now: i64 = 1_700_000_000;
        let payload = json!({"exp": now - 10, "nbf": now - 100, "iat": now - 500});
        let mut checked = Vec::new();
        // Expired by 10s with default 60s leeway: accepted.
        let outcome = validate_claims(&payload, now, 60, None, None, &mut checked).unwrap();
        assert!(outcome.is_none());
        assert_eq!(checked, vec!["exp", "nbf", "iat"]);
        // Zero leeway: expired.
        let mut checked = Vec::new();
        let outcome = validate_claims(&payload, now, 0, None, None, &mut checked).unwrap();
        assert!(outcome.as_deref().unwrap_or_default().contains("expired"));
        // Large leeway accepts a far-past exp.
        let mut checked = Vec::new();
        let outcome = validate_claims(&payload, now, 10_000_000, None, None, &mut checked).unwrap();
        assert!(outcome.is_none());
        // Future nbf rejected.
        let payload = json!({"nbf": now + 3600});
        let mut checked = Vec::new();
        let outcome = validate_claims(&payload, now, 60, None, None, &mut checked).unwrap();
        assert!(outcome
            .as_deref()
            .unwrap_or_default()
            .contains("not yet valid"));
    }

    #[test]
    fn malformed_numeric_date_is_typed_error() {
        let payload = json!({"exp": "1516239022"});
        let mut checked = Vec::new();
        let err = validate_claims(&payload, 0, 60, None, None, &mut checked).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Decode);
        assert_eq!(err.parameter.as_deref(), Some("exp"));
        for bad in [
            json!({"exp": true}),
            json!({"exp": [1]}),
            json!({"exp": {"a": 1}}),
        ] {
            let mut checked = Vec::new();
            assert!(validate_claims(&bad, 0, 60, None, None, &mut checked).is_err());
        }
        // Missing claims are simply not validated.
        let mut checked = Vec::new();
        let outcome = validate_claims(&json!({}), 0, 60, None, None, &mut checked).unwrap();
        assert!(outcome.is_none());
        assert!(checked.is_empty());
    }

    #[test]
    fn iss_and_aud_exact_match() {
        let payload = json!({"iss": "issuer-1", "aud": ["a", "b"]});
        let mut checked = Vec::new();
        let outcome =
            validate_claims(&payload, 0, 60, Some("issuer-1"), Some("b"), &mut checked).unwrap();
        assert!(outcome.is_none());
        let mut checked = Vec::new();
        let outcome =
            validate_claims(&payload, 0, 60, Some("issuer-2"), Some("c"), &mut checked).unwrap();
        assert!(outcome.is_some());
        // aud as a plain string also matches.
        let payload = json!({"aud": "mobile-app"});
        let mut checked = Vec::new();
        let outcome =
            validate_claims(&payload, 0, 60, None, Some("mobile-app"), &mut checked).unwrap();
        assert!(outcome.is_none());
        // Missing iss claim with expected_iss set fails validation.
        let mut checked = Vec::new();
        let outcome =
            validate_claims(&json!({}), 0, 60, Some("issuer-1"), None, &mut checked).unwrap();
        assert!(outcome.is_some());
    }

    #[test]
    fn tampered_header_rejected() {
        // Same alg but a different header: the signature no longer covers the
        // new signing input, so the MAC check fails.
        let other_header = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImsxIn0"; // {"alg":"HS256","kid":"k1"}
        let tampered =
            format!("{other_header}.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
        let result =
            jwt_verify(&tampered, JwtAlg::Hs256, "your-256-bit-secret", &params()).unwrap();
        assert!(!result.valid);
        // Changing the header alg instead is an algorithm-verification error.
        let swapped = format!(
            "{}.{}.{}",
            "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9", // {"alg":"HS512","typ":"JWT"}
            "eyJzdWIiOiIxIn0",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        );
        let err =
            jwt_verify(&swapped, JwtAlg::Hs256, "your-256-bit-secret", &params()).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidInput);
        assert_eq!(err.actual.as_deref(), Some("HS512"));
    }

    #[test]
    fn alg_swap_hs_signed_rs_claimed_rejected() {
        // Sign with HS256 + a shared secret, then claim RS256 verification:
        // algorithm verification must fail before any RSA work.
        let token = crate::jwt::jwt_sign(
            json!({"sub": "victim"}),
            Value::Null,
            JwtAlg::Hs256,
            "attacker-controlled-secret",
            &crate::jwt::JwtSignParams::default(),
        )
        .unwrap();
        let err = jwt_verify(&token, JwtAlg::Rs256, "unused", &params()).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidInput);
        assert_eq!(err.expected.as_deref(), Some("RS256"));
        assert_eq!(err.actual.as_deref(), Some("HS256"));
    }

    #[test]
    fn unsigned_token_rejected_with_policy_error() {
        // Empty signature segment: the token protects nothing.
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.";
        let err = jwt_verify(token, JwtAlg::Hs256, "k", &params()).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Unsupported);
        assert!(err.details.as_deref().unwrap_or_default().contains("8725"));
    }

    #[test]
    fn hs_pem_looking_secret_is_confusion_error() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----";
        let err = jwt_verify(JWT_IO_SAMPLE, JwtAlg::Hs256, pem, &params()).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::KeyError);
        assert!(err.message.contains("PEM"), "{}", err.message);
    }

    #[test]
    fn hs384_hs512_roundtrip_with_hex_secret() {
        for alg in [JwtAlg::Hs384, JwtAlg::Hs512] {
            let sp = crate::jwt::JwtSignParams {
                secret_encoding: SecretEncoding::Hex,
                ..crate::jwt::JwtSignParams::default()
            };
            let token = crate::jwt::jwt_sign(
                json!({"sub": "hex"}),
                Value::Null,
                alg,
                "00ffa1b2c3d4e5f6",
                &sp,
            )
            .unwrap();
            let mut vp = params();
            vp.secret_encoding = SecretEncoding::Hex;
            let verified = jwt_verify(&token, alg, "00ffa1b2c3d4e5f6", &vp).unwrap();
            assert!(verified.valid, "{alg}: {:?}", verified.reason);
            // The MAC length sanity check: truncating the signature b64
            // either breaks base64 canonicity (Decode) or shortens the MAC
            // below the digest size (LengthMismatch) — both are typed
            // errors, never a "valid" token and never a panic.
            let truncated = &token[..token.len() - 4];
            let err = jwt_verify(truncated, alg, "00ffa1b2c3d4e5f6", &vp).unwrap_err();
            assert!(
                matches!(
                    err.kind,
                    cybercipher_core::ErrorKind::Decode
                        | cybercipher_core::ErrorKind::LengthMismatch
                ),
                "{alg}: {err:?}"
            );
        }
    }

    #[test]
    fn exp_nbf_via_verify_with_injected_clock() {
        let now: i64 = 1_700_000_000;
        let make = |claims: Value| {
            crate::jwt::jwt_sign(
                claims,
                Value::Null,
                JwtAlg::Hs256,
                "clock-secret",
                &crate::jwt::JwtSignParams::default(),
            )
            .unwrap()
        };
        // exp 100s in the past, default 60s leeway -> expired.
        let expired = make(json!({"exp": now - 100, "iat": now - 200}));
        let result =
            jwt_verify_at(&expired, JwtAlg::Hs256, "clock-secret", &params(), now).unwrap();
        assert!(!result.valid);
        assert!(result
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("expired"));
        assert!(result.claims_checked.contains(&"exp".to_string()));
        // Same token, large leeway -> accepted.
        let mut lenient = params();
        lenient.leeway_secs = 1000;
        let result = jwt_verify_at(&expired, JwtAlg::Hs256, "clock-secret", &lenient, now).unwrap();
        assert!(result.valid, "{:?}", result.reason);
        // validate_claims off -> temporal claims ignored entirely.
        let mut no_claims = params();
        no_claims.validate_claims = false;
        let result =
            jwt_verify_at(&expired, JwtAlg::Hs256, "clock-secret", &no_claims, now).unwrap();
        assert!(result.valid);
        assert!(result.claims_checked.is_empty());
        // Future nbf -> not yet valid.
        let early = make(json!({"nbf": now + 3600, "exp": now + 7200}));
        let result = jwt_verify_at(&early, JwtAlg::Hs256, "clock-secret", &params(), now).unwrap();
        assert!(!result.valid);
        assert!(result
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("not yet valid"));
        // Leeway covers small nbf skew.
        let mut skewed = params();
        skewed.leeway_secs = 7200;
        let result = jwt_verify_at(&early, JwtAlg::Hs256, "clock-secret", &skewed, now).unwrap();
        assert!(result.valid, "{:?}", result.reason);
    }

    #[test]
    fn iss_aud_via_verify() {
        let now: i64 = 1_700_000_000;
        let token = crate::jwt::jwt_sign(
            json!({"iss": "https://auth.example.test", "aud": ["api", "admin"], "exp": now + 100}),
            Value::Null,
            JwtAlg::Hs256,
            "iss-secret",
            &crate::jwt::JwtSignParams::default(),
        )
        .unwrap();
        // Matching iss + aud (array member) passes.
        let mut p = params();
        p.expected_iss = Some("https://auth.example.test".to_string());
        p.expected_aud = Some("api".to_string());
        let result = jwt_verify_at(&token, JwtAlg::Hs256, "iss-secret", &p, now).unwrap();
        assert!(result.valid, "{:?}", result.reason);
        // Wrong iss fails.
        p.expected_iss = Some("https://evil.example.test".to_string());
        let result = jwt_verify_at(&token, JwtAlg::Hs256, "iss-secret", &p, now).unwrap();
        assert!(!result.valid);
        assert!(result
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("issuer"));
        // Wrong aud fails.
        p.expected_iss = Some("https://auth.example.test".to_string());
        p.expected_aud = Some("other".to_string());
        let result = jwt_verify_at(&token, JwtAlg::Hs256, "iss-secret", &p, now).unwrap();
        assert!(!result.valid);
        assert!(result
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("audience"));
    }

    #[test]
    fn malformed_exp_claim_surfaces_as_typed_error() {
        let now: i64 = 1_700_000_000;
        let token = crate::jwt::jwt_sign(
            json!({"exp": "1700000100"}),
            Value::Null,
            JwtAlg::Hs256,
            "k",
            &crate::jwt::JwtSignParams::default(),
        )
        .unwrap();
        let err = jwt_verify_at(&token, JwtAlg::Hs256, "k", &params(), now).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Decode);
        assert_eq!(err.parameter.as_deref(), Some("exp"));
    }

    #[test]
    fn rs_sig_length_must_equal_modulus() {
        use base64ct::Encoding as _;
        let keypair = crate::keys::generate_rsa_keypair(2048, "010001").unwrap();
        let public_pem = keypair.to_public_spki_pem().unwrap();
        // 128 bytes: valid base64url but half the 256-byte modulus size.
        let short_sig = base64ct::Base64UrlUnpadded::encode_string(&[0xABu8; 128]);
        let token = format!("eyJhbGciOiJSUzI1NiJ9.eyJhIjoxfQ.{short_sig}");
        let err = jwt_verify(&token, JwtAlg::Rs256, &public_pem, &params()).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::LengthMismatch);
        assert!(
            err.expected
                .as_deref()
                .unwrap_or_default()
                .contains("modulus"),
            "{:?}",
            err.expected
        );
    }

    #[test]
    fn es_sig_length_typed_error_names_expected_size() {
        use base64ct::Encoding as _;
        let mut vp = params();
        vp.key_encoding = KeyEncoding::Hex;
        for (alg, curve, wrong_len, expected) in [
            (
                JwtAlg::Es256,
                crate::ecc::EccCurve::P256,
                65usize,
                "64 bytes",
            ),
            (JwtAlg::Es384, crate::ecc::EccCurve::P384, 95, "96 bytes"),
        ] {
            let kp = crate::ecc::generate_ecc_keypair(curve).unwrap();
            let bad_sig = base64ct::Base64UrlUnpadded::encode_string(&vec![0x11u8; wrong_len]);
            let header = match alg {
                JwtAlg::Es256 => "eyJhbGciOiJFUzI1NiJ9",
                _ => "eyJhbGciOiJFUzM4NCJ9",
            };
            let token = format!("{header}.eyJhIjoxfQ.{bad_sig}");
            let err = jwt_verify(&token, alg, &kp.public_uncompressed_hex, &vp).unwrap_err();
            assert_eq!(
                err.kind,
                cybercipher_core::ErrorKind::LengthMismatch,
                "{alg}"
            );
            let expected_msg = format!("{expected} (r||s for {alg})");
            assert_eq!(
                err.expected.as_deref(),
                Some(expected_msg.as_str()),
                "{alg}"
            );
        }
    }

    #[test]
    fn eddsa_sig_length_typed_error() {
        use base64ct::Encoding as _;
        let kp = crate::ecc::generate_ecc_keypair(crate::ecc::EccCurve::Ed25519).unwrap();
        let mut vp = params();
        vp.key_encoding = KeyEncoding::Hex;
        let short = base64ct::Base64UrlUnpadded::encode_string(&[0x22u8; 63]);
        let token = format!("eyJhbGciOiJFZERTQSJ9.eyJhIjoxfQ.{short}");
        let err = jwt_verify(&token, JwtAlg::EdDsa, &kp.public_compressed_hex, &vp).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::LengthMismatch);
        assert_eq!(err.expected.as_deref(), Some("64 bytes (R||S for EdDSA)"));
    }

    #[test]
    fn verify_accepts_private_pem_and_reduces_to_public_half() {
        let keypair = crate::keys::generate_rsa_keypair(2048, "010001").unwrap();
        let private_pem = keypair.to_pkcs8_pem().unwrap();
        let token = crate::jwt::jwt_sign(
            json!({"sub": "pem-reduce"}),
            Value::Null,
            JwtAlg::Rs256,
            &private_pem,
            &crate::jwt::JwtSignParams::default(),
        )
        .unwrap();
        // Verifying with the *private* PEM works: it carries the public half.
        let result = jwt_verify(&token, JwtAlg::Rs256, &private_pem, &params()).unwrap();
        assert!(result.valid, "{:?}", result.reason);
    }
}
