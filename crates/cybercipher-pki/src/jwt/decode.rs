//! JWT compact-serialization decoding (RFC 7519 section 3, RFC 7515
//! section 7.1): split into exactly three dot-separated base64url segments,
//! strict-decode each, and JSON-parse the JOSE header and payload.
//!
//! Decoding is *structural only* — it never touches a key and never verifies
//! anything. The result carries `verified: false` and every consumer must
//! treat the payload as attacker-controlled data until [`crate::jwt::
//! jwt_verify`] succeeds.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{b64url_decode_strict, MAX_TOKEN_BYTES};
use crate::error::{PkiError, PkiResult};

/// A structurally decoded JWS compact serialization. **Not verified.**
///
/// `verified` is always `false` on values produced by [`jwt_decode`] (the
/// decoder has no key material and performs no cryptographic work); the field
/// exists so the "unverified" state is explicit in the data model, in the
/// JSON reports, and in every UI that renders this struct.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwtDecoded {
    /// Always `false`: decoding never verifies. See the struct docs.
    pub verified: bool,
    /// The decoded JOSE header (guaranteed to be a JSON object with a string
    /// `alg` member — the strictest profile a decoder can check).
    pub header: Value,
    /// The decoded payload (any JSON value; usually a claims object).
    pub payload: Value,
    /// The signature segment, hex-encoded.
    pub signature_hex: String,
    /// The two base64url segments including the middle dot — the exact bytes
    /// (as text) the signature covers.
    pub signing_input: String,
    /// The untouched header segment.
    pub header_b64: String,
    /// The untouched payload segment.
    pub payload_b64: String,
}

/// Decode a JWT/JWS compact serialization: `header.payload.signature`.
///
/// Strictness:
/// - exactly three dot-separated segments (no fewer, no more);
/// - every segment is non-empty and strict unpadded base64url (padding,
///   non-alphabet characters — including `+`, `/`, and NUL bytes — are
///   rejected);
/// - the header segment is a JSON *object* whose `alg` member is a *string*;
/// - the payload segment is any valid JSON;
/// - tokens larger than [`super::MAX_TOKEN_BYTES`] are rejected up front.
///
/// None of this is verification: an attacker-chosen token decodes just as
/// happily as a legitimate one.
pub fn jwt_decode(token: &str) -> PkiResult<JwtDecoded> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Err(PkiError::invalid_input("JWT token is empty")
            .with_expected("header.payload.signature (compact JWS serialization)")
            .with_actual("empty"));
    }
    if trimmed.len() > MAX_TOKEN_BYTES {
        return Err(PkiError::length(
            format!("at most {MAX_TOKEN_BYTES} bytes"),
            format!("{} bytes", trimmed.len()),
            "JWT token exceeds the compact-serialization size bound",
        )
        .with_parameter("token"));
    }

    let segments: Vec<&str> = trimmed.split('.').collect();
    if segments.len() != 3 {
        return Err(PkiError::length(
            "3 dot-separated segments (header.payload.signature)",
            format!("{} segments", segments.len()),
            "JWT compact serialization must have exactly three segments",
        )
        .with_parameter("token"));
    }
    let header_b64 = segments[0];
    let payload_b64 = segments[1];
    let signature_b64 = segments[2];
    for (name, segment) in [
        ("header", header_b64),
        ("payload", payload_b64),
        ("signature", signature_b64),
    ] {
        if segment.is_empty() {
            // An empty signature segment is not merely malformed: it is an
            // unsigned token, which CyberCipher rejects as a policy.
            if name == "signature" {
                return Err(super::reject_unsigned_token());
            }
            return Err(PkiError::invalid_input(format!(
                "JWT {name} segment is empty"
            ))
            .with_parameter("token")
            .with_expected("three non-empty base64url segments"));
        }
    }

    let header_bytes = b64url_decode_strict(header_b64, "header")?;
    let payload_bytes = b64url_decode_strict(payload_b64, "payload")?;
    let signature_bytes = b64url_decode_strict(signature_b64, "signature")?;

    let header: Value = parse_json(&header_bytes, "header")?;
    if !header.is_object() {
        return Err(PkiError::decode("JWT header is not a JSON object")
            .with_parameter("header")
            .with_expected("a JSON object with a string 'alg' member")
            .with_actual(preview_json(&header)));
    }
    let alg = header
        .get("alg")
        .ok_or_else(|| missing_alg())?;
    if !alg.is_string() {
        return Err(PkiError::decode("JWT header 'alg' is not a string")
            .with_parameter("alg")
            .with_expected("a JSON string naming the JWS algorithm")
            .with_actual(preview_json(alg)));
    }

    let payload: Value = parse_json(&payload_bytes, "payload")?;

    Ok(JwtDecoded {
        verified: false,
        header,
        payload,
        signature_hex: crate::keys::to_hex(&signature_bytes),
        signing_input: format!("{header_b64}.{payload_b64}"),
        header_b64: header_b64.to_string(),
        payload_b64: payload_b64.to_string(),
    })
}

fn parse_json(bytes: &[u8], name: &str) -> PkiResult<Value> {
    serde_json::from_slice(bytes)
        .map_err(|e| {
            PkiError::decode(format!("JWT {name} segment is not valid JSON"))
                .with_parameter(name)
                .with_details(e.to_string())
        })
}

fn missing_alg() -> PkiError {
    PkiError::decode("JWT header has no 'alg' member")
        .with_parameter("alg")
        .with_expected("a JSON string naming the JWS algorithm")
        .with_actual("missing")
}

fn preview_json(value: &Value) -> String {
    let rendered = value.to_string();
    crate::keys::preview(&rendered, 48)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The classic jwt.io sample token (HS256, secret `your-256-bit-secret`).
    const JWT_IO_SAMPLE: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    /// RFC 7515 A.2 RS256 example (compact serialization, one line).
    const RFC7515_A2_TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

    #[test]
    fn decode_jwt_io_sample_exact_values() {
        let decoded = jwt_decode(JWT_IO_SAMPLE).unwrap();
        assert!(!decoded.verified, "decode must never claim verification");
        assert_eq!(
            decoded.header,
            json!({"alg": "HS256", "typ": "JWT"}),
            "header exact values"
        );
        assert_eq!(
            decoded.payload,
            json!({"sub": "1234567890", "name": "John Doe", "iat": 1516239022}),
            "payload exact values"
        );
        assert_eq!(decoded.signature_hex, "49f94ac7044948c78a285d904f87f0a4c7897f7e8f3a4eb2255fda750b2cc397");
        assert_eq!(decoded.signing_input, format!("{}.{}", decoded.header_b64, decoded.payload_b64));
        assert_eq!(
            decoded.header_b64,
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        );
        assert_eq!(
            decoded.payload_b64,
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        );
    }

    #[test]
    fn decode_rfc7515_a2_rs256_sample() {
        let decoded = jwt_decode(RFC7515_A2_TOKEN).unwrap();
        assert_eq!(decoded.header, json!({"alg": "RS256"}));
        assert_eq!(decoded.payload["iss"], json!("joe"));
        assert_eq!(decoded.payload["exp"], json!(1300819380));
        assert_eq!(decoded.payload["http://example.com/is_root"], json!(true));
        // 256-byte RSA signature.
        assert_eq!(decoded.signature_hex.len(), 512);
    }

    #[test]
    fn decode_rejects_two_segments() {
        let err = jwt_decode("eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ").unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::LengthMismatch);
        assert!(err.message.contains("exactly three segments"));
    }

    #[test]
    fn decode_rejects_four_segments() {
        let err = jwt_decode("a.b.c.d").unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::LengthMismatch);
        assert!(err.actual.as_deref().unwrap_or_default().contains("4"));
    }

    #[test]
    fn decode_rejects_bad_base64_chars() {
        // '!' is not in the base64url alphabet; '+' and '/' are not URL-safe.
        for bad in ["eyJhbGc!.eyJhIjoxfQ.c2ln", "eyJhbGc+.eyJhIjoxfQ.c2ln", "a.b.c2!n"] {
            let err = jwt_decode(bad).unwrap_err();
            assert_eq!(err.kind, cybercipher_core::ErrorKind::Decode, "{bad}");
            assert!(err.message.contains("base64url"), "{bad}");
        }
    }

    #[test]
    fn decode_rejects_padded_segments() {
        // base64 with '=' padding: valid base64, invalid compact JWS.
        let err = jwt_decode("eyJhbGc=.eyJhIjoxfQ.c2ln").unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Decode);
        assert!(err.message.contains("padding"));
    }

    #[test]
    fn decode_rejects_non_json_payload() {
        // base64url("###") decodes to 3 bytes that are not JSON.
        let err = jwt_decode("eyJhbGciOiJIUzI1NiJ9.IyMj.c2ln").unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Decode);
        assert!(err.message.contains("payload"), "{}", err.message);
        // And a payload that is not even base64url reports the segment too.
        let err = jwt_decode("eyJhbGciOiJIUzI1NiJ9.###.c2ln").unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Decode);
        assert!(err.message.contains("payload"), "{}", err.message);
    }

    #[test]
    fn decode_rejects_non_object_header() {
        // Base64url of "[1,2,3]" — valid JSON, not an object.
        let err = jwt_decode("WzEsMiwzXQ.eyJhIjoxfQ.c2ln").unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Decode);
        assert!(err.message.contains("not a JSON object"));
    }

    #[test]
    fn decode_rejects_missing_alg() {
        // {"typ":"JWT"} without alg.
        let err = jwt_decode("eyJ0eXAiOiJKV1QifQ.eyJhIjoxfQ.c2ln").unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Decode);
        assert!(err.message.contains("no 'alg'"));
    }

    #[test]
    fn decode_rejects_non_string_alg() {
        // {"alg":123} — alg must be a string.
        let err = jwt_decode("eyJhbGciOjEyM30.eyJhIjoxfQ.c2ln").unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Decode);
        assert!(err.message.contains("not a string"));
    }

    #[test]
    fn decode_rejects_empty_and_empty_segments() {
        assert!(jwt_decode("").is_err());
        assert!(jwt_decode("   ").is_err());
        // Literal alg:none token shape with an empty signature segment: the
        // empty-segment structural check fires here (the none-alg policy
        // error fires in jwt_verify).
        let err = jwt_decode("eyJhbGciOiJub25lIn0..").unwrap_err();
        assert!(err.message.contains("empty"), "{}", err.message);
    }

    #[test]
    fn decode_rejects_nul_bytes_in_token() {
        let hostile = "eyJhbGciOiJIUzI1NiJ9\u{0}.eyJhIjoxfQ.c2ln";
        let err = jwt_decode(hostile).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Decode);
    }

    #[test]
    fn decode_deeply_nested_header_is_typed_error_not_panic() {
        // 200-deep nested arrays: serde_json's recursion limit (128) turns
        // this into a typed error instead of a stack overflow.
        let mut header = String::new();
        for _ in 0..200 {
            header.push('[');
        }
        for _ in 0..200 {
            header.push(']');
        }
        use base64ct::Encoding as _;
        let header_b64 = base64ct::Base64UrlUnpadded::encode_string(header.as_bytes());
        let token = format!("{header_b64}.eyJhIjoxfQ.c2ln");
        let result = jwt_decode(&token);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, cybercipher_core::ErrorKind::Decode);
    }

    #[test]
    fn decode_huge_token_is_bounded() {
        let blob = "A".repeat(MAX_TOKEN_BYTES + 1);
        let err = jwt_decode(&blob).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::LengthMismatch);
        assert!(err.message.contains("size bound"));
    }

    #[test]
    fn decoded_serializes_with_verified_false() {
        let decoded = jwt_decode(JWT_IO_SAMPLE).unwrap();
        let json = serde_json::to_value(&decoded).unwrap();
        assert_eq!(json["verified"], serde_json::Value::Bool(false));
    }
}
