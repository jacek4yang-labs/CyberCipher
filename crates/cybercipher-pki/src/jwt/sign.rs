//! JWT creation (RFC 7515 section 7.1): canonical JOSE header, compact
//! serialization, and signing with the same algorithm set as
//! [`crate::jwt::jwt_verify`].
//!
//! - The header is exactly `{"alg": <alg>, "typ": "JWT"}` plus caller
//!   extras — CyberCipher invents no other fields. Extras may override
//!   `typ` but never `alg` (the header algorithm must be the algorithm the
//!   token is actually signed with).
//! - Base64url is unpadded; JSON is serde_json's compact form (BTreeMap
//!   ordering, so the header is deterministic for a given extras map).
//! - ECDSA uses the RFC 6979 deterministic-nonce path of
//!   [`crate::ecc::ecdsa_sign`] (the crate default), so signing the same
//!   claims twice produces the same token.

use serde_json::Value;

use super::{b64url_encode, hmac_secret_bytes, JwtAlg, KeyEncoding, SecretEncoding};
use crate::ecc::{ecdsa_sign, EcdsaDigest, EcdsaNonceMode, EcdsaSignatureFormat};
use crate::error::{PkiError, PkiResult};
use crate::ops::rsa_sign_pkcs1v15;

/// Parameters for [`jwt_sign`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JwtSignParams {
    /// Shared-secret interpretation for HS* (`utf8` | `hex`).
    pub secret_encoding: SecretEncoding,
    /// Key interpretation for ES*/EdDSA (`pem` | `hex`).
    pub key_encoding: KeyEncoding,
}

/// Create a signed compact JWS: `header.payload.signature` with the given
/// claims and algorithm. `header_extra` must be a JSON object (or `null`)
/// whose members are merged into the canonical header after `alg`/`typ`.
///
/// Key expectations per family (typed errors otherwise):
/// - HS*: shared secret (`secret_encoding` utf8|hex; PEM-looking secrets are
///   rejected);
/// - RS*: private key PEM (`PRIVATE KEY` / `RSA PRIVATE KEY`);
/// - ES*: private key PKCS#8 PEM or hex scalar (`key_encoding`);
/// - EdDSA: private key PKCS#8 PEM or 32-byte hex seed (`key_encoding`).
pub fn jwt_sign(
    claims: Value,
    header_extra: Value,
    alg: JwtAlg,
    key: &str,
    params: &JwtSignParams,
) -> PkiResult<String> {
    if !claims.is_object() {
        return Err(
            PkiError::invalid_input("JWT payload (claims) must be a JSON object")
                .with_expected("a JSON object of claims")
                .with_actual(preview(&claims)),
        );
    }

    let mut header = serde_json::Map::new();
    header.insert("alg".to_string(), Value::String(alg.label().to_string()));
    header.insert("typ".to_string(), Value::String("JWT".to_string()));
    match &header_extra {
        Value::Null => {}
        Value::Object(extra) => {
            for (member, value) in extra {
                if member == "alg" {
                    return Err(PkiError::invalid_param(
                        "header_extra",
                        "header_extra cannot override 'alg': the header algorithm must equal the algorithm this function signs with",
                    )
                    .with_expected("extras without an 'alg' member")
                    .with_actual(preview(value)));
                }
                header.insert(member.clone(), value.clone());
            }
        }
        other => {
            return Err(PkiError::invalid_param(
                "header_extra",
                "header_extra must be a JSON object of JOSE header members (or null)",
            )
            .with_expected("a JSON object")
            .with_actual(preview(other)));
        }
    }

    let header_json = serde_json::to_string(&Value::Object(header)).map_err(|e| {
        PkiError::internal("JOSE header serialization failed").with_details(e.to_string())
    })?;
    let claims_json = serde_json::to_string(&claims).map_err(|e| {
        PkiError::internal("claims serialization failed").with_details(e.to_string())
    })?;
    let header_b64 = b64url_encode(header_json.as_bytes());
    let payload_b64 = b64url_encode(claims_json.as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");

    let signature = match alg {
        JwtAlg::Hs256 | JwtAlg::Hs384 | JwtAlg::Hs512 => {
            let secret = hmac_secret_bytes(key, params.secret_encoding)?;
            super::verify::hmac_signature(alg, &secret, signing_input.as_bytes())?
        }
        JwtAlg::Rs256 | JwtAlg::Rs384 | JwtAlg::Rs512 => {
            let digest = match alg {
                JwtAlg::Rs256 => crate::ops::RsaDigest::Sha256,
                JwtAlg::Rs384 => crate::ops::RsaDigest::Sha384,
                _ => crate::ops::RsaDigest::Sha512,
            };
            let keypair = super::verify::rsa_private_from_key_text(key, "JWT signing")?;
            rsa_sign_pkcs1v15(&keypair.material(), digest, signing_input.as_bytes())?
        }
        JwtAlg::Es256 | JwtAlg::Es384 => {
            let curve = alg
                .ecdsa_curve()
                .ok_or_else(|| PkiError::internal("ecdsa dispatch on non-ES alg"))?;
            let digest = match alg {
                JwtAlg::Es256 => EcdsaDigest::Sha256,
                _ => EcdsaDigest::Sha384,
            };
            let private_hex = ec_private_hex(key, params.key_encoding, curve)?;
            // RFC 6979 deterministic nonce, fixed-width r||s output: the
            // exact encoding JWS carries. ecdsa_sign returns hex; the JWS
            // layer wants raw bytes.
            let fixed_hex = ecdsa_sign(
                curve,
                &private_hex,
                signing_input.as_bytes(),
                digest,
                EcdsaNonceMode::Deterministic,
                EcdsaSignatureFormat::Fixed,
            )?;
            crate::ecc::decode_hex("signature", &fixed_hex)?
        }
        JwtAlg::EdDsa => {
            let private_hex = ed_private_hex(key, params.key_encoding)?;
            let sig_hex = crate::ecc::ed25519_sign(&private_hex, signing_input.as_bytes())?;
            crate::ecc::decode_hex("signature", &sig_hex)?
        }
    };

    let signature_b64 = b64url_encode(&signature);
    Ok(format!("{signing_input}.{signature_b64}"))
}

/// EC private-key material for ES* signing: PKCS#8 PEM (curve-verified) or a
/// fixed-width hex scalar (validated by the ECDSA layer).
fn ec_private_hex(
    key: &str,
    encoding: KeyEncoding,
    curve: crate::ecc::EccCurve,
) -> PkiResult<String> {
    match encoding {
        KeyEncoding::Pem => {
            let keypair = crate::ecc::ecc_private_key_from_pkcs8_pem(key)?;
            if keypair.curve != curve {
                return Err(key_curve_mismatch(curve, keypair.curve));
            }
            Ok(keypair.private_hex)
        }
        KeyEncoding::Hex => Ok(key.trim().to_string()),
    }
}

/// Ed25519 private-key material for EdDSA signing: PKCS#8 PEM (curve-checked)
/// or the raw 32-byte seed as hex.
fn ed_private_hex(key: &str, encoding: KeyEncoding) -> PkiResult<String> {
    match encoding {
        KeyEncoding::Pem => {
            let keypair = crate::ecc::ecc_private_key_from_pkcs8_pem(key)?;
            if keypair.curve != crate::ecc::EccCurve::Ed25519 {
                return Err(key_curve_mismatch(
                    crate::ecc::EccCurve::Ed25519,
                    keypair.curve,
                ));
            }
            Ok(keypair.private_hex)
        }
        KeyEncoding::Hex => Ok(key.trim().to_string()),
    }
}

fn key_curve_mismatch(expected: crate::ecc::EccCurve, actual: crate::ecc::EccCurve) -> PkiError {
    PkiError::invalid_input(
        "key curve does not match the JWS algorithm: use the curve the alg is defined for",
    )
    .with_parameter("key")
    .with_expected(expected.label())
    .with_actual(actual.label())
}

fn preview(value: &Value) -> String {
    crate::keys::preview(&value.to_string(), 48)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc::{
        ecc_private_key_to_pkcs8_pem, ecc_public_key_to_spki_pem, generate_ecc_keypair, EccCurve,
    };
    use crate::jwt::{jwt_decode, jwt_verify, JwtVerifyParams};
    use crate::keys::generate_rsa_keypair;
    use serde_json::json;

    fn claims() -> Value {
        json!({"sub": "1234567890", "name": "John Doe", "admin": true})
    }

    fn params() -> JwtSignParams {
        JwtSignParams::default()
    }

    #[test]
    fn header_is_canonical_alg_typ_only() {
        let token = jwt_sign(claims(), Value::Null, JwtAlg::Hs256, "k", &params()).unwrap();
        let decoded = jwt_decode(&token).unwrap();
        assert_eq!(decoded.header, json!({"alg": "HS256", "typ": "JWT"}));
    }

    #[test]
    fn header_extra_merges_and_cannot_override_alg() {
        let token = jwt_sign(
            claims(),
            json!({"kid": "key-1", "typ": "JOSE", "crit": ["url"]}),
            JwtAlg::Hs256,
            "k",
            &params(),
        )
        .unwrap();
        let decoded = jwt_decode(&token).unwrap();
        assert_eq!(
            decoded.header,
            json!({"alg": "HS256", "crit": ["url"], "kid": "key-1", "typ": "JOSE"})
        );

        let err = jwt_sign(
            claims(),
            json!({"alg": "RS256"}),
            JwtAlg::Hs256,
            "k",
            &params(),
        )
        .unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidParam);
        assert_eq!(err.parameter.as_deref(), Some("header_extra"));
    }

    #[test]
    fn non_object_claims_rejected() {
        for bad in [json!([1, 2]), json!("str"), json!(42)] {
            let err = jwt_sign(bad, Value::Null, JwtAlg::Hs256, "k", &params()).unwrap_err();
            assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidInput);
        }
        // Non-object (non-null) header_extra also rejected.
        let err = jwt_sign(claims(), json!("oops"), JwtAlg::Hs256, "k", &params()).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidParam);
    }

    #[test]
    fn hs256_sign_verify_roundtrip_both_secret_encodings() {
        for (secret, encoding) in [
            ("your-256-bit-secret", SecretEncoding::Utf8),
            ("deadbeefcafebabe0123456789", SecretEncoding::Hex),
        ] {
            let mut sp = params();
            sp.secret_encoding = encoding;
            let token = jwt_sign(claims(), Value::Null, JwtAlg::Hs256, secret, &sp).unwrap();
            let mut vp = JwtVerifyParams::new();
            vp.secret_encoding = encoding;
            let verified = jwt_verify(&token, JwtAlg::Hs256, secret, &vp).unwrap();
            assert!(verified.valid, "{encoding:?}: {:?}", verified.reason);
            assert_eq!(verified.payload, claims());
        }
    }

    #[test]
    fn hs_deterministic_and_alg_separation() {
        let a = jwt_sign(claims(), Value::Null, JwtAlg::Hs384, "s", &params()).unwrap();
        let b = jwt_sign(claims(), Value::Null, JwtAlg::Hs384, "s", &params()).unwrap();
        assert_eq!(a, b, "HMAC signing is deterministic");
        // Different alg -> different header -> different token.
        let c = jwt_sign(claims(), Value::Null, JwtAlg::Hs512, "s", &params()).unwrap();
        assert_ne!(a, c);
        // HS384 token must not verify as HS512.
        let err = jwt_verify(&a, JwtAlg::Hs512, "s", &JwtVerifyParams::new()).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidInput);
    }

    #[test]
    fn rsa_all_digests_roundtrip() {
        let keypair = generate_rsa_keypair(2048, "010001").unwrap();
        let private_pem = keypair.to_pkcs1_pem().unwrap();
        let public_pem = keypair.to_public_spki_pem().unwrap();
        for alg in [JwtAlg::Rs256, JwtAlg::Rs384, JwtAlg::Rs512] {
            let token = jwt_sign(claims(), Value::Null, alg, &private_pem, &params()).unwrap();
            let verified = jwt_verify(&token, alg, &public_pem, &JwtVerifyParams::new()).unwrap();
            assert!(verified.valid, "{alg}: {:?}", verified.reason);
        }
    }

    #[test]
    fn rsa_signing_with_public_key_rejected() {
        let keypair = generate_rsa_keypair(2048, "010001").unwrap();
        let public_pem = keypair.to_public_spki_pem().unwrap();
        let err =
            jwt_sign(claims(), Value::Null, JwtAlg::Rs256, &public_pem, &params()).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidInput);
        assert!(err.message.contains("private key"));
    }

    #[test]
    fn ec_all_curves_roundtrip_pem_and_hex() {
        for (alg, curve) in [
            (JwtAlg::Es256, EccCurve::P256),
            (JwtAlg::Es384, EccCurve::P384),
        ] {
            let keypair = generate_ecc_keypair(curve).unwrap();
            let private_pem = ecc_private_key_to_pkcs8_pem(curve, &keypair.private_hex).unwrap();
            let public_pem =
                ecc_public_key_to_spki_pem(curve, &keypair.public_uncompressed_hex).unwrap();

            let token_pem = jwt_sign(claims(), Value::Null, alg, &private_pem, &params()).unwrap();
            let verified =
                jwt_verify(&token_pem, alg, &public_pem, &JwtVerifyParams::new()).unwrap();
            assert!(verified.valid, "{alg} pem: {:?}", verified.reason);

            let mut hex_params = params();
            hex_params.key_encoding = KeyEncoding::Hex;
            let token_hex = jwt_sign(
                claims(),
                Value::Null,
                alg,
                &keypair.private_hex,
                &hex_params,
            )
            .unwrap();
            let mut vp = JwtVerifyParams::new();
            vp.key_encoding = KeyEncoding::Hex;
            let verified =
                jwt_verify(&token_hex, alg, &keypair.public_uncompressed_hex, &vp).unwrap();
            assert!(verified.valid, "{alg} hex: {:?}", verified.reason);

            // Deterministic (RFC 6979): same claims -> same token.
            assert_eq!(
                token_hex,
                jwt_sign(
                    claims(),
                    Value::Null,
                    alg,
                    &keypair.private_hex,
                    &hex_params
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn ec_curve_confusion_rejected() {
        // A P-384 key must not sign an ES256 token.
        let keypair = generate_ecc_keypair(EccCurve::P384).unwrap();
        let private_pem =
            ecc_private_key_to_pkcs8_pem(EccCurve::P384, &keypair.private_hex).unwrap();
        let err = jwt_sign(
            claims(),
            Value::Null,
            JwtAlg::Es256,
            &private_pem,
            &params(),
        )
        .unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidInput);
    }

    #[test]
    fn eddsa_roundtrip_pem_and_hex() {
        let keypair = generate_ecc_keypair(EccCurve::Ed25519).unwrap();
        let private_pem =
            ecc_private_key_to_pkcs8_pem(EccCurve::Ed25519, &keypair.private_hex).unwrap();
        let public_pem =
            ecc_public_key_to_spki_pem(EccCurve::Ed25519, &keypair.public_uncompressed_hex)
                .unwrap();

        let token_pem = jwt_sign(
            claims(),
            Value::Null,
            JwtAlg::EdDsa,
            &private_pem,
            &params(),
        )
        .unwrap();
        let verified = jwt_verify(
            &token_pem,
            JwtAlg::EdDsa,
            &public_pem,
            &JwtVerifyParams::new(),
        )
        .unwrap();
        assert!(verified.valid, "{:?}", verified.reason);

        let mut hex_params = params();
        hex_params.key_encoding = KeyEncoding::Hex;
        let token_hex = jwt_sign(
            claims(),
            Value::Null,
            JwtAlg::EdDsa,
            &keypair.private_hex,
            &hex_params,
        )
        .unwrap();
        let mut vp = JwtVerifyParams::new();
        vp.key_encoding = KeyEncoding::Hex;
        let verified = jwt_verify(
            &token_hex,
            JwtAlg::EdDsa,
            &keypair.public_compressed_hex,
            &vp,
        )
        .unwrap();
        assert!(verified.valid, "{:?}", verified.reason);
        // Ed25519 is deterministic by construction: PEM path and hex path of
        // the same key produce the same signature.
        assert_eq!(token_pem, token_hex);
    }

    #[test]
    fn no_invented_fields_and_unpadded_output() {
        let token = jwt_sign(json!({"a": 1}), Value::Null, JwtAlg::Hs256, "s", &params()).unwrap();
        assert!(
            !token.contains('='),
            "JWS base64url segments must be unpadded"
        );
        assert_eq!(token.split('.').count(), 3);
        let decoded = jwt_decode(&token).unwrap();
        // Header has exactly alg + typ: no kid/jku/x5c invented server-side.
        assert_eq!(decoded.header.as_object().unwrap().len(), 2);
        assert_eq!(decoded.payload, json!({"a": 1}));
    }
}
