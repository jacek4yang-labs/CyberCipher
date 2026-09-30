//! JWT end-to-end acceptance tests (M8-PKI-F-JWT): external RFC 7515 vectors
//! verified through the public API, and JWK interop — generated keys round
//! tripping through `keys::jwk` into token verification.

#![allow(clippy::result_large_err)]

use cybercipher_pki::ecc::{
    ecc_private_key_to_pkcs8_pem, ecc_public_key_to_spki_pem, generate_ecc_keypair, EccCurve,
};
use cybercipher_pki::jwt::{
    jwt_decode, jwt_sign, jwt_verify, jwt_verify_at, JwtAlg, JwtSignParams, JwtVerifyParams,
    KeyEncoding,
};
use cybercipher_pki::keys::{
    ecc_jwk_to_public_material, ecc_keypair_to_jwk, jwk_to_public_material, parse_ecc_jwk, RsaJwk,
};
use serde_json::json;

/// Far-future exp so claim validation passes on generated tokens.
const FUTURE_EXP: i64 = 4_102_444_800; // 2100-01-01

/// RFC 7515 A.2: the classic RS256 JWT sample ({"alg":"RS256"} header,
/// iss=joe payload). Verified against the RFC's own RSA JWK.
const RFC7515_A2_TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

/// RFC 7515 A.2 RSA public JWK (kty/n/e only).
const RFC7515_A2_JWK_JSON: &str = concat!(
    r#"{"kty":"RSA","n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx"#,
    r#"HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs"#,
    r#"D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH"#,
    r#"SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV"#,
    r#"MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8"#,
    r#"NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ","e":"AQAB"}"#
);

#[test]
fn rfc7515_a2_rs256_vector_verifies_via_jwk() {
    // JWK -> public material -> SPKI PEM -> jwt_verify.
    let jwk: RsaJwk = serde_json::from_str(RFC7515_A2_JWK_JSON).unwrap();
    let material = jwk_to_public_material(&jwk).unwrap();
    assert_eq!(material.bits(), 2048);
    let public_pem = material.to_spki_pem().unwrap();

    let mut params = JwtVerifyParams::new();
    params.validate_claims = false; // the vector's exp is from 2011
    let verified = jwt_verify(RFC7515_A2_TOKEN, JwtAlg::Rs256, &public_pem, &params).unwrap();
    assert!(verified.valid, "{:?}", verified.reason);
    assert_eq!(verified.header, json!({"alg": "RS256"}));
    assert_eq!(verified.payload["iss"], json!("joe"));
    assert_eq!(verified.signature_hex.len(), 512);

    // Tampering with one byte of the RSA signature invalidates the token.
    let mut tampered = RFC7515_A2_TOKEN.to_string();
    let last = tampered.pop().unwrap();
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    let result = jwt_verify(&tampered, JwtAlg::Rs256, &public_pem, &params).unwrap();
    assert!(!result.valid);
}

#[test]
fn es256_jwk_interop_sign_and_verify() {
    // Generate an ES256 key, export it as a JWK (RFC 7518 6.2), and verify a
    // token signed with the private scalar against the JWK-derived public key.
    let keypair = generate_ecc_keypair(EccCurve::P256).unwrap();
    let jwk = ecc_keypair_to_jwk(&keypair).unwrap();
    assert_eq!(jwk.kty, "EC");
    assert_eq!(jwk.crv, "P-256");

    // JWK survives a JSON round trip.
    let parsed = parse_ecc_jwk(&serde_json::to_string(&jwk).unwrap()).unwrap();
    assert_eq!(parsed, jwk);
    let material = ecc_jwk_to_public_material(&parsed).unwrap();
    assert_eq!(
        material.public_uncompressed_hex,
        keypair.public_uncompressed_hex
    );
    let public_pem =
        ecc_public_key_to_spki_pem(EccCurve::P256, &material.public_uncompressed_hex).unwrap();

    let claims = json!({"sub": "jwk-user", "role": "ctf", "exp": FUTURE_EXP});
    let sign_params = JwtSignParams {
        key_encoding: KeyEncoding::Hex,
        ..JwtSignParams::default()
    };
    let token = jwt_sign(
        claims.clone(),
        json!({"kid": "ec-key-1"}),
        JwtAlg::Es256,
        &keypair.private_hex,
        &sign_params,
    )
    .unwrap();

    // Decode shows the kid extra and unverified status.
    let decoded = jwt_decode(&token).unwrap();
    assert_eq!(decoded.header["kid"], json!("ec-key-1"));
    assert!(!decoded.verified);

    let verified = jwt_verify(&token, JwtAlg::Es256, &public_pem, &JwtVerifyParams::new()).unwrap();
    assert!(verified.valid, "{:?}", verified.reason);
    assert_eq!(verified.payload, claims);

    // A JWK for a different key must not verify this token.
    let other = generate_ecc_keypair(EccCurve::P256).unwrap();
    let other_material = ecc_jwk_to_public_material(&ecc_keypair_to_jwk(&other).unwrap()).unwrap();
    let other_pem =
        ecc_public_key_to_spki_pem(EccCurve::P256, &other_material.public_uncompressed_hex)
            .unwrap();
    let result = jwt_verify(&token, JwtAlg::Es256, &other_pem, &JwtVerifyParams::new()).unwrap();
    assert!(!result.valid);
}

#[test]
fn full_matrix_all_nine_algs_sign_verify_decode() {
    // One sign -> verify -> decode pass for every supported algorithm, using
    // generated keys where the family needs them. Claim validation stays on
    // (the far-future exp passes).
    let rsa = cybercipher_pki::keys::generate_rsa_keypair(2048, "010001").unwrap();
    let rsa_private = rsa.to_pkcs1_pem().unwrap();
    let rsa_public = rsa.to_public_spki_pem().unwrap();
    let p256 = generate_ecc_keypair(EccCurve::P256).unwrap();
    let p384 = generate_ecc_keypair(EccCurve::P384).unwrap();
    let ed = generate_ecc_keypair(EccCurve::Ed25519).unwrap();

    let hex_sign = JwtSignParams {
        key_encoding: KeyEncoding::Hex,
        ..JwtSignParams::default()
    };
    let hex_verify = JwtVerifyParams {
        key_encoding: KeyEncoding::Hex,
        ..JwtVerifyParams::new()
    };

    let cases: Vec<(JwtAlg, String, String, JwtSignParams, JwtVerifyParams)> = vec![
        hs_case(JwtAlg::Hs256, "hs256-secret"),
        hs_case(JwtAlg::Hs384, "hs384-secret"),
        hs_case(JwtAlg::Hs512, "hs512-secret"),
        (
            JwtAlg::Rs256,
            rsa_private.clone(),
            rsa_public.clone(),
            JwtSignParams::default(),
            JwtVerifyParams::new(),
        ),
        (
            JwtAlg::Rs384,
            rsa_private.clone(),
            rsa_public.clone(),
            JwtSignParams::default(),
            JwtVerifyParams::new(),
        ),
        (
            JwtAlg::Rs512,
            rsa_private.clone(),
            rsa_public,
            JwtSignParams::default(),
            JwtVerifyParams::new(),
        ),
        (
            JwtAlg::Es256,
            p256.private_hex.clone(),
            p256.public_uncompressed_hex.clone(),
            hex_sign.clone(),
            hex_verify.clone(),
        ),
        (
            JwtAlg::Es384,
            p384.private_hex.clone(),
            p384.public_uncompressed_hex.clone(),
            hex_sign.clone(),
            hex_verify.clone(),
        ),
        (
            JwtAlg::EdDsa,
            ed.private_hex.clone(),
            ed.public_compressed_hex.clone(),
            hex_sign,
            hex_verify,
        ),
    ];

    for (alg, sign_key, verify_key, sp, vp) in cases {
        let claims = json!({"alg_under_test": alg.to_string(), "exp": FUTURE_EXP});
        let token = jwt_sign(claims, serde_json::Value::Null, alg, &sign_key, &sp).unwrap();

        // Decode is structural only.
        let decoded = jwt_decode(&token).unwrap();
        assert!(!decoded.verified, "{alg}");
        assert_eq!(decoded.header["alg"], json!(alg.to_string()), "{alg}");

        // Verification with the matching key/alg passes.
        let verified = jwt_verify(&token, alg, &verify_key, &vp).unwrap();
        assert!(verified.valid, "{alg}: {:?}", verified.reason);
        assert_eq!(verified.payload["alg_under_test"], json!(alg.to_string()));

        // The same token must NOT verify under any other algorithm (header
        // mismatch fires first).
        for other in [JwtAlg::Hs256, JwtAlg::Rs256, JwtAlg::Es256, JwtAlg::EdDsa] {
            if other == alg {
                continue;
            }
            assert!(
                jwt_verify(&token, other, &verify_key, &vp).is_err(),
                "{alg} vs {other}"
            );
        }
    }
}

fn hs_case(alg: JwtAlg, secret: &str) -> (JwtAlg, String, String, JwtSignParams, JwtVerifyParams) {
    (
        alg,
        secret.to_string(),
        secret.to_string(),
        JwtSignParams::default(),
        JwtVerifyParams::new(),
    )
}

#[test]
fn es384_pkcs8_pem_roundtrip_and_frozen_clock_agree() {
    let keypair = generate_ecc_keypair(EccCurve::P384).unwrap();
    let private_pem = ecc_private_key_to_pkcs8_pem(EccCurve::P384, &keypair.private_hex).unwrap();
    let public_pem =
        ecc_public_key_to_spki_pem(EccCurve::P384, &keypair.public_uncompressed_hex).unwrap();
    let token = jwt_sign(
        json!({"sub": "p384", "exp": FUTURE_EXP}),
        serde_json::Value::Null,
        JwtAlg::Es384,
        &private_pem,
        &JwtSignParams::default(),
    )
    .unwrap();

    // Injected clock and system clock agree on a non-expiring token.
    let frozen = jwt_verify_at(
        &token,
        JwtAlg::Es384,
        &public_pem,
        &JwtVerifyParams::new(),
        1_700_000_000,
    )
    .unwrap();
    let system = jwt_verify(&token, JwtAlg::Es384, &public_pem, &JwtVerifyParams::new()).unwrap();
    assert!(frozen.valid, "{:?}", frozen.reason);
    assert!(system.valid, "{:?}", system.reason);
    assert_eq!(frozen.signature_hex, system.signature_hex);
}
