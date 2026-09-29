//! JWK / JWKS conversion for RSA keys (RFC 7517 + RFC 7518 section 6.3).
//!
//! JWK big integers are base64url-encoded without padding (`n`, `e`, `d`,
//! `p`, `q`, `dp`, `dq`, `qi`); CyberCipher's own transport format is hex, so
//! conversion happens on both sides of the JWK boundary.
//!
//! Encoding is strictly RFC-compliant (unpadded base64url); decoding
//! tolerates padded input for interop with sloppy producers.

use base64ct::Encoding as _;
use serde::{Deserialize, Serialize};

use crate::error::{PkiError, PkiResult};
use crate::keys::{
    biguint_from_hex, to_hex, InspectKey, KeyFormat, KeyInspection, KeyType, RsaKeypair,
    RsaPublicKeyMaterial,
};

/// An RSA JSON Web Key. Public JWKs carry only `kty`, `n`, `e` (plus optional
/// `kid`); private JWKs additionally carry `d` and the CRT parameters `p`,
/// `q`, `dp`, `dq`, `qi` (optional per RFC 7518 section 6.3.2 — missing CRT
/// parameters are re-derived when converting to a keypair).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaJwk {
    pub kty: String,
    pub n: String,
    pub e: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dq: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qi: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// Convert a keypair to a private JWK (all RFC 7518 section 6.3.2 parameters).
pub fn keypair_to_jwk(keypair: &RsaKeypair) -> RsaJwk {
    let m = keypair.material();
    RsaJwk {
        kty: "RSA".to_string(),
        n: hex_to_b64url(&m.n),
        e: hex_to_b64url(&m.e),
        d: Some(hex_to_b64url(&m.d)),
        p: Some(hex_to_b64url(&m.p)),
        q: Some(hex_to_b64url(&m.q)),
        dp: Some(hex_to_b64url(&m.dp)),
        dq: Some(hex_to_b64url(&m.dq)),
        qi: Some(hex_to_b64url(&m.qinv)),
        kid: None,
    }
}

/// Convert public material to a public JWK (only `kty`, `n`, `e`).
pub fn public_material_to_jwk(material: &RsaPublicKeyMaterial) -> RsaJwk {
    RsaJwk {
        kty: "RSA".to_string(),
        n: hex_to_b64url(&material.n),
        e: hex_to_b64url(&material.e),
        d: None,
        p: None,
        q: None,
        dp: None,
        dq: None,
        qi: None,
        kid: None,
    }
}

/// Convert a public JWK to validated public material.
pub fn jwk_to_public_material(jwk: &RsaJwk) -> PkiResult<RsaPublicKeyMaterial> {
    require_kty_rsa(jwk)?;
    let n = b64url_to_hex(&jwk.n, "n")?;
    let e = b64url_to_hex(&jwk.e, "e")?;
    crate::keys::pem::public_material_from_parts(
        biguint_from_hex(&n).map_err(|err| err.with_parameter("n"))?,
        biguint_from_hex(&e).map_err(|err| err.with_parameter("e"))?,
    )
}

/// Convert a private JWK to a full keypair.
///
/// Requires `d`, `p`, and `q` (reconstructing primes from `(n, e, d)` is not
/// supported yet); `dp`, `dq`, `qi` are optional and re-derived canonically.
pub fn jwk_to_keypair(jwk: &RsaJwk) -> PkiResult<RsaKeypair> {
    require_kty_rsa(jwk)?;
    let Some(d_b64) = jwk.d.as_deref() else {
        return Err(PkiError::invalid_input(
            "JWK has no 'd' parameter: this is a public key, not a private key",
        )
        .with_parameter("d")
        .with_expected("private JWK with 'd' present")
        .with_actual("public JWK"));
    };
    let Some(p_b64) = jwk.p.as_deref() else {
        return Err(PkiError::unsupported(
            "JWK private key is missing the 'p' parameter: reconstructing primes from (n, e, d) is not supported yet",
        )
        .with_parameter("p")
        .with_details("re-serialize the key including p/q (and CRT parameters)"));
    };
    let Some(q_b64) = jwk.q.as_deref() else {
        return Err(PkiError::unsupported(
            "JWK private key is missing the 'q' parameter: reconstructing primes from (n, e, d) is not supported yet",
        )
        .with_parameter("q")
        .with_details("re-serialize the key including p/q (and CRT parameters)"));
    };

    let n = b64url_decode("n", &jwk.n)?;
    let e = b64url_decode("e", &jwk.e)?;
    let d = b64url_decode("d", d_b64)?;
    let p = b64url_decode("p", p_b64)?;
    let q = b64url_decode("q", q_b64)?;

    RsaKeypair::from_parts_bytes(&n, &e, &d, &p, &q)
}

// -- JWK/JWKS JSON ------------------------------------------------------------

/// Parse a single JWK from JSON.
pub fn parse_jwk(json: &str) -> PkiResult<RsaJwk> {
    serde_json::from_str(json)
        .map_err(|e| PkiError::decode("invalid JWK JSON").with_details(e.to_string()))
}

/// Serialize a JWK to JSON (compact, no trailing newline).
pub fn jwk_to_json(jwk: &RsaJwk) -> PkiResult<String> {
    serde_json::to_string(jwk)
        .map_err(|e| PkiError::internal("JWK serialization failed").with_details(e.to_string()))
}

/// Parse a JWKS: either `{"keys": [...]}` (RFC 7517 section 5) or a bare JSON
/// array of JWKs.
pub fn parse_jwks(json: &str) -> PkiResult<Vec<RsaJwk>> {
    #[derive(Deserialize)]
    struct Jwks {
        keys: Vec<RsaJwk>,
    }
    if let Ok(jwks) = serde_json::from_str::<Jwks>(json) {
        return Ok(jwks.keys);
    }
    if let Ok(bare) = serde_json::from_str::<Vec<RsaJwk>>(json) {
        return Ok(bare);
    }
    Err(PkiError::decode("invalid JWKS JSON")
        .with_expected("{\"keys\": [ ... ]} or a bare JSON array of JWKs")
        .with_details("neither a JWKS object nor an array"))
}

/// Serialize a set of JWKs as a JWKS object (`{"keys": [...]}`).
pub fn jwks_to_json(keys: &[RsaJwk]) -> PkiResult<String> {
    #[derive(Serialize)]
    struct Jwks<'a> {
        keys: &'a [RsaJwk],
    }
    serde_json::to_string(&Jwks { keys })
        .map_err(|e| PkiError::internal("JWKS serialization failed").with_details(e.to_string()))
}

// -- Inspection ----------------------------------------------------------------

impl InspectKey for RsaJwk {
    fn inspect(&self) -> PkiResult<KeyInspection> {
        require_kty_rsa(self)?;
        let n_bytes = b64url_decode("n", &self.n)?;
        let e_bytes = b64url_decode("e", &self.e)?;
        let is_private = self.d.is_some();
        let opt_hex = |v: &Option<String>, param: &str| -> PkiResult<Option<String>> {
            v.as_deref().map(|s| b64url_to_hex(s, param)).transpose()
        };
        let bits = crate::keys::bytes_bit_length(&n_bytes);
        let summary = format!(
            "RSA {} key ({}, {} bits, e = {}){}",
            if is_private { "private" } else { "public" },
            KeyFormat::Jwk.label(),
            bits,
            to_hex(&e_bytes),
            crate::keys::legacy_suffix(bits)
        );
        Ok(KeyInspection {
            key_type: if is_private {
                KeyType::RsaPrivate
            } else {
                KeyType::RsaPublic
            },
            format: KeyFormat::Jwk,
            bit_length: bits,
            n: to_hex(&n_bytes),
            e: to_hex(&e_bytes),
            d: opt_hex(&self.d, "d")?,
            p: opt_hex(&self.p, "p")?,
            q: opt_hex(&self.q, "q")?,
            dp: opt_hex(&self.dp, "dp")?,
            dq: opt_hex(&self.dq, "dq")?,
            qinv: opt_hex(&self.qi, "qi")?,
            strength: crate::keys::strength_note(bits).to_string(),
            summary,
        })
    }
}

// -- helpers -------------------------------------------------------------------

fn hex_to_b64url(hex: &str) -> String {
    // Hex produced by our own transport layer is always valid; on the off
    // chance of malformed input, fall back to an empty string rather than
    // panicking — conversion callers validate before encoding.
    let bytes = hex_to_bytes(hex).unwrap_or_default();
    base64ct::Base64UrlUnpadded::encode_string(&bytes)
}

fn b64url_to_hex(s: &str, parameter: &str) -> PkiResult<String> {
    let bytes = b64url_decode(parameter, s)?;
    Ok(to_hex(&bytes))
}

fn b64url_decode(parameter: &str, s: &str) -> PkiResult<Vec<u8>> {
    let s = s.trim();
    base64ct::Base64UrlUnpadded::decode_vec(s)
        .or_else(|_| base64ct::Base64Url::decode_vec(s))
        .map_err(|e| {
            PkiError::decode(format!(
                "invalid base64url encoding in JWK '{parameter}' parameter"
            ))
            .with_parameter(parameter)
            .with_details(e.to_string())
        })
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.strip_prefix("0x").or_else(|| hex.strip_prefix("0X")).unwrap_or(hex);
    if hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn require_kty_rsa(jwk: &RsaJwk) -> PkiResult<()> {
    if !jwk.kty.eq_ignore_ascii_case("RSA") {
        return Err(PkiError::unsupported(format!(
            "unsupported JWK key type: kty = '{}' (only RSA is supported)",
            jwk.kty
        ))
        .with_parameter("kty")
        .with_expected("RSA")
        .with_actual(jwk.kty.clone()));
    }
    Ok(())
}
