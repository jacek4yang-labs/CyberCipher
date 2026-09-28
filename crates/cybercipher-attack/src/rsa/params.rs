//! RSA parameter model and parsing.

use num_bigint::BigUint;
use num_traits::Zero;
use serde::{Deserialize, Serialize};

/// Known RSA parameters. Any subset may be provided; attacks declare what
/// they need and enrich the working copy as they succeed.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RsaParams {
    pub n: Option<BigUint>,
    pub e: Option<BigUint>,
    pub c: Option<BigUint>,
    pub d: Option<BigUint>,
    pub p: Option<BigUint>,
    pub q: Option<BigUint>,
    pub phi: Option<BigUint>,
    pub dp: Option<BigUint>,
    pub dq: Option<BigUint>,
    pub qinv: Option<BigUint>,
    /// Optional known-plaintext hint used for verification.
    pub hint: Option<String>,
    /// Additional (n, e, c) sets for common-modulus / Hastad attacks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sets: Vec<RsaSet>,
    /// Additional moduli for shared-prime / batch-gcd.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ns: Vec<BigUint>,
}

/// One (n, e, c) set.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RsaSet {
    pub n: Option<BigUint>,
    pub e: Option<BigUint>,
    pub c: Option<BigUint>,
}

impl RsaParams {
    /// Parse from JSON with case-insensitive keys. Values may be integers
    /// (JSON numbers for small values) or strings in decimal, or hex with a
    /// `0x` prefix. Big integers MUST be strings.
    pub fn from_json(value: &serde_json::Value) -> Result<RsaParams, String> {
        let obj = value
            .as_object()
            .ok_or("RSA parameter document must be a JSON object")?;
        let mut params = RsaParams::default();
        for (key, val) in obj {
            let key = key.to_lowercase();
            let parsed = parse_big_value(val).map_err(|e| format!("parameter `{key}`: {e}"))?;
            match key.as_str() {
                "n" => params.n = parsed,
                "e" => params.e = parsed,
                "c" | "ct" | "ciphertext" => params.c = parsed,
                "d" => params.d = parsed,
                "p" => params.p = parsed,
                "q" => params.q = parsed,
                "phi" | "euler" => params.phi = parsed,
                "dp" | "dmp" => params.dp = parsed,
                "dq" | "dmq" => params.dq = parsed,
                "qinv" | "iqmp" => params.qinv = parsed,
                "hint" | "plaintext_hint" => params.hint = val.as_str().map(|s| s.to_string()),
                "sets" => {
                    let arr = val
                        .as_array()
                        .ok_or("`sets` must be an array of {n, e, c} objects")?;
                    let mut sets = Vec::new();
                    for item in arr {
                        let obj = item
                            .as_object()
                            .ok_or("each `sets` entry must be an object")?;
                        let mut set = RsaSet::default();
                        for (k, v) in obj {
                            let parsed = parse_big_value(v)
                                .map_err(|e| format!("sets entry field `{k}`: {e}"))?;
                            match k.to_lowercase().as_str() {
                                "n" => set.n = parsed,
                                "e" => set.e = parsed,
                                "c" | "ct" | "ciphertext" => set.c = parsed,
                                other => return Err(format!("unknown set field `{other}`")),
                            }
                        }
                        sets.push(set);
                    }
                    params.sets = sets;
                }
                "ns" | "moduli" => {
                    let arr = val.as_array().ok_or("`ns` must be an array of integers")?;
                    let mut ns = Vec::new();
                    for item in arr {
                        if let Some(v) = parse_big_value(item)? {
                            ns.push(v);
                        }
                    }
                    params.ns = ns;
                }
                other => return Err(format!("unknown RSA parameter `{other}`")),
            }
        }
        Ok(params)
    }

    /// Serialize back to the same string format (hex for large values).
    pub fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        let fields = [
            ("n", &self.n),
            ("e", &self.e),
            ("c", &self.c),
            ("d", &self.d),
            ("p", &self.p),
            ("q", &self.q),
            ("phi", &self.phi),
            ("dp", &self.dp),
            ("dq", &self.dq),
            ("qinv", &self.qinv),
        ];
        for (name, val) in fields {
            if let Some(v) = val {
                obj.insert(
                    name.to_string(),
                    serde_json::Value::String(format!("0x{v:x}")),
                );
            }
        }
        if let Some(h) = &self.hint {
            obj.insert("hint".to_string(), serde_json::Value::String(h.clone()));
        }
        if !self.sets.is_empty() {
            let sets: Vec<serde_json::Value> = self
                .sets
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "n": s.n.as_ref().map(|v| format!("0x{v:x}")),
                        "e": s.e.as_ref().map(|v| format!("0x{v:x}")),
                        "c": s.c.as_ref().map(|v| format!("0x{v:x}")),
                    })
                })
                .collect();
            obj.insert("sets".to_string(), serde_json::Value::Array(sets));
        }
        if !self.ns.is_empty() {
            obj.insert(
                "ns".to_string(),
                serde_json::Value::Array(
                    self.ns
                        .iter()
                        .map(|v| serde_json::Value::String(format!("0x{v:x}")))
                        .collect(),
                ),
            );
        }
        serde_json::Value::Object(obj)
    }

    /// Fill in n, phi, dp, dq, qinv from p and q when possible.
    pub fn enrich_from_factors(&mut self) -> bool {
        let (Some(p), Some(q)) = (&self.p, &self.q) else {
            return false;
        };
        // Degenerate "factors" (0 or 1) must never enter the key model: they
        // would underflow p-1 / q-1 below.
        if p <= &BigUint::from(2u32) || q <= &BigUint::from(2u32) {
            return false;
        }
        self.n = Some(p * q);
        let pm1 = p - 1u32;
        let qm1 = q - 1u32;
        let phi = &pm1 * &qm1;
        self.phi = Some(phi.clone());
        if let Some(e) = &self.e {
            if let Some(d) = crate::math::modinv(e, &phi) {
                self.d = Some(d.clone());
                self.dp = Some(&d % &pm1);
                self.dq = Some(&d % &qm1);
                self.qinv = Some(crate::math::modinv(q, p).unwrap_or_default());
            }
        }
        true
    }

    /// Decrypt ciphertext via an explicit d, returning m.
    pub fn decrypt_with(&self, d: &BigUint) -> Option<BigUint> {
        let (n, c) = (self.n.as_ref()?, self.c.as_ref()?);
        if n.is_zero() {
            return None; // modpow would panic on a zero modulus
        }
        Some(c.modpow(d, n))
    }

    /// Round-trip check that `m` re-encrypts to the stored c under e.
    /// True when e, n or c are absent (nothing to check against).
    pub fn verify_decryption(&self, m: &BigUint) -> bool {
        let (Some(e), Some(n), Some(c)) = (&self.e, &self.n, &self.c) else {
            return true;
        };
        &m.modpow(e, n) == c
    }

    /// Decrypt ciphertext via d if available, returning m.
    pub fn decrypt(&self) -> Option<BigUint> {
        let d = self.d.as_ref()?;
        self.decrypt_with(d)
    }
}

/// Parse one parameter value: JSON number (small) or string (dec or 0x hex).
pub fn parse_big_value(val: &serde_json::Value) -> Result<Option<BigUint>, String> {
    match val {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Number(num) => {
            let n = num
                .as_u64()
                .ok_or("numeric parameter out of range — use a string for big integers")?;
            Ok(Some(BigUint::from(n)))
        }
        serde_json::Value::String(text) => {
            let text = text.trim();
            if text.is_empty() {
                return Ok(None);
            }
            let (radix, digits) =
                if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                    (16, hex)
                } else {
                    (10, text)
                };
            let cleaned: String = digits.chars().filter(|c| !c.is_whitespace()).collect();
            let value = BigUint::parse_bytes(cleaned.as_bytes(), radix)
                .ok_or_else(|| format!("`{text}` is not a valid base-{radix} integer"))?;
            Ok(Some(value))
        }
        other => Err(format!("expected number or string, got {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_decimal_and_hex() {
        let params = RsaParams::from_json(&json!({
            "n": "0xDEADBEEF",
            "e": 65537,
            "c": "123456789012345678901234567890"
        }))
        .unwrap();
        assert_eq!(params.n, Some(BigUint::from(0xDEADBEEFu64)));
        assert_eq!(params.e, Some(BigUint::from(65537u64)));
        assert_eq!(params.e.as_ref().map(|v| v.bits()), Some(17));
    }

    #[test]
    fn rejects_unknown_keys_and_bad_values() {
        assert!(RsaParams::from_json(&json!({"secret": "1"})).is_err());
        assert!(RsaParams::from_json(&json!({"n": "zzz"})).is_err());
        assert!(RsaParams::from_json(&json!({"n": "0xZZ"})).is_err());
    }

    #[test]
    fn enrich_completes_key() {
        let mut params = RsaParams::from_json(&json!({
            "p": "61", "q": "53", "e": 17
        }))
        .unwrap();
        assert!(params.enrich_from_factors());
        assert_eq!(params.n, Some(BigUint::from(3233u64)));
        assert_eq!(params.phi, Some(BigUint::from(3120u64)));
        assert_eq!(params.d, Some(BigUint::from(2753u64)));
    }
}
