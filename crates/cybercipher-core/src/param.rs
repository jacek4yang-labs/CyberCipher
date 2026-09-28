//! Runtime parameter values and the parameter map.
//!
//! Parameters are deliberately simple and JSON-serializable: they must round
//! trip through the public recipe format without exposing Rust internals.

use crate::error::{ErrorKind, OpResult, OperationError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A single runtime parameter value. Serialization is intentionally plain
/// (untagged): recipe files carry ordinary JSON strings/numbers/booleans.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ParamValue {
    Str(String),
    Int(i64),
    Bool(bool),
    Float(f64),
}

impl ParamValue {
    pub fn kind_name(&self) -> &'static str {
        match self {
            ParamValue::Str(_) => "string",
            ParamValue::Int(_) => "integer",
            ParamValue::Bool(_) => "boolean",
            ParamValue::Float(_) => "float",
        }
    }
}

impl From<&str> for ParamValue {
    fn from(s: &str) -> Self {
        ParamValue::Str(s.to_string())
    }
}

impl From<String> for ParamValue {
    fn from(s: String) -> Self {
        ParamValue::Str(s)
    }
}

impl From<i64> for ParamValue {
    fn from(i: i64) -> Self {
        ParamValue::Int(i)
    }
}

impl From<bool> for ParamValue {
    fn from(b: bool) -> Self {
        ParamValue::Bool(b)
    }
}

impl From<f64> for ParamValue {
    fn from(f: f64) -> Self {
        ParamValue::Float(f)
    }
}

/// Ordered map of parameter key -> value. `BTreeMap` guarantees stable key
/// ordering, which keeps canonical serialization (and therefore cache keys)
/// deterministic.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(transparent)]
pub struct ParamMap(BTreeMap<String, ParamValue>);

impl ParamMap {
    pub fn new() -> Self {
        ParamMap(BTreeMap::new())
    }

    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<ParamValue>) {
        self.0.insert(key.into(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&ParamValue> {
        self.0.get(key)
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        match self.0.get(key) {
            Some(ParamValue::Str(s)) => Some(s),
            _ => None,
        }
    }

    pub fn get_int(&self, key: &str) -> Option<i64> {
        match self.0.get(key) {
            Some(ParamValue::Int(i)) => Some(*i),
            _ => None,
        }
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.0.get(key) {
            Some(ParamValue::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    pub fn get_float(&self, key: &str) -> Option<f64> {
        match self.0.get(key) {
            Some(ParamValue::Float(f)) => Some(*f),
            _ => None,
        }
    }

    /// Fetch a string parameter that must be present.
    pub fn require_str(&self, key: &str) -> OpResult<&str> {
        self.get_str(key).ok_or_else(|| {
            OperationError::new(
                ErrorKind::InvalidParam,
                format!("missing string parameter `{key}`"),
            )
            .with_parameter(key)
        })
    }

    /// Fetch an integer parameter that must be present and in range.
    pub fn require_int(&self, key: &str, min: i64, max: i64) -> OpResult<i64> {
        let v = self.get_int(key).ok_or_else(|| {
            OperationError::new(
                ErrorKind::InvalidParam,
                format!("missing integer parameter `{key}`"),
            )
            .with_parameter(key)
        })?;
        if v < min || v > max {
            return Err(OperationError::invalid_param(
                key,
                format!("parameter `{key}` must be between {min} and {max}"),
            )
            .with_expected(format!("{min}..{max}"))
            .with_actual(v.to_string()));
        }
        Ok(v)
    }

    /// Fetch a boolean parameter with a fallback default.
    pub fn bool_or(&self, key: &str, default: bool) -> bool {
        self.get_bool(key).unwrap_or(default)
    }

    pub fn str_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.get_str(key).unwrap_or(default)
    }

    pub fn int_or(&self, key: &str, default: i64) -> i64 {
        self.get_int(key).unwrap_or(default)
    }

    /// Canonical JSON serialization used for cache keys and hashing. Key
    /// ordering is stable because the underlying map is a `BTreeMap`.
    pub fn canonical_json(&self) -> String {
        serde_json::to_string(&self.0).unwrap_or_default()
    }
}

impl FromIterator<(String, ParamValue)> for ParamMap {
    fn from_iter<T: IntoIterator<Item = (String, ParamValue)>>(iter: T) -> Self {
        ParamMap(BTreeMap::from_iter(iter))
    }
}

impl FromIterator<(&'static str, ParamValue)> for ParamMap {
    fn from_iter<T: IntoIterator<Item = (&'static str, ParamValue)>>(iter: T) -> Self {
        ParamMap(BTreeMap::from_iter(
            iter.into_iter().map(|(k, v)| (k.to_string(), v)),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_is_stable() {
        let mut a = ParamMap::new();
        a.insert("zeta", "1");
        a.insert("alpha", 2);
        let mut b = ParamMap::new();
        b.insert("alpha", 2);
        b.insert("zeta", "1");
        assert_eq!(a.canonical_json(), b.canonical_json());
        assert!(a.canonical_json().contains(r#"{"alpha""#));
    }

    #[test]
    fn require_int_validates_range() {
        let mut p = ParamMap::new();
        p.insert("amount", 9);
        assert!(p.require_int("amount", 0, 7).is_err());
        assert_eq!(p.require_int("amount", 0, 9).unwrap(), 9);
        assert!(p.require_int("nope", 0, 1).is_err());
    }
}
