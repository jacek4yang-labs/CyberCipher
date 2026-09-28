//! Typed value model. The engine is **not** `String -> String`: every value
//! flowing through a recipe carries an explicit kind so operations can
//! validate inputs, and the UI can render results faithfully.

use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// The static kind of a [`Value`], used in operation specifications and
/// diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueKind {
    Bytes,
    Text,
    Integer,
    IntegerList,
    Json,
    List,
    Null,
}

impl ValueKind {
    pub fn name(self) -> &'static str {
        match self {
            ValueKind::Bytes => "bytes",
            ValueKind::Text => "text",
            ValueKind::Integer => "integer",
            ValueKind::IntegerList => "integer list",
            ValueKind::Json => "json",
            ValueKind::List => "list",
            ValueKind::Null => "null",
        }
    }
}

/// A dynamically typed value produced or consumed by operations.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Raw bytes. The most common intermediate representation in a pipeline.
    Bytes(Vec<u8>),
    /// Valid UTF-8 text.
    Text(String),
    /// Arbitrary-precision integer.
    Integer(BigInt),
    /// A list of arbitrary-precision integers.
    IntegerList(Vec<BigInt>),
    /// Structured JSON data.
    Json(serde_json::Value),
    /// A heterogeneous list of values (e.g. the output of `split`).
    List(Vec<Value>),
    /// Explicitly empty.
    Null,
}

impl Value {
    pub fn kind(&self) -> ValueKind {
        match self {
            Value::Bytes(_) => ValueKind::Bytes,
            Value::Text(_) => ValueKind::Text,
            Value::Integer(_) => ValueKind::Integer,
            Value::IntegerList(_) => ValueKind::IntegerList,
            Value::Json(_) => ValueKind::Json,
            Value::List(_) => ValueKind::List,
            Value::Null => ValueKind::Null,
        }
    }

    /// Borrow the value as bytes when possible. `Text` coerces to its UTF-8
    /// representation; `Null` coerces to empty.
    pub fn as_bytes(&self) -> Option<Cow<'_, [u8]>> {
        match self {
            Value::Bytes(b) => Some(Cow::Borrowed(b)),
            Value::Text(t) => Some(Cow::Borrowed(t.as_bytes())),
            Value::Null => Some(Cow::Borrowed(&[])),
            _ => None,
        }
    }

    /// Borrow the value as text when it is text.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    /// Rough byte size of the value's payload, for status display and budgets.
    pub fn size_hint(&self) -> usize {
        match self {
            Value::Bytes(b) => b.len(),
            Value::Text(t) => t.len(),
            Value::Integer(_) => 16,
            Value::IntegerList(l) => l.len() * 8,
            Value::Json(j) => j.to_string().len(),
            Value::List(l) => l.iter().map(Value::size_hint).sum(),
            Value::Null => 0,
        }
    }

    /// Build a `Value::Bytes` or `Value::Text` from raw bytes, promoting to
    /// `Text` when the bytes are valid UTF-8.
    pub fn from_bytes(bytes: Vec<u8>) -> Value {
        match String::from_utf8(bytes) {
            Ok(text) => Value::Text(text),
            Err(e) => Value::Bytes(e.into_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_coerces_to_bytes() {
        let v = Value::Text("hi".to_string());
        assert_eq!(v.as_bytes().unwrap().as_ref(), b"hi");
        assert_eq!(v.kind(), ValueKind::Text);
    }

    #[test]
    fn from_bytes_promotes_utf8() {
        assert_eq!(Value::from_bytes(vec![104, 105]), Value::Text("hi".into()));
        assert!(matches!(Value::from_bytes(vec![0xff]), Value::Bytes(_)));
    }
}
