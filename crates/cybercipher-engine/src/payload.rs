//! Serializable projections of [`Value`] for IPC and reporting. Large data
//! stays in Rust; the frontend receives bounded payloads with previews.

use cybercipher_core::util::{printable_ratio, shannon_entropy};
use cybercipher_core::Value;
use serde::Serialize;

/// Bounded, self-describing snapshot of a value for the frontend.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ValuePayload {
    Text {
        text: String,
        size: usize,
        entropy: f64,
    },
    Bytes {
        base64: String,
        /// Lossy UTF-8 rendering for preview purposes.
        text_lossy: String,
        is_utf8: bool,
        size: usize,
        entropy: f64,
    },
    Json {
        value: serde_json::Value,
        size: usize,
    },
    IntegerList {
        items: Vec<String>,
        count: usize,
    },
    List {
        count: usize,
        preview: Vec<String>,
    },
    Null,
}

/// Maximum number of list items embedded in a payload preview.
const LIST_PREVIEW_ITEMS: usize = 100;
/// Maximum characters of lossy text embedded in a bytes payload.
const TEXT_PREVIEW_CHARS: usize = 64 * 1024;

impl ValuePayload {
    pub fn from_value(v: &Value) -> Self {
        match v {
            Value::Text(t) => ValuePayload::Text {
                text: t.clone(),
                size: t.len(),
                entropy: shannon_entropy(t.as_bytes()),
            },
            Value::Bytes(b) => {
                let entropy = shannon_entropy(b);
                let size = b.len();
                match std::str::from_utf8(b) {
                    Ok(text) => ValuePayload::Bytes {
                        base64: b64_encode(b),
                        text_lossy: truncate_chars(text, TEXT_PREVIEW_CHARS).to_string(),
                        is_utf8: true,
                        size,
                        entropy,
                    },
                    Err(_) => {
                        let lossy = String::from_utf8_lossy(b);
                        ValuePayload::Bytes {
                            base64: b64_encode(b),
                            text_lossy: truncate_chars(&lossy, TEXT_PREVIEW_CHARS).to_string(),
                            is_utf8: false,
                            size,
                            entropy,
                        }
                    }
                }
            }
            Value::Integer(i) => ValuePayload::Json {
                value: serde_json::json!({ "integer": i.to_string() }),
                size: 16,
            },
            Value::Json(j) => ValuePayload::Json {
                value: j.clone(),
                size: j.to_string().len(),
            },
            Value::IntegerList(list) => ValuePayload::IntegerList {
                items: list
                    .iter()
                    .take(LIST_PREVIEW_ITEMS)
                    .map(|i| i.to_string())
                    .collect(),
                count: list.len(),
            },
            Value::List(items) => ValuePayload::List {
                count: items.len(),
                preview: items
                    .iter()
                    .take(LIST_PREVIEW_ITEMS)
                    .map(|i| match i {
                        Value::Text(t) => t.clone(),
                        other => format!("{:?}", other).chars().take(200).collect(),
                    })
                    .collect(),
            },
            Value::Null => ValuePayload::Null,
        }
    }

    /// Byte size of the underlying data.
    pub fn size(&self) -> usize {
        match self {
            ValuePayload::Text { size, .. }
            | ValuePayload::Bytes { size, .. }
            | ValuePayload::Json { size, .. } => *size,
            ValuePayload::IntegerList { count, .. } => *count * 8,
            ValuePayload::List { count, .. } => *count,
            ValuePayload::Null => 0,
        }
    }

    pub fn entropy(&self) -> f64 {
        match self {
            ValuePayload::Text { entropy, .. } | ValuePayload::Bytes { entropy, .. } => *entropy,
            _ => 0.0,
        }
    }
}

fn truncate_chars(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

fn b64_encode(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Canonical byte representation of a value for cache-key hashing.
pub fn value_cache_bytes(v: &Value) -> Vec<u8> {
    match v {
        Value::Bytes(b) => b.clone(),
        Value::Text(t) => t.as_bytes().to_vec(),
        Value::Integer(i) => i.to_string().into_bytes(),
        Value::IntegerList(l) => l
            .iter()
            .flat_map(|i| {
                i.to_string()
                    .into_bytes()
                    .into_iter()
                    .chain(std::iter::once(b','))
            })
            .collect(),
        Value::Json(j) => j.to_string().into_bytes(),
        Value::List(l) => {
            let mut out = Vec::new();
            for item in l {
                out.extend_from_slice(&value_cache_bytes(item));
                out.push(0x1f);
            }
            out
        }
        Value::Null => Vec::new(),
    }
}

/// Quick summary used by the status bar for the raw input.
#[derive(Debug, Clone, Serialize)]
pub struct ValueSummary {
    pub kind: String,
    pub size: usize,
    pub entropy: f64,
    pub printable_ratio: f64,
}

impl ValueSummary {
    pub fn of_bytes(bytes: &[u8]) -> Self {
        ValueSummary {
            kind: "bytes".to_string(),
            size: bytes.len(),
            entropy: shannon_entropy(bytes),
            printable_ratio: printable_ratio(bytes),
        }
    }
}
