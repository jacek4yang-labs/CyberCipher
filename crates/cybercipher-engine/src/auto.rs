//! Auto Decode: bounded, explainable automatic multi-layer decoding.
//!
//! Architecture (per project charter):
//!   cheap detectors -> plausible transformations -> execution -> scoring
//!   -> deduplication -> beam search
//!
//! Hard bounds: max depth, beam width, wall-clock deadline, and a
//! decompressed-size cap inside the codec. Random/binary inputs collapse to
//! "no confident candidate" instead of unbounded brute force. Every candidate
//! carries its evidence; Auto Decode never claims certainty it cannot show.

use crate::payload::value_cache_bytes;
use cybercipher_core::util::printable_ratio;
use cybercipher_core::{ExecutionContext, OperationRegistry, ParamMap, Value, ValueKind};
use serde::Serialize;
use std::collections::HashSet;
use std::time::{Duration, Instant};

pub const MAX_DEPTH: usize = 6;
pub const BEAM_WIDTH: usize = 16;
/// Candidates at or above this score are flagged as confident.
pub const CONFIDENT_SCORE: f64 = 0.70;
const MAX_CANDIDATES_REPORTED: usize = 12;
const DEADLINE: Duration = Duration::from_millis(3000);

#[derive(Debug, Clone, Serialize)]
pub struct AutoCandidate {
    pub score: f64,
    pub confident: bool,
    /// Operation ids in application order.
    pub path: Vec<String>,
    pub evidence: Vec<String>,
    pub kind: String,
    pub size: usize,
    /// Bounded text preview of the decoded value.
    pub preview: String,
    pub is_utf8: bool,
    pub flag_like: Option<String>,
}

impl AutoCandidate {
    /// Operation ids only — the basis for "apply as recipe".
    pub fn recipe_ops(&self) -> &[String] {
        &self.path
    }
}

/// One transformation available at a frontier node.
struct Step {
    op: &'static str,
    /// Cheap applicability gate over (bytes, value-kind). Never executes.
    applies: fn(&[u8], &str) -> bool,
    evidence: &'static str,
}

/// Strict hex gate: only hex digits + whitespace, even digit count.
fn is_hex_strict(data: &[u8]) -> bool {
    let mut digits = 0usize;
    for &b in data {
        match b {
            b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => digits += 1,
            b' ' | b'\n' | b'\r' | b'\t' => {}
            _ => return false,
        }
    }
    digits >= 4 && digits.is_multiple_of(2)
}

/// Relaxed base64 gate: >=95% standard alphabet, mixed letters and digits,
/// plausible length. Pure-digit strings are left to the hex/decimal paths.
fn is_base64_like(data: &[u8]) -> bool {
    let mut alpha = 0usize;
    let mut total = 0usize;
    for &b in data {
        total += 1;
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'+' | b'/' | b'=' => alpha += 1,
            b' ' | b'\n' | b'\r' | b'\t' => {}
            _ => return false,
        }
    }
    let has_letter = data.iter().any(|&b| b.is_ascii_alphabetic());
    let has_digit_or_op = data
        .iter()
        .any(|&b| b.is_ascii_digit() || b == b'+' || b == b'/' || b == b'=');
    total >= 8 && alpha * 100 >= total * 95 && has_letter && has_digit_or_op
}

fn is_base32_like(data: &[u8]) -> bool {
    let mut alpha = 0usize;
    let mut total = 0usize;
    for &b in data {
        total += 1;
        match b {
            b'A'..=b'Z' | b'2'..=b'7' | b'=' => alpha += 1,
            b' ' | b'\n' | b'\r' | b'\t' => {}
            _ => return false,
        }
    }
    total >= 8 && alpha * 100 >= total * 95 && data.iter().any(|&b| b.is_ascii_digit() || b == b'=')
}

fn is_url_encoded(data: &[u8]) -> bool {
    data.len() >= 6
        && data
            .windows(3)
            .filter(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
            .count()
            >= 2
}

fn is_gzip(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

fn is_zlib(data: &[u8]) -> bool {
    data.len() >= 2
        && data[0] == 0x78
        && matches!(
            data[1],
            0x01 | 0x5e | 0x9c | 0xda | 0x20 | 0x7d | 0xbb | 0xf9
        )
}

/// The step set. Compression first (magic-exact), then syntax-gated decoders.
const STEPS: &[Step] = &[
    Step {
        op: "from-gzip",
        applies: |d, _| is_gzip(d),
        evidence: "gzip magic 1f 8b",
    },
    Step {
        op: "from-zlib",
        applies: |d, _| is_zlib(d),
        evidence: "zlib header 0x78",
    },
    Step {
        op: "from-base64",
        applies: |d, _| is_base64_like(d),
        evidence: "valid Base64 alphabet and length",
    },
    Step {
        op: "from-base32",
        applies: |d, _| is_base32_like(d),
        evidence: "valid Base32 alphabet",
    },
    Step {
        op: "from-hex",
        applies: |d, _| is_hex_strict(d),
        evidence: "strict hex syntax",
    },
    Step {
        op: "from-url",
        applies: |d, _| is_url_encoded(d),
        evidence: "percent escapes",
    },
    Step {
        op: "decode-text",
        applies: |d, k| k == "bytes" && std::str::from_utf8(d).is_ok(),
        evidence: "valid UTF-8",
    },
];

struct Frontier {
    value: Value,
    kind: String,
    path: Vec<String>,
    evidence: Vec<String>,
}

/// Run Auto Decode on raw input bytes. Returns ranked candidates.
pub fn auto_decode(
    registry: &OperationRegistry,
    input: &[u8],
    ctx: &ExecutionContext,
) -> Vec<AutoCandidate> {
    let started = Instant::now();
    let mut results: Vec<AutoCandidate> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();

    let input_kind = if std::str::from_utf8(input).is_ok() {
        "text"
    } else {
        "bytes"
    };
    let mut frontier = vec![Frontier {
        value: Value::Bytes(input.to_vec()),
        kind: input_kind.to_string(),
        path: Vec::new(),
        evidence: vec![],
    }];

    for _depth in 0..MAX_DEPTH {
        if frontier.is_empty() || ctx.is_cancelled() || started.elapsed() >= DEADLINE {
            break;
        }
        let mut next: Vec<Frontier> = Vec::new();
        for node in &frontier {
            if ctx.is_cancelled() || started.elapsed() >= DEADLINE {
                break;
            }
            let bytes = node
                .value
                .as_bytes()
                .map(|c| c.to_vec())
                .unwrap_or_default();
            let kind = node.kind.clone();
            for step in STEPS {
                if !(step.applies)(&bytes, &kind) {
                    continue;
                }
                let Some(op) = registry.get(step.op) else {
                    continue;
                };
                // Lossless adaptation matching the executor's coercion rule.
                let coerced = adapt(&node.value, op.spec().input_kinds);
                let Ok(out) = op.execute(&coerced, &ParamMap::new(), ctx) else {
                    continue;
                };
                let mut path = node.path.clone();
                path.push(step.op.to_string());
                let mut evidence = node.evidence.clone();
                evidence.push(step.evidence.to_string());
                let candidate = Frontier {
                    kind: out.kind().name().to_string(),
                    value: out,
                    path,
                    evidence,
                };
                collect_candidate(&candidate, &bytes, &mut seen, &mut results);
                next.push(candidate);
            }
        }
        next.sort_by_cached_key(|n| std::cmp::Reverse(beam_rank(n)));
        next.truncate(BEAM_WIDTH);
        frontier = next;
    }

    results.sort_by(|a, b| b.score.total_cmp(&a.score));
    results.truncate(MAX_CANDIDATES_REPORTED);
    results
}

/// Lossless Text/Bytes adaptation (mirrors the executor's coercion rule).
fn adapt(value: &Value, accepted: &[ValueKind]) -> Value {
    if accepted.contains(&value.kind()) {
        return value.clone();
    }
    match value {
        Value::Bytes(b) if accepted.contains(&ValueKind::Text) => match std::str::from_utf8(b) {
            Ok(text) => Value::Text(text.to_string()),
            Err(_) => value.clone(),
        },
        other => other.clone(),
    }
}

fn beam_rank(node: &Frontier) -> u32 {
    let bytes = node
        .value
        .as_bytes()
        .map(|c| c.to_vec())
        .unwrap_or_default();
    let printable = printable_ratio(&bytes) * 100.0;
    bytes.len().min(64 * 1024) as u32 / 16 + printable as u32
}

fn collect_candidate(
    node: &Frontier,
    prev: &[u8],
    seen: &mut HashSet<u64>,
    results: &mut Vec<AutoCandidate>,
) {
    if node.path.is_empty() {
        return;
    }
    let bytes = node
        .value
        .as_bytes()
        .map(|c| c.to_vec())
        .unwrap_or_default();
    let key = xxhash_rust::xxh3::xxh3_64(&value_cache_bytes(&node.value));
    if !seen.insert(key) || bytes.is_empty() || bytes == prev {
        return;
    }

    let is_utf8 = std::str::from_utf8(&bytes).is_ok();
    let printable = printable_ratio(&bytes);
    let flag_like = flag_pattern(&bytes);
    let mut evidence = node.evidence.clone();
    let mut score = 0.30 + 0.25 * printable;

    if is_utf8 {
        score += 0.15;
        evidence.push("UTF-8 output".to_string());
    }
    if flag_like.is_some() {
        score = (score + 0.45).min(0.99);
        evidence.push("flag-like pattern".to_string());
    }
    if looks_like_json(&bytes) {
        score = (score + 0.30).min(0.99);
        evidence.push("valid JSON".to_string());
    }
    if looks_like_pem(&bytes) {
        score = (score + 0.25).min(0.99);
        evidence.push("PEM structure".to_string());
    }
    for (name, magic) in MAGIC {
        if bytes.starts_with(magic) {
            score = (score + 0.35).min(0.99);
            evidence.push(format!("{name} magic"));
            break;
        }
    }
    if printable > 0.95 && bytes.len() >= 8 {
        evidence.push("high printable ratio".to_string());
    }
    // Penalize obviously degraded outputs.
    if bytes.len() > prev.len() * 64 + 1024 {
        score *= 0.5;
        evidence.push("size explosion (probable false positive)".to_string());
    }
    if !is_utf8 && printable < 0.2 {
        score *= 0.4;
    }
    score = score.min(0.99);

    let preview: String = String::from_utf8_lossy(&bytes[..bytes.len().min(2048)]).into_owned();
    results.push(AutoCandidate {
        score: (score * 100.0).round() / 100.0,
        confident: score >= CONFIDENT_SCORE,
        path: node.path.clone(),
        evidence,
        kind: node.kind.clone(),
        size: bytes.len(),
        preview,
        is_utf8,
        flag_like,
    });
    if results.len() > 64 {
        results.truncate(64);
    }
}

const MAGIC: &[(&str, &[u8])] = &[
    ("PNG", b"\x89PNG\r\n\x1a\n"),
    ("JPEG", b"\xff\xd8\xff"),
    ("ZIP", b"PK\x03\x04"),
    ("PDF", b"%PDF"),
    ("ELF", b"\x7fELF"),
    ("BZIP2", b"BZh"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
];

fn flag_pattern(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(64 * 1024)]);
    for pat in ["flag{", "FLAG{", "ctf{", "CTF{", "picoCTF{", "HTB{"] {
        if let Some(idx) = text.find(pat) {
            let rest = &text[idx..];
            if let Some(end) = rest.find('}') {
                if end <= 128 {
                    return Some(rest[..=end].to_string());
                }
            }
        }
    }
    None
}

fn looks_like_json(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(&bytes[..bytes.len().min(4096)]) else {
        return false;
    };
    let trimmed = text.trim_start();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(bytes).is_ok()
}

fn looks_like_pem(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(&bytes[..bytes.len().min(512)]) else {
        return false;
    };
    text.starts_with("-----BEGIN ")
}
