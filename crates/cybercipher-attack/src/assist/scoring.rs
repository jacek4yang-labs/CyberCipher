//! Plaintext scoring for Crypto Assist candidates.
//!
//! Reuses the statistical ideas from the XOR lab's scorer (printable ratio,
//! English chi-square fit, flag patterns) and adds structure detectors
//! (JSON, file magic) that are meaningful for decrypted payloads. Every
//! component is reported individually so evidence lines can cite it.

use serde::Serialize;

/// File-magic signatures meaningful for decrypted payloads.
const MAGIC: &[(&str, &[u8])] = &[
    ("PNG", b"\x89PNG\r\n\x1a\n"),
    ("JPEG", b"\xff\xd8\xff"),
    ("ZIP", b"PK\x03\x04"),
    ("PDF", b"%PDF"),
    ("ELF", b"\x7fELF"),
    ("gzip", b"\x1f\x8b"),
];

/// Composite plaintext score with per-component breakdown.
#[derive(Debug, Clone, Serialize)]
pub struct AssistScore {
    /// Total score in 0.0..=1.0 (flag/JSON/magic bonuses included, clamped).
    pub total: f64,
    /// Ratio of printable ASCII bytes.
    pub printable: f64,
    /// English chi-square fit over letters (0 when too few letters).
    pub english_fit: f64,
    /// True when the full sample decodes as UTF-8.
    pub valid_utf8: bool,
    /// Flag-like token found (already extracted, e.g. `flag{...}`).
    pub flag_pattern: Option<String>,
    /// Human-readable name of the recognized file magic, if any.
    pub file_magic: Option<String>,
    /// True when the sample parses as JSON.
    pub valid_json: bool,
}

impl AssistScore {
    /// Score a candidate plaintext.
    pub fn of(data: &[u8]) -> Self {
        let sample = &data[..data.len().min(64 * 1024)];
        let printable = cybercipher_core::util::printable_ratio(sample);
        let fit = if sample.iter().filter(|b| b.is_ascii_alphabetic()).count() >= 3 {
            crate::xor::scoring::english_fit(sample)
        } else {
            0.0
        };
        let valid_utf8 = std::str::from_utf8(sample).is_ok();
        let flag_pattern = crate::xor::scoring::find_flag_pattern(sample);
        let file_magic = MAGIC
            .iter()
            .find(|(_, magic)| sample.starts_with(magic))
            .map(|(name, _)| name.to_string());
        let valid_json = looks_like_json(sample);

        let mut total = 0.35 * printable + 0.30 * fit;
        if valid_utf8 {
            total += 0.15;
        }
        if flag_pattern.is_some() {
            total += 0.30;
        }
        if valid_json {
            total += 0.20;
        }
        if file_magic.is_some() {
            total += 0.25;
        }
        // Entropy-style uniform garbage stays low: a printable-but-random
        // payload cannot exceed ~0.5 without structure.
        AssistScore {
            total: total.min(1.0),
            printable,
            english_fit: fit,
            valid_utf8,
            flag_pattern,
            file_magic,
            valid_json,
        }
    }

    /// Human-readable evidence lines for the components that fired.
    pub fn evidence(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.valid_utf8 {
            out.push("output is valid UTF-8".to_string());
        }
        if self.english_fit > 0.3 {
            out.push("output fits English letter frequencies".to_string());
        }
        if let Some(flag) = &self.flag_pattern {
            out.push(format!("contains flag-like token {flag}"));
        }
        if self.valid_json {
            out.push("output parses as JSON".to_string());
        }
        if let Some(magic) = &self.file_magic {
            out.push(format!("output starts with {magic} magic"));
        }
        out
    }
}

fn looks_like_json(data: &[u8]) -> bool {
    let trimmed: &[u8] = {
        let start = data
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(data.len());
        &data[start..]
    };
    if !(trimmed.starts_with(b"{") || trimmed.starts_with(b"[")) {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(data).is_ok()
}
