//! Appended-data carving: report the bytes that live after a container's
//! logical end of file (PNG IEND, JPEG EOI, GIF trailer, BMP pixel-array end).
//!
//! Behavioral reference: StegSolver `FileAnalyzer`/`FileReport` trailing-data
//! detection (commit `c14bfa9`, MIT). Detected magic reuses the codec crate's
//! `fileinfo` signature table — the same detector the `file-magic` operation
//! and Auto Decode see, so a carved tail reports the type the rest of the
//! workbench would act on. Carving only inspects: it never decodes further,
//! unpacks, or executes anything.

use serde_json::{json, Value as Json};

/// Upper bound of the hex preview in a carve report.
pub const MAX_PREVIEW_BYTES: usize = 256;
/// How much of the tail is scanned for printable strings.
const STRINGS_SCAN_LIMIT: usize = 4096;
/// Total characters emitted in the printable-string snippet.
const MAX_STRINGS_CHARS: usize = 512;
/// Minimum length of a printable run to be reported (POSIX `strings` default).
const MIN_STRING_RUN: usize = 4;

/// Bytes found after a container's logical end of file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carved {
    /// Offset of the first appended byte (end-exclusive logical EOF).
    pub offset: u64,
    /// Number of appended bytes (`file_size - offset`).
    pub size: u64,
    /// Detected file type of the tail (codec `fileinfo` magic), if any.
    pub magic: Option<cybercipher_codec::MagicMatch>,
    /// Lowercase hex of the first [`MAX_PREVIEW_BYTES`] tail bytes.
    pub preview_hex: String,
    /// Bounded printable-string snippet of the tail.
    pub strings: String,
}

/// Carves the bytes after `end`. Returns `None` when `end` is `None`, does not
/// fit in the buffer, or sits at/past the end of the file (nothing appended).
#[must_use]
pub fn carve_at(data: &[u8], end: Option<u64>) -> Option<Carved> {
    let offset = usize::try_from(end?).ok()?;
    if offset >= data.len() {
        return None;
    }
    let tail = &data[offset..];
    Some(Carved {
        offset: offset as u64,
        size: tail.len() as u64,
        magic: cybercipher_codec::sniff_magic(tail),
        preview_hex: tail
            .iter()
            .take(MAX_PREVIEW_BYTES)
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        strings: printable_strings(tail),
    })
}

/// Runs the structural analyzers and carves the bytes after the detected
/// logical end of file. `None` when the format is unknown or nothing is
/// appended.
#[must_use]
pub fn carve(data: &[u8]) -> Option<Carved> {
    let (_, report) = crate::structure::analyze_any(data)?;
    let end = report.get("expected_end").and_then(Json::as_u64);
    carve_at(data, end)
}

/// Printable-string snippet of the tail: runs of at least
/// [`MIN_STRING_RUN`] printable ASCII characters, newline-separated, capped at
/// [`MAX_STRINGS_CHARS`] characters with a trailing ellipsis marker.
#[must_use]
pub fn printable_strings(tail: &[u8]) -> String {
    let mut out = String::new();
    let mut run = String::new();
    for &byte in tail.iter().take(STRINGS_SCAN_LIMIT) {
        if (0x20..=0x7E).contains(&byte) {
            run.push(byte as char);
        } else if run.len() >= MIN_STRING_RUN {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&run);
            if out.len() >= MAX_STRINGS_CHARS {
                out.push_str(" …");
                return out;
            }
            run.clear();
        } else {
            run.clear();
        }
    }
    if run.len() >= MIN_STRING_RUN && out.len() < MAX_STRINGS_CHARS {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&run[..run.len().min(MAX_STRINGS_CHARS - out.len())]);
    }
    if out.len() >= MAX_STRINGS_CHARS {
        out.push_str(" …");
    }
    out
}

/// The `appended` section shared by every structural report. `expected_end` is
/// the format's logical end of file; appended data exists only when that
/// offset lies strictly inside the buffer.
#[must_use]
pub fn appended_json(data: &[u8], expected_end: Option<u64>) -> Json {
    match carve_at(data, expected_end) {
        None => json!({ "present": false }),
        Some(carved) => json!({
            "present": true,
            "offset": carved.offset,
            "size": carved.size,
            "preview_bytes": carved.preview_hex.len() / 2,
            "preview_hex": carved.preview_hex,
            "magic": magic_json(carved.magic),
            "strings": carved.strings,
        }),
    }
}

#[must_use]
fn magic_json(magic: Option<cybercipher_codec::MagicMatch>) -> Json {
    match magic {
        None => Json::Null,
        Some(m) => json!({
            "id": m.id,
            "name": m.name,
            "mime": m.mime,
            "extension": m.extension,
            "confidence": m.confidence,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carve_at_reports_offset_size_and_magic() {
        let mut data = vec![0u8; 40];
        data.extend_from_slice(b"PK\x03\x04payload");
        let carved = carve_at(&data, Some(40)).expect("tail exists");
        assert_eq!(carved.offset, 40);
        assert_eq!(carved.size, 11);
        assert_eq!(carved.magic.expect("zip").id, "zip");
        assert!(carved.preview_hex.starts_with("504b0304"));
        assert_eq!(carved.preview_hex.len(), 11 * 2);
        assert_eq!(carved.strings, "payload");
    }

    #[test]
    fn carve_at_is_none_without_a_tail() {
        let data = vec![1, 2, 3];
        assert!(carve_at(&data, None).is_none());
        assert!(carve_at(&data, Some(3)).is_none());
        assert!(carve_at(&data, Some(4)).is_none());
        assert!(carve_at(&data, Some(u64::MAX)).is_none());
    }

    #[test]
    fn preview_and_strings_are_bounded() {
        let tail = vec![0x41u8; 100_000];
        let carved = carve_at(&tail, Some(0)).expect("tail exists");
        assert_eq!(carved.preview_hex.len(), MAX_PREVIEW_BYTES * 2);
        let strings = printable_strings(&tail);
        assert!(strings.len() <= MAX_STRINGS_CHARS + 4);
        assert!(strings.ends_with('…'));
    }

    #[test]
    fn strings_skip_short_runs_and_non_printables() {
        let tail = b"ab\x00\x01long_enough\xFFtail";
        assert_eq!(printable_strings(tail), "long_enough\ntail");
        assert_eq!(printable_strings(b"ab"), "");
    }
}
