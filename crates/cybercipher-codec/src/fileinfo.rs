//! File-level utilities: magic-byte type detection, UTF-16 conversion and
//! string extraction, and block-based entropy analysis. All byte-prefix
//! matching is done against a static signature table — no external crates.

use crate::helpers::{input_bytes, p_bool, p_int, p_opts, spec};
use cybercipher_core::prelude::*;

// ---------------------------------------------------------------------------
// file-magic
// ---------------------------------------------------------------------------

struct Sig {
    id: &'static str,
    name: &'static str,
    mime: &'static str,
    ext: &'static str,
    confidence: &'static str,
    offset: usize,
    prefix: &'static [u8],
}

macro_rules! sig {
    ($id:literal, $name:literal, $mime:literal, $ext:literal, $conf:literal, [$($b:literal),*]) => {
        Sig {
            id: $id,
            name: $name,
            mime: $mime,
            ext: $ext,
            confidence: $conf,
            offset: 0,
            prefix: &[$($b),*],
        }
    };
    ($id:literal, $name:literal, $mime:literal, $ext:literal, $conf:literal, $off:literal, [$($b:literal),*]) => {
        Sig {
            id: $id,
            name: $name,
            mime: $mime,
            ext: $ext,
            confidence: $conf,
            offset: $off,
            prefix: &[$($b),*],
        }
    };
}

static SIGNATURES: &[Sig] = &[
    sig!(
        "png",
        "PNG image",
        "image/png",
        "png",
        "high",
        [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
    ),
    sig!(
        "jpeg",
        "JPEG image",
        "image/jpeg",
        "jpg",
        "high",
        [0xFF, 0xD8, 0xFF]
    ),
    sig!(
        "gif87a",
        "GIF image (87a)",
        "image/gif",
        "gif",
        "high",
        [0x47, 0x49, 0x46, 0x38, 0x37, 0x61]
    ),
    sig!(
        "gif89a",
        "GIF image (89a)",
        "image/gif",
        "gif",
        "high",
        [0x47, 0x49, 0x46, 0x38, 0x39, 0x61]
    ),
    sig!(
        "pdf",
        "PDF document",
        "application/pdf",
        "pdf",
        "high",
        [0x25, 0x50, 0x44, 0x46, 0x2D]
    ),
    sig!(
        "zip",
        "ZIP archive",
        "application/zip",
        "zip",
        "high",
        [0x50, 0x4B, 0x03, 0x04]
    ),
    sig!(
        "zip-empty",
        "ZIP archive (empty)",
        "application/zip",
        "zip",
        "high",
        [0x50, 0x4B, 0x05, 0x06]
    ),
    sig!(
        "zip-spanned",
        "ZIP archive (spanned)",
        "application/zip",
        "zip",
        "medium",
        [0x50, 0x4B, 0x07, 0x08]
    ),
    sig!(
        "rar",
        "RAR archive",
        "application/vnd.rar",
        "rar",
        "high",
        [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]
    ),
    sig!(
        "sevenzip",
        "7-Zip archive",
        "application/x-7z-compressed",
        "7z",
        "high",
        [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]
    ),
    sig!(
        "gzip",
        "Gzip compressed data",
        "application/gzip",
        "gz",
        "high",
        [0x1F, 0x8B]
    ),
    sig!(
        "bzip2",
        "Bzip2 compressed data",
        "application/x-bzip2",
        "bz2",
        "high",
        [0x42, 0x5A, 0x68]
    ),
    sig!(
        "xz",
        "XZ compressed data",
        "application/x-xz",
        "xz",
        "high",
        [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]
    ),
    sig!(
        "zstd",
        "Zstandard compressed data",
        "application/zstd",
        "zst",
        "high",
        [0x28, 0xB5, 0x2F, 0xFD]
    ),
    sig!(
        "lz4",
        "LZ4 frame compressed data",
        "application/x-lz4",
        "lz4",
        "high",
        [0x04, 0x22, 0x4D, 0x18]
    ),
    sig!(
        "elf",
        "ELF executable",
        "application/x-executable",
        "elf",
        "high",
        [0x7F, 0x45, 0x4C, 0x46]
    ),
    sig!(
        "pe-mz",
        "Windows PE executable",
        "application/x-msdownload",
        "exe",
        "medium",
        [0x4D, 0x5A]
    ),
    sig!(
        "macho-be32",
        "Mach-O binary (32-bit big-endian)",
        "application/x-mach-binary",
        "macho",
        "high",
        [0xFE, 0xED, 0xFA, 0xCE]
    ),
    sig!(
        "macho-be64",
        "Mach-O binary (64-bit big-endian)",
        "application/x-mach-binary",
        "macho",
        "high",
        [0xFE, 0xED, 0xFA, 0xCF]
    ),
    sig!(
        "macho-le32",
        "Mach-O binary (32-bit little-endian)",
        "application/x-mach-binary",
        "macho",
        "high",
        [0xCE, 0xFA, 0xED, 0xFE]
    ),
    sig!(
        "macho-le64",
        "Mach-O binary (64-bit little-endian)",
        "application/x-mach-binary",
        "macho",
        "high",
        [0xCF, 0xFA, 0xED, 0xFE]
    ),
    sig!(
        "wasm",
        "WebAssembly module",
        "application/wasm",
        "wasm",
        "high",
        [0x00, 0x61, 0x73, 0x6D]
    ),
    sig!(
        "sqlite",
        "SQLite 3 database",
        "application/vnd.sqlite3",
        "sqlite",
        "high",
        [
            0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20,
            0x33, 0x00
        ]
    ),
    sig!(
        "ico",
        "Windows icon",
        "image/x-icon",
        "ico",
        "medium",
        [0x00, 0x00, 0x01, 0x00]
    ),
    sig!(
        "mp3-id3",
        "MP3 audio (ID3 tag)",
        "audio/mpeg",
        "mp3",
        "high",
        [0x49, 0x44, 0x33]
    ),
    sig!(
        "flac",
        "FLAC audio",
        "audio/flac",
        "flac",
        "high",
        [0x66, 0x4C, 0x61, 0x43]
    ),
    sig!(
        "ogg",
        "OGG container",
        "audio/ogg",
        "ogg",
        "high",
        [0x4F, 0x67, 0x67, 0x53]
    ),
    sig!(
        "javaclass",
        "Java class file",
        "application/java-vm",
        "class",
        "high",
        [0xCA, 0xFE, 0xBA, 0xBE]
    ),
    sig!(
        "xml",
        "XML document",
        "application/xml",
        "xml",
        "medium",
        [0x3C, 0x3F, 0x78, 0x6D, 0x6C]
    ),
];

/// RIFF container sub-format at offset 8 ("WEBP"/"WAVE"/"AVI ").
fn detect_riff(data: &[u8]) -> Option<&'static str> {
    let form = &data[8..12];
    match form {
        b"WEBP" => Some("webp"),
        b"WAVE" => Some("wav"),
        b"AVI " => Some("avi"),
        _ => Some("riff"),
    }
}

fn sig_info(
    id: &str,
) -> (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
) {
    match id {
        "webp" => ("webp", "WebP image", "image/webp", "webp", "high"),
        "wav" => ("wav", "WAV audio", "audio/wav", "wav", "high"),
        "avi" => ("avi", "AVI video", "video/x-msvideo", "avi", "high"),
        "riff" => (
            "riff",
            "RIFF container",
            "application/x-riff",
            "riff",
            "medium",
        ),
        "mp4" => ("mp4", "MP4 / QuickTime video", "video/mp4", "mp4", "high"),
        "mp3-sync" => (
            "mp3",
            "MP3 audio (frame sync)",
            "audio/mpeg",
            "mp3",
            "medium",
        ),
        "html" => ("html", "HTML document", "text/html", "html", "low"),
        other => match SIGNATURES.iter().find(|s| s.id == other) {
            Some(sig) => (sig.id, sig.name, sig.mime, sig.ext, sig.confidence),
            // `detect_magic` only returns static ids; this is a safety net.
            None => (
                "unknown",
                "Unknown",
                "application/octet-stream",
                "bin",
                "none",
            ),
        },
    }
}

/// A file type detected by the static signature table (the detector behind
/// the `file-magic` operation), exposed as a public struct so other crates can
/// report detected types without forking the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MagicMatch {
    pub id: &'static str,
    pub name: &'static str,
    pub mime: &'static str,
    pub extension: &'static str,
    pub confidence: &'static str,
}

/// Sniffs `data` against the static signature table and returns the detected
/// type, or `None` when nothing matches. This is the same detector the
/// `file-magic` operation uses (RIFF/MP4/MP3/HTML special cases included).
pub fn sniff_magic(data: &[u8]) -> Option<MagicMatch> {
    detect_magic(data).map(|id| {
        let (id, name, mime, ext, confidence) = sig_info(id);
        MagicMatch {
            id,
            name,
            mime,
            extension: ext,
            confidence,
        }
    })
}

fn detect_magic(data: &[u8]) -> Option<&'static str> {
    // RIFF family: sub-format lives at offset 8.
    if data.len() >= 12 && &data[0..4] == b"RIFF" {
        return detect_riff(data);
    }
    // MP4 / QuickTime: "ftyp" brand box at offset 4.
    if data.len() >= 8 && &data[4..8] == b"ftyp" {
        return Some("mp4");
    }
    // MP3 raw frame sync (0xFFE maskable). Kept behind the table so ID3 wins.
    if data.len() >= 2 && data[0] == 0xFF && matches!(data[1], 0xFB | 0xF3 | 0xF2) {
        return Some("mp3-sync");
    }
    // HTML heuristics (case-insensitive, leading whitespace tolerated).
    let head: Vec<u8> = data
        .iter()
        .copied()
        .skip_while(|&b| b.is_ascii_whitespace())
        .take(15)
        .collect();
    let lower: Vec<u8> = head.iter().map(|b| b.to_ascii_lowercase()).collect();
    if lower.starts_with(b"<!doctype html") || lower.starts_with(b"<html") {
        return Some("html");
    }
    SIGNATURES
        .iter()
        .find(|sig| {
            data.len() >= sig.offset + sig.prefix.len()
                && &data[sig.offset..sig.offset + sig.prefix.len()] == sig.prefix
        })
        .map(|sig| sig.id)
}

fn file_magic_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "File Magic")?;
    let detected = detect_magic(bytes.as_ref()).map(sig_info);
    let detected_json = match detected {
        Some((id, name, mime, ext, confidence)) => serde_json::json!({
            "id": id,
            "name": name,
            "mime": mime,
            "extension": ext,
            "confidence": confidence,
        }),
        None => serde_json::Value::Null,
    };
    Ok(Value::Json(serde_json::json!({
        "length": bytes.len(),
        "detected": detected_json,
    })))
}

// ---------------------------------------------------------------------------
// UTF-16 conversion
// ---------------------------------------------------------------------------

fn utf16_encode(text: &str, big_endian: bool, add_bom: bool) -> Vec<u8> {
    let mut units: Vec<u16> = Vec::with_capacity(text.len() + 1);
    if add_bom {
        units.push(0xFEFF);
    }
    units.extend(text.encode_utf16());
    let mut out = Vec::with_capacity(units.len() * 2);
    for unit in units {
        let pair = if big_endian {
            unit.to_be_bytes()
        } else {
            unit.to_le_bytes()
        };
        out.extend_from_slice(&pair);
    }
    out
}

fn utf16_decode(data: &[u8], big_endian: bool, strip_bom: bool, op_name: &str) -> OpResult<String> {
    if !data.len().is_multiple_of(2) {
        return Err(OperationError::length(
            "even number of bytes",
            format!("{} bytes", data.len()),
            format!("`{op_name}` input has a trailing odd byte (UTF-16 needs byte pairs)"),
        ));
    }
    let mut units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            if big_endian {
                u16::from_be_bytes(*pair)
            } else {
                u16::from_le_bytes(*pair)
            }
        })
        .collect();
    if strip_bom && units.first() == Some(&0xFEFF) {
        units.remove(0);
    }
    String::from_utf16(&units).map_err(|e| {
        OperationError::decode(format!("invalid UTF-16 data: {e}"))
            .with_expected("valid UTF-16 code units (no unpaired surrogates)")
    })
}

fn to_utf16_op(
    big_endian: bool,
) -> impl Fn(&Value, &ParamMap, &ExecutionContext) -> OpResult<Value> {
    move |v: &Value, map: &ParamMap, _: &ExecutionContext| -> OpResult<Value> {
        let text = v.as_text().ok_or_else(|| {
            OperationError::invalid_input(format!(
                "`{}` operates on text, but received {}",
                if big_endian {
                    "To Utf16be"
                } else {
                    "To Utf16le"
                },
                v.kind().name()
            ))
            .with_expected("text")
            .with_actual(v.kind().name())
        })?;
        let add_bom = map.bool_or("add_bom", false);
        Ok(Value::Bytes(utf16_encode(text, big_endian, add_bom)))
    }
}

fn from_utf16_op(
    big_endian: bool,
) -> impl Fn(&Value, &ParamMap, &ExecutionContext) -> OpResult<Value> {
    move |v: &Value, map: &ParamMap, _: &ExecutionContext| -> OpResult<Value> {
        let bytes = input_bytes(
            v,
            if big_endian {
                "From Utf16be"
            } else {
                "From Utf16le"
            },
        )?;
        let strip_bom = map.bool_or("strip_bom", true);
        let text = utf16_decode(
            bytes.as_ref(),
            big_endian,
            strip_bom,
            if big_endian {
                "From Utf16be"
            } else {
                "From Utf16le"
            },
        )?;
        Ok(Value::Text(text))
    }
}

// ---------------------------------------------------------------------------
// extract-strings-utf16
// ---------------------------------------------------------------------------

static BYTE_ORDER_OPTS: &[ParamOption] = &[
    ParamOption {
        value: "both",
        label: "Both (LE scan, then BE scan)",
    },
    ParamOption {
        value: "le",
        label: "UTF-16LE",
    },
    ParamOption {
        value: "be",
        label: "UTF-16BE",
    },
];

fn scan_utf16_strings(
    data: &[u8],
    big_endian: bool,
    min_len: usize,
    ctx: &ExecutionContext,
) -> OpResult<Vec<String>> {
    let mut out = Vec::new();
    let mut current = String::new();
    for pair in data.as_chunks::<2>().0 {
        ctx.check()?;
        let unit = if big_endian {
            u16::from_be_bytes(*pair)
        } else {
            u16::from_le_bytes(*pair)
        };
        if (0x20..=0x7E).contains(&unit) {
            current.push(unit as u8 as char);
        } else if !current.is_empty() {
            if current.chars().count() >= min_len {
                out.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
        }
    }
    if current.chars().count() >= min_len {
        out.push(current);
    }
    Ok(out)
}

/// Integer param with spec-default fallback and explicit range validation
/// (the registry does not inject `ParamSpec` defaults at runtime).
fn ranged_int(
    map: &ParamMap,
    key: &'static str,
    default: i64,
    min: i64,
    max: i64,
) -> OpResult<i64> {
    let value = map.int_or(key, default);
    if value < min || value > max {
        return Err(OperationError::invalid_param(
            key,
            format!("parameter `{key}` must be between {min} and {max}"),
        )
        .with_expected(format!("{min}..{max}"))
        .with_actual(value.to_string()));
    }
    Ok(value)
}

fn extract_strings_utf16_op(v: &Value, map: &ParamMap, ctx: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "Extract Strings Utf16")?;
    let min_len = ranged_int(map, "min_length", 4, 1, 4096)? as usize;
    let order = map.str_or("byte_order", "both");
    let mut results = Vec::new();
    if order == "both" || order == "le" {
        results.extend(scan_utf16_strings(bytes.as_ref(), false, min_len, ctx)?);
    }
    if order == "both" || order == "be" {
        results.extend(scan_utf16_strings(bytes.as_ref(), true, min_len, ctx)?);
    }
    Ok(Value::Text(results.join("\n")))
}

// ---------------------------------------------------------------------------
// file-entropy (block based)
// ---------------------------------------------------------------------------

fn file_entropy_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "File Entropy")?;
    let requested = ranged_int(map, "blocks", 16, 1, 4096)? as usize;
    let block_size = if bytes.is_empty() {
        0
    } else {
        bytes.len().div_ceil(requested)
    };
    let blocks: Vec<serde_json::Value> = bytes
        .chunks(block_size.max(1))
        .enumerate()
        .map(|(i, chunk)| {
            serde_json::json!({
                "index": i,
                "offset": i * block_size,
                "size": chunk.len(),
                "entropy": (cybercipher_core::util::shannon_entropy(chunk) * 10_000.0).round() / 10_000.0,
            })
        })
        .collect();

    let entropies: Vec<f64> = blocks
        .iter()
        .filter_map(|b| b["entropy"].as_f64())
        .collect();
    let (mean, min, max) = if entropies.is_empty() {
        (0.0, 0.0, 0.0)
    } else {
        let sum: f64 = entropies.iter().sum();
        (
            sum / entropies.len() as f64,
            entropies.iter().cloned().fold(f64::INFINITY, f64::min),
            entropies.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        )
    };
    let round4 = |x: f64| (x * 10_000.0).round() / 10_000.0;
    let high = entropies.iter().filter(|&&e| e >= 7.5).count();

    Ok(Value::Json(serde_json::json!({
        "length": bytes.len(),
        "blocks_requested": requested,
        "block_count": blocks.len(),
        "block_size": block_size,
        "blocks": blocks,
        "mean_entropy": round4(mean),
        "min_entropy": round4(min),
        "max_entropy": round4(max),
        "high_entropy_blocks": high,
        "high_entropy_threshold_bits": 7.5,
    })))
}

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    use cybercipher_core::{
        Category::{Analysis as A, Encoding as E, File as F, Utility as U},
        ValueKind::{Bytes as B, Json as J, Text as T},
    };

    let file_tags: &'static [&'static str] = &["file", "ctf", "forensics"];
    let enc_tags: &'static [&'static str] = &["encoding", "unicode", "ctf"];

    reg.add_simple(
        spec(
            "file-magic",
            "File Magic",
            "Detects the file type from magic bytes via a static signature table (images, archives, executables, audio/video, databases, markup) and reports type, MIME hint, and confidence.",
            F,
            &[B, T],
            J,
            CostClass::Instant,
            false,
            vec![],
            file_tags,
            &["magic bytes", "file type", "signature detection"],
            "De facto file-format signatures (libmagic-style table)",
            "Known signature prefixes per format",
        ),
        file_magic_op,
    );

    reg.add_simple(
        spec(
            "to-utf16le",
            "To Utf16le",
            "Encodes text as UTF-16 little-endian bytes, optionally with a BOM.",
            E,
            &[T],
            B,
            CostClass::Instant,
            true,
            vec![p_bool(
                "add_bom",
                "Add BOM",
                false,
                "Prepend the U+FEFF byte-order mark.",
            )],
            enc_tags,
            &["utf-16le encode", "ucs2"],
            "Unicode 15.0, UTF-16 encoding form",
            "Round-trip + BOM tests",
        ),
        to_utf16_op(false),
    );

    reg.add_simple(
        spec(
            "to-utf16be",
            "To Utf16be",
            "Encodes text as UTF-16 big-endian bytes, optionally with a BOM.",
            E,
            &[T],
            B,
            CostClass::Instant,
            true,
            vec![p_bool(
                "add_bom",
                "Add BOM",
                false,
                "Prepend the U+FEFF byte-order mark.",
            )],
            enc_tags,
            &["utf-16be encode", "ucs2"],
            "Unicode 15.0, UTF-16 encoding form",
            "Round-trip + BOM tests",
        ),
        to_utf16_op(true),
    );

    reg.add_simple(
        spec(
            "from-utf16le",
            "From Utf16le",
            "Decodes UTF-16 little-endian bytes into text, stripping a leading BOM by default.",
            E,
            &[B],
            T,
            CostClass::Instant,
            true,
            vec![p_bool(
                "strip_bom",
                "Strip BOM",
                true,
                "Remove a leading U+FEFF mark before decoding.",
            )],
            enc_tags,
            &["utf-16le decode"],
            "Unicode 15.0, UTF-16 encoding form",
            "Round-trip + BOM tests",
        ),
        from_utf16_op(false),
    );

    reg.add_simple(
        spec(
            "from-utf16be",
            "From Utf16be",
            "Decodes UTF-16 big-endian bytes into text, stripping a leading BOM by default.",
            E,
            &[B],
            T,
            CostClass::Instant,
            true,
            vec![p_bool(
                "strip_bom",
                "Strip BOM",
                true,
                "Remove a leading U+FEFF mark before decoding.",
            )],
            enc_tags,
            &["utf-16be decode"],
            "Unicode 15.0, UTF-16 encoding form",
            "Round-trip + BOM tests",
        ),
        from_utf16_op(true),
    );

    reg.add_simple(
        spec(
            "extract-strings-utf16",
            "Extract Strings Utf16",
            "Extracts printable UTF-16 string runs (2-byte aligned), scanning little-endian, big-endian, or both.",
            U,
            &[B, T],
            T,
            CostClass::Interactive,
            false,
            vec![
                p_int(
                    "min_length",
                    "Minimum length",
                    4,
                    "Minimum run length to report.",
                ),
                p_opts(
                    "byte_order",
                    "Byte order",
                    "both",
                    BYTE_ORDER_OPTS,
                    "Which endianness to scan.",
                ),
            ],
            &["forensics", "ctf", "unicode", "wide strings"],
            &["utf16 strings", "widechar strings"],
            "Behavior modeled on POSIX `strings -e`",
            "Round-trip hand-checked cases",
        ),
        extract_strings_utf16_op,
    );

    reg.add_simple(
        spec(
            "file-entropy",
            "File Entropy",
            "Computes Shannon entropy per block (default 16 blocks) to locate embedded encrypted or compressed regions.",
            A,
            &[B, T],
            J,
            CostClass::Instant,
            false,
            vec![p_int(
                "blocks",
                "Number of blocks",
                16,
                "How many blocks to split the input into (1-4096).",
            )],
            &["analysis", "ctf", "forensics"],
            &["entropy map", "entropy blocks"],
            "Shannon (1948); block segmentation CyberCipher-native",
            "Analytic hand-checked cases",
        ),
        file_entropy_op,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_roundtrips() {
        for text in ["", "hi", "héllo wörld", "emoji \u{1F600} surrogate pair"] {
            for be in [false, true] {
                let encoded = utf16_encode(text, be, false);
                assert_eq!(utf16_decode(&encoded, be, true, "t").unwrap(), text);
            }
        }
    }

    #[test]
    fn magic_table_detects_formats() {
        assert_eq!(detect_magic(b"\x89PNG\r\n\x1a\n...."), Some("png"));
        assert_eq!(detect_magic(b"\xFF\xD8\xFF\xE0.."), Some("jpeg"));
        assert_eq!(detect_magic(b"%PDF-1.7 ..."), Some("pdf"));
        assert_eq!(detect_magic(b"PK\x03\x04...."), Some("zip"));
        assert_eq!(detect_magic(b"GIF89a..."), Some("gif89a"));
        assert_eq!(detect_magic(b"RIFF\x00\x00\x00\x00WEBPVP8 "), Some("webp"));
        assert_eq!(detect_magic(b"\x00\x00\x00\x18ftypmp42"), Some("mp4"));
        assert_eq!(detect_magic(b"\x7FELF..."), Some("elf"));
        assert_eq!(detect_magic(b"  <!DOCTYPE html><html>"), Some("html"));
        assert_eq!(detect_magic(b"\xDE\xAD\xBE\xEF"), None);
    }
}
