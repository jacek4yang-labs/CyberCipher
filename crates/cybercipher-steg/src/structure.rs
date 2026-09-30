//! Structural container analysis for PNG, JPEG, GIF and BMP files.
//!
//! The four analyzers walk the **raw file bytes** (never decoded pixels) and
//! produce a bounded JSON report: chunk/segment/block lists with offsets and
//! lengths, header geometry, palettes, comments, CRC status and the logical
//! end of file (IEND end, EOI end, GIF trailer, BMP pixel-array end). Bytes
//! past the logical end are reported by [`crate::carving`].
//!
//! Behavioral reference: StegSolver `PngAnalyzer`/`JpegAnalyzer`/
//! `GifAnalyzer`/`BmpAnalyzer`/`FileReport` (commit `c14bfa9`, MIT). The
//! section/line report shape became a JSON document; the semantics kept are
//! the bounds handling (every read is a checked `get`, malformed lengths end
//! the walk with a "truncated at offset N" marker instead of an error) and
//! the trailing-data detection.
//!
//! Resource bounds: at most [`MAX_ENTRIES`] chunks/segments/blocks per
//! report, [`MAX_TEXT_BYTES`] per extracted comment, [`MAX_COMMENTS`]
//! comments, [`MAX_WARNINGS`] warnings, [`MAX_PALETTE_ENTRIES_LISTED`]
//! palette entries listed and a 256-byte hex preview per carve. Every walk
//! step advances at least one byte and carries an extra step cap, so hostile
//! input cannot spin; the analyzers allocate nothing proportional to
//! untrusted length fields.

use crate::carving::appended_json;
use cybercipher_core::prelude::*;
use cybercipher_core::{ExecutionContext, OperationRegistry, Value};
use serde_json::{json, Value as Json};

/// Maximum number of chunks/segments/blocks visited per report.
pub const MAX_ENTRIES: usize = 512;
/// Maximum bytes extracted per comment string (per the design contract).
pub const MAX_TEXT_BYTES: usize = 1024;
/// Maximum number of extracted comments per report.
pub const MAX_COMMENTS: usize = 64;
/// Maximum warnings kept per report.
pub const MAX_WARNINGS: usize = 64;
/// Maximum palette entries listed per report (the rest are counted only).
pub const MAX_PALETTE_ENTRIES_LISTED: usize = 64;

const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// Maximum iterations of any byte-scan loop, relative to the input size.
/// Every loop body advances at least one byte, so this never trips on honest
/// input; it is a belt-and-braces bound against non-advancing walks.
fn step_cap(data_len: usize) -> u64 {
    (data_len as u64) * 2 + 4096
}

// ---------------------------------------------------------------------------
// Bounds-checked reader (no slicing panics: every access is a checked get)
// ---------------------------------------------------------------------------

struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    /// True when `need` bytes at `off` are inside the buffer (overflow-free).
    fn fits(&self, off: u64, need: u64) -> bool {
        let len = self.data.len() as u64;
        off <= len && need <= len - off
    }

    fn u8(&self, off: u64) -> Option<u8> {
        self.data.get(off as usize).copied()
    }

    fn u16le(&self, off: u64) -> Option<u16> {
        let b = self.bytes(off, 2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u16be(&self, off: u64) -> Option<u16> {
        let b = self.bytes(off, 2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32le(&self, off: u64) -> Option<u32> {
        let b = self.bytes(off, 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u32be(&self, off: u64) -> Option<u32> {
        let b = self.bytes(off, 4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn bytes(&self, off: u64, len: u64) -> Option<&'a [u8]> {
        let start = usize::try_from(off).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        self.data.get(start..end)
    }

    /// Printable-ASCII rendering of a range; unprintable bytes become '.'.
    fn ascii(&self, off: u64, len: u64, cap: usize) -> String {
        let Some(bytes) = self.bytes(off, len) else {
            return String::new();
        };
        bytes
            .iter()
            .take(cap)
            .map(|&b| {
                if (0x20..=0x7E).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect()
    }

    fn chunk_header(&self, pos: u64) -> Option<(u32, [u8; 4])> {
        let length = self.u32be(pos)?;
        let raw = self.bytes(pos + 4, 4)?;
        let mut kind = [0u8; 4];
        kind.copy_from_slice(raw);
        Some((length, kind))
    }
}

/// PNG CRC-32 (IEEE, reflected, poly 0xEDB88320) over type + data.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// ---------------------------------------------------------------------------
// Report builder (bounded warnings + truncation marker)
// ---------------------------------------------------------------------------

struct Report {
    root: Json,
    warnings: Vec<String>,
    truncated: bool,
    warnings_dropped: bool,
}

impl Report {
    fn new(format: &'static str, size: usize) -> Self {
        Report {
            root: json!({ "format": format, "file_size": size }),
            warnings: Vec::new(),
            truncated: false,
            warnings_dropped: false,
        }
    }

    fn warn(&mut self, message: impl Into<String>) {
        if self.warnings.len() < MAX_WARNINGS {
            self.warnings.push(message.into());
        } else {
            self.warnings_dropped = true;
        }
    }

    /// Records the "truncated at offset N" style marker: the walk stopped
    /// early on malformed input, but everything found so far is kept.
    fn truncate_at(&mut self, message: impl Into<String>) {
        self.truncated = true;
        self.warn(message);
    }

    fn finish(mut self, complete: bool, expected_end: Option<u64>, data: &[u8]) -> Json {
        self.root["complete"] = json!(complete);
        self.root["expected_end"] = json!(expected_end);
        self.root["appended"] = appended_json(data, expected_end);
        if self.warnings_dropped {
            self.warnings.push("further warnings suppressed".to_owned());
        }
        self.root["truncated"] = json!(self.truncated);
        self.root["warnings"] = json!(self.warnings);
        self.root
    }
}

// ---------------------------------------------------------------------------
// Format detection + dispatch
// ---------------------------------------------------------------------------

/// The four containers this module understands structurally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContainerFormat {
    Png,
    Jpeg,
    Gif,
    Bmp,
}

impl ContainerFormat {
    /// Stable identifier used in reports (`"png"`, `"jpeg"`, ...).
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            ContainerFormat::Png => "png",
            ContainerFormat::Jpeg => "jpeg",
            ContainerFormat::Gif => "gif",
            ContainerFormat::Bmp => "bmp",
        }
    }
}

/// Sniffs the container magic (never decodes pixels).
#[must_use]
pub fn detect_format(data: &[u8]) -> Option<ContainerFormat> {
    if data.starts_with(&PNG_SIGNATURE) {
        Some(ContainerFormat::Png)
    } else if data.starts_with(&[0xFF, 0xD8]) {
        Some(ContainerFormat::Jpeg)
    } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        Some(ContainerFormat::Gif)
    } else if data.starts_with(b"BM") {
        Some(ContainerFormat::Bmp)
    } else {
        None
    }
}

/// Runs the analyzer for the detected format, or `None` for unknown magic.
#[must_use]
pub fn analyze_any(data: &[u8]) -> Option<(ContainerFormat, Json)> {
    let format = detect_format(data)?;
    let report = match format {
        ContainerFormat::Png => analyze_png(data),
        ContainerFormat::Jpeg => analyze_jpeg(data),
        ContainerFormat::Gif => analyze_gif(data),
        ContainerFormat::Bmp => analyze_bmp(data),
    };
    Some((format, report))
}

// ---------------------------------------------------------------------------
// PNG
// ---------------------------------------------------------------------------

/// Structural analysis of a PNG stream: chunk walk with per-chunk CRC check,
/// IHDR details, palette, text comments and the logical EOF at IEND.
#[must_use]
pub fn analyze_png(data: &[u8]) -> Json {
    let reader = Reader::new(data);
    let mut report = Report::new("png", data.len());
    let signature_valid = data.starts_with(&PNG_SIGNATURE);
    report.root["signature_valid"] = json!(signature_valid);
    if data.len() < 8 {
        report.warn("File is shorter than the 8-byte PNG signature");
        return report.finish(false, None, data);
    }
    if !signature_valid {
        report.warn("PNG signature bytes are wrong");
    }

    let mut pos: u64 = 8;
    let mut chunks: Vec<Json> = Vec::new();
    let mut comments: Vec<Json> = Vec::new();
    let mut comments_dropped = false;
    let mut ihdr: Option<Json> = None;
    let mut palette: Option<Json> = None;
    let mut idat_chunks: u64 = 0;
    let mut idat_bytes: u64 = 0;
    let mut saw_iend = false;
    let mut expected_end: Option<u64> = None;
    let mut entries_truncated = false;
    let mut last_type = String::new();

    while pos < reader.len() as u64 && !saw_iend {
        if chunks.len() >= MAX_ENTRIES {
            entries_truncated = true;
            report.warn(format!(
                "Report truncated at {MAX_ENTRIES} chunks; further details omitted"
            ));
            break;
        }
        let Some((length, kind)) = reader.chunk_header(pos) else {
            report.truncate_at(format!(
                "truncated at offset {pos}: incomplete chunk header"
            ));
            break;
        };
        let kind_str: String = String::from_utf8_lossy(&kind).into_owned();
        let data_start = pos + 8;
        if !reader.fits(data_start, u64::from(length) + 4) {
            let available = reader.len().saturating_sub(data_start as usize);
            report.truncate_at(format!(
                "truncated at offset {pos}: chunk '{kind_str}' declares {length} data bytes but only {available} bytes follow the header"
            ));
            break;
        }

        let Some(crc_stored) = reader.u32be(data_start + u64::from(length)) else {
            break;
        };
        let crc_body = reader.bytes(pos + 4, u64::from(length) + 4);
        let crc_computed = crc32(crc_body.unwrap_or(&[]));
        let crc_valid = crc_stored == crc_computed;
        if !crc_valid {
            report.warn(format!(
                "CRC mismatch in chunk '{kind_str}' at offset {pos} (stored {crc_stored:08x}, computed {crc_computed:08x})"
            ));
        }

        let mut entry = json!({
            "index": chunks.len() + 1,
            "type": kind_str,
            "offset": pos,
            "length": length,
            "data_offset": data_start,
            "crc": format!("{crc_stored:08x}"),
            "crc_valid": crc_valid,
        });
        let (flags, flag_warning) = chunk_flags(&kind_str);
        entry["flags"] = flags;
        if let Some(message) = flag_warning {
            report.warn(message);
        }

        match &kind {
            b"IHDR" => {
                let parsed = png_ihdr(&reader, data_start, length);
                match parsed {
                    Some((value, warnings)) => {
                        for message in warnings {
                            report.warn(message);
                        }
                        ihdr = Some(value);
                    }
                    None => report.warn(format!(
                        "IHDR must be 13 bytes long but declares {length} bytes"
                    )),
                }
            }
            b"PLTE" => {
                let parsed = png_plte(&reader, data_start, length);
                if let Some(warning) = parsed.warning {
                    report.warn(warning);
                }
                palette = Some(parsed.value);
            }
            b"IDAT" => {
                idat_chunks += 1;
                idat_bytes += u64::from(length);
            }
            b"IEND" => {
                saw_iend = true;
                expected_end = Some(data_start + u64::from(length) + 4);
                if length != 0 {
                    report.warn(format!(
                        "IEND chunk declares {length} bytes of data, it must be empty"
                    ));
                }
            }
            b"tEXt" | b"zTXt" | b"iTXt" => {
                let payload = reader.bytes(data_start, u64::from(length)).unwrap_or(&[]);
                if comments.len() < MAX_COMMENTS {
                    if let Some(comment) = png_text_comment(&kind, payload) {
                        comments.push(comment);
                    }
                } else {
                    comments_dropped = true;
                }
            }
            b"tIME" if length >= 7 => {
                if let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(s)) = (
                    reader.u16be(data_start),
                    reader.u8(data_start + 2),
                    reader.u8(data_start + 3),
                    reader.u8(data_start + 4),
                    reader.u8(data_start + 5),
                    reader.u8(data_start + 6),
                ) {
                    entry["timestamp"] =
                        json!(format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}"));
                }
            }
            b"pHYs" if length >= 9 => {
                entry["pixels_per_unit_x"] = json!(reader.u32be(data_start));
                entry["pixels_per_unit_y"] = json!(reader.u32be(data_start + 4));
                entry["unit"] = json!(if reader.u8(data_start + 8) == Some(1) {
                    "metre"
                } else {
                    "unknown"
                });
            }
            _ => {}
        }

        chunks.push(entry);
        last_type = kind_str;
        pos = data_start + u64::from(length) + 4;
    }

    report.root["chunks"] = json!(chunks);
    report.root["chunk_count"] = json!(chunks.len());
    report.root["entries_truncated"] = json!(entries_truncated);
    report.root["comments"] = json!(comments);
    report.root["comments_dropped"] = json!(comments_dropped);
    report.root["ihdr"] = ihdr.unwrap_or(Json::Null);
    report.root["palette"] = palette.unwrap_or(Json::Null);
    report.root["idat"] = json!({ "chunks": idat_chunks, "bytes": idat_bytes });
    report.root["last_chunk"] = json!(last_type);

    let complete = saw_iend;
    if !saw_iend {
        report.truncate_at(
            "No IEND chunk found: the file may be truncated or data may have been appended",
        );
    } else if let Some(end) = expected_end {
        if end < reader.len() as u64 {
            report.warn(format!(
                "{} bytes appended after the IEND chunk",
                reader.len() as u64 - end
            ));
        }
    }
    report.finish(complete, expected_end, data)
}

fn png_ihdr(reader: &Reader, data_start: u64, length: u32) -> Option<(Json, Vec<String>)> {
    if length < 13 {
        return None;
    }
    let mut warnings = Vec::new();
    let width = reader.u32be(data_start)?;
    let height = reader.u32be(data_start + 4)?;
    let bit_depth = reader.u8(data_start + 8)?;
    let color_type = reader.u8(data_start + 9)?;
    let compression = reader.u8(data_start + 10)?;
    let filter = reader.u8(data_start + 11)?;
    let interlace = reader.u8(data_start + 12)?;

    if width == 0 || height == 0 {
        warnings.push(format!("IHDR declares an empty image: {width}x{height}"));
    }
    if compression != 0 {
        warnings.push(format!("Unknown compression method {compression} in IHDR"));
    }
    if filter != 0 {
        warnings.push(format!("Unknown filter method {filter} in IHDR"));
    }
    if !png_valid_depth(bit_depth, color_type) {
        warnings.push(format!(
            "Bit depth {bit_depth} is not valid for colour type {color_type}"
        ));
    }
    let mut value = json!({
        "width": width,
        "height": height,
        "bit_depth": bit_depth,
        "color_type": color_type,
        "color_type_name": png_color_type_name(color_type),
        "compression": compression,
        "filter": filter,
        "interlace": interlace,
        "interlace_name": match interlace {
            0 => "none",
            1 => "Adam7",
            _ => "unknown",
        },
    });
    let channels: i32 = match color_type {
        0 => 1,
        2 => 3,
        3 => 1,
        4 => 2,
        6 => 4,
        _ => -1,
    };
    if channels > 0 && width > 0 && height > 0 {
        // Hostile headers can declare enormous dimensions: every product is
        // checked so the estimate can never overflow.
        match u64::from(width).checked_mul(u64::from(height)) {
            Some(pixels) => {
                let raw_data_bytes = pixels
                    .checked_mul(channels as u64)
                    .and_then(|bits| bits.checked_mul(u64::from(bit_depth)))
                    .map(|bits| bits.div_ceil(8));
                value["pixels"] = json!(pixels);
                value["raw_data_bytes"] = json!(raw_data_bytes);
                if pixels > 500_000_000 {
                    warnings.push(format!(
                        "IHDR claims an implausibly large image ({pixels} pixels)"
                    ));
                }
            }
            None => warnings
                .push("IHDR dimensions overflow; the declared image is impossible".to_owned()),
        }
    }
    if length > 13 {
        warnings.push(format!(
            "IHDR must be 13 bytes long but declares {length} bytes"
        ));
    }
    Some((value, warnings))
}

fn png_color_type_name(color_type: u8) -> &'static str {
    match color_type {
        0 => "grayscale",
        2 => "truecolour",
        3 => "palette",
        4 => "grayscale + alpha",
        6 => "truecolour + alpha",
        _ => "invalid",
    }
}

fn png_valid_depth(bit_depth: u8, color_type: u8) -> bool {
    match color_type {
        0 => matches!(bit_depth, 1 | 2 | 4 | 8 | 16),
        2 | 4 | 6 => matches!(bit_depth, 8 | 16),
        3 => matches!(bit_depth, 1 | 2 | 4 | 8),
        _ => false,
    }
}

fn png_plte(reader: &Reader, data_start: u64, length: u32) -> ParsedPalette {
    let mut warning = None;
    if !length.is_multiple_of(3) {
        warning = Some(format!("PLTE length {length} is not a multiple of 3"));
    }
    let entries = length / 3;
    if entries > 256 {
        warning = Some(format!("PLTE declares more than 256 entries ({entries})"));
    }
    let listed = (entries as usize).min(MAX_PALETTE_ENTRIES_LISTED);
    let mut sample = Vec::with_capacity(listed);
    for i in 0..listed as u64 {
        let at = data_start + i * 3;
        let r = reader.u8(at);
        let g = reader.u8(at + 1);
        let b = reader.u8(at + 2);
        if let (Some(r), Some(g), Some(b)) = (r, g, b) {
            sample.push(json!([r, g, b]));
        }
    }
    ParsedPalette {
        value: json!({
            "entries": entries,
            "sample": sample,
            "sample_omitted": (entries as usize).saturating_sub(MAX_PALETTE_ENTRIES_LISTED),
        }),
        warning,
    }
}

struct ParsedPalette {
    value: Json,
    warning: Option<String>,
}

/// Extracts a bounded comment from a tEXt/zTXt/iTXt payload.
fn png_text_comment(kind: &[u8; 4], payload: &[u8]) -> Option<Json> {
    let nul = payload.iter().position(|&b| b == 0)?;
    let keyword = bounded_lossy(&payload[..nul]);
    let rest = &payload[nul + 1..];
    let mut comment = json!({
        "chunk": String::from_utf8_lossy(kind),
        "keyword": keyword,
    });
    match kind {
        b"tEXt" => {
            let (text, truncated) = bounded_text(rest);
            comment["text"] = json!(text);
            comment["text_truncated"] = json!(truncated);
        }
        b"zTXt" => {
            comment["compressed"] = json!(true);
            let method = *rest.first()?;
            comment["compression_method"] = json!(method);
            if method == 0 {
                let (text, truncated, error) = inflate_bounded(&rest[1..]);
                comment["text"] = json!(text);
                comment["text_truncated"] = json!(truncated);
                if let Some(error) = error {
                    comment["decompression_error"] = json!(error);
                }
            } else {
                comment["decompression_error"] = json!("unknown compression method");
            }
        }
        b"iTXt" => {
            let flag = *rest.first()?;
            let method = *rest.get(1)?;
            comment["compression_method"] = json!(method);
            let after_method = &rest[2..];
            let lang_end = after_method.iter().position(|&b| b == 0)?;
            comment["language"] = json!(bounded_lossy(&after_method[..lang_end]));
            let after_lang = &after_method[lang_end + 1..];
            let translated_end = after_lang.iter().position(|&b| b == 0)?;
            comment["translated_keyword"] = json!(bounded_lossy(&after_lang[..translated_end]));
            let text_bytes = &after_lang[translated_end + 1..];
            if flag == 1 {
                comment["compressed"] = json!(true);
                let (text, truncated, error) = inflate_bounded(text_bytes);
                comment["text"] = json!(text);
                comment["text_truncated"] = json!(truncated);
                if let Some(error) = error {
                    comment["decompression_error"] = json!(error);
                }
            } else {
                let (text, truncated) = bounded_text(text_bytes);
                comment["text"] = json!(text);
                comment["text_truncated"] = json!(truncated);
            }
        }
        _ => return None,
    }
    Some(comment)
}

/// Lossy UTF-8 rendering capped at [`MAX_TEXT_BYTES`]; returns the text and
/// whether bytes were cut off.
fn bounded_text(bytes: &[u8]) -> (String, bool) {
    let truncated = bytes.len() > MAX_TEXT_BYTES;
    let capped = if truncated {
        &bytes[..MAX_TEXT_BYTES]
    } else {
        bytes
    };
    (String::from_utf8_lossy(capped).into_owned(), truncated)
}

fn bounded_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Inflates a zlib stream, returning at most [`MAX_TEXT_BYTES`] bytes of
/// lossy text plus whether the stream was cut short (a bounded answer to a
/// hostile decompression bomb). The third element is a zlib error message.
fn inflate_bounded(data: &[u8]) -> (String, bool, Option<String>) {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    let mut decoder = ZlibDecoder::new(data);
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        match decoder.read(&mut buf) {
            Ok(0) => return (bounded_lossy(&out), false, None),
            Ok(n) => {
                let room = MAX_TEXT_BYTES - out.len();
                let take = n.min(room);
                out.extend_from_slice(&buf[..take]);
                if out.len() == MAX_TEXT_BYTES {
                    let mut probe = [0u8; 1];
                    let more = decoder.read(&mut probe).map(|n| n > 0).unwrap_or(true);
                    return (bounded_lossy(&out), more, None);
                }
            }
            Err(e) => {
                let text = bounded_lossy(&out);
                return (text, !out.is_empty(), Some(e.to_string()));
            }
        }
    }
}

/// The four properties encoded in the case of the chunk type letters, plus
/// the well-known chunk description. Returns an optional warning for a
/// forbidden reserved bit (third letter must be upper case).
fn chunk_flags(kind: &str) -> (Json, Option<String>) {
    let bytes = kind.as_bytes();
    if bytes.len() != 4 || !bytes.iter().all(u8::is_ascii_alphabetic) {
        return (
            json!({ "valid_type": false }),
            Some(format!("Chunk type '{kind}' is not four ASCII letters")),
        );
    }
    let critical = bytes[0].is_ascii_uppercase();
    let public = bytes[1].is_ascii_uppercase();
    let reserved_valid = bytes[2].is_ascii_uppercase();
    let safe_to_copy = bytes[3].is_ascii_lowercase();
    let warning = if reserved_valid {
        None
    } else {
        Some(format!(
            "Chunk '{kind}' has the reserved bit set (third letter must be upper case), which the specification forbids"
        ))
    };
    (
        json!({
            "critical": critical,
            "public": public,
            "reserved_bit_valid": reserved_valid,
            "safe_to_copy": safe_to_copy,
            "description": describe_chunk(kind),
        }),
        warning,
    )
}

fn describe_chunk(kind: &str) -> Option<&'static str> {
    match kind {
        "IHDR" => Some("Image header"),
        "PLTE" => Some("Palette"),
        "IDAT" => Some("Image data (zlib compressed)"),
        "IEND" => Some("Image end"),
        "tRNS" => Some("Transparency"),
        "gAMA" => Some("Image gamma"),
        "cHRM" => Some("Primary chromaticities and white point"),
        "sRGB" => Some("Standard RGB colour space"),
        "iCCP" => Some("Embedded ICC profile"),
        "sBIT" => Some("Significant bits"),
        "bKGD" => Some("Background colour"),
        "hIST" => Some("Palette histogram"),
        "pHYs" => Some("Physical pixel dimensions"),
        "sPLT" => Some("Suggested palette"),
        "tIME" => Some("Last modification time"),
        "tEXt" => Some("Uncompressed text"),
        "zTXt" => Some("Compressed text"),
        "iTXt" => Some("International text"),
        "acTL" => Some("APNG animation control"),
        "fcTL" => Some("APNG frame control"),
        "fdAT" => Some("APNG frame data"),
        "eXIf" => Some("Exif metadata"),
        "cICP" => Some("Coding independent code points"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// JPEG
// ---------------------------------------------------------------------------

const SOF_MARKERS: [u8; 13] = [
    0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF,
];

/// Structural analysis of a JPEG stream: marker walk with segment
/// offsets/lengths, APPn identifiers, SOF geometry and the entropy-coded
/// scan walked with `FF00`/RST handling; logical EOF at EOI.
#[must_use]
pub fn analyze_jpeg(data: &[u8]) -> Json {
    let reader = Reader::new(data);
    let mut report = Report::new("jpeg", data.len());
    let signature_valid = data.len() >= 2 && data[0] == 0xFF && data[1] == 0xD8;
    report.root["signature_valid"] = json!(signature_valid);
    let mut pos: u64 = if signature_valid {
        2
    } else {
        report.warn("File does not start with the SOI marker");
        0
    };

    let mut segments: Vec<Json> = Vec::new();
    let mut comments: Vec<Json> = Vec::new();
    let mut comments_dropped = false;
    let mut frame: Option<Json> = None;
    let mut scan: Option<Json> = None;
    let mut saw_eoi = false;
    let mut expected_end: Option<u64> = None;
    let mut entries_truncated = false;
    let mut last_marker = String::new();

    while pos < reader.len() as u64 {
        // Markers may be preceded by any number of 0xFF fill bytes.
        let mut marker_start = pos;
        while marker_start < reader.len() as u64 && reader.u8(marker_start) == Some(0xFF) {
            marker_start += 1;
        }
        let Some(marker) = reader.u8(marker_start) else {
            break;
        };
        match marker {
            0x00 => {
                report.warn(format!(
                    "Stray 0xFF00 sequence outside scan data at offset {pos}"
                ));
                pos = marker_start + 1;
                continue;
            }
            0xD9 => {
                saw_eoi = true;
                // EOI is exactly FF D9: the code byte plus its fill byte.
                expected_end = Some(marker_start + 1);
                last_marker = "EOI".to_owned();
                break;
            }
            0xD8 => {
                report.warn(format!(
                    "Unexpected second SOI marker at offset {marker_start}"
                ));
                pos = marker_start + 1;
                continue;
            }
            0xD0..=0xD7 => {
                report.warn(format!(
                    "Restart marker RST{} outside scan data at offset {marker_start}",
                    marker - 0xD0
                ));
                pos = marker_start + 1;
                continue;
            }
            _ => {}
        }

        if segments.len() >= MAX_ENTRIES {
            entries_truncated = true;
            report.warn(format!(
                "Report truncated at {MAX_ENTRIES} segments; further details omitted"
            ));
            break;
        }
        let Some(seg_len) = reader.u16be(marker_start + 1) else {
            report.truncate_at(format!(
                "truncated at offset {marker_start}: segment FF{marker:02X} has no length field"
            ));
            break;
        };
        if seg_len < 2 {
            report.truncate_at(format!(
                "truncated at offset {marker_start}: segment FF{marker:02X} declares an impossible length of {seg_len}"
            ));
            break;
        }
        let data_start = marker_start + 3;
        let data_len = u64::from(seg_len) - 2;
        if !reader.fits(data_start, data_len) {
            let available = reader.len().saturating_sub(data_start as usize);
            report.truncate_at(format!(
                "truncated at offset {marker_start}: segment FF{marker:02X} declares {data_len} data bytes but only {available} are available"
            ));
            break;
        }

        let mut entry = json!({
            "index": segments.len() + 1,
            "marker": marker_name(marker),
            "marker_byte": marker,
            "offset": marker_start,
            "length": seg_len,
            "data_offset": data_start,
            "data_length": data_len,
        });
        last_marker = marker_name(marker);

        if SOF_MARKERS.contains(&marker) {
            frame = jpeg_frame(&reader, marker, data_start, data_len);
            if let Some(frame) = &frame {
                if let Some(warnings) = frame["warnings"].as_array() {
                    for message in warnings {
                        if let Some(text) = message.as_str() {
                            report.warn(text);
                        }
                    }
                }
                entry["frame_type"] = frame["frame_type"].clone();
            }
        }
        match marker {
            0xDD if data_len >= 2 => {
                entry["restart_interval"] = json!(reader.u16be(data_start));
            }
            0xDC if data_len >= 2 => {
                entry["number_of_lines"] = json!(reader.u16be(data_start));
            }
            0xDA => {
                if data_len >= 1 {
                    entry["components_in_scan"] = json!(reader.u8(data_start));
                }
                let scan_start = data_start + data_len;
                let scan_end = jpeg_find_scan_end(&reader, scan_start, &mut report);
                let terminated = scan_end < reader.len() as u64;
                if !terminated {
                    report
                        .warn("Scan data runs to the end of the file without a terminating marker");
                }
                scan = Some(json!({
                    "offset": scan_start,
                    "bytes": scan_end.saturating_sub(scan_start),
                    "end": scan_end,
                    "terminated": terminated,
                }));
                entry["scan_bytes"] = json!(scan_end.saturating_sub(scan_start));
                pos = scan_end;
                segments.push(entry);
                continue;
            }
            0xE0..=0xEF => {
                entry["identifier"] = json!(jpeg_app_identifier(&reader, data_start, data_len));
            }
            0xFE => {
                let text = reader.ascii(data_start, data_len, MAX_TEXT_BYTES);
                if comments.len() < MAX_COMMENTS {
                    comments.push(json!({
                        "kind": "COM",
                        "offset": marker_start,
                        "length": data_len,
                        "text": text,
                        "text_truncated": data_len > MAX_TEXT_BYTES as u64,
                    }));
                } else {
                    comments_dropped = true;
                }
            }
            _ => {}
        }

        segments.push(entry);
        pos = data_start + data_len;
    }

    report.root["segments"] = json!(segments);
    report.root["segment_count"] = json!(segments.len());
    report.root["entries_truncated"] = json!(entries_truncated);
    report.root["comments"] = json!(comments);
    report.root["comments_dropped"] = json!(comments_dropped);
    report.root["frame"] = frame
        .map(|mut f| {
            f.as_object_mut().map(|o| o.remove("warnings"));
            f
        })
        .unwrap_or(Json::Null);
    report.root["scan"] = scan.unwrap_or(Json::Null);
    report.root["eoi_offset"] = json!(expected_end.map(|e| e - 2));
    report.root["last_marker"] = json!(last_marker);

    let complete = saw_eoi;
    if !saw_eoi {
        report
            .truncate_at("No EOI marker found: the file is truncated or padded with foreign data");
    } else if let Some(end) = expected_end {
        if end < reader.len() as u64 {
            report.warn(format!(
                "{} bytes appended after the end of the JPEG stream",
                reader.len() as u64 - end
            ));
        }
    }
    report.finish(complete, expected_end, data)
}

fn jpeg_frame(reader: &Reader, marker: u8, data_start: u64, data_len: u64) -> Option<Json> {
    let mut warnings = Vec::new();
    if data_len < 6 {
        warnings.push("Frame header is too short to contain the image geometry".to_owned());
        return Some(json!({
            "marker": marker_name(marker),
            "frame_type": jpeg_frame_type(marker),
            "warnings": warnings,
        }));
    }
    let precision = reader.u8(data_start)?;
    let height = reader.u16be(data_start + 1)?;
    let width = reader.u16be(data_start + 3)?;
    let components = reader.u8(data_start + 5)?;
    if width == 0 || height == 0 {
        warnings.push(format!("Frame declares an empty image: {width}x{height}"));
    }
    let mut component_list = Vec::new();
    let mut component_warnings = 0;
    for i in 0..u64::from(components) {
        let offset = data_start + 6 + i * 3;
        if !reader.fits(offset, 3) || offset + 3 > data_start + data_len {
            component_warnings += 1;
            break;
        }
        if component_list.len() < 16 {
            component_list.push(json!({
                "id": reader.u8(offset),
                "sampling": format!(
                    "{}x{}",
                    reader.u8(offset + 1).unwrap_or(0) >> 4,
                    reader.u8(offset + 1).unwrap_or(0) & 0x0F
                ),
                "quantisation_table": reader.u8(offset + 2),
            }));
        }
    }
    if component_warnings > 0 {
        warnings.push("Component descriptors are missing from the frame header".to_owned());
    }
    let expected_minimum = 6 + u64::from(components) * 3;
    if data_len < expected_minimum {
        warnings.push(format!(
            "Frame header declares {components} components but only contains {data_len} bytes of data (expected at least {expected_minimum})"
        ));
    }
    Some(json!({
        "marker": marker_name(marker),
        "frame_type": jpeg_frame_type(marker),
        "coding": if marker < 0xC8 { "Huffman" } else { "arithmetic" },
        "precision": precision,
        "width": width,
        "height": height,
        "components": components,
        "component_list": component_list,
        "warnings": warnings,
    }))
}

/// Finds the next real marker after the entropy-coded data, honouring `FF00`
/// byte stuffing and restart markers. Bounded by a step cap so hostile data
/// cannot spin; returns the file size when no marker follows.
fn jpeg_find_scan_end(reader: &Reader, start: u64, report: &mut Report) -> u64 {
    let len = reader.len() as u64;
    let cap = step_cap(reader.len());
    let mut index = start;
    let mut steps = 0u64;
    while index + 1 < len {
        steps += 1;
        if steps > cap {
            report.truncate_at(format!(
                "truncated at offset {index}: entropy-scan walk exceeded its step cap"
            ));
            return len;
        }
        let Some(byte) = reader.u8(index) else {
            return len;
        };
        if byte != 0xFF {
            index += 1;
            continue;
        }
        let Some(next) = reader.u8(index + 1) else {
            return len;
        };
        if next == 0x00 || (0xD0..=0xD7).contains(&next) {
            index += 2;
        } else if next == 0xFF {
            index += 1;
        } else {
            return index;
        }
    }
    len
}

fn jpeg_app_identifier(reader: &Reader, data_start: u64, data_len: u64) -> Option<String> {
    let probe_len = data_len.min(32);
    let raw = reader.bytes(data_start, probe_len)?;
    let has_prefix = |sig: &[u8]| raw.starts_with(sig);
    let name = if has_prefix(b"JFIF\0") {
        "JFIF".to_owned()
    } else if has_prefix(b"JFXX\0") {
        "JFXX".to_owned()
    } else if has_prefix(b"Exif\0\0") {
        "Exif".to_owned()
    } else if has_prefix(b"ICC_PROFILE\0") {
        "ICC profile".to_owned()
    } else if has_prefix(b"Photoshop 3.0\0") {
        "Photoshop IRB".to_owned()
    } else if has_prefix(b"Adobe\0") {
        "Adobe".to_owned()
    } else if has_prefix(b"http://ns.adobe.com/xap/1.0/\0") {
        "XMP".to_owned()
    } else {
        return None;
    };
    Some(name)
}

fn jpeg_frame_type(marker: u8) -> &'static str {
    match marker {
        0xC0 => "baseline DCT",
        0xC1 => "extended sequential DCT",
        0xC2 => "progressive DCT",
        0xC3 => "lossless (sequential)",
        0xC5 => "differential sequential DCT",
        0xC6 => "differential progressive DCT",
        0xC7 => "differential lossless",
        0xC9 => "extended sequential DCT (arithmetic)",
        0xCA => "progressive DCT (arithmetic)",
        0xCB => "lossless (arithmetic)",
        0xCD => "differential sequential DCT (arithmetic)",
        0xCE => "differential progressive DCT (arithmetic)",
        0xCF => "differential lossless (arithmetic)",
        _ => "unknown frame type",
    }
}

fn marker_name(marker: u8) -> String {
    match marker {
        0xD8 => "SOI".to_owned(),
        0xD9 => "EOI".to_owned(),
        0xDA => "SOS".to_owned(),
        0xDB => "DQT".to_owned(),
        0xC4 => "DHT".to_owned(),
        0xCC => "DAC".to_owned(),
        0xDD => "DRI".to_owned(),
        0xDC => "DNL".to_owned(),
        0xDE => "DHP".to_owned(),
        0xDF => "EXP".to_owned(),
        0xFE => "COM".to_owned(),
        0xC0..=0xCF => format!("SOF{}", marker - 0xC0),
        0xE0..=0xEF => format!("APP{}", marker - 0xE0),
        _ => format!("FF{marker:02X}"),
    }
}

// ---------------------------------------------------------------------------
// GIF
// ---------------------------------------------------------------------------

/// Structural analysis of a GIF stream: logical screen descriptor, colour
/// tables, image descriptors (with the LZW minimum-code-size offset) and
/// extension blocks; logical EOF at the 0x3B trailer.
#[must_use]
pub fn analyze_gif(data: &[u8]) -> Json {
    let reader = Reader::new(data);
    let mut report = Report::new("gif", data.len());
    if data.len() < 13 {
        report.root["signature_valid"] = json!(data.starts_with(b"GIF8"));
        report.warn("File is too short to contain a GIF logical screen descriptor");
        return report.finish(false, None, data);
    }
    let version = reader.ascii(0, 6, 6);
    let signature_valid = version == "GIF87a" || version == "GIF89a";
    report.root["signature_valid"] = json!(signature_valid);
    if !signature_valid {
        report.warn(format!(
            "GIF version string is not GIF87a/GIF89a: '{version}'"
        ));
    }
    let width = reader.u16le(6);
    let height = reader.u16le(8);
    let flags = reader.u8(10);
    let background = reader.u8(11);
    let aspect = reader.u8(12);
    let (Some(width), Some(height), Some(flags)) = (width, height, flags) else {
        report.truncate_at("truncated at offset 13: incomplete logical screen descriptor");
        return report.finish(false, None, data);
    };
    let gct_entries = if flags & 0x80 != 0 {
        1u64 << ((flags & 0x07) + 1)
    } else {
        0
    };
    report.root["version"] = json!(version);
    report.root["screen"] = json!({
        "width": width,
        "height": height,
        "background_color_index": background,
        "pixel_aspect_ratio": aspect,
        "flags": flags,
        "color_resolution_bits": ((flags >> 4) & 0x07) + 1,
        "global_color_table_sorted": flags & 0x10 != 0,
        "global_color_table_entries": gct_entries,
    });

    let mut pos: u64 = 13;
    if gct_entries > 0 {
        if !reader.fits(pos, gct_entries * 3) {
            report.truncate_at(format!(
                "truncated at offset {pos}: global colour table declares {gct_entries} entries but the file ends first"
            ));
            return report.finish(false, None, data);
        }
        report.root["global_color_table"] = gif_palette(&reader, pos, gct_entries);
        pos += gct_entries * 3;
    }

    let mut blocks: Vec<Json> = Vec::new();
    let mut comments: Vec<Json> = Vec::new();
    let mut comments_dropped = false;
    let mut frames: u64 = 0;
    let mut saw_trailer = false;
    let mut expected_end: Option<u64> = None;
    let mut entries_truncated = false;

    while pos < reader.len() as u64 {
        if blocks.len() >= MAX_ENTRIES {
            entries_truncated = true;
            report.warn(format!(
                "Report truncated at {MAX_ENTRIES} blocks; further details omitted"
            ));
            break;
        }
        let Some(introducer) = reader.u8(pos) else {
            break;
        };
        match introducer {
            0x3B => {
                saw_trailer = true;
                expected_end = Some(pos + 1);
                report.root["trailer_offset"] = json!(pos);
                break;
            }
            0x2C => {
                let Some(descriptor) =
                    gif_image_descriptor(&reader, pos, width, height, &mut report, &mut frames)
                else {
                    report.truncate_at(format!(
                        "truncated at offset {pos}: image descriptor or its data runs past the end of the file"
                    ));
                    break;
                };
                pos = descriptor["end_offset"].as_u64().unwrap_or(pos);
                blocks.push(descriptor);
            }
            0x21 => {
                let Some(label) = reader.u8(pos + 1) else {
                    report.truncate_at(format!(
                        "truncated at offset {pos}: extension introducer has no label"
                    ));
                    break;
                };
                let Some((entry, end, comment)) =
                    gif_extension(&reader, pos, label, &mut comments, &mut comments_dropped)
                else {
                    report.truncate_at(format!(
                        "truncated at offset {pos}: extension 0x{label:02x} runs past the end of the file"
                    ));
                    break;
                };
                if let Some(comment) = comment {
                    report.warn(comment);
                }
                pos = end;
                blocks.push(entry);
            }
            other => {
                report.truncate_at(format!(
                    "truncated at offset {pos}: unrecognised block introducer 0x{other:02x}"
                ));
                break;
            }
        }
    }

    report.root["blocks"] = json!(blocks);
    report.root["block_count"] = json!(blocks.len());
    report.root["entries_truncated"] = json!(entries_truncated);
    report.root["comments"] = json!(comments);
    report.root["comments_dropped"] = json!(comments_dropped);
    report.root["frames"] = json!(frames);

    let complete = saw_trailer;
    if !saw_trailer {
        report.truncate_at("No trailer block found: the GIF is truncated");
    } else if let Some(end) = expected_end {
        if end < reader.len() as u64 {
            report.warn(format!(
                "{} bytes appended after the GIF trailer",
                reader.len() as u64 - end
            ));
        }
    }
    report.finish(complete, expected_end, data)
}

fn gif_palette(reader: &Reader, offset: u64, entries: u64) -> Json {
    let listed = (entries as usize).min(MAX_PALETTE_ENTRIES_LISTED);
    let mut sample = Vec::with_capacity(listed);
    let mut duplicates = 0u64;
    let mut previous: Option<[u8; 3]> = None;
    for i in 0..entries {
        let at = offset + i * 3;
        let rgb = match (reader.u8(at), reader.u8(at + 1), reader.u8(at + 2)) {
            (Some(r), Some(g), Some(b)) => [r, g, b],
            _ => break,
        };
        if let Some(prev) = previous {
            if prev == rgb {
                duplicates += 1;
            }
        }
        previous = Some(rgb);
        if (i as usize) < listed {
            sample.push(json!([rgb[0], rgb[1], rgb[2]]));
        }
    }
    let mut value = json!({
        "entries": entries,
        "sample": sample,
        "sample_omitted": (entries as usize).saturating_sub(listed),
    });
    if duplicates > 0 {
        value["adjacent_duplicates"] = json!(duplicates);
    }
    value
}

fn gif_image_descriptor(
    reader: &Reader,
    pos: u64,
    screen_width: u16,
    screen_height: u16,
    report: &mut Report,
    frames: &mut u64,
) -> Option<Json> {
    let descriptor_offset = pos;
    if !reader.fits(pos, 10) {
        return None;
    }
    *frames += 1;
    let left = reader.u16le(pos + 1)?;
    let top = reader.u16le(pos + 3)?;
    let frame_width = reader.u16le(pos + 5)?;
    let frame_height = reader.u16le(pos + 7)?;
    let frame_flags = reader.u8(pos + 9)?;
    let interlace = frame_flags & 0x40 != 0;
    if u32::from(left) + u32::from(frame_width) > u32::from(screen_width)
        || u32::from(top) + u32::from(frame_height) > u32::from(screen_height)
    {
        report.warn(format!(
            "Frame {frames} extends past the logical screen bounds"
        ));
    }
    if frame_flags & 0x18 != 0 {
        report.warn(format!("Frame {frames} has reserved flag bits set"));
    }
    let mut pos = pos + 10;
    let mut local_color_table = None;
    if frame_flags & 0x80 != 0 {
        let lct_entries = 1u64 << ((frame_flags & 0x07) + 1);
        if !reader.fits(pos, lct_entries * 3) {
            return None;
        }
        local_color_table = Some(gif_palette(reader, pos, lct_entries));
        pos += lct_entries * 3;
    }
    let lzw_code_size_offset = pos;
    let lzw_min_code_size = reader.u8(pos)?;
    pos += 1;
    let data_start = pos;
    let (collected, end) = gif_sub_blocks(reader, data_start)?;
    let mut entry = json!({
        "type": "image",
        "index": *frames,
        "offset": descriptor_offset,
        "left": left,
        "top": top,
        "width": frame_width,
        "height": frame_height,
        "interlace": interlace,
        "flags": frame_flags,
        "lzw_min_code_size": lzw_min_code_size,
        "lzw_code_size_offset": lzw_code_size_offset,
        "compressed_bytes": end - data_start,
        "end_offset": end,
    });
    if let Some(lct) = local_color_table {
        entry["local_color_table"] = lct;
    }
    if (end - data_start).saturating_sub(1) > collected.len() as u64 {
        entry["data_preview_truncated"] = json!(true);
    }
    Some(entry)
}

fn gif_extension(
    reader: &Reader,
    pos: u64,
    label: u8,
    comments: &mut Vec<Json>,
    comments_dropped: &mut bool,
) -> Option<(Json, u64, Option<String>)> {
    match label {
        0xF9 => {
            if !reader.fits(pos + 2, 5) {
                return None;
            }
            let block_size = reader.u8(pos + 2)?;
            let gce_flags = reader.u8(pos + 3)?;
            let delay = reader.u16le(pos + 4)?;
            let transparent = if gce_flags & 0x01 != 0 {
                reader.u8(pos + 6)?
            } else {
                0
            };
            let (_, end) = gif_sub_blocks(reader, pos + 3 + u64::from(block_size))?;
            let entry = json!({
                "type": "graphic_control",
                "offset": pos,
                "block_size": block_size,
                "block_size_correct": block_size == 4,
                "disposal_method": (gce_flags >> 2) & 0x07,
                "user_input": gce_flags & 0x02 != 0,
                "transparent_color": if gce_flags & 0x01 != 0 {
                    Json::from(transparent)
                } else {
                    Json::Null
                },
                "delay_cs": delay,
                "end_offset": end,
            });
            let warning = if gce_flags & 0xE0 != 0 {
                Some("Graphic control extension has reserved flag bits set".to_owned())
            } else {
                None
            };
            Some((entry, end, warning))
        }
        0xFE => {
            let text_start = pos + 2;
            let (text, end) = gif_sub_blocks(reader, text_start)?;
            if comments.len() < MAX_COMMENTS {
                comments.push(json!({
                    "kind": "comment",
                    "offset": pos,
                    "text": String::from_utf8_lossy(&text),
                    "text_truncated": text.len() >= MAX_TEXT_BYTES,
                }));
            } else {
                *comments_dropped = true;
            }
            let entry = json!({
                "type": "comment",
                "offset": pos,
                "length": end.saturating_sub(text_start),
                "end_offset": end,
            });
            Some((entry, end, None))
        }
        0x01 => {
            if !reader.fits(pos + 2, 13) {
                return None;
            }
            let block_size = reader.u8(pos + 2)?;
            let text_start = pos + 15;
            let (text, end) = gif_sub_blocks(reader, text_start)?;
            if comments.len() < MAX_COMMENTS {
                comments.push(json!({
                    "kind": "plain_text",
                    "offset": pos,
                    "text": String::from_utf8_lossy(&text),
                    "text_truncated": text.len() >= MAX_TEXT_BYTES,
                }));
            } else {
                *comments_dropped = true;
            }
            let entry = json!({
                "type": "plain_text",
                "offset": pos,
                "block_size": block_size,
                "block_size_correct": block_size == 12,
                "grid_left": reader.u16le(pos + 3),
                "grid_top": reader.u16le(pos + 5),
                "grid_width": reader.u16le(pos + 7),
                "grid_height": reader.u16le(pos + 9),
                "cell_width": reader.u8(pos + 11),
                "cell_height": reader.u8(pos + 12),
                "text_foreground_index": reader.u8(pos + 13),
                "text_background_index": reader.u8(pos + 14),
                "end_offset": end,
            });
            Some((entry, end, None))
        }
        0xFF => {
            if !reader.fits(pos + 2, 12) {
                return None;
            }
            let block_size = reader.u8(pos + 2)?;
            let data_start = pos + 14;
            let (data, end) = gif_sub_blocks(reader, data_start)?;
            let entry = json!({
                "type": "application",
                "offset": pos,
                "block_size": block_size,
                "block_size_correct": block_size == 11,
                "identifier": reader.ascii(pos + 3, 8, 8),
                "auth_code": reader.ascii(pos + 11, 3, 3),
                "data_bytes": end.saturating_sub(data_start),
                "data_preview_hex": data.iter().take(64).map(|b| format!("{b:02x}")).collect::<String>(),
                "end_offset": end,
            });
            Some((entry, end, None))
        }
        other => {
            let (data, end) = gif_sub_blocks(reader, pos + 2)?;
            let entry = json!({
                "type": "unknown_extension",
                "offset": pos,
                "label": other,
                "length": end.saturating_sub(pos + 2),
                "data_preview_hex": data.iter().take(64).map(|b| format!("{b:02x}")).collect::<String>(),
                "end_offset": end,
            });
            Some((entry, end, None))
        }
    }
}

/// Walks a chain of GIF sub-blocks, collecting at most [`MAX_TEXT_BYTES`]
/// bytes of payload, and returns the collected bytes plus the offset after
/// the terminating zero-length block. `None` when the chain runs past the
/// end of the file or exceeds its step cap.
fn gif_sub_blocks(reader: &Reader, start: u64) -> Option<(Vec<u8>, u64)> {
    let mut pos = start;
    let mut out = Vec::new();
    let cap = step_cap(reader.len());
    let mut steps = 0u64;
    loop {
        steps += 1;
        if steps > cap {
            return None;
        }
        let size = reader.u8(pos)? as usize;
        if size == 0 {
            return Some((out, pos + 1));
        }
        if out.len() < MAX_TEXT_BYTES {
            let take = size.min(MAX_TEXT_BYTES - out.len());
            out.extend_from_slice(reader.bytes(pos + 1, take as u64)?);
        }
        pos += 1 + size as u64;
    }
}

// ---------------------------------------------------------------------------
// BMP
// ---------------------------------------------------------------------------

/// Structural analysis of a Windows bitmap: file header, DIB header (OS/2
/// core and INFO+ variants), colour table, header-to-pixels gap and the
/// pixel-array layout computed from header math and validated against the
/// real file size; logical EOF at the pixel-array end.
#[must_use]
pub fn analyze_bmp(data: &[u8]) -> Json {
    let reader = Reader::new(data);
    let mut report = Report::new("bmp", data.len());
    let signature_valid = data.starts_with(b"BM");
    report.root["signature_valid"] = json!(signature_valid);
    if data.len() < 14 {
        report.warn("File is too short to contain a BITMAPFILEHEADER");
        return report.finish(false, None, data);
    }
    let declared_size = reader.u32le(2);
    let reserved_a = reader.u16le(6);
    let reserved_b = reader.u16le(8);
    let off_bits = reader.u32le(10);
    let (Some(declared_size), Some(off_bits)) = (declared_size, off_bits) else {
        report.truncate_at("truncated at offset 14: incomplete BITMAPFILEHEADER");
        return report.finish(false, None, data);
    };
    report.root["file_header"] = json!({
        "declared_size": declared_size,
        "declared_size_matches": declared_size == reader.len() as u32,
        "reserved": [reserved_a.unwrap_or(0), reserved_b.unwrap_or(0)],
        "pixel_data_offset": off_bits,
    });
    if u64::from(off_bits) < 14 {
        report.warn(format!(
            "Pixel data offset {off_bits} points inside the file header"
        ));
        return report.finish(false, None, data);
    }
    if !reader.fits(14, 4) {
        report.warn("File is too short to contain a DIB header");
        return report.finish(false, None, data);
    }
    let dib_size_signed = i64::from(reader.u32le(14).unwrap_or(0));
    if dib_size_signed < 12 {
        report.warn(format!(
            "DIB header size {dib_size_signed} is smaller than the OS/2 v1 header (12 bytes)"
        ));
        return report.finish(false, None, data);
    }
    let dib_size = dib_size_signed as u64;
    if !reader.fits(14, dib_size) {
        report.truncate_at(format!(
            "truncated at offset 14: DIB header declares {dib_size} bytes but the file ends first"
        ));
        return report.finish(false, None, data);
    }
    let core_header = dib_size == 12;
    if !core_header && dib_size < 40 {
        report.warn(format!(
            "DIB header size {dib_size} sits between the OS/2 and Windows formats; geometry cannot be parsed"
        ));
        return report.finish(false, None, data);
    }

    let (
        width_signed,
        height_signed,
        planes,
        bits_per_pixel,
        compression,
        image_size,
        x_ppm,
        y_ppm,
        colours_used,
        important_colours,
    ) = if core_header {
        (
            i64::from(reader.u16le(18).unwrap_or(0)),
            i64::from(reader.u16le(20).unwrap_or(0)),
            reader.u16le(22).unwrap_or(0),
            reader.u16le(24).unwrap_or(0),
            0u32,
            0u32,
            0u32,
            0u32,
            0u32,
            0u32,
        )
    } else {
        (
            i64::from(reader.u32le(18).unwrap_or(0)),
            i64::from(reader.u32le(22).unwrap_or(0)),
            reader.u16le(26).unwrap_or(0),
            reader.u16le(28).unwrap_or(0),
            reader.u32le(30).unwrap_or(0),
            reader.u32le(34).unwrap_or(0),
            reader.u32le(38).unwrap_or(0),
            reader.u32le(42).unwrap_or(0),
            reader.u32le(46).unwrap_or(0),
            reader.u32le(50).unwrap_or(0),
        )
    };
    let top_down = height_signed < 0;
    let width = width_signed.unsigned_abs();
    let height = height_signed.unsigned_abs();
    if planes != 1 {
        report.warn(format!(
            "Header declares {planes} colour planes, the specification allows only 1"
        ));
    }
    if width == 0 || height == 0 {
        report.warn(format!("Header declares an empty image: {width}x{height}"));
        return report.finish(false, None, data);
    }
    if !valid_bpp(bits_per_pixel) {
        report.warn(format!("Unusual bit depth {bits_per_pixel}"));
    }

    let dib = json!({
        "size": dib_size,
        "variant": dib_header_name(dib_size),
        "width": width,
        "height": height,
        "top_down": top_down,
        "planes": planes,
        "bits_per_pixel": bits_per_pixel,
        "compression": compression,
        "compression_name": bmp_compression_name(compression),
        "declared_image_size": image_size,
        "pixels_per_metre": [x_ppm, y_ppm],
        "colors_used": colours_used,
        "important_colors": important_colours,
    });
    report.root["dib"] = dib;

    let entry_size: u64 = if core_header { 3 } else { 4 };
    let palette_entries: u64 = if bits_per_pixel <= 8 {
        if colours_used != 0 {
            u64::from(colours_used)
        } else {
            1u64 << bits_per_pixel
        }
    } else {
        0
    };
    let colour_table_start = 14 + dib_size;
    let colour_table_end = colour_table_start + palette_entries * entry_size;
    report.root["color_table"] = json!({
        "entries": palette_entries,
        "entry_size": entry_size,
        "offset": colour_table_start,
        "sample": bmp_palette_sample(&reader, colour_table_start, palette_entries, entry_size),
    });
    if colour_table_end > reader.len() as u64 {
        report.warn(format!(
            "Colour table ends past the end of the file ({colour_table_end} > {})",
            reader.len()
        ));
    }
    if colour_table_end < u64::from(off_bits) {
        let gap = u64::from(off_bits) - colour_table_end;
        report.root["gap_bytes"] = json!(gap);
        report.root["gap_preview_hex"] = json!(reader
            .bytes(colour_table_end, gap.min(64))
            .map(|b| b.iter().map(|x| format!("{x:02x}")).collect::<String>())
            .unwrap_or_default());
        report.warn(format!(
            "{gap} bytes between the colour table and the pixel data"
        ));
    } else if colour_table_end > u64::from(off_bits) {
        report.warn(format!(
            "Pixel data offset {off_bits} is inside the colour table ({colour_table_end})"
        ));
    }

    let Some(stride) = (width)
        .checked_mul(u64::from(bits_per_pixel))
        .and_then(|bits| bits.checked_add(31))
        .map(|bits| bits / 32 * 4)
    else {
        report.warn("Row stride overflows; the header geometry is impossible");
        return report.finish(false, None, data);
    };
    let Some(expected_pixels) = stride.checked_mul(height) else {
        report.warn("Pixel-array size overflows; the header geometry is impossible");
        return report.finish(false, None, data);
    };
    let pixel_end = u64::from(off_bits).checked_add(expected_pixels);
    report.root["pixel_array"] = json!({
        "offset": off_bits,
        "row_stride": stride,
        "expected_bytes": expected_pixels,
        "declared_bytes": image_size,
    });
    if image_size != 0 && u64::from(image_size) != expected_pixels {
        report.warn(format!(
            "Header declares {image_size} bytes of pixel data but the geometry implies {expected_pixels}"
        ));
    }
    if compression != 0 {
        report.warn(format!(
            "Compression {} ({}) is used, so the pixel data layout could not be verified and appended-data carving is disabled",
            compression,
            bmp_compression_name(compression)
        ));
        return report.finish(false, None, data);
    }
    let Some(pixel_end) = pixel_end else {
        report.warn("Pixel-array end overflows; the header geometry is impossible");
        return report.finish(false, None, data);
    };

    if pixel_end > reader.len() as u64 {
        let available = reader.len().saturating_sub(off_bits as usize);
        report.truncate_at(format!(
            "truncated at offset {off_bits}: pixel data needs {expected_pixels} bytes but only {available} are present"
        ));
        // expected_end documents the header math even though the file ends first.
        return report.finish(false, Some(pixel_end), data);
    }
    if pixel_end < reader.len() as u64 {
        report.warn(format!(
            "{} bytes appended after the pixel data (offset {pixel_end})",
            reader.len() as u64 - pixel_end
        ));
        report.warn(
            "Appended bytes often mean the height in the header is smaller than the real image: try increasing the height to reveal a hidden image",
        );
    }
    report.finish(true, Some(pixel_end), data)
}

fn bmp_palette_sample(reader: &Reader, start: u64, entries: u64, entry_size: u64) -> Vec<Json> {
    let listed = entries.min(MAX_PALETTE_ENTRIES_LISTED as u64);
    let mut sample = Vec::with_capacity(listed as usize);
    for i in 0..listed {
        let at = start + i * entry_size;
        let bytes = reader.bytes(at, entry_size);
        let Some(bytes) = bytes else {
            break;
        };
        sample.push(json!(bytes.to_vec()));
    }
    sample
}

fn valid_bpp(bits_per_pixel: u16) -> bool {
    matches!(bits_per_pixel, 1 | 2 | 4 | 8 | 16 | 24 | 32 | 48 | 64)
}

fn dib_header_name(size: u64) -> &'static str {
    match size {
        12 => "OS/2 BITMAPCOREHEADER",
        40 => "BITMAPINFOHEADER",
        52 => "BITMAPV2INFOHEADER",
        56 => "BITMAPV3INFOHEADER",
        64 => "OS/2 v2 BITMAPCOREHEADER2",
        108 => "BITMAPV4HEADER",
        124 => "BITMAPV5HEADER",
        _ => "unknown header variant",
    }
}

fn bmp_compression_name(compression: u32) -> String {
    match compression {
        0 => "no compression".to_owned(),
        1 => "RLE8".to_owned(),
        2 => "RLE4".to_owned(),
        3 => "bit fields".to_owned(),
        4 => "JPEG".to_owned(),
        5 => "PNG".to_owned(),
        6 => "alpha bit fields".to_owned(),
        other => format!("unknown (0x{other:08x})"),
    }
}

// ---------------------------------------------------------------------------
// Registry operations
// ---------------------------------------------------------------------------

fn input_file_bytes<'a>(v: &'a Value, op: &str) -> OpResult<&'a [u8]> {
    match v {
        Value::Bytes(b) => Ok(b),
        other => {
            let found = format!("{:?}", other.kind());
            Err(
                OperationError::invalid_input(format!("{op} expects file bytes, got {found}"))
                    .with_expected("Bytes"),
            )
        }
    }
}

fn unknown_container(op: &str) -> OperationError {
    OperationError::unsupported(format!(
        "{op}: input is not a PNG, JPEG, GIF or BMP container"
    ))
    .with_expected("PNG, JPEG, GIF or BMP magic bytes")
    .with_actual("unrecognised signature")
}

fn structure_op(
    format: ContainerFormat,
) -> impl Fn(&Value, &ParamMap, &ExecutionContext) -> OpResult<Value> {
    move |v: &Value, _: &ParamMap, _: &ExecutionContext| {
        let bytes = input_file_bytes(v, "Structure Analysis")?;
        let report = match format {
            ContainerFormat::Png => analyze_png(bytes),
            ContainerFormat::Jpeg => analyze_jpeg(bytes),
            ContainerFormat::Gif => analyze_gif(bytes),
            ContainerFormat::Bmp => analyze_bmp(bytes),
        };
        Ok(Value::Json(report))
    }
}

fn image_structure_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    const OP: &str = "Image Structure";
    let bytes = input_file_bytes(v, OP)?;
    let (_, report) = analyze_any(bytes).ok_or_else(|| unknown_container(OP))?;
    Ok(Value::Json(report))
}

fn image_extract_appended_op(
    v: &Value,
    params: &ParamMap,
    _: &ExecutionContext,
) -> OpResult<Value> {
    const OP: &str = "Extract Appended";
    let bytes = input_file_bytes(v, OP)?;
    let (_, report) = analyze_any(bytes).ok_or_else(|| unknown_container(OP))?;
    let max_bytes = (params
        .int_or("max_bytes", crate::ops::DEFAULT_PREVIEW_BYTES as i64)
        .max(0) as u64)
        .min(crate::ops::MAX_EXTRACT_BYTES as u64) as usize;

    let end = report
        .get("expected_end")
        .and_then(Json::as_u64)
        .and_then(|e| usize::try_from(e).ok())
        .filter(|&e| e < bytes.len());
    let mut header = json!({
        "format": report["format"],
        "complete": report["complete"],
        "max_bytes": max_bytes,
    });
    let payload: &[u8] = match end {
        None => {
            header["present"] = json!(false);
            &[]
        }
        Some(offset) => {
            let appended = report["appended"].clone();
            header["present"] = json!(true);
            for key in [
                "offset",
                "size",
                "magic",
                "preview_hex",
                "preview_bytes",
                "strings",
            ] {
                if let Some(value) = appended.get(key) {
                    header[key] = value.clone();
                }
            }
            let emit = bytes.len().saturating_sub(offset).min(max_bytes);
            header["emitted_bytes"] = json!(emit);
            header["truncated"] = json!(emit < bytes.len() - offset);
            &bytes[offset..offset + emit]
        }
    };
    // The image_extract_bits transport: JSON report header line, then the
    // raw appended bytes as the payload so recipes can chain them onward.
    let mut out = serde_json::to_vec(&header)
        .map_err(|e| OperationError::internal(format!("serialize appended-data header: {e}")))?;
    out.push(b'\n');
    out.extend_from_slice(payload);
    Ok(Value::Bytes(out))
}

/// Registers the structure/carving operations.
pub(crate) fn register(reg: &mut OperationRegistry) {
    use cybercipher_core::Category::Analysis as A;
    use cybercipher_core::ValueKind::{Bytes as B, Json as J};

    let tags: &'static [&'static str] = &["steg", "image", "ctf", "structure", "carving"];
    let standard = "Semantics ported from StegSolver c14bfa9 (MIT): PngAnalyzer/JpegAnalyzer/GifAnalyzer/BmpAnalyzer bounds policy";
    let vectors =
        "Hand-built minimal fixtures; truncation-at-every-offset and hostile-mutation loops";

    for (id, name, description, format) in [
        (
            "png_structure",
            "PNG Structure",
            "Walks the PNG chunk list over raw file bytes: per-chunk offsets/lengths/CRC validity, chunk-type flags and descriptions, IHDR geometry, palette, bounded tEXt/zTXt/iTXt comment extraction (zTXt/iTXt decompressed with a cap), and the logical end of file at IEND with appended-data detection.",
            ContainerFormat::Png,
        ),
        (
            "jpeg_structure",
            "JPEG Structure",
            "Walks the JPEG marker stream over raw file bytes: segment offsets/lengths, APPn identifiers (JFIF/Exif/ICC/Photoshop/XMP), SOF geometry, entropy-coded scan bounded by FF00/RST handling, COM comments, and the logical end of file at EOI with appended-data detection.",
            ContainerFormat::Jpeg,
        ),
        (
            "gif_structure",
            "GIF Structure",
            "Walks the GIF block stream over raw file bytes: logical screen descriptor, global/local colour tables, image descriptors with LZW minimum-code-size offsets, graphic control/comment/plain-text/application extensions, frame count, and the logical end of file at the 0x3B trailer with appended-data detection.",
            ContainerFormat::Gif,
        ),
        (
            "bmp_structure",
            "BMP Structure",
            "Parses the BMP file and DIB headers (OS/2 core and INFO+ variants) over raw file bytes: geometry, bit depth, compression, colour table size/offset, header-to-pixels gap, pixel-array layout from header math validated against the real file size, and appended-data detection at the pixel-array end.",
            ContainerFormat::Bmp,
        ),
    ] {
        reg.add_simple(
            crate::ops::spec(
                id,
                name,
                description,
                A,
                &[B],
                J,
                CostClass::Instant,
                false,
                vec![],
                tags,
                &[],
                standard,
                vectors,
            ),
            structure_op(format),
        );
    }

    reg.add_simple(
        crate::ops::spec(
            "image_structure",
            "Image Structure",
            "Sniffs the container format (PNG/JPEG/GIF/BMP magic) and runs the matching structural analyzer; unknown signatures produce a typed error. See the per-format ops for the report shape.",
            A,
            &[B],
            J,
            CostClass::Instant,
            false,
            vec![],
            tags,
            &["image structure"],
            standard,
            vectors,
        ),
        image_structure_op,
    );

    reg.add_simple(
        crate::ops::spec(
            "image_extract_appended",
            "Extract Appended",
            "Carves data appended after a container's logical end of file (PNG IEND, JPEG EOI, GIF trailer, BMP pixel-array end). Output is a JSON report header line (offset, size, detected magic via the file-magic table, hex preview, printable-string snippet) followed by the raw appended bytes as the payload. Never unpacks or executes anything.",
            A,
            &[B],
            B,
            CostClass::Interactive,
            false,
            vec![crate::ops::p_int(
                "max_bytes",
                "Max bytes",
                crate::ops::DEFAULT_PREVIEW_BYTES as i64,
                "Bounded payload size. Hard cap 16 MiB; the header reports the total appended size and a truncated flag.",
            )],
            tags,
            &["carve", "appended data", "trailing data"],
            standard,
            vectors,
        ),
        image_extract_appended_op,
    );
}

// ---------------------------------------------------------------------------
// Tests: hand-built fixtures (no binary fixtures committed), walk correctness,
// truncation at every structural boundary, hostile mutations, registry ops.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::carving::carve;

    // -----------------------------------------------------------------
    // Fixture builders (bytes constructed in-test)
    // -----------------------------------------------------------------

    fn png_chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::with_capacity(4 + payload.len());
        body.extend_from_slice(kind);
        body.extend_from_slice(payload);
        let crc = crc32(&body);
        let mut out = Vec::with_capacity(12 + payload.len());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&crc.to_be_bytes());
        out
    }

    fn ihdr_chunk(w: u32, h: u32) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&w.to_be_bytes());
        payload.extend_from_slice(&h.to_be_bytes());
        payload.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit truecolour, no interlace
        png_chunk(b"IHDR", &payload)
    }

    fn minimal_png() -> Vec<u8> {
        let mut out = PNG_SIGNATURE.to_vec();
        out.extend_from_slice(&ihdr_chunk(4, 3));
        out.extend_from_slice(&png_chunk(b"IDAT", &[0xAB; 16]));
        out.extend_from_slice(&png_chunk(b"IEND", &[]));
        out
    }

    fn png_with_tail() -> Vec<u8> {
        let mut out = minimal_png();
        out.extend_from_slice(b"PK\x03\x04abc");
        out
    }

    fn zlib_compress(data: &[u8]) -> Vec<u8> {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).expect("compress");
        encoder.finish().expect("finish")
    }

    fn jpeg_seg(marker: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0xFF, marker];
        out.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// SOI, APP0/JFIF, DQT, SOF0 (6x4), DHT, SOS with FF00/RST-stuffed scan
    /// data, EOI. 130 bytes total; scan runs 119..128.
    fn minimal_jpeg() -> Vec<u8> {
        let mut out = vec![0xFF, 0xD8];
        out.extend_from_slice(&jpeg_seg(
            0xE0,
            b"JFIF\0\x01\x01\x00\x00\x01\x00\x01\x00\x00",
        ));
        out.extend_from_slice(&jpeg_seg(0xDB, &[0u8; 65]));
        out.extend_from_slice(&jpeg_seg(0xC0, &[8, 0, 4, 0, 6, 1, 0x11, 0x03, 0]));
        out.extend_from_slice(&jpeg_seg(0xC4, &[0x00, 0x01, 0x00]));
        out.extend_from_slice(&jpeg_seg(0xDA, &[1, 0x11, 0x00, 0, 63, 0]));
        out.extend_from_slice(&[0x12, 0x34, 0xFF, 0x00, 0xAB, 0xFF, 0xD0, 0x56, 0x78]);
        out.extend_from_slice(&[0xFF, 0xD9]);
        out
    }

    fn jpeg_with_tail() -> Vec<u8> {
        let mut out = minimal_jpeg();
        out.extend_from_slice(b"\x1F\x8B payload");
        out
    }

    fn gif_sub_block(data: &[u8]) -> Vec<u8> {
        let mut out = vec![data.len() as u8];
        out.extend_from_slice(data);
        out
    }

    /// GIF89a, 8x4 screen, 4-entry GCT, graphic control, comment, one frame,
    /// trailer. 64 bytes total; trailer at 63.
    fn minimal_gif() -> Vec<u8> {
        let mut out = b"GIF89a".to_vec();
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.push(0x81); // GCT present, 4 entries
        out.push(0); // background
        out.push(0); // aspect
        out.extend_from_slice(&[
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0,
        ]);
        out.extend_from_slice(&[0x21, 0xF9, 0x04, 0x01, 0x05, 0x00, 0x03, 0x00]);
        out.extend_from_slice(&[0x21, 0xFE]);
        out.extend_from_slice(&gif_sub_block(b"gif secret"));
        out.push(0x00);
        out.extend_from_slice(&[0x2C, 0x00, 0x00, 0x00, 0x00]);
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.push(0x00); // no local colour table, not interlaced
        out.push(0x02); // LZW minimum code size
        out.extend_from_slice(&gif_sub_block(&[0x9C, 0x11, 0x33]));
        out.push(0x00);
        out.push(0x3B);
        out
    }

    fn gif_with_tail() -> Vec<u8> {
        let mut out = minimal_gif();
        out.extend_from_slice(b"tail bytes");
        out
    }

    /// 8x2 24-bit BMP with a BITMAPINFOHEADER: 102 bytes, pixel array at 54.
    fn bmp_info() -> Vec<u8> {
        let stride: u32 = (8u32 * 24).div_ceil(32) * 4; // 24
        let pixels = stride * 2; // 48
        let offset: u32 = 14 + 40;
        let mut out = b"BM".to_vec();
        out.extend_from_slice(&(offset + pixels).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&40u32.to_le_bytes());
        out.extend_from_slice(&8i32.to_le_bytes());
        out.extend_from_slice(&2i32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&24u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&pixels.to_le_bytes());
        out.extend_from_slice(&[0u8; 16]); // ppm x2, colours used, important
        out.extend(vec![0x5A; pixels as usize]);
        out
    }

    /// 8x2 1-bpp OS/2 BITMAPCOREHEADER BMP with a 2-entry palette: 40 bytes.
    fn bmp_core() -> Vec<u8> {
        let stride: u32 = 8u32.div_ceil(32) * 4; // 8 px at 1 bpp -> 4-byte rows
        let pixels = stride * 2; // 8
        let offset: u32 = 14 + 12 + 6;
        let mut out = b"BM".to_vec();
        out.extend_from_slice(&(offset + pixels).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&12u32.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF]);
        out.extend(vec![0x11; pixels as usize]);
        out
    }

    fn bmp_with_tail() -> Vec<u8> {
        let mut out = bmp_info();
        out.extend_from_slice(b"appended!");
        out
    }

    fn analyze_all(data: &[u8]) -> Vec<Json> {
        vec![
            analyze_png(data),
            analyze_jpeg(data),
            analyze_gif(data),
            analyze_bmp(data),
        ]
    }

    fn lcg(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state >> 33
    }

    /// Cuts the fixture at every offset and asserts the completion invariant:
    /// below the logical EOF the report must not claim `complete`; at or past
    /// it, it must. Also asserts the walk never panics (implicit).
    fn assert_truncation_invariants(fixture: &[u8]) {
        let (format, full) = analyze_any(fixture).expect("fixture format is known");
        let end = full["expected_end"].as_u64().expect("logical EOF");
        assert_eq!(full["format"], json!(format.id()));
        let analyze = |data: &[u8]| match format {
            ContainerFormat::Png => analyze_png(data),
            ContainerFormat::Jpeg => analyze_jpeg(data),
            ContainerFormat::Gif => analyze_gif(data),
            ContainerFormat::Bmp => analyze_bmp(data),
        };
        for cut in 0..fixture.len() {
            let report = analyze(&fixture[..cut]);
            let complete = report["complete"].as_bool().expect("complete flag");
            if (cut as u64) < end {
                assert!(
                    !complete,
                    "{format:?}: cut {cut} below expected_end {end} must not be complete"
                );
            } else {
                assert!(
                    complete,
                    "{format:?}: cut {cut} at/after expected_end {end} must stay complete"
                );
            }
        }
    }

    // -----------------------------------------------------------------
    // PNG
    // -----------------------------------------------------------------

    #[test]
    fn png_valid_fixture_walk() {
        let data = minimal_png(); // 8 + 25 + 28 + 12 = 73 bytes
        let report = analyze_png(&data);
        assert_eq!(report["format"], "png");
        assert_eq!(report["signature_valid"], true);
        assert_eq!(report["complete"], true);
        assert_eq!(report["expected_end"], 73);
        assert_eq!(report["truncated"], false);
        assert_eq!(report["appended"]["present"], false);
        assert_eq!(report["warnings"], json!([]));

        let chunks = report["chunks"].as_array().unwrap();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0]["type"], "IHDR");
        assert_eq!(chunks[0]["offset"], 8);
        assert_eq!(chunks[0]["data_offset"], 16);
        assert_eq!(chunks[0]["length"], 13);
        assert_eq!(chunks[0]["crc_valid"], true);
        assert_eq!(chunks[0]["flags"]["critical"], true);
        assert_eq!(chunks[0]["flags"]["description"], "Image header");
        assert_eq!(chunks[2]["type"], "IEND");
        assert_eq!(report["last_chunk"], "IEND");

        let ihdr = &report["ihdr"];
        assert_eq!(ihdr["width"], 4);
        assert_eq!(ihdr["height"], 3);
        assert_eq!(ihdr["bit_depth"], 8);
        assert_eq!(ihdr["color_type"], 2);
        assert_eq!(ihdr["color_type_name"], "truecolour");
        assert_eq!(ihdr["interlace"], 0);
        assert_eq!(ihdr["pixels"], 12);
        assert_eq!(ihdr["raw_data_bytes"], 36);

        assert_eq!(report["idat"]["chunks"], 1);
        assert_eq!(report["idat"]["bytes"], 16);
    }

    #[test]
    fn png_text_comments_extracted_bounded() {
        let text = b"Title\0CyberCipher steg".to_vec();
        let mut ztxt = b"Comment\0\x00".to_vec();
        ztxt.extend_from_slice(&zlib_compress(b"secret payload"));
        let itxt = b"Note\0\x00\x00en\0\0actual text".to_vec();

        let mut data = PNG_SIGNATURE.to_vec();
        data.extend_from_slice(&ihdr_chunk(1, 1));
        data.extend_from_slice(&png_chunk(b"tEXt", &text));
        data.extend_from_slice(&png_chunk(b"zTXt", &ztxt));
        data.extend_from_slice(&png_chunk(b"iTXt", &itxt));
        data.extend_from_slice(&png_chunk(b"IEND", &[]));

        let report = analyze_png(&data);
        let comments = report["comments"].as_array().unwrap();
        assert_eq!(comments.len(), 3);
        assert_eq!(comments[0]["chunk"], "tEXt");
        assert_eq!(comments[0]["keyword"], "Title");
        assert_eq!(comments[0]["text"], "CyberCipher steg");
        assert_eq!(comments[0]["text_truncated"], false);
        assert_eq!(comments[1]["chunk"], "zTXt");
        assert_eq!(comments[1]["keyword"], "Comment");
        assert_eq!(comments[1]["compressed"], true);
        assert_eq!(comments[1]["text"], "secret payload");
        assert_eq!(comments[2]["chunk"], "iTXt");
        assert_eq!(comments[2]["keyword"], "Note");
        assert_eq!(comments[2]["language"], "en");
        assert_eq!(comments[2]["text"], "actual text");
    }

    #[test]
    fn png_comment_and_count_caps() {
        // A 2 KiB text value is capped at 1 KiB per the design contract.
        let mut big = b"K\0".to_vec();
        big.extend(vec![b'x'; 2048]);
        let mut data = PNG_SIGNATURE.to_vec();
        data.extend_from_slice(&ihdr_chunk(1, 1));
        data.extend_from_slice(&png_chunk(b"tEXt", &big));
        data.extend_from_slice(&png_chunk(b"IEND", &[]));
        let report = analyze_png(&data);
        let comments = report["comments"].as_array().unwrap();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0]["text"].as_str().unwrap().len(), MAX_TEXT_BYTES);
        assert_eq!(comments[0]["text_truncated"], true);

        // More than MAX_COMMENTS comment chunks: later ones are dropped.
        let mut many = PNG_SIGNATURE.to_vec();
        many.extend_from_slice(&ihdr_chunk(1, 1));
        for _ in 0..(MAX_COMMENTS + 10) {
            many.extend_from_slice(&png_chunk(b"tEXt", b"k\0v"));
        }
        many.extend_from_slice(&png_chunk(b"IEND", &[]));
        let report = analyze_png(&many);
        assert_eq!(report["comments"].as_array().unwrap().len(), MAX_COMMENTS);
        assert_eq!(report["comments_dropped"], true);
        assert_eq!(report["complete"], true);
    }

    #[test]
    fn png_entry_cap_at_512_chunks() {
        let mut data = PNG_SIGNATURE.to_vec();
        data.extend_from_slice(&ihdr_chunk(1, 1));
        for _ in 0..600 {
            data.extend_from_slice(&png_chunk(b"tEXt", b"k\0v"));
        }
        data.extend_from_slice(&png_chunk(b"IEND", &[]));
        let report = analyze_png(&data);
        assert_eq!(report["chunks"].as_array().unwrap().len(), MAX_ENTRIES);
        assert_eq!(report["entries_truncated"], true);
        // The walk stopped at the cap, so IEND was never reached.
        assert_eq!(report["complete"], false);
    }

    #[test]
    fn png_crc_mismatch_flagged() {
        let mut data = minimal_png();
        let crc_index = data.len() - 5; // last byte of the IEND CRC
        data[crc_index] ^= 0xFF;
        let report = analyze_png(&data);
        let chunks = report["chunks"].as_array().unwrap();
        assert_eq!(chunks[2]["crc_valid"], false);
        let warnings = report["warnings"].as_array().unwrap();
        assert!(warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("CRC mismatch")));
    }

    #[test]
    fn png_palette_entry_count() {
        let mut data = PNG_SIGNATURE.to_vec();
        data.extend_from_slice(&ihdr_chunk(1, 1));
        data.extend_from_slice(&png_chunk(b"PLTE", &[1, 2, 3, 4, 5, 6, 7, 8, 9]));
        data.extend_from_slice(&png_chunk(b"IDAT", &[0u8; 4]));
        data.extend_from_slice(&png_chunk(b"IEND", &[]));
        let report = analyze_png(&data);
        let palette = &report["palette"];
        assert_eq!(palette["entries"], 3);
        assert_eq!(palette["sample"].as_array().unwrap().len(), 3);
        assert_eq!(palette["sample"][2], json!([7, 8, 9]));
    }

    #[test]
    fn png_truncated_chunk_reports_marker() {
        let full = minimal_png();
        // Cut inside the IDAT chunk data.
        let report = analyze_png(&full[..40]);
        assert_eq!(report["truncated"], true);
        assert_eq!(report["complete"], false);
        let warnings = report["warnings"].as_array().unwrap();
        assert!(warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("truncated at offset 33")));
        assert_eq!(report["expected_end"], json!(null));
    }

    #[test]
    fn png_impossible_chunk_length_truncates_cleanly() {
        // A chunk claiming ~4 GiB must end the walk with a marker, not an
        // allocation.
        let mut data = minimal_png();
        data.truncate(33); // signature + IHDR only
        data.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        data.extend_from_slice(b"tEXt");
        data.extend_from_slice(b"oops");
        let report = analyze_png(&data);
        assert_eq!(report["truncated"], true);
        assert_eq!(report["chunks"].as_array().unwrap().len(), 1);
        let warnings = report["warnings"].as_array().unwrap();
        assert!(warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("truncated at offset 33")));
        assert_eq!(report["complete"], false);
    }

    #[test]
    fn png_appended_data_after_iend() {
        let data = png_with_tail(); // 73-byte PNG + 7-byte zip-magic tail
        let report = analyze_png(&data);
        assert_eq!(report["complete"], true);
        assert_eq!(report["expected_end"], 73);
        let appended = &report["appended"];
        assert_eq!(appended["present"], true);
        assert_eq!(appended["offset"], 73);
        assert_eq!(appended["size"], 7);
        assert_eq!(appended["magic"]["id"], "zip");
        assert!(appended["preview_hex"]
            .as_str()
            .unwrap()
            .starts_with("504b0304"));

        let carved = carve(&data).expect("tail carved");
        assert_eq!(carved.offset, 73);
        assert_eq!(carved.size, 7);
        assert_eq!(carved.magic.expect("zip").id, "zip");
    }

    #[test]
    fn png_truncation_at_every_offset() {
        assert_truncation_invariants(&minimal_png());
        assert_truncation_invariants(&png_with_tail());
        // A PNG with a claimed 4 GiB chunk must survive every cut too.
        let mut hostile = minimal_png();
        hostile.truncate(33);
        hostile.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        hostile.extend_from_slice(b"tEXtp");
        for cut in 0..hostile.len() {
            let _ = analyze_png(&hostile[..cut]);
        }
    }

    // -----------------------------------------------------------------
    // JPEG
    // -----------------------------------------------------------------

    #[test]
    fn jpeg_valid_fixture_walk() {
        let data = minimal_jpeg(); // 130 bytes
        let report = analyze_jpeg(&data);
        assert_eq!(report["format"], "jpeg");
        assert_eq!(report["signature_valid"], true);
        assert_eq!(report["complete"], true);
        assert_eq!(report["expected_end"], 130);
        assert_eq!(report["eoi_offset"], 128);
        assert_eq!(report["truncated"], false);
        assert_eq!(report["appended"]["present"], false);

        let segments = report["segments"].as_array().unwrap();
        assert_eq!(segments.len(), 5);
        assert_eq!(segments[0]["marker"], "APP0");
        assert_eq!(segments[0]["offset"], 3); // marker code byte
        assert_eq!(segments[0]["identifier"], "JFIF");
        assert_eq!(segments[1]["marker"], "DQT");
        assert_eq!(segments[1]["offset"], 21);
        assert_eq!(segments[2]["marker"], "SOF0");
        assert_eq!(segments[4]["marker"], "SOS");
        assert_eq!(segments[4]["offset"], 110);
        assert_eq!(segments[4]["scan_bytes"], 9);

        let frame = &report["frame"];
        assert_eq!(frame["marker"], "SOF0");
        assert_eq!(frame["frame_type"], "baseline DCT");
        assert_eq!(frame["precision"], 8);
        assert_eq!(frame["width"], 6);
        assert_eq!(frame["height"], 4);
        assert_eq!(frame["components"], 1);
    }

    #[test]
    fn jpeg_scan_skips_stuffing_and_restart_markers() {
        let report = analyze_jpeg(&minimal_jpeg());
        let scan = &report["scan"];
        assert_eq!(scan["offset"], 119);
        assert_eq!(scan["bytes"], 9); // FF00 and FFD0 stuffed pairs skipped
        assert_eq!(scan["end"], 128);
        assert_eq!(scan["terminated"], true);
    }

    #[test]
    fn jpeg_appn_identifiers() {
        let mut data = vec![0xFF, 0xD8];
        data.extend_from_slice(&jpeg_seg(0xE1, b"Exif\0\0MM\x00\x2A"));
        data.extend_from_slice(&jpeg_seg(0xE2, b"ICC_PROFILE\0\x00abc"));
        data.extend_from_slice(&jpeg_seg(0xEE, b"Adobe\x00\x01"));
        data.extend_from_slice(&jpeg_seg(0xFE, b"a JPEG comment"));
        data.extend_from_slice(&[0xFF, 0xD9]);

        let report = analyze_jpeg(&data);
        let segments = report["segments"].as_array().unwrap();
        assert_eq!(segments[0]["identifier"], "Exif");
        assert_eq!(segments[1]["identifier"], "ICC profile");
        assert_eq!(segments[2]["marker"], "APP14");
        assert_eq!(segments[2]["identifier"], "Adobe");
        let comments = report["comments"].as_array().unwrap();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0]["text"], "a JPEG comment");
    }

    #[test]
    fn jpeg_comment_cap() {
        let mut data = vec![0xFF, 0xD8];
        data.extend_from_slice(&jpeg_seg(0xFE, &vec![b'a'; 4096]));
        data.extend_from_slice(&[0xFF, 0xD9]);
        let report = analyze_jpeg(&data);
        let comments = report["comments"].as_array().unwrap();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0]["text"].as_str().unwrap().len(), MAX_TEXT_BYTES);
        assert_eq!(comments[0]["text_truncated"], true);
    }

    #[test]
    fn jpeg_no_eoi_reports_truncated_and_no_append() {
        let full = jpeg_with_tail();
        // Cut at the EOI: even with a foreign tail following, nothing may be
        // carved because the logical EOF was never reached.
        let report = analyze_jpeg(&full[..128]);
        assert_eq!(report["truncated"], true);
        assert_eq!(report["complete"], false);
        assert_eq!(report["appended"]["present"], false);
        let warnings = report["warnings"].as_array().unwrap();
        assert!(warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("No EOI marker")));
    }

    #[test]
    fn jpeg_truncation_at_every_offset() {
        assert_truncation_invariants(&minimal_jpeg());
        assert_truncation_invariants(&jpeg_with_tail());
    }

    // -----------------------------------------------------------------
    // GIF
    // -----------------------------------------------------------------

    #[test]
    fn gif_valid_fixture_walk() {
        let data = minimal_gif(); // 64 bytes
        let report = analyze_gif(&data);
        assert_eq!(report["format"], "gif");
        assert_eq!(report["signature_valid"], true);
        assert_eq!(report["version"], "GIF89a");
        let screen = &report["screen"];
        assert_eq!(screen["width"], 8);
        assert_eq!(screen["height"], 4);
        assert_eq!(screen["global_color_table_entries"], 4);
        assert_eq!(report["global_color_table"]["entries"], 4);
        assert_eq!(
            report["global_color_table"]["sample"][3],
            json!([0xA0, 0xB0, 0xC0])
        );

        let blocks = report["blocks"].as_array().unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0]["type"], "graphic_control");
        assert_eq!(blocks[1]["type"], "comment");
        assert_eq!(blocks[2]["type"], "image");
        let image = &blocks[2];
        assert_eq!(image["offset"], 47);
        assert_eq!(image["left"], 0);
        assert_eq!(image["width"], 8);
        assert_eq!(image["height"], 4);
        assert_eq!(image["interlace"], false);
        assert_eq!(image["lzw_min_code_size"], 2);
        assert_eq!(image["lzw_code_size_offset"], 57);
        assert_eq!(image["compressed_bytes"], 5);

        assert_eq!(report["frames"], 1);
        assert_eq!(report["trailer_offset"], 63);
        assert_eq!(report["complete"], true);
        assert_eq!(report["expected_end"], 64);
        assert_eq!(report["appended"]["present"], false);
        assert_eq!(report["warnings"], json!([]));
    }

    #[test]
    fn gif_comment_extension_extracted() {
        let report = analyze_gif(&minimal_gif());
        let comments = report["comments"].as_array().unwrap();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0]["kind"], "comment");
        assert_eq!(comments[0]["text"], "gif secret");
        assert_eq!(comments[0]["text_truncated"], false);
    }

    #[test]
    fn gif_graphic_control_fields() {
        let report = analyze_gif(&minimal_gif());
        let gce = &report["blocks"].as_array().unwrap()[0];
        assert_eq!(gce["block_size"], 4);
        assert_eq!(gce["block_size_correct"], true);
        assert_eq!(gce["delay_cs"], 5);
        assert_eq!(gce["transparent_color"], 3);
        assert_eq!(gce["disposal_method"], 0);
    }

    #[test]
    fn gif_two_frames_with_appended_tail() {
        let mut data = b"GIF89a".to_vec();
        data.extend_from_slice(&8u16.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());
        data.push(0x00); // no GCT
        data.push(0);
        data.push(0);
        for _ in 0..2 {
            data.extend_from_slice(&[0x2C, 0, 0, 0, 0]);
            data.extend_from_slice(&8u16.to_le_bytes());
            data.extend_from_slice(&4u16.to_le_bytes());
            data.push(0x00);
            data.push(0x02);
            data.extend_from_slice(&gif_sub_block(&[0xAA, 0xBB]));
            data.push(0x00);
        }
        let trailer_at = data.len() as u64;
        data.push(0x3B);
        data.extend_from_slice(b"PK\x03\x04");

        let report = analyze_gif(&data);
        assert_eq!(report["frames"], 2);
        assert_eq!(report["trailer_offset"], trailer_at);
        assert_eq!(report["expected_end"], trailer_at + 1);
        assert_eq!(report["appended"]["present"], true);
        assert_eq!(report["appended"]["magic"]["id"], "zip");
        assert_eq!(report["appended"]["size"], 4);
    }

    #[test]
    fn gif_truncation_at_every_offset() {
        assert_truncation_invariants(&minimal_gif());
        assert_truncation_invariants(&gif_with_tail());
    }

    // -----------------------------------------------------------------
    // BMP
    // -----------------------------------------------------------------

    #[test]
    fn bmp_infoheader_structure() {
        let data = bmp_info(); // 102 bytes
        let report = analyze_bmp(&data);
        assert_eq!(report["format"], "bmp");
        assert_eq!(report["signature_valid"], true);
        assert_eq!(report["complete"], true);
        assert_eq!(report["expected_end"], 102);
        assert_eq!(report["appended"]["present"], false);
        assert_eq!(report["warnings"], json!([]));

        let file_header = &report["file_header"];
        assert_eq!(file_header["declared_size"], 102);
        assert_eq!(file_header["declared_size_matches"], true);
        assert_eq!(file_header["pixel_data_offset"], 54);

        let dib = &report["dib"];
        assert_eq!(dib["size"], 40);
        assert_eq!(dib["variant"], "BITMAPINFOHEADER");
        assert_eq!(dib["width"], 8);
        assert_eq!(dib["height"], 2);
        assert_eq!(dib["top_down"], false);
        assert_eq!(dib["planes"], 1);
        assert_eq!(dib["bits_per_pixel"], 24);
        assert_eq!(dib["compression"], 0);
        assert_eq!(dib["compression_name"], "no compression");

        let color_table = &report["color_table"];
        assert_eq!(color_table["entries"], 0);
        let pixels = &report["pixel_array"];
        assert_eq!(pixels["offset"], 54);
        assert_eq!(pixels["row_stride"], 24);
        assert_eq!(pixels["expected_bytes"], 48);
        assert_eq!(pixels["declared_bytes"], 48);
    }

    #[test]
    fn bmp_core_header_variant() {
        let data = bmp_core(); // 40 bytes
        let report = analyze_bmp(&data);
        let dib = &report["dib"];
        assert_eq!(dib["size"], 12);
        assert_eq!(dib["variant"], "OS/2 BITMAPCOREHEADER");
        assert_eq!(dib["width"], 8);
        assert_eq!(dib["height"], 2);
        assert_eq!(dib["bits_per_pixel"], 1);
        let color_table = &report["color_table"];
        assert_eq!(color_table["entries"], 2);
        assert_eq!(color_table["entry_size"], 3);
        assert_eq!(color_table["offset"], 26); // 14 + 12
        assert_eq!(color_table["sample"].as_array().unwrap().len(), 2);
        assert_eq!(report["pixel_array"]["row_stride"], 4);
        assert_eq!(report["complete"], true);
        assert_eq!(report["expected_end"], 40);
    }

    #[test]
    fn bmp_appended_after_pixel_array() {
        let data = bmp_with_tail();
        let report = analyze_bmp(&data);
        assert_eq!(report["expected_end"], 102);
        assert_eq!(report["complete"], true);
        let appended = &report["appended"];
        assert_eq!(appended["present"], true);
        assert_eq!(appended["offset"], 102);
        assert_eq!(appended["size"], 9);
        let warnings = report["warnings"].as_array().unwrap();
        assert!(warnings.iter().any(|w| w
            .as_str()
            .unwrap()
            .contains("appended after the pixel data")));
    }

    #[test]
    fn bmp_truncated_pixel_array() {
        let full = bmp_info();
        let report = analyze_bmp(&full[..60]);
        assert_eq!(report["truncated"], true);
        assert_eq!(report["complete"], false);
        // expected_end still documents the header math.
        assert_eq!(report["expected_end"], 102);
        assert_eq!(report["appended"]["present"], false);
        let warnings = report["warnings"].as_array().unwrap();
        assert!(warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("pixel data needs 48 bytes")));
    }

    #[test]
    fn bmp_compressed_layout_disables_carving() {
        let mut data = bmp_info();
        // compression = 1 (RLE8) lives at file offset 30 (14-byte file header
        // + 16 bytes into the BITMAPINFOHEADER).
        data[30..34].copy_from_slice(&1u32.to_le_bytes());
        let report = analyze_bmp(&data);
        assert_eq!(report["complete"], false);
        assert_eq!(report["expected_end"], json!(null));
        assert_eq!(report["appended"]["present"], false);
        assert_eq!(report["dib"]["compression_name"], "RLE8");
        let warnings = report["warnings"].as_array().unwrap();
        assert!(warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("carving is disabled")));
    }

    #[test]
    fn bmp_truncation_at_every_offset() {
        assert_truncation_invariants(&bmp_info());
        assert_truncation_invariants(&bmp_core());
        assert_truncation_invariants(&bmp_with_tail());
    }

    // -----------------------------------------------------------------
    // Hostile input
    // -----------------------------------------------------------------

    #[test]
    fn hostile_mutations_and_random_truncations_never_panic() {
        let fixtures = [
            minimal_png(),
            png_with_tail(),
            minimal_jpeg(),
            jpeg_with_tail(),
            minimal_gif(),
            gif_with_tail(),
            bmp_info(),
            bmp_core(),
        ];
        let mut state = 0x5EED_0001u64;
        for _ in 0..300 {
            let mut data = fixtures[(lcg(&mut state) as usize) % fixtures.len()].clone();
            let flips = 1 + (lcg(&mut state) % 12) as usize;
            for _ in 0..flips {
                let pos = (lcg(&mut state) as usize) % data.len();
                data[pos] = (lcg(&mut state) & 0xFF) as u8;
            }
            if lcg(&mut state).is_multiple_of(2) {
                let cut = (lcg(&mut state) as usize) % (data.len() + 1);
                data.truncate(cut);
            }
            for report in analyze_all(&data) {
                assert!(report.get("format").is_some());
                assert!(report.get("truncated").is_some());
                assert!(report.get("appended").is_some());
            }
        }
    }

    #[test]
    fn detect_format_and_dispatch() {
        assert_eq!(detect_format(&minimal_png()), Some(ContainerFormat::Png));
        assert_eq!(detect_format(&minimal_jpeg()), Some(ContainerFormat::Jpeg));
        assert_eq!(detect_format(&minimal_gif()), Some(ContainerFormat::Gif));
        assert_eq!(detect_format(&bmp_info()), Some(ContainerFormat::Bmp));
        assert_eq!(detect_format(b"not an image"), None);
        assert_eq!(ContainerFormat::Png.id(), "png");
        assert_eq!(ContainerFormat::Bmp.id(), "bmp");

        for (fixture, expected) in [
            (minimal_png(), ContainerFormat::Png),
            (minimal_jpeg(), ContainerFormat::Jpeg),
            (minimal_gif(), ContainerFormat::Gif),
            (bmp_info(), ContainerFormat::Bmp),
        ] {
            let (format, report) = analyze_any(&fixture).expect("known format");
            assert_eq!(format, expected);
            assert_eq!(report["format"], json!(expected.id()));
            assert_eq!(report["complete"], true);
        }
        assert!(analyze_any(b"garbage data!").is_none());
    }

    // -----------------------------------------------------------------
    // Registry operations
    // -----------------------------------------------------------------

    fn registry() -> OperationRegistry {
        let mut reg = OperationRegistry::new();
        crate::register_all(&mut reg);
        reg
    }

    #[test]
    fn registry_structure_ops_roundtrip() {
        let reg = registry();
        let cases = [
            ("png_structure", minimal_png()),
            ("jpeg_structure", minimal_jpeg()),
            ("gif_structure", minimal_gif()),
            ("bmp_structure", bmp_info()),
        ];
        for (id, fixture) in cases {
            let op = reg.get(id).unwrap_or_else(|| panic!("{id} registered"));
            let out = op
                .execute(
                    &Value::Bytes(fixture),
                    &ParamMap::new(),
                    &ExecutionContext::new(),
                )
                .unwrap_or_else(|e| panic!("{id}: {e}"));
            let Value::Json(report) = out else {
                panic!("{id} must return Json");
            };
            assert_eq!(report["complete"], true, "{id}");
            assert_eq!(report["truncated"], false, "{id}");
            assert_eq!(report["appended"]["present"], false, "{id}");
        }
    }

    #[test]
    fn registry_image_structure_dispatch() {
        let reg = registry();
        let op = reg.get("image_structure").unwrap();
        for (fixture, format) in [
            (minimal_png(), "png"),
            (minimal_jpeg(), "jpeg"),
            (minimal_gif(), "gif"),
            (bmp_info(), "bmp"),
        ] {
            let out = op
                .execute(
                    &Value::Bytes(fixture),
                    &ParamMap::new(),
                    &ExecutionContext::new(),
                )
                .unwrap();
            let Value::Json(report) = out else {
                panic!("expected json");
            };
            assert_eq!(report["format"], format);
        }

        // Unknown container: typed unsupported error.
        let err = op
            .execute(
                &Value::Bytes(b"plain text, no image magic".to_vec()),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Unsupported);

        // Non-bytes input: typed invalid-input error.
        let err = op
            .execute(
                &Value::Text("not bytes".to_owned()),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidInput);
    }

    #[test]
    fn registry_extract_appended_header_and_payload() {
        let reg = registry();
        let op = reg.get("image_extract_appended").unwrap();
        let data = png_with_tail(); // zip bytes after IEND
        let out = op
            .execute(
                &Value::Bytes(data),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap();
        let Value::Bytes(bytes) = out else {
            panic!("expected bytes");
        };
        let header_end = bytes.iter().position(|&b| b == b'\n').expect("header line");
        let header: Json = serde_json::from_slice(&bytes[..header_end]).unwrap();
        assert_eq!(header["format"], "png");
        assert_eq!(header["present"], true);
        assert_eq!(header["offset"], 73);
        assert_eq!(header["size"], 7);
        assert_eq!(header["magic"]["id"], "zip");
        assert_eq!(header["truncated"], false);
        assert_eq!(&bytes[header_end + 1..], b"PK\x03\x04abc");

        // A capped max_bytes truncates the payload, not the report.
        let mut params = ParamMap::new();
        params.insert("max_bytes", 4i64);
        let out = op
            .execute(
                &Value::Bytes(png_with_tail()),
                &params,
                &ExecutionContext::new(),
            )
            .unwrap();
        let Value::Bytes(bytes) = out else {
            panic!("expected bytes");
        };
        let header_end = bytes.iter().position(|&b| b == b'\n').unwrap();
        let header: Json = serde_json::from_slice(&bytes[..header_end]).unwrap();
        assert_eq!(header["emitted_bytes"], 4);
        assert_eq!(header["truncated"], true);
        assert_eq!(&bytes[header_end + 1..], b"PK\x03\x04");
    }

    #[test]
    fn registry_extract_appended_without_tail_and_typed_errors() {
        let reg = registry();
        let op = reg.get("image_extract_appended").unwrap();

        // Nothing appended: present=false and an empty payload, not an error.
        let out = op
            .execute(
                &Value::Bytes(minimal_png()),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap();
        let Value::Bytes(bytes) = out else {
            panic!("expected bytes");
        };
        let header: Json = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(header["present"], false);

        // Unknown container: typed unsupported error.
        let err = op
            .execute(
                &Value::Bytes(b"no magic here".to_vec()),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Unsupported);

        // Non-bytes input: typed invalid-input error.
        let err = op
            .execute(
                &Value::Text("nope".to_owned()),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidInput);
    }
}
