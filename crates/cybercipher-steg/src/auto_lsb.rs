//! Bounded automatic LSB scanning — a port of the StegSolver
//! `AutoLsbScanner` / `LsbCandidate` (reference commit `c14bfa9`, MIT).
//!
//! Two-phase model, exactly as upstream:
//!
//! * **Phase 1** (this module) evaluates a bounded prefix (default 64 KiB,
//!   [`SCAN_PREFIX_LIMIT`]) of every Fast/Deep extraction configuration,
//!   scores each extract with deterministic evidence (CTF flag syntax, file
//!   signatures, text tiers, base64, entropy), deduplicates equivalent
//!   configurations and ranks by score. Cancellation is checked per
//!   candidate and inside every bounded extraction.
//! * **Phase 2** is a plain full extraction: apply a candidate by calling
//!   [`crate::extract::extract_bounded`] with `candidate.options` and any
//!   `max_bytes` the caller wants. No extra machinery.
//!
//! The scoring table is ported verbatim from upstream `scorePayload` — high
//! entropy noise never ranks above valid file signatures or readable text.
//! Entropy comes from `cybercipher_core::util::shannon_entropy`; the
//! classification comes from [`crate::payload`]. One scoring system, no
//! fork.

use std::collections::HashMap;

use cybercipher_core::{ExecutionContext, OpResult};
use cybercipher_media::{RgbaImage, Roi};
use xxhash_rust::xxh3::xxh3_64;

use crate::extract::{extract_bounded, ExtractionOptions, RgbOrder};
use crate::payload::{self, PayloadInfo, PayloadType};
use crate::transforms::Channel;

/// Default prefix extraction limit for Phase 1 scanning: 64 KiB.
pub const SCAN_PREFIX_LIMIT: usize = 65_536;

/// The upstream `RgbOrder` declaration order (legacy codes 1..=6).
const ALL_ORDERS: &[RgbOrder] = &[
    RgbOrder::Rgb,
    RgbOrder::Rbg,
    RgbOrder::Grb,
    RgbOrder::Gbr,
    RgbOrder::Brg,
    RgbOrder::Bgr,
];

/// The label upstream attaches to each RGB order (`RgbOrder.label()`).
#[must_use]
pub fn order_label(order: RgbOrder) -> &'static str {
    match order {
        RgbOrder::Rgb => "RGB",
        RgbOrder::Rbg => "RBG",
        RgbOrder::Grb => "GRB",
        RgbOrder::Gbr => "GBR",
        RgbOrder::Brg => "BRG",
        RgbOrder::Bgr => "BGR",
    }
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

/// Generates the bounded list of extraction configurations for Fast Scan.
///
/// Covers the essential CTF combinations, in the exact upstream order:
///
/// 1. RGB bit 0: 6 orders x row/col x invert — 24
/// 2. RGB bit 1 and bit 2: {RGB, BGR} x row/col — 4 + 4
/// 3. RGB bits 0+1: 6 orders x row/col x MSB/LSB x invert — 48
/// 4. RGB bits 0+1+2: {RGB, BGR} x row/col x MSB/LSB — 8
/// 5. single R/G/B: bit 0 x row/col x invert (12), bit 1 x row/col (6),
///    bits 0+1 x row/col x MSB/LSB (12) — 30
/// 6. when the image has alpha: alpha bit 0 x row/col x invert — 4, and
///    RGBA bit 0 x {RGB, BGR} x row/col x invert — 8
///
/// Totals: 118 options without alpha, 130 with — matching the
/// `AutoLsbScanner.fastScanOptions` enumeration at reference commit
/// `c14bfa9` item for item (see `compatibility/stegsolver.toml`).
#[must_use]
pub fn fast_scan_options(has_alpha: bool) -> Vec<ExtractionOptions> {
    let mut list = Vec::with_capacity(if has_alpha { 130 } else { 118 });

    // 1. RGB (all three channels), bit 0.
    for &order in ALL_ORDERS {
        for &row_first in &[true, false] {
            for &invert in &[false, true] {
                list.push(rgb_options(&[0], order, row_first, true, invert));
            }
        }
    }

    // RGB bits 1 and 2, {RGB, BGR} x row/col.
    for plane in [1u32, 2] {
        for &order in &[RgbOrder::Rgb, RgbOrder::Bgr] {
            for &row_first in &[true, false] {
                list.push(rgb_options(&[plane], order, row_first, true, false));
            }
        }
    }

    // RGB bits 0+1 (2-bit LSB).
    for &order in ALL_ORDERS {
        for &row_first in &[true, false] {
            for &lsb_first in &[true, false] {
                for &invert in &[false, true] {
                    list.push(rgb_options(&[0, 1], order, row_first, lsb_first, invert));
                }
            }
        }
    }

    // RGB bits 0+1+2 (3-bit LSB).
    for &order in &[RgbOrder::Rgb, RgbOrder::Bgr] {
        for &row_first in &[true, false] {
            for &lsb_first in &[true, false] {
                list.push(rgb_options(&[0, 1, 2], order, row_first, lsb_first, false));
            }
        }
    }

    // 2. Single channels: Red, Green, Blue.
    for &channel in &[Channel::Red, Channel::Green, Channel::Blue] {
        for &row_first in &[true, false] {
            for &invert in &[false, true] {
                list.push(single_channel_options(
                    channel,
                    &[0],
                    row_first,
                    true,
                    invert,
                ));
            }
            list.push(single_channel_options(
                channel,
                &[1],
                row_first,
                true,
                false,
            ));
            for &lsb_first in &[true, false] {
                list.push(single_channel_options(
                    channel,
                    &[0, 1],
                    row_first,
                    lsb_first,
                    false,
                ));
            }
        }
    }

    // 3. Alpha channel (when the image has one).
    if has_alpha {
        for &row_first in &[true, false] {
            for &invert in &[false, true] {
                list.push(single_channel_options(
                    Channel::Alpha,
                    &[0],
                    row_first,
                    true,
                    invert,
                ));
            }
        }
        for &order in &[RgbOrder::Rgb, RgbOrder::Bgr] {
            for &row_first in &[true, false] {
                for &invert in &[false, true] {
                    list.push(
                        rgb_options(&[0], order, row_first, true, invert).with_plane(
                            Channel::Alpha,
                            0,
                            true,
                        ),
                    );
                }
            }
        }
    }

    list
}

/// Generates a broader enumerated search space for Deep Scan — the Fast
/// list plus, in upstream order:
///
/// 1. 3-bit LSB across the four permutations Fast only covers as
///    {RGB, BGR}: 4 x row/col x MSB/LSB — 16
/// 2. 4-bit LSB (bits 0..3): {RGB, BGR} x row/col x MSB/LSB — 8
/// 3. MSB bit 7: {RGB, BGR} x row/col — 4
/// 4. single R/G/B bit 2 (LSB) and bit 7 (MSB): 3 x row/col x 2 — 12
///
/// Totals: 158 options without alpha, 170 with. Still bounded and
/// completely cancellable.
#[must_use]
pub fn deep_scan_options(has_alpha: bool) -> Vec<ExtractionOptions> {
    let mut list = fast_scan_options(has_alpha);

    for &order in &[RgbOrder::Rbg, RgbOrder::Grb, RgbOrder::Gbr, RgbOrder::Brg] {
        for &row_first in &[true, false] {
            for &lsb_first in &[true, false] {
                list.push(rgb_options(&[0, 1, 2], order, row_first, lsb_first, false));
            }
        }
    }

    for &order in &[RgbOrder::Rgb, RgbOrder::Bgr] {
        for &row_first in &[true, false] {
            for &lsb_first in &[true, false] {
                list.push(rgb_options(
                    &[0, 1, 2, 3],
                    order,
                    row_first,
                    lsb_first,
                    false,
                ));
            }
        }
    }

    for &order in &[RgbOrder::Rgb, RgbOrder::Bgr] {
        for &row_first in &[true, false] {
            list.push(rgb_options(&[7], order, row_first, false, false));
        }
    }

    for &channel in &[Channel::Red, Channel::Green, Channel::Blue] {
        for &row_first in &[true, false] {
            list.push(single_channel_options(
                channel,
                &[2],
                row_first,
                true,
                false,
            ));
            list.push(single_channel_options(
                channel,
                &[7],
                row_first,
                false,
                false,
            ));
        }
    }

    list
}

/// RGB bit planes 0..7 of all three colour channels in one configuration.
fn rgb_options(
    planes: &[u32],
    order: RgbOrder,
    row_first: bool,
    lsb_first: bool,
    invert: bool,
) -> ExtractionOptions {
    let mut options = ExtractionOptions::none()
        .with_order(order)
        .with_row_first(row_first)
        .with_lsb_first(lsb_first)
        .with_invert_bits(invert);
    for channel in [Channel::Red, Channel::Green, Channel::Blue] {
        for &plane in planes {
            options = options.with_plane(channel, plane, true);
        }
    }
    options
}

/// One channel's bit planes in one configuration.
fn single_channel_options(
    channel: Channel,
    planes: &[u32],
    row_first: bool,
    lsb_first: bool,
    invert: bool,
) -> ExtractionOptions {
    let mut options = ExtractionOptions::none()
        .with_row_first(row_first)
        .with_lsb_first(lsb_first)
        .with_invert_bits(invert);
    for &plane in planes {
        options = options.with_plane(channel, plane, true);
    }
    options
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/// The deterministic verdict for one extract: a ranking score plus the
/// human-readable reason (upstream `AutoLsbScanner.Evaluation`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub score: u32,
    pub reason: String,
}

/// One CTF flag keyword of the upstream pattern
/// `(?i)(?:flag|ctf|steg|key|secret|pico|htb|thm)\{[\x20-\x7e]{1,128}\}`;
/// alternation order is match priority, as in the Java regex.
const FLAG_KEYWORDS: &[&[u8]] = &[
    b"flag", b"ctf", b"steg", b"key", b"secret", b"pico", b"htb", b"thm",
];

/// Bytes scanned for CTF flag syntax (upstream `findCtfFlag`).
const FLAG_SEARCH_LIMIT: usize = 16_384;

/// Deterministically scores a candidate payload.
///
/// Ported verbatim from upstream `scorePayload`: the uniform-byte and CTF
/// flag checks run before the classification switch, and the text tiers use
/// the upstream printable definition (0x20..=0x7E only — whitespace is
/// *not* printable there; that is what keeps the 80 "Text sequence" tier
/// reachable for classified text, which is why the whitespace-inclusive
/// `cybercipher_core::util::printable_ratio` is not used for the tiers).
#[must_use]
pub fn score_payload(data: &[u8], info: &PayloadInfo) -> Evaluation {
    if data.is_empty() {
        return Evaluation {
            score: 0,
            reason: "Empty extract".to_owned(),
        };
    }

    // All bytes identical (e.g. all 0x00 or all 0xFF).
    if is_all_same_byte(data) {
        return Evaluation {
            score: 1,
            reason: format!("Uniform byte sequence (all 0x{:x})", data[0]),
        };
    }

    // Common CTF flag patterns beat every other signal.
    if let Some(flag) = find_ctf_flag(data) {
        return Evaluation {
            score: 98,
            reason: format!("CTF flag: {flag}"),
        };
    }

    match info.payload_type {
        PayloadType::Zip => Evaluation {
            score: 100,
            reason: "ZIP archive signature (PK\\x03\\x04)".to_owned(),
        },
        PayloadType::SevenZip => Evaluation {
            score: 100,
            reason: "7-Zip archive signature".to_owned(),
        },
        PayloadType::Rar => Evaluation {
            score: 100,
            reason: "RAR archive signature".to_owned(),
        },
        PayloadType::Gzip => Evaluation {
            score: 100,
            reason: "gzip compressed stream signature".to_owned(),
        },
        PayloadType::Bzip2 => Evaluation {
            score: 100,
            reason: "bzip2 compressed stream signature".to_owned(),
        },
        PayloadType::Xz => Evaluation {
            score: 100,
            reason: "xz compressed stream signature".to_owned(),
        },
        PayloadType::Tar => Evaluation {
            score: 100,
            reason: "tar archive magic (ustar)".to_owned(),
        },
        PayloadType::Png => Evaluation {
            score: 100,
            reason: "PNG image signature".to_owned(),
        },
        PayloadType::Jpeg => Evaluation {
            score: 100,
            reason: "JPEG image signature".to_owned(),
        },
        PayloadType::Gif => Evaluation {
            score: 100,
            reason: "GIF image signature".to_owned(),
        },
        PayloadType::Bmp => {
            if data.len() >= 14 {
                Evaluation {
                    score: 95,
                    reason: "BMP bitmap signature".to_owned(),
                }
            } else {
                Evaluation {
                    score: 80,
                    reason: "Possible BM header".to_owned(),
                }
            }
        }
        PayloadType::WebP => Evaluation {
            score: 100,
            reason: "WebP image container signature".to_owned(),
        },
        PayloadType::Pdf => Evaluation {
            score: 100,
            reason: "PDF document signature".to_owned(),
        },
        PayloadType::Elf => Evaluation {
            score: 100,
            reason: "ELF executable / shared object header".to_owned(),
        },
        PayloadType::Pe => {
            if payload::has_pe_header(data) {
                Evaluation {
                    score: 100,
                    reason: "Windows PE executable header".to_owned(),
                }
            } else {
                Evaluation {
                    score: 65,
                    reason: "Possible MZ header (PE signature not verified)".to_owned(),
                }
            }
        }
        PayloadType::JavaClass => Evaluation {
            score: 100,
            reason: "Java class bytecode (0xCAFEBABE)".to_owned(),
        },
        PayloadType::Base64Text => {
            if data.len() >= 24 {
                Evaluation {
                    score: 72,
                    reason: "Base64 alphabet and length match".to_owned(),
                }
            } else {
                Evaluation {
                    score: 45,
                    reason: "Short possible Base64 text".to_owned(),
                }
            }
        }
        PayloadType::TextAscii | PayloadType::TextUtf8 => {
            evaluate_text(data, info.payload_type == PayloadType::TextAscii)
        }
        PayloadType::Binary => {
            if is_script_header(data) {
                Evaluation {
                    score: 94,
                    reason: "Script executable header (#!)".to_owned(),
                }
            } else if is_json_structure(data) {
                Evaluation {
                    score: 92,
                    reason: "JSON structured text".to_owned(),
                }
            } else if is_xml_or_html(data) {
                Evaluation {
                    score: 92,
                    reason: "XML/HTML markup".to_owned(),
                }
            } else {
                evaluate_binary(data, info)
            }
        }
        // Every remaining type (Empty cannot reach here: the empty check
        // above ran first).
        _ => Evaluation {
            score: 10,
            reason: "Unclassified data".to_owned(),
        },
    }
}

/// Text tiers: 90 readable (spaces and printable > 0.90), 86 valid
/// (printable > 0.95), 80 otherwise. The printable count is the upstream
/// definition (0x20..=0x7E per byte).
fn evaluate_text(data: &[u8], ascii: bool) -> Evaluation {
    let (spaces, printable) = count_printable(data);
    let printable_ratio = printable as f64 / data.len().max(1) as f64;
    let (readable, valid) = if ascii {
        ("Readable ASCII text", "Valid ASCII text")
    } else {
        ("Readable UTF-8 text", "Valid UTF-8 text")
    };
    if spaces > 0 && printable_ratio > 0.90 {
        Evaluation {
            score: 90,
            reason: readable.to_owned(),
        }
    } else if printable_ratio > 0.95 {
        Evaluation {
            score: 86,
            reason: valid.to_owned(),
        }
    } else {
        Evaluation {
            score: 80,
            reason: "Text sequence".to_owned(),
        }
    }
}

/// Binary tiers: 65 partially printable, 5 low byte variation, 15
/// high-entropy noise (never above file signatures), 30 structured binary,
/// 20 unrecognised binary.
fn evaluate_binary(data: &[u8], info: &PayloadInfo) -> Evaluation {
    let (_, printable) = count_printable(data);
    let printable_ratio = printable as f64 / data.len().max(1) as f64;
    if printable_ratio > 0.70 {
        return Evaluation {
            score: 65,
            reason: "Partially printable text fragments".to_owned(),
        };
    }
    if info.distinct_bytes < 5 {
        return Evaluation {
            score: 5,
            reason: "Low byte variation".to_owned(),
        };
    }
    if info.entropy > 7.6 {
        // High-entropy noise: random bytes. Do NOT rank above file
        // signatures.
        return Evaluation {
            score: 15,
            reason: "High-entropy unrecognised binary noise".to_owned(),
        };
    }
    if info.distinct_bytes >= 16 && (3.0..=7.0).contains(&info.entropy) {
        return Evaluation {
            score: 30,
            reason: "Structured binary data".to_owned(),
        };
    }
    Evaluation {
        score: 20,
        reason: "Unrecognised binary data".to_owned(),
    }
}

/// Counts bytes in 0x20..=0x7E (upstream "printable") and space/tab bytes
/// (upstream "spaces"; newlines are neither).
fn count_printable(data: &[u8]) -> (u64, u64) {
    let mut spaces = 0u64;
    let mut printable = 0u64;
    for &byte in data {
        if byte == b' ' || byte == b'\t' {
            spaces += 1;
        }
        if (0x20..=0x7E).contains(&byte) {
            printable += 1;
        }
    }
    (spaces, printable)
}

/// Finds the leftmost CTF flag in the first 16 KiB, reproducing the Java
/// regex `(?i)(?:flag|ctf|steg|key|secret|pico|htb|thm)\{[\x20-\x7e]{1,128}\}`
/// with leftmost-first alternation and greedy `]{1,128}` backtracking (the
/// match ends at the *last* possible `}` inside the printable run).
fn find_ctf_flag(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    let end = data.len().min(FLAG_SEARCH_LIMIT);
    for i in 0..end {
        for keyword in FLAG_KEYWORDS {
            let keyword_end = i + keyword.len();
            if keyword_end >= end || !data[i..keyword_end].eq_ignore_ascii_case(keyword) {
                continue;
            }
            if data[keyword_end] != b'{' {
                continue;
            }
            // Greedy {1,128} over the printable run, longest first.
            let mut run = 0usize;
            while keyword_end + 1 + run < end
                && (0x20..=0x7E).contains(&data[keyword_end + 1 + run])
            {
                run += 1;
            }
            for body in (1..=run.min(128)).rev() {
                let close = keyword_end + 1 + body;
                if close < end && data[close] == b'}' {
                    return Some(String::from_utf8_lossy(&data[i..=close]).into_owned());
                }
            }
        }
    }
    None
}

fn is_all_same_byte(data: &[u8]) -> bool {
    data.iter().all(|&byte| byte == data[0])
}

fn is_script_header(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == b'#' && data[1] == b'!'
}

fn is_json_structure(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    let mut idx = 0;
    while idx < data.len() && matches!(data[idx], b' ' | b'\t' | b'\n' | b'\r') {
        idx += 1;
    }
    if idx < data.len() && (data[idx] == b'{' || data[idx] == b'[') {
        // Check if mostly printable.
        let check = data.len().min(idx + 64);
        for &byte in &data[idx..check] {
            if byte < 32 && !matches!(byte, b'\t' | b'\n' | b'\r') {
                return false;
            }
        }
        return true;
    }
    false
}

fn is_xml_or_html(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }
    let mut idx = 0;
    while idx < data.len() && matches!(data[idx], b' ' | b'\t' | b'\n' | b'\r') {
        idx += 1;
    }
    if idx + 4 <= data.len() && data[idx] == b'<' {
        let take = data.len().saturating_sub(idx).min(10);
        let tag = data[idx..idx + take].to_ascii_lowercase();
        return tag.starts_with(b"<?xml")
            || tag.starts_with(b"<!doctype")
            || tag.starts_with(b"<html")
            || tag.starts_with(b"<svg");
    }
    false
}

// ---------------------------------------------------------------------------
// Candidates, dedup and the scan loop
// ---------------------------------------------------------------------------

/// A candidate result from an automatic LSB scan (upstream `LsbCandidate`).
#[derive(Debug, Clone)]
pub struct LsbCandidate {
    /// The exact extraction configuration that produced this result.
    pub options: ExtractionOptions,
    /// Ranking score from 0 (empty) to 100 (confirmed file format).
    pub score: u32,
    /// Human-readable deterministic reason for the score.
    pub reason: String,
    /// Classification of the extract (upstream `PayloadInfo.type`).
    pub payload_type: PayloadType,
    /// Shannon entropy of the extract, bits per byte.
    pub entropy: f64,
    /// Distinct byte values in the extract.
    pub distinct_bytes: u32,
    /// Bounded extracted bytes (the Phase 1 prefix).
    pub preview: Vec<u8>,
    /// Bytes the full extraction would produce.
    pub total_bytes: u64,
    /// True when `preview` is shorter than `total_bytes`.
    pub truncated: bool,
}

impl LsbCandidate {
    /// Stable fingerprint of the scanned prefix bytes (XXH3-64, the
    /// workspace hash) for deduplication.
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        xxh3_64(&self.preview)
    }

    /// Human-readable configuration, e.g. `RGB · b0 · Row · LSB`
    /// (upstream `formatConfig`).
    #[must_use]
    pub fn formatted_config(&self) -> String {
        let options = &self.options;
        if options.is_empty() {
            return "(none)".to_owned();
        }
        let mut parts: Vec<String> = Vec::new();

        // 1. Channel component.
        let has = |channel: Channel| (0..8).any(|plane| options.is_selected(channel, plane));
        let (has_a, has_r, has_g, has_b) = (
            has(Channel::Alpha),
            has(Channel::Red),
            has(Channel::Green),
            has(Channel::Blue),
        );
        let label = order_label(options.order);
        if has_r && has_g && has_b && !has_a {
            parts.push(label.to_owned());
        } else if has_r && has_g && has_b && has_a {
            parts.push(format!("A+{label}"));
        } else if has_r && !has_g && !has_b && !has_a {
            parts.push("R".to_owned());
        } else if !has_r && has_g && !has_b && !has_a {
            parts.push("G".to_owned());
        } else if !has_r && !has_g && has_b && !has_a {
            parts.push("B".to_owned());
        } else if !has_r && !has_g && !has_b && has_a {
            parts.push("A".to_owned());
        } else {
            let mut channels = String::new();
            if has_a {
                channels.push('A');
            }
            for channel in options.order.colours() {
                let letter = match channel {
                    Channel::Red if has_r => Some('R'),
                    Channel::Green if has_g => Some('G'),
                    Channel::Blue if has_b => Some('B'),
                    _ => None,
                };
                if let Some(letter) = letter {
                    channels.push(letter);
                }
            }
            parts.push(if channels.is_empty() {
                label.to_owned()
            } else {
                channels
            });
        }

        // 2. Bit planes component.
        let planes: Vec<u32> = (0..8u32)
            .filter(|plane| {
                [Channel::Alpha, Channel::Red, Channel::Green, Channel::Blue]
                    .iter()
                    .any(|channel| options.is_selected(*channel, *plane))
            })
            .collect();
        if !planes.is_empty() {
            let joined: Vec<String> = planes.iter().map(ToString::to_string).collect();
            parts.push(format!("b{}", joined.join(",")));
        }

        // 3-5. Traversal, bit order, inversion.
        parts.push(if options.row_first { "Row" } else { "Col" }.to_owned());
        parts.push(if options.lsb_first { "LSB" } else { "MSB" }.to_owned());
        if options.invert_bits {
            parts.push("Inverted".to_owned());
        }

        parts.join(" \u{b7} ")
    }
}

/// Executes one candidate Phase 1 evaluation synchronously and scores it.
///
/// `max_bytes` bounds the extract (the scan uses [`SCAN_PREFIX_LIMIT`]);
/// cancellation and deadlines come from `ctx`, checked per row inside the
/// extraction.
///
/// # Errors
///
/// Fails with [`cybercipher_core::OperationError`] on cancellation or when
/// the deadline is exceeded.
pub fn evaluate_candidate(
    image: &RgbaImage,
    region: Roi,
    options: ExtractionOptions,
    max_bytes: usize,
    ctx: &ExecutionContext,
) -> OpResult<LsbCandidate> {
    let result = extract_bounded(image, region, options, max_bytes, ctx)?;
    let info = payload::detect(&result.data);
    let evaluation = score_payload(&result.data, &info);
    Ok(LsbCandidate {
        options,
        score: evaluation.score,
        reason: evaluation.reason,
        payload_type: info.payload_type,
        entropy: info.entropy,
        distinct_bytes: info.distinct_bytes,
        preview: result.data,
        total_bytes: result.total_bytes,
        truncated: result.truncated,
    })
}

/// Incremental dedup + rank used by the scan (upstream: `LinkedHashMap`
/// keyed by `fingerprint + totalBytes`, options appended when truncated —
/// a matching bounded prefix does not prove identical full payloads).
///
/// On a duplicate key the candidate with the higher score replaces the
/// stored one in place; insertion order is kept otherwise, and `finish`
/// ranks by score descending with ties in insertion order (a stable sort,
/// as upstream).
#[derive(Debug, Default)]
pub struct DedupRanker {
    accepted: Vec<LsbCandidate>,
    index: HashMap<String, usize>,
}

impl DedupRanker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of accepted (deduplicated) candidates so far.
    pub fn len(&self) -> usize {
        self.accepted.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accepted.is_empty()
    }

    /// Inserts a candidate; returns true when it was accepted (new key, or
    /// a higher score than the stored candidate for the same key).
    pub fn push(&mut self, candidate: LsbCandidate) -> bool {
        let key = dedup_key(&candidate);
        match self.index.get(&key) {
            None => {
                self.index.insert(key, self.accepted.len());
                self.accepted.push(candidate);
                true
            }
            Some(&slot) => {
                if candidate.score > self.accepted[slot].score {
                    self.accepted[slot] = candidate;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Ranks the accepted candidates: score descending, ties in insertion
    /// order.
    pub fn finish(self) -> Vec<LsbCandidate> {
        let mut accepted = self.accepted;
        accepted.sort_by_key(|candidate| std::cmp::Reverse(candidate.score));
        accepted
    }
}

/// The dedup key: `fingerprint + total_bytes`, plus the full configuration
/// when the extract is truncated (a matching prefix does not prove that
/// two truncated extracts agree beyond the prefix).
fn dedup_key(candidate: &LsbCandidate) -> String {
    let base = format!("{:016x}:{}", candidate.fingerprint(), candidate.total_bytes);
    if candidate.truncated {
        format!(
            "{base}:{}|{}|{}|{}|{}",
            candidate.options.plane_mask,
            candidate.options.order.legacy_code(),
            candidate.options.lsb_first as u8,
            candidate.options.row_first as u8,
            candidate.options.invert_bits as u8,
        )
    } else {
        base
    }
}

/// Runs a bounded, cancellable Phase 1 scan with the upstream prefix limit
/// ([`SCAN_PREFIX_LIMIT`]).
///
/// # Errors
///
/// Fails with [`cybercipher_core::OperationError`] on cancellation or
/// deadline blowout.
pub fn scan(
    image: &RgbaImage,
    region: Roi,
    deep: bool,
    ctx: &ExecutionContext,
    on_progress: impl FnMut(usize, usize, usize),
) -> OpResult<Vec<LsbCandidate>> {
    scan_with_limits(image, region, deep, SCAN_PREFIX_LIMIT, ctx, on_progress)
}

/// Runs a bounded, cancellable Phase 1 scan with an explicit prefix limit.
///
/// `on_progress` receives `(completed, total, deduplicated_candidates)` —
/// called every 8 candidates and once at the end, as upstream.
///
/// # Errors
///
/// Fails with [`cybercipher_core::OperationError`] on cancellation or
/// deadline blowout.
pub fn scan_with_limits(
    image: &RgbaImage,
    region: Roi,
    deep: bool,
    prefix_bytes: usize,
    ctx: &ExecutionContext,
    mut on_progress: impl FnMut(usize, usize, usize),
) -> OpResult<Vec<LsbCandidate>> {
    let options_list = if deep {
        deep_scan_options(image.has_alpha)
    } else {
        fast_scan_options(image.has_alpha)
    };
    let total = options_list.len();

    let mut ranker = DedupRanker::new();
    for (index, &options) in options_list.iter().enumerate() {
        ctx.check()?;
        let candidate = evaluate_candidate(image, region, options, prefix_bytes, ctx)?;
        ranker.push(candidate);
        let completed = index + 1;
        if completed % 8 == 0 || completed == total {
            on_progress(completed, total, ranker.len());
        }
    }
    Ok(ranker.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cybercipher_core::ErrorKind;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    fn ctx() -> ExecutionContext {
        ExecutionContext::new()
    }

    fn evaluate(data: &[u8]) -> Evaluation {
        score_payload(data, &payload::detect(data))
    }

    // ------------------------------------------------------- enumeration

    /// Per-group totals of the upstream `AutoLsbScanner.fastScanOptions`:
    /// 24 + 4 + 4 + 48 + 8 + 30 = 118 without alpha, +12 with.
    #[test]
    fn fast_enumeration_counts_match_upstream() {
        assert_eq!(fast_scan_options(false).len(), 118);
        assert_eq!(fast_scan_options(true).len(), 130);
    }

    /// Deep = Fast + 16 + 8 + 4 + 12 = 158 / 170.
    #[test]
    fn deep_enumeration_counts_match_upstream() {
        assert_eq!(deep_scan_options(false).len(), 158);
        assert_eq!(deep_scan_options(true).len(), 170);
        let fast = fast_scan_options(false);
        let deep = deep_scan_options(false);
        assert_eq!(&deep[..fast.len()], &fast[..], "deep extends fast");
        let fast_alpha = fast_scan_options(true);
        let deep_alpha = deep_scan_options(true);
        assert_eq!(&deep_alpha[..fast_alpha.len()], &fast_alpha[..]);
    }

    #[test]
    fn all_enumerated_options_are_distinct() {
        // Deep intentionally extends fast, so each list is checked for
        // internal distinctness with its own set.
        for list in [
            fast_scan_options(false),
            deep_scan_options(false),
            fast_scan_options(true),
            deep_scan_options(true),
        ] {
            let mut seen = std::collections::HashSet::new();
            for options in list {
                assert!(seen.insert(format!("{options:?}")), "duplicate {options:?}");
            }
        }
    }

    #[test]
    fn pinned_fast_group_boundaries() {
        let fast = fast_scan_options(false);
        // Group 1: RGB bit 0, six orders x row x invert. First entry is the
        // canonical RGB-bit-0 configuration (LSB plane order; the crate
        // `ExtractionOptions::default` differs in `lsb_first` and is not
        // part of the enumeration).
        let expected_first = ExtractionOptions::none()
            .with_plane(Channel::Red, 0, true)
            .with_plane(Channel::Green, 0, true)
            .with_plane(Channel::Blue, 0, true)
            .with_order(RgbOrder::Rgb)
            .with_row_first(true)
            .with_lsb_first(true);
        assert_eq!(fast[0], expected_first);
        assert_eq!(fast[0].describe(), "r0 g0 b0");
        // ARGB space: red occupies the high byte, so r0g0b0 spreads over
        // 0x00010101 (plane space is 0x01010100).
        assert_eq!(fast[0].argb_mask(), 0x0001_0101);
        assert!(fast[0].lsb_first && fast[0].row_first && !fast[0].invert_bits);
        assert!(fast[3].invert_bits); // first order, row, inverted
        assert_eq!(fast[4].order, RgbOrder::Rbg); // second order starts at 4
        assert_eq!(fast[23].order, RgbOrder::Bgr);
        assert!(fast[23].invert_bits && !fast[23].row_first);

        // Group 2 (24..28): RGB bit 1, {RGB, BGR} x row/col.
        assert_eq!(fast[24].plane_mask, 0x0202_0200);
        assert_eq!(fast[24].describe(), "r1 g1 b1");
        assert_eq!(fast[26].order, RgbOrder::Bgr);
        // Group 3 (28..32): RGB bit 2.
        assert_eq!(fast[28].plane_mask, 0x0404_0400);
        assert_eq!(fast[28].describe(), "r2 g2 b2");
        // Group 4 (32..80): RGB bits 0+1, six orders x row x msb/lsb x invert.
        assert_eq!(fast[32].plane_mask, 0x0303_0300);
        assert_eq!(fast[32].describe(), "r1 r0 g1 g0 b1 b0");
        assert!(fast[32].lsb_first && !fast[32].invert_bits);
        assert!(fast[33].invert_bits);
        assert!(!fast[34].lsb_first); // MSB-first plane order
        assert_eq!(fast[79].order, RgbOrder::Bgr);
        // Group 5 (80..88): RGB bits 0+1+2, {RGB, BGR} x row x msb/lsb.
        assert_eq!(fast[80].plane_mask, 0x0707_0700);
        assert_eq!(fast[80].describe(), "r2 r1 r0 g2 g1 g0 b2 b1 b0");
        assert_eq!(fast[84].order, RgbOrder::Bgr);
        // Group 6 (88..118): single channels.
        assert_eq!(fast[88].describe(), "r0");
        assert_eq!(fast[88].plane_mask, 0x0000_0100);
        assert!(fast[89].invert_bits);
        assert_eq!(fast[90].describe(), "r1");
        assert_eq!(fast[91].describe(), "r1 r0");
        assert!(fast[91].lsb_first);
        assert!(!fast[92].lsb_first);
        assert!(!fast[93].row_first);
        assert_eq!(fast[98].describe(), "g0");
        assert_eq!(fast[98].plane_mask, 0x0001_0000);
        assert_eq!(fast[108].describe(), "b0");
        assert_eq!(fast[108].plane_mask, 0x0100_0000);
    }

    #[test]
    fn pinned_alpha_and_deep_groups() {
        let fast = fast_scan_options(true);
        // Alpha bit 0 (118..122), RGBA bit 0 (122..130).
        assert_eq!(fast[118].describe(), "a0");
        assert_eq!(fast[118].plane_mask, 0x0000_0001);
        assert!(fast[118].row_first && !fast[118].invert_bits);
        assert!(fast[119].invert_bits);
        assert!(!fast[120].row_first);
        assert_eq!(fast[122].describe(), "a0 r0 g0 b0");
        assert_eq!(fast[122].plane_mask, 0x0101_0101);
        assert_eq!(fast[122].argb_mask(), 0x0101_0101);
        assert_eq!(fast[126].order, RgbOrder::Bgr);
        // Without alpha none of the alpha variants are enumerated.
        assert_eq!(fast_scan_options(false).len(), 118);

        let deep = deep_scan_options(false);
        // 3-bit LSB across the remaining four permutations (118..134).
        assert_eq!(deep[118].plane_mask, 0x0707_0700);
        assert_eq!(deep[118].order, RgbOrder::Rbg);
        assert!(deep[118].lsb_first);
        assert!(!deep[119].lsb_first);
        assert_eq!(deep[122].order, RgbOrder::Grb);
        // 4-bit LSB (134..142).
        assert_eq!(deep[134].plane_mask, 0x0F0F_0F00);
        assert_eq!(deep[134].order, RgbOrder::Rgb);
        assert!(deep[134].lsb_first);
        // MSB bit 7 (142..146).
        assert_eq!(deep[142].plane_mask, 0x8080_8000);
        assert_eq!(deep[142].describe(), "r7 g7 b7");
        assert!(!deep[142].lsb_first);
        // Single channel bit 2 / bit 7 (146..158); per traversal the bit-2
        // (LSB) entry precedes the bit-7 (MSB) entry.
        assert_eq!(deep[146].describe(), "r2");
        assert!(deep[146].lsb_first);
        assert_eq!(deep[147].describe(), "r7");
        assert!(!deep[147].lsb_first);
        assert_eq!(deep[148].describe(), "r2");
        assert!(!deep[148].row_first);
        assert_eq!(deep[154].describe(), "b2");
        assert_eq!(deep[155].describe(), "b7");
        assert!(!deep[155].lsb_first);
    }

    #[test]
    fn formatted_config_matches_upstream_format() {
        let candidate = |options: ExtractionOptions| LsbCandidate {
            options,
            score: 0,
            reason: String::new(),
            payload_type: PayloadType::Binary,
            entropy: 0.0,
            distinct_bytes: 0,
            preview: Vec::new(),
            total_bytes: 0,
            truncated: false,
        };
        // The crate default (MSB plane order) formats the same way; the
        // enumeration entries use LSB.
        assert_eq!(
            candidate(ExtractionOptions::default()).formatted_config(),
            "RGB \u{b7} b0 \u{b7} Row \u{b7} MSB"
        );
        let alpha_only = single_channel_options(Channel::Alpha, &[0], false, true, false);
        assert_eq!(
            candidate(alpha_only).formatted_config(),
            "A \u{b7} b0 \u{b7} Col \u{b7} LSB"
        );
        let rgba = fast_scan_options(true)[122];
        assert_eq!(
            candidate(rgba).formatted_config(),
            "A+RGB \u{b7} b0 \u{b7} Row \u{b7} LSB"
        );
        let inverted = single_channel_options(Channel::Red, &[1], false, true, true);
        assert_eq!(
            candidate(inverted).formatted_config(),
            "R \u{b7} b1 \u{b7} Col \u{b7} LSB \u{b7} Inverted"
        );
        assert_eq!(
            candidate(ExtractionOptions::none()).formatted_config(),
            "(none)"
        );
    }

    // ---------------------------------------------------------- scoring

    #[test]
    fn empty_and_uniform_payloads() {
        assert_eq!(
            evaluate(b""),
            Evaluation {
                score: 0,
                reason: "Empty extract".to_owned()
            }
        );
        assert_eq!(
            evaluate(&[0x00u8; 32]),
            Evaluation {
                score: 1,
                reason: "Uniform byte sequence (all 0x0)".to_owned()
            }
        );
        assert_eq!(
            evaluate(&[0xFFu8; 9]),
            Evaluation {
                score: 1,
                reason: "Uniform byte sequence (all 0xff)".to_owned()
            }
        );
        // Uniform check beats the text tiers.
        assert_eq!(evaluate(&[b'#'; 8]).score, 1);
    }

    #[test]
    fn strong_magic_signatures_score_100() {
        let cases: &[(&[u8], &str)] = &[
            (
                b"PK\x03\x04\x14\x00....",
                "ZIP archive signature (PK\\x03\\x04)",
            ),
            (b"7z\xBC\xAF\x27\x1C....", "7-Zip archive signature"),
            (b"Rar!\x1A\x07\x00....", "RAR archive signature"),
            (
                b"\x1F\x8B\x08\x00.......",
                "gzip compressed stream signature",
            ),
            (b"BZh9...............", "bzip2 compressed stream signature"),
            (b"\xFD7zXZ\x00........", "xz compressed stream signature"),
            (b"\x89PNG\r\n\x1A\nIHDR....", "PNG image signature"),
            (b"\xFF\xD8\xFF\xE0........", "JPEG image signature"),
            (b"GIF89a\x01\x00\x01\x00..", "GIF image signature"),
            (
                b"RIFF\x24\x00\x00\x00WEBPVP8 ",
                "WebP image container signature",
            ),
            (b"%PDF-1.7\n...........", "PDF document signature"),
            (
                b"\x7FELF\x02\x01\x01\x00....",
                "ELF executable / shared object header",
            ),
            (
                b"\xCA\xFE\xBA\xBE\x00\x00\x00\x34",
                "Java class bytecode (0xCAFEBABE)",
            ),
        ];
        for (data, reason) in cases {
            let evaluation = evaluate(data);
            assert_eq!(evaluation.score, 100, "{reason}");
            assert_eq!(&evaluation.reason, reason);
        }
        let mut tar = vec![0u8; 300];
        tar[257..262].copy_from_slice(b"ustar");
        assert_eq!(evaluate(&tar).score, 100);
        assert_eq!(evaluate(&tar).reason, "tar archive magic (ustar)");
    }

    #[test]
    fn bmp_and_pe_partial_signatures() {
        // BMP needs at least 14 bytes for the 95 tier.
        let mut bmp = b"BM".to_vec();
        bmp.extend_from_slice(&[0u8; 12]);
        assert_eq!(
            evaluate(&bmp),
            Evaluation {
                score: 95,
                reason: "BMP bitmap signature".to_owned()
            }
        );
        assert_eq!(evaluate(b"BM").score, 80);

        // Verified PE header.
        let mut pe = vec![0u8; 0x44];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        assert_eq!(
            evaluate(&pe),
            Evaluation {
                score: 100,
                reason: "Windows PE executable header".to_owned()
            }
        );
        // Bare MZ without a verifiable signature.
        assert_eq!(
            evaluate(b"MZ..........."),
            Evaluation {
                score: 65,
                reason: "Possible MZ header (PE signature not verified)".to_owned()
            }
        );
    }

    #[test]
    fn ctf_flag_scores_98_and_beats_magic() {
        let mut payload = b"garbage prefix ".to_vec();
        payload.extend_from_slice(b"flag{test_1234}");
        payload.extend_from_slice(b" trailing");
        assert_eq!(
            evaluate(&payload),
            Evaluation {
                score: 98,
                reason: "CTF flag: flag{test_1234}".to_owned()
            }
        );
        // Case-insensitive keywords; alternation finds the leftmost match.
        assert_eq!(
            evaluate(b"xx picoCTF{and_flags} xx").reason,
            "CTF flag: CTF{and_flags}"
        );
        // The flag check runs before the magic switch.
        let mut zip = b"PK\x03\x04\x00\x00".to_vec();
        zip.extend_from_slice(b"flag{inside_zip}");
        assert_eq!(evaluate(&zip).score, 98);
        // Greedy {1,128}: the match ends at the last possible brace.
        assert_eq!(evaluate(b"flag{a}b} xx").reason, "CTF flag: flag{a}b}");
    }

    #[test]
    fn ctf_flag_window_is_16_kib() {
        let mut inside = vec![b'A'; 16_000];
        inside.extend_from_slice(b"flag{window_hit}");
        assert_eq!(evaluate(&inside).score, 98);

        // Outside the 16 KiB window the payload falls through to the text
        // tiers (all printable, no spaces -> 86).
        let mut outside = vec![b'A'; 17_000];
        let start = 16_500;
        outside[start..start + 16].copy_from_slice(b"flag{too_deeply}");
        assert_eq!(evaluate(&outside).score, 86);
    }

    #[test]
    fn text_tiers_90_86_80() {
        assert_eq!(
            evaluate(b"hello world example text"),
            Evaluation {
                score: 90,
                reason: "Readable ASCII text".to_owned()
            }
        );
        // Multi-byte UTF-8 with spaces stays readable while the strict
        // printable ratio stays above 0.90.
        let utf8 =
            "this is readable utf8 text with one \u{e9} and many ascii spaces to pad the ratio";
        assert_eq!(
            evaluate(utf8.as_bytes()),
            Evaluation {
                score: 90,
                reason: "Readable UTF-8 text".to_owned()
            }
        );
        // No spaces: valid but not readable. (21 chars so the shape is not
        // a valid base64 blob — that classification runs first.)
        assert_eq!(
            evaluate(b"abcdefghijklmnopqrstu"),
            Evaluation {
                score: 86,
                reason: "Valid ASCII text".to_owned()
            }
        );
        // Whitespace bytes are not upstream-printable, dragging the ratio
        // down to the base tier (41 bytes: not base64-shaped either).
        let mut sparse = vec![b'a'; 21];
        sparse.extend_from_slice(&[b'\n'; 20]);
        assert_eq!(
            evaluate(&sparse),
            Evaluation {
                score: 80,
                reason: "Text sequence".to_owned()
            }
        );
    }

    #[test]
    fn base64_tiers_72_and_45() {
        assert_eq!(
            evaluate(b"QUJDREVGR0hJSktMTU5PUQ=="),
            Evaluation {
                score: 72,
                reason: "Base64 alphabet and length match".to_owned()
            }
        );
        assert_eq!(
            evaluate(b"QUJDREVGR0g="),
            Evaluation {
                score: 45,
                reason: "Short possible Base64 text".to_owned()
            }
        );
    }

    #[test]
    fn script_json_xml_tiers_are_binary_classified() {
        // A pure-ASCII shebang classifies as text; the 94 tier requires the
        // payload to be BINARY-classified (upstream checks it inside the
        // BINARY arm only).
        assert_eq!(evaluate(b"#!/bin/sh\nls -la").score, 90);
        assert_eq!(
            evaluate(b"#!/usr/bin/env\x00python"),
            Evaluation {
                score: 94,
                reason: "Script executable header (#!)".to_owned()
            }
        );
        // JSON/XML tiers likewise: an invalid byte forces BINARY while the
        // structure check tolerates it.
        assert_eq!(
            evaluate(b"{\"key\": \"v\xFFalue\", \"n\": 1}").reason,
            "JSON structured text"
        );
        assert_eq!(evaluate(b"{\"key\": \"v\xFFalue\", \"n\": 1}").score, 92);
        assert_eq!(
            evaluate(b"  <!doctype html>\xFF<html>").reason,
            "XML/HTML markup"
        );
        assert_eq!(evaluate(b"<?xml version=\"1.0\"?\xFF>").score, 92);
        assert_eq!(evaluate(b"<svg\xFFxmlns=\"x\">").score, 92);
        // An ASCII JSON object is plain readable text, not the JSON tier.
        assert_eq!(evaluate(b"{\"key\": \"value\"}").score, 90);
    }

    #[test]
    fn binary_tiers_65_5_15_30_20() {
        // Partially printable.
        let mut partial = vec![b'A'; 71];
        partial.extend_from_slice(&[0x00; 29]);
        assert_eq!(
            evaluate(&partial),
            Evaluation {
                score: 65,
                reason: "Partially printable text fragments".to_owned()
            }
        );
        // Low byte variation.
        let low_variation = [0u8, 1, 2].repeat(40);
        assert_eq!(
            evaluate(&low_variation),
            Evaluation {
                score: 5,
                reason: "Low byte variation".to_owned()
            }
        );
        // Structured binary: 32 distinct values, entropy exactly 5.0.
        let structured = (0..=31u8).collect::<Vec<u8>>().repeat(32);
        assert_eq!(
            evaluate(&structured),
            Evaluation {
                score: 30,
                reason: "Structured binary data".to_owned()
            }
        );
        // Unrecognised binary: few distinct values, entropy below 3.0.
        let mut unrecognised = vec![0u8; 90];
        for byte in 1..=4u8 {
            unrecognised.extend_from_slice(&[byte, byte]);
        }
        assert_eq!(
            evaluate(&unrecognised),
            Evaluation {
                score: 20,
                reason: "Unrecognised binary data".to_owned()
            }
        );
        // High-entropy noise: deterministic PRNG stream, 4096 bytes.
        let noise = pseudo_random(4096);
        assert_eq!(
            evaluate(&noise),
            Evaluation {
                score: 15,
                reason: "High-entropy unrecognised binary noise".to_owned()
            }
        );
    }

    /// Deterministic 64-bit LCG stream (no external PRNG dependency).
    fn pseudo_random(len: usize) -> Vec<u8> {
        let mut state = 0x0123_4567_89AB_CDEFu64;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (state >> 33) as u8
            })
            .collect()
    }

    // -------------------------------------------------- candidate + scan

    /// 32x32 image with `message` hidden in the RGB bit-0 planes,
    /// MSB-first bit packing, row-major (the crate default configuration).
    fn image_with_hidden_rgb_bit0(message: &[u8], alpha: bool) -> RgbaImage {
        let (width, height) = (32u32, 32u32);
        let mut bits = Vec::with_capacity(message.len() * 8);
        for &byte in message {
            for shift in (0..8).rev() {
                bits.push((byte >> shift) & 1);
            }
        }
        let mut argb = Vec::with_capacity((width * height) as usize);
        for pixel_index in 0..(width * height) as usize {
            // Base colour with clear low bits so unrelated planes stay 0.
            let mut pixel = 0xFF40_4040;
            for (lane, shift) in [16u32, 8, 0].into_iter().enumerate() {
                let bit_index = pixel_index * 3 + lane;
                let bit = if bit_index < bits.len() {
                    bits[bit_index]
                } else {
                    0
                };
                pixel = (pixel & !(1 << shift)) | (u32::from(bit) << shift);
            }
            argb.push(pixel);
        }
        RgbaImage::new(width, height, argb, alpha).unwrap()
    }

    #[test]
    fn scan_ranks_hidden_payload_top_and_apply_recovers_it() {
        let message = b"flag{auto_lsb_scan_works}";
        let image = image_with_hidden_rgb_bit0(message, false);
        let candidates =
            scan(&image, Roi::whole(32, 32), false, &ctx(), |_, _, _| {}).expect("scan succeeds");
        assert!(!candidates.is_empty());
        assert!(
            candidates.windows(2).all(|w| w[0].score >= w[1].score),
            "candidates are ranked by score descending"
        );

        let top = &candidates[0];
        assert_eq!(top.score, 98);
        assert_eq!(top.reason, "CTF flag: flag{auto_lsb_scan_works}");
        // The winning configuration is the first enumerated one: RGB bit 0,
        // RGB order, row-major, LSB plane order, no inversion.
        assert_eq!(top.options, fast_scan_options(false)[0]);
        assert_eq!(top.total_bytes, 384); // 1024 pixels * 3 planes / 8
        assert!(!top.truncated);
        assert!(
            top.preview.starts_with(message),
            "preview carries the message"
        );

        // Phase 2 = full extraction with the candidate's options.
        let applied =
            extract_bounded(&image, Roi::whole(32, 32), top.options, 4096, &ctx()).unwrap();
        assert_eq!(&applied.data[..message.len()], message);
        assert_eq!(applied.total_bytes, 384);
        assert!(!applied.truncated);
    }

    #[test]
    fn evaluate_candidate_reports_tiers() {
        let image = image_with_hidden_rgb_bit0(b"\x00\x01\x02", false);
        let candidate = evaluate_candidate(
            &image,
            Roi::whole(32, 32),
            ExtractionOptions::default(),
            16,
            &ctx(),
        )
        .unwrap();
        assert_eq!(candidate.preview.len(), 16); // capped by max_bytes
        assert_eq!(candidate.total_bytes, 384); // 1024 pixels * 3 planes / 8
        assert!(candidate.truncated);
        assert_eq!(candidate.payload_type, PayloadType::Binary);
        assert_eq!(candidate.score, 5); // low byte variation
        assert_eq!(candidate.reason, "Low byte variation");
    }

    #[test]
    fn scan_reports_progress_every_eight_and_at_end() {
        let image = image_with_hidden_rgb_bit0(b"ok", false);
        let mut events = Vec::new();
        let total = fast_scan_options(false).len();
        scan(
            &image,
            Roi::whole(32, 32),
            false,
            &ctx(),
            |completed, total, matches| {
                events.push((completed, total, matches));
            },
        )
        .unwrap();
        assert_eq!(events.last().unwrap().0, total);
        assert_eq!(events.last().unwrap().1, total);
        for event in &events[..events.len() - 1] {
            assert_eq!(event.0 % 8, 0, "intermediate events every 8: {event:?}");
        }
        assert!(events.len() >= 2);
        // The deduplicated count never exceeds the completed count.
        assert!(events
            .iter()
            .all(|(completed, _, matches)| matches <= completed));
    }

    #[test]
    fn scan_is_cancellable_mid_scan() {
        let image = image_with_hidden_rgb_bit0(b"cancel me", false);
        let flag = Arc::new(AtomicBool::new(false));
        let ctx = ExecutionContext::new().with_cancel(flag.clone());
        let result = scan(
            &image,
            Roi::whole(32, 32),
            false,
            &ctx,
            |completed, _, _| {
                if completed >= 8 {
                    flag.store(true, Ordering::Relaxed);
                }
            },
        );
        let err = result.expect_err("cancelled scan is an error");
        assert_eq!(err.kind, ErrorKind::Cancelled);
    }

    #[test]
    fn deadline_is_honoured_during_scan() {
        let image = image_with_hidden_rgb_bit0(b"late", false);
        let ctx = ExecutionContext::new()
            .with_deadline(std::time::Instant::now() - std::time::Duration::from_secs(1));
        let err = scan(&image, Roi::whole(32, 32), false, &ctx, |_, _, _| {})
            .expect_err("expired deadline is an error");
        assert_eq!(err.kind, ErrorKind::BudgetExceeded);
    }

    // ------------------------------------------------------- dedup + rank

    fn candidate_for(
        options: ExtractionOptions,
        preview: &[u8],
        total_bytes: u64,
        truncated: bool,
        score: u32,
    ) -> LsbCandidate {
        LsbCandidate {
            options,
            score,
            reason: format!("score {score}"),
            payload_type: PayloadType::Binary,
            entropy: 1.0,
            distinct_bytes: 4,
            preview: preview.to_vec(),
            total_bytes,
            truncated,
        }
    }

    #[test]
    fn dedup_collapses_identical_complete_extracts() {
        let preview = b"same payload bytes".to_vec();
        let rgb = single_channel_options(Channel::Red, &[0], true, true, false);
        let bgr = rgb.with_order(RgbOrder::Bgr); // identical extract, different config
        let mut ranker = DedupRanker::new();
        assert!(ranker.push(candidate_for(rgb, &preview, 18, false, 86)));
        assert!(!ranker.push(candidate_for(bgr, &preview, 18, false, 86)));
        assert_eq!(ranker.len(), 1);
        let ranked = ranker.finish();
        assert_eq!(ranked.len(), 1);
        // Ties keep the first inserted candidate.
        assert_eq!(ranked[0].options, rgb);
    }

    #[test]
    fn dedup_keeps_higher_scoring_duplicate_in_place() {
        let preview = b"escalating".to_vec();
        let rgb = single_channel_options(Channel::Red, &[0], true, true, false);
        let mut ranker = DedupRanker::new();
        assert!(ranker.push(candidate_for(rgb, &preview, 10, false, 65)));
        let bgr = rgb.with_order(RgbOrder::Bgr);
        assert!(ranker.push(candidate_for(bgr, &preview, 10, false, 94)));
        assert_eq!(ranker.len(), 1);
        assert_eq!(ranker.finish()[0].score, 94);
    }

    #[test]
    fn truncated_same_prefix_with_different_options_is_not_collapsed() {
        let prefix = vec![0xABu8; 32];
        let rgb = single_channel_options(Channel::Red, &[0], true, true, false);
        let bgr = rgb.with_order(RgbOrder::Bgr);
        let mut ranker = DedupRanker::new();
        assert!(ranker.push(candidate_for(rgb, &prefix, 65_704, true, 20)));
        // Same prefix, same total, but truncated: the options stay part of
        // the key.
        assert!(ranker.push(candidate_for(bgr, &prefix, 65_704, true, 20)));
        assert_eq!(ranker.len(), 2);
        // A non-truncated twin would collapse instead.
        let mut ranker = DedupRanker::new();
        assert!(ranker.push(candidate_for(rgb, &prefix, 32, false, 20)));
        assert!(!ranker.push(candidate_for(bgr, &prefix, 32, false, 20)));
        assert_eq!(ranker.len(), 1);
    }

    #[test]
    fn rank_keeps_insertion_order_for_ties() {
        let mut ranker = DedupRanker::new();
        for (index, score) in [30u32, 90, 5, 90].into_iter().enumerate() {
            let options = single_channel_options(Channel::Red, &[0], true, true, false);
            // Distinct previews: identical payloads would be deduplicated
            // before ranking ever sees them.
            let preview = format!("payload-{index}-{score}").into_bytes();
            ranker.push(candidate_for(
                options,
                &preview,
                preview.len() as u64,
                false,
                score,
            ));
        }
        let ranked = ranker.finish();
        let scores: Vec<u32> = ranked.iter().map(|c| c.score).collect();
        assert_eq!(scores, vec![90, 90, 30, 5]);
        // The two 90s stay in insertion order (stable sort).
        assert_eq!(ranked[0].reason, "score 90");
        assert_eq!(ranked[1].reason, "score 90");
    }

    #[test]
    fn scan_dedups_equivalent_single_channel_configurations() {
        // Hide the message in the red bit-0 plane only: all six RGB orders
        // produce byte-identical extracts and must collapse to one entry.
        let message = b"hidden in red";
        let (width, height) = (16u32, 16u32);
        let mut bits = Vec::new();
        for &byte in message {
            for shift in (0..8).rev() {
                bits.push((byte >> shift) & 1);
            }
        }
        let mut argb = Vec::new();
        for pixel_index in 0..(width * height) as usize {
            let bit = if pixel_index < bits.len() {
                bits[pixel_index]
            } else {
                0
            };
            // 0xFF404040: red bit 0 carries the payload, g/b stay clear.
            argb.push(0xFF40_4040 | (u32::from(bit) << 16));
        }
        let image = RgbaImage::new(width, height, argb, false).unwrap();
        let candidates =
            scan(&image, Roi::whole(16, 16), false, &ctx(), |_, _, _| {}).expect("scan succeeds");
        let hits: Vec<&LsbCandidate> = candidates
            .iter()
            .filter(|c| c.preview.starts_with(message))
            .collect();
        assert_eq!(hits.len(), 1, "one deduplicated red-bit0 candidate");
        assert_eq!(hits[0].options.plane_mask, 0x0000_0100);
        assert_eq!(hits[0].options.order, RgbOrder::Rgb);
        // "hidden in red" + zero padding: binary, few distinct bytes.
        assert_eq!(hits[0].score, 20);
    }
}
