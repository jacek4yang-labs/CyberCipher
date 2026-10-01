//! QR / barcode scanning with a bytes-first payload model.
//!
//! Port of the StegSolver `barcode` package (reference commit `c14bfa9`, MIT:
//! `BarcodeScanner`, `ScanOptions`, `ScanResult`, `BarcodeHit`, `HitMerge`,
//! `RotationMapper`, `StructuredAppendMerger`) onto the [`rxing`] crate — the
//! maintained Rust port of the same ZXing base the reference builds on, so the
//! decode semantics (1D+2D format breadth, byte segments, Structured Append,
//! mirrored-QR correction) carry over.
//!
//! The scanner is deliberately greedy but honest about payloads:
//!
//! - the whole image or a clamped region of interest can be scanned;
//! - `TRY_HARDER` is always on, with practical fallbacks — inverted polarity,
//!   quarter turns and a bounded rescale chain, each stage only running when
//!   every earlier attempt came up empty and each cancellable through the
//!   [`ExecutionContext`];
//! - several symbols in one image are found through a QR multi-symbol pass
//!   (whose Structured Append parts are kept separate, exactly like the
//!   reference's `MultiDetector` path) plus a generic multi-format reader and
//!   a single-symbol pass on every attempt bitmap;
//! - QR Structured Append parts are merged explicitly, validated and in index
//!   order — an incomplete or conflicting sequence is never guessed;
//! - the binary payload is the decoder's byte segments concatenated verbatim —
//!   it is never rebuilt from the decoded text;
//! - found positions are mapped back through rotation/scale into original
//!   image coordinates;
//! - payloads are classified with the shared [`crate::payload`] detector and
//!   are never opened, unpacked or executed.

use std::collections::BTreeMap;

use cybercipher_core::{ExecutionContext, OpResult, OperationError, ParamMap, Value};
use cybercipher_media::{RgbaImage, Roi};
use rxing::common::DetectorRXingResult as _;
use rxing::multi::MultipleBarcodeReader as _;
use rxing::qrcode::decoder::qrcode_decoder::decode_bitmatrix_with_hints;
use rxing::Reader as _;
use rxing::{
    common::{GlobalHistogramBinarizer, HybridBinarizer},
    multi::{qrcode::detector::MultiDetector, GenericMultipleBarcodeReader},
    qrcode::decoder::QRCodeDecoderMetaData,
    BinaryBitmap, DecodeHints, LuminanceSource, MultiFormatReader, RGBLuminanceSource, RXingResult,
    RXingResultMetadataValue,
};

use crate::payload::{self, PayloadInfo};

/// Largest side below which a scan copy is upscaled for the rescale fallback
/// (upstream `UPSCALE_THRESHOLD_PX`).
const UPSCALE_THRESHOLD_PX: u32 = 400;
/// Largest side above which a scan copy is downscaled for the rescale fallback
/// (upstream `DOWNSCALE_THRESHOLD_PX`).
const DOWNSCALE_THRESHOLD_PX: u32 = 2600;
/// Distance below which two hits with the same content are considered the same
/// symbol (upstream `HitMerge.DUPLICATE_DISTANCE_PX`).
const DUPLICATE_DISTANCE_PX: f32 = 12.0;
/// Maximum Structured Append sequence length (QR specification; upstream
/// `StructuredAppend.MAX_SYMBOLS`).
pub const SA_MAX_SYMBOLS: usize = 16;
/// Padding applied around the mapped symbol points for the bounding box
/// (upstream `boundsOf`).
const BOUNDS_PADDING: f32 = 3.0;
/// Bounded hex preview size for a hit.
const PREVIEW_BYTES: usize = 256;
/// Default `max_symbols` (mirrors the everyday upstream defaults).
pub const DEFAULT_MAX_SYMBOLS: usize = 16;
/// Hard cap for `max_symbols`.
pub const MAX_SYMBOLS_CAP: usize = 64;

/// Options of a barcode scan (upstream `ScanOptions`, reduced to the knobs the
/// registry op exposes; `TRY_HARDER` is always on, as upstream default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanOptions {
    /// Also scans an inverted copy, for light symbols on a dark background.
    pub try_inverted: bool,
    /// Also tries quarter turns of the image (90/180/270 degrees).
    pub try_rotations: bool,
    /// Adds the rescale fallback (and the alternate binarizer) when every
    /// earlier attempt came up empty.
    pub try_rescale: bool,
    /// Maximum number of reported symbols (hard cap [`MAX_SYMBOLS_CAP`]).
    pub max_symbols: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            try_inverted: true,
            try_rotations: true,
            try_rescale: false,
            max_symbols: DEFAULT_MAX_SYMBOLS,
        }
    }
}

/// Structured Append information of a QR symbol: a long message can be split
/// over up to 16 symbols, each carrying its position and a parity byte that
/// identifies the sequence (upstream `StructuredAppend`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructuredAppend {
    /// 0-based position of the symbol in the sequence.
    pub index: usize,
    /// Number of symbols in the sequence (1..=16).
    pub total: usize,
    /// The parity byte shared by all symbols of the sequence.
    pub parity: u8,
}

impl StructuredAppend {
    /// Builds the record from the raw 8-bit sequence value the decoder exposes
    /// (index in the high nibble) plus the parity byte (upstream
    /// `StructuredAppend.fromRawSequence`).
    fn from_raw(sequence: i32, parity: i32) -> Option<Self> {
        if sequence < 0 {
            return None;
        }
        let index = ((sequence >> 4) & 0x0f) as usize;
        let total = ((sequence & 0x0f) + 1) as usize;
        if index >= total || total > SA_MAX_SYMBOLS {
            return None;
        }
        Some(StructuredAppend {
            index,
            total,
            parity: (parity & 0xff) as u8,
        })
    }
}

/// One decoded symbol, reported bytes-first (upstream `BarcodeHit`): the
/// binary payload is the decoder's byte segments and is never rebuilt from
/// `text`.
#[derive(Debug, Clone, PartialEq)]
pub struct BarcodeHit {
    /// Decoder format name, e.g. `QR_CODE`, `DATA_MATRIX`, `CODE_128`.
    pub format: String,
    /// Decoded text when the decoder produced a printable one; `None` for
    /// binary-only symbols.
    pub text: Option<String>,
    /// Exact binary payload: the decoder's byte segments concatenated
    /// verbatim; `None` when the symbol carries no byte segments (text only).
    pub payload: Option<Vec<u8>>,
    /// The decoder's raw bytes (codewords); kept for provenance, never a
    /// substitute for [`BarcodeHit::payload`].
    pub raw_bytes: Option<Vec<u8>>,
    /// Symbol corner points in original image coordinates.
    pub points: Vec<(f32, f32)>,
    /// Bounding box of the symbol in original image coordinates.
    pub bounds: Option<Roi>,
    /// Rotation that had to be applied to decode (0/90/180/270 degrees,
    /// counter-clockwise).
    pub rotation_deg: i32,
    /// True when only the inverted copy decoded.
    pub inverted: bool,
    /// Scale factor that had to be applied to decode (1.0 = none).
    pub scale: f32,
    /// Human-readable facts about the symbol and the decode attempt.
    pub metadata: BTreeMap<String, String>,
    /// Structured Append header of the symbol, when present.
    pub structured_append: Option<StructuredAppend>,
    /// Shared payload classification (signature/text/entropy; inspect only).
    pub payload_info: PayloadInfo,
}

impl BarcodeHit {
    /// True when the symbol carries a non-empty binary payload.
    #[must_use]
    pub fn has_binary_payload(&self) -> bool {
        self.payload.as_ref().is_some_and(|p| !p.is_empty())
    }

    /// Full hex of the binary payload (empty for text-only symbols).
    #[must_use]
    pub fn payload_hex(&self) -> String {
        hex(self.payload.as_deref().unwrap_or(&[]))
    }

    /// Hex preview of the first [`PREVIEW_BYTES`] payload bytes.
    #[must_use]
    pub fn preview_hex(&self) -> String {
        let payload = self.payload.as_deref().unwrap_or(&[]);
        hex(&payload[..payload.len().min(PREVIEW_BYTES)])
    }

    fn located(&self) -> bool {
        !self.points.is_empty()
    }

    fn payload_size(&self) -> usize {
        self.payload.as_ref().map_or(0, Vec::len)
    }
}

/// Result of a scan: every distinct symbol found, plus the validated merges of
/// QR Structured Append sequences (upstream `ScanResult` + `MergeOutcome`).
#[derive(Debug, Clone, PartialEq)]
pub struct ScanResult {
    /// All distinct symbols found (deduplicated, ordered top-to-bottom,
    /// left-to-right).
    pub hits: Vec<BarcodeHit>,
    /// Complete Structured Append sequences merged from [`ScanResult::hits`]
    /// in symbol order, with exact concatenated payload bytes.
    pub merged: Vec<BarcodeHit>,
    /// Diagnostics about empty scans, caps and merge decisions.
    pub notes: Vec<String>,
    /// The clamped region that was scanned.
    pub scanned_area: Roi,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Decodes barcodes/QR codes in `region` of `image` (clamped to the image
/// bounds first). Decode failures are the normal case for most attempts and
/// are never errors; only cancellation/deadline failures propagate.
///
/// # Errors
/// [`OperationError::Cancelled`] / [`OperationError::BudgetExceeded`] when the
/// execution context says so between attempts.
pub fn scan(
    image: &RgbaImage,
    region: Roi,
    options: ScanOptions,
    ctx: &ExecutionContext,
) -> Result<ScanResult, OperationError> {
    let area = region.clamp_to(image.width, image.height);
    if area.is_empty() {
        return Ok(ScanResult {
            hits: Vec::new(),
            merged: Vec::new(),
            notes: vec!["The selected region is empty".to_owned()],
            scanned_area: area,
        });
    }
    ctx.check()?;
    let base = image.crop(area).map_err(|e| {
        OperationError::internal(format!("QR scan: cropping the region failed: {e}"))
    })?;
    let options = ScanOptions {
        max_symbols: options.max_symbols.clamp(1, MAX_SYMBOLS_CAP),
        ..options
    };
    let mut hits: Vec<BarcodeHit> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // Phase 1: the common case — both polarities, no rotation.
    run_attempt(
        &base.argb,
        base.width,
        base.height,
        0,
        1.0,
        BinarizerChoice::Hybrid,
        options,
        area,
        image.width,
        image.height,
        &mut hits,
        ctx,
    )?;

    // Phase 2: quarter turns, but only when nothing was found.
    if options.try_rotations && hits.is_empty() {
        let mut buffer = base.argb.clone();
        let (mut width, mut height) = (base.width, base.height);
        for turns in 1..=3u32 {
            ctx.check()?;
            let rotated = rotate_argb_ccw(&buffer, width, height);
            buffer = rotated.0;
            width = rotated.1;
            height = rotated.2;
            run_attempt(
                &buffer,
                width,
                height,
                turns,
                1.0,
                BinarizerChoice::Hybrid,
                options,
                area,
                image.width,
                image.height,
                &mut hits,
                ctx,
            )?;
            if !hits.is_empty() {
                break;
            }
        }
    }

    // Phase 3: rescaled copies and the alternate binarizer, for hard images.
    if hits.is_empty() && options.try_rescale {
        let longest = base.width.max(base.height);
        if longest < UPSCALE_THRESHOLD_PX {
            for factor in [2.0f32, 3.0] {
                ctx.check()?;
                let (buffer, width, height) =
                    scale_argb_nearest(&base.argb, base.width, base.height, factor);
                run_attempt(
                    &buffer,
                    width,
                    height,
                    0,
                    factor,
                    BinarizerChoice::Hybrid,
                    options,
                    area,
                    image.width,
                    image.height,
                    &mut hits,
                    ctx,
                )?;
                if !hits.is_empty() {
                    break;
                }
            }
        } else if longest > DOWNSCALE_THRESHOLD_PX {
            ctx.check()?;
            let (buffer, width, height) =
                scale_argb_nearest(&base.argb, base.width, base.height, 0.5);
            run_attempt(
                &buffer,
                width,
                height,
                0,
                0.5,
                BinarizerChoice::Hybrid,
                options,
                area,
                image.width,
                image.height,
                &mut hits,
                ctx,
            )?;
        }
        if hits.is_empty() {
            ctx.check()?;
            run_attempt(
                &base.argb,
                base.width,
                base.height,
                0,
                1.0,
                BinarizerChoice::GlobalHistogram,
                options,
                area,
                image.width,
                image.height,
                &mut hits,
                ctx,
            )?;
        }
    }

    if hits.len() >= options.max_symbols {
        notes.push(format!(
            "Stopped at the max_symbols limit ({}): results may be incomplete",
            options.max_symbols
        ));
    }
    for hit in &hits {
        if let Some(sa) = hit.structured_append {
            notes.push(format!(
                "Structured Append symbol {} of {} (parity 0x{:02x})",
                sa.index + 1,
                sa.total,
                sa.parity
            ));
        }
    }
    sort_hits(&mut hits);
    let merged = merge_structured_append(&hits);
    notes.extend(merged.notes.iter().cloned());
    if hits.is_empty() {
        notes.push(
            "No symbol could be decoded. Practical next steps: scan a smaller region, enable the \
             rescale fallback (try_rescale), or use a bit plane transform to increase contrast \
             first"
                .to_owned(),
        );
    }
    Ok(ScanResult {
        hits,
        merged: merged.merged,
        notes,
        scanned_area: area,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinarizerChoice {
    /// Local adaptive thresholds (the ZXing default).
    Hybrid,
    /// One global threshold over the whole bitmap (the alternate binarizer).
    GlobalHistogram,
}

/// Static description of one attempt, used to map coordinates back and to
/// label the hit metadata.
struct AttemptInfo {
    quarter_turns: u32,
    scale: f32,
    inverted: bool,
    description: String,
}

#[allow(clippy::too_many_arguments)]
fn run_attempt(
    pixels: &[u32],
    width: u32,
    height: u32,
    quarter_turns: u32,
    scale: f32,
    binarizer: BinarizerChoice,
    options: ScanOptions,
    area: Roi,
    image_width: u32,
    image_height: u32,
    hits: &mut Vec<BarcodeHit>,
    ctx: &ExecutionContext,
) -> Result<(), OperationError> {
    if hits.len() >= options.max_symbols {
        return Ok(());
    }
    ctx.check()?;
    let Ok(source) =
        RGBLuminanceSource::new_with_width_height_pixels(width as usize, height as usize, pixels)
    else {
        return Ok(());
    };
    let mut inverted_source = source.clone();
    LuminanceSource::invert(&mut inverted_source);

    let info = AttemptInfo {
        quarter_turns,
        scale,
        inverted: false,
        description: describe_attempt(quarter_turns, scale, binarizer, false),
    };
    let inverted_info = AttemptInfo {
        quarter_turns,
        scale,
        inverted: true,
        description: describe_attempt(quarter_turns, scale, binarizer, true),
    };
    let hints = decode_hints();
    match binarizer {
        BinarizerChoice::Hybrid => {
            let bitmap = BinaryBitmap::new(HybridBinarizer::new(source));
            collect_hits(
                bitmap,
                &info,
                &hints,
                options,
                area,
                image_width,
                image_height,
                hits,
            );
            if options.try_inverted && hits.len() < options.max_symbols {
                let bitmap = BinaryBitmap::new(HybridBinarizer::new(inverted_source));
                collect_hits(
                    bitmap,
                    &inverted_info,
                    &hints,
                    options,
                    area,
                    image_width,
                    image_height,
                    hits,
                );
            }
        }
        BinarizerChoice::GlobalHistogram => {
            let bitmap = BinaryBitmap::new(GlobalHistogramBinarizer::new(source));
            collect_hits(
                bitmap,
                &info,
                &hints,
                options,
                area,
                image_width,
                image_height,
                hits,
            );
            if options.try_inverted && hits.len() < options.max_symbols {
                let bitmap = BinaryBitmap::new(GlobalHistogramBinarizer::new(inverted_source));
                collect_hits(
                    bitmap,
                    &inverted_info,
                    &hints,
                    options,
                    area,
                    image_width,
                    image_height,
                    hits,
                );
            }
        }
    }
    Ok(())
}

/// Runs every decode pass (QR multi-symbol, generic multi-format, single) on
/// one bitmap polarity and merges the results into `hits`.
#[allow(clippy::too_many_arguments)]
fn collect_hits<B: rxing::Binarizer>(
    bitmap: BinaryBitmap<B>,
    info: &AttemptInfo,
    hints: &DecodeHints,
    options: ScanOptions,
    area: Roi,
    image_width: u32,
    image_height: u32,
    hits: &mut Vec<BarcodeHit>,
) {
    let mut bitmap = bitmap;
    let mut found = decode_qr_parts(&bitmap, hints);
    found.extend(decode_multiple_generic(&mut bitmap, hints));
    if found.is_empty() {
        // The single symbol reader is both faster and more forgiving on very
        // small images.
        let mut reader = MultiFormatReader::default();
        if let Ok(result) = reader.decode_with_hints(&mut bitmap, hints) {
            found.push(rxing_result_to_raw(&result));
        }
    }
    for raw in found {
        if hits.len() >= options.max_symbols {
            return;
        }
        let hit = to_hit(raw, info, area, image_width, image_height);
        hit_merge_add(hits, hit);
    }
}

/// One decode result in the raw decoder shape, before attempt bookkeeping.
struct RawDecoded {
    format: String,
    text: String,
    raw_bytes: Vec<u8>,
    byte_segments: Vec<Vec<u8>>,
    points: Vec<(f32, f32)>,
    metadata: BTreeMap<String, String>,
    structured_append: Option<StructuredAppend>,
}

/// QR multi-symbol pass over the black matrix. The parts are decoded
/// individually so Structured Append headers are preserved per symbol — the
/// stock multi reader would merge even unrelated sequences (upstream
/// `decodeQrParts`).
fn decode_qr_parts<B: rxing::Binarizer>(
    bitmap: &BinaryBitmap<B>,
    hints: &DecodeHints,
) -> Vec<RawDecoded> {
    let mut out = Vec::new();
    let Ok(detected) = MultiDetector::new(bitmap.get_black_matrix()).detectMulti(hints) else {
        // No QR candidates in this pass — the normal case.
        return out;
    };
    for symbol in detected {
        let Ok(decoded) = decode_bitmatrix_with_hints(symbol.getBits(), hints) else {
            // Other detected candidates may still decode.
            continue;
        };
        let mut points = symbol.getPoints().to_vec();
        // If the code was mirrored: swap the bottom-left and top-right points.
        if let Some(other) = decoded.getOther() {
            if let Some(mirrored) = other.downcast_ref::<QRCodeDecoderMetaData>() {
                mirrored.applyMirroredCorrection(&mut points);
            }
        }
        let mut metadata = BTreeMap::new();
        let byte_segments = decoded.getByteSegments().clone();
        if !byte_segments.is_empty() {
            let total: usize = byte_segments.iter().map(Vec::len).sum();
            metadata.insert(
                "byte_segments".to_owned(),
                format!("{} segment(s), {total} bytes", byte_segments.len()),
            );
        }
        let ec_level = decoded.getECLevel();
        if !ec_level.is_empty() {
            metadata.insert("error_correction_level".to_owned(), ec_level.to_owned());
        }
        metadata.insert(
            "symbology_identifier".to_owned(),
            format!("]Q{}", decoded.getSymbologyModifier()),
        );
        let structured_append = if decoded.hasStructuredAppend() {
            StructuredAppend::from_raw(
                decoded.getStructuredAppendSequenceNumber(),
                decoded.getStructuredAppendParity(),
            )
        } else {
            None
        };
        out.push(RawDecoded {
            format: "QR_CODE".to_owned(),
            text: decoded.getText().to_owned(),
            raw_bytes: decoded.getRawBytes().clone(),
            byte_segments,
            points: points.iter().map(|p| (p.x, p.y)).collect(),
            metadata,
            structured_append,
        });
    }
    out
}

/// Generic multi-format pass: repeatedly decodes portions of the image left of,
/// above, right of and below a found symbol (upstream `GenericMultipleBarcodeReader`).
fn decode_multiple_generic<B: rxing::Binarizer>(
    bitmap: &mut BinaryBitmap<B>,
    hints: &DecodeHints,
) -> Vec<RawDecoded> {
    let mut reader = GenericMultipleBarcodeReader::new(MultiFormatReader::default());
    match reader.decode_multiple_with_hints(bitmap, hints) {
        Ok(results) => results.iter().map(rxing_result_to_raw).collect(),
        Err(_) => Vec::new(),
    }
}

/// Converts a reader result into the raw shape, extracting byte segments and
/// Structured Append headers from the result metadata.
fn rxing_result_to_raw(result: &RXingResult) -> RawDecoded {
    let mut metadata = BTreeMap::new();
    let mut byte_segments: Vec<Vec<u8>> = Vec::new();
    let mut sequence: Option<i32> = None;
    let mut parity: Option<i32> = None;
    for value in result.getRXingResultMetadata().values() {
        match value {
            RXingResultMetadataValue::ByteSegments(segments) => {
                let total: usize = segments.iter().map(Vec::len).sum();
                if !segments.is_empty() {
                    metadata.insert(
                        "byte_segments".to_owned(),
                        format!("{} segment(s), {total} bytes", segments.len()),
                    );
                }
                byte_segments = segments.clone();
            }
            RXingResultMetadataValue::StructuredAppendSequence(value) => sequence = Some(*value),
            RXingResultMetadataValue::StructuredAppendParity(value) => parity = Some(*value),
            other => {
                if let Some((key, text)) = describe_metadata(other) {
                    metadata.insert(key, text);
                }
            }
        }
    }
    let structured_append = match (sequence, parity) {
        (Some(sequence), Some(parity)) => StructuredAppend::from_raw(sequence, parity),
        _ => None,
    };
    RawDecoded {
        format: format!("{:?}", result.getBarcodeFormat()),
        text: result.getText().to_owned(),
        raw_bytes: result.getRawBytes().to_vec(),
        byte_segments,
        points: result.getPoints().iter().map(|p| (p.x, p.y)).collect(),
        metadata,
        structured_append,
    }
}

/// One metadata entry worth reporting; `None` for values that carry no
/// analyst-visible fact.
fn describe_metadata(value: &RXingResultMetadataValue) -> Option<(String, String)> {
    let entry = match value {
        RXingResultMetadataValue::ErrorCorrectionLevel(text) => {
            ("error_correction_level", text.clone())
        }
        RXingResultMetadataValue::SymbologyIdentifier(text) => {
            ("symbology_identifier", text.clone())
        }
        RXingResultMetadataValue::ContentType(text) => ("content_type", text.clone()),
        RXingResultMetadataValue::OTHER(text) => ("other", text.clone()),
        RXingResultMetadataValue::Orientation(degrees) => ("orientation", degrees.to_string()),
        RXingResultMetadataValue::IsMirrored(flag) => ("is_mirrored", flag.to_string()),
        RXingResultMetadataValue::IsInverted(flag) => ("is_inverted", flag.to_string()),
        _ => return None,
    };
    Some((entry.0.to_owned(), entry.1))
}

/// Builds the final bytes-first hit: payload from byte segments, text only
/// when printable, points mapped back into original image coordinates.
fn to_hit(
    raw: RawDecoded,
    info: &AttemptInfo,
    area: Roi,
    image_width: u32,
    image_height: u32,
) -> BarcodeHit {
    let concatenated = raw
        .byte_segments
        .iter()
        .flatten()
        .copied()
        .collect::<Vec<u8>>();
    let payload = if concatenated.is_empty() {
        None
    } else {
        Some(concatenated)
    };
    // The decoder text is a Rust `String` (valid UTF-8 by construction) but
    // binary byte-mode payloads decode to mojibake sprinkled with replacement
    // characters; such text is not a fact worth reporting.
    let text = if raw.text.is_empty() || raw.text.contains('\u{FFFD}') {
        None
    } else {
        Some(raw.text)
    };
    let mut metadata = raw.metadata;
    metadata.insert("symbology".to_owned(), raw.format.clone());
    metadata.insert("decode".to_owned(), info.description.clone());
    metadata.insert(
        "rotation_deg".to_owned(),
        (info.quarter_turns * 90).to_string(),
    );
    metadata.insert("scale".to_owned(), format!("{:.1}", info.scale));
    metadata.insert("inverted".to_owned(), info.inverted.to_string());
    if payload.is_none() {
        if let Some(text) = &text {
            metadata.insert(
                "payload".to_owned(),
                "text only: the decoder returned no byte segments, so there are no payload bytes \
                 to save"
                    .to_owned(),
            );
            metadata.insert("decoded_text".to_owned(), text.clone());
        }
    }
    if let Some(sa) = raw.structured_append {
        metadata.insert(
            "structured_append".to_owned(),
            format!(
                "symbol {} of {} (parity 0x{:02x})",
                sa.index + 1,
                sa.total,
                sa.parity
            ),
        );
        metadata.insert("structured_append_total".to_owned(), sa.total.to_string());
        metadata.insert(
            "structured_append_parity".to_owned(),
            format!("0x{:02x}", sa.parity),
        );
    }
    if !raw.raw_bytes.is_empty() {
        metadata.insert(
            "decoder_raw_bytes".to_owned(),
            format!("{} bytes", raw.raw_bytes.len()),
        );
    }
    let points = raw
        .points
        .iter()
        .map(|(x, y)| map_back(*x, *y, info, area))
        .collect::<Vec<(f32, f32)>>();
    let bounds = bounds_of(&points, image_width, image_height);
    let payload_info = payload::detect(payload.as_deref().unwrap_or(&[]));
    BarcodeHit {
        format: raw.format,
        text,
        payload,
        raw_bytes: if raw.raw_bytes.is_empty() {
            None
        } else {
            Some(raw.raw_bytes)
        },
        points,
        bounds,
        rotation_deg: (info.quarter_turns * 90) as i32,
        inverted: info.inverted,
        scale: info.scale,
        metadata,
        structured_append: raw.structured_append,
        payload_info,
    }
}

/// Maps a point from the (rotated, scaled) attempt bitmap back into original
/// image coordinates (upstream `RotationMapper` + `mapBack`).
///
/// Rotation and rescale never combine in the attempt chain (rotations run at
/// scale 1.0, rescales at 0 turns), so `area`'s dimensions are the
/// pre-rotation dimensions of the bitmap whenever a rotation is undone.
fn map_back(x: f32, y: f32, info: &AttemptInfo, area: Roi) -> (f32, f32) {
    let (unrotated_x, unrotated_y) = to_original(x, y, info.quarter_turns, area.width, area.height);
    (
        unrotated_x / info.scale + area.x as f32,
        unrotated_y / info.scale + area.y as f32,
    )
}

/// Width of a bitmap rotated counter-clockwise by `turns`.
fn rotated_width(turns: u32, width: u32, height: u32) -> u32 {
    if turns % 2 == 1 {
        height
    } else {
        width
    }
}

/// Height of a bitmap rotated counter-clockwise by `turns`.
fn rotated_height(turns: u32, width: u32, height: u32) -> u32 {
    if turns % 2 == 1 {
        width
    } else {
        height
    }
}

/// Maps a point from a bitmap rotated counter-clockwise by `quarter_turns`
/// back into the original image of the given size (upstream
/// `RotationMapper.toOriginal`).
///
/// `original_width`/`original_height` are the dimensions *before* the
/// rotation; the point coordinates are in the rotated (and, if applicable,
/// scaled) bitmap's space.
fn to_original(
    x: f32,
    y: f32,
    quarter_turns: u32,
    original_width: u32,
    original_height: u32,
) -> (f32, f32) {
    let turns = quarter_turns % 4;
    if turns == 0 {
        return (x, y);
    }
    // Dimensions of the rotated bitmap, then undo each turn from the outside in.
    let mut width = rotated_width(turns, original_width, original_height) as f32;
    let mut height = rotated_height(turns, original_width, original_height) as f32;
    let mut px = x;
    let mut py = y;
    for _ in 0..turns {
        let source_x = height - 1.0 - py;
        let source_y = px;
        px = source_x;
        py = source_y;
        std::mem::swap(&mut width, &mut height);
    }
    (px, py)
}

/// Bounding box of the symbol's mapped points, clamped to the image; `None`
/// when the decode carried no position.
fn bounds_of(points: &[(f32, f32)], image_width: u32, image_height: u32) -> Option<Roi> {
    if points.is_empty() {
        return None;
    }
    let min_x = points.iter().map(|(x, _)| *x).fold(f32::MAX, f32::min);
    let min_y = points.iter().map(|(_, y)| *y).fold(f32::MAX, f32::min);
    let max_x = points.iter().map(|(x, _)| *x).fold(f32::MIN, f32::max);
    let max_y = points.iter().map(|(_, y)| *y).fold(f32::MIN, f32::max);
    let x0 = (min_x - BOUNDS_PADDING).max(0.0).floor() as u32;
    let y0 = (min_y - BOUNDS_PADDING).max(0.0).floor() as u32;
    let x1 = (max_x + BOUNDS_PADDING).ceil() as u32;
    let y1 = (max_y + BOUNDS_PADDING).ceil() as u32;
    let width = x1.saturating_sub(x0);
    let height = y1.saturating_sub(y0);
    Some(Roi::new(x0, y0, width, height).clamp_to(image_width, image_height))
}

/// Rotates an ARGB pixel buffer counter-clockwise by 90 degrees (upstream
/// `ImageOps.rotateCounterClockwise`).
#[must_use]
pub fn rotate_argb_ccw(pixels: &[u32], width: u32, height: u32) -> (Vec<u32>, u32, u32) {
    let new_width = height;
    let new_height = width;
    let mut out = vec![0u32; (new_width as usize) * (new_height as usize)];
    // Forward mapping: rotated(x, y) = original(width - 1 - y, x).
    for new_y in 0..new_height {
        for new_x in 0..new_width {
            let source_x = width - 1 - new_y;
            let source_y = new_x;
            out[new_y as usize * new_width as usize + new_x as usize] =
                pixels[source_y as usize * width as usize + source_x as usize];
        }
    }
    (out, new_width, new_height)
}

/// Nearest-neighbour rescale of an ARGB pixel buffer (upstream
/// `ImageOps.scaleNearest`).
#[must_use]
pub fn scale_argb_nearest(
    pixels: &[u32],
    width: u32,
    height: u32,
    factor: f32,
) -> (Vec<u32>, u32, u32) {
    if factor <= 0.0 || !factor.is_finite() || factor == 1.0 {
        return (pixels.to_vec(), width, height);
    }
    let new_width = ((width as f32 * factor).round() as u32).max(1);
    let new_height = ((height as f32 * factor).round() as u32).max(1);
    let mut out = Vec::with_capacity(new_width as usize * new_height as usize);
    for new_y in 0..new_height {
        let source_y = ((new_y as f32 / factor) as u32).min(height - 1);
        for new_x in 0..new_width {
            let source_x = ((new_x as f32 / factor) as u32).min(width - 1);
            out.push(pixels[source_y as usize * width as usize + source_x as usize]);
        }
    }
    (out, new_width, new_height)
}

/// `TRY_HARDER` on, every symbology, and — deliberately like the reference —
/// no `CHARACTER_SET` hint so the decoder distinguishes ISO-8859-1, UTF-8 and
/// Shift_JIS by itself. The payload bytes are unaffected either way because
/// they are taken from the byte segments rather than the text.
fn decode_hints() -> DecodeHints {
    DecodeHints {
        TryHarder: Some(true),
        ..DecodeHints::default()
    }
}

fn describe_attempt(turns: u32, scale: f32, binarizer: BinarizerChoice, inverted: bool) -> String {
    let mut label: Vec<String> = Vec::new();
    if turns != 0 {
        label.push(format!("{}\u{b0}", turns * 90));
    }
    if scale != 1.0 {
        label.push(format!("{scale:.1}x"));
    }
    if binarizer == BinarizerChoice::GlobalHistogram {
        label.push("global histogram".to_owned());
    }
    let mut description = if label.is_empty() {
        "original".to_owned()
    } else {
        label.join(", ")
    };
    if inverted {
        description.push_str(", inverted");
    }
    description
}

// ---------------------------------------------------------------------------
// HitMerge: decides when two decoded symbols are really the same one.
// ---------------------------------------------------------------------------

/// True when two hits describe the same symbol: same content and the same
/// place (upstream `HitMerge.describesSameSymbol`).
fn describes_same_symbol(existing: &BarcodeHit, candidate: &BarcodeHit) -> bool {
    if existing.structured_append != candidate.structured_append {
        return false;
    }
    if existing.format != candidate.format || existing.text != candidate.text {
        return false;
    }
    // Content identity: the payload bytes when there are any, the decoded text
    // otherwise (the text was already compared above).
    match (&existing.payload, &candidate.payload) {
        (Some(a), Some(b)) if a == b => {}
        (None, None) => {}
        _ => return false,
    }
    // A decode without result points covers the whole scanned area, so it
    // cannot be located and has to be treated as overlapping everything with
    // the same content.
    if !existing.located() || !candidate.located() {
        return true;
    }
    let (Some(a), Some(b)) = (existing.bounds, candidate.bounds) else {
        return true;
    };
    let dx = a.x as f32 - b.x as f32;
    let dy = a.y as f32 - b.y as f32;
    (dx * dx + dy * dy).sqrt() <= DUPLICATE_DISTANCE_PX
}

/// Adds a hit to the list, replacing an existing report of the same symbol
/// when the new report is more useful: the located one, and among two located
/// reports the one with more payload bytes (upstream `HitMerge.add`).
fn hit_merge_add(hits: &mut Vec<BarcodeHit>, candidate: BarcodeHit) {
    for existing in hits.iter_mut() {
        if !describes_same_symbol(existing, &candidate) {
            continue;
        }
        let candidate_located = candidate.located();
        let existing_located = existing.located();
        if candidate_located && !existing_located {
            *existing = candidate;
        } else if !candidate_located && existing_located {
            // Keep the located one.
        } else if candidate.payload_size() > existing.payload_size() {
            *existing = candidate;
        }
        return;
    }
    hits.push(candidate);
}

/// Deterministic output order: located symbols top-to-bottom, left-to-right,
/// then unlocated reports.
fn sort_hits(hits: &mut [BarcodeHit]) {
    hits.sort_by(|a, b| {
        let key = |hit: &BarcodeHit| match hit.bounds {
            Some(bounds) => (bounds.y, bounds.x, hit.format.clone()),
            None => (u32::MAX, u32::MAX, hit.format.clone()),
        };
        key(a).cmp(&key(b))
    });
}

// ---------------------------------------------------------------------------
// StructuredAppendMerger: merges QR Structured Append sequences explicitly.
// ---------------------------------------------------------------------------

/// Merges the parts of QR Structured Append sequences: groups by (parity,
/// total), validates that a sequence is complete and unambiguous and
/// concatenates the parts' payload bytes in index order — never rebuilt from
/// text (upstream `StructuredAppendMerger`).
#[must_use]
pub fn merge_structured_append(hits: &[BarcodeHit]) -> MergeOutcome {
    let mut unmerged = Vec::new();
    let mut groups: BTreeMap<(u8, usize), Vec<BarcodeHit>> = BTreeMap::new();
    for hit in hits {
        match hit.structured_append {
            Some(sa) if hit.has_binary_payload() || hit.text.is_some() => {
                groups
                    .entry((sa.parity, sa.total))
                    .or_default()
                    .push(hit.clone());
            }
            _ => unmerged.push(hit.clone()),
        }
    }

    let mut merged = Vec::new();
    let mut notes = Vec::new();
    for ((parity, total), parts) in groups {
        if parts.len() == 1 && total == 1 {
            unmerged.extend(parts);
            continue;
        }
        if !complete_and_unambiguous(&parts) {
            unmerged.extend(parts);
            notes.push(
                "Kept incomplete or conflicting Structured Append parts separate; no payload was \
                 guessed"
                    .to_owned(),
            );
            continue;
        }
        merged.push(merge_sequence(&parts, parity, &mut notes));
    }
    MergeOutcome {
        merged,
        unmerged,
        notes,
    }
}

/// Outcome of [`merge_structured_append`].
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MergeOutcome {
    /// One hit per complete sequence, in symbol order.
    pub merged: Vec<BarcodeHit>,
    /// Hits that were not merged (no SA header, or incomplete/conflicting).
    pub unmerged: Vec<BarcodeHit>,
    /// Diagnostics about what was merged and what is missing.
    pub notes: Vec<String>,
}

/// All parts share total/parity, every index is present exactly once with the
/// same content, and the sequence length is within the QR specification
/// (upstream `completeAndUnambiguous`).
fn complete_and_unambiguous(parts: &[BarcodeHit]) -> bool {
    let Some(header) = parts.first().and_then(|hit| hit.structured_append) else {
        return false;
    };
    let mut slots: BTreeMap<usize, &BarcodeHit> = BTreeMap::new();
    for part in parts {
        let Some(sa) = part.structured_append else {
            return false;
        };
        if sa.total != header.total || sa.parity != header.parity {
            return false;
        }
        if sa.index >= sa.total || sa.total > SA_MAX_SYMBOLS {
            return false;
        }
        if let Some(existing) = slots.insert(sa.index, part) {
            if existing.payload != part.payload || existing.text != part.text {
                return false;
            }
        }
    }
    slots.len() == header.total
}

/// Merges one (complete) sequence in index order (upstream `mergeSequence`).
fn merge_sequence(parts: &[BarcodeHit], parity: u8, notes: &mut Vec<String>) -> BarcodeHit {
    let mut ordered: Vec<&BarcodeHit> = parts.iter().collect();
    ordered.sort_by_key(|hit| hit.structured_append.map_or(0, |sa| sa.index));
    let total = ordered
        .iter()
        .filter_map(|hit| hit.structured_append)
        .map(|sa| sa.total)
        .max()
        .unwrap_or(ordered.len());
    let mut seen = [false; SA_MAX_SYMBOLS];
    let mut text = String::new();
    let mut payload: Vec<u8> = Vec::new();
    let mut raw_bytes: Vec<u8> = Vec::new();
    let mut points: Vec<(f32, f32)> = Vec::new();
    let mut duplicates: Vec<String> = Vec::new();
    let mut last_index: i64 = -1;
    for part in &ordered {
        let Some(sa) = part.structured_append else {
            continue;
        };
        if seen[sa.index] {
            duplicates.push((sa.index + 1).to_string());
            continue;
        }
        seen[sa.index] = true;
        if let Some(part_text) = &part.text {
            text.push_str(part_text);
        }
        if let Some(part_payload) = &part.payload {
            payload.extend_from_slice(part_payload);
        }
        if let Some(part_raw) = &part.raw_bytes {
            raw_bytes.extend_from_slice(part_raw);
        }
        points.extend_from_slice(&part.points);
        last_index = sa.index as i64;
    }
    let missing: Vec<String> = (0..total.min(SA_MAX_SYMBOLS))
        .filter(|index| !seen[*index])
        .map(|index| (index + 1).to_string())
        .collect();
    if !duplicates.is_empty() {
        notes.push(format!(
            "Ignored duplicate structured append part(s): {}",
            duplicates.join(", ")
        ));
    }
    if missing.is_empty() && total as i64 == last_index + 1 {
        notes.push(format!(
            "Merged a complete structured append sequence of {total} symbols"
        ));
    } else {
        let missing_text = if missing.is_empty() {
            format!("{} unknown", (total as i64 - (last_index + 1)).max(0))
        } else {
            missing.join(", ")
        };
        notes.push(format!(
            "Merged structured append parts; symbol(s) {missing_text} of {total} are still missing"
        ));
    }
    let payload = if payload.is_empty() {
        None
    } else {
        Some(payload)
    };
    let payload_info = payload::detect(payload.as_deref().unwrap_or(&[]));
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "structured_append".to_owned(),
        format!("merged from {} symbols", ordered.len()),
    );
    metadata.insert("structured_append_total".to_owned(), total.to_string());
    metadata.insert(
        "structured_append_parity".to_owned(),
        format!("0x{parity:02x}"),
    );
    let first = ordered[0];
    BarcodeHit {
        format: first.format.clone(),
        text: if text.is_empty() { None } else { Some(text) },
        payload,
        raw_bytes: if raw_bytes.is_empty() {
            None
        } else {
            Some(raw_bytes)
        },
        points,
        bounds: first.bounds,
        rotation_deg: 0,
        inverted: false,
        scale: 1.0,
        metadata,
        structured_append: None,
        payload_info,
    }
}

// ---------------------------------------------------------------------------
// Registry ops
// ---------------------------------------------------------------------------

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    use cybercipher_core::Category::Analysis as A;
    use cybercipher_core::CostClass::Interactive;
    use cybercipher_core::ValueKind::{Bytes as B, Json as J};

    let tags: &'static [&'static str] = &["steg", "image", "ctf", "qr", "barcode"];
    let standard = "Semantics ported from StegSolver c14bfa9 (MIT): BarcodeScanner/ScanOptions/HitMerge/StructuredAppendMerger on the rxing (ZXing) decoder";
    let vectors =
        "In-test synthetic QR/Code-128 fixtures via the rxing encoder; synthetic Structured Append merge fixtures; hostile-noise scans";

    reg.add_simple(
        crate::ops::spec(
            "image_scan_qr",
            "QR / Barcode Scan",
            "Scans an image (whole or ROI) for QR codes and 1D/2D barcodes with TRY_HARDER and practical fallbacks: inverted polarity, quarter turns, and (optional) rescaled copies plus the alternate binarizer — each stage only when every earlier attempt came up empty. Finds several symbols per image, preserves QR Structured Append parts and reports their validated merge. Bytes-first: each hit reports the exact raw payload bytes (hex), the decoded text only when printable, the symbol position, metadata and the shared payload classification. Never opens or executes payloads.",
            A,
            &[B],
            J,
            Interactive,
            false,
            vec![
                crate::ops::p_text("roi", "Region", "", "Optional 'x,y,width,height' region; defaults to the whole image."),
                crate::ops::p_bool("try_inverted", "Try inverted", true, "Also scans an inverted copy, for light symbols on a dark background."),
                crate::ops::p_bool("try_rotations", "Try rotations", true, "Also tries quarter turns (90/180/270 degrees) when nothing decoded upright."),
                crate::ops::p_bool("try_rescale", "Try rescale", false, "Adds rescaled copies (2x/3x upscale for small images, 0.5x downscale for very large ones) and a global-histogram binarizer pass when everything else failed."),
                crate::ops::p_int("max_symbols", "Max symbols", DEFAULT_MAX_SYMBOLS as i64, "Maximum number of symbols reported. Hard cap 64."),
            ],
            tags,
            &["qr", "barcode", "scan", "structured append"],
            standard,
            vectors,
        ),
        image_scan_qr_op,
    );

    reg.add_simple(
        crate::ops::spec(
            "image_scan_qr_bytes",
            "QR / Barcode Scan Bytes",
            "Same scan as QR / Barcode Scan, emitting the first hit's exact raw payload bytes as the payload after a JSON report header line (the established header-line transport) so recipes can chain the bytes into Auto Decode or the Workbench. Selection: the first complete Structured Append sequence when one was merged, otherwise the topmost-leftmost detected symbol. A text-only symbol yields an empty payload with payload_present=false — bytes are never invented from text. Never opens or executes payloads.",
            A,
            &[B],
            B,
            Interactive,
            false,
            vec![
                crate::ops::p_text("roi", "Region", "", "Optional 'x,y,width,height' region; defaults to the whole image."),
                crate::ops::p_bool("try_inverted", "Try inverted", true, "Also scans an inverted copy, for light symbols on a dark background."),
                crate::ops::p_bool("try_rotations", "Try rotations", true, "Also tries quarter turns (90/180/270 degrees) when nothing decoded upright."),
                crate::ops::p_bool("try_rescale", "Try rescale", false, "Adds rescaled copies and a global-histogram binarizer pass when everything else failed."),
                crate::ops::p_int("max_symbols", "Max symbols", DEFAULT_MAX_SYMBOLS as i64, "Maximum number of symbols scanned for. Hard cap 64."),
                crate::ops::p_int("max_bytes", "Max bytes", 65_536, "Bounded payload size. Hard cap 16 MiB; the header reports the total size and a truncated flag."),
            ],
            tags,
            &["qr", "barcode", "scan", "bytes"],
            standard,
            vectors,
        ),
        image_scan_qr_bytes_op,
    );
}

fn scan_options_from_params(params: &ParamMap) -> OpResult<ScanOptions> {
    let max_symbols = (params
        .int_or("max_symbols", DEFAULT_MAX_SYMBOLS as i64)
        .max(0) as usize)
        .clamp(1, MAX_SYMBOLS_CAP);
    Ok(ScanOptions {
        try_inverted: params.bool_or("try_inverted", true),
        try_rotations: params.bool_or("try_rotations", true),
        try_rescale: params.bool_or("try_rescale", false),
        max_symbols,
    })
}

fn image_scan_qr_op(v: &Value, params: &ParamMap, ctx: &ExecutionContext) -> OpResult<Value> {
    const OP: &str = "QR / Barcode Scan";
    let image = crate::ops::decode_input_image(v, OP)?;
    let options = scan_options_from_params(params)?;
    let roi =
        crate::ops::parse_roi(params)?.unwrap_or_else(|| Roi::whole(image.width, image.height));
    let result = scan(&image, roi, options, ctx)?;
    let hits: Vec<serde_json::Value> = result.hits.iter().map(hit_json).collect();
    let merged: Vec<serde_json::Value> = result.merged.iter().map(hit_json).collect();
    Ok(Value::Json(serde_json::json!({
        "scanned_area": {
            "x": result.scanned_area.x,
            "y": result.scanned_area.y,
            "width": result.scanned_area.width,
            "height": result.scanned_area.height,
        },
        "symbol_count": result.hits.len(),
        "merged_count": result.merged.len(),
        "notes": result.notes,
        "hits": hits,
        "merged": merged,
    })))
}

/// Serialises one hit in the documented bytes-first shape:
/// `{ format, raw_payload_bytes, decoded_text, position, metadata,
/// payload_type, payload_length, preview_hex }`. `decoded_text` and
/// `position` are only present when the decoder produced them.
pub(crate) fn hit_json(hit: &BarcodeHit) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    object.insert("format".to_owned(), serde_json::json!(hit.format));
    object.insert(
        "raw_payload_bytes".to_owned(),
        serde_json::json!(hit.payload_hex()),
    );
    if let Some(text) = &hit.text {
        object.insert("decoded_text".to_owned(), serde_json::json!(text));
    }
    if !hit.points.is_empty() {
        let points: Vec<serde_json::Value> = hit
            .points
            .iter()
            .map(|(x, y)| serde_json::json!([x, y]))
            .collect();
        let bounds = hit.bounds.map(|bounds| {
            serde_json::json!({
                "x": bounds.x,
                "y": bounds.y,
                "width": bounds.width,
                "height": bounds.height,
            })
        });
        object.insert(
            "position".to_owned(),
            serde_json::json!({ "points": points, "bounds": bounds }),
        );
    }
    object.insert("metadata".to_owned(), serde_json::json!(hit.metadata));
    object.insert(
        "payload_type".to_owned(),
        serde_json::json!(hit.payload_info.payload_type.id()),
    );
    object.insert(
        "payload_length".to_owned(),
        serde_json::json!(hit.payload_info.length),
    );
    object.insert(
        "preview_hex".to_owned(),
        serde_json::json!(hit.preview_hex()),
    );
    serde_json::Value::Object(object)
}

fn image_scan_qr_bytes_op(v: &Value, params: &ParamMap, ctx: &ExecutionContext) -> OpResult<Value> {
    const OP: &str = "QR / Barcode Scan Bytes";
    let image = crate::ops::decode_input_image(v, OP)?;
    let options = scan_options_from_params(params)?;
    let roi =
        crate::ops::parse_roi(params)?.unwrap_or_else(|| Roi::whole(image.width, image.height));
    let result = scan(&image, roi, options, ctx)?;
    let max_bytes = (params
        .int_or("max_bytes", crate::ops::DEFAULT_PREVIEW_BYTES as i64)
        .max(0) as u64)
        .min(crate::ops::MAX_EXTRACT_BYTES as u64) as usize;
    // Selection: a complete merged Structured Append sequence carries the full
    // payload, so it wins over its individual parts; otherwise the first
    // (topmost-leftmost) detected symbol.
    let selected = result.merged.first().or_else(|| result.hits.first());
    let Some(hit) = selected else {
        return Err(OperationError::invalid_input(format!(
            "{OP}: no barcode or QR symbol found in the scanned region"
        ))
        .with_details(result.notes.join("; ")));
    };
    let payload = hit.payload.as_deref().unwrap_or(&[]);
    let emit = payload.len().min(max_bytes);
    let header = serde_json::json!({
        "format": hit.format,
        "from_merged_sequence": !result.merged.is_empty(),
        "payload_present": !payload.is_empty(),
        "payload_length": payload.len(),
        "emitted_bytes": emit,
        "truncated": emit < payload.len(),
        "payload_type": hit.payload_info.payload_type.id(),
        "decoded_text": hit.text,
        "total_hits": result.hits.len(),
        "notes": result.notes,
    });
    // The established transport: JSON report header line, then the raw bytes
    // as the payload so recipes can chain them onward.
    let mut out = serde_json::to_vec(&header)
        .map_err(|e| OperationError::internal(format!("serialize QR scan header: {e}")))?;
    out.push(b'\n');
    out.extend_from_slice(&payload[..emit]);
    Ok(Value::Bytes(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    use cybercipher_core::{ErrorKind, OperationRegistry};
    use cybercipher_media::{decode, encode_png, DecodeLimits};
    use rxing::{common::BitMatrix, BarcodeFormat, EncodeHints, MultiFormatWriter, Writer};

    fn ctx() -> ExecutionContext {
        ExecutionContext::new()
    }

    // -----------------------------------------------------------------
    // Synthetic QR fixtures via the rxing encoder (dev-dependency only).
    // -----------------------------------------------------------------

    /// Encodes `content` into a QR `BitMatrix`. The writer keeps the requested
    /// size when it fits the symbol plus its quiet zone.
    fn qr_matrix(content: &str, hints: &EncodeHints, size: i32) -> BitMatrix {
        MultiFormatWriter
            .encode_with_hints(content, &BarcodeFormat::QR_CODE, size, size, hints)
            .expect("QR fixture must encode")
    }

    /// Renders a `BitMatrix` (black modules on white) as an ARGB image.
    fn matrix_image(matrix: &BitMatrix) -> RgbaImage {
        let width = matrix.width();
        let height = matrix.height();
        let mut argb = Vec::with_capacity((width as usize) * (height as usize));
        for y in 0..height {
            for x in 0..width {
                argb.push(if matrix.get(x, y) {
                    0xFF00_0000
                } else {
                    0xFFFF_FFFF
                });
            }
        }
        RgbaImage::new(width, height, argb, false).expect("fixture dimensions")
    }

    fn qr_image(content: &str) -> RgbaImage {
        matrix_image(&qr_matrix(content, &EncodeHints::default(), 290))
    }

    /// Binary-payload QR: each byte becomes the ISO-8859-1 character with the
    /// same value, so the encoder's BYTE mode carries the exact bytes back.
    fn qr_image_binary(payload: &[u8]) -> RgbaImage {
        let content: String = payload.iter().map(|&byte| byte as char).collect();
        let hints = EncodeHints {
            CharacterSet: Some("ISO-8859-1".to_owned()),
            ..EncodeHints::default()
        };
        matrix_image(&qr_matrix(&content, &hints, 290))
    }

    fn inverted_image(image: &RgbaImage) -> RgbaImage {
        let argb = image.argb.iter().map(|pixel| pixel ^ 0x00FF_FFFF).collect();
        RgbaImage::new(image.width, image.height, argb, false).expect("fixture dimensions")
    }

    fn rotate_ccw_n(image: &RgbaImage, turns: u32) -> RgbaImage {
        let mut buffer = image.argb.clone();
        let (mut width, mut height) = (image.width, image.height);
        for _ in 0..turns {
            let (next, next_width, next_height) = rotate_argb_ccw(&buffer, width, height);
            buffer = next;
            width = next_width;
            height = next_height;
        }
        RgbaImage::new(width, height, buffer, false).expect("fixture dimensions")
    }

    fn paste_onto(canvas: &mut [u32], canvas_width: u32, image: &RgbaImage, at_x: u32, at_y: u32) {
        for y in 0..image.height {
            for x in 0..image.width {
                canvas[((at_y + y) * canvas_width + at_x + x) as usize] =
                    image.argb[(y * image.width + x) as usize];
            }
        }
    }

    /// Two upright QR symbols side by side on a white canvas.
    fn two_qr_canvas() -> RgbaImage {
        let first = qr_image("FIRST-SYMBOL-1");
        let second = qr_image("SECOND-SYMBOL-2");
        let gap = 60u32;
        let width = first.width + gap + second.width;
        let height = first.height.max(second.height);
        let mut argb = vec![0xFFFF_FFFF; (width as usize) * (height as usize)];
        paste_onto(&mut argb, width, &first, 0, 0);
        paste_onto(&mut argb, width, &second, first.width + gap, 0);
        RgbaImage::new(width, height, argb, false).expect("fixture dimensions")
    }

    /// A QR pasted into a larger white canvas at a known offset.
    fn positioned_qr_canvas() -> RgbaImage {
        let qr = qr_image("POSITIONED-OK");
        let (width, height) = (700u32, 500u32);
        let mut argb = vec![0xFFFF_FFFF; (width as usize) * (height as usize)];
        paste_onto(&mut argb, width, &qr, 200, 150);
        RgbaImage::new(width, height, argb, false).expect("fixture dimensions")
    }

    /// Deterministic pseudo-noise: an undecodable hostile image.
    fn noise_image(width: u32, height: u32) -> RgbaImage {
        let mut state = 0x5EED_0001_u32;
        let mut argb = Vec::with_capacity((width as usize) * (height as usize));
        for _ in 0..(width as usize) * (height as usize) {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            argb.push(0xFF00_0000 | (state & 0x00FF_FFFF));
        }
        RgbaImage::new(width, height, argb, false).expect("fixture dimensions")
    }

    fn scan_whole(image: &RgbaImage, options: ScanOptions) -> ScanResult {
        scan(
            image,
            Roi::whole(image.width, image.height),
            options,
            &ctx(),
        )
        .expect("scan must not fail")
    }

    // -----------------------------------------------------------------
    // Scan behaviour.
    // -----------------------------------------------------------------

    #[test]
    fn single_qr_text_decodes_exactly() {
        let image = qr_image("CYBER{qr_text_ok}");
        let result = scan_whole(&image, ScanOptions::default());
        assert_eq!(
            result.hits.len(),
            1,
            "one symbol, deduplicated across passes"
        );
        let hit = &result.hits[0];
        assert_eq!(hit.format, "QR_CODE");
        assert_eq!(hit.text.as_deref(), Some("CYBER{qr_text_ok}"));
        // The payload is the decoder's byte segments: exactly the text bytes.
        assert_eq!(
            hit.payload.as_deref(),
            Some(b"CYBER{qr_text_ok}".as_slice())
        );
        assert_eq!(hit.payload_hex(), hex(b"CYBER{qr_text_ok}"));
        assert_eq!(
            hit.payload_info.payload_type,
            crate::payload::PayloadType::TextAscii
        );
        assert!(hit.located(), "upright decode reports positions");
        assert_eq!(hit.rotation_deg, 0);
        assert!(!hit.inverted);
        assert_eq!(hit.scale, 1.0);
        assert!(result.merged.is_empty());
    }

    #[test]
    fn single_qr_binary_payload_exact_bytes() {
        // PNG magic prefix: the classification must see a PNG, not text.
        let payload = [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0xFA, 0xFF,
        ];
        let image = qr_image_binary(&payload);
        let result = scan_whole(&image, ScanOptions::default());
        assert_eq!(result.hits.len(), 1);
        let hit = &result.hits[0];
        assert_eq!(hit.format, "QR_CODE");
        assert_eq!(hit.payload.as_deref(), Some(payload.as_slice()));
        assert_eq!(
            hit.payload_info.payload_type,
            crate::payload::PayloadType::Png
        );
        assert_eq!(hit.payload_info.length, payload.len());
    }

    #[test]
    fn binary_payload_without_signature_is_binary() {
        let payload = [0x00, 0x01, 0xFA, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF];
        let image = qr_image_binary(&payload);
        let result = scan_whole(&image, ScanOptions::default());
        assert_eq!(result.hits.len(), 1);
        let hit = &result.hits[0];
        assert_eq!(hit.payload.as_deref(), Some(payload.as_slice()));
        assert_eq!(
            hit.payload_info.payload_type,
            crate::payload::PayloadType::Binary
        );
        assert!(hit.preview_hex().starts_with("0001faff"));
    }

    #[test]
    fn alphanumeric_symbol_reports_no_invented_payload() {
        // Pure alphanumeric-mode content: the symbol carries text only, no
        // byte segments — and no payload bytes may be invented from the text.
        let image = qr_image("TOPSECRET 42");
        let result = scan_whole(&image, ScanOptions::default());
        assert_eq!(result.hits.len(), 1);
        let hit = &result.hits[0];
        assert_eq!(hit.text.as_deref(), Some("TOPSECRET 42"));
        assert!(hit.payload.is_none());
        assert!(!hit.has_binary_payload());
        assert_eq!(hit.payload_hex(), "");
        assert_eq!(hit.preview_hex(), "");
        assert_eq!(
            hit.payload_info.payload_type,
            crate::payload::PayloadType::Empty
        );
        assert!(hit.metadata.contains_key("payload"));
    }

    #[test]
    fn roi_scan_finds_symbol_and_maps_position() {
        let canvas = positioned_qr_canvas();
        // A region containing only the QR decodes it.
        let roi = Roi::new(180, 130, 340, 340);
        let result = scan(&canvas, roi, ScanOptions::default(), &ctx()).expect("scan");
        assert_eq!(result.scanned_area, Roi::new(180, 130, 340, 340));
        assert_eq!(result.hits.len(), 1);
        let hit = &result.hits[0];
        assert_eq!(hit.text.as_deref(), Some("POSITIONED-OK"));
        let bounds = hit.bounds.expect("located symbol has bounds");
        // The bounds live in original image coordinates around (200, 150).
        assert!(
            bounds.x >= 190 && bounds.max_x() <= 500,
            "bounds.x {bounds:?}"
        );
        assert!(
            bounds.y >= 140 && bounds.max_y() <= 460,
            "bounds.y {bounds:?}"
        );
    }

    #[test]
    fn empty_and_disjoint_regions_return_empty_result() {
        let canvas = positioned_qr_canvas();
        // A region with nothing in it: empty result with a note, no error.
        let result = scan(
            &canvas,
            Roi::new(0, 0, 100, 100),
            ScanOptions::default(),
            &ctx(),
        )
        .expect("scan");
        assert!(result.hits.is_empty());
        assert!(!result.notes.is_empty());
        // A region outside the image is empty by definition.
        let result = scan(
            &canvas,
            Roi::new(1000, 1000, 50, 50),
            ScanOptions::default(),
            &ctx(),
        )
        .expect("scan");
        assert!(result.hits.is_empty());
        assert!(result.notes.iter().any(|note| note.contains("empty")));
        assert_eq!(result.scanned_area.width, 0);
    }

    #[test]
    fn hostile_noise_image_yields_no_hits() {
        let image = noise_image(160, 120);
        let result = scan_whole(&image, ScanOptions::default());
        assert!(result.hits.is_empty());
        assert!(result.merged.is_empty());
        assert!(result.notes.iter().any(|note| note.contains("No symbol")));
    }

    #[test]
    fn inverted_qr_decodes_only_via_inverted_fallback() {
        let image = inverted_image(&qr_image("INVERTED-OK"));
        // Without the inverted pass the light-on-dark symbol stays invisible.
        let result = scan_whole(
            &image,
            ScanOptions {
                try_inverted: false,
                ..ScanOptions::default()
            },
        );
        assert!(result.hits.is_empty());
        // With it, the symbol decodes and the hit says so.
        let result = scan_whole(&image, ScanOptions::default());
        assert_eq!(result.hits.len(), 1);
        let hit = &result.hits[0];
        assert_eq!(hit.text.as_deref(), Some("INVERTED-OK"));
        assert!(hit.inverted);
        assert_eq!(
            hit.metadata.get("inverted").map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn rotated_qr_decodes_via_rotation_fallback() {
        // The fixture is the QR rotated 90 degrees counter-clockwise; the
        // scanner must find it with a further 270 degree CCW turn.
        let image = rotate_ccw_n(&qr_image("ROTATED-OK"), 1);
        let result = scan_whole(&image, ScanOptions::default());
        assert_eq!(result.hits.len(), 1);
        let hit = &result.hits[0];
        assert_eq!(hit.text.as_deref(), Some("ROTATED-OK"));
        assert_eq!(hit.rotation_deg, 270);
        assert!(!hit.inverted);
        assert_eq!(hit.payload.as_deref(), Some(b"ROTATED-OK".as_slice()));
    }

    #[test]
    fn rotation_disabled_yields_nothing_on_rotated_input() {
        let image = rotate_ccw_n(&qr_image("ROTATED-OK"), 1);
        let result = scan_whole(
            &image,
            ScanOptions {
                try_rotations: false,
                ..ScanOptions::default()
            },
        );
        assert!(result.hits.is_empty());
    }

    #[test]
    fn two_symbols_both_found_in_position_order() {
        let canvas = two_qr_canvas();
        let result = scan_whole(&canvas, ScanOptions::default());
        assert_eq!(result.hits.len(), 2, "both symbols found and kept distinct");
        assert!(result.merged.is_empty());
        // Deterministic output order: top-to-bottom, left-to-right.
        assert_eq!(result.hits[0].text.as_deref(), Some("FIRST-SYMBOL-1"));
        assert_eq!(result.hits[1].text.as_deref(), Some("SECOND-SYMBOL-2"));
        let (first, second) = (
            result.hits[0].bounds.expect("located"),
            result.hits[1].bounds.expect("located"),
        );
        assert!(first.max_x() <= second.x + 3);
    }

    #[test]
    fn max_symbols_caps_results() {
        let canvas = two_qr_canvas();
        let result = scan_whole(
            &canvas,
            ScanOptions {
                max_symbols: 1,
                ..ScanOptions::default()
            },
        );
        assert_eq!(result.hits.len(), 1);
        assert!(result.notes.iter().any(|note| note.contains("max_symbols")));
    }

    #[test]
    fn code128_1d_barcode_decodes() {
        let matrix = MultiFormatWriter
            .encode_with_hints(
                "CYBER-123",
                &BarcodeFormat::CODE_128,
                300,
                60,
                &EncodeHints::default(),
            )
            .expect("Code-128 fixture must encode");
        let image = matrix_image(&matrix);
        let result = scan_whole(&image, ScanOptions::default());
        assert_eq!(result.hits.len(), 1);
        let hit = &result.hits[0];
        assert_eq!(hit.format, "CODE_128");
        assert_eq!(hit.text.as_deref(), Some("CYBER-123"));
        // 1D symbologies report text; the payload stays empty rather than
        // being rebuilt from the text.
        assert!(hit.payload.is_none());
    }

    #[test]
    fn rescale_chain_does_not_break_normal_scans() {
        let image = qr_image("CYBER{rescale_safe}");
        let result = scan_whole(
            &image,
            ScanOptions {
                try_rescale: true,
                ..ScanOptions::default()
            },
        );
        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].text.as_deref(), Some("CYBER{rescale_safe}"));
    }

    #[test]
    fn scan_honours_cancellation() {
        let image = qr_image("CYBER{cancelled}");
        let flag = Arc::new(AtomicBool::new(true));
        let cancelled = ExecutionContext::new().with_cancel(flag);
        let error = scan(
            &image,
            Roi::whole(image.width, image.height),
            ScanOptions::default(),
            &cancelled,
        )
        .expect_err("cancelled scan must fail");
        assert_eq!(error.kind, ErrorKind::Cancelled);
    }

    // -----------------------------------------------------------------
    // Geometry helpers.
    // -----------------------------------------------------------------

    #[test]
    fn scale_argb_nearest_preserves_pixels_and_dims() {
        let pixels = vec![1u32, 2, 3, 4];
        let (out, width, height) = scale_argb_nearest(&pixels, 2, 2, 2.0);
        assert_eq!((width, height), (4, 4));
        assert_eq!(out, vec![1, 1, 2, 2, 1, 1, 2, 2, 3, 3, 4, 4, 3, 3, 4, 4]);
        let (out, width, height) = scale_argb_nearest(&pixels, 2, 2, 0.5);
        assert_eq!((width, height), (1, 1));
        assert_eq!(out, vec![1]);
        let (out, width, height) = scale_argb_nearest(&pixels, 2, 2, 1.0);
        assert_eq!(out.as_slice(), pixels.as_slice());
        assert_eq!((width, height), (2, 2));
    }

    #[test]
    fn rotate_argb_ccw_roundtrip_after_four_turns() {
        let (width, height) = (5u32, 3u32);
        let original: Vec<u32> = (0..width * height).map(|i| 0xFF00_0000 | i).collect();
        let mut buffer = original.clone();
        let (mut w, mut h) = (width, height);
        for turns in 1..=4u32 {
            let (next, nw, nh) = rotate_argb_ccw(&buffer, w, h);
            buffer = next;
            w = nw;
            h = nh;
            if turns % 2 == 1 {
                assert_eq!((w, h), (height, width));
            } else {
                assert_eq!((w, h), (width, height));
            }
        }
        assert_eq!(buffer, original);
    }

    #[test]
    fn to_original_maps_rotated_points_back() {
        // Original 6x4 with a marker pixel at (1, 2).
        let (width, height) = (6u32, 4u32);
        let mut pixels = vec![0xFFFF_FFFFu32; (width * height) as usize];
        pixels[(2 * width + 1) as usize] = 0xFF00_0000;
        for turns in 1..=3u32 {
            let mut buffer = pixels.clone();
            let (mut w, mut h) = (width, height);
            for _ in 0..turns {
                let (next, nw, nh) = rotate_argb_ccw(&buffer, w, h);
                buffer = next;
                w = nw;
                h = nh;
            }
            let mut marker = None;
            for y in 0..h {
                for x in 0..w {
                    if buffer[(y * w + x) as usize] == 0xFF00_0000 {
                        marker = Some((x as f32, y as f32));
                    }
                }
            }
            let (marker_x, marker_y) = marker.expect("marker survived the rotation");
            let (original_x, original_y) = to_original(marker_x, marker_y, turns, width, height);
            assert_eq!(
                (original_x, original_y),
                (1.0, 2.0),
                "turn {turns}: ({marker_x}, {marker_y}) must map back to (1, 2)"
            );
        }
    }

    // -----------------------------------------------------------------
    // Structured Append merge.
    // -----------------------------------------------------------------

    fn sa_hit(index: usize, total: usize, parity: u8, text: &str, payload: &[u8]) -> BarcodeHit {
        BarcodeHit {
            format: "QR_CODE".to_owned(),
            text: Some(text.to_owned()),
            payload: Some(payload.to_vec()),
            raw_bytes: None,
            points: Vec::new(),
            bounds: None,
            rotation_deg: 0,
            inverted: false,
            scale: 1.0,
            metadata: BTreeMap::new(),
            structured_append: Some(StructuredAppend {
                index,
                total,
                parity,
            }),
            payload_info: crate::payload::detect(payload),
        }
    }

    #[test]
    fn sa_merge_complete_sequence_in_index_order() {
        // Parts arrive out of order; the merge must concatenate by index.
        let hits = vec![
            sa_hit(2, 3, 0x5A, "c", b"c-bytes"),
            sa_hit(0, 3, 0x5A, "a", b"a-bytes"),
            sa_hit(1, 3, 0x5A, "b", b"b-bytes"),
        ];
        let outcome = merge_structured_append(&hits);
        assert_eq!(outcome.merged.len(), 1);
        assert!(outcome.unmerged.is_empty());
        assert!(outcome
            .notes
            .iter()
            .any(|note| note.contains("complete structured append sequence of 3")));
        let merged = &outcome.merged[0];
        assert_eq!(
            merged.payload.as_deref(),
            Some(b"a-bytesb-bytesc-bytes".as_slice())
        );
        assert_eq!(merged.text.as_deref(), Some("abc"));
        assert_eq!(
            merged
                .metadata
                .get("structured_append_total")
                .map(String::as_str),
            Some("3")
        );
        assert_eq!(
            merged
                .metadata
                .get("structured_append_parity")
                .map(String::as_str),
            Some("0x5a")
        );
        assert_eq!(
            merged.metadata.get("structured_append").map(String::as_str),
            Some("merged from 3 symbols")
        );
        assert_eq!(merged.payload_info.length, 21);
    }

    #[test]
    fn sa_merge_incomplete_sequence_kept_separate() {
        let hits = vec![sa_hit(0, 3, 0x5A, "a", b"a"), sa_hit(2, 3, 0x5A, "c", b"c")];
        let outcome = merge_structured_append(&hits);
        assert!(outcome.merged.is_empty());
        assert_eq!(outcome.unmerged.len(), 2);
        assert!(outcome
            .notes
            .iter()
            .any(|note| note.contains("no payload was guessed")));
    }

    #[test]
    fn sa_merge_conflicting_parts_rejected() {
        let hits = vec![
            sa_hit(0, 2, 0x5A, "a", b"one"),
            sa_hit(1, 2, 0x5A, "b", b"two"),
            sa_hit(1, 2, 0x5A, "b2", b"three"),
        ];
        let outcome = merge_structured_append(&hits);
        assert!(outcome.merged.is_empty());
        assert_eq!(outcome.unmerged.len(), 3);
    }

    #[test]
    fn sa_merge_single_part_sequence_passes_through() {
        let hits = vec![sa_hit(0, 1, 0x11, "solo", b"solo")];
        let outcome = merge_structured_append(&hits);
        assert!(outcome.merged.is_empty());
        assert_eq!(outcome.unmerged.len(), 1);
    }

    #[test]
    fn sa_merge_skips_unlocated_hits_without_content() {
        let mut empty = sa_hit(0, 2, 0x5A, "", b"");
        empty.text = None;
        empty.payload = None;
        let outcome = merge_structured_append(&[empty]);
        assert!(outcome.merged.is_empty());
        assert_eq!(outcome.unmerged.len(), 1);
    }

    // -----------------------------------------------------------------
    // Registry ops.
    // -----------------------------------------------------------------

    fn registry() -> OperationRegistry {
        let mut reg = OperationRegistry::new();
        register(&mut reg);
        reg
    }

    #[test]
    fn image_scan_qr_op_roundtrips() {
        let reg = registry();
        let op = reg.get("image_scan_qr").expect("op registered");
        let png = encode_png(&qr_image("CYBER{registry_ok}")).expect("png");
        let out = op
            .execute(&Value::Bytes(png), &ParamMap::new(), &ctx())
            .expect("scan op");
        let Value::Json(report) = out else {
            panic!("expected json output");
        };
        assert_eq!(report["symbol_count"], 1);
        assert_eq!(report["merged_count"], 0);
        assert_eq!(report["scanned_area"]["width"], 290);
        let hit = &report["hits"][0];
        assert_eq!(hit["format"], "QR_CODE");
        assert_eq!(hit["payload_type"], "text-ascii");
        let payload_hex = hit["raw_payload_bytes"].as_str().expect("hex");
        assert!(
            payload_hex.starts_with("43594245527b"),
            "hex of \"CYBER{{\": {payload_hex}"
        );
        assert_eq!(hit["decoded_text"], "CYBER{registry_ok}");
        assert!(hit["position"]["points"].as_array().expect("points").len() >= 3);
        assert!(hit["position"]["bounds"].is_object());
        assert_eq!(hit["metadata"]["symbology"], "QR_CODE");
        assert!(hit["preview_hex"].is_string());
    }

    #[test]
    fn image_scan_qr_bytes_transport_exact_bytes() {
        let reg = registry();
        let op = reg.get("image_scan_qr_bytes").expect("op registered");
        let payload = [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0xFA, 0xFF,
        ];
        let png = encode_png(&qr_image_binary(&payload)).expect("png");
        let out = op
            .execute(&Value::Bytes(png), &ParamMap::new(), &ctx())
            .expect("scan op");
        let Value::Bytes(bytes) = out else {
            panic!("expected bytes output");
        };
        let header_end = bytes
            .iter()
            .position(|&byte| byte == b'\n')
            .expect("header line");
        let header: serde_json::Value = serde_json::from_slice(&bytes[..header_end]).expect("json");
        assert_eq!(header["payload_present"], true);
        assert_eq!(header["payload_length"], payload.len());
        assert_eq!(header["emitted_bytes"], payload.len());
        assert_eq!(header["truncated"], false);
        assert_eq!(header["payload_type"], "png");
        assert_eq!(header["from_merged_sequence"], false);
        assert_eq!(header["total_hits"], 1);
        assert_eq!(bytes[header_end + 1..], payload);
    }

    #[test]
    fn image_scan_qr_bytes_text_only_yields_empty_payload() {
        let reg = registry();
        let op = reg.get("image_scan_qr_bytes").expect("op registered");
        let png = encode_png(&qr_image("TOPSECRET 42")).expect("png");
        let out = op
            .execute(&Value::Bytes(png), &ParamMap::new(), &ctx())
            .expect("scan op");
        let Value::Bytes(bytes) = out else {
            panic!("expected bytes output");
        };
        let header_end = bytes
            .iter()
            .position(|&byte| byte == b'\n')
            .expect("header line");
        let header: serde_json::Value = serde_json::from_slice(&bytes[..header_end]).expect("json");
        assert_eq!(header["payload_present"], false);
        assert_eq!(header["payload_length"], 0);
        assert_eq!(header["decoded_text"], "TOPSECRET 42");
        // No invented bytes: the payload section is empty.
        assert_eq!(bytes.len(), header_end + 1);
    }

    #[test]
    fn image_scan_qr_bytes_no_symbol_is_a_typed_error() {
        let reg = registry();
        let op = reg.get("image_scan_qr_bytes").expect("op registered");
        let png = encode_png(&noise_image(120, 90)).expect("png");
        let error = op
            .execute(&Value::Bytes(png), &ParamMap::new(), &ctx())
            .expect_err("no symbol must be an error");
        assert_eq!(error.kind, ErrorKind::InvalidInput);
    }

    #[test]
    fn registry_ops_typed_errors() {
        let reg = registry();
        for id in ["image_scan_qr", "image_scan_qr_bytes"] {
            let op = reg.get(id).unwrap();
            // Non-image input.
            let error = op
                .execute(
                    &Value::Text("not bytes".to_owned()),
                    &ParamMap::new(),
                    &ctx(),
                )
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::InvalidInput, "{id}");
            // Garbage image bytes.
            let error = op
                .execute(
                    &Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
                    &ParamMap::new(),
                    &ctx(),
                )
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::Decode, "{id}");
            // Malformed roi.
            let mut params = ParamMap::new();
            params.insert("roi", "1,2,3");
            let png = encode_png(&qr_image("CYBER{param_check}")).expect("png");
            let error = op.execute(&Value::Bytes(png), &params, &ctx()).unwrap_err();
            assert_eq!(error.kind, ErrorKind::InvalidParam, "{id}");
        }
    }

    #[test]
    fn registered_ops_expose_expected_spec() {
        let reg = registry();
        let scan_spec = reg.get("image_scan_qr").expect("registered").spec();
        assert_eq!(scan_spec.id, "image_scan_qr");
        assert_eq!(scan_spec.output_kind, cybercipher_core::ValueKind::Json);
        assert_eq!(scan_spec.cost, cybercipher_core::CostClass::Interactive);
        assert_eq!(scan_spec.category, cybercipher_core::Category::Analysis);
        let bytes_spec = reg.get("image_scan_qr_bytes").expect("registered").spec();
        assert_eq!(bytes_spec.output_kind, cybercipher_core::ValueKind::Bytes);
        assert_eq!(bytes_spec.cost, cybercipher_core::CostClass::Interactive);
    }

    #[test]
    fn decoded_png_roundtrip_matches_fixture() {
        let image = qr_image("CYBER{roundtrip}");
        let png = encode_png(&image).expect("png");
        let decoded = decode(&png, &DecodeLimits::default()).expect("png decode");
        assert_eq!(decoded.width, image.width);
        assert_eq!(decoded.height, image.height);
        assert_eq!(decoded.argb, image.argb);
    }
}
