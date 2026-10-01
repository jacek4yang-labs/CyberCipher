//! Registry operations for the steg engine.
//!
//! Images travel through the registry as PNG-encoded bytes (the only binary
//! carrier in the [`Value`] model is `Bytes`), so ops decode bounded, apply,
//! and re-encode. The GUI drives the crate API directly for live transform
//! stepping; these ops make the same semantics composable in recipes, the
//! CLI and Auto Analyze.

use cybercipher_core::prelude::*;
use cybercipher_core::{ExecutionContext, OpResult, OperationRegistry, Value};
use cybercipher_media::{decode, encode_png, DecodeLimits, Roi};

use crate::auto_lsb;
use crate::combine::{self, CombineMode};
use crate::extract::{extract_bounded, ExtractionOptions, RgbOrder};
use crate::frames;
use crate::stereo;
use crate::transforms::{self};

/// Default bounded-preview size shared by the extraction and carving ops.
pub(crate) const DEFAULT_PREVIEW_BYTES: usize = 65_536;
/// Hard payload cap for the extraction and carving ops.
pub(crate) const MAX_EXTRACT_BYTES: usize = 16 * 1024 * 1024;
/// Hard caps for the Auto LSB scan op (defaults live in the param specs).
const MAX_SCAN_CANDIDATES: usize = 200;
const MAX_SCAN_PREFIX_BYTES: usize = 1024 * 1024;

fn media_error(e: cybercipher_media::MediaError, op: &str) -> OperationError {
    use cybercipher_media::MediaError;
    let (message, details) = match &e {
        MediaError::TooLarge {
            what,
            limit,
            actual,
        } => (
            format!("{op}: {what} exceeds the configured cap"),
            format!("limit {limit}, actual {actual}"),
        ),
        MediaError::UnsupportedFormat { detail } => {
            (format!("{op}: unsupported image format"), detail.clone())
        }
        MediaError::Corrupt { detail } => (
            format!("{op}: image is corrupt or truncated"),
            detail.clone(),
        ),
        MediaError::Io { detail } => (format!("{op}: image I/O failure"), detail.clone()),
    };
    OperationError::decode(message).with_details(details)
}

fn decode_input_image(v: &Value, op: &str) -> OpResult<cybercipher_media::RgbaImage> {
    let bytes = match v {
        Value::Bytes(b) => b,
        other => {
            let found = format!("{:?}", other.kind());
            return Err(OperationError::invalid_input(format!(
                "{op} expects image bytes (a PNG or other supported image), got {found}"
            ))
            .with_expected("Bytes"));
        }
    };
    decode(bytes, &DecodeLimits::default()).map_err(|e| media_error(e, op))
}

fn image_info_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let image = decode_input_image(v, "Image Info")?;
    let info = serde_json::json!({
        "width": image.width,
        "height": image.height,
        "pixel_count": image.pixel_count(),
        "has_alpha": image.has_alpha,
        "indexed": image.indexed.as_ref().map(|ix| serde_json::json!({
            "palette_entries": ix.palette.len(),
        })),
        "estimated_bytes": image.estimated_bytes(),
    });
    Ok(Value::Json(info))
}

fn image_transform_op(v: &Value, params: &ParamMap, ctx: &ExecutionContext) -> OpResult<Value> {
    const OP: &str = "Image Transform";
    let image = decode_input_image(v, OP)?;
    let index = params.require_int("transform", 0, 41)? as usize;
    let transformed = transforms::apply_checked(index, &image, ctx)?;
    let png = encode_png(&transformed).map_err(|e| media_error(e, OP))?;
    Ok(Value::Bytes(png))
}

// ---------------------------------------------------------------------------
// Stereo / combine / GIF frames
// ---------------------------------------------------------------------------

fn image_stereo_shift_op(v: &Value, params: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    const OP: &str = "Stereo Shift";
    let image = decode_input_image(v, OP)?;
    let offset = params.int_or("offset", 1);
    let result = if params.bool_or("edge_hold", false) {
        stereo::edge_hold(&image, offset)
    } else {
        stereo::shifted_xor(&image, offset)
    };
    let png = encode_png(&result).map_err(|e| media_error(e, OP))?;
    Ok(Value::Bytes(png))
}

fn image_stereo_auto_op(v: &Value, params: &ParamMap, ctx: &ExecutionContext) -> OpResult<Value> {
    const OP: &str = "Stereo Auto";
    let image = decode_input_image(v, OP)?;
    let sample_step = params.int_or("sample_step", 2).max(1) as usize;
    let best = stereo::best_offset(&image, sample_step, ctx)?;
    Ok(Value::Json(serde_json::json!({
        "best_offset": best,
        "sample_step": sample_step,
        "width": image.width,
        "height": image.height,
        "hint": if best == 0 {
            "no repeating pattern found"
        } else {
            "apply the offset with Stereo Shift to reveal the depth map"
        },
    })))
}

fn decode_two_images(
    v: &Value,
    op: &str,
) -> OpResult<(cybercipher_media::RgbaImage, cybercipher_media::RgbaImage)> {
    let items = match v {
        Value::List(items) => items,
        other => {
            let found = format!("{:?}", other.kind());
            return Err(OperationError::invalid_input(format!(
                "{op} expects a list of two images [image A, image B], got {found}"
            ))
            .with_expected("List of two Bytes items")
            .with_actual(found));
        }
    };
    if items.len() != 2 {
        return Err(OperationError::invalid_input(format!(
            "{op} expects exactly two images, got {}",
            items.len()
        ))
        .with_expected("2 items")
        .with_actual(items.len().to_string()));
    }
    Ok((
        decode_input_image(&items[0], op)?,
        decode_input_image(&items[1], op)?,
    ))
}

fn image_combine_op(v: &Value, params: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    const OP: &str = "Image Combine";
    let (first, second) = decode_two_images(v, OP)?;
    let mode_index = params.require_int("mode", 0, 12)? as usize;
    let mode = CombineMode::from_legacy_index(mode_index).ok_or_else(|| {
        OperationError::invalid_param("mode", format!("no combine mode {mode_index}"))
            .with_expected("0..12")
    })?;
    let combined = combine::combine(mode, &first, &second)?;
    let png = encode_png(&combined).map_err(|e| media_error(e, OP))?;
    Ok(Value::Bytes(png))
}

fn gif_bytes_input<'a>(v: &'a Value, op: &str) -> OpResult<&'a [u8]> {
    match v {
        Value::Bytes(b) => Ok(b),
        other => {
            let found = format!("{:?}", other.kind());
            Err(
                OperationError::invalid_input(format!("{op} expects GIF file bytes, got {found}"))
                    .with_expected("Bytes")
                    .with_actual(found),
            )
        }
    }
}

fn image_gif_info_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    const OP: &str = "GIF Info";
    let bytes = gif_bytes_input(v, OP)?;
    let index = frames::index_frames(bytes, &DecodeLimits::default())?;
    let frames_json: Vec<serde_json::Value> = index
        .frames
        .iter()
        .map(|f| {
            serde_json::json!({
                "index": f.index,
                "left": f.left,
                "top": f.top,
                "width": f.width,
                "height": f.height,
                "delay_cs": f.delay_cs,
                "disposal": f.disposal.name(),
                "transparent_index": f.transparent_index,
                "interlaced": f.interlaced,
            })
        })
        .collect();
    Ok(Value::Json(serde_json::json!({
        "screen": { "width": index.screen_width, "height": index.screen_height },
        "frame_count": index.frames.len(),
        "frames_truncated": index.truncated,
        "frames": frames_json,
    })))
}

fn image_gif_frame_op(v: &Value, params: &ParamMap, ctx: &ExecutionContext) -> OpResult<Value> {
    const OP: &str = "GIF Frame";
    let bytes = gif_bytes_input(v, OP)?;
    let index = params.int_or("frame", 0).max(0) as usize;
    let composed = frames::decode_frame(bytes, index, &DecodeLimits::default(), ctx)?;
    let png = encode_png(&composed).map_err(|e| media_error(e, OP))?;
    Ok(Value::Bytes(png))
}

fn parse_roi(params: &ParamMap) -> OpResult<Option<Roi>> {
    let text = match params.get_str("roi") {
        None => return Ok(None),
        Some(t) if t.trim().is_empty() => return Ok(None),
        Some(t) => t.trim(),
    };
    let parts: Vec<&str> = text.split(',').map(str::trim).collect();
    if parts.len() != 4 {
        return Err(
            OperationError::invalid_param("roi", "expected 'x,y,width,height'")
                .with_expected("x,y,width,height")
                .with_actual(text.to_owned()),
        );
    }
    let mut nums = [0u32; 4];
    for (slot, part) in nums.iter_mut().zip(parts) {
        *slot = part
            .parse()
            .map_err(|_| OperationError::invalid_param("roi", format!("bad number '{part}'")))?;
    }
    Ok(Some(Roi::new(nums[0], nums[1], nums[2], nums[3])))
}

fn image_extract_bits_op(v: &Value, params: &ParamMap, ctx: &ExecutionContext) -> OpResult<Value> {
    const OP: &str = "Extract Bits";
    let image = decode_input_image(v, OP)?;
    let mask_text = params.get_str("plane_mask").unwrap_or("000000ff");
    let plane_mask = u32::from_str_radix(mask_text.trim_start_matches("0x"), 16).map_err(|_| {
        OperationError::invalid_param("plane_mask", "expected a hex 32-bit plane mask")
            .with_expected("hex mask in plane space, e.g. 01010100 for RGB bit 0")
            .with_actual(mask_text.to_owned())
    })?;
    let order_code = params.int_or("order", 1) as u32;
    let order = RgbOrder::from_legacy_code(order_code)?;
    let options = ExtractionOptions {
        plane_mask,
        order,
        lsb_first: params.bool_or("lsb_first", false),
        row_first: params.bool_or("row_first", true),
        invert_bits: params.bool_or("invert_bits", false),
    };
    let max_bytes = (params
        .int_or("max_bytes", DEFAULT_PREVIEW_BYTES as i64)
        .max(0) as u64)
        .min(MAX_EXTRACT_BYTES as u64) as usize;
    let roi = parse_roi(params)?.unwrap_or_else(|| Roi::whole(image.width, image.height));
    let result = extract_bounded(&image, roi, options, max_bytes, ctx)?;
    let report = serde_json::json!({
        "total_bytes": result.total_bytes,
        "truncated": result.truncated,
        "settings": options.describe(),
    });
    // The extracted bytes are the payload; the report travels as a header
    // line so recipes can chain the bytes directly into the next op while
    // keeping the provenance inspectable.
    let mut out = serde_json::to_vec(&report).expect("serialise extraction report");
    out.push(b'\n');
    out.extend_from_slice(&result.data);
    Ok(Value::Bytes(out))
}

/// Serialises one scan candidate for the JSON output.
fn candidate_json(candidate: &auto_lsb::LsbCandidate) -> serde_json::Value {
    let preview_limit = candidate.preview.len().min(256);
    let preview_hex: String = candidate.preview[..preview_limit]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let options = candidate.options;
    serde_json::json!({
        "settings": {
            "description": options.describe(),
            "config": candidate.formatted_config(),
            "plane_mask": format!("{:08x}", options.plane_mask),
            "argb_mask": format!("{:08x}", options.argb_mask()),
            "order": auto_lsb::order_label(options.order),
            "order_code": options.order.legacy_code(),
            "lsb_first": options.lsb_first,
            "row_first": options.row_first,
            "invert_bits": options.invert_bits,
        },
        "score": candidate.score,
        "reason": candidate.reason,
        "payload_type": candidate.payload_type.type_name(),
        "payload_type_id": candidate.payload_type.id(),
        "preview_hex": preview_hex,
        "preview_bytes": candidate.preview.len(),
        "total_bytes": candidate.total_bytes,
        "truncated": candidate.truncated,
        "fingerprint": format!("{:016x}", candidate.fingerprint()),
    })
}

fn auto_lsb_scan_op(v: &Value, params: &ParamMap, ctx: &ExecutionContext) -> OpResult<Value> {
    const OP: &str = "Auto LSB Scan";
    let image = decode_input_image(v, OP)?;
    let deep = params.bool_or("deep", false);
    let roi = parse_roi(params)?.unwrap_or_else(|| Roi::whole(image.width, image.height));
    let max_candidates =
        (params.int_or("max_candidates", 50).max(0) as usize).min(MAX_SCAN_CANDIDATES);
    let prefix_bytes = (params
        .int_or("prefix_bytes", auto_lsb::SCAN_PREFIX_LIMIT as i64)
        .max(0) as usize)
        .min(MAX_SCAN_PREFIX_BYTES);

    // Cancellation/deadline travel through the execution context; progress
    // is not surfaced by the registry (the command layer owns cancellation),
    // so the callback is a no-op here.
    let ranked = auto_lsb::scan_with_limits(&image, roi, deep, prefix_bytes, ctx, |_, _, _| {})?;
    let items: Vec<serde_json::Value> = ranked
        .iter()
        .take(max_candidates)
        .map(candidate_json)
        .collect();
    Ok(Value::Json(serde_json::Value::Array(items)))
}

fn plane_mask_param() -> ParamSpec {
    ParamSpec {
        key: "plane_mask",
        label: "Plane mask",
        kind: ParamKind::Text,
        default: ParamDefault::Str("01010100"),
        optional: false,
        hint: "32-bit hex mask in plane space: bit channel_ordinal*8+plane selects that plane (ordinals: alpha=0, red=1, green=2, blue=3). 01010100 = RGB bit 0; 80000000 = alpha bit 7.",
        options: &[],
    }
}

// ---------------------------------------------------------------------------
// Local spec/param helpers (same shape as the codec crate's; steg does not
// depend on the codec crate, so the small builders are duplicated here).
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub(crate) fn spec(
    id: &'static str,
    name: &'static str,
    description: &'static str,
    category: Category,
    inputs: &[ValueKind],
    output: ValueKind,
    cost: CostClass,
    reversible: bool,
    params: Vec<ParamSpec>,
    tags: &[&'static str],
    aliases: &[&'static str],
    standard: &'static str,
    vectors: &'static str,
) -> &'static OperationSpec {
    Box::leak(Box::new(OperationSpec {
        id,
        name,
        description,
        category,
        input_kinds: Box::leak(inputs.to_vec().into_boxed_slice()),
        output_kind: output,
        params: Box::leak(params.into_boxed_slice()),
        cost,
        security: Security::Neutral,
        deterministic: true,
        reversible,
        aliases: Box::leak(aliases.to_vec().into_boxed_slice()),
        tags: Box::leak(tags.to_vec().into_boxed_slice()),
        provenance: Provenance {
            standard,
            implementation: "CyberCipher native Rust (StegSolve-compatible semantics)",
            test_vectors: vectors,
        },
    }))
}

pub(crate) fn p_text(
    key: &'static str,
    label: &'static str,
    default: &'static str,
    hint: &'static str,
) -> ParamSpec {
    ParamSpec {
        key,
        label,
        kind: ParamKind::Text,
        default: ParamDefault::Str(default),
        optional: false,
        hint,
        options: &[],
    }
}

pub(crate) fn p_bool(
    key: &'static str,
    label: &'static str,
    default: bool,
    hint: &'static str,
) -> ParamSpec {
    ParamSpec {
        key,
        label,
        kind: ParamKind::Boolean,
        default: ParamDefault::Bool(default),
        optional: false,
        hint,
        options: &[],
    }
}

pub(crate) fn p_int(
    key: &'static str,
    label: &'static str,
    default: i64,
    hint: &'static str,
) -> ParamSpec {
    ParamSpec {
        key,
        label,
        kind: ParamKind::Integer,
        default: ParamDefault::Int(default),
        optional: false,
        hint,
        options: &[],
    }
}

pub(crate) fn register(reg: &mut OperationRegistry) {
    use cybercipher_core::Category::Analysis as A;
    use cybercipher_core::ValueKind::{Bytes as B, Json as J};

    reg.add_simple(
        spec(
            "image_info",
            "Image Info",
            "Reports dimensions, pixel count, alpha/palette presence and estimated memory of a bounded-decoded image.",
            A,
            &[B],
            J,
            CostClass::Instant,
            false,
            vec![],
            &["steg", "image", "ctf"],
            &[],
            "Semantics ported from StegSolve via StegSolver c14bfa9 (MIT)",
            "Golden tests against deterministic synthetic images",
        ),
        image_info_op,
    );

    reg.add_simple(
        spec(
            "image_transform",
            "Image Transform",
            "Applies one of the 42 StegSolve-compatible transforms (bit planes 7..0 of alpha/red/green/blue, invert, full channels, three random colour maps, gray pixels) and returns the PNG of the result.",
            A,
            &[B],
            B,
            CostClass::Instant,
            false,
            vec![p_int(
                "transform",
                "Transform index",
                1,
                "Catalog index 0..41 in StegSolve order (2..9 alpha planes 7..0, 10..17 red, 18..25 green, 26..33 blue, 34..37 full channels, 38..40 random maps, 41 gray).",
            )],
            &["steg", "image", "ctf"],
            &[],
            "Semantics ported from StegSolve via StegSolver c14bfa9 (MIT); transform order preserves the original StegSolve numbering",
            "Golden parity tests against a tests-only legacy oracle",
        ),
        image_transform_op,
    );

    reg.add_simple(
        spec(
            "image_extract_bits",
            "Extract Bits",
            "Extracts a bit stream from image planes with StegSolve conventions: alpha-first visit order, configurable RGB permutation, row/column traversal, LSB/MSB plane order, bit inversion, bounded preview.",
            A,
            &[B],
            B,
            CostClass::Interactive,
            false,
            vec![
                plane_mask_param(),
                p_int("order", "RGB order", 1, "Colour channel visit order: 1=RGB .. 6=BGR (legacy codes); alpha is always visited first."),
                p_bool("lsb_first", "LSB-first plane order", false, "Visit planes 0..7 (LSB-first) instead of 7..0 (MSB-first) inside each channel."),
                p_bool("row_first", "Row-first traversal", true, "Traverse row by row instead of column by column."),
                p_bool("invert_bits", "Invert bits", false, "Complement every pixel before reading planes."),
                p_text("roi", "Region", "", "Optional 'x,y,width,height' region; defaults to the whole image."),
                p_int("max_bytes", "Max bytes", 65_536, "Bounded preview size; the full extraction is available via the engine API. Hard cap 16 MiB."),
            ],
            &["steg", "image", "ctf", "lsb"],
            &[],
            "Semantics ported from StegSolve via StegSolver c14bfa9 (MIT)",
            "Hand-computed extraction vectors over synthetic images",
        ),
        image_extract_bits_op,
    );

    reg.add_simple(
        spec(
            "image_stereo_shift",
            "Stereo Shift",
            "Stereogram solver: XORs the image with a horizontally shifted copy of itself, which reveals the depth map of an autostereogram once the shift matches the repeating pattern width. Wraps the sample at the right edge (or clamps it with edge hold); offset 0 collapses to opaque black.",
            A,
            &[B],
            B,
            CostClass::Instant,
            false,
            vec![
                p_int("offset", "Offset (pixels)", 1, "Horizontal shift; negative values and values at or beyond the width wrap around (normalized into 0..width-1)."),
                p_bool("edge_hold", "Edge hold", false, "Clamp the sample at the right edge instead of wrapping, removing the wrap-around seam on the last columns."),
            ],
            &["steg", "image", "ctf", "stereo"],
            &[],
            "Semantics ported from StegSolve via StegSolver c14bfa9 (MIT): StereoTransform.shiftedXor/withEdgeHold",
            "Hand-computed vectors over a period-8 pattern plus edge-hold/normalization fixtures",
        ),
        image_stereo_shift_op,
    );

    reg.add_simple(
        spec(
            "image_stereo_auto",
            "Stereo Auto",
            "Scans for the stereogram offset with the strongest self similarity: offsets 1..=width/2 are compared on every Nth row and column and the best match wins, with the smallest offset preferred among equals so the fundamental pattern period beats its multiples.",
            A,
            &[B],
            J,
            CostClass::Interactive,
            false,
            vec![p_int(
                "sample_step",
                "Sample step",
                2,
                "Compare only every Nth row and column (1 = exhaustive). The scan is O(width^2 * height / step).",
            )],
            &["steg", "image", "ctf", "stereo", "auto"],
            &[],
            "Semantics ported from StegSolve via StegSolver c14bfa9 (MIT): StereoTransform.bestOffset",
            "Period-8 autostereogram fixtures; tie-breaking and cancellation tests",
        ),
        image_stereo_auto_op,
    );

    reg.add_simple(
        spec(
            "image_combine",
            "Image Combine",
            "Combines two images with one of the 13 StegSolve combiner modes (bit-exact): XOR/OR/AND/ADD/SUB/MUL whole-pixel with Java int wraparound, per-channel ADD/SUB/MUL wrapping within each 8-bit lane, per-channel Lightest/Darkest, and row/column interlacing on the size intersection. Mismatched sizes use the max canvas with transparent-black fill; every output is opaque. Input: a list of exactly two images [A, B].",
            A,
            &[cybercipher_core::ValueKind::List],
            B,
            CostClass::Instant,
            false,
            vec![p_int(
                "mode",
                "Mode",
                0,
                "Legacy combiner number 0..12: 0 XOR, 1 OR, 2 AND, 3 ADD, 4 ADD (R,G,B separate), 5 SUB, 6 SUB (R,G,B separate), 7 MUL, 8 MUL (R,G,B separate), 9 Lightest, 10 Darkest, 11 Interlace rows, 12 Interlace columns.",
            )],
            &["steg", "image", "ctf", "combine"],
            &[],
            "Semantics ported from StegSolve via StegSolver c14bfa9 (MIT): CombineMode.combine/combinePixels",
            "Hand-computed per-mode vectors including Java wraparound, size-mismatch and interlace geometry fixtures",
        ),
        image_combine_op,
    );

    reg.add_simple(
        spec(
            "image_gif_info",
            "GIF Info",
            "Indexes the frames of a GIF file without decoding pixel data: logical screen size, frame count, and per-frame region, delay, disposal method, transparency and interlace. Indexing stops at 4096 frames and reports the cut.",
            A,
            &[B],
            J,
            CostClass::Interactive,
            false,
            vec![],
            &["steg", "image", "ctf", "gif", "frames"],
            &[],
            "GIF89a block semantics; frame metadata via the gif crate (StegSolver Lane C frames model)",
            "Synthetic multi-frame GIF fixtures with disposal/transparency checks",
        ),
        image_gif_info_op,
    );

    reg.add_simple(
        spec(
            "image_gif_frame",
            "GIF Frame",
            "Decodes one GIF frame and returns it as PNG. Frames are composited onto the logical screen in order (restore-to-background/previous honoured), so the result is what a viewer displays while that frame is shown; undrawn regions stay transparent.",
            A,
            &[B],
            B,
            CostClass::Interactive,
            false,
            vec![p_int(
                "frame",
                "Frame index",
                0,
                "Zero-based frame number; the stream is decoded up to this frame (no random access).",
            )],
            &["steg", "image", "ctf", "gif", "frames"],
            &[],
            "GIF89a disposal semantics; decoding via the gif crate (StegSolver Lane C frames model)",
            "Synthetic three-frame fixture with disposal-chain and transparency assertions",
        ),
        image_gif_frame_op,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use cybercipher_media::{encode_png, RgbaImage};

    fn registry() -> OperationRegistry {
        let mut reg = OperationRegistry::new();
        register(&mut reg);
        reg
    }

    fn png_input() -> Vec<u8> {
        let img = RgbaImage::new(
            3,
            2,
            vec![
                0xFF112233, 0xFF445566, 0xFF778899, 0xFFAABBCC, 0xFFDDEEFF, 0xFF0F1F2F,
            ],
            false,
        )
        .unwrap();
        encode_png(&img).unwrap()
    }

    #[test]
    fn image_transform_roundtrips_through_registry() {
        let reg = registry();
        let op = reg.get("image_transform").expect("op registered");
        let mut params = ParamMap::new();
        params.insert("transform", 1i64); // invert
        let out = op
            .execute(
                &Value::Bytes(png_input()),
                &params,
                &ExecutionContext::new(),
            )
            .unwrap();
        let Value::Bytes(png) = out else {
            panic!("expected bytes");
        };
        let decoded = decode(&png, &DecodeLimits::default()).unwrap();
        assert_eq!(decoded.argb[0], 0xFFEEDDCC); // 0xFF112233 inverted
    }

    #[test]
    fn image_info_reports_structure() {
        let reg = registry();
        let op = reg.get("image_info").expect("op registered");
        let out = op
            .execute(
                &Value::Bytes(png_input()),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap();
        let Value::Json(info) = out else {
            panic!("expected json");
        };
        assert_eq!(info["width"], 3);
        assert_eq!(info["height"], 2);
        assert_eq!(info["has_alpha"], false);
    }

    #[test]
    fn image_extract_bits_reports_and_extracts() {
        let reg = registry();
        let op = reg.get("image_extract_bits").expect("op registered");
        let mut params = ParamMap::new();
        params.insert("plane_mask", "01010100");
        params.insert("order", 1i64);
        let out = op
            .execute(
                &Value::Bytes(png_input()),
                &params,
                &ExecutionContext::new(),
            )
            .unwrap();
        let Value::Bytes(bytes) = out else {
            panic!("expected bytes");
        };
        // The report is a JSON header line; the payload follows.
        let header_end = bytes.iter().position(|&b| b == b'\n').unwrap();
        let report: serde_json::Value = serde_json::from_slice(&bytes[..header_end]).unwrap();
        assert_eq!(report["truncated"], false);
        // Mask selects RGB bit 0 (3 planes). ARGB pixels 0xFF112233,
        // 0xFF445566, 0xFF778899, 0xFFAABBCC, 0xFFDDEEFF, 0xFF0F1F2F:
        // per pixel bits r,g,b = 1,0,1  0,1,0  1,0,1  ... 18 bits total ->
        // 3 bytes; first byte 0b10101010.
        assert_eq!(report["total_bytes"], 3);
        assert_eq!(bytes[header_end + 1], 0b1010_1010);
        // Payload length: 3 bytes after the report header line.
        assert_eq!(bytes.len() - header_end - 1, 3);
    }

    #[test]
    fn ops_reject_non_image_input_with_typed_errors() {
        let reg = registry();
        for id in ["image_info", "image_transform", "image_extract_bits"] {
            let op = reg.get(id).unwrap();
            let err = op
                .execute(
                    &Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
                    &ParamMap::new(),
                    &ExecutionContext::new(),
                )
                .unwrap_err();
            assert_eq!(err.kind, cybercipher_core::ErrorKind::Decode, "{id}");
        }
        let op = reg.get("image_info").unwrap();
        let err = op
            .execute(
                &Value::Text("not bytes".to_owned()),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidInput);
    }

    /// 32x32 PNG with `flag{auto_lsb_scan_works}` hidden in RGB bit 0,
    /// MSB-first, row-major.
    fn hidden_flag_png() -> Vec<u8> {
        let message = b"flag{auto_lsb_scan_works}";
        let mut bits = Vec::with_capacity(message.len() * 8);
        for &byte in message {
            for shift in (0..8).rev() {
                bits.push((byte >> shift) & 1);
            }
        }
        let mut argb = Vec::with_capacity(32 * 32);
        for pixel_index in 0..32 * 32 {
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
        let image = RgbaImage::new(32, 32, argb, false).unwrap();
        encode_png(&image).unwrap()
    }

    #[test]
    fn auto_lsb_scan_roundtrips_with_hidden_flag() {
        let reg = registry();
        let op = reg.get("auto_lsb_scan").expect("op registered");
        let out = op
            .execute(
                &Value::Bytes(hidden_flag_png()),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap();
        let Value::Json(candidates) = out else {
            panic!("expected json");
        };
        let candidates = candidates.as_array().expect("array of candidates");
        assert!(!candidates.is_empty());
        assert!(candidates.len() <= 50, "default max_candidates");

        let top = &candidates[0];
        assert_eq!(top["score"], 98);
        assert_eq!(top["reason"], "CTF flag: flag{auto_lsb_scan_works}");
        // The flag + zero padding is BINARY-classified (the flag check runs
        // before the classification switch, as upstream).
        assert_eq!(top["payload_type"], "BIN");
        assert_eq!(top["payload_type_id"], "binary");
        assert_eq!(top["settings"]["description"], "r0 g0 b0");
        assert_eq!(
            top["settings"]["config"],
            "RGB \u{b7} b0 \u{b7} Row \u{b7} LSB"
        );
        assert_eq!(top["settings"]["plane_mask"], "01010100");
        assert_eq!(top["settings"]["order"], "RGB");
        assert_eq!(top["settings"]["order_code"], 1);
        assert_eq!(top["total_bytes"], 384);
        assert_eq!(top["truncated"], false);
        // Preview hex starts with "flag{" and is capped at 256 bytes.
        let hex = top["preview_hex"].as_str().unwrap();
        assert!(hex.starts_with("666c61677b"), "hex of \"flag{{\": {hex}");
        assert_eq!(top["preview_bytes"], 384);
        assert_eq!(hex.len(), 256 * 2);
        // Scores are ranked descending.
        let scores: Vec<u64> = candidates
            .iter()
            .map(|c| c["score"].as_u64().unwrap())
            .collect();
        assert!(scores.windows(2).all(|w| w[0] >= w[1]));
    }

    #[test]
    fn auto_lsb_scan_validates_params() {
        let reg = registry();
        let op = reg.get("auto_lsb_scan").unwrap();

        // Bad roi: typed invalid-parameter error.
        let mut params = ParamMap::new();
        params.insert("roi", "1,2,3");
        let err = op
            .execute(
                &Value::Bytes(hidden_flag_png()),
                &params,
                &ExecutionContext::new(),
            )
            .unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidParam);

        // Non-image input: typed invalid-input error.
        let err = op
            .execute(
                &Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Decode);
    }

    #[test]
    fn auto_lsb_scan_honours_candidate_and_prefix_caps() {
        let reg = registry();
        let op = reg.get("auto_lsb_scan").unwrap();
        let input = Value::Bytes(hidden_flag_png());

        let mut params = ParamMap::new();
        params.insert("max_candidates", 3i64);
        let out = op
            .execute(&input, &params, &ExecutionContext::new())
            .unwrap();
        let Value::Json(candidates) = out else {
            panic!("expected json");
        };
        assert_eq!(candidates.as_array().unwrap().len(), 3);

        // Oversized prefix_bytes clamps to the 1 MiB cap; deep scan runs.
        let mut params = ParamMap::new();
        params.insert("prefix_bytes", 5_000_000i64);
        params.insert("deep", true);
        let out = op
            .execute(&input, &params, &ExecutionContext::new())
            .unwrap();
        let Value::Json(candidates) = out else {
            panic!("expected json");
        };
        assert!(!candidates.as_array().unwrap().is_empty());

        // Cancellation through the execution context.
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let ctx = ExecutionContext::new().with_cancel(flag);
        let err = op.execute(&input, &ParamMap::new(), &ctx).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Cancelled);
    }

    // ------------------------------------------------------- stereo ops ----

    /// PNG of a 32x4 image whose colour depends only on `x % 8` (period 8).
    fn periodic8_png() -> Vec<u8> {
        let mut argb = Vec::new();
        for _y in 0..4u32 {
            for x in 0..32u32 {
                let v = 0x10 + (x % 8) * 0x1E;
                argb.push(0xFF00_0000 | (v << 16) | (v << 8) | v);
            }
        }
        encode_png(&RgbaImage::new(32, 4, argb, false).unwrap()).unwrap()
    }

    #[test]
    fn image_stereo_shift_roundtrips_through_registry() {
        let reg = registry();
        let op = reg.get("image_stereo_shift").expect("op registered");
        let input = Value::Bytes(periodic8_png());

        let mut params = ParamMap::new();
        params.insert("offset", 8i64);
        let out = op
            .execute(&input, &params, &ExecutionContext::new())
            .unwrap();
        let Value::Bytes(png) = out else {
            panic!("expected bytes");
        };
        let decoded = decode(&png, &DecodeLimits::default()).unwrap();
        assert_eq!((decoded.width, decoded.height), (32, 4));
        assert!(decoded.argb.iter().all(|&p| p == 0xFF00_0000));

        // Edge hold on a non-matching offset still returns a full PNG.
        let mut params = ParamMap::new();
        params.insert("offset", 3i64);
        params.insert("edge_hold", true);
        let out = op
            .execute(&input, &params, &ExecutionContext::new())
            .unwrap();
        let Value::Bytes(png) = out else {
            panic!("expected bytes");
        };
        let decoded = decode(&png, &DecodeLimits::default()).unwrap();
        assert_eq!(decoded.argb.len(), 128);
    }

    #[test]
    fn image_stereo_auto_reports_the_period() {
        let reg = registry();
        let op = reg.get("image_stereo_auto").expect("op registered");
        let out = op
            .execute(
                &Value::Bytes(periodic8_png()),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap();
        let Value::Json(report) = out else {
            panic!("expected json");
        };
        assert_eq!(report["best_offset"], 8);
        assert_eq!(report["sample_step"], 2);
        assert_eq!(report["width"], 32);
        assert_eq!(report["height"], 4);

        // Cancellation through the execution context.
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let ctx = ExecutionContext::new().with_cancel(flag);
        let err = op
            .execute(&Value::Bytes(periodic8_png()), &ParamMap::new(), &ctx)
            .unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Cancelled);
    }

    // ------------------------------------------------------ combine ops ----

    fn combine_png(pixels: &[u32]) -> Vec<u8> {
        encode_png(&RgbaImage::new(1, 1, pixels.to_vec(), true).unwrap()).unwrap()
    }

    #[test]
    fn image_combine_roundtrips_through_registry() {
        let reg = registry();
        let op = reg.get("image_combine").expect("op registered");
        let input = Value::List(vec![
            Value::Bytes(combine_png(&[0x0000_FF01])),
            Value::Bytes(combine_png(&[0x0000_00FF])),
        ]);

        // Whole-pixel ADD carries into red: 0x0000FF01 + 0x000000FF.
        let mut params = ParamMap::new();
        params.insert("mode", 3i64);
        let out = op
            .execute(&input, &params, &ExecutionContext::new())
            .unwrap();
        let Value::Bytes(png) = out else {
            panic!("expected bytes");
        };
        assert_eq!(
            decode(&png, &DecodeLimits::default()).unwrap().argb,
            vec![0xFF01_0000]
        );

        // Per-channel ADD wraps within the blue lane instead.
        let mut params = ParamMap::new();
        params.insert("mode", 4i64);
        let out = op
            .execute(&input, &params, &ExecutionContext::new())
            .unwrap();
        let Value::Bytes(png) = out else {
            panic!("expected bytes");
        };
        assert_eq!(
            decode(&png, &DecodeLimits::default()).unwrap().argb,
            vec![0xFF00_FF00]
        );
    }

    #[test]
    fn image_combine_validates_input_shape_and_mode() {
        let reg = registry();
        let op = reg.get("image_combine").unwrap();

        // Not a list.
        let err = op
            .execute(
                &Value::Bytes(combine_png(&[0xFF00_0000])),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidInput);

        // A list of one.
        let err = op
            .execute(
                &Value::List(vec![Value::Bytes(combine_png(&[0xFF00_0000]))]),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidInput);

        // A list whose second item is not an image.
        let err = op
            .execute(
                &Value::List(vec![
                    Value::Bytes(combine_png(&[0xFF00_0000])),
                    Value::Bytes(vec![0xDE, 0xAD]),
                ]),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Decode);

        // Out-of-range mode.
        let mut params = ParamMap::new();
        params.insert("mode", 13i64);
        let err = op
            .execute(
                &Value::List(vec![
                    Value::Bytes(combine_png(&[0xFF00_0000])),
                    Value::Bytes(combine_png(&[0xFF00_0000])),
                ]),
                &params,
                &ExecutionContext::new(),
            )
            .unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidParam);
    }

    // --------------------------------------------------------- gif ops ----

    /// 4x2 GIF with three frames: full red (keep), blue 2x1 at (1,0)
    /// (restore-to-background), transparent+green 2x1 at (0,0).
    fn three_frame_gif_bytes() -> Vec<u8> {
        use std::borrow::Cow;
        const RED: u8 = 0;
        const BLUE: u8 = 1;
        const GREEN: u8 = 2;
        let palette: [u8; 9] = [0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0xC0, 0x00];
        let mut out = Vec::new();
        {
            let mut encoder = gif::Encoder::new(&mut out, 4, 2, &palette).unwrap();
            let base = |width: u16, height: u16, left: u16, top: u16, pixels: Vec<u8>| gif::Frame {
                width,
                height,
                left,
                top,
                buffer: Cow::Owned(pixels),
                ..gif::Frame::default()
            };
            encoder
                .write_frame(&gif::Frame {
                    delay: 5,
                    dispose: gif::DisposalMethod::Keep,
                    ..base(4, 2, 0, 0, vec![RED; 8])
                })
                .unwrap();
            encoder
                .write_frame(&gif::Frame {
                    delay: 10,
                    dispose: gif::DisposalMethod::Background,
                    ..base(2, 1, 1, 0, vec![BLUE; 2])
                })
                .unwrap();
            encoder
                .write_frame(&gif::Frame {
                    transparent: Some(RED),
                    ..base(2, 1, 0, 0, vec![RED, GREEN])
                })
                .unwrap();
        }
        out
    }

    #[test]
    fn image_gif_info_roundtrips_through_registry() {
        let reg = registry();
        let op = reg.get("image_gif_info").expect("op registered");
        let out = op
            .execute(
                &Value::Bytes(three_frame_gif_bytes()),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap();
        let Value::Json(info) = out else {
            panic!("expected json");
        };
        assert_eq!(info["screen"]["width"], 4);
        assert_eq!(info["screen"]["height"], 2);
        assert_eq!(info["frame_count"], 3);
        assert_eq!(info["frames_truncated"], false);
        assert_eq!(info["frames"][0]["delay_cs"], 5);
        assert_eq!(info["frames"][0]["disposal"], "keep");
        assert_eq!(info["frames"][1]["left"], 1);
        assert_eq!(info["frames"][1]["disposal"], "background");
        assert_eq!(info["frames"][2]["transparent_index"], 0);

        // Non-GIF input: typed decode error.
        let err = op
            .execute(
                &Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Decode);

        // Wrong input kind.
        let err = op
            .execute(
                &Value::Text("nope".to_owned()),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidInput);
    }

    #[test]
    fn image_gif_frame_roundtrips_through_registry() {
        let reg = registry();
        let op = reg.get("image_gif_frame").expect("op registered");
        let input = Value::Bytes(three_frame_gif_bytes());

        // Frame 1: blue subregion composited over the kept red canvas.
        let mut params = ParamMap::new();
        params.insert("frame", 1i64);
        let out = op
            .execute(&input, &params, &ExecutionContext::new())
            .unwrap();
        let Value::Bytes(png) = out else {
            panic!("expected bytes");
        };
        let decoded = decode(&png, &DecodeLimits::default()).unwrap();
        assert_eq!((decoded.width, decoded.height), (4, 2));
        assert_eq!(
            decoded.argb,
            vec![
                0xFFFF_0000,
                0xFF00_00FF,
                0xFF00_00FF,
                0xFFFF_0000,
                0xFFFF_0000,
                0xFFFF_0000,
                0xFFFF_0000,
                0xFFFF_0000,
            ]
        );

        // Out-of-range frame: typed invalid-parameter error.
        let mut params = ParamMap::new();
        params.insert("frame", 7i64);
        let err = op
            .execute(&input, &params, &ExecutionContext::new())
            .unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidParam);
    }
}
