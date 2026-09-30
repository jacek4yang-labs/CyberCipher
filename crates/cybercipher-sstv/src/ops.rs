//! Registry operations for the SSTV engine.
//!
//! SSTV decode registers as [`CostClass::Heavy`]: audio ingestion, the
//! analysis FFT pass, and — up to `max_candidates` times — the
//! full-resolution raster decode all run per invocation, so the op must
//! never auto-bake. It takes audio **bytes** (any container symphonia
//! recognises) and returns a single `Bytes` value laid out exactly like
//! `image_extract_bits`'s output in `cybercipher-steg/src/ops.rs`: a compact
//! JSON report as the first line, a newline, then the payload — here the PNG
//! bytes of the best detection. Registry values cannot carry multiple
//! payloads, so further detections travel as metadata (`images`,
//! `primary_image`) inside the JSON header; the Tauri command layer returns
//! every image explicitly.
//!
//! Resource bounds (applied identically by the registry op, the Tauri
//! commands and the CLI through [`decode_bounded`]):
//!
//! * empty input is rejected up front, and the channel / forced-mode
//!   parameters are validated before any audio work;
//! * the audio is ingested once ([`audio::load_bytes`]) and its duration is
//!   checked against `max_duration_seconds` **before** any decode work;
//! * `max_candidates` caps how many hypotheses reach the expensive
//!   full-resolution raster stage;
//! * [`ExecutionContext::check`] is applied before ingestion and after the
//!   duration check.
//!
//! The migrated core's internal stages expose no cancellation hooks —
//! `pipeline::decode_bytes` is one opaque call — but each stage is bounded
//! by design: analysis always runs at a fixed 22.05 kHz regardless of the
//! input rate, the raster backend caps its own tail padding
//! (`backend::MAX_TAIL_PADDING_SECONDS` is internal, 300 s), and the
//! full-resolution decode runs at most `max_candidates` times.

#![allow(clippy::result_large_err)]

use cybercipher_core::prelude::*;
use cybercipher_core::{ExecutionContext, OperationRegistry};

use crate::audio::{self, ChannelChoice};
use crate::backend;
use crate::modes;
use crate::pipeline;
use crate::report::Report;

/// Default cap on the decoded audio length, seconds.
///
/// Complete SSTV images take at least ~8 s (Robot 24) and commonly 36 s or
/// more, so 90 s accepts every supported mode with headroom for preamble.
pub const DEFAULT_MAX_DURATION_SECONDS: i64 = 90;

/// Hard cap for `max_duration_seconds`, seconds. Values above this are
/// clamped down; audio longer than the (clamped) cap is rejected before any
/// decode work.
pub const MAX_DURATION_SECONDS_CAP: i64 = 300;

/// Default number of ranked candidates decoded at full resolution.
pub const DEFAULT_MAX_CANDIDATES: i64 = 5;

/// Hard cap for `max_candidates`.
pub const MAX_CANDIDATES_CAP: i64 = 20;

/// Clamp a requested duration cap into the accepted range.
#[must_use]
pub fn clamp_duration(seconds: i64) -> i64 {
    seconds.clamp(1, MAX_DURATION_SECONDS_CAP)
}

/// Clamp a requested candidate cap into the accepted range.
#[must_use]
pub fn clamp_candidates(count: i64) -> i64 {
    count.clamp(1, MAX_CANDIDATES_CAP)
}

/// A decode request with CyberCipher resource bounds, shared by the registry
/// op, the Tauri command layer and the CLI so all three enforce the same
/// limits.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodeRequest {
    /// Channel selection: `auto`, `mono` (average of all channels), `left`,
    /// `right`, or a zero-based channel index. See
    /// [`ChannelChoice::parse`].
    pub channel: String,
    /// Restrict the decode to this mode (slug or display name, e.g.
    /// `robot36`); `None` or blank means automatic detection.
    pub forced_mode: Option<String>,
    /// Allow blind sync-period inference when the VIS header is absent.
    pub blind: bool,
    /// Reject audio longer than this (clamped into `1..=300` seconds)
    /// before any decode work.
    pub max_duration_seconds: i64,
    /// How many ranked candidates to decode at full resolution (clamped
    /// into `1..=20`).
    pub max_candidates: i64,
}

impl Default for DecodeRequest {
    fn default() -> Self {
        Self {
            channel: "auto".to_owned(),
            forced_mode: None,
            blind: true,
            max_duration_seconds: DEFAULT_MAX_DURATION_SECONDS,
            max_candidates: DEFAULT_MAX_CANDIDATES,
        }
    }
}

/// One decoded image, aligned with `report["detections"]` by
/// [`DecodedSstvImage::detection_index`].
#[derive(Debug, Clone)]
pub struct DecodedSstvImage {
    /// Index into the report's `detections` array.
    pub detection_index: usize,
    /// Stable lowercase mode slug (e.g. `robot36`).
    pub mode_slug: String,
    /// Human-readable mode name (e.g. `Robot 36`).
    pub mode_name: String,
    /// Image width in pixels.
    pub width: u32,
    /// Image height in pixels.
    pub height: u32,
    /// PNG-encoded image bytes.
    pub png: Vec<u8>,
}

/// What a bounded decode produced: the full report as JSON plus every
/// decoded image as PNG bytes. Nothing is written to disk.
#[derive(Debug, Clone)]
pub struct DecodedSstv {
    /// The complete run report (`report::Report` serialized) with an
    /// added `images` metadata array describing [`DecodedSstv::images`].
    pub report: serde_json::Value,
    /// Decoded images, best first, aligned with the report's detections.
    pub images: Vec<DecodedSstvImage>,
}

/// Decode audio bytes with the CyberCipher resource bounds applied.
///
/// This is the single entry point the registry op, the Tauri commands and
/// the CLI all use; see the module docs for what is bounded where.
///
/// # Errors
///
/// Returns a typed [`OperationError`]: `InvalidInput` for empty bytes,
/// `InvalidParam` for a bad channel or unknown mode, `BudgetExceeded` when
/// the audio outlasts `max_duration_seconds`, and `Decode` for audio that
/// cannot be ingested or a pipeline failure. A recording that simply
/// contains no SSTV is *not* an error: the report carries the warnings.
pub fn decode_bounded(
    bytes: &[u8],
    request: &DecodeRequest,
    ctx: &ExecutionContext,
) -> Result<DecodedSstv, OperationError> {
    ctx.check()?;
    if bytes.is_empty() {
        return Err(OperationError::invalid_input(
            "SSTV Decode expects audio bytes, received none",
        ));
    }
    let channel = parse_channel(&request.channel)?;
    let forced_mode = validate_forced_mode(request.forced_mode.as_deref())?;

    // Ingest once for the duration check. The pipeline ingests again
    // internally; keeping the migrated core untouched is worth one extra
    // linear pass, and this is the only way to bound the run *before* the
    // analysis and decode stages.
    let audio = audio::load_bytes(bytes, channel)
        .map_err(|e| OperationError::decode(format!("SSTV Decode: {e:#}")))?;
    let max_seconds = clamp_duration(request.max_duration_seconds);
    let duration = audio.duration_seconds();
    if duration > max_seconds as f64 {
        return Err(OperationError::new(
            ErrorKind::BudgetExceeded,
            format!("audio is {duration:.1}s long, exceeding the {max_seconds}s cap"),
        )
        .with_expected(format!("audio no longer than {max_seconds}s"))
        .with_actual(format!("{duration:.1}s")));
    }
    ctx.check()?;

    let options = pipeline::Options {
        channel,
        blind: request.blind,
        max_candidates: clamp_candidates(request.max_candidates) as usize,
        keep_candidates: false,
        forced_mode: forced_mode.map(str::to_owned),
        verbose: false,
    };
    let outcome = pipeline::decode_bytes(bytes, &options)
        .map_err(|e| OperationError::decode(format!("SSTV Decode: {e:#}")))?;

    let mut images = Vec::with_capacity(outcome.images.len());
    for (index, (detection, image)) in outcome.detections.iter().zip(&outcome.images).enumerate() {
        let png = backend::encode_png(&image.pixels, image.width, image.height)
            .map_err(|e| OperationError::decode(format!("SSTV Decode: {e:#}")))?;
        images.push(DecodedSstvImage {
            detection_index: index,
            mode_slug: detection.mode_slug.clone(),
            mode_name: detection.mode.clone(),
            width: image.width,
            height: image.height,
            png,
        });
    }

    let mut report = report_value(&outcome.report)?;
    report["images"] = serde_json::Value::Array(
        images
            .iter()
            .map(|image| {
                serde_json::json!({
                    "detection_index": image.detection_index,
                    "format": "png",
                    "width": image.width,
                    "height": image.height,
                    "bytes": image.png.len(),
                })
            })
            .collect(),
    );
    Ok(DecodedSstv { report, images })
}

/// Parse the `channel` parameter into a [`ChannelChoice`].
fn parse_channel(text: &str) -> Result<ChannelChoice, OperationError> {
    ChannelChoice::parse(text).map_err(|e| {
        OperationError::invalid_param("channel", format!("invalid channel '{text}': {e}"))
            .with_expected(
                "auto, mono (average of all channels), left, right, or a zero-based channel index",
            )
            .with_actual(text.to_owned())
    })
}

/// Validate the optional `forced_mode` parameter before any audio work.
///
/// Returns the trimmed mode name, or `None` when the caller left it blank
/// (automatic detection).
fn validate_forced_mode(mode: Option<&str>) -> Result<Option<&str>, OperationError> {
    let Some(name) = mode.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if modes::from_name(name).is_none() {
        return Err(
            OperationError::invalid_param("forced_mode", format!("unknown mode `{name}`"))
                .with_expected(format!("one of: {}", modes::slug_list()))
                .with_actual(name.to_owned()),
        );
    }
    Ok(Some(name))
}

/// Serialize the report the same way `Report::to_json` does for the on-disk
/// `report.json`, then re-parse it into a JSON value.
fn report_value(report: &Report) -> Result<serde_json::Value, OperationError> {
    let json = report
        .to_json()
        .map_err(|e| OperationError::internal(format!("serialize SSTV report: {e}")))?;
    serde_json::from_slice(&json)
        .map_err(|e| OperationError::internal(format!("re-parse SSTV report: {e}")))
}

fn sstv_decode_op(v: &Value, params: &ParamMap, ctx: &ExecutionContext) -> OpResult<Value> {
    const OP: &str = "SSTV Decode";
    let bytes = match v {
        Value::Bytes(b) => b,
        other => {
            let found = format!("{:?}", other.kind());
            return Err(OperationError::invalid_input(format!(
                "{OP} expects audio bytes (WAV, FLAC, MP3, Ogg, ...), got {found}"
            ))
            .with_expected("Bytes"));
        }
    };
    let request = DecodeRequest {
        channel: params.str_or("channel", "auto").to_owned(),
        forced_mode: params
            .get_str("forced_mode")
            .map(str::to_owned)
            .filter(|m| !m.trim().is_empty()),
        blind: params.bool_or("blind", true),
        max_duration_seconds: params.int_or("max_duration_seconds", DEFAULT_MAX_DURATION_SECONDS),
        max_candidates: params.int_or("max_candidates", DEFAULT_MAX_CANDIDATES),
    };
    let decoded = decode_bounded(bytes, &request, ctx)?;

    let mut header = decoded.report.clone();
    header["primary_image"] = match decoded.images.first() {
        Some(image) => serde_json::json!({
            "detection_index": image.detection_index,
            "format": "png",
            "width": image.width,
            "height": image.height,
            "bytes": image.png.len(),
        }),
        None => serde_json::Value::Null,
    };
    // The image_extract_bits transport: the JSON report is the header line
    // and the payload bytes follow, so recipes can chain the PNG directly
    // into the next op while keeping the report inspectable. serde_json
    // escapes newlines inside strings, so the header is always one line.
    let mut out = serde_json::to_vec(&header)
        .map_err(|e| OperationError::internal(format!("serialize SSTV report header: {e}")))?;
    out.push(b'\n');
    if let Some(image) = decoded.images.first() {
        out.extend_from_slice(&image.png);
    }
    Ok(Value::Bytes(out))
}

// ---------------------------------------------------------------------------
// Local spec/param helpers (same shape as the steg crate's; the sstv crate
// does not depend on the codec crate, so the small builders are duplicated
// here too).
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn spec(
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
            implementation:
                "CyberCipher native Rust (migrated sstv-auto modules; slowrx 0.5.3 raster backend)",
            test_vectors: vectors,
        },
    }))
}

fn p_text(
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

fn p_bool(key: &'static str, label: &'static str, default: bool, hint: &'static str) -> ParamSpec {
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

fn p_int(key: &'static str, label: &'static str, default: i64, hint: &'static str) -> ParamSpec {
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
    use cybercipher_core::ValueKind::Bytes as B;

    reg.add_simple(
        spec(
            "sstv_decode",
            "SSTV Decode",
            "Decodes an SSTV transmission from audio bytes: automatic VIS/sync mode detection, frequency-offset and clock recovery, inverse-model candidate ranking, and a full-resolution decode of the best candidates. Output is a JSON report header line (detections, timing evidence, warnings, image metadata) followed by the PNG bytes of the best detection; further detections are described in the report.",
            A,
            &[B],
            B,
            CostClass::Heavy,
            false,
            vec![
                p_text(
                    "channel",
                    "Channel",
                    "auto",
                    "auto (score every channel and pick the strongest), mono (average of all channels), left, right, or a zero-based channel index.",
                ),
                p_text(
                    "forced_mode",
                    "Forced mode",
                    "",
                    "Restrict the decode to one mode by slug or name (e.g. robot36, Robot 36, martin1) instead of detecting; blank = automatic. Unknown names are rejected.",
                ),
                p_bool(
                    "blind",
                    "Blind inference",
                    true,
                    "Fall back to sync-period inference when the VIS header is absent or damaged.",
                ),
                p_int(
                    "max_duration_seconds",
                    "Max duration (s)",
                    DEFAULT_MAX_DURATION_SECONDS,
                    "Reject audio longer than this before any decode work. Clamped to at most 300 s.",
                ),
                p_int(
                    "max_candidates",
                    "Max candidates",
                    DEFAULT_MAX_CANDIDATES,
                    "How many ranked hypotheses are decoded at full resolution. Clamped to at most 20.",
                ),
            ],
            &["sstv", "audio", "ctf", "image", "radio"],
            &["sstv", "sstv-decode"],
            "sstv-auto f626d50 (MIT) migrated in-tree; slowrx decode backend",
            "Synthetic SSTV transmissions rendered in-test (hound WAV fixtures)",
        ),
        sstv_decode_op,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> OperationRegistry {
        let mut reg = OperationRegistry::new();
        register(&mut reg);
        reg
    }

    /// Render a synthetic transmission to a WAV blob.
    ///
    /// hound's `finalize` consumes its writer and never hands the buffer
    /// back, so — like the crate's e2e tests — the fixture takes a short
    /// trip through a uniquely-named temp file and is read back as bytes.
    fn synthetic_wav(slug: &str, rate: u32) -> Vec<u8> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);

        let mode = modes::from_name(slug).expect("mode exists");
        let grid = crate::synth::test_grid(&mode);
        let signal = crate::synth::render_with_vis(&grid, &mode, rate, 0.0, None);
        let path =
            std::env::temp_dir().join(format!("cybercipher_sstv_ops_{slug}_{rate}_{unique}.wav"));
        let spec = hound::WavSpec {
            channels: 1,
            sample_rate: rate,
            bits_per_sample: 16,
            sample_format: hound::SampleFormat::Int,
        };
        let mut writer = hound::WavWriter::create(&path, spec).expect("create wav writer");
        for sample in &signal {
            let scaled = (f64::from(*sample).clamp(-1.0, 1.0) * 32_000.0).round() as i16;
            writer.write_sample(scaled).expect("write sample");
        }
        writer.finalize().expect("finalize wav");
        let bytes = std::fs::read(&path).expect("read wav back");
        let _ = std::fs::remove_file(&path);
        bytes
    }

    /// Split the image_extract_bits-style output into header and payload.
    fn split_output(bytes: &[u8]) -> (serde_json::Value, &[u8]) {
        let header_end = bytes
            .iter()
            .position(|&b| b == b'\n')
            .expect("a header line must be present");
        let header: serde_json::Value =
            serde_json::from_slice(&bytes[..header_end]).expect("header parses as JSON");
        (header, &bytes[header_end + 1..])
    }

    #[test]
    fn sstv_decode_roundtrips_through_registry() {
        let reg = registry();
        let op = reg.get("sstv_decode").expect("op registered");
        // max_candidates = 1: the Robot 24/36 ambiguity otherwise decodes
        // both, and one full-resolution decode keeps this test fast.
        let mut params = ParamMap::new();
        params.insert("max_candidates", 1i64);
        let out = op
            .execute(
                &Value::Bytes(synthetic_wav("robot24", 22_050)),
                &params,
                &ExecutionContext::new(),
            )
            .expect("decode succeeds");
        let Value::Bytes(bytes) = out else {
            panic!("expected bytes output");
        };
        let (header, payload) = split_output(&bytes);
        let detections = header["detections"].as_array().expect("detections array");
        assert!(
            detections
                .iter()
                .any(|d| d["mode_slug"] == "robot24" && d["detected_by"] == "vis"),
            "expected a robot24 VIS detection, got {detections:?}"
        );
        assert_eq!(header["primary_image"]["format"], "png");
        assert_eq!(header["primary_image"]["detection_index"], 0);
        // The payload is the primary image's PNG, starting with the PNG magic.
        assert_eq!(&payload[..4], &[0x89, b'P', b'N', b'G']);
        assert_eq!(
            payload.len(),
            header["primary_image"]["bytes"].as_u64().expect("bytes") as usize
        );
        // Every image is described in the report metadata.
        assert_eq!(header["images"].as_array().expect("images").len(), 1);
        assert_eq!(header["images"][0]["detection_index"], 0);
        assert_eq!(header["images"][0]["format"], "png");
    }

    #[test]
    fn oversized_duration_is_rejected_before_decoding() {
        let request = DecodeRequest {
            max_duration_seconds: 1,
            ..DecodeRequest::default()
        };
        let error = decode_bounded(
            &synthetic_wav("robot24", 22_050),
            &request,
            &ExecutionContext::new(),
        )
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::BudgetExceeded);
        assert!(error.message.contains("cap"), "message {}", error.message);
        assert!(
            error.actual.as_deref().is_some_and(|a| a.ends_with('s')),
            "the measured duration should be reported: {:?}",
            error.actual
        );
    }

    #[test]
    fn unknown_forced_mode_is_rejected_up_front() {
        let request = DecodeRequest {
            forced_mode: Some("martian9".to_owned()),
            ..DecodeRequest::default()
        };
        // Non-audio bytes on purpose: the mode check must fire before any
        // audio ingestion.
        let error =
            decode_bounded(b"not-even-audio", &request, &ExecutionContext::new()).unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidParam);
        assert_eq!(error.parameter.as_deref(), Some("forced_mode"));
        assert!(
            error
                .expected
                .as_deref()
                .unwrap_or_default()
                .contains("robot36"),
            "expected hint should list modes: {:?}",
            error.expected
        );
    }

    #[test]
    fn bad_channel_is_rejected_up_front() {
        let request = DecodeRequest {
            channel: "backwards".to_owned(),
            ..DecodeRequest::default()
        };
        let error =
            decode_bounded(b"not-even-audio", &request, &ExecutionContext::new()).unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidParam);
        assert_eq!(error.parameter.as_deref(), Some("channel"));
    }

    #[test]
    fn empty_and_non_audio_input_is_rejected() {
        let error =
            decode_bounded(&[], &DecodeRequest::default(), &ExecutionContext::new()).unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidInput);

        let error = decode_bounded(b"junk", &DecodeRequest::default(), &ExecutionContext::new())
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Decode);
    }

    #[test]
    fn op_rejects_non_bytes_input() {
        let reg = registry();
        let op = reg.get("sstv_decode").expect("op registered");
        let error = op
            .execute(
                &Value::Text("wave".to_owned()),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidInput);
    }

    #[test]
    fn cancelled_context_stops_the_op() {
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let ctx = ExecutionContext::new().with_cancel(flag);
        let error = decode_bounded(b"anything", &DecodeRequest::default(), &ctx).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Cancelled);
    }

    #[test]
    fn bound_helpers_clamp() {
        assert_eq!(clamp_duration(0), 1);
        assert_eq!(clamp_duration(90), 90);
        assert_eq!(clamp_duration(10_000), MAX_DURATION_SECONDS_CAP);
        assert_eq!(clamp_candidates(0), 1);
        assert_eq!(clamp_candidates(5), 5);
        assert_eq!(clamp_candidates(100), MAX_CANDIDATES_CAP);
    }
}
