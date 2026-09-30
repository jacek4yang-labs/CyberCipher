//! Tauri IPC commands for SSTV decoding (the SSTV Lab page arrives in a
//! later lane; these commands and the registry op are its backend).
//!
//! The command layer is a thin adapter over `cybercipher-sstv::ops`: all
//! bounds (empty input, duration cap, candidate cap), validation and error
//! typing live in the engine crate via `ops::decode_bounded`, so the
//! registry op, the CLI and these commands behave identically. Errors cross
//! the IPC boundary as the engine's full structured `OperationError` (kind
//! as the snake_case label), mirroring `pki_commands.rs`.
//!
//! The decode runs on the blocking thread pool
//! (`tauri::async_runtime::spawn_blocking`) so the DSP-heavy pipeline never
//! freezes the UI.
//!
//! Transport notes:
//!
//! * audio never touches disk — `SstvDecodeResult::report_path` is always
//!   `None` until a later lane adds explicit save actions;
//! * images cross the IPC boundary base64-encoded (data-URL ready). This
//!   deliberately differs from the pki commands' hex transport: PNG frames
//!   are orders of magnitude larger than key material, and the frontend can
//!   render them straight from `data:image/png;base64,...`.

use base64::Engine as _;
use cybercipher_core::OperationError;
use cybercipher_sstv as sstv;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error transport
// ---------------------------------------------------------------------------

/// Structured error crossing the IPC boundary. Mirrors the engine's
/// `OperationError` field-for-field (kind as the snake_case label) so the
/// frontend can render kind/parameter/expected/actual/details directly.
#[derive(Debug, Serialize)]
pub struct SstvCmdError {
    pub kind: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl From<OperationError> for SstvCmdError {
    fn from(e: OperationError) -> Self {
        SstvCmdError {
            kind: serde_json::to_value(e.kind)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "internal".to_string()),
            message: e.message,
            parameter: e.parameter,
            expected: e.expected,
            actual: e.actual,
            details: e.details,
        }
    }
}

// ---------------------------------------------------------------------------
// sstv_decode_audio
// ---------------------------------------------------------------------------

/// Decode options, mirroring the `sstv_decode` op's parameters. Every field
/// defaults like the op, so the frontend can pass an empty object.
#[derive(Debug, Deserialize)]
pub struct SstvDecodeOptions {
    /// `auto` | `mono` | `left` | `right` | zero-based channel index.
    #[serde(default = "default_channel")]
    pub channel: String,
    /// Restrict the decode to one mode (slug or display name); `None` or
    /// blank means automatic detection.
    #[serde(default)]
    pub forced_mode: Option<String>,
    /// Allow blind sync-period inference when the VIS header is absent.
    #[serde(default = "default_true")]
    pub blind: bool,
    /// Reject audio longer than this many seconds (hard cap 300) before any
    /// decode work.
    #[serde(default = "default_max_duration_seconds")]
    pub max_duration_seconds: i64,
    /// How many ranked candidates to decode at full resolution (cap 20).
    #[serde(default = "default_max_candidates")]
    pub max_candidates: i64,
}

fn default_channel() -> String {
    "auto".to_owned()
}

fn default_true() -> bool {
    true
}

fn default_max_duration_seconds() -> i64 {
    sstv::ops::DEFAULT_MAX_DURATION_SECONDS
}

fn default_max_candidates() -> i64 {
    sstv::ops::DEFAULT_MAX_CANDIDATES
}

impl Default for SstvDecodeOptions {
    fn default() -> Self {
        SstvDecodeOptions {
            channel: default_channel(),
            forced_mode: None,
            blind: default_true(),
            max_duration_seconds: default_max_duration_seconds(),
            max_candidates: default_max_candidates(),
        }
    }
}

impl SstvDecodeOptions {
    /// Map onto the engine's shared `DecodeRequest` (bounds are applied and
    /// clamped inside `decode_bounded`).
    fn request(&self) -> sstv::ops::DecodeRequest {
        sstv::ops::DecodeRequest {
            channel: self.channel.clone(),
            forced_mode: self.forced_mode.clone(),
            blind: self.blind,
            max_duration_seconds: self.max_duration_seconds,
            max_candidates: self.max_candidates,
        }
    }
}

/// One decoded image, best detection first in the enclosing result.
#[derive(Debug, Serialize)]
pub struct SstvImage {
    /// Index into `report.detections`.
    pub detection_index: usize,
    /// Stable lowercase mode slug (e.g. `robot36`).
    pub mode_slug: String,
    /// Human-readable mode name (e.g. `Robot 36`).
    pub mode_name: String,
    /// Image width in pixels.
    pub width: u32,
    /// Image height in pixels.
    pub height: u32,
    /// PNG byte count (before base64).
    pub size: usize,
    /// Base64-encoded PNG bytes, ready for a `data:image/png;base64,...` URL.
    pub png_base64: String,
}

#[derive(Debug, Serialize)]
pub struct SstvDecodeResult {
    /// The complete run report (detections, timing evidence, warnings,
    /// per-image metadata) as JSON.
    pub report: serde_json::Value,
    /// Decoded images, best first, aligned with `report.detections`.
    pub images: Vec<SstvImage>,
    /// Always `None`: decoded bytes never touch disk in the command layer.
    pub report_path: Option<String>,
}

/// Synchronous body of [`sstv_decode_audio`], so tests can exercise the
/// wrapper without a Tauri runtime.
pub fn decode_audio_sync(
    bytes: Vec<u8>,
    options: SstvDecodeOptions,
) -> Result<SstvDecodeResult, SstvCmdError> {
    let decoded = sstv::ops::decode_bounded(
        &bytes,
        &options.request(),
        &cybercipher_core::ExecutionContext::new(),
    )
    .map_err(SstvCmdError::from)?;
    Ok(SstvDecodeResult {
        report: decoded.report,
        images: decoded
            .images
            .into_iter()
            .map(|image| SstvImage {
                detection_index: image.detection_index,
                mode_slug: image.mode_slug,
                mode_name: image.mode_name,
                width: image.width,
                height: image.height,
                size: image.png.len(),
                png_base64: base64::engine::general_purpose::STANDARD.encode(&image.png),
            })
            .collect(),
        report_path: None,
    })
}

#[tauri::command]
pub async fn sstv_decode_audio(
    bytes: Vec<u8>,
    options: SstvDecodeOptions,
) -> Result<SstvDecodeResult, SstvCmdError> {
    tauri::async_runtime::spawn_blocking(move || decode_audio_sync(bytes, options))
        .await
        .map_err(|e| {
            SstvCmdError::from(OperationError::internal(format!("sstv task failed: {e}")))
        })?
}

// ---------------------------------------------------------------------------
// sstv_modes
// ---------------------------------------------------------------------------

/// Metadata for one supported SSTV mode, so a later GUI can populate mode
/// selectors without hardcoding the database.
#[derive(Debug, Serialize)]
pub struct SstvModeInfo {
    /// Stable lowercase slug (e.g. `robot36`).
    pub slug: String,
    /// Human-readable display name (e.g. `Robot 36`).
    pub name: String,
    /// 7-bit VIS code identifying the mode.
    pub vis_code: u8,
    /// Structural family: `pd`, `robot_alternating`, `robot_sequential` or
    /// `sequential`.
    pub family: String,
    /// Colour space the family transmits in: `ycbcr` or `rgb`.
    pub palette: String,
    /// Visible pixels per radio line.
    pub width: u32,
    /// Visible image rows.
    pub height: u32,
    /// Total transmitted image duration, seconds (excludes the VIS header).
    pub image_seconds: f64,
}

fn family_label(family: sstv::modes::Family) -> &'static str {
    match family {
        sstv::modes::Family::Pd => "pd",
        sstv::modes::Family::RobotAlternating => "robot_alternating",
        sstv::modes::Family::RobotSequential => "robot_sequential",
        sstv::modes::Family::Sequential => "sequential",
    }
}

/// List every supported SSTV mode with its geometry and family metadata.
#[tauri::command]
pub fn sstv_modes() -> Vec<SstvModeInfo> {
    sstv::modes::all()
        .into_iter()
        .map(|mode| SstvModeInfo {
            slug: mode.short_name.to_owned(),
            name: mode.name.to_owned(),
            vis_code: mode.vis_code,
            family: family_label(mode.family).to_owned(),
            palette: match mode.family.palette() {
                sstv::modes::Palette::YCbCr => "ycbcr",
                sstv::modes::Palette::Rgb => "rgb",
            }
            .to_owned(),
            width: mode.line_pixels,
            height: mode.image_lines,
            image_seconds: mode.image_seconds(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> SstvDecodeOptions {
        SstvDecodeOptions::default()
    }

    #[test]
    fn options_default_like_the_op() {
        let request = options().request();
        assert_eq!(request.channel, "auto");
        assert_eq!(request.forced_mode, None);
        assert!(request.blind);
        assert_eq!(request.max_duration_seconds, 90);
        assert_eq!(request.max_candidates, 5);
        // serde defaults agree with Default::default().
        let parsed: SstvDecodeOptions = serde_json::from_str("{}").expect("empty options object");
        assert_eq!(parsed.request(), request);
    }

    #[test]
    fn empty_bytes_are_rejected() {
        let error = decode_audio_sync(Vec::new(), options()).unwrap_err();
        assert_eq!(error.kind, "invalid_input");
        assert!(error.message.contains("audio bytes"));
    }

    #[test]
    fn unknown_mode_is_rejected_before_audio_work() {
        let mut opts = options();
        opts.forced_mode = Some("martian9".to_owned());
        // Garbage bytes: the mode check must fire before any audio decoding.
        let error = decode_audio_sync(b"not-even-audio".to_vec(), opts).unwrap_err();
        assert_eq!(error.kind, "invalid_param");
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
    fn bad_channel_is_rejected() {
        let mut opts = options();
        opts.channel = "backwards".to_owned();
        let error = decode_audio_sync(b"not-even-audio".to_vec(), opts).unwrap_err();
        assert_eq!(error.kind, "invalid_param");
        assert_eq!(error.parameter.as_deref(), Some("channel"));
        assert!(error
            .expected
            .as_deref()
            .unwrap_or_default()
            .contains("auto"));
    }

    #[test]
    fn duration_bound_is_enforced_by_the_engine() {
        // The duration cap is clamped and enforced inside decode_bounded;
        // the command layer only maps the request, and the engine clamps
        // out-of-range values to the 300 s hard cap.
        let mut opts = options();
        opts.max_duration_seconds = 10_000;
        let request = opts.request();
        assert_eq!(
            request.max_duration_seconds, 10_000,
            "clamping happens in decode_bounded, not in the mapping"
        );
        assert_eq!(sstv::ops::clamp_duration(request.max_duration_seconds), 300);
    }

    #[test]
    fn sstv_modes_lists_the_database() {
        let modes = sstv_modes();
        // Every mode the crate supports is listed with usable geometry.
        assert!(modes.iter().any(|m| m.slug == "robot36"));
        assert!(modes.iter().any(|m| m.slug == "martin1"));
        assert!(modes.iter().any(|m| m.slug == "pd120" && m.family == "pd"));
        assert!(modes
            .iter()
            .all(|m| m.width > 0 && m.height > 0 && m.image_seconds > 0.0));
        assert!(modes
            .iter()
            .all(|m| matches!(m.palette.as_str(), "ycbcr" | "rgb")));
    }
}
