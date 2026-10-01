//! GIF frame access: lazy frame indexing and bounded single-frame decoding.
//!
//! The `image` crate only ever surfaces the first frame of a GIF; frame
//! access goes through the `gif` crate (already in the tree via image's
//! `gif` feature) for explicit frame control.
//!
//! [`index_frames`] walks the stream with `skip_frame_decoding` enabled, so
//! frame metadata (count, region, delay, disposal, transparency) is collected
//! without ever LZW-decoding pixel data. [`decode_frame`] decodes frames
//! `0..=index` (the GIF stream has no random access) and composites them onto
//! the logical screen canvas, honouring the disposal method between frames —
//! the composed canvas is what a viewer displays while frame `index` is
//! shown. Documented composition choices, matching common viewers:
//!
//! * the canvas starts out fully transparent (an undrawn region shows as
//!   transparent, not as the screen background colour),
//! * transparent-index pixels leave the canvas pixel unchanged,
//! * restore-to-background clears the frame region to transparent (the GIF
//!   background colour is not resolved),
//! * restore-to-previous restores the canvas snapshot taken before the frame
//!   was drawn.
//!
//! Resource bounds: the encoded input is capped by [`DecodeLimits`]
//! max_file_bytes, the canvas is capped by max_pixels before allocation,
//! each frame's decode buffer by a 256 MiB `MemoryLimit` (64 megapixels of
//! RGBA, the media engine's pixel cap), and indexing stops at
//! [`MAX_FRAMES_INDEXED`] frames.

use std::io::Cursor;
use std::num::NonZeroU64;

use cybercipher_core::{ExecutionContext, OpResult, OperationError};
use cybercipher_media::{DecodeLimits, RgbaImage};

/// Hard cap on the number of frames indexed per GIF.
pub const MAX_FRAMES_INDEXED: usize = 4096;
/// Per-frame decode buffer cap: 64 megapixels of RGBA, matching the media
/// engine's pixel cap.
const MAX_FRAME_BUFFER_BYTES: u64 = 64 * 1024 * 1024 * 4;

/// Disposal method of a frame: what a viewer must do with the canvas before
/// drawing the next one. Unknown codes arrive as `Any` (the `gif` crate maps
/// them there, and the spec requires no action for them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposal {
    /// No action required (covers unspecified codes 4..7).
    Any,
    /// Leave the canvas as-is.
    Keep,
    /// Clear the frame region (restored to transparent here).
    Background,
    /// Restore the canvas as it was before this frame was drawn.
    Previous,
}

impl Disposal {
    fn from_gif(method: gif::DisposalMethod) -> Self {
        match method {
            gif::DisposalMethod::Any => Disposal::Any,
            gif::DisposalMethod::Keep => Disposal::Keep,
            gif::DisposalMethod::Background => Disposal::Background,
            gif::DisposalMethod::Previous => Disposal::Previous,
        }
    }

    /// Lowercase name used in reports.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Disposal::Any => "any",
            Disposal::Keep => "keep",
            Disposal::Background => "background",
            Disposal::Previous => "previous",
        }
    }
}

/// Metadata of one frame, read from the stream without decoding pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameInfo {
    /// Zero-based position in the stream.
    pub index: usize,
    /// Left edge of the frame region on the logical screen.
    pub left: u16,
    /// Top edge of the frame region on the logical screen.
    pub top: u16,
    /// Width of the frame region.
    pub width: u16,
    /// Height of the frame region.
    pub height: u16,
    /// Frame delay in centiseconds (the GIF stores units of 10 ms).
    pub delay_cs: u16,
    /// Disposal method applied after this frame is shown.
    pub disposal: Disposal,
    /// Palette index that marks transparent pixels, if declared.
    pub transparent_index: Option<u8>,
    /// Whether the frame data is stored interlaced.
    pub interlaced: bool,
}

/// Lazy frame index of a GIF: logical screen size plus per-frame metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GifIndex {
    pub screen_width: u16,
    pub screen_height: u16,
    /// One entry per frame, in stream order.
    pub frames: Vec<FrameInfo>,
    /// True when the GIF has more than [`MAX_FRAMES_INDEXED`] frames and the
    /// index was cut at the cap.
    pub truncated: bool,
}

fn gif_error(e: gif::DecodingError) -> OperationError {
    match e {
        gif::DecodingError::Io(err) => {
            OperationError::decode("GIF I/O failure").with_details(err.to_string())
        }
        other => {
            OperationError::decode("GIF is corrupt or truncated").with_details(other.to_string())
        }
    }
}

fn check_input_size(bytes: &[u8], limits: &DecodeLimits) -> OpResult<()> {
    if bytes.len() as u64 > limits.max_file_bytes {
        return Err(
            OperationError::decode("GIF exceeds the configured cap").with_details(format!(
                "file size limit {} bytes, actual {} bytes",
                limits.max_file_bytes,
                bytes.len()
            )),
        );
    }
    Ok(())
}

/// Indexes the frames of a GIF without decoding any pixel data.
///
/// # Errors
///
/// Returns a typed error when the input exceeds the file-size cap or the
/// stream is malformed.
pub fn index_frames(bytes: &[u8], limits: &DecodeLimits) -> OpResult<GifIndex> {
    check_input_size(bytes, limits)?;
    let mut options = gif::DecodeOptions::new();
    // Metadata only: LZW payloads are never decoded on this path.
    options.skip_frame_decoding(true);
    let mut decoder = options.read_info(Cursor::new(bytes)).map_err(gif_error)?;
    let mut frames = Vec::new();
    let mut truncated = false;
    while let Some(frame) = decoder.next_frame_info().map_err(gif_error)? {
        if frames.len() >= MAX_FRAMES_INDEXED {
            truncated = true;
            break;
        }
        frames.push(FrameInfo {
            index: frames.len(),
            left: frame.left,
            top: frame.top,
            width: frame.width,
            height: frame.height,
            delay_cs: frame.delay,
            disposal: Disposal::from_gif(frame.dispose),
            transparent_index: frame.transparent,
            interlaced: frame.interlaced,
        });
    }
    Ok(GifIndex {
        screen_width: decoder.width(),
        screen_height: decoder.height(),
        frames,
        truncated,
    })
}

/// Decodes and composites frame `index` onto the logical screen canvas.
///
/// The GIF stream has no random access, so frames `0..=index` are decoded and
/// composited in order (each call costs O(index) frame decodes; the GUI lane
/// owns caching). The result preserves transparency where the disposal chain
/// leaves regions undrawn.
///
/// # Errors
///
/// Returns a typed [`OperationError`] when the index is out of range or
/// beyond the frame cap, the input exceeds a cap, or the stream is malformed.
pub fn decode_frame(
    bytes: &[u8],
    index: usize,
    limits: &DecodeLimits,
    ctx: &ExecutionContext,
) -> OpResult<RgbaImage> {
    check_input_size(bytes, limits)?;
    if index >= MAX_FRAMES_INDEXED {
        return Err(OperationError::invalid_param(
            "frame",
            format!("frame index {index} exceeds the {MAX_FRAMES_INDEXED}-frame cap"),
        )
        .with_expected(format!("0..{}", MAX_FRAMES_INDEXED - 1))
        .with_actual(index.to_string()));
    }
    let mut options = gif::DecodeOptions::new();
    options.set_color_output(gif::ColorOutput::RGBA);
    options.set_memory_limit(gif::MemoryLimit::Bytes(
        NonZeroU64::new(MAX_FRAME_BUFFER_BYTES).expect("frame buffer cap is nonzero"),
    ));
    let mut decoder = options.read_info(Cursor::new(bytes)).map_err(gif_error)?;
    let screen_width = decoder.width();
    let screen_height = decoder.height();
    let canvas_pixels = u64::from(screen_width) * u64::from(screen_height);
    if canvas_pixels > limits.max_pixels {
        return Err(
            OperationError::decode("GIF canvas exceeds the configured cap").with_details(format!(
                "pixel count limit {}, actual {canvas_pixels}",
                limits.max_pixels
            )),
        );
    }
    let sw = screen_width as usize;
    let sh = screen_height as usize;
    let mut canvas = vec![0u32; sw * sh];
    let mut saved: Option<Vec<u32>> = None;
    let mut frame_index = 0usize;
    while let Some(frame) = decoder.read_next_frame().map_err(gif_error)? {
        ctx.check()?;
        if frame_index == index {
            draw_frame(&mut canvas, sw, sh, frame)?;
            return RgbaImage::new(
                u32::from(screen_width),
                u32::from(screen_height),
                canvas,
                true,
            )
            .map_err(|e| {
                OperationError::decode("decoded frame is inconsistent").with_details(e.to_string())
            });
        }
        if frame.dispose == gif::DisposalMethod::Previous {
            saved = Some(canvas.clone());
        }
        draw_frame(&mut canvas, sw, sh, frame)?;
        match frame.dispose {
            gif::DisposalMethod::Background => clear_region(&mut canvas, sw, sh, frame),
            gif::DisposalMethod::Previous => {
                if let Some(previous) = saved.take() {
                    canvas.copy_from_slice(&previous);
                }
            }
            _ => {}
        }
        frame_index += 1;
    }
    Err(OperationError::invalid_param(
        "frame",
        format!("frame index {index} out of range; the GIF has {frame_index} frame(s)"),
    )
    .with_expected(format!("0..{}", frame_index.saturating_sub(1)))
    .with_actual(index.to_string()))
}

/// Blits one decoded RGBA frame region onto the canvas, skipping transparent
/// pixels (they leave the canvas pixel unchanged) and clamping regions that
/// run past the logical screen.
fn draw_frame(canvas: &mut [u32], sw: usize, sh: usize, frame: &gif::Frame<'_>) -> OpResult<()> {
    let fw = frame.width as usize;
    let fh = frame.height as usize;
    // `read_next_frame` with RGBA output fills exactly the region; the raw
    // LZW pass of pre-encoded streams must not be misread as pixels.
    let expected = fw as u64 * fh as u64 * 4;
    if frame.buffer.len() as u64 != expected {
        return Err(
            OperationError::decode("GIF frame data was not expanded to pixels").with_details(
                format!(
                    "region {}x{} expects {expected} bytes, got {}",
                    frame.width,
                    frame.height,
                    frame.buffer.len()
                ),
            ),
        );
    }
    let left = frame.left as usize;
    let top = frame.top as usize;
    for ry in 0..fh {
        let cy = top + ry;
        if cy >= sh {
            break;
        }
        for rx in 0..fw {
            let cx = left + rx;
            if cx >= sw {
                break;
            }
            let offset = (ry * fw + rx) * 4;
            let alpha = u32::from(frame.buffer[offset + 3]);
            if alpha == 0 {
                continue;
            }
            canvas[cy * sw + cx] = (alpha << 24)
                | (u32::from(frame.buffer[offset]) << 16)
                | (u32::from(frame.buffer[offset + 1]) << 8)
                | u32::from(frame.buffer[offset + 2]);
        }
    }
    Ok(())
}

/// Clears a frame region to transparent (restore-to-background).
fn clear_region(canvas: &mut [u32], sw: usize, sh: usize, frame: &gif::Frame<'_>) {
    let fw = frame.width as usize;
    let fh = frame.height as usize;
    let left = frame.left as usize;
    let top = frame.top as usize;
    for ry in 0..fh {
        let cy = top + ry;
        if cy >= sh {
            break;
        }
        for rx in 0..fw {
            let cx = left + rx;
            if cx >= sw {
                break;
            }
            canvas[cy * sw + cx] = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    const RED: u8 = 0;
    const BLUE: u8 = 1;
    const GREEN: u8 = 2;
    const PALETTE: [u8; 9] = [0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0xC0, 0x00];

    fn frame(width: u16, height: u16, left: u16, top: u16, pixels: Vec<u8>) -> gif::Frame<'static> {
        gif::Frame {
            width,
            height,
            left,
            top,
            buffer: Cow::Owned(pixels),
            ..gif::Frame::default()
        }
    }

    /// 4x2 screen with three frames:
    /// 0: full red (keep, delay 5)
    /// 1: blue 2x1 at (1, 0) (restore-to-background, delay 10)
    /// 2: [transparent, green] 2x1 at (0, 0) (keep)
    fn three_frame_gif() -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut encoder = gif::Encoder::new(&mut out, 4, 2, &PALETTE).unwrap();
            let f0 = gif::Frame {
                delay: 5,
                dispose: gif::DisposalMethod::Keep,
                ..frame(4, 2, 0, 0, vec![RED; 8])
            };
            encoder.write_frame(&f0).unwrap();
            let f1 = gif::Frame {
                delay: 10,
                dispose: gif::DisposalMethod::Background,
                ..frame(2, 1, 1, 0, vec![BLUE; 2])
            };
            encoder.write_frame(&f1).unwrap();
            let f2 = gif::Frame {
                transparent: Some(RED),
                dispose: gif::DisposalMethod::Keep,
                ..frame(2, 1, 0, 0, vec![RED, GREEN])
            };
            encoder.write_frame(&f2).unwrap();
        }
        out
    }

    fn limits() -> DecodeLimits {
        DecodeLimits::default()
    }

    #[test]
    fn index_frames_reports_metadata_without_decoding() {
        let index = index_frames(&three_frame_gif(), &limits()).unwrap();
        assert_eq!((index.screen_width, index.screen_height), (4, 2));
        assert_eq!(index.frames.len(), 3);
        assert!(!index.truncated);
        let f0 = index.frames[0];
        assert_eq!((f0.left, f0.top, f0.width, f0.height), (0, 0, 4, 2));
        assert_eq!(f0.delay_cs, 5);
        assert_eq!(f0.disposal, Disposal::Keep);
        assert_eq!(f0.transparent_index, None);
        assert!(!f0.interlaced);
        let f1 = index.frames[1];
        assert_eq!((f1.left, f1.top, f1.width, f1.height), (1, 0, 2, 1));
        assert_eq!(f1.delay_cs, 10);
        assert_eq!(f1.disposal, Disposal::Background);
        let f2 = index.frames[2];
        assert_eq!(f2.disposal, Disposal::Keep);
        assert_eq!(f2.transparent_index, Some(RED));
        assert_eq!(Disposal::Background.name(), "background");
    }

    #[test]
    fn index_frames_is_bounded_by_the_frame_cap() {
        // 4097 one-pixel frames: the index stops at 4096 and reports the cut.
        let mut out = Vec::new();
        {
            let mut encoder = gif::Encoder::new(&mut out, 1, 1, &PALETTE).unwrap();
            for _ in 0..=MAX_FRAMES_INDEXED {
                encoder.write_frame(&frame(1, 1, 0, 0, vec![RED])).unwrap();
            }
        }
        let index = index_frames(&out, &limits()).unwrap();
        assert_eq!(index.frames.len(), MAX_FRAMES_INDEXED);
        assert!(index.truncated);
        // Frame decode beyond the cap is a typed error before any decoding.
        let err = decode_frame(
            &out,
            MAX_FRAMES_INDEXED,
            &limits(),
            &ExecutionContext::new(),
        )
        .unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidParam);
    }

    #[test]
    fn decode_frame_composites_the_disposal_chain() {
        let gif_bytes = three_frame_gif();
        let ctx = ExecutionContext::new();
        // Frame 0: the red full-screen frame over a transparent canvas.
        let f0 = decode_frame(&gif_bytes, 0, &limits(), &ctx).unwrap();
        assert_eq!((f0.width, f0.height), (4, 2));
        assert!(f0.argb.iter().all(|&p| p == 0xFFFF_0000));
        // Frame 1: blue 2x1 at (1, 0) drawn over the kept red canvas.
        let f1 = decode_frame(&gif_bytes, 1, &limits(), &ctx).unwrap();
        assert_eq!(
            f1.argb,
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
        // Frame 2: frame 1 was restore-to-background, so its region was
        // cleared to transparent first; frame 2's transparent-index pixel
        // leaves (0,0) red, its green pixel lands on (1,0).
        let f2 = decode_frame(&gif_bytes, 2, &limits(), &ctx).unwrap();
        assert_eq!(
            f2.argb,
            vec![
                0xFFFF_0000, // untouched by the transparent-index pixel
                0xFF00_C000, // green
                0x0000_0000, // cleared by restore-to-background
                0xFFFF_0000,
                0xFFFF_0000,
                0xFFFF_0000,
                0xFFFF_0000,
                0xFFFF_0000,
            ]
        );
        assert!(f2.has_alpha);
    }

    #[test]
    fn decode_frame_out_of_range_is_a_typed_error() {
        let gif_bytes = three_frame_gif();
        let err = decode_frame(&gif_bytes, 3, &limits(), &ExecutionContext::new()).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidParam);
        assert!(err.message.contains("has 3 frame(s)"), "{}", err.message);
    }

    #[test]
    fn decode_frame_rejects_a_canvas_over_the_pixel_cap() {
        // A valid GIF whose logical screen (65535x65535) exceeds the 64 MP
        // canvas cap: indexing still works (no canvas is allocated), frame
        // decoding is refused before any allocation.
        let mut out = Vec::new();
        {
            let mut encoder = gif::Encoder::new(&mut out, 0xFFFF, 0xFFFF, &PALETTE).unwrap();
            encoder.write_frame(&frame(1, 1, 0, 0, vec![RED])).unwrap();
        }
        let index = index_frames(&out, &limits()).unwrap();
        assert_eq!(index.frames.len(), 1);
        assert_eq!((index.screen_width, index.screen_height), (0xFFFF, 0xFFFF));
        let err = decode_frame(&out, 0, &limits(), &ExecutionContext::new()).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Decode);
        assert!(err.message.contains("canvas"), "{}", err.message);
    }

    #[test]
    fn decode_frame_observes_cancellation() {
        let gif_bytes = three_frame_gif();
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let ctx = ExecutionContext::new().with_cancel(flag);
        let err = decode_frame(&gif_bytes, 2, &limits(), &ctx).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Cancelled);
    }

    #[test]
    fn index_frames_rejects_truncated_and_oversized_input() {
        // Not a GIF at all.
        let err = index_frames(b"not a gif", &limits()).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Decode);
        // A real GIF cut short mid-stream.
        let full = three_frame_gif();
        let err = index_frames(&full[..full.len() - 10], &limits()).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Decode);
        // File-size cap.
        let tight = DecodeLimits {
            max_file_bytes: 32,
            ..DecodeLimits::default()
        };
        let err = index_frames(&full, &tight).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Decode);
        assert!(err.message.contains("exceeds"), "{}", err.message);
    }

    #[test]
    fn encode_png_roundtrips_a_composed_frame() {
        let gif_bytes = three_frame_gif();
        let composed = decode_frame(&gif_bytes, 2, &limits(), &ExecutionContext::new()).unwrap();
        let png = cybercipher_media::encode_png(&composed).unwrap();
        let decoded = cybercipher_media::decode(&png, &DecodeLimits::default()).unwrap();
        assert_eq!(decoded.width, 4);
        assert_eq!(decoded.height, 2);
        assert!(decoded.has_alpha);
        assert_eq!(decoded.argb, composed.argb);
    }
}
