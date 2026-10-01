//! Stereogram solver: shifted-XOR autostereogram analysis.
//!
//! Bit-exact port of the StegSolver `StereoTransform` (reference commit
//! `c14bfa9`, MIT, which itself rebuilds the original StegSolve by Caesum).
//! XORing an autostereogram with a horizontally shifted copy of itself
//! reveals the hidden depth map once the shift matches the repeating pattern
//! width: `out(x, y) = in(x, y) XOR in((x + offset) mod w, y)`.
//!
//! Compatibility quirks that are part of the established behaviour are
//! reproduced exactly: the right-edge wrap of the sample position (the
//! original did not clamp), the fully opaque output of every pixel (the
//! legacy tool wrote into a `TYPE_INT_RGB` image, so a matched pattern is
//! black rather than transparent), the offset-0 shortcut that returns an
//! opaque black image, and the `best_offset` scan that prefers the smallest
//! offset among equals so the fundamental period wins over its multiples.

use cybercipher_core::{ExecutionContext, OpResult};
use cybercipher_media::RgbaImage;

use crate::transforms::opaque;

/// Brings an offset into `[0, width - 1]` (reference `normalizeOffset`).
///
/// Negative offsets wrap from the left, offsets at or beyond the width wrap
/// around, and a multiple of the width normalizes to 0.
///
/// # Panics
///
/// Panics when `width` is 0 — the reference throws for a non-positive width,
/// and callers always pass a real image width (never 0).
#[must_use]
pub fn normalize_offset(offset: i64, width: u32) -> u32 {
    debug_assert!(width > 0, "width must be positive");
    let w = width as i64;
    let value = offset % w;
    if value < 0 {
        (value + w) as u32
    } else {
        value as u32
    }
}

/// XORs the image with a copy of itself shifted by `offset` pixels, wrapping
/// the sample at the right edge (reference `shiftedXor`).
///
/// Offset 0 (or any multiple of the width) short-circuits to an opaque black
/// image, exactly as the reference: `in XOR in` is 0 everywhere.
#[must_use]
pub fn shifted_xor(source: &RgbaImage, offset: i64) -> RgbaImage {
    let width = source.width;
    let height = source.height;
    let w = width as usize;
    let shift = normalize_offset(offset, width) as usize;
    if shift == 0 {
        return RgbaImage::opaque(width, height, vec![0xFF00_0000; source.argb.len()]);
    }
    let mut out = Vec::with_capacity(source.argb.len());
    for y in 0..height as usize {
        let row = y * w;
        for x in 0..w {
            // x + shift < 2w, so one subtraction brings the sample back into
            // the row: the legacy right-edge wrap.
            let sample = if x + shift < w {
                x + shift
            } else {
                x + shift - w
            };
            out.push(opaque(source.argb[row + x] ^ source.argb[row + sample]));
        }
    }
    RgbaImage::opaque(width, height, out)
}

/// Like [`shifted_xor`] but clamps the sample position at the right edge
/// instead of wrapping, which removes the wrap-around seam on the last
/// `offset` columns (reference `withEdgeHold`).
#[must_use]
pub fn edge_hold(source: &RgbaImage, offset: i64) -> RgbaImage {
    let width = source.width;
    let w = width as usize;
    let shift = normalize_offset(offset, width) as usize;
    let last = w - 1;
    let mut out = Vec::with_capacity(source.argb.len());
    for y in 0..source.height as usize {
        let row = y * w;
        for x in 0..w {
            let sample = (x + shift).min(last);
            out.push(opaque(source.argb[row + x] ^ source.argb[row + sample]));
        }
    }
    RgbaImage::opaque(width, source.height, out)
}

/// Searches for the offset with the strongest self similarity — the pattern
/// width of an autostereogram (reference `bestOffset`).
///
/// Only every `sample_step`-th row and column is compared, which keeps the
/// scan fast on large images. The scan covers offsets `1..=width / 2` because
/// a repeating pattern also matches at multiples of its period and the
/// smallest match is the useful one. The strict `>` comparison means the
/// smallest offset wins ties, so the fundamental period beats its multiples.
///
/// Cancellation is observed through the [`ExecutionContext`] once per offset
/// (each offset's scan is one full row sweep, matching the reference's
/// interrupt granularity).
///
/// # Errors
///
/// Returns a typed [`cybercipher_core::OperationError`] when the context
/// signals cancellation.
pub fn best_offset(
    source: &RgbaImage,
    sample_step: usize,
    ctx: &ExecutionContext,
) -> OpResult<usize> {
    if source.width < 2 || source.height < 1 {
        return Ok(0);
    }
    let step = sample_step.max(1);
    let w = source.width as usize;
    let height = source.height as usize;
    let pixels = &source.argb;
    let max_offset = (w / 2).max(1);
    let mut best_offset = 0usize;
    // Starts below zero so the first compared offset always wins, exactly as
    // the reference's `long bestMatches = -1`.
    let mut best_matches: i64 = -1;
    for offset in 1..=max_offset {
        ctx.check()?;
        let mut matches: i64 = 0;
        let mut compared: i64 = 0;
        let mut y = 0usize;
        while y < height {
            let row = y * w;
            let mut x = 0usize;
            while x + offset < w {
                compared += 1;
                if pixels[row + x] == pixels[row + x + offset] {
                    matches += 1;
                }
                x += step;
            }
            y += step;
        }
        if compared == 0 {
            continue;
        }
        // Prefer the smallest offset among equals, so the fundamental period
        // wins. Transcribed verbatim (strict >), do not rewrite as >=.
        if matches > best_matches {
            best_matches = matches;
            best_offset = offset;
        }
    }
    Ok(best_offset)
}

/// Next offset, wrapping around, as the legacy ">" button did.
#[must_use]
pub fn next_offset(offset: i64, width: u32) -> u32 {
    (normalize_offset(offset, width) + 1) % width
}

/// Previous offset, wrapping around, as the legacy "<" button did.
#[must_use]
pub fn previous_offset(offset: i64, width: u32) -> u32 {
    let value = i64::from(normalize_offset(offset, width)) - 1;
    if value < 0 {
        width - 1
    } else {
        value as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cybercipher_core::ErrorKind;

    /// 32x4 image whose colour depends only on `x % 8`: the true pattern
    /// period is 8, and the width is a multiple of it.
    fn periodic8() -> RgbaImage {
        let mut argb = Vec::new();
        for _y in 0..4u32 {
            for x in 0..32u32 {
                let v = 0x10 + (x % 8) * 0x1E;
                argb.push(0xFF00_0000 | (v << 16) | (v << 8) | v);
            }
        }
        RgbaImage::new(32, 4, argb, false).unwrap()
    }

    #[test]
    fn shifted_xor_at_true_period_is_opaque_black() {
        let img = periodic8();
        for offset in [8i64, 16, 24, 32] {
            let out = shifted_xor(&img, offset);
            assert_eq!(out.width, 32);
            assert_eq!(out.height, 4);
            assert!(
                out.argb.iter().all(|&p| p == 0xFF00_0000),
                "offset {offset} must collapse to opaque black"
            );
        }
    }

    #[test]
    fn shifted_xor_off_period_is_not_black() {
        let img = periodic8();
        let out = shifted_xor(&img, 7);
        assert!(out.argb.iter().any(|&p| p != 0xFF00_0000));
        // And the output is always opaque, like the legacy TYPE_INT_RGB path.
        assert!(out.argb.iter().all(|&p| p & 0xFF00_0000 == 0xFF00_0000));
    }

    #[test]
    fn shifted_xor_offset_zero_shortcuts_to_black() {
        let img = periodic8();
        let out = shifted_xor(&img, 0);
        assert!(out.argb.iter().all(|&p| p == 0xFF00_0000));
    }

    #[test]
    fn shifted_xor_wraps_sample_at_right_edge() {
        // One row of single-bit values so every XOR result is distinctive:
        // offset 3 wraps in[5]^in[0], in[6]^in[1], in[7]^in[2] on the tail.
        let row: Vec<u32> = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
            .iter()
            .map(|&v| 0xFF00_0000u32 | v)
            .collect();
        let img = RgbaImage::new(8, 1, row, false).unwrap();
        let expected: Vec<u32> = [
            0x01u32 ^ 0x08, // x=0: in[0]^in[3]
            0x02u32 ^ 0x10, // x=1
            0x04u32 ^ 0x20, // x=2
            0x08u32 ^ 0x40, // x=3
            0x10u32 ^ 0x80, // x=4
            0x20u32 ^ 0x01, // x=5: wrapped to in[0]
            0x40u32 ^ 0x02, // x=6: wrapped to in[1]
            0x80u32 ^ 0x04, // x=7: wrapped to in[2]
        ]
        .iter()
        .map(|&v| 0xFF00_0000 | v)
        .collect();
        assert_eq!(shifted_xor(&img, 3).argb, expected);
    }

    #[test]
    fn edge_hold_clamps_sample_at_right_edge() {
        let row: Vec<u32> = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
            .iter()
            .map(|&v| 0xFF00_0000u32 | v)
            .collect();
        let img = RgbaImage::new(8, 1, row, false).unwrap();
        let wrapped = shifted_xor(&img, 3);
        let held = edge_hold(&img, 3);
        // Columns with an in-bounds sample are identical to the wrap variant.
        for x in 0..5 {
            assert_eq!(held.argb[x], wrapped.argb[x], "column {x}");
        }
        // The last `offset` columns differ: the sample clamps to in[7].
        let expected_tail: Vec<u32> = [0x20u32 ^ 0x80, 0x40u32 ^ 0x80, 0x80u32 ^ 0x80]
            .iter()
            .map(|&v| 0xFF00_0000 | v)
            .collect();
        assert_eq!(&held.argb[5..], &expected_tail[..]);
        // Every tail column differs from the wrap variant here.
        for x in 5..8 {
            assert_ne!(held.argb[x], wrapped.argb[x], "column {x}");
        }
    }

    #[test]
    fn best_offset_finds_fundamental_period() {
        let img = periodic8();
        // Offsets 8 and 16 both match everywhere (period and its multiple),
        // but the fundamental period must win.
        assert_eq!(best_offset(&img, 1, &ExecutionContext::new()).unwrap(), 8);
        assert_eq!(best_offset(&img, 2, &ExecutionContext::new()).unwrap(), 8);
        assert_eq!(best_offset(&img, 3, &ExecutionContext::new()).unwrap(), 8);
    }

    #[test]
    fn best_offset_ties_prefer_the_smallest_offset() {
        // A uniform image matches at every offset; the strict `>` comparison
        // keeps the first (smallest) one.
        let img = RgbaImage::new(8, 2, vec![0xFF40_4040; 16], false).unwrap();
        assert_eq!(best_offset(&img, 1, &ExecutionContext::new()).unwrap(), 1);
    }

    #[test]
    fn best_offset_returns_zero_for_tiny_images() {
        let img = RgbaImage::new(1, 1, vec![0xFF00_0000], false).unwrap();
        assert_eq!(best_offset(&img, 1, &ExecutionContext::new()).unwrap(), 0);
    }

    #[test]
    fn best_offset_observes_cancellation() {
        let img = periodic8();
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let ctx = ExecutionContext::new().with_cancel(flag);
        let err = best_offset(&img, 1, &ctx).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Cancelled);
    }

    #[test]
    fn offsets_normalize_into_half_open_width_range() {
        assert_eq!(normalize_offset(0, 8), 0);
        assert_eq!(normalize_offset(7, 8), 7);
        assert_eq!(normalize_offset(8, 8), 0);
        assert_eq!(normalize_offset(9, 8), 1);
        assert_eq!(normalize_offset(-1, 8), 7);
        assert_eq!(normalize_offset(-8, 8), 0);
        assert_eq!(normalize_offset(-9, 8), 7);
        assert_eq!(normalize_offset(16, 8), 0);
    }

    #[test]
    fn normalized_offset_zero_collapses_to_black() {
        let img = periodic8();
        for offset in [16i64, -8] {
            let out = shifted_xor(&img, offset);
            assert!(out.argb.iter().all(|&p| p == 0xFF00_0000));
        }
        // -1 is the same shift as 7.
        assert_eq!(shifted_xor(&img, -1).argb, shifted_xor(&img, 7).argb);
    }

    #[test]
    fn next_and_previous_offset_wrap_around() {
        assert_eq!(next_offset(0, 8), 1);
        assert_eq!(next_offset(7, 8), 0);
        assert_eq!(next_offset(-1, 8), 0);
        assert_eq!(previous_offset(0, 8), 7);
        assert_eq!(previous_offset(1, 8), 0);
        assert_eq!(previous_offset(9, 8), 0);
        assert_eq!(previous_offset(-1, 8), 6);
        assert_eq!(next_offset(0, 1), 0);
        assert_eq!(previous_offset(0, 1), 0);
    }

    #[test]
    fn edge_hold_at_offset_zero_is_black() {
        // in ^ in == 0; the reference has no shortcut here but the arithmetic
        // collapses all the same.
        let img = periodic8();
        let out = edge_hold(&img, 0);
        assert!(out.argb.iter().all(|&p| p == 0xFF00_0000));
    }
}
