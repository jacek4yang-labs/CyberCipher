//! The 13 image combination modes of the original StegSolve combiner,
//! preserved bit for bit (StegSolver `CombineMode`, reference commit
//! `c14bfa9`, MIT).
//!
//! Modes 0..10 combine two images pixel by pixel. When the images differ in
//! size the result is as large as the bigger one and missing pixels are
//! treated as fully transparent black, exactly as the legacy implementation
//! did. Modes 11 and 12 interlace instead and use the intersection of the
//! two sizes.
//!
//! As in the legacy implementation every mode produces an opaque image: the
//! alpha byte of the inputs only matters where the whole-pixel arithmetic
//! happens to reach into it, and the final result is masked to 24 bits and
//! made fully opaque, exactly like the legacy write into a `TYPE_INT_RGB`
//! image. Whole-pixel ADD/SUBTRACT/MULTIPLY reproduce Java `int` (32-bit
//! two's complement) wraparound; the per-channel variants wrap within each
//! 8-bit lane. Neither input is ever modified.

use cybercipher_core::{OpResult, OperationError};
use cybercipher_media::RgbaImage;

use crate::transforms::opaque;

/// One combination mode; the declaration order is the legacy transform
/// number (0..12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CombineMode {
    /// Whole-pixel XOR.
    Xor,
    /// Whole-pixel OR.
    Or,
    /// Whole-pixel AND.
    And,
    /// Whole-pixel ADD with Java int wraparound.
    Add,
    /// Per-channel ADD, wrapping within each 8-bit lane.
    AddPerChannel,
    /// Whole-pixel SUBTRACT with Java int wraparound.
    Subtract,
    /// Per-channel SUBTRACT, wrapping within each 8-bit lane.
    SubtractPerChannel,
    /// Whole-pixel MULTIPLY with Java int wraparound.
    Multiply,
    /// Per-channel MULTIPLY, product masked to 8 bits per lane.
    MultiplyPerChannel,
    /// Per-channel maximum (R, G, B only).
    Lightest,
    /// Per-channel minimum (R, G, B only).
    Darkest,
    /// Row interlace: output is `w x h*2`, alternating input rows.
    InterlaceRows,
    /// Column interlace: output is `w*2 x h`, alternating input pixels.
    InterlaceColumns,
}

/// Legacy labels of the 13 modes, indexed by mode number.
const LABELS: [&str; 13] = [
    "XOR",
    "OR",
    "AND",
    "ADD",
    "ADD (R,G,B separate)",
    "SUB",
    "SUB (R,G,B separate)",
    "MUL",
    "MUL (R,G,B separate)",
    "Lightest (R,G,B separate)",
    "Darkest (R,G,B separate)",
    "Interlace rows",
    "Interlace columns",
];

impl CombineMode {
    /// All modes in legacy order; `ALL[i].legacy_index() == i`.
    pub const ALL: [CombineMode; 13] = [
        CombineMode::Xor,
        CombineMode::Or,
        CombineMode::And,
        CombineMode::Add,
        CombineMode::AddPerChannel,
        CombineMode::Subtract,
        CombineMode::SubtractPerChannel,
        CombineMode::Multiply,
        CombineMode::MultiplyPerChannel,
        CombineMode::Lightest,
        CombineMode::Darkest,
        CombineMode::InterlaceRows,
        CombineMode::InterlaceColumns,
    ];

    /// The transform number of the legacy combiner (the declaration order).
    #[must_use]
    pub fn legacy_index(self) -> usize {
        match self {
            CombineMode::Xor => 0,
            CombineMode::Or => 1,
            CombineMode::And => 2,
            CombineMode::Add => 3,
            CombineMode::AddPerChannel => 4,
            CombineMode::Subtract => 5,
            CombineMode::SubtractPerChannel => 6,
            CombineMode::Multiply => 7,
            CombineMode::MultiplyPerChannel => 8,
            CombineMode::Lightest => 9,
            CombineMode::Darkest => 10,
            CombineMode::InterlaceRows => 11,
            CombineMode::InterlaceColumns => 12,
        }
    }

    /// The mode for a legacy transform number 0..12.
    #[must_use]
    pub fn from_legacy_index(index: usize) -> Option<Self> {
        CombineMode::ALL.get(index).copied()
    }

    /// The legacy combiner label.
    #[must_use]
    pub fn label(self) -> &'static str {
        LABELS[self.legacy_index()]
    }

    /// Whether the mode interlaces instead of blending pixel by pixel.
    #[must_use]
    pub fn is_interlace(self) -> bool {
        matches!(
            self,
            CombineMode::InterlaceRows | CombineMode::InterlaceColumns
        )
    }
}

/// Combines two images under `mode`, returning a new opaque image. Neither
/// input is modified.
///
/// # Errors
///
/// Returns a typed [`OperationError`] when an interlace mode is applied to
/// images that do not overlap (empty intersection), or when the per-pixel
/// arithmetic is asked to run for an interlace mode.
pub fn combine(mode: CombineMode, first: &RgbaImage, second: &RgbaImage) -> OpResult<RgbaImage> {
    if mode.is_interlace() {
        interlace(mode, first, second)
    } else {
        Ok(blend(mode, first, second))
    }
}

/// Modes 0..10: the result is as large as the bigger input; out-of-bounds
/// samples read transparent black (0), exactly as the reference.
fn blend(mode: CombineMode, first: &RgbaImage, second: &RgbaImage) -> RgbaImage {
    let width = first.width.max(second.width);
    let height = first.height.max(second.height);
    let mut out = Vec::with_capacity(width as usize * height as usize);
    for y in 0..height {
        for x in 0..width {
            let color1 = if x < first.width && y < first.height {
                first.argb[y as usize * first.width as usize + x as usize]
            } else {
                0
            };
            let color2 = if x < second.width && y < second.height {
                second.argb[y as usize * second.width as usize + x as usize]
            } else {
                0
            };
            // Per-pixel modes cannot fail here (only interlace modes error).
            out.push(combine_pixels(mode, color1, color2).expect("non-interlace mode"));
        }
    }
    RgbaImage::opaque(width, height, out)
}

/// Modes 11/12: interlace on the intersection of the two sizes.
fn interlace(mode: CombineMode, first: &RgbaImage, second: &RgbaImage) -> OpResult<RgbaImage> {
    let width = first.width.min(second.width);
    let height = first.height.min(second.height);
    if width == 0 || height == 0 {
        return Err(OperationError::invalid_input(format!(
            "images do not overlap: {}x{} and {}x{}",
            first.width, first.height, second.width, second.height
        )));
    }
    let w = width as usize;
    if mode == CombineMode::InterlaceRows {
        let mut out = Vec::with_capacity(w * height as usize * 2);
        for y in 0..height as usize {
            let a_row = y * first.width as usize;
            let b_row = y * second.width as usize;
            for x in 0..w {
                out.push(opaque(first.argb[a_row + x]));
            }
            for x in 0..w {
                out.push(opaque(second.argb[b_row + x]));
            }
        }
        return Ok(RgbaImage::opaque(width, height * 2, out));
    }
    // InterlaceColumns: out stride is width * 2.
    let stride = w * 2;
    let mut out = vec![0u32; stride * height as usize];
    for y in 0..height as usize {
        let a_row = y * first.width as usize;
        let b_row = y * second.width as usize;
        let out_row = y * stride;
        for x in 0..w {
            out[out_row + x * 2] = opaque(first.argb[a_row + x]);
            out[out_row + x * 2 + 1] = opaque(second.argb[b_row + x]);
        }
    }
    Ok(RgbaImage::opaque(width * 2, height, out))
}

/// The per-pixel arithmetic of the non-interlace modes (reference
/// `combinePixels`), bit-exact including Java int wraparound.
///
/// # Errors
///
/// Returns a typed error for the interlace modes, which have no per-pixel
/// arithmetic (the reference throws).
pub fn combine_pixels(mode: CombineMode, color1: u32, color2: u32) -> OpResult<u32> {
    // u32 wrapping arithmetic has the same bit patterns as Java int (32-bit
    // two's complement) for +, -, *, ^, |, &, so the legacy semantics are
    // transcribed directly; opaque() then masks to 24 bits as the legacy
    // TYPE_INT_RGB write did.
    let value = match mode {
        CombineMode::Xor => opaque(color1 ^ color2),
        CombineMode::Or => opaque(color1 | color2),
        CombineMode::And => opaque(color1 & color2),
        CombineMode::Add => opaque(color1.wrapping_add(color2)),
        CombineMode::AddPerChannel => {
            let r = ((color1 & 0xFF0000) + (color2 & 0xFF0000)) & 0xFF0000;
            let g = ((color1 & 0xFF00) + (color2 & 0xFF00)) & 0xFF00;
            let b = ((color1 & 0xFF) + (color2 & 0xFF)) & 0xFF;
            opaque(r | g | b)
        }
        CombineMode::Subtract => opaque(color1.wrapping_sub(color2)),
        CombineMode::SubtractPerChannel => {
            let r = ((color1 & 0xFF0000).wrapping_sub(color2 & 0xFF0000)) & 0xFF0000;
            let g = ((color1 & 0xFF00).wrapping_sub(color2 & 0xFF00)) & 0xFF00;
            let b = ((color1 & 0xFF).wrapping_sub(color2 & 0xFF)) & 0xFF;
            opaque(r | g | b)
        }
        CombineMode::Multiply => opaque(color1.wrapping_mul(color2)),
        CombineMode::MultiplyPerChannel => {
            let r = ((((color1 & 0xFF0000) >> 16) * ((color2 & 0xFF0000) >> 16)) & 0xFF) << 16;
            let g = ((((color1 & 0xFF00) >> 8) * ((color2 & 0xFF00) >> 8)) & 0xFF) << 8;
            let b = ((color1 & 0xFF) * (color2 & 0xFF)) & 0xFF;
            opaque(r | g | b)
        }
        CombineMode::Lightest => {
            let r = if (color1 & 0xFF0000) > (color2 & 0xFF0000) {
                color1 & 0xFF0000
            } else {
                color2 & 0xFF0000
            };
            let g = if (color1 & 0xFF00) > (color2 & 0xFF00) {
                color1 & 0xFF00
            } else {
                color2 & 0xFF00
            };
            let b = if (color1 & 0xFF) > (color2 & 0xFF) {
                color1 & 0xFF
            } else {
                color2 & 0xFF
            };
            opaque(r | g | b)
        }
        CombineMode::Darkest => {
            let r = if (color1 & 0xFF0000) < (color2 & 0xFF0000) {
                color1 & 0xFF0000
            } else {
                color2 & 0xFF0000
            };
            let g = if (color1 & 0xFF00) < (color2 & 0xFF00) {
                color1 & 0xFF00
            } else {
                color2 & 0xFF00
            };
            let b = if (color1 & 0xFF) < (color2 & 0xFF) {
                color1 & 0xFF
            } else {
                color2 & 0xFF
            };
            opaque(r | g | b)
        }
        CombineMode::InterlaceRows | CombineMode::InterlaceColumns => {
            return Err(OperationError::invalid_input(format!(
                "{mode:?} is not a per-pixel combine mode"
            )));
        }
    };
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pair of test colours used across the per-mode vector tests:
    /// `c1 = 0x0000FF01`, `c2 = 0x000000FF` — chosen so whole-pixel and
    /// per-channel modes visibly disagree (the ADD carry into red, the
    /// SUBTRACT borrow, the b-lane wrap).
    const C1: u32 = 0x0000_FF01;
    const C2: u32 = 0x0000_00FF;

    fn one_pixel(argb: u32) -> RgbaImage {
        RgbaImage::new(1, 1, vec![argb], true).unwrap()
    }

    #[test]
    fn mode_catalog_is_in_legacy_order() {
        assert_eq!(CombineMode::ALL.len(), 13);
        for (i, mode) in CombineMode::ALL.iter().enumerate() {
            assert_eq!(mode.legacy_index(), i);
            assert_eq!(CombineMode::from_legacy_index(i), Some(*mode));
            assert_eq!(mode.label(), LABELS[i]);
        }
        assert_eq!(CombineMode::from_legacy_index(13), None);
        assert_eq!(CombineMode::Xor.label(), "XOR");
        assert_eq!(CombineMode::InterlaceRows.label(), "Interlace rows");
        assert_eq!(
            CombineMode::ALL
                .iter()
                .filter(|m| m.is_interlace())
                .copied()
                .collect::<Vec<_>>(),
            vec![CombineMode::InterlaceRows, CombineMode::InterlaceColumns]
        );
    }

    #[test]
    fn whole_pixel_modes_match_java_int_wraparound() {
        assert_eq!(
            combine_pixels(CombineMode::Xor, C1, C2).unwrap(),
            0xFF00_FFFE
        );
        assert_eq!(
            combine_pixels(CombineMode::Or, C1, C2).unwrap(),
            0xFF00_FFFF
        );
        assert_eq!(
            combine_pixels(CombineMode::And, C1, C2).unwrap(),
            0xFF00_0001
        );
        // 0x0000FF01 + 0x000000FF = 0x00010000: the carry reaches into red.
        assert_eq!(
            combine_pixels(CombineMode::Add, C1, C2).unwrap(),
            0xFF01_0000
        );
        // 0x0000FF01 - 0x000000FF = 0x0000FE02: the borrow stays in green.
        assert_eq!(
            combine_pixels(CombineMode::Subtract, C1, C2).unwrap(),
            0xFF00_FE02
        );
        // 0xFF01 * 0xFF = 0xFE01FF, no 32-bit overflow.
        assert_eq!(
            combine_pixels(CombineMode::Multiply, C1, C2).unwrap(),
            0xFFFE_01FF
        );
    }

    #[test]
    fn whole_pixel_overflow_wraps_like_java_int() {
        // 0x80000000 + 0x80000000 wraps to 0x00000000 in 32-bit arithmetic;
        // opaque() then makes it black, not transparent.
        assert_eq!(
            combine_pixels(CombineMode::Add, 0x8000_0000, 0x8000_0000).unwrap(),
            0xFF00_0000
        );
        // 0x00000040 * 0x10000000 overflows 32 bits: low word is 0.
        assert_eq!(
            combine_pixels(CombineMode::Multiply, 0x0000_0040, 0x1000_0000).unwrap(),
            0xFF00_0000
        );
        // 0x00000001 - 0x00000002 wraps to 0xFFFFFFFF; masked to 0xFFFFFF.
        assert_eq!(
            combine_pixels(CombineMode::Subtract, 0x0000_0001, 0x0000_0002).unwrap(),
            0xFF00_FFFF
        );
        // Alpha participates in whole-pixel arithmetic before the mask.
        assert_eq!(
            combine_pixels(CombineMode::Add, 0x4000_0000, 0x4000_0000).unwrap(),
            0xFF00_0000
        );
        assert_eq!(
            combine_pixels(CombineMode::And, 0x4000_0000, 0x4000_0000).unwrap(),
            0xFF00_0000
        );
    }

    #[test]
    fn per_channel_modes_wrap_within_lanes() {
        // ADD: lanes 0x00|0xFF+0x00|0x01+0xFF -> no carry into red.
        assert_eq!(
            combine_pixels(CombineMode::AddPerChannel, C1, C2).unwrap(),
            0xFF00_FF00
        );
        // SUBTRACT: 0x01 - 0xFF wraps to 0x02 within the blue lane.
        assert_eq!(
            combine_pixels(CombineMode::SubtractPerChannel, C1, C2).unwrap(),
            0xFF00_FF02
        );
        // MULTIPLY: products masked to 8 bits per lane.
        assert_eq!(
            combine_pixels(CombineMode::MultiplyPerChannel, C1, C2).unwrap(),
            0xFF00_00FF
        );
        // Per-channel ADD of maxed lanes wraps: 0xFF + 0x01 -> 0x00.
        assert_eq!(
            combine_pixels(CombineMode::AddPerChannel, 0x0000_00FF, 0x0000_0001).unwrap(),
            0xFF00_0000
        );
    }

    #[test]
    fn lightest_and_darkest_compare_per_channel() {
        assert_eq!(
            combine_pixels(CombineMode::Lightest, C1, C2).unwrap(),
            0xFF00_FFFF
        );
        assert_eq!(
            combine_pixels(CombineMode::Darkest, C1, C2).unwrap(),
            0xFF00_0001
        );
        // Alpha is not compared: only R, G, B lanes.
        assert_eq!(
            combine_pixels(CombineMode::Lightest, 0x1000_0000, 0xE000_0000).unwrap(),
            0xFF00_0000
        );
    }

    #[test]
    fn interlace_modes_have_no_per_pixel_arithmetic() {
        for mode in [CombineMode::InterlaceRows, CombineMode::InterlaceColumns] {
            let err = combine_pixels(mode, 0, 0).unwrap_err();
            assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn size_mismatch_uses_max_canvas_with_transparent_black_fill() {
        // A is 2x2, B is 3x1: the result is 3x2. Missing pixels read as 0.
        let a = RgbaImage::new(
            2,
            2,
            vec![0xFF11_2233, 0xFF44_5566, 0xFF77_8899, 0xFFAA_BBCC],
            false,
        )
        .unwrap();
        let b = RgbaImage::new(3, 1, vec![0xFF01_0203, 0xFF04_0506, 0xFF07_0809], false).unwrap();
        let out = combine(CombineMode::Xor, &a, &b).unwrap();
        assert_eq!((out.width, out.height), (3, 2));
        // Row 0: both in bounds.
        assert_eq!(out.argb[0], opaque(0xFF112233 ^ 0xFF010203));
        assert_eq!(out.argb[1], opaque(0xFF445566 ^ 0xFF040506));
        // (2,0): A is out of bounds -> 0 XOR b.
        assert_eq!(out.argb[2], opaque(0xFF070809));
        // (0,1): B is out of bounds -> a XOR 0.
        assert_eq!(out.argb[3], opaque(0xFF778899));
        // (2,1): both out of bounds -> opaque black.
        assert_eq!(out.argb[5], 0xFF00_0000);
        // The other orientation too.
        let flipped = combine(CombineMode::Xor, &b, &a).unwrap();
        assert_eq!((flipped.width, flipped.height), (3, 2));
        assert_eq!(flipped.argb[0], out.argb[0]);
    }

    #[test]
    fn interlace_rows_stack_alternating_input_rows() {
        let a = RgbaImage::new(2, 1, vec![0xFF00_0011, 0xFF00_0022], false).unwrap();
        let b = RgbaImage::new(2, 1, vec![0xFF00_0033, 0xFF00_0044], false).unwrap();
        let out = combine(CombineMode::InterlaceRows, &a, &b).unwrap();
        assert_eq!((out.width, out.height), (2, 2));
        assert_eq!(
            out.argb,
            vec![
                opaque(0xFF00_0011),
                opaque(0xFF00_0022), // row 0 = A row 0
                opaque(0xFF00_0033),
                opaque(0xFF00_0044), // row 1 = B row 0
            ]
        );
    }

    #[test]
    fn interlace_rows_use_the_size_intersection() {
        // A is 3x2, B is 1x1: intersection 1x2 -> output 1x4.
        let a = RgbaImage::new(
            3,
            2,
            vec![
                0xFF00_000A,
                0xFF00_000B,
                0xFF00_000C,
                0xFF00_000D,
                0xFF00_000E,
                0xFF00_000F,
            ],
            false,
        )
        .unwrap();
        let b = RgbaImage::new(1, 1, vec![0xFF00_00B1], false).unwrap();
        let out = combine(CombineMode::InterlaceRows, &a, &b).unwrap();
        assert_eq!((out.width, out.height), (1, 4));
        assert_eq!(
            out.argb,
            vec![
                opaque(0xFF00_000A),
                opaque(0xFF00_00B1),
                opaque(0xFF00_000D),
                opaque(0xFF00_00B1),
            ]
        );
    }

    #[test]
    fn interlace_columns_alternate_input_pixels() {
        let a = RgbaImage::new(2, 1, vec![0xFF00_0011, 0xFF00_0022], false).unwrap();
        let b = RgbaImage::new(2, 1, vec![0xFF00_0033, 0xFF00_0044], false).unwrap();
        let out = combine(CombineMode::InterlaceColumns, &a, &b).unwrap();
        assert_eq!((out.width, out.height), (4, 1));
        assert_eq!(
            out.argb,
            vec![
                opaque(0xFF00_0011),
                opaque(0xFF00_0033),
                opaque(0xFF00_0022),
                opaque(0xFF00_0044),
            ]
        );
    }

    #[test]
    fn interlace_columns_output_is_twice_as_wide() {
        // 2x2 with 1x1: intersection 1x1 -> output 2x1.
        let a = RgbaImage::new(2, 2, vec![0xFF00_0001; 4], false).unwrap();
        let b = RgbaImage::new(1, 1, vec![0xFF00_0002], false).unwrap();
        let out = combine(CombineMode::InterlaceColumns, &a, &b).unwrap();
        assert_eq!((out.width, out.height), (2, 1));
        assert_eq!(out.argb, vec![opaque(0xFF00_0001), opaque(0xFF00_0002)]);
    }

    #[test]
    fn inputs_are_never_mutated() {
        let a_snapshot = vec![0x1122_3344u32, 0xFF7F_01FF, 0x0000_0000, 0x8080_8080];
        let b_snapshot = vec![0x0000_00FFu32, 0x7FFF_FFFF, 0xFF00_0000, 0x0000_0001];
        let a = RgbaImage::new(2, 2, a_snapshot.clone(), true).unwrap();
        let b = RgbaImage::new(2, 2, b_snapshot.clone(), true).unwrap();
        for mode in CombineMode::ALL {
            let _ = combine(mode, &a, &b).unwrap();
            assert_eq!(a.argb, a_snapshot, "mode {}", mode.label());
            assert_eq!(b.argb, b_snapshot, "mode {}", mode.label());
        }
    }

    #[test]
    fn every_mode_produces_opaque_output() {
        let a = one_pixel(0x0000_0000);
        let b = one_pixel(0x0000_0000);
        for mode in CombineMode::ALL {
            let out = combine(mode, &a, &b).unwrap();
            assert!(
                out.argb.iter().all(|&p| p & 0xFF00_0000 == 0xFF00_0000),
                "mode {} must be opaque",
                mode.label()
            );
        }
    }
}
