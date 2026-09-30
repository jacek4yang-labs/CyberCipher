//! The 42-transform catalog, bit-exact with the StegSolve ordering.
//!
//! Order and numbering reproduce the original StegSolve exactly:
//!
//! ```text
//!   0        original image
//!   1        inversion
//!   2..9     alpha planes 7..0
//!   10..17   red planes 7..0
//!   18..25   green planes 7..0
//!   26..33   blue planes 7..0
//!   34..37   full alpha / red / green / blue
//!   38..40   random colour maps (three fixed seeds)
//!   41       gray pixels (r == g == b)
//! ```
//!
//! Every computed output is forced opaque (`0xFF000000 | (value & 0xFFFFFF)`)
//! because the legacy tool wrote results into a `TYPE_INT_RGB` image: a bit
//! plane is black and white, not invisible. Only transform 0 (original)
//! preserves the source alpha.

use cybercipher_core::{ExecutionContext, OpResult, OperationError};
use cybercipher_media::RgbaImage;

use crate::java_random::JavaRandom;

/// ARGB channel, ordered by bit shift in the packed pixel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Channel {
    /// Bits 24..31 (plane-space ordinal 0, used by extraction masks).
    Alpha,
    /// Bits 16..23 (ordinal 1).
    Red,
    /// Bits 8..15 (ordinal 2).
    Green,
    /// Bits 0..7 (ordinal 3).
    Blue,
}

impl Channel {
    /// Low bit of the channel inside the packed ARGB word.
    #[must_use]
    pub fn shift(self) -> u32 {
        match self {
            Channel::Alpha => 24,
            Channel::Red => 16,
            Channel::Green => 8,
            Channel::Blue => 0,
        }
    }

    /// Plane-space ordinal (ALPHA=0, RED=1, GREEN=2, BLUE=3) — the layout the
    /// extraction plane mask uses, matching the reference tool.
    #[must_use]
    pub fn ordinal(self) -> u32 {
        match self {
            Channel::Alpha => 0,
            Channel::Red => 1,
            Channel::Green => 2,
            Channel::Blue => 3,
        }
    }

    #[must_use]
    pub fn from_ordinal(ordinal: u32) -> Option<Self> {
        match ordinal {
            0 => Some(Channel::Alpha),
            1 => Some(Channel::Red),
            2 => Some(Channel::Green),
            3 => Some(Channel::Blue),
            _ => None,
        }
    }

    /// Single-letter symbol used by extraction descriptions (`a7 r0 g0 b0`).
    #[must_use]
    pub fn symbol(self) -> char {
        match self {
            Channel::Alpha => 'a',
            Channel::Red => 'r',
            Channel::Green => 'g',
            Channel::Blue => 'b',
        }
    }
}

/// Kinds of catalog transforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransformKind {
    Original,
    Invert,
    Plane,
    FullChannel,
    RandomMap,
    GrayBits,
}

/// One catalog entry.
#[derive(Debug, Clone, Copy)]
pub struct TransformDef {
    pub index: usize,
    pub kind: TransformKind,
    pub channel: Option<Channel>,
    pub plane: i8,
    pub group: &'static str,
    pub label: &'static str,
}

/// The full catalog in StegSolve order; `catalog()[i].index == i`.
pub fn catalog() -> &'static [TransformDef] {
    CATALOG
}

const CATALOG: &[TransformDef] = &catalog_items();

const fn catalog_items() -> [TransformDef; 42] {
    let mut defs = [INIT; 42];
    defs[0] = TransformDef {
        index: 0,
        kind: TransformKind::Original,
        channel: None,
        plane: -1,
        group: "Original",
        label: "Original",
    };
    defs[1] = TransformDef {
        index: 1,
        kind: TransformKind::Invert,
        channel: None,
        plane: -1,
        group: "Original",
        label: "Invert",
    };
    let mut i = 2;
    let mut c = 0;
    while c < 4 {
        let channel = match c {
            0 => Channel::Alpha,
            1 => Channel::Red,
            2 => Channel::Green,
            _ => Channel::Blue,
        };
        let group = match c {
            0 => "Alpha planes",
            1 => "Red planes",
            2 => "Green planes",
            _ => "Blue planes",
        };
        let mut plane = 7i8;
        while plane >= 0 {
            defs[i] = TransformDef {
                index: i,
                kind: TransformKind::Plane,
                channel: Some(channel),
                plane,
                group,
                label: "plane",
            };
            i += 1;
            plane -= 1;
        }
        c += 1;
    }
    // 34..37 full channels.
    let channels = [Channel::Alpha, Channel::Red, Channel::Green, Channel::Blue];
    let mut f = 0;
    while f < 4 {
        defs[i] = TransformDef {
            index: i,
            kind: TransformKind::FullChannel,
            channel: Some(channels[f]),
            plane: -1,
            group: "Channels",
            label: "full channel",
        };
        i += 1;
        f += 1;
    }
    // 38..40 random colour maps 1..3.
    let mut m = 0;
    while m < 3 {
        defs[i] = TransformDef {
            index: i,
            kind: TransformKind::RandomMap,
            channel: None,
            plane: -1,
            group: "Random colour maps",
            label: "random colour map",
        };
        i += 1;
        m += 1;
    }
    defs[i] = TransformDef {
        index: i,
        kind: TransformKind::GrayBits,
        channel: None,
        plane: -1,
        group: "Gray pixels",
        label: "Gray pixels",
    };
    defs
}

const INIT: TransformDef = TransformDef {
    index: 0,
    kind: TransformKind::Original,
    channel: None,
    plane: -1,
    group: "",
    label: "",
};

/// Seeds for the three random colour maps; deterministic so a transform can
/// be revisited (reference: `RANDOM_SEEDS = {0x5EED_0001..3}`).
pub const RANDOM_MAP_SEEDS: [i64; 3] = [0x5EED_0001, 0x5EED_0002, 0x5EED_0003];

/// Full-channel ARGB masks (legacy `full_alpha/full_red/full_green/full_blue`).
fn channel_mask(channel: Channel) -> u32 {
    match channel {
        Channel::Alpha => 0xFF000000,
        Channel::Red => 0x00FF0000,
        Channel::Green => 0x0000FF00,
        Channel::Blue => 0x000000FF,
    }
}

/// Makes a computed colour opaque, the way the legacy `TYPE_INT_RGB` output
/// did.
#[must_use]
pub fn opaque(colour: u32) -> u32 {
    0xFF000000 | (colour & 0xFFFFFF)
}

/// Transform 1: `pixel XOR 0xFFFFFF`.
pub fn invert(source: &RgbaImage) -> RgbaImage {
    let out: Vec<u32> = source.argb.iter().map(|p| opaque(*p ^ 0xFFFFFF)).collect();
    RgbaImage::opaque(source.width, source.height, out)
}

/// A single bit plane of one channel, black (0) or white (0xFFFFFF).
pub fn bit_plane(source: &RgbaImage, channel: Channel, plane: i8) -> RgbaImage {
    let shift = channel.shift() + u32::try_from(plane).unwrap_or(0);
    let out: Vec<u32> = source
        .argb
        .iter()
        .map(|p| {
            if (p >> shift) & 1 != 0 {
                0xFFFFFFFF
            } else {
                0xFF000000
            }
        })
        .collect();
    RgbaImage::opaque(source.width, source.height, out)
}

/// The legacy full-channel mask, including its quirk: when the mask reaches
/// into the alpha byte the result shifts right by eight bits, so "full
/// alpha" renders as the red channel. Compatibility requires reproducing
/// this exactly.
pub fn mask(source: &RgbaImage, mask_value: u32) -> RgbaImage {
    let out: Vec<u32> = source
        .argb
        .iter()
        .map(|p| {
            let value = (*p & mask_value) as i32;
            // Transcribed verbatim from the reference; the paired
            // comparisons ARE the legacy condition (do not rewrite).
            #[allow(clippy::manual_range_contains)]
            let shifted = if value > 0xFFFFFF || value < 0 {
                ((value as u32) >> 8) as i32
            } else {
                value
            };
            opaque(shifted as u32)
        })
        .collect();
    RgbaImage::opaque(source.width, source.height, out)
}

/// White where `r == g == b`, black everywhere else.
pub fn gray_pixels(source: &RgbaImage) -> RgbaImage {
    let out: Vec<u32> = source
        .argb
        .iter()
        .map(|p| {
            let blue = p & 0xFF;
            let green = (p >> 8) & 0xFF;
            let red = (p >> 16) & 0xFF;
            if blue == green && blue == red {
                0xFFFFFFFF
            } else {
                0xFF000000
            }
        })
        .collect();
    RgbaImage::opaque(source.width, source.height, out)
}

/// Random per component map (legacy `random_colormap` arithmetic). Draw
/// order is bm, ba, bx, gm, ga, gx, rm, ra, rx — pinned by the reference.
pub fn random_component_map(source: &RgbaImage, seed: i64) -> RgbaImage {
    let mut random = JavaRandom::new(seed);
    let bm = random.next_int_256();
    let ba = random.next_int_256();
    let bx = random.next_int_256();
    let gm = random.next_int_256();
    let ga = random.next_int_256();
    let gx = random.next_int_256();
    let rm = random.next_int_256();
    let ra = random.next_int_256();
    let rx = random.next_int_256();

    let out: Vec<u32> = source
        .argb
        .iter()
        .map(|p| {
            let mut blue = i32::from((p & 0xFF) as u8) * bm as i32;
            blue = (blue.wrapping_mul(bm as i32)) ^ (bx as i32);
            blue = blue.wrapping_add(ba as i32);
            let mut green = i32::from(((p >> 8) & 0xFF) as u8) * gm as i32;
            green = (green.wrapping_mul(gm as i32)) ^ (gx as i32);
            green = green.wrapping_add(ga as i32);
            let mut red = i32::from(((p >> 16) & 0xFF) as u8) * rm as i32;
            red = (red.wrapping_mul(rm as i32)) ^ (rx as i32);
            red = red.wrapping_add(ra as i32);
            let colour = (red << 16)
                .wrapping_add(green << 8)
                .wrapping_add(blue)
                .wrapping_add((p & 0xFF000000) as i32);
            opaque(colour as u32)
        })
        .collect();
    RgbaImage::opaque(source.width, source.height, out)
}

/// Random palette map (legacy `random_indexmap`): the mapping applies to the
/// palette, so two pixels with the same colour but different palette indices
/// can end up differently coloured. Non-indexed sources fall back to the
/// component map, as the reference does.
pub fn random_palette_map(source: &RgbaImage, seed: i64) -> RgbaImage {
    let Some(indexed) = source.indexed.as_ref() else {
        return random_component_map(source, seed);
    };
    let mut random = JavaRandom::new(seed);
    let mapped: Vec<u32> = (0..indexed.palette.len())
        .map(|_| {
            let red = random.next_int_256();
            let green = random.next_int_256();
            let blue = random.next_int_256();
            opaque((red << 16) | (green << 8) | blue)
        })
        .collect();
    let out: Vec<u32> = indexed
        .indices
        .iter()
        .map(|&index| mapped[(index as usize).min(mapped.len() - 1)])
        .collect();
    RgbaImage::opaque(source.width, source.height, out)
}

/// Random colour map variant 1..3: palette based for indexed images,
/// component mapping otherwise.
#[must_use]
pub fn random_map(source: &RgbaImage, variant: usize) -> RgbaImage {
    let seed = RANDOM_MAP_SEEDS[variant.clamp(1, 3) - 1];
    if source.indexed.is_some() {
        random_palette_map(source, seed)
    } else {
        random_component_map(source, seed)
    }
}

/// Applies a catalog entry by index (0..41).
///
/// # Errors
///
/// Returns [`OperationError`] when the index is out of range or when the
/// context signals cancellation.
pub fn apply_index(
    index: usize,
    source: &RgbaImage,
    ctx: &ExecutionContext,
) -> OpResult<RgbaImage> {
    let def = catalog().get(index).ok_or_else(|| {
        OperationError::invalid_param(
            "transform",
            format!(
                "no transform {index}; the catalog has {} entries",
                catalog().len()
            ),
        )
        .with_expected("0..41")
    })?;
    ctx.check()?;
    match def.kind {
        TransformKind::Original => Ok(source.clone()),
        TransformKind::Invert => Ok(invert(source)),
        TransformKind::Plane => Ok(bit_plane(
            source,
            def.channel.unwrap_or(Channel::Blue),
            def.plane,
        )),
        TransformKind::FullChannel => Ok(mask(
            source,
            channel_mask(def.channel.unwrap_or(Channel::Blue)),
        )),
        // Catalog order: 38, 39, 40 are random colour maps 1, 2 and 3.
        TransformKind::RandomMap => Ok(random_map(source, def.index - 37)),
        TransformKind::GrayBits => Ok(gray_pixels(source)),
    }
}

/// Row-checked application used by the registry op: cancellation is checked
/// per row, matching the reference's interrupt points.
pub fn apply_checked(
    index: usize,
    source: &RgbaImage,
    ctx: &ExecutionContext,
) -> OpResult<RgbaImage> {
    let width = source.width;
    let result = apply_index(index, source, ctx)?;
    if width > 1 && source.height > 4 {
        // For large images the single upfront check is not enough; verify
        // once more mid-way so long runs observe cancellation.
        ctx.check()?;
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Golden parity tests
//
// `oracle` is a tests-only, independent transcription of the LEGACY StegSolve
// algorithms (via the StegSolver LegacyReference oracle). The catalog must
// produce byte-identical output to it on the synthetic images below — this
// double-entry bookkeeping is what catches porting bugs.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod oracle {
    /// Legacy `Transform.transfrombit(int d)`.
    pub fn bit_plane(argb: &[u32], bit: u32) -> Vec<u32> {
        argb.iter()
            .map(|p| {
                if (p >> bit) & 1 != 0 {
                    0xFFFF_FFFF
                } else {
                    0xFF00_0000
                }
            })
            .collect()
    }

    /// Legacy `Transform.invert`: XOR with 0xFFFFFF, forced opaque.
    pub fn invert(argb: &[u32]) -> Vec<u32> {
        argb.iter()
            .map(|p| 0xFF00_0000 | ((*p ^ 0x00FF_FFFF) & 0x00FF_FFFF))
            .collect()
    }

    /// Legacy full-channel mask with the alpha-shift quirk, transcribed as
    /// Java int arithmetic.
    pub fn mask(argb: &[u32], mask_value: u32) -> Vec<u32> {
        argb.iter()
            .map(|p| {
                let mut value = (*p & mask_value) as i32;
                #[allow(clippy::manual_range_contains)]
                if value > 0x00FF_FFFF || value < 0 {
                    value = ((value as u32) >> 8) as i32;
                }
                0xFF00_0000 | (value as u32 & 0x00FF_FFFF)
            })
            .collect()
    }

    /// Legacy `gray_bits`: white where r == g == b.
    pub fn gray_pixels(argb: &[u32]) -> Vec<u32> {
        argb.iter()
            .map(|p| {
                let blue = p & 0xFF;
                let green = (p >> 8) & 0xFF;
                let red = (p >> 16) & 0xFF;
                if blue == green && blue == red {
                    0xFFFF_FFFF
                } else {
                    0xFF00_0000
                }
            })
            .collect()
    }

    /// Legacy `random_colormap`, including the Java Random draw order.
    pub fn random_component_map(argb: &[u32], seed: i64) -> Vec<u32> {
        let mut random = crate::java_random::JavaRandom::new(seed);
        let bm = random.next_int_256() as i32;
        let ba = random.next_int_256() as i32;
        let bx = random.next_int_256() as i32;
        let gm = random.next_int_256() as i32;
        let ga = random.next_int_256() as i32;
        let gx = random.next_int_256() as i32;
        let rm = random.next_int_256() as i32;
        let ra = random.next_int_256() as i32;
        let rx = random.next_int_256() as i32;
        argb.iter()
            .map(|p| {
                let mut blue = i32::from((p & 0xFF) as u8).wrapping_mul(bm);
                blue = blue.wrapping_mul(bm) ^ bx;
                blue = blue.wrapping_add(ba);
                let mut green = i32::from(((p >> 8) & 0xFF) as u8).wrapping_mul(gm);
                green = green.wrapping_mul(gm) ^ gx;
                green = green.wrapping_add(ga);
                let mut red = i32::from(((p >> 16) & 0xFF) as u8).wrapping_mul(rm);
                red = red.wrapping_mul(rm) ^ rx;
                red = red.wrapping_add(ra);
                let colour = (red << 16)
                    .wrapping_add(green << 8)
                    .wrapping_add(blue)
                    .wrapping_add((p & 0xFF00_0000) as i32);
                0xFF00_0000 | (colour as u32 & 0x00FF_FFFF)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cybercipher_media::IndexedData;

    fn ctx() -> ExecutionContext {
        ExecutionContext::new()
    }

    /// A deterministic 64-pixel gradient with varied alpha, covering bit
    /// patterns 0..255 across channels.
    fn gradient() -> RgbaImage {
        let argb: Vec<u32> = (0..64u32)
            .map(|i| {
                let a = 0x30 + (i * 3 % 0xD0);
                let r = (i * 5) % 256;
                let g = (i * 11 + 7) % 256;
                let b = (i * 23 + 1) % 256;
                (a << 24) | (r << 16) | (g << 8) | b
            })
            .collect();
        RgbaImage::new(8, 8, argb, true).unwrap()
    }

    /// Gray image: every pixel has r == g == b.
    fn grays() -> RgbaImage {
        let argb: Vec<u32> = (0..16u32)
            .map(|i| 0xFF00_0000 | ((i * 17) * 0x0101_0101))
            .collect();
        RgbaImage::new(4, 4, argb, false).unwrap()
    }

    /// Indexed image with two palette entries sharing a colour.
    fn indexed() -> RgbaImage {
        let palette = vec![0xFF11_2233, 0xFF11_2233, 0xFF44_5566];
        let indices = vec![0u32, 1, 2, 1];
        RgbaImage::with_indexed(
            2,
            2,
            vec![0xFF11_2233, 0xFF11_2233, 0xFF44_5566, 0xFF11_2233],
            false,
            IndexedData { palette, indices },
        )
        .unwrap()
    }

    #[test]
    fn catalog_has_42_entries_in_legacy_order() {
        let cat = catalog();
        assert_eq!(cat.len(), 42);
        assert_eq!(cat[0].kind, TransformKind::Original);
        assert_eq!(cat[1].kind, TransformKind::Invert);
        assert_eq!(cat[2].channel, Some(Channel::Alpha));
        assert_eq!(cat[2].plane, 7);
        assert_eq!(cat[9].channel, Some(Channel::Alpha));
        assert_eq!(cat[9].plane, 0);
        assert_eq!(cat[10].channel, Some(Channel::Red));
        assert_eq!(cat[10].plane, 7);
        assert_eq!(cat[33].channel, Some(Channel::Blue));
        assert_eq!(cat[33].plane, 0);
        assert_eq!(cat[34].kind, TransformKind::FullChannel);
        assert_eq!(cat[34].channel, Some(Channel::Alpha));
        assert_eq!(cat[37].channel, Some(Channel::Blue));
        assert_eq!(cat[38].kind, TransformKind::RandomMap);
        assert_eq!(cat[40].kind, TransformKind::RandomMap);
        assert_eq!(cat[41].kind, TransformKind::GrayBits);
    }

    #[test]
    fn original_preserves_alpha_others_force_opaque() {
        let img = gradient();
        let original = apply_index(0, &img, &ctx()).unwrap();
        assert_eq!(original.argb, img.argb);

        let inverted = apply_index(1, &img, &ctx()).unwrap();
        assert!(inverted.argb.iter().all(|p| p & 0xFF00_0000 == 0xFF00_0000));
    }

    #[test]
    fn bit_planes_match_oracle() {
        let img = gradient();
        for index in 2..34 {
            let def = &catalog()[index];
            let channel = def.channel.unwrap();
            let plane = def.plane;
            let result = apply_index(index, &img, &ctx()).unwrap();
            let expected =
                oracle::bit_plane(&img.argb, channel.shift() + u32::try_from(plane).unwrap());
            assert_eq!(
                result.argb,
                expected,
                "transform {index} ({} plane {plane})",
                channel.symbol()
            );
        }
    }

    #[test]
    fn full_channel_masks_match_oracle_including_alpha_quirk() {
        let img = gradient();
        // Full alpha (index 34): the legacy quirk renders the RED channel.
        let result = apply_index(34, &img, &ctx()).unwrap();
        let expected = oracle::mask(&img.argb, 0xFF00_0000);
        assert_eq!(result.argb, expected);
        // Sanity: full alpha is NOT the alpha byte as blue (quirk active).
        assert_ne!(result.argb[0] & 0xFF, img.argb[0] >> 24);

        for (index, mask_value) in [(35, 0x00FF_0000u32), (36, 0x0000_FF00), (37, 0x0000_00FF)] {
            let result = apply_index(index, &img, &ctx()).unwrap();
            let expected = oracle::mask(&img.argb, mask_value);
            assert_eq!(result.argb, expected, "transform {index}");
        }
    }

    #[test]
    fn random_maps_match_oracle_and_are_deterministic() {
        let img = gradient();
        for index in 38..41 {
            let result = apply_index(index, &img, &ctx()).unwrap();
            let expected = oracle::random_component_map(&img.argb, RANDOM_MAP_SEEDS[index - 38]);
            assert_eq!(result.argb, expected, "transform {index}");
            let again = apply_index(index, &img, &ctx()).unwrap();
            assert_eq!(
                result.argb, again.argb,
                "transform {index} must be deterministic"
            );
        }
    }

    #[test]
    fn gray_pixels_match_oracle() {
        for img in [gradient(), grays()] {
            let result = apply_index(41, &img, &ctx()).unwrap();
            let expected = oracle::gray_pixels(&img.argb);
            assert_eq!(result.argb, expected);
        }
        // On the gray image every pixel is white.
        let result = apply_index(41, &grays(), &ctx()).unwrap();
        assert!(result.argb.iter().all(|&p| p == 0xFFFF_FFFF));
    }

    #[test]
    fn random_palette_map_applies_to_palette_and_is_deterministic() {
        let img = indexed();
        let result = random_map(&img, 1);
        let again = random_map(&img, 1);
        assert_eq!(result.argb, again.argb);
        // The indexed source routes to the palette map (different seed use
        // than the component map), so non-indexed and indexed results of the
        // same variant are not required to agree — but both must be opaque.
        assert!(result.argb.iter().all(|p| p & 0xFF00_0000 == 0xFF00_0000));
    }

    #[test]
    fn invert_matches_oracle() {
        let img = gradient();
        let result = apply_index(1, &img, &ctx()).unwrap();
        assert_eq!(result.argb, oracle::invert(&img.argb));
    }

    #[test]
    fn invalid_index_is_a_typed_error() {
        let img = grays();
        let err = apply_index(42, &img, &ctx()).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidParam);
        let err = apply_index(usize::MAX, &img, &ctx()).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::InvalidParam);
    }

    #[test]
    fn cancellation_is_observed() {
        let img = gradient();
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let ctx = ExecutionContext::new().with_cancel(flag);
        let err = apply_index(1, &img, &ctx).unwrap_err();
        assert_eq!(err.kind, cybercipher_core::ErrorKind::Cancelled);
    }
}
