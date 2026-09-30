//! PNG encoding of computed images.
//!
//! Transforms, extraction previews and decoded SSTV frames all produce
//! [`RgbaImage`] buffers; this is the single serialization path back to
//! bytes. Output is 8-bit truecolor RGB, or RGBA when the image carries an
//! alpha channel. Palette data is intentionally not re-emitted: computed
//! images (bit planes, masks, combined frames) are always opaque RGB in the
//! reference model.

use crate::error::MediaError;
use crate::image::RgbaImage;
use image::codecs::png::PngEncoder;
use image::{ExtendedColorType, ImageEncoder};

/// Encodes an image as PNG bytes.
pub fn encode_png(source: &RgbaImage) -> Result<Vec<u8>, MediaError> {
    let color = if source.has_alpha {
        ExtendedColorType::Rgba8
    } else {
        ExtendedColorType::Rgb8
    };
    let mut rgba: Vec<u8> = Vec::with_capacity(source.argb.len() * 4);
    for &argb in &source.argb {
        let a = ((argb >> 24) & 0xFF) as u8;
        let r = ((argb >> 16) & 0xFF) as u8;
        let g = ((argb >> 8) & 0xFF) as u8;
        let b = (argb & 0xFF) as u8;
        if source.has_alpha {
            rgba.extend_from_slice(&[r, g, b, a]);
        } else {
            rgba.extend_from_slice(&[r, g, b]);
        }
    }
    let mut out = Vec::new();
    PngEncoder::new(&mut out)
        .write_image(&rgba, source.width, source.height, color)
        .map_err(|e| MediaError::Io {
            detail: format!("PNG encode failed: {e}"),
        })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{decode, DecodeLimits};

    #[test]
    fn encode_png_roundtrips_through_decode() {
        // Opaque images are encoded as RGB: alpha is normalized to 0xFF on
        // the roundtrip (an input alpha byte below 0xFF is not preserved).
        let img = RgbaImage::new(
            2,
            2,
            vec![0xFF102030, 0xFFA0B0C0, 0xFF00FF00, 0xFF010203],
            false,
        )
        .unwrap();
        let bytes = encode_png(&img).unwrap();
        let decoded = decode(&bytes, &DecodeLimits::default()).unwrap();
        assert_eq!(decoded.width, 2);
        assert_eq!(decoded.height, 2);
        assert!(!decoded.has_alpha);
        assert_eq!(
            decoded.argb,
            vec![0xFF102030, 0xFFA0B0C0, 0xFF00FF00, 0xFF010203]
        );
    }

    #[test]
    fn encode_png_keeps_alpha_when_present() {
        let img = RgbaImage::new(1, 1, vec![0x40102030], true).unwrap();
        let bytes = encode_png(&img).unwrap();
        let decoded = decode(&bytes, &DecodeLimits::default()).unwrap();
        assert!(decoded.has_alpha);
        assert_eq!(decoded.argb, vec![0x40102030]);
    }
}
