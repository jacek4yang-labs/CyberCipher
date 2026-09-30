//! The pixel model: one non-premultiplied `0xAARRGGBB` [`u32`] per pixel in a
//! flat row-major buffer — the exact layout of the StegSolver `ImageData`
//! (reference commit `c14bfa9`), which in turn matches Java's
//! `BufferedImage.getRGB(int, int)`.
//!
//! For palette (indexed) sources the original palette indices are retained so
//! that the legacy "random colour map" transform can be applied to the
//! palette instead of to the resolved colours, which is observable when two
//! palette entries share the same colour.

use crate::error::MediaError;
use crate::roi::Roi;

/// Palette data of an indexed source: one ARGB [`u32`] per palette entry plus
/// one palette index per pixel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedData {
    /// Palette as `0xAARRGGBB` values (alpha `0xFF` unless the source carried
    /// per-entry transparency).
    pub palette: Vec<u32>,
    /// Palette index per pixel, row-major, `width * height` entries.
    pub indices: Vec<u32>,
}

/// The shared image representation of the steg/SSTV engines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RgbaImage {
    pub width: u32,
    pub height: u32,
    /// Non-premultiplied `0xAARRGGBB` per pixel, flat, row-major
    /// (`argb.len() == width * height`).
    pub argb: Vec<u32>,
    /// True when the source carried an alpha channel, even if every pixel is
    /// fully opaque.
    pub has_alpha: bool,
    /// Palette + per-pixel indices for indexed sources.
    pub indexed: Option<IndexedData>,
}

impl RgbaImage {
    /// Wraps an existing pixel buffer, validating dimensions.
    pub fn new(width: u32, height: u32, argb: Vec<u32>, has_alpha: bool) -> Result<Self, MediaError> {
        RgbaImage::build(width, height, argb, has_alpha, None)
    }

    /// Wraps an existing pixel buffer plus palette data, validating
    /// dimensions and index count.
    pub fn with_indexed(
        width: u32,
        height: u32,
        argb: Vec<u32>,
        has_alpha: bool,
        indexed: IndexedData,
    ) -> Result<Self, MediaError> {
        if indexed.indices.len() != argb.len() {
            return Err(MediaError::corrupt(format!(
                "index count {} does not match pixel count {}",
                indexed.indices.len(),
                argb.len()
            )));
        }
        RgbaImage::build(width, height, argb, has_alpha, Some(indexed))
    }

    fn build(
        width: u32,
        height: u32,
        argb: Vec<u32>,
        has_alpha: bool,
        indexed: Option<IndexedData>,
    ) -> Result<Self, MediaError> {
        if width == 0 || height == 0 {
            return Err(MediaError::corrupt(format!(
                "invalid image size: {width}x{height}"
            )));
        }
        // u32*u32 always fits u64, so the product itself cannot overflow.
        let expected = width as u64 * height as u64;
        if argb.len() as u64 != expected {
            return Err(MediaError::corrupt(format!(
                "pixel array length {} does not match {}x{}",
                argb.len(),
                width,
                height
            )));
        }
        Ok(RgbaImage {
            width,
            height,
            argb,
            has_alpha,
            indexed,
        })
    }

    /// Builds an image from a freshly computed pixel array. The caller
    /// guarantees the length; misuse is a programming error.
    pub(crate) fn opaque(width: u32, height: u32, argb: Vec<u32>) -> Self {
        debug_assert_eq!(argb.len(), width as usize * height as usize);
        RgbaImage {
            width,
            height,
            argb,
            has_alpha: false,
            indexed: None,
        }
    }

    pub fn pixel_count(&self) -> u64 {
        self.width as u64 * self.height as u64
    }

    /// The pixel at `(x, y)`, or `None` when out of bounds.
    pub fn pixel(&self, x: u32, y: u32) -> Option<u32> {
        if x >= self.width || y >= self.height {
            return None;
        }
        self.argb.get(y as usize * self.width as usize + x as usize)
            .copied()
    }

    /// Copies a rectangular region out of this image. The region is clamped
    /// to the image bounds first; a region that does not intersect the image
    /// is an error, mirroring the reference behaviour.
    pub fn crop(&self, roi: Roi) -> Result<RgbaImage, MediaError> {
        let clamped = roi.clamp_to(self.width, self.height);
        if clamped.is_empty() {
            return Err(MediaError::corrupt(format!(
                "crop region {} does not intersect {}x{}",
                roi.describe(),
                self.width,
                self.height
            )));
        }
        let area = clamped.area() as usize;
        let row_span = |indices: &Vec<u32>, y: u32| -> &[u32] {
            let start = y as usize * self.width as usize + clamped.x as usize;
            &indices[start..start + clamped.width as usize]
        };
        let mut out = Vec::with_capacity(area);
        for y in clamped.y..clamped.max_y() {
            out.extend_from_slice(row_span(&self.argb, y));
        }
        match &self.indexed {
            None => RgbaImage::new(clamped.width, clamped.height, out, self.has_alpha),
            Some(indexed) => {
                let mut indices = Vec::with_capacity(area);
                for y in clamped.y..clamped.max_y() {
                    indices.extend_from_slice(row_span(&indexed.indices, y));
                }
                RgbaImage::with_indexed(
                    clamped.width,
                    clamped.height,
                    out,
                    self.has_alpha,
                    IndexedData {
                        palette: indexed.palette.clone(),
                        indices,
                    },
                )
            }
        }
    }

    /// Estimated memory footprint of the pixel data in bytes (4 bytes per
    /// pixel plus 4 bytes per palette entry and per index).
    pub fn estimated_bytes(&self) -> u64 {
        let mut bytes = 4u64 * self.argb.len() as u64;
        if let Some(indexed) = &self.indexed {
            bytes += 4u64 * indexed.indices.len() as u64;
            bytes += 4u64 * indexed.palette.len() as u64;
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RgbaImage {
        // 2x2: 0x10203040 0xA0B0C0D0 / 0xFF00FF00 0x01020304
        RgbaImage::new(
            2,
            2,
            vec![0x10203040, 0xA0B0C0D0, 0xFF00FF00, 0x01020304],
            true,
        )
        .unwrap()
    }

    #[test]
    fn constructor_validates_dimensions_and_length() {
        assert!(RgbaImage::new(0, 4, vec![0; 4], false).is_err());
        assert!(RgbaImage::new(4, 0, vec![0; 4], false).is_err());
        assert!(RgbaImage::new(2, 2, vec![0; 3], false).is_err());
        assert!(RgbaImage::new(2, 2, vec![0; 5], false).is_err());
        // u32::MAX x u32::MAX must be rejected without overflowing the math.
        let huge = RgbaImage::new(u32::MAX, u32::MAX, vec![0; 4], false);
        assert!(huge.is_err());
        assert!(RgbaImage::new(2, 2, vec![1, 2, 3, 4], false).is_ok());
    }

    #[test]
    fn with_indexed_validates_index_count() {
        let indexed = IndexedData {
            palette: vec![0xFF000000],
            indices: vec![0, 0, 0],
        };
        assert!(RgbaImage::with_indexed(2, 2, vec![0; 4], false, indexed).is_err());
        let indexed = IndexedData {
            palette: vec![0xFF000000],
            indices: vec![0, 0, 0, 0],
        };
        assert!(RgbaImage::with_indexed(2, 2, vec![0; 4], false, indexed).is_ok());
    }

    #[test]
    fn pixel_reads_row_major() {
        let img = sample();
        assert_eq!(img.pixel(0, 0), Some(0x10203040));
        assert_eq!(img.pixel(1, 0), Some(0xA0B0C0D0));
        assert_eq!(img.pixel(0, 1), Some(0xFF00FF00));
        assert_eq!(img.pixel(1, 1), Some(0x01020304));
        assert_eq!(img.pixel(2, 0), None);
        assert_eq!(img.pixel(0, 2), None);
        assert_eq!(img.pixel_count(), 4);
    }

    #[test]
    fn crop_clamps_and_keeps_palette() {
        let indexed = IndexedData {
            palette: vec![0xFF112233, 0xFF445566],
            indices: vec![0, 1, 1, 0, 0, 0, 1, 1, 1],
        };
        let img = RgbaImage::with_indexed(3, 3, vec![0; 9], true, indexed).unwrap();
        let crop = img.crop(Roi::new(1, 1, 9, 9)).unwrap();
        assert_eq!((crop.width, crop.height), (2, 2));
        assert_eq!(crop.indexed.as_ref().unwrap().indices, vec![0, 0, 1, 1]);
        assert_eq!(crop.indexed.as_ref().unwrap().palette.len(), 2);
        assert!(img.crop(Roi::new(5, 5, 2, 2)).is_err());
    }

    #[test]
    fn estimated_bytes_counts_indices_and_palette() {
        let img = sample();
        assert_eq!(img.estimated_bytes(), 16);
        let indexed = IndexedData {
            palette: vec![0xFF000000; 4],
            indices: vec![0; 4],
        };
        let img = RgbaImage::with_indexed(2, 2, vec![0; 4], false, indexed).unwrap();
        assert_eq!(img.estimated_bytes(), 16 + 16 + 16);
    }
}
