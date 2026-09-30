//! Bounded decoding of untrusted image bytes.
//!
//! Caps are enforced **before** any pixel buffer is allocated: the file-size
//! cap applies to the input bytes, and the pixel-count cap is validated
//! against the header dimensions (which are untrusted) together with the
//! buffer-math overflow check. PNG is first-class: indexed (palette) PNGs
//! keep their palette + per-pixel indices so the legacy random palette map
//! stays observable. JPEG/GIF/BMP/WebP decode best-effort through the `image`
//! crate.

use crate::error::MediaError;
use crate::image::{IndexedData, RgbaImage};
use std::io::Cursor;

/// Resource caps for decoding untrusted images.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeLimits {
    /// Maximum encoded input size in bytes.
    pub max_file_bytes: u64,
    /// Maximum pixel count (`width * height`) accepted after header parse.
    pub max_pixels: u64,
}

impl DecodeLimits {
    /// 256 MiB of encoded input.
    pub const DEFAULT_MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
    /// 64 megapixels.
    pub const DEFAULT_MAX_PIXELS: u64 = 64 * 1024 * 1024;
}

impl Default for DecodeLimits {
    fn default() -> Self {
        DecodeLimits {
            max_file_bytes: DecodeLimits::DEFAULT_MAX_FILE_BYTES,
            max_pixels: DecodeLimits::DEFAULT_MAX_PIXELS,
        }
    }
}

/// Decodes an image from raw bytes under the given limits.
///
/// The format is sniffed from the magic bytes; anything outside PNG, JPEG,
/// GIF, BMP and WebP is rejected as unsupported. Every failure is a typed
/// [`MediaError`] — malformed input never panics.
pub fn decode(bytes: &[u8], limits: &DecodeLimits) -> Result<RgbaImage, MediaError> {
    // Cap 1: input size, before anything else touches the bytes.
    if bytes.len() as u64 > limits.max_file_bytes {
        return Err(MediaError::too_large(
            "file size",
            limits.max_file_bytes,
            bytes.len() as u64,
        ));
    }

    let format = image::guess_format(bytes)
        .map_err(|_| MediaError::unsupported_format("unrecognized image magic"))?;
    let supported = matches!(
        format,
        image::ImageFormat::Png
            | image::ImageFormat::Jpeg
            | image::ImageFormat::Gif
            | image::ImageFormat::Bmp
            | image::ImageFormat::WebP
    );
    if !supported {
        return Err(MediaError::unsupported_format(format!("{format:?}")));
    }

    // Cap 2: header dimensions against the pixel cap, before allocation.
    let mut header = image::ImageReader::new(Cursor::new(bytes));
    header.set_format(format);
    let (width, height) = header
        .into_dimensions()
        .map_err(map_image_error)?;
    if width == 0 || height == 0 {
        return Err(MediaError::corrupt(format!("zero dimension {width}x{height}")));
    }
    let pixels = (width as u64).checked_mul(height as u64).ok_or_else(|| {
        MediaError::too_large("pixel count", limits.max_pixels, u64::MAX)
    })?;
    if pixels > limits.max_pixels {
        return Err(MediaError::too_large(
            "pixel count",
            limits.max_pixels,
            pixels,
        ));
    }

    // Decode the resolved pixels through the `image` crate.
    let mut reader = image::ImageReader::new(Cursor::new(bytes));
    reader.set_format(format);
    let decoded = reader.decode().map_err(map_image_error)?;
    let mut has_alpha = color_type_has_alpha(decoded.color());
    let rgba = decoded.to_rgba8();
    let mut argb = Vec::with_capacity(rgba.pixels().len());
    for p in rgba.pixels() {
        argb.push(
            ((p[3] as u32) << 24)
                | ((p[0] as u32) << 16)
                | ((p[1] as u32) << 8)
                | (p[2] as u32),
        );
    }

    // First-class indexed PNG: attach palette + per-pixel indices.
    let indexed = if format == image::ImageFormat::Png {
        decode_png_indexed(bytes)?
    } else {
        None
    };
    if let Some((indexed_data, has_trns)) = &indexed {
        if *has_trns {
            has_alpha = true;
        }
        RgbaImage::with_indexed(width, height, argb, has_alpha, indexed_data.clone())
    } else {
        RgbaImage::new(width, height, argb, has_alpha)
    }
}

/// The `image` crate does not expose the PNG palette or per-pixel indices, so
/// the indexed path reads them with the `png` crate (already in the tree via
/// image's `png` feature). Returns `None` for non-indexed PNGs.
fn decode_png_indexed(bytes: &[u8]) -> Result<Option<(IndexedData, bool)>, MediaError> {
    let decoder = png::Decoder::new(Cursor::new(bytes));
    let mut reader = decoder
        .read_info()
        .map_err(map_png_error)?
        .try_into()
        .map_err(|_| MediaError::corrupt("png reader unavailable"))?;
    let info = reader.info().clone();
    if info.color_type != png::ColorType::Indexed {
        return Ok(None);
    }
    if info.width == 0 || info.height == 0 {
        return Ok(None);
    }
    let width = info.width as usize;
    let height = info.height as usize;
    let bit_depth = info.bit_depth as usize;
    let mut buf = vec![0u8; reader.output_buffer_size()];
    reader
        .next_frame(&mut buf)
        .map_err(map_png_error)?;

    // Palette: RGB triples, with per-entry alpha from tRNS when present
    // (entries beyond tRNS are fully opaque, per the PNG specification).
    let raw_palette = info.palette.clone().unwrap_or_default();
    let trns = info.trns.clone().unwrap_or_default();
    let entry_count = raw_palette.len() / 3;
    let mut palette = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let r = raw_palette[i * 3] as u32;
        let g = raw_palette[i * 3 + 1] as u32;
        let b = raw_palette[i * 3 + 2] as u32;
        let a = trns.get(i).copied().unwrap_or(0xFF) as u32;
        palette.push((a << 24) | (r << 16) | (g << 8) | b);
    }

    // Indices: one palette index per pixel. Sub-byte bit depths (1/2/4) are
    // packed MSB-first within each row; the `png` crate has already
    // de-interlaced the frame for us.
    let line_bytes = reader.output_line_size(info.width);
    let mut indices = Vec::with_capacity(width * height);
    for row in 0..height {
        let line = &buf[row * line_bytes..(row + 1) * line_bytes];
        if bit_depth == 8 {
            indices.extend(line.iter().take(width).map(|&b| b as u32));
        } else {
            for x in 0..width {
                let bit_pos = x * bit_depth;
                let byte = line[bit_pos / 8] as u32;
                let shift = 8 - bit_depth - (bit_pos % 8);
                let mask = (1u32 << bit_depth) - 1;
                indices.push((byte >> shift) & mask);
            }
        }
    }

    let has_trns = !trns.is_empty();
    Ok(Some((
        IndexedData {
            palette,
            indices,
        },
        has_trns,
    )))
}

fn map_image_error(err: image::ImageError) -> MediaError {
    match err {
        image::ImageError::Io(e) => MediaError::Io {
            detail: e.to_string(),
        },
        image::ImageError::Unsupported(u) => MediaError::UnsupportedFormat {
            detail: u.to_string(),
        },
        other => MediaError::Corrupt {
            detail: other.to_string(),
        },
    }
}

fn map_png_error(err: png::DecodingError) -> MediaError {
    if let png::DecodingError::IoError(e) = err {
        MediaError::Io {
            detail: e.to_string(),
        }
    } else {
        MediaError::Corrupt {
            detail: err.to_string(),
        }
    }
}

/// Whether a decoded colour type carries an alpha channel (even if every
/// pixel is opaque).
fn color_type_has_alpha(color: image::ColorType) -> bool {
    matches!(
        color,
        image::ColorType::La8
            | image::ColorType::La16
            | image::ColorType::Rgba8
            | image::ColorType::Rgba16
            | image::ColorType::Rgba32F
    )
}
