//! CyberCipher media: the shared image representation and bounded
//! decode/encode path used by the steganography and SSTV engines.
//!
//! The pixel model is a 1:1 port of the StegSolver `ImageData` layout
//! (reference commit `c14bfa9`, MIT): a width, a height and one
//! non-premultiplied `0xAARRGGBB` [`u32`] per pixel in a flat row-major
//! [`Vec`] — the same layout as Java's `BufferedImage.getRGB`. Keeping the
//! layout identical is what lets golden parity tests transfer from the
//! reference implementation.
//!
//! Untrusted input is hostile: [`decode`] enforces a file-size cap and a
//! pixel-count cap **before** any pixel buffer is allocated, validates header
//! dimensions against both caps and buffer math overflow, and maps every
//! failure to a typed [`MediaError`] — it never panics on malformed input.

mod decode;
mod encode;
mod error;
mod image;
mod roi;

pub use decode::{decode, DecodeLimits};
pub use encode::encode_png;
pub use error::MediaError;
pub use image::{IndexedData, RgbaImage};
pub use roi::Roi;
