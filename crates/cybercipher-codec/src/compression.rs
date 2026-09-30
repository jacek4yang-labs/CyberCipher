//! Compression decoding operations (gzip/zlib/raw deflate), used directly by
//! recipes and by the Auto Decode candidate engine.

use crate::helpers::{input_bytes, p_bool, spec};
use cybercipher_core::prelude::*;
use std::io::Read;

/// Decompressed-output cap for interactive use (64 MiB).
pub(crate) const DECOMPRESS_LIMIT: usize = 64 * 1024 * 1024;

/// Maximum tolerated expansion ratio. Once the compressed payload is at
/// least [`RATIO_FLOOR`] bytes, an output larger than this multiple of the
/// compressed size is rejected as a probable decompression bomb.
pub(crate) const BOMB_RATIO: usize = 100;

/// Ratio checks below this compressed-size floor are skipped: tiny payloads
/// compress extremely well (a few bytes can legitimately expand 1000x), so
/// the ratio heuristic is only meaningful once the payload is substantial.
const RATIO_FLOOR: usize = 1024;

/// Reject implausible expansion before returning decompressed bytes.
pub(crate) fn check_bomb_ratio(
    compressed_len: usize,
    out_len: usize,
    format: &str,
) -> OpResult<()> {
    if compressed_len >= RATIO_FLOOR && out_len > BOMB_RATIO * compressed_len {
        return Err(OperationError::new(
            ErrorKind::BudgetExceeded,
            format!(
                "{format} expansion exceeds {BOMB_RATIO}x — refusing probable decompression bomb"
            ),
        )
        .with_expected(format!("at most {BOMB_RATIO}x expansion"))
        .with_actual(format!(
            "{out_len} bytes from {compressed_len} compressed bytes"
        )));
    }
    Ok(())
}

/// Read a decompressor stream to the end under the output cap, then apply
/// the bomb-ratio rejection. Reads one byte past the cap so truncation is
/// detected instead of silently accepted.
pub(crate) fn decompress_capped<R: Read>(
    reader: R,
    compressed_len: usize,
    format: &str,
) -> OpResult<Vec<u8>> {
    let mut out = Vec::new();
    reader
        .take(DECOMPRESS_LIMIT as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| OperationError::decode(format!("{format} decompression failed: {e}")))?;
    if out.len() > DECOMPRESS_LIMIT {
        return Err(OperationError::new(
            ErrorKind::BudgetExceeded,
            format!("{format} output exceeds the decompression safety cap"),
        )
        .with_expected(format!("at most {DECOMPRESS_LIMIT} decompressed bytes"))
        .with_actual(format!("more than {DECOMPRESS_LIMIT} bytes")));
    }
    check_bomb_ratio(compressed_len, out.len(), format)?;
    Ok(out)
}

pub fn gunzip(data: &[u8]) -> OpResult<Vec<u8>> {
    let decoder = flate2::read::MultiGzDecoder::new(data);
    let out = decompress_capped(decoder, data.len(), "gzip")?;
    Ok(out)
}

pub fn zlib_decompress(data: &[u8]) -> OpResult<Vec<u8>> {
    let mut decoder = flate2::read::ZlibDecoder::new(data);
    let out = decompress_capped(&mut decoder, data.len(), "zlib")?;
    Ok(out)
}

pub fn raw_deflate(data: &[u8]) -> OpResult<Vec<u8>> {
    let mut decoder = flate2::read::DeflateDecoder::new(data);
    let out = decompress_capped(&mut decoder, data.len(), "deflate")?;
    Ok(out)
}

fn gunzip_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "From Gzip")?;
    if bytes.len() < 2 || bytes[0] != 0x1f || bytes[1] != 0x8b {
        return Err(OperationError::decode("input is not gzip data")
            .with_expected("gzip magic 1f 8b")
            .with_actual(if bytes.is_empty() {
                "empty input".to_string()
            } else {
                format!("{:02x} {:02x}", bytes[0], bytes[1])
            }));
    }
    Ok(Value::from_bytes(gunzip(bytes.as_ref())?))
}

fn zlib_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "From Zlib")?;
    if bytes.len() < 2 || bytes[0] != 0x78 {
        return Err(OperationError::decode("input does not look like zlib data")
            .with_expected("zlib header byte 0x78")
            .with_actual(if bytes.is_empty() {
                "empty input".to_string()
            } else {
                format!("{:02x}", bytes[0])
            }));
    }
    Ok(Value::from_bytes(zlib_decompress(bytes.as_ref())?))
}

fn deflate_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "From Raw Deflate")?;
    Ok(Value::from_bytes(raw_deflate(bytes.as_ref())?))
}

/// Compression *encoding* op (To Gzip) so round-trips and tests are possible.
fn gzip_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Gzip")?;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(bytes.as_ref())
        .map_err(|e| OperationError::internal(format!("gzip failed: {e}")))?;
    Ok(Value::from_bytes(encoder.finish().map_err(|e| {
        OperationError::internal(format!("gzip failed: {e}"))
    })?))
}

/// Compression *encoding* op (To Zlib).
fn zlib_compress(data: &[u8]) -> OpResult<Vec<u8>> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| OperationError::internal(format!("zlib failed: {e}")))?;
    encoder
        .finish()
        .map_err(|e| OperationError::internal(format!("zlib failed: {e}")))
}

fn zlib_encode_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Zlib")?;
    Ok(Value::from_bytes(zlib_compress(bytes.as_ref())?))
}

/// Compression *encoding* op (To Deflate): raw DEFLATE stream, no wrapper.
fn deflate_compress(data: &[u8]) -> OpResult<Vec<u8>> {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| OperationError::internal(format!("deflate failed: {e}")))?;
    encoder
        .finish()
        .map_err(|e| OperationError::internal(format!("deflate failed: {e}")))
}

fn deflate_encode_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Deflate")?;
    Ok(Value::from_bytes(deflate_compress(bytes.as_ref())?))
}

// ---------------------------------------------------------------------------
// bzip2
// ---------------------------------------------------------------------------

fn bzip2_decompress(data: &[u8]) -> OpResult<Vec<u8>> {
    let decoder = bzip2::read::BzDecoder::new(data);
    decompress_capped(decoder, data.len(), "bzip2")
}

fn bzip2_compress(data: &[u8]) -> OpResult<Vec<u8>> {
    let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| OperationError::internal(format!("bzip2 failed: {e}")))?;
    encoder
        .finish()
        .map_err(|e| OperationError::internal(format!("bzip2 failed: {e}")))
}

/// Validate the bzip2 stream header: `BZh` followed by a level digit 1-9.
fn require_bzip2_magic(bytes: &[u8]) -> OpResult<()> {
    if bytes.len() < 4 || &bytes[..3] != b"BZh" || !bytes[3].is_ascii_digit() || bytes[3] == b'0' {
        return Err(OperationError::decode("input is not bzip2 data")
            .with_expected("bzip2 magic 'BZh' plus level digit 1-9")
            .with_actual(if bytes.is_empty() {
                "empty input".to_string()
            } else {
                let head: Vec<String> = bytes.iter().take(4).map(|b| format!("{b:02x}")).collect();
                head.join(" ")
            }));
    }
    Ok(())
}

fn from_bzip2_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "From Bzip2")?;
    require_bzip2_magic(bytes.as_ref())?;
    Ok(Value::from_bytes(bzip2_decompress(bytes.as_ref())?))
}

fn to_bzip2_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Bzip2")?;
    Ok(Value::from_bytes(bzip2_compress(bytes.as_ref())?))
}

// ---------------------------------------------------------------------------
// xz
// ---------------------------------------------------------------------------

const XZ_MAGIC: [u8; 6] = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];

fn xz_decompress(data: &[u8]) -> OpResult<Vec<u8>> {
    // Multi-decoder also accepts concatenated .xz streams.
    let decoder = xz2::read::XzDecoder::new_multi_decoder(data);
    decompress_capped(decoder, data.len(), "xz")
}

fn xz_compress(data: &[u8]) -> OpResult<Vec<u8>> {
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
    encoder
        .write_all(data)
        .map_err(|e| OperationError::internal(format!("xz failed: {e}")))?;
    encoder
        .finish()
        .map_err(|e| OperationError::internal(format!("xz failed: {e}")))
}

fn require_xz_magic(bytes: &[u8]) -> OpResult<()> {
    if bytes.len() < XZ_MAGIC.len() || bytes[..XZ_MAGIC.len()] != XZ_MAGIC {
        return Err(OperationError::decode("input is not xz data")
            .with_expected("xz magic fd 37 7a 58 5a 00")
            .with_actual(if bytes.is_empty() {
                "empty input".to_string()
            } else {
                let head: Vec<String> = bytes
                    .iter()
                    .take(XZ_MAGIC.len())
                    .map(|b| format!("{b:02x}"))
                    .collect();
                head.join(" ")
            }));
    }
    Ok(())
}

fn from_xz_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "From Xz")?;
    require_xz_magic(bytes.as_ref())?;
    Ok(Value::from_bytes(xz_decompress(bytes.as_ref())?))
}

fn to_xz_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Xz")?;
    Ok(Value::from_bytes(xz_compress(bytes.as_ref())?))
}

// ---------------------------------------------------------------------------
// zstd
// ---------------------------------------------------------------------------

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

fn zstd_decompress(data: &[u8]) -> OpResult<Vec<u8>> {
    let decoder = zstd::stream::read::Decoder::new(data)
        .map_err(|e| OperationError::decode(format!("zstd decoder setup failed: {e}")))?;
    decompress_capped(decoder, data.len(), "zstd")
}

fn zstd_compress(data: &[u8]) -> OpResult<Vec<u8>> {
    zstd::stream::encode_all(data, 3)
        .map_err(|e| OperationError::internal(format!("zstd failed: {e}")))
}

fn require_zstd_magic(bytes: &[u8]) -> OpResult<()> {
    if bytes.len() < ZSTD_MAGIC.len() || bytes[..ZSTD_MAGIC.len()] != ZSTD_MAGIC {
        return Err(OperationError::decode("input is not zstd data")
            .with_expected("zstd magic 28 b5 2f fd")
            .with_actual(if bytes.is_empty() {
                "empty input".to_string()
            } else {
                let head: Vec<String> = bytes
                    .iter()
                    .take(ZSTD_MAGIC.len())
                    .map(|b| format!("{b:02x}"))
                    .collect();
                head.join(" ")
            }));
    }
    Ok(())
}

fn from_zstd_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "From Zstd")?;
    require_zstd_magic(bytes.as_ref())?;
    Ok(Value::from_bytes(zstd_decompress(bytes.as_ref())?))
}

fn to_zstd_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Zstd")?;
    Ok(Value::from_bytes(zstd_compress(bytes.as_ref())?))
}

// ---------------------------------------------------------------------------
// lz4 (frame format)
// ---------------------------------------------------------------------------

const LZ4_FRAME_MAGIC: [u8; 4] = [0x04, 0x22, 0x4D, 0x18];

fn lz4_decompress(data: &[u8]) -> OpResult<Vec<u8>> {
    let decoder = lz4_flex::frame::FrameDecoder::new(data);
    decompress_capped(decoder, data.len(), "lz4")
}

fn lz4_compress(data: &[u8]) -> OpResult<Vec<u8>> {
    let mut encoder = lz4_flex::frame::FrameEncoder::new(Vec::new());
    encoder
        .write_all(data)
        .map_err(|e| OperationError::internal(format!("lz4 failed: {e}")))?;
    encoder
        .finish()
        .map_err(|e| OperationError::internal(format!("lz4 failed: {e}")))
}

fn require_lz4_magic(bytes: &[u8]) -> OpResult<()> {
    if bytes.len() < LZ4_FRAME_MAGIC.len() || bytes[..LZ4_FRAME_MAGIC.len()] != LZ4_FRAME_MAGIC {
        return Err(OperationError::decode("input is not lz4 frame data")
            .with_expected("lz4 frame magic 04 22 4d 18")
            .with_actual(if bytes.is_empty() {
                "empty input".to_string()
            } else {
                let head: Vec<String> = bytes
                    .iter()
                    .take(LZ4_FRAME_MAGIC.len())
                    .map(|b| format!("{b:02x}"))
                    .collect();
                head.join(" ")
            }));
    }
    Ok(())
}

fn from_lz4_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "From Lz4")?;
    require_lz4_magic(bytes.as_ref())?;
    Ok(Value::from_bytes(lz4_decompress(bytes.as_ref())?))
}

fn to_lz4_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Lz4")?;
    Ok(Value::from_bytes(lz4_compress(bytes.as_ref())?))
}

// ---------------------------------------------------------------------------
// brotli (no magic number — decoding trusts the input, like CyberChef)
// ---------------------------------------------------------------------------

fn brotli_decompress(data: &[u8]) -> OpResult<Vec<u8>> {
    let decoder = brotli::Decompressor::new(data, 4096);
    decompress_capped(decoder, data.len(), "brotli")
}

fn brotli_compress(data: &[u8]) -> OpResult<Vec<u8>> {
    let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 5, 22);
    encoder
        .write_all(data)
        .map_err(|e| OperationError::internal(format!("brotli failed: {e}")))?;
    Ok(encoder.into_inner())
}

fn from_brotli_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "From Brotli")?;
    Ok(Value::from_bytes(brotli_decompress(bytes.as_ref())?))
}

fn to_brotli_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Brotli")?;
    Ok(Value::from_bytes(brotli_compress(bytes.as_ref())?))
}

use std::io::Write;

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    use cybercipher_core::{
        Category::Compression as C,
        ValueKind::{Bytes as B, Text as T},
    };

    let tags: &'static [&'static str] = &["compression", "ctf"];

    reg.add_simple(
        spec(
            "from-gzip",
            "From Gzip",
            "Decompresses gzip data (multi-member aware).",
            C,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![p_bool(
                "raw_output",
                "Raw bytes output",
                true,
                "Keep decompressed bytes as-is.",
            )],
            tags,
            &["gunzip", "ungzip"],
            "RFC 1952 (GZIP)",
            "Round-trip + magic-detection tests",
        ),
        gunzip_op,
    );

    reg.add_simple(
        spec(
            "from-zlib",
            "From Zlib",
            "Decompresses zlib-wrapped deflate data.",
            C,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["inflate", "zlib decode"],
            "RFC 1950 (ZLIB)",
            "Round-trip tests",
        ),
        zlib_op,
    );

    reg.add_simple(
        spec(
            "from-raw-deflate",
            "From Raw Deflate",
            "Decompresses raw DEFLATE streams (no wrapper).",
            C,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["deflate decode"],
            "RFC 1951 (DEFLATE)",
            "Round-trip tests",
        ),
        deflate_op,
    );

    reg.add_simple(
        spec(
            "to-gzip",
            "To Gzip",
            "Compresses bytes into a gzip stream.",
            C,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["gzip compress"],
            "RFC 1952 (GZIP)",
            "Round-trip tests",
        ),
        gzip_op,
    );

    reg.add_simple(
        spec(
            "to-zlib",
            "To Zlib",
            "Compresses bytes into a zlib-wrapped deflate stream.",
            C,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["zlib compress", "zlib encode"],
            "RFC 1950 (ZLIB)",
            "Round-trip tests",
        ),
        zlib_encode_op,
    );

    reg.add_simple(
        spec(
            "to-deflate",
            "To Deflate",
            "Compresses bytes into a raw DEFLATE stream (no zlib/gzip wrapper).",
            C,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["to-raw-deflate", "deflate compress"],
            "RFC 1951 (DEFLATE)",
            "Round-trip tests",
        ),
        deflate_encode_op,
    );

    reg.add_simple(
        spec(
            "from-bzip2",
            "From Bzip2",
            "Decompresses bzip2 data.",
            C,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["bunzip2", "bzip2 decode"],
            "bzip2 stream format (J. Seward, de facto)",
            "Round-trip + magic tests (python bz2 reference)",
        ),
        from_bzip2_op,
    );

    reg.add_simple(
        spec(
            "to-bzip2",
            "To Bzip2",
            "Compresses bytes into a bzip2 stream.",
            C,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["bzip2 compress"],
            "bzip2 stream format (J. Seward, de facto)",
            "Round-trip + magic tests",
        ),
        to_bzip2_op,
    );

    reg.add_simple(
        spec(
            "from-xz",
            "From Xz",
            "Decompresses .xz data (concatenated-stream aware).",
            C,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["unxz", "xz decode", "lzma2"],
            "The .xz file format v1.0.4 (XZ Utils)",
            "Round-trip + magic tests (python lzma reference)",
        ),
        from_xz_op,
    );

    reg.add_simple(
        spec(
            "to-xz",
            "To Xz",
            "Compresses bytes into an .xz stream (LZMA2, preset 6).",
            C,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["xz compress"],
            "The .xz file format v1.0.4 (XZ Utils)",
            "Round-trip + magic tests",
        ),
        to_xz_op,
    );

    reg.add_simple(
        spec(
            "from-zstd",
            "From Zstd",
            "Decompresses Zstandard data.",
            C,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["zstandard decode", "unzstd"],
            "Zstandard frame format (RFC 8878)",
            "Round-trip + magic tests",
        ),
        from_zstd_op,
    );

    reg.add_simple(
        spec(
            "to-zstd",
            "To Zstd",
            "Compresses bytes into a Zstandard stream (level 3).",
            C,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["zstandard compress", "zstd encode"],
            "Zstandard frame format (RFC 8878)",
            "Round-trip tests",
        ),
        to_zstd_op,
    );

    reg.add_simple(
        spec(
            "from-lz4",
            "From Lz4",
            "Decompresses LZ4 frame-format data.",
            C,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["lz4 decode", "unlz4"],
            "LZ4 Frame format v1.6.3",
            "Round-trip + magic tests",
        ),
        from_lz4_op,
    );

    reg.add_simple(
        spec(
            "to-lz4",
            "To Lz4",
            "Compresses bytes into an LZ4 frame stream.",
            C,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["lz4 compress", "lz4 encode"],
            "LZ4 Frame format v1.6.3",
            "Round-trip tests",
        ),
        to_lz4_op,
    );

    reg.add_simple(
        spec(
            "from-brotli",
            "From Brotli",
            "Decompresses Brotli data (no magic number exists; decoding trusts the input).",
            C,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["brotli decode", "unbrotli"],
            "RFC 7932 (Brotli Compressed Data Format)",
            "Round-trip tests (no magic to assert)",
        ),
        from_brotli_op,
    );

    reg.add_simple(
        spec(
            "to-brotli",
            "To Brotli",
            "Compresses bytes into a Brotli stream (quality 5, window 22).",
            C,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![],
            tags,
            &["brotli compress", "brotli encode"],
            "RFC 7932 (Brotli Compressed Data Format)",
            "Round-trip tests (no magic to assert)",
        ),
        to_brotli_op,
    );
}
