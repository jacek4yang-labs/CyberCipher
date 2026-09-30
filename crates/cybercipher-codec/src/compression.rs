//! Compression decoding operations (gzip/zlib/raw deflate), used directly by
//! recipes and by the Auto Decode candidate engine.

use crate::helpers::{input_bytes, p_bool, spec};
use cybercipher_core::prelude::*;
use std::io::Read;

fn decompress_multi<R: Read>(reader: R, limit: usize) -> OpResult<Vec<u8>> {
    let mut out = Vec::new();
    reader
        .take(limit as u64)
        .read_to_end(&mut out)
        .map_err(|e| OperationError::decode(format!("decompression failed: {e}")))?;
    Ok(out)
}

/// Decompressed-output cap for interactive use (64 MiB).
const DECOMPRESS_LIMIT: usize = 64 * 1024 * 1024;

pub fn gunzip(data: &[u8]) -> OpResult<Vec<u8>> {
    let decoder = flate2::read::MultiGzDecoder::new(data);
    decompress_multi(decoder, DECOMPRESS_LIMIT)
}

pub fn zlib_decompress(data: &[u8]) -> OpResult<Vec<u8>> {
    let mut decoder = flate2::read::ZlibDecoder::new(data);
    decompress_multi(&mut decoder, DECOMPRESS_LIMIT)
}

pub fn raw_deflate(data: &[u8]) -> OpResult<Vec<u8>> {
    let mut decoder = flate2::read::DeflateDecoder::new(data);
    decompress_multi(&mut decoder, DECOMPRESS_LIMIT)
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
}
