//! Archive operations: tar and zip member listing, extraction, and creation.
//! Both formats are handled in-memory with the shared decompression safety
//! cap (64 MiB) and zip-bomb ratio rejection.

use crate::compression::{check_bomb_ratio, DECOMPRESS_LIMIT};
use crate::helpers::{input_bytes, p_bool, p_text, spec};
use cybercipher_core::prelude::*;
use std::io::{Read, Write};

fn tar_op_error(e: std::io::Error) -> OperationError {
    OperationError::decode(format!("tar parsing failed: {e}"))
}

// ---------------------------------------------------------------------------
// tar
// ---------------------------------------------------------------------------

/// The `ustar` magic sits at offset 257 in both the POSIX (`ustar\0`) and
/// GNU (`ustar `) variants.
fn require_tar_magic(bytes: &[u8]) -> OpResult<()> {
    if bytes.len() < 512 || &bytes[257..262] != b"ustar" {
        return Err(OperationError::decode("input is not a tar archive")
            .with_expected("tar archive with 'ustar' magic at offset 257")
            .with_actual(if bytes.len() >= 262 {
                let head: String = bytes[257..262].iter().map(|&b| b as char).collect();
                format!("'{}' at offset 257", head.escape_default())
            } else {
                format!("only {} bytes", bytes.len())
            }));
    }
    Ok(())
}

/// One archive listing entry: (member name, uncompressed size).
type ListingEntry = (String, u64);
/// Result of scanning a tar archive: listing plus extracted member contents.
type TarScan = (Vec<ListingEntry>, Vec<Vec<u8>>);
/// One zip listing entry: (name, uncompressed size, compressed size).
type ZipListingEntry = (String, u64, u64);
/// Result of scanning a zip archive: listing, contents, total uncompressed
/// size, and total compressed size (for the bomb-ratio check).
type ZipScan = (Vec<ZipListingEntry>, Vec<Vec<u8>>, u64, u64);

fn tar_members(data: &[u8]) -> OpResult<TarScan> {
    let mut archive = tar::Archive::new(std::io::Cursor::new(data));
    let entries = archive.entries().map_err(tar_op_error)?;
    let mut listing = Vec::new();
    let mut contents = Vec::new();
    let mut total = 0usize;
    for entry in entries {
        let entry = entry.map_err(tar_op_error)?;
        let name = entry
            .path()
            .map_err(tar_op_error)?
            .to_string_lossy()
            .into_owned();
        let size = entry.header().size().map_err(tar_op_error)?;
        listing.push((name.clone(), size));
        let mut buf = Vec::new();
        // `tar::Entry` itself is the content reader (its `Read` impl yields
        // exactly the member data, positioned after the header).
        entry
            .take(DECOMPRESS_LIMIT as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(tar_op_error)?;
        total += buf.len();
        if total > DECOMPRESS_LIMIT {
            return Err(OperationError::new(
                ErrorKind::BudgetExceeded,
                "tar contents exceed the decompression safety cap",
            )
            .with_expected(format!("at most {DECOMPRESS_LIMIT} bytes"))
            .with_actual(format!("more than {DECOMPRESS_LIMIT} bytes")));
        }
        contents.push(buf);
    }
    Ok((listing, contents))
}

fn from_tar_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "From Tar")?;
    require_tar_magic(bytes.as_ref())?;
    let (listing, contents) = tar_members(bytes.as_ref())?;
    if map.bool_or("list_only", false) {
        let members: Vec<serde_json::Value> = listing
            .iter()
            .map(|(name, size)| serde_json::json!({ "name": name, "size": size }))
            .collect();
        return Ok(Value::Json(serde_json::json!({
            "member_count": members.len(),
            "total_size": members.iter().map(|m| m["size"].as_u64().unwrap_or(0)).sum::<u64>(),
            "members": members,
        })));
    }
    let mut out = Vec::new();
    for content in contents {
        out.extend_from_slice(&content);
    }
    Ok(Value::from_bytes(out))
}

fn to_tar_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Tar")?;
    let name = map.str_or("filename", "data.bin");
    if name.is_empty() {
        return Err(OperationError::invalid_param(
            "filename",
            "member name must not be empty",
        ));
    }
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, name, bytes.as_ref())
        .map_err(tar_op_error)?;
    let out = builder.into_inner().map_err(tar_op_error)?;
    Ok(Value::Bytes(out))
}

// ---------------------------------------------------------------------------
// zip
// ---------------------------------------------------------------------------

fn require_zip_magic(bytes: &[u8]) -> OpResult<()> {
    let ok = bytes.len() >= 4
        && (bytes[..4] == [0x50, 0x4B, 0x03, 0x04]
            || bytes[..4] == [0x50, 0x4B, 0x05, 0x06]
            || bytes[..4] == [0x50, 0x4B, 0x07, 0x08]);
    if !ok {
        return Err(OperationError::decode("input is not zip data")
            .with_expected("zip signature 'PK\\x03\\x04' (or empty/spanned marker)")
            .with_actual(if bytes.len() >= 4 {
                format!(
                    "{:02x} {:02x} {:02x} {:02x}",
                    bytes[0], bytes[1], bytes[2], bytes[3]
                )
            } else {
                format!("only {} bytes", bytes.len())
            }));
    }
    Ok(())
}

/// Shared member iteration: collects names/sizes and (when `extract`) the
/// member contents under the safety cap. Returns the compressed size total
/// for the bomb-ratio check.
fn zip_scan(bytes: &[u8], extract: bool) -> OpResult<ZipScan> {
    let reader = std::io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader)
        .map_err(|e| OperationError::decode(format!("zip parsing failed: {e}")))?;
    let mut listing = Vec::new();
    let mut contents = Vec::new();
    let mut total_uncompressed = 0u64;
    let mut total_compressed = 0u64;
    let mut total_read = 0usize;
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| OperationError::decode(format!("zip member {i}: {e}")))?;
        let name = file.name().to_string();
        let size = file.size();
        let compressed = file.compressed_size();
        listing.push((name, size, compressed));
        total_uncompressed += size;
        total_compressed += compressed;
        if !extract {
            continue;
        }
        let mut buf = Vec::new();
        (&mut file)
            .take(DECOMPRESS_LIMIT as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|e| OperationError::decode(format!("zip extraction failed: {e}")))?;
        total_read += buf.len();
        if total_read > DECOMPRESS_LIMIT {
            return Err(OperationError::new(
                ErrorKind::BudgetExceeded,
                "zip contents exceed the decompression safety cap",
            )
            .with_expected(format!("at most {DECOMPRESS_LIMIT} bytes"))
            .with_actual(format!("more than {DECOMPRESS_LIMIT} bytes")));
        }
        contents.push(buf);
    }
    Ok((listing, contents, total_uncompressed, total_compressed))
}

fn from_zip_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "From Zip")?;
    require_zip_magic(bytes.as_ref())?;

    if map.bool_or("list_only", false) {
        let (listing, _, total_uncompressed, total_compressed) = zip_scan(bytes.as_ref(), false)?;
        let members: Vec<serde_json::Value> = listing
            .iter()
            .map(|(name, size, compressed)| {
                serde_json::json!({ "name": name, "size": size, "compressed_size": compressed })
            })
            .collect();
        return Ok(Value::Json(serde_json::json!({
            "member_count": members.len(),
            "total_uncompressed": total_uncompressed,
            "total_compressed": total_compressed,
            "members": members,
        })));
    }

    let wanted = map.str_or("member", "");
    let (listing, contents, total_uncompressed, total_compressed) = zip_scan(bytes.as_ref(), true)?;
    check_bomb_ratio(
        bytes.len().max(total_compressed as usize),
        total_uncompressed as usize,
        "zip",
    )?;

    // Extract-all: multiple members are concatenated with named separators;
    // a single member (or an explicit `member` selection) comes out raw so
    // round-trips are byte-exact.
    let mut indices: Vec<usize> = (0..listing.len())
        .filter(|&i| {
            let name = &listing[i].0;
            !name.ends_with('/') && (wanted.is_empty() || name == wanted)
        })
        .collect();
    if !wanted.is_empty() && indices.is_empty() {
        return Err(
            OperationError::invalid_input(format!("no zip member named {wanted:?}"))
                .with_expected("member name present in the archive")
                .with_actual(format!(
                    "{} members in archive",
                    listing.iter().filter(|(n, _, _)| !n.ends_with('/')).count()
                )),
        );
    }
    indices.sort();

    if indices.len() == 1 {
        return Ok(Value::Bytes(contents[indices[0]].clone()));
    }
    let mut out = Vec::new();
    for (n, i) in indices.iter().enumerate() {
        if n > 0 {
            out.push(b'\n');
        }
        out.extend_from_slice(format!("===== {} =====\n", listing[*i].0).as_bytes());
        out.extend_from_slice(&contents[*i]);
    }
    Ok(Value::Bytes(out))
}

fn to_zip_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Zip")?;
    let name = map.str_or("filename", "data.bin");
    if name.is_empty() {
        return Err(OperationError::invalid_param(
            "filename",
            "member name must not be empty",
        ));
    }
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    writer
        .start_file(name, options)
        .map_err(|e| OperationError::internal(format!("zip encoding failed: {e}")))?;
    writer
        .write_all(bytes.as_ref())
        .map_err(|e| OperationError::internal(format!("zip encoding failed: {e}")))?;

    // Additional members come from `extra_files`, one `name=value` per line.
    let extra = map.str_or("extra_files", "");
    for line in extra.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Some((mname, mvalue)) = line.split_once('=') else {
            return Err(OperationError::invalid_param(
                "extra_files",
                format!("extra_files lines must be `name=value`, got {line:?}"),
            ));
        };
        let mname = mname.trim();
        if mname.is_empty() {
            return Err(OperationError::invalid_param(
                "extra_files",
                "extra_files member name must not be empty",
            ));
        }
        writer
            .start_file(mname, options)
            .map_err(|e| OperationError::internal(format!("zip encoding failed: {e}")))?;
        writer
            .write_all(mvalue.as_bytes())
            .map_err(|e| OperationError::internal(format!("zip encoding failed: {e}")))?;
    }

    let cursor = writer
        .finish()
        .map_err(|e| OperationError::internal(format!("zip encoding failed: {e}")))?;
    Ok(Value::Bytes(cursor.into_inner()))
}

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    use cybercipher_core::{
        Category::File as F,
        ValueKind::{Bytes as B, Text as T},
    };

    let tags: &'static [&'static str] = &["archive", "ctf", "forensics"];

    reg.add_simple(
        spec(
            "from-tar",
            "From Tar",
            "Lists or extracts members of a tar archive (ustar/GNU). Extract-all concatenates member contents in archive order.",
            F,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![p_bool(
                "list_only",
                "List members only",
                false,
                "Return a JSON member listing instead of the concatenated contents.",
            )],
            tags,
            &["untar", "tar decode", "tar list"],
            "POSIX ustar / GNU tar header format",
            "Hand-built header vector + round-trip tests",
        ),
        from_tar_op,
    );

    reg.add_simple(
        spec(
            "to-tar",
            "To Tar",
            "Packs the input bytes as a single-member tar archive (GNU variant).",
            F,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![p_text(
                "filename",
                "Member name",
                "data.bin",
                "Name of the single archive member.",
            )],
            tags,
            &["tar create", "tar pack"],
            "POSIX ustar / GNU tar header format",
            "Round-trip tests",
        ),
        to_tar_op,
    );

    reg.add_simple(
        spec(
            "from-zip",
            "From Zip",
            "Lists or extracts zip members (deflate/stored). Extract-all concatenates multiple members with `===== name =====` separators; a single member comes out byte-exact.",
            F,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![
                p_text(
                    "member",
                    "Member name",
                    "",
                    "Exact member name to extract; empty extracts all file members.",
                ),
                p_bool(
                    "list_only",
                    "List members only",
                    false,
                    "Return a JSON member listing instead of the contents.",
                ),
            ],
            tags,
            &["unzip", "zip decode", "zip list"],
            "PKWARE APPNOTE.TXT (.ZIP File Format Specification)",
            "Round-trip, magic, and bomb-ratio tests",
        ),
        from_zip_op,
    );

    reg.add_simple(
        spec(
            "to-zip",
            "To Zip",
            "Creates a zip archive: the input becomes the member named by `filename`; further `name=value` lines in `extra_files` become text members.",
            F,
            &[B, T],
            B,
            CostClass::Interactive,
            true,
            vec![
                p_text(
                    "filename",
                    "Member name",
                    "data.bin",
                    "Name for the member holding the input bytes.",
                ),
                p_text(
                    "extra_files",
                    "Extra members",
                    "",
                    "Optional, one `name=value` per line (values are UTF-8 text).",
                ),
            ],
            tags,
            &["zip create", "zip pack"],
            "PKWARE APPNOTE.TXT (.ZIP File Format Specification)",
            "Round-trip + magic tests",
        ),
        to_zip_op,
    );
}
