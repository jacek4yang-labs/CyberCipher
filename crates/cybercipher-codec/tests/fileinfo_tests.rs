//! Known-answer and round-trip tests for file-info operations.
//! Vectors: canonical format signatures (PNG/JPEG/PDF/ZIP), Unicode UTF-16
//! encoding forms with BOM handling.

// See cybercipher-core/src/lib.rs for the rationale.
#![allow(clippy::result_large_err)]

use cybercipher_core::prelude::*;
use cybercipher_core::OperationRegistry;

fn run_op(
    reg: &OperationRegistry,
    id: &str,
    input: Value,
    params: &[(&str, ParamValue)],
) -> OpResult<Value> {
    let op = reg.get(id).unwrap_or_else(|| panic!("missing op {id}"));
    let mut map = ParamMap::new();
    for (k, v) in params {
        map.insert(*k, v.clone());
    }
    op.execute(&input, &map, &ExecutionContext::new())
}

fn run_bytes(
    reg: &OperationRegistry,
    id: &str,
    input: &[u8],
    params: &[(&str, ParamValue)],
) -> OpResult<Value> {
    run_op(reg, id, Value::Bytes(input.to_vec()), params)
}

fn pt(params: &[(&'static str, &str)]) -> Vec<(&'static str, ParamValue)> {
    params
        .iter()
        .map(|(k, v)| (*k, ParamValue::Str(v.to_string())))
        .collect()
}

fn bytes_of(v: Value) -> Vec<u8> {
    match v {
        Value::Bytes(b) => b,
        Value::Text(t) => t.into_bytes(),
        other => panic!("expected bytes/text, got {other:?}"),
    }
}

fn reg() -> OperationRegistry {
    let mut r = OperationRegistry::new();
    cybercipher_codec::register_all(&mut r);
    r
}

#[test]
fn file_magic_detects_common_formats() {
    let r = reg();
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (b"\x89PNG\r\n\x1a\n\x00\x00".to_vec(), "png"),
        (b"\xFF\xD8\xFF\xE0\x00\x10".to_vec(), "jpeg"),
        (b"%PDF-1.7\n...".to_vec(), "pdf"),
        (b"PK\x03\x04\x14\x00".to_vec(), "zip"),
        (b"Rar!\x1A\x07\x01\x00".to_vec(), "rar"),
        (b"7z\xBC\xAF\x27\x1C".to_vec(), "sevenzip"),
        (b"\x1F\x8B\x08\x00".to_vec(), "gzip"),
        (b"BZh9...".to_vec(), "bzip2"),
        (b"\xFD7zXZ\x00\x00".to_vec(), "xz"),
        (b"\x28\xB5\x2F\xFD\x00".to_vec(), "zstd"),
        (b"\x04\x22\x4D\x18".to_vec(), "lz4"),
        (b"\x7FELF\x02\x01\x01".to_vec(), "elf"),
        (b"MZ\x90\x00\x03".to_vec(), "pe-mz"),
        (b"\x00\x61\x73\x6D\x01\x00".to_vec(), "wasm"),
        (b"SQLite format 3\x00..".to_vec(), "sqlite"),
        (b"ID3\x04\x00".to_vec(), "mp3-id3"),
        (b"fLaC\x00\x00".to_vec(), "flac"),
        (b"OggS\x00\x02".to_vec(), "ogg"),
        (b"RIFF\x24\x00\x00\x00WEBPVP8L".to_vec(), "webp"),
        (b"RIFF\x24\x00\x00\x00WAVEfmt ".to_vec(), "wav"),
        (b"RIFF\x24\x00\x00\x00AVI LIST".to_vec(), "avi"),
        (b"\x00\x00\x00\x18ftypmp42\x00".to_vec(), "mp4"),
        (b"\xFE\xED\xFA\xCE".to_vec(), "macho-be32"),
        (b"  <!DOCTYPE html><html>".to_vec(), "html"),
    ];
    for (data, expected) in cases {
        let out = run_bytes(&r, "file-magic", &data, &[]).unwrap();
        match out {
            Value::Json(j) => assert_eq!(
                j["detected"]["id"],
                expected,
                "input {:?} -> {j}",
                &data[..8.min(data.len())]
            ),
            other => panic!("expected JSON, got {other:?}"),
        }
    }

    // Unknown and empty inputs report null detection.
    for data in [b"\xDE\xAD\xBE\xEF\xCA\xFE".to_vec(), Vec::new()] {
        let out = run_bytes(&r, "file-magic", &data, &[]).unwrap();
        match out {
            Value::Json(j) => assert!(j["detected"].is_null(), "expected null, got {j}"),
            other => panic!("expected JSON, got {other:?}"),
        }
    }

    // Confidence is reported for a high-confidence hit.
    let out = run_bytes(&r, "file-magic", b"\x89PNG\r\n\x1a\n", &[]).unwrap();
    match out {
        Value::Json(j) => {
            assert_eq!(j["detected"]["confidence"], "high");
            assert_eq!(j["detected"]["mime"], "image/png");
        }
        other => panic!("expected JSON, got {other:?}"),
    }
}

#[test]
fn utf16le_roundtrip_and_bom() {
    let r = reg();

    // Known answer: "hi" in UTF-16LE is 68 00 69 00.
    let encoded = bytes_of(run_op(&r, "to-utf16le", Value::Text("hi".into()), &[]).unwrap());
    assert_eq!(encoded, vec![0x68, 0x00, 0x69, 0x00]);

    // With BOM: FF FE prefix (U+FEFF little-endian).
    let encoded = bytes_of(
        run_op(
            &r,
            "to-utf16le",
            Value::Text("hi".into()),
            &[("add_bom", ParamValue::Bool(true))],
        )
        .unwrap(),
    );
    assert_eq!(encoded, vec![0xFF, 0xFE, 0x68, 0x00, 0x69, 0x00]);

    // Decode strips the BOM by default and keeps it when asked.
    let decoded = run_bytes(&r, "from-utf16le", &encoded, &[]).unwrap();
    assert_eq!(decoded, Value::Text("hi".into()));
    let decoded = run_bytes(
        &r,
        "from-utf16le",
        &encoded,
        &[("strip_bom", ParamValue::Bool(false))],
    )
    .unwrap();
    assert_eq!(decoded, Value::Text("\u{FEFF}hi".into()));

    // Round-trip incl. non-BMP characters (surrogate pairs) and nulls.
    for text in ["plain", "naïve wörld", "\u{1F600} emoji", "a\u{0000}b"] {
        let encoded = bytes_of(run_op(&r, "to-utf16le", Value::Text(text.into()), &[]).unwrap());
        let decoded = run_bytes(&r, "from-utf16le", &encoded, &[]).unwrap();
        assert_eq!(decoded, Value::Text(text.into()));
    }

    // Odd byte count is a typed length error.
    let err = run_bytes(&r, "from-utf16le", &[0x68, 0x00, 0x69], &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::LengthMismatch, "{err}");
}

#[test]
fn utf16be_roundtrip_and_bom() {
    let r = reg();

    // Known answer: "hi" in UTF-16BE is 00 68 00 69.
    let encoded = bytes_of(run_op(&r, "to-utf16be", Value::Text("hi".into()), &[]).unwrap());
    assert_eq!(encoded, vec![0x00, 0x68, 0x00, 0x69]);

    // With BOM: FE FF prefix (U+FEFF big-endian).
    let encoded = bytes_of(
        run_op(
            &r,
            "to-utf16be",
            Value::Text("hi".into()),
            &[("add_bom", ParamValue::Bool(true))],
        )
        .unwrap(),
    );
    assert_eq!(encoded, vec![0xFE, 0xFF, 0x00, 0x68, 0x00, 0x69]);
    let decoded = run_bytes(&r, "from-utf16be", &encoded, &[]).unwrap();
    assert_eq!(decoded, Value::Text("hi".into()));

    let text = "big endian \u{2603} snowman";
    let encoded = bytes_of(run_op(&r, "to-utf16be", Value::Text(text.into()), &[]).unwrap());
    let decoded = run_bytes(&r, "from-utf16be", &encoded, &[]).unwrap();
    assert_eq!(decoded, Value::Text(text.into()));
}

#[test]
fn extract_strings_utf16_finds_le_and_be_runs() {
    let r = reg();

    // A "binary" with an embedded UTF-16LE secret and a UTF-16BE marker.
    let mut data: Vec<u8> = vec![0x00, 0xFF, 0x13, 0x37];
    for unit in "secret_file".encode_utf16() {
        data.extend_from_slice(&unit.to_le_bytes());
    }
    data.extend_from_slice(&[0xAB, 0xCD]);
    for unit in "hidden_note".encode_utf16() {
        data.extend_from_slice(&unit.to_be_bytes());
    }

    let out = run_bytes(&r, "extract-strings-utf16", &data, &[]).unwrap();
    let text = match out {
        Value::Text(t) => t,
        other => panic!("expected text, got {other:?}"),
    };
    assert!(text.contains("secret_file"), "LE run missing: {text:?}");
    assert!(text.contains("hidden_note"), "BE run missing: {text:?}");

    // LE-only scan finds only the LE run.
    let out = run_bytes(
        &r,
        "extract-strings-utf16",
        &data,
        &pt(&[("byte_order", "le")]),
    )
    .unwrap();
    match out {
        Value::Text(t) => {
            assert!(t.contains("secret_file"));
            assert!(!t.contains("hidden_note"));
        }
        other => panic!("expected text, got {other:?}"),
    }

    // min_length filters short runs.
    let out = run_bytes(
        &r,
        "extract-strings-utf16",
        &data,
        &[("min_length", ParamValue::Int(20))],
    )
    .unwrap();
    match out {
        Value::Text(t) => assert!(t.is_empty(), "expected no long runs, got {t:?}"),
        other => panic!("expected text, got {other:?}"),
    }
}

#[test]
fn file_entropy_blocks() {
    let r = reg();

    // First half zeros (entropy 0), second half varied data.
    let data: Vec<u8> = [
        vec![0u8; 32],
        (0..32u32).map(|i| (i * 37 + 11) as u8).collect(),
    ]
    .concat();

    let out = run_bytes(&r, "file-entropy", &data, &[("blocks", ParamValue::Int(2))]).unwrap();
    match out {
        Value::Json(j) => {
            assert_eq!(j["block_count"], 2);
            assert_eq!(j["block_size"], 32);
            assert_eq!(j["blocks"][0]["entropy"], 0.0, "zeros have zero entropy");
            assert!(
                j["blocks"][1]["entropy"].as_f64().unwrap() > 4.0,
                "varied data should have high entropy: {j}"
            );
            assert_eq!(
                j["high_entropy_blocks"], 0,
                "5-bit block is below the 7.5 threshold"
            );
            assert_eq!(j["min_entropy"], 0.0);
        }
        other => panic!("expected JSON, got {other:?}"),
    }

    // A block holding all 256 byte values has full 8-bit entropy and trips
    // the high-entropy threshold.
    let full_range: Vec<u8> = (0..=255u8).collect();
    let out = run_bytes(
        &r,
        "file-entropy",
        &full_range,
        &[("blocks", ParamValue::Int(1))],
    )
    .unwrap();
    match out {
        Value::Json(j) => {
            assert_eq!(j["blocks"][0]["entropy"], 8.0);
            assert_eq!(j["high_entropy_blocks"], 1);
        }
        other => panic!("expected JSON, got {other:?}"),
    }

    // Uniform data: every block has zero entropy.
    let out = run_bytes(
        &r,
        "file-entropy",
        &[0xAA; 64],
        &[("blocks", ParamValue::Int(4))],
    )
    .unwrap();
    match out {
        Value::Json(j) => {
            assert_eq!(j["block_count"], 4);
            assert_eq!(j["max_entropy"], 0.0);
        }
        other => panic!("expected JSON, got {other:?}"),
    }

    // Empty input yields an empty block list without panicking.
    let out = run_bytes(&r, "file-entropy", &[], &[]).unwrap();
    match out {
        Value::Json(j) => assert_eq!(j["block_count"], 0),
        other => panic!("expected JSON, got {other:?}"),
    }

    // Invalid block count is a typed parameter error.
    let err = run_bytes(
        &r,
        "file-entropy",
        &[0u8; 8],
        &[("blocks", ParamValue::Int(0))],
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidParam, "{err}");
}
