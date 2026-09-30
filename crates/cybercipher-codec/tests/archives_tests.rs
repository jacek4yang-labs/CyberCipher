//! Known-answer and round-trip tests for archive (tar/zip) operations.
//! Vectors: hand-built POSIX ustar header; PKWARE APPNOTE signatures.

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

/// Build a minimal POSIX ustar member: 512-byte header for `a.txt` holding
/// `hello`, plus content block. Mirrors the on-disk format byte-for-byte.
fn hand_built_ustar() -> Vec<u8> {
    let mut header = [0u8; 512];
    header[..5].copy_from_slice(b"a.txt");
    header[100..107].copy_from_slice(b"0000644"); // mode
    header[108..115].copy_from_slice(b"0000000"); // uid
    header[116..123].copy_from_slice(b"0000000"); // gid
    header[124..135].copy_from_slice(b"00000000005"); // size (octal)
    header[136..147].copy_from_slice(b"00000000000"); // mtime
    header[156] = b'0'; // regular file
    header[257..262].copy_from_slice(b"ustar");
    header[263..265].copy_from_slice(b"00");
    // Checksum over the header with the chksum field read as spaces.
    let mut sum: u64 = 8 * b' ' as u64;
    for (i, &b) in header.iter().enumerate() {
        if !(148..156).contains(&i) {
            sum += b as u64;
        }
    }
    let chk = format!("{sum:06o}\0 ");
    header[148..156].copy_from_slice(chk.as_bytes());

    let mut out = header.to_vec();
    out.extend_from_slice(b"hello");
    out.resize(1024, 0); // content padding block
    out
}

#[test]
fn tar_known_header_vector() {
    let r = reg();
    let out = run_bytes(&r, "from-tar", &hand_built_ustar(), &[]).unwrap();
    assert_eq!(bytes_of(out), b"hello".to_vec());
}

#[test]
fn tar_roundtrip_and_listing() {
    let r = reg();
    let payload = b"tar round trip".to_vec();
    let archive =
        bytes_of(run_bytes(&r, "to-tar", &payload, &pt(&[("filename", "note.txt")])).unwrap());
    // The ustar magic must sit at offset 257.
    assert_eq!(&archive[257..262], b"ustar");

    let back = bytes_of(run_bytes(&r, "from-tar", &archive, &[]).unwrap());
    assert_eq!(back, payload);

    let listing = run_bytes(
        &r,
        "from-tar",
        &archive,
        &[("list_only", ParamValue::Bool(true))],
    )
    .unwrap();
    match listing {
        Value::Json(j) => {
            assert_eq!(j["member_count"], 1);
            assert_eq!(j["members"][0]["name"], "note.txt");
            assert_eq!(j["members"][0]["size"], payload.len() as u64);
        }
        other => panic!("expected JSON listing, got {other:?}"),
    }

    // Negative: not a tar archive.
    let err = run_bytes(&r, "from-tar", b"plainly not a tar archive at all", &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode, "{err}");
}

#[test]
fn zip_roundtrip_magic_and_selection() {
    let r = reg();

    // Known-answer: zip output starts with the local file header signature.
    let archive = bytes_of(
        run_bytes(
            &r,
            "to-zip",
            b"zip round trip",
            &pt(&[("filename", "a.bin")]),
        )
        .unwrap(),
    );
    assert_eq!(&archive[..4], b"PK\x03\x04");

    // Single member extracts byte-exact.
    let back = bytes_of(run_bytes(&r, "from-zip", &archive, &[]).unwrap());
    assert_eq!(back, b"zip round trip".to_vec());

    // Multi-member archive with an extra text member.
    let multi = bytes_of(
        run_bytes(
            &r,
            "to-zip",
            b"primary",
            &pt(&[
                ("filename", "primary.bin"),
                ("extra_files", "notes.txt=side notes"),
            ]),
        )
        .unwrap(),
    );
    // Explicit member selection is byte-exact.
    let picked =
        bytes_of(run_bytes(&r, "from-zip", &multi, &pt(&[("member", "notes.txt")])).unwrap());
    assert_eq!(picked, b"side notes".to_vec());

    // Extract-all concatenates with named separators.
    let all = bytes_of(run_bytes(&r, "from-zip", &multi, &[]).unwrap());
    let text = String::from_utf8(all).unwrap();
    assert!(text.contains("===== primary.bin ====="));
    assert!(text.contains("===== notes.txt ====="));
    assert!(text.contains("primary"));
    assert!(text.contains("side notes"));

    // Unknown member name is a typed error.
    let err = run_bytes(&r, "from-zip", &multi, &pt(&[("member", "nope.txt")])).unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidInput, "{err}");

    // Negative: not a zip.
    let err = run_bytes(&r, "from-zip", b"Rar! plain garbage", &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode, "{err}");
}

#[test]
fn zip_listing_reports_members() {
    let r = reg();
    let archive = bytes_of(
        run_bytes(
            &r,
            "to-zip",
            b"0123456789",
            &pt(&[("filename", "nums.txt"), ("extra_files", "empty.txt=")]),
        )
        .unwrap(),
    );
    let listing = run_bytes(
        &r,
        "from-zip",
        &archive,
        &[("list_only", ParamValue::Bool(true))],
    )
    .unwrap();
    match listing {
        Value::Json(j) => {
            assert_eq!(j["member_count"], 2);
            assert_eq!(j["members"][0]["name"], "nums.txt");
            assert_eq!(j["members"][0]["size"], 10);
            assert_eq!(j["members"][1]["name"], "empty.txt");
            assert_eq!(j["members"][1]["size"], 0);
        }
        other => panic!("expected JSON listing, got {other:?}"),
    }
}

#[test]
fn zip_bomb_ratio_rejected() {
    let r = reg();
    // ~8 MiB of zeros: zip-deflate lands above the 1 KiB ratio floor and
    // expands far beyond 100x -> BudgetExceeded.
    let payload = vec![0u8; 8 * 1024 * 1024];
    let archive =
        bytes_of(run_bytes(&r, "to-zip", &payload, &pt(&[("filename", "bomb.bin")])).unwrap());
    let err = run_bytes(&r, "from-zip", &archive, &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::BudgetExceeded, "{err}");
}
