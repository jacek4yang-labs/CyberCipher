//! Known-answer and round-trip tests for the base-family operations.
//!
//! Vectors:
//! * Base45: RFC 9285 §4, plus a hand-computed vector pinned from the RFC
//!   algorithm ("Hello world!").
//! * Base58/Base58Check: Bitcoin Wiki Base58Check example, cross-checked
//!   with an independent Python implementation.
//! * Ascii85: Python `base64.a85encode` (independent reference).
//! * Z85: 0MQ spec 32 test vector.
//! * Base91: the canonical reference implementation (mscdex/base91.js).

// See cybercipher-core/src/lib.rs for the rationale.
#![allow(clippy::result_large_err)]

use cybercipher_core::prelude::*;
use cybercipher_core::OperationRegistry;

fn reg() -> OperationRegistry {
    let mut r = OperationRegistry::new();
    cybercipher_codec::register_all(&mut r);
    r
}

fn run(
    reg: &OperationRegistry,
    id: &str,
    input: Value,
    params: &[(&'static str, ParamValue)],
) -> OpResult<Value> {
    let op = reg.get(id).unwrap_or_else(|| panic!("missing op {id}"));
    let mut map = ParamMap::new();
    for (k, v) in params {
        map.insert(*k, v.clone());
    }
    op.execute(&input, &map, &ExecutionContext::new())
}

fn run_text(
    reg: &OperationRegistry,
    id: &str,
    input: &str,
    params: &[(&'static str, ParamValue)],
) -> OpResult<Value> {
    run(reg, id, Value::Text(input.to_string()), params)
}

fn run_bytes(
    reg: &OperationRegistry,
    id: &str,
    input: &[u8],
    params: &[(&'static str, ParamValue)],
) -> OpResult<Value> {
    run(reg, id, Value::Bytes(input.to_vec()), params)
}

fn pvb(params: &[(&'static str, bool)]) -> Vec<(&'static str, ParamValue)> {
    params
        .iter()
        .map(|(k, v)| (*k, ParamValue::Bool(*v)))
        .collect()
}

fn pvi(params: &[(&'static str, i64)]) -> Vec<(&'static str, ParamValue)> {
    params
        .iter()
        .map(|(k, v)| (*k, ParamValue::Int(*v)))
        .collect()
}

fn assert_text(out: OpResult<Value>, expected: &str) {
    match out.expect("operation failed") {
        Value::Text(t) => assert_eq!(t, expected),
        other => panic!("expected text, got {other:?}"),
    }
}

fn assert_bytes(out: OpResult<Value>, expected: &[u8]) {
    match out.expect("operation failed") {
        Value::Bytes(b) => assert_eq!(b, expected),
        other => panic!("expected bytes, got {other:?}"),
    }
}

fn expect_decode_err(out: OpResult<Value>, needle: &str) -> OperationError {
    let err = out.expect_err("expected a decode error");
    assert!(
        err.message.contains(needle),
        "error `{}` does not contain `{needle}`",
        err.message
    );
    err
}

// ------------------------------------------------------------- Base45 ----

#[test]
fn rfc9285_base45_vectors() {
    let r = reg();
    for (input, expected) in [
        ("AB", "BB8"),
        ("Hello!!", "%69 VD92EX0"),
        ("base-45", "UJCLQE7W581"),
        // Hand-computed from the RFC algorithm (pinned):
        ("Hello world!", "%69 VD82EK4F.KESTC"),
    ] {
        let enc = run_text(&r, "to-base45", input, &[]);
        assert_text(enc, expected);
        let dec = run_text(&r, "from-base45", expected, &[]);
        assert_bytes(dec, input.as_bytes());
    }
}

#[test]
fn rfc9285_base45_decode_vector() {
    let r = reg();
    // RFC 9285 §4 decode example.
    assert_bytes(run_text(&r, "from-base45", "QED8WEX0", &[]), b"ietf!");
}

#[test]
fn base45_rejects_rfc_violations() {
    let r = reg();
    // A lone trailing character cannot form a group.
    expect_decode_err(run_text(&r, "from-base45", "A", &[]), "length is invalid");
    // Three-character group exceeding 65535 (RFC 9285 requires rejection).
    expect_decode_err(
        run_text(&r, "from-base45", ":::", &[]),
        "exceeds the 16-bit",
    );
    // Final two-character group exceeding 255.
    expect_decode_err(run_text(&r, "from-base45", "QED06", &[]), "single-byte");
    // The space character is a legitimate Base45 symbol (value 36): strict
    // mode must accept it as part of an encoded group.
    assert_bytes(
        run_text(&r, "from-base45", "%69 VD92EX0", &pvb(&[("strict", true)])),
        b"Hello!!",
    );
    // Other whitespace is rejected in strict mode. Relaxed mode drops it,
    // which can shift the 3-character grouping — only edge whitespace is
    // safe to drop, which is exactly how trailing newlines appear in CTF
    // inputs.
    expect_decode_err(
        run_text(&r, "from-base45", "%69\nVD92EX0", &pvb(&[("strict", true)])),
        "whitespace",
    );
    assert_bytes(
        run_text(
            &r,
            "from-base45",
            "%69 VD92EX0\n",
            &pvb(&[("strict", false)]),
        ),
        b"Hello!!",
    );
}

// ------------------------------------------------------------- Base58 ----

#[test]
fn base58_vectors_and_leading_zeros() {
    let r = reg();
    assert_text(run_bytes(&r, "to-base58", b"hello", &[]), "Cn8eVZg");
    assert_text(
        run_bytes(&r, "to-base58", b"\x00\x00hello", &[]),
        "11Cn8eVZg",
    );
    assert_text(run_bytes(&r, "to-base58", b"", &[]), "");
    assert_text(run_bytes(&r, "to-base58", &[0], &[]), "1");
    assert_text(run_bytes(&r, "to-base58", &[0, 0], &[]), "11");

    assert_bytes(run_text(&r, "from-base58", "Cn8eVZg", &[]), b"hello");
    assert_bytes(
        run_text(&r, "from-base58", "11Cn8eVZg", &[]),
        b"\x00\x00hello",
    );
    assert_bytes(run_text(&r, "from-base58", "1", &[]), &[0]);
    assert_bytes(run_text(&r, "from-base58", "", &[]), b"");
}

#[test]
fn base58_strict_and_relaxed_policy() {
    let r = reg();
    // Strict: internal whitespace is rejected with a diagnostic.
    let err = expect_decode_err(
        run_text(&r, "from-base58", "Cn8e VZg", &pvb(&[("strict", true)])),
        "offset 4",
    );
    assert!(err.message.contains(' '));
    // Relaxed: whitespace is dropped and the value still decodes.
    assert_bytes(
        run_text(&r, "from-base58", "Cn8e VZg", &pvb(&[("strict", false)])),
        b"hello",
    );
    // Strict: look-alike characters outside the Bitcoin alphabet are named
    // with their offset.
    let err = expect_decode_err(
        run_text(&r, "from-base58", "0OIl", &pvb(&[("strict", true)])),
        "offset 0",
    );
    assert!(err.message.contains('0'));
    // Relaxed: they are dropped, yielding empty output.
    assert_bytes(
        run_text(&r, "from-base58", "0OIl", &pvb(&[("strict", false)])),
        b"",
    );
}

// -------------------------------------------------------- Base58Check ----

#[test]
fn base58check_bitcoin_wiki_vector() {
    let r = reg();
    // Bitcoin Wiki Base58Check example: version 0x00, hash160
    // 010966776006953D5567439E5E39F86A0D273BEE -> the P2PKH address
    // 16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM.
    let payload = hex_bytes("010966776006953D5567439E5E39F86A0D273BEE");
    let enc = run_bytes(&r, "to-base58check", &payload, &pvi(&[("version", 0)]));
    assert_text(enc, "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM");

    // Decode recovers the payload.
    let dec = run_text(
        &r,
        "from-base58check",
        "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
        &pvi(&[("version", 0)]),
    );
    assert_bytes(dec, &payload);

    // `output = versioned` keeps and thereby reports the version byte.
    let dec = run_text(
        &r,
        "from-base58check",
        "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
        &[
            ("version", ParamValue::Int(-1)),
            ("output", ParamValue::Str("versioned".to_string())),
        ],
    );
    assert_bytes(dec, &[&[0x00], payload.as_slice()].concat());
}

#[test]
fn base58check_checksum_and_version_errors() {
    let r = reg();
    // Corrupt one symbol: the checksum must fail.
    let corrupted = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvN"; // last char flipped
    let err = expect_decode_err(
        run_text(&r, "from-base58check", corrupted, &[]),
        "checksum mismatch",
    );
    assert!(err.details.as_deref().unwrap().contains("Version byte"));

    // Version byte enforcement.
    expect_decode_err(
        run_text(
            &r,
            "from-base58check",
            "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
            &pvi(&[("version", 0x6f)]),
        ),
        "version byte mismatch",
    );

    // Too short to carry version + payload + checksum.
    expect_decode_err(run_text(&r, "from-base58check", "1", &[]), "too short");

    // Invalid version parameter.
    let err = run_bytes(&r, "to-base58check", b"x", &pvi(&[("version", 300)]))
        .expect_err("expected invalid param");
    assert_eq!(err.kind, ErrorKind::InvalidParam);
}

// ------------------------------------------------------------- Base62 ----

#[test]
fn base62_vectors_and_roundtrip() {
    let r = reg();
    // Cross-checked with an independent big-integer implementation.
    assert_text(run_bytes(&r, "to-base62", b"Hi", &[]), "4oz");
    assert_text(run_bytes(&r, "to-base62", b"hello", &[]), "7tQLFHz");

    // Round-trips are exact; leading zero bytes are trimmed by convention
    // (documented: Base62 has no leading-zero convention), except that an
    // all-zero input encodes to `0` and decodes back to a single zero byte.
    let samples: &[&[u8]] = &[
        b"",
        b"\x00",
        b"\x00\x00\x05",
        b"\xff\xff\xff\xff",
        b"random CTF payload 123",
    ];
    for sample in samples {
        let enc = run_bytes(&r, "to-base62", sample, &[]).unwrap();
        let dec = run(&r, "from-base62", enc, &[]).unwrap();
        let mut expected: Vec<u8> = sample.iter().skip_while(|&&b| b == 0).copied().collect();
        if expected.is_empty() && !sample.is_empty() {
            expected.push(0);
        }
        assert_bytes(Ok(dec), &expected);
    }
    assert_bytes(run_text(&r, "from-base62", "0", &[]), &[0]);
}

#[test]
fn base62_strict_policy() {
    let r = reg();
    // Case-sensitive alphabet: strict rejects whitespace and foreign chars
    // with offsets.
    let err = expect_decode_err(
        run_text(&r, "from-base62", "4o z", &pvb(&[("strict", true)])),
        "offset 2",
    );
    assert!(err.message.contains(' '));
    assert_bytes(
        run_text(&r, "from-base62", "4o z", &pvb(&[("strict", false)])),
        b"Hi",
    );
}

// ------------------------------------------------------------- Base36 ----

#[test]
fn base36_vectors_and_case_insensitivity() {
    let r = reg();
    assert_text(run_bytes(&r, "to-base36", b"hello", &[]), "5PZCSZU7");
    assert_text(run_bytes(&r, "to-base36", b"foobar", &[]), "13X8YD7YWI");

    // Decode is case-insensitive by convention.
    assert_bytes(run_text(&r, "from-base36", "5pzcszu7", &[]), b"hello");
    assert_bytes(run_text(&r, "from-base36", "5PZCSZU7", &[]), b"hello");

    // All-zero input encodes to a single zero digit.
    assert_text(run_bytes(&r, "to-base36", &[0], &[]), "0");
    assert_bytes(run_text(&r, "from-base36", "0", &[]), &[0]);
}

#[test]
fn base36_strict_policy() {
    let r = reg();
    let err = expect_decode_err(
        run_text(&r, "from-base36", "hello!", &pvb(&[("strict", true)])),
        "offset 5",
    );
    assert!(err.message.contains('!'));
    // Relaxed drops the foreign character.
    assert_bytes(
        run_text(&r, "from-base36", "5pzc-szu7", &pvb(&[("strict", false)])),
        b"hello",
    );
}

// ------------------------------------------------------------ Ascii85 ----

#[test]
fn ascii85_vectors() {
    let r = reg();
    // Cross-checked against Python base64.a85encode.
    assert_text(
        run_bytes(&r, "to-ascii85", b"Hello, world!", &[]),
        "87cURD_*#TDfTZ)+T",
    );
    assert_text(
        run_bytes(
            &r,
            "to-ascii85",
            b"Hello, world!",
            &pvb(&[("delimiters", true)]),
        ),
        "<~87cURD_*#TDfTZ)+T~>",
    );
    // All-zero group -> 'z' (Adobe).
    assert_text(run_bytes(&r, "to-ascii85", &[0, 0, 0, 0], &[]), "z");
    // Four spaces -> 'y' with the btoa -y option.
    assert_text(
        run_bytes(&r, "to-ascii85", b"    ", &pvb(&[("y_shorthand", true)])),
        "y",
    );
    // Partial groups emit length+1 characters.
    assert_text(run_bytes(&r, "to-ascii85", b"A", &[]), "5l");
    assert_text(run_bytes(&r, "to-ascii85", b"AB", &[]), "5sb");
    assert_text(run_bytes(&r, "to-ascii85", b"ABC", &[]), "5sdp");
}

#[test]
fn ascii85_decode_and_delimiters() {
    let r = reg();
    assert_bytes(
        run_text(&r, "from-ascii85", "87cURD_*#TDfTZ)+T", &[]),
        b"Hello, world!",
    );
    // Delimiters are detected automatically.
    assert_bytes(
        run_text(&r, "from-ascii85", "<~87cURD_*#TDfTZ)+T~>", &[]),
        b"Hello, world!",
    );
    assert_bytes(run_text(&r, "from-ascii85", "z", &[]), &[0, 0, 0, 0]);
    assert_bytes(
        run_text(&r, "from-ascii85", "y", &pvb(&[("y_shorthand", true)])),
        b"    ",
    );
    assert_bytes(run_text(&r, "from-ascii85", "5l", &[]), b"A");
    assert_bytes(run_text(&r, "from-ascii85", "5sdp", &[]), b"ABC");
    // Empty stream.
    assert_text(
        run_bytes(&r, "to-ascii85", b"", &pvb(&[("delimiters", true)])),
        "<~~>",
    );
    assert_bytes(run_text(&r, "from-ascii85", "<~~>", &[]), b"");
}

#[test]
fn ascii85_strict_errors_and_relaxed() {
    let r = reg();
    // Strict: whitespace inside the payload is rejected.
    expect_decode_err(
        run_text(&r, "from-ascii85", "87cU RD_*#T", &pvb(&[("strict", true)])),
        "whitespace",
    );
    // Relaxed: whitespace is dropped and the rest decodes.
    assert_bytes(
        run_text(
            &r,
            "from-ascii85",
            "87cU RD_*#T",
            &pvb(&[("strict", false)]),
        ),
        b"Hello, w",
    );
    // Invalid symbol is named with its offset ('~' is not a digit).
    let err = expect_decode_err(
        run_text(&r, "from-ascii85", "87cUR~", &pvb(&[("strict", true)])),
        "offset 5",
    );
    assert!(err.message.contains('~'));
    // Shorthand inside a group is a structural error in all modes.
    expect_decode_err(
        run_text(&r, "from-ascii85", "8z", &pvb(&[("strict", false)])),
        "inside a group",
    );
    // A lone trailing character encodes zero bytes and is invalid.
    expect_decode_err(run_text(&r, "from-ascii85", "5", &[]), "lone trailing");
    // Unbalanced delimiters.
    expect_decode_err(run_text(&r, "from-ascii85", "<~87cUR", &[]), "unbalanced");
}

// ---------------------------------------------------------------- Z85 ----

#[test]
fn z85_spec_vector_and_roundtrip() {
    let r = reg();
    // 0MQ spec 32 test vector.
    let frame = hex_bytes("864FD26FB559F75B");
    assert_text(run_bytes(&r, "to-z85", &frame, &[]), "HelloWorld");
    assert_bytes(run_text(&r, "from-z85", "HelloWorld", &[]), &frame);

    // Arbitrary multiples of 4 round-trip.
    let blob: Vec<u8> = (0..24u8)
        .map(|i| i.wrapping_mul(37).wrapping_add(11))
        .collect();
    let enc = run_bytes(&r, "to-z85", &blob, &[]).unwrap();
    assert_bytes(run(&r, "from-z85", enc, &[]), &blob);
}

#[test]
fn z85_length_and_symbol_errors() {
    let r = reg();
    // Encode requires input length % 4 == 0.
    let err = run_bytes(&r, "to-z85", b"Hello", &[]).expect_err("expected length error");
    assert_eq!(err.kind, ErrorKind::LengthMismatch);
    // Decode requires character length % 5 == 0 ("Hell" is 4 characters).
    let err = run_text(&r, "from-z85", "Hell", &[]).expect_err("expected length error");
    assert_eq!(err.kind, ErrorKind::LengthMismatch);
    // "Hello" is exactly one valid Z85 group (a nice property of the spec
    // vector: it encodes the 4 bytes 86 4F D2 6F).
    assert_bytes(
        run_text(&r, "from-z85", "Hello", &[]),
        &hex_bytes("864FD26F"),
    );
    // Invalid symbol with offset ('_' is not in the Z85 alphabet).
    let corrupted = "HelloWorld".replace('o', "_"); // first 'o' sits at offset 4
    let err = expect_decode_err(run_text(&r, "from-z85", &corrupted, &[]), "offset 4");
    assert!(err.message.contains('_'));
    // Strict rejects whitespace; relaxed tolerates it.
    expect_decode_err(
        run_text(&r, "from-z85", "Hello World", &pvb(&[("strict", true)])),
        "whitespace",
    );
    assert_bytes(
        run_text(&r, "from-z85", "Hello World", &pvb(&[("strict", false)])),
        &hex_bytes("864FD26FB559F75B"),
    );
}

// ------------------------------------------------------------- Base91 ----

#[test]
fn base91_reference_vectors() {
    let r = reg();
    // Vectors generated with the canonical reference implementation
    // (mscdex/base91.js, a port of Joachim Henke's basE91).
    assert_text(run_bytes(&r, "to-base91", b"hello", &[]), "TPwJh>A");
    assert_text(run_bytes(&r, "to-base91", b"basE91", &[]), "[D7gZoHB");
    assert_text(
        run_bytes(&r, "to-base91", b"Hello, world!", &[]),
        ">OwJh>}A\"=r@@Y?F",
    );
    assert_text(run_bytes(&r, "to-base91", &[0], &[]), "AA");
    assert_text(run_bytes(&r, "to-base91", &[0, 0, 1], &[]), "AAEA");
    assert_text(
        run_bytes(&r, "to-base91", &[0xff, 0xff, 0xff, 0xff], &[]),
        "B\"B\"#",
    );

    // Decode vectors and round-trips.
    assert_bytes(run_text(&r, "from-base91", "TPwJh>A", &[]), b"hello");
    let blob: Vec<u8> = (0..64u8)
        .map(|i| i.wrapping_mul(31).wrapping_add(7))
        .collect();
    let enc = run_bytes(&r, "to-base91", &blob, &[]).unwrap();
    assert_bytes(run(&r, "from-base91", enc, &[]), &blob);
}

#[test]
fn base91_strict_and_relaxed_policy() {
    let r = reg();
    // Strict: foreign characters are named with offsets.
    let err = expect_decode_err(
        run_text(&r, "from-base91", "TPwJh A", &pvb(&[("strict", true)])),
        "offset 5",
    );
    assert!(err.message.contains(' '));
    // Relaxed: skips them (the reference decoder's behavior).
    assert_bytes(
        run_text(&r, "from-base91", "TPwJh >A", &pvb(&[("strict", false)])),
        b"hello",
    );
}

// --------------------------------------------------------- Input bounds ----

#[test]
fn bignum_conversions_capped_at_1mib() {
    let r = reg();
    let too_big = vec![0x41u8; (1 << 20) + 1];
    for id in ["to-base36", "to-base58", "to-base62"] {
        let err = run_bytes(&r, id, &too_big, &[]).expect_err("expected budget error");
        assert_eq!(err.kind, ErrorKind::BudgetExceeded, "{id}");
    }
    let big_text = "1".repeat((1 << 20) + 1);
    for (id, params) in [
        ("from-base36", Vec::new()),
        ("from-base58", Vec::new()),
        ("from-base62", Vec::new()),
    ] {
        let err = run_text(&r, id, &big_text, &params).expect_err("expected budget error");
        assert_eq!(err.kind, ErrorKind::BudgetExceeded, "{id}");
    }
}

/// Test-local hex decoder (independent of the operations under test).
fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}
