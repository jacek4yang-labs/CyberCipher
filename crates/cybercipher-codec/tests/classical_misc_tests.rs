//! Round-trip and known-answer tests for the classical/misc encodings:
//! Morse (ITU-R M.1677), A1Z26, tap code, Bacon, and Braille.

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

fn pv(params: &[(&'static str, &str)]) -> Vec<(&'static str, ParamValue)> {
    params
        .iter()
        .map(|(k, v)| (*k, ParamValue::Str(v.to_string())))
        .collect()
}

fn pvb(params: &[(&'static str, bool)]) -> Vec<(&'static str, ParamValue)> {
    params
        .iter()
        .map(|(k, v)| (*k, ParamValue::Bool(*v)))
        .collect()
}

fn assert_text(out: OpResult<Value>, expected: &str) {
    match out.expect("operation failed") {
        Value::Text(t) => assert_eq!(t, expected),
        other => panic!("expected text, got {other:?}"),
    }
}

fn expect_err(out: OpResult<Value>, needle: &str) -> OperationError {
    let err = out.expect_err("expected an error");
    assert!(
        err.message.contains(needle),
        "error `{}` does not contain `{needle}`",
        err.message
    );
    err
}

// -------------------------------------------------------------- Morse ----

#[test]
fn morse_sos_roundtrip_and_word_separator() {
    let r = reg();
    assert_text(run_text(&r, "to-morse", "SOS", &[]), "... --- ...");
    assert_text(run_text(&r, "from-morse", "... --- ...", &[]), "SOS");

    // Words are separated by " / ".
    assert_text(
        run_text(&r, "to-morse", "SOS SOS", &[]),
        "... --- ... / ... --- ...",
    );
    assert_text(
        run_text(&r, "from-morse", "... --- ... / ... --- ...", &[]),
        "SOS SOS",
    );

    // Digits and punctuation subset (ITU-R M.1677).
    assert_text(run_text(&r, "to-morse", "A1", &[]), ".- .----");
    assert_text(run_text(&r, "from-morse", ".- .----", &[]), "A1");
    assert_text(run_text(&r, "to-morse", "CTF?", &[]), "-.-. - ..-. ..--..");
    assert_text(
        run_text(&r, "from-morse", "-.-. - ..-. ..--..", &[]),
        "CTF?",
    );
}

#[test]
fn morse_errors() {
    let r = reg();
    // Unknown character is named with its offset in strict mode.
    let err = expect_err(run_text(&r, "to-morse", "SO#S", &[]), "no Morse code");
    assert!(err.message.contains('#'));
    assert!(err.message.contains("offset 2"));
    // Relaxed mode drops it.
    assert_text(
        run_text(&r, "to-morse", "SO#S", &pvb(&[("strict", false)])),
        "... --- ...",
    );
    // Unknown sequence in strict decode.
    expect_err(
        run_text(&r, "from-morse", "........", &[]),
        "unknown Morse sequence",
    );
    // Relaxed decode drops unknown sequences.
    assert_text(
        run_text(
            &r,
            "from-morse",
            "... -------- ---",
            &pvb(&[("strict", false)]),
        ),
        "SO",
    );
}

// ------------------------------------------------------------- A1Z26 ----

#[test]
fn a1z26_roundtrip_with_delimiters() {
    let r = reg();
    assert_text(run_text(&r, "to-a1z26", "HELLO", &[]), "8-5-12-12-15");
    assert_text(run_text(&r, "from-a1z26", "8-5-12-12-15", &[]), "HELLO");

    // Word separator is emitted surrounded by spaces.
    assert_text(run_text(&r, "to-a1z26", "HI YOU", &[]), "8-9 / 25-15-21");
    assert_text(run_text(&r, "from-a1z26", "8-9 / 25-15-21", &[]), "HI YOU");

    // Custom delimiter round-trip.
    let params = pv(&[("delimiter", "+")]);
    assert_text(run_text(&r, "to-a1z26", "ABC", &params), "1+2+3");
    assert_text(run_text(&r, "from-a1z26", "1+2+3", &params), "ABC");

    // Lowercase input folds to uppercase letters.
    assert_text(run_text(&r, "to-a1z26", "abc", &[]), "1-2-3");
}

#[test]
fn a1z26_delimiter_required_and_validation() {
    let r = reg();
    // Documented ambiguity handling: a bare `12` is the single number 12 (L);
    // `1-2` is required for AB.
    assert_text(run_text(&r, "from-a1z26", "12", &[]), "L");
    assert_text(run_text(&r, "from-a1z26", "1-2", &[]), "AB");
    // Runs of digits longer than two are ambiguous -> rejected.
    expect_err(
        run_text(&r, "from-a1z26", "1920", &[]),
        "ambiguous without delimiters",
    );
    // Values outside 1-26 are rejected.
    expect_err(run_text(&r, "from-a1z26", "27-1", &[]), "outside the 1-26");
    expect_err(run_text(&r, "from-a1z26", "0", &[]), "outside the 1-26");
    // Non-numeric tokens are rejected.
    expect_err(run_text(&r, "from-a1z26", "8-x", &[]), "not a number");
    // Encode rejects non-letters in strict mode, drops them relaxed.
    let err = expect_err(run_text(&r, "to-a1z26", "H1", &[]), "not a letter");
    assert!(err.message.contains('1'));
    assert_text(
        run_text(&r, "to-a1z26", "H1!", &pvb(&[("strict", false)])),
        "8",
    );
    // Empty delimiter parameter is rejected (ambiguity by design).
    let err = run_text(&r, "from-a1z26", "1 2", &pv(&[("delimiter", "")]))
        .expect_err("expected invalid param");
    assert_eq!(err.kind, ErrorKind::InvalidParam);
}

// ----------------------------------------------------------- Tap code ----

#[test]
fn tapcode_roundtrip_and_k_convention() {
    let r = reg();
    assert_text(
        run_text(&r, "to-tapcode", "HELLO", &[]),
        ".. ... / . ..... / ... . / ... . / ... ....",
    );
    assert_text(
        run_text(
            &r,
            "from-tapcode",
            ".. ... / . ..... / ... . / ... . / ... ....",
            &[],
        ),
        "HELLO",
    );
    // Classic convention: K is tapped as C (row 1, column 3).
    assert_text(run_text(&r, "to-tapcode", "K", &[]), ". ...");
    // Decode maps the cell back to C (K is indistinguishable, documented).
    assert_text(run_text(&r, "from-tapcode", ". ...", &[]), "C");
}

#[test]
fn tapcode_errors() {
    let r = reg();
    // Non-letters in strict encode.
    let err = expect_err(run_text(&r, "to-tapcode", "H3", &[]), "not a letter");
    assert!(err.message.contains('3'));
    assert_text(
        run_text(&r, "to-tapcode", "H3", &pvb(&[("strict", false)])),
        ".. ...",
    );
    // A group must have exactly two dot groups.
    expect_err(
        run_text(&r, "from-tapcode", "... ... ..", &[]),
        "two dot groups",
    );
    // Dot counts outside 1-5 are rejected.
    expect_err(run_text(&r, "from-tapcode", "...... ..", &[]), "1-5");
    // Foreign symbols inside a dot group are rejected.
    expect_err(
        run_text(&r, "from-tapcode", "..- ..", &[]),
        "other than `.`",
    );
}

// -------------------------------------------------------------- Bacon ----

#[test]
fn bacon_roundtrip() {
    let r = reg();
    // Standard Bacon 24-letter table: A=0 ... H=7 = aabbb, E=4 = aabaa,
    // L=10 = ababa, O=13 = abbab.
    assert_text(
        run_text(&r, "to-bacon", "HELLO", &[]),
        "AABBB AABAA ABABA ABABA ABBAB",
    );
    assert_text(
        run_text(&r, "from-bacon", "AABBB AABAA ABABA ABABA ABBAB", &[]),
        "HELLO",
    );

    // J merges into I (8 = abaaa), V merges into U (19 = baabb).
    assert_text(run_text(&r, "to-bacon", "JJ", &[]), "ABAAA ABAAA");
    assert_text(run_text(&r, "from-bacon", "ABAAA ABAAA", &[]), "II");
    assert_text(run_text(&r, "to-bacon", "V", &[]), "BAABB");

    // Custom symbols (dot/dash style) round-trip.
    let params = pv(&[("letter_a", "."), ("letter_b", "-")]);
    assert_text(
        run_text(&r, "to-bacon", "HELLO", &params),
        "..--- ..-.. .-.-. .-.-. .--.-",
    );
    assert_text(
        run_text(&r, "from-bacon", "..--- ..-.. .-.-. .-.-. .--.-", &params),
        "HELLO",
    );

    // Lowercase folds; the canonical opening of the Bacon alphabet.
    assert_text(run_text(&r, "to-bacon", "abc", &[]), "AAAAA AAAAB AAABA");
}

#[test]
fn bacon_errors() {
    let r = reg();
    // Non-letters in strict encode.
    expect_err(run_text(&r, "to-bacon", "AB C", &[]), "not one of the 24");
    assert_text(
        run_text(&r, "to-bacon", "AB C", &pvb(&[("strict", false)])),
        "AAAAA AAAAB AAABA",
    );
    // Foreign symbols in strict decode.
    expect_err(
        run_text(&r, "from-bacon", "AAACB", &[]),
        "neither the A symbol",
    );
    // Out-of-range group value (BBBBB = 31 > 23).
    expect_err(
        run_text(&r, "from-bacon", "BBBBB", &[]),
        "outside the 24-letter",
    );
    // Relaxed decode drops the group.
    assert_text(
        run_text(&r, "from-bacon", "BBBBB AAAAA", &pvb(&[("strict", false)])),
        "A",
    );
    // Symbol count not a multiple of 5.
    expect_err(run_text(&r, "from-bacon", "AAAA", &[]), "multiple of 5");
    // Identical A/B symbols are rejected.
    let err = run_text(
        &r,
        "to-bacon",
        "AB",
        &pv(&[("letter_a", "x"), ("letter_b", "x")]),
    )
    .expect_err("expected invalid param");
    assert_eq!(err.kind, ErrorKind::InvalidParam);
}

// ------------------------------------------------------------ Braille ----

#[test]
fn braille_roundtrip() {
    let r = reg();
    assert_text(
        run_text(&r, "to-braille", "Hello", &[]),
        "\u{2813}\u{2811}\u{2807}\u{2807}\u{2815}",
    );
    assert_text(
        run_text(
            &r,
            "from-braille",
            "\u{2813}\u{2811}\u{2807}\u{2807}\u{2815}",
            &[],
        ),
        "HELLO",
    );

    // Digits carry the number sign before each digit (reversible).
    assert_text(
        run_text(&r, "to-braille", "Hi 42", &[]),
        "\u{2813}\u{280a} \u{283c}\u{2819}\u{283c}\u{2803}",
    );
    assert_text(
        run_text(
            &r,
            "from-braille",
            "\u{2813}\u{280a} \u{283c}\u{2819}\u{283c}\u{2803}",
            &[],
        ),
        "HI 42",
    );

    // Punctuation subset.
    assert_text(
        run_text(&r, "to-braille", "Hi!", &[]),
        "\u{2813}\u{280a}\u{2816}",
    );
    assert_text(
        run_text(&r, "from-braille", "\u{2813}\u{280a}\u{2816}", &[]),
        "HI!",
    );

    // With the number sign disabled, digits use bare a-j patterns
    // (ambiguous with letters, documented).
    assert_text(
        run_text(&r, "to-braille", "42", &pvb(&[("digit_sign", false)])),
        "\u{2819}\u{2803}",
    );
}

#[test]
fn braille_errors() {
    let r = reg();
    // Unsupported character in strict encode.
    let err = expect_err(run_text(&r, "to-braille", "a~b", &[]), "no grade-1 Braille");
    assert!(err.message.contains('~'));
    assert_text(
        run_text(&r, "to-braille", "a~b", &pvb(&[("strict", false)])),
        "\u{2801}\u{2803}",
    );
    // Unsupported pattern in strict decode (U+287F uses dots 7/8).
    expect_err(
        run_text(&r, "from-braille", "\u{2813}\u{287f}", &[]),
        "unsupported Braille pattern",
    );
    // Non-Braille character in strict decode.
    expect_err(
        run_text(&r, "from-braille", "x\u{2801}", &[]),
        "not a Braille pattern",
    );
    // Relaxed decode drops them.
    assert_text(
        run_text(
            &r,
            "from-braille",
            "\u{2813}\u{287f}\u{2811}",
            &pvb(&[("strict", false)]),
        ),
        "HE",
    );
    // A number sign must be followed by a digit pattern (a-j). W (`⠺`,
    // 0x3A) is a letter pattern outside the digit set.
    expect_err(
        run_text(&r, "from-braille", "\u{283c}\u{283a}", &[]),
        "expected a digit pattern",
    );
    // Digit patterns double as letters a-j: after a number sign they decode
    // as digits (H = digit 8).
    assert_text(run_text(&r, "from-braille", "\u{283c}\u{2813}", &[]), "8");
}

// ------------------------------------------------------------ ROT13 ----

#[test]
fn rot13_known_answer_and_involution() {
    let r = reg();
    assert_text(
        run_text(&r, "rot13", "Hello, World! 123", &[]),
        "Uryyb, Jbeyq! 123",
    );
    // Involution: applying it twice reproduces the input.
    let once = run_text(&r, "rot13", "flag{rot13_roundtrip}", &[]).unwrap();
    let Value::Text(once) = once else { panic!() };
    assert_text(run_text(&r, "rot13", &once, &[]), "flag{rot13_roundtrip}");
}

#[test]
fn rot13_non_letters_pass_through() {
    let r = reg();
    assert_text(
        run_text(&r, "rot13", "ABC-xyz_019 {[{}]}", &[]),
        "NOP-klm_019 {[{}]}",
    );
}

// ------------------------------------------------------------ Atbash ----

#[test]
fn atbash_known_answer_and_involution() {
    let r = reg();
    assert_text(
        run_text(&r, "atbash", "Hello, World!", &[]),
        "Svool, Dliow!",
    );
    let once = run_text(&r, "atbash", "flag{atbash_roundtrip}", &[]).unwrap();
    let Value::Text(once) = once else { panic!() };
    assert_text(run_text(&r, "atbash", &once, &[]), "flag{atbash_roundtrip}");
}
