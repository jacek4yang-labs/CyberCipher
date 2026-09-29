//! Simple substitution ciphers: Caesar, the ROT family, Atbash, and Affine.
//!
//! All of them are monoalphabetic substitutions over `A`..=`Z`: letters are
//! mapped one-to-one, non-letters pass through untouched, and
//! [`CaseOptions::preserve_case`] (default `true`) decides whether the output
//! keeps each letter's original case. Ciphers that are involutions (ROT13,
//! ROT47, Atbash) expose `decode` as a documented alias of `encode`.
//!
//! Errors are typed: an Affine multiplier that is not invertible mod 26 (e.g.
//! `a = 13`, `gcd(13, 26) = 13`) is rejected with expected/actual evidence
//! instead of silently colliding letters.

use super::{check_text, TextResult};
use cybercipher_core::error::OperationError;
use serde::{Deserialize, Serialize};

/// Case handling shared by the simple and polyalphabetic ciphers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaseOptions {
    /// Keep each letter's original case in the output. Default: `true`.
    pub preserve_case: bool,
}

impl Default for CaseOptions {
    fn default() -> Self {
        Self {
            preserve_case: true,
        }
    }
}

/// Map every ASCII letter through `f` (which operates on `A`..=`Z`), leaving
/// other characters untouched. `preserve_case` re-applies the original case to
/// the mapped letter.
fn map_letters(
    text: &str,
    options: &CaseOptions,
    f: impl Fn(u8) -> u8,
) -> Result<TextResult, OperationError> {
    check_text(text)?;
    let mut out = String::with_capacity(text.len());
    let mut letters = 0usize;
    let mut passthrough = 0usize;
    for ch in text.chars() {
        if ch.is_ascii_alphabetic() {
            let upper = ch.to_ascii_uppercase();
            let mapped = f(upper as u8) as char;
            out.push(if options.preserve_case && ch.is_ascii_lowercase() {
                mapped.to_ascii_lowercase()
            } else {
                mapped
            });
            letters += 1;
        } else {
            out.push(ch);
            passthrough += 1;
        }
    }
    Ok(TextResult {
        output: out,
        letters,
        passthrough,
    })
}

/// Validate and normalize an Affine multiplier: returns `a mod 26` when
/// `gcd(a, 26) == 1`, else a typed error with expected/actual evidence.
fn affine_multiplier(a: u32) -> Result<u32, OperationError> {
    let a = a % 26;
    let gcd = gcd(a, 26);
    if gcd != 1 {
        return Err(OperationError::invalid_param(
            "a",
            "Affine multiplier must satisfy gcd(a, 26) = 1",
        )
        .with_expected("gcd(a, 26) = 1")
        .with_actual(format!("gcd({a}, 26) = {gcd}"))
        .with_details(
            "every multiplier that shares a factor with 26 maps two letters to the same \
             ciphertext letter, making the cipher non-invertible",
        ));
    }
    Ok(a)
}

fn gcd(a: u32, b: u32) -> u32 {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

/// Modular inverse of `a` mod 26, assuming `gcd(a, 26) == 1`.
fn inverse_mod_26(a: u32) -> u32 {
    for x in 1u32..26 {
        if (a * x) % 26 == 1 {
            return x;
        }
    }
    unreachable!("gcd(a, 26) == 1 guarantees an inverse in 1..26")
}

// ------------------------------------------------------------ Caesar ----

/// Caesar-encode `text` with shift `k` (`c = (p + k) mod 26`). Negative
/// shifts are accepted and normalized (`shift.rem_euclid(26)`).
pub fn caesar_encode(
    text: &str,
    shift: i32,
    options: &CaseOptions,
) -> Result<TextResult, OperationError> {
    let k = shift.rem_euclid(26) as u8;
    map_letters(text, options, |p| (p - b'A' + k) % 26 + b'A')
}

/// Caesar-decode `text` with shift `k` (`p = (c - k) mod 26`).
pub fn caesar_decode(
    text: &str,
    shift: i32,
    options: &CaseOptions,
) -> Result<TextResult, OperationError> {
    caesar_encode(text, -shift, options)
}

/// ROT13 = Caesar with shift 13. The canonical newsgroup cipher; an
/// involution, so decode is an alias of encode.
pub fn rot13_encode(text: &str, options: &CaseOptions) -> Result<TextResult, OperationError> {
    caesar_encode(text, 13, options)
}

/// ROT13-decode: identical to [`rot13_encode`] (ROT13 is its own inverse).
pub fn rot13_decode(text: &str, options: &CaseOptions) -> Result<TextResult, OperationError> {
    caesar_encode(text, 13, options)
}

// ------------------------------------------------------------- ROT5 ----

/// ROT5-encode: rotate digits `0`..=`9` by 5; letters and other characters
/// pass through. An involution, so decode is an alias of encode.
pub fn rot5_encode(text: &str) -> Result<TextResult, OperationError> {
    check_text(text)?;
    let mut out = String::with_capacity(text.len());
    let mut letters = 0usize;
    let mut passthrough = 0usize;
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            out.push(((ch as u8 - b'0' + 5) % 10 + b'0') as char);
            letters += 1;
        } else {
            out.push(ch);
            passthrough += 1;
        }
    }
    Ok(TextResult {
        output: out,
        letters,
        passthrough,
    })
}

/// ROT5-decode: identical to [`rot5_encode`] (ROT5 is its own inverse).
pub fn rot5_decode(text: &str) -> Result<TextResult, OperationError> {
    rot5_encode(text)
}

/// ROT18-encode: ROT13 for letters combined with ROT5 for digits (the "NT"
/// text-obfuscation scheme). An involution, so decode is an alias of encode.
pub fn rot18_encode(text: &str, options: &CaseOptions) -> Result<TextResult, OperationError> {
    check_text(text)?;
    let caesar = caesar_encode(text, 13, options)?;
    let rot5 = rot5_encode(&caesar.output)?;
    Ok(TextResult {
        output: rot5.output,
        letters: caesar.letters,
        passthrough: caesar.passthrough,
    })
}

/// ROT18-decode: identical to [`rot18_encode`] (ROT18 is its own inverse).
pub fn rot18_decode(text: &str, options: &CaseOptions) -> Result<TextResult, OperationError> {
    rot18_encode(text, options)
}

// ------------------------------------------------------------ ROT47 ----

/// ROT47-encode: rotate ASCII 33..=126 by 47 (a 94-character alphabet), which
/// scrambles punctuation and digits along with letters. Characters outside
/// the range pass through. An involution, so decode is an alias of encode.
pub fn rot47_encode(text: &str) -> Result<TextResult, OperationError> {
    check_text(text)?;
    let mut out = String::with_capacity(text.len());
    let mut letters = 0usize;
    let mut passthrough = 0usize;
    for ch in text.chars() {
        let code = ch as u32;
        if (33..=126).contains(&code) {
            out.push(char::from_u32(33 + (code - 33 + 47) % 94).expect("33..=126 maps to ASCII"));
            letters += 1;
        } else {
            out.push(ch);
            passthrough += 1;
        }
    }
    Ok(TextResult {
        output: out,
        letters,
        passthrough,
    })
}

/// ROT47-decode: identical to [`rot47_encode`] (ROT47 is its own inverse).
pub fn rot47_decode(text: &str) -> Result<TextResult, OperationError> {
    rot47_encode(text)
}

// ------------------------------------------------------------ Atbash ----

/// Atbash-encode: mirror the alphabet (`a↔z`, `b↔y`, ...). An involution, so
/// decode is an alias of encode.
pub fn atbash_encode(text: &str, options: &CaseOptions) -> Result<TextResult, OperationError> {
    map_letters(text, options, |p| b'Z' - (p - b'A'))
}

/// Atbash-decode: identical to [`atbash_encode`] (Atbash is its own inverse).
pub fn atbash_decode(text: &str, options: &CaseOptions) -> Result<TextResult, OperationError> {
    atbash_encode(text, options)
}

// ------------------------------------------------------------ Affine ----

/// Precomputed invertibility facts about an Affine multiplier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffineCheck {
    /// The multiplier as given.
    pub a: u32,
    /// `gcd(a, 26)`.
    pub gcd: u32,
    /// `true` when `a` is usable (`gcd == 1`).
    pub invertible: bool,
    /// The modular inverse `a⁻¹ mod 26` when invertible.
    pub a_inverse: Option<u32>,
}

/// Inspect an Affine multiplier without transforming text: reports the gcd
/// with 26, invertibility, and the modular inverse when one exists.
pub fn affine_check(a: u32) -> AffineCheck {
    let a = a % 26;
    let g = gcd(a, 26);
    AffineCheck {
        a,
        gcd: g,
        invertible: g == 1,
        a_inverse: (g == 1).then(|| inverse_mod_26(a)),
    }
}

/// Affine-encode `text`: `c = (a·p + b) mod 26`. The multiplier must satisfy
/// `gcd(a, 26) = 1` (every letter then maps to a distinct letter); otherwise
/// a typed error with expected/actual is returned.
pub fn affine_encode(
    text: &str,
    a: u32,
    b: u32,
    options: &CaseOptions,
) -> Result<TextResult, OperationError> {
    let a = affine_multiplier(a)?;
    let b = b % 26;
    map_letters(text, options, |p| {
        ((a * u32::from(p - b'A') + b) % 26) as u8 + b'A'
    })
}

/// Affine-decode `text`: `p = a⁻¹·(c - b) mod 26`. Same `gcd(a, 26) = 1`
/// validation as [`affine_encode`].
pub fn affine_decode(
    text: &str,
    a: u32,
    b: u32,
    options: &CaseOptions,
) -> Result<TextResult, OperationError> {
    let a = affine_multiplier(a)?;
    let a_inv = inverse_mod_26(a);
    let b = (b % 26) as i32;
    map_letters(text, options, |c| {
        let x = (i32::from(c - b'A') - b).rem_euclid(26);
        ((a_inv * x as u32) % 26) as u8 + b'A'
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPT: CaseOptions = CaseOptions {
        preserve_case: true,
    };

    #[test]
    fn caesar_known_vector() {
        assert_eq!(
            caesar_encode("THE QUICK BROWN FOX", 3, &OPT)
                .unwrap()
                .output,
            "WKH TXLFN EURZQ IRA"
        );
        assert_eq!(
            caesar_decode("WKH TXLFN EURZQ IRA", 3, &OPT)
                .unwrap()
                .output,
            "THE QUICK BROWN FOX"
        );
    }

    #[test]
    fn rot13_known_vector_and_involution() {
        assert_eq!(rot13_encode("Hello", &OPT).unwrap().output, "Uryyb");
        assert_eq!(rot13_decode("Uryyb", &OPT).unwrap().output, "Hello");
        assert_eq!(
            rot13_decode(rot13_encode("Hello", &OPT).unwrap().output.as_str(), &OPT)
                .unwrap()
                .output,
            "Hello"
        );
    }

    #[test]
    fn caesar_wraps_and_normalizes_shift() {
        assert_eq!(caesar_encode("xyz", 3, &OPT).unwrap().output, "abc");
        assert_eq!(
            caesar_encode("abc", 26 + 3, &OPT).unwrap().output,
            caesar_encode("abc", 3, &OPT).unwrap().output
        );
        assert_eq!(
            caesar_encode("abc", -23, &OPT).unwrap().output,
            caesar_encode("abc", 3, &OPT).unwrap().output
        );
    }

    #[test]
    fn preserve_case_off_uppercases_everything() {
        let opt = CaseOptions {
            preserve_case: false,
        };
        assert_eq!(rot13_encode("Hello", &opt).unwrap().output, "URYYB");
    }

    #[test]
    fn rot5_rotates_digits_only() {
        assert_eq!(rot5_encode("a1b2!").unwrap().output, "a6b7!");
        assert_eq!(rot5_decode("a6b7!").unwrap().output, "a1b2!");
        assert_eq!(rot5_encode("0123456789").unwrap().output, "5678901234");
    }

    #[test]
    fn rot18_combines_rot13_and_rot5() {
        let out = rot18_encode("Attack at 10:45!", &OPT).unwrap().output;
        assert_eq!(out, "Nggnpx ng 65:90!");
        assert_eq!(rot18_decode(&out, &OPT).unwrap().output, "Attack at 10:45!");
    }

    #[test]
    fn rot47_known_vector_and_involution() {
        assert_eq!(rot47_encode("Hello").unwrap().output, "w6==@");
        assert_eq!(rot47_encode("ab").unwrap().output, "23");
        let enc = rot47_encode("Hello, World! 123 {abc}").unwrap().output;
        assert_eq!(
            rot47_decode(&enc).unwrap().output,
            "Hello, World! 123 {abc}"
        );
        // Non-range characters pass through.
        assert_eq!(rot47_encode("a\tb\n").unwrap().output, "2\t3\n");
    }

    #[test]
    fn atbash_mirrors_and_involutes() {
        assert_eq!(atbash_encode("Hello", &OPT).unwrap().output, "Svool");
        assert_eq!(atbash_decode("Svool", &OPT).unwrap().output, "Hello");
        assert_eq!(atbash_encode("AZaz", &OPT).unwrap().output, "ZAza");
    }

    #[test]
    fn affine_known_vector() {
        // Classic Wikipedia example: a=5, b=8.
        let enc = affine_encode("AFFINECIPHER", 5, 8, &OPT).unwrap();
        assert_eq!(enc.output, "IHHWVCSWFRCP");
        assert_eq!(
            affine_decode("IHHWVCSWFRCP", 5, 8, &OPT).unwrap().output,
            "AFFINECIPHER"
        );
    }

    #[test]
    fn affine_rejects_non_invertible_multiplier() {
        let err = affine_encode("test", 13, 4, &OPT).unwrap_err();
        assert_eq!(err.expected.as_deref(), Some("gcd(a, 26) = 1"));
        assert_eq!(err.actual.as_deref(), Some("gcd(13, 26) = 13"));
        assert!(matches!(
            err.kind,
            cybercipher_core::error::ErrorKind::InvalidParam
        ));
        assert!(affine_decode("test", 0, 4, &OPT).is_err());
        // Invertible multipliers round-trip.
        for a in [1u32, 3, 5, 7, 11, 17, 25] {
            let enc = affine_encode("roundtrip", a, 9, &OPT).unwrap();
            assert_eq!(
                affine_decode(&enc.output, a, 9, &OPT).unwrap().output,
                "roundtrip"
            );
        }
    }

    #[test]
    fn affine_check_reports_inverse() {
        let ok = affine_check(5);
        assert!(ok.invertible);
        assert_eq!(ok.a_inverse, Some(21));
        let bad = affine_check(13);
        assert!(!bad.invertible);
        assert_eq!(bad.a_inverse, None);
        let wrapped = affine_check(31);
        assert_eq!(wrapped.a, 5);
    }

    #[test]
    fn counters_are_honest() {
        let r = caesar_encode("ab, cd!", 1, &OPT).unwrap();
        assert_eq!(r.letters, 4);
        assert_eq!(r.passthrough, 3, "comma, space, exclamation");
        let r = caesar_encode("a b", 1, &OPT).unwrap();
        assert_eq!(r.letters, 2);
        assert_eq!(r.passthrough, 1);
    }

    #[test]
    fn oversized_input_rejected() {
        let big = "a".repeat(super::super::MAX_TEXT_BYTES + 1);
        assert!(caesar_encode(&big, 1, &OPT).is_err());
        assert!(rot47_encode(&big).is_err());
    }
}
