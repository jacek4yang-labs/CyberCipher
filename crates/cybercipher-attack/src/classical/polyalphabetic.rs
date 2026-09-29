//! Polyalphabetic substitution ciphers: Vigenere, Autokey, Beaufort,
//! Gronsfeld, and Porta.
//!
//! All of them take a key that advances per plaintext letter (non-letters pass
//! through and do not advance the key), normalize to `A`..=`Z` internally, and
//! honor [`super::simple::CaseOptions::preserve_case`].
//!
//! Variant semantics:
//!
//! * **Vigenère** — `c = (p + k) mod 26` with the key repeated over letters.
//! * **Autokey** — the running key is the key followed by the plaintext
//!   itself (key-then-plaintext convention), so decryption reconstructs the
//!   keystream progressively.
//! * **Beaufort** — `c = (k - p) mod 26`; an involution, so decode is an
//!   alias of encode.
//! * **Gronsfeld** — Vigenère with a numeric key: each decimal digit of the
//!   key is the shift for its letter position (digits 0..=9 only).
//! * **Porta** — the reciprocal 13-row tableau (keys `A/B` share row 0,
//!   `C/D` row 1, ...): for row `r`, letters `a..m` map to
//!   `n + ((p + r) mod 13)` and letters `n..z` map to `(p - r) mod 13`.
//!   Every row is an involution, so decode is an alias of encode.
//!
//! Keys must contain at least one letter (Gronsfeld: at least one digit) and
//! at most 1 KiB; otherwise a typed [`OperationError`] with expected/actual is
//! returned.

use super::simple::CaseOptions;
use super::{check_key, check_text, TextResult};
use cybercipher_core::error::OperationError;

/// Normalize a key to uppercase ASCII letters; errors when nothing usable
/// remains.
fn letter_key(key: &str) -> Result<Vec<u8>, OperationError> {
    check_key(key)?;
    let letters: Vec<u8> = key
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase() as u8)
        .collect();
    if letters.is_empty() {
        return Err(OperationError::key("key must contain at least one letter")
            .with_parameter("key")
            .with_expected("at least one ASCII letter")
            .with_actual(format!("{key:?}")));
    }
    Ok(letters)
}

/// Normalize a Gronsfeld key to decimal digits; errors when nothing usable
/// remains.
fn digit_key(key: &str) -> Result<Vec<u8>, OperationError> {
    check_key(key)?;
    let digits: Vec<u8> = key
        .chars()
        .filter_map(|c| c.to_digit(10))
        .map(|d| d as u8)
        .collect();
    if digits.is_empty() {
        return Err(
            OperationError::key("Gronsfeld key must contain at least one digit")
                .with_parameter("key")
                .with_expected("at least one decimal digit (0-9)")
                .with_actual(format!("{key:?}")),
        );
    }
    Ok(digits)
}

/// Shared transform over letters with a cycling key: `f(plaintext_letter,
/// key_letter) -> ciphertext_letter`. Non-letters pass through without
/// advancing the key.
fn transform_with_key(
    text: &str,
    key: &[u8],
    options: &CaseOptions,
    f: impl Fn(u8, u8) -> u8,
) -> Result<TextResult, OperationError> {
    check_text(text)?;
    let mut out = String::with_capacity(text.len());
    let mut letters = 0usize;
    let mut passthrough = 0usize;
    for ch in text.chars() {
        if ch.is_ascii_alphabetic() {
            let upper = ch.to_ascii_uppercase() as u8;
            let k = key[letters % key.len()];
            let mapped = f(upper, k) as char;
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

// ---------------------------------------------------------- Vigenere ----

/// Vigenère-encode `text` with `key` (`c = (p + k) mod 26`).
pub fn vigenere_encode(
    text: &str,
    key: &str,
    options: &CaseOptions,
) -> Result<TextResult, OperationError> {
    let key = letter_key(key)?;
    transform_with_key(text, &key, options, |p, k| {
        (p - b'A' + k - b'A') % 26 + b'A'
    })
}

/// Vigenère-decode `text` with `key` (`p = (c - k) mod 26`).
pub fn vigenere_decode(
    text: &str,
    key: &str,
    options: &CaseOptions,
) -> Result<TextResult, OperationError> {
    let key = letter_key(key)?;
    transform_with_key(text, &key, options, |c, k| (c + 26 - k) % 26 + b'A')
}

// ------------------------------------------------------------ Autokey ----

/// Autokey-encode `text`: the running key is `key` followed by the plaintext
/// letters themselves. Errors when the text has no letters to extend the
/// keystream with beyond the key (the key must be at least one letter).
pub fn autokey_encode(
    text: &str,
    key: &str,
    options: &CaseOptions,
) -> Result<TextResult, OperationError> {
    let key = letter_key(key)?;
    check_text(text)?;
    // Pass 1: collect the plaintext letters to build the full keystream.
    let mut keystream = key.clone();
    for ch in text.chars() {
        if ch.is_ascii_alphabetic() {
            keystream.push(ch.to_ascii_uppercase() as u8);
        }
    }
    transform_with_key(text, &keystream, options, |p, k| {
        (p - b'A' + k - b'A') % 26 + b'A'
    })
}

/// Autokey-decode `text`: the keystream is `key` followed by the plaintext as
/// it is recovered, letter by letter.
pub fn autokey_decode(
    text: &str,
    key: &str,
    options: &CaseOptions,
) -> Result<TextResult, OperationError> {
    let key = letter_key(key)?;
    check_text(text)?;
    // The keystream so far: key letters first, then recovered plaintext
    // letters (stored as ASCII uppercase like the key itself).
    let mut keystream: Vec<u8> = key.clone();
    let mut letters = 0usize;
    let mut out = String::with_capacity(text.len());
    let mut passthrough = 0usize;
    for ch in text.chars() {
        if ch.is_ascii_alphabetic() {
            let c = ch.to_ascii_uppercase() as u8;
            let k = keystream[letters];
            let p = (c + 26 - k) % 26;
            keystream.push(p + b'A');
            let mapped = (p + b'A') as char;
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

// ----------------------------------------------------------- Beaufort ----

/// Beaufort-encode `text` (`c = (k - p) mod 26`). An involution, so decode is
/// an alias of encode.
pub fn beaufort_encode(
    text: &str,
    key: &str,
    options: &CaseOptions,
) -> Result<TextResult, OperationError> {
    let key = letter_key(key)?;
    transform_with_key(text, &key, options, |p, k| (k + 26 - p) % 26 + b'A')
}

/// Beaufort-decode `text`: identical to [`beaufort_encode`] (the Beaufort
/// table is reciprocal).
pub fn beaufort_decode(
    text: &str,
    key: &str,
    options: &CaseOptions,
) -> Result<TextResult, OperationError> {
    beaufort_encode(text, key, options)
}

// ---------------------------------------------------------- Gronsfeld ----

/// Gronsfeld-encode `text`: Vigenère with a numeric key — decimal digit `d`
/// shifts its letter by `d` (0..=9), so the effective keyspace is tiny and
/// [`super::cracking::crack_vigenere`] handles it directly.
pub fn gronsfeld_encode(
    text: &str,
    key: &str,
    options: &CaseOptions,
) -> Result<TextResult, OperationError> {
    let digits = digit_key(key)?;
    transform_with_key(text, &digits, options, |p, d| (p - b'A' + d) % 26 + b'A')
}

/// Gronsfeld-decode `text` with the numeric `key`.
pub fn gronsfeld_decode(
    text: &str,
    key: &str,
    options: &CaseOptions,
) -> Result<TextResult, OperationError> {
    let digits = digit_key(key)?;
    transform_with_key(text, &digits, options, |c, d| {
        (c - b'A' + 26 - d) % 26 + b'A'
    })
}

// --------------------------------------------------------------- Porta ----

/// Porta-encode `text` with the reciprocal 13-row tableau: key letters `A/B`
/// share row 0, `C/D` row 1, ... `Y/Z` row 12. For row `r`, letters `a..m`
/// map to `n + ((p + r) mod 13)` and letters `n..z` map to `(p - r) mod 13`.
/// Every row is an involution, so decode is an alias of encode.
pub fn porta_encode(
    text: &str,
    key: &str,
    options: &CaseOptions,
) -> Result<TextResult, OperationError> {
    let key = letter_key(key)?;
    transform_with_key(text, &key, options, |p, k| {
        let row = (k - b'A') / 2;
        if p < b'N' {
            b'N' + (p - b'A' + row) % 13
        } else {
            b'A' + (p - b'N' + 13 - row) % 13
        }
    })
}

/// Porta-decode `text`: identical to [`porta_encode`] (every Porta row is an
/// involution).
pub fn porta_decode(
    text: &str,
    key: &str,
    options: &CaseOptions,
) -> Result<TextResult, OperationError> {
    porta_encode(text, key, options)
}

// ------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::super::simple::map_letters;
    use super::*;

    const OPT: CaseOptions = CaseOptions {
        preserve_case: true,
    };

    #[test]
    fn vigenere_classic_vector() {
        // The textbook vector: ATTACKATDAWN under key LEMON.
        let enc = vigenere_encode("ATTACKATDAWN", "LEMON", &OPT).unwrap();
        assert_eq!(enc.output, "LXFOPVEFRNHR");
        assert_eq!(enc.letters, 12);
        assert_eq!(
            vigenere_decode("LXFOPVEFRNHR", "LEMON", &OPT)
                .unwrap()
                .output,
            "ATTACKATDAWN"
        );
    }

    #[test]
    fn vigenere_skips_non_letters_in_key_advance() {
        // Spaces must not advance the key: "A A A A" with key "BC" gives
        // A+B, A+C, A+B, A+C = B C B C interleaved with spaces.
        assert_eq!(vigenere_encode("AAAA", "BC", &OPT).unwrap().output, "BCBC");
        assert_eq!(
            vigenere_encode("A A A A", "BC", &OPT).unwrap().output,
            "B C B C"
        );
    }

    #[test]
    fn vigenere_preserves_case_and_rejects_bad_keys() {
        assert_eq!(
            vigenere_encode("Attack", "lemon", &OPT).unwrap().output,
            "Lxfopv"
        );
        assert!(vigenere_encode("text", "", &OPT).is_err());
        assert!(vigenere_encode("text", "3!7@", &OPT).is_err(), "no letters");
        assert!(
            vigenere_encode("text", "1234", &OPT).is_err(),
            "digits only"
        );
        let big = "a".repeat(super::super::MAX_KEY_BYTES + 1);
        assert!(vigenere_encode("text", &big, &OPT).is_err());
    }

    #[test]
    fn autokey_key_then_plaintext() {
        // Hand-derived: keystream = QUEENLY + ATTACKATDAWN.
        let enc = autokey_encode("ATTACKATDAWN", "QUEENLY", &OPT).unwrap();
        assert_eq!(enc.output, "QNXEPVYTWTWP");
        assert_eq!(
            autokey_decode("QNXEPVYTWTWP", "QUEENLY", &OPT)
                .unwrap()
                .output,
            "ATTACKATDAWN"
        );
    }

    #[test]
    fn autokey_round_trip_with_mixed_text() {
        let enc = autokey_encode("Attack at dawn!", "que enly", &OPT).unwrap();
        assert_eq!(
            autokey_decode(&enc.output, "que enly", &OPT)
                .unwrap()
                .output,
            "Attack at dawn!"
        );
    }

    #[test]
    fn beaufort_is_involution() {
        // Hand-derived: key LEMON over ATTACKATDAWN (c = k - p).
        let enc = beaufort_encode("ATTACKATDAWN", "LEMON", &OPT).unwrap();
        assert_eq!(enc.output, "LLTOLBETLNPR");
        assert_eq!(
            beaufort_decode(&enc.output, "LEMON", &OPT).unwrap().output,
            "ATTACKATDAWN"
        );
        // Reciprocity: encode(encode(x)) == x.
        let twice = beaufort_encode(&enc.output, "LEMON", &OPT).unwrap();
        assert_eq!(twice.output, "ATTACKATDAWN");
    }

    #[test]
    fn gronsfeld_numeric_key() {
        let enc = gronsfeld_encode("ABCDEF", "1234", &OPT).unwrap();
        assert_eq!(enc.output, "BDFHFH");
        assert_eq!(
            gronsfeld_decode("BDFHFH", "1234", &OPT).unwrap().output,
            "ABCDEF"
        );
        // Digits other than 0-9 in the key are filtered; empty result errors.
        assert!(gronsfeld_encode("ABC", "abc", &OPT).is_err());
    }

    #[test]
    fn porta_reciprocal_table() {
        // Row AB (keys A and B): a→n, n→a, m→z, z→m.
        assert_eq!(porta_encode("ANMZ", "A", &OPT).unwrap().output, "NAZM");
        assert_eq!(
            porta_encode("ANMZ", "B", &OPT).unwrap().output,
            "NAZM",
            "B shares row AB"
        );
        // Row CD (key C): a→o, n→m.
        assert_eq!(porta_encode("AN", "C", &OPT).unwrap().output, "OM");
        // Involution for every key letter over the whole alphabet.
        let alphabet: String = (b'A'..=b'Z').map(|b| b as char).collect();
        for k in b'A'..=b'Z' {
            let key = (k as char).to_string();
            let enc = porta_encode(&alphabet, &key, &OPT).unwrap().output;
            assert_eq!(
                porta_decode(&enc, &key, &OPT).unwrap().output,
                alphabet,
                "key {k}"
            );
        }
    }

    #[test]
    fn oversized_text_rejected() {
        let big = "a".repeat(super::super::MAX_TEXT_BYTES + 1);
        assert!(vigenere_encode(&big, "key", &OPT).is_err());
        assert!(autokey_decode(&big, "key", &OPT).is_err());
    }

    #[test]
    fn map_letters_helper_matches_transform_counters() {
        // The shared helper used by other modules stays consistent with the
        // transform counters contract; preserve_case keeps lowercase input
        // lowercase under an identity map.
        let r = map_letters("a b!", &OPT, |p| p).unwrap();
        assert_eq!(r.output, "a b!");
        assert_eq!(r.letters, 2);
        assert_eq!(r.passthrough, 2);
        let r = map_letters(
            "a b!",
            &CaseOptions {
                preserve_case: false,
            },
            |p| p,
        )
        .unwrap();
        assert_eq!(r.output, "A B!");
    }
}
