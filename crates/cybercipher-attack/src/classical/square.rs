//! Square-based ciphers: Polybius, Playfair, Bifid, Trifid, Four-square,
//! ADFGX/ADFGVX, and Hill.
//!
//! All of them normalize to `A`..=`Z` internally (letters only; other
//! characters are dropped and counted). Where a 5x5 square is used, the
//! default alphabet is I/J-merged (`J` maps to `I`, matching the classic
//! Playfair/Polybius convention); [`AlphabetMode::NoQ`] offers the
//! alternative 25-letter alphabet that omits `Q`, which many historical
//! Four-square examples use. ADFGVX uses a full 6x6 square over `A`..=`Z`
//! plus `0`..=`9`.
//!
//! Every routine returns a [`SquareResult`] whose `square` field carries the
//! exact row-major square used (when one exists) so a UI can show the
//! evidence; Hill returns `square: None` and echoes validity via typed
//! errors instead.

use super::{check_key, check_text, MAX_PERIOD};
use cybercipher_core::error::OperationError;
use serde::{Deserialize, Serialize};

/// The 25-letter alphabet used by 5x5 squares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AlphabetMode {
    /// `A`..=`Z` with `J` merged into `I` (classic Playfair/Polybius).
    /// Default.
    #[default]
    IjMerged,
    /// `A`..=`Z` with `Q` omitted (common in historical Four-square tables).
    NoQ,
}

impl AlphabetMode {
    /// The 25-letter alphabet for this mode.
    pub fn alphabet(self) -> &'static str {
        match self {
            AlphabetMode::IjMerged => "ABCDEFGHIKLMNOPQRSTUVWXYZ",
            AlphabetMode::NoQ => "ABCDEFGHIJKLMNOPRSTUVWXYZ",
        }
    }
}

/// Result payload for square ciphers: the transform plus the square used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SquareResult {
    /// The transformed text.
    pub output: String,
    /// Number of input letters consumed (before filler/pad expansion).
    pub letters: usize,
    /// Number of non-letter characters dropped (this module is letters-only).
    pub passthrough: usize,
    /// The row-major square used (25/27/36 chars), when one exists.
    pub square: Option<String>,
}

fn ok(output: String, letters: usize, dropped: usize, square: Option<String>) -> SquareResult {
    SquareResult {
        output,
        letters,
        passthrough: dropped,
        square,
    }
}

/// Validate a caller-supplied square: exactly `expected` unique uppercase
/// ASCII letters/digits.
fn parse_square(square: &str, expected: usize) -> Result<Vec<u8>, OperationError> {
    let chars: Vec<u8> = square
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase() as u8)
        .collect();
    if chars.len() != expected {
        return Err(OperationError::invalid_param(
            "square",
            format!("square must contain exactly {expected} characters"),
        )
        .with_expected(format!("{expected} characters"))
        .with_actual(format!("{} characters", chars.len())));
    }
    let mut seen = [false; 256];
    for &c in &chars {
        if !(c.is_ascii_alphanumeric()) {
            return Err(OperationError::invalid_param(
                "square",
                "square may only contain ASCII letters and digits",
            )
            .with_actual(format!("{}", c as char)));
        }
        if seen[c as usize] {
            return Err(OperationError::invalid_param(
                "square",
                "square characters must be unique",
            )
            .with_actual(format!("{}", c as char)));
        }
        seen[c as usize] = true;
    }
    Ok(chars)
}

/// Build a keyed 5x5 square: keyword letters (deduplicated, with the mode's
/// omitted letter mapped away) followed by the rest of the alphabet.
fn build_square_25(key: Option<&str>, mode: AlphabetMode) -> Result<Vec<u8>, OperationError> {
    let omitted = match mode {
        AlphabetMode::IjMerged => b'J',
        AlphabetMode::NoQ => b'Q',
    };
    let replacement = match mode {
        AlphabetMode::IjMerged => b'I',
        AlphabetMode::NoQ => b'P',
    };
    let mut key_letters: Vec<u8> = Vec::new();
    if let Some(key) = key {
        check_key(key)?;
        for ch in key.chars() {
            if !ch.is_ascii_alphabetic() {
                continue;
            }
            let mut u = ch.to_ascii_uppercase() as u8;
            if u == omitted {
                u = replacement;
            }
            key_letters.push(u);
        }
    }
    Ok(build_square_25_from_key_letters(&key_letters, mode))
}

/// Assemble a 5x5 square from deduplicated key letters plus the rest of the
/// mode's alphabet.
fn build_square_25_from_key_letters(key: &[u8], mode: AlphabetMode) -> Vec<u8> {
    let alphabet = mode.alphabet();
    let mut square: Vec<u8> = Vec::with_capacity(25);
    for &b in key {
        if !square.contains(&b) && alphabet.as_bytes().contains(&b) {
            square.push(b);
        }
    }
    for &c in alphabet.as_bytes() {
        if !square.contains(&c) {
            square.push(c);
        }
    }
    square
}

/// Build a keyed 6x6 ADFGVX square: keyword letters (deduplicated), then the
/// rest of `A`..=`Z`, then `0`..=`9`.
fn build_square_36(key: &str) -> Result<Vec<u8>, OperationError> {
    check_key(key)?;
    let mut square: Vec<u8> = Vec::new();
    for ch in key.chars() {
        if ch.is_ascii_alphabetic() {
            let u = ch.to_ascii_uppercase() as u8;
            if !square.contains(&u) {
                square.push(u);
            }
        }
    }
    for c in b'A'..=b'Z' {
        if !square.contains(&c) {
            square.push(c);
        }
    }
    for c in b'0'..=b'9' {
        if !square.contains(&c) {
            square.push(c);
        }
    }
    Ok(square)
}

/// Locate a letter in a square, mapping the mode's omitted letter first.
fn locate(square: &[u8], mut letter: u8, omitted: Option<(u8, u8)>) -> Option<usize> {
    if let Some((from, to)) = omitted {
        if letter == from {
            letter = to;
        }
    }
    square.iter().position(|&c| c == letter)
}

fn letters_only(text: &str) -> (Vec<u8>, usize) {
    let mut letters = Vec::new();
    let mut dropped = 0usize;
    for ch in text.chars() {
        if ch.is_ascii_alphabetic() {
            letters.push(ch.to_ascii_uppercase() as u8);
        } else {
            dropped += 1;
        }
    }
    (letters, dropped)
}

// ------------------------------------------------------------ Polybius ----

/// Options for [`polybius_encode`] / [`polybius_decode`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolybiusOptions {
    /// Optional keyword for a keyed square. Default: unkeyed.
    pub key: Option<String>,
    /// Explicit 25-character square override (row-major). Wins over `key`.
    /// Default: none.
    pub square: Option<String>,
    /// Which 25-letter alphabet to use. Default: [`AlphabetMode::IjMerged`].
    pub alphabet: AlphabetMode,
}

/// Polybius-encode `text`: each letter becomes its 1-based row/column digits,
/// concatenated (e.g. `HELLO` → `2315313134` with the unkeyed I/J square).
pub fn polybius_encode(
    text: &str,
    options: &PolybiusOptions,
) -> Result<SquareResult, OperationError> {
    check_text(text)?;
    let square = match &options.square {
        Some(s) => parse_square(s, 25)?,
        None => build_square_25(options.key.as_deref(), options.alphabet)?,
    };
    let omitted = omitted_pair(options.alphabet);
    let (letters, dropped) = letters_only(text);
    let mut out = String::with_capacity(letters.len() * 2);
    for &letter in &letters {
        let idx = locate(&square, letter, omitted).ok_or_else(|| {
            OperationError::invalid_input(format!("letter {} is not in the square", letter as char))
        })?;
        out.push(((idx / 5) as u8 + b'1') as char);
        out.push(((idx % 5) as u8 + b'1') as char);
    }
    Ok(ok(
        out,
        letters.len(),
        dropped,
        Some(String::from_utf8_lossy(&square).into_owned()),
    ))
}

/// Polybius-decode `text`: digit pairs (1..=5) map back through the square.
pub fn polybius_decode(
    text: &str,
    options: &PolybiusOptions,
) -> Result<SquareResult, OperationError> {
    check_text(text)?;
    let square = match &options.square {
        Some(s) => parse_square(s, 25)?,
        None => build_square_25(options.key.as_deref(), options.alphabet)?,
    };
    let digits: Vec<u8> = text
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c as u8)
        .collect();
    let dropped = text.chars().count() - text.chars().filter(|c| c.is_ascii_digit()).count();
    if !digits.len().is_multiple_of(2) {
        return Err(OperationError::length(
            "an even number of coordinate digits",
            format!("{} digits", digits.len()),
            "Polybius ciphertext must be pairs of coordinates",
        ));
    }
    let mut out = String::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        let (row, col) = (pair[0] - b'0', pair[1] - b'0');
        if !(1..=5).contains(&row) || !(1..=5).contains(&col) {
            return Err(
                OperationError::invalid_input("Polybius coordinates must be digits 1..=5")
                    .with_expected("digits 1..=5")
                    .with_actual(format!("{}{}", row as char, col as char)),
            );
        }
        let idx = (row as usize - 1) * 5 + (col as usize - 1);
        out.push(square[idx] as char);
    }
    let out_len = out.len();
    Ok(ok(
        out,
        out_len,
        dropped,
        Some(String::from_utf8_lossy(&square).into_owned()),
    ))
}

fn omitted_pair(mode: AlphabetMode) -> Option<(u8, u8)> {
    match mode {
        AlphabetMode::IjMerged => Some((b'J', b'I')),
        AlphabetMode::NoQ => Some((b'Q', b'P')),
    }
}

// ------------------------------------------------------------ Playfair ----

/// Options for [`playfair_encode`] / [`playfair_decode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlayfairOptions {
    /// Key phrase for the keyed square. Required (non-empty after
    /// normalization). Default: `playfair example`? No — there is no sensible
    /// default; an empty key is a typed error.
    pub key: String,
    /// Filler letter for doubled letters and the final pad. Default: `'X'`
    /// (`'Q'` is substituted when the filler would double an `X`).
    pub filler: char,
}

impl Default for PlayfairOptions {
    fn default() -> Self {
        Self {
            key: String::new(),
            filler: 'X',
        }
    }
}

/// Split letters into Playfair digraphs, inserting the filler between doubled
/// letters and padding the final odd letter.
fn playfair_digraphs(letters: &[u8], filler: u8) -> Vec<(u8, u8)> {
    let filler_for = |c: u8| if c == filler { b'Q' } else { filler };
    let mut pairs = Vec::new();
    let mut i = 0usize;
    while i < letters.len() {
        let a = letters[i];
        let b = letters.get(i + 1).copied();
        match b {
            Some(b) if b != a => {
                pairs.push((a, b));
                i += 2;
            }
            Some(_) => {
                // doubled letter: insert filler between the two
                pairs.push((a, filler_for(a)));
                i += 1;
            }
            None => {
                // trailing single letter: pad
                pairs.push((a, filler_for(a)));
                i += 1;
            }
        }
    }
    pairs
}

fn require_playfair_key(key: &str) -> Result<Vec<u8>, OperationError> {
    check_key(key)?;
    let normalized: Vec<u8> = key
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase() as u8)
        .map(|b| if b == b'J' { b'I' } else { b })
        .collect();
    if normalized.is_empty() {
        return Err(
            OperationError::key("Playfair key must contain at least one letter")
                .with_parameter("key")
                .with_expected("at least one ASCII letter")
                .with_actual(format!("{key:?}")),
        );
    }
    Ok(normalized)
}

/// Playfair-encode `text` with the classic rules: same row → letter to the
/// right, same column → letter below, otherwise swap corners of the
/// rectangle. The square is keyed by [`PlayfairOptions::key`] with `J`
/// merged into `I`.
pub fn playfair_encode(
    text: &str,
    options: &PlayfairOptions,
) -> Result<SquareResult, OperationError> {
    check_text(text)?;
    let key = require_playfair_key(&options.key)?;
    let square = build_square_25_from_letters(&key);
    let (raw, dropped) = letters_only(text);
    let letters: Vec<u8> = raw
        .iter()
        .map(|&b| if b == b'J' { b'I' } else { b })
        .collect();
    let filler = options.filler.to_ascii_uppercase() as u8;
    let mut out = String::with_capacity(letters.len() + 8);
    for (a, b) in playfair_digraphs(&letters, filler) {
        let (ia, ib) = (
            locate(&square, a, None).expect("normalized letters are in the square"),
            locate(&square, b, None).expect("normalized letters are in the square"),
        );
        let (ra, ca, rb, cb) = (ia / 5, ia % 5, ib / 5, ib % 5);
        let (ia2, ib2) = if ra == rb {
            (ra * 5 + (ca + 1) % 5, rb * 5 + (cb + 1) % 5)
        } else if ca == cb {
            ((ra + 1) % 5 * 5 + ca, (rb + 1) % 5 * 5 + cb)
        } else {
            (ra * 5 + cb, rb * 5 + ca)
        };
        out.push(square[ia2] as char);
        out.push(square[ib2] as char);
    }
    Ok(ok(
        out,
        raw.len(),
        dropped,
        Some(String::from_utf8_lossy(&square).into_owned()),
    ))
}

/// Playfair-decode `text`: inverse table walk (same row → left, same column →
/// up, otherwise swap corners). Filler letters inserted by encryption remain
/// in the output — that is inherent to the cipher.
pub fn playfair_decode(
    text: &str,
    options: &PlayfairOptions,
) -> Result<SquareResult, OperationError> {
    check_text(text)?;
    let key = require_playfair_key(&options.key)?;
    let square = build_square_25_from_letters(&key);
    let (raw, dropped) = letters_only(text);
    if raw.len() % 2 != 0 {
        return Err(OperationError::length(
            "an even number of letters",
            format!("{} letters", raw.len()),
            "Playfair ciphertext must be digraphs",
        ));
    }
    let mut out = String::with_capacity(raw.len());
    for pair in raw.chunks(2) {
        let (ia, ib) = (
            locate(&square, pair[0], None).ok_or_else(|| bad_cipher_letter(pair[0]))?,
            locate(&square, pair[1], None).ok_or_else(|| bad_cipher_letter(pair[1]))?,
        );
        let (ra, ca, rb, cb) = (ia / 5, ia % 5, ib / 5, ib % 5);
        let (ia2, ib2) = if ra == rb {
            (ra * 5 + (ca + 4) % 5, rb * 5 + (cb + 4) % 5)
        } else if ca == cb {
            ((ra + 4) % 5 * 5 + ca, (rb + 4) % 5 * 5 + cb)
        } else {
            (ra * 5 + cb, rb * 5 + ca)
        };
        out.push(square[ia2] as char);
        out.push(square[ib2] as char);
    }
    Ok(ok(
        out,
        raw.len(),
        dropped,
        Some(String::from_utf8_lossy(&square).into_owned()),
    ))
}

fn bad_cipher_letter(c: u8) -> OperationError {
    OperationError::invalid_input("ciphertext letter is not in the square")
        .with_actual(format!("{}", c as char))
}

fn build_square_25_from_letters(key: &[u8]) -> Vec<u8> {
    let mut square: Vec<u8> = Vec::with_capacity(25);
    for &b in key {
        if !square.contains(&b) {
            square.push(b);
        }
    }
    for c in b'A'..=b'Z' {
        let b = if c == b'J' { b'I' } else { c };
        if !square.contains(&b) {
            square.push(b);
        }
    }
    square
}

// --------------------------------------------------------------- Bifid ----

/// Options for [`bifid_encode`] / [`bifid_decode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BifidOptions {
    /// Fractionation period, 1..=[`MAX_PERIOD`]. Default: 5.
    pub period: usize,
}

impl Default for BifidOptions {
    fn default() -> Self {
        Self { period: 5 }
    }
}

/// The fixed unkeyed Bifid square (I/J merged), row-major.
const BIFID_SQUARE: &[u8; 25] = b"ABCDEFGHIKLMNOPQRSTUVWXYZ";

/// Bifid-encode `text`: within each block of `period` letters, write each
/// letter's row/column coordinates vertically, concatenate the rows then the
/// columns, and regroup the digit stream into letters.
pub fn bifid_encode(text: &str, options: &BifidOptions) -> Result<SquareResult, OperationError> {
    check_text(text)?;
    validate_period(options.period)?;
    let (raw, dropped) = letters_only(text);
    let letters: Vec<u8> = raw
        .iter()
        .map(|&b| if b == b'J' { b'I' } else { b })
        .collect();
    let mut out = String::with_capacity(letters.len());
    for block in letters.chunks(options.period) {
        let n = block.len();
        let mut rows = Vec::with_capacity(n);
        let mut cols = Vec::with_capacity(n);
        for &letter in block {
            let idx = locate(BIFID_SQUARE, letter, None).expect("I/J-normalized letter");
            rows.push((idx / 5) as u8);
            cols.push((idx % 5) as u8);
        }
        let stream: Vec<u8> = rows.into_iter().chain(cols).collect();
        for pair in stream.chunks(2) {
            let idx = (pair[0] as usize) * 5 + pair[1] as usize;
            out.push(BIFID_SQUARE[idx] as char);
        }
    }
    Ok(ok(
        out,
        raw.len(),
        dropped,
        Some(String::from_utf8_lossy(BIFID_SQUARE).into_owned()),
    ))
}

/// Bifid-decode `text`: split each block's coordinate stream back into rows
/// and columns and re-locate the letters.
pub fn bifid_decode(text: &str, options: &BifidOptions) -> Result<SquareResult, OperationError> {
    check_text(text)?;
    validate_period(options.period)?;
    let (raw, dropped) = letters_only(text);
    let letters: Vec<u8> = raw
        .iter()
        .map(|&b| if b == b'J' { b'I' } else { b })
        .collect();
    let mut out = String::with_capacity(letters.len());
    for block in letters.chunks(options.period) {
        let n = block.len();
        let mut stream = Vec::with_capacity(2 * n);
        for &letter in block {
            let idx =
                locate(BIFID_SQUARE, letter, None).ok_or_else(|| bad_cipher_letter(letter))?;
            stream.push((idx / 5) as u8);
            stream.push((idx % 5) as u8);
        }
        for i in 0..n {
            let idx = (stream[i] as usize) * 5 + stream[n + i] as usize;
            out.push(BIFID_SQUARE[idx] as char);
        }
    }
    Ok(ok(
        out,
        raw.len(),
        dropped,
        Some(String::from_utf8_lossy(BIFID_SQUARE).into_owned()),
    ))
}

fn validate_period(period: usize) -> Result<(), OperationError> {
    if period == 0 || period > MAX_PERIOD {
        return Err(OperationError::invalid_param(
            "period",
            format!("period must be in 1..={MAX_PERIOD}"),
        )
        .with_expected(format!("1..={MAX_PERIOD}"))
        .with_actual(period.to_string()));
    }
    Ok(())
}

// --------------------------------------------------------------- Trifid ----

/// The fixed unkeyed Trifid cube alphabet (27 letters, `+` fills the last
/// cell), row-major through three 3x3 layers.
const TRIFID_ALPHABET: &[u8; 27] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ+";

/// Options for [`trifid_encode`] / [`trifid_decode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrifidOptions {
    /// Fractionation period, 1..=[`MAX_PERIOD`]. Default: 5.
    pub period: usize,
}

impl Default for TrifidOptions {
    fn default() -> Self {
        Self { period: 5 }
    }
}

/// Trifid letter extraction: unlike the 25-letter squares, the Trifid cube
/// contains `+` as a genuine 27th letter, so it must survive filtering (a
/// dropped `+` in ciphertext would misalign the whole block).
fn trifid_letters(text: &str) -> (Vec<u8>, usize) {
    let mut letters = Vec::with_capacity(text.len());
    let mut dropped = 0usize;
    for c in text.chars() {
        let upper = c.to_ascii_uppercase() as u8;
        if c.is_ascii_alphabetic() {
            letters.push(upper);
        } else if c == '+' {
            letters.push(b'+');
        } else {
            dropped += 1;
        }
    }
    (letters, dropped)
}

/// Trifid-encode `text`: within each block of `period` letters, write each
/// letter's (layer, row, column) triple vertically, concatenate layer digits,
/// then row digits, then column digits, and regroup into letters via the
/// 27-letter cube (`A`..=`Z` plus `+`).
pub fn trifid_encode(text: &str, options: &TrifidOptions) -> Result<SquareResult, OperationError> {
    check_text(text)?;
    validate_period(options.period)?;
    let (letters, dropped) = trifid_letters(text);
    let mut out = String::with_capacity(letters.len());
    for block in letters.chunks(options.period) {
        let n = block.len();
        let mut layers = Vec::with_capacity(n);
        let mut rows = Vec::with_capacity(n);
        let mut cols = Vec::with_capacity(n);
        for &letter in block {
            let idx =
                locate(TRIFID_ALPHABET, letter, None).ok_or_else(|| bad_cipher_letter(letter))?;
            layers.push((idx / 9) as u8);
            rows.push(((idx % 9) / 3) as u8);
            cols.push((idx % 3) as u8);
        }
        let stream: Vec<u8> = layers.into_iter().chain(rows).chain(cols).collect();
        for triple in stream.chunks(3) {
            let idx = (triple[0] as usize) * 9 + (triple[1] as usize) * 3 + triple[2] as usize;
            out.push(TRIFID_ALPHABET[idx] as char);
        }
    }
    Ok(ok(
        out,
        letters.len(),
        dropped,
        Some(String::from_utf8_lossy(TRIFID_ALPHABET).into_owned()),
    ))
}

/// Trifid-decode `text`: split each block's digit stream back into layers,
/// rows, and columns and re-locate the letters.
pub fn trifid_decode(text: &str, options: &TrifidOptions) -> Result<SquareResult, OperationError> {
    check_text(text)?;
    validate_period(options.period)?;
    let (letters, dropped) = trifid_letters(text);
    let mut out = String::with_capacity(letters.len());
    for block in letters.chunks(options.period) {
        let n = block.len();
        let mut stream = Vec::with_capacity(3 * n);
        for &letter in block {
            let idx =
                locate(TRIFID_ALPHABET, letter, None).ok_or_else(|| bad_cipher_letter(letter))?;
            stream.push((idx / 9) as u8);
            stream.push(((idx % 9) / 3) as u8);
            stream.push((idx % 3) as u8);
        }
        for i in 0..n {
            let idx = (stream[i] as usize) * 9
                + (stream[n + i] as usize) * 3
                + stream[2 * n + i] as usize;
            out.push(TRIFID_ALPHABET[idx] as char);
        }
    }
    Ok(ok(
        out,
        letters.len(),
        dropped,
        Some(String::from_utf8_lossy(TRIFID_ALPHABET).into_owned()),
    ))
}

// ----------------------------------------------------------- Four-square ----

/// Options for [`foursquare_encode`] / [`foursquare_decode`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FoursquareOptions {
    /// Key for the top-right (first) cipher square. Required.
    pub key1: String,
    /// Key for the bottom-left (second) cipher square. Required.
    pub key2: String,
    /// Which 25-letter alphabet the plaintext squares use.
    /// Default: [`AlphabetMode::IjMerged`].
    pub alphabet: AlphabetMode,
}

fn normalize_key_letters(key: &str, mode: AlphabetMode) -> Result<Vec<u8>, OperationError> {
    check_key(key)?;
    let (omitted, replacement) = match mode {
        AlphabetMode::IjMerged => (b'J', b'I'),
        AlphabetMode::NoQ => (b'Q', b'P'),
    };
    let letters: Vec<u8> = key
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase() as u8)
        .map(|b| if b == omitted { replacement } else { b })
        .collect();
    if letters.is_empty() {
        return Err(
            OperationError::key("square key must contain at least one letter")
                .with_parameter("key")
                .with_expected("at least one ASCII letter")
                .with_actual(format!("{key:?}")),
        );
    }
    Ok(letters)
}

/// Four-square-encode `text`: two plaintext squares (top-left, bottom-right)
/// and two keyed cipher squares (top-right, bottom-left). For a digraph with
/// plaintext letters at `(r1, c1)` and `(r2, c2)`:
/// `c1' = TR[r1][c2]`, `c2' = BL[r2][c1]` (pure rectangle rule). An odd
/// trailing letter is padded with the filler (`X`, or `Q` after an `X`).
pub fn foursquare_encode(
    text: &str,
    options: &FoursquareOptions,
) -> Result<SquareResult, OperationError> {
    check_text(text)?;
    let omitted = omitted_pair(options.alphabet);
    let key1 = normalize_key_letters(&options.key1, options.alphabet)?;
    let key2 = normalize_key_letters(&options.key2, options.alphabet)?;
    let tl = build_square_25_from_key_letters(&[], options.alphabet);
    let br = build_square_25_from_key_letters(&[], options.alphabet);
    let tr = build_square_25_from_key_letters(&key1, options.alphabet);
    let bl = build_square_25_from_key_letters(&key2, options.alphabet);
    let (raw, dropped) = letters_only(text);
    let filler = b'X';
    let digraphs = playfair_digraphs(&raw, filler);
    let mut out = String::with_capacity(digraphs.len() * 2);
    for (a, b) in digraphs {
        let p1 = locate(&tl, a, omitted).ok_or_else(|| bad_cipher_letter(a))?;
        let p2 = locate(&br, b, omitted).ok_or_else(|| bad_cipher_letter(b))?;
        let (r1, c1, r2, c2) = (p1 / 5, p1 % 5, p2 / 5, p2 % 5);
        out.push(tr[r1 * 5 + c2] as char);
        out.push(bl[r2 * 5 + c1] as char);
    }
    Ok(ok(
        out,
        raw.len(),
        dropped,
        Some(format!(
            "TL={} TR={} BL={} BR={}",
            String::from_utf8_lossy(&tl),
            String::from_utf8_lossy(&tr),
            String::from_utf8_lossy(&bl),
            String::from_utf8_lossy(&br)
        )),
    ))
}

/// Four-square-decode `text`: inverse rectangle lookup.
pub fn foursquare_decode(
    text: &str,
    options: &FoursquareOptions,
) -> Result<SquareResult, OperationError> {
    check_text(text)?;
    let key1 = normalize_key_letters(&options.key1, options.alphabet)?;
    let key2 = normalize_key_letters(&options.key2, options.alphabet)?;
    let tl = build_square_25_from_key_letters(&[], options.alphabet);
    let br = build_square_25_from_key_letters(&[], options.alphabet);
    let tr = build_square_25_from_key_letters(&key1, options.alphabet);
    let bl = build_square_25_from_key_letters(&key2, options.alphabet);
    let (raw, dropped) = letters_only(text);
    if raw.len() % 2 != 0 {
        return Err(OperationError::length(
            "an even number of letters",
            format!("{} letters", raw.len()),
            "Four-square ciphertext must be digraphs",
        ));
    }
    let mut out = String::with_capacity(raw.len());
    for pair in raw.chunks(2) {
        let c1 = locate(&tr, pair[0], None).ok_or_else(|| bad_cipher_letter(pair[0]))?;
        let c2 = locate(&bl, pair[1], None).ok_or_else(|| bad_cipher_letter(pair[1]))?;
        let (r1, cc1, r2, cc2) = (c1 / 5, c1 % 5, c2 / 5, c2 % 5);
        let p1 = tl[r1 * 5 + cc2];
        let p2 = br[r2 * 5 + cc1];
        out.push(p1 as char);
        out.push(p2 as char);
    }
    Ok(ok(
        out,
        raw.len(),
        dropped,
        Some(format!(
            "TL={} TR={} BL={} BR={}",
            String::from_utf8_lossy(&tl),
            String::from_utf8_lossy(&tr),
            String::from_utf8_lossy(&bl),
            String::from_utf8_lossy(&br)
        )),
    ))
}

// ------------------------------------------------------ ADFGX / ADFGVX ----

/// Options for [`adfgx_encode`] / [`adfgx_decode`] (and the ADFGVX pair,
/// which share the shape).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdfgxOptions {
    /// Keyword for the fractionation square. Default: unkeyed square.
    pub key: String,
    /// Keyword for the fractionated columnar transposition. Required
    /// (letters only, no duplicates).
    pub transposition_key: String,
    /// Explicit square override (25 characters, row-major). Default: none.
    pub square: Option<String>,
}

/// Options for [`adfgvx_encode`] / [`adfgvx_decode`]: same shape as
/// [`AdfgxOptions`] but the square is 36 characters (`A`..=`Z`, `0`..=`9`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdfgvxOptions {
    /// Keyword for the fractionation square. Default: unkeyed square.
    pub key: String,
    /// Keyword for the transposition. Required.
    pub transposition_key: String,
    /// Explicit 36-character square override. Default: none.
    pub square: Option<String>,
}

const ADFGX_SYMBOLS: &[u8; 5] = b"ADFGX";
const ADFGVX_SYMBOLS: &[u8; 6] = b"ADFGVX";

fn validate_transposition_key(key: &str) -> Result<Vec<u8>, OperationError> {
    check_key(key)?;
    let letters: Vec<u8> = key
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase() as u8)
        .collect();
    if letters.is_empty() {
        return Err(
            OperationError::key("transposition key must contain at least one letter")
                .with_parameter("transposition_key")
                .with_expected("at least one ASCII letter")
                .with_actual(format!("{key:?}")),
        );
    }
    for (i, &a) in letters.iter().enumerate() {
        if letters[i + 1..].contains(&a) {
            return Err(OperationError::key(
                "transposition key letters must be unique to define a column order",
            )
            .with_parameter("transposition_key")
            .with_actual(format!("duplicate {}", a as char)));
        }
    }
    Ok(letters)
}

/// Fractionate letters through a square into coordinate symbols.
fn fractionate(letters: &[u8], square: &[u8], symbols: &[u8]) -> Result<Vec<u8>, OperationError> {
    let width = symbols.len();
    let mut out = Vec::with_capacity(letters.len() * 2);
    for &letter in letters {
        let idx = square
            .iter()
            .position(|&c| c == letter)
            .ok_or_else(|| bad_cipher_letter(letter))?;
        out.push(symbols[idx / width]);
        out.push(symbols[idx % width]);
    }
    Ok(out)
}

/// Columnar transposition over the fractionated stream: write row-wise under
/// the keyword, read columns in keyword-sorted order.
fn adf_transpose_encrypt(stream: &[u8], keyword: &[u8]) -> Vec<u8> {
    let n = keyword.len();
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|&i| (keyword[i], i));
    let mut out = Vec::with_capacity(stream.len());
    for &col in &order {
        let mut idx = col;
        while idx < stream.len() {
            out.push(stream[idx]);
            idx += n;
        }
    }
    out
}

/// Inverse of [`adf_transpose_encrypt`].
fn adf_transpose_decrypt(stream: &[u8], keyword: &[u8]) -> Vec<u8> {
    let n = keyword.len();
    let total = stream.len();
    let mut heights = vec![0usize; n];
    for (i, h) in heights.iter_mut().enumerate() {
        *h = (total + n - 1 - i) / n;
    }
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|&i| (keyword[i], i));
    let mut columns: Vec<Vec<u8>> = vec![Vec::new(); n];
    let mut offset = 0usize;
    for &col in &order {
        let len = heights[col];
        columns[col] = stream[offset..offset + len].to_vec();
        offset += len;
    }
    let mut idxs = vec![0usize; n];
    let mut out = Vec::with_capacity(total);
    // Ragged columns: the tallest column may exceed n rows, so iterate until
    // every symbol is consumed rather than exactly n times.
    'rows: for _ in 0..*heights.iter().max().unwrap_or(&0) {
        for col in 0..n {
            if idxs[col] < heights[col] {
                out.push(columns[col][idxs[col]]);
                idxs[col] += 1;
                if out.len() == total {
                    break 'rows;
                }
            }
        }
    }
    out
}

/// Defractionate symbol pairs back into letters.
fn defractionate(stream: &[u8], square: &[u8], symbols: &[u8]) -> Result<String, OperationError> {
    let width = symbols.len();
    let mut out = String::with_capacity(stream.len() / 2);
    for pair in stream.chunks(2) {
        let row = symbols
            .iter()
            .position(|&s| s == pair[0])
            .ok_or_else(|| bad_cipher_letter(pair[0]))?;
        let col = symbols
            .iter()
            .position(|&s| s == pair[1])
            .ok_or_else(|| bad_cipher_letter(pair[1]))?;
        out.push(square[row * width + col] as char);
    }
    Ok(out)
}

fn adf_encode(
    text: &str,
    square: Vec<u8>,
    symbols: &[u8],
    transposition_key: &str,
    with_digits: bool,
) -> Result<SquareResult, OperationError> {
    check_text(text)?;
    let keyword = validate_transposition_key(transposition_key)?;
    let mut letters: Vec<u8> = Vec::new();
    let mut dropped = 0usize;
    for ch in text.chars() {
        if ch.is_ascii_alphabetic() {
            letters.push(ch.to_ascii_uppercase() as u8);
        } else if with_digits && ch.is_ascii_digit() {
            letters.push(ch as u8);
        } else {
            dropped += 1;
        }
    }
    // 5x5 squares have no J cell: normalize J to I like the classic tables.
    if !square.contains(&b'J') {
        for letter in &mut letters {
            if *letter == b'J' {
                *letter = b'I';
            }
        }
    }
    let stream = fractionate(&letters, &square, symbols)?;
    let out = adf_transpose_encrypt(&stream, &keyword);
    Ok(ok(
        String::from_utf8(out).expect("ADF symbols are ASCII"),
        letters.len(),
        dropped,
        Some(String::from_utf8_lossy(&square).into_owned()),
    ))
}

fn adf_decode(
    text: &str,
    square: Vec<u8>,
    symbols: &[u8],
    transposition_key: &str,
) -> Result<SquareResult, OperationError> {
    check_text(text)?;
    let keyword = validate_transposition_key(transposition_key)?;
    let upper = text.to_ascii_uppercase();
    let stream: Vec<u8> = upper
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c as u8)
        .collect();
    let dropped = text.chars().count() - stream.len();
    if !stream.len().is_multiple_of(2) {
        return Err(OperationError::length(
            "an even number of coordinate symbols",
            format!("{} symbols", stream.len()),
            "ADFG cipher symbols come in coordinate pairs",
        ));
    }
    for &s in &stream {
        if !symbols.contains(&s) {
            return Err(OperationError::invalid_input(
                "ciphertext contains symbols outside the ADFG(VX) alphabet",
            )
            .with_expected(format!("only {}", String::from_utf8_lossy(symbols)))
            .with_actual(format!("{}", s as char)));
        }
    }
    let detransposed = adf_transpose_decrypt(&stream, &keyword);
    let output = defractionate(&detransposed, &square, symbols)?;
    Ok(ok(
        output,
        stream.len() / 2,
        dropped,
        Some(String::from_utf8_lossy(&square).into_owned()),
    ))
}

/// ADFGX-encode `text` (5x5 keyed square, I/J merged, fractionated through a
/// columnar transposition over [`AdfgxOptions::transposition_key`]).
pub fn adfgx_encode(text: &str, options: &AdfgxOptions) -> Result<SquareResult, OperationError> {
    let square = match &options.square {
        Some(s) => parse_square(s, 25)?,
        None => build_square_25(non_empty(&options.key), AlphabetMode::IjMerged)?,
    };
    adf_encode(
        text,
        square,
        ADFGX_SYMBOLS,
        &options.transposition_key,
        false,
    )
}

/// ADFGX-decode `text`.
pub fn adfgx_decode(text: &str, options: &AdfgxOptions) -> Result<SquareResult, OperationError> {
    let square = match &options.square {
        Some(s) => parse_square(s, 25)?,
        None => build_square_25(non_empty(&options.key), AlphabetMode::IjMerged)?,
    };
    adf_decode(text, square, ADFGX_SYMBOLS, &options.transposition_key)
}

/// ADFGVX-encode `text` (6x6 keyed square over `A`..=`Z` + `0`..=`9`;
/// digits in the input are cipher material, everything else is dropped).
pub fn adfgvx_encode(text: &str, options: &AdfgvxOptions) -> Result<SquareResult, OperationError> {
    let square = match &options.square {
        Some(s) => parse_square(s, 36)?,
        None => build_square_36(&options.key)?,
    };
    adf_encode(
        text,
        square,
        ADFGVX_SYMBOLS,
        &options.transposition_key,
        true,
    )
}

/// ADFGVX-decode `text`.
pub fn adfgvx_decode(text: &str, options: &AdfgvxOptions) -> Result<SquareResult, OperationError> {
    let square = match &options.square {
        Some(s) => parse_square(s, 36)?,
        None => build_square_36(&options.key)?,
    };
    adf_decode(text, square, ADFGVX_SYMBOLS, &options.transposition_key)
}

fn non_empty(key: &str) -> Option<&str> {
    if key.is_empty() {
        None
    } else {
        Some(key)
    }
}

// ----------------------------------------------------------------- Hill ----

/// Options for [`hill_encode`] / [`hill_decode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HillOptions {
    /// Case handling. Default: preserve. Hill mixes whole blocks, so the
    /// output letter at position `i` simply inherits the case of the input
    /// letter at position `i`.
    pub case: super::simple::CaseOptions,
}

/// Hill-encode `text` with a key given as 4 or 9 letters (row-major matrix
/// mod 26; e.g. `DDCF` = [[3,3],[2,5]], `GYBNQKURP` =
/// [[6,24,1],[13,16,10],[20,17,15]]). The matrix determinant must be
/// invertible mod 26, otherwise a typed error with expected/actual is
/// returned. A trailing partial block is padded with `X`.
pub fn hill_encode(
    text: &str,
    key: &str,
    options: &HillOptions,
) -> Result<SquareResult, OperationError> {
    check_text(text)?;
    let (matrix, n) = hill_matrix(key)?;
    // A singular key matrix silently destroys information — reject it for
    // encryption too, not only on the decode path.
    hill_inverse(&matrix, n)?;
    let (raw, dropped) = letters_only(text);
    let was_lower: Vec<bool> = text
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.is_ascii_lowercase())
        .collect();
    let mut letters = raw.clone();
    let remainder = letters.len() % n;
    if remainder != 0 {
        letters.extend(std::iter::repeat_n(b'X', n - remainder));
    }
    let mut out_bytes = Vec::with_capacity(letters.len());
    for block in letters.chunks(n) {
        for row in &matrix {
            let acc: i32 = row
                .iter()
                .enumerate()
                .map(|(c, &k)| k as i32 * (block[c] - b'A') as i32)
                .sum();
            out_bytes.push(acc.rem_euclid(26) as u8 + b'A');
        }
    }
    let preserve = options.case.preserve_case;
    let output = out_bytes
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            let c = b as char;
            if preserve && was_lower.get(i).copied().unwrap_or(false) {
                c.to_ascii_lowercase()
            } else {
                c
            }
        })
        .collect();
    Ok(ok(output, raw.len(), dropped, None))
}

/// Hill-decode `text` with the inverse matrix mod 26. Padding letters are
/// part of the returned plaintext.
pub fn hill_decode(
    text: &str,
    key: &str,
    options: &HillOptions,
) -> Result<SquareResult, OperationError> {
    check_text(text)?;
    let (matrix, n) = hill_matrix(key)?;
    let inv = hill_inverse(&matrix, n)?;
    let (raw, dropped) = letters_only(text);
    if raw.len() % n != 0 {
        return Err(OperationError::length(
            format!("a multiple of {n} letters (the key matrix is {n}x{n})"),
            format!("{} letters", raw.len()),
            "Hill ciphertext must be whole blocks",
        ));
    }
    let was_lower: Vec<bool> = text
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.is_ascii_lowercase())
        .collect();
    let mut out_bytes = Vec::with_capacity(raw.len());
    for block in raw.chunks(n) {
        for row in &inv {
            let acc: i32 = row
                .iter()
                .enumerate()
                .map(|(c, &k)| k as i32 * (block[c] - b'A') as i32)
                .sum();
            out_bytes.push(acc.rem_euclid(26) as u8 + b'A');
        }
    }
    let preserve = options.case.preserve_case;
    let output = out_bytes
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            let c = b as char;
            if preserve && was_lower.get(i).copied().unwrap_or(false) {
                c.to_ascii_lowercase()
            } else {
                c
            }
        })
        .collect();
    Ok(ok(output, raw.len(), dropped, None))
}

/// Parse a Hill key: 4 or 9 letters, row-major mod 26.
fn hill_matrix(key: &str) -> Result<(Vec<Vec<u8>>, usize), OperationError> {
    check_key(key)?;
    let letters: Vec<u8> = key
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase() as u8 - b'A')
        .collect();
    let n = match letters.len() {
        4 => 2usize,
        9 => 3usize,
        _ => {
            return Err(OperationError::invalid_param(
                "key",
                "Hill key must be 4 letters (2x2) or 9 letters (3x3)",
            )
            .with_expected("4 or 9 letters")
            .with_actual(format!("{} letters", letters.len())))
        }
    };
    let mut matrix = vec![vec![0u8; n]; n];
    for (i, &v) in letters.iter().enumerate() {
        matrix[i / n][i % n] = v;
    }
    Ok((matrix, n))
}

/// Determinant mod 26 (2x2 direct, 3x3 cofactor expansion).
fn determinant(matrix: &[Vec<u8>]) -> i32 {
    let n = matrix.len();
    if n == 2 {
        (matrix[0][0] as i32 * matrix[1][1] as i32 - matrix[0][1] as i32 * matrix[1][0] as i32)
            .rem_euclid(26)
    } else {
        let m = |i: usize, j: usize| matrix[i][j] as i32;
        let det = m(0, 0) * (m(1, 1) * m(2, 2) - m(1, 2) * m(2, 1))
            - m(0, 1) * (m(1, 0) * m(2, 2) - m(1, 2) * m(2, 0))
            + m(0, 2) * (m(1, 0) * m(2, 1) - m(1, 1) * m(2, 0));
        det.rem_euclid(26)
    }
}

fn mod_inverse_26(value: i32) -> Option<u32> {
    let v = value.rem_euclid(26);
    for x in 1i32..26 {
        if (v * x).rem_euclid(26) == 1 {
            return Some(x as u32);
        }
    }
    None
}

/// Invert the key matrix mod 26; errors when the determinant is not coprime
/// with 26.
fn hill_inverse(matrix: &[Vec<u8>], n: usize) -> Result<Vec<Vec<u8>>, OperationError> {
    let det = determinant(matrix);
    let inv_det = mod_inverse_26(det).ok_or_else(|| {
        OperationError::invalid_param(
            "key",
            "the key matrix must be invertible mod 26 (determinant odd and not divisible by 13)",
        )
        .with_expected("gcd(det, 26) = 1")
        .with_actual(format!("det = {det} mod 26"))
    })?;
    let mut inv = vec![vec![0u8; n]; n];
    if n == 2 {
        let a = matrix;
        let adj = [
            [a[1][1] as i32, 26 - a[0][1] as i32],
            [26 - a[1][0] as i32, a[0][0] as i32],
        ];
        for (r, row) in adj.iter().enumerate() {
            for (c, &v) in row.iter().enumerate() {
                inv[r][c] = ((inv_det as i32 * v).rem_euclid(26)) as u8;
            }
        }
    } else {
        let m = |i: usize, j: usize| matrix[i][j] as i32;
        // Adjugate (cofactor transpose) mod 26. Minor indices must be in
        #[allow(clippy::needless_range_loop)]
        // ascending order — cyclic (r+1)%3 pairs silently flip the minor's
        // sign for half the cells.
        let others = |x: usize| -> (usize, usize) {
            let a = (x + 1) % 3;
            let b = (x + 2) % 3;
            if a < b {
                (a, b)
            } else {
                (b, a)
            }
        };
        #[allow(clippy::needless_range_loop)] // adj[c][r] transposes the indices
        for r in 0..3 {
            for c in 0..3 {
                let (i0, i1) = others(r);
                let (j0, j1) = others(c);
                let minor = m(i0, j0) * m(i1, j1) - m(i0, j1) * m(i1, j0);
                let sign = if (r + c) % 2 == 0 { 1 } else { -1 };
                // Adjugate is the TRANSPOSE of cofactors: adj[c][r].
                inv[c][r] = ((inv_det as i32 * sign * minor).rem_euclid(26)) as u8;
            }
        }
    }
    Ok(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polybius_known_pairs() {
        let enc = polybius_encode("HELLO", &PolybiusOptions::default()).unwrap();
        assert_eq!(enc.output, "2315313134");
        assert_eq!(enc.square.as_deref(), Some("ABCDEFGHIKLMNOPQRSTUVWXYZ"));
        let dec = polybius_decode("2315313134", &PolybiusOptions::default()).unwrap();
        assert_eq!(dec.output, "HELLO");
        // J merges into I in both directions.
        let enc = polybius_encode("JAIL", &PolybiusOptions::default()).unwrap();
        let dec = polybius_decode(&enc.output, &PolybiusOptions::default()).unwrap();
        // J merges into I: the decoded text keeps the merged letter.
        assert_eq!(dec.output, "IAIL");
    }

    #[test]
    fn polybius_keyed_square_and_override() {
        let options = PolybiusOptions {
            key: Some("secret".into()),
            ..PolybiusOptions::default()
        };
        let enc = polybius_encode("AB", &options).unwrap();
        assert_eq!(enc.square.as_deref(), Some("SECRTABDFGHIKLMNOPQUVWXYZ"));
        assert_eq!(polybius_decode(&enc.output, &options).unwrap().output, "AB");
        let override_options = PolybiusOptions {
            square: Some("ABCDEFGHIJKLMNOPRSTUVWXY".into()),
            ..PolybiusOptions::default()
        };
        let err = polybius_encode("AB", &override_options).unwrap_err();
        assert!(err.message.contains("exactly 25"), "{err:?}");
    }

    #[test]
    fn polybius_rejects_malformed_ciphertext() {
        assert!(polybius_decode("123", &PolybiusOptions::default()).is_err());
        assert!(polybius_decode("06", &PolybiusOptions::default()).is_err());
        let err = polybius_decode("96", &PolybiusOptions::default()).unwrap_err();
        assert_eq!(err.expected.as_deref(), Some("digits 1..=5"));
    }

    #[test]
    fn playfair_classic_vector() {
        let options = PlayfairOptions {
            key: "playfair example".into(),
            filler: 'X',
        };
        let enc = playfair_encode("hide the gold in the tree stump", &options).unwrap();
        assert_eq!(enc.output, "BMODZBXDNABEKUDMUIXMMOUVIF");
        assert_eq!(enc.letters, 25, "input letters counted before fillers");
    }

    #[test]
    fn playfair_doubles_and_padding() {
        let options = PlayfairOptions {
            key: "test".into(),
            filler: 'X',
        };
        // "balloon" → BA LX LO ON: doubled L gets an X between; also check the
        // double X rule through "xx" → XQ.
        let enc = playfair_encode("balloon", &options).unwrap();
        assert_eq!(enc.output.len(), 8, "BA LX LO ON");
        let xx = playfair_encode("xx", &options).unwrap();
        assert_eq!(xx.output.len(), 4, "doubled X becomes XQ + pad");
    }

    #[test]
    fn playfair_round_trip_without_doubles() {
        let options = PlayfairOptions {
            key: "monarchy".into(),
            filler: 'X',
        };
        let text = "CRYPTOGRAPHY"; // 12 letters, no doubled pairs
        let enc = playfair_encode(text, &options).unwrap();
        assert_eq!(playfair_decode(&enc.output, &options).unwrap().output, text);
        // Fillers inserted at doubled letters remain after decoding —
        // inherent to the cipher, documented on playfair_decode.
        let balloon = playfair_encode("balloon", &options).unwrap();
        let dec = playfair_decode(&balloon.output, &options).unwrap();
        assert_eq!(dec.output, "BALXLOON");
    }

    #[test]
    fn playfair_rejects_empty_key_and_odd_ciphertext() {
        assert!(playfair_encode("hi", &PlayfairOptions::default()).is_err());
        let options = PlayfairOptions {
            key: "key".into(),
            filler: 'X',
        };
        assert!(playfair_decode("ABC", &options).is_err());
    }

    #[test]
    fn bifid_known_vector_and_round_trip() {
        // Hand-derived: H(1,2) E(0,4) L(2,0) L(2,0) O(2,3), period 5:
        // rows 1,0,2,2,2 + cols 2,4,0,0,3 → pairs (1,0)F (2,2)N (2,2)N
        // (2,4)P (0,3)D.
        let options = BifidOptions { period: 5 };
        let enc = bifid_encode("HELLO", &options).unwrap();
        assert_eq!(enc.output, "FNNVD");
        assert_eq!(bifid_decode(&enc.output, &options).unwrap().output, "HELLO");
        let whole = bifid_encode("ATTACK", &BifidOptions { period: 100 }).unwrap();
        assert_eq!(
            bifid_decode(&whole.output, &BifidOptions { period: 100 })
                .unwrap()
                .output,
            "ATTACK"
        );
    }

    #[test]
    fn bifid_period_changes_ciphertext() {
        let a = bifid_encode("ATTACKATDAWN", &BifidOptions { period: 3 }).unwrap();
        let b = bifid_encode("ATTACKATDAWN", &BifidOptions { period: 4 }).unwrap();
        assert_ne!(a.output, b.output);
        assert_eq!(
            bifid_decode(&a.output, &BifidOptions { period: 3 })
                .unwrap()
                .output,
            "ATTACKATDAWN"
        );
    }

    #[test]
    fn trifid_known_vector_and_round_trip() {
        // Hand-derived with alphabet A-Z+ (layer,row,col triples):
        // H(0,2,1) E(0,1,1) L(1,0,2) L(1,0,2) O(1,1,2), period 5:
        // layers 0,0,1,1,1 + rows 2,1,0,0,1 + cols 1,1,2,2,2 →
        // triples (0,0,1)B (1,1,2)O (1,0,0)J (1,1,1)N (2,2,2)+.
        let options = TrifidOptions { period: 5 };
        let enc = trifid_encode("HELLO", &options).unwrap();
        assert_eq!(enc.output, "BOJN+");
        assert_eq!(
            trifid_decode(&enc.output, &options).unwrap().output,
            "HELLO"
        );
    }

    #[test]
    fn trifid_round_trips_prose() {
        let options = TrifidOptions { period: 7 };
        let text = "THEQUICKBROWNFOXJUMPSTHELAZYDOGNEXTWEEK";
        let enc = trifid_encode(text, &options).unwrap();
        assert_eq!(trifid_decode(&enc.output, &options).unwrap().output, text);
    }

    #[test]
    fn foursquare_wikipedia_vector_leading_digraphs() {
        // Wikipedia's example uses keys example/keyword over Q-omitted
        // plaintext squares; the leading digraph "he" → FY is invariant
        // under both alphabet conventions (no Q/J involved).
        let options = FoursquareOptions {
            key1: "example".into(),
            key2: "keyword".into(),
            alphabet: AlphabetMode::IjMerged,
        };
        let enc = foursquare_encode("help me obiwan kenobi", &options).unwrap();
        assert!(enc.output.starts_with("FY"), "got {}", enc.output);
        assert_eq!(
            foursquare_decode(&enc.output, &options).unwrap().output,
            "HELPMEOBIWANKENOBI"
        );
    }

    #[test]
    fn foursquare_noq_mode_round_trips() {
        let options = FoursquareOptions {
            key1: "example".into(),
            key2: "keyword".into(),
            alphabet: AlphabetMode::NoQ,
        };
        let text = "ABCDEF"; // even length, no doubled letters
        let enc = foursquare_encode(text, &options).unwrap();
        assert_eq!(
            foursquare_decode(&enc.output, &options).unwrap().output,
            text
        );
        // The NoQ plaintext squares place Q's cell at P: only the round trip
        // through an existing letter is exact.
    }

    #[test]
    fn foursquare_requires_two_keys() {
        let options = FoursquareOptions {
            key1: String::new(),
            key2: "keyword".into(),
            alphabet: AlphabetMode::IjMerged,
        };
        assert!(foursquare_encode("hi", &options).is_err());
    }

    #[test]
    fn adfgx_wikipedia_vector() {
        // The classic 1918-style example: mixed square BTALP/DHOZK/QFVSN/
        // GICUX/MREWY, transposition key CARGO, plaintext attackatonce.
        let options = AdfgxOptions {
            key: String::new(),
            transposition_key: "cargo".into(),
            square: Some("BTALPDHOZKQFVSNGICUXMREWY".into()),
        };
        let enc = adfgx_encode("attackatonce", &options).unwrap();
        assert_eq!(enc.output, "FAXDFADDDGDGFFFAFAXAFAFX");
        let dec = adfgx_decode(&enc.output, &options).unwrap();
        assert_eq!(dec.output, "ATTACKATONCE");
    }

    #[test]
    fn adfgx_keyed_square_round_trip() {
        let options = AdfgxOptions {
            key: "shadow".into(),
            transposition_key: "night".into(),
            square: None,
        };
        let text = "MEETMEATTHEDIVIDER";
        let enc = adfgx_encode(text, &options).unwrap();
        assert!(enc.output.chars().all(|c| "ADFGX".contains(c)));
        assert_eq!(enc.output.len(), 2 * 18);
        assert_eq!(adfgx_decode(&enc.output, &options).unwrap().output, text);
        // J merges into I.
        let jay = adfgx_encode("JAZZ", &options).unwrap();
        assert_eq!(adfgx_decode(&jay.output, &options).unwrap().output, "IAZZ");
    }

    #[test]
    fn adfgvx_hand_derived_vector() {
        // Key NACHTBOMEN, row-major 6-wide: NACHTB | OMEDFG | IJKLPQ |
        // RSUVWX | YZ0123 | 456789. HELLO -> AG DF FG FG DA; transposition
        // key KEY over the 10 symbols: col heights [4,3,3], columns
        // K=AFFA E=GFG Y=DGD, read E,K,Y -> GFGAFFADGD.
        let options = AdfgvxOptions {
            key: "nachtbomen".into(),
            transposition_key: "key".into(),
            square: None,
        };
        let enc = adfgvx_encode("hello", &options).unwrap();
        assert_eq!(enc.output, "GFGAFFADGD");
        assert_eq!(
            adfgvx_decode(&enc.output, &options).unwrap().output,
            "HELLO"
        );
    }

    #[test]
    fn adfgvx_handles_digits_and_rejects_bad_symbols() {
        let options = AdfgvxOptions {
            key: "test".into(),
            transposition_key: "abend".into(),
            square: None,
        };
        let enc = adfgvx_encode("r4nd0m", &options).unwrap();
        assert_eq!(
            adfgvx_decode(&enc.output, &options).unwrap().output,
            "R4ND0M"
        );
        assert!(
            adfgvx_decode("QQAQ", &options).is_err(),
            "Q is not an ADFGVX symbol"
        );
        assert!(
            adfgx_decode("VAVAVA", &AdfgxOptions::default()).is_err(),
            "V is not an ADFGX symbol"
        );
    }

    #[test]
    fn adf_rejects_duplicate_transposition_keys() {
        let options = AdfgxOptions {
            key: String::new(),
            transposition_key: "cacao".into(),
            square: None,
        };
        let err = adfgx_encode("hi", &options).unwrap_err();
        assert!(err.actual.as_deref().unwrap().contains("duplicate"));
    }

    #[test]
    fn hill_classic_vectors() {
        // 2x2: [[3,3],[2,5]] (key DDCF), HELP -> HIAT.
        let enc = hill_encode("HELP", "DDCF", &HillOptions::default()).unwrap();
        assert_eq!(enc.output, "HIAT");
        assert_eq!(
            hill_decode("HIAT", "DDCF", &HillOptions::default())
                .unwrap()
                .output,
            "HELP"
        );
        // 3x3: GYBNQKURP, ACT -> POH.
        let enc = hill_encode("ACT", "GYBNQKURP", &HillOptions::default()).unwrap();
        assert_eq!(enc.output, "POH");
        assert_eq!(
            hill_decode("POH", "GYBNQKURP", &HillOptions::default())
                .unwrap()
                .output,
            "ACT"
        );
    }

    #[test]
    fn hill_pads_partial_blocks() {
        let enc = hill_encode("HELPM", "DDCF", &HillOptions::default()).unwrap();
        assert_eq!(enc.output.len(), 6, "5 letters pad to 6 (three 2x2 blocks)");
        let dec = hill_decode(&enc.output, "DDCF", &HillOptions::default())
            .unwrap()
            .output;
        assert_eq!(dec, "HELPMX");
    }

    #[test]
    fn hill_rejects_singular_matrices() {
        // [[13, 0], [0, 1]]: det 13 shares a factor with 26.
        let err = hill_encode("AB", "NAAB", &HillOptions::default()).unwrap_err();
        assert_eq!(err.expected.as_deref(), Some("gcd(det, 26) = 1"));
        assert_eq!(err.actual.as_deref(), Some("det = 13 mod 26"));
        // det = 0: [[1,2],[2,4]] -> key B C C E.
        assert!(hill_encode("AB", "BCCE", &HillOptions::default()).is_err());
        // Wrong key length.
        assert!(hill_encode("AB", "ABC", &HillOptions::default()).is_err());
        // Ciphertext not a whole block.
        assert!(hill_decode("ABC", "DDCF", &HillOptions::default()).is_err());
    }

    #[test]
    fn square_oversized_input_rejected() {
        let big = "a".repeat(super::super::MAX_TEXT_BYTES + 1);
        assert!(polybius_encode(&big, &PolybiusOptions::default()).is_err());
        assert!(bifid_encode(&big, &BifidOptions::default()).is_err());
        assert!(hill_encode(&big, "DDCF", &HillOptions::default()).is_err());
    }
}
