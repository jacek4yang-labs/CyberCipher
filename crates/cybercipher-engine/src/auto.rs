//! Auto Decode: bounded, explainable automatic multi-layer decoding.
//!
//! Architecture (per project charter):
//!   cheap detectors -> plausible transformations -> execution -> scoring
//!   -> deduplication -> beam search
//!
//! Hard bounds: max depth, beam width, wall-clock deadline, and a
//! decompressed-size cap inside the codec. Random/binary inputs collapse to
//! "no confident candidate" instead of unbounded brute force. Every candidate
//! carries its evidence; Auto Decode never claims certainty it cannot show.

use crate::payload::value_cache_bytes;
use cybercipher_core::util::printable_ratio;
use cybercipher_core::{ExecutionContext, OperationRegistry, ParamMap, Value, ValueKind};
use serde::Serialize;
use std::collections::HashSet;
use std::time::{Duration, Instant};

pub const MAX_DEPTH: usize = 6;
pub const BEAM_WIDTH: usize = 16;
/// Candidates at or above this score are flagged as confident.
pub const CONFIDENT_SCORE: f64 = 0.70;
const MAX_CANDIDATES_REPORTED: usize = 12;
/// XOR exploration is O(256·len): cap the input size to keep the beam cheap.
const XOR_EXPLORE_LIMIT: usize = 32 * 1024;
/// How many XOR-decoded nodes may enter the beam per expanded node.
const XOR_BEAM_SLOTS: usize = 3;
const DEADLINE: Duration = Duration::from_millis(3000);
/// Base58/62/36 decode the whole input as one big integer: O(n^2). Cap the
/// speculative input size so a single decode stays in the low milliseconds
/// (8 KiB measured ~25ms in a debug build) and the beam cannot blow the
/// wall-clock deadline. Larger inputs remain available through the explicit
/// From Base58/62/36 operations.
const BIGNUM_EXPLORE_LIMIT: usize = 8 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct AutoCandidate {
    pub score: f64,
    pub confident: bool,
    /// Operation ids in application order.
    pub path: Vec<String>,
    pub evidence: Vec<String>,
    pub kind: String,
    pub size: usize,
    /// Bounded text preview of the decoded value.
    pub preview: String,
    pub is_utf8: bool,
    pub flag_like: Option<String>,
}

impl AutoCandidate {
    /// Operation ids only — the basis for "apply as recipe".
    pub fn recipe_ops(&self) -> &[String] {
        &self.path
    }
}

/// One transformation available at a frontier node.
struct Step {
    op: &'static str,
    /// Cheap applicability gate over (bytes, value-kind). Never executes.
    applies: fn(&[u8], &str) -> bool,
    evidence: &'static str,
}

/// Strict hex gate: only hex digits + whitespace, even digit count.
fn is_hex_strict(data: &[u8]) -> bool {
    let mut digits = 0usize;
    for &b in data {
        match b {
            b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => digits += 1,
            b' ' | b'\n' | b'\r' | b'\t' => {}
            _ => return false,
        }
    }
    digits >= 4 && digits.is_multiple_of(2)
}

/// Relaxed base64 gate: >=95% standard alphabet, mixed letters and digits,
/// plausible length. Pure-digit strings are left to the hex/decimal paths.
fn is_base64_like(data: &[u8]) -> bool {
    let mut alpha = 0usize;
    let mut total = 0usize;
    for &b in data {
        total += 1;
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'+' | b'/' | b'=' => alpha += 1,
            b' ' | b'\n' | b'\r' | b'\t' => {}
            _ => return false,
        }
    }
    let has_letter = data.iter().any(|&b| b.is_ascii_alphabetic());
    let has_digit_or_op = data
        .iter()
        .any(|&b| b.is_ascii_digit() || b == b'+' || b == b'/' || b == b'=');
    total >= 8 && alpha * 100 >= total * 95 && has_letter && has_digit_or_op
}

fn is_base32_like(data: &[u8]) -> bool {
    let mut alpha = 0usize;
    let mut total = 0usize;
    for &b in data {
        total += 1;
        match b {
            b'A'..=b'Z' | b'2'..=b'7' | b'=' => alpha += 1,
            b' ' | b'\n' | b'\r' | b'\t' => {}
            _ => return false,
        }
    }
    total >= 8 && alpha * 100 >= total * 95 && data.iter().any(|&b| b.is_ascii_digit() || b == b'=')
}

// ------------------------- base-family gates (chunked/bignum alphabets) ----

/// Bitcoin Base58 alphabet: excludes 0, O, I and l (mirrors the codec).
const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE62_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/// ZeroMQ Z85 alphabet (0MQ spec 32/ZMTP).
const Z85_ALPHABET: &[u8] =
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
/// basE91 alphabet (Joachim Henke): printable ASCII minus space, `'`, `\`, `-`.
const BASE91_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";
/// Base36 upper-case convention used by the codec's gate (decode itself is
/// case-insensitive, but uppercase-only evidence keeps lowercase prose out).
const BASE36_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// (in-alphabet count, non-whitespace count). Whitespace is ignored: a
/// trailing newline is presentation, not encoding evidence.
fn alphabet_stats(data: &[u8], alphabet: &[u8]) -> (usize, usize) {
    let mut hits = 0usize;
    let mut total = 0usize;
    for &b in data {
        if b.is_ascii_whitespace() {
            continue;
        }
        total += 1;
        if alphabet.contains(&b) {
            hits += 1;
        }
    }
    (hits, total)
}

/// Base58 gate: >=90% of non-whitespace chars in the Bitcoin alphabet, and
/// the absolute disqualifiers 0/O/I/l absent — a single one proves the data
/// is NOT Base58 no matter how the ratios look. (Base62 is a superset: when
/// both gates fire the scorer disambiguates by output quality.)
fn is_base58_like(data: &[u8]) -> bool {
    if data.iter().any(|&b| matches!(b, b'0' | b'O' | b'I' | b'l')) {
        return false;
    }
    let (hits, total) = alphabet_stats(data, BASE58_ALPHABET);
    total >= 8 && hits * 100 >= total * 90
}

/// Base62 gate: 0-9A-Za-z with >=95% compliance. Weaker evidence than the
/// padding-checked Base64 gate — the scorer does the disambiguation.
fn is_base62_like(data: &[u8]) -> bool {
    let (hits, total) = alphabet_stats(data, BASE62_ALPHABET);
    total >= 8 && hits * 100 >= total * 95
}

/// Ascii85 gate: every char in '!'..'u' (0x21..=0x75) plus the 'z' shorthand,
/// with optional Adobe <~ ~> delimiters stripped first. Fires on length >= 10
/// or whenever the Adobe delimiters are present.
fn is_ascii85_like(data: &[u8]) -> bool {
    let body = data
        .strip_prefix(b"<~")
        .map(|rest| rest.strip_suffix(b"~>").unwrap_or(rest))
        .unwrap_or(data);
    !body.is_empty()
        && body
            .iter()
            .all(|&b| (0x21..=0x75).contains(&b) || b == b'z')
        && (body.len() >= 10 || data.starts_with(b"<~"))
}

/// Z85 gate: exact alphabet match, length a multiple of 5 (4 bytes -> 5 chars).
fn is_z85_like(data: &[u8]) -> bool {
    let (hits, total) = alphabet_stats(data, Z85_ALPHABET);
    total >= 10 && total % 5 == 0 && hits == total
}

/// basE91 gate: >=90% compliance with the 91-char alphabet. Almost everything
/// printable passes it, so it is weak evidence — scored accordingly.
fn is_base91_like(data: &[u8]) -> bool {
    let (hits, total) = alphabet_stats(data, BASE91_ALPHABET);
    total >= 10 && hits * 100 >= total * 90
}

/// Base36 gate: 0-9A-Z only (case-insensitive decode, but lowercase prose
/// must not become a Base36 candidate), minimum length 10.
fn is_base36_like(data: &[u8]) -> bool {
    let (hits, total) = alphabet_stats(data, BASE36_ALPHABET);
    total >= 10 && hits == total
}

fn is_url_encoded(data: &[u8]) -> bool {
    data.len() >= 6
        && data
            .windows(3)
            .filter(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
            .count()
            >= 2
}

fn is_gzip(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

fn is_zlib(data: &[u8]) -> bool {
    data.len() >= 2
        && data[0] == 0x78
        && matches!(
            data[1],
            0x01 | 0x5e | 0x9c | 0xda | 0x20 | 0x7d | 0xbb | 0xf9
        )
}

// ------------------------------ v3 wrapper gates (magic + syntax) ----------

fn is_bzip2_magic(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..3] == b"BZh" && data[3].is_ascii_digit() && data[3] != b'0'
}

fn is_xz_magic(data: &[u8]) -> bool {
    data.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00])
}

fn is_zstd_magic(data: &[u8]) -> bool {
    data.starts_with(&[0x28, 0xB5, 0x2F, 0xFD])
}

fn is_lz4_magic(data: &[u8]) -> bool {
    data.starts_with(&[0x04, 0x22, 0x4D, 0x18])
}

/// Unicode escapes: >= 4 well-formed `\uXXXX` / `\u{...}` / `\xXX` escapes.
/// The count requirement keeps lone escapes (and Windows-style paths like
/// `C:\users`) out of the beam.
fn is_unicode_escapes(data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    let b = text.as_bytes();
    let mut count = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        if b[i] != b'\\' || i + 1 >= b.len() {
            i += 1;
            continue;
        }
        match b[i + 1] {
            b'u' if i + 2 < b.len() && b[i + 2] == b'{' => {
                // \u{...}: 1-6 hex digits then '}'.
                let mut j = i + 3;
                let mut digits = 0usize;
                while j < b.len() && b[j] != b'}' && digits < 7 {
                    if !b[j].is_ascii_hexdigit() {
                        break;
                    }
                    digits += 1;
                    j += 1;
                }
                if j < b.len() && b[j] == b'}' && (1..=6).contains(&digits) {
                    count += 1;
                    i = j + 1;
                } else {
                    i += 1;
                }
            }
            b'u' if i + 5 < b.len() && b[i + 2..i + 6].iter().all(|c| c.is_ascii_hexdigit()) => {
                count += 1;
                i += 6;
            }
            b'x' if i + 3 < b.len()
                && b[i + 2].is_ascii_hexdigit()
                && b[i + 3].is_ascii_hexdigit() =>
            {
                count += 1;
                i += 4;
            }
            _ => i += 1,
        }
    }
    count >= 4
}

/// HTML entities: >= 2 well-formed references — numeric `&#NNN;` / `&#xHH;`
/// or named `&name;`. A lone `&amp;` (or prose like `R&D`) must not fire.
fn is_html_entities(data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    let b = text.as_bytes();
    let mut count = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        if b[i] != b'&' {
            i += 1;
            continue;
        }
        let rest = &b[i + 1..];
        let consumed = if rest.first() == Some(&b'#') {
            // Numeric: optional x/X, 1-7 hex digits, then ';'.
            let hex_mode = rest.get(1) == Some(&b'x') || rest.get(1) == Some(&b'X');
            let digits_start = if hex_mode { 2 } else { 1 };
            let mut end = digits_start;
            while end < rest.len() && rest[end].is_ascii_hexdigit() && end - digits_start < 7 {
                end += 1;
            }
            if end > digits_start && rest.get(end) == Some(&b';') {
                Some(end + 1)
            } else {
                None
            }
        } else {
            // Named: 2-10 alphanumerics then ';'.
            let mut end = 0usize;
            while end < rest.len() && rest[end].is_ascii_alphanumeric() && end < 10 {
                end += 1;
            }
            if (2..=10).contains(&end) && rest.get(end) == Some(&b';') {
                Some(end + 1)
            } else {
                None
            }
        };
        match consumed {
            Some(len) => {
                count += 1;
                i += 1 + len;
            }
            None => i += 1,
        }
    }
    count >= 2
}

/// Quoted-printable: >= 4 `=XX` hex escapes, or any soft line break
/// (`=\r\n` / `=\n`) plus at least one `=XX` escape.
fn is_quoted_printable(data: &[u8]) -> bool {
    let mut escapes = 0usize;
    let mut soft_breaks = 0usize;
    let mut i = 0usize;
    while i < data.len() {
        if data[i] == b'=' {
            if data.get(i + 1) == Some(&b'\n')
                || (data.get(i + 1) == Some(&b'\r') && data.get(i + 2) == Some(&b'\n'))
            {
                soft_breaks += 1;
                i += 1;
                continue;
            }
            if i + 2 < data.len()
                && data[i + 1].is_ascii_hexdigit()
                && data[i + 2].is_ascii_hexdigit()
            {
                escapes += 1;
                i += 3;
                continue;
            }
        }
        i += 1;
    }
    escapes >= 4 || (soft_breaks >= 1 && escapes >= 1)
}

/// Punycode: an `xn--` ACE prefix (case-insensitive) followed by >= 4
/// LDH characters (letters, digits, hyphen) — the label body of a real ACE
/// label. Bounded like the other big-number explorations.
const PUNYCODE_EXPLORE_LIMIT: usize = 64 * 1024;

fn is_punycode_ace(data: &[u8]) -> bool {
    let lower = data.to_ascii_lowercase();
    let mut search = 0usize;
    while let Some(pos) = lower[search..].windows(4).position(|w| w == b"xn--") {
        let start = search + pos + 4;
        let body = &lower[start..];
        let body_len = body
            .iter()
            .take_while(|b| matches!(**b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
            .count();
        if body_len >= 4 {
            return true;
        }
        search = start.max(search + 1);
    }
    false
}

/// uuencode/xxencode: the shared `begin <mode> <name>` first line and a
/// trailing `end` line. The table choice is decided by the decode itself.
fn is_uu_envelope(data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    let mut lines = text.lines().map(str::trim_end).filter(|l| !l.is_empty());
    let Some(first) = lines.next() else {
        return false;
    };
    let fb = first.as_bytes();
    if !fb.starts_with(b"begin ") || fb.len() < 10 {
        return false;
    }
    if !fb[6..9].iter().all(|b| (b'0'..=b'7').contains(b)) || fb[9] != b' ' {
        return false;
    }
    let Some(end) = text.lines().next_back() else {
        return false;
    };
    end.trim_end().eq_ignore_ascii_case("end")
}

/// yEnc: the `=ybegin` control line.
fn is_yenc_envelope(data: &[u8]) -> bool {
    let first = data.split(|&b| b == b'\n').next().unwrap_or(data);
    let first = first.strip_suffix(b"\r").unwrap_or(first);
    first.starts_with(b"=ybegin")
}

/// Socialist core values: (trimmed) character count even and every 2-char
/// pair is one of the 12 slogan phrases; at least 4 phrases.
const CORE_VALUE_PHRASES: [&str; 12] = [
    "富强", "民主", "文明", "和谐", "自由", "平等", "公正", "法治", "爱国", "敬业", "诚信", "友善",
];

fn is_core_values(data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    let text = text.trim();
    let chars: Vec<char> = text.chars().collect();
    if chars.len() < 8 || !chars.len().is_multiple_of(2) {
        return false;
    }
    chars.chunks(2).all(|chunk| {
        let phrase: String = chunk.iter().collect();
        CORE_VALUE_PHRASES.contains(&phrase.as_str())
    })
}

/// Buddha says (与佛论禅): the `佛曰：` / `魔曰：` envelope (full-width or
/// ASCII colon).
fn is_buddha_payload(data: &[u8]) -> bool {
    for prefix in ["佛曰：", "佛曰:", "魔曰：", "魔曰:"] {
        if data.starts_with(prefix.as_bytes()) {
            return true;
        }
    }
    false
}

/// New Buddha (新佛曰): the `佛又曰：` envelope.
fn is_buddha_pbe_payload(data: &[u8]) -> bool {
    data.starts_with("佛又曰：".as_bytes()) || data.starts_with("佛又曰:".as_bytes())
}

/// Bear says (熊曰): the `熊曰：` envelope.
fn is_bear_payload(data: &[u8]) -> bool {
    data.starts_with("熊曰：".as_bytes()) || data.starts_with("熊曰:".as_bytes())
}

/// Beast speak (兽音译者): the `~呜嗷 … 啊` envelope with the default codec.
fn is_beast_payload(data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    let trimmed = text.trim();
    trimmed.starts_with("~呜嗷") && trimmed.ends_with('啊') && trimmed.chars().count() >= 10
}

/// Brainfuck: only the 8-command vocabulary (plus whitespace), at least 20
/// commands, at least one output command, and balanced brackets.
fn is_brainfuck_program(data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    let mut commands = 0usize;
    let mut outputs = 0usize;
    let mut depth = 0i64;
    for c in text.chars() {
        match c {
            '+' | '-' | '<' | '>' | '[' | ']' | '.' | ',' => {
                commands += 1;
                if c == '.' {
                    outputs += 1;
                }
                if c == '[' {
                    depth += 1;
                } else if c == ']' {
                    depth -= 1;
                    if depth < 0 {
                        return false;
                    }
                }
            }
            c if c.is_whitespace() => {}
            _ => return false,
        }
    }
    commands >= 20 && outputs >= 1 && depth == 0
}

/// Ook!: at least 8 `Ook.` / `Ook?` / `Ook!` token occurrences.
fn is_ook_program(data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    let mut tokens = 0usize;
    let mut rest = text;
    while let Some(pos) = rest.find("Ook") {
        let tail = &rest[pos + 3..];
        match tail.chars().next() {
            Some('.') | Some('?') | Some('!') => tokens += 1,
            _ => {}
        }
        rest = tail;
    }
    tokens >= 8
}

/// Cheap English-language sanity check used by the ROT13/Atbash gates: the
/// vowel share of the letters must land in the natural-language band. Both
/// shifts permute vowels into consonants and vice versa, so a wrongly chosen
/// candidate has (approximately) the input's ratio and does not fire.
fn vowel_share(text: &str) -> Option<f64> {
    let mut letters = 0usize;
    let mut vowels = 0usize;
    for c in text.chars() {
        if c.is_ascii_alphabetic() {
            letters += 1;
            if matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u') {
                vowels += 1;
            }
        }
    }
    if letters >= 8 {
        Some(vowels as f64 / letters as f64)
    } else {
        None
    }
}

fn shifted_share(data: &[u8], shift: fn(char) -> char) -> Option<f64> {
    let Ok(text) = std::str::from_utf8(data) else {
        return None;
    };
    let shifted: String = text.chars().map(shift).collect();
    vowel_share(&shifted)
}

fn rot13_char(c: char) -> char {
    match c {
        'a'..='z' => ((c as u8 - b'a' + 13) % 26 + b'a') as char,
        'A'..='Z' => ((c as u8 - b'A' + 13) % 26 + b'A') as char,
        other => other,
    }
}

fn atbash_char(c: char) -> char {
    match c {
        'a'..='z' => (b'z' - (c as u8 - b'a')) as char,
        'A'..='Z' => (b'Z' - (c as u8 - b'A')) as char,
        other => other,
    }
}

/// ROT13/Atbash gate: the shifted text must gain a plausible vowel share
/// over the input (at least 8 points, landing in the 28-65% band). Random
/// alphanumerics keep their ratio under both shifts and never fire; plain
/// English loses its share and does not either.
fn is_shifted_language(data: &[u8], shift: fn(char) -> char) -> bool {
    let Some(shifted) = shifted_share(data, shift) else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    let Some(original) = vowel_share(text) else {
        return false;
    };
    (0.28..=0.65).contains(&shifted) && shifted - original >= 0.08
}

/// Reversed flag gate: the input ends with `}` and its reversal starts with
/// a known flag prefix. Precise evidence, near-zero false positives.
fn is_reversed_flag(data: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    let trimmed = text.trim();
    if trimmed.len() < 8 || !trimmed.ends_with('}') {
        return false;
    }
    let reversed: String = trimmed.chars().rev().collect();
    let lowered = reversed.to_lowercase();
    ["flag{", "ctf{", "picoctf{", "htb{", "key{"]
        .iter()
        .any(|prefix| lowered.starts_with(prefix))
}

// ------------------------- structured-format gates (bounded walks) ----------

/// A bounded structural walk over CBOR (RFC 8949). Definite lengths only
/// (indefinite items are left to the explicit op); validates that every head
/// fits the buffer and the stream is fully consumed. Depth- and
/// element-capped so hostile inputs stay cheap.
fn is_cbor_like(data: &[u8]) -> bool {
    const MAX_ITEMS: usize = 4096;
    const MAX_DEPTH: usize = 64;
    let mut stack: Vec<u64> = Vec::new();
    let mut items = 0usize;
    stack.push(1);
    let mut pos = 0usize;
    while let Some(remaining) = stack.last_mut() {
        items += 1;
        if items > MAX_ITEMS || stack.len() > MAX_DEPTH || pos >= data.len() {
            return false;
        }
        let ib = data[pos];
        let major = ib >> 5;
        let ai = ib & 0x1F;
        pos += 1;
        let length: Option<u64> = match ai {
            0..=23 => Some(ai as u64),
            24 => data.get(pos).map(|_| {
                pos += 1;
                data[pos - 1] as u64
            }),
            25 => data.get(pos + 1).map(|_| {
                let v = u16::from_be_bytes([data[pos], data[pos + 1]]) as u64;
                pos += 2;
                v
            }),
            26 => data.get(pos + 3).map(|_| {
                let v = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                    as u64;
                pos += 4;
                v
            }),
            27 => data.get(pos + 7).map(|_| {
                let mut b = [0u8; 8];
                b.copy_from_slice(&data[pos..pos + 8]);
                pos += 8;
                u64::from_be_bytes(b)
            }),
            _ => None, // indefinite / reserved: not gated
        };
        let Some(length) = length else {
            return false;
        };
        match major {
            0 | 1 | 7 => {
                *remaining -= 1;
            }
            2 | 3 => {
                let end = pos.checked_add(usize::try_from(length).unwrap_or(usize::MAX));
                let Some(end) = end.filter(|&end| end <= data.len()) else {
                    return false;
                };
                pos = end;
                *remaining -= 1;
            }
            4 => {
                *remaining -= 1;
                if length > 0 {
                    stack.push(length);
                }
            }
            5 => {
                *remaining -= 1;
                if length > 0 {
                    stack.push(length.saturating_mul(2));
                }
            }
            6 => {
                // Tag: the tag itself consumes one parent slot and wraps one
                // child item.
                *remaining -= 1;
                stack.push(1);
            }
            _ => return false,
        }
        while let Some(top) = stack.last() {
            if *top == 0 {
                stack.pop();
            } else {
                break;
            }
        }
    }
    pos == data.len()
}

/// A bounded structural walk over MessagePack. Validates every format byte
/// and length against the buffer, requiring full consumption.
fn is_msgpack_like(data: &[u8]) -> bool {
    const MAX_ITEMS: usize = 4096;
    const MAX_DEPTH: usize = 64;

    // Read a big-endian length field of 1/2/4 bytes at `pos`.
    fn read_len(data: &[u8], pos: &mut usize, bytes: usize) -> Option<u64> {
        let end = pos.checked_add(bytes)?;
        if end > data.len() {
            return None;
        }
        let mut length = 0u64;
        for &b in &data[*pos..end] {
            length = (length << 8) | b as u64;
        }
        *pos = end;
        Some(length)
    }

    let mut stack: Vec<u64> = Vec::new();
    let mut items = 0usize;
    stack.push(1);
    let mut pos = 0usize;
    while let Some(remaining) = stack.last_mut() {
        items += 1;
        if items > MAX_ITEMS || stack.len() > MAX_DEPTH || pos >= data.len() {
            return false;
        }
        let b = data[pos];
        pos += 1;
        // (payload bytes to skip, child count pushed when > 0)
        let (skip, children): (usize, u64) = match b {
            // positive fixint / negative fixint / nil / false / true
            0x00..=0x7F | 0xE0..=0xFF | 0xC0 | 0xC2 | 0xC3 => (0, 0),
            // fixmap / fixarray
            0x80..=0x8F => (0, (b & 0x0F) as u64 * 2),
            0x90..=0x9F => (0, (b & 0x0F) as u64),
            // fixstr
            0xA0..=0xBF => (((b & 0x1F) as usize), 0),
            0xC1 => return false, // never used
            // bin8/16/32 and str8/16/32
            0xC4 | 0xC5 | 0xC6 | 0xD9 | 0xDA | 0xDB => {
                let len_bytes = match b {
                    0xC4 | 0xD9 => 1,
                    0xC5 | 0xDA => 2,
                    _ => 4,
                };
                let length = read_len(data, &mut pos, len_bytes)?;
                (usize::try_from(length).unwrap_or(usize::MAX), 0)
            }
            // float32/64
            0xCA | 0xCB => (if b == 0xCA { 4 } else { 8 }, 0),
            // uint 8/16/32/64, int 8/16/32/64
            0xCC..=0xCF | 0xD0..=0xD3 => (
                match b {
                    0xCC | 0xD0 => 1,
                    0xCD | 0xD1 => 2,
                    0xCE | 0xD2 => 4,
                    _ => 8,
                },
                0,
            ),
            // fixext1/2/4/8/16 (one extra type byte + payload)
            0xD4..=0xD8 => (
                match b {
                    0xD4 => 1,
                    0xD5 => 2,
                    0xD6 => 4,
                    0xD7 => 8,
                    _ => 16,
                } + 1,
                0,
            ),
            // ext8/16/32: length + 1 type byte
            0xC7 | 0xC8 | 0xC9 => {
                let len_bytes = match b {
                    0xC7 => 1,
                    0xC8 => 2,
                    _ => 4,
                };
                let length = read_len(data, &mut pos, len_bytes)?;
                (
                    usize::try_from(length)
                        .unwrap_or(usize::MAX)
                        .saturating_add(1),
                    0,
                )
            }
            // array16/32
            0xDC | 0xDD => {
                let length = read_len(data, &mut pos, if b == 0xDC { 2 } else { 4 })?;
                (0, length)
            }
            // map16/32
            0xDE | 0xDF => {
                let length = read_len(data, &mut pos, if b == 0xDE { 2 } else { 4 })?;
                (0, length.saturating_mul(2))
            }
            _ => return false,
        };
        let Some(end) = pos.checked_add(skip) else {
            return false;
        };
        if end > data.len() {
            return false;
        }
        pos = end;
        *remaining -= 1;
        if children > 0 {
            stack.push(children);
        }
        while let Some(top) = stack.last() {
            if *top == 0 {
                stack.pop();
            } else {
                break;
            }
        }
    }
    pos == data.len()
}

/// The step set. Compression first (magic-exact), then syntax-gated decoders,
/// then the v3 wrapper vocabulary (each gated by a cheap deterministic
/// detector that runs before the op).
const STEPS: &[Step] = &[
    Step {
        op: "from-gzip",
        applies: |d, _| is_gzip(d),
        evidence: "gzip magic 1f 8b",
    },
    Step {
        op: "from-zlib",
        applies: |d, _| is_zlib(d),
        evidence: "zlib header 0x78",
    },
    Step {
        op: "from-bzip2",
        applies: |d, _| is_bzip2_magic(d),
        evidence: "bzip2 magic 'BZh' + level digit",
    },
    Step {
        op: "from-xz",
        applies: |d, _| is_xz_magic(d),
        evidence: "xz magic fd 37 7a 58 5a 00",
    },
    Step {
        op: "from-zstd",
        applies: |d, _| is_zstd_magic(d),
        evidence: "zstd magic 28 b5 2f fd",
    },
    Step {
        op: "from-lz4",
        applies: |d, _| is_lz4_magic(d),
        evidence: "lz4 frame magic 04 22 4d 18",
    },
    Step {
        op: "from-cbor",
        applies: |d, _| is_cbor_like(d),
        evidence: "valid CBOR structure",
    },
    Step {
        op: "from-msgpack",
        applies: |d, _| is_msgpack_like(d),
        evidence: "valid MessagePack structure",
    },
    Step {
        op: "from-base64",
        applies: |d, _| is_base64_like(d),
        evidence: "valid Base64 alphabet and length",
    },
    Step {
        op: "from-base32",
        applies: |d, _| is_base32_like(d),
        evidence: "valid Base32 alphabet",
    },
    Step {
        op: "from-base58",
        applies: |d, _| d.len() <= BIGNUM_EXPLORE_LIMIT && is_base58_like(d),
        evidence: "Base58 alphabet match",
    },
    Step {
        op: "from-base62",
        applies: |d, _| d.len() <= BIGNUM_EXPLORE_LIMIT && is_base62_like(d),
        evidence: "Base62 alphabet match",
    },
    Step {
        op: "from-ascii85",
        applies: |d, _| is_ascii85_like(d),
        evidence: "Ascii85 alphabet match",
    },
    Step {
        op: "from-z85",
        applies: |d, _| is_z85_like(d),
        evidence: "Z85 alphabet and length match",
    },
    Step {
        op: "from-base91",
        applies: |d, _| is_base91_like(d),
        evidence: "basE91 alphabet match",
    },
    Step {
        op: "from-base36",
        applies: |d, _| d.len() <= BIGNUM_EXPLORE_LIMIT && is_base36_like(d),
        evidence: "Base36 alphabet match",
    },
    Step {
        op: "from-hex",
        applies: |d, _| is_hex_strict(d),
        evidence: "strict hex syntax",
    },
    Step {
        op: "from-url",
        applies: |d, _| is_url_encoded(d),
        evidence: "percent escapes",
    },
    // ---- v3 wrapper vocabulary ----
    Step {
        op: "from-unicode-escapes",
        applies: |d, _| is_unicode_escapes(d),
        evidence: "unicode escape sequences (\\uXXXX / \\u{...} / \\xXX)",
    },
    Step {
        op: "from-html-entities",
        applies: |d, _| is_html_entities(d),
        evidence: "HTML entities",
    },
    Step {
        op: "from-quoted-printable",
        applies: |d, _| is_quoted_printable(d),
        evidence: "quoted-printable =XX escapes",
    },
    Step {
        op: "from-punycode",
        applies: |d, _| d.len() <= PUNYCODE_EXPLORE_LIMIT && is_punycode_ace(d),
        evidence: "ACE (xn--) punycode label",
    },
    Step {
        op: "from-uuencode",
        applies: |d, _| is_uu_envelope(d),
        evidence: "uuencode begin/end envelope",
    },
    Step {
        op: "from-xxencode",
        applies: |d, _| is_uu_envelope(d),
        evidence: "xxencode begin/end envelope",
    },
    Step {
        op: "from-yenc",
        applies: |d, _| is_yenc_envelope(d),
        evidence: "yEnc =ybegin envelope",
    },
    Step {
        op: "from-buddha",
        applies: |d, _| is_buddha_payload(d),
        evidence: "Buddha (佛曰/魔曰) envelope",
    },
    Step {
        op: "from-buddha-pbe",
        applies: |d, _| is_buddha_pbe_payload(d),
        evidence: "new Buddha (佛又曰) envelope",
    },
    Step {
        op: "from-bear",
        applies: |d, _| is_bear_payload(d),
        evidence: "bear says (熊曰) envelope",
    },
    Step {
        op: "from-beast",
        applies: |d, _| is_beast_payload(d),
        evidence: "beast speak (~呜嗷…啊) envelope",
    },
    Step {
        op: "from-core-values",
        applies: |d, _| is_core_values(d),
        evidence: "socialist core values phrase table",
    },
    Step {
        op: "run-brainfuck",
        applies: |d, _| is_brainfuck_program(d),
        evidence: "Brainfuck command vocabulary",
    },
    Step {
        op: "from-ook",
        applies: |d, _| is_ook_program(d),
        evidence: "Ook! token pairs",
    },
    Step {
        op: "rot13",
        applies: |d, _| is_shifted_language(d, rot13_char),
        evidence: "ROT13 letter-frequency sanity",
    },
    Step {
        op: "atbash",
        applies: |d, _| is_shifted_language(d, atbash_char),
        evidence: "Atbash letter-frequency sanity",
    },
    Step {
        op: "reverse",
        applies: |d, _| is_reversed_flag(d),
        evidence: "reversed flag-like text",
    },
    Step {
        op: "decode-text",
        applies: |d, k| k == "bytes" && std::str::from_utf8(d).is_ok(),
        evidence: "valid UTF-8",
    },
];

struct Frontier {
    value: Value,
    kind: String,
    path: Vec<String>,
    evidence: Vec<String>,
}

/// Serialize a frontier value to bytes for gates, scoring and ranking.
/// `Value::Json` (the output of from-cbor / from-msgpack) serializes as its
/// JSON representation; other kinds borrow or fall back to empty.
fn value_to_bytes(value: &Value) -> Vec<u8> {
    match value {
        Value::Json(j) => serde_json::to_vec(j).unwrap_or_default(),
        other => other.as_bytes().map(|c| c.to_vec()).unwrap_or_default(),
    }
}

/// Run Auto Decode on raw input bytes. Returns ranked candidates.
pub fn auto_decode(
    registry: &OperationRegistry,
    input: &[u8],
    ctx: &ExecutionContext,
) -> Vec<AutoCandidate> {
    let started = Instant::now();
    let mut results: Vec<AutoCandidate> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();

    let input_kind = if std::str::from_utf8(input).is_ok() {
        "text"
    } else {
        "bytes"
    };
    let mut frontier = vec![Frontier {
        value: Value::Bytes(input.to_vec()),
        kind: input_kind.to_string(),
        path: Vec::new(),
        evidence: vec![],
    }];

    for _depth in 0..MAX_DEPTH {
        if frontier.is_empty() || ctx.is_cancelled() || started.elapsed() >= DEADLINE {
            break;
        }
        let mut next: Vec<Frontier> = Vec::new();
        for node in &frontier {
            if ctx.is_cancelled() || started.elapsed() >= DEADLINE {
                break;
            }
            let bytes = value_to_bytes(&node.value);
            let kind = node.kind.clone();
            // Single-byte XOR exploration: 256 cheap candidates for small
            // inputs — the classic CTF layer that syntax detectors cannot see.
            // All are scored and reported, but only the best few enter the
            // beam so they cannot crowd out the syntax-driven steps.
            if bytes.len() <= XOR_EXPLORE_LIMIT {
                let mut xor_nodes: Vec<Frontier> = Vec::new();
                for key in 1u16..256 {
                    if ctx.is_cancelled() || started.elapsed() >= DEADLINE {
                        break;
                    }
                    let key = key as u8;
                    let unxored: Vec<u8> = bytes.iter().map(|b| b ^ key).collect();
                    let out = Value::from_bytes(unxored);
                    let mut path = node.path.clone();
                    path.push("xor-single-byte".to_string());
                    let mut evidence = node.evidence.clone();
                    evidence.push(format!("single-byte XOR key 0x{key:02x}"));
                    let candidate = Frontier {
                        kind: out.kind().name().to_string(),
                        value: out,
                        path,
                        evidence,
                    };
                    collect_candidate(&candidate, &bytes, &mut seen, &mut results);
                    xor_nodes.push(candidate);
                }
                xor_nodes.sort_by_cached_key(|n| std::cmp::Reverse(beam_rank(n)));
                next.extend(xor_nodes.into_iter().take(XOR_BEAM_SLOTS));
            }
            for step in STEPS {
                if !(step.applies)(&bytes, &kind) {
                    continue;
                }
                let Some(op) = registry.get(step.op) else {
                    continue;
                };
                // Lossless adaptation matching the executor's coercion rule.
                let coerced = adapt(&node.value, op.spec().input_kinds);
                let Ok(out) = op.execute(&coerced, &ParamMap::new(), ctx) else {
                    continue;
                };
                let mut path = node.path.clone();
                path.push(step.op.to_string());
                let mut evidence = node.evidence.clone();
                evidence.push(step.evidence.to_string());
                let candidate = Frontier {
                    kind: out.kind().name().to_string(),
                    value: out,
                    path,
                    evidence,
                };
                collect_candidate(&candidate, &bytes, &mut seen, &mut results);
                next.push(candidate);
            }
        }
        next.sort_by_cached_key(|n| std::cmp::Reverse(beam_rank(n)));
        next.truncate(BEAM_WIDTH);
        frontier = next;
    }

    results.sort_by(|a, b| b.score.total_cmp(&a.score));
    results.truncate(MAX_CANDIDATES_REPORTED);
    results
}

/// Lossless Text/Bytes adaptation (mirrors the executor's coercion rule).
fn adapt(value: &Value, accepted: &[ValueKind]) -> Value {
    if accepted.contains(&value.kind()) {
        return value.clone();
    }
    match value {
        Value::Bytes(b) if accepted.contains(&ValueKind::Text) => match std::str::from_utf8(b) {
            Ok(text) => Value::Text(text.to_string()),
            Err(_) => value.clone(),
        },
        other => other.clone(),
    }
}

fn beam_rank(node: &Frontier) -> u32 {
    let bytes = value_to_bytes(&node.value);
    let printable = printable_ratio(&bytes) * 100.0;
    bytes.len().min(64 * 1024) as u32 / 16 + printable as u32
}

fn collect_candidate(
    node: &Frontier,
    prev: &[u8],
    seen: &mut HashSet<u64>,
    results: &mut Vec<AutoCandidate>,
) {
    if node.path.is_empty() {
        return;
    }
    let bytes = value_to_bytes(&node.value);
    let key = xxhash_rust::xxh3::xxh3_64(&value_cache_bytes(&node.value));
    if !seen.insert(key) || bytes.is_empty() || bytes == prev {
        return;
    }

    let is_utf8 = std::str::from_utf8(&bytes).is_ok();
    let printable = printable_ratio(&bytes);
    let flag_like = flag_pattern(&bytes);
    let mut evidence = node.evidence.clone();
    let mut score = 0.30 + 0.25 * printable;

    if is_utf8 {
        score += 0.15;
        evidence.push("UTF-8 output".to_string());
    }
    if flag_like.is_some() {
        score = (score + 0.45).min(0.99);
        evidence.push("flag-like pattern".to_string());
    }
    if looks_like_json(&bytes) {
        score = (score + 0.30).min(0.99);
        evidence.push("valid JSON".to_string());
    }
    if looks_like_pem(&bytes) {
        score = (score + 0.25).min(0.99);
        evidence.push("PEM structure".to_string());
    }
    for (name, magic) in MAGIC {
        if bytes.starts_with(magic) {
            score = (score + 0.35).min(0.99);
            evidence.push(format!("{name} magic"));
            break;
        }
    }
    if printable > 0.95 && bytes.len() >= 8 {
        evidence.push("high printable ratio".to_string());
    }
    // Penalize obviously degraded outputs.
    if bytes.len() > prev.len() * 64 + 1024 {
        score *= 0.5;
        evidence.push("size explosion (probable false positive)".to_string());
    }
    if !is_utf8 && printable < 0.2 {
        score *= 0.4;
    }
    // Mass-search candidates (255 of 256 XOR keys are noise): penalize so a
    // lucky printable decoding cannot outrank a positive syntax decode —
    // strong evidence (flags, JSON, magic) still lifts them back to the top.
    if node
        .path
        .last()
        .map(|p| p == "xor-single-byte")
        .unwrap_or(false)
    {
        score *= 0.85;
    }
    // ROT13/Atbash share the same mass-search character: the frequency gate
    // is weak evidence, so the printable-output score alone must not reach
    // confidence. Flag/JSON-grade evidence still lifts past the penalty.
    if node
        .path
        .last()
        .map(|p| p == "rot13" || p == "atbash")
        .unwrap_or(false)
    {
        score *= 0.85;
        evidence.push("weak-evidence transform (frequency heuristic)".to_string());
    }
    score = score.min(0.99);

    let preview: String = String::from_utf8_lossy(&bytes[..bytes.len().min(2048)]).into_owned();
    results.push(AutoCandidate {
        score: (score * 100.0).round() / 100.0,
        confident: score >= CONFIDENT_SCORE,
        path: node.path.clone(),
        evidence,
        kind: node.kind.clone(),
        size: bytes.len(),
        preview,
        is_utf8,
        flag_like,
    });
    // Keep the best 64 (not the newest): the 255-candidate XOR sweep must
    // not starve the syntax-driven decoders out of the report.
    if results.len() > 64 {
        results.sort_by(|a, b| b.score.total_cmp(&a.score));
        results.truncate(64);
    }
}

const MAGIC: &[(&str, &[u8])] = &[
    ("PNG", b"\x89PNG\r\n\x1a\n"),
    ("JPEG", b"\xff\xd8\xff"),
    ("ZIP", b"PK\x03\x04"),
    ("PDF", b"%PDF"),
    ("ELF", b"\x7fELF"),
    ("BZIP2", b"BZh"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
];

fn flag_pattern(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(64 * 1024)]);
    for pat in ["flag{", "FLAG{", "ctf{", "CTF{", "picoCTF{", "HTB{"] {
        if let Some(idx) = text.find(pat) {
            let rest = &text[idx..];
            if let Some(end) = rest.find('}') {
                if end <= 128 {
                    return Some(rest[..=end].to_string());
                }
            }
        }
    }
    None
}

fn looks_like_json(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(&bytes[..bytes.len().min(4096)]) else {
        return false;
    };
    let trimmed = text.trim_start();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(bytes).is_ok()
}

fn looks_like_pem(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(&bytes[..bytes.len().min(512)]) else {
        return false;
    };
    text.starts_with("-----BEGIN ")
}
