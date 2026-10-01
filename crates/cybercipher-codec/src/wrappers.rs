//! Wrapper text codecs used by Auto Decode v3 (and directly): Unicode
//! escapes, HTML entities, quoted-printable, Punycode (RFC 3492), uuencode /
//! xxencode, and yEnc.
//!
//! Conventions (matching the rest of the crate):
//!
//! * Every decoder has a strict (default) and a relaxed mode. Strict mode
//!   validates the syntax and fails with typed errors; relaxed mode keeps
//!   malformed constructs verbatim (or repairs them) instead of guessing.
//! * Decoders never guess: an unknown HTML named entity or an unknown
//!   backslash escape is *not* interpreted.
//! * Punycode implements RFC 3492 directly (mixed-case annotation and ACE
//!   `xn--` labels per RFC 5891); overflow and invalid digits are typed
//!   errors, and the O(n²) label decode is budget-capped.
//! * uuencode/xxencode implement the classic table algorithms behind the
//!   `begin <mode> <name>` / `end` envelope. Strict mode requires the
//!   envelope, an octal mode, and exact line lengths; relaxed mode also
//!   decodes envelope-less streams.
//! * yEnc is byte-oriented: its *output* is 8-bit data by design, so the
//!   encoder emits bytes and the decoder walks raw lines (only the control
//!   lines must be ASCII).

use crate::helpers::{input_bytes, input_text, p_bool, p_opts, spec};
use cybercipher_core::prelude::*;

/// Budget cap for wrapper decoders (8 MiB — generous for interactive use,
/// small enough to keep every decode inside its cost class).
const WRAPPER_MAX_INPUT: usize = 8 * 1024 * 1024;

/// Punycode labels decode code-point by code-point with an O(n) insertion:
/// cap the label size so one decode stays in the low milliseconds.
const PUNYCODE_MAX_LABEL: usize = 8 * 1024;

fn check_budget(len: usize, what: &str) -> OpResult<()> {
    if len > WRAPPER_MAX_INPUT {
        return Err(OperationError::new(
            ErrorKind::BudgetExceeded,
            format!("{what} input of {len} bytes exceeds the 8 MiB wrapper limit"),
        )
        .with_expected("at most 8388608 bytes")
        .with_actual(format!("{len} bytes")));
    }
    Ok(())
}

// ======================================================= Unicode escapes ====

/// Push a scalar value as UTF-8. Surrogates and out-of-range values are
/// typed errors in strict mode and U+FFFD in relaxed mode.
fn push_scalar(cp: u32, strict: bool, out: &mut Vec<u8>) -> OpResult<()> {
    match char::from_u32(cp) {
        Some(c) => {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            Ok(())
        }
        None if strict => Err(OperationError::decode(format!(
            "unicode escape value U+{cp:04X} is not a scalar value (surrogate half or out of range)"
        ))
        .with_expected("U+0000..U+10FFFF excluding surrogates")
        .with_actual(format!("U+{cp:04X}"))),
        None => {
            out.extend_from_slice("\u{FFFD}".as_bytes());
            Ok(())
        }
    }
}

/// Decode `\uXXXX`, `\u{...}` and `\xXX` escape sequences. Everything
/// outside an escape is copied verbatim. Strict mode rejects unknown
/// escapes, truncated hex and lone surrogates; relaxed mode keeps unknown
/// constructs verbatim and maps lone surrogates to U+FFFD.
pub fn decode_unicode_escapes(text: &str, strict: bool) -> OpResult<Vec<u8>> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            i += 1;
            continue;
        }
        match chars.get(i + 1) {
            Some('u') => {
                if chars.get(i + 2) == Some(&'{') {
                    i = decode_braced_escape(&chars, i, strict, &mut out)?;
                } else {
                    i = decode_fixed_escape(&chars, i, strict, &mut out)?;
                }
            }
            Some('x') => {
                let digits: String = chars[i + 2..(i + 4).min(chars.len())].iter().collect();
                if digits.chars().count() == 2 && digits.chars().all(|h| h.is_ascii_hexdigit()) {
                    let value = u32::from_str_radix(&digits, 16)
                        .map_err(|_| OperationError::internal("validated hex failed to parse"))?;
                    out.push(value as u8);
                    i += 4;
                } else if strict {
                    return Err(OperationError::decode(
                        "malformed \\xXX escape: expected exactly two hex digits",
                    )
                    .with_expected("\\xXX")
                    .with_actual(format!("`\\x{digits}`")));
                } else {
                    out.extend_from_slice(b"\\x");
                    i += 2;
                }
            }
            Some(other) => {
                if strict {
                    return Err(OperationError::decode(format!(
                        "unknown escape `\\{other}` (only \\uXXXX, \\u{{...}} and \\xXX are supported)"
                    ))
                    .with_expected("\\uXXXX, \\u{...} or \\xXX")
                    .with_actual(format!("`\\{other}`")));
                }
                out.push(b'\\');
                i += 1;
            }
            None => {
                if strict {
                    return Err(
                        OperationError::decode("input ends with a dangling backslash")
                            .with_expected("an escape sequence")
                            .with_actual("backslash at end of input"),
                    );
                }
                out.push(b'\\');
                i += 1;
            }
        }
    }
    Ok(out)
}

/// `\u{...}`: one to six hex digits inside braces. Returns the index to
/// resume from (after the closing brace, or past the re-emitted `\u{`).
fn decode_braced_escape(
    chars: &[char],
    i: usize,
    strict: bool,
    out: &mut Vec<u8>,
) -> OpResult<usize> {
    let mut j = i + 3;
    let mut hex = String::new();
    while j < chars.len() && chars[j] != '}' && hex.len() < 7 {
        hex.push(chars[j]);
        j += 1;
    }
    let well_formed = j < chars.len()
        && chars[j] == '}'
        && (1..=6).contains(&hex.len())
        && hex.chars().all(|h| h.is_ascii_hexdigit());
    if !well_formed {
        if strict {
            return Err(OperationError::decode(
                "malformed \\u{...} escape: expected 1-6 hex digits and a closing `}`",
            )
            .with_expected("\\u{hex}")
            .with_actual(format!(
                "`{}`",
                chars[i..(j + 1).min(chars.len())]
                    .iter()
                    .collect::<String>()
            )));
        }
        out.extend_from_slice(b"\\u{");
        return Ok(i + 3);
    }
    let cp = u32::from_str_radix(&hex, 16)
        .map_err(|_| OperationError::internal("validated hex failed to parse"))?;
    push_scalar(cp, strict, out)?;
    Ok(j + 1)
}

/// `\uXXXX`: exactly four hex digits, surrogate pairs combined. Returns the
/// index to resume from.
fn decode_fixed_escape(
    chars: &[char],
    i: usize,
    strict: bool,
    out: &mut Vec<u8>,
) -> OpResult<usize> {
    let hex: String = chars[i + 2..(i + 6).min(chars.len())].iter().collect();
    if hex.chars().count() != 4 || !hex.chars().all(|h| h.is_ascii_hexdigit()) {
        if strict {
            return Err(OperationError::decode(
                "malformed \\uXXXX escape: expected exactly four hex digits",
            )
            .with_expected("\\uXXXX")
            .with_actual(format!("`\\u{hex}`")));
        }
        out.extend_from_slice(b"\\u");
        return Ok(i + 2);
    }
    let cp = u32::from_str_radix(&hex, 16)
        .map_err(|_| OperationError::internal("validated hex failed to parse"))?;
    if (0xD800..=0xDBFF).contains(&cp) {
        // High surrogate: combine with a following \uXXXX low half.
        let low: Option<u32> = (chars.get(i + 6) == Some(&'\\') && chars.get(i + 7) == Some(&'u'))
            .then(|| {
                chars[i + 8..(i + 12).min(chars.len())]
                    .iter()
                    .collect::<String>()
            })
            .filter(|tail| tail.chars().count() == 4 && tail.chars().all(|h| h.is_ascii_hexdigit()))
            .and_then(|tail| u32::from_str_radix(&tail, 16).ok())
            .filter(|v| (0xDC00..=0xDFFF).contains(v));
        match low {
            Some(low) => {
                let combined = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                push_scalar(combined, strict, out)?;
                Ok(i + 12)
            }
            None => {
                if strict {
                    return Err(OperationError::decode(
                        "lone high surrogate in \\uXXXX escape (missing the low half)",
                    )
                    .with_expected("a paired \\uDCxx low surrogate")
                    .with_actual(format!("U+{cp:04X}")));
                }
                out.extend_from_slice("\u{FFFD}".as_bytes());
                Ok(i + 6)
            }
        }
    } else if (0xDC00..=0xDFFF).contains(&cp) {
        if strict {
            return Err(
                OperationError::decode("lone low surrogate in \\uXXXX escape")
                    .with_expected("a scalar value")
                    .with_actual(format!("U+{cp:04X}")),
            );
        }
        out.extend_from_slice("\u{FFFD}".as_bytes());
        Ok(i + 6)
    } else {
        push_scalar(cp, strict, out)?;
        Ok(i + 6)
    }
}

/// Encode text with the chosen escape style: every character outside
/// printable ASCII (and the backslash itself) becomes an escape, which makes
/// the encoding exactly reversible for any input.
fn encode_unicode_escapes(text: &str, style: &str) -> OpResult<String> {
    let mut out = String::with_capacity(text.len() * 2);
    for c in text.chars() {
        let cp = c as u32;
        if (0x20..=0x7E).contains(&cp) && c != '\\' {
            out.push(c);
            continue;
        }
        match style {
            "braced" => {
                out.push_str(&format!("\\u{{{cp:x}}}"));
            }
            "x" => {
                let mut buf = [0u8; 4];
                for b in c.encode_utf8(&mut buf).as_bytes() {
                    out.push_str(&format!("\\x{b:02x}"));
                }
            }
            "uXXXX" => {
                if cp <= 0xFFFF {
                    out.push_str(&format!("\\u{cp:04x}"));
                } else {
                    // Astral plane: a UTF-16 surrogate pair.
                    let v = cp - 0x10000;
                    let high = 0xD800 + (v >> 10);
                    let low = 0xDC00 + (v & 0x3FF);
                    out.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
                }
            }
            other => {
                return Err(OperationError::invalid_param(
                    "escape_style",
                    format!("unknown escape style `{other}`"),
                )
                .with_expected("uXXXX, braced or x")
                .with_actual(other));
            }
        }
    }
    Ok(out)
}

fn from_unicode_escapes_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From Unicode Escapes")?;
    check_budget(text.len(), "Unicode escapes decode")?;
    let strict = map.bool_or("strict", true);
    let bytes = decode_unicode_escapes(text, strict)?;
    Ok(Value::from_bytes(bytes))
}

fn to_unicode_escapes_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Unicode Escapes")?;
    let text = std::str::from_utf8(bytes.as_ref()).map_err(|_| {
        OperationError::invalid_input("`To Unicode Escapes` input must be valid UTF-8 text")
            .with_actual("non-UTF-8 bytes")
    })?;
    let style = map.str_or("escape_style", "uXXXX");
    Ok(Value::Text(encode_unicode_escapes(text, style)?))
}

// ========================================================= HTML entities ====

/// Named entities decoded without guessing. The table covers the HTML4
/// Latin-1 / symbol / arrow sets that appear in CTF payloads; anything
/// outside it is left verbatim (documented behaviour, never guessed).
const NAMED_ENTITIES: &[(&str, &str)] = &[
    ("amp", "&"),
    ("lt", "<"),
    ("gt", ">"),
    ("quot", "\""),
    ("apos", "'"),
    ("nbsp", "\u{a0}"),
    ("iexcl", "\u{a1}"),
    ("cent", "\u{a2}"),
    ("pound", "\u{a3}"),
    ("curren", "\u{a4}"),
    ("yen", "\u{a5}"),
    ("brvbar", "\u{a6}"),
    ("sect", "\u{a7}"),
    ("uml", "\u{a8}"),
    ("copy", "\u{a9}"),
    ("ordf", "\u{aa}"),
    ("laquo", "\u{ab}"),
    ("not", "\u{ac}"),
    ("shy", "\u{ad}"),
    ("reg", "\u{ae}"),
    ("macr", "\u{af}"),
    ("deg", "\u{b0}"),
    ("plusmn", "\u{b1}"),
    ("sup2", "\u{b2}"),
    ("sup3", "\u{b3}"),
    ("acute", "\u{b4}"),
    ("micro", "\u{b5}"),
    ("para", "\u{b6}"),
    ("middot", "\u{b7}"),
    ("cedil", "\u{b8}"),
    ("sup1", "\u{b9}"),
    ("ordm", "\u{ba}"),
    ("raquo", "\u{bb}"),
    ("frac14", "\u{bc}"),
    ("frac12", "\u{bd}"),
    ("frac34", "\u{be}"),
    ("iquest", "\u{bf}"),
    ("times", "\u{d7}"),
    ("divide", "\u{f7}"),
    ("fnof", "\u{192}"),
    ("circ", "\u{2c6}"),
    ("tilde", "\u{2dc}"),
    ("ndash", "\u{2013}"),
    ("mdash", "\u{2014}"),
    ("lsquo", "\u{2018}"),
    ("rsquo", "\u{2019}"),
    ("sbquo", "\u{201a}"),
    ("ldquo", "\u{201c}"),
    ("rdquo", "\u{201d}"),
    ("bdquo", "\u{201e}"),
    ("dagger", "\u{2020}"),
    ("Dagger", "\u{2021}"),
    ("bull", "\u{2022}"),
    ("hellip", "\u{2026}"),
    ("permil", "\u{2030}"),
    ("prime", "\u{2032}"),
    ("Prime", "\u{2033}"),
    ("lsaquo", "\u{2039}"),
    ("rsaquo", "\u{203a}"),
    ("oline", "\u{203e}"),
    ("euro", "\u{20ac}"),
    ("trade", "\u{2122}"),
    ("larr", "\u{2190}"),
    ("uarr", "\u{2191}"),
    ("rarr", "\u{2192}"),
    ("darr", "\u{2193}"),
    ("harr", "\u{2194}"),
    ("minus", "\u{2212}"),
    ("lowast", "\u{2217}"),
    ("radic", "\u{221a}"),
    ("infin", "\u{221e}"),
    ("cap", "\u{2229}"),
    ("cup", "\u{222a}"),
    ("int", "\u{222b}"),
    ("there4", "\u{2234}"),
    ("sim", "\u{223c}"),
    ("cong", "\u{2245}"),
    ("asymp", "\u{2248}"),
    ("ne", "\u{2260}"),
    ("equiv", "\u{2261}"),
    ("le", "\u{2264}"),
    ("ge", "\u{2265}"),
    ("sub", "\u{2282}"),
    ("sup", "\u{2283}"),
    ("nsub", "\u{2284}"),
    ("sube", "\u{2286}"),
    ("supe", "\u{2287}"),
    ("oplus", "\u{2295}"),
    ("otimes", "\u{2297}"),
    ("perp", "\u{22a5}"),
    ("sdot", "\u{22c5}"),
    ("lceil", "\u{2308}"),
    ("rceil", "\u{2309}"),
    ("lfloor", "\u{230a}"),
    ("rfloor", "\u{230b}"),
    ("lang", "\u{2329}"),
    ("rang", "\u{232a}"),
    ("loz", "\u{25ca}"),
    ("spades", "\u{2660}"),
    ("clubs", "\u{2663}"),
    ("hearts", "\u{2665}"),
    ("diams", "\u{2666}"),
    ("alpha", "\u{3b1}"),
    ("beta", "\u{3b2}"),
    ("gamma", "\u{3b3}"),
    ("delta", "\u{3b4}"),
    ("epsilon", "\u{3b5}"),
    ("zeta", "\u{3b6}"),
    ("eta", "\u{3b7}"),
    ("theta", "\u{3b8}"),
    ("iota", "\u{3b9}"),
    ("kappa", "\u{3ba}"),
    ("lambda", "\u{3bb}"),
    ("mu", "\u{3bc}"),
    ("nu", "\u{3bd}"),
    ("xi", "\u{3be}"),
    ("omicron", "\u{3bf}"),
    ("pi", "\u{3c0}"),
    ("rho", "\u{3c1}"),
    ("sigma", "\u{3c3}"),
    ("tau", "\u{3c4}"),
    ("upsilon", "\u{3c5}"),
    ("phi", "\u{3c6}"),
    ("chi", "\u{3c7}"),
    ("psi", "\u{3c8}"),
    ("omega", "\u{3c9}"),
    ("Alpha", "\u{391}"),
    ("Beta", "\u{392}"),
    ("Gamma", "\u{393}"),
    ("Delta", "\u{394}"),
    ("Theta", "\u{398}"),
    ("Lambda", "\u{39b}"),
    ("Pi", "\u{3a0}"),
    ("Sigma", "\u{3a3}"),
    ("Phi", "\u{3a6}"),
    ("Psi", "\u{3a8}"),
    ("Omega", "\u{3a9}"),
];

/// One parsed entity: either a scalar value (numeric references) or a
/// replacement string (named references).
enum Entity {
    Scalar(u32),
    Replacement(&'static str),
}

/// Parse one entity reference starting right after the `&` (the `;` is
/// still ahead). Returns the entity and the number of bytes consumed
/// including the `;`, or `None` when the syntax is malformed or the name is
/// unknown.
fn parse_entity(rest: &[u8]) -> Option<(Entity, usize)> {
    if rest.is_empty() {
        return None;
    }
    if rest[0] == b'#' {
        // Numeric: &#NNN; or &#xHH; / &#XHH;
        let (digits, start): (&[u8], usize) = if rest.len() > 1 && (rest[1] | 0x20) == b'x' {
            (&rest[2..], 2)
        } else {
            (&rest[1..], 1)
        };
        let end = digits
            .iter()
            .position(|b| !b.is_ascii_hexdigit())
            .unwrap_or(digits.len());
        if end == 0 || end > 7 || digits.get(end) != Some(&b';') {
            return None;
        }
        let radix = if start == 2 { 16 } else { 10 };
        let text = std::str::from_utf8(&digits[..end]).ok()?;
        let value = u32::from_str_radix(text, radix).ok()?;
        return Some((Entity::Scalar(value), start + end + 1));
    }
    // Named: ASCII alphanumerics, 2-10 characters, then `;`.
    let end = rest
        .iter()
        .position(|b| !b.is_ascii_alphanumeric())
        .unwrap_or(rest.len());
    if !(2..=10).contains(&end) || rest.get(end) != Some(&b';') {
        return None;
    }
    let name = std::str::from_utf8(&rest[..end]).ok()?;
    NAMED_ENTITIES
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, replacement)| (Entity::Replacement(replacement), end + 1))
}

/// Decode HTML character references. Strict mode fails on malformed `&`
/// syntax (dangling ampersands, truncated numerics, out-of-range code
/// points); unknown *named* entities are never guessed and stay verbatim in
/// both modes. Relaxed mode keeps malformed constructs verbatim.
pub fn decode_html_entities(text: &str, strict: bool) -> OpResult<String> {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'&' {
            let c = text[i..].chars().next().expect("index on char boundary");
            out.push(c);
            i += c.len_utf8();
            continue;
        }
        // An unknown *named* reference (well-formed `&name;` not in the
        // table) stays verbatim in both modes; only malformed syntax and
        // non-scalar numerics are strict errors.
        let well_formed_named = {
            let rest = &bytes[i + 1..];
            let end = rest
                .iter()
                .position(|b| !b.is_ascii_alphanumeric())
                .unwrap_or(rest.len());
            (2..=10).contains(&end) && rest.get(end) == Some(&b';')
        };
        match parse_entity(&bytes[i + 1..]) {
            Some((Entity::Scalar(cp), consumed)) => {
                match char::from_u32(cp) {
                    Some(c) => out.push(c),
                    None if strict => {
                        return Err(OperationError::decode(format!(
                            "numeric HTML reference &#{cp}; is not a scalar value"
                        ))
                        .with_expected("U+0000..U+10FFFF excluding surrogates")
                        .with_actual(format!("U+{cp:04X}")));
                    }
                    None => {
                        // Relaxed: keep the reference verbatim. Advance past
                        // the '&' only — a real hang existed here (i was not
                        // advanced, so non-scalar references looped forever).
                        out.push('&');
                        i += 1;
                    }
                }
                i += 1 + consumed;
            }
            Some((Entity::Replacement(s), consumed)) => {
                out.push_str(s);
                i += 1 + consumed;
            }
            None if strict && !well_formed_named => {
                let peek: String = text[i..].chars().take(12).collect();
                return Err(
                    OperationError::decode("malformed HTML entity reference at `&`")
                        .with_expected("&name; &#NNN; or &#xHH;")
                        .with_actual(format!("`{peek}`")),
                );
            }
            None => {
                out.push('&');
                i += 1;
            }
        }
    }
    Ok(out)
}

/// Escape text as HTML: the five markup-significant characters become named
/// references, everything non-ASCII becomes a hex numeric reference.
fn encode_html_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if (c as u32) < 0x80 => out.push(c),
            c => out.push_str(&format!("&#x{:x};", c as u32)),
        }
    }
    out
}

fn from_html_entities_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From HTML Entities")?;
    check_budget(text.len(), "HTML entity decode")?;
    let strict = map.bool_or("strict", true);
    Ok(Value::Text(decode_html_entities(text, strict)?))
}

fn to_html_entities_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To HTML Entities")?;
    let text = std::str::from_utf8(bytes.as_ref()).map_err(|_| {
        OperationError::invalid_input("`To HTML Entities` input must be valid UTF-8 text")
            .with_actual("non-UTF-8 bytes")
    })?;
    Ok(Value::Text(encode_html_entities(text)))
}

// ====================================================== Quoted-printable ====

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode quoted-printable (RFC 2045 §6.7): `=XX` hex escapes and soft line
/// breaks `=\r\n` / `=\n`. Strict mode rejects any `=` that does not start
/// a valid escape; relaxed mode keeps it verbatim.
pub fn decode_quoted_printable(bytes: &[u8], strict: bool) -> OpResult<Vec<u8>> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b != b'=' {
            out.push(b);
            i += 1;
            continue;
        }
        // Soft line breaks.
        if bytes.get(i + 1) == Some(&b'\r') && bytes.get(i + 2) == Some(&b'\n') {
            i += 3;
            continue;
        }
        if bytes.get(i + 1) == Some(&b'\n') {
            i += 2;
            continue;
        }
        match (bytes.get(i + 1).copied(), bytes.get(i + 2).copied()) {
            (Some(h1), Some(h2)) if hex_val(h1).is_some() && hex_val(h2).is_some() => {
                let value = (hex_val(h1).unwrap() << 4) | hex_val(h2).unwrap();
                out.push(value);
                i += 3;
            }
            _ => {
                if strict {
                    return Err(OperationError::decode(
                        "malformed quoted-printable escape: `=` must be followed by two hex digits or a soft line break",
                    )
                    .with_expected("=XX, =\\r\\n or =\\n")
                    .with_actual(format!(
                        "offset {i}: `=` followed by {:?}",
                        bytes.get(i + 1).map(|b| *b as char)
                    )));
                }
                out.push(b'=');
                i += 1;
            }
        }
    }
    Ok(out)
}

/// Encode quoted-printable per RFC 2045 §6.7: printable ASCII except `=`
/// passes through, space/tab are kept except at line end, lines are limited
/// to 76 characters with soft breaks, and `\n` becomes a hard break.
fn encode_quoted_printable(bytes: &[u8]) -> String {
    const LINE_MAX: usize = 76;
    let mut out = String::with_capacity(bytes.len() * 4 / 3 + 8);
    let mut line_len = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\n' {
            // Hard break: a raw space/tab immediately before the break must
            // be re-emitted encoded (RFC 2045 rule 3).
            let trailing = out.len() - out.trim_end_matches([' ', '\t']).len();
            if trailing > 0 {
                out.truncate(out.len() - trailing);
                line_len -= trailing;
                for &t in &bytes[i - trailing..i] {
                    if line_len + 3 > LINE_MAX {
                        out.push_str("=\r
");
                        line_len = 0;
                    }
                    out.push_str(&format!("={t:02X}"));
                    line_len += 3;
                }
            }
            out.push('\n');
            line_len = 0;
            i += 1;
            continue;
        }
        let must_encode = !(0x20..=0x7E).contains(&b) || b == b'=';
        // A space/tab that would end the line raw must be encoded eagerly.
        let at_risk_eol = (b == b' ' || b == b'\t')
            && (i + 1 == bytes.len() || bytes[i + 1] == b'\n' || bytes[i + 1] == b'\r');
        let token = if must_encode || at_risk_eol {
            format!("={b:02X}")
        } else {
            (b as char).to_string()
        };
        if line_len + token.len() > LINE_MAX {
            out.push_str("=\r\n");
            line_len = 0;
        }
        out.push_str(&token);
        line_len += token.len();
        i += 1;
    }
    let _ = line_len;
    out
}

fn from_quoted_printable_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "From Quoted Printable")?;
    check_budget(bytes.len(), "quoted-printable decode")?;
    let strict = map.bool_or("strict", true);
    Ok(Value::from_bytes(decode_quoted_printable(
        bytes.as_ref(),
        strict,
    )?))
}

fn to_quoted_printable_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Quoted Printable")?;
    check_budget(bytes.len(), "quoted-printable encode")?;
    Ok(Value::Text(encode_quoted_printable(bytes.as_ref())))
}

// ============================================================== Punycode ====

const PUNY_BASE: u32 = 36;
const PUNY_TMIN: u32 = 1;
const PUNY_TMAX: u32 = 26;
const PUNY_SKEW: u32 = 38;
const PUNY_DAMP: u32 = 700;
const PUNY_INITIAL_BIAS: u32 = 72;
const PUNY_INITIAL_N: u32 = 0x80;

fn puny_adapt(mut delta: u32, num_points: u32, first_time: bool) -> u32 {
    delta = if first_time {
        delta / PUNY_DAMP
    } else {
        delta / 2
    };
    delta += delta / num_points;
    let mut k = 0;
    while delta > ((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) / 2 {
        delta /= PUNY_BASE - PUNY_TMIN;
        k += PUNY_BASE;
    }
    k + (((PUNY_BASE - PUNY_TMIN + 1) * delta) / (delta + PUNY_SKEW))
}

/// RFC 3492 digit decode: letters map to values 0-25 (the case carries the
/// mixed-case annotation flag), digits to 26-35.
fn puny_digit(c: char) -> Option<(u32, bool)> {
    match c {
        'a'..='z' => Some((c as u32 - 'a' as u32, false)),
        'A'..='Z' => Some((c as u32 - 'A' as u32, true)),
        '0'..='9' => Some((c as u32 - '0' as u32 + 26, false)),
        _ => None,
    }
}

/// RFC 3492 digit encode with the mixed-case annotation.
fn puny_encode_digit(digit: u32, flag: bool) -> char {
    if digit < 26 {
        let base = b'a' as u32 + digit;
        char::from_u32(if flag { base - 0x20 } else { base }).expect("ascii letter")
    } else {
        char::from_u32(b'0' as u32 + digit - 26).expect("ascii digit")
    }
}

/// Decode one RFC 3492 label body (no `xn--` prefix) with overflow checks
/// and case restoration. Returns the decoded text and its per-code-point
/// case flags.
fn punycode_decode_body(body: &str) -> OpResult<(Vec<char>, Vec<bool>)> {
    if body.chars().count() > PUNYCODE_MAX_LABEL {
        return Err(OperationError::new(
            ErrorKind::BudgetExceeded,
            format!(
                "punycode label of {} characters exceeds the {PUNYCODE_MAX_LABEL} label limit",
                body.chars().count()
            ),
        )
        .with_expected(format!("at most {PUNYCODE_MAX_LABEL} characters"))
        .with_actual(format!("{} characters", body.chars().count())));
    }
    let chars: Vec<char> = body.chars().collect();
    let mut output: Vec<char> = Vec::new();
    let mut flags: Vec<bool> = Vec::new();
    let mut extended_start = 0usize;
    if let Some(pos) = chars.iter().rposition(|&c| c == '-') {
        for &c in &chars[..pos] {
            if c as u32 >= 0x80 {
                return Err(OperationError::decode(
                    "non-basic code point in the punycode basic section",
                )
                .with_expected("ASCII basic code points before the last `-`")
                .with_actual(format!("U+{:04X}", c as u32)));
            }
            output.push(c);
            flags.push(c.is_ascii_uppercase());
        }
        extended_start = pos + 1;
    }

    let mut n: u32 = PUNY_INITIAL_N;
    let mut i: u32 = 0;
    let mut bias: u32 = PUNY_INITIAL_BIAS;
    let mut first_time = true;
    let mut idx = extended_start;
    while idx < chars.len() {
        let old_i = i;
        let mut w: u32 = 1;
        let mut k = PUNY_BASE;
        // Every loop iteration assigns the flag before it is read, so the
        // initial value is never observed.
        #[allow(unused_assignments)]
        let mut last_flag = false;
        loop {
            let Some(&c) = chars.get(idx) else {
                return Err(OperationError::decode(
                    "truncated punycode: the digit sequence ends mid-number",
                )
                .with_expected("a complete digit sequence")
                .with_actual("input exhausted"));
            };
            let Some((digit, flag)) = puny_digit(c) else {
                return Err(
                    OperationError::decode(format!("invalid punycode digit `{c}`"))
                        .with_expected("a-z, A-Z or 0-9")
                        .with_actual(format!("`{c}`")),
                );
            };
            idx += 1;
            last_flag = flag;
            let prod = digit.checked_mul(w).ok_or_else(|| {
                OperationError::decode("punycode decode overflow")
                    .with_expected("a representable delta")
                    .with_actual("digit * weight overflow")
            })?;
            i = i.checked_add(prod).ok_or_else(|| {
                OperationError::decode("punycode decode overflow")
                    .with_expected("a representable delta")
                    .with_actual("delta overflow")
            })?;
            let t = if k <= bias {
                PUNY_TMIN
            } else if k >= bias + PUNY_TMAX {
                PUNY_TMAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            w = w.checked_mul(PUNY_BASE - t).ok_or_else(|| {
                OperationError::decode("punycode decode overflow")
                    .with_expected("a representable weight")
                    .with_actual("weight overflow")
            })?;
            k += PUNY_BASE;
        }
        let out_len = output.len() as u32 + 1;
        let delta = i - old_i;
        bias = puny_adapt(delta, out_len, first_time);
        first_time = false;
        n = n.checked_add(i / out_len).ok_or_else(|| {
            OperationError::decode("punycode decode overflow")
                .with_expected("a code point below U+10FFFF")
                .with_actual("n overflow")
        })?;
        i %= out_len;
        if n > 0x10FFFF || (0xD800..=0xDFFF).contains(&n) {
            return Err(OperationError::decode(format!(
                "punycode decoded code point U+{n:X} is not a scalar value"
            ))
            .with_expected("U+0000..U+10FFFF excluding surrogates")
            .with_actual(format!("U+{n:X}")));
        }
        let c = char::from_u32(n).expect("checked above");
        output.insert(i as usize, c);
        flags.insert(i as usize, last_flag);
        i += 1;
    }
    Ok((output, flags))
}

/// Decode an ACE label into text, applying the recorded case flags.
fn punycode_label_to_text(body: &str) -> OpResult<String> {
    let (output, flags) = punycode_decode_body(body)?;
    let mut out = String::with_capacity(output.len());
    for (c, flag) in output.iter().zip(flags.iter()) {
        if *flag {
            out.extend(c.to_uppercase());
        } else {
            out.push(*c);
        }
    }
    Ok(out)
}

/// Encode one label body per RFC 3492 (no `xn--` prefix), preserving case
/// through the mixed-case annotation.
pub fn punycode_encode_body(text: &str) -> OpResult<String> {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() > PUNYCODE_MAX_LABEL {
        return Err(OperationError::new(
            ErrorKind::BudgetExceeded,
            format!(
                "punycode label of {} characters exceeds the {PUNYCODE_MAX_LABEL} label limit",
                chars.len()
            ),
        )
        .with_expected(format!("at most {PUNYCODE_MAX_LABEL} characters"))
        .with_actual(format!("{} characters", chars.len())));
    }
    let mut output = String::new();
    // (numeric value used for the delta arithmetic, case flag)
    let mut values: Vec<(u32, bool)> = Vec::new();
    for &c in &chars {
        let cp = c as u32;
        if cp < 0x80 {
            output.push(c);
        } else {
            let flag = c.is_uppercase();
            let value = if flag {
                c.to_lowercase().next().map(|l| l as u32).unwrap_or(cp)
            } else {
                cp
            };
            values.push((value, flag));
        }
    }
    let basic_len = output.chars().count() as u32;
    if !output.is_empty() {
        output.push('-');
    }

    let mut n: u32 = PUNY_INITIAL_N;
    let mut delta: u32 = 0;
    // RFC 3492: the first adapt call is the dampening pass and does not read
    // the incoming bias, so the initial value here is never observed.
    #[allow(unused_assignments)]
    let mut bias: u32 = PUNY_INITIAL_BIAS;
    let mut first_time = true;
    let mut handled = basic_len;
    let total = chars.len() as u32;
    while handled < total {
        // The smallest non-basic value >= n. handled < total implies at
        // least one value remains un-emitted, and un-emitted values are
        // always >= n, so this cannot fail.
        let Some(m) = values.iter().map(|&(v, _)| v).filter(|&v| v >= n).min() else {
            return Err(OperationError::internal(
                "punycode encode invariant violated: no remaining value",
            ));
        };
        let step = (m - n)
            .checked_mul(handled + 1)
            .ok_or_else(|| OperationError::decode("punycode encode overflow"))?;
        delta = delta
            .checked_add(step)
            .ok_or_else(|| OperationError::decode("punycode encode overflow"))?;
        n = m;
        for &(value, flag) in &values {
            if value < n {
                delta = delta
                    .checked_add(1)
                    .ok_or_else(|| OperationError::decode("punycode encode overflow"))?;
            } else if value == n {
                bias = puny_adapt(delta, handled + 1, first_time);
                first_time = false;
                // Emit delta as digits; the last digit carries the case flag.
                let mut q = delta;
                let mut k = PUNY_BASE;
                loop {
                    let t = if k <= bias {
                        PUNY_TMIN
                    } else if k >= bias + PUNY_TMAX {
                        PUNY_TMAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    let digit = t + ((q - t) % (PUNY_BASE - t));
                    output.push(puny_encode_digit(digit, false));
                    q = (q - t) / (PUNY_BASE - t);
                    k += PUNY_BASE;
                }
                output.push(puny_encode_digit(q, flag));
                delta = 0;
                handled += 1;
            }
        }
        // RFC 3492 main-encode step: scale the accumulator after each full
        // sweep over the input (missing here, which produced wrong labels).
        delta = delta
            .checked_mul(handled + 1)
            .ok_or_else(|| OperationError::decode("punycode encode overflow"))?;
        n += 1;
    }
    Ok(output)
}

/// Decode ACE labels: every `xn--`-prefixed dot-separated label is decoded,
/// other labels pass through. Strict mode fails when a prefixed label is
/// malformed; relaxed mode keeps it verbatim.
pub fn punycode_decode_labels(text: &str, strict: bool) -> OpResult<String> {
    let mut labels: Vec<String> = Vec::new();
    for label in text.split('.') {
        let is_ace = label.len() >= 4 && label[..4].eq_ignore_ascii_case("xn--");
        if is_ace {
            let body = &label[4..];
            if body.is_empty() {
                if strict {
                    return Err(OperationError::decode(
                        "ACE label `xn--` has an empty punycode body",
                    )
                    .with_expected("xn--<punycode>")
                    .with_actual(label.to_string()));
                }
                labels.push(label.to_string());
                continue;
            }
            match punycode_label_to_text(body) {
                Ok(decoded) => labels.push(decoded),
                Err(e) => {
                    if strict {
                        return Err(e.with_actual(label.to_string()));
                    }
                    labels.push(label.to_string());
                }
            }
        } else {
            labels.push(label.to_string());
        }
    }
    Ok(labels.join("."))
}

/// Encode labels: every label containing non-ASCII becomes an `xn--` ACE
/// label, ASCII labels pass through.
fn punycode_encode_labels(text: &str) -> OpResult<String> {
    let mut labels: Vec<String> = Vec::new();
    for label in text.split('.') {
        if label.is_ascii() {
            labels.push(label.to_string());
        } else {
            let body = punycode_encode_body(label)?;
            labels.push(format!("xn--{body}"));
        }
    }
    Ok(labels.join("."))
}

fn from_punycode_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From Punycode")?;
    check_budget(text.len(), "punycode decode")?;
    let strict = map.bool_or("strict", true);
    Ok(Value::Text(punycode_decode_labels(text, strict)?))
}

fn to_punycode_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Punycode")?;
    let text = std::str::from_utf8(bytes.as_ref()).map_err(|_| {
        OperationError::invalid_input("`To Punycode` input must be valid UTF-8 text")
            .with_actual("non-UTF-8 bytes")
    })?;
    check_budget(text.len(), "punycode encode")?;
    Ok(Value::Text(punycode_encode_labels(text)?))
}

// ======================================================== uuencode / xxencode

/// Classic uuencode table: value = char - 0x20 (0x20..=0x5F). The backtick
/// (0x60) is accepted as a value-0 padding character (some encoders pad the
/// final group with it); it can never appear inside a real data group.
fn uu_value(c: u8) -> Option<u8> {
    if (0x20..=0x5F).contains(&c) {
        Some(c - 0x20)
    } else if c == 0x60 {
        Some(0)
    } else {
        None
    }
}

/// Classic xxencode table ("+-0-9A-Za-z").
const XX_ALPHABET: &[u8; 64] = b"+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn xx_value(c: u8) -> Option<u8> {
    XX_ALPHABET.iter().position(|&a| a == c).map(|p| p as u8)
}

/// Locate the shared `begin <mode> <name>` / `end` envelope and return the
/// data lines. Strict mode requires the envelope, an octal mode, and the
/// `end` line; relaxed mode also decodes envelope-less streams.
fn find_envelope(text: &str, strict: bool, what: &str) -> OpResult<Vec<String>> {
    let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
    let first = lines.iter().position(|l| !l.is_empty());
    let last = lines.iter().rposition(|l| !l.is_empty());
    let (Some(first), Some(last)) = (first, last) else {
        return Err(
            OperationError::decode(format!("{what} input contains no data"))
                .with_expected("a `begin <mode> <name>` ... `end` envelope"),
        );
    };
    let begin = lines[first];
    if !begin.starts_with("begin ") {
        if strict {
            return Err(OperationError::decode(format!(
                "{what} stream must start with a `begin <mode> <name>` line"
            ))
            .with_expected("begin <mode> <name>")
            .with_actual(format!("`{}`", begin.chars().take(20).collect::<String>())));
        }
        // Envelope-less relaxed mode: every non-empty line is data, except a
        // trailing `end` line if one happens to be present.
        let data_end = if lines[last].trim().eq_ignore_ascii_case("end") {
            last
        } else {
            last + 1
        };
        return Ok(lines[first..data_end]
            .iter()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect());
    }
    let mode_and_name = &begin[6..];
    if strict {
        let valid_mode = mode_and_name
            .as_bytes()
            .get(..3)
            .is_some_and(|m| m.iter().all(|b| (b'0'..=b'7').contains(b)))
            && mode_and_name.as_bytes().get(3) == Some(&b' ');
        if !valid_mode {
            return Err(OperationError::decode(format!(
                "{what} begin line must be `begin <octal mode> <name>`"
            ))
            .with_expected("three octal digits after `begin `")
            .with_actual(format!(
                "`{}`",
                mode_and_name.chars().take(8).collect::<String>()
            )));
        }
    }
    let end_present = last > first && lines[last].trim().eq_ignore_ascii_case("end");
    if strict && !end_present {
        return Err(
            OperationError::decode(format!("{what} stream is missing the `end` line"))
                .with_expected("an `end` line after the data")
                .with_actual(format!(
                    "`{}`",
                    lines[last].chars().take(20).collect::<String>()
                )),
        );
    }
    // Data lines run between the begin line and the end line (or, in relaxed
    // mode with a missing end line, through the last non-empty line).
    let data_end = if end_present { last } else { last + 1 };
    Ok(lines[first + 1..data_end]
        .iter()
        .filter(|l| !l.trim().eq_ignore_ascii_case("end"))
        .map(|l| l.to_string())
        .collect())
}

/// Decode the classic base64-style 6-bit groups (uuencode/xxencode share the
/// layout; they differ only in the value table and length characters).
fn decode_uu_lines(
    data_lines: &[String],
    value: fn(u8) -> Option<u8>,
    strict: bool,
    what: &str,
) -> OpResult<Vec<u8>> {
    let mut out = Vec::new();
    for (lidx, line) in data_lines.iter().enumerate() {
        let bytes = line.as_bytes();
        // Terminator: a lone `` ` ``, a lone space, or an empty line.
        if bytes == b"`" || bytes == b" " || bytes.is_empty() {
            continue;
        }
        let len_char = bytes[0];
        let n = match value(len_char) {
            Some(v) => v as usize,
            None => {
                if strict {
                    return Err(OperationError::decode(format!(
                        "{what} line {} has an invalid length character",
                        lidx + 1
                    ))
                    .with_expected("a length character within the table")
                    .with_actual(format!("`{}`", len_char as char)));
                }
                continue;
            }
        };
        if n == 0 {
            // Zero-length data line: end of data.
            break;
        }
        let body = &bytes[1..];
        let expected = 4 * n.div_ceil(3);
        if strict && body.len() != expected {
            return Err(OperationError::decode(format!(
                "{what} line {} has a wrong body length: {} characters for {n} data bytes",
                lidx + 1,
                body.len()
            ))
            .with_expected(format!("exactly {expected} body characters"))
            .with_actual(format!("{} characters", body.len())));
        }
        if body.len() < expected {
            if strict {
                return Err(OperationError::decode(format!(
                    "{what} line {} is truncated: {} body characters for {n} data bytes",
                    lidx + 1,
                    body.len()
                ))
                .with_expected(format!("at least {expected} body characters"))
                .with_actual(format!("{} characters", body.len())));
            }
            continue;
        }
        let body = &body[..expected];
        let mut vals = [0u8; 4];
        // The data-byte budget is PER LINE: the previous computation mixed the
        // global output length in, which underflowed on the second line and
        // pushed garbage for every padding group of a multi-line stream.
        let mut line_produced = 0usize;
        for chunk in body.chunks(4) {
            let produced = (n - line_produced).min(3);
            line_produced += produced;
            for (slot, &c) in chunk.iter().enumerate() {
                match value(c) {
                    Some(v) => vals[slot] = v,
                    None => {
                        if strict {
                            return Err(OperationError::decode(format!(
                                "{what} line {} contains a character outside the table: `{}`",
                                lidx + 1,
                                c as char
                            ))
                            .with_expected("characters within the table")
                            .with_actual(format!("`{}`", c as char)));
                        }
                        vals[slot] = 0;
                    }
                }
            }
            out.push((vals[0] << 2) | (vals[1] >> 4));
            if produced > 1 {
                out.push(((vals[1] & 0xF) << 4) | (vals[2] >> 2));
            }
            if produced > 2 {
                out.push(((vals[2] & 0x3) << 6) | vals[3]);
            }
        }
    }
    Ok(out)
}

/// Encode bytes with the given 6-bit table and length-character mapping.
fn encode_uu_lines(data: &[u8], table: &dyn Fn(u8) -> u8, len_char: &dyn Fn(u8) -> u8) -> String {
    let mut out = String::new();
    if data.is_empty() {
        // Classic uu/xx encoders emit a zero-length data line for empty
        // input; the decoder treats length 0 as end-of-data.
        out.push(len_char(0) as char);
        out.push('\n');
        return out;
    }
    for chunk in data.chunks(45) {
        out.push(len_char(chunk.len() as u8) as char);
        for group in chunk.chunks(3) {
            let b = [
                group[0],
                *group.get(1).unwrap_or(&0),
                *group.get(2).unwrap_or(&0),
            ];
            let v = [
                b[0] >> 2,
                ((b[0] & 0x3) << 4) | (b[1] >> 4),
                ((b[1] & 0xF) << 2) | (b[2] >> 6),
                b[2] & 0x3F,
            ];
            for value in v {
                out.push(table(value) as char);
            }
        }
        out.push('\n');
    }
    out
}

fn decode_uu_op(
    v: &Value,
    map: &ParamMap,
    what: &'static str,
    value: fn(u8) -> Option<u8>,
) -> OpResult<Value> {
    let bytes = input_bytes(v, what)?;
    check_budget(bytes.len(), what)?;
    let text = std::str::from_utf8(bytes.as_ref()).map_err(|_| {
        OperationError::invalid_input(format!("`{what}` input must be ASCII/UTF-8 envelope text"))
            .with_actual("non-UTF-8 bytes")
    })?;
    let strict = map.bool_or("strict", true);
    let data_lines = find_envelope(text, strict, what)?;
    let decoded = decode_uu_lines(&data_lines, value, strict, what)?;
    // Byte-oriented decoder: the result stays Bytes even when it happens to
    // be valid UTF-8 (the spec declares a Bytes output).
    Ok(Value::Bytes(decoded))
}

fn from_uuencode_op(v: &Value, map: &ParamMap, _ctx: &ExecutionContext) -> OpResult<Value> {
    decode_uu_op(v, map, "From Uuencode", uu_value)
}

fn from_xxencode_op(v: &Value, map: &ParamMap, _ctx: &ExecutionContext) -> OpResult<Value> {
    decode_uu_op(v, map, "From Xxencode", xx_value)
}

fn to_uuencode_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Uuencode")?;
    check_budget(bytes.len(), "uuencode encode")?;
    let mut out = String::from("begin 644 file.bin\n");
    out.push_str(&encode_uu_lines(
        bytes.as_ref(),
        &|v| (0x20u32 + v as u32) as u8,
        &|n| (0x20u32 + n as u32) as u8,
    ));
    if !bytes.is_empty() {
        out.push_str("`\n");
    }
    out.push_str("end\n");
    Ok(Value::Text(out))
}

fn to_xxencode_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Xxencode")?;
    check_budget(bytes.len(), "xxencode encode")?;
    let mut out = String::from("begin 644 file.bin\n");
    out.push_str(&encode_uu_lines(
        bytes.as_ref(),
        &|v| XX_ALPHABET[v as usize],
        &|n| XX_ALPHABET[(n & 0x3F) as usize],
    ));
    if !bytes.is_empty() {
        out.push_str("+\n");
    }
    out.push_str("end\n");
    Ok(Value::Text(out))
}

// ================================================================== yEnc ====

/// yEnc control lines start with `=ybegin`, `=ypart` or `=yend`.
fn yenc_control(line: &[u8]) -> bool {
    line.starts_with(b"=ybegin") || line.starts_with(b"=ypart") || line.starts_with(b"=yend")
}

/// Extract `key=value` parameters from a yEnc control line.
fn yenc_params(line: &[u8]) -> Vec<(&str, u64)> {
    let Ok(text) = std::str::from_utf8(line) else {
        return Vec::new();
    };
    text.split_whitespace()
        .skip(1)
        .filter_map(|token| token.split_once('='))
        .filter_map(|(key, value)| value.parse::<u64>().ok().map(|v| (key, v)))
        .collect()
}

/// Split into lines on `\n`, trimming a trailing `\r`.
fn yenc_lines(bytes: &[u8]) -> Vec<&[u8]> {
    bytes
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .collect()
}

/// Decode yEnc. Strict mode requires the `=ybegin`/`=yend` envelope with a
/// declared size matching the decoded length, and only valid escaped bytes
/// (`=@ =J =M =}`); relaxed mode also decodes envelope-less data. Line
/// breaks are never part of the data.
pub fn decode_yenc(bytes: &[u8], strict: bool) -> OpResult<Vec<u8>> {
    let lines = yenc_lines(bytes);
    let first = lines.iter().position(|l| !l.is_empty());
    let has_envelope = first
        .map(|i| lines[i].starts_with(b"=ybegin"))
        .unwrap_or(false);

    let mut declared_size: Option<u64> = None;
    let data_lines: &[&[u8]] = if has_envelope {
        let header = lines[first.unwrap()];
        declared_size = yenc_params(header)
            .into_iter()
            .find(|(key, _)| *key == "size")
            .map(|(_, v)| v);
        if strict && declared_size.is_none() {
            return Err(OperationError::decode(
                "yEnc =ybegin header is missing the size= parameter",
            )
            .with_expected("size=<n> in the =ybegin line")
            .with_actual(format!(
                "`{}`",
                String::from_utf8_lossy(&header[..header.len().min(60)])
            )));
        }
        let trailer = match lines.iter().rposition(|l| l.starts_with(b"=yend")) {
            Some(t) => t,
            None if strict => {
                return Err(
                    OperationError::decode("yEnc stream is missing the =yend trailer")
                        .with_expected("a =yend line after the data")
                        .with_actual("none found"),
                );
            }
            None => lines.len(),
        };
        &lines[first.unwrap() + 1..trailer]
    } else {
        if strict {
            return Err(
                OperationError::decode("yEnc stream must start with an =ybegin line")
                    .with_expected("=ybegin line=<n> size=<n> name=<name>")
                    .with_actual(format!(
                        "`{}`",
                        first
                            .map(|i| String::from_utf8_lossy(&lines[i][..lines[i].len().min(60)]))
                            .unwrap_or_else(|| "empty input".into())
                    )),
            );
        }
        &lines[..]
    };

    let mut out = Vec::new();
    for line in data_lines {
        if yenc_control(line) {
            continue;
        }
        let mut i = 0usize;
        while i < line.len() {
            let b = line[i];
            if b == b'=' {
                let Some(&c) = line.get(i + 1) else {
                    if strict {
                        return Err(OperationError::decode(
                            "yEnc escape character `=` at end of line has no following byte",
                        )
                        .with_expected("an escaped byte after `=`")
                        .with_actual("dangling escape"));
                    }
                    break;
                };
                if strict && !matches!(c, b'@' | b'J' | b'M' | b'}') {
                    return Err(OperationError::decode(format!(
                        "yEnc escape `={}` is not a valid escaped byte",
                        c as char
                    ))
                    .with_expected("one of =@ =J =M =}")
                    .with_actual(format!("`={}`", c as char)));
                }
                out.push(c.wrapping_sub(106));
                i += 2;
            } else {
                out.push(b.wrapping_sub(42));
                i += 1;
            }
        }
    }

    if strict {
        if let Some(declared) = declared_size {
            if declared != out.len() as u64 {
                return Err(OperationError::decode(format!(
                    "yEnc size mismatch: =ybegin declares {declared} bytes but {} were decoded",
                    out.len()
                ))
                .with_expected(format!("{declared} bytes"))
                .with_actual(format!("{} bytes", out.len())));
            }
        }
    }
    Ok(out)
}

/// yEnc line length used by the encoder (the common 128-character line).
const YENC_LINE: usize = 128;

fn from_yenc_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "From Yenc")?;
    check_budget(bytes.len(), "yEnc decode")?;
    let strict = map.bool_or("strict", true);
    Ok(Value::from_bytes(decode_yenc(bytes.as_ref(), strict)?))
}

fn to_yenc_op(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let bytes = input_bytes(v, "To Yenc")?;
    check_budget(bytes.len(), "yEnc encode")?;
    let mut encoded = Vec::with_capacity(bytes.len());
    for &b in bytes.as_ref() {
        let e = b.wrapping_add(42);
        if matches!(e, 0x00 | 0x0A | 0x0D | 0x3D) {
            encoded.push(b'=');
            encoded.push(e.wrapping_add(64));
        } else {
            encoded.push(e);
        }
    }
    let mut out = format!(
        "=ybegin line={YENC_LINE} size={} name=file.bin\r\n",
        bytes.len()
    )
    .into_bytes();
    // Emit data lines of at most YENC_LINE characters without ever splitting
    // a two-byte escape pair across a line break.
    let mut line: Vec<u8> = Vec::with_capacity(YENC_LINE);
    let mut units = 0usize;
    let mut idx = 0usize;
    while idx < encoded.len() {
        let unit_len = usize::from(encoded[idx] == b'=') + 1;
        if units + 1 > YENC_LINE {
            out.extend_from_slice(&line);
            out.extend_from_slice(b"\r\n");
            line.clear();
            units = 0;
        }
        line.extend_from_slice(&encoded[idx..idx + unit_len]);
        units += 1;
        idx += unit_len;
    }
    if !line.is_empty() {
        out.extend_from_slice(&line);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("=yend size={}\r\n", bytes.len()).as_bytes());
    Ok(Value::Bytes(out))
}

// ============================================================ registry =====

pub(crate) fn register(reg: &mut OperationRegistry) {
    use cybercipher_core::Category::Encoding as E;
    use cybercipher_core::CostClass::Instant;
    use cybercipher_core::ValueKind::{Bytes as B, Text as T};

    let enc_tag: &'static [&'static str] = &["encoding", "ctf", "wrapper"];

    reg.add_simple(
        spec(
            "to-unicode-escapes",
            "To Unicode Escapes",
            "Encodes text as Unicode escape sequences (\\uXXXX, \\u{...} or \\xXX). \
             Non-printable-ASCII characters and the backslash itself are escaped, \
             making the encoding exactly reversible.",
            E,
            &[B, T],
            T,
            Instant,
            true,
            vec![p_opts(
                "escape_style",
                "Escape style",
                "uXXXX",
                &[
                    ParamOption {
                        value: "uXXXX",
                        label: "\\uXXXX (fixed four digits)",
                    },
                    ParamOption {
                        value: "braced",
                        label: "\\u{...} (braced)",
                    },
                    ParamOption {
                        value: "x",
                        label: "\\xXX (one byte per escape)",
                    },
                ],
                "Which spelling to emit.",
            )],
            enc_tag,
            &["unicode escape", "to_unicode_unescape", "unescape encode"],
            "Unicode Standard scalar values; C/Java/Rust escape conventions",
            "Round-trip tests (all styles) + surrogate pair vectors",
        ),
        to_unicode_escapes_op,
    );

    reg.add_simple(
        spec(
            "from-unicode-escapes",
            "From Unicode Escapes",
            "Decodes \\uXXXX, \\u{...} and \\xXX escape sequences (surrogate pairs are \
             combined). Strict mode rejects malformed escapes and lone surrogates; \
             relaxed mode keeps unknown constructs verbatim and maps lone surrogates \
             to U+FFFD.",
            E,
            &[T],
            B,
            Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Fail on malformed escapes and lone surrogates instead of keeping them verbatim.",
            )],
            enc_tag,
            &["unicode unescape", "unicode_unescape", "unescape"],
            "Unicode Standard scalar values; C/Java/Rust escape conventions",
            "Round-trip tests (all styles) + malformed/surrogate tests",
        ),
        from_unicode_escapes_op,
    );

    reg.add_simple(
        spec(
            "to-html-entities",
            "To HTML Entities",
            "Encodes text as HTML character references: & < > \" ' become named \
             entities, everything non-ASCII becomes a hex numeric reference.",
            E,
            &[B, T],
            T,
            Instant,
            true,
            vec![],
            enc_tag,
            &["html escape", "html entities encode"],
            "HTML Standard character references",
            "Round-trip tests + named table vectors",
        ),
        to_html_entities_op,
    );

    reg.add_simple(
        spec(
            "from-html-entities",
            "From HTML Entities",
            "Decodes HTML character references: named (&amp;) and numeric (&#NNN;, \
             &#xHH;) forms. Strict mode fails on malformed `&` syntax; unknown named \
             entities are never guessed and stay verbatim in both modes.",
            E,
            &[T],
            T,
            Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Fail on malformed `&` syntax instead of keeping it verbatim.",
            )],
            enc_tag,
            &["html unescape", "html_unescape", "html entities decode"],
            "HTML Standard character references",
            "Round-trip tests + named table vectors + malformed tests",
        ),
        from_html_entities_op,
    );

    reg.add_simple(
        spec(
            "to-quoted-printable",
            "To Quoted Printable",
            "Encodes bytes as quoted-printable (RFC 2045 §6.7): `=` and non-printable \
             bytes become =XX, lines are limited to 76 characters with soft breaks.",
            E,
            &[B, T],
            T,
            Instant,
            true,
            vec![],
            enc_tag,
            &[
                "qp encode",
                "quoted printable encode",
                "to_quoted_printable",
            ],
            "RFC 2045 §6.7 (Quoted-Printable)",
            "RFC 2045 vectors + round-trip tests",
        ),
        to_quoted_printable_op,
    );

    reg.add_simple(
        spec(
            "from-quoted-printable",
            "From Quoted Printable",
            "Decodes quoted-printable (RFC 2045 §6.7): =XX hex escapes and soft line \
             breaks. Strict mode rejects any `=` that does not start a valid escape; \
             relaxed mode keeps it verbatim.",
            E,
            &[T],
            B,
            Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Fail on malformed `=` escapes instead of keeping them verbatim.",
            )],
            enc_tag,
            &[
                "qp decode",
                "from_quoted_printable",
                "quoted printable decode",
            ],
            "RFC 2045 §6.7 (Quoted-Printable)",
            "RFC 2045 vectors + round-trip + malformed tests",
        ),
        from_quoted_printable_op,
    );

    reg.add_simple(
        spec(
            "to-punycode",
            "To Punycode",
            "Encodes each dot-separated label containing non-ASCII as an ACE (`xn--`) \
             Punycode label per RFC 3492, preserving case through the mixed-case \
             annotation.",
            E,
            &[B, T],
            T,
            Instant,
            true,
            vec![],
            enc_tag,
            &["punycode encode", "idn ace encode", "idna"],
            "RFC 3492 (Punycode) + RFC 5891 (IDNA ACE prefix)",
            "RFC 3492 sample vectors (bücher/münchen) + round-trip tests",
        ),
        to_punycode_op,
    );

    reg.add_simple(
        spec(
            "from-punycode",
            "From Punycode",
            "Decodes ACE (`xn--`) Punycode labels per RFC 3492, label by label. Strict \
             mode fails on malformed labels; relaxed mode keeps them verbatim. \
             Overflow and invalid digits are typed errors, never panics.",
            E,
            &[T],
            T,
            Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Fail on malformed punycode labels instead of keeping them verbatim.",
            )],
            enc_tag,
            &["from_punycode", "punycode decode", "idn ace decode", "idna"],
            "RFC 3492 (Punycode) + RFC 5891 (IDNA ACE prefix)",
            "RFC 3492 sample vectors (bücher/münchen) + round-trip tests",
        ),
        from_punycode_op,
    );

    reg.add_simple(
        spec(
            "to-uuencode",
            "To Uuencode",
            "Encodes bytes as classic uuencode inside the `begin 644` / `end` envelope.",
            E,
            &[B, T],
            T,
            Instant,
            true,
            vec![],
            enc_tag,
            &["uu encode", "to_uuencode", "uudecode table"],
            "de-facto uuencode convention (POSIX uudecode)",
            "Round-trip tests (binary, all lengths) + envelope tests",
        ),
        to_uuencode_op,
    );

    reg.add_simple(
        spec(
            "from-uuencode",
            "From Uuencode",
            "Decodes classic uuencode data. Strict mode requires the `begin <octal> \
             <name>` / `end` envelope, exact line lengths, and table characters; \
             relaxed mode also decodes envelope-less streams.",
            E,
            &[B, T],
            B,
            Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Require the complete begin/end envelope and exact line lengths.",
            )],
            enc_tag,
            &["from_uuencode", "uudecode", "uu decode"],
            "de-facto uuencode convention (POSIX uudecode)",
            "Round-trip tests (binary, all lengths) + malformed tests",
        ),
        from_uuencode_op,
    );

    reg.add_simple(
        spec(
            "to-xxencode",
            "To Xxencode",
            "Encodes bytes as classic xxencode (the uuencode layout over the \
             `+-0-9A-Za-z` table) inside the `begin 644` / `end` envelope.",
            E,
            &[B, T],
            T,
            Instant,
            true,
            vec![],
            enc_tag,
            &["xx encode", "to_xxencode"],
            "de-facto xxencode convention (esolangs/ToolsFx references)",
            "Round-trip tests (binary, all lengths) + envelope tests",
        ),
        to_xxencode_op,
    );

    reg.add_simple(
        spec(
            "from-xxencode",
            "From Xxencode",
            "Decodes classic xxencode data (uuencode layout over the `+-0-9A-Za-z` \
             table). Strict mode requires the `begin`/`end` envelope, exact line \
             lengths, and table characters; relaxed mode also decodes envelope-less \
             streams.",
            E,
            &[B, T],
            B,
            Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Require the complete begin/end envelope and exact line lengths.",
            )],
            enc_tag,
            &["from_xxencode", "xxdecode", "xx decode"],
            "de-facto xxencode convention (esolangs/ToolsFx references)",
            "Round-trip tests (binary, all lengths) + malformed tests",
        ),
        from_xxencode_op,
    );

    reg.add_simple(
        spec(
            "to-yenc",
            "To Yenc",
            "Encodes bytes as yEnc: every byte is shifted by +42 and the bytes that \
             land on NUL/LF/CR/`=` are escaped, wrapped in the `=ybegin` / `=yend` \
             envelope. The output is 8-bit data by design and emitted as bytes.",
            E,
            &[B, T],
            B,
            Instant,
            true,
            vec![],
            enc_tag,
            &["yenc encode", "to_yenc"],
            "yEnc specification (J. Helbing, easynews.com)",
            "Round-trip tests (all 256 byte values) + envelope tests",
        ),
        to_yenc_op,
    );

    reg.add_simple(
        spec(
            "from-yenc",
            "From Yenc",
            "Decodes yEnc data: the -42 shift with `=` escapes. Strict mode requires \
             the `=ybegin`/`=yend` envelope, a declared size, and only valid escaped \
             bytes; relaxed mode also decodes envelope-less data.",
            E,
            &[B, T],
            B,
            Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Require the envelope, declared size and valid escapes.",
            )],
            enc_tag,
            &["from_yenc", "yenc decode"],
            "yEnc specification (J. Helbing, easynews.com)",
            "Round-trip tests (all 256 byte values) + malformed tests",
        ),
        from_yenc_op,
    );
}

// -------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ExecutionContext {
        ExecutionContext::new()
    }

    fn relaxed() -> ParamMap {
        let mut map = ParamMap::new();
        map.insert("strict", false);
        map
    }

    // -------------------------------------------------- unicode escapes ----

    #[test]
    fn unicode_roundtrip_all_styles() {
        let text = "flag{unicode_é世界} \u{1F511} tail";
        for style in ["uXXXX", "braced", "x"] {
            let mut map = ParamMap::new();
            map.insert("escape_style", style);
            let enc = to_unicode_escapes_op(&Value::Text(text.into()), &map, &ctx()).unwrap();
            let Value::Text(enc) = enc else { panic!() };
            let dec = decode_unicode_escapes(&enc, true).unwrap();
            assert_eq!(String::from_utf8(dec).unwrap(), text, "style {style}");
        }
    }

    #[test]
    fn unicode_decode_knows_all_spellings_at_once() {
        let mixed = "a\\u0042\\u{43}\\x44";
        let out = decode_unicode_escapes(mixed, true).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "aBCD");
    }

    #[test]
    fn unicode_surrogate_pair_combined() {
        // U+1F511 as a UTF-16 surrogate pair.
        let out = decode_unicode_escapes("\\ud83d\\udd11", true).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "\u{1F511}");
    }

    #[test]
    fn unicode_strict_rejects_malformed() {
        for bad in [
            "\\u00",
            "\\uGGGG",
            "\\u{",
            "\\u{}",
            "\\u{12345678}",
            "\\x4",
            "\\xZZ",
            "\\q",
            "trailing\\",
        ] {
            assert!(
                decode_unicode_escapes(bad, true).is_err(),
                "strict must reject {bad}"
            );
        }
    }

    #[test]
    fn unicode_relaxed_keeps_verbatim_and_replaces_surrogates() {
        let out = decode_unicode_escapes("a\\u00", false).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "a\\u00");
        let out = decode_unicode_escapes("\\ud83dx", false).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "\u{FFFD}x");
    }

    // ------------------------------------------------------- html entities ----

    #[test]
    fn html_roundtrip() {
        let text = "a < b & c > \"d\" 'e' ü 世界";
        let enc = encode_html_entities(text);
        assert!(enc.contains("&amp;") && enc.contains("&#x"));
        assert_eq!(decode_html_entities(&enc, true).unwrap(), text);
    }

    #[test]
    fn html_named_and_numeric() {
        let out =
            decode_html_entities("&amp;&lt;&gt;&quot;&apos;&nbsp;&euro;&frac12;", true).unwrap();
        assert_eq!(out, "&<>\"'\u{a0}\u{20ac}\u{bd}");
        assert_eq!(
            decode_html_entities("&#72;&#x69;&#X21;", true).unwrap(),
            "Hi!"
        );
    }

    #[test]
    fn html_unknown_named_left_verbatim() {
        // Unknown named entities are NOT decoded in strict mode (documented).
        let out = decode_html_entities("a &notarealentity; b", true).unwrap();
        assert_eq!(out, "a &notarealentity; b");
    }

    #[test]
    fn html_strict_rejects_malformed() {
        for bad in [
            "dangling & amp",
            "&#xZZ;",
            "&#;",
            "&#1114112;",
            "&#xD800;",
            "&",
        ] {
            assert!(
                decode_html_entities(bad, true).is_err(),
                "strict must reject {bad}"
            );
        }
        // Relaxed keeps malformed constructs verbatim (including non-scalar
        // numeric references).
        assert_eq!(decode_html_entities("a & b", false).unwrap(), "a & b");
        assert_eq!(
            decode_html_entities("&#xD800; x", false).unwrap(),
            "&#xD800; x"
        );
    }

    // --------------------------------------------------- quoted printable ----

    #[test]
    fn qp_roundtrip_binary() {
        let data: Vec<u8> = (0..=255u8).cycle().take(600).collect();
        let enc = encode_quoted_printable(&data);
        let dec = decode_quoted_printable(enc.as_bytes(), true).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn qp_soft_breaks_and_lines() {
        let enc = encode_quoted_printable(&[b'A'; 100]);
        for line in enc.lines() {
            assert!(line.len() <= 76, "line too long: {line}");
        }
        assert_eq!(
            decode_quoted_printable("foo=\r\nbar=\nbaz".as_bytes(), true).unwrap(),
            b"foobarbaz".to_vec()
        );
    }

    #[test]
    fn qp_strict_rejects_malformed() {
        for bad in ["a=b", "=4", "=G1", "end=", "=x"] {
            assert!(
                decode_quoted_printable(bad.as_bytes(), true).is_err(),
                "strict must reject {bad}"
            );
        }
        assert_eq!(
            decode_quoted_printable(b"a=b", false).unwrap(),
            b"a=b".to_vec()
        );
    }

    #[test]
    fn qp_trailing_space_is_encoded() {
        let enc = encode_quoted_printable(b"two  \nspaces");
        assert!(
            enc.contains("=20"),
            "trailing spaces must be encoded: {enc}"
        );
        assert_eq!(
            decode_quoted_printable(enc.as_bytes(), true).unwrap(),
            b"two  \nspaces".to_vec()
        );
    }

    // ============================================================ punycode ====

    #[test]
    fn punycode_rfc_vectors() {
        // Widely cited RFC 3492 / IDNA examples.
        assert_eq!(punycode_label_to_text("bcher-kva").unwrap(), "bücher");
        assert_eq!(punycode_label_to_text("mnchen-3ya").unwrap(), "münchen");
        assert_eq!(punycode_label_to_text("fiqs8s").unwrap(), "中国");
        assert_eq!(punycode_encode_body("bücher").unwrap(), "bcher-kva");
        assert_eq!(punycode_label_to_text("Bcher-kva").unwrap(), "Bücher");
    }

    #[test]
    fn punycode_roundtrip_mixed_case() {
        for text in [
            "münchen",
            "BüCHER",
            "中国",
            "\u{1F511}\u{1F600}",
            "Ωmega",
            "final ς sigma",
        ] {
            let enc = punycode_encode_body(text).unwrap();
            let dec = punycode_label_to_text(&enc).unwrap();
            assert_eq!(dec.to_lowercase(), text.to_lowercase(), "body {enc}");
        }
    }

    #[test]
    fn punycode_labels() {
        assert_eq!(
            punycode_decode_labels("xn--bcher-kva.example", true).unwrap(),
            "bücher.example"
        );
        assert_eq!(
            punycode_encode_labels("münchen.cn").unwrap(),
            "xn--mnchen-3ya.cn"
        );
        // Round trip through the ops.
        let enc =
            to_punycode_op(&Value::Text("münchen.cn".into()), &ParamMap::new(), &ctx()).unwrap();
        let Value::Text(enc) = enc else { panic!() };
        let dec = from_punycode_op(&Value::Text(enc), &ParamMap::new(), &ctx()).unwrap();
        assert_eq!(dec, Value::Text("münchen.cn".into()));
    }

    #[test]
    fn punycode_strict_rejects_malformed() {
        for bad in [
            "xn--bcher-kv]",
            "xn--",
            "xn--!!!!!",
            "xn--zzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            assert!(
                from_punycode_op(&Value::Text(bad.into()), &ParamMap::new(), &ctx()).is_err(),
                "strict must reject {bad}"
            );
        }
        // Relaxed keeps malformed labels verbatim.
        let out =
            from_punycode_op(&Value::Text("xn--!!!!.com".into()), &relaxed(), &ctx()).unwrap();
        assert_eq!(out, Value::Text("xn--!!!!.com".into()));
    }

    // ==================================================== uuencode / xxencode ====

    #[test]
    fn uu_roundtrip_binary() {
        for len in [0usize, 1, 2, 3, 44, 45, 46, 91, 300] {
            let data: Vec<u8> = (0..len as u8).cycle().take(len).collect();
            let enc =
                to_uuencode_op(&Value::Bytes(data.clone()), &ParamMap::new(), &ctx()).unwrap();
            let Value::Text(enc) = enc else { panic!() };
            let dec = from_uuencode_op(&Value::Text(enc), &ParamMap::new(), &ctx()).unwrap();
            assert_eq!(dec, Value::Bytes(data), "len {len}");
        }
    }

    #[test]
    fn xx_roundtrip_binary() {
        for len in [0usize, 1, 3, 45, 92, 200] {
            let data: Vec<u8> = (0..len as u8).cycle().take(len).collect();
            let enc =
                to_xxencode_op(&Value::Bytes(data.clone()), &ParamMap::new(), &ctx()).unwrap();
            let Value::Text(enc) = enc else { panic!() };
            let dec = from_xxencode_op(&Value::Text(enc), &ParamMap::new(), &ctx()).unwrap();
            assert_eq!(dec, Value::Bytes(data), "len {len}");
        }
    }

    #[test]
    fn uu_strict_requires_envelope() {
        // Missing end line.
        let body = "begin 644 f\n%9F]O\n";
        assert!(from_uuencode_op(&Value::Text(body.into()), &ParamMap::new(), &ctx()).is_err());
        // Missing begin line.
        let body = "%9F]O\n`\nend\n";
        assert!(from_uuencode_op(&Value::Text(body.into()), &ParamMap::new(), &ctx()).is_err());
        // Invalid octal mode.
        let body = "begin 999 f\n%9F]O\n`\nend\n";
        assert!(from_uuencode_op(&Value::Text(body.into()), &ParamMap::new(), &ctx()).is_err());
    }

    #[test]
    fn uu_envelopeless_relaxed_mode() {
        // Strip the begin/terminator/end lines and feed only the data lines:
        // relaxed mode must still decode them.
        let enc = to_uuencode_op(&Value::Bytes(b"Foo".to_vec()), &ParamMap::new(), &ctx()).unwrap();
        let Value::Text(enc) = enc else { panic!() };
        let body: String = enc
            .lines()
            .filter(|&l| !l.starts_with("begin ") && l != "end" && l != "`")
            .collect::<Vec<&str>>()
            .join("\n");
        let out = from_uuencode_op(&Value::Text(body), &relaxed(), &ctx()).unwrap();
        assert_eq!(out, Value::Bytes(b"Foo".to_vec()));
    }

    #[test]
    fn uu_body_rejected_by_xx_decoder() {
        // A uu body with characters outside the xx table must fail as xx.
        let uu = to_uuencode_op(
            &Value::Bytes(b"hello world, this uses spaces".to_vec()),
            &ParamMap::new(),
            &ctx(),
        )
        .unwrap();
        let Value::Text(uu) = uu else { panic!() };
        assert!(from_xxencode_op(&Value::Text(uu), &ParamMap::new(), &ctx()).is_err());
    }

    // ================================================================ yEnc ====

    #[test]
    fn yenc_roundtrip_all_bytes() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let enc = to_yenc_op(&Value::Bytes(data.clone()), &ParamMap::new(), &ctx()).unwrap();
        let Value::Bytes(enc) = enc else { panic!() };
        let dec = from_yenc_op(&Value::Bytes(enc), &ParamMap::new(), &ctx()).unwrap();
        assert_eq!(dec, Value::Bytes(data));
    }

    #[test]
    fn yenc_strict_requires_envelope() {
        assert!(from_yenc_op(
            &Value::Bytes(b"plain data".to_vec()),
            &ParamMap::new(),
            &ctx()
        )
        .is_err());
        // Missing =yend trailer.
        assert!(from_yenc_op(
            &Value::Bytes(b"=ybegin line=128 size=3 name=f\r\nJ;IJ\r\n".to_vec()),
            &ParamMap::new(),
            &ctx()
        )
        .is_err());
        // Declared size mismatch (4 data bytes, declared 9).
        assert!(from_yenc_op(
            &Value::Bytes(b"=ybegin line=128 size=9 name=f\r\nJ;IJ\r\n=yend size=9\r\n".to_vec()),
            &ParamMap::new(),
            &ctx()
        )
        .is_err());
    }

    #[test]
    fn yenc_strict_rejects_bogus_escape() {
        let text = "=ybegin line=128 size=2 name=f\r\n=pp\r\n=yend size=2\r\n";
        assert!(from_yenc_op(
            &Value::Bytes(text.as_bytes().to_vec()),
            &ParamMap::new(),
            &ctx()
        )
        .is_err());
    }

    #[test]
    fn yenc_relaxed_envelopeless() {
        // yEnc encode shifts +42: "test" -> [0x9E, 0x8F, 0x9D, 0x9E] (none of
        // which need `=` escaping). The earlier fixture "J;IJ" was backwards.
        let out = from_yenc_op(
            &Value::Bytes(vec![0x9E, 0x8F, 0x9D, 0x9E]),
            &relaxed(),
            &ctx(),
        )
        .unwrap();
        assert_eq!(out, Value::Bytes(b"test".to_vec()));
    }

    // ============================================================ budgets ====

    #[test]
    fn oversized_inputs_are_budget_errors() {
        let big = vec![b'a'; WRAPPER_MAX_INPUT + 1];
        assert!(
            to_quoted_printable_op(&Value::Bytes(big.clone()), &ParamMap::new(), &ctx()).is_err()
        );
        assert!(from_yenc_op(&Value::Bytes(big), &ParamMap::new(), &ctx()).is_err());
    }
}
