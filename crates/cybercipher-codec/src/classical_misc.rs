//! Classical/misc text encodings: Morse (ITU), A1Z26, tap code, Bacon's
//! bilateral cipher, and Unicode Braille.
//!
//! All operations are text-to-text and reversible. Strict mode (the
//! default) reports the offending character and its offset; relaxed mode
//! silently drops unsupported characters (documented per operation).

use crate::helpers::{input_text, p_bool, p_text, spec};
use cybercipher_core::prelude::*;

// -------------------------------------------------------------- Morse ----

/// ITU-R M.1677 international Morse code: 26 letters, 10 digits, and a
/// common punctuation subset.
const MORSE_TABLE: &[(char, &str)] = &[
    ('A', ".-"),
    ('B', "-..."),
    ('C', "-.-."),
    ('D', "-.."),
    ('E', "."),
    ('F', "..-."),
    ('G', "--."),
    ('H', "...."),
    ('I', ".."),
    ('J', ".---"),
    ('K', "-.-"),
    ('L', ".-.."),
    ('M', "--"),
    ('N', "-."),
    ('O', "---"),
    ('P', ".--."),
    ('Q', "--.-"),
    ('R', ".-."),
    ('S', "..."),
    ('T', "-"),
    ('U', "..-"),
    ('V', "...-"),
    ('W', ".--"),
    ('X', "-..-"),
    ('Y', "-.--"),
    ('Z', "--.."),
    ('0', "-----"),
    ('1', ".----"),
    ('2', "..---"),
    ('3', "...--"),
    ('4', "....-"),
    ('5', "....."),
    ('6', "-...."),
    ('7', "--..."),
    ('8', "---.."),
    ('9', "----."),
    ('.', ".-.-.-"),
    (',', "--..--"),
    ('?', "..--.."),
    ('\'', ".----."),
    ('!', "-.-.--"),
    ('/', "-..-."),
    ('(', "-.--."),
    (')', "-.--.-"),
    ('&', ".-..."),
    (':', "---..."),
    (';', "-.-.-."),
    ('=', "-...-"),
    ('+', ".-.-."),
    ('-', "-....-"),
    ('_', "..--.-"),
    ('"', ".-..-."),
    ('$', "...-..-"),
    ('@', ".--.-."),
];

fn morse_encode_char(c: char) -> Option<&'static str> {
    let upper = c.to_ascii_uppercase();
    MORSE_TABLE
        .iter()
        .find(|(ch, _)| *ch == upper)
        .map(|(_, code)| *code)
}

fn morse_encode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "To Morse")?;
    let strict = map.bool_or("strict", true);
    let mut words: Vec<String> = Vec::new();
    let mut cur = String::new();
    for (idx, c) in text.char_indices() {
        if c.is_whitespace() {
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
            continue;
        }
        match morse_encode_char(c) {
            Some(code) => {
                if !cur.is_empty() {
                    cur.push(' ');
                }
                cur.push_str(code);
            }
            None if strict => {
                return Err(OperationError::decode(format!(
                    "character `{c}` at offset {idx} has no Morse code"
                ))
                .with_expected("A-Z, 0-9 or the supported punctuation subset")
                .with_actual(format!("character at offset {idx}"))
                .with_details("Disable strict mode to drop unsupported characters."));
            }
            None => {}
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    // Letters are separated by a single space, words by " / ".
    Ok(Value::Text(words.join(" / ")))
}

fn morse_decode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From Morse")?;
    let strict = map.bool_or("strict", true);
    let mut out = String::with_capacity(text.len() / 2);
    for (widx, word) in text.split('/').enumerate() {
        if widx > 0 {
            out.push(' ');
        }
        for token in word.split_whitespace() {
            match MORSE_TABLE.iter().find(|(_, code)| *code == token) {
                Some((ch, _)) => out.push(*ch),
                None if strict => {
                    return Err(OperationError::decode(format!(
                        "unknown Morse sequence `{token}`"
                    ))
                    .with_expected("a sequence from the ITU-R M.1677 table")
                    .with_actual(format!("word #{widx}, sequence `{token}`"))
                    .with_details(
                        "Sequences may only contain `.` and `-`; disable strict mode to drop unknown sequences.",
                    ));
                }
                None => {}
            }
        }
    }
    Ok(Value::Text(out))
}

// ------------------------------------------------------------- A1Z26 ----

fn a1z26_params(map: &ParamMap) -> OpResult<(String, String)> {
    let delim = crate::helpers::decode_delimiter(map.str_or("delimiter", "-"));
    let word_sep = crate::helpers::decode_delimiter(map.str_or("word_separator", "/"));
    if delim.is_empty() {
        return Err(OperationError::invalid_param(
            "delimiter",
            "the A1Z26 delimiter must not be empty (numbers are ambiguous without one)",
        ));
    }
    if word_sep.is_empty() {
        return Err(OperationError::invalid_param(
            "word_separator",
            "the A1Z26 word separator must not be empty",
        ));
    }
    Ok((delim, word_sep))
}

fn a1z26_encode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "To A1Z26")?;
    let (delim, word_sep) = a1z26_params(map)?;
    let strict = map.bool_or("strict", true);
    let mut words: Vec<String> = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    for (idx, c) in text.char_indices() {
        if c.is_ascii_alphabetic() {
            let n = (c.to_ascii_uppercase() as u8 - b'A' + 1) as u32;
            cur.push(n.to_string());
        } else if c.is_whitespace() {
            if !cur.is_empty() {
                words.push(cur.join(&delim));
                cur.clear();
            }
        } else if strict {
            return Err(OperationError::decode(format!(
                "character `{c}` at offset {idx} is not a letter"
            ))
            .with_expected("letters A-Z (spaces separate words)")
            .with_actual(format!("character at offset {idx}"))
            .with_details("Disable strict mode to drop non-letter characters."));
        }
    }
    if !cur.is_empty() {
        words.push(cur.join(&delim));
    }
    Ok(Value::Text(words.join(&format!(" {word_sep} "))))
}

fn a1z26_decode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From A1Z26")?;
    let (delim, word_sep) = a1z26_params(map)?;
    let mut words: Vec<String> = Vec::new();
    for (widx, chunk) in text.split(&word_sep).enumerate() {
        let chunk = chunk.trim();
        if chunk.is_empty() {
            continue;
        }
        let mut letters = String::new();
        for token in chunk.split(&delim) {
            let token = token.trim();
            let fail = |msg: String, actual: String| {
                OperationError::decode(msg)
                    .with_expected("numbers 1-26 separated by the delimiter")
                    .with_actual(actual)
            };
            if token.is_empty() {
                return Err(fail(
                    format!("word #{widx} contains an empty number (dangling delimiter)"),
                    format!("word `{chunk}`"),
                ));
            }
            if !token.chars().all(|c| c.is_ascii_digit()) {
                return Err(fail(
                    format!("token `{token}` in word #{widx} is not a number"),
                    format!("token `{token}`"),
                ));
            }
            if token.len() > 2 {
                return Err(fail(
                    format!(
                        "token `{token}` is longer than two digits: A1Z26 is ambiguous without delimiters between numbers"
                    ),
                    format!("token `{token}`"),
                ));
            }
            let value: u32 = token.parse().map_err(|_| {
                fail(
                    format!("token `{token}` is not a number"),
                    format!("token `{token}`"),
                )
            })?;
            if !(1..=26).contains(&value) {
                return Err(fail(
                    format!("value {value} is outside the 1-26 letter range"),
                    format!("token `{token}`"),
                ));
            }
            letters.push((b'A' + value as u8 - 1) as char);
        }
        words.push(letters);
    }
    Ok(Value::Text(words.join(" ")))
}

// ----------------------------------------------------------- Tap code ----

/// Classic 5x5 tap-code square: 25 cells for 26 letters, `K` omitted
/// (`C` stands for both `C` and `K`).
const TAP_ROWS: [&str; 5] = ["ABCDE", "FGHIJ", "LMNOP", "QRSTU", "VWXYZ"];

fn tap_position(c: char) -> Option<(usize, usize)> {
    let mut u = c.to_ascii_uppercase();
    if u == 'K' {
        u = 'C'; // classic tap convention: K is tapped as C
    }
    for (row, r) in TAP_ROWS.iter().enumerate() {
        if let Some(col) = r.chars().position(|x| x == u) {
            return Some((row + 1, col + 1));
        }
    }
    None
}

fn tap_encode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "To Tap Code")?;
    let strict = map.bool_or("strict", true);
    let mut groups: Vec<String> = Vec::new();
    for (idx, c) in text.char_indices() {
        match tap_position(c) {
            Some((row, col)) => {
                groups.push(format!("{} {}", ".".repeat(row), ".".repeat(col)));
            }
            None if strict => {
                return Err(OperationError::decode(format!(
                    "character `{c}` at offset {idx} is not a letter"
                ))
                .with_expected("letters A-Z (K is tapped as C)")
                .with_actual(format!("character at offset {idx}"))
                .with_details("Disable strict mode to drop non-letter characters."));
            }
            None => {}
        }
    }
    Ok(Value::Text(groups.join(" / ")))
}

fn count_dots(token: &str, label: &str) -> OpResult<usize> {
    let dots = token.chars().filter(|&c| c == '.').count();
    if token.chars().any(|c| c != '.') {
        return Err(OperationError::decode(format!(
            "{label} group `{token}` contains characters other than `.`"
        ))
        .with_expected("one or more `.` characters"));
    }
    if !(1..=5).contains(&dots) {
        return Err(OperationError::decode(format!(
            "{label} group has {dots} dots; tap code uses 1-5"
        ))
        .with_expected("1-5 dots")
        .with_actual(format!("{dots} dots in `{token}`")));
    }
    Ok(dots)
}

fn tap_decode(v: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From Tap Code")?;
    let mut out = String::new();
    for (gidx, piece) in text.split('/').enumerate() {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        let parts: Vec<&str> = piece.split_whitespace().collect();
        if parts.len() != 2 {
            return Err(OperationError::decode(format!(
                "tap group #{} must consist of two dot groups (row and column), found {}",
                gidx + 1,
                parts.len()
            ))
            .with_expected("two `.` groups separated by whitespace")
            .with_actual(format!("group `{piece}`")));
        }
        let row = count_dots(parts[0], "row")?;
        let col = count_dots(parts[1], "column")?;
        out.push(
            TAP_ROWS[row - 1]
                .chars()
                .nth(col - 1)
                .ok_or_else(|| OperationError::internal("tap index out of range"))?,
        );
    }
    Ok(Value::Text(out))
}

// -------------------------------------------------------------- Bacon ----

/// 24-letter Bacon alphabet: `J` merges into `I` and `V` into `U`.
const BACON24: &[u8] = b"ABCDEFGHIKLMNOPQRSTUWXYZ";

fn bacon_index(c: char) -> Option<usize> {
    let mut u = c.to_ascii_uppercase();
    if u == 'J' {
        u = 'I';
    } else if u == 'V' {
        u = 'U';
    }
    if !u.is_ascii_uppercase() {
        return None;
    }
    BACON24.iter().position(|&b| b as char == u)
}

fn bacon_letters(map: &ParamMap) -> OpResult<(char, char)> {
    let a = map.str_or("letter_a", "A");
    let b = map.str_or("letter_b", "B");
    let (a, b) = (a.chars().next(), b.chars().next());
    match (a, b) {
        (Some(a), Some(b)) if a != b => Ok((a, b)),
        (Some(_), Some(_)) => Err(OperationError::invalid_param(
            "letter_b",
            "the two Bacon symbols must be distinct",
        )
        .with_expected("two different single characters")
        .with_actual("identical characters")),
        _ => Err(OperationError::invalid_param(
            "letter_a",
            "the Bacon symbols must each be exactly one character",
        )),
    }
}

fn bacon_encode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "To Bacon")?;
    let (a, b) = bacon_letters(map)?;
    let strict = map.bool_or("strict", true);
    let mut groups: Vec<String> = Vec::new();
    let mut cur = String::with_capacity(5);
    for (idx, c) in text.char_indices() {
        match bacon_index(c) {
            Some(i) => {
                for k in (0..5).rev() {
                    cur.push(if (i >> k) & 1 == 1 { b } else { a });
                }
                if cur.len() == 5 {
                    groups.push(std::mem::take(&mut cur));
                }
            }
            None if strict => {
                return Err(OperationError::decode(format!(
                    "character `{c}` at offset {idx} is not one of the 24 Bacon letters (J->I, V->U merged)"
                ))
                .with_expected("letters A-Z excluding J and V")
                .with_actual(format!("character at offset {idx}"))
                .with_details("Disable strict mode to drop unsupported characters."));
            }
            None => {}
        }
    }
    if !cur.is_empty() {
        // Only possible if the input letter count is not a multiple of 5;
        // the trailing symbols cannot form a group.
        return Err(OperationError::decode(
            "letter count is not a multiple of 5: the trailing letters cannot form a Bacon group",
        )
        .with_expected("a multiple of 5 letters")
        .with_actual(format!("{} trailing letter(s)", cur.len())));
    }
    Ok(Value::Text(groups.join(" ")))
}

fn bacon_decode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From Bacon")?;
    let (a, b) = bacon_letters(map)?;
    let strict = map.bool_or("strict", true);
    let mut bits: Vec<bool> = Vec::with_capacity(text.len());
    for (idx, c) in text.char_indices() {
        if c == a {
            bits.push(false);
        } else if c == b {
            bits.push(true);
        } else if c.is_whitespace() {
            continue;
        } else if strict {
            return Err(OperationError::decode(format!(
                "character `{c}` at offset {idx} is neither the A symbol `{a}` nor the B symbol `{b}`"
            ))
            .with_expected(format!("`{a}` or `{b}`"))
            .with_actual(format!("character at offset {idx}"))
            .with_details("Disable strict mode to drop foreign characters."));
        }
    }
    if !bits.len().is_multiple_of(5) {
        return Err(
            OperationError::decode("Bacon symbol count is not a multiple of 5")
                .with_expected("a multiple of 5 symbols")
                .with_actual(format!("{} symbols", bits.len())),
        );
    }
    let mut out = String::with_capacity(bits.len() / 5);
    for (gidx, group) in bits.as_chunks::<5>().0.iter().enumerate() {
        let mut value = 0usize;
        for &bit in group {
            value = (value << 1) | bit as usize;
        }
        if value >= BACON24.len() {
            if strict {
                return Err(OperationError::decode(format!(
                    "Bacon group #{gidx} has value {value}, outside the 24-letter alphabet (00000-10111)"
                ))
                .with_expected("a group value of 0-23")
                .with_actual(format!("group value {value}")));
            }
            continue;
        }
        out.push(BACON24[value] as char);
    }
    Ok(Value::Text(out))
}

// ------------------------------------------------------------ Braille ----

/// Unicode Braille patterns: U+2800 + dot bitmask (dot 1 = 0x01 ... dot 6
/// = 0x20). Grade-1 letters, digits (via the number sign), and a small
/// punctuation subset are supported.
const BRAILLE_BASE: u32 = 0x2800;
const NUMBER_SIGN: u8 = 0x3c; // dots 3456

const BRAILLE_LETTERS: &[(u8, u8)] = &[
    (b'A', 0x01),
    (b'B', 0x03),
    (b'C', 0x09),
    (b'D', 0x19),
    (b'E', 0x11),
    (b'F', 0x0b),
    (b'G', 0x1b),
    (b'H', 0x13),
    (b'I', 0x0a),
    (b'J', 0x1a),
    (b'K', 0x05),
    (b'L', 0x07),
    (b'M', 0x0d),
    (b'N', 0x1d),
    (b'O', 0x15),
    (b'P', 0x0f),
    (b'Q', 0x1f),
    (b'R', 0x17),
    (b'S', 0x0e),
    (b'T', 0x1e),
    (b'U', 0x25),
    (b'V', 0x27),
    (b'W', 0x3a),
    (b'X', 0x2d),
    (b'Y', 0x3d),
    (b'Z', 0x35),
];

/// Digits share the letter patterns of a-j and require the number sign.
const BRAILLE_DIGITS: &[(u8, u8)] = &[
    (b'1', 0x01),
    (b'2', 0x03),
    (b'3', 0x09),
    (b'4', 0x19),
    (b'5', 0x11),
    (b'6', 0x0b),
    (b'7', 0x1b),
    (b'8', 0x13),
    (b'9', 0x0a),
    (b'0', 0x1a),
];

/// Supported punctuation subset (English grade-1 conventions).
const BRAILLE_PUNCT: &[(char, u8)] = &[
    ('.', 0x32),  // dots 256
    (',', 0x02),  // dot 2
    ('?', 0x39),  // dots 1456
    ('!', 0x16),  // dots 235
    ('\'', 0x04), // dot 3
    ('-', 0x24),  // dots 36
    (':', 0x12),  // dots 25
    (';', 0x06),  // dots 23
];

fn braille_char(mask: u8) -> char {
    char::from_u32(BRAILLE_BASE + mask as u32)
        .expect("mask < 0x40 yields a valid braille codepoint")
}

fn braille_encode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "To Braille")?;
    let digit_sign = map.bool_or("digit_sign", true);
    let strict = map.bool_or("strict", true);
    let mut out = String::with_capacity(text.len() * 2);
    for (idx, c) in text.char_indices() {
        if c.is_ascii_alphabetic() {
            let upper = c.to_ascii_uppercase();
            let mask = BRAILLE_LETTERS
                .iter()
                .find(|(ch, _)| *ch as char == upper)
                .map(|(_, m)| *m)
                .expect("A-Z are all in the table");
            out.push(braille_char(mask));
        } else if c.is_ascii_digit() {
            let mask = BRAILLE_DIGITS
                .iter()
                .find(|(ch, _)| *ch == c as u8)
                .map(|(_, m)| *m)
                .expect("0-9 are all in the table");
            if digit_sign {
                // The number sign is emitted before every digit so that the
                // encoding is unambiguous and exactly reversible.
                out.push(braille_char(NUMBER_SIGN));
            }
            out.push(braille_char(mask));
        } else if c == ' ' {
            out.push(' ');
        } else if let Some((_, mask)) = BRAILLE_PUNCT.iter().find(|(ch, _)| *ch == c) {
            out.push(braille_char(*mask));
        } else if strict {
            return Err(OperationError::decode(format!(
                "character `{c}` at offset {idx} has no grade-1 Braille pattern here"
            ))
            .with_expected("A-Z, 0-9, space or the supported punctuation subset (.,?!'-:;)")
            .with_actual(format!("character at offset {idx}"))
            .with_details("Disable strict mode to drop unsupported characters."));
        }
    }
    Ok(Value::Text(out))
}

fn braille_decode(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From Braille")?;
    let strict = map.bool_or("strict", true);
    let mut out = String::with_capacity(text.len());
    let mut digit_mode = false;
    for (idx, c) in text.char_indices() {
        let cp = c as u32;
        if c == ' ' || cp == BRAILLE_BASE {
            // U+2800 (blank pattern) is commonly used for space as well.
            out.push(' ');
            digit_mode = false;
            continue;
        }
        if !(BRAILLE_BASE..=BRAILLE_BASE + 0xff).contains(&cp) {
            if strict {
                return Err(OperationError::decode(format!(
                    "character `{c}` at offset {idx} is not a Braille pattern"
                ))
                .with_expected("U+2800-U+28FF")
                .with_actual(format!("U+{cp:04X}"))
                .with_details("Disable strict mode to drop non-Braille characters."));
            }
            continue;
        }
        let mask = (cp - BRAILLE_BASE) as u8;
        if mask == NUMBER_SIGN {
            digit_mode = true;
            continue;
        }
        if digit_mode {
            match BRAILLE_DIGITS.iter().find(|(_, m)| *m == mask) {
                Some((ch, _)) => {
                    out.push(*ch as char);
                    // The number sign applies to the single following cell
                    // in this workbench's convention (mirrors the encoder).
                    digit_mode = false;
                }
                None if strict => {
                    return Err(OperationError::decode(format!(
                        "expected a digit pattern after the number sign, found U+{cp:04X} at offset {idx}"
                    ))
                    .with_expected("one of the digit patterns a-j")
                    .with_actual(format!("U+{cp:04X}")));
                }
                None => {}
            }
            continue;
        }
        if mask >= 0x40 {
            // 8-dot patterns (U+2840-U+28FF) are outside the 6-dot grade-1
            // subset this operation supports.
            if strict {
                return Err(OperationError::decode(format!(
                    "unsupported Braille pattern U+{cp:04X} at offset {idx}"
                ))
                .with_expected("a 6-dot grade-1 pattern (U+2800-U+283F)")
                .with_actual(format!("U+{cp:04X}"))
                .with_details("Disable strict mode to drop unsupported patterns."));
            }
            continue;
        }
        if let Some((ch, _)) = BRAILLE_LETTERS.iter().find(|(_, m)| *m == mask) {
            out.push(*ch as char);
        } else if let Some((ch, _)) = BRAILLE_PUNCT.iter().find(|(_, m)| *m == mask) {
            out.push(*ch);
        } else if strict {
            return Err(OperationError::decode(format!(
                "unsupported Braille pattern U+{cp:04X} at offset {idx}"
            ))
            .with_expected("a grade-1 letter, digit or punctuation pattern")
            .with_actual(format!("U+{cp:04X}"))
            .with_details("Disable strict mode to drop unsupported patterns."));
        }
    }
    Ok(Value::Text(out))
}

// ------------------------------------------------------------ registry ----

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    use cybercipher_core::Category::Encoding as E;
    use cybercipher_core::ValueKind::Text as T;

    let tag: &'static [&'static str] = &["encoding", "classical", "ctf"];

    reg.add_simple(
        spec(
            "to-morse",
            "To Morse",
            "Encodes text as international Morse code (ITU-R M.1677): letters separated by a \
             single space, words by ` / `. Supports A-Z, 0-9 and a punctuation subset.",
            E,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Fail on characters without a Morse code; relaxed mode drops them.",
            )],
            tag,
            &["morse encode", "morse code"],
            "ITU-R M.1677 international Morse code",
            "Round-trip tests (SOS, words, digits, punctuation)",
        ),
        morse_encode,
    );

    reg.add_simple(
        spec(
            "from-morse",
            "From Morse",
            "Decodes Morse code text: letters separated by spaces, words by `/`. Unknown or \
             malformed sequences are rejected in strict mode.",
            E,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Fail on unknown sequences; relaxed mode drops them.",
            )],
            tag,
            &["morse decode"],
            "ITU-R M.1677 international Morse code",
            "Round-trip tests (SOS, words, digits, punctuation)",
        ),
        morse_decode,
    );

    reg.add_simple(
        spec(
            "to-a1z26",
            "To A1Z26",
            "Encodes letters as their 1-26 alphabet position (A=1 ... Z=26). Numbers are \
             joined by the delimiter, words by the word separator. Non-letters fail in \
             strict mode.",
            E,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![
                p_text(
                    "delimiter",
                    "Delimiter",
                    "-",
                    "Between numbers. Required for unambiguous decoding.",
                ),
                p_text(
                    "word_separator",
                    "Word separator",
                    "/",
                    "Between words, emitted surrounded by spaces.",
                ),
                p_bool(
                    "strict",
                    "Strict",
                    true,
                    "Fail on non-letter characters; relaxed mode drops them.",
                ),
            ],
            tag,
            &["a1z26 encode", "letter numbers", "alphabet position"],
            "Common CTF convention (A=1 ... Z=26)",
            "Round-trip tests",
        ),
        a1z26_encode,
    );

    reg.add_simple(
        spec(
            "from-a1z26",
            "From A1Z26",
            "Decodes A1Z26 numbers back to letters. Delimiter mode is required: every number \
             must be separated by the delimiter (run `12` means the letter L; write `1-2` \
             for AB). Values outside 1-26 are rejected.",
            E,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![
                p_text(
                    "delimiter",
                    "Delimiter",
                    "-",
                    "Between numbers; without it the decode is ambiguous and rejected.",
                ),
                p_text("word_separator", "Word separator", "/", "Between words."),
            ],
            tag,
            &["a1z26 decode"],
            "Common CTF convention (A=1 ... Z=26)",
            "Round-trip tests",
        ),
        a1z26_decode,
    );

    reg.add_simple(
        spec(
            "to-tapcode",
            "To Tap Code",
            "Encodes letters as tap-code dot pairs (row column) on the classic 5x5 square \
             without K: `K` is tapped as `C`. Letters are joined by ` / `.",
            E,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Fail on non-letter characters; relaxed mode drops them.",
            )],
            tag,
            &["tap code encode", "knock code", "polybius tap"],
            "Classic POW tap code convention (5x5 square, K=C)",
            "Round-trip tests",
        ),
        tap_encode,
    );

    reg.add_simple(
        spec(
            "from-tapcode",
            "From Tap Code",
            "Decodes tap-code dot pairs (e.g. `.... ..`) into letters on the classic 5x5 \
             square. `C` decodes to `C`; a tapped K cannot be distinguished from C.",
            E,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![],
            tag,
            &["tap code decode", "knock code decode"],
            "Classic POW tap code convention (5x5 square, K=C)",
            "Round-trip tests",
        ),
        tap_decode,
    );

    reg.add_simple(
        spec(
            "to-bacon",
            "To Bacon",
            "Encodes text as Bacon's bilateral (24-letter) cipher: every letter becomes a \
             5-symbol group of the A and B letters. J merges into I and V into U; other \
             characters fail in strict mode.",
            E,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![
                p_text("letter_a", "A symbol", "A", "Symbol emitted for a 0 bit."),
                p_text("letter_b", "B symbol", "B", "Symbol emitted for a 1 bit."),
                p_bool(
                    "strict",
                    "Strict",
                    true,
                    "Fail on non-letters; relaxed mode drops them.",
                ),
            ],
            tag,
            &["bacon encode", "baconian cipher"],
            "Francis Bacon's bilateral cipher (24-letter alphabet, J/I and V/U merged)",
            "Round-trip tests",
        ),
        bacon_encode,
    );

    reg.add_simple(
        spec(
            "from-bacon",
            "From Bacon",
            "Decodes Bacon 5-symbol groups back into the 24-letter alphabet (`I` and `U` \
             stand for the merged pairs). Group values above 23 are rejected in strict \
             mode.",
            E,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![
                p_text("letter_a", "A symbol", "A", "Symbol read as a 0 bit."),
                p_text("letter_b", "B symbol", "B", "Symbol read as a 1 bit."),
                p_bool(
                    "strict",
                    "Strict",
                    true,
                    "Fail on foreign characters and out-of-range groups; relaxed mode drops them.",
                ),
            ],
            tag,
            &["bacon decode", "baconian decode"],
            "Francis Bacon's bilateral cipher (24-letter alphabet, J/I and V/U merged)",
            "Round-trip tests",
        ),
        bacon_decode,
    );

    reg.add_simple(
        spec(
            "to-braille",
            "To Braille",
            "Encodes text as grade-1 Unicode Braille patterns (U+2800-U+283F): letters A-Z, \
             digits 0-9 (each prefixed with the number sign), space, and a punctuation \
             subset (.,?!'-:;).",
            E,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![
                p_bool(
                    "digit_sign",
                    "Number sign per digit",
                    true,
                    "Emit the number-sign cell before every digit (keeps the encoding reversible).",
                ),
                p_bool(
                    "strict",
                    "Strict",
                    true,
                    "Fail on unsupported characters; relaxed mode drops them.",
                ),
            ],
            tag,
            &["braille encode", "unicode braille", "grade 1 braille"],
            "The Unicode Standard Braille Patterns block (U+2800-U+28FF); grade-1 English conventions",
            "Round-trip tests",
        ),
        braille_encode,
    );

    reg.add_simple(
        spec(
            "from-braille",
            "From Braille",
            "Decodes grade-1 Unicode Braille patterns (U+2800-U+283F) back into text: \
             letters, digits (after a number sign), and the supported punctuation subset. \
             Unknown patterns are rejected in strict mode.",
            E,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![p_bool(
                "strict",
                "Strict",
                true,
                "Fail on unsupported patterns; relaxed mode drops them.",
            )],
            tag,
            &["braille decode"],
            "The Unicode Standard Braille Patterns block (U+2800-U+28FF); grade-1 English conventions",
            "Round-trip tests",
        ),
        braille_decode,
    );
}
