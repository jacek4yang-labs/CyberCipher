//! CTF specialty encodings: Brainfuck (and Ook!), 与佛论禅 (Buddha says),
//! 新佛曰 (new Buddha), 兽音译者 (beast speak), 熊曰 (bear says), 社会主义
//! 核心价值观 (socialist core values), AAEncode and JJEncode.
//!
//! Every algorithm here is ported from a concrete reference implementation and
//! pinned against its vectors (source URLs cited per op and in the tests):
//!
//! - Brainfuck/Ook!: the reference engines shipped with CTF toolboxes
//!   (ToolsFx `BrainfuckEngine`/`OokEngine`, themselves derived from Fabian
//!   M.'s Java interpreter) plus the canonical esolangs Ook! token table.
//! - 与佛论禅: ToolsFx `BuddhaCipher.kt` (AES-256-CBC over UTF-16LE with the
//!   keyfc.net key/IV, byte-mapped onto a 128-character sutra table).
//! - 新佛曰: ToolsFx `BuddhaPbeCipher.kt` (OpenSSL-style `PBEWithMD5and256bit
//!   AES-CBC-OPENSSL`: EVP_BytesToKey(MD5) + AES-256-CBC + base64 mapped onto
//!   a 65-character table; upstream <https://github.com/takuron/talk-with-buddha>).
//! - 兽音: `sgdrg15rdg/beast_js` (the original 兽音译者 engine, mirrored by
//!   `SycAlright/beast_sdk`), cross-checked against `EBCTFCodeBox roar.js`.
//! - 熊曰: raw-DEFLATE + basE91 + a 91-character bear dictionary with a
//!   `熊曰：呋` envelope (verified against reference vectors; same algorithm is
//!   implemented by `EBCTFCodeBox xiongyue.js` and `Abracadabra`).
//! - 核心价值观: hex-per-byte mapped onto the 12-phrase slogan table
//!   (ToolsFx `SocialistCoreValues.kt`).
//! - AAEncode/JJEncode: deterministic, execution-free decoders for the
//!   self-decoding payloads of Yosuke Hasegawa's utf-8.jp reference scripts.
//!   The reference decoders `eval` the payload; CyberCipher instead parses the
//!   escape stream directly (details on each op).

use crate::helpers::{input_text, p_int, p_text, spec};
use cybercipher_core::prelude::*;

// --------------------------------------------------------- Brainfuck ----

/// Default number of tape cells (the de-facto standard 30k tape).
const BF_DEFAULT_CELLS: i64 = 30_000;
/// Upper bound for the `memory_cells` parameter.
const BF_MAX_CELLS: i64 = 1_000_000;
/// Default execution budget: one million steps.
const BF_DEFAULT_STEPS: i64 = 1_000_000;
/// Hard cap for the `max_steps` parameter.
const BF_MAX_STEPS: i64 = 10_000_000;

/// Pre-compute the bracket jump table for a Brainfuck program.
///
/// Returns `jump[i]` = index of the matching bracket for every `[` / `]` in
/// the program. Unmatched brackets produce typed errors; nothing here can
/// panic on arbitrary input.
fn bf_bracket_map(program: &str) -> OpResult<Vec<Option<usize>>> {
    let bytes = program.as_bytes();
    let mut jumps = vec![None; bytes.len()];
    let mut stack: Vec<usize> = Vec::new();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'[' => stack.push(i),
            b']' => {
                let open = stack.pop().ok_or_else(|| {
                    OperationError::decode(format!(
                        "unmatched `]` at byte offset {i}: no preceding `[`"
                    ))
                    .with_expected("balanced `[` before every `]`")
                    .with_actual(format!("`]` at offset {i}"))
                })?;
                jumps[open] = Some(i);
                jumps[i] = Some(open);
            }
            _ => {}
        }
    }
    if let Some(open) = stack.pop() {
        return Err(OperationError::decode(format!(
            "unmatched `[` at byte offset {open}: no closing `]`"
        ))
        .with_expected("balanced `]` after every `[`")
        .with_actual(format!("`[` at offset {open}")));
    }
    Ok(jumps)
}

/// Execute a Brainfuck program with bounded resources.
///
/// Standard 8-op spec: 8-bit wrapping cells, `,` yields 0 at end of input,
/// non-command bytes are comments. Every executed instruction counts as one
/// step; the step budget and tape size are hard limits (never a hang, never a
/// panic).
fn bf_run(program: &str, input: &[u8], cells: usize, max_steps: u64) -> OpResult<Vec<u8>> {
    let jumps = bf_bracket_map(program)?;
    let bytes = program.as_bytes();
    let mut tape = vec![0u8; cells];
    let mut ptr = 0usize;
    let mut pc = 0usize;
    let mut steps: u64 = 0;
    let mut input_pos = 0usize;
    let mut out = Vec::new();
    while pc < bytes.len() {
        steps += 1;
        if steps > max_steps {
            return Err(OperationError::new(
                ErrorKind::BudgetExceeded,
                format!("Brainfuck program exceeded the step budget of {max_steps} steps"),
            )
            .with_details(
                "Increase `max_steps` (hard cap 10,000,000) or shorten the program; \
                 loops that never terminate cannot be executed.",
            ));
        }
        match bytes[pc] {
            b'>' => {
                ptr += 1;
                if ptr >= cells {
                    return Err(OperationError::decode(format!(
                        "data pointer moved past the last cell at program offset {pc}"
                    ))
                    .with_expected(format!("pointer below the tape size ({cells} cells)"))
                    .with_actual(format!("pointer {ptr}"))
                    .with_details(
                        "Increase `memory_cells` or make the program respect the tape bounds.",
                    ));
                }
            }
            b'<' => {
                if ptr == 0 {
                    return Err(OperationError::decode(format!(
                        "data pointer moved below cell 0 at program offset {pc}"
                    ))
                    .with_expected("pointer >= 0")
                    .with_actual("pointer -1"));
                }
                ptr -= 1;
            }
            b'+' => tape[ptr] = tape[ptr].wrapping_add(1),
            b'-' => tape[ptr] = tape[ptr].wrapping_sub(1),
            b'.' => out.push(tape[ptr]),
            b',' => {
                tape[ptr] = input.get(input_pos).copied().unwrap_or(0);
                input_pos += 1;
            }
            b'[' if tape[ptr] == 0 => {
                pc = jumps[pc].expect("bracket map covers every `[`");
            }
            b']' if tape[ptr] != 0 => {
                pc = jumps[pc].expect("bracket map covers every `]`");
            }
            _ => {} // everything else is a comment
        }
        pc += 1;
    }
    Ok(out)
}

/// Generate a Brainfuck program that prints `data` (UTF-8 bytes).
///
/// Single-cell delta encoder: the cell always holds the previous byte, so the
/// program only needs `+`/`-`/`.`. Deterministic and at most 128 signs per
/// byte.
fn bf_generate(data: &[u8]) -> String {
    let mut program = String::with_capacity(data.len() * 8);
    let mut prev = 0u8;
    for &b in data {
        let forward = b.wrapping_sub(prev);
        let (count, sign) = if forward <= 128 {
            (forward, '+')
        } else {
            (b.wrapping_sub(prev).wrapping_neg(), '-')
        };
        for _ in 0..count {
            program.push(sign);
        }
        program.push('.');
        prev = b;
    }
    program
}

/// Canonical Ook! token table (esolangs Ook! spec; identical to the
/// `OokEngine` token map in reference CTF toolboxes). `OOK_MAP[(a, b)]` maps
/// the token pair "Ook<a> Ook<b>" onto the Brainfuck command.
const OOK_MAP: [(char, char, u8); 8] = [
    ('.', '?', b'>'),
    ('?', '.', b'<'),
    ('.', '.', b'+'),
    ('!', '!', b'-'),
    ('!', '.', b'.'),
    ('.', '!', b','),
    ('!', '?', b'['),
    ('?', '!', b']'),
];

/// Translate an Ook! program into Brainfuck. Tokens are recognized
/// case-insensitively ("Ook", "OOK" and "ook" all appear in the wild);
/// anything that is not whitespace or an `Ook` token is a typed error.
fn ook_to_bf(text: &str) -> OpResult<String> {
    let mut symbols = String::new();
    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if lower[i..].starts_with("ook") {
            i += 3;
            match bytes.get(i) {
                Some(&c @ (b'.' | b'!' | b'?')) => {
                    symbols.push(c as char);
                    i += 1;
                }
                _ => {
                    return Err(OperationError::decode(format!(
                        "`ook` token at byte offset {i} is not followed by `.`, `!` or `?`"
                    ))
                    .with_expected("Ook. / Ook! / Ook? token pairs")
                    .with_actual("dangling `ook`"));
                }
            }
        } else {
            return Err(OperationError::decode(format!(
                "character at byte offset {i} is not part of an Ook! token"
            ))
            .with_expected("Ook. / Ook! / Ook? token pairs")
            .with_actual(format!("byte 0x{:02x}", bytes[i])));
        }
    }
    if symbols.is_empty() {
        return Err(OperationError::decode("no Ook! tokens found in input")
            .with_expected("Ook. / Ook! / Ook? token pairs")
            .with_actual("empty token stream"));
    }
    if !symbols.len().is_multiple_of(2) {
        return Err(OperationError::decode(
            "Ook! programs are token pairs, but the input has an odd token count",
        )
        .with_expected("even number of Ook tokens")
        .with_actual(format!("{} tokens", symbols.len())));
    }
    let mut bf = String::with_capacity(symbols.len() / 2);
    for pair in symbols.as_bytes().chunks(2) {
        let a = pair[0] as char;
        let b = pair[1] as char;
        match OOK_MAP.iter().find(|(x, y, _)| *x == a && *y == b) {
            Some((_, _, op)) => bf.push(*op as char),
            None => {
                return Err(OperationError::decode(format!(
                    "invalid Ook! token pair `Ook{a} Ook{b}`"
                ))
                .with_expected("one of the 8 canonical Ook! token pairs")
                .with_actual(format!("Ook{a} Ook{b}")));
            }
        }
    }
    Ok(bf)
}

/// Render a Brainfuck program as an Ook! program (1:1 token mapping).
fn bf_to_ook(program: &str) -> String {
    let mut out = String::new();
    for c in program.chars() {
        if let Some((x, y)) = OOK_MAP
            .iter()
            .find(|(_, _, op)| *op as char == c)
            .map(|(x, y, _)| (*x, *y))
        {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(&format!("Ook{x} Ook{y}"));
        }
    }
    out
}

fn bf_limits(map: &ParamMap) -> OpResult<(usize, u64)> {
    let cells = map.int_or("memory_cells", BF_DEFAULT_CELLS);
    if !(1..=BF_MAX_CELLS).contains(&cells) {
        return Err(OperationError::invalid_param(
            "memory_cells",
            format!("`memory_cells` must be between 1 and {BF_MAX_CELLS}"),
        ));
    }
    let steps = map.int_or("max_steps", BF_DEFAULT_STEPS);
    if !(1..=BF_MAX_STEPS).contains(&steps) {
        return Err(OperationError::invalid_param(
            "max_steps",
            format!("`max_steps` must be between 1 and {BF_MAX_STEPS}"),
        ));
    }
    Ok((cells as usize, steps as u64))
}

fn run_brainfuck_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let program = input_text(v, "Run Brainfuck")?;
    let (cells, steps) = bf_limits(map)?;
    let input = map.str_or("input", "").as_bytes().to_vec();
    let out = bf_run(program, &input, cells, steps)?;
    Ok(Value::from_bytes(out))
}

fn to_brainfuck_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let _ = map;
    let text = input_text(v, "To Brainfuck")?;
    Ok(Value::Text(bf_generate(text.as_bytes())))
}

fn from_ook_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From Ook!")?;
    let (cells, steps) = bf_limits(map)?;
    let input = map.str_or("input", "").as_bytes().to_vec();
    let program = ook_to_bf(text)?;
    let out = bf_run(&program, &input, cells, steps)?;
    Ok(Value::from_bytes(out))
}

fn to_ook_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let _ = map;
    let text = input_text(v, "To Ook!")?;
    let program = bf_generate(text.as_bytes());
    Ok(Value::Text(bf_to_ook(&program)))
}

// ------------------------------------------------- Buddha (与佛论禅) ----

/// keyfc.net 与佛论禅 AES key/IV (ToolsFx `BuddhaCipher.kt`).
const BUDDHA_KEY: &[u8; 32] = b"XDXDtudou@KeyFansClub^_^Encode!!";
const BUDDHA_IV: &[u8; 16] = b"Potato@Key@_@=_=";

/// 128-entry sutra table: table index = low 7 bits of the ciphertext byte.
const BUDDHA_BYTE_MAP: &str = "滅苦婆娑耶陀跋多漫都殿悉夜爍帝吉利阿無南那怛喝羯勝摩伽謹波者穆僧室藝尼瑟地彌菩提蘇醯盧呼舍佛參沙伊隸麼遮闍度蒙孕薩夷迦他姪豆特逝朋輸楞栗寫數曳諦羅曰咒即密若般故不實真訶切一除能等是上明大神知三藐耨得依諸世槃涅竟究想夢倒顛離遠怖恐有礙心所以亦智道。集盡死老至";

/// 11 marker characters emitted before a high (>= 0x80) ciphertext byte; the
/// reference picks one at random, CyberCipher always emits the first one to
/// stay deterministic.
const BUDDHA_HIGH_MARKERS: &str = "奢梵呐俱哆怯諳罰侄缽皤";

const BUDDHA_HEADER: &str = "佛曰：";
const BUDDHA_MO_HEADER: &str = "魔曰：";

/// AES-256-CBC with PKCS#7 padding (hand-wired over the `aes` block cipher;
/// the mode is 15 lines and validated against NIST SP 800-38A below).
mod cbc {
    use aes::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

    type AesBlock = Block<aes::Aes256>;

    pub fn encrypt(key: &[u8], iv: &[u8], padded: &mut [u8]) {
        let cipher = aes::Aes256::new_from_slice(key).expect("AES-256 key is 32 bytes");
        let mut prev = [0u8; 16];
        prev.copy_from_slice(iv);
        for chunk in padded.as_chunks_mut::<16>().0 {
            let slice: &mut [u8] = chunk;
            let block: &mut AesBlock = slice.try_into().expect("chunk is 16 bytes");
            for (a, b) in block.iter_mut().zip(prev.iter()) {
                *a ^= *b;
            }
            cipher.encrypt_block(block);
            prev.copy_from_slice(block);
        }
    }

    pub fn decrypt(key: &[u8], iv: &[u8], data: &mut [u8]) {
        let cipher = aes::Aes256::new_from_slice(key).expect("AES-256 key is 32 bytes");
        let mut prev = [0u8; 16];
        prev.copy_from_slice(iv);
        for chunk in data.as_chunks_mut::<16>().0 {
            let mut out = [0u8; 16];
            out.copy_from_slice(chunk);
            {
                let slice: &mut [u8] = &mut out;
                let block: &mut AesBlock = slice.try_into().expect("16 bytes");
                cipher.decrypt_block(block);
                for (a, b) in block.iter_mut().zip(prev.iter()) {
                    *a ^= *b;
                }
            }
            prev.copy_from_slice(chunk);
            chunk.copy_from_slice(&out);
        }
    }
}

/// Strip PKCS#7 padding (block size 16). Strict: every pad byte must match.
fn pkcs7_unpad(data: &[u8]) -> OpResult<&[u8]> {
    let Some(&pad) = data.last() else {
        return Err(OperationError::decode("cannot unpad empty ciphertext")
            .with_expected("at least one AES block"));
    };
    let pad = pad as usize;
    if pad == 0 || pad > 16 || pad > data.len() {
        return Err(
            OperationError::decode(format!("invalid PKCS#7 padding byte {pad}"))
                .with_expected("padding bytes in 1..=16 matching the pad length")
                .with_actual(format!("trailing byte {pad}")),
        );
    }
    if data[data.len() - pad..].iter().any(|&b| b as usize != pad) {
        return Err(OperationError::decode(
            "corrupt ciphertext: PKCS#7 padding bytes are inconsistent (wrong key?)",
        )
        .with_expected("all trailing bytes equal to the pad length")
        .with_actual("mismatched padding"));
    }
    Ok(&data[..data.len() - pad])
}

fn pkcs7_pad(data: &mut Vec<u8>) {
    let pad = 16 - (data.len() % 16);
    data.extend(std::iter::repeat_n(pad as u8, pad));
}

fn utf16le_from_bytes(bytes: &[u8]) -> OpResult<String> {
    if !bytes.len().is_multiple_of(2) {
        return Err(OperationError::decode(
            "decrypted data has an odd byte count and cannot be UTF-16LE",
        )
        .with_expected("even-length UTF-16LE plaintext")
        .with_actual(format!("{} bytes", bytes.len())));
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16(&units)
        .map_err(|_| OperationError::decode("decrypted data is not valid UTF-16 text"))
}

fn to_buddha_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let _ = map;
    let text = input_text(v, "To Buddha")?;
    let mut data: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    pkcs7_pad(&mut data);
    cbc::encrypt(BUDDHA_KEY, BUDDHA_IV, &mut data);
    let table: Vec<char> = BUDDHA_BYTE_MAP.chars().collect();
    let marker = BUDDHA_HIGH_MARKERS
        .chars()
        .next()
        .expect("marker table is non-empty");
    let mut out = String::from(BUDDHA_HEADER);
    for &b in &data {
        if b < 0x80 {
            out.push(table[b as usize]);
        } else {
            out.push(marker);
            out.push(table[(b - 0x80) as usize]);
        }
    }
    Ok(Value::Text(out))
}

fn from_buddha_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let _ = map;
    let text = input_text(v, "From Buddha")?;
    let trimmed = text.trim();
    let (raw_body, reversed) = if let Some(rest) = trimmed.strip_prefix(BUDDHA_MO_HEADER) {
        (rest, true)
    } else if let Some(rest) = trimmed.strip_prefix("魔曰:") {
        (rest, true)
    } else if let Some(rest) = trimmed.strip_prefix(BUDDHA_HEADER) {
        (rest, false)
    } else if let Some(rest) = trimmed.strip_prefix("佛曰:") {
        (rest, false)
    } else {
        return Err(OperationError::decode(
            "Buddha ciphertext must start with `佛曰：` or `魔曰：`",
        )
        .with_expected("the 与佛论禅 header")
        .with_actual(format!(
            "prefix `{}`",
            trimmed.chars().take(3).collect::<String>()
        )));
    };
    let body: String = if reversed {
        raw_body.chars().rev().collect()
    } else {
        raw_body.to_string()
    };
    let table: Vec<char> = BUDDHA_BYTE_MAP.chars().collect();
    let mut ciphertext: Vec<u8> = Vec::with_capacity(body.len() / 2);
    let mut high = false;
    for c in body.chars() {
        if let Some(pos) = table.iter().position(|&t| t == c) {
            ciphertext.push(pos as u8 + if high { 0x80 } else { 0 });
            high = false;
        } else {
            // The reference treats any non-table character as a "high bit"
            // marker for the next table character (the 10-char marker set is
            // disjoint from the table); whitespace and the random marker
            // characters are therefore tolerated.
            high = true;
        }
    }
    if ciphertext.is_empty() {
        return Err(
            OperationError::decode("no Buddha table characters found after the header")
                .with_expected("ciphertext over the sutra table"),
        );
    }
    if !ciphertext.len().is_multiple_of(16) {
        return Err(OperationError::length(
            "a multiple of 16 mapped bytes",
            format!("{} mapped bytes", ciphertext.len()),
            "Buddha ciphertext does not align to AES blocks",
        ));
    }
    cbc::decrypt(BUDDHA_KEY, BUDDHA_IV, &mut ciphertext);
    let padded = pkcs7_unpad(&ciphertext)?;
    Ok(Value::Text(utf16le_from_bytes(padded)?))
}

// ----------------------------------------------- New Buddha (新佛曰) ----

/// Base64 alphabet order of the 新佛曰 table (ToolsFx `BuddhaPbeCipher.kt`,
/// upstream <https://github.com/takuron/talk-with-buddha>).
const BUDDHA_PBE_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const BUDDHA_PBE_TABLE: &str = "埵孕唵呼羯蒙沙谨吉度俱尼喝佛迦豆地墀驮提伊伽烁阇他遮摩无陀阿啰醯罚那耶哆怛萨卢娑诃南室悉夜婆唎菩帝皤嚧利穆参舍苏钵曳数写栗楞咩输漫";
const BUDDHA_PBE_HEADER: &str = "佛又曰：";
const BUDDHA_PBE_DEFAULT_PASSWORD: &str = "takuron.top";
/// Upstream generates a random 8-byte salt per message; CyberCipher requires
/// an explicit salt so the operation stays deterministic. Every salt is
/// decodable by the reference implementation.
const BUDDHA_PBE_DEFAULT_SALT_HEX: &str = "0001020304050607";

/// OpenSSL `EVP_BytesToKey` with MD5 and one iteration: the exact key
/// schedule of `PBEWithMD5and256bitAES-CBC-OPENSSL` (key 32 bytes + IV 16).
fn evp_bytestokey_md5(password: &[u8], salt: &[u8]) -> ([u8; 32], [u8; 16]) {
    use md5::Digest;
    let mut out = Vec::with_capacity(64);
    let mut prev: Option<[u8; 16]> = None;
    while out.len() < 48 {
        let mut hasher = md5::Md5::new();
        if let Some(p) = prev {
            hasher.update(p);
        }
        hasher.update(password);
        hasher.update(salt);
        let block: [u8; 16] = hasher.finalize().into();
        out.extend_from_slice(&block);
        prev = Some(block);
    }
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&out[..32]);
    iv.copy_from_slice(&out[32..48]);
    (key, iv)
}

fn pbe_table_index(c: char) -> OpResult<usize> {
    BUDDHA_PBE_TABLE
        .chars()
        .position(|t| t == c)
        .ok_or_else(|| {
            OperationError::decode(format!("character `{c}` is not in the 新佛曰 table"))
                .with_expected("one of the 65 新佛曰 table characters")
                .with_actual(format!("`{c}`"))
        })
}

fn to_buddha_pbe_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    use base64::Engine;
    let text = input_text(v, "To Buddha PBE")?;
    let password = map.str_or("password", BUDDHA_PBE_DEFAULT_PASSWORD);
    let salt_raw = map.str_or("salt", BUDDHA_PBE_DEFAULT_SALT_HEX).trim();
    let salt = hex_decode_param(salt_raw, "salt", 8)?;
    let (key, iv) = evp_bytestokey_md5(password.as_bytes(), &salt);
    let mut data = text.as_bytes().to_vec();
    pkcs7_pad(&mut data);
    cbc::encrypt(&key, &iv, &mut data);
    let mut envelope = b"Salted__".to_vec();
    envelope.extend_from_slice(&salt);
    envelope.extend_from_slice(&data);
    let mut b64 = base64::engine::general_purpose::STANDARD.encode(envelope);
    // The reference drops the first 10 base64 characters (which encode the
    // fixed `Salted__` magic plus two salt bits) and re-adds `U2FsdGVkX1`
    // during decode.
    b64.replace_range(..10, "");
    let mut out = String::from(BUDDHA_PBE_HEADER);
    for c in b64.bytes() {
        let idx = BUDDHA_PBE_ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or_else(|| OperationError::internal("base64 emitted a non-alphabet byte"))?;
        out.push(
            BUDDHA_PBE_TABLE
                .chars()
                .nth(idx)
                .expect("table has 65 entries"),
        );
    }
    Ok(Value::Text(out))
}

fn from_buddha_pbe_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    use base64::Engine;
    let text = input_text(v, "From Buddha PBE")?;
    let password = map.str_or("password", BUDDHA_PBE_DEFAULT_PASSWORD);
    let body = text.trim();
    let body = body
        .strip_prefix(BUDDHA_PBE_HEADER)
        .or_else(|| body.strip_prefix("佛又曰:"))
        .ok_or_else(|| {
            OperationError::decode("new Buddha ciphertext must start with `佛又曰：`")
                .with_expected("the 新佛曰 header")
                .with_actual(format!(
                    "prefix `{}`",
                    body.chars().take(4).collect::<String>()
                ))
        })?;
    let mut b64 = String::from("U2FsdGVkX1");
    for c in body.chars() {
        if c.is_whitespace() {
            continue;
        }
        b64.push(
            BUDDHA_PBE_ALPHABET
                .get(pbe_table_index(c)?)
                .copied()
                .expect("alphabet index is in range") as char,
        );
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| {
            OperationError::decode(format!("mapped payload is not valid base64: {e}"))
                .with_details("The ciphertext may be truncated or use a different variant.")
        })?;
    if raw.len() < 8 + 8 + 16 || &raw[..8] != b"Salted__" {
        return Err(OperationError::decode(
            "payload does not carry the OpenSSL `Salted__` envelope",
        )
        .with_expected("Salted__ + 8-byte salt + ciphertext"));
    }
    let salt = &raw[8..16];
    let ciphertext = &raw[16..];
    let (key, iv) = evp_bytestokey_md5(password.as_bytes(), salt);
    let mut buf = ciphertext.to_vec();
    cbc::decrypt(&key, &iv, &mut buf);
    let padded = pkcs7_unpad(&buf)?;
    String::from_utf8(padded.to_vec())
        .map(Value::Text)
        .map_err(|_| {
            OperationError::decode("decrypted data is not valid UTF-8 (wrong password?)")
                .with_expected("UTF-8 plaintext")
        })
}

/// Decode a hex parameter of exact expected length.
fn hex_decode_param(raw: &str, param: &str, expected_len: usize) -> OpResult<Vec<u8>> {
    let clean: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    let expected_chars = expected_len * 2;
    if clean.len() != expected_chars || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(OperationError::invalid_param(
            param,
            format!("`{param}` must be {expected_len} bytes of hex ({expected_chars} characters)"),
        )
        .with_actual(format!("`{raw}`")));
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| OperationError::invalid_param(param, format!("invalid hex: {e}")))
}

// ------------------------------------------------ Beast (兽音译者) ----

/// Default codec `嗷呜啊~` (sgdrg15rdg/beast_js, mirrored by
/// SycAlright/beast_sdk). Custom 4-character codecs are supported, matching
/// the upstream "customize the beast array" feature.
const BEAST_DEFAULT_CODEC: &str = "嗷呜啊~";

fn beast_codec_param(map: &ParamMap) -> OpResult<Vec<char>> {
    let codec: Vec<char> = map.str_or("codec", BEAST_DEFAULT_CODEC).chars().collect();
    if codec.len() != 4 || {
        let mut sorted = codec.clone();
        sorted.sort();
        sorted.dedup();
        sorted.len() != 4
    } {
        return Err(OperationError::invalid_param(
            "codec",
            "the beast codec must be exactly 4 distinct characters",
        )
        .with_actual(format!("{} characters", codec.len())));
    }
    Ok(codec)
}

fn to_beast_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "To Beast")?;
    let codec = beast_codec_param(map)?;
    let mut out = String::new();
    out.push(codec[3]);
    out.push(codec[1]);
    out.push(codec[0]);
    for (i, unit) in text.encode_utf16().enumerate() {
        for k in 0..4 {
            let shift = 12 - k * 4;
            let nib = ((unit >> shift) & 0xF) as usize;
            let pos = i * 4 + k;
            let value = (nib + pos % 16) % 16;
            out.push(codec[value / 4]);
            out.push(codec[value % 4]);
        }
    }
    out.push(codec[2]);
    Ok(Value::Text(out))
}

fn from_beast_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let text = input_text(v, "From Beast")?;
    let codec = beast_codec_param(map)?;
    let body = text.trim();
    let prefix: String = codec[3].to_string() + &codec[1].to_string() + &codec[0].to_string();
    let suffix = codec[2];
    let middle: &str = if let Some(rest) = body.strip_prefix(prefix.as_str()) {
        rest.strip_suffix(suffix).ok_or_else(|| {
            OperationError::decode(format!(
                "beast ciphertext has the `{prefix}` prefix but is missing the `{suffix}` suffix"
            ))
            .with_expected(format!("`{prefix}…{suffix}`"))
        })?
    } else {
        // Bare form (SycAlright/beast_sdk `encode`): middle only.
        body
    };
    let chars: Vec<char> = middle.chars().collect();
    if !chars.len().is_multiple_of(2) {
        return Err(OperationError::length(
            "an even number of codec characters",
            format!("{} characters", chars.len()),
            "beast ciphertext payload is truncated",
        ));
    }
    let mut units: Vec<u16> = Vec::with_capacity(chars.len() / 8);
    for (pair, chunk) in chars.chunks(2).enumerate() {
        let hi = codec.iter().position(|&c| c == chunk[0]).ok_or_else(|| {
            OperationError::decode(format!(
                "character `{}` is not in the beast codec",
                chunk[0]
            ))
            .with_expected("characters from the codec table")
        })?;
        let lo = codec.iter().position(|&c| c == chunk[1]).ok_or_else(|| {
            OperationError::decode(format!(
                "character `{}` is not in the beast codec",
                chunk[1]
            ))
            .with_expected("characters from the codec table")
        })?;
        let value = (hi * 4 + lo + 16 - pair % 16) % 16;
        let slot = pair % 4;
        let shift = match slot {
            0 => 12,
            1 => 8,
            2 => 4,
            _ => 0,
        };
        if slot == 0 {
            units.push(0);
        }
        let last = units.last_mut().expect("slot 0 always pushes a unit first");
        *last |= (value << shift) as u16;
    }
    String::from_utf16(&units).map(Value::Text).map_err(|_| {
        OperationError::decode("decoded code units are not valid UTF-16")
            .with_expected("valid UTF-16 code units")
    })
}

// -------------------------------------------------- Bear (熊曰) ----

/// 91-character bear dictionary (order-sensitive; indices are basE91 values).
const BEAR_DICT: &str = "食性很雜既溫和會誘捕動物家住山洞沒有冬眠偶爾襲擊人類呱哞嗄哈嘍啽唬咯呦嗷嗡哮嗥嗒嗚吖吃嗅嘶噔咬噗嘿嚁噤囑非常喜歡堅果魚肉蜂蜜註取象發達你覺出更盜森氏我誒怎寶麼圖現破嚄告訴樣呆萌笨拙意";
const BEAR_HEADER: &str = "熊曰：";
const BEAR_MARKER: char = '呋';

fn base91_encode_values(data: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    let mut b: u32 = 0;
    let mut n: u32 = 0;
    for &byte in data {
        b |= (byte as u32) << n;
        n += 8;
        if n > 13 {
            let mut v = b & 8191;
            if v > 88 {
                b >>= 13;
                n -= 13;
            } else {
                v = b & 16383;
                b >>= 14;
                n -= 14;
            }
            out.push(v % 91);
            out.push(v / 91);
        }
    }
    if n > 0 {
        out.push(b % 91);
        if n > 7 || b > 90 {
            out.push(b / 91);
        }
    }
    out
}

fn base91_decode_values(values: &[u32]) -> OpResult<Vec<u8>> {
    let mut out = Vec::new();
    let mut b: u64 = 0;
    let mut n: u32 = 0;
    let mut pending: Option<u32> = None;
    for &val in values {
        let Some(v0) = pending else {
            pending = Some(val);
            continue;
        };
        pending = None;
        let v = v0 as u64 + val as u64 * 91;
        b += v << n;
        n += if (v & 8191) > 88 { 13 } else { 14 };
        while n > 7 {
            out.push((b & 0xff) as u8);
            b >>= 8;
            n -= 8;
        }
    }
    if let Some(v0) = pending {
        out.push((b + ((v0 as u64) << n)) as u8);
    }
    Ok(out)
}

fn to_bear_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    use std::io::Write;
    let _ = map;
    let text = input_text(v, "To Bear")?;
    let dict: Vec<char> = BEAR_DICT.chars().collect();
    // Raw DEFLATE (no zlib/gzip framing). The upstream tool compresses at
    // level 1; any level decodes identically, so CyberCipher uses the default.
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(text.as_bytes())
        .map_err(|e| OperationError::internal(format!("deflate write failed: {e}")))?;
    let compressed = encoder
        .finish()
        .map_err(|e| OperationError::internal(format!("deflate finish failed: {e}")))?;
    let values = base91_encode_values(&compressed);
    let mut mapped: Vec<char> = values.iter().map(|&v| dict[v as usize]).collect();
    mapped.reverse();
    let mut out = String::from(BEAR_HEADER);
    out.push(BEAR_MARKER);
    out.extend(mapped);
    Ok(Value::Text(out))
}

fn from_bear_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    use std::io::Read;
    let _ = map;
    let text = input_text(v, "From Bear")?;
    let body = text.trim();
    let body = body
        .strip_prefix(BEAR_HEADER)
        .or_else(|| body.strip_prefix("熊曰:"))
        .ok_or_else(|| {
            OperationError::decode("bear ciphertext must start with `熊曰：`")
                .with_expected("the 熊曰 header")
                .with_actual(format!(
                    "prefix `{}`",
                    body.chars().take(3).collect::<String>()
                ))
        })?;
    let body = body.strip_prefix(BEAR_MARKER).ok_or_else(|| {
        OperationError::decode(format!(
            "missing the `{BEAR_MARKER}` marker after the bear header"
        ))
        .with_expected(format!("`{BEAR_HEADER}{BEAR_MARKER}…`"))
    })?;
    let dict: Vec<char> = BEAR_DICT.chars().collect();
    let mut values: Vec<u32> = Vec::with_capacity(body.len());
    for c in body.chars().rev() {
        let idx = dict.iter().position(|&d| d == c).ok_or_else(|| {
            OperationError::decode(format!("character `{c}` is not in the bear dictionary"))
                .with_expected("one of the 91 bear dictionary characters")
                .with_actual(format!("`{c}`"))
        })?;
        values.push(idx as u32);
    }
    let compressed = base91_decode_values(&values)?;
    let mut decoder = flate2::read::DeflateDecoder::new(compressed.as_slice());
    let mut plain = Vec::new();
    decoder.read_to_end(&mut plain).map_err(|e| {
        OperationError::decode(format!("raw-deflate payload is corrupt: {e}"))
            .with_details("The bear ciphertext may be truncated or altered.")
    })?;
    String::from_utf8(plain).map(Value::Text).map_err(|_| {
        OperationError::decode("decompressed bear payload is not valid UTF-8")
            .with_expected("UTF-8 plaintext")
    })
}

// ------------------------- Socialist core values (社会主义核心价值观) ----

/// The 12 two-character phrases, in slogan order (ToolsFx
/// `SocialistCoreValues.kt`). Digit `d` of the UTF-8 hex form maps to phrase
/// `d`; hex digits A-F are encoded as phrase 10 (or 11) followed by a
/// disambiguating phrase.
const SOCIALISM_PHRASES: [&str; 12] = [
    "富强", "民主", "文明", "和谐", "自由", "平等", "公正", "法治", "爱国", "敬业", "诚信", "友善",
];

fn to_core_values_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let _ = map;
    let text = input_text(v, "To Core Values")?;
    let hex: String = text.as_bytes().iter().map(|b| format!("{b:02X}")).collect();
    let mut out = String::new();
    for c in hex.chars() {
        let digit = c.to_digit(16).expect("hex digit") as usize;
        if digit < 10 {
            out.push_str(SOCIALISM_PHRASES[digit]);
        } else {
            // Deterministic choice: marker phrase 10 (诚信) + phrase
            // (digit - 10). The reference randomizes between markers 10 and
            // 11; both decode identically.
            out.push_str(SOCIALISM_PHRASES[10]);
            out.push_str(SOCIALISM_PHRASES[digit - 10]);
        }
    }
    Ok(Value::Text(out))
}

fn from_core_values_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let _ = map;
    let text = input_text(v, "From Core Values")?;
    let body = text.trim();
    let chars: Vec<char> = body.chars().collect();
    if !chars.len().is_multiple_of(2) {
        return Err(OperationError::length(
            "an even number of characters (2 per phrase)",
            format!("{} characters", chars.len()),
            "core-values ciphertext is truncated",
        ));
    }
    let mut hex = String::new();
    let mut marker: Option<usize> = None;
    for chunk in chars.chunks(2) {
        let phrase: String = chunk.iter().collect();
        let idx = SOCIALISM_PHRASES
            .iter()
            .position(|&p| p == phrase)
            .ok_or_else(|| {
                OperationError::decode(format!(
                    "character pair `{phrase}` is not one of the 12 socialist core values phrases"
                ))
                .with_expected("富强民主文明和谐自由平等公正法治爱国敬业诚信友善")
                .with_actual(format!("`{phrase}`"))
            })?;
        if idx < 10 {
            match marker {
                None => hex.push(char::from_digit(idx as u32, 16).expect("digit < 10")),
                Some(10) => hex.push(char::from_digit(idx as u32 + 10, 16).expect("digit < 16")),
                Some(11) => hex.push(char::from_digit((idx + 6) as u32, 16).expect("digit < 16")),
                Some(_) => unreachable!("marker is only set to 10 or 11"),
            }
            marker = None;
        } else {
            marker = Some(idx);
        }
    }
    if marker.is_some() {
        return Err(OperationError::decode(
            "core-values ciphertext ends with a dangling marker phrase",
        )
        .with_expected("a digit phrase after each A-F marker"));
    }
    if !hex.len().is_multiple_of(2) {
        return Err(OperationError::decode(
            "core-values decode produced an odd number of hex digits",
        ));
    }
    let bytes: OpResult<Vec<u8>> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| unreachable!("validated hex")))
        .collect();
    match bytes {
        Ok(bytes) => String::from_utf8(bytes).map(Value::Text).map_err(|_| {
            OperationError::decode("core-values decode is not valid UTF-8")
                .with_expected("UTF-8 plaintext")
        }),
        Err(e) => Err(e),
    }
}

// ------------------------------------------------------- AAEncode ----

/// The 16 emoticon expressions that evaluate to the digits 0-F in the
/// aaencode payload (reference: utf-8.jp `aaencode`).
const AA_DIGIT_EXPRS: [&str; 16] = [
    "(c^_^o)",
    "(ﾟΘﾟ)",
    "((o^_^o) - (ﾟΘﾟ))",
    "(o^_^o)",
    "(ﾟｰﾟ)",
    "((ﾟｰﾟ) + (ﾟΘﾟ))",
    "((o^_^o) +(o^_^o))",
    "((ﾟｰﾟ) + (o^_^o))",
    "((ﾟｰﾟ) + (ﾟｰﾟ))",
    "((ﾟｰﾟ) + (ﾟｰﾟ) + (ﾟΘﾟ))",
    "(ﾟДﾟ) .ﾟωﾟﾉ",
    "(ﾟДﾟ) .ﾟΘﾟﾉ",
    "(ﾟДﾟ) ['c']",
    "(ﾟДﾟ) .ﾟｰﾟﾉ",
    "(ﾟДﾟ) .ﾟДﾟﾉ",
    "(ﾟДﾟ) [ﾟΘﾟ]",
];
/// Start of a new JS string escape (`\`).
const AA_ESCAPE_MARKER: &str = "(ﾟДﾟ)[ﾟεﾟ]";
/// The `u` of a `\uXXXX` escape.
const AA_U_EXPR: &str = "(oﾟｰﾟo)";
/// The payload is sandwiched between this fixed preamble tail and postamble.
const AA_PAYLOAD_START: &str = "(ﾟДﾟ) ['_'] ( (ﾟДﾟ) ['_'] (ﾟεﾟ+(ﾟДﾟ)[ﾟoﾟ]+";
const AA_PAYLOAD_END: &str = "(ﾟДﾟ)[ﾟoﾟ]) (ﾟΘﾟ)) ('_');";

/// Decode an AAEncode payload WITHOUT executing any JavaScript.
///
/// The reference `aadecode` evals a self-decoding script; the data itself,
/// however, is a plain sequence of JS string escapes (`\ooo` octal for
/// code units <= 127, `\uXXXX` for the rest) spelled with the emoticon digit
/// expressions above. CyberCipher parses that escape stream directly and
/// reconstructs the original text from its UTF-16 code units — the exact
/// value the reference's inner `Function("return \"…\"")` would produce,
/// without ever evaluating it.
fn aa_decode_text(input: &str) -> OpResult<String> {
    let trimmed = input.trim();
    let start_idx = trimmed.find(AA_PAYLOAD_START).ok_or_else(|| {
        OperationError::decode("input is not AAEncode (preamble not found)")
            .with_expected("an aaencode payload built by utf-8.jp aaencode")
    })?;
    let rest = &trimmed[start_idx + AA_PAYLOAD_START.len()..];
    if !rest.ends_with(AA_PAYLOAD_END) {
        return Err(OperationError::decode(
            "input is not AAEncode (postamble not found or payload truncated)",
        )
        .with_expected("the payload to end with the aaencode postamble"));
    }
    let payload = &rest[..rest.len() - AA_PAYLOAD_END.len()];

    let mut tokens: Vec<&str> = vec![AA_ESCAPE_MARKER, AA_U_EXPR];
    tokens.extend_from_slice(&AA_DIGIT_EXPRS);
    // Longest match first keeps the multi-character expressions unambiguous
    // (every expression is distinguishable at its first character, but sorting
    // by length makes that property explicit).
    tokens.sort_by_key(|t| std::cmp::Reverse(t.len()));

    let mut units: Vec<u16> = Vec::new();
    let mut mode: Option<char> = None; // None, 'o' (octal), 'u' (unicode)
    let mut oct_digits = String::new();
    let mut hex_digits = String::new();
    let mut pos = 0usize;
    while pos < payload.len() {
        let c = payload.as_bytes()[pos];
        if c == b'+' || c == b' ' || c == b'\r' || c == b'\n' || c == b'\t' {
            pos += 1;
            continue;
        }
        let matched = tokens
            .iter()
            .find(|t| payload[pos..].starts_with(*t))
            .copied()
            .ok_or_else(|| {
                OperationError::decode(format!(
                    "unexpected emoticon expression at payload offset {pos}"
                ))
                .with_expected("aaencode digit expressions")
                .with_actual(format!(
                    "`{}`",
                    payload[pos..].chars().take(24).collect::<String>()
                ))
            })?;
        pos += matched.len();
        if matched == AA_ESCAPE_MARKER {
            if mode == Some('o') && !oct_digits.is_empty() {
                push_octal(&mut units, &oct_digits)?;
                oct_digits.clear();
            }
            if mode == Some('u') {
                return Err(OperationError::decode(
                    "aaencode payload contains an unterminated \\uXXXX escape",
                ));
            }
            mode = Some('o');
        } else if matched == AA_U_EXPR {
            if mode == Some('o') && !oct_digits.is_empty() {
                push_octal(&mut units, &oct_digits)?;
                oct_digits.clear();
            }
            mode = Some('u');
            hex_digits.clear();
        } else {
            let value = AA_DIGIT_EXPRS
                .iter()
                .position(|t| *t == matched)
                .expect("matched token comes from the digit table");
            match mode {
                Some('o') => oct_digits.push(std::char::from_digit(value as u32, 16).unwrap()),
                Some('u') => {
                    hex_digits.push(std::char::from_digit(value as u32, 16).unwrap());
                    if hex_digits.len() == 4 {
                        let unit = u16::from_str_radix(&hex_digits, 16)
                            .map_err(|_| unreachable!("4 hex digits"))?;
                        units.push(unit);
                        hex_digits.clear();
                        mode = None;
                    }
                }
                _ => {
                    return Err(OperationError::decode(
                        "aaencode payload has a digit expression outside of an escape sequence",
                    ));
                }
            }
        }
    }
    if mode == Some('u') {
        return Err(OperationError::decode(
            "aaencode payload ends inside a \\uXXXX escape",
        ));
    }
    if mode == Some('o') && !oct_digits.is_empty() {
        push_octal(&mut units, &oct_digits)?;
    }
    String::from_utf16(&units).map_err(|_| {
        OperationError::decode("aaencode payload decodes to invalid UTF-16 (lone surrogates)")
            .with_expected("valid UTF-16 code units")
    })
}

fn push_octal(units: &mut Vec<u16>, digits: &str) -> OpResult<()> {
    // Corrupt payloads can smuggle a digit >= 8 into an octal run; that is a
    // typed decode error, never a panic.
    let value = u16::from_str_radix(digits, 8).map_err(|_| {
        OperationError::decode(format!(
            "aaencode payload has invalid octal escape digits `{digits}`"
        ))
    })?;
    units.push(value);
    Ok(())
}

fn from_aaencode_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let _ = map;
    let text = input_text(v, "From AAEncode")?;
    Ok(Value::Text(aa_decode_text(text)?))
}

// ------------------------------------------------------- JJEncode ----

/// The 16 `$`-symbol groups that evaluate to the digits 0-F (reference:
/// utf-8.jp `jjencode`).
const JJ_DIGITS: [&str; 16] = [
    "___", "__$", "_$_", "_$$", "$__", "$_$", "$$_", "$$$", "$___", "$__$", "$_$_", "$_$$", "$$__",
    "$$_$", "$$$_", "$$$$",
];

/// Decode a JJEncode payload WITHOUT executing any JavaScript.
///
/// The reference `jjdecode` (shipped alongside the utf-8.jp encoder) is a
/// pure token walker over the generated source: the payload is a concatenation
/// of quoted literal runs, `\ooo` octal escapes and `\uXXXX`-style hex
/// escapes spelled with the `$`-symbol digit groups. CyberCipher ports that
/// walker to Rust. Two deliberate deviations, both strictly more capable than
/// the reference walker:
///
/// 1. A literal space (0x20) inside a quoted run is accepted — the reference
///    scanner omits 0x20 and would spin forever on it, while the encoder
///    happily emits spaces inside runs.
/// 2. Hex escapes read at most 4 digit groups (a UTF-16 code unit is at most
///    `\uFFFF`); the reference reads only 2 after a run-opening escape, which
///    mis-decodes non-ASCII text.
///
/// The palindrome-wrapped variant (`encode_jj(..., p = true)`) is rejected
/// with a typed error.
fn jj_decode_text(input: &str) -> OpResult<String> {
    let text = input.trim();
    if text.starts_with('"') {
        return Err(OperationError::unsupported(
            "palindrome-wrapped JJEncode (the p=true variant) is not supported",
        )
        .with_details(
            "Strip the `\"\\\"+\'+\",` … palindrome wrapper first; the inner \
             payload decodes normally.",
        ));
    }
    let eq = text.find('=').ok_or_else(|| {
        OperationError::decode("input is not JJEncode (no global variable assignment found)")
            .with_expected("JJEncode output starting with `<gv>=~[];`")
    })?;
    let gv = &text[..eq];
    if gv.is_empty() {
        return Err(OperationError::decode("JJEncode global variable is empty"));
    }
    // Payload markers (gv-independent; `$$` is a fixed property name):
    // `$$+"\""+` … `"\")())();`
    const START: &str = "$$+\"\\\"\"+";
    const END: &str = "\"\\\"\"\")())();";
    let start_idx = text.find(START).ok_or_else(|| {
        OperationError::decode("input is not JJEncode (payload start marker not found)")
            .with_expected("JJEncode output with the `$$+\"\\\"\"+` payload marker")
    })? + START.len();
    // The utf-8.jp encoder ends with `""\")())();`; some encoders vary the
    // number of quote/backslash escapes in that final literal, so fall back
    // to the `)())();` anchor and step over the 3-byte `""\` prefix.
    let end_idx = match text.rfind(END) {
        Some(idx) => idx,
        None => {
            const ANCHOR: &str = ")())();";
            let tail_debug: String = text
                .chars()
                .rev()
                .take(24)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<String>()
                .escape_debug()
                .to_string();
            let anchor = text.rfind(ANCHOR).ok_or_else(|| {
                OperationError::decode("input is not JJEncode (payload end marker not found)")
                    .with_expected("JJEncode output ending with `\"\\\")())();`")
                    .with_details(format!("input tail: {tail_debug}"))
            })?;
            if anchor < 3 {
                return Err(OperationError::decode(
                    "JJEncode payload end marker is truncated",
                ));
            }
            anchor - 3
        }
    };
    if start_idx > end_idx {
        return Err(OperationError::decode(
            "JJEncode payload markers are inverted (corrupt input)",
        ));
    }
    let data = &text[start_idx..end_idx];

    let str_l = format!("(![]+\"\")[{gv}._$_]+");
    let str_o = format!("{gv}._$+");
    let str_t = format!("{gv}.__+");
    let str_u = format!("{gv}._+");
    let str_hex = format!("{gv}.");
    let gvsig = str_hex.clone();
    let bs: char = '\\';
    let str_quote: String = [bs, bs, bs, '"'].iter().collect();
    let str_slash: String = [bs, bs, bs, bs].iter().collect();
    let str_lower: String = [bs, bs, '"', '+'].iter().collect();
    let str_upper: String = format!("{}{}._+", str_lower, gv);
    let str_end = "\"+".to_string();
    let b: Vec<String> = JJ_DIGITS.iter().map(|d| format!("{d}+")).collect();

    let mut units: Vec<u16> = Vec::new();

    macro_rules! parse_hex {
        ($data:expr, $limit:expr) => {{
            let mut dd = $data;
            let mut ch = String::new();
            let mut lotux: Option<char> = None;
            let mut j = 0usize;
            while j < $limit {
                if j > 1 {
                    let mut hit = false;
                    for (sym, tok) in [('l', &str_l), ('o', &str_o), ('t', &str_t), ('u', &str_u)] {
                        if dd.starts_with(tok.as_str()) {
                            dd = &dd[tok.len()..];
                            lotux = Some(sym);
                            hit = true;
                            break;
                        }
                    }
                    if hit {
                        break;
                    }
                }
                if dd.starts_with(gvsig.as_str()) {
                    dd = &dd[gvsig.len()..];
                    let matched = b
                        .iter()
                        .find(|tok| dd.starts_with(tok.as_str()))
                        .ok_or_else(|| {
                            OperationError::decode(
                                "JJEncode payload has a corrupted hex digit group",
                            )
                        })?;
                    ch.push(
                        std::char::from_digit(
                            b.iter()
                                .position(|t| *t == *matched)
                                .expect("matched from b") as u32,
                            16,
                        )
                        .unwrap(),
                    );
                    dd = &dd[matched.len()..];
                } else {
                    break;
                }
                j += 1;
            }
            (dd, ch, lotux)
        }};
    }

    macro_rules! parse_oct {
        ($data:expr) => {{
            let mut dd = $data;
            let mut ch = String::new();
            let mut lotux: Option<char> = None;
            let mut j = 0usize;
            while j < 3 {
                if j > 1 {
                    let mut hit = false;
                    for (sym, tok) in [('l', &str_l), ('o', &str_o), ('t', &str_t), ('u', &str_u)] {
                        if dd.starts_with(tok.as_str()) {
                            dd = &dd[tok.len()..];
                            lotux = Some(sym);
                            hit = true;
                            break;
                        }
                    }
                    if hit {
                        break;
                    }
                }
                if dd.starts_with(gvsig.as_str()) {
                    let temp = &dd[gvsig.len()..];
                    let mut matched: Option<(usize, &String)> = None;
                    for (k, tok) in b.iter().enumerate().take(8) {
                        if temp.starts_with(tok.as_str()) {
                            matched = Some((k, tok));
                            break;
                        }
                    }
                    let Some((k, tok)) = matched else {
                        break;
                    };
                    let candidate = format!("{ch}{k}");
                    let value = i32::from_str_radix(&candidate, 8)
                        .map_err(|_| unreachable!("octal digits"))?;
                    if value > 128 {
                        // Reference quirk: an over-long octal run is re-read
                        // as one hex digit.
                        if !dd.starts_with(str_hex.as_str()) {
                            return Err(OperationError::decode(
                                "JJEncode payload has a corrupted escape sequence",
                            ));
                        }
                        dd = &dd[str_hex.len()..];
                        let hex_matched = b
                            .iter()
                            .find(|tok| dd.starts_with(tok.as_str()))
                            .ok_or_else(|| {
                                OperationError::decode(
                                    "JJEncode payload has a corrupted hex digit group",
                                )
                            })?;
                        lotux = Some(
                            std::char::from_digit(
                                b.iter().position(|t| *t == *hex_matched).expect("matched") as u32,
                                16,
                            )
                            .expect("hex digit"),
                        );
                        dd = &dd[hex_matched.len()..];
                        break;
                    }
                    ch.push(std::char::from_digit(k as u32, 10).unwrap());
                    dd = &dd[gvsig.len() + tok.len()..];
                } else {
                    break;
                }
                j += 1;
            }
            (dd, ch, lotux)
        }};
    }

    let mut data = data;
    while !data.is_empty() {
        if data.starts_with(str_l.as_str()) {
            data = &data[str_l.len()..];
            units.push('l' as u16);
            continue;
        }
        if data.starts_with(str_o.as_str()) {
            data = &data[str_o.len()..];
            units.push('o' as u16);
            continue;
        }
        if data.starts_with(str_t.as_str()) {
            data = &data[str_t.len()..];
            units.push('t' as u16);
            continue;
        }
        if data.starts_with(str_u.as_str()) {
            data = &data[str_u.len()..];
            units.push('u' as u16);
            continue;
        }
        if data.starts_with(str_hex.as_str()) {
            data = &data[str_hex.len()..];
            let matched = b
                .iter()
                .find(|tok| data.starts_with(tok.as_str()))
                .ok_or_else(|| {
                    OperationError::decode("JJEncode payload has a corrupted hex digit group")
                })?;
            units.push(
                std::char::from_digit(
                    b.iter().position(|t| *t == *matched).expect("matched") as u32,
                    16,
                )
                .expect("hex digit") as u16,
            );
            data = &data[matched.len()..];
            continue;
        }
        if data.starts_with('"') {
            data = &data[1..];
            if data.starts_with(str_upper.as_str()) {
                data = &data[str_upper.len()..];
                let (rest, ch, lotux) = parse_hex!(data, 4);
                data = rest;
                push_jj_escape(&mut units, &ch, lotux, 16)?;
                continue;
            }
            if data.starts_with(str_lower.as_str()) {
                data = &data[str_lower.len()..];
                let (rest, ch, lotux) = parse_oct!(data);
                data = rest;
                push_jj_escape(&mut units, &ch, lotux, 8)?;
                continue;
            }
            let mut matched_literals = 0usize;
            loop {
                if data.is_empty() {
                    return Err(OperationError::decode(
                        "JJEncode quoted run ends unexpectedly",
                    ));
                }
                if data.starts_with(str_quote.as_str()) {
                    data = &data[str_quote.len()..];
                    units.push('"' as u16);
                    matched_literals += 1;
                    continue;
                }
                if data.starts_with(str_slash.as_str()) {
                    data = &data[str_slash.len()..];
                    units.push('\\' as u16);
                    matched_literals += 1;
                    continue;
                }
                if data.starts_with(str_end.as_str()) {
                    if matched_literals == 0 {
                        return Err(OperationError::decode("JJEncode quoted run is empty"));
                    }
                    data = &data[str_end.len()..];
                    break;
                }
                if data.starts_with(str_upper.as_str()) {
                    if matched_literals == 0 {
                        return Err(OperationError::decode(
                            "JJEncode quoted run ends in a hex escape without literal content",
                        ));
                    }
                    data = &data[str_upper.len()..];
                    let (rest, ch, lotux) = parse_hex!(data, 4);
                    data = rest;
                    push_jj_escape(&mut units, &ch, lotux, 16)?;
                    break;
                }
                if data.starts_with(str_lower.as_str()) {
                    if matched_literals == 0 {
                        return Err(OperationError::decode(
                            "JJEncode quoted run ends in an octal escape without literal content",
                        ));
                    }
                    data = &data[str_lower.len()..];
                    let (rest, ch, lotux) = parse_oct!(data);
                    data = rest;
                    push_jj_escape(&mut units, &ch, lotux, 8)?;
                    break;
                }
                let n = data.as_bytes()[0];
                if matches!(n,
                    0x20..=0x2f | 0x3a..=0x40 | 0x5b..=0x60 | 0x7b..=0x7f)
                {
                    units.push(n as u16);
                    data = &data[1..];
                    matched_literals += 1;
                    continue;
                }
                return Err(OperationError::decode(format!(
                    "JJEncode quoted run contains an unsupported byte 0x{n:02x}"
                ))
                .with_expected("literal punctuation or an escape sequence"));
            }
            continue;
        }
        return Err(OperationError::decode(format!(
            "unexpected JJEncode structure at payload offset {}",
            text.len() - data.len()
        ))
        .with_expected("literal run, escape sequence or symbol token"));
    }
    String::from_utf16(&units).map_err(|_| {
        OperationError::decode("JJEncode payload decodes to invalid UTF-16 (lone surrogates)")
            .with_expected("valid UTF-16 code units")
    })
}

fn push_jj_escape(
    units: &mut Vec<u16>,
    digits: &str,
    lotux: Option<char>,
    radix: u32,
) -> OpResult<()> {
    if digits.is_empty() {
        return Err(OperationError::decode(
            "JJEncode escape sequence carries no digits",
        ));
    }
    let value = u16::from_str_radix(digits, radix).map_err(|_| {
        OperationError::decode(format!(
            "JJEncode payload has invalid base-{radix} escape digits `{digits}`"
        ))
    })?;
    units.push(value);
    if let Some(sym) = lotux {
        units.push(sym as u16);
    }
    Ok(())
}

fn from_jjencode_op(v: &Value, map: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
    let _ = map;
    let text = input_text(v, "From JJEncode")?;
    Ok(Value::Text(jj_decode_text(text)?))
}

// --------------------------------------------------------- registry ----

pub(crate) fn register(reg: &mut cybercipher_core::OperationRegistry) {
    use cybercipher_core::Category::Classical as C;
    use cybercipher_core::ValueKind::Text as T;

    let tag: &'static [&'static str] = &["classical", "ctf", "specialty"];

    fn p_text_area(
        key: &'static str,
        label: &'static str,
        default: &'static str,
        hint: &'static str,
    ) -> ParamSpec {
        ParamSpec {
            kind: ParamKind::TextArea,
            ..p_text(key, label, default, hint)
        }
    }

    let bf_params = || -> Vec<ParamSpec> {
        vec![
            p_text_area(
                "input",
                "Program input (stdin)",
                "",
                "Bytes fed to `,` one per execution; end of input reads 0.",
            ),
            p_int(
                "memory_cells",
                "Memory cells",
                BF_DEFAULT_CELLS,
                "Tape size (cells); hard cap 1,000,000.",
            ),
            p_int(
                "max_steps",
                "Step limit",
                BF_DEFAULT_STEPS,
                "Executed instructions before aborting; hard cap 10,000,000.",
            ),
        ]
    };

    reg.add_simple(
        spec(
            "run-brainfuck",
            "Run Brainfuck",
            "Executes a Brainfuck program (><+-.,[]) with the standard 8-op spec: 8-bit \
             wrapping cells, `,` reads the `input` parameter byte-per-execution (0 at end \
             of input), and any other character is a comment. Bounded: a step budget and \
             a fixed tape size; unmatched brackets and pointer under/overflow are typed \
             errors, never panics.",
            C,
            &[T],
            T,
            CostClass::Instant,
            false,
            bf_params(),
            tag,
            &["brainfuck", "bf interpreter", "brainfuck run"],
            "Standard Brainfuck spec (Müller 1993); bounded like reference CTF engines",
            "Hello World + echo/loop/limit tests; ToolsFx BrainfuckEngine behaviour",
        ),
        run_brainfuck_op,
    );

    reg.add_simple(
        spec(
            "to-brainfuck",
            "To Brainfuck",
            "Generates a Brainfuck program that prints the input text (UTF-8 bytes). \
             Single-cell delta encoder; the round trip through `run-brainfuck` \
             reproduces the input exactly.",
            C,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![],
            tag,
            &["brainfuck generator", "bf encode"],
            "Standard Brainfuck spec (Müller 1993)",
            "Round-trip tests (text -> program -> run -> text)",
        ),
        to_brainfuck_op,
    );

    reg.add_simple(
        spec(
            "from-ook",
            "From Ook!",
            "Executes an Ook! program. The canonical 8 Ook! token pairs (Ook. Ook? = `>`, \
             Ook? Ook. = `<`, Ook. Ook. = `+`, Ook! Ook! = `-`, Ook! Ook. = `.`, Ook. Ook! = \
             `,`, Ook! Ook? = `[`, Ook? Ook! = `]`) are translated to Brainfuck and run \
             through the same bounded interpreter as `run-brainfuck`.",
            C,
            &[T],
            T,
            CostClass::Instant,
            false,
            bf_params(),
            tag,
            &["ook", "ook interpreter", "orangutan"],
            "Canonical Ook! token table (esolangs wiki; ToolsFx OokEngine)",
            "Token-table tests + Brainfuck round trip",
        ),
        from_ook_op,
    );

    reg.add_simple(
        spec(
            "to-ook",
            "To Ook!",
            "Renders a generated Brainfuck program (same encoder as `to-brainfuck`) as \
             canonical Ook! token pairs. Round trips through `from-ook`.",
            C,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![],
            tag,
            &["ook generator", "ook encode"],
            "Canonical Ook! token table (esolangs wiki; ToolsFx OokEngine)",
            "Round-trip tests (text -> Ook -> run -> text)",
        ),
        to_ook_op,
    );

    reg.add_simple(
        spec(
            "to-buddha",
            "To Buddha",
            "与佛论禅 (Buddha says) encryption exactly like the keyfc.net reference tool: \
             the text (UTF-16LE) is AES-256-CBC encrypted with the fixed keyfc key and IV, \
             PKCS#7-padded, and each ciphertext byte is mapped onto a 128-character sutra \
             table (bytes >= 0x80 get one of 11 marker characters first — CyberCipher \
             emits the first marker deterministically). Decode with `from-buddha`.",
            C,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![],
            tag,
            &["buddha", "fo yue", "与佛论禅", "buddha says encode"],
            "keyfc.net 与佛论禅 (tudoucode.aspx); ToolsFx BuddhaCipher.kt port",
            "ToolsFx BuddhaTest vector + round-trip tests",
        ),
        to_buddha_op,
    );

    reg.add_simple(
        spec(
            "from-buddha",
            "From Buddha",
            "Decodes 与佛论禅 ciphertext (`佛曰：…`, also the `魔曰：` reversed variant): \
             maps the sutra-table characters back to bytes, then AES-256-CBC decrypts \
             (fixed keyfc key/IV, PKCS#7) and reconstructs the UTF-16LE text.",
            C,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![],
            tag,
            &["buddha", "fo yue", "与佛论禅", "buddha says decode"],
            "keyfc.net 与佛论禅 (tudoucode.aspx); ToolsFx BuddhaCipher.kt port",
            "ToolsFx BuddhaTest vector + round-trip tests",
        ),
        from_buddha_op,
    );

    reg.add_simple(
        spec(
            "to-buddha-pbe",
            "To Buddha PBE",
            "新佛曰 (new Buddha) encryption: OpenSSL-style PBE (EVP_BytesToKey with MD5, \
             AES-256-CBC, PKCS#7 over UTF-8), base64 of `Salted__ + salt + ciphertext` \
             with the fixed prefix dropped, then mapped onto the 65-character 新佛曰 \
             table and wrapped in `佛又曰：`. Unlike the reference (random salt per \
             message) the 8-byte `salt` parameter is explicit so output is \
             deterministic; any salt round-trips with the reference decoder.",
            C,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![
                p_text(
                    "password",
                    "Password",
                    BUDDHA_PBE_DEFAULT_PASSWORD,
                    "PBE password; upstream default is takuron.top.",
                ),
                p_text(
                    "salt",
                    "Salt (hex)",
                    BUDDHA_PBE_DEFAULT_SALT_HEX,
                    "8 bytes of hex; upstream randomizes, we pin it for determinism.",
                ),
            ],
            tag,
            &["buddha pbe", "新佛曰", "new buddha", "talk-with-buddha"],
            "与佛论禅加密版 v2 (takuron/talk-with-buddha); ToolsFx BuddhaPbeCipher.kt",
            "ToolsFx/wiki 新佛曰 vector + round-trip + EVP_BytesToKey KAT",
        ),
        to_buddha_pbe_op,
    );

    reg.add_simple(
        spec(
            "from-buddha-pbe",
            "From Buddha PBE",
            "Decodes 新佛曰 ciphertext (`佛又曰：…`): maps the table characters back to \
             base64, re-adds the `U2FsdGVkX1` prefix, derives key/IV with \
             EVP_BytesToKey(MD5) from the password and embedded salt, and \
             AES-256-CBC decrypts.",
            C,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![p_text(
                "password",
                "Password",
                BUDDHA_PBE_DEFAULT_PASSWORD,
                "PBE password; upstream default is takuron.top.",
            )],
            tag,
            &["buddha pbe", "新佛曰", "new buddha", "talk-with-buddha"],
            "与佛论禅加密版 v2 (takuron/talk-with-buddha); ToolsFx BuddhaPbeCipher.kt",
            "ToolsFx/wiki 新佛曰 vector + round-trip + EVP_BytesToKey KAT",
        ),
        from_buddha_pbe_op,
    );

    reg.add_simple(
        spec(
            "to-beast",
            "To Beast",
            "兽音译者 (beast speak) encoding: every UTF-16 code unit becomes four hex \
             nibbles, each nibble is shifted by its position (mod 16) and packed base-4 \
             into pairs of the 4-character codec (default 嗯-order `嗷呜啊~`), wrapped as \
             `~呜嗷…啊`. The `codec` parameter accepts any 4 distinct characters, \
             matching the upstream customization feature.",
            C,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![p_text(
                "codec",
                "Codec",
                BEAST_DEFAULT_CODEC,
                "Exactly 4 distinct characters (upstream beast array).",
            )],
            tag,
            &["beast", "roar", "兽音", "beast speak encode", "aowu"],
            "sgdrg15rdg/beast_js (original 兽音译者); mirrored by SycAlright/beast_sdk",
            "beast_sdk README vector (你好) + ToolsFx wiki vector + round-trips",
        ),
        to_beast_op,
    );

    reg.add_simple(
        spec(
            "from-beast",
            "From Beast",
            "Decodes 兽音译者 ciphertext: strips the `~呜嗷`/`啊` envelope (a bare payload \
             without the envelope is also accepted), reverses the position shift and \
             reassembles UTF-16 code units. Characters outside the codec are typed \
             errors.",
            C,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![p_text(
                "codec",
                "Codec",
                BEAST_DEFAULT_CODEC,
                "Exactly 4 distinct characters (upstream beast array).",
            )],
            tag,
            &["beast", "roar", "兽音", "beast speak decode", "aowu"],
            "sgdrg15rdg/beast_js (original 兽音译者); mirrored by SycAlright/beast_sdk",
            "beast_sdk README vector (你好) + ToolsFx wiki vector + round-trips",
        ),
        from_beast_op,
    );

    reg.add_simple(
        spec(
            "to-bear",
            "To Bear",
            "熊曰 (bear says) encoding: the text is UTF-8 encoded, raw-DEFLATE compressed \
             (no zlib framing), basE91-encoded onto a 91-character bear dictionary, \
             reversed and wrapped as `熊曰：呋…`. Upstream compresses at level 1; any \
             level decodes identically.",
            C,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![],
            tag,
            &["bear", "xiong yue", "熊曰", "bear says encode", "与熊论道"],
            "与熊论道 (hi.pcmoe.net); EBCTFCodeBox xiongyue.js / Abracadabra ports",
            "ToolsFx wiki 熊曰 vector + round-trip tests",
        ),
        to_bear_op,
    );

    reg.add_simple(
        spec(
            "from-bear",
            "From Bear",
            "Decodes 熊曰 ciphertext (`熊曰：呋…`): strips the envelope, reverses, maps the \
             dictionary back to basE91 values, raw-inflates and UTF-8 decodes.",
            C,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![],
            tag,
            &["bear", "xiong yue", "熊曰", "bear says decode", "与熊论道"],
            "与熊论道 (hi.pcmoe.net); EBCTFCodeBox xiongyue.js / Abracadabra ports",
            "ToolsFx wiki 熊曰 vector + round-trip tests",
        ),
        from_bear_op,
    );

    reg.add_simple(
        spec(
            "to-core-values",
            "To Core Values",
            "社会主义核心价值观 encoding: each UTF-8 byte becomes two uppercase hex digits, \
             and every hex digit maps onto a two-character phrase from the 12-phrase \
             slogan table (A-F use marker phrase 诚信 plus an offset phrase; the \
             reference randomizes between the 诚信/友善 markers, CyberCipher picks 诚信 \
             deterministically).",
            C,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![],
            tag,
            &["socialist core values", "核心价值观", "core values encode"],
            "ToolsFx SocialistCoreValues.kt (12-phrase slogan table)",
            "ToolsFx wiki vector + round-trip tests",
        ),
        to_core_values_op,
    );

    reg.add_simple(
        spec(
            "from-core-values",
            "From Core Values",
            "Decodes 社会主义核心价值观 ciphertext: pairs of characters are looked up in \
             the 12-phrase table, 诚信/友善 markers select the A-F mapping, and the \
             reconstructed hex is UTF-8 decoded.",
            C,
            &[T],
            T,
            CostClass::Instant,
            true,
            vec![],
            tag,
            &["socialist core values", "核心价值观", "core values decode"],
            "ToolsFx SocialistCoreValues.kt (12-phrase slogan table)",
            "ToolsFx wiki vector + round-trip tests",
        ),
        from_core_values_op,
    );

    reg.add_simple(
        spec(
            "from-aaencode",
            "From AAEncode",
            "Decodes AAEncode (ああああ-emoticon) payloads WITHOUT executing JavaScript: \
             the aaencode self-decoder evals a generated script, but the data itself is a \
             plain sequence of JS string escapes (octal for ASCII, \\uXXXX otherwise) \
             spelled with 16 fixed emoticon digit expressions. CyberCipher parses that \
             escape stream and reconstructs the text from its UTF-16 code units — the \
             deterministic data path of the reference decoder. Encoding stays \
             out of scope (it is the JS generator itself).",
            C,
            &[T],
            T,
            CostClass::Instant,
            false,
            vec![],
            tag,
            &["aaencode", "aa encode", "kaomoji", "emoticon js"],
            "utf-8.jp aaencode (Yosuke Hasegawa); ToolsFx aaencode.js copy",
            "Reference-format samples (ASCII + CJK) decoded byte-for-byte",
        ),
        from_aaencode_op,
    );

    reg.add_simple(
        spec(
            "from-jjencode",
            "From JJEncode",
            "Decodes JJEncode ($=~[];… payloads) WITHOUT executing JavaScript: ports the \
             reference jjdecode token walker (quoted literal runs, octal escapes, \
             $-symbol hex escapes) to Rust. Two fixes over the reference walker: literal \
             spaces inside quoted runs are accepted (the reference hangs on them), and \
             hex escapes read up to 4 digit groups (the reference mis-decodes non-ASCII \
             text). The palindrome-wrapped p=true variant is rejected with a typed \
             error.",
            C,
            &[T],
            T,
            CostClass::Instant,
            false,
            vec![],
            tag,
            &["jjencode", "jj decode", "js obfuscation"],
            "utf-8.jp jjencode (Yosuke Hasegawa); reference jjdecode algorithm",
            "Reference-format sample decoded byte-for-byte; 145 KB real corpus check",
        ),
        from_jjencode_op,
    );
}

// -------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------- brainfuck ----

    #[test]
    fn bf_hello_world() {
        let program = "++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++\
                       ..+++.>>.<-.<.+++.------.--------.>>+.>++.";
        let out = bf_run(program, b"", 30_000, 1_000_000).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "Hello World!\n");
    }

    #[test]
    fn bf_echoes_program_input() {
        // ,[,]: echo every input byte until end of input (EOF -> 0 halts).
        let out = bf_run(",[.,]", b"ctf rules", 30_000, 1_000_000).unwrap();
        assert_eq!(out, b"ctf rules");
        // EOF reads 0: `,.` prints one zero byte for empty input.
        assert_eq!(bf_run(",.", b"", 30_000, 1_000_000).unwrap(), vec![0]);
    }

    #[test]
    fn bf_wrapping_cells() {
        // 255 + 1 wraps to 0; 1 - 2 wraps to 255.
        let out = bf_run("-.", b"", 30_000, 1000).unwrap();
        assert_eq!(out, vec![255]);
    }

    #[test]
    fn bf_ignores_comments() {
        // Everything except the 8 commands is a comment; brackets still jump
        // (the cell is 0, so the "loop" body is skipped).
        let out = bf_run(
            "hello +-. world! [this is not a loop] +.",
            b"",
            30_000,
            1000,
        )
        .unwrap();
        assert_eq!(out, vec![0, 1]);
    }

    #[test]
    fn bf_unmatched_brackets_are_typed_errors() {
        let err = bf_run("[[++]", b"", 30_000, 1000).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Decode);
        assert!(err.message.contains("unmatched `[`"), "{}", err.message);
        let err = bf_run("++++]", b"", 30_000, 1000).unwrap_err();
        assert!(err.message.contains("unmatched `]`"), "{}", err.message);
    }

    #[test]
    fn bf_pointer_bounds_are_typed_errors() {
        let err = bf_run("+<", b"", 30_000, 1000).unwrap_err();
        assert!(err.message.contains("below cell 0"), "{}", err.message);
        let err = bf_run(">+", b"", 1, 1000).unwrap_err();
        assert!(
            err.message.contains("past the last cell"),
            "{}",
            err.message
        );
    }

    #[test]
    fn bf_step_budget_exceeded() {
        let err = bf_run("+[]", b"", 30_000, 1_000_000).unwrap_err();
        assert_eq!(err.kind, ErrorKind::BudgetExceeded);
        assert!(err.message.contains("step budget"), "{}", err.message);
        // The same program passes with a tiny budget of exactly one step.
        assert!(bf_run(".", b"", 30_000, 1).is_ok());
    }

    #[test]
    fn to_brainfuck_roundtrip() {
        for text in ["Hello, World!\n", "CyberCipher \u{1F40D} 中文", ""] {
            let program = bf_generate(text.as_bytes());
            let out = bf_run(&program, b"", 30_000, 1_000_000).unwrap();
            assert_eq!(String::from_utf8(out).unwrap(), text);
        }
    }

    #[test]
    fn ook_token_table_matches_reference() {
        // The canonical mapping (esolangs Ook!; ToolsFx OokEngine):
        assert_eq!(ook_to_bf("Ook. Ook?").unwrap(), ">");
        assert_eq!(ook_to_bf("Ook? Ook.").unwrap(), "<");
        assert_eq!(ook_to_bf("Ook. Ook.").unwrap(), "+");
        assert_eq!(ook_to_bf("Ook! Ook!").unwrap(), "-");
        assert_eq!(ook_to_bf("Ook! Ook.").unwrap(), ".");
        assert_eq!(ook_to_bf("Ook. Ook!").unwrap(), ",");
        assert_eq!(ook_to_bf("Ook! Ook?").unwrap(), "[");
        assert_eq!(ook_to_bf("Ook? Ook!").unwrap(), "]");
        // Case-insensitive and whitespace tolerant.
        assert_eq!(ook_to_bf("OOK!OOK!").unwrap(), "-");
    }

    #[test]
    fn ook_roundtrip_through_the_interpreter() {
        let text = "Ook! says moo\n";
        let ook = bf_to_ook(&bf_generate(text.as_bytes()));
        let program = ook_to_bf(&ook).unwrap();
        let out = bf_run(&program, b"", 30_000, 1_000_000).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), text);
    }

    #[test]
    fn ook_rejects_garbage() {
        assert!(ook_to_bf("Ook.").is_err()); // odd token count
        let err = ook_to_bf("Ook. Ookx").unwrap_err();
        assert!(err.message.contains("not followed by"), "{}", err.message);
        let err = ook_to_bf("hello").unwrap_err();
        assert!(
            err.message.contains("not part of an Ook! token"),
            "{}",
            err.message
        );
        assert!(ook_to_bf("   ").is_err());
        // A token pair that exists is fine; a bogus pair is a typed error.
        let err = ook_to_bf("Ook. Ook Ook! Ook.").unwrap_err();
        assert!(err.message.contains("not followed by"), "{}", err.message);
    }

    // ------------------------------------------------------- buddha ----

    #[test]
    fn buddha_table_shapes() {
        assert_eq!(BUDDHA_BYTE_MAP.chars().count(), 128);
        assert_eq!(BUDDHA_HIGH_MARKERS.chars().count(), 11);
        assert!(BUDDHA_BYTE_MAP
            .chars()
            .all(|c| !BUDDHA_HIGH_MARKERS.contains(c)));
    }

    /// ToolsFx `BuddhaTest.kt` pinned vector:
    /// `"佛曰：冥耶以缽醯以梵蘇心缽參哆能哆他多罰姪實悉那遮奢三".buddhaExplain()
    /// == "与佛论禅666"` (github.com/Leon406/ToolsFx).
    #[test]
    fn buddha_decode_reference_vector() {
        let out = from_buddha_op(
            &Value::Text("佛曰：冥耶以缽醯以梵蘇心缽參哆能哆他多罰姪實悉那遮奢三".into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap();
        assert_eq!(out, Value::Text("与佛论禅666".into()));
    }

    #[test]
    fn buddha_roundtrip() {
        let text = "Hello, 世界！ CTF{buddha_says_hi} 123";
        let enc = to_buddha_op(
            &Value::Text(text.into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap();
        let Value::Text(enc) = enc else { panic!() };
        assert!(enc.starts_with(BUDDHA_HEADER));
        let dec = from_buddha_op(
            &Value::Text(enc),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap();
        assert_eq!(dec, Value::Text(text.into()));
    }

    /// The 魔曰 variant is the mapped ciphertext in reverse order
    /// (ToolsFx `buddhaExplain` reverses after stripping the header).
    #[test]
    fn buddha_mo_reversed_variant() {
        let text = "reverse me";
        let Value::Text(enc) = to_buddha_op(
            &Value::Text(text.into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap() else {
            panic!()
        };
        let body: String = enc.chars().skip(BUDDHA_HEADER.chars().count()).collect();
        let mo: String = BUDDHA_MO_HEADER.chars().chain(body.chars().rev()).collect();
        let dec =
            from_buddha_op(&Value::Text(mo), &ParamMap::new(), &ExecutionContext::new()).unwrap();
        assert_eq!(dec, Value::Text(text.into()));
    }

    #[test]
    fn buddha_rejects_headerless_and_bad_alignments() {
        let err = from_buddha_op(
            &Value::Text("冥耶以缽醯以梵".into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap_err();
        assert!(err.message.contains("must start with"), "{}", err.message);
        // A header but no table characters.
        let err = from_buddha_op(
            &Value::Text("佛曰：hello".into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap_err();
        assert!(
            err.message.contains("no Buddha table characters"),
            "{}",
            err.message
        );
    }

    // -------------------------------------------------- buddha pbe ----

    #[test]
    fn buddha_pbe_table_shapes() {
        assert_eq!(BUDDHA_PBE_TABLE.chars().count(), 65);
        assert_eq!(BUDDHA_PBE_ALPHABET.len(), 65);
    }

    /// OpenSSL EVP_BytesToKey(MD5, 1 iteration) known-answer, computed with
    /// hashlib: password "PasswordX", salt 0102030405060708.
    #[test]
    fn evp_bytestokey_md5_kat() {
        let (key, iv) = evp_bytestokey_md5(b"PasswordX", &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            hex_encode(&key),
            "0586eb5c824053cd03e9179d9315ffed3a1dfffc880329cc5a80c35ad10a941c"
        );
        assert_eq!(hex_encode(&iv), "858bf342ffacbfc81b87736b86462bc0");
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// ToolsFx wiki vector (doc/wiki/CTF.md, 与佛论禅加密版v2, default
    /// password takuron.top): decodes to `123123`.
    #[test]
    fn buddha_pbe_decode_reference_vector() {
        let out = from_buddha_pbe_op(
            &Value::Text(
                "佛又曰：输啰提尼佛尼唎穆度伽阿孕写罚怛阿婆羯帝喝输唎舍室俱烁谨谨烁阇曳蒙喝漫"
                    .into(),
            ),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap();
        assert_eq!(out, Value::Text("123123".into()));
    }

    #[test]
    fn buddha_pbe_roundtrip() {
        let text = "新佛曰 round trip 456";
        let mut params = ParamMap::new();
        params.insert("password", BUDDHA_PBE_DEFAULT_PASSWORD);
        params.insert("salt", "0001020304050607");
        let Value::Text(enc) =
            to_buddha_pbe_op(&Value::Text(text.into()), &params, &ExecutionContext::new()).unwrap()
        else {
            panic!()
        };
        let mut decode_params = ParamMap::new();
        decode_params.insert("password", BUDDHA_PBE_DEFAULT_PASSWORD);
        let dec = from_buddha_pbe_op(&Value::Text(enc), &decode_params, &ExecutionContext::new())
            .unwrap();
        assert_eq!(dec, Value::Text(text.into()));
    }

    #[test]
    fn buddha_pbe_rejects_bad_input() {
        let err = from_buddha_pbe_op(
            &Value::Text("佛又曰：任意的文字".into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap_err();
        assert!(err.message.contains("not in the"), "{}", err.message);
        let err = from_buddha_pbe_op(
            &Value::Text("佛曰：输啰提尼佛尼唎穆度".into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap_err();
        assert!(err.message.contains("佛又曰"), "{}", err.message);
        let mut params = ParamMap::new();
        params.insert("salt", "not-hex");
        assert!(
            to_buddha_pbe_op(&Value::Text("x".into()), &params, &ExecutionContext::new()).is_err()
        );
    }

    // ----------------------------------------------------- beast ----

    /// ToolsFx wiki vector (doc/wiki/CTF.md, 兽音 section) decodes to the
    /// SubCrawler link.
    #[test]
    fn beast_decode_reference_vector() {
        let wiki = "~呜嗷嗷嗷嗷呜啊嗷啊~呜嗷呜呜~呜啊~啊嗷啊呜嗷呜~~~嗷~呜呜呜~~嗷嗷嗷呜啊呜呜啊呜嗷呜呜啊呜嗷呜啊嗷啊呜~嗷啊啊~嗷~呜嗷嗷~啊嗷嗷嗷呜啊嗷啊啊呜嗷呜呜~嗷嗷嗷啊嗷啊呜嗷呜~~~嗷~呜呜嗷呜~嗷嗷嗷呜啊呜啊嗷呜嗷呜呜~嗷啊呜啊嗷啊呜~嗷啊呜~嗷~呜呜嗷嗷啊嗷嗷嗷呜啊嗷嗷啊呜嗷呜呜~嗷呜嗷啊嗷啊呜~嗷啊啊~嗷~呜嗷啊啊~嗷嗷嗷呜啊嗷啊嗷呜嗷呜呜~嗷呜啊啊嗷啊呜嗷嗷啊呜~嗷~呜嗷呜嗷~嗷嗷嗷呜呜呜嗷~呜嗷呜呜啊呜~呜啊嗷啊呜~嗷啊啊~嗷~呜嗷~嗷啊嗷嗷嗷呜啊呜啊嗷呜嗷呜呜~嗷啊呜啊嗷啊呜~啊~啊~嗷~呜呜呜嗷呜嗷嗷嗷呜啊嗷呜嗷呜嗷呜呜~呜~啊啊嗷啊呜嗷嗷呜~~嗷~呜呜嗷呜嗷嗷嗷嗷呜啊呜呜呜啊";
        let out = from_beast_op(
            &Value::Text(wiki.into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap();
        assert_eq!(
            out,
            Value::Text("https://github.com/Leon406/SubCrawler".into())
        );
    }

    /// SycAlright/beast_sdk README pins `encode("你好")` to the middle payload
    /// `呜嗷嗷嗷啊嗷嗷~啊呜~啊~呜呜嗷`; beast_js (the upstream engine) adds the
    /// `~呜嗷` prefix and `啊` suffix.
    #[test]
    fn beast_encode_sdk_vector() {
        let out = to_beast_op(
            &Value::Text("你好".into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap();
        assert_eq!(
            out,
            Value::Text("~呜嗷呜嗷嗷嗷啊嗷嗷~啊呜~啊~呜呜嗷啊".into())
        );
    }

    #[test]
    fn beast_roundtrip() {
        for text in [
            "hello world",
            "中文测试 with emoji \u{1F511} and \u{1F600}",
            "a",
        ] {
            let Value::Text(enc) = to_beast_op(
                &Value::Text(text.into()),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap() else {
                panic!()
            };
            let dec = from_beast_op(
                &Value::Text(enc),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap();
            assert_eq!(dec, Value::Text(text.into()));
        }
    }

    #[test]
    fn beast_accepts_bare_sdk_form() {
        // SycAlright/beast_sdk ships the payload without the ~呜嗷/啊 envelope.
        let out = from_beast_op(
            &Value::Text("呜嗷嗷嗷啊嗷嗷~啊呜~啊~呜呜嗷".into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap();
        assert_eq!(out, Value::Text("你好".into()));
    }

    #[test]
    fn beast_rejects_bad_codec_and_foreign_chars() {
        let mut params = ParamMap::new();
        params.insert("codec", "嗷呜啊");
        assert!(from_beast_op(
            &Value::Text("~呜嗷啊".into()),
            &params,
            &ExecutionContext::new()
        )
        .is_err());
        let err = from_beast_op(
            &Value::Text("~呜嗷Xy啊".into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap_err();
        assert!(
            err.message.contains("not in the beast codec"),
            "{}",
            err.message
        );
        // Truncated payload: odd character count in the middle.
        let err = from_beast_op(
            &Value::Text("~呜嗷呜嗷嗷啊".into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap_err();
        assert!(err.message.contains("truncated"), "{}", err.message);
    }

    // ------------------------------------------------------ bear ----

    #[test]
    fn bear_dict_shape() {
        assert_eq!(BEAR_DICT.chars().count(), 91);
    }

    /// ToolsFx wiki vector (doc/wiki/CTF.md, 熊曰 section): the plaintext is a
    /// greasyfork userscript URL, as noted in the wiki ("结果是油猴脚本链接").
    #[test]
    fn bear_decode_reference_vector() {
        let wiki = "熊曰：呋性呱吖萌盜性森破捕訴嗒喜冬呱唬嗡盜偶哈魚嗥麼噔囑襲達嗥取喜捕嘿家咬嗡性既洞喜達嗒嘿沒類嚁麼常哈現襲啽樣動你嗅嘍嗚爾現氏蜜動眠常嗡嗥破住啽嗥囑更沒常破嘍森唬偶嗅人氏拙怎噔雜很誒";
        let out = from_bear_op(
            &Value::Text(wiki.into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap();
        assert_eq!(
            out,
            Value::Text("https://greasyfork.org/zh-CN/scripts/439266-网盘有效性检查".into())
        );
    }

    #[test]
    fn bear_roundtrip() {
        for text in ["bear says hello", "熊出没注意！\nsecond line"] {
            let Value::Text(enc) = to_bear_op(
                &Value::Text(text.into()),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap() else {
                panic!()
            };
            assert!(enc.starts_with(BEAR_HEADER));
            let dec = from_bear_op(
                &Value::Text(enc),
                &ParamMap::new(),
                &ExecutionContext::new(),
            )
            .unwrap();
            assert_eq!(dec, Value::Text(text.into()));
        }
    }

    #[test]
    fn bear_rejects_unknown_char_and_missing_marker() {
        let err = from_bear_op(
            &Value::Text("熊曰：呋性X".into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap_err();
        assert!(
            err.message.contains("not in the bear dictionary"),
            "{}",
            err.message
        );
        let err = from_bear_op(
            &Value::Text("熊曰：性很".into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap_err();
        assert!(err.message.contains("marker"), "{}", err.message);
        let err = from_bear_op(
            &Value::Text("性很雜".into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap_err();
        assert!(err.message.contains("must start with"), "{}", err.message);
    }

    #[test]
    fn base91_known_answer() {
        assert!(base91_encode_values(b"").is_empty());
        assert_eq!(base91_decode_values(&[]).unwrap(), Vec::<u8>::new());
        let values = base91_encode_values(&[0, 0, 0]);
        assert_eq!(base91_decode_values(&values).unwrap(), vec![0, 0, 0]);
        // Every byte sequence round-trips through the value coder.
        for data in [b"abc".as_slice(), &[0xffu8, 0x10, 0x88, 0x01], &[0x7fu8; 5]] {
            let values = base91_encode_values(data);
            assert!(values.iter().all(|&v| v < 91));
            assert_eq!(base91_decode_values(&values).unwrap(), data);
        }
    }

    // --------------------------------------------- core values ----

    /// ToolsFx wiki vector (doc/wiki/CTF.md, socialCoreValue section) decodes
    /// to `hello开发工具箱`.
    #[test]
    fn core_values_decode_reference_vector() {
        let wiki = "公正爱国公正平等公正诚信文明公正诚信文明公正诚信平等友善爱国平等诚信民主诚信文明爱国富强友善爱国平等爱国诚信平等敬业民主诚信自由平等友善平等法治诚信富强平等友善爱国平等爱国平等诚信民主法治诚信自由法治友善自由友善爱国友善平等民主";
        let out = from_core_values_op(
            &Value::Text(wiki.into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap();
        assert_eq!(out, Value::Text("hello开发工具箱".into()));
    }

    #[test]
    fn core_values_roundtrip() {
        let text = "Core values 007!";
        let Value::Text(enc) = to_core_values_op(
            &Value::Text(text.into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(enc.chars().count() % 2, 0);
        let dec = from_core_values_op(
            &Value::Text(enc),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap();
        assert_eq!(dec, Value::Text(text.into()));
    }

    #[test]
    fn core_values_rejects_bad_pairs() {
        let err = from_core_values_op(
            &Value::Text("富强民".into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap_err();
        assert!(err.message.contains("truncated"), "{}", err.message);
        let err = from_core_values_op(
            &Value::Text("富强誒怎".into()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .unwrap_err();
        assert!(err.message.contains("not one of the 12"), "{}", err.message);
    }

    // -------------------------------------------------- aaencode ----

    /// Reference-format sample produced by the utf-8.jp `aaencode` algorithm
    /// (preamble byte-for-byte from the upstream script) for
    /// `alert("Hello, JavaScript")`, the canonical utf-8.jp demo input.
    const AA_ALERT_SAMPLE: &str = include_str!("../vectors/specialty/aa_sample_alert.txt");
    const AA_CJK_SAMPLE: &str = include_str!("../vectors/specialty/aa_sample_cjk.txt");
    const JJ_ALERT_SAMPLE: &str = include_str!("../vectors/specialty/jj_sample_alert.txt");

    #[test]
    fn aa_decode_reference_alert_sample() {
        let out = aa_decode_text(AA_ALERT_SAMPLE).unwrap();
        assert_eq!(out, "alert(\"Hello, JavaScript\")");
    }

    /// CJK sample: every code unit above 127 rides a `\uXXXX` escape.
    #[test]
    fn aa_decode_reference_cjk_sample() {
        let out = aa_decode_text(AA_CJK_SAMPLE).unwrap();
        assert_eq!(out, "文章テスト");
    }

    #[test]
    fn aa_rejects_non_aa_input() {
        let err = aa_decode_text("alert(1);").unwrap_err();
        assert!(err.message.contains("not AAEncode"), "{}", err.message);
        let truncated = AA_ALERT_SAMPLE.split_once("(ﾟДﾟ)[ﾟoﾟ]+ ").unwrap().0;
        let err = aa_decode_text(truncated).unwrap_err();
        assert!(err.message.contains("not AAEncode"), "{}", err.message);
    }

    // ------------------------------------------------- jjencode ----

    #[test]
    fn jj_decode_reference_alert_sample() {
        // The tail invariant must hold for the marker search; pin it so a
        // resampled fixture fails here with a clear message, not deep inside
        // the decoder.
        assert!(
            JJ_ALERT_SAMPLE.ends_with("\"\\\"\"\")())();") || JJ_ALERT_SAMPLE.ends_with(")())();"),
            "JJ sample tail changed: {:?}",
            JJ_ALERT_SAMPLE.chars().rev().take(24).collect::<Vec<_>>()
        );
        let out = jj_decode_text(JJ_ALERT_SAMPLE).unwrap();
        assert_eq!(out, "alert(\"Hello, JavaScript\")");
    }

    #[test]
    fn jj_rejects_non_jj_and_palindrome() {
        let err = jj_decode_text("alert(1);").unwrap_err();
        assert!(err.message.contains("not JJEncode"), "{}", err.message);
        // Palindrome-wrapped variant (encode_jj with p = true).
        let palindrome = "\"'\\\"+\\'+\",$=~[];...";
        let err = jj_decode_text(palindrome).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Unsupported);
        assert!(err.message.contains("palindrome"), "{}", err.message);
    }

    // -------------------------------------------------- AES glue ----

    /// NIST SP 800-38A F.2.5 AES-256-CBC known-answer (first block).
    #[test]
    fn aes256_cbc_nist_vector() {
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let pt: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expected: [u8; 16] = [
            0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b,
            0xfb, 0xd6,
        ];
        let mut buf = pt;
        cbc::encrypt(&key, &iv, &mut buf);
        assert_eq!(buf, expected);
        cbc::decrypt(&key, &iv, &mut buf);
        assert_eq!(buf, pt);
    }

    #[test]
    fn pkcs7_pad_unpad_roundtrip() {
        for len in 0..32usize {
            let mut data: Vec<u8> = (0..len as u8).collect();
            let expected: Vec<u8> = (0..len as u8).collect();
            pkcs7_pad(&mut data);
            assert_eq!(data.len(), (len / 16 + 1) * 16);
            assert_eq!(pkcs7_unpad(&data).unwrap(), expected);
        }
        assert!(pkcs7_unpad(&[0x00; 16]).is_err());
        assert!(pkcs7_unpad(&[0x11; 16]).is_err());
        // Any buffer ending in 0x01 is VALID padding (pad length 1) — the
        // earlier expectation here rejected correct ciphertexts.
        assert_eq!(pkcs7_unpad(&[0x02, 0x01]).unwrap().len(), 1);
        assert!(pkcs7_unpad(&[0x01, 0x05]).is_err()); // pad > buffer length
        assert!(pkcs7_unpad(&[0x00, 0x00, 0x02]).is_err()); // inconsistent pad
    }
}
