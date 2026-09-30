//! Payload classification for extracted byte streams — a port of the
//! StegSolver `PayloadDetector` / `PayloadType` (reference commit `c14bfa9`,
//! MIT) reduced to what the Auto LSB scanner consumes.
//!
//! Provenance note (see `compatibility/stegsolver.toml`,
//! `auto_lsb_scoring`): this module intentionally mirrors the *upstream*
//! signature list — ZIP/7z/RAR/gzip/bzip2/xz/tar/PNG/JPEG/GIF/BMP/WebP/PDF/
//! ELF/PE/Java class plus text/base64/binary — because the scoring table in
//! [`crate::auto_lsb`] is keyed on exactly these types.
//! `cybercipher-codec::fileinfo` has the same magic prefixes for the
//! overlapping formats but does not expose a reusable sniff function, and the
//! two tables are not identical (the codec carries more formats and no
//! text/base64 classification). When the codec grows a public
//! file-sniff API, the magic half of this module should delegate to it; the
//! text classification stays here either way. Entropy is
//! `cybercipher_core::util::shannon_entropy` — one scoring system, no fork.

use cybercipher_core::util::shannon_entropy;

/// What an extracted byte stream looks like. Mirrors the upstream
/// `PayloadType` enum one-to-one (badge text included).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadType {
    Empty,
    Zip,
    SevenZip,
    Rar,
    Gzip,
    Bzip2,
    Xz,
    Tar,
    Png,
    Jpeg,
    Gif,
    Bmp,
    WebP,
    Pdf,
    Elf,
    Pe,
    JavaClass,
    TextUtf8,
    TextAscii,
    Base64Text,
    Binary,
}

impl PayloadType {
    /// Stable identifier used in JSON output (`"zip"`, `"7z"`, `"text"`...).
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            PayloadType::Empty => "empty",
            PayloadType::Zip => "zip",
            PayloadType::SevenZip => "7z",
            PayloadType::Rar => "rar",
            PayloadType::Gzip => "gzip",
            PayloadType::Bzip2 => "bzip2",
            PayloadType::Xz => "xz",
            PayloadType::Tar => "tar",
            PayloadType::Png => "png",
            PayloadType::Jpeg => "jpeg",
            PayloadType::Gif => "gif",
            PayloadType::Bmp => "bmp",
            PayloadType::WebP => "webp",
            PayloadType::Pdf => "pdf",
            PayloadType::Elf => "elf",
            PayloadType::Pe => "pe",
            PayloadType::JavaClass => "class",
            PayloadType::TextUtf8 => "text-utf8",
            PayloadType::TextAscii => "text-ascii",
            PayloadType::Base64Text => "base64",
            PayloadType::Binary => "binary",
        }
    }

    /// Short badge text such as `ZIP` (upstream `badge()`; `7z`/`Class`
    /// collapse to the same badges as the table display uses).
    #[must_use]
    pub fn badge(self) -> &'static str {
        match self {
            PayloadType::Empty => "",
            PayloadType::Zip => "ZIP",
            PayloadType::SevenZip => "7z",
            PayloadType::Rar => "RAR",
            PayloadType::Gzip => "GZ",
            PayloadType::Bzip2 => "BZ2",
            PayloadType::Xz => "XZ",
            PayloadType::Tar => "TAR",
            PayloadType::Png => "PNG",
            PayloadType::Jpeg => "JPG",
            PayloadType::Gif => "GIF",
            PayloadType::Bmp => "BMP",
            PayloadType::WebP => "WEBP",
            PayloadType::Pdf => "PDF",
            PayloadType::Elf => "ELF",
            PayloadType::Pe => "EXE",
            PayloadType::JavaClass => "CLASS",
            PayloadType::TextUtf8 | PayloadType::TextAscii => "TXT",
            PayloadType::Base64Text => "B64",
            PayloadType::Binary => "BIN",
        }
    }

    /// Short type name for table display (upstream `LsbCandidate.typeName`).
    #[must_use]
    pub fn type_name(self) -> &'static str {
        match self {
            PayloadType::TextUtf8 | PayloadType::TextAscii => "Text",
            PayloadType::Base64Text => "Base64",
            PayloadType::SevenZip => "7z",
            PayloadType::JavaClass => "Class",
            other => other.badge(),
        }
    }

    #[must_use]
    pub fn is_text(self) -> bool {
        matches!(
            self,
            PayloadType::TextAscii | PayloadType::TextUtf8 | PayloadType::Base64Text
        )
    }
}

/// Facts about a classified payload (the subset of upstream `PayloadInfo`
/// the scanner needs). The detector only inspects; it never decodes further
/// or executes anything.
#[derive(Debug, Clone, PartialEq)]
pub struct PayloadInfo {
    pub payload_type: PayloadType,
    pub length: usize,
    /// Shannon entropy in bits per byte (0.0 ..= 8.0).
    pub entropy: f64,
    /// Number of distinct byte values present.
    pub distinct_bytes: u32,
    /// The payload as UTF-8 text for text-classified payloads.
    pub text: Option<String>,
}

/// Classifies the payload and collects the facts the ranking uses.
#[must_use]
pub fn detect(data: &[u8]) -> PayloadInfo {
    let entropy = shannon_entropy(data);
    let distinct = distinct_byte_values(data);
    if data.is_empty() {
        return PayloadInfo {
            payload_type: PayloadType::Empty,
            length: 0,
            entropy: 0.0,
            distinct_bytes: 0,
            text: None,
        };
    }
    let payload_type = detect_type(data);
    let text = if payload_type.is_text() {
        // Text types are valid UTF-8 by construction (see `is_utf8_text`).
        Some(String::from_utf8_lossy(data).into_owned())
    } else {
        None
    };
    PayloadInfo {
        payload_type,
        length: data.len(),
        entropy,
        distinct_bytes: distinct,
        text,
    }
}

/// Signature-only classification; [`PayloadType::Binary`] when nothing
/// matches. Ported statement-by-statement from upstream
/// `PayloadDetector.detectType` — order matters (BMP before WEBP, PE after
/// ELF, text after every signature).
#[must_use]
pub fn detect_type(data: &[u8]) -> PayloadType {
    if data.is_empty() {
        return PayloadType::Empty;
    }
    if starts_with(data, &[0x50, 0x4B, 0x03, 0x04])
        || starts_with(data, &[0x50, 0x4B, 0x05, 0x06])
        || starts_with(data, &[0x50, 0x4B, 0x07, 0x08])
    {
        return PayloadType::Zip;
    }
    if starts_with(data, &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return PayloadType::SevenZip;
    }
    if starts_with(data, &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]) {
        return PayloadType::Rar;
    }
    if starts_with(data, &[0x1F, 0x8B]) {
        return PayloadType::Gzip;
    }
    if starts_with(data, &[0x42, 0x5A, 0x68]) {
        return PayloadType::Bzip2;
    }
    if starts_with(data, &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
        return PayloadType::Xz;
    }
    if data.len() > 262 && matches_ascii(data, 257, b"ustar") {
        return PayloadType::Tar;
    }
    if starts_with(data, &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return PayloadType::Png;
    }
    if starts_with(data, &[0xFF, 0xD8, 0xFF]) {
        return PayloadType::Jpeg;
    }
    if starts_with(data, b"GIF87a") || starts_with(data, b"GIF89a") {
        return PayloadType::Gif;
    }
    if starts_with(data, b"BM") {
        return PayloadType::Bmp;
    }
    if starts_with(data, b"RIFF") && matches_ascii(data, 8, b"WEBP") {
        return PayloadType::WebP;
    }
    if starts_with(data, &[0x25, 0x50, 0x44, 0x46]) {
        return PayloadType::Pdf;
    }
    if starts_with(data, &[0x7F, 0x45, 0x4C, 0x46]) {
        return PayloadType::Elf;
    }
    if starts_with(data, b"MZ") {
        return PayloadType::Pe;
    }
    if starts_with(data, &[0xCA, 0xFE, 0xBA, 0xBE]) {
        return PayloadType::JavaClass;
    }
    if is_ascii_text(data) {
        return if looks_like_base64(data) {
            PayloadType::Base64Text
        } else {
            PayloadType::TextAscii
        };
    }
    if is_utf8_text(data) {
        return PayloadType::TextUtf8;
    }
    PayloadType::Binary
}

/// Number of distinct byte values present in the payload.
#[must_use]
pub fn distinct_byte_values(data: &[u8]) -> u32 {
    let mut seen = [false; 256];
    let mut distinct = 0;
    for &value in data {
        if !seen[value as usize] {
            seen[value as usize] = true;
            distinct += 1;
        }
    }
    distinct
}

/// True when every byte is printable ASCII (tab, newline and carriage return
/// allowed). Ported from upstream `isAsciiText`.
#[must_use]
pub fn is_ascii_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    data.iter()
        .all(|&value| matches!(value, 9 | 10 | 13) || (0x20..=0x7E).contains(&value))
}

/// True when the payload decodes as UTF-8 and contains no control characters
/// other than tab/newline/CR. Ported from upstream `isUtf8Text`.
#[must_use]
pub fn is_utf8_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    match std::str::from_utf8(data) {
        Ok(text) => text
            .chars()
            .all(|c| c >= ' ' || matches!(c, '\t' | '\n' | '\r')),
        Err(_) => false,
    }
}

/// Heuristic: a base64 blob with a length that is a multiple of four.
/// Ported from upstream `looksLikeBase64` (padding only at the end, at most
/// two pad characters).
#[must_use]
pub fn looks_like_base64(data: &[u8]) -> bool {
    if data.len() < 8 || !data.len().is_multiple_of(4) {
        return false;
    }
    let mut padding = 0;
    for &byte in data {
        let c = byte as char;
        let valid =
            c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '\n' || c == '\r';
        if !valid {
            return false;
        }
        if c == '=' {
            padding += 1;
        } else if padding > 0 {
            return false;
        }
    }
    padding <= 2
}

/// True when the DOS header carries a verified `PE\0\0` signature at the
/// `e_lfanew` offset. Ported from upstream `hasPeHeader` (used by the
/// scoring table to separate a confirmed PE from a bare `MZ`).
#[must_use]
pub fn has_pe_header(data: &[u8]) -> bool {
    if data.len() < 64 {
        return false;
    }
    let offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]);
    let offset = offset as usize;
    offset <= data.len() - 4 && &data[offset..offset + 4] == b"PE\0\0"
}

fn starts_with(data: &[u8], prefix: &[u8]) -> bool {
    data.len() >= prefix.len() && &data[..prefix.len()] == prefix
}

fn matches_ascii(data: &[u8], offset: usize, text: &[u8]) -> bool {
    offset + text.len() <= data.len() && &data[offset..offset + text.len()] == text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_table_matches_upstream_types() {
        assert_eq!(detect_type(b"PK\x03\x04...."), PayloadType::Zip);
        assert_eq!(detect_type(b"PK\x05\x06.."), PayloadType::Zip);
        assert_eq!(detect_type(b"PK\x07\x08.."), PayloadType::Zip);
        assert_eq!(detect_type(b"7z\xBC\xAF\x27\x1C"), PayloadType::SevenZip);
        assert_eq!(detect_type(b"Rar!\x1A\x07"), PayloadType::Rar);
        assert_eq!(detect_type(b"\x1F\x8B\x08\x00"), PayloadType::Gzip);
        assert_eq!(detect_type(b"BZh9...."), PayloadType::Bzip2);
        assert_eq!(detect_type(b"\xFD7zXZ\x00.."), PayloadType::Xz);
        assert_eq!(detect_type(b"\x89PNG\r\n\x1A\n...."), PayloadType::Png);
        assert_eq!(detect_type(b"\xFF\xD8\xFF\xE0.."), PayloadType::Jpeg);
        assert_eq!(detect_type(b"GIF89a..."), PayloadType::Gif);
        assert_eq!(detect_type(b"GIF87a..."), PayloadType::Gif);
        assert_eq!(detect_type(b"BM\x36\x00...."), PayloadType::Bmp);
        assert_eq!(
            detect_type(b"RIFF\x00\x00\x00\x00WEBPVP8 "),
            PayloadType::WebP
        );
        assert_eq!(detect_type(b"%PDF-1.7 ..."), PayloadType::Pdf);
        assert_eq!(detect_type(b"\x7FELF..."), PayloadType::Elf);
        assert_eq!(detect_type(b"MZ.........."), PayloadType::Pe);
        assert_eq!(detect_type(b"\xCA\xFE\xBA\xBE...."), PayloadType::JavaClass);
        assert_eq!(detect_type(b""), PayloadType::Empty);
        assert_eq!(detect_type(b"\xDE\xAD\xBE\xEF"), PayloadType::Binary);
    }

    #[test]
    fn tar_requires_ustar_at_257() {
        let mut tar = vec![0u8; 300];
        tar[257..262].copy_from_slice(b"ustar");
        assert_eq!(detect_type(&tar), PayloadType::Tar);
        // Too short, or magic at the wrong offset: not tar.
        assert_eq!(detect_type(&tar[..250]), PayloadType::Binary);
        let mut wrong = vec![0u8; 300];
        wrong[100..105].copy_from_slice(b"ustar");
        assert_eq!(detect_type(&wrong), PayloadType::Binary);
    }

    #[test]
    fn text_classification_and_base64() {
        assert_eq!(detect_type(b"hello world"), PayloadType::TextAscii);
        assert_eq!(detect_type("héllo wörld".as_bytes()), PayloadType::TextUtf8);
        assert_eq!(detect_type(b"a\x01b"), PayloadType::Binary); // control char
        assert_eq!(detect_type(b"\xFF\xFE"), PayloadType::Binary); // bad UTF-8
        assert_eq!(
            detect_type(b"QUJDREVGR0hJSktMTU5PUQ=="),
            PayloadType::Base64Text
        );
        // Not a multiple of four: plain ASCII, not base64.
        assert_eq!(detect_type(b"QUJDRE="), PayloadType::TextAscii);
        // Padding not at the end: plain ASCII.
        assert_eq!(
            detect_type(b"QU=DREVGR0hJSktMTU5PUQ=="),
            PayloadType::TextAscii
        );
        // Three pad characters: not accepted.
        assert_eq!(detect_type(b"QUJD===="), PayloadType::TextAscii);
    }

    #[test]
    fn pe_header_verification() {
        let mut pe = vec![0u8; 0x44];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        assert!(has_pe_header(&pe));
        // Bare MZ without a verifiable signature.
        assert!(!has_pe_header(b"MZ........."));
        // Offset pointing outside the buffer.
        let mut bad = vec![0u8; 0x44];
        bad[0..2].copy_from_slice(b"MZ");
        bad[0x3C..0x40].copy_from_slice(&0xF0u32.to_le_bytes());
        assert!(!has_pe_header(&bad));
    }

    #[test]
    fn detect_collects_entropy_and_distinct_bytes() {
        let info = detect(b"aaaa");
        assert_eq!(info.payload_type, PayloadType::TextAscii);
        assert_eq!(info.distinct_bytes, 1);
        assert!(info.entropy.abs() < 1e-9);
        assert_eq!(info.text.as_deref(), Some("aaaa"));

        let info = detect(b"");
        assert_eq!(info.payload_type, PayloadType::Empty);
        assert_eq!(info.length, 0);
        assert!(info.text.is_none());

        let info = detect(b"\x00\x01\x02");
        assert_eq!(info.payload_type, PayloadType::Binary);
        assert_eq!(info.distinct_bytes, 3);
        assert!(info.text.is_none());
    }

    #[test]
    fn badges_and_type_names() {
        assert_eq!(PayloadType::Zip.type_name(), "ZIP");
        assert_eq!(PayloadType::TextAscii.type_name(), "Text");
        assert_eq!(PayloadType::Base64Text.type_name(), "Base64");
        assert_eq!(PayloadType::SevenZip.type_name(), "7z");
        assert_eq!(PayloadType::JavaClass.type_name(), "Class");
        assert!(PayloadType::TextUtf8.is_text());
        assert!(!PayloadType::Binary.is_text());
    }
}
