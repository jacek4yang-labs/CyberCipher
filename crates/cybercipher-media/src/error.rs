//! Typed media errors. Decode/encode failures cross the registry boundary as
//! structured errors, never string parsing.

use std::fmt;

/// Classification of a media (decode/encode) failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaError {
    /// An input exceeded a configured cap (file size or pixel count). The
    /// caps are enforced before any allocation.
    TooLarge {
        what: &'static str,
        limit: u64,
        actual: u64,
    },
    /// The input is not a supported image format.
    UnsupportedFormat { detail: String },
    /// The input is recognized but corrupt, truncated, or undecodable, or a
    /// requested region/dimension is invalid.
    Corrupt { detail: String },
    /// An underlying I/O failure (in-memory decoders rarely produce this).
    Io { detail: String },
}

impl MediaError {
    pub fn unsupported_format(detail: impl Into<String>) -> Self {
        MediaError::UnsupportedFormat {
            detail: detail.into(),
        }
    }

    pub fn corrupt(detail: impl Into<String>) -> Self {
        MediaError::Corrupt {
            detail: detail.into(),
        }
    }

    pub fn io(detail: impl Into<String>) -> Self {
        MediaError::Io {
            detail: detail.into(),
        }
    }

    pub fn too_large(what: &'static str, limit: u64, actual: u64) -> Self {
        MediaError::TooLarge {
            what,
            limit,
            actual,
        }
    }
}

impl fmt::Display for MediaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MediaError::TooLarge {
                what,
                limit,
                actual,
            } => write!(f, "{what} exceeds the configured limit ({actual} > {limit})"),
            MediaError::UnsupportedFormat { detail } => {
                write!(f, "unsupported image format: {detail}")
            }
            MediaError::Corrupt { detail } => write!(f, "corrupt or invalid image: {detail}"),
            MediaError::Io { detail } => write!(f, "image I/O error: {detail}"),
        }
    }
}

impl std::error::Error for MediaError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_human_readable() {
        let e = MediaError::too_large("pixel count", 64 * 1024 * 1024, 100_000_000);
        assert_eq!(
            e.to_string(),
            "pixel count exceeds the configured limit (100000000 > 67108864)"
        );
        let e = MediaError::corrupt("truncated IDAT");
        assert_eq!(e.to_string(), "corrupt or invalid image: truncated IDAT");
        let e = MediaError::unsupported_format("TIFF");
        assert_eq!(e.to_string(), "unsupported image format: TIFF");
    }
}
