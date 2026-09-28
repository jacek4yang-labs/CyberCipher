//! Typed error model. Errors cross the IPC boundary as structured JSON so the
//! frontend can render useful, actionable diagnostics — never string parsing.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Classification of an operation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// A parameter is missing, malformed, or out of range.
    InvalidParam,
    /// The input value cannot be processed by this operation.
    InvalidInput,
    /// Decoding failed (bad hex, bad base64, invalid UTF-8, ...).
    Decode,
    /// A key/IV has an unacceptable length or content.
    KeyError,
    /// A length constraint is violated (e.g. ciphertext not block aligned).
    LengthMismatch,
    /// The operation does not support the requested configuration.
    Unsupported,
    /// The run was cancelled by the user.
    Cancelled,
    /// A time/size/candidate budget was exhausted.
    BudgetExceeded,
    /// Unexpected internal failure.
    Internal,
}

/// A structured, serializable operation error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationError {
    pub kind: ErrorKind,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

pub type OpResult<T> = Result<T, OperationError>;

impl OperationError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        OperationError {
            kind,
            message: message.into(),
            parameter: None,
            expected: None,
            actual: None,
            details: None,
        }
    }

    pub fn invalid_param(parameter: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidParam, message).with_parameter(parameter)
    }

    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidInput, message)
    }

    pub fn decode(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Decode, message)
    }

    pub fn key(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::KeyError, message)
    }

    pub fn length(
        expected: impl Into<String>,
        actual: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(ErrorKind::LengthMismatch, message)
            .with_expected(expected)
            .with_actual(actual)
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unsupported, message)
    }

    pub fn cancelled() -> Self {
        Self::new(ErrorKind::Cancelled, "Operation cancelled")
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal, message)
    }

    pub fn with_parameter(mut self, p: impl Into<String>) -> Self {
        self.parameter = Some(p.into());
        self
    }

    pub fn with_expected(mut self, e: impl Into<String>) -> Self {
        self.expected = Some(e.into());
        self
    }

    pub fn with_actual(mut self, a: impl Into<String>) -> Self {
        self.actual = Some(a.into());
        self
    }

    pub fn with_details(mut self, d: impl Into<String>) -> Self {
        self.details = Some(d.into());
        self
    }
}

impl fmt::Display for OperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)?;
        if let (Some(e), Some(a)) = (&self.expected, &self.actual) {
            write!(f, " (expected {e}, got {a})")?;
        } else if let Some(a) = &self.actual {
            write!(f, " (got {a})")?;
        }
        Ok(())
    }
}

impl std::error::Error for OperationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_serializes_with_details() {
        let e = OperationError::length("multiple of 16", "37 bytes", "CBC requires full blocks")
            .with_parameter("ciphertext")
            .with_details("use CTR/CFB/OFB or enable CTS");
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("length_mismatch"));
        assert!(json.contains("multiple of 16"));
        let back: OperationError = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, ErrorKind::LengthMismatch);
    }

    #[test]
    fn display_is_human_readable() {
        let e = OperationError::length("16", "7", "bad length");
        assert_eq!(e.to_string(), "bad length (expected 16, got 7)");
    }
}
