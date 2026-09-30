//! Crate-local error transport.
//!
//! Upstream `sstv-auto` used `anyhow` for error plumbing. CyberCipher does
//! not carry `anyhow`, so this module provides the minimal equivalent the
//! migrated modules need: one [`SstvError`] type carrying a human-readable
//! message plus an optional source error, a [`Context`] extension trait
//! mirroring `anyhow::Context`, and drop-in `anyhow!`/`bail!` macros. The
//! macro names are kept identical to upstream so the migrated algorithm code
//! and its doc comments stay verbatim.
//!
//! `Display` behaves like `anyhow::Error`: `{}` renders the top-level
//! message, and the alternate form `{:#}` renders the whole chain
//! (`message: source`), which is what the migrated tests assert on.

use std::fmt;

/// The error type for this crate: a message plus an optional underlying
/// source error.
#[derive(Debug)]
pub struct SstvError {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl SstvError {
    /// Create an error from a message.
    #[must_use]
    pub fn msg(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }
}

impl fmt::Display for SstvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)?;
        if f.alternate() {
            let mut source = std::error::Error::source(self);
            while let Some(error) = source {
                write!(f, ": {error}")?;
                source = error.source();
            }
        }
        Ok(())
    }
}

impl std::error::Error for SstvError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|error| &**error as &(dyn std::error::Error + 'static))
    }
}

/// Crate-wide result alias standing in for `anyhow::Result`.
pub type Result<T> = std::result::Result<T, SstvError>;

/// Mirror of `anyhow::Context`: attach a message to an error, keeping the
/// original error as the source.
pub trait Context<T> {
    /// Wrap the error's report with `message`.
    fn context(self, message: impl Into<String>) -> Result<T>;

    /// Wrap the error's report with a lazily formatted message.
    fn with_context<F>(self, producer: F) -> Result<T>
    where
        F: FnOnce() -> String;
}

impl<T, E> Context<T> for std::result::Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn context(self, message: impl Into<String>) -> Result<T> {
        self.with_context(|| message.into())
    }

    fn with_context<F>(self, producer: F) -> Result<T>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|error| SstvError {
            message: producer(),
            source: Some(Box::new(error)),
        })
    }
}

/// Drop-in replacement for `anyhow!`, producing a [`SstvError`].
#[macro_export]
macro_rules! anyhow {
    ($($arg:tt)*) => { $crate::error::SstvError::msg(format!($($arg)*)) };
}

/// Drop-in replacement for `bail!`, returning a [`SstvError`].
#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => { return Err($crate::anyhow!($($arg)*)) };
}
