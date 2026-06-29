//! Crate-wide error model. Verification failures are first-class so callers
//! can "fail closed" on untrusted data (DESIGN.md principle #7).

use core::fmt;

/// The crate-wide error type.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Transport / connectivity failure.
    Transport(String),
    /// A cryptographic operation failed.
    Crypto(String),
    /// Signature or hash-chain verification failed — data is untrusted.
    Verify(String),
    /// Capability check failed — caller lacks authority.
    Capability(String),
    /// Requested item does not exist.
    NotFound,
    /// Catch-all.
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Transport(s) => write!(f, "transport error: {s}"),
            Error::Crypto(s) => write!(f, "crypto error: {s}"),
            Error::Verify(s) => write!(f, "verification failed: {s}"),
            Error::Capability(s) => write!(f, "capability denied: {s}"),
            Error::NotFound => write!(f, "not found"),
            Error::Other(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for Error {}

/// Convenient result alias used across the framework.
pub type Result<T> = core::result::Result<T, Error>;
