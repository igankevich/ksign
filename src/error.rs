use thiserror::Error;

/// Common error values.
#[derive(Debug, Error)]
pub enum Error {
    /// Unsupported key/KDF algorithm.
    #[error("unsupported key/kdf algorithm")]
    Algorithm,
    /// Verification error.
    #[error("verification error")]
    Verification,
    /// Binary format error.
    #[error("invalid key/signature/fingerprint format")]
    Format,
    /// Input/output error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}
