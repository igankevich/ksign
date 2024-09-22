use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("unsupported key/kdf algorithm")]
    Algorithm,
    #[error("verification error")]
    Verification,
    #[error("invalid key/signature/fingerprint format")]
    Format,
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}
