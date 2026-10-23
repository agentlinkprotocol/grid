use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("invalid signature: {0}")]
    Signature(&'static str),
    #[error("invalid {field}: {reason}")]
    Invalid { field: &'static str, reason: String },
    #[error("expired")]
    Expired,
    #[error("version {got} is not newer than {known}")]
    StaleVersion { got: u64, known: u64 },
    #[error("proof of work does not meet difficulty {0}")]
    ProofOfWork(u32),
    #[error("quota exceeded for operator")]
    Quota,
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Error::Invalid { field, reason: reason.into() }
    }
}
