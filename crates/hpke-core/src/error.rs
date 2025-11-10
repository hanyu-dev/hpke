//! Error types

use core::fmt;

use hpke_crypto::CryptoError;

/// HPKE Error types.
#[derive(Debug)]
pub enum Error {
    /// Generic invalid input.
    InvalidInput(&'static str),

    /// Inconsistent PSK input.
    InconsistentPsk,

    /// PSK input is required but missing.
    MissingPsk,

    /// PSK input is provided but not needed.
    UnnecessaryPsk,

    /// PSK input is too short (needs to be at least 32 bytes).
    InsecurePsk,

    /// The message limit for this AEAD, key, and nonce.
    MessageLimitReached,

    /// Error passed from the underlying crypto implementation.
    CryptoError(CryptoError),
}

impl Error {
    /// Returns true if the error is `Error::InvalidInput`.
    pub const fn is_invalid_input(&self) -> bool {
        matches!(self, Error::InvalidInput(_))
    }

    /// Returns true if the error is due to the crypto backend not supporting
    /// the requested KEM.
    pub const fn is_unsupported_kem(&self) -> bool {
        matches!(self, Error::CryptoError(CryptoError::KemUnsupported))
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Error::CryptoError(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidInput(msg) => write!(f, "Invalid input: {msg}"),
            Error::InconsistentPsk => write!(f, "Inconsistent PSK input"),
            Error::MissingPsk => write!(f, "PSK input is required but missing"),
            Error::UnnecessaryPsk => write!(f, "PSK input is provided but not needed"),
            Error::InsecurePsk => {
                write!(f, "PSK input is too short (needs to be at least 32 bytes)")
            }
            Error::MessageLimitReached => {
                write!(f, "The message limit for this AEAD, key, and nonce")
            }
            Error::CryptoError(e) => write!(f, "Crypto error: {e}"),
        }
    }
}

impl From<CryptoError> for Error {
    fn from(e: CryptoError) -> Self {
        Error::CryptoError(e)
    }
}
