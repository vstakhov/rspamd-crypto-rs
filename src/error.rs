//! Error types for the Rspamd cryptography library

use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum RspamdError {
    EncryptionError(String),
    SignatureError(String),
    InvalidKeyError(String),
    IOError(std::io::Error),
}

impl Display for RspamdError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RspamdError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            RspamdError::SignatureError(msg) => write!(f, "Signature error: {}", msg),
            RspamdError::InvalidKeyError(msg) => write!(f, "Invalid key: {}", msg),
            RspamdError::IOError(err) => write!(f, "IO error: {}", err),
        }
    }
}

impl std::error::Error for RspamdError {}

impl From<std::io::Error> for RspamdError {
    fn from(error: std::io::Error) -> Self {
        RspamdError::IOError(error)
    }
}
