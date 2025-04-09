//! Rspamd cryptography support in Rust
//!
//! This library provides cryptographic primitives and protocols used by Rspamd.

pub mod error;
pub mod primitives;
pub mod pubkey;
pub mod signatures;
pub mod keypairs;
pub mod httpcrypt;

// Re-export commonly used types
pub use crate::error::RspamdError;
pub use primitives::RspamdNM;
