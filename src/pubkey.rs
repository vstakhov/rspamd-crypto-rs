//! Public key encryption operations for Rspamd
//!
//! This module provides public key encryption functionality including support
//! for storing and reusing scalar multiplication results similar to the
//! `crypto_box_beforenm` function in libsodium/NaCl.

use crate::error::RspamdError;
use crate::primitives::{RspamdNM, derive_shared_secret, scalarmult};

use chacha20::XNonce;
use crypto_box::aead::OsRng;
use crypto_box::SecretKey;
use poly1305::Tag;
use std::collections::HashMap;
use chacha20::cipher::crypto_common::rand_core::RngCore;

/// Precomputed shared secret for faster encryption/decryption
pub struct PrecomputedSharedSecret {
    nm: RspamdNM,
}

impl PrecomputedSharedSecret {
    /// Create a new precomputed shared secret from a public key and secret key
    pub fn new(public_key: &[u8], secret_key: &[u8]) -> Result<Self, RspamdError> {
        let scalar_result = scalarmult(secret_key, public_key)?;
        let nm = derive_shared_secret(&scalar_result)?;

        Ok(PrecomputedSharedSecret { nm })
    }

    /// Get the shared secret
    pub fn shared_secret(&self) -> &RspamdNM {
        &self.nm
    }
}

/// Public key encryption manager that can store precomputed shared secrets
pub struct PublicKeyEncryption {
    cached_secrets: HashMap<Vec<u8>, PrecomputedSharedSecret>,
}

impl PublicKeyEncryption {
    /// Create a new public key encryption manager
    pub fn new() -> Self {
        PublicKeyEncryption {
            cached_secrets: HashMap::new(),
        }
    }

    /// Precompute and store a shared secret for later use
    pub fn precompute(&mut self, public_key: &[u8], secret_key: &[u8]) -> Result<(), RspamdError> {
        let shared_secret = PrecomputedSharedSecret::new(public_key, secret_key)?;
        self.cached_secrets.insert(public_key.to_vec(), shared_secret);
        Ok(())
    }

    /// Get a precomputed shared secret, or compute it if not cached
    pub fn get_shared_secret(&mut self, public_key: &[u8], secret_key: &[u8]) -> Result<&RspamdNM, RspamdError> {
        if !self.cached_secrets.contains_key(public_key) {
            self.precompute(public_key, secret_key)?;
        }

        Ok(&self.cached_secrets.get(public_key).unwrap().nm)
    }

    /// Encrypt a message using public key encryption
    pub fn encrypt(&mut self, message: &[u8], recipient_pk: &[u8], sender_sk: &[u8]) -> Result<(Vec<u8>, Tag), RspamdError> {
        let nm = self.get_shared_secret(recipient_pk, sender_sk)?;

        // Generate nonce
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let nonce = XNonce::from_slice(&nonce);

        // Create secretbox
        let secretbox = crate::primitives::StreamEncryption::new(nm, nonce.as_slice())?;

        // Encrypt
        let mut ciphertext = message.to_vec();
        let tag = secretbox.encrypt_in_place(&mut ciphertext);

        // Prepare result with nonce prepended
        let mut result = Vec::with_capacity(24 + ciphertext.len());
        result.extend_from_slice(nonce.as_slice());
        result.extend_from_slice(&ciphertext);

        Ok((result, tag))
    }

    /// Decrypt a message using public key encryption
    pub fn decrypt(&mut self, ciphertext: &[u8], tag: &Tag, sender_pk: &[u8], recipient_sk: &[u8]) -> Result<Vec<u8>, RspamdError> {
        if ciphertext.len() < 24 {
            return Err(RspamdError::EncryptionError("Invalid ciphertext".to_string()));
        }

        let nm = self.get_shared_secret(sender_pk, recipient_sk)?;

        // Extract nonce
        let nonce = &ciphertext[0..24];

        // Create secretbox
        let secretbox = crate::primitives::StreamEncryption::new(nm, nonce)?;

        // Decrypt
        let mut plaintext = ciphertext[24..].to_vec();
        secretbox.decrypt_in_place(&mut plaintext, tag)?;

        Ok(plaintext)
    }
}

impl Default for PublicKeyEncryption {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a new keypair for public key encryption
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let secret_key = SecretKey::generate(&mut OsRng);
    let public_key = secret_key.public_key();

    (secret_key.to_bytes().to_vec(), public_key.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_precomputed_shared_secret() {
        let (sk, pk) = generate_keypair();

        let shared_secret = PrecomputedSharedSecret::new(&pk, &sk).unwrap();
        assert_eq!(shared_secret.shared_secret().as_slice().len(), 32);
    }

    #[test]
    fn test_public_key_encryption() {
        let (alice_sk, alice_pk) = generate_keypair();
        let (bob_sk, bob_pk) = generate_keypair();

        let mut pk_enc = PublicKeyEncryption::new();

        // Alice sends message to Bob
        let message = b"Hello, Bob!";
        let (ciphertext, tag) = pk_enc.encrypt(message, &bob_pk, &alice_sk).unwrap();

        // Bob decrypts message from Alice
        let plaintext = pk_enc.decrypt(&ciphertext, &tag, &alice_pk, &bob_sk).unwrap();

        assert_eq!(plaintext, message);
    }
}
