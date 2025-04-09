//! Ed25519 signature support for Rspamd
//!
//! This module provides basic Ed25519 signature functionality

use chacha20::cipher::crypto_common::rand_core::RngCore;
use ed25519_dalek::{SecretKey, Signature, Signer, SigningKey, Verifier, VerifyingKey};
use crypto_box::aead::OsRng;

use crate::error::RspamdError;

/// Generate a new Ed25519 keypair
pub fn generate_signing_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut secret = SecretKey::default();
    OsRng.fill_bytes(&mut secret);
    let signing_key: SigningKey = SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();

    (signing_key.to_bytes().to_vec(), verifying_key.to_bytes().to_vec())
}

/// Sign a message using Ed25519
pub fn sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, RspamdError> {
    if secret_key.len() != 32 {
        return Err(RspamdError::SignatureError("Invalid secret key size".to_string()));
    }

    let secret_key_bytes: [u8; 32] = secret_key.try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&secret_key_bytes);

    let signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Verify an Ed25519 signature
pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), RspamdError> {
    if signature.len() != 64 || public_key.len() != 32 {
        return Err(RspamdError::SignatureError("Invalid signature or public key size".to_string()));
    }

    let signature_bytes: [u8; 64] = signature.try_into().unwrap();
    let signature = Signature::from_bytes(&signature_bytes);

    let public_key_bytes: [u8; 32] = public_key.try_into().unwrap();
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|e| RspamdError::SignatureError(format!("Invalid public key: {}", e)))?;

    verifying_key.verify(message, &signature)
        .map_err(|e| RspamdError::SignatureError(format!("Signature verification failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let (sk, pk) = generate_signing_keypair();
        let message = b"test message";

        let signature = sign(message, &sk).unwrap();
        assert_eq!(signature.len(), 64);

        // Verify the signature
        let result = verify(message, &signature, &pk);
        assert!(result.is_ok());

        // Verify with modified message should fail
        let modified_message = b"test message modified";
        let result = verify(modified_message, &signature, &pk);
        assert!(result.is_err());
    }
}
