//! Low-level cryptographic primitives used by Rspamd
//!
//! This module contains implementations for basic cryptographic operations
//! such as scalar multiplication and stream encryption.

use chacha20::cipher::consts::U10;
use chacha20::cipher::consts::U32;
use chacha20::cipher::zeroize::Zeroizing;
use chacha20::hchacha;
use chacha20::{cipher::KeyIvInit, XChaCha20};
use chacha20::cipher::{StreamCipher};
use crypto_box::aead::generic_array::{GenericArray, arr};
use curve25519_dalek::{MontgomeryPoint, Scalar};
use curve25519_dalek::scalar::clamp_integer;
use poly1305::{Poly1305, Tag};
use poly1305::universal_hash::{KeyInit};

use crate::error::RspamdError;

pub type RspamdNM = Zeroizing<GenericArray<u8, U32>>;

/// Performs scalar multiplication using X25519
pub fn scalarmult(scalar: &[u8], point: &[u8]) -> Result<Vec<u8>, RspamdError> {
    if scalar.len() != 32 || point.len() != 32 {
        return Err(RspamdError::EncryptionError("Invalid key size".to_string()));
    }

    let scalar_arr: [u8; 32] = scalar.try_into().unwrap();
    let point_arr: [u8; 32] = point.try_into().unwrap();

    let e = Scalar::from_bytes_mod_order(clamp_integer(scalar_arr));
    let p = MontgomeryPoint(point_arr);
    let result = e * p;

    Ok(result.0.to_vec())
}

/// Derive a shared secret from an X25519 point using HChaCha20
pub fn derive_shared_secret(point: &[u8]) -> Result<RspamdNM, RspamdError> {
    if point.len() != 32 {
        return Err(RspamdError::EncryptionError("Invalid point size".to_string()));
    }

    let point_arr: [u8; 32] = point.try_into().unwrap();
    let n0 = arr![u8; 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,];
    Ok(Zeroizing::new(hchacha::<U10>(&point_arr.into(), &n0)))
}

/// Stream encryption implementation using XChaCha20-Poly1305
pub struct StreamEncryption {
    enc_ctx: XChaCha20,
    mac_ctx: Poly1305,
}

impl StreamEncryption {
    /// Create a new stream encryption context
    pub fn new(key: &RspamdNM, nonce: &[u8]) -> Result<Self, RspamdError> {
        if nonce.len() != 24 {
            return Err(RspamdError::EncryptionError("Invalid nonce size".to_string()));
        }

        let nonce_arr = chacha20::XNonce::from_slice(nonce);
        let mut chacha = XChaCha20::new_from_slices(key.as_slice(), nonce_arr.as_slice())
            .map_err(|e| RspamdError::EncryptionError(e.to_string()))?;

        // Generate Poly1305 key using ChaCha20
        let mut mac_key = [0u8; 64];
        chacha.apply_keystream(&mut mac_key);

        // Create Poly1305 context
        let poly = Poly1305::new_from_slice(&mac_key[0..32])
            .map_err(|_| RspamdError::EncryptionError("Failed to create Poly1305 context".to_string()))?;

        Ok(StreamEncryption {
            enc_ctx: chacha,
            mac_ctx: poly,
        })
    }

    /// Encrypt data in place and return authentication tag
    pub fn encrypt_in_place(mut self, data: &mut [u8]) -> Tag {
        self.enc_ctx.apply_keystream(data);
        self.mac_ctx.compute_unpadded(data)
    }

    /// Decrypt data in place if the authentication tag is valid
    pub fn decrypt_in_place(mut self, data: &mut [u8], tag: &Tag) -> Result<(), RspamdError> {
        let computed = self.mac_ctx.compute_unpadded(data);

        if computed != *tag {
            return Err(RspamdError::EncryptionError("Authentication failed".to_string()));
        }

        self.enc_ctx.apply_keystream(data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20::cipher::generic_array::GenericArray;

    #[test]
    fn test_scalarmult() {
        let scalar = [1u8; 32];
        let point = [9u8; 32];

        let result = scalarmult(&scalar, &point).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_derive_shared_secret() {
        let point = [1u8; 32];
        let secret = derive_shared_secret(&point).unwrap();
        assert_eq!(secret.as_slice().len(), 32);
    }

    #[test]
    fn test_stream_encryption() {
        let key = Zeroizing::new(GenericArray::clone_from_slice(&[1u8; 32]));
        let nonce = [1u8; 24];
        let mut data = b"test message".to_vec();

        let enc = StreamEncryption::new(&key, &nonce).unwrap();
        let tag = enc.encrypt_in_place(&mut data);

        // Data should be encrypted
        assert_ne!(data, b"test message");

        let dec = StreamEncryption::new(&key, &nonce).unwrap();
        dec.decrypt_in_place(&mut data, &tag).unwrap();

        assert_eq!(data, b"test message");
    }
}
