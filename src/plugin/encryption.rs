use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("Encryption key not configured")]
    KeyNotConfigured,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid ciphertext format")]
    InvalidFormat,
}

const NONCE_SIZE: usize = 12;

/// Encrypt data using AES-256-GCM
/// Returns: nonce || ciphertext || tag (concatenated)
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncryptionError::EncryptionFailed)?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    // Concatenate: nonce || ciphertext
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data encrypted with encrypt()
pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if ciphertext.len() < NONCE_SIZE + 16 {
        // Minimum: nonce + auth tag
        return Err(EncryptionError::InvalidFormat);
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncryptionError::DecryptionFailed)?;

    let nonce = Nonce::from_slice(&ciphertext[..NONCE_SIZE]);
    let encrypted = &ciphertext[NONCE_SIZE..];

    cipher
        .decrypt(nonce, encrypted)
        .map_err(|_| EncryptionError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"hello world";

        let ciphertext = encrypt(&key, plaintext).unwrap();
        assert_ne!(&ciphertext[NONCE_SIZE..], plaintext);

        let decrypted = decrypt(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_nonces() {
        let key = [0x42u8; 32];
        let plaintext = b"hello world";

        let ct1 = encrypt(&key, plaintext).unwrap();
        let ct2 = encrypt(&key, plaintext).unwrap();

        // Same plaintext should produce different ciphertext (different nonces)
        assert_ne!(ct1, ct2);

        // Both should decrypt correctly
        assert_eq!(decrypt(&key, &ct1).unwrap(), plaintext);
        assert_eq!(decrypt(&key, &ct2).unwrap(), plaintext);
    }

    #[test]
    fn test_invalid_ciphertext() {
        let key = [0x42u8; 32];

        // Too short
        assert!(matches!(
            decrypt(&key, &[0u8; 10]),
            Err(EncryptionError::InvalidFormat)
        ));

        // Corrupted
        let mut ciphertext = encrypt(&key, b"hello").unwrap();
        ciphertext[NONCE_SIZE] ^= 0xFF;
        assert!(matches!(
            decrypt(&key, &ciphertext),
            Err(EncryptionError::DecryptionFailed)
        ));
    }
}
