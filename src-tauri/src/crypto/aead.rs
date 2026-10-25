//! AES-256-GCM authenticated encryption helpers.
//!
//! Wire convention matches the Android app: `iv (12 B) ‖ ciphertext ‖ tag (16 B)`.

use aes_gcm::{
    aead::{Aead, KeyInit, Nonce},
    Aes256Gcm,
};

use super::error::{CryptoError, Result};

/// AES key length (bytes).
pub const KEY_LEN: usize = 32;
/// GCM nonce/IV length (bytes).
pub const IV_LEN: usize = 12;
/// GCM authentication tag length (bytes).
pub const TAG_LEN: usize = 16;

/// Encrypt `plaintext` under `key`, returning `iv ‖ ciphertext ‖ tag`.
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::Primitive(e.to_string()))?;
    let iv: [u8; IV_LEN] = super::random()?;
    let nonce = Nonce::<Aes256Gcm>::from(iv);

    let mut ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::Primitive("AES-GCM encrypt failed".into()))?;

    let mut out = Vec::with_capacity(IV_LEN + ct.len());
    out.extend_from_slice(&iv);
    out.append(&mut ct);
    Ok(out)
}

/// Decrypt `blob` (format `iv ‖ ciphertext ‖ tag`) under `key`.
///
/// # Errors
/// [`CryptoError::AuthenticationFailed`] if the tag does not verify (wrong key
/// or tampered data), or [`CryptoError::InvalidFormat`] if the blob is too short.
pub fn decrypt(key: &[u8; KEY_LEN], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < IV_LEN + TAG_LEN {
        return Err(CryptoError::InvalidFormat(format!(
            "ciphertext too short: {} bytes",
            blob.len()
        )));
    }
    let (iv, ct) = blob.split_at(IV_LEN);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::Primitive(e.to_string()))?;
    let nonce = Nonce::<Aes256Gcm>::try_from(iv)
        .map_err(|e| CryptoError::InvalidFormat(e.to_string()))?;
    cipher
        .decrypt(&nonce, ct)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = [9u8; KEY_LEN];
        let pt = b"the quick brown fox jumps over the lazy dog";
        let ct = encrypt(&key, pt).unwrap();
        assert_ne!(&ct[..pt.len()], pt);
        let back = decrypt(&key, &ct).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn iv_is_random_per_call() {
        let key = [9u8; KEY_LEN];
        let a = encrypt(&key, b"same").unwrap();
        let b = encrypt(&key, b"same").unwrap();
        assert_ne!(&a[..IV_LEN], &b[..IV_LEN]);
    }

    #[test]
    fn wrong_key_fails_auth() {
        let ct = encrypt(&[1u8; KEY_LEN], b"secret").unwrap();
        assert!(matches!(
            decrypt(&[2u8; KEY_LEN], &ct),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let key = [3u8; KEY_LEN];
        let mut ct = encrypt(&key, b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(matches!(
            decrypt(&key, &ct),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn short_blob_rejected() {
        assert!(matches!(
            decrypt(&[0u8; KEY_LEN], &[1, 2, 3]),
            Err(CryptoError::InvalidFormat(_))
        ));
    }

    #[test]
    fn empty_plaintext_round_trip() {
        let key = [4u8; KEY_LEN];
        let ct = encrypt(&key, b"").unwrap();
        assert_eq!(ct.len(), IV_LEN + TAG_LEN);
        assert_eq!(decrypt(&key, &ct).unwrap(), b"");
    }
}
