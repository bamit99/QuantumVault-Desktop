//! Argon2id passphrase key-derivation function.
//!
//! Memory-hard, GPU/ASIC-resistant. Desktop "secure by default" tuning:
//! `t=3`, `m=256 MiB`, `p=1`. Salt is public by design — the passphrase is
//! the secret.

use argon2::{Algorithm, Argon2, Params, Version};

use super::error::{CryptoError, Result};

/// Argon2 salt length (bytes).
pub const SALT_LEN: usize = 32;
/// Derived key length (bytes) — matches a 256-bit AES key.
pub const KEY_LEN: usize = 32;

/// Argon2id cost parameters (secure-by-default desktop profile).
const ITERATIONS: u32 = 3; // t_cost
const MEMORY_KIB: u32 = 256 * 1024; // m_cost — 256 MiB
const PARALLELISM: u32 = 1; // p_cost

/// Generate a fresh random salt.
pub fn new_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt)?;
    Ok(salt)
}

/// Derive a 32-byte key from `passphrase` and `salt`.
///
/// # Errors
/// Returns [`CryptoError`] if the KDF fails (e.g. invalid params) or the RNG
/// used for salt generation fails.
pub fn derive(passphrase: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    if salt.len() != SALT_LEN {
        return Err(CryptoError::InvalidFormat(format!(
            "Argon2 salt must be {SALT_LEN} bytes (got {})",
            salt.len()
        )));
    }
    if passphrase.is_empty() {
        return Err(CryptoError::MissingPassphrase);
    }

    let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, Some(KEY_LEN))
        .map_err(|e| CryptoError::Primitive(format!("Argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| CryptoError::Primitive(format!("Argon2 derive: {e}")))?;
    Ok(out)
}

/// Basic UI-facing strength check. Returns a reason the passphrase is weak, or
/// `None` if acceptable. Kept in sync with the Android app's guidance.
pub fn strength_problem(passphrase: &str) -> Option<&'static str> {
    let word_count = passphrase.split(' ').filter(|w| !w.is_empty()).count();
    if passphrase.len() < 12 && word_count < 4 {
        return Some("Use at least 12 characters or a 4-word passphrase");
    }
    if matches!(
        passphrase.to_ascii_lowercase().as_str(),
        "password" | "passphrase" | "123456789012" | "password1234"
    ) {
        return Some("That passphrase is a gift to attackers — pick something unique");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic() {
        let salt = [7u8; SALT_LEN];
        let a = derive(b"correct horse battery staple", &salt).unwrap();
        let b = derive(b"correct horse battery staple", &salt).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_passphrase_differs() {
        let salt = [7u8; SALT_LEN];
        let a = derive(b"correct horse battery staple", &salt).unwrap();
        let b = derive(b"correct horse battery stapler", &salt).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_salt_differs() {
        let a = derive(b"password", &[1u8; SALT_LEN]).unwrap();
        let b = derive(b"password", &[2u8; SALT_LEN]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn empty_passphrase_rejected() {
        assert!(matches!(
            derive(b"", &[1u8; SALT_LEN]),
            Err(CryptoError::MissingPassphrase)
        ));
    }

    #[test]
    fn wrong_salt_length_rejected() {
        assert!(matches!(
            derive(b"password", &[1u8; 16]),
            Err(CryptoError::InvalidFormat(_))
        ));
    }

    #[test]
    fn output_is_32_bytes() {
        let out = derive(b"password", &[1u8; SALT_LEN]).unwrap();
        assert_eq!(out.len(), KEY_LEN);
    }

    #[test]
    fn strength_check_flags_short() {
        assert!(strength_problem("short").is_some());
    }

    #[test]
    fn strength_check_accepts_long() {
        assert!(strength_problem("this is a fairly long passphrase").is_none());
    }
}
