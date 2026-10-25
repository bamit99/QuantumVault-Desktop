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

/// Common/compromised substrings that make a passphrase guessable regardless
/// of length (QV2-07). Checked case-insensitively.
const WEAK_PATTERNS: &[&str] = &[
    "password", "passphrase", "letmein", "welcome", "iloveyou", "admin",
    "qwerty", "asdf", "zxcv", "1234", "abcd", "monkey", "dragon", "football",
    "master", "login", "secret", "changeme", "trustno1", "sunshine",
];

/// Strength assessment shared by the UI and the backend policy.
///
/// Returns `None` when acceptable, or a human-readable reason.
///
/// This is deliberately conservative but *heuristic*: it favours length and
/// randomness, and rejects obviously weak material. It is not an entropy
/// estimator — a short passphrase built from common words can still be weak
/// even if it passes. Users should prefer randomly generated multi-word
/// passphrases.
pub fn strength_problem(passphrase: &str) -> Option<&'static str> {
    let chars = passphrase.chars().count();
    let words = passphrase.split(' ').filter(|w| !w.is_empty()).count();

    if chars < 12 && words < 4 {
        return Some("Use at least 12 characters or a 4-word passphrase");
    }

    // Too little variety (e.g. "aaaaaaaaaaaa", "abababababab").
    let mut unique = passphrase.chars().collect::<Vec<_>>();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() < 5 {
        return Some("Too few distinct characters — use something less repetitive");
    }

    let lower = passphrase.to_ascii_lowercase();
    if WEAK_PATTERNS.iter().any(|p| lower.contains(p)) {
        return Some("Contains a very common word or sequence — pick something unique");
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
    fn strength_check_flags_common_and_repetitive() {
        // QV2-07: common sequences and low-variety strings are rejected.
        assert!(strength_problem("qwertyuiop12").is_some());
        assert!(strength_problem("MyPassword2024").is_some());
        assert!(strength_problem("aaaaaaaaaaaaaa").is_some());
        assert!(strength_problem("ababababababab").is_some());
    }

    #[test]
    fn strength_check_accepts_four_random_words() {
        assert!(strength_problem("harbor static pebble wing").is_none());
    }

    #[test]
    fn strength_check_accepts_long() {
        assert!(strength_problem("tundra velvet orbit lamplight").is_none());
    }
}
