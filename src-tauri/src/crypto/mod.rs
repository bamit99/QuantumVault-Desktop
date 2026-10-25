//! Cryptographic core for Quantum Vault (Windows).
//!
//! Modules:
//! * [`aead`] — AES-256-GCM authenticated encryption.
//! * [`kdf`]  — Argon2id passphrase key derivation.
//! * [`kem`]  — ML-KEM-768 + X25519 hybrid key encapsulation.
//! * [`format`] — QVAULT file-blob encode/decode.
//! * [`error`] — unified error type.

pub mod aead;
pub mod dpapi;
pub mod error;
pub mod format;
pub mod kdf;
pub mod kem;

/// Fill `buf` with cryptographically secure random bytes.
pub(crate) fn random<const N: usize>() -> error::Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf)?;
    Ok(buf)
}
