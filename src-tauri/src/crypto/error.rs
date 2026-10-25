//! Unified error type for the cryptographic layer.

use std::fmt;

/// Errors produced by the cryptographic core.
///
/// We deliberately expose no secret material in any `Display`/`Debug` output.
#[derive(Debug)]
pub enum CryptoError {
    /// Invalid or malformed input (wrong sizes, bad magic, truncated blob).
    InvalidFormat(String),
    /// Authentication failed (GCM tag mismatch → wrong key or tampered data).
    AuthenticationFailed,
    /// A cryptographic primitive rejected an input (bad key length, etc.).
    Primitive(String),
    /// The X25519 exchange produced an all-zero / non-contributory secret.
    AllZeroSharedSecret,
    /// Underlying OS RNG failure.
    Random(String),
    /// Unsupported vault format version.
    UnsupportedVersion(u8),
    /// A passphrase was required but not supplied (or vice-versa).
    MissingPassphrase,
    /// Other (wraps foreign errors where the type is not otherwise useful).
    #[allow(dead_code)] // used by the upcoming DPAPI / vault layer
    Other(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidFormat(m) => write!(f, "invalid format: {m}"),
            CryptoError::AuthenticationFailed => write!(f, "authentication failed"),
            CryptoError::Primitive(m) => write!(f, "crypto primitive error: {m}"),
            CryptoError::AllZeroSharedSecret => {
                write!(f, "X25519 produced an all-zero shared secret")
            }
            CryptoError::Random(m) => write!(f, "RNG failure: {m}"),
            CryptoError::UnsupportedVersion(v) => write!(f, "unsupported vault version {v}"),
            CryptoError::MissingPassphrase => write!(f, "passphrase required"),
            CryptoError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<getrandom::Error> for CryptoError {
    fn from(e: getrandom::Error) -> Self {
        CryptoError::Random(e.to_string())
    }
}

impl From<aes_gcm::Error> for CryptoError {
    fn from(_: aes_gcm::Error) -> Self {
        // GCM errors on decrypt are overwhelmingly authentication failures.
        CryptoError::AuthenticationFailed
    }
}

impl From<hkdf::InvalidLength> for CryptoError {
    fn from(e: hkdf::InvalidLength) -> Self {
        CryptoError::Primitive(format!("HKDF length: {e}"))
    }
}

impl From<argon2::Error> for CryptoError {
    fn from(e: argon2::Error) -> Self {
        CryptoError::Primitive(format!("Argon2: {e}"))
    }
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, CryptoError>;
