//! Vault lifecycle: create, open, unlock.
//!
//! A vault is a directory containing:
//! * `vault.meta` — JSON metadata: public keys, DPAPI-sealed private keys, and a
//!   passphrase verifier.
//! * `manifest.qvault` — encrypted file index (separate module).
//! * `<opaque-id>.qvault` — one encrypted blob per plaintext file.
//!
//! The device keypair (ML-KEM-768 + X25519) is generated once and its private
//! halves are sealed with DPAPI, so only the same Windows user/machine can unseal
//! them. The passphrase verifier allows fast unlock + cross-device recovery.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::crypto::error::{CryptoError, Result};
use crate::crypto::{aead, dpapi, kdf, kem};

/// Metadata filename inside a vault directory.
pub const META_FILENAME: &str = "vault.meta";
/// Encrypted manifest filename.
pub const MANIFEST_FILENAME: &str = "manifest.qvault";

const META_FORMAT: &str = "qvault-desktop";
const META_VERSION: u32 = 1;
/// Constant authenticated inside the verifier to confirm a correct passphrase.
const VERIFIER_PLAINTEXT: &[u8] = b"qvault-passphrase-verifier-v1";
/// Combined sealed-private length: X25519 scalar (32) + ML-KEM seed (64).
const SEALED_PRIV_LEN: usize = 32 + 64;

/// Serialized vault metadata (stored as `vault.meta`).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultMeta {
    pub format: String,
    pub version: u32,
    /// ML-KEM-768 public key (base64).
    pub mlkem_pub_b64: String,
    /// X25519 public key (base64).
    pub x25519_pub_b64: String,
    /// DPAPI-sealed X25519 scalar ‖ ML-KEM seed (base64).
    pub sealed_priv_b64: String,
    /// Argon2 salt for the passphrase verifier (base64).
    pub verify_salt_b64: String,
    /// AES-GCM(Argon2id(passphrase), VERIFIER_PLAINTEXT) (base64).
    pub verifier_b64: String,
}

impl VaultMeta {
    /// Decode the public keys (used for encryption on any machine).
    pub fn public_keys(&self) -> Result<kem::VaultPublic> {
        let mlkem = decode_b64(&self.mlkem_pub_b64)?;
        let x25519: [u8; 32] = decode_b64(&self.x25519_pub_b64)?
            .try_into()
            .map_err(|_| CryptoError::InvalidFormat("X25519 public key length".into()))?;
        Ok(kem::VaultPublic { mlkem, x25519 })
    }

    /// Unseal the device private keys via DPAPI.
    ///
    /// Returns `None` if unsealing fails — e.g. a different machine/user, or the
    /// sealed blob was tampered with. The passphrase leg still works in that case.
    pub fn unseal_device_keys(&self) -> Option<kem::VaultPrivate> {
        let sealed = decode_b64(&self.sealed_priv_b64).ok()?;
        let raw = dpapi::unseal(&sealed).ok()?;
        if raw.len() != SEALED_PRIV_LEN {
            return None;
        }
        let x25519: [u8; 32] = raw[..32].try_into().ok()?;
        let mlkem = raw[32..].to_vec();
        Some(kem::VaultPrivate { mlkem, x25519 })
    }

    /// Verify a passphrase and derive the session passphrase KEK in one Argon2 pass.
    pub fn derive_pass_kek(&self, passphrase: &[u8]) -> Result<[u8; 32]> {
        let salt = decode_b64(&self.verify_salt_b64)?;
        let verifier = decode_b64(&self.verifier_b64)?;
        let pass_kek = kdf::derive(passphrase, &salt)?;
        // GCM auth failure ⇒ wrong passphrase.
        aead::decrypt(&pass_kek, &verifier)?;
        Ok(pass_kek)
    }
}

/// An open (unlocked) vault.
pub struct Vault {
    /// Absolute path to the vault directory.
    pub path: PathBuf,
    /// Public keys (always available).
    pub vault_pub: kem::VaultPublic,
    /// Unsealed device private keys, if DPAPI succeeded on this machine.
    pub device_priv: Option<kem::VaultPrivate>,
    /// Session passphrase KEK (derived once at unlock).
    pub pass_kek: [u8; 32],
}

impl Vault {
    /// Create a new vault at `path`, protected by `passphrase`.
    ///
    /// Generates the device keypair, seals the private halves with DPAPI, and
    /// writes `vault.meta`. Fails if a vault already exists at `path`.
    pub fn create(path: &Path, passphrase: &[u8]) -> Result<Self> {
        // Name-conflict guard: the target must not already exist. (Windows
        // itself refuses duplicate names; we surface a clearer error.)
        if path.exists() {
            return Err(CryptoError::Other(format!(
                "a folder named \"{}\" already exists here — choose a different name",
                path.file_name().and_then(|n| n.to_str()).unwrap_or("vault")
            )));
        }
        std::fs::create_dir_all(path)
            .map_err(|e| CryptoError::Other(format!("create vault dir: {e}")))?;

        // Best-effort: tag the folder with a custom icon via desktop.ini.
        let _ = crate::folder_icon::apply(path);

        // Device keypair.
        let privk = kem::generate_keypair();
        let pubk = privk.public();

        // Seal private halves: x25519 scalar (32) ‖ ml-kem seed (64).
        let mut raw = Vec::with_capacity(SEALED_PRIV_LEN);
        raw.extend_from_slice(&privk.x25519);
        raw.extend_from_slice(&privk.mlkem);
        let sealed = dpapi::seal(&raw)?;

        // Passphrase verifier.
        let verify_salt = kdf::new_salt()?;
        let pass_kek = kdf::derive(passphrase, &verify_salt)?;
        let verifier = aead::encrypt(&pass_kek, VERIFIER_PLAINTEXT)?;
        let meta = VaultMeta {
            format: META_FORMAT.to_string(),
            version: META_VERSION,
            mlkem_pub_b64: STANDARD.encode(&pubk.mlkem),
            x25519_pub_b64: STANDARD.encode(&pubk.x25519),
            sealed_priv_b64: STANDARD.encode(&sealed),
            verify_salt_b64: STANDARD.encode(&verify_salt),
            verifier_b64: STANDARD.encode(&verifier),
        };

        let json = serde_json::to_string_pretty(&meta)
            .map_err(|e| CryptoError::Other(format!("serialize meta: {e}")))?;
        let meta_path = path.join(META_FILENAME);
        std::fs::write(&meta_path, json)
            .map_err(|e| CryptoError::Other(format!("write vault.meta: {e}")))?;

        Ok(Vault {
            path: path.to_path_buf(),
            vault_pub: pubk,
            device_priv: Some(privk),
            pass_kek,
        })
    }

    /// Open an existing vault and verify `passphrase`.
    ///
    /// Unseals device keys if DPAPI permits (this machine); otherwise `device_priv`
    /// is `None` and only the passphrase leg is available.
    pub fn open(path: &Path, passphrase: &[u8]) -> Result<Self> {
        let meta_path = path.join(META_FILENAME);
        let json = std::fs::read_to_string(&meta_path)
            .map_err(|e| CryptoError::Other(format!("read vault.meta: {e}")))?;
        let meta: VaultMeta = serde_json::from_str(&json)
            .map_err(|e| CryptoError::InvalidFormat(format!("parse vault.meta: {e}")))?;

        if meta.format != META_FORMAT || meta.version != META_VERSION {
            return Err(CryptoError::InvalidFormat(format!(
                "unsupported vault metadata {} v{}",
                meta.format, meta.version
            )));
        }

        let pass_kek = meta.derive_pass_kek(passphrase)?;
        let vault_pub = meta.public_keys()?;
        let device_priv = meta.unseal_device_keys();

        Ok(Vault {
            path: path.to_path_buf(),
            vault_pub,
            device_priv,
            pass_kek,
        })
    }
}

fn decode_b64(s: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(s)
        .map_err(|e| CryptoError::InvalidFormat(format!("base64 decode: {e}")))
}

/// Recursively find directories containing a `vault.meta` (existing vaults).
///
/// If `root` itself is a vault, it is returned directly; otherwise its
/// subfolders are scanned. Does not descend *into* a found vault (a vault is a
/// leaf). Sorted for a stable UI order.
pub fn find_vaults(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if root.join(META_FILENAME).exists() {
        out.push(root.to_path_buf());
    } else {
        find_vaults_recursive(root, &mut out);
    }
    out.sort();
    out
}

fn find_vaults_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.join(META_FILENAME).exists() {
                out.push(path);
            } else {
                find_vaults_recursive(&path, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_vault_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "qvault-test-{name}-{}",
            std::process::id()
        ))
    }

    fn clean(path: &Path) {
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn create_and_open_round_trip() {
        let path = temp_vault_path("roundtrip");
        clean(&path);
        let pass = b"correct horse battery staple";

        let v = Vault::create(&path, pass).unwrap();
        assert!(v.device_priv.is_some());

        let v2 = Vault::open(&path, pass).unwrap();
        assert_eq!(v2.vault_pub.mlkem, v.vault_pub.mlkem);
        assert_eq!(v2.vault_pub.x25519, v.vault_pub.x25519);
        assert!(v2.device_priv.is_some());
        clean(&path);
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let path = temp_vault_path("wrongpass");
        clean(&path);
        Vault::create(&path, b"the right passphrase").unwrap();
        assert!(matches!(
            Vault::open(&path, b"the wrong passphrase"),
            Err(CryptoError::AuthenticationFailed)
        ));
        clean(&path);
    }

    #[test]
    fn create_twice_fails() {
        let path = temp_vault_path("twice");
        clean(&path);
        Vault::create(&path, b"passphrase").unwrap();
        assert!(Vault::create(&path, b"passphrase").is_err());
        clean(&path);
    }

    #[test]
    fn tampered_sealed_key_means_no_device_keys_but_passphrase_ok() {
        let path = temp_vault_path("tamper");
        clean(&path);
        let pass = b"recovery passphrase";
        Vault::create(&path, pass).unwrap();

        // Simulate a different machine: corrupt the DPAPI-sealed private key.
        let meta_path = path.join(META_FILENAME);
        let json = std::fs::read_to_string(&meta_path).unwrap();
        let mut meta: VaultMeta = serde_json::from_str(&json).unwrap();
        meta.sealed_priv_b64 = STANDARD.encode(b"not-unsealable-here");
        std::fs::write(&meta_path, serde_json::to_string(&meta).unwrap()).unwrap();

        // Passphrase still verifies, but device keys can't be unsealed.
        let v = Vault::open(&path, pass).unwrap();
        assert!(v.device_priv.is_none());
        clean(&path);
    }

    #[test]
    fn public_keys_are_stable_across_open() {
        let path = temp_vault_path("stable");
        clean(&path);
        Vault::create(&path, b"passphrase").unwrap();
        let a = Vault::open(&path, b"passphrase").unwrap();
        let b = Vault::open(&path, b"passphrase").unwrap();
        assert_eq!(a.vault_pub.mlkem, b.vault_pub.mlkem);
        assert_eq!(a.vault_pub.x25519, b.vault_pub.x25519);
        clean(&path);
    }
}
