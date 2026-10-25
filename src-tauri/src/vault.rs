//! Vault lifecycle: create, open, unlock.
//!
//! A vault is a directory containing:
//! * `vault.meta` — JSON metadata: vault ID, public keys, the DPAPI-sealed
//!   private keys, and a passphrase verifier.
//! * `manifest.qvault` — encrypted file index (see [`crate::session`]).
//! * `<opaque-id>.qvault` — one encrypted blob per plaintext file.
//!
//! The device keypair (ML-KEM-768 + X25519) is generated once and its private
//! halves are sealed with DPAPI, so only the same Windows user/machine can
//! unseal them. The passphrase verifier allows fast unlock + cross-device
//! recovery. See `SECURITY.md` for the precise threat model (audit QV-02).

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::crypto::error::{CryptoError, Result};
use crate::crypto::{aead, dpapi, format, kdf, kem};
use crate::manifest::hex;

/// Metadata filename inside a vault directory.
pub const META_FILENAME: &str = "vault.meta";
/// Encrypted manifest filename.
pub const MANIFEST_FILENAME: &str = "manifest.qvault";

const META_FORMAT: &str = "qvault-desktop";
const META_VERSION: u32 = 2;
/// Constant authenticated inside the verifier to confirm a correct passphrase.
const VERIFIER_PLAINTEXT: &[u8] = b"qvault-passphrase-verifier-v1";
/// Combined raw private length: X25519 scalar (32) + ML-KEM seed (64).
const SEALED_PRIV_LEN: usize = 32 + 64;

/// Serialized vault metadata (stored as `vault.meta`).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultMeta {
    pub format: String,
    pub version: u32,
    /// Random per-vault identifier (hex). Binds blobs to this vault via AAD.
    pub vault_id: String,
    /// ML-KEM-768 public key (base64).
    pub mlkem_pub_b64: String,
    /// X25519 public key (base64).
    pub x25519_pub_b64: String,
    /// DPAPI-sealed (AAD ‖ X25519 scalar ‖ ML-KEM seed) (base64).
    pub sealed_priv_b64: String,
    /// Argon2 salt for the passphrase verifier (base64).
    pub verify_salt_b64: String,
    /// AES-GCM(Argon2id(passphrase), VERIFIER_PLAINTEXT, AAD) (base64).
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
    /// Returns `None` if unsealing fails (different machine/user, or tampered
    /// blob). The passphrase leg still works in that case.
    pub fn unseal_device_keys(&self) -> Option<kem::VaultPrivate> {
        let sealed = decode_b64(&self.sealed_priv_b64).ok()?;
        let raw = dpapi::unseal(&sealed).ok()?;

        // Verify the AAD prefix binds this blob to this vault.
        let aad = format::vault_key_aad(&self.vault_id);
        if raw.len() != aad.len() + SEALED_PRIV_LEN || !raw.starts_with(&aad) {
            return None;
        }
        let body = &raw[aad.len()..];
        let x25519: [u8; 32] = body[..32].try_into().ok()?;
        let mlkem = body[32..].to_vec();
        Some(kem::VaultPrivate { mlkem, x25519 })
    }

    /// Verify a passphrase and derive the session passphrase KEK in one Argon2 pass.
    pub fn derive_pass_kek(&self, passphrase: &[u8]) -> Result<[u8; 32]> {
        let salt = decode_b64(&self.verify_salt_b64)?;
        let verifier = decode_b64(&self.verifier_b64)?;
        let pass_kek = kdf::derive(passphrase, &salt)?;
        let aad = format::verifier_aad(&self.vault_id);
        // GCM auth failure ⇒ wrong passphrase (or wrong vault binding).
        aead::decrypt(&pass_kek, &verifier, &aad)?;
        Ok(pass_kek)
    }
}

/// An open (unlocked) vault.
pub struct Vault {
    /// Absolute path to the vault directory.
    pub path: PathBuf,
    /// Random per-vault identifier (binds every blob via AAD).
    pub vault_id: String,
    /// Public keys (always available).
    pub vault_pub: kem::VaultPublic,
    /// Unsealed device private keys, if DPAPI succeeded on this machine.
    pub device_priv: Option<kem::VaultPrivate>,
    /// Session passphrase KEK (derived once at unlock).
    pub pass_kek: [u8; 32],
}

impl Vault {
    /// Create a new vault at `path`, protected by `passphrase`.
    pub fn create(path: &Path, passphrase: &[u8]) -> Result<Self> {
        // Name-conflict guard: the target must not already exist.
        if path.exists() {
            return Err(CryptoError::Other(format!(
                "a folder named \"{}\" already exists here — choose a different name",
                path.file_name().and_then(|n| n.to_str()).unwrap_or("vault")
            )));
        }

        // QV-09: enforce the passphrase policy in the backend, not just the UI.
        enforce_passphrase_policy(passphrase)?;

        std::fs::create_dir_all(path)
            .map_err(|e| CryptoError::Other(format!("create vault dir: {e}")))?;

        // Best-effort: tag the folder with a custom icon via desktop.ini.
        let _ = crate::folder_icon::apply(path);

        // Random vault ID.
        let vault_id = hex(&crate::crypto::random::<16>()?);

        // Device keypair.
        let privk = kem::generate_keypair();
        let pubk = privk.public();

        // Seal private halves, prefixed with the AAD binding to this vault.
        let mut raw = format::vault_key_aad(&vault_id);
        raw.extend_from_slice(&privk.x25519);
        raw.extend_from_slice(&privk.mlkem);
        let sealed = dpapi::seal(&raw)?;

        // Passphrase verifier (AAD-bound).
        let verify_salt = kdf::new_salt()?;
        let pass_kek = kdf::derive(passphrase, &verify_salt)?;
        let verifier =
            aead::encrypt(&pass_kek, VERIFIER_PLAINTEXT, &format::verifier_aad(&vault_id))?;

        let meta = VaultMeta {
            format: META_FORMAT.to_string(),
            version: META_VERSION,
            vault_id: vault_id.clone(),
            mlkem_pub_b64: STANDARD.encode(&pubk.mlkem),
            x25519_pub_b64: STANDARD.encode(&pubk.x25519),
            sealed_priv_b64: STANDARD.encode(&sealed),
            verify_salt_b64: STANDARD.encode(&verify_salt),
            verifier_b64: STANDARD.encode(&verifier),
        };

        let json = serde_json::to_string_pretty(&meta)
            .map_err(|e| CryptoError::Other(format!("serialize meta: {e}")))?;
        write_atomic(&path.join(META_FILENAME), json.as_bytes())?;

        Ok(Vault {
            path: path.to_path_buf(),
            vault_id,
            vault_pub: pubk,
            device_priv: Some(privk),
            pass_kek,
        })
    }

    /// Open an existing vault and verify `passphrase`.
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
        if meta.vault_id.is_empty() {
            return Err(CryptoError::InvalidFormat("vault.meta has no vault ID".into()));
        }

        let pass_kek = meta.derive_pass_kek(passphrase)?;
        let vault_pub = meta.public_keys()?;
        let device_priv = meta.unseal_device_keys();

        Ok(Vault {
            path: path.to_path_buf(),
            vault_id: meta.vault_id.clone(),
            vault_pub,
            device_priv,
            pass_kek,
        })
    }
}

/// Enforce the backend passphrase policy (QV-09).
///
/// UI validation is advisory; this is authoritative for any caller.
fn enforce_passphrase_policy(passphrase: &[u8]) -> Result<()> {
    if passphrase.is_empty() {
        return Err(CryptoError::MissingPassphrase);
    }
    let text = String::from_utf8_lossy(passphrase);
    let word_count = text.split(' ').filter(|w| !w.is_empty()).count();
    // Require ≥ 12 characters, or a ≥ 4-word passphrase.
    if text.chars().count() < 12 && word_count < 4 {
        return Err(CryptoError::Other(
            "passphrase too weak: use at least 12 characters or a 4-word passphrase".into(),
        ));
    }
    if let Some(reason) = kdf::strength_problem(&text) {
        return Err(CryptoError::Other(format!("passphrase too weak: {reason}")));
    }
    Ok(())
}

/// Write `bytes` to `path` atomically (temp file in the same dir → rename).
///
/// Crash-safe replacement for the manifest and metadata (QV-08).
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let tmp = path.with_extension("tmp-write");
    {
        let mut f = std::fs::File::create(&tmp)
            .map_err(|e| CryptoError::Other(format!("create temp file: {e}")))?;
        f.write_all(bytes)
            .map_err(|e| CryptoError::Other(format!("write temp file: {e}")))?;
        f.sync_all()
            .map_err(|e| CryptoError::Other(format!("sync temp file: {e}")))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        CryptoError::Other(format!("atomic replace: {e}"))
    })?;
    Ok(())
}

fn decode_b64(s: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(s)
        .map_err(|e| CryptoError::InvalidFormat(format!("base64 decode: {e}")))
}

/// Recursively find directories containing a `vault.meta` (existing vaults).
///
/// If `root` itself is a vault it is returned directly. Does not descend *into*
/// a found vault, and does not follow links/reparse points (QV-06).
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
        if crate::paths::is_link(&path) {
            continue; // never follow links/reparse points
        }
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
        std::env::temp_dir().join(format!("qvault-test-{name}-{}", std::process::id()))
    }

    fn clean(path: &Path) {
        let _ = std::fs::remove_dir_all(path);
    }

    const PASS: &[u8] = b"correct horse battery staple";

    #[test]
    fn create_and_open_round_trip() {
        let path = temp_vault_path("roundtrip");
        clean(&path);

        let v = Vault::create(&path, PASS).unwrap();
        assert!(v.device_priv.is_some());
        assert!(!v.vault_id.is_empty());

        let v2 = Vault::open(&path, PASS).unwrap();
        assert_eq!(v2.vault_pub.mlkem, v.vault_pub.mlkem);
        assert_eq!(v2.vault_pub.x25519, v.vault_pub.x25519);
        assert_eq!(v2.vault_id, v.vault_id);
        assert!(v2.device_priv.is_some());
        clean(&path);
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let path = temp_vault_path("wrongpass");
        clean(&path);
        Vault::create(&path, PASS).unwrap();
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
        Vault::create(&path, PASS).unwrap();
        assert!(Vault::create(&path, PASS).is_err());
        clean(&path);
    }

    #[test]
    fn weak_passphrase_rejected_by_backend() {
        // QV-09: backend refuses weak passphrases regardless of the UI.
        let path = temp_vault_path("weak");
        clean(&path);
        assert!(Vault::create(&path, b"short").is_err());
        assert!(Vault::create(&path, b"").is_err());
        assert!(Vault::create(&path, b"password").is_err());
        clean(&path);
    }

    #[test]
    fn four_word_passphrase_accepted() {
        let path = temp_vault_path("fourwords");
        clean(&path);
        assert!(Vault::create(&path, b"alpha bravo charlie delta").is_ok());
        clean(&path);
    }

    #[test]
    fn tampered_sealed_key_means_no_device_keys_but_passphrase_ok() {
        let path = temp_vault_path("tamper");
        clean(&path);
        Vault::create(&path, PASS).unwrap();

        let meta_path = path.join(META_FILENAME);
        let json = std::fs::read_to_string(&meta_path).unwrap();
        let mut meta: VaultMeta = serde_json::from_str(&json).unwrap();
        meta.sealed_priv_b64 = STANDARD.encode(b"not-unsealable-here");
        std::fs::write(&meta_path, serde_json::to_string(&meta).unwrap()).unwrap();

        let v = Vault::open(&path, PASS).unwrap();
        assert!(v.device_priv.is_none());
        clean(&path);
    }

    #[test]
    fn device_key_blob_is_bound_to_vault_id() {
        // Swapping vault_id invalidates the DPAPI-bound device key.
        let path = temp_vault_path("vaultid");
        clean(&path);
        Vault::create(&path, PASS).unwrap();

        let meta_path = path.join(META_FILENAME);
        let json = std::fs::read_to_string(&meta_path).unwrap();
        let mut meta: VaultMeta = serde_json::from_str(&json).unwrap();
        meta.vault_id = "deadbeefdeadbeefdeadbeefdeadbeef".to_string();
        let tampered = serde_json::to_string(&meta).unwrap();
        std::fs::write(&meta_path, tampered).unwrap();

        // Passphrase no longer verifies either (verifier is AAD-bound to vault_id).
        assert!(Vault::open(&path, PASS).is_err());
        clean(&path);
    }

    #[test]
    fn public_keys_are_stable_across_open() {
        let path = temp_vault_path("stable");
        clean(&path);
        Vault::create(&path, PASS).unwrap();
        let a = Vault::open(&path, PASS).unwrap();
        let b = Vault::open(&path, PASS).unwrap();
        assert_eq!(a.vault_pub.mlkem, b.vault_pub.mlkem);
        assert_eq!(a.vault_pub.x25519, b.vault_pub.x25519);
        clean(&path);
    }
}
