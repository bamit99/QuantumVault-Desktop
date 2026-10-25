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
const META_VERSION: u32 = 3;
/// Constant authenticated inside the verifier to confirm a correct passphrase.
const VERIFIER_PLAINTEXT: &[u8] = b"qvault-passphrase-verifier-v2";
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
    /// AES-GCM(Argon2id(passphrase), VERIFIER_PLAINTEXT || metadata_digest, AAD)
    /// (base64). Authenticates the passphrase *and* the security-critical
    /// metadata (QV2-02).
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
        Some(kem::VaultPrivate {
            mlkem: zeroize::Zeroizing::new(mlkem),
            x25519: zeroize::Zeroizing::new(x25519),
        })
    }

    /// Canonical digest over the security-critical metadata (QV2-02).
    ///
    /// Authenticated by the passphrase verifier, so substituting any of these
    /// fields (in particular the public keys) makes the vault fail closed.
    pub fn metadata_digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        let mut field = |bytes: &[u8]| {
            h.update((bytes.len() as u32).to_be_bytes());
            h.update(bytes);
        };
        field(self.format.as_bytes());
        field(&self.version.to_be_bytes());
        field(self.vault_id.as_bytes());
        field(self.mlkem_pub_b64.as_bytes());
        field(self.x25519_pub_b64.as_bytes());
        field(self.sealed_priv_b64.as_bytes());
        field(self.verify_salt_b64.as_bytes());
        h.finalize().into()
    }

    /// Verify a passphrase and derive the session passphrase KEK in one Argon2 pass.
    ///
    /// Also authenticates the metadata: the verifier plaintext contains the
    /// expected metadata digest, so tampering with the public keys is detected
    /// here rather than silently redirecting future encryption (QV2-02).
    pub fn derive_pass_kek(&self, passphrase: &[u8]) -> Result<[u8; 32]> {
        let salt = decode_b64(&self.verify_salt_b64)?;
        let verifier = decode_b64(&self.verifier_b64)?;
        let pass_kek = kdf::derive(passphrase, &salt)?;
        let aad = format::verifier_aad(&self.vault_id);
        // GCM auth failure means a wrong passphrase (or wrong vault binding).
        let payload = aead::decrypt(&pass_kek, &verifier, &aad)?;

        // Metadata integrity: the verifier authenticates this digest.
        let plen = VERIFIER_PLAINTEXT.len();
        let expected = self.metadata_digest();
        let ok = payload.len() == plen + 32
            && &payload[..plen] == VERIFIER_PLAINTEXT
            && payload[plen..] == expected;
        if !ok {
            return Err(CryptoError::Other(
                "vault metadata failed integrity verification (vault.meta may have been tampered with)"
                    .into(),
            ));
        }
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
        raw.extend_from_slice(&privk.x25519[..]);
        raw.extend_from_slice(&privk.mlkem[..]);
        let sealed = dpapi::seal(&raw)?;

        // Build the metadata first (without the verifier), so its digest can be
        // authenticated by the verifier itself (QV2-02).
        let mut meta = VaultMeta {
            format: META_FORMAT.to_string(),
            version: META_VERSION,
            vault_id: vault_id.clone(),
            mlkem_pub_b64: STANDARD.encode(&pubk.mlkem),
            x25519_pub_b64: STANDARD.encode(&pubk.x25519),
            sealed_priv_b64: STANDARD.encode(&sealed),
            verify_salt_b64: STANDARD.encode(&kdf::new_salt()?),
            verifier_b64: String::new(),
        };

        let verify_salt = decode_b64(&meta.verify_salt_b64)?;
        let pass_kek = kdf::derive(passphrase, &verify_salt)?;

        // Verifier payload = label || metadata digest.
        let mut payload = Vec::with_capacity(VERIFIER_PLAINTEXT.len() + 32);
        payload.extend_from_slice(VERIFIER_PLAINTEXT);
        payload.extend_from_slice(&meta.metadata_digest());

        let verifier = aead::encrypt(&pass_kek, &payload, &format::verifier_aad(&vault_id))?;
        meta.verifier_b64 = STANDARD.encode(&verifier);

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

        // QV2-02: on this machine, prove the metadata public keys actually
        // belong to the DPAPI-unsealed private keys. A mismatch means the
        // metadata was swapped and must fail closed. (On another machine the
        // device key is unavailable and the passphrase-authenticated metadata
        // digest is the integrity check.)
        if let Some(privk) = device_priv.as_ref() {
            let derived = privk.public();
            if derived.mlkem != vault_pub.mlkem || derived.x25519 != vault_pub.x25519 {
                return Err(CryptoError::Other(
                    "vault metadata integrity check failed: public keys do not match the device key"
                        .into(),
                ));
            }
        }

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
    // Single authoritative check, shared with the UI (QV2-07).
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

    /// Recompute the passphrase verifier for a (possibly modified) metadata
    /// blob. Lets tests exercise the "legitimate metadata, unusable device key"
    /// case separately from tampering.
    fn reseal_verifier(meta: &mut VaultMeta, passphrase: &[u8]) {
        let salt = decode_b64(&meta.verify_salt_b64).unwrap();
        let kek = kdf::derive(passphrase, &salt).unwrap();
        let mut payload = VERIFIER_PLAINTEXT.to_vec();
        payload.extend_from_slice(&meta.metadata_digest());
        let v = aead::encrypt(&kek, &payload, &format::verifier_aad(&meta.vault_id)).unwrap();
        meta.verifier_b64 = STANDARD.encode(&v);
    }

    #[test]
    fn tampered_metadata_fails_closed() {
        // QV2-02: modifying sealed key material without re-authenticating the
        // metadata is detected. The vault refuses to open rather than silently
        // falling back to the passphrase leg.
        let path = temp_vault_path("tamper");
        clean(&path);
        Vault::create(&path, PASS).unwrap();

        let meta_path = path.join(META_FILENAME);
        let mut meta: VaultMeta =
            serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
        meta.sealed_priv_b64 = STANDARD.encode(b"not-unsealable-here");
        std::fs::write(&meta_path, serde_json::to_string(&meta).unwrap()).unwrap();

        assert!(Vault::open(&path, PASS).is_err());
        clean(&path);
    }

    #[test]
    fn unusable_device_key_with_valid_metadata_still_opens_by_passphrase() {
        // Simulates a different machine: the metadata is authentic, but the
        // sealed device key cannot be unsealed here. The passphrase leg works.
        let path = temp_vault_path("nodevice");
        clean(&path);
        Vault::create(&path, PASS).unwrap();

        let meta_path = path.join(META_FILENAME);
        let mut meta: VaultMeta =
            serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
        // DPAPI-sealed blob that unseals fine but fails our internal length/AAD
        // check, so device keys are unavailable.
        meta.sealed_priv_b64 = STANDARD.encode(dpapi::seal(b"wrong-shape").unwrap());
        reseal_verifier(&mut meta, PASS);
        std::fs::write(&meta_path, serde_json::to_string(&meta).unwrap()).unwrap();

        let v = Vault::open(&path, PASS).unwrap();
        assert!(v.device_priv.is_none(), "device key must be unavailable");
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
    fn public_key_substitution_is_rejected() {
        // QV2-02 regression: swapping in attacker-controlled public keys must
        // fail even though the passphrase and vault ID are unchanged.
        let path = temp_vault_path("pk-sub");
        clean(&path);
        Vault::create(&path, PASS).unwrap();

        let meta_path = path.join(META_FILENAME);
        let mut meta: VaultMeta =
            serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();

        // Attacker keypair.
        let attacker = kem::generate_keypair().public();
        meta.mlkem_pub_b64 = STANDARD.encode(&attacker.mlkem);
        meta.x25519_pub_b64 = STANDARD.encode(&attacker.x25519);
        std::fs::write(&meta_path, serde_json::to_string(&meta).unwrap()).unwrap();

        let err = Vault::open(&path, PASS);
        assert!(err.is_err(), "tampered public keys must not open");
        clean(&path);
    }

    #[test]
    fn metadata_digest_changes_with_each_field() {
        let path = temp_vault_path("digest");
        clean(&path);
        Vault::create(&path, PASS).unwrap();
        let meta_path = path.join(META_FILENAME);
        let meta: VaultMeta =
            serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
        let base = meta.metadata_digest();

        let mut m2 = meta.clone();
        m2.vault_id = "0".repeat(32);
        assert_ne!(base, m2.metadata_digest());

        let mut m3 = meta.clone();
        m3.x25519_pub_b64 = STANDARD.encode([9u8; 32]);
        assert_ne!(base, m3.metadata_digest());

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
