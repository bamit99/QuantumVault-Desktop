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

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::crypto::error::{CryptoError, Result};
use crate::crypto::{aead, dpapi, format, kdf, kem};
use crate::manifest::hex;

/// Metadata filename inside a vault directory.
pub const META_FILENAME: &str = "vault.meta";
/// Encrypted manifest filename.
pub const MANIFEST_FILENAME: &str = "manifest.qvault";

const META_FORMAT: &str = "qvault-desktop";
/// Current vault metadata version.
///
/// v4 (QV3-01) moved file metadata from a single shared `manifest.qvault`
/// index to per-file `.meta` sidecars. The version bump is what makes an
/// *older* app fail loudly on a newer vault instead of silently showing an
/// empty vault: v0.1.x looks for `manifest.qvault`, finds none, and would
/// report zero files. Refusing to open is the safe outcome.
pub const META_VERSION: u32 = 4;
/// The previous metadata version, still readable so an existing vault can be
/// migrated to sidecars on first open.
pub const META_VERSION_LEGACY: u32 = 3;
/// The original metadata version, written by v0.1.0 and v0.1.1.
///
/// A v1 vault has no `vault_id`, its passphrase verifier is a plain
/// `AES-GCM(Argon2id(passphrase), "qvault-passphrase-verifier-v1")` with no
/// metadata digest and no AAD, its device key blob is the bare 96-byte
/// private key, and its file blobs use the legacy v2 container (no AAD).
/// All of that is still readable; such a vault is migrated to the current
/// format on first open.
pub const META_VERSION_V1: u32 = 1;
/// Constant authenticated inside the verifier to confirm a correct passphrase.
pub(crate) const VERIFIER_PLAINTEXT: &[u8] = b"qvault-passphrase-verifier-v2";
/// The v1 verifier constant (v1 vaults have no metadata digest).
pub(crate) const VERIFIER_PLAINTEXT_V1: &[u8] = b"qvault-passphrase-verifier-v1";
/// Combined raw private length: X25519 scalar (32) + ML-KEM seed (64).
const SEALED_PRIV_LEN: usize = 32 + 64;

/// Serialized vault metadata (stored as `vault.meta`).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultMeta {
    pub format: String,
    pub version: u32,
    /// Random per-vault identifier (hex). Binds blobs to this vault via AAD.
    ///
    /// Empty for a v1 vault, which predates the identifier; the migration
    /// assigns one and persists it before it touches any file.
    #[serde(default)]
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

        // v1 vaults sealed the bare private key; every later version prefixes
        // it with the AAD that binds it to this vault.
        if raw.len() == SEALED_PRIV_LEN {
            let x25519: [u8; 32] = raw[..32].try_into().ok()?;
            let mlkem = raw[32..].to_vec();
            return Some(kem::VaultPrivate {
                mlkem: zeroize::Zeroizing::new(mlkem),
                x25519: zeroize::Zeroizing::new(x25519),
            });
        }

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

        // A v1 vault used a plain verifier: a fixed label, no metadata digest
        // and no AAD. The derived key is the same (same salt), so every file
        // in the vault stays readable.
        if self.version <= META_VERSION_V1 {
            let plain = aead::decrypt(&pass_kek, &verifier, &[])?;
            if plain != VERIFIER_PLAINTEXT_V1 {
                return Err(CryptoError::Other(
                    "legacy passphrase verifier is malformed".into(),
                ));
            }
            return Ok(pass_kek);
        }

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
    /// The metadata version this vault was opened with (QV3-01).
    ///
    /// A vault written by v0.1.x reports [`META_VERSION_LEGACY`]; it is
    /// migrated to sidecars and upgraded the first time the session touches
    /// it.
    pub meta_version: u32,
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
            x25519_pub_b64: STANDARD.encode(pubk.x25519),
            sealed_priv_b64: STANDARD.encode(&sealed),
            verify_salt_b64: STANDARD.encode(kdf::new_salt()?),
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
            meta_version: META_VERSION,
        })
    }

    /// Open an existing vault and verify `passphrase`.
    pub fn open(path: &Path, passphrase: &[u8]) -> Result<Self> {
        let meta_path = path.join(META_FILENAME);
        let json = std::fs::read_to_string(&meta_path)
            .map_err(|e| CryptoError::Other(format!("read vault.meta: {e}")))?;
        let mut meta: VaultMeta = serde_json::from_str(&json)
            .map_err(|e| CryptoError::InvalidFormat(format!("parse vault.meta: {e}")))?;

        if meta.format != META_FORMAT {
            return Err(CryptoError::InvalidFormat(format!(
                "unsupported vault metadata format {}",
                meta.format
            )));
        }
        if meta.version != META_VERSION
            && meta.version != META_VERSION_LEGACY
            && meta.version != META_VERSION_V1
        {
            return Err(CryptoError::InvalidFormat(format!(
                "unsupported vault metadata {} v{}",
                meta.format, meta.version
            )));
        }
        // A v1 vault has no vault ID yet; the migration assigns one.
        if meta.version > META_VERSION_V1 && meta.vault_id.is_empty() {
            return Err(CryptoError::InvalidFormat(
                "vault.meta has no vault ID".into(),
            ));
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

        // A vault written by v0.1.0/v0.1.1 is migrated to the current format
        // before it is handed out, so the rest of the app only ever sees the
        // current layout.
        if meta.version == META_VERSION_V1 {
            migrate_v1_vault(path, &mut meta, &vault_pub, device_priv.as_ref(), &pass_kek)?;
        }

        Ok(Vault {
            path: path.to_path_buf(),
            vault_id: meta.vault_id.clone(),
            vault_pub,
            device_priv,
            pass_kek,
            meta_version: meta.version,
        })
    }

    /// Re-encrypt the passphrase verifier over the current metadata digest.
    ///
    /// Used after a metadata field changes (such as the QV3-01 version bump)
    /// so the vault keeps opening with its own passphrase.
    pub fn refresh_verifier(meta: &mut VaultMeta, pass_kek: &[u8; 32]) -> Result<()> {
        let mut payload = Vec::with_capacity(VERIFIER_PLAINTEXT.len() + 32);
        payload.extend_from_slice(VERIFIER_PLAINTEXT);
        payload.extend_from_slice(&meta.metadata_digest());
        let verifier = aead::encrypt(pass_kek, &payload, &format::verifier_aad(&meta.vault_id))?;
        meta.verifier_b64 = STANDARD.encode(&verifier);
        Ok(())
    }
}

/// Migrate a v1 vault (written by v0.1.0/v0.1.1) to the current format.
///
/// A v1 vault differs from the current one in three ways: it has no vault ID,
/// its file blobs use the legacy v2 container (no AAD), and its file metadata
/// lives in one shared `manifest.qvault` index instead of per-file sidecars.
///
/// The migration is ordered so that an interruption is always recoverable:
///
/// 1. **Assign and persist a vault ID.** The migrated blobs are bound to it
///    by AAD, so a retry has to reuse the same one. The v1 verifier does not
///    cover the metadata, so the passphrase keeps working.
/// 2. **Re-encrypt every payload** from the legacy container into the
///    AAD-bound one, and write a metadata sidecar for each file. A file that
///    is already migrated is detected by its version byte and left alone, so
///    the step is idempotent.
/// 3. **Bump `vault.meta`** to the current version and recompute the
///    passphrase verifier over the new metadata digest (same salt, so the
///    same passphrase still derives the same key).
/// 4. **Remove the legacy index**, which is redundant once the sidecars
///    exist.
///
/// The version bump happens last, so a vault that claims the current version
/// always has its sidecars — never the other way round.
fn migrate_v1_vault(
    path: &Path,
    meta: &mut VaultMeta,
    vault_pub: &kem::VaultPublic,
    device_priv: Option<&kem::VaultPrivate>,
    pass_kek: &[u8; 32],
) -> Result<()> {
    // Step 1: a vault ID is required by the AAD context.
    if meta.vault_id.is_empty() {
        meta.vault_id = hex(&crate::crypto::random::<16>()?);
    }
    let vault_id = meta.vault_id.clone();

    // Re-seal the device key with the vault-ID prefix so the device leg keeps
    // working after the migration. If the key is not available on this
    // machine the legacy sealed blob is kept: it still decrypts the files
    // through the passphrase leg.
    if let Some(privk) = device_priv {
        let mut raw = format::vault_key_aad(&vault_id);
        raw.extend_from_slice(&privk.x25519[..]);
        raw.extend_from_slice(&privk.mlkem[..]);
        meta.sealed_priv_b64 = STANDARD.encode(dpapi::seal(&raw)?);
    }

    // Persist the vault ID *before* touching any file, so an interrupted
    // migration retries against the same ID.
    write_meta(path, meta)?;

    // Step 2: read the legacy shared index.
    let legacy_index = path.join(MANIFEST_FILENAME);
    let entries: Vec<crate::manifest::FileEntry> = if legacy_index.exists() {
        let blob = std::fs::read(&legacy_index)
            .map_err(|e| CryptoError::Other(format!("read legacy manifest: {e}")))?;
        // The legacy index is itself a legacy blob: no AAD.
        let plain = format::decrypt_file(
            &blob,
            device_priv,
            Some(pass_kek),
            &format::BlobContext {
                vault_id: &vault_id,
                file_id: format::MANIFEST_CONTEXT,
            },
        )?;
        let legacy: crate::manifest::Manifest = serde_json::from_slice(&plain)
            .map_err(|e| CryptoError::InvalidFormat(format!("parse legacy manifest: {e}")))?;
        legacy.files
    } else {
        Vec::new()
    };

    if entries.is_empty() {
        // No index and no names to recover: the vault holds no recoverable
        // file metadata, so refuse to claim it is migrated.
        let has_blobs = std::fs::read_dir(path)
            .map(|d| {
                d.flatten().any(|e| {
                    e.file_name()
                        .to_str()
                        .is_some_and(|n| n.ends_with(".qvault"))
                })
            })
            .unwrap_or(false);
        if has_blobs {
            return Err(CryptoError::Other(
                "this vault was created by v0.1.0/v0.1.1 and its file index is missing, so the \
                 original file names cannot be recovered. The encrypted files are untouched."
                    .into(),
            ));
        }
    }

    for entry in &entries {
        // Decrypted metadata is untrusted input: validate the ID and the name.
        entry.validate(&entry.id)?;

        let ctx = format::BlobContext {
            vault_id: &vault_id,
            file_id: &entry.id,
        };

        // Re-encrypt the payload from the legacy container if needed.
        let blob_path = crate::manifest::blob_path(path, &entry.id)?;
        if blob_path.exists() {
            let blob = std::fs::read(&blob_path)
                .map_err(|e| CryptoError::Other(format!("read encrypted file: {e}")))?;
            let version = format::blob_version(&blob)?;
            if version == format::VERSION_LEGACY {
                // If a single file cannot be re-encrypted (a damaged blob, a
                // transient I/O error) the file keeps its legacy container and
                // stays readable: the legacy container is still decryptable,
                // it is just not AAD-bound to this vault. The migration
                // continues so that one bad file cannot lock the user out of
                // the whole vault.
                match format::decrypt_file(&blob, device_priv, Some(pass_kek), &ctx)
                    .and_then(|plain| format::encrypt_file(&plain, vault_pub, pass_kek, &ctx))
                {
                    Ok(migrated) => write_atomic(&blob_path, &migrated)?,
                    Err(_) => { /* keep the legacy blob; the file still works */ }
                }
            } else {
                // Already migrated: it must still open with the current
                // context, otherwise the vault ID does not match.
                format::decrypt_file(&blob, device_priv, Some(pass_kek), &ctx)?;
            }
        }

        // Write the metadata sidecar for this file.
        let plain = crate::manifest::encode_entry(entry)?;
        let sidecar = format::encrypt_meta(&plain, vault_pub, pass_kek, &ctx)?;
        write_atomic(&crate::manifest::sidecar_path(path, &entry.id)?, &sidecar)?;
    }

    // Step 3: claim the current version and recompute the verifier over the
    // new metadata digest.
    meta.version = META_VERSION;
    Vault::refresh_verifier(meta, pass_kek)?;
    write_meta(path, meta)?;

    // Step 4: the shared index is now redundant.
    let _ = std::fs::remove_file(&legacy_index);

    Ok(())
}

/// Serialize `meta` and write it to `path` atomically.
fn write_meta(path: &Path, meta: &VaultMeta) -> Result<()> {
    let json = serde_json::to_string_pretty(meta)
        .map_err(|e| CryptoError::Other(format!("serialize meta: {e}")))?;
    write_atomic(&path.join(META_FILENAME), json.as_bytes())
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

    // The temp name is the full file name plus a suffix, NOT a replaced
    // extension: a vault holds `<id>.qvault` and `<id>.meta` side by side,
    // and `with_extension` would give both the same temp path. (QV3-01)
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tmp".to_string());
    let tmp = path.with_file_name(format!("{file_name}.tmp-write"));
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
        meta.x25519_pub_b64 = STANDARD.encode(attacker.x25519);
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

    // ───────────────────── v1 (v0.1.0/v0.1.1) compatibility ─────────────────────

    #[test]
    fn v1_vault_opens_and_is_migrated() {
        // A vault written by v0.1.0/v0.1.1 has no `vault_id` and uses the
        // legacy blob container. It must open and be migrated forward.
        let path = temp_vault_path("v1-migrate");
        clean(&path);

        let id_a = crate::legacy_fixture::random_id();
        let id_b = crate::legacy_fixture::random_id();
        crate::legacy_fixture::build(
            &path,
            PASS,
            &[
                (&id_a, "report.pdf", b"legacy payload one"),
                (&id_b, "notes.txt", b"legacy payload two"),
            ],
        );

        // The vault opens with the same passphrase.
        let v = Vault::open(&path, PASS).unwrap();
        assert!(!v.vault_id.is_empty(), "migration must assign a vault ID");
        assert_eq!(v.meta_version, META_VERSION, "vault must be upgraded");

        // The metadata on disk is now the current format.
        let meta: VaultMeta =
            serde_json::from_str(&std::fs::read_to_string(path.join(META_FILENAME)).unwrap())
                .unwrap();
        assert_eq!(meta.version, META_VERSION);
        assert_eq!(meta.vault_id, v.vault_id);

        // Every payload was re-encrypted into the AAD-bound container, and
        // the shared index is gone.
        for id in [&id_a, &id_b] {
            let blob = std::fs::read(path.join(format!("{id}.qvault"))).unwrap();
            assert_eq!(format::blob_version(&blob).unwrap(), format::VERSION);
            assert!(path.join(format!("{id}.meta")).exists(), "sidecar missing");
        }
        assert!(!path.join(MANIFEST_FILENAME).exists());

        clean(&path);
    }

    #[test]
    fn v1_vault_rejects_wrong_passphrase() {
        let path = temp_vault_path("v1-wrongpass");
        clean(&path);
        let id = crate::legacy_fixture::random_id();
        crate::legacy_fixture::build(&path, PASS, &[(id.as_str(), "a.txt", b"secret")]);

        assert!(matches!(
            Vault::open(&path, b"the wrong passphrase"),
            Err(CryptoError::AuthenticationFailed)
        ));
        clean(&path);
    }

    #[test]
    fn v1_migration_is_idempotent() {
        // Opening an already-migrated vault must not fail or change anything.
        let path = temp_vault_path("v1-idempotent");
        clean(&path);
        let id = crate::legacy_fixture::random_id();
        crate::legacy_fixture::build(&path, PASS, &[(id.as_str(), "a.txt", b"secret")]);

        let first = Vault::open(&path, PASS).unwrap();
        let meta_after_first = std::fs::read_to_string(path.join(META_FILENAME)).unwrap();

        let second = Vault::open(&path, PASS).unwrap();
        assert_eq!(first.vault_id, second.vault_id, "vault ID must be stable");
        assert_eq!(
            meta_after_first,
            std::fs::read_to_string(path.join(META_FILENAME)).unwrap(),
            "a second open must not rewrite the metadata"
        );
        clean(&path);
    }

    #[test]
    fn v1_migration_resumes_after_interruption() {
        // Simulate a crash between "the vault ID was persisted" and "the
        // payloads were re-encrypted": the retry must reuse the same ID and
        // finish the job.
        let path = temp_vault_path("v1-resume");
        clean(&path);
        let id = crate::legacy_fixture::random_id();
        crate::legacy_fixture::build(&path, PASS, &[(id.as_str(), "a.txt", b"payload")]);

        // Persist a vault ID by hand, as the first migration step would.
        let mut meta: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path.join(META_FILENAME)).unwrap())
                .unwrap();
        let vault_id = crate::legacy_fixture::random_id();
        meta["vault_id"] = serde_json::Value::String(vault_id.clone());
        std::fs::write(
            path.join(META_FILENAME),
            serde_json::to_string_pretty(&meta).unwrap(),
        )
        .unwrap();

        // The interrupted migration is completed by the next open.
        let v = Vault::open(&path, PASS).unwrap();
        assert_eq!(
            v.vault_id, vault_id,
            "the persisted vault ID must be reused"
        );
        assert_eq!(v.meta_version, META_VERSION);
        clean(&path);
    }

    #[test]
    fn v1_vault_without_index_is_reported() {
        // No index means the original file names are gone. The vault must
        // fail with a clear message instead of claiming an empty vault.
        let path = temp_vault_path("v1-noindex");
        clean(&path);
        let id = crate::legacy_fixture::random_id();
        crate::legacy_fixture::build(&path, PASS, &[(id.as_str(), "a.txt", b"payload")]);
        std::fs::remove_file(path.join(MANIFEST_FILENAME)).unwrap();

        let err = match Vault::open(&path, PASS) {
            Ok(_) => panic!("a v1 vault without an index must not open"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("file index is missing"),
            "unexpected error: {err}"
        );
        // The encrypted file is left untouched.
        assert!(path.join(format!("{id}.qvault")).exists());
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
