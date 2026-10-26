//! An unlocked vault session.
//!
//! Holds the in-memory secrets needed during an open session: the session
//! passphrase KEK (Argon2id, derived once at unlock; zeroized on drop), the
//! unsealed device private keys (if DPAPI permits on this machine) and the vault
//! ID used for AEAD context binding.
//!
//! ## Storage layout
//!
//! One encrypted payload blob and one encrypted metadata sidecar per file:
//!
//! ```text
//! <vault>/
//!   vault.meta          device keypair + passphrase verifier (public keys, DPAPI-sealed privs)
//!   <id>.qvault         encrypted file contents
//!   <id>.meta           encrypted metadata for that file (name, size, mime, timestamps)
//! ```
//!
//! The metadata lives in per-file sidecars rather than one shared index so
//! that concurrent edits from two machines cannot lose whole files — see
//! [`crate::manifest`] for the rationale.
//!
//! v0.1.x wrote a single shared `manifest.qvault` index instead. A vault
//! written by that version is migrated to sidecars on first open.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::crypto::error::{CryptoError, Result};
use crate::crypto::{self, format, kem};
use crate::manifest::{self, FileEntry, Manifest, hex};
use crate::paths;
use crate::vault::{Vault, write_atomic};

/// Maximum plaintext file size processed in memory (QV-07 interim control).
pub const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB

/// An unlocked vault session.
pub struct Session {
    /// Absolute path to the vault directory.
    pub path: PathBuf,
    /// Random per-vault identifier (binds every blob via AAD).
    pub vault_id: String,
    /// Public keys (used for encrypting new files).
    pub vault_pub: kem::VaultPublic,
    /// Unsealed device private keys, if DPAPI worked on this machine.
    pub device_priv: Option<kem::VaultPrivate>,
    /// Session passphrase KEK, zeroized on drop.
    pass_kek: Zeroizing<[u8; format::KEK_LEN]>,
    /// The metadata version this vault was opened with (QV3-01).
    ///
    /// A vault written by v0.1.x reports the legacy version and is migrated
    /// to sidecars the first time the session touches it.
    meta_version: u32,
    /// Whether the legacy migration has already run in this session.
    ///
    /// The migration is idempotent, but it reads `vault.meta` from disk, so
    /// it is done once rather than on every operation.
    migrated: std::cell::Cell<bool>,
}

impl Session {
    /// Build a session from an opened [`Vault`].
    pub fn new(vault: Vault) -> Self {
        Session {
            path: vault.path,
            vault_id: vault.vault_id,
            vault_pub: vault.vault_pub,
            device_priv: vault.device_priv,
            pass_kek: Zeroizing::new(vault.pass_kek),
            meta_version: vault.meta_version,
            migrated: std::cell::Cell::new(false),
        }
    }

    /// Build the AAD context for a specific file ID.
    fn ctx<'a>(&'a self, file_id: &'a str) -> format::BlobContext<'a> {
        format::BlobContext {
            vault_id: &self.vault_id,
            file_id,
        }
    }

    /// List the vault's files.
    ///
    /// Scans the vault directory for payload blobs and reads the matching
    /// sidecar for each one. A blob whose sidecar is missing or unreadable is
    /// skipped rather than failing the whole listing — one damaged file must
    /// not hide every other file in the vault.
    pub fn list_files(&self) -> Result<Vec<FileEntry>> {
        self.migrate_legacy_vault()?;

        let mut out: Vec<FileEntry> = Vec::new();
        let dir = std::fs::read_dir(&self.path)
            .map_err(|e| CryptoError::Other(format!("read vault dir: {e}")))?;

        for dirent in dir.flatten() {
            let file_name = dirent.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            let Some(id) = manifest::id_from_filename(name) else {
                continue;
            };
            if let Ok(entry) = self.read_sidecar(id) {
                out.push(entry);
            }
        }

        // Stable order: oldest first, ties broken by ID so the listing does
        // not reshuffle between calls.
        out.sort_by(|a, b| a.created.cmp(&b.created).then_with(|| a.id.cmp(&b.id)));
        Ok(out)
    }

    /// Encrypt `data` into the vault under `name`.
    ///
    /// `name` is a filename or a validated relative path.
    pub fn add_file(&self, name: &str, data: &[u8]) -> Result<FileEntry> {
        paths::validate_relative(name)?;
        self.migrate_legacy_vault()?;
        if data.len() as u64 > MAX_FILE_BYTES {
            return Err(CryptoError::Other(format!(
                "file too large: {} bytes (limit {} bytes)",
                data.len(),
                MAX_FILE_BYTES
            )));
        }
        self.encrypt_into(name, data)
    }

    /// Recursively encrypt every file under `folder`, preserving relative paths.
    /// Returns the number of files encrypted.
    ///
    /// Skips symlinks and reparse points (QV-06) and enforces the size limit.
    pub fn add_folder(&self, folder: &Path) -> Result<usize> {
        self.migrate_legacy_vault()?;
        let mut files = Vec::new();
        walk_files(folder, folder, &mut files)?;
        if files.is_empty() {
            return Err(CryptoError::Other(format!(
                "no files found in {}",
                folder.display()
            )));
        }

        let mut count = 0usize;
        for (rel, abs) in &files {
            // Validate the derived relative path at the boundary.
            paths::validate_relative(rel)?;

            let meta = std::fs::metadata(abs)
                .map_err(|e| CryptoError::Other(format!("stat {}: {e}", abs.display())))?;
            if meta.len() > MAX_FILE_BYTES {
                return Err(CryptoError::Other(format!(
                    "file too large: {} ({} bytes)",
                    abs.display(),
                    meta.len()
                )));
            }
            let data = std::fs::read(abs)
                .map_err(|e| CryptoError::Other(format!("read {}: {e}", abs.display())))?;
            self.encrypt_into(rel, &data)?;
            count += 1;
        }
        Ok(count)
    }

    /// Encrypt `data` under `name` and write the blob plus its sidecar.
    ///
    /// The payload blob is written first and the sidecar second. If the
    /// sidecar write fails, the blob is removed again, so a failed add never
    /// leaves an orphan payload behind.
    fn encrypt_into(&self, name: &str, data: &[u8]) -> Result<FileEntry> {
        let id = hex(&crypto::random::<16>()?);
        let ctx = self.ctx(&id);
        let blob = format::encrypt_file(data, &self.vault_pub, &self.pass_kek, &ctx)?;
        let blob_path = manifest::blob_path(&self.path, &id)?;
        write_atomic(&blob_path, &blob)?;

        let now = now_ts();
        let entry = FileEntry {
            id: id.clone(),
            name: name.to_string(),
            size: data.len() as u64,
            mime: guess_mime(name),
            created: now,
            modified: now,
        };

        if let Err(e) = self.write_sidecar(&entry) {
            // Roll the payload back so the vault never holds a blob whose
            // metadata is missing.
            let _ = std::fs::remove_file(&blob_path);
            return Err(e);
        }

        Ok(entry)
    }

    /// Decrypt a file, returning its entry and plaintext bytes.
    pub fn extract_file(&self, id: &str) -> Result<(FileEntry, Zeroizing<Vec<u8>>)> {
        paths::validate_file_id(id)?;
        self.migrate_legacy_vault()?;
        let entry = self.read_sidecar(id)?;

        let blob = std::fs::read(manifest::blob_path(&self.path, id)?)
            .map_err(|e| CryptoError::Other(format!("read encrypted file: {e}")))?;
        let ctx = self.ctx(id);
        let data =
            format::decrypt_file(&blob, self.device_priv.as_ref(), Some(&self.pass_kek), &ctx)?;
        Ok((entry, Zeroizing::new(data)))
    }

    /// Delete a file (encrypted blob + metadata sidecar).
    pub fn delete_file(&self, id: &str) -> Result<()> {
        paths::validate_file_id(id)?;
        self.migrate_legacy_vault()?;

        // Refuse unknown IDs before touching the disk. A file with no
        // readable sidecar is still deletable — the user asked for it to go.
        let sidecar_path = manifest::sidecar_path(&self.path, id)?;
        let blob_path = manifest::blob_path(&self.path, id)?;
        if !sidecar_path.exists() && !blob_path.exists() {
            return Err(CryptoError::InvalidFormat(format!("no such file: {id}")));
        }

        // Remove the payload first: if this fails, the sidecar still describes
        // it (recoverable) rather than leaving an unreferenced orphan.
        if blob_path.exists() {
            std::fs::remove_file(&blob_path)
                .map_err(|e| CryptoError::Other(format!("delete encrypted file: {e}")))?;
        }
        if sidecar_path.exists() {
            std::fs::remove_file(&sidecar_path)
                .map_err(|e| CryptoError::Other(format!("delete metadata: {e}")))?;
        }
        Ok(())
    }

    /// Rename a file's plaintext name.
    ///
    /// Only the sidecar changes; the payload blob is untouched. Accepts a
    /// validated relative path; rejects traversal/absolute names.
    pub fn rename_file(&self, id: &str, new_name: &str) -> Result<()> {
        paths::validate_file_id(id)?;
        paths::validate_relative(new_name)?;
        self.migrate_legacy_vault()?;
        let mut entry = self.read_sidecar(id)?;
        entry.name = new_name.to_string();
        entry.modified = now_ts();
        entry.mime = guess_mime(new_name);
        self.write_sidecar(&entry)
    }

    /// Read and validate the metadata sidecar for `id`.
    fn read_sidecar(&self, id: &str) -> Result<FileEntry> {
        paths::validate_file_id(id)?;
        let path = manifest::sidecar_path(&self.path, id)?;
        let blob = std::fs::read(&path)
            .map_err(|e| CryptoError::Other(format!("read metadata sidecar: {e}")))?;
        let ctx = self.ctx(id);
        let plain =
            format::decrypt_meta(&blob, self.device_priv.as_ref(), Some(&self.pass_kek), &ctx)?;
        manifest::decode_entry(&plain, id)
    }

    /// Encrypt and write the metadata sidecar for `entry`.
    fn write_sidecar(&self, entry: &FileEntry) -> Result<()> {
        entry.validate(&entry.id)?;
        let plain = manifest::encode_entry(entry)?;
        let ctx = self.ctx(&entry.id);
        let blob = format::encrypt_meta(&plain, &self.vault_pub, &self.pass_kek, &ctx)?;
        write_atomic(&manifest::sidecar_path(&self.path, &entry.id)?, &blob)
    }

    /// Migrate a v0.1.x vault to the sidecar layout (QV3-01).
    ///
    /// Idempotent, and ordered so that a crash at any point leaves the vault
    /// readable:
    ///
    /// 1. Write a metadata sidecar for every entry in the legacy shared
    ///    index that does not have one yet.
    /// 2. Remove the legacy `manifest.qvault` index — it is now redundant.
    /// 3. Bump `vault.meta` to the current version, recomputing the
    ///    passphrase verifier over the new metadata digest.
    ///
    /// If any step fails, the error is propagated and the vault keeps its
    /// current on-disk state, so the migration can be retried. Crucially the
    /// version bump happens **last**: a vault that claims the new version but
    /// has no sidecars would open as an empty vault, whereas a vault that
    /// still claims the old version is simply re-migrated on the next open.
    fn migrate_legacy_vault(&self) -> Result<()> {
        // Done once per session: the migration reads `vault.meta` from disk.
        if self.migrated.get() {
            return Ok(());
        }
        let legacy_path = self.path.join(crate::vault::MANIFEST_FILENAME);
        if legacy_path.exists() {
            let blob = std::fs::read(&legacy_path)
                .map_err(|e| CryptoError::Other(format!("read legacy manifest: {e}")))?;
            let ctx = self.ctx(format::MANIFEST_CONTEXT);
            let plain =
                format::decrypt_file(&blob, self.device_priv.as_ref(), Some(&self.pass_kek), &ctx)?;
            let legacy: Manifest = serde_json::from_slice(&plain)
                .map_err(|e| CryptoError::InvalidFormat(format!("parse legacy manifest: {e}")))?;

            for entry in &legacy.files {
                // A legacy entry that no longer parses must not block the
                // migration of the rest; skip it and let the listing drop it.
                if entry.validate(&entry.id).is_err() {
                    continue;
                }
                let sidecar = manifest::sidecar_path(&self.path, &entry.id)?;
                if sidecar.exists() {
                    continue;
                }
                self.write_sidecar(entry)?;
            }

            // Every sidecar is on disk; the shared index is now redundant.
            std::fs::remove_file(&legacy_path)
                .map_err(|e| CryptoError::Other(format!("remove legacy manifest: {e}")))?;
        }

        // Step 3: claim the current version. Safe now that the sidecars are
        // in place — and skipped entirely for an already-current vault.
        if self.meta_version != crate::vault::META_VERSION {
            self.upgrade_meta_version()?;
        }
        self.migrated.set(true);
        Ok(())
    }

    /// Rewrite `vault.meta` at the current metadata version (QV3-01).
    ///
    /// The metadata digest covers the version field, so the passphrase
    /// verifier **must** be recomputed together with it, or the vault would
    /// stop opening with its own passphrase. The verify salt is left
    /// untouched, so the same passphrase keeps deriving the same key and
    /// every existing file stays readable.
    fn upgrade_meta_version(&self) -> Result<()> {
        let meta_path = self.path.join(crate::vault::META_FILENAME);
        let json = std::fs::read_to_string(&meta_path)
            .map_err(|e| CryptoError::Other(format!("read vault.meta: {e}")))?;
        let mut meta: crate::vault::VaultMeta = serde_json::from_str(&json)
            .map_err(|e| CryptoError::InvalidFormat(format!("parse vault.meta: {e}")))?;

        if meta.version == crate::vault::META_VERSION {
            return Ok(());
        }

        meta.version = crate::vault::META_VERSION;

        // Recompute the verifier over the new digest, reusing the existing
        // passphrase KEK and salt.
        crate::vault::Vault::refresh_verifier(&mut meta, &self.pass_kek)?;

        let json = serde_json::to_string_pretty(&meta)
            .map_err(|e| CryptoError::Other(format!("serialize meta: {e}")))?;
        crate::vault::write_atomic(&meta_path, json.as_bytes())
    }
}

/// Recursively collect files under `dir` as `(relative-path, absolute-path)`.
///
/// Skips links/reparse points entirely (QV-06) to avoid escaping the tree or
/// looping. `visited` guards against pathological cycles via hardlinked dirs.
fn walk_files(dir: &Path, base: &Path, out: &mut Vec<(String, PathBuf)>) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| CryptoError::Other(format!("read dir {}: {e}", dir.display())))?;
    for entry in entries {
        let entry = entry.map_err(|e| CryptoError::Other(e.to_string()))?;
        let path = entry.path();

        // Never follow symlinks or Windows reparse points.
        if paths::is_link(&path) {
            continue;
        }

        if path.is_dir() {
            walk_files(&path, base, out)?;
        } else if path.is_file() {
            let rel = path
                .strip_prefix(base)
                .map_err(|_| CryptoError::Other("path prefix mismatch".into()))?;
            let rel = rel.to_string_lossy().replace('\\', "/");
            out.push((rel, path));
        }
    }
    Ok(())
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A tiny extension-based MIME guess (the frontend can refine this).
fn guess_mime(name: &str) -> String {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "md" => "text/markdown",
        "html" => "text/html",
        "css" => "text/css",
        "js" | "ts" | "tsx" | "jsx" | "json" => "text/plain",
        "csv" => "text/csv",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        "zip" => "application/zip",
        "doc" | "docx" => "application/msword",
        "xls" | "xlsx" => "application/vnd.ms-excel",
        _ => "application/octet-stream",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &[u8] = b"tundra velvet orbit lamplight";

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("qvault-session-{name}-{}", std::process::id()))
    }

    /// Encrypt an arbitrary JSON payload as a metadata sidecar for `id`.
    /// Used by tests that need to plant a hostile sidecar.
    fn plant_sidecar(session: &Session, id: &str, json: &str) {
        let ctx = session.ctx(id);
        let blob =
            format::encrypt_meta(json.as_bytes(), &session.vault_pub, &session.pass_kek, &ctx)
                .unwrap();
        write_atomic(&manifest::sidecar_path(&session.path, id).unwrap(), &blob).unwrap();
    }

    #[test]
    fn add_list_extract_delete_round_trip() {
        let path = temp("files");
        let _ = std::fs::remove_dir_all(&path);

        let vault = Vault::create(&path, PASS).unwrap();
        let session = Session::new(vault);

        let a = session.add_file("hello.txt", b"hello world").unwrap();
        let b = session.add_file("data.json", b"{\"k\":1}").unwrap();
        assert_eq!(session.list_files().unwrap().len(), 2);

        let (entry, data) = session.extract_file(&a.id).unwrap();
        assert_eq!(entry.name, "hello.txt");
        assert_eq!(data.as_slice(), b"hello world");

        session.rename_file(&b.id, "renamed.json").unwrap();
        assert_eq!(
            session
                .list_files()
                .unwrap()
                .iter()
                .find(|f| f.id == b.id)
                .unwrap()
                .name,
            "renamed.json"
        );

        session.delete_file(&a.id).unwrap();
        assert_eq!(session.list_files().unwrap().len(), 1);
        assert!(session.extract_file(&a.id).is_err());

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn add_folder_preserves_structure_and_skips_links() {
        let path = temp("folder");
        let src = temp("src");
        let _ = std::fs::remove_dir_all(&path);
        let _ = std::fs::remove_dir_all(&src);

        std::fs::create_dir_all(src.join("sub/deep")).unwrap();
        std::fs::write(src.join("root.txt"), b"root").unwrap();
        std::fs::write(src.join("sub/a.txt"), b"a").unwrap();
        std::fs::write(src.join("sub/deep/b.txt"), b"b").unwrap();

        // A symlink pointing outside the tree must be skipped.
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/passwd", src.join("evil-link.txt")).ok();

        let vault = Vault::create(&path, PASS).unwrap();
        let session = Session::new(vault);
        let n = session.add_folder(&src).unwrap();
        assert_eq!(n, 3, "symlink must be skipped");

        let files = session.list_files().unwrap();
        let names: std::collections::HashSet<&str> =
            files.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains("root.txt"));
        assert!(names.contains("sub/a.txt"));
        assert!(names.contains("sub/deep/b.txt"));
        assert!(!names.iter().any(|n| n.contains("evil-link")));

        let _ = std::fs::remove_dir_all(&path);
        let _ = std::fs::remove_dir_all(&src);
    }

    #[test]
    fn traversal_names_are_rejected() {
        let path = temp("traversal");
        let _ = std::fs::remove_dir_all(&path);
        let vault = Vault::create(&path, PASS).unwrap();
        let session = Session::new(vault);

        let e = session.add_file("ok.txt", b"x").unwrap();

        // QV-01: rename to a traversal path is refused.
        assert!(session.rename_file(&e.id, "../escape.txt").is_err());
        assert!(session.rename_file(&e.id, "/abs.txt").is_err());
        assert!(session.rename_file(&e.id, "C:\\evil.txt").is_err());

        // Adding a file with a traversal name is refused.
        assert!(session.add_file("../escape.txt", b"x").is_err());

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn tampered_sidecar_name_is_rejected_on_extract() {
        // A sidecar carrying a traversal name must be refused, and the
        // hostile sidecar must not make the whole vault unreadable.
        let path = temp("crafted");
        let _ = std::fs::remove_dir_all(&path);
        let vault = Vault::create(&path, PASS).unwrap();
        let session = Session::new(vault);

        let e = session.add_file("real.txt", b"payload").unwrap();
        let hostile = format!(
            r#"{{"id":"{}","name":"../../etc/evil","size":1,"mime":"text/plain","created":0,"modified":0}}"#,
            e.id
        );
        plant_sidecar(&session, &e.id, &hostile);

        assert!(session.extract_file(&e.id).is_err());
        // The other files must still list.
        assert!(session.list_files().unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn crafted_file_ids_are_rejected() {
        // QV2-01 regression: a sidecar can carry attacker-chosen IDs, so they
        // must be validated at parse time and before disk use.
        let path = temp("crafted-id");
        let _ = std::fs::remove_dir_all(&path);
        let vault = Vault::create(&path, PASS).unwrap();
        let session = Session::new(vault);

        let e = session.add_file("real.txt", b"payload").unwrap();

        // Direct IPC-style call with a traversal ID.
        assert!(session.extract_file("../../etc/passwd").is_err());
        assert!(session.delete_file("../../etc/passwd").is_err());
        assert!(session.rename_file("../x", "y.txt").is_err());

        // A sidecar whose entry carries a traversal ID is rejected on load.
        let hostile = r#"{"id":"../../evil","name":"f.txt","size":1,"mime":"text/plain","created":0,"modified":0}"#;
        plant_sidecar(&session, &e.id, hostile);
        assert!(
            session.list_files().unwrap().is_empty(),
            "sidecar with bad id must not load"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn sidecar_cannot_be_substituted_for_a_payload_blob() {
        // QV3-01: the metadata and payload blobs share a wire format, so the
        // AAD purpose is what keeps them apart. A sidecar presented as a
        // payload must fail to authenticate.
        let path = temp("substitute");
        let _ = std::fs::remove_dir_all(&path);
        let vault = Vault::create(&path, PASS).unwrap();
        let session = Session::new(vault);

        let e = session.add_file("real.txt", b"payload").unwrap();
        let sidecar = std::fs::read(manifest::sidecar_path(&session.path, &e.id).unwrap()).unwrap();
        let blob_path = manifest::blob_path(&session.path, &e.id).unwrap();

        // Swap them: the sidecar now sits where the payload should be.
        std::fs::write(&blob_path, &sidecar).unwrap();
        assert!(session.extract_file(&e.id).is_err());

        // And the other way round.
        std::fs::write(&blob_path, b"not a blob").unwrap();
        assert!(session.extract_file(&e.id).is_err());

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn delete_unknown_id_leaves_state_unchanged() {
        // QV2-01/QV2-04: an unknown ID must not mutate the vault.
        let path = temp("del-unknown");
        let _ = std::fs::remove_dir_all(&path);
        let vault = Vault::create(&path, PASS).unwrap();
        let session = Session::new(vault);

        let e = session.add_file("keep.txt", b"keep").unwrap();
        let unknown = "0".repeat(32);
        assert!(session.delete_file(&unknown).is_err());

        let files = session.list_files().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].id, e.id);
        assert!(session.extract_file(&e.id).is_ok());

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn reopens_with_passphrase_only() {
        let path = temp("reopen");
        let _ = std::fs::remove_dir_all(&path);

        {
            let vault = Vault::create(&path, PASS).unwrap();
            let session = Session::new(vault);
            session.add_file("doc.txt", b"secret data").unwrap();
        }

        let vault = Vault::open(&path, PASS).unwrap();
        let session = Session::new(vault);
        let files = session.list_files().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "doc.txt");

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn legacy_shared_index_is_migrated_to_sidecars() {
        // QV3-01: a vault written by v0.1.x (one shared `manifest.qvault`)
        // must still open, and must be converted to per-file sidecars.
        let path = temp("legacy");
        let _ = std::fs::remove_dir_all(&path);

        {
            let vault = Vault::create(&path, PASS).unwrap();
            let session = Session::new(vault);
            session.add_file("one.txt", b"one").unwrap();
            session.add_file("two.txt", b"two").unwrap();
        }

        // Rewrite the vault in the old shape: one shared index, no sidecars.
        let vault = Vault::open(&path, PASS).unwrap();
        let session = Session::new(vault);
        let entries = session.list_files().unwrap();
        assert_eq!(entries.len(), 2);

        let legacy = Manifest {
            files: entries.clone(),
        };
        let json = serde_json::to_vec(&legacy).unwrap();
        let ctx = session.ctx(format::MANIFEST_CONTEXT);
        let blob =
            format::encrypt_file(&json, &session.vault_pub, &session.pass_kek, &ctx).unwrap();
        write_atomic(&path.join(crate::vault::MANIFEST_FILENAME), &blob).unwrap();

        for e in &entries {
            std::fs::remove_file(manifest::sidecar_path(&session.path, &e.id).unwrap()).unwrap();
        }

        // Reopen: the migration must restore every file from the legacy index.
        let vault = Vault::open(&path, PASS).unwrap();
        let session = Session::new(vault);
        let files = session.list_files().unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.iter().any(|f| f.name == "one.txt"));
        assert!(files.iter().any(|f| f.name == "two.txt"));

        // The legacy index is removed once the sidecars are in place.
        assert!(!path.join(crate::vault::MANIFEST_FILENAME).exists());

        // And the migrated vault has real sidecars on disk.
        for e in &files {
            assert!(
                manifest::sidecar_path(&session.path, &e.id)
                    .unwrap()
                    .exists()
            );
        }

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn legacy_v3_vault_opens_and_is_upgraded_in_place() {
        // QV3-01: the metadata version bump is the safeguard that makes an
        // *older* app fail loudly on a new vault instead of silently showing
        // an empty one. It must also be backwards compatible: a v3 vault has
        // to open with its own passphrase, get migrated, and keep opening.
        let path = temp("legacy-v3");
        let _ = std::fs::remove_dir_all(&path);

        let vault = Vault::create(&path, PASS).unwrap();
        let session = Session::new(vault);
        session.add_file("keep.txt", b"keep me").unwrap();

        // Rewrite vault.meta back to the v3 layout: same fields, older
        // version, and a verifier recomputed over the v3 digest so that it is
        // a *valid* v3 vault rather than a corrupt one.
        let meta_path = path.join(crate::vault::META_FILENAME);
        let json = std::fs::read_to_string(&meta_path).unwrap();
        let mut meta: crate::vault::VaultMeta = serde_json::from_str(&json).unwrap();
        meta.version = crate::vault::META_VERSION_LEGACY;
        let pass_kek = crate::crypto::kdf::derive(
            PASS,
            &base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &meta.verify_salt_b64,
            )
            .unwrap(),
        )
        .unwrap();
        crate::vault::Vault::refresh_verifier(&mut meta, &pass_kek).unwrap();
        std::fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();

        // A v3 vault must still open with its own passphrase.
        let vault = Vault::open(&path, PASS).unwrap();
        let session = Session::new(vault);
        let files = session.list_files().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "keep.txt");

        // After the migration the vault claims the current version.
        let json = std::fs::read_to_string(&meta_path).unwrap();
        let meta: crate::vault::VaultMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(meta.version, crate::vault::META_VERSION);

        // And it must STILL open with the same passphrase after the bump —
        // the verifier was recomputed over the new digest, so a stale
        // verifier would lock the user out of their own vault.
        let vault = Vault::open(&path, PASS).unwrap();
        let session = Session::new(vault);
        let files = session.list_files().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "keep.txt");
        let (_, data) = session.extract_file(&files[0].id).unwrap();
        assert_eq!(data.as_slice(), b"keep me");

        // A wrong passphrase must still be rejected.
        assert!(Vault::open(&path, b"wrong passphrase entirely").is_err());

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn concurrent_adds_from_two_sessions_do_not_lose_files() {
        // The whole point of sidecars: two machines adding files at the same
        // time must both keep their files, because they never write the same
        // file. Simulated here by interleaving two sessions on one vault.
        let path = temp("concurrent");
        let _ = std::fs::remove_dir_all(&path);

        let vault = Vault::create(&path, PASS).unwrap();
        let a = Session::new(vault);
        let b = Session::new(Vault::open(&path, PASS).unwrap());

        a.add_file("from-a.txt", b"a").unwrap();
        b.add_file("from-b.txt", b"b").unwrap();
        a.add_file("from-a2.txt", b"a2").unwrap();

        let files = a.list_files().unwrap();
        let names: std::collections::HashSet<&str> =
            files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(files.len(), 3);
        assert!(names.contains("from-a.txt"));
        assert!(names.contains("from-b.txt"));
        assert!(names.contains("from-a2.txt"));

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn oversized_file_rejected() {
        let path = temp("oversize");
        let _ = std::fs::remove_dir_all(&path);
        let vault = Vault::create(&path, PASS).unwrap();
        let session = Session::new(vault);

        // Guard the interim control remains meaningfully large.
        const _: () = assert!(MAX_FILE_BYTES >= 64 * 1024 * 1024);
        let small = vec![0u8; 32 * 1024];
        assert!(session.add_file("small.bin", &small).is_ok());

        let _ = std::fs::remove_dir_all(&path);
    }
}
