//! An unlocked vault session.
//!
//! Holds the in-memory secrets needed during an open session: the session
//! passphrase KEK (Argon2id, derived once at unlock; zeroized on drop) and, if
//! DPAPI succeeded on this machine, the unsealed device private keys. All file
//! operations go through here.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::error::{CryptoError, Result};
use crate::crypto::{self, format, kem};
use crate::manifest::{hex, FileEntry, Manifest};
use crate::vault::{Vault, MANIFEST_FILENAME};

/// The `.qvault` file extension.
const FILE_EXT: &str = "qvault";

/// An unlocked vault session.
pub struct Session {
    /// Absolute path to the vault directory.
    pub path: PathBuf,
    /// Public keys (used for encrypting new files).
    pub vault_pub: kem::VaultPublic,
    /// Unsealed device private keys, if DPAPI worked on this machine.
    pub device_priv: Option<kem::VaultPrivate>,
    /// Session passphrase KEK, zeroized on drop.
    pass_kek: [u8; format::KEK_LEN],
}

impl Session {
    /// Build a session from an opened [`Vault`].
    pub fn new(vault: Vault) -> Self {
        Session {
            path: vault.path,
            vault_pub: vault.vault_pub,
            device_priv: vault.device_priv,
            pass_kek: vault.pass_kek,
        }
    }

    /// List the vault's files (decrypts the manifest).
    pub fn list_files(&self) -> Result<Vec<FileEntry>> {
        Ok(self.load_manifest()?.files)
    }

    /// Encrypt `data` into the vault under `name`.
    pub fn add_file(&self, name: &str, data: &[u8]) -> Result<FileEntry> {
        let entry = self.encrypt_into(name, data)?;
        let mut manifest = self.load_manifest()?;
        manifest.upsert(entry.clone());
        self.save_manifest(&manifest)?;
        Ok(entry)
    }

    /// Recursively encrypt every file under `folder`, preserving relative paths.
    /// Returns the number of files encrypted.
    pub fn add_folder(&self, folder: &Path) -> Result<usize> {
        let mut files = Vec::new();
        walk_files(folder, folder, &mut files)?;
        if files.is_empty() {
            return Err(CryptoError::Other(format!(
                "no files found in {}",
                folder.display()
            )));
        }

        let mut manifest = self.load_manifest()?;
        for (rel, abs) in &files {
            let data = std::fs::read(abs)
                .map_err(|e| CryptoError::Other(format!("read {}: {e}", abs.display())))?;
            let entry = self.encrypt_into(rel, &data)?;
            manifest.upsert(entry);
        }
        self.save_manifest(&manifest)?;
        Ok(files.len())
    }

    /// Encrypt `data` under `name` and write the blob; returns the manifest entry.
    fn encrypt_into(&self, name: &str, data: &[u8]) -> Result<FileEntry> {
        let id = self.new_id()?;
        let blob = format::encrypt_file(data, &self.vault_pub, &self.pass_kek)?;
        std::fs::write(self.file_path(&id), &blob)
            .map_err(|e| CryptoError::Other(format!("write encrypted file: {e}")))?;

        let now = now_ts();
        Ok(FileEntry {
            id,
            name: name.to_string(),
            size: data.len() as u64,
            mime: guess_mime(name),
            created: now,
            modified: now,
        })
    }

    /// Decrypt a file, returning its entry and plaintext bytes.
    pub fn extract_file(&self, id: &str) -> Result<(FileEntry, Vec<u8>)> {
        let manifest = self.load_manifest()?;
        let entry = manifest
            .get(id)
            .cloned()
            .ok_or_else(|| CryptoError::InvalidFormat(format!("no such file: {id}")))?;

        let blob = std::fs::read(self.file_path(id))
            .map_err(|e| CryptoError::Other(format!("read encrypted file: {e}")))?;
        let data = format::decrypt_file(&blob, self.device_priv.as_ref(), Some(&self.pass_kek))?;
        Ok((entry, data))
    }

    /// Delete a file (encrypted blob + manifest entry).
    pub fn delete_file(&self, id: &str) -> Result<()> {
        let mut manifest = self.load_manifest()?;
        manifest.remove(id);
        self.save_manifest(&manifest)?;
        std::fs::remove_file(self.file_path(id))
            .map_err(|e| CryptoError::Other(format!("delete encrypted file: {e}")))?;
        Ok(())
    }

    /// Rename a file's plaintext name (manifest-only change).
    pub fn rename_file(&self, id: &str, new_name: &str) -> Result<()> {
        let mut manifest = self.load_manifest()?;
        let entry = manifest
            .get_mut(id)
            .ok_or_else(|| CryptoError::InvalidFormat(format!("no such file: {id}")))?;
        entry.name = new_name.to_string();
        entry.modified = now_ts();
        entry.mime = guess_mime(new_name);
        self.save_manifest(&manifest)
    }

    fn load_manifest(&self) -> Result<Manifest> {
        let path = self.path.join(MANIFEST_FILENAME);
        if !path.exists() {
            return Ok(Manifest::new());
        }
        let blob = std::fs::read(&path)
            .map_err(|e| CryptoError::Other(format!("read manifest: {e}")))?;
        let json = format::decrypt_file(&blob, self.device_priv.as_ref(), Some(&self.pass_kek))?;
        serde_json::from_slice(&json)
            .map_err(|e| CryptoError::InvalidFormat(format!("parse manifest: {e}")))
    }

    fn save_manifest(&self, manifest: &Manifest) -> Result<()> {
        let json = serde_json::to_vec(manifest)
            .map_err(|e| CryptoError::Other(format!("serialize manifest: {e}")))?;
        let blob = format::encrypt_file(&json, &self.vault_pub, &self.pass_kek)?;
        std::fs::write(self.path.join(MANIFEST_FILENAME), &blob)
            .map_err(|e| CryptoError::Other(format!("write manifest: {e}")))?;
        Ok(())
    }

    fn new_id(&self) -> Result<String> {
        let bytes: [u8; 16] = crypto::random()?;
        Ok(hex(&bytes))
    }

    fn file_path(&self, id: &str) -> PathBuf {
        self.path.join(format!("{id}.{FILE_EXT}"))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.pass_kek);
    }
}

/// Recursively collect files under `dir`, as `(relative-path, absolute-path)`.
fn walk_files(dir: &Path, base: &Path, out: &mut Vec<(String, PathBuf)>) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| CryptoError::Other(format!("read dir {}: {e}", dir.display())))?;
    for entry in entries {
        let entry = entry.map_err(|e| CryptoError::Other(e.to_string()))?;
        let path = entry.path();
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

    fn temp_vault_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("qvault-session-{name}-{}", std::process::id()))
    }

    #[test]
    fn add_list_extract_delete_round_trip() {
        let path = temp_vault_path("files");
        let _ = std::fs::remove_dir_all(&path);
        let pass = b"session passphrase".to_vec();

        let vault = Vault::create(&path, &pass).unwrap();
        let session = Session::new(vault);

        let a = session.add_file("hello.txt", b"hello world").unwrap();
        let b = session.add_file("data.json", b"{\"k\":1}").unwrap();

        assert_eq!(session.list_files().unwrap().len(), 2);

        let (entry, data) = session.extract_file(&a.id).unwrap();
        assert_eq!(entry.name, "hello.txt");
        assert_eq!(data, b"hello world");

        session.rename_file(&b.id, "renamed.json").unwrap();
        assert_eq!(
            session.list_files().unwrap().iter().find(|f| f.id == b.id).unwrap().name,
            "renamed.json"
        );

        session.delete_file(&a.id).unwrap();
        assert_eq!(session.list_files().unwrap().len(), 1);
        assert!(session.extract_file(&a.id).is_err());

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn add_folder_preserves_structure() {
        let path = temp_vault_path("folder");
        let _ = std::fs::remove_dir_all(&path);
        let pass = b"folder passphrase".to_vec();

        // Build a small source tree.
        let src = temp_vault_path("src");
        let _ = std::fs::remove_dir_all(&src);
        std::fs::create_dir_all(src.join("sub/deep")).unwrap();
        std::fs::write(src.join("root.txt"), b"root").unwrap();
        std::fs::write(src.join("sub/a.txt"), b"a").unwrap();
        std::fs::write(src.join("sub/deep/b.txt"), b"b").unwrap();

        let vault = Vault::create(&path, &pass).unwrap();
        let session = Session::new(vault);

        let n = session.add_folder(&src).unwrap();
        assert_eq!(n, 3);

        let files = session.list_files().unwrap();
        let names: std::collections::HashSet<&str> =
            files.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains("root.txt"));
        assert!(names.contains("sub/a.txt"));
        assert!(names.contains("sub/deep/b.txt"));

        // Extract one nested file and check content.
        let nested = files.iter().find(|f| f.name == "sub/deep/b.txt").unwrap();
        let (_, data) = session.extract_file(&nested.id).unwrap();
        assert_eq!(data, b"b");

        let _ = std::fs::remove_dir_all(&path);
        let _ = std::fs::remove_dir_all(&src);
    }

    #[test]
    fn reopens_with_passphrase_only() {
        let path = temp_vault_path("reopen");
        let _ = std::fs::remove_dir_all(&path);
        let pass = b"reopen passphrase".to_vec();

        {
            let vault = Vault::create(&path, &pass).unwrap();
            let session = Session::new(vault);
            session.add_file("doc.txt", b"secret data").unwrap();
        }

        let vault = Vault::open(&path, &pass).unwrap();
        let session = Session::new(vault);
        let files = session.list_files().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "doc.txt");

        let _ = std::fs::remove_dir_all(&path);
    }
}
