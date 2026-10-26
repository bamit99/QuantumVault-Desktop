//! Per-file metadata sidecars, and the legacy shared index.
//!
//! Each encrypted file in the vault carries its metadata (original name,
//! size, MIME type, timestamps) in its own encrypted sidecar, `<id>.meta`,
//! sitting next to the `<id>.qvault` payload blob.
//!
//! ## Why sidecars instead of one shared index
//!
//! A vault folder is designed to live inside a cloud-synced directory
//! (OneDrive, Google Drive, Dropbox) and to be edited on more than one
//! machine. A single shared index file must be *rewritten in full* on every
//! add, rename or delete, so two devices editing the vault at the same time
//! produce two conflicting copies of that index. The cloud sync client then
//! resolves the conflict by keeping one side's version — and the other
//! device's files silently disappear from the index, even though their
//! payload blobs are still sitting in the folder.
//!
//! Per-file sidecars are disjoint files: a concurrent add on two machines
//! writes two different sidecars and never touches the same file, so there is
//! nothing to conflict. Only a rename or delete of the *same* file can
//! conflict, and that is a genuine last-writer-wins race on one item rather
//! than a whole-index loss.
//!
//! ## Wire format
//!
//! A sidecar is encrypted with the same dual-wrap scheme as a payload blob
//! (fresh per-blob key, AES-256-GCM, hybrid ML-KEM-768 + X25519 device leg
//! and Argon2id passphrase leg), but it is bound to *distinct* AAD purposes.
//! A sidecar therefore can never be substituted for a payload blob, or the
//! reverse: both the payload layer and the key-wrap layer fail to
//! authenticate. See [`crate::crypto::format`].

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::crypto::error::{CryptoError, Result};
use crate::paths;

/// Extension of a payload blob (`<id>.qvault`).
pub const FILE_EXT: &str = "qvault";
/// Extension of a metadata sidecar (`<id>.meta`).
pub const META_EXT: &str = "meta";

/// One entry describing an encrypted file in the vault.
///
/// This is the plaintext form; on disk it only ever exists inside an
/// encrypted sidecar.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileEntry {
    /// Opaque on-disk identifier (also the filename stem, minus the extension).
    pub id: String,
    /// Original plaintext filename (hidden inside the encrypted sidecar).
    pub name: String,
    /// Plaintext size in bytes.
    pub size: u64,
    /// MIME type, if known.
    pub mime: String,
    /// Unix timestamp (seconds) when the file was added.
    pub created: u64,
    /// Unix timestamp (seconds) of last modification.
    pub modified: u64,
}

impl FileEntry {
    /// Validate an entry that came out of decrypted storage.
    ///
    /// Sidecar contents are decrypted data and must never be trusted: the ID
    /// must match the grammar *and* the file it was read from, and the name
    /// must be a safe relative path.
    pub fn validate(&self, expected_id: &str) -> Result<()> {
        paths::validate_file_id(&self.id).map_err(|_| {
            CryptoError::InvalidFormat("metadata sidecar contains an invalid file id".into())
        })?;
        if self.id != expected_id {
            return Err(CryptoError::InvalidFormat(
                "metadata sidecar id does not match the file it describes".into(),
            ));
        }
        paths::validate_relative(&self.name).map_err(|_| {
            CryptoError::InvalidFormat("metadata sidecar contains an unsafe file name".into())
        })?;
        Ok(())
    }
}

/// The legacy shared index, written by v0.1.x and earlier.
///
/// Retained only so an existing vault can be migrated to sidecars on read.
/// New vaults never write this file.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Manifest {
    /// Entries keyed in insertion order.
    pub files: Vec<FileEntry>,
}

/// Path of the payload blob for `id` inside `base`.
pub fn blob_path(base: &Path, id: &str) -> Result<PathBuf> {
    paths::validate_file_id(id)?;
    Ok(base.join(format!("{id}.{FILE_EXT}")))
}

/// Path of the metadata sidecar for `id` inside `base`.
pub fn sidecar_path(base: &Path, id: &str) -> Result<PathBuf> {
    paths::validate_file_id(id)?;
    Ok(base.join(format!("{id}.{META_EXT}")))
}

/// Encode an entry as the plaintext of a sidecar.
pub fn encode_entry(entry: &FileEntry) -> Result<Vec<u8>> {
    serde_json::to_vec(entry).map_err(|e| CryptoError::Other(format!("serialize sidecar: {e}")))
}

/// Decode a sidecar plaintext into an entry, validating it against `id`.
pub fn decode_entry(bytes: &[u8], expected_id: &str) -> Result<FileEntry> {
    let entry: FileEntry = serde_json::from_slice(bytes)
        .map_err(|e| CryptoError::InvalidFormat(format!("parse sidecar: {e}")))?;
    entry.validate(expected_id)?;
    Ok(entry)
}

/// Extract the file ID from a vault-directory filename.
///
/// Returns `None` for names that are not vault files (the legacy shared
/// index, the folder icon, `desktop.ini`, temporary write files, …).
pub fn id_from_filename(name: &str) -> Option<&str> {
    let id = name.strip_suffix(&format!(".{FILE_EXT}"))?;
    // The legacy shared index lives in the same directory and shares the
    // extension. It is not a valid file ID, so the grammar check rejects it.
    if id.len() != paths::FILE_ID_HEX_LEN {
        return None;
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    Some(id)
}

/// Encode `bytes` as lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, name: &str) -> FileEntry {
        FileEntry {
            id: id.to_string(),
            name: name.to_string(),
            size: 10,
            mime: "text/plain".into(),
            created: 1,
            modified: 2,
        }
    }

    #[test]
    fn sidecar_round_trip() {
        let e = entry("a".repeat(32).as_str(), "dir/file.txt");
        let bytes = encode_entry(&e).unwrap();
        let back = decode_entry(&bytes, &e.id).unwrap();
        assert_eq!(back.name, "dir/file.txt");
        assert_eq!(back.size, 10);
    }

    #[test]
    fn sidecar_id_must_match_its_file() {
        let e = entry("a".repeat(32).as_str(), "f.txt");
        let bytes = encode_entry(&e).unwrap();
        // A sidecar copied onto a different file must not be accepted.
        assert!(decode_entry(&bytes, &"b".repeat(32)).is_err());
    }

    #[test]
    fn sidecar_rejects_unsafe_name() {
        let mut e = entry("a".repeat(32).as_str(), "../escape.txt");
        e.name = "../../etc/passwd".into();
        let bytes = encode_entry(&e).unwrap();
        assert!(decode_entry(&bytes, &e.id).is_err());
    }

    #[test]
    fn sidecar_rejects_bad_id() {
        let mut e = entry("a".repeat(32).as_str(), "f.txt");
        e.id = "../../evil".into();
        let bytes = encode_entry(&e).unwrap();
        assert!(decode_entry(&bytes, &e.id).is_err());
    }

    #[test]
    fn filename_to_id() {
        let id = "ab".repeat(16);
        assert_eq!(id_from_filename(&format!("{id}.qvault")), Some(id.as_str()));
        // The legacy shared index must not be mistaken for a vault file.
        assert_eq!(id_from_filename("manifest.qvault"), None);
        // Sidecars, temp files and unrelated names are not vault files.
        assert_eq!(id_from_filename(&format!("{id}.meta")), None);
        assert_eq!(id_from_filename(&format!("{id}.qvault.tmp-write")), None);
        assert_eq!(id_from_filename("desktop.ini"), None);
        // Uppercase hex is not the grammar we generate.
        assert_eq!(
            id_from_filename(&format!("{}.qvault", "AB".repeat(16))),
            None
        );
    }
}
