//! The encrypted file index (manifest).
//!
//! The manifest is a JSON document mapping opaque IDs to the *original* file
//! metadata (name, size, MIME, timestamps). It is itself encrypted with the same
//! dual-wrap scheme as files, so neither filenames nor metadata leak to the cloud.

use serde::{Deserialize, Serialize};

/// One entry in the manifest (an encrypted file in the vault).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileEntry {
    /// Opaque on-disk identifier (also the filename stem, minus `.qvault`).
    pub id: String,
    /// Original plaintext filename (hidden inside the encrypted blob).
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

/// The vault's file index.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Manifest {
    /// Entries keyed in insertion order.
    pub files: Vec<FileEntry>,
}

impl Manifest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, id: &str) -> Option<&FileEntry> {
        self.files.iter().find(|f| f.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut FileEntry> {
        self.files.iter_mut().find(|f| f.id == id)
    }

    pub fn upsert(&mut self, entry: FileEntry) {
        if let Some(existing) = self.files.iter_mut().find(|f| f.id == entry.id) {
            *existing = entry;
        } else {
            self.files.push(entry);
        }
    }

    pub fn remove(&mut self, id: &str) -> Option<FileEntry> {
        if let Some(pos) = self.files.iter().position(|f| f.id == id) {
            Some(self.files.remove(pos))
        } else {
            None
        }
    }
}

/// Encode `bytes` as lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
