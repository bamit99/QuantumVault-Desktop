//! Persistent registry of known vaults (name + path).
//!
//! Stored as JSON in the app data directory. Non-secret — only display names
//! and paths. Lock state and availability are computed at query time, not stored.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::crypto::error::{CryptoError, Result};

/// A registered vault (display name + absolute path).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultRecord {
    pub name: String,
    pub path: String,
}

/// Load the registry (missing file ⇒ empty list).
pub fn load(path: &Path) -> Vec<VaultRecord> {
    let Ok(json) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    serde_json::from_str(&json).unwrap_or_default()
}

/// Persist the registry.
pub fn save(path: &Path, records: &[VaultRecord]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CryptoError::Other(format!("create registry dir: {e}")))?;
    }
    let json = serde_json::to_string_pretty(records)
        .map_err(|e| CryptoError::Other(format!("serialize registry: {e}")))?;
    std::fs::write(path, json).map_err(|e| CryptoError::Other(format!("write registry: {e}")))?;
    Ok(())
}

/// Add a record if not already present (matched by normalized path).
pub fn add(records: &mut Vec<VaultRecord>, name: &str, path: &str) -> bool {
    let norm = |p: &str| {
        p.replace('\\', "/")
            .trim_end_matches('/')
            .to_ascii_lowercase()
    };
    if records.iter().any(|r| norm(&r.path) == norm(path)) {
        return false;
    }
    records.push(VaultRecord {
        name: name.to_string(),
        path: path.to_string(),
    });
    true
}

/// Remove records matching the given path.
pub fn remove(records: &mut Vec<VaultRecord>, path: &str) {
    let norm = |p: &str| {
        p.replace('\\', "/")
            .trim_end_matches('/')
            .to_ascii_lowercase()
    };
    records.retain(|r| norm(&r.path) != norm(path));
}
