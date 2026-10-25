//! Quantum Vault — Tauri backend.
//!
//! Manages a registry of known vaults plus an in-memory map of unlocked
//! [`Session`]s (one per vault, keyed by normalized path).

mod crypto;
mod folder_icon;
mod manifest;
mod paths;
mod registry;
#[cfg(test)]
mod robustness;
mod session;
mod vault;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;
use tauri::State;

use crate::manifest::FileEntry;
use crate::session::Session;
use crate::vault::Vault;

/// Shared application state.
struct AppState {
    /// Unlocked sessions, keyed by normalized vault path.
    sessions: Mutex<HashMap<String, Session>>,
    /// Absolute path to the persisted registry JSON.
    registry_path: std::path::PathBuf,
}

/// A registered vault, with computed status for the UI.
#[derive(Serialize)]
struct VaultStatus {
    name: String,
    path: String,
    /// Whether the path (and its `vault.meta`) still exists on disk.
    exists: bool,
    /// Whether there is an active unlocked session.
    unlocked: bool,
}

/// A decrypted file returned to the frontend.
#[derive(Serialize)]
struct ExtractedFile {
    id: String,
    name: String,
    mime: String,
    data: Vec<u8>,
}

/// Normalize a path into a stable session/registry key.
fn norm_key(path: &str) -> String {
    path.replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

fn basename(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("Vault")
        .to_string()
}

/// Run `f` against the unlocked session for `vault`.
fn with_session<R>(
    state: &AppState,
    vault: &str,
    f: impl FnOnce(&Session) -> Result<R, String>,
) -> Result<R, String> {
    let guard = state
        .sessions
        .lock()
        .map_err(|_| "session lock poisoned".to_string())?;
    let session = guard
        .get(&norm_key(vault))
        .ok_or_else(|| "vault is locked".to_string())?;
    f(session)
}

// ─────────────────────────── vault lifecycle ───────────────────────────

#[tauri::command]
fn create_vault(
    state: State<AppState>,
    path: String,
    passphrase: String,
) -> Result<String, String> {
    // QV-05: hold the passphrase in a buffer we can zeroize.
    let pb = zeroize::Zeroizing::new(passphrase.into_bytes());
    let vault = Vault::create(Path::new(&path), &pb).map_err(|e| e.to_string())?;
    let key = norm_key(&path);

    let name = basename(&path);
    let mut records = registry::load(&state.registry_path);
    registry::add(&mut records, &name, &path);
    registry::save(&state.registry_path, &records).map_err(|e| e.to_string())?;

    state
        .sessions
        .lock()
        .map_err(|_| "session lock poisoned".to_string())?
        .insert(key.clone(), Session::new(vault));
    Ok(key)
}

#[tauri::command]
fn open_vault(state: State<AppState>, path: String, passphrase: String) -> Result<String, String> {
    let pb = zeroize::Zeroizing::new(passphrase.into_bytes());
    let vault = Vault::open(Path::new(&path), &pb).map_err(|e| e.to_string())?;
    let key = norm_key(&path);

    let name = basename(&path);
    let mut records = registry::load(&state.registry_path);
    if registry::add(&mut records, &name, &path) {
        registry::save(&state.registry_path, &records).map_err(|e| e.to_string())?;
    }

    state
        .sessions
        .lock()
        .map_err(|_| "session lock poisoned".to_string())?
        .insert(key.clone(), Session::new(vault));
    Ok(key)
}

/// Lock a vault (drop its in-memory session) but keep it registered.
#[tauri::command]
fn lock_vault(state: State<AppState>, path: String) -> Result<(), String> {
    state
        .sessions
        .lock()
        .map_err(|_| "session lock poisoned".to_string())?
        .remove(&norm_key(&path));
    Ok(())
}

/// Unregister a vault (and lock it).
#[tauri::command]
fn remove_vault(state: State<AppState>, path: String) -> Result<(), String> {
    state
        .sessions
        .lock()
        .map_err(|_| "session lock poisoned".to_string())?
        .remove(&norm_key(&path));

    let mut records = registry::load(&state.registry_path);
    registry::remove(&mut records, &path);
    registry::save(&state.registry_path, &records).map_err(|e| e.to_string())?;
    Ok(())
}

/// List registered vaults with availability + lock status.
#[tauri::command]
fn list_vaults(state: State<AppState>) -> Result<Vec<VaultStatus>, String> {
    let records = registry::load(&state.registry_path);
    let guard = state
        .sessions
        .lock()
        .map_err(|_| "session lock poisoned".to_string())?;
    Ok(records
        .into_iter()
        .map(|r| {
            let exists = Path::new(&r.path).join(vault::META_FILENAME).exists();
            let unlocked = guard.contains_key(&norm_key(&r.path));
            VaultStatus {
                name: r.name,
                path: r.path,
                exists,
                unlocked,
            }
        })
        .collect())
}

/// Recursively find existing vaults (folders containing `vault.meta`).
#[tauri::command]
fn discover_vaults(folder: String) -> Result<Vec<String>, String> {
    Ok(vault::find_vaults(Path::new(&folder))
        .into_iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect())
}

#[tauri::command]
fn is_unlocked(state: State<AppState>, path: String) -> Result<bool, String> {
    Ok(state
        .sessions
        .lock()
        .map_err(|_| "session lock poisoned".to_string())?
        .contains_key(&norm_key(&path)))
}

/// UI-facing passphrase strength hint.
#[tauri::command]
fn passphrase_strength(passphrase: String) -> Option<&'static str> {
    crate::crypto::kdf::strength_problem(&passphrase)
}

// ─────────────────────────── file commands ───────────────────────────

#[tauri::command]
fn list_files(state: State<AppState>, vault: String) -> Result<Vec<FileEntry>, String> {
    with_session(&state, &vault, |s| {
        s.list_files().map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn add_file_from_path(
    state: State<AppState>,
    vault: String,
    path: String,
) -> Result<FileEntry, String> {
    with_session(&state, &vault, |s| {
        let p = Path::new(&path);
        let name = p
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        // QV-01: validate the basename before it enters the manifest.
        crate::paths::validate_basename(&name).map_err(|e| e.to_string())?;
        let meta = std::fs::metadata(p).map_err(|e| format!("stat file: {e}"))?;
        if meta.len() > crate::session::MAX_FILE_BYTES {
            return Err(format!(
                "file too large: {} bytes (limit {} bytes)",
                meta.len(),
                crate::session::MAX_FILE_BYTES
            ));
        }
        let data = std::fs::read(p).map_err(|e| format!("read file: {e}"))?;
        s.add_file(&name, &data).map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn add_folder_from_path(
    state: State<AppState>,
    vault: String,
    path: String,
) -> Result<usize, String> {
    with_session(&state, &vault, |s| {
        s.add_folder(Path::new(&path)).map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn extract_file(
    state: State<AppState>,
    vault: String,
    id: String,
) -> Result<ExtractedFile, String> {
    with_session(&state, &vault, |s| {
        s.extract_file(&id)
            .map(|(entry, data)| ExtractedFile {
                id: entry.id,
                name: entry.name,
                mime: entry.mime,
                data: data.to_vec(),
            })
            .map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn extract_file_to(
    state: State<AppState>,
    vault: String,
    id: String,
    dest_dir: String,
) -> Result<String, String> {
    with_session(&state, &vault, |s| {
        let (entry, data) = s.extract_file(&id).map_err(|e| e.to_string())?;
        // QV2-03: create the destination without following links or junctions,
        // and refuse to overwrite an existing file. Path checks alone are not
        // enough: a pre-existing symlink under the destination could redirect a
        // lexically-valid relative path outside the chosen directory.
        let (dest, mut file) =
            crate::paths::create_file_nofollow(Path::new(&dest_dir), &entry.name)
                .map_err(|e| e.to_string())?;
        std::io::Write::write_all(&mut file, &data).map_err(|e| format!("write file: {e}"))?;
        file.sync_all().map_err(|e| format!("sync file: {e}"))?;
        Ok(dest.to_string_lossy().to_string())
    })
}

#[tauri::command]
fn delete_file(state: State<AppState>, vault: String, id: String) -> Result<(), String> {
    with_session(&state, &vault, |s| {
        s.delete_file(&id).map_err(|e| e.to_string())
    })
}

#[tauri::command]
fn rename_file(
    state: State<AppState>,
    vault: String,
    id: String,
    new_name: String,
) -> Result<(), String> {
    with_session(&state, &vault, |s| {
        s.rename_file(&id, &new_name).map_err(|e| e.to_string())
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            use tauri::Manager;
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            app.manage(AppState {
                sessions: Mutex::new(HashMap::new()),
                registry_path: dir.join("vaults.json"),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            create_vault,
            open_vault,
            lock_vault,
            remove_vault,
            list_vaults,
            discover_vaults,
            is_unlocked,
            passphrase_strength,
            list_files,
            add_file_from_path,
            add_folder_from_path,
            extract_file,
            extract_file_to,
            delete_file,
            rename_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
