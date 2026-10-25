//! Tag a vault folder with a custom icon via `desktop.ini`.
//!
//! Writes a hidden `desktop.ini` + a hidden `.vault-icon.ico` (the app icon,
//! embedded in the binary) into the vault folder and marks the folder with the
//! `System` attribute so Windows Explorer renders the custom icon.
//!
//! This is best-effort and cosmetic: it shows in Windows Explorer (including the
//! local view of a Google Drive / OneDrive synced folder). Cloud providers' *web*
//! UIs render folders with their own icons and ignore `desktop.ini`. The icon and
//! `desktop.ini` themselves sync as ordinary files, so the custom icon also
//! appears on other Windows machines that open the synced folder.

use std::path::Path;

use windows::Win32::Storage::FileSystem::{
    SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM,
};
use windows::core::HSTRING;

/// Hidden icon filename inside the vault folder.
const ICON_NAME: &str = ".vault-icon.ico";
/// The app icon, embedded at compile time.
const ICON_BYTES: &[u8] = include_bytes!("../icons/icon.ico");
/// desktop.ini contents (icon referenced relative to the folder).
const DESKTOP_INI: &str = "[.ShellClassInfo]\r\nIconResource=.vault-icon.ico,0\r\nIconIndex=0\r\n";

/// Apply the custom folder icon. Best-effort — errors are ignored by the caller.
pub fn apply(path: &Path) -> std::io::Result<()> {
    std::fs::write(path.join(ICON_NAME), ICON_BYTES)?;
    std::fs::write(path.join("desktop.ini"), DESKTOP_INI)?;

    set_attr(&path.join("desktop.ini"), FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
    set_attr(&path.join(ICON_NAME), FILE_ATTRIBUTE_HIDDEN);
    // The folder itself needs the System attribute for Explorer to read desktop.ini.
    set_attr(path, FILE_ATTRIBUTE_SYSTEM);

    Ok(())
}

fn set_attr(
    path: &Path,
    flags: windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES,
) {
    let ws = HSTRING::from(path.to_string_lossy().as_ref());
    // SAFETY: `ws` is a valid null-terminated wide string describing a path we
    // just created. Best-effort — ignore failures (e.g. on non-Windows targets).
    let _ = unsafe { SetFileAttributesW(&ws, flags) };
}
