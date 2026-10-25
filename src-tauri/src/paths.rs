//! Path validation and link detection (audit QV-01, QV-06).
//!
//! All filename validation happens **in the backend**, at the trust boundary.
//! Manifest contents are decrypted data and must never be trusted as paths.

use std::path::{Component, Path, PathBuf};

use crate::crypto::error::{CryptoError, Result};

/// Maximum length for a single filename component.
const MAX_NAME_LEN: usize = 255;

/// Windows reserved device names (case-insensitive, with or without extension).
const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

fn bad(msg: impl Into<String>) -> CryptoError {
    CryptoError::InvalidFormat(format!("unsafe path: {}", msg.into()))
}

/// Validate a **single filename** (no directory separators).
///
/// Rejects: empty names, separators (`/`, `\`), absolute/UNC paths, drive
/// prefixes, `.`/`..`, control characters, trailing dots/spaces (Windows
/// silently trims these, which can alias another file), reserved device names,
/// and over-long components.
pub fn validate_basename(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(bad("empty filename"));
    }
    if name.chars().count() > MAX_NAME_LEN {
        return Err(bad("filename too long"));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(bad("filename contains a path separator"));
    }
    if name == "." || name == ".." {
        return Err(bad("filename is a directory reference"));
    }
    // Absolute / drive-prefixed / UNC style.
    if name.contains(':') {
        return Err(bad("filename contains a drive or stream separator"));
    }
    // Control characters (incl. NUL) are never valid in a filename.
    if name.chars().any(|c| c.is_control()) {
        return Err(bad("filename contains control characters"));
    }
    // Windows strips trailing dots and spaces, which can alias other names.
    if name.ends_with('.') || name.ends_with(' ') {
        return Err(bad("filename ends with a dot or space"));
    }
    // Reserved device names (checked on the stem, case-insensitively).
    let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        return Err(bad("filename is a reserved device name"));
    }
    Ok(())
}

/// Validate a **relative path** used for folder encryption (may contain
/// separators, but only ordinary components).
pub fn validate_relative(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(bad("empty path"));
    }
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(bad("absolute path"));
    }
    if name.contains(':') {
        return Err(bad("drive or stream separator"));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(bad("control characters"));
    }
    // Every component must be a plain name (no root, parent, or prefix).
    let p = Path::new(name);
    let mut saw_normal = false;
    for comp in p.components() {
        match comp {
            Component::Normal(part) => {
                saw_normal = true;
                validate_basename(&part.to_string_lossy())?;
            }
            Component::CurDir => return Err(bad("'.' component")),
            Component::ParentDir => return Err(bad("'..' component")),
            Component::RootDir => return Err(bad("root component")),
            Component::Prefix(_) => return Err(bad("drive prefix")),
        }
    }
    if !saw_normal {
        return Err(bad("path has no name components"));
    }
    Ok(())
}

/// Length of a file ID in hex characters (16 random bytes → 32 hex chars).
pub const FILE_ID_HEX_LEN: usize = 32;

/// Validate a **file ID** (QV2-01).
///
/// IDs are generated internally as 16 random bytes hex-encoded, so the grammar
/// is exact: 32 lowercase hex characters. Anything else — traversal, absolute
/// paths, drive/UNC prefixes, mixed case, empty — is rejected. This must be
/// enforced at *every* entry point that turns an ID into a path, including the
/// manifest parser and IPC commands, because an encrypted manifest can carry
/// attacker-chosen IDs.
pub fn validate_file_id(id: &str) -> Result<()> {
    if id.len() != FILE_ID_HEX_LEN {
        return Err(CryptoError::InvalidFormat(format!(
            "invalid file id: expected {FILE_ID_HEX_LEN} hex characters, got {}",
            id.len()
        )));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CryptoError::InvalidFormat(
            "invalid file id: must be lowercase hexadecimal".into(),
        ));
    }
    Ok(())
}

/// True if `path` is a symlink or a Windows reparse point (junction).
///
/// Used to refuse traversing out of the selected tree (QV-06).
pub fn is_link(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

/// Join `base` with a validated relative `name` and assert the result stays
/// inside `base` (defense in depth against unusual platform path semantics).
pub fn safe_join(base: &Path, name: &str) -> Result<PathBuf> {
    validate_relative(name)?;
    let joined = base.join(name);
    // Lexical containment check on the normalized components.
    if !lexically_within(base, &joined) {
        return Err(bad("path escapes the destination directory"));
    }
    Ok(joined)
}

/// Resolve `rel` under `base`, creating directories as needed, refusing to
/// traverse any existing symlink or reparse point (QV2-03).
///
/// Returns the full path to the (not yet created) leaf file.
pub fn prepare_destination(base: &Path, rel: &str) -> Result<PathBuf> {
    // Layer 1: grammar + lexical containment.
    let _ = safe_join(base, rel)?;

    // Base must exist and must not itself be a link.
    if is_link(base) {
        return Err(bad("destination directory is a link"));
    }

    let mut cur = base.to_path_buf();
    let components: Vec<_> = Path::new(rel)
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_os_string()),
            _ => None,
        })
        .collect();

    if components.is_empty() {
        return Err(bad("path has no name components"));
    }

    // Walk every directory component, refusing links in the existing chain.
    for dir in &components[..components.len() - 1] {
        cur.push(dir);
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if is_link(&cur) {
                    return Err(bad(format!(
                        "'{}' is a symlink or junction; refusing to follow it",
                        cur.display()
                    )));
                }
                if !meta.is_dir() {
                    return Err(bad(format!(
                        "'{}' exists and is not a directory",
                        cur.display()
                    )));
                }
            }
            Err(_) => {
                std::fs::create_dir(&cur).map_err(|e| {
                    CryptoError::Other(format!("create dir {}: {e}", cur.display()))
                })?;
            }
        }
    }

    cur.push(components.last().unwrap());
    Ok(cur)
}

/// Create a new file at `base/rel` without following links and without
/// overwriting an existing file.
///
/// `create_new` maps to `O_CREAT|O_EXCL` / `CREATE_NEW`, which fails if the
/// path already exists — including when it is a link to an existing file. That
/// makes the write fail closed rather than clobbering or redirecting.
pub fn create_file_nofollow(base: &Path, rel: &str) -> Result<(PathBuf, std::fs::File)> {
    let dest = prepare_destination(base, rel)?;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&dest)
    {
        Ok(f) => Ok((dest, f)),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(CryptoError::Other(format!(
                "a file already exists at '{}' — refusing to overwrite",
                dest.display()
            )))
        }
        Err(e) => Err(CryptoError::Other(format!(
            "create {}: {e}",
            dest.display()
        ))),
    }
}

/// Lexical containment: `child` must not resolve above `base`.
///
/// Both paths are normalized into component lists (resolving `.` and `..`
/// lexically) and compared. This is defense-in-depth on top of
/// [`validate_relative`], which already rejects `..` outright.
fn lexically_within(base: &Path, child: &Path) -> bool {
    let Some(base_norm) = normalize(base) else {
        return false;
    };
    let Some(child_norm) = normalize(child) else {
        return false;
    };
    child_norm.len() >= base_norm.len() && child_norm.starts_with(&base_norm)
}

/// Normalize a path into lowercase components, resolving `.` and `..` lexically.
///
/// Returns `None` if a `..` would escape above the root/prefix.
fn normalize(path: &Path) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for comp in path.components() {
        match comp {
            Component::Prefix(pr) => {
                // Windows drive/UNC prefix: reset and record it as the anchor.
                out.clear();
                out.push(format!(
                    "prefix:{}",
                    pr.as_os_str().to_string_lossy().to_lowercase()
                ));
            }
            Component::RootDir => { /* anchors the path; nothing to record */ }
            Component::CurDir => {}
            Component::ParentDir => {
                // Cannot pop above the prefix/root anchor.
                if out.last().map(|s| s.starts_with("prefix:")).unwrap_or(true) {
                    return None;
                }
                out.pop();
            }
            Component::Normal(n) => out.push(n.to_string_lossy().to_lowercase()),
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_names() {
        for ok in ["report.pdf", "my file.txt", "photo.jpg", "a.b.c"] {
            assert!(validate_basename(ok).is_ok(), "{ok} should be valid");
        }
    }

    #[test]
    fn rejects_traversal() {
        for bad_name in ["..", ".", "../outside.txt", "a/../../b"] {
            assert!(
                validate_basename(bad_name).is_err(),
                "{bad_name} should fail"
            );
        }
    }

    #[test]
    fn rejects_separators_and_absolute() {
        for bad_name in [
            "a/b",
            "a\\b",
            "/etc/passwd",
            "C:\\evil",
            "\\\\server\\share",
        ] {
            assert!(
                validate_basename(bad_name).is_err(),
                "{bad_name} should fail"
            );
        }
    }

    #[test]
    fn rejects_reserved_and_control() {
        assert!(validate_basename("CON").is_err());
        assert!(validate_basename("nul.txt").is_err());
        assert!(validate_basename("a\u{0}b").is_err());
        assert!(validate_basename("a\nb").is_err());
    }

    #[test]
    fn rejects_trailing_dot_or_space() {
        assert!(validate_basename("evil.").is_err());
        assert!(validate_basename("evil ").is_err());
    }

    #[test]
    fn rejects_empty_and_over_long() {
        assert!(validate_basename("").is_err());
        assert!(validate_basename(&"a".repeat(300)).is_err());
    }

    #[test]
    fn relative_paths_accept_nested() {
        assert!(validate_relative("a/b/c.txt").is_ok());
        assert!(validate_relative("a\\b\\c.txt").is_ok());
    }

    #[test]
    fn relative_paths_reject_parent_and_absolute() {
        assert!(validate_relative("../x").is_err());
        assert!(validate_relative("a/../../x").is_err());
        assert!(validate_relative("/abs").is_err());
        assert!(validate_relative("C:/x").is_err());
    }

    #[test]
    fn safe_join_blocks_escape() {
        let base = Path::new("/tmp/vault");
        assert!(safe_join(base, "ok.txt").is_ok());
        assert!(safe_join(base, "sub/ok.txt").is_ok());
        assert!(safe_join(base, "../escape.txt").is_err());
        assert!(safe_join(base, "sub/../../escape.txt").is_err());
    }

    #[test]
    fn file_id_accepts_generated_form() {
        assert!(validate_file_id("0123456789abcdef0123456789abcdef").is_ok());
        assert!(validate_file_id(&"a".repeat(32)).is_ok());
    }

    #[test]
    fn file_id_rejects_traversal_and_malformed() {
        // QV2-01 regression.
        for bad_id in [
            "../0123456789abcdef0123456789abcd",
            "..\\0123456789abcdef0123456789abc",
            "/etc/passwd",
            "C:\\evil",
            "",
            "abc",
            "0123456789abcdef0123456789ABCDEF",  // uppercase
            "0123456789abcdef0123456789abcdeg",  // non-hex
            "0123456789abcdef0123456789abcdef0", // too long
        ] {
            assert!(
                validate_file_id(bad_id).is_err(),
                "id '{bad_id}' must be rejected"
            );
        }
    }

    #[test]
    fn create_file_nofollow_writes_nested() {
        let base = std::env::temp_dir().join(format!("qvault-nf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        let (dest, mut f) = create_file_nofollow(&base, "sub/dir/file.txt").unwrap();
        std::io::Write::write_all(&mut f, b"hi").unwrap();
        drop(f);
        assert_eq!(std::fs::read(&dest).unwrap(), b"hi");
        assert!(dest.starts_with(&base));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn create_file_nofollow_refuses_overwrite() {
        let base = std::env::temp_dir().join(format!("qvault-nf2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("exists.txt"), b"original").unwrap();

        assert!(create_file_nofollow(&base, "exists.txt").is_err());
        // Original untouched.
        assert_eq!(std::fs::read(base.join("exists.txt")).unwrap(), b"original");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn create_file_nofollow_rejects_symlinked_dir() {
        // QV2-03 regression: a symlink inside the destination must not redirect.
        let base = std::env::temp_dir().join(format!("qvault-nf3-{}", std::process::id()));
        let outside = std::env::temp_dir().join(format!("qvault-nf3-out-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, base.join("sub")).unwrap();
            let res = create_file_nofollow(&base, "sub/report.txt");
            assert!(res.is_err(), "must refuse to write through a symlinked dir");
            assert!(
                !outside.join("report.txt").exists(),
                "nothing may be written outside the destination"
            );
        }

        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn detects_symlinks() {
        let dir = std::env::temp_dir().join(format!("qvault-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("real.txt");
        std::fs::write(&file, b"x").unwrap();
        assert!(!is_link(&file));

        #[cfg(unix)]
        {
            let link = dir.join("link.txt");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            assert!(is_link(&link));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
