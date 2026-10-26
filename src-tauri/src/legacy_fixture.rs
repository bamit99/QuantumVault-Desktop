//! Test support: builds a byte-accurate **v1 vault**.
//!
//! v0.1.0/v0.1.1 wrote a different vault format:
//!
//! * `vault.meta` had no `vault_id` field and `version: 1`;
//! * the passphrase verifier was a plain
//!   `AES-GCM(Argon2id(passphrase), "qvault-passphrase-verifier-v1")` with no
//!   AAD and no metadata digest;
//! * the device key was sealed with DPAPI as the bare 96-byte private key,
//!   without the vault-ID AAD prefix;
//! * file blobs used the legacy v2 container (no AAD at all);
//! * the file index was one shared `manifest.qvault` blob.
//!
//! This module reproduces that layout exactly, so the migration path can be
//! tested against a real legacy vault rather than a mock.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::crypto::{aead, dpapi, format, kdf, kem};
use crate::manifest::{FileEntry, Manifest, hex};

/// Build a v1-format vault in `path`.
///
/// `files` are `(file id, plaintext name, contents)`.
pub fn build(path: &Path, passphrase: &[u8], files: &[(&str, &str, &[u8])]) {
    let _ = std::fs::remove_dir_all(path);
    std::fs::create_dir_all(path).unwrap();

    let private = kem::generate_keypair();
    let public = private.public();

    // Legacy device-key seal: the bare private key, no AAD prefix.
    let mut raw = private.x25519.to_vec();
    raw.extend_from_slice(&private.mlkem);
    assert_eq!(raw.len(), 96);
    let sealed = dpapi::seal(&raw).unwrap();

    let salt = kdf::new_salt().unwrap();
    let pass_kek = kdf::derive(passphrase, &salt).unwrap();

    // Legacy verifier: fixed label, no digest, no AAD.
    let verifier = aead::encrypt(&pass_kek, crate::vault::VERIFIER_PLAINTEXT_V1, &[]).unwrap();

    // The legacy metadata file: no `vault_id` field at all.
    let meta = serde_json::json!({
        "format": "qvault-desktop",
        "version": 1,
        "mlkem_pub_b64": STANDARD.encode(&public.mlkem),
        "x25519_pub_b64": STANDARD.encode(public.x25519),
        "sealed_priv_b64": STANDARD.encode(&sealed),
        "verify_salt_b64": STANDARD.encode(salt),
        "verifier_b64": STANDARD.encode(&verifier),
    });
    std::fs::write(
        path.join(crate::vault::META_FILENAME),
        serde_json::to_string_pretty(&meta).unwrap(),
    )
    .unwrap();

    // The file blobs and the shared index.
    let mut entries = Vec::new();
    for (id, name, data) in files {
        let blob = format::encrypt_file_legacy(data, &public, &pass_kek).unwrap();
        std::fs::write(path.join(format!("{id}.qvault")), &blob).unwrap();
        entries.push(FileEntry {
            id: (*id).to_string(),
            name: (*name).to_string(),
            size: data.len() as u64,
            mime: "application/octet-stream".to_string(),
            created: 1_700_000_000,
            modified: 1_700_000_000,
        });
    }

    let index = serde_json::to_vec(&Manifest { files: entries }).unwrap();
    let index_blob = format::encrypt_file_legacy(&index, &public, &pass_kek).unwrap();
    std::fs::write(path.join(crate::vault::MANIFEST_FILENAME), &index_blob).unwrap();
}

/// A random, well-formed file ID (32 lowercase hex characters).
pub fn random_id() -> String {
    hex(&crate::crypto::random::<16>().unwrap())
}
