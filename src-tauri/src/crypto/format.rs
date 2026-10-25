//! QVAULT file-blob format: self-describing, versioned, dual-wrapped, AAD-bound.
//!
//! Wire layout (v3):
//!
//! ```text
//! MAGIC "QVAULT" (6 B)
//! version byte (0x03)
//! X25519 ephemeral pub        (32 B)
//! ML-KEM-768 encapsulation    (1088 B)
//! HKDF salt (device leg)      (32 B)
//! wrapped FileKey (device)    (12+32+16 = 60 B)   iv‖ct‖tag
//! wrapped FileKey (passphrase)(60 B)               iv‖ct‖tag
//! payload                      iv‖ct‖tag
//! ```
//!
//! **Context binding (QV-04).** Every AEAD operation carries associated data
//! built from a domain-separation label, the format version, the vault ID and
//! the file ID. A blob therefore cannot be replayed into a different vault, a
//! different file slot, or a different purpose: decryption fails on AAD
//! mismatch. The context is *not* stored in the blob — it comes from the
//! authenticated manifest / vault metadata, which is exactly what makes
//! substitution detectable.

use super::aead::{self, TAG_LEN};
use super::error::{CryptoError, Result};
use super::kem::{self, VaultPrivate, VaultPublic};

/// Magic prefix identifying a QVAULT blob.
pub const MAGIC: &[u8; 6] = b"QVAULT";
/// Current format version (v3 = AAD-bound).
pub const VERSION: u8 = 3;

/// AAD domain-separation label.
const AAD_LABEL: &[u8] = b"QVAULT-AAD-v1";
/// Reserved "file ID" for the vault manifest.
pub const MANIFEST_CONTEXT: &str = "manifest";

/// Fresh per-file AES key length (bytes).
pub const FILE_KEY_LEN: usize = 32;
/// Passphrase KEK length (bytes).
pub const KEK_LEN: usize = 32;
/// Serialized wrapped-key length: iv (12) + key (32) + tag (16).
pub const WRAPPED_KEY_LEN: usize = aead::IV_LEN + FILE_KEY_LEN + TAG_LEN;

/// Header length up to (but not including) the payload.
const HEADER_LEN: usize = MAGIC.len()
    + 1 // version
    + kem::X25519_PUB_LEN
    + kem::MLKEM768_ENCAP_LEN
    + kem::SALT_LEN
    + WRAPPED_KEY_LEN
    + WRAPPED_KEY_LEN;

/// The authenticated context an operation is bound to.
#[derive(Clone, Copy)]
pub struct BlobContext<'a> {
    /// Random, per-vault identifier (hex). Ties blobs to one vault.
    pub vault_id: &'a str,
    /// The file's opaque ID (or [`MANIFEST_CONTEXT`] for the manifest).
    pub file_id: &'a str,
}

/// AAD purpose tags.
const PURPOSE_KEYWRAP: &[u8] = b"keywrap";
const PURPOSE_PAYLOAD: &[u8] = b"payload";
const PURPOSE_VERIFIER: &[u8] = b"verifier";
const PURPOSE_VAULT_KEY: &[u8] = b"vault-key";

/// Append a length-prefixed field (unambiguous encoding).
fn push_field(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
    buf.extend_from_slice(field);
}

/// Build the AAD for a given purpose and context.
pub fn build_aad(purpose: &[u8], ctx: &BlobContext<'_>) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64 + ctx.vault_id.len() + ctx.file_id.len());
    push_field(&mut aad, AAD_LABEL);
    push_field(&mut aad, purpose);
    aad.push(VERSION);
    push_field(&mut aad, ctx.vault_id.as_bytes());
    push_field(&mut aad, ctx.file_id.as_bytes());
    aad
}

/// Build AAD for the passphrase verifier (bound to the vault, not a file).
pub fn verifier_aad(vault_id: &str) -> Vec<u8> {
    build_aad(
        PURPOSE_VERIFIER,
        &BlobContext {
            vault_id,
            file_id: "verifier",
        },
    )
}

/// Build AAD for the DPAPI-sealed device key blob.
pub fn vault_key_aad(vault_id: &str) -> Vec<u8> {
    build_aad(
        PURPOSE_VAULT_KEY,
        &BlobContext {
            vault_id,
            file_id: "device-key",
        },
    )
}

/// Encrypt `plaintext` into a QVAULT blob.
///
/// `vault_pub` provides the device leg (hybrid KEM); `pass_kek` is the
/// session-derived passphrase key; `ctx` binds the blob to its vault and file.
pub fn encrypt_file(
    plaintext: &[u8],
    vault_pub: &VaultPublic,
    pass_kek: &[u8; KEK_LEN],
    ctx: &BlobContext<'_>,
) -> Result<Vec<u8>> {
    let keywrap_aad = build_aad(PURPOSE_KEYWRAP, ctx);
    let payload_aad = build_aad(PURPOSE_PAYLOAD, ctx);

    // 1. Fresh per-file key.
    let file_key = zeroize::Zeroizing::new(super::random::<FILE_KEY_LEN>()?);

    // 2. AES-GCM the payload (AAD-bound).
    let payload = aead::encrypt(&file_key, plaintext, &payload_aad)?;

    // 3. Device leg: hybrid KEM → KEK → wrap FileKey.
    let encap = kem::encapsulate(vault_pub)?;
    let device_kek = &encap.kek;
    let wrapped_device = aead::encrypt(device_kek, &*file_key, &keywrap_aad)?;

    // 4. Passphrase leg: wrap FileKey with the session passphrase KEK.
    let wrapped_pass = aead::encrypt(pass_kek, &*file_key, &keywrap_aad)?;

    // 5. Assemble.
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&encap.eph_pub);
    out.extend_from_slice(&encap.ct);
    out.extend_from_slice(&encap.salt);
    out.extend_from_slice(&wrapped_device);
    out.extend_from_slice(&wrapped_pass);
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Decrypt a QVAULT blob bound to `ctx`.
///
/// Tries the device leg first (fast, no Argon2); falls back to the passphrase
/// leg. At least one of `device_priv` / `pass_kek` must be supplied.
pub fn decrypt_file(
    blob: &[u8],
    device_priv: Option<&VaultPrivate>,
    pass_kek: Option<&[u8; KEK_LEN]>,
    ctx: &BlobContext<'_>,
) -> Result<Vec<u8>> {
    let fields = parse(blob)?;
    let keywrap_aad = build_aad(PURPOSE_KEYWRAP, ctx);
    let payload_aad = build_aad(PURPOSE_PAYLOAD, ctx);

    // Leg 1: device keys.
    if let Some(privk) = device_priv
        && let Ok(kek) =
            kem::decapsulate(privk, &fields.eph_pub, &fields.encapsulation, &fields.salt)
        && let Ok(fk) = aead::decrypt(&kek, &fields.wrapped_device, &keywrap_aad)
    {
        let file_key: [u8; FILE_KEY_LEN] = fk
            .try_into()
            .map_err(|_| CryptoError::InvalidFormat("unwrapped FileKey length".into()))?;
        let file_key = zeroize::Zeroizing::new(file_key);
        if let Ok(pt) = aead::decrypt(&file_key, &fields.payload, &payload_aad) {
            return Ok(pt);
        }
    }

    // Leg 2: passphrase (cross-device recovery path).
    if let Some(pass_kek) = pass_kek
        && let Ok(fk) = aead::decrypt(pass_kek, &fields.wrapped_pass, &keywrap_aad)
    {
        let file_key: [u8; FILE_KEY_LEN] = fk
            .try_into()
            .map_err(|_| CryptoError::InvalidFormat("unwrapped FileKey length".into()))?;
        let file_key = zeroize::Zeroizing::new(file_key);
        return aead::decrypt(&file_key, &fields.payload, &payload_aad);
    }

    Err(CryptoError::AuthenticationFailed)
}

/// Parsed header fields (payload excluded).
struct Parsed {
    eph_pub: [u8; kem::X25519_PUB_LEN],
    encapsulation: Vec<u8>,
    salt: [u8; kem::SALT_LEN],
    wrapped_device: Vec<u8>,
    wrapped_pass: Vec<u8>,
    payload: Vec<u8>,
}

/// True if `blob` starts with the QVAULT magic.
pub fn has_magic(blob: &[u8]) -> bool {
    blob.len() >= MAGIC.len() && &blob[..MAGIC.len()] == MAGIC
}

/// Parse a QVAULT blob, validating structure and version.
fn parse(blob: &[u8]) -> Result<Parsed> {
    if !has_magic(blob) {
        return Err(CryptoError::InvalidFormat("not a QVAULT blob".into()));
    }
    // The magic alone (6 bytes) must not index the version byte: a truncated
    // blob is untrusted input. (Found by the robustness/fuzz tests.)
    if blob.len() < MAGIC.len() + 1 {
        return Err(CryptoError::InvalidFormat("blob too short".into()));
    }
    let mut off = MAGIC.len();
    let version = blob[off];
    off += 1;
    if version != VERSION {
        return Err(CryptoError::UnsupportedVersion(version));
    }

    if blob.len() < HEADER_LEN {
        return Err(CryptoError::InvalidFormat("blob too short".into()));
    }

    let eph_pub: [u8; kem::X25519_PUB_LEN] = blob[off..off + kem::X25519_PUB_LEN]
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat("eph pub".into()))?;
    off += kem::X25519_PUB_LEN;

    let encapsulation = blob[off..off + kem::MLKEM768_ENCAP_LEN].to_vec();
    off += kem::MLKEM768_ENCAP_LEN;

    let salt: [u8; kem::SALT_LEN] = blob[off..off + kem::SALT_LEN]
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat("salt".into()))?;
    off += kem::SALT_LEN;

    let wrapped_device = blob[off..off + WRAPPED_KEY_LEN].to_vec();
    off += WRAPPED_KEY_LEN;

    let wrapped_pass = blob[off..off + WRAPPED_KEY_LEN].to_vec();
    off += WRAPPED_KEY_LEN;

    let payload = blob[off..].to_vec();

    Ok(Parsed {
        eph_pub,
        encapsulation,
        salt,
        wrapped_device,
        wrapped_pass,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pass_kek(pass: &[u8]) -> [u8; KEK_LEN] {
        super::super::kdf::derive(pass, &[7u8; 32]).unwrap()
    }

    fn ctx<'a>(vault: &'a str, file: &'a str) -> BlobContext<'a> {
        BlobContext {
            vault_id: vault,
            file_id: file,
        }
    }

    #[test]
    fn full_round_trip_device_leg() {
        let privk = kem::generate_keypair();
        let pubk = privk.public();
        let pt = b"sensitive document contents";
        let pass_kek = test_pass_kek(b"correct horse battery staple");
        let c = ctx("vault-abc", "file-1");

        let blob = encrypt_file(pt, &pubk, &pass_kek, &c).unwrap();
        assert!(has_magic(&blob));
        assert_eq!(decrypt_file(&blob, Some(&privk), None, &c).unwrap(), pt);
    }

    #[test]
    fn full_round_trip_passphrase_leg_only() {
        let privk = kem::generate_keypair();
        let pubk = privk.public();
        let pt = b"cross-device recovery test";
        let pass_kek = test_pass_kek(b"my passphrase here");
        let c = ctx("vault-abc", "file-2");

        let blob = encrypt_file(pt, &pubk, &pass_kek, &c).unwrap();
        assert_eq!(decrypt_file(&blob, None, Some(&pass_kek), &c).unwrap(), pt);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let pubk = kem::generate_keypair().public();
        let pass_kek = test_pass_kek(b"correct passphrase");
        let c = ctx("v", "f");
        let blob = encrypt_file(b"secret", &pubk, &pass_kek, &c).unwrap();
        let wrong = test_pass_kek(b"wrong passphrase");
        assert!(matches!(
            decrypt_file(&blob, None, Some(&wrong), &c),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn blob_cannot_be_swapped_to_another_file_id() {
        // QV-04 regression: same vault, different file ID must fail.
        let privk = kem::generate_keypair();
        let pubk = privk.public();
        let pass_kek = test_pass_kek(b"pass");
        let blob = encrypt_file(b"secret", &pubk, &pass_kek, &ctx("v", "file-1")).unwrap();

        assert!(decrypt_file(&blob, Some(&privk), Some(&pass_kek), &ctx("v", "file-2")).is_err());
        // Original context still works.
        assert!(decrypt_file(&blob, Some(&privk), Some(&pass_kek), &ctx("v", "file-1")).is_ok());
    }

    #[test]
    fn blob_cannot_be_swapped_to_another_vault() {
        // QV-04 regression: different vault ID must fail.
        let privk = kem::generate_keypair();
        let pubk = privk.public();
        let pass_kek = test_pass_kek(b"pass");
        let blob = encrypt_file(b"secret", &pubk, &pass_kek, &ctx("vault-A", "file-1")).unwrap();

        assert!(
            decrypt_file(
                &blob,
                Some(&privk),
                Some(&pass_kek),
                &ctx("vault-B", "file-1")
            )
            .is_err()
        );
    }

    #[test]
    fn wrong_device_key_but_correct_passphrase_succeeds() {
        let pubk = kem::generate_keypair().public();
        let pass_kek = test_pass_kek(b"the passphrase");
        let c = ctx("v", "f");
        let blob = encrypt_file(b"secret", &pubk, &pass_kek, &c).unwrap();
        let wrong_device = kem::generate_keypair();
        assert_eq!(
            decrypt_file(&blob, Some(&wrong_device), Some(&pass_kek), &c).unwrap(),
            b"secret"
        );
    }

    #[test]
    fn tampered_payload_fails() {
        let privk = kem::generate_keypair();
        let pubk = privk.public();
        let pass_kek = test_pass_kek(b"pass");
        let c = ctx("v", "f");
        let mut blob = encrypt_file(b"secret", &pubk, &pass_kek, &c).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(decrypt_file(&blob, Some(&privk), None, &c).is_err());
    }

    #[test]
    fn magic_only_blob_does_not_panic() {
        // Regression: a blob that is exactly the magic used to index past the
        // end while reading the version byte (found by the robustness tests).
        let pass_kek = test_pass_kek(b"pass");
        let c = ctx("v", "f");
        assert!(matches!(
            decrypt_file(MAGIC, None, Some(&pass_kek), &c),
            Err(CryptoError::InvalidFormat(_))
        ));
        // Every prefix short of the full header must be rejected cleanly.
        let pubk = kem::generate_keypair().public();
        let full = encrypt_file(b"x", &pubk, &pass_kek, &c).unwrap();
        for len in 0..HEADER_LEN.min(64) {
            let _ = decrypt_file(&full[..len], None, Some(&pass_kek), &c);
        }
    }

    #[test]
    fn rejects_non_qvault_blob() {
        let pass_kek = test_pass_kek(b"pass");
        assert!(matches!(
            decrypt_file(b"not a vault", None, Some(&pass_kek), &ctx("v", "f")),
            Err(CryptoError::InvalidFormat(_))
        ));
    }

    #[test]
    fn no_credentials_rejected() {
        let pubk = kem::generate_keypair().public();
        let pass_kek = test_pass_kek(b"pass");
        let c = ctx("v", "f");
        let blob = encrypt_file(b"x", &pubk, &pass_kek, &c).unwrap();
        assert!(matches!(
            decrypt_file(&blob, None, None, &c),
            Err(CryptoError::AuthenticationFailed)
        ));
    }
}
