//! QVAULT file-blob format: self-describing, versioned, dual-wrapped.
//!
//! Wire layout (v2, dual-wrap — device leg **and** passphrase leg):
//!
//! ```text
//! MAGIC "QVAULT" (6 B)
//! version byte (0x02)
//! X25519 ephemeral pub        (32 B)
//! ML-KEM-768 encapsulation    (1088 B)
//! HKDF salt (device leg)      (32 B)
//! wrapped FileKey (device)    (12+32+16 = 60 B)   iv‖ct‖tag
//! wrapped FileKey (passphrase)(60 B)               iv‖ct‖tag
//! payload                      iv‖ct‖tag
//! ```
//!
//! The `FileKey` is a fresh 256-bit key per file, wrapped by **both** the device
//! KEK (hybrid X25519 + ML-KEM, fresh per file) and the passphrase KEK (Argon2id,
//! derived **once at unlock**, not per file). Deriving Argon2 once per unlock —
//! rather than once per file — keeps encryption fast while preserving the
//! brute-force resistance of the passphrase.

use super::aead::{self, TAG_LEN};
use super::error::{CryptoError, Result};
use super::kem::{self, VaultPrivate, VaultPublic};

/// Magic prefix identifying a QVAULT blob.
pub const MAGIC: &[u8; 6] = b"QVAULT";
/// Dual-wrap format version.
pub const VERSION: u8 = 2;

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

/// Encrypt `plaintext` into a QVAULT blob.
///
/// `vault_pub` provides the device leg (hybrid KEM); `pass_kek` is the
/// session-derived passphrase key (Argon2id) for the recovery leg.
pub fn encrypt_file(
    plaintext: &[u8],
    vault_pub: &VaultPublic,
    pass_kek: &[u8; KEK_LEN],
) -> Result<Vec<u8>> {
    // 1. Fresh per-file key.
    let file_key: [u8; FILE_KEY_LEN] = super::random()?;

    // 2. AES-GCM the payload.
    let payload = aead::encrypt(&file_key, plaintext)?;

    // 3. Device leg: hybrid KEM → KEK → wrap FileKey.
    let encap = kem::encapsulate(vault_pub)?;
    let wrapped_device = aead::encrypt(&encap.kek, &file_key)?;

    // 4. Passphrase leg: wrap FileKey with the session passphrase KEK.
    let wrapped_pass = aead::encrypt(pass_kek, &file_key)?;

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

/// Decrypt a QVAULT blob.
///
/// Tries the device leg first (fast, no Argon2); falls back to the passphrase
/// leg. At least one of `device_priv` / `pass_kek` must be supplied.
pub fn decrypt_file(
    blob: &[u8],
    device_priv: Option<&VaultPrivate>,
    pass_kek: Option<&[u8; KEK_LEN]>,
) -> Result<Vec<u8>> {
    let fields = parse(blob)?;

    // Leg 1: device keys.
    if let Some(privk) = device_priv {
        if let Ok(kek) = kem::decapsulate(privk, &fields.eph_pub, &fields.encapsulation, &fields.salt)
        {
            if let Ok(fk) = aead::decrypt(&kek, &fields.wrapped_device) {
                let file_key: [u8; FILE_KEY_LEN] = fk
                    .try_into()
                    .map_err(|_| CryptoError::InvalidFormat("unwrapped FileKey has wrong length".into()))?;
                if let Ok(pt) = aead::decrypt(&file_key, &fields.payload) {
                    return Ok(pt);
                }
            }
        }
    }

    // Leg 2: passphrase (cross-device recovery path).
    if let Some(pass_kek) = pass_kek {
        if let Ok(fk) = aead::decrypt(pass_kek, &fields.wrapped_pass) {
            let file_key: [u8; FILE_KEY_LEN] = fk
                .try_into()
                .map_err(|_| CryptoError::InvalidFormat("unwrapped FileKey has wrong length".into()))?;
            return aead::decrypt(&file_key, &fields.payload);
        }
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

    #[test]
    fn full_round_trip_device_leg() {
        let privk = kem::generate_keypair();
        let pubk = privk.public();
        let pt = b"sensitive document contents";
        let pass_kek = test_pass_kek(b"correct horse battery staple");

        let blob = encrypt_file(pt, &pubk, &pass_kek).unwrap();
        assert!(has_magic(&blob));

        let back = decrypt_file(&blob, Some(&privk), None).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn full_round_trip_passphrase_leg_only() {
        let privk = kem::generate_keypair();
        let pubk = privk.public();
        let pt = b"cross-device recovery test";
        let pass_kek = test_pass_kek(b"my passphrase here");

        let blob = encrypt_file(pt, &pubk, &pass_kek).unwrap();

        // Simulate a fresh device: no vault private key, only the passphrase KEK.
        let back = decrypt_file(&blob, None, Some(&pass_kek)).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let pubk = kem::generate_keypair().public();
        let pass_kek = test_pass_kek(b"correct passphrase");
        let blob = encrypt_file(b"secret", &pubk, &pass_kek).unwrap();

        let wrong = test_pass_kek(b"wrong passphrase");
        assert!(matches!(
            decrypt_file(&blob, None, Some(&wrong)),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn wrong_device_key_but_correct_passphrase_succeeds() {
        let pubk = kem::generate_keypair().public();
        let pass_kek = test_pass_kek(b"the passphrase");
        let blob = encrypt_file(b"secret", &pubk, &pass_kek).unwrap();
        let wrong_device = kem::generate_keypair();
        let back = decrypt_file(&blob, Some(&wrong_device), Some(&pass_kek)).unwrap();
        assert_eq!(back, b"secret");
    }

    #[test]
    fn tampered_payload_fails() {
        let privk = kem::generate_keypair();
        let pubk = privk.public();
        let pass_kek = test_pass_kek(b"pass");
        let mut blob = encrypt_file(b"secret", &pubk, &pass_kek).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(decrypt_file(&blob, Some(&privk), None).is_err());
    }

    #[test]
    fn rejects_non_qvault_blob() {
        let pass_kek = test_pass_kek(b"pass");
        assert!(matches!(
            decrypt_file(b"not a vault", None, Some(&pass_kek)),
            Err(CryptoError::InvalidFormat(_))
        ));
    }

    #[test]
    fn no_credentials_rejected() {
        let pubk = kem::generate_keypair().public();
        let pass_kek = test_pass_kek(b"pass");
        let blob = encrypt_file(b"x", &pubk, &pass_kek).unwrap();
        assert!(matches!(
            decrypt_file(&blob, None, None),
            Err(CryptoError::AuthenticationFailed)
        ));
    }
}
