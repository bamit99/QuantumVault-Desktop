//! Post-quantum hybrid key-encapsulation layer.
//!
//! Mirrors the Android `HybridPQCrypto` design (NIST/Google hybrid KEM):
//!
//! ```text
//! KEK ← HKDF-SHA256( X25519_secret ‖ ML-KEM-768_secret , salt , info )
//! ```
//!
//! * Classical leg: X25519 ECDH — broken by a CRQC, but fast and universal.
//! * PQ leg: ML-KEM-768 (FIPS 203) — believed quantum-hard.
//! * An attacker must break **both** to recover the FileKey → defeats
//!   "harvest now, decrypt later."

use hkdf::Hkdf;
use ml_kem::{
    MlKem768,
    kem::{self, Decapsulate, Encapsulate, Kem, Key, KeyExport, KeyInit},
};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::error::{CryptoError, Result};

/// HKDF domain-separation info (matches Android).
const HKDF_INFO: &[u8] = b"qvault-pq-hybrid-v1";

/// Length of the X25519 public key / shared secret (bytes).
pub const X25519_PUB_LEN: usize = 32;
/// Length of the ML-KEM-768 ciphertext (FIPS 203, k=3: 32 + 3·352).
pub const MLKEM768_ENCAP_LEN: usize = 1088;
/// Length of the ML-KEM-768 encapsulation (public) key.
#[allow(dead_code)] // documents the wire format; asserted in tests
pub const MLKEM768_PUB_LEN: usize = 1184;
/// Length of the ML-KEM-768 decapsulation (private) key as serialized.
///
/// `KeyExport` serializes the decapsulation key to its **seed** form (`d ‖ z`),
/// which is the compact 64-byte representation.
#[allow(dead_code)] // documents the wire format; asserted in tests
pub const MLKEM768_PRIV_LEN: usize = 64;
/// HKDF salt length (bytes).
pub const SALT_LEN: usize = 32;
/// Derived KEK length (bytes).
pub const KEK_LEN: usize = 32;

/// The public half of a vault's keypair (what the encryptor needs).
#[derive(Clone)]
pub struct VaultPublic {
    /// ML-KEM-768 encapsulation (public) key, encoded.
    pub mlkem: Vec<u8>,
    /// X25519 public key.
    pub x25519: [u8; X25519_PUB_LEN],
}

/// The private half of a vault's keypair (what the decryptor needs).
///
/// Secret bytes are held in `Zeroizing` containers and wiped on drop (QV2-05).
/// Note the usual caveat: allocator copies, crash dumps and compiler behaviour
/// mean this reduces exposure lifetime; it is not a guarantee of erasure.
pub struct VaultPrivate {
    /// ML-KEM-768 decapsulation (private) key, encoded.
    pub mlkem: Zeroizing<Vec<u8>>,
    /// X25519 static secret scalar.
    pub x25519: Zeroizing<[u8; X25519_PUB_LEN]>,
}

impl VaultPrivate {
    /// Derive the corresponding public half.
    pub fn public(&self) -> VaultPublic {
        let sk = StaticSecret::from(*self.x25519);
        let x_pub = PublicKey::from(&sk).to_bytes();
        // ML-KEM public key is derivable from the private key via the KEM trait.
        let dk = mlkem_dk_from_bytes(&self.mlkem).expect("stored ML-KEM private key must be valid");
        VaultPublic {
            mlkem: dk.encapsulation_key().to_bytes().to_vec(),
            x25519: x_pub,
        }
    }
}

/// Generate a fresh vault keypair (ML-KEM-768 + X25519).
pub fn generate_keypair() -> VaultPrivate {
    let (dk, _ek) = MlKem768::generate_keypair();
    let sk = StaticSecret::random();
    VaultPrivate {
        mlkem: Zeroizing::new(dk.to_bytes().to_vec()),
        x25519: Zeroizing::new(sk.to_bytes()),
    }
}

/// Material produced during encapsulation, stored alongside each encrypted file.
pub struct Encapsulation {
    /// X25519 ephemeral public key.
    pub eph_pub: [u8; X25519_PUB_LEN],
    /// ML-KEM-768 ciphertext.
    pub ct: Vec<u8>,
    /// HKDF salt.
    pub salt: [u8; SALT_LEN],
    /// The derived key-encryption key (32 B), zeroized on drop.
    pub kek: Zeroizing<[u8; KEK_LEN]>,
}

/// Encapsulate a fresh key-encryption key to the vault's public keys.
///
/// Generates a new X25519 ephemeral key and a fresh ML-KEM encapsulation,
/// combines both shared secrets via HKDF, and returns the KEK plus the
/// material the decryptor needs.
pub fn encapsulate(vault_pub: &VaultPublic) -> Result<Encapsulation> {
    // Classical leg: ephemeral X25519 ECDH.
    let eph = EphemeralSecret::random();
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let their_pub = PublicKey::from(vault_pub.x25519);
    let shared_x = eph.diffie_hellman(&their_pub);
    require_contributory(&shared_x)?;

    // PQ leg: ML-KEM-768 encapsulate.
    let ek = mlkem_ek_from_bytes(&vault_pub.mlkem)?;
    let (ct, shared_pq) = ek.encapsulate();

    // Combine both shared secrets (IKM is secret, so zeroize it).
    let mut ikm = Zeroizing::new([0u8; 2 * X25519_PUB_LEN]);
    ikm[..X25519_PUB_LEN].copy_from_slice(shared_x.as_bytes());
    ikm[X25519_PUB_LEN..].copy_from_slice(shared_pq.as_slice());

    let salt: [u8; SALT_LEN] = super::random()?;
    let kek = hkdf_sha256(&ikm[..], &salt)?;

    Ok(Encapsulation {
        eph_pub,
        ct: ct.as_slice().to_vec(),
        salt,
        kek: Zeroizing::new(kek),
    })
}

/// Decapsulate the key-encryption key using the vault's private keys.
pub fn decapsulate(
    vault_priv: &VaultPrivate,
    eph_pub: &[u8; X25519_PUB_LEN],
    ct: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<[u8; KEK_LEN]> {
    // Classical leg.
    let sk = StaticSecret::from(*vault_priv.x25519);
    let eph_pub = PublicKey::from(*eph_pub);
    let shared_x = sk.diffie_hellman(&eph_pub);
    require_contributory(&shared_x)?;

    // PQ leg.
    let dk = mlkem_dk_from_bytes(&vault_priv.mlkem)?;
    let ct = kem::Ciphertext::<MlKem768>::try_from(ct)
        .map_err(|e| CryptoError::InvalidFormat(format!("ML-KEM ciphertext: {e}")))?;
    let shared_pq = dk.decapsulate(&ct);

    let mut ikm = Zeroizing::new([0u8; 2 * X25519_PUB_LEN]);
    ikm[..X25519_PUB_LEN].copy_from_slice(shared_x.as_bytes());
    ikm[X25519_PUB_LEN..].copy_from_slice(shared_pq.as_slice());

    hkdf_sha256(&ikm[..], salt)
}

/// HKDF-SHA256 key-derivation (extract + expand to 32 bytes).
fn hkdf_sha256(secret: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; KEK_LEN]> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut okm = [0u8; KEK_LEN];
    hkdf.expand(HKDF_INFO, &mut okm)?;
    Ok(okm)
}

/// Reject a non-contributory (all-zero) X25519 shared secret.
fn require_contributory(shared: &x25519_dalek::SharedSecret) -> Result<()> {
    if !shared.was_contributory() {
        return Err(CryptoError::AllZeroSharedSecret);
    }
    Ok(())
}

fn mlkem_ek_from_bytes(bytes: &[u8]) -> Result<kem::EncapsulationKey<MlKem768>> {
    let key = Key::<kem::EncapsulationKey<MlKem768>>::try_from(bytes)
        .map_err(|e| CryptoError::InvalidFormat(format!("ML-KEM public key length: {e}")))?;
    kem::EncapsulationKey::<MlKem768>::new(&key)
        .map_err(|_| CryptoError::InvalidFormat("ML-KEM public key invalid".into()))
}

fn mlkem_dk_from_bytes(bytes: &[u8]) -> Result<kem::DecapsulationKey<MlKem768>> {
    let key = Key::<kem::DecapsulationKey<MlKem768>>::try_from(bytes)
        .map_err(|e| CryptoError::InvalidFormat(format!("ML-KEM private key length: {e}")))?;
    Ok(kem::DecapsulationKey::<MlKem768>::new(&key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_shared_kek() {
        let privk = generate_keypair();
        let pubk = privk.public();

        let encap = encapsulate(&pubk).unwrap();
        let recovered = decapsulate(&privk, &encap.eph_pub, &encap.ct, &encap.salt).unwrap();
        assert_eq!(&encap.kek[..], &recovered[..]);
    }

    #[test]
    fn public_key_derivation_matches() {
        let privk = generate_keypair();
        let pubk = privk.public();
        // Public derivation must be stable.
        let pubk2 = privk.public();
        assert_eq!(pubk.mlkem, pubk2.mlkem);
        assert_eq!(pubk.x25519, pubk2.x25519);
    }

    #[test]
    fn each_encapsulation_is_unique() {
        let pubk = generate_keypair().public();
        let a = encapsulate(&pubk).unwrap();
        let b = encapsulate(&pubk).unwrap();
        assert_ne!(a.ct, b.ct);
        assert_ne!(a.eph_pub, b.eph_pub);
        assert_ne!(&a.kek[..], &b.kek[..]);
    }

    #[test]
    fn wrong_private_key_fails() {
        let pubk = generate_keypair().public();
        let other = generate_keypair();
        let encap = encapsulate(&pubk).unwrap();
        // Decapsulation with the wrong key yields a different KEK (KEM implicit
        // rejection), not the same one.
        let wrong = decapsulate(&other, &encap.eph_pub, &encap.ct, &encap.salt).unwrap();
        assert_ne!(&encap.kek[..], &wrong[..]);
    }

    #[test]
    fn tampered_ciphertext_gives_different_kek() {
        let privk = generate_keypair();
        let pubk = privk.public();
        let mut encap = encapsulate(&pubk).unwrap();
        encap.ct[0] ^= 0x01;
        let kek = decapsulate(&privk, &encap.eph_pub, &encap.ct, &encap.salt).unwrap();
        assert_ne!(&encap.kek[..], &kek[..]);
    }

    #[test]
    fn key_lengths_match_spec() {
        let privk = generate_keypair();
        let pubk = privk.public();
        assert_eq!(privk.mlkem.len(), MLKEM768_PRIV_LEN);
        assert_eq!(pubk.mlkem.len(), MLKEM768_PUB_LEN);
        assert_eq!(pubk.x25519.len(), X25519_PUB_LEN);
    }
}
