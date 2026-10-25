//! Windows DPAPI sealing for the vault's device private keys.
//!
//! `CryptProtectData`/`CryptUnprotectData` with **CurrentUser** scope and no UI.
//! This is the desktop analog of the Android Keystore wrap key: the private
//! halves of the ML-KEM-768 + X25519 keypair are sealed so only the same Windows
//! user on the same machine can unseal them. The passphrase leg remains the
//! portable recovery path.

use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
};
use windows::core::PCWSTR;

use super::error::{CryptoError, Result};

/// Seal `data` with DPAPI (CurrentUser, no UI). Returns the sealed bytes.
pub fn seal(data: &[u8]) -> Result<Vec<u8>> {
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    // SAFETY: `in_blob` points to valid `data`; `out_blob` is zero-initialized and
    // the returned buffer is copied out and freed with `LocalFree` before return.
    unsafe {
        CryptProtectData(
            &in_blob,
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
        .map_err(|e| CryptoError::Other(format!("DPAPI protect failed: {e}")))?;
    }

    let result = copy_out(&out_blob);
    // SAFETY: `out_blob.pbData` was allocated by `CryptProtectData` and must be
    // freed with `LocalFree`.
    unsafe {
        LocalFree(Some(HLOCAL(out_blob.pbData as *mut core::ffi::c_void)));
    }
    Ok(result)
}

/// Unseal data previously produced by [`seal`].
pub fn unseal(data: &[u8]) -> Result<Vec<u8>> {
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    // SAFETY: as in [`seal`].
    unsafe {
        CryptUnprotectData(
            &in_blob,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
        .map_err(|e| CryptoError::Other(format!("DPAPI unprotect failed: {e}")))?;
    }

    let result = copy_out(&out_blob);
    // SAFETY: `out_blob.pbData` was allocated by `CryptUnprotectData`.
    unsafe {
        LocalFree(Some(HLOCAL(out_blob.pbData as *mut core::ffi::c_void)));
    }
    Ok(result)
}

/// Copy the bytes out of a `CRYPT_INTEGER_BLOB` before it is freed.
fn copy_out(blob: &CRYPT_INTEGER_BLOB) -> Vec<u8> {
    if blob.pbData.is_null() || blob.cbData == 0 {
        return Vec::new();
    }
    // SAFETY: `pbData` is valid for `cbData` bytes per the DPAPI contract.
    unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize) }.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_round_trip() {
        let secret = b"device private key material";
        let sealed = seal(secret).unwrap();
        assert_ne!(sealed, secret);
        let back = unseal(&sealed).unwrap();
        assert_eq!(back, secret);
    }

    #[test]
    fn seal_is_randomized_but_both_unseal() {
        // DPAPI uses a fresh random IV/session key per call, so outputs differ,
        // but both unseal to the original plaintext.
        let a = seal(b"hello").unwrap();
        let b = seal(b"hello").unwrap();
        assert_ne!(a, b);
        assert_eq!(unseal(&a).unwrap(), b"hello");
        assert_eq!(unseal(&b).unwrap(), b"hello");
    }

    #[test]
    fn empty_input_round_trip() {
        let sealed = seal(b"").unwrap();
        assert_eq!(unseal(&sealed).unwrap(), b"");
    }
}
