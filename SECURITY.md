# Security Design & Threat Model

This document states **precisely** what Quantum Vault protects against, and what
it does not. Please read the "Key wrapping" section carefully — it documents a
property that is easy to misread.

## Cryptographic primitives

| Purpose | Algorithm | Notes |
|---|---|---|
| Post-quantum KEM | ML-KEM-768 (FIPS 203) | Lattice-based; quantum-resistant |
| Classical KEM | X25519 (RFC 7748) | Contributes classical security |
| Combiner | HKDF-SHA256 | `KEK = HKDF(X25519 ‖ MLKEM, salt, info)` |
| Passphrase KDF | Argon2id v19, t=3, m=256 MiB, p=1 | Memory-hard |
| Bulk encryption | AES-256-GCM | AEAD, AAD-bound |
| Device key sealing | Windows DPAPI (CurrentUser) | OS-bound key protection |

## Key wrapping: two independent unlock paths

Each file gets a fresh random 256-bit **FileKey**. That FileKey is wrapped
**twice**:

1. **Device leg** — `KEK_device = HKDF(X25519(eph, static) ‖ ML-KEM-768)` →
   wraps the FileKey.
2. **Passphrase leg** — `KEK_pass = Argon2id(passphrase, salt)` → wraps the
   FileKey.

Decryption tries the device leg first, then falls back to the passphrase leg.

### ⚠️ What this means (read this)

These are **two alternative**, not **two mandatory**, factors.

> **An attacker holding the vault does NOT need to break ML-KEM or X25519.**
> They only need to guess the passphrase, and then verify the guess offline
> against the passphrase-wrapped FileKey.

The hybrid KEM protects the *device* leg. It does not add work to the passphrase
leg. **The practical security of a stolen vault equals the strength of your
passphrase, hardened by Argon2id.**

This is a deliberate design choice: it enables recovery of the vault on a new
machine (the device leg is unavailable there). It is the same trade-off any
"passphrase-encrypted archive" makes.

### Practical consequence

Because brute-force resistance rests on Argon2id + passphrase entropy, the cost
parameters matter. Defaults are `m=256 MiB, t=3, p=1`; on desktop hardware this
is roughly a fraction of a second per guess, which is meaningful but not
absolute. **Use a long, high-entropy passphrase** (a 4+ word random passphrase is
excellent).

If you require true multi-factor enforcement (device possession **and** a
passphrase, neither sufficient alone), that is a different key hierarchy and is
not implemented here.

## Context binding (AEAD associated data)

Every encryption operation is bound to an **AAD** derived from:

- a domain-separation label,
- the format version,
- the **vault ID** (random per vault),
- the **file ID** (opaque per file; `manifest` for the index).

Consequences:

- A blob **cannot** be copied into a different vault's folder and decrypted.
- A blob **cannot** be swapped between two file IDs in the same vault.
- A tampered or substituted manifest entry fails authentication.

The AAD context is not stored in the blob — it comes from the authenticated
manifest and the vault metadata. That is exactly what makes substitution
detectable.

## Path safety

Filenames are validated in the **Rust backend**, never trusting the manifest:

- Single-file names must be a plain basename (no separators, no drive/UNC
  prefixes, no `.`/`..`, no control characters, no trailing dot/space, no
  reserved device names).
- Relative paths only accept ordinary components.
- Extraction re-validates the decrypted name and asserts the destination stays
  inside the chosen directory.
- Symlinks and Windows reparse points (junctions) are **never followed** during
  folder encryption or vault discovery.

## Limits & known constraints

| Area | Current behaviour |
|---|---|
| File size | Files above **1 GiB** are rejected (in-memory processing, interim control) |
| Concurrency | Single-process; cloud-sync conflict resolution is not implemented |
| Manifest | Written atomically (temp file → rename) but not versioned/rollback-proof |
| Zeroization | Secrets held in `Zeroizing` buffers; compiler/allocator copies cannot be fully erased |
| Rollback | A full-directory rollback by an attacker is not detectable without external trusted state |

## Non-goals

- Protecting against a compromised operating system, kernel malware, or a
  keylogger.
- Defending against an attacker who has your unlocked machine.
- Hiding the fact that encrypted data exists (file sizes and count are visible).
- Protecting metadata from a local attacker while the vault is unlocked.

## Reporting

Security issues: [Amit Bhatnagar](https://www.linkedin.com/in/amitxbhatnagar/).
