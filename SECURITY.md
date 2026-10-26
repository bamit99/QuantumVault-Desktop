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
- the **file ID** (opaque per file).
- a **purpose** tag, which distinguishes the payload blob from the metadata
  sidecar that describes it.

Consequences:

- A blob **cannot** be copied into a different vault's folder and decrypted.
- A blob **cannot** be swapped between two file IDs in the same vault.
- A metadata sidecar **cannot** be substituted for a payload blob, or the
  reverse: both the payload layer and the key-wrap layer fail to authenticate.
- A tampered or substituted metadata sidecar fails authentication.

The AAD context is not stored in the blob — it comes from the file ID and the
vault metadata. That is exactly what makes substitution detectable.

## Path safety

Filenames and identifiers are validated in the **Rust backend**, never trusting
the decrypted metadata (decrypted data is not trusted input):

- **File IDs** must be exactly 32 lowercase hex characters. The grammar is
  enforced in the path helper itself, when parsing a metadata sidecar, and at
  every IPC command — so a crafted ID cannot escape the vault directory.
- A sidecar's ID must also **match the file it was read from**, so a sidecar
  copied onto a different file is rejected.
- **Single-file names** must be a plain basename (no separators, no drive/UNC
  prefixes, no `.`/`..`, no control characters, no trailing dot/space, no
  reserved device names).
- **Relative paths** only accept ordinary components.
- **Extraction** re-validates the decrypted name, then walks the destination one
  component at a time, refusing any existing symlink or reparse point in the
  chain, and creates the file with `create_new` (no overwrite, no redirection).
- **Deletion** requires the file to exist before either the metadata or the
  disk is touched, and removes the payload blob before the metadata sidecar so
  a failure leaves a recoverable reference rather than an orphan.
- Symlinks and junctions are **never followed** during folder encryption or
  vault discovery.

Residual limitation: a filesystem race (a path component swapped between the
check and the write) cannot be fully eliminated without directory-handle-relative
operations; the window is reduced to a single component check per operation.

## Metadata integrity

`vault.meta` is security-critical: it holds the public keys that future files are
wrapped to. It is authenticated by the passphrase verifier, which carries a
SHA-256 digest over the format, version, vault ID, both public keys, the sealed
device key and the verifier salt.

- Substituting public keys (or any of those fields) makes the vault **fail
  closed** on unlock, rather than silently encrypting new files to an attacker's
  keys.
- On the machine where DPAPI unsealing succeeds, the public keys in the metadata
  are additionally checked against the keys derived from the unsealed private
  keys.
- This check works on a fresh machine too: it relies on the passphrase, not on
  the device key.

## Limits & known constraints

| Area | Current behaviour |
|---|---|
| File size | Files above **1 GiB** are rejected. Files are still processed whole in memory, so peak RSS can be several times the file size; the cap is an interim control until a chunked format exists |
| Concurrency | Single-process. Per-file metadata sidecars mean concurrent adds from two machines never touch the same file, so a concurrent add cannot lose another machine's files. A concurrent **rename or delete of the same file** is still last-writer-wins |
| Metadata | Each file's metadata lives in its own encrypted sidecar (`<id>.meta`), written atomically (temp file → fsync → rename). A payload blob and its sidecar are not one transaction, so a crash between the two can leave a blob whose metadata is missing — the file is then invisible in the listing, but its bytes are still on disk |
| Extraction | Refuses to overwrite an existing file; renames/creates are not transactional |
| Zeroization | Private keys, file keys, KEKs, KEM IKM and plaintext are held in `Zeroizing` containers; compiler/allocator copies and crash dumps cannot be fully erased |
| Rollback | A full-directory rollback by an attacker is not detectable without external trusted state |

## Non-goals

- Protecting against a compromised operating system, kernel malware, or a
  keylogger.
- Defending against an attacker who has your unlocked machine.
- Hiding the fact that encrypted data exists (file sizes and count are visible).
- Protecting metadata from a local attacker while the vault is unlocked.

## Passphrase policy

Enforced in the backend (not only the UI): minimum 12 characters or 4 words,
minimum character variety, and rejection of common words/sequences
(`password`, `qwerty`, `1234`, …).

This is a **heuristic, not an entropy estimator**. A passphrase of common words
chosen by a person can still be weak. Prefer a randomly generated multi-word
passphrase.

## Verification

Run before each release:

```bash
cd src-tauri
cargo test          # 83 tests
cargo clippy --all-targets
cargo fmt --check
cargo deny check    # advisories, licences, bans, sources
cargo audit
npm audit
```

A production build must enable Tauri's `custom-protocol` feature, otherwise the
binary loads the dev server (`http://localhost:1420`) instead of the bundled
frontend and shows "This page can't be displayed":

```bash
npm run tauri build          # shipping path (feature enabled automatically)
npm run build:release        # manual cargo build (feature enabled explicitly)
```

After building, launch the app and run the UI smoke test — it asserts that the
Create Vault button is enabled exactly when the backend passphrase policy
accepts the passphrase:

```bash
npm run smoke
```

`cargo deny` is scoped to the shipped Windows target (`deny.toml`), so warnings
about Linux-only transitive crates do not mask anything in the actual binary.
`cargo audit` may still report Linux-only crates (D-Bus/`rfd`); confirm with
`cargo tree -i <crate> --target x86_64-pc-windows-msvc`, which prints nothing
when the crate is not in the Windows graph.

`src-tauri/src/robustness.rs` provides deterministic fuzz-style tests (seeded RNG, no
nightly required): random and mutated blobs through the parser, random strings
through the path validators, and a containment check on random extraction names.
Coverage-guided fuzzing with `cargo-fuzz` remains recommended as a further step.

## Reporting

Security issues: [Amit Bhatnagar](https://www.linkedin.com/in/amitxbhatnagar/).
