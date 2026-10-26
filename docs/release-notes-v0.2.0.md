## Quantum Vault v0.2.0 — per-file metadata sidecars

This release replaces the vault's single shared index file with **per-file encrypted metadata sidecars**, and ships the CI pipeline that re-verifies every assurance claim in these notes.

### QV3-01 — per-file encrypted metadata sidecars

The vault layout changed:

```
<vault>/
  vault.meta        device keypair + passphrase verifier
  <id>.qvault       encrypted file contents
  <id>.meta         encrypted metadata (name, size, mime, timestamps)
```

**Why.** A vault is meant to live in a cloud-synced folder and be edited from more than one machine. The old shared `manifest.qvault` index was *rewritten in full* on every add, rename or delete, so two devices editing at the same time produced two conflicting copies of that one file. The sync client then kept one side — and the other device's files silently vanished from the index, even though their ciphertext was still sitting in the folder.

Per-file sidecars are disjoint files. A concurrent add on two machines writes two different sidecars and never touches the same file, so there is nothing to conflict. Only a rename or delete of the *same* file remains last-writer-wins, on one item rather than a whole-index loss.

**Crypto.** A sidecar uses the same dual-wrap container as a payload blob (fresh per-blob key, AES-256-GCM, hybrid ML-KEM-768 + X25519 device leg, Argon2id passphrase leg) but is bound to distinct AAD purposes (`meta-keywrap` / `meta-payload`). A sidecar can never be substituted for a payload blob, or the reverse — both the payload layer and the key-wrap layer fail to authenticate.

**Versioning.** `vault.meta` moves v3 → v4. An older app now refuses a v4 vault instead of opening it as an empty vault, which is the silent-data-loss case the bump exists to prevent. The metadata digest covers the version field, so the passphrase verifier is recomputed with it while reusing the existing verify salt — the same passphrase keeps working and every file stays readable.

**Migration.** A v3 vault migrates lazily on first use, ordered so a crash at any point is safe: write sidecars → remove the legacy index → bump the version. The bump happens last, so a vault that claims v4 always has its sidecars.

### Also in this release

- **CI** — `.github/workflows/ci.yml` runs the frontend build, `cargo fmt`/`clippy`/`test`/`deny`/`audit`, and a full Windows release build with SHA-256 checksums on every push. A drift guard fails the build if the README test badge does not match the real `#[test]` count.
- **Production build fix** — `Cargo.toml` now declares Tauri's `custom-protocol` feature. Without it a binary built outside the Tauri CLI ran in dev mode and tried to load `http://localhost:1420`, showing "This page can't be displayed" instead of the app.
- **Passphrase gate** — the Create Vault screen now asks the backend for the verdict, so the button is enabled exactly when the backend policy accepts the passphrase (12+ characters **or** a 4-word passphrase, no common words, no low-variety strings) instead of only checking length.
- **`write_atomic` fix** — the temp file name is the full file name plus a suffix, so `<id>.qvault` and `<id>.meta` no longer collide on the same temp path.

### Verification

83 Rust tests pass, `cargo clippy -D warnings` and `cargo fmt --check` are clean, `cargo deny check` and `cargo audit` report no issues, `npm audit` reports no vulnerabilities, and the CI pipeline is green on this commit.

### Install

| File | Use it if you want |
|---|---|
| `quantum-vault-desktop.exe` | Portable — double-click and run, nothing installed |
| `Quantum.Vault_0.2.0_x64-setup.exe` | Installer — Start Menu shortcut + uninstaller |
| `Quantum.Vault_0.2.0_x64_en-US.msi` | MSI — managed/silent deployment |
| `quantum-vault-codesign.cer` | Trust the publisher — see SIGNING.md |
| `SHA256SUMS.txt` | Verify the downloads |

Windows 10 or 11; WebView2 is preinstalled. Signed with a self-signed certificate — on a machine that has not trusted it, Windows shows the standard SmartScreen prompt (*More info → Run anyway*).
