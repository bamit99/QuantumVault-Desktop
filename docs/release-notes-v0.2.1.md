## Quantum Vault v0.2.1 — legacy vault recovery (v1 vaults)

Fixes a **data-access regression**: a vault created by v0.1.0 or v0.1.1 could not be opened by any build since v0.1.2.

### The bug

Those early builds wrote a different vault format:

- `vault.meta` had no `vault_id` field and `version: 1`;
- the passphrase verifier was a plain `AES-GCM(Argon2id(passphrase), "qvault-passphrase-verifier-v1")` with no metadata digest and no AAD;
- the device key was sealed with DPAPI as the bare 96-byte private key, without the vault-ID prefix;
- file blobs used the legacy v2 container, which carries **no associated data**;
- the file index was one shared `manifest.qvault` blob.

v0.1.2 introduced the vault ID and made the metadata digest part of the verifier, so `vault_id` became a required field. Unlocking such a vault failed with:

```
invalid format: parse vault.meta: missing field `vault_id` at line 9 column 1
```

The files were never damaged — the vault was simply unreadable by the newer app.

### The fix

The legacy format is still fully readable, so v0.2.1 **migrates those vaults forward on first unlock** instead of refusing them:

1. **Assign and persist a vault ID** before touching any file, so an interrupted migration retries against the same ID.
2. **Re-encrypt every payload** from the legacy container into the AAD-bound one, and write a metadata sidecar per file. Files already in the current container are detected by their version byte and left alone.
3. **Re-seal the device key** with the vault-ID prefix, so the fast device-unlock path keeps working.
4. **Bump the metadata version** to v4 and recompute the passphrase verifier over the new digest — the same Argon2 salt is reused, so **the same passphrase keeps working** and every file stays readable.
5. **Remove the legacy shared index**, which is redundant once the sidecars exist.

The version bump happens last, so a vault that claims the current version is always fully migrated. The migration is idempotent, survives an interruption, and a single unreadable file keeps its legacy container instead of locking you out of the whole vault.

If the legacy index is missing, the original file names cannot be recovered; the app says so plainly and leaves the encrypted files untouched rather than showing an empty vault.

### Verification

90 Rust tests pass (7 new ones covering the v1 path, against a byte-accurate v1 vault fixture), `cargo clippy -D warnings` and `cargo fmt --check` are clean, `cargo deny check` and `cargo audit` report no issues, and `npm audit` reports no vulnerabilities.

### Install

| File | Use it if you want |
|---|---|
| `quantum-vault-desktop.exe` | Portable — double-click and run, nothing installed |
| `Quantum.Vault_0.2.1_x64-setup.exe` | Installer — Start Menu shortcut + uninstaller |
| `Quantum.Vault_0.2.1_x64_en-US.msi` | MSI — managed/silent deployment |
| `quantum-vault-codesign.cer` | Trust the publisher — see SIGNING.md |
| `SHA256SUMS.txt` | Verify the downloads |

> **First unlock of an old vault takes longer than usual** — the migration re-encrypts every file in the vault. That happens once, on the first unlock after upgrading.

Windows 10 or 11; WebView2 is preinstalled. Signed with a self-signed certificate — on a machine that has not trusted it, Windows shows the standard SmartScreen prompt (*More info → Run anyway*).
