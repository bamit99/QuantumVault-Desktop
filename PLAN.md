# Quantum-Vault for Windows — Project Plan

> A post-quantum encrypted file vault for Windows. Files are encrypted locally and
> placed inside any cloud-synced folder (Google Drive for Desktop, OneDrive, Dropbox,
> etc.), so the ciphertext syncs to the cloud automatically. No OAuth, no cloud API —
> the cloud provider never sees anything but opaque ciphertext.

**Status:** Approved for build · **Ports from:** `bamit99/Quantum-Vault` (Android)

---

## 1. Goals & Non-Goals

### Goals
- Post-quantum-resistant encryption at rest (ML-KEM-768 + X25519 hybrid KEM).
- Create an encrypted **vault folder** inside a user-chosen cloud-synced directory.
- Unlock vaults with a secure passphrase; optional Windows Hello unlock (Phase 2).
- Modern, custom, animated UI — deliberately *not* stock Windows chrome.
- Faithful cryptographic parity with the Android app (same primitives, same threat model).

### Non-Goals (v1)
- Byte-identical cross-platform vault sharing with Android (targeted as stretch).
- Multi-user / shared vaults, real-time collaboration.
- Native Google Drive API integration / OAuth (by design — provider-agnostic).
- Mobile/other-OS builds (architecture is portable; not in scope now).

---

## 2. Platform & Stack

| Layer | Choice | Why |
|---|---|---|
| Shell | **Tauri 2** | ~5–10 MB binary, memory-safe Rust core, WebView2 already on Win10/11 |
| Core lang | **Rust** | First-class PQ crypto crates (`ml-kem`, `x25519-dalek`, `argon2`) |
| UI | React 18 + TypeScript + Vite | Fast, huge ecosystem, easy custom theming |
| Styling | Tailwind CSS + framer-motion | Custom design system, animated micro-interactions |
| Native dialogs | `rfd` | Native folder picker for choosing the cloud folder |
| Key sealing | Windows **DPAPI** | Analog of Android Keystore for sealing the device private key |
| Packaging | Tauri bundler → NSIS/MSI | Single installer, code signing (required) |

### Key Rust crates
`ml-kem` (FIPS 203) · `x25519-dalek` · `argon2` · `aes-gcm` · `hkdf` · `sha2` ·
`zeroize` · `rfd` · `dpapi` · `serde` · `bincode` · `rand`

---

## 3. Cryptographic Architecture

Faithful port of the Android `HybridPQCrypto` / `PassphraseKDF` design.

### 3.1 Key derivation (passphrase)
- **Argon2id**, v19: `t=3`, `m=256 MiB` (secure-by-default desktop cost, vs. phone's 64 MiB), `p=1`.
  Target unlock latency < 2 s on a reference desktop.
- Produces the **passphrase KEK** (32 B). Salt is public, stored with the vault.

### 3.2 Hybrid KEM (the quantum-resistant leg)
- **Classical leg:** ephemeral X25519 ECDH → 32 B shared secret.
- **Post-quantum leg:** ML-KEM-768 (FIPS 203) encapsulation → 32 B shared secret.
- **Combiner:** `KEK = HKDF-SHA256(X25519_secret ‖ MLKEM_secret, salt, info="qvault-pq-hybrid-v1")`.
- An attacker must break **both** the ECDH and the lattice problem to recover the
  key → defeats "harvest now, decrypt later."

### 3.3 File encryption
1. Fresh random 256-bit **FileKey** per file.
2. Payload = `AES-256-GCM(FileKey, plaintext)` (iv ‖ ct ‖ tag).
3. FileKey wrapped by the hybrid **device KEK** (device leg).
4. FileKey wrapped by the **passphrase KEK** (passphrase leg) — dual-wrap.

### 3.4 Device key storage (Windows analog of Android Keystore)
- On vault creation, generate one ML-KEM-768 + X25519 keypair per vault.
- Private halves sealed with **DPAPI** (CurrentUser scope) into `vault.meta`.
- Public halves stored in `vault.meta` for encapsulation + a display fingerprint.
- Dual-wrap means: **password alone** unlocks on any machine (recovery); the PQ
  device leg still protects at rest even if DPAPI is unavailable.

### 3.5 Zeroization
- All transient key material (`FileKey`, `KEK`, shared secrets, passphrase bytes)
  wiped via `zeroize`. Passphrase kept as `SecString`/gated, never logged.

---

## 4. Vault Format

### 4.1 On-disk layout
```
<vault folder>/
  vault.meta          # version, salts, DPAPI-sealed device private keys, pub keys, fingerprint
  manifest.qvault     # encrypted index: {opaque_id -> (filename, size, mime, mtime, wrapped keys)}
  <opaque-id>.qvault  # one encrypted file per plaintext file
```

### 4.2 File blob header (self-describing, versioned)
```
MAGIC "QVAULT" (6 B)
version byte
X25519 ephemeral pub (32 B)
ML-KEM-768 encapsulation (1088 B)
salt (32 B)
argon2 salt (32 B)
wrapped FileKey (device leg)   [iv ‖ ct ‖ tag]
wrapped FileKey (passphrase leg)[iv ‖ ct ‖ tag]
AES-GCM payload                 [iv ‖ ct ‖ tag]
```

### 4.3 Metadata hiding
- On-disk filenames are random opaque IDs (`.qvault`). Original filename/size/mime
  are inside the authenticated plaintext (AES-GCM), so nothing leaks to the cloud.

---

## 5. Cloud Mapping Model

- User picks **any folder** (typically `G:\My Drive\`, OneDrive, Dropbox, or a NAS-synced
  dir) via native dialog. The app creates `<chosen>/<vault-name>/` inside it.
- Drive/OneDrive/Dropbox sync the ciphertext as opaque files. No provider integration.
- **File-level** (not a single container): one file changed = one `.qvault` re-synced.
  Incremental and sync-friendly.
- Handles sync conflicts gracefully via the manifest's integrity checks.

---

## 6. Feature Set & Use Cases

### Core flows (Phase 1)
| # | Use case | Description |
|---|---|---|
| UC-1 | Create vault | Pick cloud folder → name vault → set passphrase (strength check) → vault + device keypair generated |
| UC-2 | Open/unlock | Pick vault folder → enter passphrase → decrypt manifest → browse |
| UC-3 | Add file | Drag-drop / pick files → encrypted into `.qvault` with hidden names |
| UC-4 | Decrypt/extract | Select file → decrypt to a temp/system-chosen location → auto-wipe temp |
| UC-5 | Browse | Grid/list of files (decrypted metadata), search, sort |
| UC-6 | Manage | Rename (updates manifest), delete (secure wipe), reveal encrypted file in Explorer |
| UC-7 | Cross-device unlock | Same passphrase unlocks the vault on a second machine (passphrase leg) |
| UC-8 | Wrong password | Graceful auth failure, no partial decrypt, rate-limit hint |

### Windows Hello (Phase 2)
- Register Windows Hello (WebAuthn/`windows-hello` via Tauri plugin) to derive/unlock a
  **Hello-wrapped copy** of the vault master secret — no passphrase typed on unlock.
- Enrolled per-device, revocable; passphrase remains the recovery root of trust.
- Deferred if it adds heavy native dependency work; passphrase unlock ships first.

---

## 7. UI / UX Direction

**Aesthetic:** dark-first, aurora/glassmorphism, animated. Anti-"pale Windows".

### Screens
1. **Welcome** — brand mark, "Create a vault" / "Open existing" (folder picker).
2. **Create** — vault name, folder picker, passphrase + strength meter + confirm.
3. **Unlock** — centered passphrase input, reveal toggle, animated unlock.
4. **Vault browser** — encrypted file grid, drag-drop zone, metadata pane, search,
   context menu (extract / rename / delete / reveal).
5. **Settings / About** — crypto explainer ("why quantum-resistant"), vault fingerprint,
   Windows Hello enrollment (Phase 2), lock timer.

### Design system
- Custom token set (colors, radii, shadows, motion). Glass panels, aurora gradient
  accents, subtle grain/glow. Framer-motion for unlock/reveal transitions.
- Skills to load before UI build: **`ui-ux-pro-max`** and **`design-taste-frontend`**.

---

## 8. Project Structure

```
QuantumVault-Desktop/
  PLAN.md
  docs/                 # this plan + design/security docs
  src-tauri/            # Rust core
    src/
      crypto/           # hybrid_kem.rs, argon2_kdf.rs, aes_gcm.rs, dpapi_seal.rs
      vault/            # create.rs, open.rs, manifest.rs, format.rs
      commands/         # Tauri #[tauri::command] handlers
      main.rs, lib.rs
    Cargo.toml, tauri.conf.json
  src/                  # React frontend
    components/, screens/, lib/, styles/
    App.tsx, main.tsx
  tests/                # integration tests
  package.json, vite.config.ts, tailwind.config.js
```

---

## 9. Build Order (Milestones)

| Phase | Milestone | Deliverable |
|---|---|---|
| **P1** | Crypto core (Rust) + unit tests | Port of hybrid KEM + Argon2id + AES-GCM, zeroize |
| **P1** | Vault create/open/unlock commands | `vault.meta`, DPAPI sealing, manifest |
| **P1** | Encrypt/decrypt/list commands | File-level crypto + metadata hiding |
| **P1** | UI shell + design system | Custom theme, all screens wired to commands |
| **P1** | Drag-drop + polish | Animations, error/empty states, a11y |
| **P1** | Packaging | NSIS/MSI installer, icon, code signing |
| **P2** | Windows Hello unlock | Hello enrollment + unlock, passphrase fallback |
| **P2** | Cross-platform vault sharing (stretch) | Byte-compat with Android QVAULT format |

---

## 10. Review & Quality Gates

### Code review checklist
- [ ] All crypto uses reviewed, audited crates (no hand-rolled primitives).
- [ ] Keys/salts/nonces are unique per encryption; no IV reuse.
- [ ] Zeroization on every transient secret; no `Debug`/logging of secrets.
- [ ] DPAPI scope correct (CurrentUser); failure path still allows passphrase unlock.
- [ ] Manifest is authenticated (tamper → detectable failure, not silent corruption).
- [ ] No plaintext ever written to disk outside user-chosen extract location.

### Security review (before v1 release)
- Independent review of the hybrid-KEM combiner and dual-wrap logic.
- Confirm ML-KEM-768 is the current FIPS 203 parameter set (not deprecated ML-KEM-512).
- Threat model doc: "harvest now, decrypt later", cloud-provider-threat, local-attacker.

---

## 11. Testing Plan

### Unit tests (Rust)
- Argon2id determinism + wrong-passphrase failure.
- X25519 shared-secret agreement; all-zero-secret rejection.
- ML-KEM-768 encaps/decaps round-trip; tampered ciphertext rejection.
- HKDF combiner vectors; AES-GCM round-trip + tag mismatch failure.
- Vault format encode/decode round-trip (all field boundaries).

### Integration tests
- Create vault → add file → unlock → decrypt == original bytes.
- Wrong passphrase → no file decrypts; manifest unreadable.
- Cross-machine simulation: create on "device A" (seal keys), unlock with passphrase
  only on "device B" (no DPAPI) → decrypt succeeds (dual-wrap leg).
- Tamper a `.qvault` byte → decryption fails cleanly (auth tag).
- Large file (multi-GB) streaming; memory stays bounded.
- Special filenames (unicode, spaces, emoji) round-trip.

### UI / E2E
- Full create→add→unlock→extract flow.
- Drag-drop multiple files; cancel mid-operation.
- Folder picker paths with spaces/unicode.
- Empty vault, error, and first-run states.

### Performance
- Argon2 unlock latency target < 1.5 s on a reference desktop.
- Encrypt/decrypt throughput target ≥ 100 MB/s (AES-NI).
- Manifest load for 10k files < 250 ms.

---

## 12. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| PQ crate immaturity / spec churn | Pin to FIPS 203 `ml-kem`; wrap behind an interface for easy swap |
| DPAPI ties keys to one Windows account | Dual-wrap: passphrase leg is the portable recovery path |
| Cloud sync renames/conflicts on ciphertext | Opaque random names + authenticated manifest tolerate it |
| User forgets passphrase | Irrecoverable by design; clear warning at setup (like Android app) |
| Windows Hello native binding pain (P2) | Isolate behind a plugin; passphrase unlock unaffected if deferred |
| SmartScreen "unknown publisher" | OV/EV code-sign cert + reputation accrual; sign both installer and .exe |

---

## 13. Decisions Log (to confirm before/at build)

1. **Platform:** Tauri 2 + Rust + React. ✅ (approved)
2. **Crypto:** mirror Android (Argon2id + ML-KEM-768/X25519 + AES-256-GCM, DPAPI, dual-wrap). ✅
3. **Cloud:** provider-agnostic "encrypt inside any synced folder". ✅
4. **Windows Hello:** Phase 2. ✅
5. **Argon2 memory:** 256 MiB, secure-by-default. ✅
6. **Frontend framework:** React (chosen for ecosystem + framer-motion polish). ✅
7. **Byte-compat with Android vaults:** stretch goal, not v1. *(pending)*
8. **Code signing:** required — OV/EV cert via CA or Azure Trusted Signing. ✅

---

## 14. Open Questions

- [ ] Target Windows version (Win 10 1809+ for WebView2; DPAPI works everywhere)?
- [x] Code signing: required — OV/EV cert or Azure Trusted Signing (see §15).
- [x] Default Argon2 cost: 256 MiB, secure-by-default.
- [ ] Vault locking policy (auto-lock after N min idle)?

---

*Plan written 2026-10-25. Next action: scaffold Tauri + Rust project, then build P1 crypto core with tests.*

---

## 15. Code Signing

**Requirement:** all shipped binaries (the `.exe` and the NSIS/MSI installer) are
code-signed to avoid "unknown publisher" / SmartScreen warnings and guarantee
binaries are tamper-evident.

### Certificate options
| Option | Notes |
|---|---|
| **Azure Trusted Signing** | Modern, cheapest (~$10/mo), cloud HSM, no hardware token, EV/OV profiles, easy CI integration. **Recommended.** |
| **OV cert (Sectigo/DigiCert/SSL.com)** | ~$80–250/yr, validates org identity, private key on USB token or HSM. |
| **EV cert** | Highest trust, ~$300–500/yr, requires hardware token, instant SmartScreen reputation in many cases. |

### Signing flow
1. Obtain cert (Azure Trusted Signing → `Trusted Signing Account` → `Certificate Profile`).
2. Sign in CI: `signtool sign` (or `azuresigntool`) the built `.exe`, then the NSIS/MSI.
3. **SmartScreen reality:** a brand-new cert still shows a warning until *reputation* accrues from install volume/time. Plan for this — it is not a sign that signing failed.
4. Store the signing identity in a protected secret store; never commit keys.
