# Code Signing

Quantum Vault ships **self-signed** Authenticode signatures. This is free, and it
removes the "unknown publisher" label for anyone who trusts the certificate — but
it does **not** make the binary trusted by default on machines that have never seen
the certificate.

> **Why not Let's Encrypt?** Let's Encrypt issues TLS *server* certificates only.
> Its CPS explicitly excludes code signing, and code-signing certificates require
> legal identity vetting plus HSM/token key protection, which no ACME profile
> automates. There is no free public CA for code signing.

## For users (verifying / trusting the build)

1. Download `quantum-vault-codesign.cer` from the repo (`certs/`).
2. Right-click → **Install Certificate** → *Current User* →
   **Place all certificates in the following store** →
   **Trusted Root Certification Authorities**.
   Or run, from the repo:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\Install-Certificate.ps1
   ```
3. Verify a signed binary:
   ```powershell
   Get-AuthenticodeSignature .\quantum-vault-desktop.exe | Format-List
   # Status    : Valid
   # Signer    : CN=Amit Bhatnagar, O=Quantum Vault, C=IN
   ```

Only do this if you trust the author. A certificate placed in Trusted Root means
Windows will trust *anything* signed with it.

## For the maintainer

### One-time setup

```powershell
npm run cert:new      # creates certs\quantum-vault-codesign.cer + thumbprint.txt
npm run cert:trust    # imports it into your own Trusted Root / Trusted Publishers
```

The certificate is `RSA-3072`, `SHA-256`, 3-year validity, with the Code Signing
EKU (`1.3.6.1.5.5.7.3.3`). The private key stays in
`Cert:\CurrentUser\My` and is never written to the repo.

### Sign a build

```powershell
npm run tauri build -- --no-bundle   # or the full build
npm run sign
```

`sign.ps1` will:

- locate the newest SDK `signtool.exe`,
- resolve the thumbprint from `certs\thumbprint.txt` (or `-Thumbprint`),
- sign with SHA-256 and an RFC 3161 timestamp (falls back to unsigned-timestamp
  if the timestamp server is unreachable),
- verify the result.

`npm run tauri build` does not sign automatically — run `npm run sign` after it,
or wire it into your release script.

### CI / another machine

Export a password-protected PFX and pass it:

```powershell
.\scripts\New-SelfSignedCert.ps1 -PfxPassword (Read-Host -AsSecureString)

.\scripts\sign.ps1 `
  -PfxPath certs\quantum-vault-codesign.pfx `
  -PfxPassword (Read-Host -AsSecureString)
```

Store the PFX and password as CI secrets. **Never commit the PFX.**

## Switching to a real CA certificate later

Nothing in the pipeline is self-signed specific. Either:

- drop the CA-issued cert into `Cert:\CurrentUser\My` and pass its thumbprint, or
- pass `-PfxPath` / `-PfxPassword` for a CA-issued PFX.

Only the certificate changes — `sign.ps1` stays the same.

Expectations for a real certificate:

| Certificate | Removes "unknown publisher" | Removes SmartScreen warning |
|---|---|---|
| Self-signed (trusted by the user) | ✅ | ❌ |
| OV code signing | ✅ | ⏳ only after reputation accrues |
| EV code signing | ✅ | ✅ usually quickly |

SmartScreen reputation is driven by download volume over time, not by the
certificate alone.
