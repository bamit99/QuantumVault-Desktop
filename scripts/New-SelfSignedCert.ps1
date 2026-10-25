<#
.SYNOPSIS
  Creates a self-signed code-signing certificate for Quantum Vault.

.DESCRIPTION
  Generates an RSA-3072 code-signing certificate (Code Signing EKU, Digital
  Signature key usage), installs it in the current user's personal store, and
  exports:
    * certs/quantum-vault-codesign.cer  - public cert to distribute
    * certs/quantum-vault-codesign.pfx  - password-protected bundle for CI

  Idempotent: if a cert with the given subject already exists and is still
  valid, it is reused rather than duplicated.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\New-SelfSignedCert.ps1
#>
[CmdletBinding()]
param(
  [string]$Subject   = "CN=Amit Bhatnagar, O=Quantum Vault, C=IN",
  [int]   $Years     = 3,
  [string]$OutDir,
  [securestring]$PfxPassword
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $OutDir) { $OutDir = Join-Path $scriptDir "..\certs" }
$OutDir = [System.IO.Path]::GetFullPath($OutDir)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# -- Reuse an existing valid cert if present ----------------------------------
$existing = Get-ChildItem Cert:\CurrentUser\My |
  Where-Object { $_.Subject -eq $Subject -and $_.NotAfter -gt (Get-Date).AddDays(30) -and
                 $_.HasPrivateKey -and ($_.EnhancedKeyUsageList.ObjectId.Value -contains "1.3.6.1.5.5.7.3.3") } |
  Sort-Object NotAfter -Descending | Select-Object -First 1

if ($existing) {
  Write-Host "Reusing existing code-signing certificate." -ForegroundColor Yellow
  $cert = $existing
} else {
  Write-Host "Creating new self-signed code-signing certificate..." -ForegroundColor Cyan
  # -Type CodeSigningCert sets the Code Signing EKU (1.3.6.1.5.5.7.3.3).
  $cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $Subject `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -KeyUsage DigitalSignature `
    -KeyExportPolicy Exportable `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddYears($Years)
}

# -- Export public cert (.cer) -----------------------------------------------
$cerPath = Join-Path $OutDir "quantum-vault-codesign.cer"
Export-Certificate -Cert $cert -FilePath $cerPath -Type CERT | Out-Null
Write-Host "  public cert : $cerPath" -ForegroundColor Green

# -- Export PFX for CI (only when a password is supplied) --------------------
if ($PfxPassword) {
  $pfxPath = Join-Path $OutDir "quantum-vault-codesign.pfx"
  Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $PfxPassword | Out-Null
  Write-Host "  pfx bundle  : $pfxPath (password-protected)" -ForegroundColor Green
}

# -- Summary -----------------------------------------------------------------
Write-Host ""
Write-Host "Certificate ready" -ForegroundColor Cyan
Write-Host "  Subject    : $($cert.Subject)"
Write-Host "  Thumbprint : $($cert.Thumbprint)"
Write-Host "  Expires    : $($cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Sign the build           :  powershell -ExecutionPolicy Bypass -File scripts\sign.ps1"
Write-Host "  2. Share certs\quantum-vault-codesign.cer with your users so they can run"
Write-Host "     scripts\Install-Certificate.ps1 and see a verified publisher."

# Persist the thumbprint so sign.ps1 can find it without arguments.
$thumbFile = Join-Path $OutDir "thumbprint.txt"
Set-Content -Path $thumbFile -Value $cert.Thumbprint -NoNewline
Write-Host "  3. Thumbprint saved to $thumbFile"
