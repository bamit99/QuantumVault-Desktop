<#
.SYNOPSIS
  Trusts the Quantum Vault self-signed code-signing certificate.

.DESCRIPTION
  Imports the public certificate (certs/quantum-vault-codesign.cer) into the
  CURRENT USER's "Trusted Root Certification Authorities" and "Trusted
  Publishers" stores, so Windows recognises the publisher as verified and stops
  showing "unknown publisher".

  No administrator rights are required because both stores are per-user.

  Only run this if you trust the person who built the binary. A code-signing
  certificate in Trusted Root means Windows will trust anything signed with it.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\Install-Certificate.ps1
#>
[CmdletBinding()]
param(
  [string]$CerPath
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $CerPath) { $CerPath = Join-Path $scriptDir "..\certs\quantum-vault-codesign.cer" }
$CerPath = [System.IO.Path]::GetFullPath($CerPath)

if (-not (Test-Path $CerPath)) {
  throw "Certificate not found: $CerPath`nAsk the publisher for it, or run scripts\New-SelfSignedCert.ps1 if you built it yourself."
}

# Load the certificate to report its details and thumbprint.
$x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CerPath)

Write-Host "Importing $CerPath" -ForegroundColor Cyan

# Trusted Root: makes the chain valid.
Import-Certificate -FilePath $CerPath -CertStoreLocation "Cert:\CurrentUser\Root" | Out-Null
Write-Host "  OK  Trusted Root Certification Authorities" -ForegroundColor Green

# Trusted Publishers: makes Windows show the publisher name without a prompt.
Import-Certificate -FilePath $CerPath -CertStoreLocation "Cert:\CurrentUser\TrustedPublisher" | Out-Null
Write-Host "  OK  Trusted Publishers" -ForegroundColor Green

Write-Host ""
Write-Host "Done. Binaries signed by this certificate will now show a verified publisher:" -ForegroundColor Green
Write-Host ("  Subject    : " + $x509.Subject)
Write-Host ("  Thumbprint : " + $x509.Thumbprint)
Write-Host ("  Expires    : " + $x509.NotAfter.ToString("yyyy-MM-dd"))
Write-Host ""
Write-Host "To remove it later (current user):"
Write-Host ("  Get-ChildItem Cert:\CurrentUser\Root, Cert:\CurrentUser\TrustedPublisher | Where-Object {{ `$_.Thumbprint -eq '{0}' }} | Remove-Item" -f $x509.Thumbprint)
