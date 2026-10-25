<#
.SYNOPSIS
  Signs Quantum Vault binaries with Authenticode.

.DESCRIPTION
  Locates signtool.exe from the Windows SDK and signs the given files (or the
  default release outputs) using either:
    * a certificate thumbprint from the current user's store (default), or
    * a PFX file (for CI), via -PfxPath / -PfxPassword.

  Timestamping is attempted first; if the timestamp server is unreachable the
  signature is applied without a timestamp so an offline build still succeeds.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\sign.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\sign.ps1 -Files "dist\app.exe"
#>
[CmdletBinding()]
param(
  [string[]]$Files,
  [string]  $Thumbprint,
  [string]  $PfxPath,
  [securestring]$PfxPassword,
  [string]  $TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = [System.IO.Path]::GetFullPath((Join-Path $scriptDir ".."))

# -- Locate signtool.exe (newest Windows SDK, x64) ---------------------------
function Find-SignTool {
  $roots = @(
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
    "$env:ProgramFiles\Windows Kits\10\bin"
  ) | Where-Object { $_ -and (Test-Path $_) }

  foreach ($r in $roots) {
    $candidate = Get-ChildItem $r -Directory |
      Where-Object { $_.Name -match '^10\.' } |
      Sort-Object { [version]$_.Name } -Descending |
      ForEach-Object { Join-Path $_.FullName "x64\signtool.exe" } |
      Where-Object { Test-Path $_ } |
      Select-Object -First 1
    if ($candidate) { return $candidate }
  }
  return $null
}

$signtool = Find-SignTool
if (-not $signtool) {
  throw "signtool.exe not found. Install the Windows SDK (Windows 10/11 SDK) to sign binaries."
}
Write-Host "Using signtool: $signtool" -ForegroundColor DarkGray

# -- Resolve the certificate ------------------------------------------------
$usePfx = $false
if ($PfxPath) {
  if (-not (Test-Path $PfxPath)) { throw "PFX not found: $PfxPath" }
  $usePfx = $true
  Write-Host "Signing with PFX: $PfxPath" -ForegroundColor Cyan
} else {
  if (-not $Thumbprint) {
    $thumbFile = Join-Path $root "certs\thumbprint.txt"
    if (Test-Path $thumbFile) {
      $Thumbprint = (Get-Content $thumbFile -Raw).Trim()
    }
  }
  if (-not $Thumbprint) {
    throw "No certificate thumbprint. Run scripts\New-SelfSignedCert.ps1 first, or pass -Thumbprint / -PfxPath."
  }
  $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $Thumbprint }
  if (-not $cert) { throw "Certificate $Thumbprint not found in Cert:\CurrentUser\My" }
  Write-Host "Signing with cert: $($cert.Subject) (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))" -ForegroundColor Cyan
}

# -- Resolve target files ---------------------------------------------------
if (-not $Files -or $Files.Count -eq 0) {
  $exe = Join-Path $root "src-tauri\target\release\quantum-vault-desktop.exe"
  $Files = @($exe)
  $bundle = Join-Path $root "src-tauri\target\release\bundle"
  if (Test-Path $bundle) {
    $Files += Get-ChildItem $bundle -Recurse -Include *.exe, *.msi |
      Where-Object { $_.Name -notlike "*quantum-vault-desktop.exe" } |
      Select-Object -ExpandProperty FullName
  }
}

$missing = $Files | Where-Object { -not (Test-Path $_) }
if ($missing) {
  Write-Host "Skipping missing files:" -ForegroundColor Yellow
  $missing | ForEach-Object { Write-Host "  $_" }
  $Files = $Files | Where-Object { Test-Path $_ }
}
if (-not $Files) { throw "No files to sign. Build first: npm run tauri build" }

# -- Build the signtool argument list ---------------------------------------
function New-SignArgs([string]$file, [bool]$withTimestamp) {
  $a = @("sign", "/fd", "SHA256", "/td", "SHA256", "/v")
  if ($usePfx) {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
      [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword))
    $a += @("/f", $PfxPath, "/p", $plain, "/tr", $TimestampUrl)
  } else {
    $a += @("/sha1", $Thumbprint, "/tr", $TimestampUrl)
  }
  if (-not $withTimestamp) {
    # Drop the RFC3161 timestamp switch for offline signing.
    $idx = $a.IndexOf("/tr")
    if ($idx -ge 0) { $a = $a[0..($idx-1)] + $a[($idx+2)..($a.Count-1)] }
  }
  $a += $file
  return $a
}

# -- Sign each file ---------------------------------------------------------
foreach ($f in $Files) {
  Write-Host ""
  Write-Host "Signing: $f" -ForegroundColor Cyan
  $ok = $false
  try {
    & $signtool @(New-SignArgs $f $true) | Out-Null
    $ok = ($LASTEXITCODE -eq 0)
  } catch {
    $ok = $false
  }
  if (-not $ok) {
    Write-Host "  timestamped signing failed; retrying without timestamp" -ForegroundColor Yellow
    & $signtool @(New-SignArgs $f $false) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Signing failed for $f" }
  }

  & $signtool verify /pa /q $f
  if ($LASTEXITCODE -eq 0) {
    Write-Host "  OK - signature verified" -ForegroundColor Green
  } else {
    Write-Host "  Signed, but chain verification needs the cert trusted on this machine." -ForegroundColor Yellow
  }
}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
