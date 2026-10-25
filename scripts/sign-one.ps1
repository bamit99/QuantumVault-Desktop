<#
.SYNOPSIS
  Signs a single binary. Used by Tauri's bundle signCommand.

.DESCRIPTION
  Invoked by tauri.conf.json -> bundle.windows.signCommand with the path to the
  binary as the only argument ("%1" in the config).

  Signing happens DURING bundling, which matters: the bundler rewrites the main
  executable (bundle-type marker) before embedding it in the installer. Signing
  afterwards would leave the shipped exe unsigned.

  If no certificate is available (fresh clone, CI without secrets), this exits 0
  with a warning so the build still succeeds unsigned. Set
  QUANTUMVAULT_REQUIRE_SIGNING=1 to turn that into a hard failure.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$File,
  [string]$Thumbprint,
  [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = [System.IO.Path]::GetFullPath((Join-Path $scriptDir ".."))

function Find-SignTool {
  $roots = @(
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
    "$env:ProgramFiles\Windows Kits\10\bin"
  ) | Where-Object { $_ -and (Test-Path $_) }
  foreach ($r in $roots) {
    $c = Get-ChildItem $r -Directory |
      Where-Object { $_.Name -match '^10\.' } |
      Sort-Object { [version]$_.Name } -Descending |
      ForEach-Object { Join-Path $_.FullName "x64\signtool.exe" } |
      Where-Object { Test-Path $_ } |
      Select-Object -First 1
    if ($c) { return $c }
  }
  return $null
}

# Resolve the certificate.
if (-not $Thumbprint) {
  $tf = Join-Path $root "certs\thumbprint.txt"
  if (Test-Path $tf) { $Thumbprint = (Get-Content $tf -Raw).Trim() }
}

$cert = $null
if ($Thumbprint) {
  $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $Thumbprint }
}

if (-not $cert) {
  $msg = "No code-signing certificate found; leaving '$File' unsigned."
  if ($env:QUANTUMVAULT_REQUIRE_SIGNING -eq "1") { throw $msg }
  Write-Host "WARNING: $msg" -ForegroundColor Yellow
  exit 0
}

$signtool = Find-SignTool
if (-not $signtool) {
  $msg = "signtool.exe not found (install the Windows SDK); cannot sign '$File'."
  if ($env:QUANTUMVAULT_REQUIRE_SIGNING -eq "1") { throw $msg }
  Write-Host "WARNING: $msg" -ForegroundColor Yellow
  exit 0
}

Write-Host "Signing $File" -ForegroundColor Cyan
& $signtool sign /fd SHA256 /td SHA256 /sha1 $cert.Thumbprint /tr $TimestampUrl $File | Out-Null
if ($LASTEXITCODE -ne 0) {
  Write-Host "  timestamped signing failed; retrying without timestamp" -ForegroundColor Yellow
  & $signtool sign /fd SHA256 /sha1 $cert.Thumbprint $File | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Signing failed for $File" }
}

Write-Host "  signed OK" -ForegroundColor Green
exit 0
