param(
  [string]$ProcessName = "quantum-vault-desktop",
  [string]$Out = "$PWD\shot.png"
)

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Drawing;
using System.Runtime.InteropServices;
public class Cap {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint flags);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
}
"@

# Captures the Quantum Vault window to a PNG (works even when the window is
# behind other apps, unlike a full-screen grab).
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/capture-window.ps1 -Out shot.png

$proc = Get-Process $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $proc) { Write-Output "NOT RUNNING: $ProcessName"; exit 1 }
$h = $proc.MainWindowHandle
Write-Output ("handle: " + $h + "  title: " + $proc.MainWindowTitle)

$r = New-Object Cap+RECT
[void][Cap]::GetWindowRect($h, [ref]$r)
$w = $r.R - $r.L
$ht = $r.B - $r.T
Write-Output ("rect: " + $r.L + "," + $r.T + " " + $w + "x" + $ht)

[void][Cap]::ShowWindow($h, 9)
[void][Cap]::SetWindowPos($h, [IntPtr]::Zero, 80, 40, $w, $ht, 0x0040)
Start-Sleep -Milliseconds 1200
[void][Cap]::SetForegroundWindow($h)
Start-Sleep -Milliseconds 800

$bmp = New-Object System.Drawing.Bitmap($w, $ht)
$gfx = [System.Drawing.Graphics]::FromImage($bmp)
$hdc = $gfx.GetHdc()
$ok = [Cap]::PrintWindow($h, $hdc, 2)
$gfx.ReleaseHdc($hdc)
$gfx.Dispose()
$bmp.Save($Out)
Write-Output ("printwindow ok: " + $ok + " -> " + $Out)
