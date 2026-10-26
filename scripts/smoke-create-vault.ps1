# End-to-end UI smoke test for the Create Vault screen.
#
# Drives the running app through the Windows UI Automation API and asserts
# that the "Create vault" button is enabled exactly when the backend
# passphrase policy accepts the passphrase (12+ characters OR 4 words, and
# not a common-word / low-variety string).
#
# The test only *reads* the button state - it never clicks it - so it cannot
# create a vault.
#
#   npm run tauri build            # or: cargo build --release --features custom-protocol
#   start the app
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/smoke-create-vault.ps1
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$proc = Get-Process quantum-vault-desktop -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $proc) { Write-Output "NOT RUNNING: start the app first"; exit 1 }
$root = [System.Windows.Automation.AutomationElement]::FromHandle($proc.MainWindowHandle)

function Find-ByName([string]$name) {
  $cond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::NameProperty, $name)
  $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $cond)
}
function Click($el) { $el.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke() }
function State([string]$label) {
  $f = Find-ByName $label
  if ($f.Count -eq 0) { return "absent" }
  return ("enabled=" + $f[0].Current.IsEnabled)
}
function EditFields {
  $root.FindAll([System.Windows.Automation.TreeScope]::Descendants,
    (New-Object System.Windows.Automation.PropertyCondition(
      [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
      [System.Windows.Automation.ControlType]::Edit)))
}
function Box([string]$name) {
  $all = EditFields
  $all | Where-Object { $_.Current.Name -match $name } | Select-Object -First 1
}
function Set-Box($b, [string]$v) {
  $b.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).SetValue($v)
}

# Navigate Home -> Create vault, unless we are already on the Create screen.
# NOTE: the Create screen's submit button is also called "Create vault", so we
# only click when the form fields are absent (i.e. we are on the home screen).
if (-not (Box "Vault name")) {
  $cv = Find-ByName "Create vault"
  if ($cv.Count -eq 0) { Write-Output "no 'Create vault' button on the home screen"; exit 2 }
  Click $cv[0]
  Start-Sleep -Seconds 2
}
if (-not (Box "Vault name")) { Write-Output "could not reach the Create vault screen"; exit 2 }

Set-Box (Box "Vault name") "SmokeTestVault"
Set-Box (Box "Cloud folder") "C:\Users\Public"
Start-Sleep -Seconds 1

# passphrase, expected enabled state, description
$cases = @(
  @("MyPassword2024", $false, "weak pattern (common word)"),
  @("short", $false, "too short"),
  @("harbor static pebble wing", $true, "4 words"),
  @("a b c d", $true, "4 short words"),
  @("tundra velvet orbit lamplight", $true, "4 good words")
)

$failures = 0
foreach ($case in $cases) {
  Set-Box (Box "Passphrase") $case[0]
  Set-Box (Box "Confirm") $case[0]
  Start-Sleep -Seconds 2
  $state = State "Create vault"
  $enabled = $state -eq "enabled=True"
  $ok = $enabled -eq $case[1]
  if (-not $ok) { $failures++ }
  $tag = if ($ok) { "PASS" } else { "FAIL" }
  Write-Output ("{0,-6} '{1}' -> {2} (expected enabled={3}) - {4}" -f $tag, $case[0], $state, $case[1], $case[2])
}
Write-Output ("failures: " + $failures)
exit $failures
