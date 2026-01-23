$modulePath = Join-Path $PSScriptRoot "..\DnsSecTools.psd1"
$fixtureScript = Join-Path $PSScriptRoot "Generate-Fixtures.ps1"

Write-Host "Launching clean runspace for fixture generation..."

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "pwsh"
$psi.Arguments = "-NoProfile -NoLogo -Command `"Import-Module '$modulePath' -Force; & '$fixtureScript'`""
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true

$proc = [System.Diagnostics.Process]::Start($psi)
$proc.WaitForExit()

Write-Host $proc.StandardOutput.ReadToEnd()
Write-Host $proc.StandardError.ReadToEnd()
