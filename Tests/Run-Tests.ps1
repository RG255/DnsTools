using module dnstools

param(
    [switch]$CI
)

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$tests = Join-Path $root "Tests"

Write-Host "Running Pester tests from: $tests"

# Import the module under test
$modulePath = Join-Path $root "DnsToolkit.psm1"
Import-Module $modulePath -Force

$configuration = New-PesterConfiguration

$configuration.Run.Path = $tests
$configuration.Run.PassThru = $true
$configuration.Output.Verbosity = if ($CI) { "Detailed" } else { "Normal" }

$result = Invoke-Pester -Configuration $configuration

if ($CI -and $result.FailedCount -gt 0) {
    Write-Error "One or more tests failed"
    exit 1
}
