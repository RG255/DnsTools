# Tests/debug.ps1
$modulePath = Join-Path $PSScriptRoot '..\DnsTools.psm1'
Import-Module $modulePath -Force -Verbose

# Example function calls to exercise the module:
# Resolve-Dnssec -Name 'example.com' -Type A
# Get-DnssecTrustAnchors

Write-Host "Module loaded. Place breakpoints in DnsTools.psm1 and run this script."