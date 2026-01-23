param(
    [string]$ModulePath = "$PSScriptRoot\DnsSecTools.psd1"
)

# Detect polluted session BEFORE loading the module
if ([System.Management.Automation.PSTypeName]'DnsBinaryWriter'.Type) {
    Write-Warning @"
DnsSecTools: A previous version of this module (or another module defining DNS classes)
has already been loaded in this PowerShell session. PowerShell cannot reload or replace
class definitions once they exist. For reliable behavior, start a fresh PowerShell session.
"@
}

Import-Module $ModulePath -Force
