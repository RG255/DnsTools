#!/usr/bin/env powershell
#requires -Version 5.0

# ============================================================
#  TOP‑LEVEL: ABSOLUTELY NO EXECUTABLE CODE BEFORE CLASS LOAD
# ============================================================

# ------------------------------------------------------------
# 1. LOAD CLASSES FIRST - BEFORE ANY TRY/CATCH, FUNCTIONS, ETC.
# ------------------------------------------------------------

. "$PSScriptRoot\Classes\BinaryInfrastructure\DnsBinaryWriter.ps1"
. "$PSScriptRoot\Classes\BinaryInfrastructure\DnsBinaryReader.ps1"
. "$PSScriptRoot\Classes\Core\DnsHeader.ps1"
. "$PSScriptRoot\Classes\Core\DnsQuestion.ps1"
. "$PSScriptRoot\Classes\Basic\DnsARecord.ps1"
. "$PSScriptRoot\Classes\Basic\DnsAaaaRecord.ps1"
. "$PSScriptRoot\Classes\Basic\DnsCnameRecord.ps1"
. "$PSScriptRoot\Classes\Basic\DnsMxRecord.ps1"
. "$PSScriptRoot\Classes\Basic\DnsTxtRecord.ps1"
. "$PSScriptRoot\Classes\Basic\DnsSrvRecord.ps1"
. "$PSScriptRoot\Classes\Basic\DnsNsRecord.ps1"
. "$PSScriptRoot\Classes\DnsSec\DnsDnskeyRecord.ps1"
. "$PSScriptRoot\Classes\DnsSec\DnsDsRecord.ps1"
. "$PSScriptRoot\Classes\DnsSec\DnsRrsigRecord.ps1"
. "$PSScriptRoot\Classes\DnsSec\DnsNsecRecord.ps1"
. "$PSScriptRoot\Classes\DnsSec\DnsNsec3Record.ps1"
. "$PSScriptRoot\Classes\Resource\DnsResourceRecord.ps1"
. "$PSScriptRoot\Classes\EDNS-OPT\DnsOptRecord.ps1"
. "$PSScriptRoot\Classes\DNS\DnsPacket.ps1"
. "$PSScriptRoot\Classes\Transport\DnsDotClient.ps1"
. "$PSScriptRoot\Classes\Transport\DnsDohClient.ps1"

$ModuleScriptRoot = $PSScriptRoot
$ModuleName       = (Split-Path -Path (Split-Path -Path $ModuleScriptRoot -Parent) -Leaf)
$PSD1Path         = Join-Path -Path $ModuleScriptRoot -ChildPath ("{0}.psd1" -f $ModuleName)

# ============================================================
# 2. NOW SAFE TO DEFINE FUNCTIONS AND EXECUTE CODE
# ============================================================

function Get-Psd1Data {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Microsoft.PowerShell.DesiredStateConfiguration.ArgumentToConfigurationDataTransformation()]
        [Hashtable] $PathToPsd1file
    )
    $PathToPsd1file
}

function Initialize-Folders {
    param([Parameter(Mandatory)][Array]$Folders)

    foreach ($Item in $Folders) {
        $Path = Join-Path -Path $ModuleScriptRoot -ChildPath $Item
        if (-not (Test-Path -Path $Path)) {
            $null = New-Item -Path $Path -ItemType Directory
        }
    }
}

function Publish-MyEnvironment {
    param([String]$Option = $null)

    if ($MyVariables = Get-ChildItem -Path (Join-Path $ModuleScriptRoot ("Functions{0}\Define-Variables*.ps1" -f $Option)) -ErrorAction Ignore) {
        foreach ($Item in ($MyVariables.FullName | Sort-Object)) { . $Item }
    }

    if ($MyCustomXML = Get-ChildItem -Path (Join-Path $ModuleScriptRoot ("Functions{0}\Define-CustomXML.ps1" -f $Option)) -ErrorAction Ignore) {
        foreach ($Item in ($MyCustomXML.FullName | Sort-Object)) { . $Item }
    }
}

function Publish-CustomXML {
    foreach ($Item in ($MyCustomXML.GetEnumerator() | Sort-Object -Property key).Name) {
        $XMLItem = Join-Path -Path $ModuleScriptRoot -ChildPath ("Functions{0}\{1}" -f $Option, $MyCustomXML[$Item].file)
        if (Test-Path -Path $XMLItem) {
            switch ($MyCustomXML[$Item].Action) {
                'Update-FormatData' {
                    switch ($MyCustomXML[$Item].Option) {
                        'Prependpath' { Update-FormatData -PrependPath $XMLItem -ErrorAction Stop }
                        'Appendpath'  { Update-FormatData -AppendPath  $XMLItem -ErrorAction Stop }
                    }
                }
                default {
                    "Unknown item in `$MyCustomXML: [$Item] Option: [$($MyCustomXML[$Item].Option)]" | Write-Warning
                }
            }
        }
    }
}

function Publish-Variables {
    try {
        foreach ($VarSet in ($MyVars.GetEnumerator() | Sort-Object -Property key).Name) {
            foreach ($Item in ($MyVars[$VarSet].GetEnumerator() | Sort-Object -Property key).Name) {

                $Params = @{
                    Name   = $Item
                    Value  = $MyVars[$VarSet][$Item].Value
                    Option = $MyVars[$VarSet][$Item].Option
                    Scope  = $MyVars[$VarSet][$Item].Scope
                }

                New-Variable @Params -ErrorAction Stop
                Export-ModuleMember -Variable $Item -ErrorAction Stop
            }
        }
    }
    catch {
        Write-Warning "Variable [$Item] failed to create"
    }
}

# ============================================================
# 3. MAIN MODULE INITIALIZATION
# ============================================================

try {
    Initialize-Folders -Folders @(
        'Classes\BinaryInfrastructure',
        'Classes\Core',
        'Classes\Basic',
        'Classes\DNSSEC',
        'Classes\Resource',
        'Classes\EDNS-OPT',
        'Classes\DNS',
        'Classes\Transport',
        'Helpers',
        'Functions',
        'FunctionsLinux',
        'FunctionsWindows',
        'FunctionsMacOS'
    )

    $PSD1Data = Get-Psd1Data -PathToPsd1file ("{0}" -f $PSD1Path)

    Publish-MyEnvironment

    # Load common functions
    $Exclude = @('Define-CustomXML|Define-Variables|\.zip$')
    $CommonFunctions = Get-ChildItem -Path (Join-Path $ModuleScriptRoot 'Functions\*.ps1') |
                       Where-Object { $_.Name -inotmatch $Exclude }

    foreach ($Item in $CommonFunctions) {
        . $Item.FullName
        Export-ModuleMember -Function $Item.BaseName -ErrorAction Stop
    }

    # OS-specific functions
    switch ($true) {

        ($IsWindows -or $PSVersionTable.PSVersion.Major -lt 7) {
            Publish-MyEnvironment -Option 'Windows'
            $WinFunctions = Get-ChildItem (Join-Path $ModuleScriptRoot 'FunctionsWindows\*.ps1') |
                            Where-Object { $_.Name -inotmatch $Exclude }
            foreach ($Item in $WinFunctions) {
                . $Item.FullName
                Export-ModuleMember -Function $Item.BaseName -ErrorAction Stop
            }
        }

        $IsLinux {
            Publish-MyEnvironment -Option 'Linux'
            $LinFunctions = Get-ChildItem (Join-Path $ModuleScriptRoot 'FunctionsLinux\*.ps1') |
                            Where-Object { $_.Name -inotmatch $Exclude }
            foreach ($Item in $LinFunctions) {
                . $Item.FullName
                Export-ModuleMember -Function $Item.BaseName -ErrorAction Stop
            }
        }

        $IsMacOS {
            Publish-MyEnvironment -Option 'MacOS'
            $MacFunctions = Get-ChildItem (Join-Path $ModuleScriptRoot 'FunctionsMacOS\*.ps1') |
                            Where-Object { $_.Name -inotmatch $Exclude }
            foreach ($Item in $MacFunctions) {
                . $Item.FullName
                Export-ModuleMember -Function $Item.BaseName -ErrorAction Stop
            }
        }

        default { throw "Operating System Unknown" }
    }

}
catch {
    Write-Warning "Module initialization failed: $($_.Exception.Message)"
    throw "Unable to initialise module: $ModuleName"
}
