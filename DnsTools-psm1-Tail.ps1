# ============================================================
# Module paths / identity
# ============================================================

$ModuleScriptRoot = $PSScriptRoot
$ModuleName       = (Split-Path -Path (Split-Path -Path $ModuleScriptRoot -Parent) -Leaf)
$PSD1Path         = Join-Path -Path $ModuleScriptRoot -ChildPath ('{0}.psd1' -f $ModuleName)

# ============================================================
# 1. Support functions
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
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Array] $Folders
    )

    foreach ($Item in $Folders) {
        $Path = Join-Path -Path $ModuleScriptRoot -ChildPath $Item
        if (-not (Test-Path -Path $Path)) {
            $null = New-Item -Path $Path -ItemType Directory
        }
    }
}

function Publish-MyEnvironment {
    [CmdletBinding()]
    param(
        [String] $Option = $null
    )

    return  # keeping your original short-circuit

    if ($MyVariables = Get-ChildItem -Path (Join-Path $ModuleScriptRoot -ChildPath ('Functions{0}\Define-Variables*.ps1' -f $Option)) -ErrorAction Ignore) {
        foreach ($Item in ($MyVariables.FullName | Sort-Object)) { . $Item }
    }

    if ($MyCustomXML = Get-ChildItem -Path (Join-Path $ModuleScriptRoot -ChildPath ('Functions{0}\Define-CustomXML.ps1' -f $Option)) -ErrorAction Ignore) {
        foreach ($Item in ($MyCustomXML.FullName | Sort-Object)) { . $Item }
    }
}

function Publish-CustomXML {
    foreach ($Item in ($MyCustomXML.GetEnumerator() | Sort-Object -Property key).Name) {
        $XMLItem = Join-Path -Path $ModuleScriptRoot -ChildPath ('Functions{0}\{1}' -f $Option, $MyCustomXML[$Item].file)
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
# 2. MAIN MODULE INITIALIZATION
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

	$PSD1Data = Get-Psd1Data -PathToPsd1file ('{0}' -f $PSD1Path)

	Publish-MyEnvironment

	# Load common functions
	$Exclude = @('Define-CustomXML|Define-Variables|\.zip$')
	$CommonFunctions = Get-ChildItem -Path (Join-Path $ModuleScriptRoot -ChildPath 'Functions\*.ps1') |
	Where-Object { $_.Name -inotmatch $Exclude }

	foreach ($Item in $CommonFunctions) {
		. $Item.FullName
		#Export-ModuleMember -Function $Item.BaseName -ErrorAction Stop
	}

	# OS-specific functions
	switch ($true) {

		($IsWindows -or $PSVersionTable.PSVersion.Major -lt 7) {
			Publish-MyEnvironment -Option 'Windows'
			$WinFunctions = Get-ChildItem (Join-Path $ModuleScriptRoot -ChildPath 'FunctionsWindows\*.ps1') |
			Where-Object { $_.Name -inotmatch $Exclude }

			foreach ($Item in $WinFunctions) {
				. $Item.FullName
				#Export-ModuleMember -Function $Item.BaseName -ErrorAction Stop
			}
		}

		$IsLinux {
			Publish-MyEnvironment -Option 'Linux'
			$LinFunctions = Get-ChildItem (Join-Path $ModuleScriptRoot -ChildPath 'FunctionsLinux\*.ps1') |
			Where-Object { $_.Name -inotmatch $Exclude }

			foreach ($Item in $LinFunctions) {
				. $Item.FullName
				#Export-ModuleMember -Function $Item.BaseName -ErrorAction Stop
			}
		}

		$IsMacOS {
			Publish-MyEnvironment -Option 'MacOS'
			$MacFunctions = Get-ChildItem (Join-Path $ModuleScriptRoot -ChildPath 'FunctionsMacOS\*.ps1') |
			Where-Object { $_.Name -inotmatch $Exclude }

			foreach ($Item in $MacFunctions) {
				. $Item.FullName
				#Export-ModuleMember -Function $Item.BaseName -ErrorAction Stop
			}
		}
		default {
			throw 'Operating System Unknown'
		}
	}
	$PublicFunctions = @(
		'Add-DnssecTrustAnchor'
		'ConvertFrom-DnsWireBytes'
		'ConvertTo-DnsWireBytes'
		'ConvertTo-HexString'
		'Format-DnssecResult'
		'Get-DnssecCanonicalNameWire'
		'Get-DnssecCanonicalRrsetData'
		'Get-DnssecCanonicalRrWire'
		'Get-DnssecKeyDigest'
		'Get-DnssecKeyDigestHex'
		'Get-DnssecNsec3Hash'
		'Get-DnssecSignedData'
		'Get-DnssecSigningKey'
		'Get-DnssecTrustAnchors'
		'Import-DnssecTrustAnchors'
		'Initialize-DnssecTrustAnchors'
		'Invoke-DnsUdpQuery'
		'New-DnsQueryPacket'
		'Resolve-DnsIterative'
		'Resolve-Dnssec'
		'Resolve-DnssecChain'
		'Resolve-DnssecName'
		'Resolve-NameserverAddress'
		'Test-DnssecAnchoredDnskey'
		'Test-DnssecChain'
		'Test-DnssecDsForDnskey'
		'Test-DnssecName'
		'Test-DnssecNsec3Nodata'
		'Test-DnssecNsec3Nxdomain'
		'Test-DnssecNsec3OptOut'
		'Test-DnssecRrsig'
		'Test-DnssecSignature'
		'Test-DnssecTimeWindow'
	)
	Export-ModuleMember -Function $PublicFunctions #-Alias @() -Variable @()
}
catch {
		Write-Warning "Module initialization failed: $($_.Exception.Message)"
		throw "Unable to initialise module: $ModuleName"
}
