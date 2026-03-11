# ============================================================
# Module paths / identity
# ============================================================

$ModuleScriptRoot = $PSScriptRoot
$ModuleName       = (Split-Path -Path (Split-Path -Path $ModuleScriptRoot -Parent) -Leaf)
$PSD1Path         = Join-Path -Path $ModuleScriptRoot -ChildPath ('{0}.psd1' -f $ModuleName)

# ============================================================
# 1. Support functions
# ============================================================

function Get-Psd1Data 
{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[Microsoft.PowerShell.DesiredStateConfiguration.ArgumentToConfigurationDataTransformation()]
		[Hashtable] $PathToPsd1file
	)
	$PathToPsd1file
}

function Initialize-Folders 
{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[Array] $Folders
	)

	foreach ($Item in $Folders) 
	{
		$Path = Join-Path -Path $ModuleScriptRoot -ChildPath $Item
		if (-not (Test-Path -Path $Path)) 
		{$null = New-Item -Path $Path -ItemType Directory}
	}
}

function Publish-MyEnvironment 
{
	[CmdletBinding()]
	param(
		[String] $Option = $null
	)

	foreach ($Item in ($PSD1Data.PrivateData.ModuleVars[$Option].keys | Sort-Object))
	{
		$FilePath = Join-Path -Path $ModuleScriptRoot -ChildPath ('Functions{0}\{1}' -f $Option, $PSD1Data.PrivateData.ModuleVars[$Option][$Item]) -ErrorAction Stop
		If (Test-Path -Path $FilePath)
		{
			# Dot-source the DefineVariables file to load its variables
			. $FilePath
		}
	}

	if ($MyCustomXML = Get-ChildItem -Path (Join-Path $ModuleScriptRoot -ChildPath ('Functions{0}\Define-CustomXML.ps1' -f $Option)) -ErrorAction Ignore) 
	{
		foreach ($Item in ($MyCustomXML.FullName | Sort-Object)) 
		{. $Item}
	}
}

function Publish-CustomXML 
{
	foreach ($Item in ($MyCustomXML.GetEnumerator() | Sort-Object -Property key).Name) 
	{
		$XMLItem = Join-Path -Path $ModuleScriptRoot -ChildPath ('Functions{0}\{1}' -f $Option, $MyCustomXML[$Item].file)
		if (Test-Path -Path $XMLItem) 
		{
			switch ($MyCustomXML[$Item].Action) {
				'Update-FormatData' 
				{
					switch ($MyCustomXML[$Item].Option) {
						'Prependpath' 
						{Update-FormatData -PrependPath $XMLItem -ErrorAction Stop}
						'Appendpath'  
						{Update-FormatData -AppendPath  $XMLItem -ErrorAction Stop}
					}
				}
				default 
				{"Unknown item in `$MyCustomXML: [$Item] Option: [$($MyCustomXML[$Item].Option)]" | Write-Warning}
			}
		}
	}
}

Function Publish-Variables
{
	<#
			.SYNOPSIS
			Takes the definitions in $MyVars and processes them into the variables defined.
        
			.DESCRIPTION
			As Above
        
			.EXAMPLE
			Publish-Variables is called from the file Define-Variables.ps1 which is executed as part
			of this psm1 file when the module is initialised.
        
			.EXAMPLE
			Publish-Variables
	#>
	Try
	{
		ForEach ($VarSet in ($MyVars.GetEnumerator() | Sort-Object -Property key).Name)
		{
			ForEach ($Item in ($MyVars[$VarSet].GetEnumerator() | Sort-Object -Property key).Name)
			{
				$Params = @{
					Name   = $null
					Value  = $null
					Option = $null
					Scope  = $null
				}
				If (Test-Path -Path ('Variable:{0}:{1}' -f $MyVars[$VarSet][$Item].Scope, $Item))
				{
					$Params = @{
						Name  = $Item
						Scope = $MyVars[$VarSet][$Item].Scope
					}
					If ($Params.Scope -inotmatch $VOConstant)
					{Remove-Variable @Params -Force}
				}
				$Params = @{
					Name   = $Item
					Value  = $MyVars[$VarSet][$Item].Value
					Option = $MyVars[$VarSet][$Item].Option
					Scope  = $MyVars[$VarSet][$Item].Scope
				}
				New-Variable @Params -ErrorAction Stop
				Export-ModuleMember -Variable $Item -ErrorAction Stop
				$var = Get-Variable -Name VInfoOn -Scope Local -ErrorAction SilentlyContinue
				if ($var -and $var.Value -is [bool] -and $var.Value) 
				{
					{
						$Msg = 'Variable:[{0}] created Value: [{1}]' -f $Item, $Params.Value
						Write-Information -MessageData $Msg -InformationAction Continue
					}
				}
			}
		}
	}
	Catch
	{
		$Msg = 'Variable:[{0}] Failed to create Value: [{1}]' -f $Item, $Params.Value
		Write-Information -MessageData $Msg -InformationAction Continue
	}
}

# ============================================================
# 2. MAIN MODULE INITIALIZATION
# ============================================================

try 
{
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

	# Check if we should export all functions (for testing)
	$ExportAll = ($env:DNSTOOLS_EXPORT_ALL -eq '1')

	# Load common functions
	$VarDefFiles = @($PSD1Data.PrivateData.ModuleVars[''].Values)
	$Exclude = @('Define-CustomXML|\.zip$')
	$MyPath = (Join-Path -Path $ModuleScriptRoot -ChildPath ('Functions\*{0}' -f $StrExtPS1) -ErrorAction Stop)
	$CommonFunctions = (Get-ChildItem -Path $MyPath -ErrorAction stop | Where-Object {$_.Name -inotmatch $Exclude -and $_.Name -notin $VarDefFiles} ) |
	Where-Object {$_.Name -inotmatch $Exclude}

	foreach ($Item in $CommonFunctions)
	{
		If ($FInfoOn)
		{
			$Msg = 'Processing Function:[{0}]' -f $Item.FullName
			Write-Information -MessageData $Msg -InformationAction Continue
		}
		. $Item.FullName
		if (-not (Get-Command $Item.BaseName -CommandType Function -ErrorAction SilentlyContinue))
		{Write-Host "Function [$($Item.BaseName)] was NOT created by file [$($Item.Name)]"}
		else
		{
			$funcName = $Item.BaseName
			# Export all if env var set, otherwise check export table
			$shouldExport = $ExportAll -or $true  # Default to export if not in table
			if (-not $ExportAll -and $script:FunctionExportTable -and $script:FunctionExportTable.ContainsKey($funcName)) 
			{$shouldExport = $script:FunctionExportTable[$funcName]}
			if ($shouldExport) 
			{Export-ModuleMember -Function $funcName -ErrorAction Stop}
		}
	}

	# OS-specific functions 2=Windows 4=Linux 6=MacOS
	switch ([System.Environment]::OSVersion.Platform.value__) {
		2
		{
			Publish-MyEnvironment -Option 'Windows'
			$VarDefFiles = @($PSD1Data.PrivateData.ModuleVars['Windows'].Values)
			$Exclude = @('Define-CustomXML|{0}$' -f $StrExtZip)
			$WinFunctions = Get-ChildItem (Join-Path $ModuleScriptRoot -ChildPath 'FunctionsWindows\*.ps1') |
			Where-Object {$_.Name -inotmatch $Exclude -and $_.Name -notin $VarDefFiles}

			foreach ($Item in $WinFunctions)
			{
				If ($FInfoOn)
				{
					$Msg = 'Processing Function:[{0}]' -f $Item.FullName
					Write-Information -MessageData $Msg -InformationAction Continue
				}
				. $Item.FullName
				if (-not (Get-Command $Item.BaseName -CommandType Function -ErrorAction SilentlyContinue))
				{Write-Host "Function [$($Item.BaseName)] was NOT created by file [$($Item.Name)]"}
				else
				{
					$funcName = $Item.BaseName
					$shouldExport = $ExportAll -or $true
					if (-not $ExportAll -and $script:FunctionExportTable -and $script:FunctionExportTable.ContainsKey($funcName)) 
					{$shouldExport = $script:FunctionExportTable[$funcName]}
					if ($shouldExport) 
					{Export-ModuleMember -Function $funcName -ErrorAction Stop}
				}
			}
		}
		4
		{
			Publish-MyEnvironment -Option 'Linux'
			$LinFunctions = Get-ChildItem (Join-Path $ModuleScriptRoot -ChildPath 'FunctionsLinux\*.ps1') |
			Where-Object {$_.Name -inotmatch $Exclude}

			foreach ($Item in $LinFunctions)
			{
				If ($FInfoOn)
				{
					$Msg = 'Processing Function:[{0}]' -f $Item.FullName
					Write-Information -MessageData $Msg -InformationAction Continue
				}
				. $Item.FullName
				if (-not (Get-Command $Item.BaseName -CommandType Function -ErrorAction SilentlyContinue))
				{Write-Host "Function [$($Item.BaseName)] was NOT created by file [$($Item.Name)]"}
				else
				{
					$funcName = $Item.BaseName
					$shouldExport = $ExportAll -or $true
					if (-not $ExportAll -and $script:FunctionExportTable -and $script:FunctionExportTable.ContainsKey($funcName)) 
					{$shouldExport = $script:FunctionExportTable[$funcName]}
					if ($shouldExport) 
					{Export-ModuleMember -Function $funcName -ErrorAction Stop}
				}
			}
		}
		6
		{
			Publish-MyEnvironment -Option 'MacOS'
			$MacFunctions = Get-ChildItem (Join-Path $ModuleScriptRoot -ChildPath 'FunctionsMacOS\*.ps1') |
			Where-Object {$_.Name -inotmatch $Exclude}

			foreach ($Item in $MacFunctions)
			{
				If ($FInfoOn)
				{
					$Msg = 'Processing Function:[{0}]' -f $Item.FullName
					Write-Information -MessageData $Msg -InformationAction Continue
				}
				. $Item.FullName
				if (-not (Get-Command $Item.BaseName -CommandType Function -ErrorAction SilentlyContinue))
				{Write-Host "Function [$($Item.BaseName)] was NOT created by file [$($Item.Name)]"}
				else
				{
					$funcName = $Item.BaseName
					$shouldExport = $ExportAll -or $true
					if (-not $ExportAll -and $script:FunctionExportTable -and $script:FunctionExportTable.ContainsKey($funcName)) 
					{$shouldExport = $script:FunctionExportTable[$funcName]}
					if ($shouldExport) 
					{Export-ModuleMember -Function $funcName -ErrorAction Stop}
				}
			}
		}
		default 
		{throw 'Operating System Unknown'}
	}
}
catch 
{
	Write-Warning "Module initialization failed: $($_.Exception.Message)"
	throw "Unable to initialise module: $ModuleName"
}
