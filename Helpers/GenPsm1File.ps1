# GenPsm1File.ps1 - Generates DnsTools.psm1 from class files and tail script
# Location: Helpers folder
# NOTE: If this file or DnsTools-psm1-Tail.ps1 is edited, run this script and deploy changes

$ModuleRoot = Split-Path -Path $PSScriptRoot -Parent

$ClassFiles = @(
	# Binary infrastructure
	"$ModuleRoot\Classes\BinaryInfrastructure\DnsBinaryWriter.ps1"
	"$ModuleRoot\Classes\BinaryInfrastructure\DnsBinaryReader.ps1"

	# Core DNS structures
	"$ModuleRoot\Classes\Core\DnsHeader.ps1"
	"$ModuleRoot\Classes\Core\DnsQuestion.ps1"

	# Basic RR types
	"$ModuleRoot\Classes\Basic\DnsARecord.ps1"
	"$ModuleRoot\Classes\Basic\DnsAaaaRecord.ps1"
	"$ModuleRoot\Classes\Basic\DnsCnameRecord.ps1"
	"$ModuleRoot\Classes\Basic\DnsMxRecord.ps1"
	"$ModuleRoot\Classes\Basic\DnsTxtRecord.ps1"
	"$ModuleRoot\Classes\Basic\DnsSrvRecord.ps1"
	"$ModuleRoot\Classes\Basic\DnsNsRecord.ps1"
	"$ModuleRoot\Classes\Basic\DnsPtrRecord.ps1"
	"$ModuleRoot\Classes\Basic\DnsSoaRecord.ps1"
	"$ModuleRoot\Classes\Basic\DnsCaaRecord.ps1"
	"$ModuleRoot\Classes\Basic\DnsDnameRecord.ps1"
	"$ModuleRoot\Classes\Basic\DnsNaptrRecord.ps1"
	"$ModuleRoot\Classes\Basic\DnsSshfpRecord.ps1"
	"$ModuleRoot\Classes\Basic\DnsTlsaRecord.ps1"
	"$ModuleRoot\Classes\Basic\DnsRpRecord.ps1"
	"$ModuleRoot\Classes\Basic\DnsIpsecKeyRecord.ps1"
	"$ModuleRoot\Classes\Basic\DnsOpenPgpKeyRecord.ps1"
	"$ModuleRoot\Classes\Basic\DnsUriRecord.ps1"

	# DNSSEC
	"$ModuleRoot\Classes\DnsSec\DnsDnskeyRecord.ps1"
	"$ModuleRoot\Classes\DnsSec\DnsDsRecord.ps1"
	"$ModuleRoot\Classes\DnsSec\DnsRrsigRecord.ps1"
	"$ModuleRoot\Classes\DnsSec\DnsNsecRecord.ps1"
	"$ModuleRoot\Classes\DnsSec\DnsNsec3Record.ps1"

	# Resource & EDNS
	"$ModuleRoot\Classes\Resource\DnsResourceRecord.ps1"
	"$ModuleRoot\Classes\EDNS-OPT\DnsOptRecord.ps1"

	# DNS packet
	"$ModuleRoot\Classes\DNS\DnsPacket.ps1"

	# Transport
	"$ModuleRoot\Classes\Transport\DnsDotClient.ps1"
	"$ModuleRoot\Classes\Transport\DnsDohClient.ps1"
)

$OutFile = "$ModuleRoot\DnsTools.psm1"
$TailFile = "$PSScriptRoot\DnsTools-psm1-Tail.ps1"

# Built in memory and written ONCE with an explicit UTF-8 BOM and CRLF, so the result is byte-identical whichever
# host runs this (Out-File -Encoding UTF8 writes a BOM under Windows PowerShell 5.1 but NOT under PowerShell 7, which
# made the output depend on the host). The release chain and the test wrappers run this before anything else.
$Utf8 = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
$Lines = New-Object -TypeName System.Collections.Generic.List[string]

$Lines.Add('#requires -Version 5.0')
$Lines.Add('')
$Lines.Add('Set-StrictMode -Version Latest')
$Lines.Add('')
$Lines.Add('# ============================================================')
$Lines.Add('# Load Classes')
$Lines.Add('# ============================================================')
$Lines.Add('')

foreach ($item in $ClassFiles) {
	if (Test-Path -Path $item) {
		$Lines.AddRange([string[]][System.IO.File]::ReadAllLines($item, $Utf8))
	} else {
		Write-Error "Class file not found: $item"
		exit 1
	}
}

$Lines.Add('')
$Lines.AddRange([string[]][System.IO.File]::ReadAllLines($TailFile, $Utf8))

$Text = ($Lines -join "`r`n") + "`r`n"
[System.IO.File]::WriteAllText($OutFile, $Text, (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $true))

Write-Host "Generated: $OutFile" -ForegroundColor Green
