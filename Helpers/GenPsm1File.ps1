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

If (Test-Path -Path $OutFile) {
	Remove-Item -Path $OutFile
}

'#requires -Version 5.0' | Out-File -Append -FilePath $OutFile -Encoding UTF8
'' | Out-File -Append -FilePath $OutFile -Encoding UTF8
'Set-StrictMode -Version Latest' | Out-File -Append -FilePath $OutFile -Encoding UTF8
'' | Out-File -Append -FilePath $OutFile -Encoding UTF8
'# ============================================================' | Out-File -Append -FilePath $OutFile -Encoding UTF8
'# Load Classes' | Out-File -Append -FilePath $OutFile -Encoding UTF8
'# ============================================================' | Out-File -Append -FilePath $OutFile -Encoding UTF8
'' | Out-File -Append -FilePath $OutFile -Encoding UTF8

foreach ($item in $ClassFiles) {
	if (Test-Path $item) {
		Get-Content -Path $item | Out-File -Append -FilePath $OutFile -Encoding UTF8
	} else {
		Write-Warning "Class file not found: $item"
	}
}

'' | Out-File -Append -FilePath $OutFile -Encoding UTF8
Get-Content -Path $TailFile | Out-File -Append -FilePath $OutFile -Encoding UTF8

Write-Host "Generated: $OutFile" -ForegroundColor Green
