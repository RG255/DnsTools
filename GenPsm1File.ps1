$ClassFiles     = @(
	# Binary infrastructure
	"$PSScriptRoot\Classes\BinaryInfrastructure\DnsBinaryWriter.ps1"
	"$PSScriptRoot\Classes\BinaryInfrastructure\DnsBinaryReader.ps1"

	# Core DNS structures
	"$PSScriptRoot\Classes\Core\DnsHeader.ps1"
	"$PSScriptRoot\Classes\Core\DnsQuestion.ps1"

	# Basic RR types
	"$PSScriptRoot\Classes\Basic\DnsARecord.ps1"
	"$PSScriptRoot\Classes\Basic\DnsAaaaRecord.ps1"
	"$PSScriptRoot\Classes\Basic\DnsCnameRecord.ps1"
	"$PSScriptRoot\Classes\Basic\DnsMxRecord.ps1"
	"$PSScriptRoot\Classes\Basic\DnsTxtRecord.ps1"
	"$PSScriptRoot\Classes\Basic\DnsSrvRecord.ps1"
	"$PSScriptRoot\Classes\Basic\DnsNsRecord.ps1"

	# DNSSEC
	"$PSScriptRoot\Classes\DnsSec\DnsDnskeyRecord.ps1"
	"$PSScriptRoot\Classes\DnsSec\DnsDsRecord.ps1"
	"$PSScriptRoot\Classes\DnsSec\DnsRrsigRecord.ps1"
	"$PSScriptRoot\Classes\DnsSec\DnsNsecRecord.ps1"
	"$PSScriptRoot\Classes\DnsSec\DnsNsec3Record.ps1"

	# Resource & EDNS
	"$PSScriptRoot\Classes\Resource\DnsResourceRecord.ps1"
	"$PSScriptRoot\Classes\EDNS-OPT\DnsOptRecord.ps1"

	# DNS packet
	"$PSScriptRoot\Classes\DNS\DnsPacket.ps1"

	# Transport
	"$PSScriptRoot\Classes\Transport\DnsDotClient.ps1"
	"$PSScriptRoot\Classes\Transport\DnsDohClient.ps1"
)
$OutFile="D:\PowerShellScripts\DnsTools\0.4\DnsTools.psm1"
$TailFile="D:\PowerShellScripts\DnsTools\0.4\DnsTools-psm1-Tail.ps1"
If (test-path -path $OutFile)
{Remove-Item -Path $OutFile}
'#requires -Version 5.0' | Out-File -Append -FilePath $outfile -Encoding UTF8
'' | Out-File -Append -FilePath $outfile -Encoding UTF8
'Set-StrictMode -Version Latest' | Out-File -Append -FilePath $outfile -Encoding UTF8
'' | Out-File -Append -FilePath $outfile -Encoding UTF8
'# ============================================================' | Out-File -Append -FilePath $outfile -Encoding UTF8
'# Load Classes' | Out-File -Append -FilePath $outfile -Encoding UTF8
'# ============================================================' | Out-File -Append -FilePath $outfile -Encoding UTF8
'' | Out-File -Append -FilePath $outfile -Encoding UTF8

foreach ($item in $ClassFiles)
{
	Get-Content -Path $Item |
	Out-File -Append -FilePath $outfile -Encoding UTF8
}
'' | Out-File -Append -FilePath $outfile -Encoding UTF8
Get-Content -path $TailFile | Out-File -Append -FilePath $outfile -Encoding UTF8