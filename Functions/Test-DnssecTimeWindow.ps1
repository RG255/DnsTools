function Test-DnssecTimeWindow
{
	<#
	.SYNOPSIS
		Checks if an RRSIG is within its validity time window.

	.DESCRIPTION
		Verifies that the current time falls between the RRSIG's inception and expiration timestamps.

	.PARAMETER Rrsig
		The RRSIG record to check.
	#>
	param(
		[DnsRrsigRecord]$Rrsig
	)

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

	if ($now -lt $Rrsig.Inception)
	{return $false}

	if ($now -gt $Rrsig.Expiration)
	{return $false}

	return $true
}