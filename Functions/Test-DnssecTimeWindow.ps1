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

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

	if ($now -lt $Rrsig.Inception)
	{return $false}

	if ($now -gt $Rrsig.Expiration)
	{return $false}

	return $true
}
