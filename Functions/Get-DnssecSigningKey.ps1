function Get-DnssecSigningKey
{
	<#
	.SYNOPSIS
		Finds the DNSKEY that matches an RRSIG signature.

	.DESCRIPTION
		Searches a DNSKEY RRset for the key that matches the algorithm and key tag in an RRSIG record.

	.PARAMETER Rrsig
		The RRSIG record to match.

	.PARAMETER DnskeyRrset
		The DNSKEY RRset to search.
	#>
	param(
		[DnsRrsigRecord]$Rrsig,
		[DnsResourceRecord[]]$DnskeyRrset
	)

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	$candidates = $DnskeyRrset |
		Where-Object -FilterScript {
			$_.Type -eq 48 -and $_.RDataObject -is [DnsDnskeyRecord] -and
			$_.RDataObject.KeyTag -eq $Rrsig.KeyTag -and
			$_.RDataObject.Algorithm -eq $Rrsig.Algorithm
		}

	return $candidates | Select-Object -First 1
}