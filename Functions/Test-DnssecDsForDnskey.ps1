function Test-DnssecDsForDnskey
{
	<#
	.SYNOPSIS
		Validates that DS records match DNSKEY records.

	.DESCRIPTION
		Verifies that delegation signer (DS) records correctly reference DNSKEY records in a child zone.

	.PARAMETER DsRrset
		The DS RRset from the parent zone.

	.PARAMETER DnskeyRrset
		The DNSKEY RRset from the child zone.

	.PARAMETER ChildZoneName
		The name of the child zone.
	#>
	param(
		[psobject[]]$DsRrset,
		[psobject[]]$DnskeyRrset,
		[string]$ChildZoneName
	)

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	$results = @()

	foreach ($dsObj in $DsRrset)
	{
		$ds = $dsObj.RDataObject
		$match = $false

		foreach ($keyObj in $DnskeyRrset)
		{
			$Dnskey = $keyObj.RDataObject

			if ($Dnskey.KeyTag -ne $ds.KeyTag) 
			{continue}
			if ($Dnskey.Algorithm -ne $ds.Algorithm) 
			{continue}

			$digest = Get-DnssecKeyDigest -OwnerName $ChildZoneName -Dnskey $Dnskey -DigestType $ds.DigestType

			if ([System.Linq.Enumerable]::SequenceEqual([byte[]]$digest, [byte[]]$ds.Digest)) 
			{
				$match = $true
				break
			}
		}

		$results += [pscustomobject]@{
			DsRecord = $ds
			Valid    = $match
		}
	}

	return $results
}