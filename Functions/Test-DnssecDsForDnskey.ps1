function Test-DnssecDsForDnskey 
{
	param(
		[psobject[]]$DsRrset,
		[psobject[]]$DnskeyRrset,
		[string]$ChildZoneName
	)

	$results = @()

	foreach ($dsObj in $DsRrset) 
	{
		$ds = $dsObj.RData
		$match = $false

		foreach ($keyObj in $DnskeyRrset) 
		{
			$Dnskey = $keyObj.RData

			if ($Dnskey.KeyTag -ne $ds.KeyTag) 
			{continue}
			if ($Dnskey.Algorithm -ne $ds.Algorithm) 
			{continue}

			$digest = Get-DnssecKeyDigest -OwnerName $ChildZoneName -Dnskey $Dnskey -DigestType $ds.DigestType

			if ($digest.SequenceEqual($ds.Digest)) 
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