function Test-DnssecChain 
{
	param(
		[DnsResourceRecord[]]$DnskeyRrset,
		[DnsResourceRecord[]]$DsRrset,
		[DnsResourceRecord[]]$RrsigRrset,
		[string]$ZoneName
	)

	$dnskeys = $DnskeyRrset | ForEach-Object -Process {$_.RData}
	$dsRecords = $DsRrset | ForEach-Object -Process {$_.RData}
	$rrsigs = $RrsigRrset | ForEach-Object -Process {$_.RData}

	$dsCheck = Test-DnssecDsForDnskey -DsRrset $DsRrset -DnskeyRrset $DnskeyRrset -ChildZoneName $ZoneName

	if (-not ($dsCheck.Valid -contains $true)) 
	{
		return [pscustomobject]@{
			Valid  = $false
			Reason = 'No DNSKEY matches DS'
		}
	}

	foreach ($sigObj in $RrsigRrset) 
	{
		$sig = $sigObj.RDataObject
		$key = $dnskeys |
		Where-Object -FilterScript {$_.KeyTag -eq $sig.KeyTag -and $_.Algorithm -eq $sig.Algorithm} |
		Select-Object -First 1

		if (-not $key) 
		{
			return [pscustomobject]@{
				Valid  = $false
				Reason = 'No matching DNSKEY for RRSIG'
			}
		}

		$ok = Test-DnssecRrsig -Rrsig $sig -Rrset $DnskeyRrset -DnskeyRrset $key.RdataObject
		if (-not $ok) 
		{
			return [pscustomobject]@{
				Valid  = $false
				Reason = 'RRSIG validation failed'
			}
		}
	}

	return [pscustomobject]@{
		Valid  = $true
		Reason = 'DNSSEC chain validated'
	}
}