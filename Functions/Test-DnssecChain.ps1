function Test-DnssecChain
{
	<#
	.SYNOPSIS
		Validates a complete DNSSEC chain for a zone.

	.DESCRIPTION
		Verifies the DNSSEC chain by checking DS-to-DNSKEY matching and RRSIG signatures.

	.PARAMETER DnskeyRrset
		The DNSKEY RRset for the zone.

	.PARAMETER DsRrset
		The DS RRset from the parent zone.

	.PARAMETER RrsigRrset
		The RRSIG RRset covering the DNSKEY.

	.PARAMETER ZoneName
		The name of the zone being validated.
	#>
	param(
		[DnsResourceRecord[]]$DnskeyRrset,
		[DnsResourceRecord[]]$DsRrset,
		[DnsResourceRecord[]]$RrsigRrset,
		[string]$ZoneName
	)

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	$dnskeys = $DnskeyRrset | ForEach-Object -Process {$_.RDataObject}
	$dsRecords = $DsRrset | ForEach-Object -Process {$_.RDataObject}
	$rrsigs = $RrsigRrset | ForEach-Object -Process {$_.RDataObject}

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

		$ok = Test-DnssecRrsig -Rrsig $sig -Rrset $DnskeyRrset -DnskeyRrset $DnskeyRrset
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