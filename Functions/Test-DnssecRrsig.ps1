function Test-DnssecRrsig 
{
	param(
		[DnsRrsigRecord]$Rrsig,
		[DnsResourceRecord[]]$Rrset,
		[DnsResourceRecord[]]$DnskeyRrset
	)

	if (-not (Test-DnssecTimeWindow -Rrsig $Rrsig)) 
	{
		return [pscustomobject]@{
			Valid  = $false
			Reason = 'RRSIG not valid at current time'
		}
	}

	$dnskeyRR = Get-DnssecSigningKey -Rrsig $Rrsig -DnskeyRrset $DnskeyRrset
	if (-not $dnskeyRR) 
	{
		return [pscustomobject]@{
			Valid  = $false
			Reason = "No matching DNSKEY for key tag $($Rrsig.KeyTag)"
		}
	}
	$Dnskey = [DnsDnskeyRecord]$dnskeyRR.RData

	$SignedData = Get-DnssecSignedData -Rrsig $Rrsig -Rrset $Rrset

	$ok = Test-DnssecSignature -SignedData $SignedData -Rrsig $Rrsig -Dnskey $Dnskey

	return [pscustomobject]@{
		Valid  = $ok
		Reason = if ($ok) 
		{'OK'}
		else 
		{'Cryptographic signature check failed'}
	}
}