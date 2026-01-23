function Get-DnssecSigningKey 
{
	param(
		[DnsRrsigRecord]$Rrsig,
		[DnsResourceRecord[]]$DnskeyRrset
	)

	$candidates = $DnskeyRrset |
	Where-Object -FilterScript {
		$_.Type -eq 48 -and $_.RData -is [DnsDnskeyRecord] -and
		$_.RData.KeyTag -eq $Rrsig.KeyTag -and
		$_.RData.Algorithm -eq $Rrsig.Algorithm
	}

	return $candidates | Select-Object -First 1
}