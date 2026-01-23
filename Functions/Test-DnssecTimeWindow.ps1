function Test-DnssecTimeWindow 
{
	param(
		[DnsRrsigRecord]$Rrsig
	)

	$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

	if ($now -lt $Rrsig.Inception) 
	{return $false}

	if ($now -gt $Rrsig.Expiration) 
	{return $false}

	return $true
}