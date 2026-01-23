function Test-DnssecAnchoredDnskey 
{
	param(
		[string]$Zone,
		[DnsDnskeyRecord]$Dnskey
	)

	if (-not $script:TrustAnchors.ContainsKey($Zone)) 
	{return $false}

	$anchor = $script:TrustAnchors[$Zone]

	# HARDENING GOES HERE
	if ($null -eq $anchor) 
	{return $false}

	if ($Dnskey.KeyTag -ne $anchor.KeyTag) 
	{return $false}
	if ($Dnskey.Algorithm -ne $anchor.Algorithm) 
	{return $false}

	$digest = Get-DnssecKeyDigestHex -OwnerName $Zone -Dnskey $Dnskey -DigestType $anchor.DigestType

	return ($digest -eq $anchor.DigestHex)
}