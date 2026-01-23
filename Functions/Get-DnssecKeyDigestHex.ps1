function Get-DnssecKeyDigestHex 
{
	param(
		[string]$OwnerName,
		[DnsDnskeyRecord]$Dnskey,
		[int]$DigestType
	)

	# Compute raw digest bytes
	$digest = [byte[]](Get-DnssecKeyDigest `
		-OwnerName $OwnerName `
		-Dnskey $Dnskey `
	-DigestType $DigestType)

	# Convert to lowercase hex without widening
	$sb = New-Object -TypeName System.Text.StringBuilder
	foreach ($b in $digest) 
	{[void]$sb.AppendFormat('{0:x2}', $b)}

	return $sb.ToString()
}
