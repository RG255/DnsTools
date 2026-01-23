function Add-DnssecTrustAnchor 
{
	param(
		[string]$Zone,
		[uint16]$keyTag,
		[byte]$Algorithm,
		[byte]$DigestType,
		[string]$DigestHex
	)

	if (-not $script:TrustAnchors) 
	{$script:TrustAnchors = @{}}

	$script:TrustAnchors[$Zone] = [pscustomobject]@{
		KeyTag     = $keyTag
		Algorithm  = $Algorithm
		DigestType = $DigestType
		DigestHex  = $DigestHex.ToLower()
	}
}
