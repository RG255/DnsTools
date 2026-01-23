function Get-DnssecTrustAnchors 
{
	if (-not $script:TrustAnchors) 
	{return @()}

	return $script:TrustAnchors.GetEnumerator() | ForEach-Object -Process {
		[pscustomobject]@{
			Zone       = $_.Key
			KeyTag     = $_.Value.KeyTag
			Algorithm  = $_.Value.Algorithm
			DigestType = $_.Value.DigestType
			DigestHex  = $_.Value.DigestHex
		}
	}
}