function Add-DnssecTrustAnchor
{
	<#
	.SYNOPSIS
		Adds a DNSSEC trust anchor for a zone.

	.DESCRIPTION
		Registers a DNSSEC trust anchor (DS record) for a specified zone to establish the chain of trust.

	.PARAMETER Zone
		The DNS zone name for the trust anchor.

	.PARAMETER keyTag
		The key tag of the DNSKEY record.

	.PARAMETER Algorithm
		The cryptographic algorithm number.

	.PARAMETER DigestType
		The digest algorithm type.

	.PARAMETER DigestHex
		The hexadecimal digest value.
	#>
	param(
		[string]$Zone,
		[uint16]$keyTag,
		[byte]$Algorithm,
		[byte]$DigestType,
		[string]$DigestHex
	)

	$trustAnchorsVar = Get-Variable -Name TrustAnchors -Scope Script -ErrorAction SilentlyContinue
	if (-not $trustAnchorsVar)
	{$script:TrustAnchors = @{}}

	$script:TrustAnchors[$Zone] = [pscustomobject]@{
		KeyTag     = $keyTag
		Algorithm  = $Algorithm
		DigestType = $DigestType
		DigestHex  = $DigestHex.ToLower()
	}
}
