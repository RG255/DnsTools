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

	# Append to the zone's anchor list (a zone can have several). An identical anchor is not added twice.
	$zoneKey = $Zone.Trim().ToLower()
	if ($zoneKey -eq '')
	{$zoneKey = '.'}

	$existing = @()
	if ($script:TrustAnchors.ContainsKey($zoneKey))
	{$existing = @($script:TrustAnchors[$zoneKey])}

	$duplicate = @($existing | Where-Object -FilterScript {
			$_.KeyTag -eq $keyTag -and $_.Algorithm -eq $Algorithm -and $_.DigestType -eq $DigestType -and $_.DigestHex -eq $DigestHex.ToLower()
		})
	if ($duplicate.Count -eq 0)
	{
		$script:TrustAnchors[$zoneKey] = @($existing) + @([pscustomobject]@{
				KeyTag     = $keyTag
				Algorithm  = $Algorithm
				DigestType = $DigestType
				DigestHex  = $DigestHex.ToLower()
			})
	}
}
