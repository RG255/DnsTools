function Test-DnssecAnchoredDnskey
{
	<#
	.SYNOPSIS
		Verifies a DNSKEY against a configured trust anchor.

	.DESCRIPTION
		Checks if a DNSKEY matches a configured trust anchor for a zone, establishing the root of trust.

	.PARAMETER Zone
		The zone name to check.

	.PARAMETER Dnskey
		The DNSKEY record to verify.
	#>
	param(
		[string]$Zone,
		[DnsDnskeyRecord]$Dnskey
	)

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	$trustAnchorsVar = Get-Variable -Name TrustAnchors -Scope Script -ErrorAction SilentlyContinue
	if (-not $trustAnchorsVar -or -not $trustAnchorsVar.Value)
	{return $false}

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