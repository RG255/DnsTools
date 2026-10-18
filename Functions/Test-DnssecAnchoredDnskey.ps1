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

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	$trustAnchorsVar = Get-Variable -Name TrustAnchors -Scope Script -ErrorAction SilentlyContinue
	if (-not $trustAnchorsVar -or -not $trustAnchorsVar.Value)
	{return $false}

	if (-not $script:TrustAnchors.ContainsKey($Zone))
	{return $false}

	# A zone can hold several anchors (the root has more than one KSK digest): any match anchors the key.
	foreach ($anchor in @($script:TrustAnchors[$Zone]))
	{
		if ($null -eq $anchor)
		{continue}

		if ($Dnskey.KeyTag -ne $anchor.KeyTag)
		{continue}
		if ($Dnskey.Algorithm -ne $anchor.Algorithm)
		{continue}

		try
		{$digest = Get-DnssecKeyDigestHex -OwnerName $Zone -Dnskey $Dnskey -DigestType $anchor.DigestType}
		catch
		{
			Write-MyCatchAudit -Source 'Test-DnssecAnchoredDnskey: digest computation failed for one anchor - trying the next is correct, the key is simply not anchored by this one' -ErrorRecord $_
			continue
		}

		if ($digest -ieq $anchor.DigestHex)
		{return $true}
	}

	return $false
}
