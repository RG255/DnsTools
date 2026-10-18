function Get-DnssecTrustAnchorStore
{
	<#
	.SYNOPSIS
		Retrieves all configured DNSSEC trust anchors.

	.DESCRIPTION
		Returns the list of currently configured DNSSEC trust anchors in the module.
	#>

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	$trustAnchorsVar = Get-Variable -Name TrustAnchors -Scope Script -ErrorAction SilentlyContinue
	if (-not $trustAnchorsVar -or -not $trustAnchorsVar.Value)
	{return @()}

	# One output object per anchor (a zone can hold several).
	foreach ($entry in $script:TrustAnchors.GetEnumerator())
	{
		foreach ($anchor in @($entry.Value))
		{
			[pscustomobject]@{
				Zone       = $entry.Key
				KeyTag     = $anchor.KeyTag
				Algorithm  = $anchor.Algorithm
				DigestType = $anchor.DigestType
				DigestHex  = $anchor.DigestHex
			}
		}
	}
}
