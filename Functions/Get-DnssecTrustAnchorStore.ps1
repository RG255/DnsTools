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
