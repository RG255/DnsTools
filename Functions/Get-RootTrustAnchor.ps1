function Get-RootTrustAnchor
{
	<#
		.SYNOPSIS
		Returns the configured DNSSEC trust anchor(s) for the root zone.

		.DESCRIPTION
		2026-09-15. Written to fill a real gap: Resolve-DnssecChain.ps1 already called this function by
		name, but it had never been implemented anywhere in the module (confirmed via a repo-wide grep -
		zero definitions, including in the retired 0.5/0.6 copies, which have the identical call).

		A thin, named wrapper over Get-DnssecTrustAnchorStore (already exported) filtered to Zone '.' -
		the root zone is the one entry Resolve-DnssecChain seeds its walk with before validating any
		child zone. Populated via Import-DnssecTrustAnchorFile / Update-DnssecTrustAnchorFile, same as
		every other trust anchor.

		Returns an empty array (never throws) if no root trust anchor is configured - this is a valid
		state (the module may not have imported one yet), not an error condition specific to this
		function; a caller that needs one to proceed can check for an empty result itself.

		.OUTPUTS
		[PSCustomObject[]] - zero or more trust anchor entries for zone '.' (Zone, KeyTag, Algorithm,
		DigestType, DigestHex), same shape as Get-DnssecTrustAnchorStore.

		.EXAMPLE
		Get-RootTrustAnchor
	#>
	[CmdletBinding()]
	[OutputType([PSCustomObject[]])]
	Param ()

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	return @(Get-DnssecTrustAnchorStore | Where-Object -FilterScript { $_.Zone -eq '.' })
}
