function Get-DnssecZonePath
{
	<#
		.SYNOPSIS
		Splits a DNS name into its chain of zones from the root down to the name itself.

		.DESCRIPTION
		2026-09-15. Written to fill a real gap: Resolve-DnssecChain.ps1 already called this function by
		name, but it had never been implemented anywhere in the module (confirmed via a repo-wide grep -
		zero definitions, including in the retired 0.5/0.6 copies of Resolve-DnssecChain.ps1, which have
		the identical call). This is a straight extraction of the zone-list logic
		Test-DnssecValidation.ps1 already builds inline (its own "Step 2: Build zone path" block) into a
		reusable function, so Resolve-DnssecChain's zone-by-zone walk has the same zone list that
		function already relies on.

		For 'www.cloudflare.com' returns: '.', 'com.', 'cloudflare.com.', 'www.cloudflare.com.' - root
		first, most specific last, each entry a valid absolute (trailing-dot) zone name so it can be
		passed straight to Resolve-DnsIterative's -Name.

		.PARAMETER Name
		The DNS name to split into its zone path. A single trailing dot is permitted and ignored.

		.OUTPUTS
		[string[]] - the zone path, root ('.') first.

		.EXAMPLE
		Get-DnssecZonePath -Name 'www.cloudflare.com'
		'.', 'com.', 'cloudflare.com.', 'www.cloudflare.com.'
	#>
	[CmdletBinding()]
	[OutputType([string[]])]
	Param (
		[Parameter(Mandatory)]
		[string]$Name
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	$Private:Fqdn = $Name.TrimEnd('.').ToLower()

	$Private:Zones = @('.')
	if ([string]::IsNullOrEmpty($Private:Fqdn)) {
		return $Private:Zones
	}

	$Private:Labels = $Private:Fqdn.Split('.')
	for ($Private:i = $Private:Labels.Count - 1; $Private:i -ge 0; $Private:i--) {
		$Private:Zones += (($Private:Labels[$Private:i..($Private:Labels.Count - 1)] -join '.') + '.')
	}

	return $Private:Zones
}
