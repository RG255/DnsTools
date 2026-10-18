function Resolve-DnssecZone
{
	<#
		.SYNOPSIS
		Validates one zone's DNSSEC chain of trust and returns its authenticated DNSKEY records.

		.DESCRIPTION
		0.8: now a thin wrapper over Get-DnssecTrustedKey. The zone is valid only if its DNSKEY RRset chains to
		the configured root trust anchor: parent keys authenticated, DS RRset signed by the parent, DNSKEY
		matched by the DS and signed by a DS-matched key. The pre-0.8 version only matched the DS digest
		against a live DNSKEY RRset and never verified the DS signature or anchored the root.

		.PARAMETER Zone
		The zone to validate (absolute name, e.g. 'com.', 'cloudflare.com.').

		.PARAMETER ParentZone
		The parent zone name; kept for compatibility, the parent is derived from Zone.

		.PARAMETER RootServers
		Array of root server IP addresses to use for resolution (defaults to module-configured root servers).

		.PARAMETER Trace
		Accepted for compatibility; use -Verbose for diagnostics.

		.OUTPUTS
		[PSCustomObject] with Valid ([bool]), Reason ([string]), Dnskeys (the authenticated DNSKEY records,
		or an empty array when not valid).

		.EXAMPLE
		Resolve-DnssecZone -Zone 'com.' -ParentZone '.'
	#>
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
		Justification = 'ParentZone and Trace are kept so existing callers keep binding; the parent is derived from Zone.')]
	[CmdletBinding()]
	[OutputType([PSCustomObject])]
	Param (
		[Parameter(Mandatory)]
		[string]$Zone,

		[Parameter(Mandatory)]
		[string]$ParentZone,

		[string[]]$RootServers = $script:RootServerAddresses,

		[switch]$Trace
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	try {
		$trust = Get-DnssecTrustedKey -Zone $Zone -RootServers $RootServers
		if ($trust.Status -eq 'Secure')
		{
			return [PSCustomObject]@{
				Valid   = $true
				Reason  = "Zone $Zone validated: $($trust.Reason)"
				Dnskeys = @($trust.Dnskeys)
			}
		}

		return [PSCustomObject]@{
			Valid   = $false
			Reason  = "Zone $Zone not validated ($($trust.Status)): $($trust.Reason)"
			Dnskeys = @()
		}
	}
	catch {
		Write-MyCatchAudit -Source "Resolve-DnssecZone: unexpected error validating zone $Zone" -ErrorRecord $_
		return [PSCustomObject]@{
			Valid   = $false
			Reason  = "Unexpected error validating $Zone : $($_.Exception.Message)"
			Dnskeys = @()
		}
	}
}
