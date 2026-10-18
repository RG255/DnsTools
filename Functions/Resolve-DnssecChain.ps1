function Resolve-DnssecChain
{
	<#
		.SYNOPSIS
		Validates the complete DNSSEC chain of trust for a domain name.

		.DESCRIPTION
		Resolves the name and validates the answer with Resolve-Dnssec, which authenticates each signing zone's
		DNSKEY RRset from the configured root trust anchor down (root DNSKEY anchored, then for each zone a
		parent-signed DS, a DS-authenticated DNSKEY, and a DNSKEY RRset signed by that key). Chain holds the
		authenticated DNSKEY records for every signing zone involved, keyed by zone name.

		0.8: the previous version loaded the root anchor and then never used it, and walked every label of the
		host name as if it were a zone. The walk is now driven by the RRSIG signer names, so a host name that
		is not a zone apex no longer breaks it.

		.PARAMETER name
		The fully qualified domain name to validate.

		.PARAMETER type
		The DNS record type to query (default: A).

		.PARAMETER RootServers
		Array of root server IP addresses to use for resolution (defaults to module-configured root servers).

		.PARAMETER Trace
		Enable verbose trace output for debugging DNSSEC validation.
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$name,

		$type = 'A',

		[Parameter(DontShow)]
		[string[]]$RootServers = $script:RootServerAddresses,

		[switch]$Trace
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	try {

		$leaf = Resolve-Dnssec -name $name -type $type -RootServers $RootServers -Trace:$Trace

		$chain = if ($leaf.PSObject.Properties['Chain'])
		{$leaf.Chain}
		else
		{@{}}

		if (-not $leaf.Valid)
		{
			return [pscustomobject]@{
				Valid  = $false
				Reason = "Validation failed: $($leaf.Reason)"
				Chain  = $chain
				Leaf   = $leaf
			}
		}

		return [pscustomobject]@{
			Valid  = $true
			Reason = 'Full chain validated'
			Chain  = $chain
			Leaf   = $leaf
		}

	}
	catch {
		Write-MyCatchAudit -Source 'Resolve-DnssecChain: unexpected error during chain validation' -ErrorRecord $_
		return [pscustomobject]@{
			Valid  = $false
			Reason = "Unexpected error during chain validation: $($_.Exception.Message)"
			Chain  = $null
		}
	}
}
