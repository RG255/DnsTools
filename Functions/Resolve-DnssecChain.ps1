function Resolve-DnssecChain
{
	<#
	.SYNOPSIS
		Validates the complete DNSSEC chain of trust for a domain name.

	.DESCRIPTION
		Walks the DNSSEC chain from the root zone through all intermediate zones to validate the full chain of trust.

	.PARAMETER name
		The fully qualified domain name to validate.

	.PARAMETER type
		The DNS record type to query (default: 1 = A record).

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

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	# Convert type name to code if needed
	$TypeCode = ConvertTo-DnsTypeCode -Type $type

	# 1. Load root trust anchor (hard-coded DNSKEY RRset for ".")
	$rootKeys = Get-RootTrustAnchor

	# 2. Walk labels from right to left:
	#    ".", "com.", "cloudflare.com."
	$zones = Get-DnssecZonePath -Name $name  # returns [".", "com.", "cloudflare.com."]

	$validatedZones = @{}
	$validatedZones['.'] = $rootKeys  # trust anchor

	for ($i = 1; $i -lt $zones.Count; $i++) 
	{
		$child  = $zones[$i]
		$parent = $zones[$i - 1]

		$zoneResult = Resolve-DnssecZone -Zone $child -ParentZone $parent -RootServers $RootServers -Trace:$Trace

		if (-not $zoneResult.Valid) 
		{
			return [pscustomobject]@{
				Valid  = $false
				Reason = "Zone validation failed for $child : $($zoneResult.Reason)"
				Chain  = $validatedZones
			}
		}

		$validatedZones[$child] = $zoneResult.Dnskeys
	}

	# 3. Finally, validate the RRset at $Name using the last zone's keys
	$leaf = Resolve-Dnssec -name $name -type $TypeCode -RootServers $RootServers -Trace:$Trace

	if (-not $leaf.Valid) 
	{
		return [pscustomobject]@{
			Valid  = $false
			Reason = "Leaf RRset validation failed: $($leaf.Reason)"
			Chain  = $validatedZones
			Leaf   = $leaf
		}
	}

	[pscustomobject]@{
		Valid  = $true
		Reason = 'Full chain validated'
		Chain  = $validatedZones
		Leaf   = $leaf
	}
}