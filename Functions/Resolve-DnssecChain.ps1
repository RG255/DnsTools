function Resolve-DnssecChain 
{
	param(
		[string]$name,
		[int]$type = 1,
		[string[]]$RootServers = @(...),
		[switch]$Trace
	)

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
	$leaf = Resolve-Dnssec -name $name -type $type -RootServers $RootServers -Trace:$Trace

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