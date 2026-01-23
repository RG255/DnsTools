function Find-DnssecNsec3ClosestEncloser 
{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$QueryName,

		[AllowEmptyCollection()]
		[object[]]$Nsec3Records,

		[Parameter(Mandatory)]
		[int]$HashAlgorithm,

		[Parameter(Mandatory)]
		[int]$Iterations,

		[Parameter(Mandatory)]
		[byte[]]$salt
	)

	#
	# Filter to real DnsNsec3Record instances.
	# This avoids Pester runspace binding issues where typed arrays bind as empty.
	#
	$records = $Nsec3Records | Where-Object -FilterScript {$_ -is [DnsNsec3Record]}

	if (-not $records -or $records.Count -eq 0) 
	{return $null}

	#
	# RFC 5155 canonical name handling:
	# - lowercase
	# - remove trailing dot for label splitting
	# - add trailing dot before hashing
	#
	$labels = $QueryName.ToLower().TrimEnd('.').Split('.')

	#
	# Walk from deepest label to shallowest
	#
	for ($i = 0; $i -lt $labels.Length; $i++) 
	{
		# Build candidate name: e.g. "b.example.com"
		$candidate = ($labels[$i..($labels.Length - 1)] -join '.')
		Write-Trace -False "CANDIDATE: '$candidate'"
			
		# Canonical form for hashing: MUST end with "."
		$canon = if ($candidate.EndsWith('.')) 
		{$candidate}
		else 
		{$candidate + '.'}

		# Compute NSEC3 hash for this candidate
		$hash = Get-DnssecNsec3Hash `
		-name $canon `
		-Algorithm $HashAlgorithm `
		-Iterations $Iterations `
		-salt $salt
		Write-Trace -False "HASH: $([BitConverter]::ToString($hash))"

		#
		# Match against OwnerHash (NOT NextHash)
		#
		foreach ($rec in $records) 
		{
			if ( ($rec.OwnerHash -join ',') -eq ($hash -join ',') )
			{
				return [pscustomobject]@{
					Name   = $candidate
					Hash   = $hash
					Record = $rec
				}
			}
		}
	}

	return $null
}