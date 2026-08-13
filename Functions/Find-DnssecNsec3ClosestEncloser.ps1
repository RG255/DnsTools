function Find-DnssecNsec3ClosestEncloser
{
	<#
	.SYNOPSIS
		Finds the closest encloser in NSEC3 denial of existence proofs.

	.DESCRIPTION
		Searches NSEC3 records to find the closest existing ancestor of a queried name for authenticated denial of existence.

	.PARAMETER QueryName
		The domain name that was queried.

	.PARAMETER Nsec3Records
		The NSEC3 records to search.

	.PARAMETER HashAlgorithm
		The NSEC3 hash algorithm.

	.PARAMETER Iterations
		The number of hash iterations used.
	#>
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
		[byte[]]$salt,

		[switch]$Trace
	)

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	#
	# Filter to real DnsNsec3Record instances.
	# This avoids Pester runspace binding issues where typed arrays bind as empty.
	#
	$records = @($Nsec3Records | Where-Object -FilterScript {$_ -is [DnsNsec3Record]})

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
		if ($Trace) { Write-Trace -Message "CANDIDATE: '$candidate'" }

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
		if ($Trace) { Write-Trace -Message "HASH: $([BitConverter]::ToString($hash))" }

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