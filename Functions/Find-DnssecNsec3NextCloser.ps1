function Find-DnssecNsec3NextCloser
{
	<#
	.SYNOPSIS
		Finds the next closer name in NSEC3 denial of existence proofs.

	.DESCRIPTION
		Identifies the next closer name between the closest encloser and the query name for NSEC3 authenticated denial.

	.PARAMETER QueryName
		The domain name that was queried.

	.PARAMETER ClosestEncloserName
		The closest existing ancestor name.

	.PARAMETER Nsec3Records
		The NSEC3 records to search.

	.PARAMETER HashAlgorithm
		The NSEC3 hash algorithm.
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$QueryName,

		[Parameter(Mandatory)]
		[string]$ClosestEncloserName,

		[AllowEmptyCollection()]
		$Nsec3Records,

		[Parameter(Mandatory)]
		[int]$HashAlgorithm,

		[Parameter(Mandatory)]
		[int]$Iterations,

		[Parameter(Mandatory)]
		[AllowEmptyCollection()][byte[]]$salt
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	# Filter to real NSEC3 records
	$records = $Nsec3Records | Where-Object -FilterScript {$_ -is [DnsNsec3Record]}
	if (-not $records)
	{return $null}

	# Next closer name (RFC 5155 section 1.3): the name one label longer than the closest encloser, on the path to
	# the query name. 0.8: this used to be the query name itself, which is only right when the closest encloser is
	# the query's immediate parent; for a query several labels below the encloser it hashed the wrong name and
	# rejected valid proofs.
	$queryLabels = $QueryName.ToLower().TrimEnd('.').Split('.')
	$ceLabelCount = @($ClosestEncloserName.ToLower().TrimEnd('.').Split('.') | Where-Object -FilterScript { $_ -ne '' }).Count
	if ($queryLabels.Count -le $ceLabelCount)
	{return $null}
	$nextCloser = ($queryLabels[($queryLabels.Count - $ceLabelCount - 1)..($queryLabels.Count - 1)] -join '.')
	$canon = $nextCloser + '.'

	# Compute its hash
	$ncHash = Get-DnssecNsec3Hash -name $canon `
		-Algorithm $HashAlgorithm `
		-Iterations $Iterations `
		-salt $salt

	# Convert hash to comparable string
	$H = $ncHash -join ','

	foreach ($rec in $records)
	{
		$a = $rec.OwnerHash -join ','
		$b = $rec.NextHash  -join ','

		# Convert back to byte arrays for numeric compare
		$aBytes = $rec.OwnerHash
		$bBytes = $rec.NextHash

		# Compare lexicographically
		$cmpA = [System.BitConverter]::ToString($aBytes)
		$cmpB = [System.BitConverter]::ToString($bBytes)
		$cmpH = [System.BitConverter]::ToString($ncHash)

		$aLessB = ([string]::CompareOrdinal($cmpA, $cmpB) -lt 0)

		if ($aLessB)
		{
			# Normal interval
			if ([string]::CompareOrdinal($cmpA, $cmpH) -lt 0 -and [string]::CompareOrdinal($cmpH, $cmpB) -lt 0)
			{return $rec}
		}
		else
		{
			# Wrap-around interval
			if ([string]::CompareOrdinal($cmpH, $cmpA) -gt 0 -or [string]::CompareOrdinal($cmpH, $cmpB) -lt 0)
			{return $rec}
		}
	}

	return $null
}
