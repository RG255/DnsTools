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
		[byte[]]$salt
	)

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	# Filter to real NSEC3 records
	$records = $Nsec3Records | Where-Object -FilterScript {$_ -is [DnsNsec3Record]}
	if (-not $records) 
	{return $null}

	# Compute next-closer name (the query itself)
	$nextCloser = $QueryName.ToLower().TrimEnd('.')
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

		$aLessB = ($cmpA -lt $cmpB)

		if ($aLessB) 
		{
			# Normal interval
			if ($cmpA -lt $cmpH -and $cmpH -lt $cmpB) 
			{return $rec}
		}
		else 
		{
			# Wrap-around interval
			if ($cmpH -gt $cmpA -or $cmpH -lt $cmpB) 
			{return $rec}
		}
	}

	return $null
}