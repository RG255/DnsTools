function Test-DnssecNsec3Nxdomain
{
	<#
	.SYNOPSIS
		Proves DNSSEC authenticated denial of existence for NSEC3 NXDOMAIN.

	.DESCRIPTION
		Validates that NSEC3 records correctly prove that a name does not exist in the zone.

	.PARAMETER QueryName
		The domain name that was queried.

	.PARAMETER Nsec3Records
		The NSEC3 records to validate against.

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
		$Nsec3Records,

		[Parameter(Mandatory)]
		[int]$HashAlgorithm,

		[Parameter(Mandatory)]
		[int]$Iterations,

		[Parameter(Mandatory)]
		[byte[]]$salt
	)

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	# 1. Closest Encloser
	$ce = Find-DnssecNsec3ClosestEncloser `
	-QueryName $QueryName `
	-Nsec3Records $Nsec3Records `
	-HashAlgorithm $HashAlgorithm `
	-Iterations $Iterations `
	-salt $salt

	if (-not $ce) 
	{
		return [pscustomobject]@{
			Nxdomain = $false
			Reason   = 'No closest encloser found'
		}
	}

	# 2. Next Closer
	$nc = Find-DnssecNsec3NextCloser `
	-QueryName $QueryName `
	-ClosestEncloserName $ce.Name `
	-Nsec3Records $Nsec3Records `
	-HashAlgorithm $HashAlgorithm `
	-Iterations $Iterations `
	-salt $salt

	if (-not $nc) 
	{
		return [pscustomobject]@{
			Nxdomain = $false
			Reason   = 'No covering NSEC3 record for next-closer name'
		}
	}

	# 3. Both proofs succeeded → NXDOMAIN
	return [pscustomobject]@{
		Nxdomain        = $true
		ClosestEncloser = $ce
		NextCloser      = $nc
	}
}