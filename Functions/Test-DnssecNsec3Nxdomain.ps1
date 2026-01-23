function Test-DnssecNsec3Nxdomain 
{
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