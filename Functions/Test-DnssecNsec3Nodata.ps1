function Test-DnssecNsec3Nodata 
{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$QueryName,

		[Parameter(Mandatory)]
		[int]$QueryType,

		[AllowEmptyCollection()]
		$Nsec3Records,

		[Parameter(Mandatory)]
		[int]$HashAlgorithm,

		[Parameter(Mandatory)]
		[int]$Iterations,

		[Parameter(Mandatory)]
		[byte[]]$salt
	)

	$queryCanon = $QueryName.ToLower().TrimEnd('.')

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
			Nodata = $false
			Reason = 'No closest encloser found'
		}
	}

	# For simple NODATA: CE must be the queried name
	if ($ce.Name -ne $queryCanon) 
	{
		return [pscustomobject]@{
			Nodata = $false
			Reason = 'Closest encloser is not the query name'
		}
	}

	# 2. Type bitmap check
	$bitmap = $ce.Record.Types
	$typeExists = $bitmap -contains $QueryType

	if ($typeExists) 
	{
		return [pscustomobject]@{
			Nodata = $false
			Reason = 'Requested type exists'
		}
	}

	# All conditions satisfied → NODATA proven
	return [pscustomobject]@{
		Nodata          = $true
		ClosestEncloser = $ce
	}
}