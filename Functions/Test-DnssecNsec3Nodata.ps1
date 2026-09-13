function Test-DnssecNsec3Nodata
{
	<#
	.SYNOPSIS
		Proves DNSSEC authenticated denial of existence for NSEC3 NODATA.

	.DESCRIPTION
		Validates that NSEC3 records correctly prove that a name exists but the requested type does not.

	.PARAMETER QueryName
		The domain name that was queried.

	.PARAMETER QueryType
		The record type that was queried.

	.PARAMETER Nsec3Records
		The NSEC3 records to validate against.

	.PARAMETER HashAlgorithm
		The NSEC3 hash algorithm.
	#>
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
		Justification = 'Rule false positive - it treats "Nodata" as the Latin plural of "Nodatum" (same -a/-um heuristic as data/datum); NODATA is the correct DNSSEC term (RFC 5155) and is not a plural in normal English usage.')]
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

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

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