function ConvertFrom-DnssecAlgorithmCode
{
	<#
	.SYNOPSIS
		Converts a DNSSEC algorithm code to its name.

	.DESCRIPTION
		Accepts a numerical DNSSEC algorithm code and returns the corresponding algorithm name.
		If the code is not in the known algorithms map, returns "ALGORITHM{code}".

	.PARAMETER Algorithm
		The DNSSEC algorithm code.

	.EXAMPLE
		ConvertFrom-DnssecAlgorithmCode -Algorithm 8
		Returns: RSASHA256

	.EXAMPLE
		ConvertFrom-DnssecAlgorithmCode -Algorithm 999
		Returns: ALGORITHM999
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		[int]$Algorithm
	)

	# Check if it's in the reverse map
	if ($script:DnssecAlgorithmMap.ContainsKey($Algorithm)) {
		return $script:DnssecAlgorithmMap[$Algorithm]
	}

	# Return generic ALGORITHM format for unknown algorithms
	return "ALGORITHM$Algorithm"
}
