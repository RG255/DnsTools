function ConvertTo-DnssecAlgorithmCode
{
	<#
	.SYNOPSIS
		Converts a DNSSEC algorithm name to its numerical code.

	.DESCRIPTION
		Accepts either a DNSSEC algorithm name (e.g., 'RSASHA256', 'ECDSAP256SHA256') or a numerical code,
		and returns the numerical code.

	.PARAMETER Algorithm
		The DNSSEC algorithm name or code.

	.EXAMPLE
		ConvertTo-DnssecAlgorithmCode -Algorithm 'RSASHA256'
		Returns: 8

	.EXAMPLE
		ConvertTo-DnssecAlgorithmCode -Algorithm 13
		Returns: 13
	#>
	[CmdletBinding()]
	[OutputType([int])]
	param(
		[Parameter(Mandatory)]
		[object]$Algorithm
	)

	# If already an integer, return it
	if ($Algorithm -is [int]) {
		return $Algorithm
	}

	# If a string, try to convert it
	if ($Algorithm -is [string]) {
		$AlgorithmUpper = $Algorithm.ToUpper()

		# Check if it's in the map
		if ($script:DnssecAlgorithmMap.ContainsKey($AlgorithmUpper)) {
			return $script:DnssecAlgorithmMap[$AlgorithmUpper]
		}

		# Try to parse as number
		$numericAlgorithm = 0
		if ([int]::TryParse($Algorithm, [ref]$numericAlgorithm)) {
			return $numericAlgorithm
		}

		throw "Unknown DNSSEC algorithm: $Algorithm"
	}

	throw "Invalid DNSSEC algorithm: $Algorithm (must be string or int)"
}
