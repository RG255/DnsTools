function Format-DnssecAlgorithmName
{
	<#
	.SYNOPSIS
		Formats a DNSSEC algorithm as "Name(Code)".

	.DESCRIPTION
		Accepts a DNSSEC algorithm code and returns a formatted string showing both
		the algorithm name and numerical code, e.g., "RSASHA256(8)", "ECDSAP256SHA256(13)".

	.PARAMETER Algorithm
		The DNSSEC algorithm code.

	.EXAMPLE
		Format-DnssecAlgorithmName -Algorithm 8
		Returns: RSASHA256(8)

	.EXAMPLE
		Format-DnssecAlgorithmName -Algorithm 13
		Returns: ECDSAP256SHA256(13)
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		[int]$Algorithm
	)

	$algorithmName = ConvertFrom-DnssecAlgorithmCode -Algorithm $Algorithm
	return "$algorithmName($Algorithm)"
}
