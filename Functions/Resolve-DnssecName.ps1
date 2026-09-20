function Resolve-DnssecName
{
	<#
	.SYNOPSIS
		Resolves a DNS name with DNSSEC validation (simplified wrapper).

	.DESCRIPTION
		Convenience wrapper for Resolve-Dnssec that performs DNSSEC-validated DNS resolution.

	.PARAMETER name
		The domain name to resolve.

	.PARAMETER type
		The DNS record type to query (default: 1 = A record).
	#>
	param(
		[string]$name,
		[int]$type = 1
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	return Resolve-Dnssec -name $name -type $type
}
