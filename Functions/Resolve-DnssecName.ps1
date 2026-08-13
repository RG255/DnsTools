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

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	return Resolve-Dnssec -name $name -type $type
}