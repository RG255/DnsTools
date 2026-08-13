function Test-DnssecName
{
	<#
	.SYNOPSIS
		Tests if a DNS name passes DNSSEC validation.

	.DESCRIPTION
		Returns a boolean indicating whether DNSSEC validation succeeds for the specified name and type.

	.PARAMETER name
		The domain name to test.

	.PARAMETER type
		The DNS record type to query (default: 1 = A record).
	#>
	param(
		[string]$name,
		[int]$type = 1
	)

	If ($Script:FTrace) { Write-Trace -CallStack (Get-PSCallStack) }

	$result = Resolve-DnssecName -name $name -type $type
	return $result.Valid
}