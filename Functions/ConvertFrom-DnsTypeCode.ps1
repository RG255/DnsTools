function ConvertFrom-DnsTypeCode
{
	<#
	.SYNOPSIS
		Converts a DNS record type code to its name.

	.DESCRIPTION
		Accepts a numerical DNS record type code and returns the corresponding type name.
		If the code is not in the known types map, returns "TYPE{code}".

	.PARAMETER Type
		The DNS record type code.

	.EXAMPLE
		ConvertFrom-DnsTypeCode -Type 1
		Returns: A

	.EXAMPLE
		ConvertFrom-DnsTypeCode -Type 999
		Returns: TYPE999
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		[int]$Type
	)

	# Check if it's in the reverse map
	if ($script:QtypeMap.ContainsKey($Type)) {
		return $script:QtypeMap[$Type]
	}

	# Return generic TYPE format for unknown types
	return "TYPE$Type"
}
