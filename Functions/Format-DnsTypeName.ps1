function Format-DnsTypeName
{
	<#
	.SYNOPSIS
		Formats a DNS record type as "Name(Code)".

	.DESCRIPTION
		Accepts a DNS record type code and returns a formatted string showing both
		the type name and numerical code, e.g., "A(1)", "AAAA(28)", "MX(15)".

	.PARAMETER Type
		The DNS record type code.

	.EXAMPLE
		Format-DnsTypeName -Type 1
		Returns: A(1)

	.EXAMPLE
		Format-DnsTypeName -Type 28
		Returns: AAAA(28)
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		[int]$Type
	)

	$typeName = ConvertFrom-DnsTypeCode -Type $Type
	return "$typeName($Type)"
}
