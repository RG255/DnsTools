function Format-DnsClassName
{
	<#
	.SYNOPSIS
		Formats a DNS class as "Name(Code)".

	.DESCRIPTION
		Accepts a DNS class code and returns a formatted string showing both
		the class name and numerical code, e.g., "IN(1)", "CH(3)", "HS(4)".

	.PARAMETER Class
		The DNS class code.

	.EXAMPLE
		Format-DnsClassName -Class 1
		Returns: IN(1)

	.EXAMPLE
		Format-DnsClassName -Class 3
		Returns: CH(3)
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		[int]$Class
	)

	$className = ConvertFrom-DnsClassCode -Class $Class
	return "$className($Class)"
}
