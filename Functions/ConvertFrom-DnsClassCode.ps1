function ConvertFrom-DnsClassCode
{
	<#
	.SYNOPSIS
		Converts a DNS class code to its name.

	.DESCRIPTION
		Accepts a numerical DNS class code and returns the corresponding class name.
		If the code is not in the known classes map, returns "CLASS{code}".

	.PARAMETER Class
		The DNS class code.

	.EXAMPLE
		ConvertFrom-DnsClassCode -Class 1
		Returns: IN

	.EXAMPLE
		ConvertFrom-DnsClassCode -Class 999
		Returns: CLASS999
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param(
		[Parameter(Mandatory)]
		[int]$Class
	)

	# Check if it's in the reverse map
	if ($script:DnsClassMap.ContainsKey($Class)) {
		return $script:DnsClassMap[$Class]
	}

	# Return generic CLASS format for unknown classes
	return "CLASS$Class"
}
