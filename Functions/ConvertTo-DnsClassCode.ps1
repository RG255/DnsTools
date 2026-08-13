function ConvertTo-DnsClassCode
{
	<#
	.SYNOPSIS
		Converts a DNS class name to its numerical code.

	.DESCRIPTION
		Accepts either a DNS class name (e.g., 'IN', 'CH', 'HS') or a numerical code,
		and returns the numerical code.

	.PARAMETER Class
		The DNS class name or code.

	.EXAMPLE
		ConvertTo-DnsClassCode -Class 'IN'
		Returns: 1

	.EXAMPLE
		ConvertTo-DnsClassCode -Class 1
		Returns: 1
	#>
	[CmdletBinding()]
	[OutputType([int])]
	param(
		[Parameter(Mandatory)]
		[object]$Class
	)

	# If already an integer, return it
	if ($Class -is [int]) {
		return $Class
	}

	# If a string, try to convert it
	if ($Class -is [string]) {
		$ClassUpper = $Class.ToUpper()

		# Check if it's in the map
		if ($script:DnsClassMap.ContainsKey($ClassUpper)) {
			return $script:DnsClassMap[$ClassUpper]
		}

		# Try to parse as number
		$numericClass = 0
		if ([int]::TryParse($Class, [ref]$numericClass)) {
			return $numericClass
		}

		throw "Unknown DNS class: $Class"
	}

	throw "Invalid DNS class: $Class (must be string or int)"
}
