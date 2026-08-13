function ConvertTo-DnsTypeCode
{
	<#
	.SYNOPSIS
		Converts a DNS record type name to its numerical code.

	.DESCRIPTION
		Accepts either a DNS record type name (e.g., 'A', 'AAAA', 'MX') or a numerical code,
		and returns the numerical code.

	.PARAMETER Type
		The DNS record type name or code.

	.EXAMPLE
		ConvertTo-DnsTypeCode -Type 'A'
		Returns: 1

	.EXAMPLE
		ConvertTo-DnsTypeCode -Type 28
		Returns: 28
	#>
	[CmdletBinding()]
	[OutputType([int])]
	param(
		[Parameter(Mandatory)]
		[object]$Type
	)

	# If already an integer, return it
	if ($Type -is [int]) {
		return $Type
	}

	# If a string, try to convert it
	if ($Type -is [string]) {
		$TypeUpper = $Type.ToUpper()

		# Check if it's in the map
		if ($script:QtypeMap.ContainsKey($TypeUpper)) {
			return $script:QtypeMap[$TypeUpper]
		}

		# Try to parse as number
		$numericType = 0
		if ([int]::TryParse($Type, [ref]$numericType)) {
			return $numericType
		}

		throw "Unknown DNS record type: $Type"
	}

	throw "Invalid DNS record type: $Type (must be string or int)"
}
