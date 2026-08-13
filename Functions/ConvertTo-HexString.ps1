function ConvertTo-HexString
{
	<#
	.SYNOPSIS
		Converts a byte array to a hexadecimal string.

	.DESCRIPTION
		Converts each byte in an array to its two-digit hexadecimal representation and joins them into a single string.

	.PARAMETER bytes
		The byte array to convert to hexadecimal.
	#>
	param([byte[]]$bytes)
	-join ($bytes | ForEach-Object -Process {$_.ToString('x2')})
}