function ConvertFrom-DnsWireBuffer
{
	<#
	.SYNOPSIS
		Parses DNS wire format bytes into a DnsPacket object.

	.DESCRIPTION
		Converts a byte array in DNS wire format to a structured DnsPacket object for inspection and manipulation.

	.PARAMETER bytes
		The byte array containing DNS wire format data.
	#>
	param(
		[Parameter(Mandatory)]
		[byte[]]$bytes
	)
	return [DnsPacket]::Parse($bytes)
}