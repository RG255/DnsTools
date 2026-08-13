function ConvertFrom-DnsPacket
{
	<#
	.SYNOPSIS
		Parses a complete DNS packet from wire format bytes.

	.DESCRIPTION
		Converts a DNS packet in wire format to a structured DnsPacket object.

	.PARAMETER packet
		The DNS packet bytes to parse.
	#>
    param(
        [Parameter(Mandatory)]
        [byte[]]$packet
    )
    return [DnsPacket]::Parse($packet)
}
