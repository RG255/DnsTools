function ConvertTo-DnsWireBytes
{
	<#
	.SYNOPSIS
		Converts a DnsPacket object to DNS wire format bytes.

	.DESCRIPTION
		Serializes a DnsPacket object into a byte array in DNS wire format for transmission over the network.

	.PARAMETER packet
		The DnsPacket object to convert.
	#>
	param(
		[Parameter(Mandatory)]
		[DnsPacket]$packet
	)
	return $packet.ToArray()
}
