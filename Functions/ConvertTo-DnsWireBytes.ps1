function ConvertTo-DnsWireBytes 
{
	param(
		[Parameter(Mandatory)]
		[DnsPacket]$packet
	)
	return $packet.ToArray()
}
