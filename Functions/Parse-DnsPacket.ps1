function Parse-DnsPacket 
{
	param(
		[Parameter(Mandatory)]
		[byte[]]$packet
	)
	return [DnsPacket]::Parse($packet)
}
