function ConvertFrom-DnsWireBytes 
{
	param(
		[Parameter(Mandatory)]
		[byte[]]$bytes
	)
	return [DnsPacket]::Parse($bytes)
}