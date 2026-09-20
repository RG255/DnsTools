function Invoke-DnsUdpQuery
{
	<#
	.SYNOPSIS
		Sends a DNS query via UDP and returns the response.

	.DESCRIPTION
		Sends a DNS query packet to a server via UDP and waits for the response with timeout.

	.PARAMETER server
		The DNS server IP address to query.

	.PARAMETER query
		The DNS query packet in wire format bytes.

	.PARAMETER port
		The port number to query (default: 53).

	.PARAMETER TimeoutMs
		The timeout in milliseconds (default: 3000).
	#>
	param(
		[string]$server,
		[byte[]]$query,
		[int]$port = 53,
		[int]$TimeoutMs = 3000
	)

	If (1 -band ($env:MyFunctionTraceEnabled -as [Int])) { Write-MyFunctionTrace }

	$udp = New-Object -TypeName System.Net.Sockets.UdpClient
	$udp.Client.ReceiveTimeout = $TimeoutMs

	try
	{
		$udp.Connect($server, $port)
		$null = $udp.Send($query, $query.Length)

		$remote = New-Object -TypeName System.Net.IPEndPoint -ArgumentList ([System.Net.IPAddress]::Any, 0)
		$resp = $udp.Receive([ref]$remote)
		return $resp
	}
	finally
	{$udp.Close()}
}
