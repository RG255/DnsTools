function Invoke-DnsUdpQuery 
{
	param(
		[string]$server,
		[byte[]]$query,
		[int]$port = 53,
		[int]$TimeoutMs = 3000
	)

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