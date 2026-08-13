class DnsDotClient {
	[string] $Server
	[int]    $Port

	DnsDotClient([string]$server, [int]$port = 853) 
	{
		$this.Server = $server
		$this.Port   = $port
	}

	[DnsPacket] Query([DnsPacket]$packet)
	{
		$queryBytes = $packet.ToArray()

		try {
			$tcp = New-Object -TypeName System.Net.Sockets.TcpClient
			$tcp.Connect($this.Server, $this.Port)

			$ssl = New-Object -TypeName System.Net.Security.SslStream -ArgumentList (
				$tcp.GetStream(),
				$false,
				{param($s, $c, $ch, $e) return $true}
			)
			$ssl.AuthenticateAsClient($this.Server)

			$lenBytes = [BitConverter]::GetBytes([uint16]$queryBytes.Length)
			if ([BitConverter]::IsLittleEndian)
			{[Array]::Reverse($lenBytes)}

			$ssl.Write($lenBytes, 0, 2)
			$ssl.Write($queryBytes, 0, $queryBytes.Length)
			$ssl.Flush()

			$lenBuf = New-Object -TypeName byte[] -ArgumentList 2
			$null = $ssl.Read($lenBuf, 0, 2)
			if ([BitConverter]::IsLittleEndian)
			{[Array]::Reverse($lenBuf)}
			$respLen = [BitConverter]::ToUInt16($lenBuf, 0)

			$resp = New-Object -TypeName byte[] -ArgumentList $respLen
			$read = 0
			while ($read -lt $respLen)
			{$read += $ssl.Read($resp, $read, $respLen - $read)}

			$ssl.Close()
			$tcp.Close()

			return [DnsPacket]::Parse($resp)
		}
		catch {
			throw "DoT query failed: $($_.Exception.Message)"
		}
	}
}