class DnsDotClient {
	[string] $Server
	[int]    $Port
	[int]    $TimeoutMs = 5000

	DnsDotClient([string]$server, [int]$port = 853)
	{
		$this.Server = $server
		$this.Port   = $port
	}

	# Reads exactly $count bytes. A TLS read can return fewer, and 0 means the peer closed the connection -
	# the old loop spun forever on 0.
	hidden [byte[]] ReadExact([System.IO.Stream]$stream, [int]$count)
	{
		$buf = New-Object -TypeName byte[] -ArgumentList $count
		$got = 0
		while ($got -lt $count)
		{
			$n = $stream.Read($buf, $got, $count - $got)
			if ($n -le 0)
			{throw 'connection closed before the full DNS response arrived'}
			$got += $n
		}
		return $buf
	}

	[DnsPacket] Query([DnsPacket]$packet)
	{
		$queryBytes = $packet.ToArray()
		$tcp = $null
		$ssl = $null

		try {
			$tcp = New-Object -TypeName System.Net.Sockets.TcpClient
			$pending = $tcp.BeginConnect($this.Server, $this.Port, $null, $null)
			if (-not $pending.AsyncWaitHandle.WaitOne($this.TimeoutMs))
			{throw "connect to $($this.Server):$($this.Port) timed out after $($this.TimeoutMs) ms"}
			$tcp.EndConnect($pending)
			$tcp.ReceiveTimeout = $this.TimeoutMs
			$tcp.SendTimeout = $this.TimeoutMs

			# No certificate callback: the platform's default validation applies (chain to a trusted root, name
			# matches $this.Server, not expired). The old callback returned $true for everything, so any
			# on-path attacker could impersonate the resolver.
			$ssl = New-Object -TypeName System.Net.Security.SslStream -ArgumentList $tcp.GetStream()
			$ssl.ReadTimeout = $this.TimeoutMs
			$ssl.WriteTimeout = $this.TimeoutMs
			$ssl.AuthenticateAsClient($this.Server)

			$lenBytes = [BitConverter]::GetBytes([uint16]$queryBytes.Length)
			if ([BitConverter]::IsLittleEndian)
			{[Array]::Reverse($lenBytes)}

			$ssl.Write($lenBytes, 0, 2)
			$ssl.Write($queryBytes, 0, $queryBytes.Length)
			$ssl.Flush()

			$lenBuf = $this.ReadExact($ssl, 2)
			if ([BitConverter]::IsLittleEndian)
			{[Array]::Reverse($lenBuf)}
			$respLen = [int][BitConverter]::ToUInt16($lenBuf, 0)
			if ($respLen -lt 12)
			{throw "invalid DNS response length $respLen"}

			$resp = $this.ReadExact($ssl, $respLen)
			$parsed = [DnsPacket]::Parse($resp)
			if ($parsed.Header.Id -ne $packet.Header.Id)
			{throw 'response ID does not match the query ID'}
			return $parsed
		}
		catch {
			throw "DoT query failed: $($_.Exception.Message)"
		}
		finally {
			if ($null -ne $ssl)
			{$ssl.Dispose()}
			if ($null -ne $tcp)
			{$tcp.Close()}
		}
	}
}
