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

	# 0.8: the socket's address family must match the server's. A default (IPv4) UdpClient cannot Connect() to an
	# IPv6 server ("socket is not connected"), so every IPv6 root / glue address failed before sending anything.
	$family = [System.Net.Sockets.AddressFamily]::InterNetwork
	$parsedServer = $null
	if ([System.Net.IPAddress]::TryParse($server, [ref]$parsedServer))
	{$family = $parsedServer.AddressFamily}
	$udp = New-Object -TypeName System.Net.Sockets.UdpClient -ArgumentList $family
	$udp.Client.ReceiveTimeout = $TimeoutMs

	try
	{
		$udp.Connect($server, $port)
		$null = $udp.Send($query, $query.Length)

		$anyAddress = [System.Net.IPAddress]::Any
		if ($family -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6)
		{$anyAddress = [System.Net.IPAddress]::IPv6Any}
		$remote = New-Object -TypeName System.Net.IPEndPoint -ArgumentList ($anyAddress, 0)
		# 0.8: accept only a reply that answers THIS query: same 16-bit ID, QR set, and the same question (name, type,
		# class, compared case-insensitively). Anything else is discarded and the wait continues until the deadline,
		# so a stale or spoofed datagram can neither be parsed as the answer nor end the wait early.
		$qEnd = 12
		while ($qEnd -lt $query.Length -and $query[$qEnd] -ne 0)
		{$qEnd += 1 + $query[$qEnd]}
		$qEnd += 5   # root label + QTYPE + QCLASS
		$deadline = [Diagnostics.Stopwatch]::StartNew()
		$resp = $null
		while ($null -eq $resp)
		{
			if ($deadline.ElapsedMilliseconds -gt $TimeoutMs)
			{throw "DNS query to ${server}:$port timed out after $TimeoutMs ms (no matching reply)"}
			$candidate = $udp.Receive([ref]$remote)
			$isReply = $candidate.Length -ge $qEnd -and $candidate[0] -eq $query[0] -and $candidate[1] -eq $query[1] -and ($candidate[2] -band 0x80) -ne 0
			for ($i = 12; $isReply -and $i -lt $qEnd; $i++)
			{
				$a = $query[$i]
				$b = $candidate[$i]
				if ($a -ge 65 -and $a -le 90) { $a += 32 }
				if ($b -ge 65 -and $b -le 90) { $b += 32 }
				if ($a -ne $b) { $isReply = $false }
			}
			if ($isReply)
			{$resp = $candidate}
			if (-not $isReply)
			{Write-Verbose -Message "Discarded a datagram from $server that does not match the query (ID/question)"}
		}

		# 0.8: TC (truncated, byte 2 bit 0x02) means the UDP answer is incomplete - e.g. a large DNSKEY RRset
		# arrives without its RRSIG. Parsing it as complete made signed zones such as .org look unsigned or
		# bogus. Repeat the query over TCP (RFC 7766) and return that full answer instead.
		if ($resp.Length -ge 4 -and ($resp[2] -band 0x02) -ne 0)
		{
			Write-Verbose -Message "UDP response from $server truncated (TC) - retrying over TCP"
			$tcp = New-Object -TypeName System.Net.Sockets.TcpClient
			try
			{
				$pending = $tcp.BeginConnect($server, $port, $null, $null)
				if (-not $pending.AsyncWaitHandle.WaitOne($TimeoutMs))
				{throw "TCP connect to ${server}:$port timed out after $TimeoutMs ms"}
				$tcp.EndConnect($pending)
				$tcp.ReceiveTimeout = $TimeoutMs
				$tcp.SendTimeout = $TimeoutMs
				$stream = $tcp.GetStream()

				$frame = New-Object -TypeName byte[] -ArgumentList ($query.Length + 2)
				$frame[0] = [byte](($query.Length -shr 8) -band 0xFF)
				$frame[1] = [byte]($query.Length -band 0xFF)
				[Array]::Copy($query, 0, $frame, 2, $query.Length)
				$stream.Write($frame, 0, $frame.Length)
				$stream.Flush()

				# Read exactly N bytes: a TCP read can return fewer, and 0 means the peer closed.
				$readExact = {
					param([int]$Count)
					$buf = New-Object -TypeName byte[] -ArgumentList $Count
					$got = 0
					while ($got -lt $Count)
					{
						$n = $stream.Read($buf, $got, $Count - $got)
						if ($n -le 0)
						{throw "TCP connection to ${server}:$port closed before the full DNS response arrived"}
						$got += $n
					}
					, $buf
				}

				$lenBuf = & $readExact 2
				$respLen = ([int]$lenBuf[0] -shl 8) -bor [int]$lenBuf[1]
				if ($respLen -lt 12)
				{throw "TCP DNS response from ${server}:$port has an invalid length ($respLen)"}
				return [byte[]](& $readExact $respLen)
			}
			finally
			{$tcp.Close()}
		}

		return $resp
	}
	finally
	{$udp.Close()}
}
