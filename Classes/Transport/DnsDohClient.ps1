class DnsDohClient {
	[string] $Endpoint
	[int]    $TimeoutSeconds = 10

	# One HttpClient for the whole session: creating and disposing one per query meant a fresh TCP + TLS handshake every time
	# (and sockets left in TIME_WAIT) - a DNSSEC chain walk issues dozens of queries. It is [object], not
	# [System.Net.Http.HttpClient], because a type that Windows PowerShell 5.1 has not loaded yet cannot appear in a class
	# definition.
	static [object] $SharedClient = $null

	DnsDohClient([string]$endpoint)
	{$this.Endpoint = $endpoint}

	[DnsPacket] Query([DnsPacket]$packet)
	{
		$queryBytes = $packet.ToArray()
		$content = $null
		$response = $null

		try {
			# Queries carry the DNS wire format and must never travel in clear text.
			if ($this.Endpoint -notmatch '^https://')
			{throw 'the DoH endpoint must be an https:// URL'}

			if ($null -eq [DnsDohClient]::SharedClient)
			{
				# Windows PowerShell 5.1 does not load System.Net.Http by default (PowerShell 7 does); without this every -DoH query failed there.
				Add-Type -AssemblyName System.Net.Http
				$client = New-Object -TypeName System.Net.Http.HttpClient
				$client.Timeout = [TimeSpan]::FromSeconds($this.TimeoutSeconds)
				# RFC 8484: some servers insist on an explicit Accept for the wire format.
				$null = $client.DefaultRequestHeaders.Accept.ParseAdd('application/dns-message')
				[DnsDohClient]::SharedClient = $client
			}

			$content = New-Object -TypeName System.Net.Http.ByteArrayContent -ArgumentList (,$queryBytes)
			$content.Headers.ContentType = 'application/dns-message'

			$response = ([DnsDohClient]::SharedClient).PostAsync($this.Endpoint, $content).Result
			if (-not $response.IsSuccessStatusCode)
			{throw "HTTP $($response.StatusCode)"}

			$respBytes = $response.Content.ReadAsByteArrayAsync().Result
			# Same acceptance rule as the UDP and TCP paths: matching ID, QR set, and the question we asked.
			if (-not (Test-DnsReplyMatch -Query $queryBytes -Reply $respBytes))
			{throw 'response does not match the query (ID / QR / question)'}
			return [DnsPacket]::Parse($respBytes)
		}
		catch {
			throw "DoH query failed: $($_.Exception.Message)"
		}
		finally {
			if ($null -ne $response)
			{$response.Dispose()}
			if ($null -ne $content)
			{$content.Dispose()}
		}
	}
}
