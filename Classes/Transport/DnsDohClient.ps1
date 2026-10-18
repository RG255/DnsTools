class DnsDohClient {
	[string] $Endpoint
	[int]    $TimeoutSeconds = 10

	DnsDohClient([string]$endpoint)
	{$this.Endpoint = $endpoint}

	[DnsPacket] Query([DnsPacket]$packet)
	{
		$queryBytes = $packet.ToArray()
		$httpClient = $null
		$content = $null
		$response = $null

		try {
			# Windows PowerShell 5.1 does not load System.Net.Http by default (PowerShell 7 does); without this every -DoH query failed there.
			Add-Type -AssemblyName System.Net.Http
			$httpClient = New-Object -TypeName System.Net.Http.HttpClient
			$httpClient.Timeout = [TimeSpan]::FromSeconds($this.TimeoutSeconds)
			# RFC 8484: some servers insist on an explicit Accept for the wire format.
			$null = $httpClient.DefaultRequestHeaders.Accept.ParseAdd('application/dns-message')
			$content = New-Object -TypeName System.Net.Http.ByteArrayContent -ArgumentList (,$queryBytes)
			$content.Headers.ContentType = 'application/dns-message'

			$response = $httpClient.PostAsync($this.Endpoint, $content).Result
			if (-not $response.IsSuccessStatusCode)
			{throw "HTTP $($response.StatusCode)"}

			$respBytes = $response.Content.ReadAsByteArrayAsync().Result
			$parsed = [DnsPacket]::Parse($respBytes)
			if ($parsed.Header.Id -ne $packet.Header.Id)
			{throw 'response ID does not match the query ID'}
			return $parsed
		}
		catch {
			throw "DoH query failed: $($_.Exception.Message)"
		}
		finally {
			if ($null -ne $response)
			{$response.Dispose()}
			if ($null -ne $content)
			{$content.Dispose()}
			if ($null -ne $httpClient)
			{$httpClient.Dispose()}
		}
	}
}
