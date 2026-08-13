class DnsDohClient {
	[string] $Endpoint

	DnsDohClient([string]$endpoint) 
	{$this.Endpoint = $endpoint}

	[DnsPacket] Query([DnsPacket]$packet)
	{
		$queryBytes = $packet.ToArray()

		try {
			$httpClient = New-Object -TypeName System.Net.Http.HttpClient
			$content = New-Object -TypeName System.Net.Http.ByteArrayContent -ArgumentList (,$queryBytes)
			$content.Headers.ContentType = 'application/dns-message'

			$response = $httpClient.PostAsync($this.Endpoint, $content).Result
			if (-not $response.IsSuccessStatusCode)
			{throw "HTTP $($response.StatusCode)"}

			$respBytes = $response.Content.ReadAsByteArrayAsync().Result
			return [DnsPacket]::Parse($respBytes)
		}
		catch {
			throw "DoH query failed: $($_.Exception.Message)"
		}
	}
}