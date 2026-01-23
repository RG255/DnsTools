class DnsDohClient {
	[string] $Endpoint

	DnsDohClient([string]$endpoint) 
	{$this.Endpoint = $endpoint}

	[DnsPacket] Query([DnsPacket]$packet) 
	{
		$bytes = ConvertTo-DnsWireBytes -packet $packet

		$respBytes = Invoke-DnsTransportSafe -Context 'DoH query' -Operation {
			$client = New-Object -TypeName System.Net.Http.HttpClient
			$content = New-Object -TypeName System.Net.Http.ByteArrayContent -ArgumentList ($bytes)
			$content.Headers.ContentType = 'application/dns-message'

			$response = $client.PostAsync($this.Endpoint, $content).Result
			if (-not $response.IsSuccessStatusCode) 
			{throw "HTTP $($response.StatusCode)"}

			return $response.Content.ReadAsByteArrayAsync().Result
		}

		return ConvertFrom-DnsWireBytes -bytes $respBytes
	}
}