class DnsARecord {
	[string]$Address
	static [DnsARecord] Parse([byte[]]$rdata) 
	{
		return [DnsARecord]@{
			Address = ([System.Net.IPAddress]::new($rdata)).ToString()
		}
	}
}