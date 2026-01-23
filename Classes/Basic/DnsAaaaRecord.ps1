class DnsAaaaRecord {
	[string]$Address
	static [DnsAaaaRecord] Parse([byte[]]$rdata) 
	{
		return [DnsAaaaRecord]@{
			Address = ([System.Net.IPAddress]::new($rdata)).ToString()
		}
	}
}