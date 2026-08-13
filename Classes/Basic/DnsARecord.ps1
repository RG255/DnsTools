class DnsARecord {
	[string]$Address
	static [DnsARecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$bytes = $r.ReadBytes($len)
		return [DnsARecord]@{
			Address = ([System.Net.IPAddress]::new($bytes)).ToString()
		}
	}
}