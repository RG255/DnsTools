class DnsAaaaRecord {
	[string]$Address
	static [DnsAaaaRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$bytes = $r.ReadBytes($len)
		return [DnsAaaaRecord]@{
			Address = ([System.Net.IPAddress]::new($bytes)).ToString()
		}
	}
}