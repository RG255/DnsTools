class DnsNsRecord {
	[string]$NsName

	DnsNsRecord([string]$name)
	{$this.NsName = $name}

	static [DnsNsRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$name = $r.ReadName()
		return [DnsNsRecord]::new($name)
	}

	[byte[]]ToWire()
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteName($this.NsName)
		return $w.ToArray()
	}
}