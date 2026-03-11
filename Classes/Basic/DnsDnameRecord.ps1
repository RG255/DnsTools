class DnsDnameRecord {
	[string]$Target

	DnsDnameRecord([string]$target)
	{
		$this.Target = $target
	}

	static [DnsDnameRecord] Parse([DnsBinaryReader]$r, [int]$len)
	{
		$name = $r.ReadName()
		return [DnsDnameRecord]::new($name)
	}

	[byte[]]ToWire()
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteName($this.Target)
		return $w.ToArray()
	}
}
