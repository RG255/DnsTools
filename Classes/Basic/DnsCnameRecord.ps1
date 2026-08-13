class DnsCnameRecord {
	[string]$Target

	DnsCnameRecord([string]$target) 
	{$this.Target = $target}

	static [DnsCnameRecord] Parse([DnsBinaryReader]$r, [int]$len) 
	{
		$start = $r.Position
		$name = $r.ReadName()
		return [DnsCnameRecord]::new($name)
	}

	[byte[]]ToWire() 
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteName($this.Target)
		return $w.ToArray()
	}
}