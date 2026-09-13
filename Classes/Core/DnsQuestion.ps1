class DnsQuestion {
	[string]$Name
	[uint16]$Type
	[uint16]$Class

	DnsQuestion([string]$name, [uint16]$type, [uint16]$class)
	{
		$this.Name  = $name
		$this.Type  = $type
		$this.Class = $class
	}

	static [DnsQuestion] Parse([DnsBinaryReader]$r)
	{
		$nameValue  = $r.ReadName()
		$typeValue  = $r.ReadUInt16BE()
		$classValue = $r.ReadUInt16BE()
		return [DnsQuestion]::new($nameValue, $typeValue, $classValue)
	}

	[void]Write([DnsBinaryWriter]$w)
	{
		$w.WriteName($this.Name)
		$w.WriteUInt16BE($this.Type)
		$w.WriteUInt16BE($this.Class)
	}
}