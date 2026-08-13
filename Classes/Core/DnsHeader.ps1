class DnsHeader {
	[uint16]$Id
	[uint16]$Flags
	[uint16]$QdCount
	[uint16]$AnCount
	[uint16]$NsCount
	[uint16]$ArCount

	DnsHeader([uint16]$id, [uint16]$flags, [uint16]$qd, [uint16]$an, [uint16]$ns, [uint16]$ar) 
	{
		$this.Id      = $id
		$this.Flags   = $flags
		$this.QdCount = $qd
		$this.AnCount = $an
		$this.NsCount = $ns
		$this.ArCount = $ar
	}

	static [DnsHeader] Parse([DnsBinaryReader]$r) 
	{
		$idValue      = $r.ReadUInt16BE()
		$flagsValue   = $r.ReadUInt16BE()
		$qdValue      = $r.ReadUInt16BE()
		$anValue      = $r.ReadUInt16BE()
		$nsValue      = $r.ReadUInt16BE()
		$arValue      = $r.ReadUInt16BE()
		return [DnsHeader]::new($idValue, $flagsValue, $qdValue, $anValue, $nsValue, $arValue)
	}

	[void]Write([DnsBinaryWriter]$w) 
	{
		$w.WriteUInt16BE($this.Id)
		$w.WriteUInt16BE($this.Flags)
		$w.WriteUInt16BE($this.QdCount)
		$w.WriteUInt16BE($this.AnCount)
		$w.WriteUInt16BE($this.NsCount)
		$w.WriteUInt16BE($this.ArCount)
	}
}
