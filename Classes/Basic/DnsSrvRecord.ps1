class DnsSrvRecord {
	[uint16]$Priority
	[uint16]$Weight
	[uint16]$Port
	[string]$Target

	DnsSrvRecord([uint16]$pri,[uint16]$wgt,[uint16]$port,[string]$target) 
	{
		$this.Priority = $pri
		$this.Weight   = $wgt
		$this.Port     = $port
		$this.Target   = $target
	}

	static [DnsSrvRecord] Parse([DnsBinaryReader]$r, [int]$len)
 
	{
		$prival  = $r.ReadUInt16BE()
		$wgtval  = $r.ReadUInt16BE()
		$portval = $r.ReadUInt16BE()
		$tgtval  = $r.ReadName()
		return [DnsSrvRecord]::new($prival,$wgtval,$portval,$tgtval)
	}

	[byte[]]ToWire() 
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt16BE($this.Priority)
		$w.WriteUInt16BE($this.Weight)
		$w.WriteUInt16BE($this.Port)
		$w.WriteName($this.Target)
		return $w.ToArray()
	}
}