class DnsMxRecord {
	[uint16]$Preference
	[string]$Exchange

	DnsMxRecord([uint16]$pref, [string]$exch) 
	{
		$this.Preference = $pref
		$this.Exchange   = $exch
	}

	static [DnsMxRecord] Parse([DnsBinaryReader]$r, [int]$len) 
	{
		$pref = $r.ReadUInt16BE()
		$exch = $r.ReadName()
		return [DnsMxRecord]::new($pref, $exch)
	}

	[byte[]]ToWire() 
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt16BE($this.Preference)
		$w.WriteName($this.Exchange)
		return $w.ToArray()
	}
}
