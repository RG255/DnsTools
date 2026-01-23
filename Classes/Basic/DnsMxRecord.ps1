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
		$prefVal = $r.ReadUInt16BE()
		$exchVal = $r.ReadName()
		return [DnsMxRecord]::new($prefVal, $exchVal)
	}

	[byte[]]ToWire() 
	{
		$w = [DnsBinaryWriter]::new()
		$w.WriteUInt16BE($this.Preference)
		$w.WriteName($this.Exchange)
		return $w.ToArray()
	}
}
